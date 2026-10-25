//! heika のノードの REST。catapult の REST のうち、ウォレットが委任に使う口と、heika だけの口を返す。
//!
//! - `/node/info`: ノードの身元と、委任の鍵（`nodePublicKey`）
//! - `/node/peers`: 知っているピア。GUI のノードは、ここから最初のつなぎ先を選ぶ
//! - `/chain/info`: 高さ、スコア、確定したブロック
//! - `/node/unlockedaccount`: ハーベストしている、委任されたリモートの鍵
//! - `/heika/delegations`: 届いた委任の要求ごとに、引き受けたか、待っているか、なぜ引き受けなかったか
//! - `PUT /transactions`: 署名したトランザクションを受け付けて、ネットワークに流す
//! - `PUT /blocks`: 外で組んだブロック（16進の JSON か、`application/octet-stream` のバイト列）を受け取って、
//!   先端につながれば足し、ネットワークに流す（heika だけ）
//! - `PUT /transactions/partial`、`PUT /transactions/cosignature`: 連署を待つアグリゲートボンデッドと、その連署
//! - `/transactions/partial/{hash}`、`/transactions/partial`: 連署を待っているもの（集まった連署付き）と、その一覧
//! - `/accounts/{accountId}`、`/mosaics/{mosaicId}`、`/namespaces/{namespaceId}`、`/metadata/{compositeHash}` と、
//!   それぞれの `/merkle`: 今の状態と、状態の木の道。`?height=` を付ければ、その高さの状態（heika だけ）
//! - `POST /accounts`、`POST /mosaics`: ID を並べて、まとめて引く。これも `?height=` を受ける
//! - `/account/{address}/multisig`、`/merkle`、`/graph`: マルチシグの状態と、その木の道と、上下にたどった木。
//!   これも `?height=` を受ける
//! - `/lock/hash/{hash}`、`/lock/secret/{compositeHash}`、`/restrictions/account/{address}`、
//!   `/restrictions/mosaic/{compositeHash}` と、それぞれの `/merkle` と、`POST` でまとめて引く口: ロックと制限。
//!   これも `?height=` を受ける
//! - `/metadata`: メタデータの検索。ノードが検索表を作っているときだけ（`storage.search`）
//! - `/namespaces`、`POST /namespaces/names`、`POST /namespaces/account/names`、`POST /namespaces/mosaic/names`:
//!   ネームスペースの検索と、その名前。これもノードが検索表を作っているときだけ
//! - `/blocks/{height}`: ブロックのヘッダーと、その高さの9本の根
//! - `/network/fees/transaction`: 直近のブロックの手数料の倍率と、ノードが受け付ける下限
//! - `/network/properties`: ネットワークの設定（catapult の `config-network.properties`）
//! - `/transactions/confirmed`: 承認されたトランザクションを、関わったアドレスと高さで検索する。ノードが索引を
//!   作っているときだけ（`storage.search` の `transactions`）
//! - `/transactionStatus/{hash}`、`/transactions/confirmed/{hash}`、`/blocks/{height}/transactions/{hash}/merkle`:
//!   送ったトランザクションの行方と、入ったブロックへの Merkle の経路
//!
//! ノードの駆動役が [`Snapshot`] を書き換え、ここは読んで返すだけにする。チェーンの本体には触らない。
//! 受け付けたトランザクションは、駆動役から渡された [`Submit`] に渡し、状態とブロックは [`Reader`] で読む。
//! ID の読み方と、答えの形（見つからなければ 404 など）はここで決め、何をどう読むかは [`Reader`] に任せる。
//! catapult の REST と同じく、どこのページからでも読めるようにする（CORS）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::Request;
use axum::extract::{DefaultBodyLimit, Path, Query, RawQuery, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    CONTENT_DISPOSITION, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn, map_response};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::patricia::{self, SubCache};
use heika_rest::block::BlockInfo;
use heika_rest::merkle::{MerkleProofInfo, MerkleStateInfo};
use heika_rest::node::{
    AnnounceJson, AnnounceResultJson, ChainInfoJson, CosignatureJson, DelegationJson,
    DeploymentJson, ErrorJson, HealthStatusJson, NetworkJson, NetworkPropertiesJson,
    NodeHealthJson, NodeInfoJson, ServerInfoJson, ServerJson, TransactionFeesJson,
    UnlockedAccountJson,
};
use heika_rest::send::TransactionStatus;
use heika_rest::state::{
    AccountInfo, AccountJson, AccountNamesJson, AccountRestrictionsInfo, AccountRestrictionsJson,
    HashLockInfo, HashLockJson, MetadataEntryJson, MetadataInfo, MosaicInfo, MosaicNamesJson,
    MosaicRestrictionEntryJson, MosaicRestrictionInfo, MosaicStateJson, MultisigGraphLevel,
    MultisigInfo, MultisigJson, NamespaceInfo, NamespaceNameJson, SecretLockInfo, SecretLockJson,
};
use heika_rest::transaction::{TransactionInfo, parse_transaction_position};

/// API が返す、ノードの今の様子
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub node: NodeInfoJson,
    /// 知っているピア（ピアの `Node_Discovery_Pull_Peers` に答えるものと同じ）
    pub peers: Vec<NodeInfoJson>,
    pub chain: ChainInfoJson,
    pub unlocked: UnlockedAccountJson,
    pub delegations: Vec<DelegationJson>,
}

/// 駆動役と API で分け合う様子
pub type Shared = Arc<RwLock<Snapshot>>;

/// 署名したトランザクションのバイト列を受け付ける口。受け付けたら（もう持っていたときも）`Ok`、受け付けなかったら
/// わけを返す。ネットワークに流すのも、この口の仕事
pub type Submit = Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

/// 状態を答える `?height=` の高さ（`X-Heika-Height`）
const HEIGHT_HEADER: &str = "x-heika-height";

/// 状態を読めなかったわけ
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    /// まだその高さのブロックを実行していない
    Ahead { height: u64, tip: u64 },
    /// その高さの状態の履歴を持っていない（刈り込んだか、もともと残していない）
    NoHistory { height: u64 },
    /// 頼み方が読めない（409）。わけの文
    Invalid(String),
    /// 読めなかった。わけの文
    Other(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ahead { height, tip } => {
                write!(f, "高さ {height} は、実行した高さ {tip} より上です")
            }
            Self::NoHistory { height } => write!(f, "高さ {height} の状態の差分を持っていません"),
            Self::Invalid(message) => f.write_str(message),
            Self::Other(message) => f.write_str(message),
        }
    }
}

impl From<String> for StateError {
    fn from(message: String) -> Self {
        Self::Other(message)
    }
}

/// チェーンの中身を読む口。エラーはわけの文（500 で返す）。
///
/// 木のキーのもとと、状態のバイト列の組の並び（[`Reader::lock_or_restriction_states`]）
pub type KeyedStates = Vec<(Vec<u8>, Vec<u8>)>;

/// 状態を読む口の `at` は、そのブロックを実行したあとの状態を引く高さ。`None` なら今の状態
pub trait Reader: Send + Sync {
    /// アカウントの状態。`addresses` のうち、あるものだけを渡した順に。全部を同じ高さで読む
    fn accounts(
        &self,
        addresses: &[Address],
        at: Option<u64>,
    ) -> Result<Vec<AccountJson>, StateError>;
    /// モザイクの定義の状態。`ids` のうち、あるものだけを渡した順に。全部を同じ高さで読む
    fn mosaics(&self, ids: &[u64], at: Option<u64>) -> Result<Vec<MosaicStateJson>, StateError>;
    /// マルチシグの状態。`addresses` のうち、あるものだけを渡した順に。全部を同じ高さで読む
    fn multisigs(
        &self,
        addresses: &[Address],
        at: Option<u64>,
    ) -> Result<Vec<MultisigJson>, StateError>;
    /// ロックか制限（`cache` が [`SubCache::HashLockInfo`]、[`SubCache::SecretLockInfo`]、
    /// [`SubCache::AccountRestriction`]、[`SubCache::MosaicRestriction`]）の状態を、catapult の状態のバイト列
    /// （版の番号から）で。`keys`（木のキーのもと）のうち、あるものだけを、キーと組で渡した順に。全部を同じ高さで読む。
    /// ロックは履歴の最後のもので、使ったものや期限を過ぎたものも、状態に残っていれば返す（catapult の REST と同じ）
    fn lock_or_restriction_states(
        &self,
        cache: SubCache,
        keys: &[Vec<u8>],
        at: Option<u64>,
    ) -> Result<KeyedStates, StateError>;
    /// `address` から上と下にたどったマルチシグの木（[`multisig_graph`]）。`address` になければ `None`。
    /// 全部を同じ高さで読む
    fn multisig_graph(
        &self,
        address: &Address,
        at: Option<u64>,
    ) -> Result<Option<Vec<MultisigGraphLevel>>, StateError>;
    /// ネームスペース（ルートか子）の状態。なければ `None`。期限（猶予を含む）が過ぎても状態に残っていれば返し、
    /// `active` が `false` になる（catapult の REST と同じ）
    fn namespace(&self, id: u64, at: Option<u64>) -> Result<Option<NamespaceInfo>, StateError>;
    /// メタデータの状態。`composite_hash` は1件を指すハッシュ。なければ `None`
    fn metadata(
        &self,
        composite_hash: &Hash256,
        at: Option<u64>,
    ) -> Result<Option<MetadataEntryJson>, StateError>;
    /// メタデータを `filter` で絞り、`page` の分を返す。`after` があれば、並びでその位置より後から。
    /// `at` なら、その高さにあったものとその高さの値。
    /// 検索表を作っていなければ（`at` なら、昔の高さの分も作っていなければ）`None`
    fn search_metadata(
        &self,
        filter: &MetadataFilter,
        page: PageRequest,
        after: Option<&MetadataPosition>,
        at: Option<u64>,
    ) -> Result<Option<Vec<MetadataEntryJson>>, StateError>;
    /// ネームスペースを `filter` で絞り、`page` の分を、位置（検索表のキーの16進）と組で返す。`after` があれば、
    /// 並びでその位置（前に返した位置のバイト列）より後から。`at` なら、その高さにあったものとその高さの状態。
    /// 検索表を作っていなければ（`at` なら、昔の高さの分も作っていなければ）`None`
    fn search_namespaces(
        &self,
        filter: &NamespaceFilter,
        page: PageRequest,
        after: Option<&[u8]>,
        at: Option<u64>,
    ) -> Result<Option<Vec<(String, NamespaceInfo)>>, StateError>;
    /// ネームスペースの名前（自分の部分）と親の ID（ルートは `None`）。`ids` と、その親を全部。登録を見ていないものは
    /// 返さない。名前の表を作っていなければ `None`
    fn namespace_names(&self, ids: &[u64]) -> Result<Option<Vec<NamespaceNameJson>>, String>;
    /// `target` を別名にしている、今有効なネームスペースの名前（ルートからつないだもの）。名前の表を作っていなければ `None`
    fn alias_names(&self, target: AliasTarget) -> Result<Option<Vec<String>>, String>;
    /// 状態の木 `cache` の、根から `key` の葉への道。ないことを示す道もある
    fn state_path(
        &self,
        cache: SubCache,
        key: &Hash256,
        at: Option<u64>,
    ) -> Result<MerkleStateInfo, StateError>;
    /// `height` のブロック。なければ（まだないか、刈り込んだか、その高さの根がもうなければ）`None`
    fn block(&self, height: u64) -> Result<Option<BlockInfo>, String>;
    /// トランザクションの行方。知らなければ `None`
    fn transaction_status(&self, hash: &Hash256) -> Result<Option<TransactionStatus>, String>;
    /// 承認されたトランザクションを `filter` で絞り、`page` の分を返す。`after` があれば、並び（高さとブロックの中の
    /// 番号の順）でその位置より後から。アドレス、署名者、宛先で絞るのに要る索引（`storage.search` の
    /// `transactions`）を作っていなければ `None`。それらで絞らなければ、索引がなくてもしまってあるブロックを順に読む
    fn search_transactions(
        &self,
        filter: &TransactionFilter,
        page: PageRequest,
        after: Option<(u64, u32)>,
    ) -> Result<Option<Vec<TransactionInfo>>, String>;
    /// 承認されたトランザクション。知らなければ `None`
    fn confirmed_transaction(&self, hash: &Hash256) -> Result<Option<TransactionInfo>, String>;
    /// 高さ `height` のブロックの TransactionsHash への、`hash` のトランザクションの経路。なければ `None`
    fn transaction_merkle(
        &self,
        height: u64,
        hash: &Hash256,
    ) -> Result<Option<MerkleProofInfo>, String>;
    /// 直近のブロックの手数料の倍率と、ノードが受け付ける下限
    fn transaction_fees(&self) -> Result<TransactionFeesJson, String>;
    /// 連署を待つアグリゲートボンデッド（集まった連署付き）。知らなければ `None`
    fn partial_transaction(&self, hash: &Hash256) -> Result<Option<TransactionInfo>, String>;
    /// 連署を待つものの一覧。`filter` に合うものを、期限の早い順に
    fn partial_transactions(&self, filter: &PartialFilter) -> Result<Vec<TransactionInfo>, String>;
    /// 公開鍵からアドレスを出すときのネットワーク
    fn network(&self) -> NetworkIdentifier;
}

/// メタデータの検索の絞り込み（catapult の REST の `/metadata` と同じ意味）。全部を満たすものを返す
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataFilter {
    pub source: Option<Address>,
    pub target: Option<Address>,
    pub scoped_key: Option<u64>,
    pub target_id: Option<u64>,
    pub metadata_type: Option<u8>,
}

/// ネームスペースの検索の絞り込み（catapult の REST の `/namespaces` と同じ意味）。全部を満たすものを返す
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceFilter {
    pub owner: Option<Address>,
    /// ルートの ID。そのルートと子
    pub level0: Option<u64>,
    /// 0 ならルート、1 なら子
    pub registration_type: Option<u8>,
    /// 0 なら別名なし、1 ならモザイク、2 ならアドレス
    pub alias_type: Option<u8>,
}

/// 別名の向かう先
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasTarget {
    Address(Address),
    Mosaic(u64),
}

/// `/namespaces` のクエリ文字列
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NamespaceQuery {
    owner_address: Option<String>,
    level0: Option<String>,
    registration_type: Option<u8>,
    alias_type: Option<u8>,
    page_size: Option<usize>,
    page_number: Option<usize>,
    order: Option<String>,
    offset: Option<String>,
    height: Option<String>,
}

/// 名前を引く口に、1回で頼める数
const MAX_NAME_IDS: usize = 100;

/// アカウントやモザイクをまとめて引く口に、1回で頼める数。catapult の REST には上限がないので、ふつうの使い方で
/// 当たらないくらいに大きく取る
const MAX_STATE_IDS: usize = 1000;

/// メタデータの検索の、1件の位置（[`MetadataEntryJson::position`] を読んだもの）。ページ送りの `offset`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataPosition {
    pub source: Address,
    pub metadata_type: u8,
    pub target: Address,
    pub target_id: u64,
    pub scoped_key: u64,
}

impl MetadataPosition {
    /// [`MetadataEntryJson::position`] の16進を読む
    fn parse(text: &str) -> Option<Self> {
        if text.len() != 48 + 2 + 48 + 16 + 16 || !text.is_ascii() {
            return None;
        }
        let address = |at: usize| Address::from_hex(&text[at..at + 48]).ok();
        let id = |at: usize| hex_id(&text[at..at + 16]);
        Some(Self {
            source: address(0)?,
            metadata_type: u8::from_str_radix(&text[48..50], 16).ok()?,
            target: address(50)?,
            target_id: id(98)?,
            scoped_key: id(114)?,
        })
    }
}

/// 一覧のどのページを返すか。並びは検索表のキーの順（`descending` なら逆）。catapult の REST は登録の順なので違う
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRequest {
    /// 1 ページの件数（10 から 100）
    pub size: usize,
    /// 1 から
    pub number: usize,
    pub descending: bool,
}

/// 承認されたトランザクションの検索の絞り込み。アグリゲートの中のものは返さない（catapult の `embedded` の既定）
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionFilter {
    /// 関わったアドレス（catapult の `meta.addresses`）
    pub address: Option<Address>,
    /// 署名者（アグリゲートなら外側の）
    pub signer: Option<PublicKey>,
    /// 送金、シークレットロック、シークレットの証明の宛先（解決する前のアドレスのバイト列）
    pub recipient: Option<[u8; 24]>,
    /// トランザクションの種類のどれか。空なら絞らない
    pub types: Vec<u16>,
    /// 送金のモザイク（解決する前の ID）と、その額の範囲。額はモザイクがあるときだけ
    pub mosaic: Option<u64>,
    pub from_amount: Option<u64>,
    pub to_amount: Option<u64>,
    /// 入った高さの範囲（両端を含む）
    pub from_height: u64,
    pub to_height: u64,
}

/// `/transactions/confirmed` のクエリ文字列。heika がまだ扱わない絞り込みは、あれば 501 にするために読む
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionQuery {
    address: Option<String>,
    height: Option<String>,
    from_height: Option<String>,
    to_height: Option<String>,
    page_size: Option<usize>,
    page_number: Option<usize>,
    order: Option<String>,
    offset: Option<String>,
    embedded: Option<String>,
    signer_public_key: Option<String>,
    recipient_address: Option<String>,
    transfer_mosaic_id: Option<String>,
    from_transfer_amount: Option<String>,
    to_transfer_amount: Option<String>,
}

/// クエリ文字列の `type` を全部（catapult の REST と同じく、何回でも書ける）。読めなければ `None`
fn transaction_types(query: Option<&str>) -> Option<Vec<u16>> {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.strip_prefix("type="))
        .map(|value| value.parse::<u16>().ok())
        .collect()
}

/// `/metadata` のクエリ文字列
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataQuery {
    source_address: Option<String>,
    target_address: Option<String>,
    scoped_metadata_key: Option<String>,
    target_id: Option<String>,
    metadata_type: Option<u8>,
    page_size: Option<usize>,
    page_number: Option<usize>,
    order: Option<String>,
    offset: Option<String>,
    height: Option<String>,
}

/// 連署を待つものの一覧の絞り込み（catapult の REST と同じ意味）
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PartialFilter {
    /// 関わるアカウント（外側の署名者、中のトランザクションの署名者、連署者、送金の宛先）
    pub address: Option<Address>,
    /// 外側の署名者
    pub signer: Option<PublicKey>,
}

/// `/transactions/partial` のクエリ文字列
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PartialQuery {
    address: Option<String>,
    signer_public_key: Option<String>,
    page_size: Option<usize>,
    page_number: Option<usize>,
}

/// 一覧の1ページ（catapult の REST の `data` と `pagination`）
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Page<T> {
    data: Vec<T>,
    pagination: Pagination,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Pagination {
    page_number: usize,
    page_size: usize,
}

/// API がノードに頼む口
#[derive(Clone)]
pub struct Node {
    pub submit: Submit,
    /// 連署を待つアグリゲートボンデッドを受け付ける口
    pub submit_partial: Submit,
    /// 切り離した連署（catapult の `DetachedCosignature` の 136 バイト）を受け付ける口
    pub submit_cosignature: Submit,
    /// 外で組んだブロックを受け取る口
    pub submit_block: Submit,
    pub reader: Arc<dyn Reader>,
    /// `/network/properties` で返す、ネットワークの設定。動いている間は変わらない
    pub network_properties: Arc<NetworkPropertiesJson>,
}

/// バイナリに埋め込んだソースの ZIP。`GET /heika/sourcecode.zip` で返す
static SOURCE: OnceLock<&'static [u8]> = OnceLock::new();

/// バイナリに埋め込んだソースの ZIP を、REST で返せるようにする。AGPL-3.0 の 13 条（ネットワーク越しに使う人に
/// ソースを渡す）のため。heika に手を入れてビルドしても、そのソースが埋め込まれて返る。最初の1回だけが効く
pub fn offer_source(zip: &'static [u8]) {
    let _ = SOURCE.set(zip);
}

#[derive(Clone)]
struct Api {
    shared: Shared,
    node: Node,
}

/// 止める合図を見に行く間隔
const STOP_POLL: Duration = Duration::from_millis(200);

fn read(api: &Api) -> Snapshot {
    // 書く側が落ちていても、最後に書いたものを返す
    api.shared
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn node_info(State(api): State<Api>) -> Json<NodeInfoJson> {
    Json(read(&api).node)
}

async fn node_peers(State(api): State<Api>) -> Json<Vec<NodeInfoJson>> {
    Json(read(&api).peers)
}

/// ネットワークの名前。catapult の REST の設定の `network.name` にあたる
async fn network(State(api): State<Api>) -> Json<NetworkJson> {
    let (name, description) = match read(&api).node.network_identifier {
        104 => ("mainnet", "Symbol mainnet"),
        152 => ("testnet", "Symbol testnet"),
        _ => ("custom", "Symbol private network"),
    };
    Json(NetworkJson {
        name: name.to_owned(),
        description: description.to_owned(),
    })
}

async fn network_properties(State(api): State<Api>) -> Json<NetworkPropertiesJson> {
    Json(NetworkPropertiesJson::clone(&api.node.network_properties))
}

/// REST の版。catapult の REST の版の代わりに heika の版を返し、配った道具として heika を名乗る
async fn node_server() -> Json<ServerInfoJson> {
    let version = env!("CARGO_PKG_VERSION").to_owned();
    Json(ServerInfoJson {
        server_info: ServerJson {
            rest_version: version.clone(),
            deployment: DeploymentJson {
                deployment_tool: "heika".to_owned(),
                deployment_tool_version: version,
                last_updated_date: "N/A".to_owned(),
            },
        },
    })
}

/// REST はノードと同じプロセスにいるので、答えられればノードも DB も動いている
async fn node_health() -> Json<NodeHealthJson> {
    Json(NodeHealthJson {
        status: HealthStatusJson {
            api_node: "up".to_owned(),
            db: "up".to_owned(),
        },
    })
}

async fn chain_info(State(api): State<Api>) -> Json<ChainInfoJson> {
    Json(read(&api).chain)
}

async fn unlocked(State(api): State<Api>) -> Json<UnlockedAccountJson> {
    Json(read(&api).unlocked)
}

async fn delegations(State(api): State<Api>) -> Json<Vec<DelegationJson>> {
    Json(read(&api).delegations)
}

/// 16進のトランザクションを受け付ける。catapult の REST と同じく、受け付けたら 202、受け付けなければ 409
/// 連署を待つアグリゲートボンデッドを受け付ける
async fn announce_partial(State(api): State<Api>, Json(body): Json<AnnounceJson>) -> Response {
    let result = match decode_hex(&body.payload) {
        Some(bytes) => (api.node.submit_partial)(bytes),
        None => Err("payload が16進ではありません".to_owned()),
    };
    match result {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(AnnounceResultJson::pushed_via(256, "/transactions/partial")),
        )
            .into_response(),
        Err(message) => invalid(message),
    }
}

/// 切り離した連署を受け付ける。バージョン（0）、署名者の公開鍵、署名、アグリゲートのハッシュの順に並べて渡す
async fn announce_cosignature(
    State(api): State<Api>,
    Json(body): Json<CosignatureJson>,
) -> Response {
    let version_ok = body
        .version
        .as_deref()
        .is_none_or(|version| version.parse::<u64>() == Ok(0));
    let parts = (
        decode_hex(&body.signer_public_key).filter(|bytes| bytes.len() == 32),
        decode_hex(&body.signature).filter(|bytes| bytes.len() == 64),
        decode_hex(&body.parent_hash).filter(|bytes| bytes.len() == 32),
    );
    let result = match parts {
        (Some(key), Some(signature), Some(parent)) if version_ok => {
            let bytes = [&[0; 8][..], &key, &signature, &parent].concat();
            (api.node.submit_cosignature)(bytes)
        }
        _ => Err("連署の形が正しくありません".to_owned()),
    };
    match result {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(AnnounceResultJson::pushed_via(
                257,
                "/transactions/cosignature",
            )),
        )
            .into_response(),
        Err(message) => invalid(message),
    }
}

async fn announce(State(api): State<Api>, Json(body): Json<AnnounceJson>) -> Response {
    let result = match decode_hex(&body.payload) {
        Some(bytes) => (api.node.submit)(bytes),
        None => Err("payload が16進ではありません".to_owned()),
    };
    match result {
        Ok(()) => (StatusCode::ACCEPTED, Json(AnnounceResultJson::pushed())).into_response(),
        Err(message) => invalid(message),
    }
}

/// `PUT /blocks` で受け取るブロックの大きさの上限。待ち受けの P2P で受け取る本体（`Push_Block`）とそろえる。
/// 6,000 件の送金にそれぞれ 1024 バイトのメッセージと 255 個のモザイクを入れると、30 MB ほどになる
pub const MAX_BLOCK_BYTES: usize = 32 * 1024 * 1024;

/// ブロックを受け取る。本文は、`Content-Type` が `application/json` なら `PUT /transactions` と同じ16進の JSON、
/// `application/octet-stream` ならブロックのバイト列そのまま。ほか（書いていないものも）は 415。受け取ったら 202、
/// 受け取らなければ 409。ブロックが [`MAX_BLOCK_BYTES`]（JSON なら16進でその倍）を超えれば 413。足したかは
/// あとでチェーンが決めるので、`/chain/info` かノードのログで見る
async fn announce_block(State(api): State<Api>, headers: HeaderMap, body: Bytes) -> Response {
    let media = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase());
    let bytes: Result<Vec<u8>, &str> = match media.as_deref() {
        Some("application/octet-stream") => Ok(body.to_vec()),
        Some("application/json") => match Json::<AnnounceJson>::from_bytes(&body) {
            Ok(Json(body)) => decode_hex(&body.payload).ok_or("payload が16進ではありません"),
            Err(rejection) => return rejection.into_response(),
        },
        _ => {
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UnsupportedMediaType",
                "Content-Type は application/json か application/octet-stream にしてください"
                    .to_owned(),
            );
        }
    };
    if bytes
        .as_ref()
        .is_ok_and(|bytes| bytes.len() > MAX_BLOCK_BYTES)
    {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PayloadTooLarge",
            format!("ブロックは {MAX_BLOCK_BYTES} バイトまでです"),
        );
    }
    let result = bytes
        .map_err(str::to_owned)
        .and_then(|bytes| (api.node.submit_block)(bytes));
    match result {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(AnnounceResultJson::pushed_via(3, "/blocks")),
        )
            .into_response(),
        Err(message) => invalid(message),
    }
}

/// このノードのソース（[`offer_source`]）
async fn source_code() -> Response {
    match SOURCE.get().filter(|zip| !zip.is_empty()) {
        Some(zip) => (
            [
                (CONTENT_TYPE, "application/zip"),
                (
                    CONTENT_DISPOSITION,
                    concat!(
                        "attachment; filename=\"heika-",
                        env!("CARGO_PKG_VERSION"),
                        ".zip\""
                    ),
                ),
            ],
            *zip,
        )
            .into_response(),
        None => error(
            StatusCode::NOT_FOUND,
            "ResourceNotFound",
            "このノードのバイナリには、ソースが入っていません".to_owned(),
        ),
    }
}

/// catapult の REST と同じ形のエラー
fn error(status: StatusCode, code: &str, message: String) -> Response {
    let code = code.to_owned();
    (status, Json(ErrorJson { code, message })).into_response()
}

fn invalid(message: String) -> Response {
    error(StatusCode::CONFLICT, "InvalidArgument", message)
}

/// 状態を読む口の `?height=`（heika だけ）。そのブロックを実行したあとの状態を引く。なければ今の状態
#[derive(Debug, Default, serde::Deserialize)]
struct AtQuery {
    height: Option<String>,
}

impl AtQuery {
    /// 引く高さ
    fn at(&self) -> Result<Option<u64>, InvalidHeight> {
        self.height
            .as_deref()
            .map(|height| block_height(height).ok_or(InvalidHeight))
            .transpose()
    }
}

/// マルチシグの木の、たどる段の上限。catapult はマルチシグの深さを 3 までに抑えるので、ふつうは届かない
const MAX_MULTISIG_LEVELS: i32 = 16;

/// `address` から、上（入っているマルチシグ）と下（連署者）にたどったマルチシグの木。catapult の REST の
/// `getMultisigGraph` と同じく、段ごとに前の段の全員のアドレスを集めて引き、なくなったらやめる。上の段から順に
/// 並べる。`read` はアドレスのうち、あるものだけを返す。`address` になければ `None`
pub fn multisig_graph<E>(
    address: &Address,
    mut read: impl FnMut(&[Address]) -> Result<Vec<MultisigJson>, E>,
) -> Result<Option<Vec<MultisigGraphLevel>>, E> {
    let Some(start) = read(std::slice::from_ref(address))?.into_iter().next() else {
        return Ok(None);
    };
    // 段にあるアカウントの、上か下のアドレスを、重ねずに集める
    let next = |entries: &[MultisigJson], up: bool| {
        let mut addresses: Vec<Address> = Vec::new();
        for entry in entries {
            let side = if up {
                &entry.multisig_addresses
            } else {
                &entry.cosignatory_addresses
            };
            for address in side.iter().filter_map(|hex| Address::from_hex(hex).ok()) {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        addresses
    };
    let mut levels = vec![(0, vec![start])];
    for up in [true, false] {
        let step = if up { -1 } else { 1 };
        let mut level: i32 = 0;
        let mut entries = levels[if up { 0 } else { levels.len() - 1 }].1.clone();
        while level.abs() < MAX_MULTISIG_LEVELS {
            let addresses = next(&entries, up);
            if addresses.is_empty() {
                break;
            }
            entries = read(&addresses)?;
            if entries.is_empty() {
                break;
            }
            level += step;
            if up {
                levels.insert(0, (level, entries.clone()));
            } else {
                levels.push((level, entries.clone()));
            }
        }
    }
    Ok(Some(
        levels
            .into_iter()
            .map(|(level, entries)| MultisigGraphLevel {
                level,
                multisig_entries: entries
                    .into_iter()
                    .map(|multisig| MultisigInfo { multisig })
                    .collect(),
            })
            .collect(),
    ))
}

/// `?height=` が読めない形（409）
struct InvalidHeight;

impl IntoResponse for InvalidHeight {
    fn into_response(self) -> Response {
        invalid("height has an invalid format".to_owned())
    }
}

/// 状態を読んだものを返す。なければ 404、まだ届いていない高さなら 409、履歴を持っていない高さなら 410、
/// 読めなければ 500。`?height=` で引いたら、答えに `X-Heika-Height` でその高さを添える。catapult はこのクエリを
/// 知らずに今の状態を返すので、受け取った側はこのヘッダーで、その高さの答えかを見分けられる
fn found_at<T: serde::Serialize>(
    id: &str,
    at: Option<u64>,
    read: Result<Option<T>, StateError>,
) -> Response {
    let mut response = match read {
        Ok(read) => found(id, Ok(read)),
        Err(StateError::Ahead { height, tip }) => {
            invalid(format!("height {height} is above the chain height {tip}"))
        }
        Err(StateError::NoHistory { height }) => error(
            StatusCode::GONE,
            "Gone",
            format!("this node keeps no state history at height {height}"),
        ),
        Err(StateError::Invalid(message)) => invalid(message),
        Err(StateError::Other(message)) => found::<T>(id, Err(message)),
    };
    if let Some(height) = at {
        response
            .headers_mut()
            .insert(HEIGHT_HEADER, HeaderValue::from(height));
    }
    response
}

/// 読んだものを返す。なければ 404、読めなければ 500
fn found<T: serde::Serialize>(id: &str, read: Result<Option<T>, String>) -> Response {
    match read {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => error(
            StatusCode::NOT_FOUND,
            "ResourceNotFound",
            format!("no resource exists with id '{id}'"),
        ),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal", message),
    }
}

/// アカウントの ID。catapult の REST と同じく、アドレス（Base32 か16進）か公開鍵（16進）
fn account_address(id: &str, network: NetworkIdentifier) -> Option<Address> {
    if id.len() == 64 {
        let key: PublicKey = id.parse().ok()?;
        return Some(Address::from_public_key(&key, network));
    }
    let address = id.parse().or_else(|_| Address::from_hex(id)).ok()?;
    (address.network() == network).then_some(address)
}

/// モザイクやネームスペースの ID。上位から16進
fn hex_id(id: &str) -> Option<u64> {
    (id.len() == 16)
        .then(|| u64::from_str_radix(id, 16).ok())
        .flatten()
}

async fn account(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(address) = account_address(&id, api.node.reader.network()) else {
        return invalid("accountId has an invalid format".to_owned());
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = api.node.reader.accounts(&[address], at);
    found_at(
        &id,
        at,
        read.map(|accounts| {
            accounts
                .into_iter()
                .next()
                .map(|account| AccountInfo { account })
        }),
    )
}

/// `POST /accounts` と `POST /mosaics` の本文。catapult の REST と同じく、配列の代わりに1つの文字列でもよい
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StatesBody {
    addresses: Option<OneOrMany>,
    public_keys: Option<OneOrMany>,
    mosaic_ids: Option<OneOrMany>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }
    }
}

/// 同じものは、最初の1つだけを残す（catapult の REST は、DB に `$in` で頼むので、同じものは1回だけ返る）
fn dedup<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::with_capacity(values.len());
    for value in values {
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out
}

/// アカウントを、アドレスか公開鍵を並べてまとめて引く。あるものだけを頼んだ順に返す
async fn accounts(
    State(api): State<Api>,
    Query(query): Query<AtQuery>,
    Json(body): Json<StatesBody>,
) -> Response {
    let network = api.node.reader.network();
    let ids = match (body.addresses, body.public_keys) {
        (Some(_), Some(_)) => {
            return invalid("publicKeys and addresses cannot both be provided".to_owned());
        }
        (None, Some(keys)) => {
            body_ids(Some(&keys.into_vec()), "publicKeys", MAX_STATE_IDS, |key| {
                (key.len() == 64)
                    .then(|| account_address(key, network))
                    .flatten()
            })
        }
        (addresses, None) => body_ids(
            addresses.map(OneOrMany::into_vec).as_deref(),
            "addresses",
            MAX_STATE_IDS,
            |id| address_only(id, network),
        ),
    };
    let addresses = match ids {
        Ok(addresses) => dedup(addresses),
        Err(message) => return invalid(message),
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = api.node.reader.accounts(&addresses, at).map(|accounts| {
        accounts
            .into_iter()
            .map(|account| AccountInfo { account })
            .collect::<Vec<_>>()
    });
    found_at("", at, read.map(Some))
}

async fn account_merkle(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(address) = account_address(&id, api.node.reader.network()) else {
        return invalid("accountId has an invalid format".to_owned());
    };
    state_path(
        &api,
        &id,
        &query,
        SubCache::AccountState,
        patricia::address_key(&address),
    )
}

async fn mosaic(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(mosaic_id) = hex_id(&id) else {
        return invalid("mosaicId has an invalid format".to_owned());
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = api.node.reader.mosaics(&[mosaic_id], at);
    found_at(
        &id,
        at,
        read.map(|mosaics| {
            mosaics
                .into_iter()
                .next()
                .map(|mosaic| MosaicInfo { mosaic })
        }),
    )
}

/// モザイクの定義を、ID を並べてまとめて引く。あるものだけを頼んだ順に返す
async fn mosaics(
    State(api): State<Api>,
    Query(query): Query<AtQuery>,
    Json(body): Json<StatesBody>,
) -> Response {
    let ids = match body_ids(
        body.mosaic_ids.map(OneOrMany::into_vec).as_deref(),
        "mosaicIds",
        MAX_STATE_IDS,
        hex_id,
    ) {
        Ok(ids) => dedup(ids),
        Err(message) => return invalid(message),
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = api.node.reader.mosaics(&ids, at).map(|mosaics| {
        mosaics
            .into_iter()
            .map(|mosaic| MosaicInfo { mosaic })
            .collect::<Vec<_>>()
    });
    found_at("", at, read.map(Some))
}

async fn multisig(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(address) = address_only(&id, api.node.reader.network()) else {
        return invalid("address has an invalid format".to_owned());
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = api.node.reader.multisigs(&[address], at);
    found_at(
        &id,
        at,
        read.map(|entries| {
            entries
                .into_iter()
                .next()
                .map(|multisig| MultisigInfo { multisig })
        }),
    )
}

async fn multisig_merkle(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(address) = address_only(&id, api.node.reader.network()) else {
        return invalid("address has an invalid format".to_owned());
    };
    state_path(
        &api,
        &id,
        &query,
        SubCache::Multisig,
        patricia::address_key(&address),
    )
}

async fn multisig_graph_route(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(address) = address_only(&id, api.node.reader.network()) else {
        return invalid("address has an invalid format".to_owned());
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    found_at(&id, at, api.node.reader.multisig_graph(&address, at))
}

/// ロックと制限の口。どの木の、どんな ID か
#[derive(Clone, Copy)]
enum Kept {
    HashLock,
    SecretLock,
    AccountRestriction,
    MosaicRestriction,
}

impl Kept {
    fn cache(self) -> SubCache {
        match self {
            Kept::HashLock => SubCache::HashLockInfo,
            Kept::SecretLock => SubCache::SecretLockInfo,
            Kept::AccountRestriction => SubCache::AccountRestriction,
            Kept::MosaicRestriction => SubCache::MosaicRestriction,
        }
    }

    /// 1件の口の ID の名前と、まとめて引く本文の項目の名前（catapult の REST と同じ）
    fn names(self) -> (&'static str, &'static str) {
        match self {
            Kept::HashLock => ("hash", "hashes"),
            Kept::SecretLock | Kept::MosaicRestriction => ("compositeHash", "compositeHashes"),
            Kept::AccountRestriction => ("address", "addresses"),
        }
    }

    /// ID を木のキーのもとにする。読めなければ `None`
    fn key(self, id: &str, network: NetworkIdentifier) -> Option<Vec<u8>> {
        match self {
            Kept::AccountRestriction => address_only(id, network).map(|address| address.0.to_vec()),
            _ => hash256(id).map(|hash| hash.0.to_vec()),
        }
    }

    /// 木のキーのもとを、木のキーにする
    fn tree_key(self, key: &[u8]) -> Hash256 {
        match self {
            Kept::AccountRestriction => {
                patricia::address_key(&Address(key.try_into().expect("24 バイト")))
            }
            _ => patricia::hash_key(&Hash256(key.try_into().expect("32 バイト"))),
        }
    }

    /// 状態のバイト列を、catapult の REST と同じ JSON にする
    fn json(self, key: &[u8], bytes: &[u8]) -> Result<KeptJson, String> {
        let hash = || Hash256(key.try_into().unwrap_or([0; 32]));
        match self {
            Kept::HashLock => HashLockJson::from_state_bytes(bytes)
                .map(|lock| KeptJson::HashLock(HashLockInfo { lock })),
            Kept::SecretLock => SecretLockJson::from_state_bytes(bytes, &hash())
                .map(|lock| KeptJson::SecretLock(SecretLockInfo { lock })),
            Kept::AccountRestriction => {
                AccountRestrictionsJson::from_state_bytes(bytes).map(|account_restrictions| {
                    KeptJson::AccountRestriction(AccountRestrictionsInfo {
                        account_restrictions,
                    })
                })
            }
            Kept::MosaicRestriction => MosaicRestrictionEntryJson::from_state_bytes(bytes, &hash())
                .map(|mosaic_restriction_entry| {
                    KeptJson::MosaicRestriction(MosaicRestrictionInfo {
                        mosaic_restriction_entry,
                    })
                }),
        }
        .map_err(|error| error.to_string())
    }

    /// `keys` の状態を読んで、JSON にする
    fn read(
        self,
        api: &Api,
        keys: &[Vec<u8>],
        at: Option<u64>,
    ) -> Result<Vec<KeptJson>, StateError> {
        api.node
            .reader
            .lock_or_restriction_states(self.cache(), keys, at)?
            .iter()
            .map(|(key, bytes)| self.json(key, bytes).map_err(StateError::Other))
            .collect()
    }
}

/// ロックと制限の JSON
#[derive(serde::Serialize)]
#[serde(untagged)]
enum KeptJson {
    HashLock(HashLockInfo),
    SecretLock(SecretLockInfo),
    AccountRestriction(AccountRestrictionsInfo),
    MosaicRestriction(MosaicRestrictionInfo),
}

/// ロックと制限をまとめて引く本文。catapult の REST と同じく、配列の代わりに1つの文字列でもよい
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeptBody {
    hashes: Option<OneOrMany>,
    composite_hashes: Option<OneOrMany>,
    addresses: Option<OneOrMany>,
}

async fn kept_one(kept: Kept, api: Api, id: String, query: AtQuery) -> Response {
    let Some(key) = kept.key(&id, api.node.reader.network()) else {
        return invalid(format!("{} has an invalid format", kept.names().0));
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = kept.read(&api, &[key], at);
    found_at(&id, at, read.map(|values| values.into_iter().next()))
}

async fn kept_many(kept: Kept, api: Api, query: AtQuery, body: KeptBody) -> Response {
    let name = kept.names().1;
    let values = match kept {
        Kept::HashLock => body.hashes,
        Kept::SecretLock | Kept::MosaicRestriction => body.composite_hashes,
        Kept::AccountRestriction => body.addresses,
    }
    .map(OneOrMany::into_vec);
    let network = api.node.reader.network();
    let keys = match body_ids(values.as_deref(), name, MAX_STATE_IDS, |id| {
        kept.key(id, network)
    }) {
        Ok(keys) => dedup(keys),
        Err(message) => return invalid(message),
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    found_at("", at, kept.read(&api, &keys, at).map(Some))
}

async fn kept_merkle(kept: Kept, api: Api, id: String, query: AtQuery) -> Response {
    let Some(key) = kept.key(&id, api.node.reader.network()) else {
        return invalid(format!("{} has an invalid format", kept.names().0));
    };
    state_path(&api, &id, &query, kept.cache(), kept.tree_key(&key))
}

/// ロックと制限の、まとめて引く口と、1件の口と、木の道の口
fn kept_routes(router: Router<Api>, base: &str, kept: Kept) -> Router<Api> {
    let id = kept.names().0;
    router
        .route(
            base,
            post(
                move |State(api): State<Api>,
                      Query(query): Query<AtQuery>,
                      Json(body): Json<KeptBody>| {
                    kept_many(kept, api, query, body)
                },
            )
            .options(preflight),
        )
        .route(
            &format!("{base}/{{{id}}}"),
            get(
                move |State(api): State<Api>,
                      Path(id): Path<String>,
                      Query(query): Query<AtQuery>| kept_one(kept, api, id, query),
            ),
        )
        .route(
            &format!("{base}/{{{id}}}/merkle"),
            get(
                move |State(api): State<Api>,
                      Path(id): Path<String>,
                      Query(query): Query<AtQuery>| {
                    kept_merkle(kept, api, id, query)
                },
            ),
        )
}

async fn mosaic_merkle(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(mosaic_id) = hex_id(&id) else {
        return invalid("mosaicId has an invalid format".to_owned());
    };
    state_path(
        &api,
        &id,
        &query,
        SubCache::Mosaic,
        patricia::id_key(mosaic_id),
    )
}

async fn namespace(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(namespace_id) = hex_id(&id) else {
        return invalid("namespaceId has an invalid format".to_owned());
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    found_at(&id, at, api.node.reader.namespace(namespace_id, at))
}

/// catapult と同じく、ID をそのまま木のキーにする。子の ID は木にないので、ないことを示す道になる
async fn namespace_merkle(
    State(api): State<Api>,
    Path(id): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(namespace_id) = hex_id(&id) else {
        return invalid("namespaceId has an invalid format".to_owned());
    };
    state_path(
        &api,
        &id,
        &query,
        SubCache::Namespace,
        patricia::id_key(namespace_id),
    )
}

async fn metadata(
    State(api): State<Api>,
    Path(hash): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(composite_hash) = hash256(&hash) else {
        return invalid("compositeHash has an invalid format".to_owned());
    };
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    let read = api.node.reader.metadata(&composite_hash, at);
    found_at(
        &hash,
        at,
        read.map(|entry| {
            entry.map(|metadata_entry| MetadataInfo {
                id: Some(metadata_entry.position()),
                metadata_entry,
            })
        }),
    )
}

async fn metadata_merkle(
    State(api): State<Api>,
    Path(hash): Path<String>,
    Query(query): Query<AtQuery>,
) -> Response {
    let Some(composite_hash) = hash256(&hash) else {
        return invalid("compositeHash has an invalid format".to_owned());
    };
    state_path(
        &api,
        &hash,
        &query,
        SubCache::Metadata,
        patricia::hash_key(&composite_hash),
    )
}

/// 状態の木 `cache` の、根から `key` の葉への道を返す
fn state_path(api: &Api, id: &str, query: &AtQuery, cache: SubCache, key: Hash256) -> Response {
    let at = match query.at() {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    found_at(
        id,
        at,
        api.node.reader.state_path(cache, &key, at).map(Some),
    )
}

fn block_height(height: &str) -> Option<u64> {
    height.parse::<u64>().ok().filter(|&height| height > 0)
}

async fn block(State(api): State<Api>, Path(height): Path<String>) -> Response {
    let Some(number) = block_height(&height) else {
        return invalid("height has an invalid format".to_owned());
    };
    found(&height, api.node.reader.block(number))
}

/// トランザクションのハッシュや、メタデータの1件を指すハッシュ。16進
fn hash256(hash: &str) -> Option<Hash256> {
    if hash.len() != 64 {
        return None;
    }
    let mut bytes = [0; 32];
    base16ct::mixed::decode(hash, &mut bytes).ok()?;
    Some(Hash256(bytes))
}

async fn partial_transaction(State(api): State<Api>, Path(hash): Path<String>) -> Response {
    let Some(key) = hash256(&hash) else {
        return invalid("transactionId has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.partial_transaction(&key))
}

/// 連署を待つものの一覧。ページの大きさは catapult と同じく 10 から 100（既定 10）、ページは 1 から
/// アドレス（Base32 か16進）。公開鍵は受け付けない（catapult の REST の検索と同じ）
fn address_only(id: &str, network: NetworkIdentifier) -> Option<Address> {
    (id.len() != 64)
        .then(|| account_address(id, network))
        .flatten()
}

async fn search_metadata(State(api): State<Api>, Query(query): Query<MetadataQuery>) -> Response {
    let network = api.node.reader.network();
    // 読めなければ、どの項目かを返す
    let address = |value: &Option<String>, name: &'static str| match value.as_deref() {
        None => Ok(None),
        Some(id) => address_only(id, network).map(Some).ok_or(name),
    };
    let id = |value: &Option<String>, name: &'static str| match value.as_deref() {
        None => Ok(None),
        Some(id) => hex_id(id).map(Some).ok_or(name),
    };
    let filter = (|| {
        Ok::<_, &str>(MetadataFilter {
            source: address(&query.source_address, "sourceAddress")?,
            target: address(&query.target_address, "targetAddress")?,
            scoped_key: id(&query.scoped_metadata_key, "scopedMetadataKey")?,
            target_id: id(&query.target_id, "targetId")?,
            metadata_type: query.metadata_type,
        })
    })();
    let filter = match filter {
        Ok(filter) => filter,
        Err(name) => return invalid(format!("{name} has an invalid format")),
    };
    let at = match (AtQuery {
        height: query.height.clone(),
    })
    .at()
    {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    // 前のページの最後の件の `id` から続ける。飛ばす分をなめないので、深いページでも速い
    let after = match query.offset.as_deref().map(MetadataPosition::parse) {
        None => None,
        Some(Some(position)) => Some(position),
        Some(None) => return invalid("offset has an invalid format".to_owned()),
    };
    let page = match page_request(query.order.as_deref(), query.page_size, query.page_number) {
        Ok(page) => page,
        Err(message) => return invalid(message),
    };
    let read = api
        .node
        .reader
        .search_metadata(&filter, page, after.as_ref(), at);
    if let Ok(None) = read {
        return search_not_kept("metadata", at);
    }
    // 見つからなくても空のページを返すので、404 にはならない
    found_at(
        "metadata",
        at,
        read.map(|entries| {
            entries.map(|entries| Page {
                data: entries
                    .into_iter()
                    .map(|metadata_entry| MetadataInfo {
                        id: Some(metadata_entry.position()),
                        metadata_entry,
                    })
                    .collect(),
                pagination: Pagination {
                    page_number: page.number,
                    page_size: page.size,
                },
            })
        }),
    )
}

/// 承認されたトランザクションの検索。catapult の REST と同じく、`address`（関わったアドレス）、`signerPublicKey`、
/// `recipientAddress`、`type`、送金のモザイクと額、高さで絞る。アグリゲートの中のもの（`embedded=true`）は、まだ 501
async fn search_confirmed(
    State(api): State<Api>,
    Query(query): Query<TransactionQuery>,
    RawQuery(raw): RawQuery,
) -> Response {
    if query.address.is_some()
        && (query.signer_public_key.is_some() || query.recipient_address.is_some())
    {
        return invalid(
            "can't filter by address if signerPublicKey or recipientAddress are already provided"
                .to_owned(),
        );
    }
    if (query.from_transfer_amount.is_some() || query.to_transfer_amount.is_some())
        && query.transfer_mosaic_id.is_none()
    {
        return invalid(
            "can't filter by transfer amount if transferMosaicId is not provided".to_owned(),
        );
    }
    if query.embedded.as_deref() == Some("true") {
        return not_supported("the embedded filter");
    }
    let network = api.node.reader.network();
    let filter = (|| {
        let number = |value: &Option<String>, name: &str| match value.as_deref() {
            None => Ok(None),
            Some(text) => text
                .parse::<u64>()
                .map(Some)
                .map_err(|_| format!("{name} has an invalid format")),
        };
        let address = |value: &Option<String>, name: &str| match value.as_deref() {
            None => Ok(None),
            Some(id) => address_only(id, network)
                .map(Some)
                .ok_or_else(|| format!("{name} has an invalid format")),
        };
        let exact = number(&query.height, "height")?;
        Ok::<_, String>(TransactionFilter {
            address: address(&query.address, "address")?,
            signer: match query.signer_public_key.as_deref() {
                None => None,
                Some(key) => Some(
                    key.parse::<PublicKey>()
                        .ok()
                        .filter(|_| key.len() == 64)
                        .ok_or("signerPublicKey has an invalid format")?,
                ),
            },
            recipient: address(&query.recipient_address, "recipientAddress")?.map(|a| a.0),
            types: transaction_types(raw.as_deref()).ok_or("type has an invalid format")?,
            mosaic: match query.transfer_mosaic_id.as_deref() {
                None => None,
                Some(id) => Some(hex_id(id).ok_or("transferMosaicId has an invalid format")?),
            },
            from_amount: number(&query.from_transfer_amount, "fromTransferAmount")?,
            to_amount: number(&query.to_transfer_amount, "toTransferAmount")?,
            from_height: exact
                .or(number(&query.from_height, "fromHeight")?)
                .unwrap_or(0),
            to_height: exact
                .or(number(&query.to_height, "toHeight")?)
                .unwrap_or(u64::MAX),
        })
    })();
    let filter = match filter {
        Ok(filter) => filter,
        Err(message) => return invalid(message),
    };
    // 前のページの最後の件の `id` から続ける。飛ばす分をなめないので、深いページでも速い
    let after = match query.offset.as_deref().map(parse_transaction_position) {
        None => None,
        Some(Some(position)) => Some(position),
        Some(None) => return invalid("offset has an invalid format".to_owned()),
    };
    let page = match page_request(query.order.as_deref(), query.page_size, query.page_number) {
        Ok(page) => page,
        Err(message) => return invalid(message),
    };
    match api.node.reader.search_transactions(&filter, page, after) {
        Ok(None) => search_not_kept("transaction", None),
        Ok(Some(data)) => Json(Page {
            data,
            pagination: Pagination {
                page_number: page.number,
                page_size: page.size,
            },
        })
        .into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal", message),
    }
}

/// heika がまだ扱わない口や絞り込み（501）
fn not_supported(what: &str) -> Response {
    error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        format!("{what} is not supported by this node yet"),
    )
}

/// 一覧の並びとページ。読めなければ、409 で返すわけ
fn page_request(
    order: Option<&str>,
    size: Option<usize>,
    number: Option<usize>,
) -> Result<PageRequest, String> {
    let descending = match order {
        None | Some("asc") => false,
        Some("desc") => true,
        Some(_) => return Err("order has an invalid format".to_owned()),
    };
    Ok(PageRequest {
        size: size.unwrap_or(10).clamp(10, 100),
        number: number.unwrap_or(1).max(1),
        descending,
    })
}

/// 検索表を作っていないときの 501
fn search_not_kept(what: &str, at: Option<u64>) -> Response {
    let scope = if at.is_some() {
        "at past heights (storage.search on an archive node)"
    } else {
        "(storage.search)"
    };
    error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        format!("this node does not keep the {what} search {scope}"),
    )
}

async fn search_namespaces(
    State(api): State<Api>,
    Query(query): Query<NamespaceQuery>,
) -> Response {
    let network = api.node.reader.network();
    let owner = match query.owner_address.as_deref() {
        None => None,
        Some(id) => match address_only(id, network) {
            Some(address) => Some(address),
            None => return invalid("ownerAddress has an invalid format".to_owned()),
        },
    };
    let level0 = match query.level0.as_deref() {
        None => None,
        Some(id) => match hex_id(id) {
            Some(id) => Some(id),
            None => return invalid("level0 has an invalid format".to_owned()),
        },
    };
    let at = match (AtQuery {
        height: query.height.clone(),
    })
    .at()
    {
        Ok(at) => at,
        Err(invalid) => return invalid.into_response(),
    };
    // 前のページの最後の件の `id` から続ける
    let after = match query.offset.as_deref().map(decode_hex) {
        None => None,
        Some(Some(after)) if !after.is_empty() => Some(after),
        Some(_) => return invalid("offset has an invalid format".to_owned()),
    };
    let page = match page_request(query.order.as_deref(), query.page_size, query.page_number) {
        Ok(page) => page,
        Err(message) => return invalid(message),
    };
    let filter = NamespaceFilter {
        owner,
        level0,
        registration_type: query.registration_type,
        alias_type: query.alias_type,
    };
    let read = api
        .node
        .reader
        .search_namespaces(&filter, page, after.as_deref(), at);
    if let Ok(None) = read {
        return search_not_kept("namespace", at);
    }
    found_at(
        "namespaces",
        at,
        read.map(|entries| {
            entries.map(|entries| Page {
                data: entries
                    .into_iter()
                    .map(|(id, info)| NamespaceInfo {
                        id: Some(id),
                        ..info
                    })
                    .collect(),
                pagination: Pagination {
                    page_number: page.number,
                    page_size: page.size,
                },
            })
        }),
    )
}

/// `POST /namespaces/names` などの本文。catapult の REST と同じ名前
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NamesBody {
    namespace_ids: Option<Vec<String>>,
    addresses: Option<Vec<String>>,
    mosaic_ids: Option<Vec<String>>,
}

/// 本文の ID の並び。なければ、多すぎれば、読めなければ、409 で返すわけ
fn name_ids<T>(
    values: Option<&[String]>,
    name: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, String> {
    body_ids(values, name, MAX_NAME_IDS, parse)
}

/// 本文の ID の並びを、`max` 個まで読む。なければ、多すぎれば、読めなければ、409 で返すわけ
fn body_ids<T>(
    values: Option<&[String]>,
    name: &str,
    max: usize,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>, String> {
    let values = values.ok_or_else(|| format!("{name} is missing"))?;
    if values.len() > max {
        return Err(format!("{name} has more than {max} items"));
    }
    values
        .iter()
        .map(|value| parse(value).ok_or_else(|| format!("{name} has an invalid format")))
        .collect()
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountNamesPage {
    account_names: Vec<AccountNamesJson>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MosaicNamesPage {
    mosaic_names: Vec<MosaicNamesJson>,
}

fn names_response<T: serde::Serialize>(read: Result<Option<T>, String>) -> Response {
    match read {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => search_not_kept("namespace name", None),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal", message),
    }
}

async fn namespace_names(State(api): State<Api>, Json(body): Json<NamesBody>) -> Response {
    match name_ids(body.namespace_ids.as_deref(), "namespaceIds", hex_id) {
        Ok(ids) => names_response(api.node.reader.namespace_names(&ids)),
        Err(message) => invalid(message),
    }
}

async fn account_names(State(api): State<Api>, Json(body): Json<NamesBody>) -> Response {
    let network = api.node.reader.network();
    let addresses = match name_ids(body.addresses.as_deref(), "addresses", |id| {
        address_only(id, network)
    }) {
        Ok(addresses) => addresses,
        Err(message) => return invalid(message),
    };
    let mut out = Vec::with_capacity(addresses.len());
    for address in addresses {
        match api.node.reader.alias_names(AliasTarget::Address(address)) {
            Ok(Some(names)) => out.push(AccountNamesJson {
                address: address.to_hex(),
                names,
            }),
            other => return names_response(other.map(|_| None::<()>)),
        }
    }
    Json(AccountNamesPage { account_names: out }).into_response()
}

async fn mosaic_names(State(api): State<Api>, Json(body): Json<NamesBody>) -> Response {
    let ids = match name_ids(body.mosaic_ids.as_deref(), "mosaicIds", hex_id) {
        Ok(ids) => ids,
        Err(message) => return invalid(message),
    };
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        match api.node.reader.alias_names(AliasTarget::Mosaic(id)) {
            Ok(Some(names)) => out.push(MosaicNamesJson {
                mosaic_id: format!("{id:016X}"),
                names,
            }),
            other => return names_response(other.map(|_| None::<()>)),
        }
    }
    Json(MosaicNamesPage { mosaic_names: out }).into_response()
}

async fn partial_transactions(
    State(api): State<Api>,
    Query(query): Query<PartialQuery>,
) -> Response {
    let network = api.node.reader.network();
    let address = match query
        .address
        .as_deref()
        .map(|id| account_address(id, network))
    {
        None => None,
        Some(Some(address)) => Some(address),
        Some(None) => return invalid("address has an invalid format".to_owned()),
    };
    let signer = match query
        .signer_public_key
        .as_deref()
        .map(str::parse::<PublicKey>)
    {
        None => None,
        Some(Ok(key)) => Some(key),
        Some(Err(_)) => return invalid("signerPublicKey has an invalid format".to_owned()),
    };
    let page_size = query.page_size.unwrap_or(10).clamp(10, 100);
    let page_number = query.page_number.unwrap_or(1).max(1);
    match api
        .node
        .reader
        .partial_transactions(&PartialFilter { address, signer })
    {
        Ok(all) => Json(Page {
            data: all
                .into_iter()
                .skip((page_number - 1) * page_size)
                .take(page_size)
                .collect(),
            pagination: Pagination {
                page_number,
                page_size,
            },
        })
        .into_response(),
        Err(message) => error(StatusCode::INTERNAL_SERVER_ERROR, "Internal", message),
    }
}

async fn transaction_fees(State(api): State<Api>) -> Response {
    found("transaction", api.node.reader.transaction_fees().map(Some))
}

async fn transaction_status(State(api): State<Api>, Path(hash): Path<String>) -> Response {
    let Some(key) = hash256(&hash) else {
        return invalid("hash has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.transaction_status(&key))
}

async fn confirmed_transaction(State(api): State<Api>, Path(hash): Path<String>) -> Response {
    let Some(key) = hash256(&hash) else {
        return invalid("transactionId has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.confirmed_transaction(&key))
}

async fn transaction_merkle(
    State(api): State<Api>,
    Path((height, hash)): Path<(String, String)>,
) -> Response {
    let (Some(number), Some(key)) = (block_height(&height), hash256(&hash)) else {
        return invalid("height or hash has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.transaction_merkle(number, &key))
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    // base16ct は読めた分だけ返すので、長さは先に確かめる
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = vec![0; text.len() / 2];
    base16ct::mixed::decode(text, &mut bytes).ok()?;
    Some(bytes)
}

/// ブラウザーが PUT の前に聞いてくる問い合わせ。答えの頭は [`allow_any_origin`] が付ける
async fn preflight() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn allow_any_origin(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, PUT, POST, OPTIONS"),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    response
}

/// 口の並び
pub fn router(shared: Shared, node: Node) -> Router {
    let router = [
        ("/lock/hash", Kept::HashLock),
        ("/lock/secret", Kept::SecretLock),
        ("/restrictions/account", Kept::AccountRestriction),
        ("/restrictions/mosaic", Kept::MosaicRestriction),
    ]
    .into_iter()
    .fold(Router::new(), |router, (base, kept)| {
        kept_routes(router, base, kept)
    });
    router
        .route("/node/info", get(node_info))
        .route("/node/peers", get(node_peers))
        .route("/chain/info", get(chain_info))
        .route("/network", get(network))
        .route("/network/properties", get(network_properties))
        .route("/node/server", get(node_server))
        .route("/node/health", get(node_health))
        .route("/node/unlockedaccount", get(unlocked))
        .route("/heika/delegations", get(delegations))
        .route("/heika/sourcecode.zip", get(source_code))
        .route("/transactions", put(announce).options(preflight))
        .route(
            "/blocks",
            put(announce_block)
                .options(preflight)
                // 16進の JSON は倍になる。JSON の囲みの分だけ少し足す
                .layer(DefaultBodyLimit::max(2 * MAX_BLOCK_BYTES + 1024)),
        )
        .route(
            "/transactions/partial",
            put(announce_partial)
                .get(partial_transactions)
                .options(preflight),
        )
        .route("/transactions/partial/{hash}", get(partial_transaction))
        .route(
            "/transactions/cosignature",
            put(announce_cosignature).options(preflight),
        )
        .route("/accounts", post(accounts).options(preflight))
        .route("/accounts/{id}", get(account))
        .route("/accounts/{id}/merkle", get(account_merkle))
        .route("/account/{id}/multisig", get(multisig))
        .route("/account/{id}/multisig/merkle", get(multisig_merkle))
        .route("/account/{id}/multisig/graph", get(multisig_graph_route))
        .route("/mosaics", post(mosaics).options(preflight))
        .route("/mosaics/{id}", get(mosaic))
        .route("/mosaics/{id}/merkle", get(mosaic_merkle))
        .route("/namespaces", get(search_namespaces))
        .route(
            "/namespaces/names",
            post(namespace_names).options(preflight),
        )
        .route(
            "/namespaces/account/names",
            post(account_names).options(preflight),
        )
        .route(
            "/namespaces/mosaic/names",
            post(mosaic_names).options(preflight),
        )
        .route("/namespaces/{id}", get(namespace))
        .route("/namespaces/{id}/merkle", get(namespace_merkle))
        .route("/metadata", get(search_metadata))
        .route("/metadata/{hash}", get(metadata))
        .route("/metadata/{hash}/merkle", get(metadata_merkle))
        .route("/blocks/{height}", get(block))
        .route("/network/fees/transaction", get(transaction_fees))
        .route("/transactionStatus/{hash}", get(transaction_status))
        .route("/transactions/confirmed", get(search_confirmed))
        .route("/transactions/confirmed/{hash}", get(confirmed_transaction))
        .route(
            "/blocks/{height}/transactions/{hash}/merkle",
            get(transaction_merkle),
        )
        .layer(map_response(allow_any_origin))
        .with_state(Api { shared, node })
}

/// 待ち受ける口
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    /// 待ち受けるアドレス（`127.0.0.1:3000` など）
    pub address: String,
    /// この口で、1 秒あたりに答える要求の数。どの道への要求も数え、超えたら 429。0 なら絞らない
    pub rate_limit: u32,
}

/// 1 秒あたり `rate` 回までに絞る。ためておけるのは 1 秒分まで（トークンバケツ）
struct Throttle {
    rate: f64,
    bucket: Mutex<(f64, Instant)>,
}

impl Throttle {
    fn new(rate: u32, now: Instant) -> Self {
        let rate = f64::from(rate);
        Self {
            rate,
            bucket: Mutex::new((rate, now)),
        }
    }

    /// `now` に 1 回分を使えれば使う
    fn take(&self, now: Instant) -> bool {
        let mut bucket = self
            .bucket
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (tokens, last) = *bucket;
        let tokens =
            (tokens + now.saturating_duration_since(last).as_secs_f64() * self.rate).min(self.rate);
        let (tokens, taken) = if tokens >= 1.0 {
            (tokens - 1.0, true)
        } else {
            (tokens, false)
        };
        *bucket = (tokens, now);
        taken
    }
}

/// `app` への要求を、1 秒あたり `rate` 回までに絞る。0 なら絞らない。超えたら catapult の REST と同じく 429
pub fn limit(app: Router, rate: u32) -> Router {
    if rate == 0 {
        return app;
    }
    let throttle = Arc::new(Throttle::new(rate, Instant::now()));
    app.layer(from_fn(move |request: Request, next: Next| {
        let throttle = Arc::clone(&throttle);
        async move {
            if throttle.take(Instant::now()) {
                return next.run(request).await;
            }
            allow_any_origin(error(
                StatusCode::TOO_MANY_REQUESTS,
                "TooManyRequests",
                format!("1 秒に {rate} 回までです"),
            ))
            .await
        }
    }))
}

/// `listeners` のそれぞれで待ち受け、`stop` が立つまで答える。呼んだスレッドで tokio を回す
pub fn serve(
    listeners: &[Listener],
    shared: Shared,
    node: Node,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("API の tokio を動かせません: {error}"))?;
    runtime.block_on(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for Listener {
            address,
            rate_limit,
        } in listeners
        {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|error| format!("API を {address} で待ち受けられません: {error}"))?;
            println!("API を {address} で待ち受けます");
            let app = limit(router(Arc::clone(&shared), node.clone()), *rate_limit);
            let stop = Arc::clone(&stop);
            tasks.spawn(async move {
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        while !stop.load(Ordering::SeqCst) {
                            tokio::time::sleep(STOP_POLL).await;
                        }
                    })
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(format!("API が止まりました: {error}")),
                Err(error) => return Err(format!("API が止まりました: {error}")),
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use heika_rest::node::DelegationStateJson;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn snapshot() -> Shared {
        Arc::new(RwLock::new(Snapshot {
            node: NodeInfoJson {
                version: 0x0100_0309,
                public_key: "AA".to_owned(),
                network_generation_hash_seed: "BB".to_owned(),
                roles: 3,
                port: 7900,
                network_identifier: 0x98,
                host: String::new(),
                friendly_name: "heika".to_owned(),
                node_public_key: Some("CC".to_owned()),
            },
            peers: Vec::new(),
            chain: ChainInfoJson::new(10, 10, 1, 2, 8, "DD".to_owned()),
            unlocked: UnlockedAccountJson {
                unlocked_account: vec!["EE".to_owned()],
            },
            delegations: vec![DelegationJson {
                main_public_key: Some("FF".to_owned()),
                remote_public_key: "EE".to_owned(),
                height: Some("7".to_owned()),
                state: DelegationStateJson::Accepted,
                reason: None,
            }],
        }))
    }

    async fn get(shared: Shared, path: &str) -> (Option<HeaderValue>, serde_json::Value) {
        let response = router(shared, node(submit(Arc::default())))
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{path}: {}",
            response.status()
        );
        let origin = response.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).cloned();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (origin, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn answers_from_the_snapshot_with_open_cors() {
        let shared = snapshot();
        let (origin, node) = get(Arc::clone(&shared), "/node/info").await;
        assert_eq!(origin, Some(HeaderValue::from_static("*")));
        assert_eq!(node["nodePublicKey"], "CC");
        let (_, chain) = get(Arc::clone(&shared), "/chain/info").await;
        assert_eq!(chain["latestFinalizedBlock"]["height"], "8");
        let (_, unlocked) = get(Arc::clone(&shared), "/node/unlockedaccount").await;
        assert_eq!(unlocked["unlockedAccount"][0], "EE");
        let (_, delegations) = get(Arc::clone(&shared), "/heika/delegations").await;
        assert_eq!(delegations[0]["state"], "accepted");
        // ピアは、委任の鍵を持たない形で返す
        let peer = NodeInfoJson {
            node_public_key: None,
            host: "peer.example".to_owned(),
            ..shared.read().unwrap().node.clone()
        };
        shared.write().unwrap().peers = vec![peer];
        let (_, peers) = get(Arc::clone(&shared), "/node/peers").await;
        assert_eq!(peers[0]["host"], "peer.example");
        assert!(peers[0].get("nodePublicKey").is_none());
        // 駆動役が書き換えたら、次の問い合わせから新しいものを返す
        shared.write().unwrap().chain = ChainInfoJson::new(11, 11, 1, 3, 9, "DD".to_owned());
        let (_, chain) = get(shared, "/chain/info").await;
        assert_eq!(chain["height"], "11");
    }

    /// 公開鍵 [0x11; 32] のアカウントと、通貨のモザイクだけがある読み役
    struct FakeReader;

    /// 偽の読み役が、最後に受け取ったトランザクションの検索の絞り込み
    static LAST_FILTER: std::sync::Mutex<Option<TransactionFilter>> = std::sync::Mutex::new(None);

    const CURRENCY: u64 = 0x6BED_913F_A202_23F8;

    fn known() -> Address {
        Address::from_public_key(&PublicKey([0x11; 32]), NetworkIdentifier::TESTNET)
    }

    /// 偽の読み役にあるメタデータの1件を指すハッシュ
    fn metadata_composite() -> Hash256 {
        heika_transaction::MetadataKey {
            source_address: known(),
            target_address: known(),
            scoped_metadata_key: 1,
            target_id: 0,
            metadata_type: heika_transaction::MetadataType::Account,
        }
        .unique_key()
    }

    /// 偽の読み役は高さ 10 まで実行していて、5 より前の状態の履歴は持っていない
    /// 偽の読み役のマルチシグ。`M` は `known` と `C` が連署するマルチシグで、`M` は `U` の連署者
    fn fake_multisig_address(name: char) -> Address {
        Address::from_public_key(&PublicKey([name as u8; 32]), NetworkIdentifier::TESTNET)
    }

    fn fake_multisigs() -> Vec<MultisigJson> {
        let entry = |address: Address, cosignatories: &[Address], multisigs: &[Address]| {
            let hexes = |addresses: &[Address]| addresses.iter().map(Address::to_hex).collect();
            MultisigJson {
                version: 1,
                account_address: address.to_hex(),
                min_approval: cosignatories.len() as u32,
                min_removal: 1,
                cosignatory_addresses: hexes(cosignatories),
                multisig_addresses: hexes(multisigs),
            }
        };
        let [u, m, c] = ['U', 'M', 'C'].map(fake_multisig_address);
        vec![
            entry(u, &[m], &[]),
            entry(m, &[known(), c], &[u]),
            entry(known(), &[], &[m]),
            entry(c, &[], &[m]),
        ]
    }

    fn check_at(at: Option<u64>) -> Result<(), StateError> {
        match at {
            Some(height) if height > 10 => Err(StateError::Ahead { height, tip: 10 }),
            Some(height) if height < 5 => Err(StateError::NoHistory { height }),
            _ => Ok(()),
        }
    }

    impl Reader for FakeReader {
        fn accounts(
            &self,
            addresses: &[Address],
            at: Option<u64>,
        ) -> Result<Vec<AccountJson>, StateError> {
            check_at(at)?;
            let account = |address: &Address| {
                let mut bytes = vec![1, 0];
                bytes.extend_from_slice(&address.0);
                bytes.extend_from_slice(&1u64.to_le_bytes());
                bytes.extend_from_slice(&[0x11; 32]);
                bytes.extend_from_slice(&2u64.to_le_bytes());
                bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
                AccountJson::from_state_bytes(&bytes).unwrap()
            };
            Ok(addresses
                .iter()
                .filter(|address| **address == known())
                .map(account)
                .collect())
        }

        fn mosaics(
            &self,
            ids: &[u64],
            at: Option<u64>,
        ) -> Result<Vec<MosaicStateJson>, StateError> {
            check_at(at)?;
            let mosaic = |id: &u64| {
                let mut bytes = vec![1, 0];
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&[0; 54]);
                MosaicStateJson::from_state_bytes(&bytes).unwrap()
            };
            Ok(ids
                .iter()
                .filter(|id| **id == CURRENCY)
                .map(mosaic)
                .collect())
        }

        fn multisigs(
            &self,
            addresses: &[Address],
            at: Option<u64>,
        ) -> Result<Vec<MultisigJson>, StateError> {
            check_at(at)?;
            Ok(addresses
                .iter()
                .filter_map(|address| {
                    fake_multisigs()
                        .into_iter()
                        .find(|entry| entry.account_address == address.to_hex())
                })
                .collect())
        }

        fn multisig_graph(
            &self,
            address: &Address,
            at: Option<u64>,
        ) -> Result<Option<Vec<MultisigGraphLevel>>, StateError> {
            multisig_graph(address, |addresses| self.multisigs(addresses, at))
        }

        /// ハッシュ [0x44; 32] のハッシュロックと、`known` のアカウントの制限だけがある
        fn lock_or_restriction_states(
            &self,
            cache: SubCache,
            keys: &[Vec<u8>],
            at: Option<u64>,
        ) -> Result<KeyedStates, StateError> {
            check_at(at)?;
            let state = |key: &[u8]| match cache {
                SubCache::HashLockInfo if key == [0x44; 32] => Some(
                    HashLockJson {
                        version: 1,
                        owner_address: known().to_hex(),
                        mosaic_id: format!("{CURRENCY:016X}"),
                        amount: "10000000".to_owned(),
                        end_height: "480".to_owned(),
                        status: 0,
                        hash: "44".repeat(32),
                    }
                    .to_state_bytes()
                    .unwrap(),
                ),
                SubCache::AccountRestriction if key == known().0 => Some(
                    AccountRestrictionsJson {
                        version: 1,
                        address: known().to_hex(),
                        restrictions: vec![heika_rest::state::AccountRestrictionJson {
                            restriction_flags: 0xC004,
                            values: vec![heika_rest::state::AccountRestrictionValue::Operation(
                                0x4154,
                            )],
                        }],
                    }
                    .to_state_bytes()
                    .unwrap(),
                ),
                _ => None,
            };
            Ok(keys
                .iter()
                .filter_map(|key| state(key).map(|bytes| (key.clone(), bytes)))
                .collect())
        }

        fn namespace(&self, id: u64, at: Option<u64>) -> Result<Option<NamespaceInfo>, StateError> {
            check_at(at)?;
            // ルート 0xA1 に子 0xB2 だけがある
            let mut bytes = vec![1, 0];
            bytes.extend_from_slice(&0xA1u64.to_le_bytes());
            bytes.extend_from_slice(&[0x68; 24]);
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.extend_from_slice(&u64::MAX.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.push(1);
            bytes.extend_from_slice(&0xB2u64.to_le_bytes());
            bytes.push(0);
            let state = heika_rest::state::RootNamespaceState::from_state_bytes(&bytes).unwrap();
            Ok(state.info(id, at.unwrap_or(10)).unwrap())
        }

        fn metadata(
            &self,
            composite_hash: &Hash256,
            at: Option<u64>,
        ) -> Result<Option<MetadataEntryJson>, StateError> {
            check_at(at)?;
            if *composite_hash != metadata_composite() {
                return Ok(None);
            }
            let mut bytes = vec![1, 0];
            bytes.extend_from_slice(&known().0);
            bytes.extend_from_slice(&known().0);
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&2u16.to_le_bytes());
            bytes.extend_from_slice(b"hi");
            Ok(Some(MetadataEntryJson::from_state_bytes(&bytes).unwrap()))
        }

        fn search_metadata(
            &self,
            filter: &MetadataFilter,
            page: PageRequest,
            after: Option<&MetadataPosition>,
            at: Option<u64>,
        ) -> Result<Option<Vec<MetadataEntryJson>>, StateError> {
            check_at(at)?;
            // 対象の ID 0xDEAD は、検索表を作っていないことにする。高さ 6 は、昔の高さの分を作っていないことにする
            if filter.target_id == Some(0xDEAD) || at == Some(6) {
                return Ok(None);
            }
            // 絞り込みとページが届いたことを、返す件数と値で確かめる。送り主が known() なら1件、ほかの送り主なら 0 件、
            // 指定なしなら1ページ分。値はページの番号と、逆順なら "d"
            let count = match filter.source {
                Some(source) if source == known() => 1,
                Some(_) => 0,
                None => page.size,
            };
            let entry = self.metadata(&metadata_composite(), None).unwrap().unwrap();
            // 位置が届いたら、そのキーを値に足す
            let value = format!(
                "{}{}{}{}",
                page.number,
                if page.descending { "d" } else { "" },
                at.map(|height| format!("@{height}")).unwrap_or_default(),
                after
                    .map(|after| format!("+{:X}", after.scoped_key))
                    .unwrap_or_default()
            );
            Ok(Some(vec![
                MetadataEntryJson {
                    value: value.clone(),
                    ..entry
                };
                count
            ]))
        }

        fn search_namespaces(
            &self,
            filter: &NamespaceFilter,
            page: PageRequest,
            after: Option<&[u8]>,
            at: Option<u64>,
        ) -> Result<Option<Vec<(String, NamespaceInfo)>>, StateError> {
            check_at(at)?;
            // 別名の種類 9 は、検索表を作っていないことにする
            if filter.alias_type == Some(9) {
                return Ok(None);
            }
            // 位置は、持ち主の並べ方（先頭 4）のものだけを読む
            if after.is_some_and(|after| after[0] != 4) {
                return Err(StateError::Invalid(
                    "offset is not of this search".to_owned(),
                ));
            }
            let _ = page;
            Ok(Some(
                [0xA1, 0xB2]
                    .into_iter()
                    .filter(|&id| {
                        filter
                            .registration_type
                            .is_none_or(|kind| kind == u8::from(id != 0xA1))
                    })
                    .map(|id| {
                        let info = self.namespace(id, at).unwrap().unwrap();
                        (format!("04{id:02X}"), info)
                    })
                    .collect(),
            ))
        }

        fn namespace_names(&self, ids: &[u64]) -> Result<Option<Vec<NamespaceNameJson>>, String> {
            // 0xA1 は hina、0xB2 はその子の xym。親もたどって返す
            let mut out = Vec::new();
            for &id in ids {
                if id == 0xB2 {
                    out.push(NamespaceNameJson {
                        id: "00000000000000B2".to_owned(),
                        name: "xym".to_owned(),
                        parent_id: Some("00000000000000A1".to_owned()),
                    });
                }
                if id == 0xA1 || id == 0xB2 {
                    out.push(NamespaceNameJson {
                        id: "00000000000000A1".to_owned(),
                        name: "hina".to_owned(),
                        parent_id: None,
                    });
                }
            }
            Ok(Some(out))
        }

        fn alias_names(&self, target: AliasTarget) -> Result<Option<Vec<String>>, String> {
            Ok(match target {
                AliasTarget::Address(address) if address == known() => {
                    Some(vec!["hina.xym".to_owned()])
                }
                // モザイク 0xDEAD は、名前の表を作っていないことにする
                AliasTarget::Mosaic(0xDEAD) => None,
                AliasTarget::Mosaic(CURRENCY) => Some(vec!["symbol.xym".to_owned()]),
                _ => Some(Vec::new()),
            })
        }

        fn state_path(
            &self,
            cache: SubCache,
            key: &Hash256,
            at: Option<u64>,
        ) -> Result<MerkleStateInfo, StateError> {
            check_at(at)?;
            // 問い合わせた木とキーと高さを、そのまま返して確かめる
            let height = at.map(|height| format!("@{height}")).unwrap_or_default();
            Ok(MerkleStateInfo {
                raw: format!("{:02X}{key}{height}", cache.index()),
            })
        }

        fn block(&self, _height: u64) -> Result<Option<BlockInfo>, String> {
            Ok(None)
        }

        fn transaction_status(&self, hash: &Hash256) -> Result<Option<TransactionStatus>, String> {
            Ok((hash.0 == [0xAA; 32]).then(|| TransactionStatus {
                group: "confirmed".to_owned(),
                code: Some("Success".to_owned()),
                hash: hash.to_string(),
                deadline: Some("1".to_owned()),
                height: Some("7".to_owned()),
            }))
        }

        fn confirmed_transaction(
            &self,
            _hash: &Hash256,
        ) -> Result<Option<TransactionInfo>, String> {
            Ok(None)
        }

        /// `known` は高さ 1 から 25 のブロックの 0 番目に関わった。公開鍵 [0x23; 32] のアドレスは、索引を作っていない
        /// ことにする。受け取った絞り込みは [`LAST_FILTER`] に残す
        fn search_transactions(
            &self,
            filter: &TransactionFilter,
            page: PageRequest,
            after: Option<(u64, u32)>,
        ) -> Result<Option<Vec<TransactionInfo>>, String> {
            let unkept =
                Address::from_public_key(&PublicKey([0x23; 32]), NetworkIdentifier::TESTNET);
            *LAST_FILTER.lock().unwrap() = Some(filter.clone());
            if filter.address == Some(unkept) {
                return Ok(None);
            }
            // アドレスがなければ、全部のブロックを読んだことにする
            let mut heights: Vec<u64> = if filter.address.is_none_or(|address| address == known()) {
                (1..=25)
                    .filter(|height| (filter.from_height..=filter.to_height).contains(height))
                    .collect()
            } else {
                Vec::new()
            };
            if page.descending {
                heights.reverse();
            }
            if let Some((after, _)) = after {
                heights.retain(|&height| {
                    if page.descending {
                        height < after
                    } else {
                        height > after
                    }
                });
            }
            let transaction = heika_transaction::Transaction::new(
                PublicKey([0x11; 32]),
                NetworkIdentifier::TESTNET,
                0,
                0,
                heika_transaction::Body::Transfer(
                    heika_transaction::Transfer::new(
                        known().into(),
                        Default::default(),
                        Vec::new(),
                    )
                    .unwrap(),
                ),
            );
            Ok(Some(
                heights
                    .into_iter()
                    .skip((page.number - 1) * page.size)
                    .take(page.size)
                    .map(|height| TransactionInfo {
                        id: Some(heika_rest::transaction::transaction_position(height, 0)),
                        meta: heika_rest::transaction::TransactionMeta {
                            height: Some(height.to_string()),
                            hash: None,
                            merkle_component_hash: None,
                            index: Some(0),
                            aggregate_hash: None,
                            timestamp: None,
                            fee_multiplier: None,
                        },
                        transaction: heika_rest::transaction::TransactionJson::from(&transaction),
                    })
                    .collect(),
            ))
        }

        fn transaction_merkle(
            &self,
            height: u64,
            hash: &Hash256,
        ) -> Result<Option<MerkleProofInfo>, String> {
            Ok(
                (height == 7 && hash.0 == [0xAA; 32]).then(|| MerkleProofInfo {
                    merkle_path: Vec::new(),
                }),
            )
        }

        fn partial_transaction(&self, _hash: &Hash256) -> Result<Option<TransactionInfo>, String> {
            Ok(None)
        }

        fn partial_transactions(
            &self,
            filter: &PartialFilter,
        ) -> Result<Vec<TransactionInfo>, String> {
            // 絞り込みが届いたことを、件数で返す（署名者を指定したら 0 件、宛先なら 25 件、なしなら 3 件）
            let count = match (filter.signer, filter.address) {
                (Some(_), _) => 0,
                (None, Some(_)) => 25,
                (None, None) => 3,
            };
            let info: TransactionInfo = serde_json::from_value(serde_json::json!({
                "meta": {"height": "0"},
                "transaction": {"signerPublicKey": "AA", "version": 1, "network": 152, "type": 16961}
            }))
            .unwrap();
            Ok(vec![info; count])
        }

        fn transaction_fees(&self) -> Result<TransactionFeesJson, String> {
            Ok(TransactionFeesJson::new(vec![10, 30], 10))
        }

        fn network(&self) -> NetworkIdentifier {
            NetworkIdentifier::TESTNET
        }
    }

    fn node(submit: Submit) -> Node {
        Node {
            submit_partial: Arc::clone(&submit),
            submit_cosignature: Arc::clone(&submit),
            submit_block: Arc::clone(&submit),
            submit,
            reader: Arc::new(FakeReader),
            network_properties: Arc::new(NetworkPropertiesJson::default()),
        }
    }

    async fn get_response(path: &str) -> Response {
        router(snapshot(), node(submit(Arc::default())))
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn get_status(path: &str) -> (StatusCode, serde_json::Value) {
        let response = get_response(path).await;
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn answers_network_server_and_health_like_catapult() {
        let (status, body) = get_status("/network").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["name"].is_string() && body["description"].is_string());
        let (status, body) = get_status("/network/properties").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["network"].is_object() && body["chain"].is_object());
        assert!(body["plugins"]["aggregate"].is_object());
        let (status, body) = get_status("/node/server").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["serverInfo"]["restVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["serverInfo"]["deployment"]["deploymentTool"], "heika");
        assert_eq!(body["serverInfo"]["deployment"]["lastUpdatedDate"], "N/A");
        let (status, body) = get_status("/node/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"]["apiNode"], "up");
        assert_eq!(body["status"]["db"], "up");
    }

    #[tokio::test]
    async fn returns_the_offered_source() {
        // 渡す前は、入っていないと答える
        let (status, body) = get_status("/heika/sourcecode.zip").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "ResourceNotFound");
        offer_source(b"PK\x05\x06");
        let response = router(snapshot(), node(submit(Arc::default())))
            .oneshot(
                Request::get("/heika/sourcecode.zip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/zip");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"PK\x05\x06");
    }

    #[tokio::test]
    async fn searches_metadata_like_catapult() {
        let source = known();
        let (status, body) = get_status(&format!("/metadata?sourceAddress={source}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        assert_eq!(
            body["data"][0]["metadataEntry"]["compositeHash"],
            metadata_composite().to_string().as_str()
        );
        assert_eq!(body["pagination"]["pageNumber"], 1);
        assert_eq!(body["pagination"]["pageSize"], 10);
        // 1件ごとの id は位置で、そのまま offset に渡せる
        let id = body["data"][0]["id"].as_str().unwrap().to_owned();
        let entry: MetadataEntryJson =
            serde_json::from_value(body["data"][0]["metadataEntry"].clone()).unwrap();
        assert_eq!(id, entry.position());
        let (status, body) = get_status(&format!("/metadata?offset={id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"][0]["metadataEntry"]["value"], "1+1");
        // 1件引きにも同じ id を付ける
        let (_, body) = get_status(&format!("/metadata/{}", metadata_composite())).await;
        assert_eq!(body["id"], id.as_str());
        let other = Address::from_public_key(&PublicKey([0x22; 32]), NetworkIdentifier::TESTNET);
        let (_, body) = get_status(&format!("/metadata?sourceAddress={}", other.to_hex())).await;
        assert!(body["data"].as_array().unwrap().is_empty());

        // ページの大きさは 10 から 100 に収め、番号と並びを渡す
        let (_, body) =
            get_status("/metadata?pageSize=500&pageNumber=3&order=desc&metadataType=1").await;
        assert_eq!(body["data"].as_array().unwrap().len(), 100);
        assert_eq!(body["data"][0]["metadataEntry"]["value"], "3d");
        assert_eq!(body["pagination"]["pageSize"], 100);

        // 読めない形、公開鍵、昔の高さ、MongoDB の ID からのページ送りは 409
        for query in [
            "sourceAddress=zzz".to_owned(),
            format!("targetAddress={}", "11".repeat(32)),
            "scopedMetadataKey=12".to_owned(),
            "targetId=xyz".to_owned(),
            "order=up".to_owned(),
            "height=0".to_owned(),
            "height=11".to_owned(),
            "offset=6962CF6A2976BBB47C1054BC".to_owned(),
            format!("offset={}", "G".repeat(130)),
        ] {
            let (status, body) = get_status(&format!("/metadata?{query}")).await;
            assert_eq!(status, StatusCode::CONFLICT, "{query}");
            assert_eq!(body["code"], "InvalidArgument");
        }

        // 検索表を作っていなければ 501
        for query in ["targetId=000000000000DEAD", "height=6"] {
            let (status, body) = get_status(&format!("/metadata?{query}")).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{query}");
            assert_eq!(body["code"], "NotImplemented");
        }

        // 昔の高さは読み役まで届き、その高さを添える。差分を持っていなければ 410
        let response = get_response("/metadata?height=7").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["data"][0]["metadataEntry"]["value"], "1@7");
        assert_eq!(get_status("/metadata?height=4").await.0, StatusCode::GONE);
    }

    async fn post(path: &str, body: &str) -> (StatusCode, serde_json::Value) {
        let response = router(snapshot(), node(submit(Arc::default())))
            .oneshot(
                Request::post(path)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn reads_accounts_and_mosaics_in_a_batch_like_catapult() {
        let other = Address::from_public_key(&PublicKey([0x22; 32]), NetworkIdentifier::TESTNET);
        // ないものは飛ばし、同じものは1回だけ。アドレスは Base32 でも16進でもよい
        let (status, body) = post(
            "/accounts",
            &format!(
                r#"{{"addresses": ["{}", "{other}", "{}"]}}"#,
                known(),
                known().to_hex()
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["account"]["address"], known().to_hex().as_str());
        // 公開鍵でも、1つの文字列でもよい
        let (_, body) = post(
            "/accounts",
            &format!(r#"{{"publicKeys": "{}"}}"#, "11".repeat(32)),
        )
        .await;
        assert_eq!(body[0]["account"]["address"], known().to_hex().as_str());
        let (_, body) = post(
            "/mosaics",
            r#"{"mosaicIds": ["000000000000DEAD", "6BED913FA20223F8"]}"#,
        )
        .await;
        assert_eq!(body.as_array().unwrap().len(), 1);
        assert_eq!(body[0]["mosaic"]["id"], "6BED913FA20223F8");
        let (status, body) = post("/mosaics", r#"{"mosaicIds": []}"#).await;
        assert_eq!((status, body), (StatusCode::OK, serde_json::json!([])));

        let many: Vec<String> = (0..=MAX_STATE_IDS).map(|id| format!("{id:016X}")).collect();
        for (path, body) in [
            (
                "/accounts",
                format!(
                    r#"{{"addresses": ["{}"], "publicKeys": ["{}"]}}"#,
                    known(),
                    "11".repeat(32)
                ),
            ),
            ("/accounts", "{}".to_owned()),
            ("/accounts", r#"{"publicKeys": ["11"]}"#.to_owned()),
            ("/mosaics", r#"{"mosaicIds": ["12"]}"#.to_owned()),
            (
                "/mosaics",
                serde_json::json!({ "mosaicIds": many }).to_string(),
            ),
        ] {
            let (status, response) = post(path, &body).await;
            assert_eq!(status, StatusCode::CONFLICT, "{path} {body}");
            assert_eq!(response["code"], "InvalidArgument");
        }
    }

    #[tokio::test]
    async fn reads_multisigs_and_their_graph_like_catapult() {
        let [u, m, c] = ['U', 'M', 'C'].map(fake_multisig_address);
        let (status, body) = get_status(&format!("/account/{m}/multisig")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["multisig"]["accountAddress"], m.to_hex().as_str());
        assert_eq!(body["multisig"]["minApproval"], 2);
        let levels = |body: &serde_json::Value| -> Vec<(i64, Vec<String>)> {
            body.as_array()
                .unwrap()
                .iter()
                .map(|level| {
                    let entries = level["multisigEntries"].as_array().unwrap();
                    (
                        level["level"].as_i64().unwrap(),
                        entries
                            .iter()
                            .map(|entry| {
                                entry["multisig"]["accountAddress"]
                                    .as_str()
                                    .unwrap()
                                    .to_owned()
                            })
                            .collect(),
                    )
                })
                .collect()
        };
        // 上の段から順に。0 が引いたアカウント
        let (status, body) = get_status(&format!("/account/{m}/multisig/graph")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            levels(&body),
            vec![
                (-1, vec![u.to_hex()]),
                (0, vec![m.to_hex()]),
                (1, vec![known().to_hex(), c.to_hex()]),
            ]
        );
        let (_, body) = get_status(&format!("/account/{}/multisig/graph", known().to_hex())).await;
        assert_eq!(
            levels(&body),
            vec![
                (-2, vec![u.to_hex()]),
                (-1, vec![m.to_hex()]),
                (0, vec![known().to_hex()])
            ]
        );
        let other = fake_multisig_address('Z');
        for path in [
            format!("/account/{other}/multisig"),
            format!("/account/{other}/multisig/graph"),
        ] {
            assert_eq!(get_status(&path).await.0, StatusCode::NOT_FOUND, "{path}");
        }
        // 公開鍵では引けない（catapult と同じ）
        let key = "11".repeat(32);
        assert_eq!(
            get_status(&format!("/account/{key}/multisig")).await.0,
            StatusCode::CONFLICT
        );
        let response = get_response(&format!("/account/{m}/multisig/graph?height=7")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");
        assert_eq!(
            get_status(&format!("/account/{m}/multisig?height=4"))
                .await
                .0,
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn reads_locks_and_restrictions_like_catapult() {
        let lock = "44".repeat(32);
        let (status, body) = get_status(&format!("/lock/hash/{lock}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["lock"]["hash"], lock.as_str());
        assert_eq!(body["lock"]["status"], 0);
        assert_eq!(body["lock"]["endHeight"], "480");
        let (status, body) = get_status(&format!("/restrictions/account/{}", known())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["accountRestrictions"]["restrictions"],
            serde_json::json!([{ "restrictionFlags": 0xC004, "values": [0x4154] }])
        );
        // まとめて引けば、あるものだけ。1つの文字列でもよい
        let (status, body) = post(
            "/lock/hash",
            &format!(r#"{{"hashes": ["{lock}", "{}"]}}"#, "45".repeat(32)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 1);
        let (_, body) = post(
            "/restrictions/account",
            &format!(r#"{{"addresses": "{}"}}"#, known()),
        )
        .await;
        assert_eq!(
            body[0]["accountRestrictions"]["address"],
            known().to_hex().as_str()
        );
        let other = "45".repeat(32);
        for path in [
            format!("/lock/hash/{other}"),
            format!("/lock/secret/{other}"),
            format!("/restrictions/mosaic/{other}"),
        ] {
            assert_eq!(get_status(&path).await.0, StatusCode::NOT_FOUND, "{path}");
        }
        let (_, body) = post(
            "/lock/secret",
            &format!(r#"{{"compositeHashes": ["{other}"]}}"#),
        )
        .await;
        assert_eq!(body, serde_json::json!([]));
        for (path, body) in [
            ("/lock/hash", r#"{"hashes": ["12"]}"#.to_owned()),
            ("/lock/secret", r#"{"hashes": []}"#.to_owned()),
            (
                "/restrictions/account",
                r#"{"addresses": ["11"]}"#.to_owned(),
            ),
        ] {
            let (status, response) = post(path, &body).await;
            assert_eq!(status, StatusCode::CONFLICT, "{path} {body}");
            assert_eq!(response["code"], "InvalidArgument");
        }
        assert_eq!(get_status("/lock/hash/12").await.0, StatusCode::CONFLICT);
        let response = get_response(&format!("/lock/hash/{lock}?height=7")).await;
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");
        assert_eq!(
            get_status(&format!("/restrictions/account/{}?height=4", known()))
                .await
                .0,
            StatusCode::GONE
        );
        // 木の道の口もある（読み役が答えを持っていれば 200）
        assert_ne!(
            get_status(&format!("/lock/hash/{lock}/merkle")).await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn searches_confirmed_transactions_by_address() {
        let heights = |body: &serde_json::Value| -> Vec<String> {
            body["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|info| info["meta"]["height"].as_str().unwrap().to_owned())
                .collect()
        };
        let address = known();
        let (status, body) =
            get_status(&format!("/transactions/confirmed?address={address}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            heights(&body),
            (1..=10).map(|h| h.to_string()).collect::<Vec<_>>()
        );
        assert_eq!(
            body["pagination"],
            serde_json::json!({"pageNumber": 1, "pageSize": 10})
        );
        // 最後の件の id から続ける。新しい順、高さの範囲、ページの番号も
        let last = body["data"][9]["id"].as_str().unwrap().to_owned();
        assert_eq!(last, format!("{:016X}{:08X}", 10, 0));
        let (_, body) = get_status(&format!(
            "/transactions/confirmed?address={address}&offset={last}"
        ))
        .await;
        assert_eq!(heights(&body)[0], "11");
        let (_, body) = get_status(&format!(
            "/transactions/confirmed?address={address}&order=desc&fromHeight=3&toHeight=20&pageNumber=2"
        ))
        .await;
        assert_eq!(
            heights(&body),
            (3..=10).rev().map(|h| h.to_string()).collect::<Vec<_>>()
        );
        let (_, body) = get_status(&format!(
            "/transactions/confirmed?address={address}&height=7"
        ))
        .await;
        assert_eq!(heights(&body), vec!["7"]);
        let other = Address::from_public_key(&PublicKey([0x22; 32]), NetworkIdentifier::TESTNET);
        let (status, body) = get_status(&format!("/transactions/confirmed?address={other}")).await;
        assert_eq!(
            (status, body["data"].clone()),
            (StatusCode::OK, serde_json::json!([]))
        );

        // 絞り込みを読んで渡す。type は何回でも書ける
        let key = "11".repeat(32);
        let (status, _) = get_status(&format!(
            "/transactions/confirmed?signerPublicKey={key}&recipientAddress={other}&type=16724&type=16961\
             &transferMosaicId=6BED913FA20223F8&fromTransferAmount=5&toTransferAmount=9"
        ))
        .await;
        assert_eq!(status, StatusCode::OK);
        let filter = LAST_FILTER.lock().unwrap().clone().unwrap();
        assert_eq!(filter.address, None);
        assert_eq!(filter.signer, Some(PublicKey([0x11; 32])));
        assert_eq!(filter.recipient, Some(other.0));
        assert_eq!(filter.types, vec![0x4154, 0x4241]);
        assert_eq!(
            (filter.mosaic, filter.from_amount, filter.to_amount),
            (Some(CURRENCY), Some(5), Some(9))
        );
        // アドレスがなくても答える（索引がなければ、しまってあるブロックを読む）
        let (status, body) = get_status("/transactions/confirmed?height=3").await;
        assert_eq!(
            (status, heights(&body)),
            (StatusCode::OK, vec!["3".to_owned()])
        );

        // 索引がなければ 501。アグリゲートの中のものも、まだ 501
        let unkept = Address::from_public_key(&PublicKey([0x23; 32]), NetworkIdentifier::TESTNET);
        for path in [
            format!("/transactions/confirmed?address={unkept}"),
            format!("/transactions/confirmed?address={address}&embedded=true"),
        ] {
            let (status, body) = get_status(&path).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{path}");
            assert_eq!(body["code"], "NotImplemented");
        }
        for path in [
            format!("/transactions/confirmed?address={address}&signerPublicKey={key}"),
            format!("/transactions/confirmed?address={address}&recipientAddress={other}"),
            "/transactions/confirmed?fromTransferAmount=1".to_owned(),
            "/transactions/confirmed?address=zzz".to_owned(),
            "/transactions/confirmed?signerPublicKey=11".to_owned(),
            "/transactions/confirmed?type=x".to_owned(),
            "/transactions/confirmed?transferMosaicId=12".to_owned(),
            format!("/transactions/confirmed?address={address}&offset=12"),
            format!("/transactions/confirmed?address={address}&fromHeight=x"),
            format!("/transactions/confirmed?address={address}&order=up"),
        ] {
            let (status, body) = get_status(&path).await;
            assert_eq!(status, StatusCode::CONFLICT, "{path}");
            assert_eq!(body["code"], "InvalidArgument");
        }
    }

    #[tokio::test]
    async fn reads_a_batch_at_a_past_height() {
        let response = router(snapshot(), node(submit(Arc::default())))
            .oneshot(
                Request::post("/mosaics?height=7")
                    .header("Content-Type", "application/json")
                    .body(Body::from(r#"{"mosaicIds": ["6BED913FA20223F8"]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");
        for (height, status) in [(4, StatusCode::GONE), (11, StatusCode::CONFLICT)] {
            let (got, _) = post(
                &format!("/accounts?height={height}"),
                &format!(r#"{{"addresses": ["{}"]}}"#, known()),
            )
            .await;
            assert_eq!(got, status, "{height}");
        }
    }

    #[tokio::test]
    async fn searches_namespaces_and_their_names_like_catapult() {
        let (status, body) = get_status("/namespaces").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);
        assert_eq!(body["data"][0]["id"], "04A1");
        assert_eq!(body["data"][1]["namespace"]["parentId"], "00000000000000A1");
        let (_, body) = get_status(&format!(
            "/namespaces?registrationType=1&ownerAddress={}&level0=00000000000000A1",
            known()
        ))
        .await;
        assert_eq!(body["data"].as_array().unwrap().len(), 1);
        assert_eq!(
            get_status("/namespaces?offset=04A1").await.0,
            StatusCode::OK
        );

        // 読めない形と、ほかの検索の位置は 409、作っていなければ 501、昔の高さは添え、差分がなければ 410
        for query in [
            "ownerAddress=zzz",
            "level0=A1",
            "offset=zz",
            "offset=05A1",
            "order=up",
            "height=0",
        ] {
            let (status, body) = get_status(&format!("/namespaces?{query}")).await;
            assert_eq!(status, StatusCode::CONFLICT, "{query}");
            assert_eq!(body["code"], "InvalidArgument");
        }
        assert_eq!(
            get_status("/namespaces?aliasType=9").await.0,
            StatusCode::NOT_IMPLEMENTED
        );
        let response = get_response("/namespaces?height=7").await;
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");
        assert_eq!(get_status("/namespaces?height=4").await.0, StatusCode::GONE);

        // 名前は親もたどる
        let (status, body) = post(
            "/namespaces/names",
            r#"{"namespaceIds": ["00000000000000B2"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            serde_json::json!([
                {"id": "00000000000000B2", "name": "xym", "parentId": "00000000000000A1"},
                {"id": "00000000000000A1", "name": "hina"}
            ])
        );
        let (status, body) = post(
            "/namespaces/account/names",
            &format!(
                r#"{{"addresses": ["{}", "{}"]}}"#,
                known(),
                Address::from_public_key(&PublicKey([0x22; 32]), NetworkIdentifier::TESTNET)
                    .to_hex()
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["accountNames"][0]["address"],
            known().to_hex().as_str()
        );
        assert_eq!(
            body["accountNames"][0]["names"],
            serde_json::json!(["hina.xym"])
        );
        assert_eq!(body["accountNames"][1]["names"], serde_json::json!([]));
        let (_, body) = post(
            "/namespaces/mosaic/names",
            r#"{"mosaicIds": ["6BED913FA20223F8"]}"#,
        )
        .await;
        assert_eq!(
            body,
            serde_json::json!({"mosaicNames": [{"mosaicId": "6BED913FA20223F8", "names": ["symbol.xym"]}]})
        );

        // 本文がない、多すぎる、読めない並びは 409。名前の表を作っていなければ 501
        let many: Vec<String> = (0..101).map(|id| format!("{id:016X}")).collect();
        for (path, body) in [
            ("/namespaces/names", "{}".to_owned()),
            (
                "/namespaces/names",
                serde_json::json!({ "namespaceIds": many }).to_string(),
            ),
            (
                "/namespaces/account/names",
                r#"{"addresses": ["zzz"]}"#.to_owned(),
            ),
            (
                "/namespaces/mosaic/names",
                r#"{"mosaicIds": ["12"]}"#.to_owned(),
            ),
        ] {
            let (status, response) = post(path, &body).await;
            assert_eq!(status, StatusCode::CONFLICT, "{path} {body}");
            assert_eq!(response["code"], "InvalidArgument");
        }
        let (status, body) = post(
            "/namespaces/mosaic/names",
            r#"{"mosaicIds": ["000000000000DEAD"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["code"], "NotImplemented");
    }

    #[tokio::test]
    async fn reads_states_at_a_height() {
        // 高さを指定したら、答えにその高さを添える。指定しなければ添えない
        let response = get_response("/mosaics/6BED913FA20223F8?height=7").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");
        let response = get_response("/mosaics/6BED913FA20223F8").await;
        assert!(response.headers().get(HEIGHT_HEADER).is_none());
        // 見つからなくても添える
        let response = get_response("/mosaics/0000000000000001?height=7").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[HEIGHT_HEADER], "7");

        let address = known();
        for path in [
            format!("/accounts/{address}"),
            "/mosaics/6BED913FA20223F8".to_owned(),
            "/namespaces/00000000000000A1".to_owned(),
            format!("/accounts/{address}/merkle"),
            "/namespaces/00000000000000B2/merkle".to_owned(),
        ] {
            assert_eq!(
                get_status(&format!("{path}?height=5")).await.0,
                StatusCode::OK,
                "{path}"
            );
            // まだ届いていない高さと、読めない形は 409、履歴を持っていない高さは 410
            for height in ["11", "0", "x", "-1"] {
                let (status, body) = get_status(&format!("{path}?height={height}")).await;
                assert_eq!(status, StatusCode::CONFLICT, "{path} {height}");
                assert_eq!(body["code"], "InvalidArgument");
            }
            let (status, body) = get_status(&format!("{path}?height=4")).await;
            assert_eq!(status, StatusCode::GONE, "{path}");
            assert_eq!(body["code"], "Gone");
        }

        // 高さは読み役まで届く
        let (_, body) = get_status("/mosaics/6BED913FA20223F8/merkle?height=6").await;
        assert!(body["raw"].as_str().unwrap().ends_with("@6"));
        let composite = metadata_composite();
        assert_eq!(
            get_status(&format!("/metadata/{composite}?height=6"))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            get_status(&format!("/metadata/{composite}/merkle?height=4"))
                .await
                .0,
            StatusCode::GONE
        );
    }

    #[tokio::test]
    async fn reads_accounts_mosaics_and_blocks() {
        let address = known();
        let hex_address = address.to_hex();
        // アドレス（Base32 と16進）でも公開鍵でも引ける
        for id in [address.to_string(), hex_address.clone(), "11".repeat(32)] {
            let (status, body) = get_status(&format!("/accounts/{id}")).await;
            assert_eq!(status, StatusCode::OK, "{id}");
            assert_eq!(body["account"]["address"], hex_address.as_str());
        }
        let other = Address::from_public_key(&PublicKey([0x22; 32]), NetworkIdentifier::TESTNET);
        let (status, body) = get_status(&format!("/accounts/{other}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "ResourceNotFound");
        // 読めない形と、ほかのネットワークのアドレスは 409
        let mainnet = Address::from_public_key(&PublicKey([0x11; 32]), NetworkIdentifier::MAINNET);
        for id in ["zzz".to_owned(), mainnet.to_string()] {
            let (status, body) = get_status(&format!("/accounts/{id}")).await;
            assert_eq!(status, StatusCode::CONFLICT, "{id}");
            assert_eq!(body["code"], "InvalidArgument");
        }
        let (status, body) = get_status(&format!("/accounts/{address}/merkle")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["raw"],
            format!("00{}", patricia::address_key(&address)).as_str()
        );

        let (status, body) = get_status("/mosaics/6BED913FA20223F8").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["mosaic"]["id"], "6BED913FA20223F8");
        assert_eq!(
            get_status("/mosaics/0000000000000001").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get_status("/mosaics/6BED").await.0, StatusCode::CONFLICT);
        let (_, body) = get_status("/mosaics/6BED913FA20223F8/merkle").await;
        assert_eq!(
            body["raw"],
            format!(
                "{:02X}{}",
                SubCache::Mosaic.index(),
                patricia::id_key(CURRENCY)
            )
            .as_str()
        );

        // ネームスペースは、ルートでも子でも引ける
        let (status, body) = get_status("/namespaces/00000000000000A1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["active"], true);
        assert_eq!(body["namespace"]["registrationType"], 0);
        let (status, body) = get_status("/namespaces/00000000000000B2").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["namespace"]["level1"], "00000000000000B2");
        assert_eq!(body["namespace"]["parentId"], "00000000000000A1");
        assert_eq!(
            get_status("/namespaces/00000000000000C3").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get_status("/namespaces/A1").await.0, StatusCode::CONFLICT);
        let (_, body) = get_status("/namespaces/00000000000000A1/merkle").await;
        assert_eq!(
            body["raw"],
            format!(
                "{:02X}{}",
                SubCache::Namespace.index(),
                patricia::id_key(0xA1)
            )
            .as_str()
        );

        // メタデータは、1件を指すハッシュで引く
        let composite = metadata_composite();
        let (status, body) = get_status(&format!("/metadata/{composite}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["metadataEntry"]["compositeHash"],
            composite.to_string().as_str()
        );
        assert_eq!(body["metadataEntry"]["value"], "6869");
        assert_eq!(
            get_status(&format!("/metadata/{}", "00".repeat(32)))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(get_status("/metadata/00").await.0, StatusCode::CONFLICT);
        let (_, body) = get_status(&format!("/metadata/{composite}/merkle")).await;
        assert_eq!(
            body["raw"],
            format!(
                "{:02X}{}",
                SubCache::Metadata.index(),
                patricia::hash_key(&composite)
            )
            .as_str()
        );

        assert_eq!(get_status("/blocks/5").await.0, StatusCode::NOT_FOUND);

        // 連署を待つものの一覧は、絞り込みとページを読む
        let (status, body) = get_status("/transactions/partial").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 3);
        assert_eq!(body["pagination"]["pageSize"], 10);
        let (_, body) = get_status(&format!(
            "/transactions/partial?address={}&pageSize=20&pageNumber=2",
            known()
        ))
        .await;
        assert_eq!(body["data"].as_array().unwrap().len(), 5);
        assert_eq!(body["pagination"]["pageNumber"], 2);
        let (_, body) = get_status(&format!(
            "/transactions/partial?signerPublicKey={}",
            "11".repeat(32)
        ))
        .await;
        assert!(body["data"].as_array().unwrap().is_empty());
        assert_eq!(
            get_status("/transactions/partial?address=zzz").await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            get_status(&format!("/transactions/partial/{}", "AA".repeat(32)))
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        let (status, body) = get_status("/network/fees/transaction").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["medianFeeMultiplier"], 20);
        assert_eq!(body["minFeeMultiplier"], 10);

        let known = "AA".repeat(32);
        let (status, body) = get_status(&format!("/transactionStatus/{known}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["group"], "confirmed");
        assert_eq!(body["height"], "7");
        let unknown = "BB".repeat(32);
        assert_eq!(
            get_status(&format!("/transactionStatus/{unknown}")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_status("/transactionStatus/AB").await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            get_status(&format!("/transactions/confirmed/{known}"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        let (status, body) = get_status(&format!("/blocks/7/transactions/{known}/merkle")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["merklePath"], serde_json::json!([]));
        assert_eq!(
            get_status(&format!("/blocks/8/transactions/{known}/merkle"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        for height in ["0", "abc"] {
            assert_eq!(
                get_status(&format!("/blocks/{height}")).await.0,
                StatusCode::CONFLICT
            );
        }
    }

    /// 受け付けの口。`[1, 2]` だけを受け付け、受け取ったものを `received` に残す
    fn submit(received: Arc<std::sync::Mutex<Vec<Vec<u8>>>>) -> Submit {
        Arc::new(move |bytes: Vec<u8>| {
            received.lock().unwrap().push(bytes.clone());
            if bytes == [1, 2] {
                Ok(())
            } else {
                Err("確かめが通りません".to_owned())
            }
        })
    }

    async fn put(
        received: &Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        put_to(received, "/transactions", body).await
    }

    async fn put_to(
        received: &Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        path: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = router(snapshot(), node(submit(Arc::clone(received))))
            .oneshot(
                Request::put(path)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn announces_transactions_like_catapult() {
        let received = Arc::default();
        let (status, answer) = put(&received, r#"{"payload":"0102"}"#).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            answer["message"],
            "packet 9 was pushed to the network via /transactions"
        );
        // 受け付けなかったら、わけを付けて 409
        let (status, answer) = put(&received, r#"{"payload":"0a0B03"}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(answer["code"], "InvalidArgument");
        assert_eq!(answer["message"], "確かめが通りません");
        // 16進でなければ、口に渡さない
        for payload in ["", "010", "01XY"] {
            let (status, _) = put(&received, &format!(r#"{{"payload":"{payload}"}}"#)).await;
            assert_eq!(status, StatusCode::CONFLICT, "{payload:?}");
        }
        assert_eq!(*received.lock().unwrap(), [vec![1, 2], vec![10, 11, 3]]);
    }

    #[test]
    fn throttle_refills_up_to_one_second() {
        let start = Instant::now();
        let throttle = Throttle::new(3, start);
        assert!((0..3).all(|_| throttle.take(start)));
        assert!(!throttle.take(start));
        // 1 回分たまるのは 1/3 秒あと
        assert!(!throttle.take(start + Duration::from_millis(300)));
        assert!(throttle.take(start + Duration::from_millis(340)));
        // 長く空けても、ためておけるのは 1 秒分
        let later = start + Duration::from_secs(10);
        assert!((0..3).all(|_| throttle.take(later)));
        assert!(!throttle.take(later));
    }

    #[tokio::test]
    async fn answers_429_with_cors_over_the_limit() {
        let app = limit(router(snapshot(), node(submit(Arc::default()))), 1);
        let request = || Request::get("/chain/info").body(Body::empty()).unwrap();
        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let second = app.oneshot(request()).await.unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    }

    #[tokio::test]
    async fn takes_blocks_like_transactions() {
        let received = Arc::default();
        let (status, answer) = put_to(&received, "/blocks", r#"{"payload":"0102"}"#).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            answer["message"],
            "packet 3 was pushed to the network via /blocks"
        );
        let (status, answer) = put_to(&received, "/blocks", r#"{"payload":"0a0B03"}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(answer["message"], "確かめが通りません");
        let (status, _) = put_to(&received, "/blocks", r#"{"payload":"01XY"}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(*received.lock().unwrap(), [vec![1, 2], vec![10, 11, 3]]);
    }

    #[tokio::test]
    async fn takes_blocks_up_to_the_p2p_size() {
        let received: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
        let put_body = |content_type: &'static str, body: Vec<u8>| {
            let app = router(snapshot(), node(submit(Arc::clone(&received))));
            async move {
                app.oneshot(
                    Request::put("/blocks")
                        .header("Content-Type", content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };
        let octets = "application/octet-stream";
        // axum の既定（2 MB）より大きくても、上限までは口に渡す
        assert_eq!(
            put_body(octets, vec![0; MAX_BLOCK_BYTES]).await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            put_body(octets, vec![0; MAX_BLOCK_BYTES + 1]).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let json = |size: usize| format!(r#"{{"payload":"{}"}}"#, "00".repeat(size)).into_bytes();
        assert_eq!(
            put_body("application/json", json(MAX_BLOCK_BYTES)).await,
            StatusCode::CONFLICT
        );
        // 本文の上限の内でも、戻したブロックが上限を超えれば 413
        assert_eq!(
            put_body("application/json", json(MAX_BLOCK_BYTES + 1)).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            put_body("application/json", json(MAX_BLOCK_BYTES + 1024)).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let sizes: Vec<usize> = received.lock().unwrap().iter().map(Vec::len).collect();
        assert_eq!(sizes, [MAX_BLOCK_BYTES, MAX_BLOCK_BYTES]);
    }

    #[tokio::test]
    async fn takes_raw_blocks_as_octet_stream() {
        let received: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
        let put_raw = |content_type: &'static str, body: &'static [u8]| {
            let app = router(snapshot(), node(submit(Arc::clone(&received))));
            async move {
                app.oneshot(
                    Request::put("/blocks")
                        .header("Content-Type", content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };
        assert_eq!(
            put_raw("application/octet-stream", &[1, 2]).await,
            StatusCode::ACCEPTED
        );
        // 頭の書き方の揺れ（大文字、引数付き）も同じに読む
        assert_eq!(
            put_raw("Application/Octet-Stream; charset=binary", &[1, 2]).await,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            put_raw("application/octet-stream", &[10, 11, 3]).await,
            StatusCode::CONFLICT
        );
        // JSON と書いてバイト列を送ったら、口に渡さない
        assert!(put_raw("application/json", &[1, 2]).await.is_client_error());
        // どちらでもないものは 415（JSON でも、Content-Type を書かなければ読まない）
        assert_eq!(
            put_raw("text/plain", br#"{"payload":"0102"}"#).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            *received.lock().unwrap(),
            [vec![1, 2], vec![1, 2], vec![10, 11, 3]]
        );
    }

    #[tokio::test]
    async fn announces_partials_and_cosignatures_like_catapult() {
        let received = Arc::default();
        let (status, answer) =
            put_to(&received, "/transactions/partial", r#"{"payload":"0102"}"#).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            answer["message"],
            "packet 256 was pushed to the network via /transactions/partial"
        );
        let cosignature = format!(
            r#"{{"version":"0","signerPublicKey":"{}","signature":"{}","parentHash":"{}"}}"#,
            "11".repeat(32),
            "22".repeat(64),
            "33".repeat(32)
        );
        let (status, answer) = put_to(&received, "/transactions/cosignature", &cosignature).await;
        // 受け付けの口は [1, 2] だけを受け付けるので、形が正しくても 409 になる。渡したものを見る
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        let passed = received.lock().unwrap().last().cloned().unwrap();
        assert_eq!(passed.len(), 136);
        assert_eq!(&passed[..8], &[0; 8]);
        assert_eq!(&passed[8..40], &[0x11; 32]);
        assert_eq!(&passed[104..], &[0x33; 32]);
        // 形が違えば、口に渡さない
        let before = received.lock().unwrap().len();
        let broken = cosignature.replace(&"33".repeat(32), "33");
        assert_eq!(
            put_to(&received, "/transactions/cosignature", &broken)
                .await
                .0,
            StatusCode::CONFLICT
        );
        let other_version = cosignature.replace(r#""version":"0""#, r#""version":"1""#);
        assert_eq!(
            put_to(&received, "/transactions/cosignature", &other_version)
                .await
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(received.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn answers_the_preflight_for_put() {
        let response = router(snapshot(), node(submit(Arc::default())))
            .oneshot(
                Request::options("/transactions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let headers = response.headers();
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            headers[ACCESS_CONTROL_ALLOW_METHODS]
                .to_str()
                .unwrap()
                .contains("PUT")
        );
        assert_eq!(headers[ACCESS_CONTROL_ALLOW_HEADERS], "Content-Type");
    }
}
