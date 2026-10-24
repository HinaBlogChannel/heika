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
//! - `/accounts/{accountId}`、`/mosaics/{mosaicId}` と、それぞれの `/merkle`: 今の状態と、状態の木の道
//! - `/blocks/{height}`: ブロックのヘッダーと、その高さの9本の根
//! - `/network/fees/transaction`: 直近のブロックの手数料の倍率と、ノードが受け付ける下限
//! - `/network/properties`: ネットワークの設定（catapult の `config-network.properties`）
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
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    CONTENT_DISPOSITION, CONTENT_TYPE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{Next, from_fn, map_response};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
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
use heika_rest::state::{AccountInfo, AccountJson, MosaicInfo, MosaicStateJson};
use heika_rest::transaction::TransactionInfo;

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

/// チェーンの中身を読む口。エラーはわけの文（500 で返す）
pub trait Reader: Send + Sync {
    /// アカウントの今の状態。なければ `None`
    fn account(&self, address: &Address) -> Result<Option<AccountJson>, String>;
    /// モザイクの定義の今の状態。なければ `None`
    fn mosaic(&self, id: u64) -> Result<Option<MosaicStateJson>, String>;
    /// 状態の木 `cache` の、根から `key` の葉への道。ないことを示す道もある
    fn state_path(&self, cache: SubCache, key: &Hash256) -> Result<MerkleStateInfo, String>;
    /// `height` のブロック。なければ（まだないか、刈り込んだか、その高さの根がもうなければ）`None`
    fn block(&self, height: u64) -> Result<Option<BlockInfo>, String>;
    /// トランザクションの行方。知らなければ `None`
    fn transaction_status(&self, hash: &Hash256) -> Result<Option<TransactionStatus>, String>;
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

/// モザイクの ID。上位から16進
fn mosaic_id(id: &str) -> Option<u64> {
    (id.len() == 16)
        .then(|| u64::from_str_radix(id, 16).ok())
        .flatten()
}

async fn account(State(api): State<Api>, Path(id): Path<String>) -> Response {
    let Some(address) = account_address(&id, api.node.reader.network()) else {
        return invalid("accountId has an invalid format".to_owned());
    };
    let read = api.node.reader.account(&address);
    found(
        &id,
        read.map(|account| account.map(|account| AccountInfo { account })),
    )
}

async fn account_merkle(State(api): State<Api>, Path(id): Path<String>) -> Response {
    let Some(address) = account_address(&id, api.node.reader.network()) else {
        return invalid("accountId has an invalid format".to_owned());
    };
    let key = patricia::address_key(&address);
    found(
        &id,
        api.node
            .reader
            .state_path(SubCache::AccountState, &key)
            .map(Some),
    )
}

async fn mosaic(State(api): State<Api>, Path(id): Path<String>) -> Response {
    let Some(mosaic_id) = mosaic_id(&id) else {
        return invalid("mosaicId has an invalid format".to_owned());
    };
    let read = api.node.reader.mosaic(mosaic_id);
    found(
        &id,
        read.map(|mosaic| mosaic.map(|mosaic| MosaicInfo { mosaic })),
    )
}

async fn mosaic_merkle(State(api): State<Api>, Path(id): Path<String>) -> Response {
    let Some(mosaic_id) = mosaic_id(&id) else {
        return invalid("mosaicId has an invalid format".to_owned());
    };
    let key = patricia::id_key(mosaic_id);
    found(
        &id,
        api.node.reader.state_path(SubCache::Mosaic, &key).map(Some),
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

/// トランザクションのハッシュ。16進
fn transaction_hash(hash: &str) -> Option<Hash256> {
    if hash.len() != 64 {
        return None;
    }
    let mut bytes = [0; 32];
    base16ct::mixed::decode(hash, &mut bytes).ok()?;
    Some(Hash256(bytes))
}

async fn partial_transaction(State(api): State<Api>, Path(hash): Path<String>) -> Response {
    let Some(key) = transaction_hash(&hash) else {
        return invalid("transactionId has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.partial_transaction(&key))
}

/// 連署を待つものの一覧。ページの大きさは catapult と同じく 10 から 100（既定 10）、ページは 1 から
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
    let Some(key) = transaction_hash(&hash) else {
        return invalid("hash has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.transaction_status(&key))
}

async fn confirmed_transaction(State(api): State<Api>, Path(hash): Path<String>) -> Response {
    let Some(key) = transaction_hash(&hash) else {
        return invalid("transactionId has an invalid format".to_owned());
    };
    found(&hash, api.node.reader.confirmed_transaction(&key))
}

async fn transaction_merkle(
    State(api): State<Api>,
    Path((height, hash)): Path<(String, String)>,
) -> Response {
    let (Some(number), Some(key)) = (block_height(&height), transaction_hash(&hash)) else {
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
        HeaderValue::from_static("GET, PUT, OPTIONS"),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    response
}

/// 口の並び
pub fn router(shared: Shared, node: Node) -> Router {
    Router::new()
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
        .route("/accounts/{id}", get(account))
        .route("/accounts/{id}/merkle", get(account_merkle))
        .route("/mosaics/{id}", get(mosaic))
        .route("/mosaics/{id}/merkle", get(mosaic_merkle))
        .route("/blocks/{height}", get(block))
        .route("/network/fees/transaction", get(transaction_fees))
        .route("/transactionStatus/{hash}", get(transaction_status))
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

    const CURRENCY: u64 = 0x6BED_913F_A202_23F8;

    fn known() -> Address {
        Address::from_public_key(&PublicKey([0x11; 32]), NetworkIdentifier::TESTNET)
    }

    impl Reader for FakeReader {
        fn account(&self, address: &Address) -> Result<Option<AccountJson>, String> {
            if *address != known() {
                return Ok(None);
            }
            let mut bytes = vec![1, 0];
            bytes.extend_from_slice(&address.0);
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.extend_from_slice(&[0x11; 32]);
            bytes.extend_from_slice(&2u64.to_le_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            Ok(Some(AccountJson::from_state_bytes(&bytes).unwrap()))
        }

        fn mosaic(&self, id: u64) -> Result<Option<MosaicStateJson>, String> {
            if id != CURRENCY {
                return Ok(None);
            }
            let mut bytes = vec![1, 0];
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&[0; 54]);
            Ok(Some(MosaicStateJson::from_state_bytes(&bytes).unwrap()))
        }

        fn state_path(&self, cache: SubCache, key: &Hash256) -> Result<MerkleStateInfo, String> {
            // 問い合わせた木とキーを、そのまま返して確かめる
            Ok(MerkleStateInfo {
                raw: format!("{:02X}{key}", cache.index()),
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

    async fn get_status(path: &str) -> (StatusCode, serde_json::Value) {
        let response = router(snapshot(), node(submit(Arc::default())))
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
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
