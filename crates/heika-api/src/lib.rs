//! heika のノードの REST。catapult の REST のうち、ウォレットが委任に使う口と、heika だけの口を返す。
//!
//! - `/node/info`: ノードの身元と、委任の鍵（`nodePublicKey`）
//! - `/node/peers`: 知っているピア。GUI のノードは、ここから最初のつなぎ先を選ぶ
//! - `/chain/info`: 高さ、スコア、確定したブロック
//! - `/node/unlockedaccount`: ハーベストしている、委任されたリモートの鍵
//! - `/heika/delegations`: 届いた委任の要求ごとに、引き受けたか、待っているか、なぜ引き受けなかったか
//! - `PUT /transactions`: 署名したトランザクションを受け付けて、ネットワークに流す
//! - `/accounts/{accountId}`、`/mosaics/{mosaicId}` と、それぞれの `/merkle`: 今の状態と、状態の木の道
//! - `/blocks/{height}`: ブロックのヘッダーと、その高さの9本の根
//! - `/network/fees/transaction`: 直近のブロックの手数料の倍率と、ノードが受け付ける下限
//! - `/transactionStatus/{hash}`、`/transactions/confirmed/{hash}`、`/blocks/{height}/transactions/{hash}/merkle`:
//!   送ったトランザクションの行方と、入ったブロックへの Merkle の経路
//!
//! ノードの駆動役が [`Snapshot`] を書き換え、ここは読んで返すだけにする。チェーンの本体には触らない。
//! 受け付けたトランザクションは、駆動役から渡された [`Submit`] に渡し、状態とブロックは [`Reader`] で読む。
//! ID の読み方と、答えの形（見つからなければ 404 など）はここで決め、何をどう読むかは [`Reader`] に任せる。
//! catapult の REST と同じく、どこのページからでも読めるようにする（CORS）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::map_response;
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
    AnnounceJson, AnnounceResultJson, ChainInfoJson, DelegationJson, ErrorJson, NodeInfoJson,
    TransactionFeesJson, UnlockedAccountJson,
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
    /// 公開鍵からアドレスを出すときのネットワーク
    fn network(&self) -> NetworkIdentifier;
}

/// API がノードに頼む口
#[derive(Clone)]
pub struct Node {
    pub submit: Submit,
    pub reader: Arc<dyn Reader>,
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
        .route("/node/unlockedaccount", get(unlocked))
        .route("/heika/delegations", get(delegations))
        .route("/transactions", put(announce).options(preflight))
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

/// `addresses` のそれぞれで待ち受け、`stop` が立つまで答える。呼んだスレッドで tokio を回す
pub fn serve(
    addresses: &[String],
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
        for address in addresses {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|error| format!("API を {address} で待ち受けられません: {error}"))?;
            println!("API を {address} で待ち受けます");
            let app = router(Arc::clone(&shared), node.clone());
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

        fn transaction_fees(&self) -> Result<TransactionFeesJson, String> {
            Ok(TransactionFeesJson::new(vec![10, 30], 10))
        }

        fn network(&self) -> NetworkIdentifier {
            NetworkIdentifier::TESTNET
        }
    }

    fn node(submit: Submit) -> Node {
        Node {
            submit,
            reader: Arc::new(FakeReader),
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
        let response = router(snapshot(), node(submit(Arc::clone(received))))
            .oneshot(
                Request::put("/transactions")
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
