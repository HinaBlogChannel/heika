//! heika のノードの REST。catapult の REST のうち、ウォレットが委任に使う口と、heika だけの口を返す。
//!
//! - `/node/info`: ノードの身元と、委任の鍵（`nodePublicKey`）
//! - `/chain/info`: 高さ、スコア、確定したブロック
//! - `/node/unlockedaccount`: ハーベストしている、委任されたリモートの鍵
//! - `/heika/delegations`: 届いた委任の要求ごとに、引き受けたか、待っているか、なぜ引き受けなかったか
//! - `PUT /transactions`: 署名したトランザクションを受け付けて、ネットワークに流す
//!
//! ノードの駆動役が [`Snapshot`] を書き換え、ここは読んで返すだけにする。チェーンの本体には触らない。
//! 受け付けたトランザクションは、駆動役から渡された [`Submit`] に渡す。
//! catapult の REST と同じく、どこのページからでも読めるようにする（CORS）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::map_response;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use heika_rest::node::{
    AnnounceJson, AnnounceResultJson, ChainInfoJson, DelegationJson, ErrorJson, NodeInfoJson,
    UnlockedAccountJson,
};

/// API が返す、ノードの今の様子
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub node: NodeInfoJson,
    pub chain: ChainInfoJson,
    pub unlocked: UnlockedAccountJson,
    pub delegations: Vec<DelegationJson>,
}

/// 駆動役と API で分け合う様子
pub type Shared = Arc<RwLock<Snapshot>>;

/// 署名したトランザクションのバイト列を受け付ける口。受け付けたら（もう持っていたときも）`Ok`、受け付けなかったら
/// わけを返す。ネットワークに流すのも、この口の仕事
pub type Submit = Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

#[derive(Clone)]
struct Api {
    shared: Shared,
    submit: Submit,
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
        Some(bytes) => (api.submit)(bytes),
        None => Err("payload が16進ではありません".to_owned()),
    };
    match result {
        Ok(()) => (StatusCode::ACCEPTED, Json(AnnounceResultJson::pushed())).into_response(),
        Err(message) => (
            StatusCode::CONFLICT,
            Json(ErrorJson {
                code: "InvalidArgument".to_owned(),
                message,
            }),
        )
            .into_response(),
    }
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
pub fn router(shared: Shared, submit: Submit) -> Router {
    Router::new()
        .route("/node/info", get(node_info))
        .route("/chain/info", get(chain_info))
        .route("/node/unlockedaccount", get(unlocked))
        .route("/heika/delegations", get(delegations))
        .route("/transactions", put(announce).options(preflight))
        .layer(map_response(allow_any_origin))
        .with_state(Api { shared, submit })
}

/// `addresses` のそれぞれで待ち受け、`stop` が立つまで答える。呼んだスレッドで tokio を回す
pub fn serve(
    addresses: &[String],
    shared: Shared,
    submit: Submit,
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
            let app = router(Arc::clone(&shared), Arc::clone(&submit));
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
                node_public_key: "CC".to_owned(),
            },
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
        let response = router(shared, submit(Arc::default()))
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
        // 駆動役が書き換えたら、次の問い合わせから新しいものを返す
        shared.write().unwrap().chain = ChainInfoJson::new(11, 11, 1, 3, 9, "DD".to_owned());
        let (_, chain) = get(shared, "/chain/info").await;
        assert_eq!(chain["height"], "11");
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
        let response = router(snapshot(), submit(Arc::clone(received)))
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
        let response = router(snapshot(), submit(Arc::default()))
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
