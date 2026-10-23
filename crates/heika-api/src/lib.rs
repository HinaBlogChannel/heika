//! heika のノードの REST。catapult の REST のうち、ウォレットが委任に使う口と、heika だけの口を返す。
//!
//! - `/node/info`: ノードの身元と、委任の鍵（`nodePublicKey`）
//! - `/chain/info`: 高さ、スコア、確定したブロック
//! - `/node/unlockedaccount`: ハーベストしている、委任されたリモートの鍵
//! - `/heika/delegations`: 届いた委任の要求ごとに、引き受けたか、待っているか、なぜ引き受けなかったか
//!
//! ノードの駆動役が [`Snapshot`] を書き換え、ここは読んで返すだけにする。チェーンの本体には触らない。
//! catapult の REST と同じく、どこのページからでも読めるようにする（CORS）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN;
use axum::middleware::map_response;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use heika_rest::node::{ChainInfoJson, DelegationJson, NodeInfoJson, UnlockedAccountJson};

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

/// 止める合図を見に行く間隔
const STOP_POLL: Duration = Duration::from_millis(200);

fn read(shared: &Shared) -> Snapshot {
    // 書く側が落ちていても、最後に書いたものを返す
    shared
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

async fn node_info(State(shared): State<Shared>) -> Json<NodeInfoJson> {
    Json(read(&shared).node)
}

async fn chain_info(State(shared): State<Shared>) -> Json<ChainInfoJson> {
    Json(read(&shared).chain)
}

async fn unlocked(State(shared): State<Shared>) -> Json<UnlockedAccountJson> {
    Json(read(&shared).unlocked)
}

async fn delegations(State(shared): State<Shared>) -> Json<Vec<DelegationJson>> {
    Json(read(&shared).delegations)
}

async fn allow_any_origin(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response
}

/// 口の並び
pub fn router(shared: Shared) -> Router {
    Router::new()
        .route("/node/info", get(node_info))
        .route("/chain/info", get(chain_info))
        .route("/node/unlockedaccount", get(unlocked))
        .route("/heika/delegations", get(delegations))
        .layer(map_response(allow_any_origin))
        .with_state(shared)
}

/// `addresses` のそれぞれで待ち受け、`stop` が立つまで答える。呼んだスレッドで tokio を回す
pub fn serve(addresses: &[String], shared: Shared, stop: Arc<AtomicBool>) -> Result<(), String> {
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
            let (app, stop) = (router(Arc::clone(&shared)), Arc::clone(&stop));
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
        let response = router(shared)
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
}
