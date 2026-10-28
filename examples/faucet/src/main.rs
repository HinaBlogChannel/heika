//! 蛇口。ページ 1 枚と、それが使う API を出し、受け付けたものをまとめて 1 つのアグリゲートで送る。
//!
//! ```sh
//! faucet <ノードの設定> <蛇口の設定>
//! ```
//!
//! ノードの設定は `heika experimental peer start` と同じもので、ネットワークと REST（最初の `rest` の口）を決める。
//!
//! - `GET /`: ページ
//! - `GET /api/info`: 1 回に配る量と待ち時間
//! - `GET /api/challenge?address=…`: もらえるかを確かめ、解かせるパズルを返す
//! - `POST /api/claim`: パズルの答えを出して、受け付けてもらう
//! - `GET /api/claims/{id}`: 受け付けたものが、どうなったか

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{ConnectInfo, Path as UrlPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use faucet::{Budget, Cooldown, FaucetConfig, Manifest, Puzzle, human, random_id};
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest as NodeManifest;
use heika_node::driver;
use heika_node::keys::{others_can_read, read_private_key};
use heika_rest::node::TransactionFeesJson;
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body};
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, Transaction, Transfer, UnresolvedAddress,
    UnresolvedMosaicId,
};
use serde::{Deserialize, Serialize};

/// ページ。JS も CSS も中に書いてある
const PAGE: &str = include_str!("../index.html");
/// 出したまま解かれていないパズルの数の上限。これを超えたら、しばらく新しく出さない
const MAX_CHALLENGES: usize = 10_000;
/// 送ったトランザクションの期限
const LIFETIME: Duration = Duration::from_secs(60 * 60);
/// 終わった受付を覚えておく長さ
const KEEP_CLAIMS: Duration = Duration::from_secs(60 * 60);

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
});

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [node, faucet] = args.as_slice() else {
        eprintln!("使い方: faucet <ノードの設定> <蛇口の設定>");
        return ExitCode::from(2);
    };
    match run(Path::new(node), Path::new(faucet)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run(node: &Path, faucet: &Path) -> Result<(), String> {
    let node = NodeManifest::load(node).map_err(|error| error.to_string())?;
    let parameters = driver::network_parameters(&node.spec).map_err(|error| error.to_string())?;
    let listen = &node
        .spec
        .rest
        .first()
        .ok_or("ノードの設定に rest がありません")?
        .address;
    let rest = format!("http://{}", listen.replace("0.0.0.0", "127.0.0.1"));
    let text = std::fs::read_to_string(faucet)
        .map_err(|error| format!("{}: {error}", faucet.display()))?;
    let config = Manifest::parse(&text)?.spec;
    if others_can_read(&config.signer).unwrap_or(false) {
        eprintln!("{} は、持ち主のほかも読めます", config.signer.display());
    }
    let key = read_private_key(&config.signer).map_err(|error| error.to_string())?;
    let signer = PublicKey::from_private_key(&key);
    let max_transfers = config
        .batch
        .max_transfers
        .min(parameters.max_transactions_per_aggregate);
    let now = Instant::now();
    let app = Arc::new(App {
        state: Mutex::new(Shared {
            budget: Budget::new(&config.budget, now),
            cooldown: Cooldown::new(Duration::from_secs(config.cooldown_seconds)),
            challenges: HashMap::new(),
            queue: Vec::new(),
            claims: HashMap::new(),
        }),
        config,
        parameters,
        rest,
        key,
        signer,
        max_transfers,
    });
    println!(
        "{} から配ります。ページ: http://{}",
        Address::from_public_key(&signer, parameters.identifier),
        app.config.listen
    );

    tokio::spawn(send_batches(app.clone()));
    let router = Router::new()
        .route("/", get(|| async { Html(PAGE) }))
        .route("/api/info", get(info))
        .route("/api/challenge", get(challenge))
        .route("/api/claim", post(claim))
        .route("/api/claims/{id}", get(claim_status))
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind(&app.config.listen)
        .await
        .map_err(|error| format!("{}: {error}", app.config.listen))?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|error| error.to_string())
}

struct App {
    state: Mutex<Shared>,
    config: FaucetConfig,
    parameters: &'static NetworkParameters,
    /// ノードの REST（`http://127.0.0.1:3000` など）
    rest: String,
    key: PrivateKey,
    signer: PublicKey,
    max_transfers: usize,
}

impl App {
    fn state(&self) -> MutexGuard<'_, Shared> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 接続元。設定にヘッダーがあれば、その最後の値（手前のリバースプロキシが足したもの）
    fn client(&self, peer: SocketAddr, headers: &HeaderMap) -> String {
        let forwarded = self.config.client_address_header.as_ref().and_then(|name| {
            let value = headers
                .get_all(name.as_str())
                .iter()
                .next_back()?
                .to_str()
                .ok()?;
            Some(value.rsplit(',').next()?.trim().to_owned())
        });
        forwarded.unwrap_or_else(|| peer.ip().to_string())
    }

    /// ネットワークの時刻（エポックからのミリ秒）
    fn now(&self) -> Result<u64, String> {
        self.parameters
            .timestamp_at(SystemTime::now())
            .map(|timestamp| timestamp.0)
            .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
    }
}

struct Shared {
    budget: Budget,
    cooldown: Cooldown,
    challenges: HashMap<String, Challenge>,
    /// まだ送っていない受付の ID
    queue: Vec<String>,
    claims: HashMap<String, Claim>,
}

impl Shared {
    /// アドレスと接続元の、どちらかがまだ待つなら、そのわけ
    fn waiting(&self, address: &str, client: &str, now: Instant) -> Option<Rejection> {
        let left = self
            .cooldown
            .waiting(address, now)
            .max(self.cooldown.waiting(client, now))?;
        Some(Rejection::busy(format!(
            "もうもらっています。あと {} 待ってください",
            human(left)
        )))
    }
}

struct Challenge {
    address: Address,
    client: String,
    puzzle: Puzzle,
    expires: Instant,
}

struct Claim {
    address: Address,
    client: String,
    state: ClaimState,
    /// 終わった時刻。終わっていなければ `None`
    done: Option<Instant>,
}

#[derive(Clone, Serialize)]
#[serde(tag = "state")]
enum ClaimState {
    Queued,
    Announced { hash: String },
    Confirmed { hash: String, height: String },
    Failed { reason: String },
}

/// 断るときの答え
struct Rejection {
    status: StatusCode,
    message: String,
}

impl Rejection {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn busy(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            message: String,
        }
        (
            self.status,
            Json(Body {
                message: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Info {
    amount: u64,
    cooldown_seconds: u64,
}

async fn info(State(app): State<Arc<App>>) -> Json<Info> {
    Json(Info {
        amount: app.config.amount,
        cooldown_seconds: app.config.cooldown_seconds,
    })
}

#[derive(Deserialize)]
struct ChallengeQuery {
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeJson {
    id: String,
    bits: u32,
    count: u32,
    expected_seconds: f64,
}

async fn challenge(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeJson>, Rejection> {
    let address: Address = query
        .address
        .trim()
        .replace('-', "")
        .to_uppercase()
        .parse()
        .map_err(|_| Rejection::bad("アドレスが読めません"))?;
    if address.network() != app.parameters.identifier {
        return Err(Rejection::bad("このネットワークのアドレスではありません"));
    }
    let client = app.client(peer, &headers);
    let now = Instant::now();
    let mut state = app.state();
    if let Some(rejection) = state.waiting(&address.to_string(), &client, now) {
        return Err(rejection);
    }
    let remaining = state.budget.remaining(now);
    let lacking = (app.config.amount as f64 / app.config.budget.amount as f64) - remaining;
    if lacking > 0.0 {
        let left = Duration::from_secs(app.config.budget.period_seconds).mul_f64(lacking);
        return Err(Rejection::busy(format!(
            "今は配れる分がありません。{} ほどで戻ります",
            human(left)
        )));
    }
    // 同じ接続元の古いパズルと、期限の切れたパズルは捨てる
    state
        .challenges
        .retain(|_, challenge| challenge.client != client && challenge.expires > now);
    if state.challenges.len() >= MAX_CHALLENGES {
        return Err(Rejection::busy("混み合っています。少し待ってください"));
    }
    let puzzle = Puzzle::for_budget(&app.config.pow, remaining);
    let expected_seconds = puzzle.expected_seconds(app.config.pow.reference_hash_rate);
    // 遅い端末でも間に合うように、めやすの 10 倍と 5 分の長いほう
    let expires = now + Duration::from_secs_f64((expected_seconds * 10.0).max(300.0));
    let id = random_id();
    state.challenges.insert(
        id.clone(),
        Challenge {
            address,
            client,
            puzzle,
            expires,
        },
    );
    Ok(Json(ChallengeJson {
        id,
        bits: puzzle.bits,
        count: puzzle.count,
        expected_seconds,
    }))
}

#[derive(Deserialize)]
struct ClaimRequest {
    challenge: String,
    solutions: Vec<u64>,
}

#[derive(Serialize)]
struct ClaimJson {
    id: String,
}

async fn claim(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<ClaimRequest>,
) -> Result<Json<ClaimJson>, Rejection> {
    let client = app.client(peer, &headers);
    let now = Instant::now();
    let mut state = app.state();
    // 合っていても間違っていても、一度出したパズルはこれで使い終わり
    let challenge = state
        .challenges
        .remove(&request.challenge)
        .filter(|challenge| challenge.expires > now)
        .ok_or_else(|| Rejection::bad("パズルの期限が切れました。やり直してください"))?;
    let solved =
        request.solutions.len() == challenge.puzzle.count as usize
            && request.solutions.iter().zip(0..).all(|(&counter, index)| {
                challenge.puzzle.solved(&request.challenge, index, counter)
            });
    if !solved {
        return Err(Rejection::bad("パズルの答えが合っていません"));
    }
    let address = challenge.address.to_string();
    if let Some(rejection) = state.waiting(&address, &client, now) {
        return Err(rejection);
    }
    state.budget.take(app.config.amount, now).map_err(|left| {
        Rejection::busy(format!(
            "今は配れる分がありません。{} ほどで戻ります",
            human(left)
        ))
    })?;
    state.cooldown.record(address, now);
    state.cooldown.record(client.clone(), now);
    let id = request.challenge;
    state.queue.push(id.clone());
    state.claims.insert(
        id.clone(),
        Claim {
            address: challenge.address,
            client,
            state: ClaimState::Queued,
            done: None,
        },
    );
    Ok(Json(ClaimJson { id }))
}

async fn claim_status(
    State(app): State<Arc<App>>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<ClaimState>, Rejection> {
    let state = app.state();
    let claim = state.claims.get(&id).ok_or(Rejection {
        status: StatusCode::NOT_FOUND,
        message: "受け付けたものが見つかりません".into(),
    })?;
    Ok(Json(claim.state.clone()))
}

/// `batch.intervalSeconds` ごとに、たまった受付を 1 つのアグリゲートにして送る
async fn send_batches(app: Arc<App>) {
    let mut interval =
        tokio::time::interval(Duration::from_secs(app.config.batch.interval_seconds));
    loop {
        interval.tick().await;
        let batch: Vec<(String, Address)> = {
            let mut state = app.state();
            let now = Instant::now();
            state
                .claims
                .retain(|_, claim| claim.done.is_none_or(|done| now - done < KEEP_CLAIMS));
            let count = state.queue.len().min(app.max_transfers);
            let ids: Vec<String> = state.queue.drain(..count).collect();
            ids.into_iter()
                .filter_map(|id| {
                    let address = state.claims.get(&id)?.address;
                    Some((id, address))
                })
                .collect()
        };
        if batch.is_empty() {
            continue;
        }
        let worker = app.clone();
        let addresses: Vec<Address> = batch.iter().map(|(_, address)| *address).collect();
        let sent = tokio::task::spawn_blocking(move || worker.send(&addresses))
            .await
            .unwrap_or_else(|error| Err(error.to_string()));
        match sent {
            Ok(transaction) => {
                let hash = transaction
                    .hash(&app.parameters.generation_hash_seed)
                    .to_string();
                println!("{} 件をまとめて送りました（{hash}）", batch.len());
                app.update(&batch, ClaimState::Announced { hash });
                tokio::spawn(watch(app.clone(), batch, transaction));
            }
            Err(error) => {
                eprintln!("送れませんでした: {error}");
                app.fail(&batch, "送れませんでした。もう一度試してください");
            }
        }
    }
}

/// 承認されるか、期限が切れるまで見る
async fn watch(app: Arc<App>, batch: Vec<(String, Address)>, transaction: Transaction) {
    let path = TransactionStatus::path(&transaction, &app.parameters.generation_hash_seed);
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let worker = app.clone();
        let path = path.clone();
        let status = tokio::task::spawn_blocking(move || worker.get(&path))
            .await
            .unwrap_or_else(|error| Err(error.to_string()));
        let status = match status {
            Ok(Some(body)) => TransactionStatus::from_slice(&body).ok(),
            Ok(None) => None,
            Err(error) => {
                eprintln!("{error}");
                None
            }
        };
        match status {
            Some(status) if status.group == "confirmed" => {
                let height = status.height.unwrap_or_default();
                println!("高さ {height} で承認されました（{}）", status.hash);
                app.update(
                    &batch,
                    ClaimState::Confirmed {
                        hash: status.hash,
                        height,
                    },
                );
                return;
            }
            Some(status) if status.group == "failed" => {
                let code = status.code.unwrap_or_default();
                eprintln!("弾かれました: {code}（{}）", status.hash);
                // ブロックに入らなかったので、配っていない
                app.fail(&batch, &format!("弾かれました（{code}）"));
                return;
            }
            _ => {}
        }
        // heika のノードは、残高が足りないなどで外したものを failed にしない。期限が過ぎたら、もう入らない
        if app.now().is_ok_and(|now| now > transaction.deadline) {
            app.fail(&batch, "期限までに承認されませんでした");
            return;
        }
    }
}

impl App {
    fn update(&self, batch: &[(String, Address)], to: ClaimState) {
        let done = matches!(to, ClaimState::Confirmed { .. }).then(Instant::now);
        let mut state = self.state();
        for (id, _) in batch {
            if let Some(claim) = state.claims.get_mut(id) {
                claim.state = to.clone();
                claim.done = done;
            }
        }
    }

    /// 配れなかったので、予算と待ち時間を戻す
    fn fail(&self, batch: &[(String, Address)], reason: &str) {
        let now = Instant::now();
        let mut state = self.state();
        for (id, _) in batch {
            let Some(claim) = state.claims.get_mut(id) else {
                continue;
            };
            claim.state = ClaimState::Failed {
                reason: reason.to_owned(),
            };
            claim.done = Some(now);
            let (address, client) = (claim.address.to_string(), claim.client.clone());
            state.budget.give_back(self.config.amount);
            state.cooldown.forget(&address);
            state.cooldown.forget(&client);
        }
    }

    /// 受け付けたアドレスに 1 回分ずつ送るアグリゲートを作り、署名して送る
    fn send(&self, addresses: &[Address]) -> Result<Transaction, String> {
        let network = self.parameters.identifier;
        let transfers = addresses
            .iter()
            .map(|address| {
                let transfer = Transfer::new(
                    UnresolvedAddress::from(*address),
                    [(
                        UnresolvedMosaicId(self.parameters.currency_mosaic_id),
                        self.config.amount,
                    )]
                    .into(),
                    Vec::new(),
                )
                .expect("one mosaic and no message");
                EmbeddedTransaction::new(self.signer, network, Body::Transfer(transfer))
            })
            .collect();
        let aggregate = Aggregate::new(transfers).expect("no nested aggregates");
        let mut transaction = Transaction::new(
            self.signer,
            network,
            0,
            self.now()? + LIFETIME.as_millis() as u64,
            Body::AggregateComplete(aggregate),
        );
        transaction.fee = transaction.fee_for(self.fee_multiplier()?, 0);
        transaction
            .sign(&self.key, &self.parameters.generation_hash_seed)
            .map_err(|error| error.to_string())?;
        let response = AGENT
            .put(&format!("{}{ANNOUNCE_PATH}", self.rest))
            .header("Content-Type", "application/json")
            .send(announce_body(&transaction))
            .map_err(|error| format!("REST に送れませんでした: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "REST が受け付けませんでした: {}",
                response.status()
            ));
        }
        Ok(transaction)
    }

    /// 直近のブロックの中央値。ノードの下限より低ければ下限
    fn fee_multiplier(&self) -> Result<u32, String> {
        let body = self
            .get("/network/fees/transaction")?
            .ok_or("手数料の倍率が取れません")?;
        let fees: TransactionFeesJson =
            serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        Ok(fees.median_fee_multiplier.max(fees.min_fee_multiplier))
    }

    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let mut response = AGENT
            .get(&format!("{}{path}", self.rest))
            .call()
            .map_err(|error| format!("{path}: {error}"))?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .read_to_vec()
                .map(Some)
                .map_err(|error| format!("{path}: {error}")),
            404 => Ok(None),
            status => Err(format!("{path}: {status}")),
        }
    }
}
