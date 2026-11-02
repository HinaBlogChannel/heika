//! DB を持ち、REST から同期する Web Worker。
//!
//! Web Locks でオリジンに1つだけにしてから動く。画面から REST のオリジンの一覧を受け取ったら、そのネットワークの
//! DB を OPFS に開き、確定した高さまで、取る、確かめて実行する、書く、を繰り返す。追いついたら、少し待って続きを見る。
//!
//! 画面から受け取るもの:
//! - `["sync", オリジンを改行で区切った文字列]`: 同期を始める
//! - `["stop"]`: 今の区切りを書いてから止める
//!
//! 画面に送るもの:
//! - `["waiting"]`: ほかのタブの Worker が DB を持っている。そのタブが閉じるまで待つ
//! - `["ready"]`: DB を持てた。同期を始められる
//! - `["status", 文]`: いまやっていること
//! - `["progress", ネットワーク, 書いた高さ, 確定した高さ, 1 秒あたりのブロック, StateHash, ファイルのバイト数]`
//! - `["warning", 文]`: 1つの REST が取れないか、正しくないものを返した。ほかの REST で続ける
//! - `["stopped"]` と `["error", 理由]`: 同期が終わった

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use futures::channel::oneshot;
use heika_store_redb::Db;
use heika_store_redb::replay::{Replay, ReplayError};
use js_sys::Array;
use node_web::rest::{self, FetchError, Network, PAGE_SIZE};
use node_web::{OpfsFile, hold_lock};
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

/// DB を持つ Worker を1つにするロックの名前
const LOCK: &str = "heika-node-web/db";
/// redb のキャッシュの上限
const CACHE_SIZE: usize = 64 << 20;
/// 少なくともこの間隔（ミリ秒）でコミットする。短いほど止めたときに失うものが少ないが、書く回数が増える
const COMMIT_EVERY_MS: f64 = 5_000.0;
/// 追いついたあと、確定した高さを見直すまで待つ時間（ミリ秒）
const IDLE_MS: i32 = 30_000;
/// 取れなかったとき、次に取りに行くまで待つ時間（ミリ秒）
const RETRY_MS: i32 = 3_000;

/// 開いた DB。ネットワークごとに別のファイルにする
struct Opened {
    network: &'static str,
    db: Rc<Db>,
    file: OpfsFile,
}

thread_local! {
    static OPENED: RefCell<Option<Opened>> = const { RefCell::new(None) };
}

fn scope() -> DedicatedWorkerGlobalScope {
    js_sys::global().unchecked_into()
}

fn post(parts: &[JsValue]) {
    let _ = scope().post_message(&parts.iter().collect::<Array>());
}

fn status(text: &str) {
    post(&["status".into(), text.into()]);
}

fn now() -> f64 {
    scope()
        .performance()
        .map_or(0.0, |performance| performance.now())
}

fn main() {
    wasm_bindgen_futures::spawn_local(async {
        let waiting = || post(&["waiting".into()]);
        if let Err(error) = hold_lock(LOCK, waiting).await {
            post(&["error".into(), format!("{error:?}").into()]);
            return;
        }
        let stopping = Rc::new(Cell::new(false));
        let running = Rc::new(Cell::new(false));
        let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
            let message: Array = event.data().unchecked_into();
            match message.get(0).as_string().as_deref() {
                Some("sync") if !running.get() => {
                    let origins = message.get(1).as_string().unwrap_or_default();
                    running.set(true);
                    stopping.set(false);
                    let (running, stopping) = (running.clone(), stopping.clone());
                    wasm_bindgen_futures::spawn_local(async move {
                        match sync(&origins, &stopping).await {
                            Ok(()) => post(&["stopped".into()]),
                            Err(error) => post(&["error".into(), error.into()]),
                        }
                        running.set(false);
                    });
                }
                Some("stop") => stopping.set(true),
                _ => {}
            }
        });
        scope().set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        // Worker が終わるまで受け取り続けるので、放さない
        onmessage.forget();
        post(&["ready".into()]);
    });
}

/// オリジンの一覧を読む。空行と、末尾の `/` は除く
fn origins(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.trim().trim_end_matches('/').to_owned())
        .filter(|line| !line.is_empty())
        .collect()
}

/// `network` の DB を開く。もう開いていればそれを使う。別のネットワークのものを開いていれば断る
async fn open(network: &'static str) -> Result<(Rc<Db>, OpfsFile), String> {
    if let Some(opened) = OPENED.with_borrow(|opened| {
        opened
            .as_ref()
            .map(|opened| (opened.network, opened.db.clone(), opened.file.clone()))
    }) {
        return match opened {
            (name, db, file) if name == network => Ok((db, file)),
            (name, _, _) => Err(format!(
                "{name} の DB を開いています。{network} を同期するなら、ページを読み込み直してください"
            )),
        };
    }
    let file = OpfsFile::open(&format!("heika-{network}.redb"))
        .await
        .map_err(|error| format!("OPFS を開けません: {error:?}"))?;
    let db = Rc::new(
        Db::open_with_backend(file.clone(), CACHE_SIZE).map_err(|error| error.to_string())?,
    );
    OPENED.with_borrow_mut(|opened| {
        *opened = Some(Opened {
            network,
            db: db.clone(),
            file: file.clone(),
        });
    });
    Ok((db, file))
}

/// 1つの区切りを取る。すぐに取りに行き、結果は受け取り口で待つ（取っているあいだに、前の区切りを実行できる）
fn spawn_fetch(
    origin: String,
    from: u64,
    to: u64,
) -> oneshot::Receiver<Result<Vec<Vec<u8>>, FetchError>> {
    let (sender, receiver) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = sender.send(rest::fetch_blocks(&origin, from, to).await);
    });
    receiver
}

/// 止められるか、続けられなくなるまで同期する
async fn sync(text: &str, stopping: &Cell<bool>) -> Result<(), String> {
    let origins = origins(text);
    if origins.is_empty() {
        return Err("REST のオリジンを1つ以上入れてください".into());
    }
    status("REST のネットワークを確かめています");
    let mut network = None;
    let mut usable = Vec::new();
    for origin in &origins {
        let found = match rest::get_json(origin, "/node/info").await {
            Ok(info) => Network::from_node_info(&info),
            Err(error) => Err(error.to_string()),
        };
        match found {
            Err(error) => post(&[
                "warning".into(),
                format!("{origin} を使いません: {error}").into(),
            ]),
            Ok(found) => match &network {
                None => {
                    network = Some(found);
                    usable.push(origin.clone());
                }
                Some(Network { name, .. }) if *name == found.name => usable.push(origin.clone()),
                Some(Network { name, .. }) => post(&[
                    "warning".into(),
                    format!(
                        "{origin} は {} なので使いません（{name} を同期します）",
                        found.name
                    )
                    .into(),
                ]),
            },
        }
    }
    let network = network.ok_or("使える REST がありません")?;
    let (db, file) = open(network.name).await?;

    status("DB から続きを用意しています");
    let open_replay = || {
        Replay::open(
            &db,
            network.config.clone(),
            network.parameters,
            network.nemesis,
        )
        .map_err(|error| error.to_string())
    };
    let mut replay = open_replay()?;
    // 取る区切りごとに、使う REST を順に替える
    let mut turn = 0;
    let mut pick = || {
        turn += 1;
        usable[turn % usable.len()].clone()
    };
    // 同じ高さで続けて弾かれた数。どの REST でも弾かれるなら、止める
    let mut rejected = 0;
    let mut last_commit = now();
    let mut rate = Rate::new(replay.committed(), now());

    while !stopping.get() {
        let origin = pick();
        let target = match rest::finalized_height(&origin).await {
            Ok(target) => target,
            Err(error) => {
                post(&["warning".into(), format!("{origin}: {error}").into()]);
                rest::sleep(RETRY_MS).await;
                continue;
            }
        };
        if replay.height() >= target {
            report(&network, &replay, target, &rate, &file);
            status("確定した高さに追いつきました。続きを待っています");
            for _ in 0..IDLE_MS / 1000 {
                if stopping.get() {
                    break;
                }
                rest::sleep(1000).await;
            }
            continue;
        }
        status("同期しています");

        // 1つ先の区切りを取りながら、手元の区切りを実行する
        let range = |from: u64| (from, (from + PAGE_SIZE - 1).min(target));
        let (from, mut to) = range(replay.height() + 1);
        let mut current = (origin.clone(), spawn_fetch(origin, from, to));
        loop {
            let (source, receiver) = current;
            let fetched = receiver.await.unwrap_or_else(|_| {
                Err(FetchError::Unavailable("取るのが途中で止まりました".into()))
            });
            let next_from = to + 1;
            let ahead = (next_from <= target && !stopping.get()).then(|| {
                let origin = pick();
                let (next_from, next_to) = range(next_from);
                (
                    origin.clone(),
                    spawn_fetch(origin, next_from, next_to),
                    next_to,
                )
            });

            let blocks = match fetched {
                Ok(blocks) => blocks,
                Err(error) => {
                    post(&["warning".into(), format!("{source}: {error}").into()]);
                    rest::sleep(RETRY_MS).await;
                    break;
                }
            };
            let mut failure = None;
            for bytes in blocks {
                if let Err(error) = replay.push(bytes) {
                    failure = Some(error);
                    break;
                }
            }
            match failure {
                None => rejected = 0,
                Some(ReplayError::Invalid { height, reason }) => {
                    // 書きかけは捨て、最後のコミットから開き直す。続けて弾かれるなら、自分の側の問題かもしれない
                    rejected += 1;
                    post(&[
                        "warning".into(),
                        format!("{source} の高さ {height} を弾きました: {reason}").into(),
                    ]);
                    if rejected > usable.len() {
                        return Err(format!(
                            "高さ {height} を、どの REST から取っても確かめられません: {reason}"
                        ));
                    }
                    drop(replay);
                    replay = open_replay()?;
                    break;
                }
                Some(error) => return Err(error.to_string()),
            }

            let reached = replay.height() >= target;
            if reached || stopping.get() || now() - last_commit >= COMMIT_EVERY_MS {
                replay.commit().map_err(|error| error.to_string())?;
                last_commit = now();
                rate.update(replay.committed(), last_commit);
                report(&network, &replay, target, &rate, &file);
            }
            match ahead {
                Some((origin, receiver, next_to)) if !stopping.get() => {
                    to = next_to;
                    current = (origin, receiver);
                }
                _ => break,
            }
        }
    }
    replay.commit().map_err(|error| error.to_string())?;
    report_final(&network, &replay, &file);
    Ok(())
}

/// 書いた高さの伸びから求めた、1 秒あたりのブロック。直近の 30 秒ほどで均す
struct Rate {
    samples: Vec<(u64, f64)>,
}

impl Rate {
    fn new(height: u64, at: f64) -> Self {
        Self {
            samples: vec![(height, at)],
        }
    }

    fn update(&mut self, height: u64, at: f64) {
        self.samples.push((height, at));
        let keep_after = at - 30_000.0;
        while self.samples.len() > 2 && self.samples[1].1 < keep_after {
            self.samples.remove(0);
        }
    }

    fn per_second(&self) -> f64 {
        let (first, last) = (self.samples[0], self.samples[self.samples.len() - 1]);
        let seconds = (last.1 - first.1) / 1000.0;
        if seconds <= 0.0 {
            return 0.0;
        }
        (last.0 - first.0) as f64 / seconds
    }
}

fn report(network: &Network, replay: &Replay<'_>, target: u64, rate: &Rate, file: &OpfsFile) {
    post(&[
        "progress".into(),
        network.name.into(),
        (replay.committed() as f64).into(),
        (target as f64).into(),
        rate.per_second().into(),
        replay
            .state_hash()
            .map(|hash| hash.to_string())
            .unwrap_or_default()
            .into(),
        (file.size().unwrap_or(0) as f64).into(),
    ]);
}

fn report_final(network: &Network, replay: &Replay<'_>, file: &OpfsFile) {
    post(&[
        "progress".into(),
        network.name.into(),
        (replay.committed() as f64).into(),
        JsValue::NULL,
        0.0.into(),
        replay
            .state_hash()
            .map(|hash| hash.to_string())
            .unwrap_or_default()
            .into(),
        (file.size().unwrap_or(0) as f64).into(),
    ]);
}
