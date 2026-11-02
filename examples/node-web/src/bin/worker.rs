//! DB を持ち、REST から同期する Web Worker。
//!
//! Web Locks でオリジンに1つだけにしてから動く。画面から REST のオリジンの一覧を受け取ったら、そのネットワークの
//! DB を OPFS に開き、確定した高さまで、取る、確かめて実行する、書く、を繰り返す。追いついたら、少し待って続きを見る。
//!
//! 画面から受け取るもの:
//! - `["sync", オリジンを改行で区切った文字列, ハーベスト]`: 同期を始める。ハーベストは、しないなら `null`、するなら
//!   `[署名の鍵, VRF の鍵, ブロックを出す REST のオリジンを改行で区切った文字列]`。鍵は16進の秘密鍵で、委任だけで
//!   ハーベストするなら空にする
//! - `["stop"]`: 今の区切りを書いてから止める
//! - `["import", File]`: 手元のノードの DB（redb）を、そのネットワークの DB として OPFS に写す。同期していないときだけ
//!
//! 画面に送るもの:
//! - `["waiting"]`: ほかのタブの Worker が DB を持っている。そのタブが閉じるまで待つ
//! - `["ready", ノードの公開鍵]`: DB を持てた。同期を始められる。委任は、ノードの公開鍵あてに送ってもらう
//! - `["status", 文]`: いまやっていること
//! - `["progress", ネットワーク, 書いた高さ, 確定した高さ, 1 秒あたりのブロック, StateHash, ファイルのバイト数]`
//! - `["warning", 文]`: 1つの REST が取れないか、正しくないものを返した。ほかの REST で続ける
//! - `["stopped"]` と `["error", 理由]`: 同期が終わった
//! - `["imported", ネットワーク, 先端の高さ]`: 写し終えた
//! - `["tip", ネットワーク, 手元の先端の高さ, REST の言う先端の高さ, ファイルのバイト数, 先端のブロックのハッシュ]`:
//!   確定した先の先端を追っている
//! - `["plan", 文]`: ハーベストするとき、次の当たり
//! - `["harvested", 文]`: ハーベストしてブロックを作ったか、それを REST に出した結果
//! - `["delegations", [[要求の高さ, メインアカウントのアドレス（なければ空）, 使っているか, わけ], …]]`: 届いた委任

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use heika_block::Block;
use heika_chain::chain::Keep;
use heika_chain::chain::{Action, Chain, HarvestPlan, Notice, Outcome};
use heika_chain::env::Env;
use heika_chain::event::{ChainEvent, PeerCommand, PeerId};
use heika_chain::store::EXECUTOR_META;
use heika_chain::verify::{Tip, verify_alone};
use heika_core::key::PrivateKey;
use heika_mempool::{Config as MempoolConfig, Mempool, SharedMempool};
use heika_store_redb::Db;
use heika_store_redb::replay::{Replay, ReplayError};
use js_sys::Array;
use node_web::delegation::{Delegations, NodeKey};
use node_web::rest::{self, FetchError, Network, PAGE_SIZE};
use node_web::{OpfsFile, hold_lock, remove, rename};
use wasm_bindgen::prelude::*;
use web_sys::{Blob, DedicatedWorkerGlobalScope, MessageEvent};

/// DB を持つ Worker を1つにするロックの名前
const LOCK: &str = "heika-node-web/db";
/// redb のキャッシュの上限
const CACHE_SIZE: usize = 64 << 20;
/// 当たりがこれより近ければ（ミリ秒）、未承認のトランザクションを取りに行く。遠いうちは REST に頼まない
const PENDING_AHEAD_MS: u128 = 60_000;
/// 当たりが近いあいだ、未承認のトランザクションを取り直す間隔（ミリ秒）
const PENDING_EVERY_MS: f64 = 5_000.0;
/// 未承認のトランザクションを取るページの数の上限（1 ページ 100 件）
const PENDING_PAGES: u32 = 10;
/// 委任の要求を REST で探し直し、状態で確かめ直す間隔（ミリ秒）
const DELEGATION_MS: f64 = 60_000.0;
/// 少なくともこの間隔（ミリ秒）でコミットする。短いほど止めたときに失うものが少ないが、書く回数が増える
const COMMIT_EVERY_MS: f64 = 5_000.0;
/// 先端を追うあいだ、中核に Tick を入れる間隔（ミリ秒）。ノードと同じ 5 秒
const TICK_MS: i32 = 5_000;
/// 中核が外した REST を、また使い始めるまでの時間（ミリ秒）
const READD_MS: i32 = 60_000;
/// 取れなかったとき、次に取りに行くまで待つ時間（ミリ秒）
const RETRY_MS: i32 = 3_000;
/// ライトのノードと同じ残し方。状態と木の差分は確定から 2 エポック分、ブロックとステートメントは再開に要る分だけ残す
const KEEP: Keep = Keep {
    state: 2,
    trie: 2,
    history: true,
};

/// 開いた DB。ネットワークごとに別のファイルにする
struct Opened {
    network: &'static str,
    db: Rc<Db>,
    file: OpfsFile,
}

thread_local! {
    static OPENED: RefCell<Option<Opened>> = const { RefCell::new(None) };
    /// ノードの鍵。委任の要求を開くのに使う
    static NODE_KEY: RefCell<Option<NodeKey>> = const { RefCell::new(None) };
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
        // 鍵を作るのは、ロックを持ってから（2つのタブで別々に作らないように）
        let node_key = match NodeKey::load_or_create().await {
            Ok(key) => {
                let public_key = key.public_key.to_string();
                NODE_KEY.with_borrow_mut(|node_key| *node_key = Some(key));
                public_key
            }
            Err(error) => {
                post(&[
                    "warning".into(),
                    format!("委任は受けられません: {error}").into(),
                ]);
                String::new()
            }
        };
        let stopping = Rc::new(Cell::new(false));
        let running = Rc::new(Cell::new(false));
        let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
            let message: Array = event.data().unchecked_into();
            match message.get(0).as_string().as_deref() {
                Some("sync") if !running.get() => {
                    let origins = message.get(1).as_string().unwrap_or_default();
                    let harvest = message.get(2);
                    let harvest = (!harvest.is_null() && !harvest.is_undefined()).then(|| {
                        let harvest: Array = harvest.unchecked_into();
                        let text = |index| harvest.get(index).as_string().unwrap_or_default();
                        (text(0), text(1), text(2))
                    });
                    running.set(true);
                    stopping.set(false);
                    let (running, stopping) = (running.clone(), stopping.clone());
                    wasm_bindgen_futures::spawn_local(async move {
                        match sync(&origins, harvest, &stopping).await {
                            Ok(()) => post(&["stopped".into()]),
                            Err(error) => post(&["error".into(), error.into()]),
                        }
                        running.set(false);
                    });
                }
                Some("stop") => stopping.set(true),
                Some("import") if !running.get() => {
                    let blob: Blob = message.get(1).unchecked_into();
                    running.set(true);
                    let running = running.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Err(error) = import(&blob).await {
                            post(&["error".into(), error.into()]);
                        }
                        running.set(false);
                    });
                }
                _ => {}
            }
        });
        scope().set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        // Worker が終わるまで受け取り続けるので、放さない
        onmessage.forget();
        post(&["ready".into(), node_key.into()]);
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

/// 読み込みの途中のファイルの名前。確かめてから、ネットワークの DB の名前に変える
const IMPORTING: &str = "heika-import.redb";

/// 手元のノードの DB を、そのネットワークの DB として写す。開いている DB は閉じる。
///
/// ここで確かめるのは、redb として開けて、実行した状態と先端のブロックがあり、ネットワークがわかることまで。
/// 本物のチェーンのものかは、同期を続けたときに、REST から取った次のブロックが先端につながるかで確かめる
async fn import(blob: &Blob) -> Result<(), String> {
    let js = |error: JsValue| format!("{error:?}");
    if let Some(opened) = OPENED.take() {
        drop(opened.db);
        opened.file.close();
    }
    let mut shown = -1.0;
    let file = OpfsFile::import(blob, IMPORTING, |done, total| {
        let percent = (done / total * 100.0).floor();
        if percent > shown {
            shown = percent;
            status(&format!("DB を写しています（{percent:.0}%）"));
        }
    })
    .await
    .map_err(js)?;

    status("写した DB を確かめています");
    let checked = (|| -> Result<(&'static str, u64), String> {
        let db =
            Db::open_with_backend(file.clone(), CACHE_SIZE).map_err(|error| error.to_string())?;
        if db
            .meta(EXECUTOR_META)
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err("実行した状態がない DB です".into());
        }
        let tip = db.blocks_tip().map_err(|error| error.to_string())?;
        let bytes = db
            .block(tip)
            .map_err(|error| error.to_string())?
            .ok_or("先端のブロックがありません")?;
        let block = Block::from_bytes(&bytes).map_err(|error| error.to_string())?;
        let network = match block.network {
            heika_core::network::NetworkIdentifier::MAINNET => "mainnet",
            heika_core::network::NetworkIdentifier::TESTNET => "testnet",
            _ => {
                return Err(
                    "メインネットとテストネットのほかの DB には、まだ対応していません".into(),
                );
            }
        };
        Ok((network, tip))
    })();
    file.close();
    let (network, tip) = match checked {
        Ok(checked) => checked,
        Err(error) => {
            let _ = remove(IMPORTING).await;
            return Err(format!("写した DB を使えません: {error}"));
        }
    };
    let target = format!("heika-{network}.redb");
    remove(&target).await.map_err(js)?;
    rename(IMPORTING, &target).await.map_err(js)?;
    post(&["imported".into(), network.into(), (tip as f64).into()]);
    Ok(())
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

/// ハーベストに使うもの
struct Harvest {
    /// 直接入れた、署名の鍵（リモートならリモートの鍵）と VRF の鍵。メモリにだけ置く
    keys: Vec<(PrivateKey, PrivateKey)>,
    /// 委任を受けるノードの鍵。作れなかったら `None`
    node_key: Option<NodeKey>,
    /// 作ったブロックを出す heika のノードの REST
    submit: Vec<String>,
}

/// 画面から受け取った鍵とオリジンを読む
fn harvest(signing: &str, vrf: &str, submit: &str) -> Result<Harvest, String> {
    let key = |text: &str, name: &str| {
        text.trim()
            .parse::<PrivateKey>()
            .map_err(|error| format!("{name}を読めません: {error}"))
    };
    let keys = match (signing.trim().is_empty(), vrf.trim().is_empty()) {
        (true, true) => Vec::new(),
        _ => vec![(key(signing, "署名の鍵")?, key(vrf, "VRF の鍵")?)],
    };
    let node_key = NODE_KEY.with_borrow(Clone::clone);
    if keys.is_empty() && node_key.is_none() {
        return Err("委任を受けられないので、ハーベストするなら鍵を直接入れてください".into());
    }
    let submit = origins(submit);
    if submit.is_empty() {
        return Err(
            "ハーベストするなら、ブロックを出す heika の REST を1つ以上入れてください".into(),
        );
    }
    Ok(Harvest {
        keys,
        node_key,
        submit,
    })
}

/// 止められるか、続けられなくなるまで同期する
async fn sync(
    text: &str,
    harvest_input: Option<(String, String, String)>,
    stopping: &Cell<bool>,
) -> Result<(), String> {
    let origins = origins(text);
    if origins.is_empty() {
        return Err("REST のオリジンを1つ以上入れてください".into());
    }
    let mut harvest = harvest_input
        .map(|(signing, vrf, submit)| self::harvest(&signing, &vrf, &submit))
        .transpose()?;
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
    if let Some(harvest) = &mut harvest {
        status("ブロックを出す REST を確かめています");
        let mut checked = Vec::new();
        for origin in &harvest.submit {
            let found = match rest::get_json(origin, "/node/info").await {
                Ok(info) => Network::from_node_info(&info).map(|found| found.name),
                Err(error) => Err(error.to_string()),
            };
            match found {
                Ok(name) if name == network.name => checked.push(origin.clone()),
                Ok(name) => post(&[
                    "warning".into(),
                    format!("{origin} は {name} なので、ブロックを出しません").into(),
                ]),
                Err(error) => post(&[
                    "warning".into(),
                    format!("{origin} にブロックを出しません: {error}").into(),
                ]),
            }
        }
        if checked.is_empty() {
            return Err("ブロックを出せる REST がありません".into());
        }
        harvest.submit = checked;
    }
    let (db, file) = open(network.name).await?;

    loop {
        if !catch_up(&db, &file, &network, &usable, stopping).await? {
            return Ok(());
        }
        match follow_tip(&db, &file, &network, &usable, harvest.as_ref(), stopping).await? {
            TipEnd::Behind => continue,
            TipEnd::Stopped => return Ok(()),
        }
    }
}

/// 確定した高さまで、取る、確かめて実行する、書くを繰り返し、確定の証明をしまう。止められたら偽
async fn catch_up(
    db: &Db,
    file: &OpfsFile,
    network: &Network,
    usable: &[String],
    stopping: &Cell<bool>,
) -> Result<bool, String> {
    status("DB から続きを用意しています");
    let open_replay = || {
        Replay::open(
            db,
            network.config.clone(),
            network.parameters,
            network.nemesis,
            Some(KEEP),
            true,
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
        let finalized = match rest::chain_info(&origin).await {
            Ok((_, finalized)) => finalized,
            Err(error) => {
                post(&["warning".into(), format!("{origin}: {error}").into()]);
                rest::sleep(RETRY_MS).await;
                continue;
            }
        };
        let target = finalized.height;
        replay
            .set_target(target)
            .map_err(|error| error.to_string())?;
        if replay.height() >= target {
            // 確定したブロックの証明を、実行して求めた投票者で確かめてしまう。先端を追う Chain は、これを確定として読む
            status("確定の証明を確かめています");
            let epoch = finalized.round.epoch;
            let stored = match rest::fetch_proof(&origin, epoch).await {
                Ok(Some(proof)) => replay.store_proof(epoch, &proof),
                Ok(None) => Err(ReplayError::Failed(format!(
                    "エポック {epoch} の証明がまだありません"
                ))),
                Err(error) => Err(ReplayError::Failed(error.to_string())),
            };
            match stored {
                Ok(Some(_)) => {
                    report(network, &replay, target, &rate, file);
                    return Ok(true);
                }
                // 証明が、まだ実行していない高さを指している。もう少し進める
                Ok(None) => continue,
                Err(error) => {
                    post(&["warning".into(), format!("{origin}: {error}").into()]);
                    rest::sleep(RETRY_MS).await;
                    continue;
                }
            }
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
                report(network, &replay, target, &rate, file);
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
    report_final(network, &replay, file);
    Ok(false)
}

/// 先端を追う段階が終わったわけ
enum TipEnd {
    /// 確定が先に進みすぎた。追いつく段階に戻る
    Behind,
    Stopped,
}

/// ブラウザの時計
struct BrowserEnv;

impl Env for BrowserEnv {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs_f64(js_sys::Date::now() / 1000.0)
    }
}

/// 確定した先の先端を、巻き戻しのある中核（[`Chain`]）で追う。中核がピアに頼むことに、REST で答える。
/// REST の1つを1つのピアとして扱う
async fn follow_tip(
    db: &Db,
    file: &OpfsFile,
    network: &Network,
    usable: &[String],
    harvest: Option<&Harvest>,
    stopping: &Cell<bool>,
) -> Result<TipEnd, String> {
    status("先端を追う用意をしています");
    let env = BrowserEnv;
    let mut chain = Chain::new(db, &env, network.config.clone(), network.parameters, true)
        .await
        .map_err(|error| format!("先端の段階を始められません: {error}"))?;
    chain.set_keep(KEEP);
    // ハーベストに使っている署名の鍵の公開鍵。変わったときだけ中核に渡す
    let mut harvesting: Vec<heika_core::key::PublicKey> = Vec::new();
    let mut delegations = Delegations::default();
    let mut last_scan = f64::NEG_INFINITY;
    let mut scan_turn = 0;
    // 未承認のトランザクションの置き場。受け付けるときに署名と規則を確かめ、状態に依ることは作るときに確かめる
    let mempool = Arc::new(SharedMempool::new(Mempool::new(
        network.parameters,
        MempoolConfig::default(),
    )));
    if harvest.is_some() {
        chain.set_pending(mempool.clone());
    }
    let mut last_pending = f64::NEG_INFINITY;
    let pending_running = Rc::new(Cell::new(false));
    let network_now = |env: &BrowserEnv| {
        env.now()
            .duration_since(network.parameters.epoch())
            .map_or(0, |elapsed| elapsed.as_millis() as u64)
    };
    let (sender, mut events) = mpsc::unbounded::<ChainEvent>();
    // ピアの番号から REST へ。外したピアの番号は使い回さないので、入れ直すときは新しい番号にする
    let mut peers: HashMap<usize, String> = HashMap::new();
    let mut next_peer = 0;
    for origin in usable {
        peers.insert(next_peer, origin.clone());
        let _ = sender.unbounded_send(ChainEvent::PeerAdded {
            peer: PeerId(next_peer),
        });
        next_peer += 1;
    }
    {
        let sender = sender.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                rest::sleep(TICK_MS).await;
                if sender.unbounded_send(ChainEvent::Tick).is_err() {
                    break;
                }
            }
        });
    }
    status("先端を追っています");
    let mut network_tip = 0;
    // 中核は作ったブロックをピアの数だけ押し付けるので、同じものは1回だけ出す
    let mut submitted: Option<Arc<Vec<u8>>> = None;
    let mut shown_plan = String::new();
    loop {
        for action in chain.take_actions() {
            match action {
                // REST から取るだけで押し付けは届かないので、押し付けは自分で作ったものだけ
                Action::Command(_, PeerCommand::Push(bytes)) => {
                    if let Some(harvest) = harvest
                        && submitted
                            .as_ref()
                            .is_none_or(|last| !Arc::ptr_eq(last, &bytes))
                    {
                        submit(&harvest.submit, bytes.clone());
                        submitted = Some(bytes);
                    }
                }
                Action::Command(peer, command) => match peers.get(&peer.0) {
                    Some(origin) => answer(network, origin.clone(), peer, command, sender.clone()),
                    None => {
                        let _ = sender.unbounded_send(ChainEvent::Failed {
                            peer,
                            error: "外した REST です".into(),
                            malformed: false,
                        });
                    }
                },
                Action::Disconnect { peer, .. } => {
                    // しばらく使わず、あとで新しい番号で入れ直す（REST は切れないので、頼まないことで外す）
                    if let Some(origin) = peers.remove(&peer.0) {
                        let _ = sender.unbounded_send(ChainEvent::PeerLost { peer });
                        let (sender, id) = (sender.clone(), next_peer);
                        next_peer += 1;
                        peers.insert(id, origin);
                        wasm_bindgen_futures::spawn_local(async move {
                            rest::sleep(READD_MS).await;
                            let _ =
                                sender.unbounded_send(ChainEvent::PeerAdded { peer: PeerId(id) });
                        });
                    }
                }
                Action::WakeAt(at) => {
                    let wait = at
                        .duration_since(env.now())
                        .unwrap_or_default()
                        .as_millis()
                        .min(i32::MAX as u128) as i32;
                    let sender = sender.clone();
                    wasm_bindgen_futures::spawn_local(async move {
                        rest::sleep(wait).await;
                        let _ = sender.unbounded_send(ChainEvent::Wake);
                    });
                }
                Action::Notify(notice) if notice.is_warning() => {
                    post(&["warning".into(), notice.to_string().into()]);
                }
                Action::Notify(notice @ Notice::Produced { .. }) => {
                    post(&["harvested".into(), notice.to_string().into()]);
                }
                Action::Included(hashes) => mempool.lock().tip_changed(
                    &hashes,
                    Vec::new(),
                    network_now(&env),
                    chain.height() + 1,
                ),
                Action::Restored(transactions) => mempool.lock().tip_changed(
                    &[],
                    transactions,
                    network_now(&env),
                    chain.height() + 1,
                ),
                Action::Dropped(hash) => {
                    mempool.lock().reject(&hash);
                }
                _ => {}
            }
        }
        report_tip(network, &chain.tip(), network_tip, file);
        if let Some(harvest) = harvest
            && now() - last_scan >= DELEGATION_MS
        {
            last_scan = now();
            let mut keys: Vec<(PrivateKey, PrivateKey)> = harvest
                .keys
                .iter()
                .map(|(signing, vrf)| {
                    (
                        PrivateKey::from_bytes(signing.as_bytes()),
                        PrivateKey::from_bytes(vrf.as_bytes()),
                    )
                })
                .collect();
            if let Some(node_key) = &harvest.node_key {
                scan_turn += 1;
                let origin = &usable[scan_turn % usable.len()];
                if let Err(error) = delegations
                    .refresh(origin, node_key, network.parameters.identifier)
                    .await
                {
                    post(&[
                        "warning".into(),
                        format!("{origin} で委任の要求を探せません: {error}").into(),
                    ]);
                }
                let (delegated, statuses) =
                    delegations.check(db, node_key, network.parameters.identifier);
                keys.extend(delegated);
                post(&[
                    "delegations".into(),
                    statuses
                        .iter()
                        .map(|status| {
                            [
                                JsValue::from(status.height as f64),
                                status
                                    .main_account
                                    .map(|address| address.to_string())
                                    .unwrap_or_default()
                                    .into(),
                                status.state.is_ok().into(),
                                status.state.clone().err().unwrap_or_default().into(),
                            ]
                            .into_iter()
                            .collect::<Array>()
                        })
                        .collect::<Array>()
                        .into(),
                ]);
            }
            let public_keys: Vec<_> = keys
                .iter()
                .map(|(signing, _)| heika_core::key::PublicKey::from_private_key(signing))
                .collect();
            if public_keys != harvesting {
                harvesting = public_keys;
                chain.set_harvesters(Arc::new(keys));
            }
        }
        // 当たりが近づいたら、未承認のトランザクションを取って置き場に入れる。取るのは裏で、待たない
        if let HarvestPlan::Hit { timestamp, .. } = chain.harvest_plan()
            && !harvesting.is_empty()
            && timestamp
                .duration_since(env.now())
                .map_or(0, |left| left.as_millis())
                <= PENDING_AHEAD_MS
            && now() - last_pending >= PENDING_EVERY_MS
            && !pending_running.get()
        {
            last_pending = now();
            pending_running.set(true);
            scan_turn += 1;
            let origin = usable[scan_turn % usable.len()].clone();
            let (mempool, running) = (mempool.clone(), pending_running.clone());
            let (at, height) = (network_now(&env), chain.height() + 1);
            wasm_bindgen_futures::spawn_local(async move {
                match rest::fetch_unconfirmed(&origin, PENDING_PAGES).await {
                    Ok(transactions) => {
                        let mut mempool = mempool.lock();
                        mempool.prune(at);
                        for bytes in transactions {
                            let _ = mempool.add(bytes, at, height);
                        }
                    }
                    Err(error) => post(&[
                        "warning".into(),
                        format!("{origin} で未承認のトランザクションを取れません: {error}").into(),
                    ]),
                }
                running.set(false);
            });
        }
        if harvest.is_some() {
            let mut plan = plan_text(chain.harvest_plan(), !harvesting.is_empty());
            let pending = mempool.lock().len();
            if pending > 0 {
                plan.push_str(&format!(
                    "。未承認のトランザクション {pending} 件が候補です"
                ));
            }
            if plan != shown_plan {
                post(&["plan".into(), plan.as_str().into()]);
                shown_plan = plan;
            }
        }
        if stopping.get() {
            return Ok(TipEnd::Stopped);
        }
        let Some(event) = events.next().await else {
            return Ok(TipEnd::Stopped);
        };
        if let ChainEvent::Statistics { statistics, .. } = &event {
            network_tip = network_tip.max(statistics.height);
        }
        match chain.handle(event).await {
            Ok(None) => {}
            Ok(Some(Outcome::Behind { .. })) => {
                status("確定が先に進んだので、追いつく段階に戻ります");
                return Ok(TipEnd::Behind);
            }
            Ok(Some(Outcome::Stopped)) => return Ok(TipEnd::Stopped),
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// 中核がピア `peer`（REST の `origin`）に頼んだことを REST で取り、答えを `sender` に入れる
fn answer(
    network: &Network,
    origin: String,
    peer: PeerId,
    command: PeerCommand,
    sender: mpsc::UnboundedSender<ChainEvent>,
) {
    let parameters = network.parameters;
    wasm_bindgen_futures::spawn_local(async move {
        let failed = |error: FetchError| ChainEvent::Failed {
            peer,
            malformed: matches!(error, FetchError::Malformed(_)),
            error: error.to_string(),
        };
        let event = match command {
            PeerCommand::Statistics => match rest::chain_info(&origin).await {
                Ok((statistics, _)) => ChainEvent::Statistics { peer, statistics },
                Err(error) => failed(error),
            },
            PeerCommand::Finalized => match rest::chain_info(&origin).await {
                Ok((_, header)) => ChainEvent::Finalized { peer, header },
                Err(error) => failed(error),
            },
            PeerCommand::PullBlocks { from, count } => {
                let to = from + u64::from(count.max(1)) - 1;
                match rest::fetch_blocks(&origin, from, to).await {
                    Ok(fetched) => {
                        // 前後に依らない確かめは、中核に渡す前に済ませる
                        let checked: Result<Vec<_>, String> = fetched
                            .into_iter()
                            .map(|bytes| {
                                let block =
                                    Block::from_bytes(&bytes).map_err(|error| error.to_string())?;
                                verify_alone(parameters, &block)
                                    .map_err(|error| error.to_string())?;
                                Ok((block, bytes))
                            })
                            .collect();
                        match checked {
                            Ok(blocks) => ChainEvent::Blocks {
                                peer,
                                from,
                                count,
                                blocks,
                            },
                            Err(error) => failed(FetchError::Malformed(error)),
                        }
                    }
                    Err(error) => failed(error),
                }
            }
            PeerCommand::PullHashes { from, count } => {
                match rest::fetch_hashes(&origin, from, count).await {
                    Ok(hashes) => ChainEvent::Hashes {
                        peer,
                        from,
                        count,
                        hashes,
                    },
                    Err(error) => failed(error),
                }
            }
            PeerCommand::PullProof { epoch } => match rest::fetch_proof(&origin, epoch).await {
                Ok(proof) => ChainEvent::Proof { peer, epoch, proof },
                Err(error) => failed(error),
            },
            // 作ったブロックを出すのは、まだしない（ハーベストしない）
            PeerCommand::Push(_) => return,
        };
        let _ = sender.unbounded_send(event);
    });
}

/// 次の当たりを、画面に出す文にする
fn plan_text(plan: HarvestPlan, has_keys: bool) -> String {
    if !has_keys {
        return "使える鍵がまだありません（委任が届くのを待っています）".into();
    }
    match plan {
        HarvestPlan::NotPlanned => {
            "当たりを求めています（REST の先端に追いつくのを待っています）".into()
        }
        HarvestPlan::NoHit => "1 時間先まで当たりがありません。次の先端で求め直します".into(),
        HarvestPlan::Hit { height, timestamp } => {
            let local = js_sys::Date::new(&JsValue::from_f64(
                timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as f64,
            ));
            let at = local
                .to_locale_time_string("ja-JP")
                .as_string()
                .unwrap_or_default();
            format!("高さ {height} が当たりです（{at} に作ります）")
        }
    }
}

/// 作ったブロックを、ブロックを出す REST のすべてに出し、結果を画面に知らせる
fn submit(origins: &[String], bytes: Arc<Vec<u8>>) {
    let (height, count) = Block::from_bytes(&bytes)
        .map_or((0, 0), |block| (block.height, block.transactions().count()));
    for origin in origins {
        let (origin, bytes) = (origin.clone(), bytes.clone());
        wasm_bindgen_futures::spawn_local(async move {
            let text = match rest::put_block(&origin, &bytes).await {
                Ok(()) => {
                    format!("高さ {height}（トランザクション {count} 件）を {origin} に出しました")
                }
                Err(error) => format!("高さ {height} を {origin} に出せませんでした: {error}"),
            };
            post(&["harvested".into(), text.into()]);
        });
    }
}

fn report_tip(network: &Network, tip: &Tip, network_tip: u64, file: &OpfsFile) {
    post(&[
        "tip".into(),
        network.name.into(),
        (tip.height as f64).into(),
        (network_tip.max(tip.height) as f64).into(),
        (file.size().unwrap_or(0) as f64).into(),
        tip.hash.to_string().into(),
    ]);
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
