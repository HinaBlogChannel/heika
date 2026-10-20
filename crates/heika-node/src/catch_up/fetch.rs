//! 追いつく段階で、いくつかのピアから高さの範囲を分け合って並列に取り、確かめて、高さの順に渡す。

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use heika_block::Block;
use heika_chain::verify::{Tip, VerifyError, verify_alone, verify_link};
use heika_core::hash::Hash256;
use heika_core::network::NetworkParameters;
use heika_peer_protocol::{ClientConnection, QueryError};
use heika_tls::Identity;
use rayon::prelude::*;

/// 取ったブロック（ブロックと、しまうならバイト列）か、取れなかったわけ
pub type Fetched = Result<(Block, Option<Vec<u8>>), String>;

/// 1回の `Pull_Blocks` で頼む上限。catapult の既定の `maxBlocksPerSyncAttempt`。多く頼んでも、ノードはここで
/// 切り詰めるので、残りを頼み直すことになる
/// つないだピア。アドレスは、つなぎ直すのと、同じノードに二度つながないためだけに持ち、どこにも出さない
pub struct Peer {
    pub address: String,
    pub connection: ClientConnection,
}

/// 追いつく段階で使うピア。つないだものと、外したら代わりにつなぐ候補のアドレスと、つなぎ直すのに使う身元
pub struct Discovered {
    pub peers: Vec<Peer>,
    pub candidates: Vec<String>,
    pub identity: std::sync::Arc<Identity>,
}

const PULL_BLOCKS: u32 = 360;
const PULL_BYTES: u32 = 16 * 1024 * 1024;

/// 実行より先に取っておく範囲の数の、ピア1つあたりの上限
const RANGES_AHEAD_PER_PEER: usize = 8;

/// 何ブロック送るごとに、取るスレッドの内訳を出すか
const REPORT_EVERY: u64 = 500_000;

/// `candidates` に並列につないでみて、答えたものを最大 `want` 個返す
pub(crate) fn connect_any(
    candidates: &[String],
    identity: &Identity,
    want: usize,
    timeout: Duration,
) -> Vec<Peer> {
    let connected: Vec<Peer> = candidates
        .par_iter()
        .filter_map(|address| {
            let mut connection = ClientConnection::connect(address, identity, timeout).ok()?;
            // 答えないノードは使わない
            connection.chain_statistics().ok()?;
            Some(Peer {
                address: address.clone(),
                connection,
            })
        })
        .collect();
    connected.into_iter().take(want).collect()
}

/// 取るスレッドのどこに時間がかかったか
#[derive(Default)]
struct Profile {
    /// どのピアの返事もなく待った時間
    waiting: Duration,
    /// つながりを確かめた時間
    linking: Duration,
    /// 渡すスレッドが、実行するスレッドが受け取るのを待った時間（実行のほうが遅い）。まとめ役は待たない
    sending: Duration,
    /// ピアごとの（取る、確かめる、ブロック、バイト）
    peers: Vec<(Duration, Duration, u64, u64)>,
}

impl Profile {
    fn report(&self, label: &str) {
        let seconds = |duration: Duration| duration.as_secs_f64();
        let peers: Vec<String> = self
            .peers
            .iter()
            .enumerate()
            .map(|(peer, (pulled, verified, blocks, bytes))| {
                format!(
                    "{peer}: 取る {:.1}、確かめる {:.1}（{blocks} ブロック、{} MB）",
                    seconds(*pulled),
                    seconds(*verified),
                    bytes / 1_000_000
                )
            })
            .collect();
        eprintln!(
            "{label}: 取るスレッドの内訳（秒）: 返事を待つ {:.1}、つなぐ {:.1}、渡すのを待つ {:.1}、ピアごと: {}",
            seconds(self.waiting),
            seconds(self.linking),
            seconds(self.sending),
            peers.join("、")
        );
    }
}

/// まとめ役から見た、ピアごとの様子
struct Slot {
    address: String,
    /// 頼みごとの送り先。外したピアは None
    requests: Option<mpsc::Sender<Request>>,
    busy: bool,
    /// 休ませているなら、頼んでよくなる時刻
    ready_at: Instant,
    /// 続けて通信に失敗した回数
    failures: u32,
    /// 確かめられないブロックを返したので、二度とつながない
    banned: bool,
}

impl Slot {
    fn usable(&self, now: Instant) -> bool {
        self.requests.is_some() && !self.busy && self.ready_at <= now
    }
}

/// `tip` の次から `target` までのブロックを、`discovered` のピアから取って確かめ、高さの順に `sender` に送る。
/// 通信に失敗したピアは休ませて、また頼む。ピアが減ったら、最初のノードが知っていたほかのノードに `identity` で
/// つなぎに行く。どのピアからも [`MAX_STALL`] のあいだ進めなければ、そのわけを送って終わる。確かめられなければ、
/// そのわけを送って終わる。`stopping` が真になったら、そこで終わる
pub fn fetch(
    discovered: Discovered,
    context: &super::Context<'_>,
    tip: Option<Tip>,
    target: u64,
    sender: &mpsc::SyncSender<Fetched>,
) {
    let super::Context {
        parameters,
        nemesis,
        stopping,
        ..
    } = *context;
    let Discovered {
        peers,
        candidates,
        identity,
    } = discovered;
    let identity = &*identity;
    // 渡し待ちの範囲の数と、渡すのを待った時間（ナノ秒）
    let queued = AtomicUsize::new(0);
    let sending = AtomicU64::new(0);
    std::thread::scope(|scope| {
        let (response_sender, responses) = mpsc::channel::<Response>();
        let wanted = peers.len();
        let start = |slots: &mut Vec<Slot>, peer: Peer| {
            let index = slots.len();
            let (request_sender, request_receiver) = mpsc::channel::<Request>();
            let response_sender = response_sender.clone();
            let address = peer.address.clone();
            scope.spawn(move || {
                serve(
                    index,
                    peer,
                    identity,
                    parameters,
                    &request_receiver,
                    &response_sender,
                );
            });
            slots.push(Slot {
                address,
                requests: Some(request_sender),
                busy: false,
                ready_at: Instant::now(),
                failures: 0,
                banned: false,
            });
        };
        let mut slots: Vec<Slot> = Vec::new();
        for peer in peers {
            start(&mut slots, peer);
        }
        // 実行するスレッドに渡すのは、別のスレッドでする。渡すのを待つあいだも、空いたピアに次の範囲を頼むため。
        // 渡し待ちの範囲も先に取った数に入れるので、ふつうはこの通り道で待たない
        let (emit_sender, emits) = mpsc::sync_channel::<Result<Checked, String>>(
            RANGES_AHEAD_PER_PEER * wanted.max(1) + 1,
        );
        let (queued_count, sending_nanos) = (&queued, &sending);
        scope.spawn(move || {
            for range in emits {
                let started = Instant::now();
                let delivered = match range {
                    Ok(blocks) => blocks
                        .into_iter()
                        .all(|(block, bytes)| sender.send(Ok((block, Some(bytes)))).is_ok()),
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        false
                    }
                };
                sending_nanos.fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
                queued_count.fetch_sub(1, Ordering::Relaxed);
                if !delivered {
                    break;
                }
            }
        });
        let fail = |error: String| {
            queued.fetch_add(1, Ordering::Relaxed);
            let _ = emit_sender.send(Err(error));
        };
        // まだ頼んでいない高さ、頼み直す範囲、返ってきてまだ送っていない範囲
        let mut next = tip.map_or(1, |tip| tip.height + 1);
        let mut retry: VecDeque<(u64, u32)> = VecDeque::new();
        // 返ってきた範囲。始まりの高さ → 取ったピアと、ブロック
        let mut arrived: BTreeMap<u64, (usize, Checked)> = BTreeMap::new();
        let mut tip = tip;
        let mut emitted = tip.map_or(0, |tip| tip.height);
        let mut profile = Profile {
            peers: vec![Default::default(); slots.len()],
            ..Profile::default()
        };
        let mut segment_start = emitted + 1;
        let mut progressed = Instant::now();
        let mut rediscovered = Instant::now();
        while emitted < target {
            if stopping() {
                return;
            }
            let now = Instant::now();
            // 渡し待ちがあるなら、待っているのは実行のほう
            if queued.load(Ordering::Relaxed) > 0 {
                progressed = now;
            }
            if now.duration_since(progressed) > MAX_STALL {
                return fail(format!(
                    "ブロックを取れるピアがありません（{} 秒進みませんでした）",
                    MAX_STALL.as_secs()
                ));
            }
            // ピアが減っていたら、ほかのノードにつなぎに行く
            let live = slots.iter().filter(|slot| slot.requests.is_some()).count();
            // 1つもいなければ、間を詰めて探す
            let every = if live == 0 {
                REDISCOVER_WHEN_NONE
            } else {
                REDISCOVER_EVERY
            };
            if live < wanted && now.duration_since(rediscovered) >= every {
                rediscovered = now;
                let in_use: Vec<&str> = slots
                    .iter()
                    .filter(|slot| slot.requests.is_some() || slot.banned)
                    .map(|slot| slot.address.as_str())
                    .collect();
                let unused: Vec<String> = candidates
                    .iter()
                    .chain(
                        slots
                            .iter()
                            .filter(|slot| !slot.banned)
                            .map(|slot| &slot.address),
                    )
                    .filter(|address| !in_use.contains(&address.as_str()))
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let found = connect_any(&unused, identity, wanted - live, CONNECT_TIMEOUT);
                for peer in found {
                    start(&mut slots, peer);
                    profile.peers.push(Default::default());
                    eprintln!(
                        "ピア {} につなぎました（{} か所）",
                        slots.len() - 1,
                        slots.iter().filter(|slot| slot.requests.is_some()).count()
                    );
                }
            }
            // 空いたピアに頼む。先に取りすぎないように、送っていない範囲の数に上限を置く
            let in_flight = slots.iter().filter(|slot| slot.busy).count();
            let mut ahead = arrived.len() + in_flight + queued.load(Ordering::Relaxed);
            // 頼み直しは、抜けている範囲を埋めるものなので、上限に関わらず頼む
            for peer in 0..slots.len() {
                if !slots[peer].usable(now) {
                    continue;
                }
                let range = match retry.pop_front() {
                    Some(range) => range,
                    None if next <= target && ahead < RANGES_AHEAD_PER_PEER * wanted.max(1) => {
                        let count = u32::try_from(target - next + 1)
                            .unwrap_or(u32::MAX)
                            .min(PULL_BLOCKS);
                        let range = (next, count);
                        next += u64::from(count);
                        range
                    }
                    None => break,
                };
                let sent = slots[peer].requests.as_ref().is_some_and(|requests| {
                    requests
                        .send(Request {
                            from: range.0,
                            count: range.1,
                        })
                        .is_ok()
                });
                if sent {
                    slots[peer].busy = true;
                    ahead += 1;
                } else {
                    retry.push_front(range);
                    drop_peer(&mut slots, peer, "ピアのスレッドが終わっていました");
                }
            }
            if !slots.iter().any(|slot| slot.busy) {
                // 先に取った範囲が上限まで渡し待ちになっているか、どのピアも休んでいる。少し待つ
                let waiting = Instant::now();
                std::thread::sleep(Duration::from_millis(10));
                profile.waiting += waiting.elapsed();
                continue;
            }
            let waiting = Instant::now();
            let received = responses.recv_timeout(Duration::from_secs(1));
            profile.waiting += waiting.elapsed();
            let response = match received {
                Ok(response) => response,
                Err(_) => continue,
            };
            slots[response.peer].busy = false;
            let spent = &mut profile.peers[response.peer];
            spent.0 += response.pulled;
            spent.1 += response.verified;
            let what = format!("高さ {} から {} 件を頼んで", response.from, response.count);
            match response.result {
                Ok(blocks) if !blocks.is_empty() => {
                    slots[response.peer].failures = 0;
                    let spent = &mut profile.peers[response.peer];
                    spent.2 += blocks.len() as u64;
                    spent.3 += blocks
                        .iter()
                        .map(|(_, bytes)| bytes.len() as u64)
                        .sum::<u64>();
                    let got = blocks.len() as u32;
                    // ノードが切り詰めた残りは、頼み直す
                    if got < response.count {
                        retry.push_front((response.from + u64::from(got), response.count - got));
                    }
                    arrived.insert(response.from, (response.peer, blocks));
                }
                Ok(_) => {
                    // まだ持っていないか、答えたくない。休ませる
                    retry.push_front((response.from, response.count));
                    rest(
                        &mut slots,
                        response.peer,
                        &format!("{what}、ブロックを返しませんでした"),
                    );
                    continue;
                }
                Err(Failure::Transient(error)) => {
                    retry.push_front((response.from, response.count));
                    rest(&mut slots, response.peer, &format!("{what}、{error}"));
                    continue;
                }
                Err(Failure::Bad(error)) => {
                    // 確かめられないピアは外す
                    retry.push_front((response.from, response.count));
                    slots[response.peer].banned = true;
                    drop_peer(&mut slots, response.peer, &format!("{what}、{error}"));
                    continue;
                }
            }
            // 次の高さから続いている範囲を、つながりを確かめながら送る
            while let Some(entry) = arrived.first_entry() {
                if *entry.key() != emitted + 1 {
                    break;
                }
                let (from, (peer, blocks)) = entry.remove_entry();
                let count = blocks.len() as u32;
                let linking = Instant::now();
                let mut linked_tip = tip;
                let mut linked = Vec::with_capacity(blocks.len());
                let mut broken = None;
                for (block, bytes) in blocks {
                    match link(linked_tip, &block, nemesis) {
                        Ok(next_tip) => {
                            linked_tip = Some(next_tip);
                            linked.push((block, bytes));
                        }
                        Err(error) => {
                            broken = Some(format!("高さ {}: {error}", block.height));
                            break;
                        }
                    }
                }
                profile.linking += linking.elapsed();
                if let Some(reason) = broken {
                    // ほかのピアのチェーンとつながらない。この範囲は頼み直し、このピアは外す
                    slots[peer].banned = true;
                    drop_peer(&mut slots, peer, &format!("つながりません（{reason}）"));
                    retry.push_front((from, count));
                    break;
                }
                queued.fetch_add(1, Ordering::Relaxed);
                if emit_sender.send(Ok(linked)).is_err() {
                    return;
                }
                progressed = Instant::now();
                tip = linked_tip;
                emitted = tip.map_or(0, |tip| tip.height);
                if emitted / REPORT_EVERY > segment_start.saturating_sub(1) / REPORT_EVERY {
                    profile.sending = Duration::from_nanos(sending.swap(0, Ordering::Relaxed));
                    profile.report(&format!("高さ {segment_start}〜{emitted}"));
                    profile = Profile {
                        peers: vec![Default::default(); slots.len()],
                        ..Profile::default()
                    };
                    segment_start = emitted + 1;
                }
            }
        }
        if segment_start <= emitted {
            profile.sending = Duration::from_nanos(sending.swap(0, Ordering::Relaxed));
            profile.report(&format!("高さ {segment_start}〜{emitted}"));
        }
        // ピアのスレッドを終わらせる
        for slot in &mut slots {
            slot.requests = None;
        }
    });
}

/// ピアを外し、そのわけを出す。アドレスは出さず、つないだ順の番号で指す
fn drop_peer(slots: &mut [Slot], peer: usize, reason: &str) {
    slots[peer].requests = None;
    let left = slots.iter().filter(|slot| slot.requests.is_some()).count();
    eprintln!("ピア {peer} を外します（残り {left}）: {reason}");
}

/// 通信に失敗したピアを休ませる。続けて [`MAX_FAILURES`] 回失敗したら外す
fn rest(slots: &mut [Slot], peer: usize, reason: &str) {
    let slot = &mut slots[peer];
    slot.failures += 1;
    if slot.failures >= MAX_FAILURES {
        drop_peer(
            slots,
            peer,
            &format!("{MAX_FAILURES} 回続けて取れません。{reason}"),
        );
        return;
    }
    let backoff = (BACKOFF_START * 2u32.pow(slot.failures - 1)).min(BACKOFF_MAX);
    slot.ready_at = Instant::now() + backoff;
    eprintln!(
        "ピア {peer} を {} 秒休ませます: {reason}",
        backoff.as_secs()
    );
}

/// つながりと、Nemesis ならこのネットワークのものか
fn link(tip: Option<Tip>, block: &Block, nemesis: Hash256) -> Result<Tip, VerifyError> {
    let linked = verify_link(tip, block)?;
    if linked.height == 1 && linked.hash != nemesis {
        return Err(VerifyError::Nemesis(linked.hash));
    }
    Ok(linked)
}

/// ピアのスレッド。頼まれた範囲を取り、前後に依らない検証を並列に済ませて返す。通信に失敗したら、その場で
/// 一度つなぎ直して頼み直す。確かめられないブロックを返したら終わる
fn serve(
    peer: usize,
    mut connection: Peer,
    identity: &Identity,
    parameters: &NetworkParameters,
    requests: &mpsc::Receiver<Request>,
    responses: &mpsc::Sender<Response>,
) {
    for request in requests {
        let started = Instant::now();
        let mut pulled = connection
            .connection
            .pull_blocks(request.from, request.count, PULL_BYTES);
        if let Err(QueryError::Request(_)) = pulled {
            pulled = match ClientConnection::connect(&connection.address, identity, CONNECT_TIMEOUT)
            {
                Ok(reconnected) => {
                    connection.connection = reconnected;
                    connection
                        .connection
                        .pull_blocks(request.from, request.count, PULL_BYTES)
                }
                Err(_) => pulled,
            };
        }
        let pulled = pulled.map_err(|error| match error {
            QueryError::Request(error) => Failure::Transient(error.to_string()),
            QueryError::Decode(_) => Failure::Bad(error.to_string()),
        });
        let pulled_in = started.elapsed();
        let started = Instant::now();
        let result = pulled.and_then(|pulled| {
            pulled
                .into_par_iter()
                .take(request.count as usize)
                .enumerate()
                .map(|(index, bytes)| {
                    let block = Block::from_bytes(&bytes).map_err(|error| error.to_string())?;
                    let expected = request.from + index as u64;
                    if block.height != expected {
                        return Err(format!(
                            "高さ {expected} を頼んで {} が来ました",
                            block.height
                        ));
                    }
                    verify_alone(parameters, &block)
                        .map_err(|error| format!("高さ {}: {error}", block.height))?;
                    Ok((block, bytes))
                })
                .collect::<Result<Checked, _>>()
                .map_err(Failure::Bad)
        });
        let bad = matches!(result, Err(Failure::Bad(_)));
        let response = Response {
            peer,
            from: request.from,
            count: request.count,
            result,
            pulled: pulled_in,
            verified: started.elapsed(),
        };
        if responses.send(response).is_err() || bad {
            return;
        }
    }
}

/// 取って確かめた範囲。ブロックと、そのバイト列
type Checked = Vec<(Block, Vec<u8>)>;

/// ピアのスレッドへの頼みごと。`from` から `count` 件
struct Request {
    from: u64,
    count: u32,
}

/// 取れなかったわけ
enum Failure {
    /// 通信がうまくいかない。つなぎ直しても取れなかった。しばらく休ませて、また頼む
    Transient(String),
    /// 読めない、確かめられないブロックを返した。外す
    Bad(String),
}

/// ピアのスレッドからの返事
struct Response {
    peer: usize,
    from: u64,
    count: u32,
    result: Result<Checked, Failure>,
    /// 取るのと、確かめるのにかかった時間
    pulled: Duration,
    verified: Duration,
}

/// 休ませる時間の始めと上限。続けて失敗するたびに倍にする
const BACKOFF_START: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// 続けてこの回数だけ通信に失敗したピアは外す。外したピアも、あとでつなぎ直す候補に戻す
const MAX_FAILURES: u32 = 5;
/// ピアが減ったとき、ほかのノードにつなぎに行く間隔
const REDISCOVER_EVERY: Duration = Duration::from_secs(60);
/// ピアが1つもいないときに、ほかのノードにつなぎに行く間隔
const REDISCOVER_WHEN_NONE: Duration = Duration::from_secs(10);
/// つなぎ直すときに待つ時間
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// どのピアからも、これだけのあいだブロックを送れなければ諦める
const MAX_STALL: Duration = Duration::from_secs(600);
