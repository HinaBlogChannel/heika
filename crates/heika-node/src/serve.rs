//! 接続してきたピアの要求に答える。チェーンの持ち主とは別に、
//! ブロックと証明は保存の口から読み、高さ、スコア、確定は持ち主が出来事ごとに書く [`Status`] から読む。
//!
//! 答え方は catapult の `handlers/ChainHandlers.cpp`、`HeightRequestProcessor.h`、`ProofHandlers.cpp`、
//! `NodeDiscoveryHandlers.cpp`、`TimeSyncHandlers.cpp` に合わせる。形の合わない要求には何も返さず、知らない種類が
//! 来たら切る。持っていないもの（未承認のトランザクション、集めている投票、ほかのノード）は空で返す。
//!
//! 相手は信用しない。同時に受ける本数、同じ鍵とアドレスからの本数、黙っている長さ、答える速さ（接続ごとと
//! 全体）に上限を置き、決まりを破った相手（知らない種類、大きすぎるパケット、確かめを通らないブロック）は、
//! 鍵でしばらく受けない。先端につながるのに中核が弾いたブロックを押し付けた鍵も、[`Gate::ban`] で受けない。

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use heika_block::Block;
use heika_block::finalization::proof::proof_header;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_packet::{
    BlockHashesRequest, ChainStatistics, NetworkTime, PullBlocksRequest, packet_type,
};
use heika_tls::{Connection, RequestError, ServerConfig};

use heika_chain::chain::Status;
use heika_chain::env::Env;
use heika_chain::event::{ChainEvent, PULL_BLOCKS, PULL_HASHES};
use heika_chain::verify::verify_alone;
use heika_store_redb::Db;

use crate::peer_thread::NodeEvent;

/// 1回の `Pull_Blocks` で返すバイト数の上限
pub const MAX_RESPONSE_BYTES: u32 = 16 * 1024 * 1024;
/// 受け取るパケットの本体の上限。押し付けられるブロックも入る大きさにする。超えたら切る
const MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// 同時に受けておく接続の数の上限。超えたら、受けてすぐ切る
pub const MAX_CONNECTIONS: usize = 16;
/// 同じ鍵から同時に受ける接続の数の上限（catapult の `maxIncomingConnectionsPerIdentity` は 6）
const MAX_PER_KEY: usize = 3;
/// 同じアドレスから同時に受ける接続の数の上限。鍵を作り替えて上の上限をすり抜けるのを防ぐ。ハンドシェイクの
/// 前に数える。ループバックとプライベートなアドレス（同じホストや LAN の中継、プライベートなネットワーク）は数えない
const MAX_PER_ADDRESS: usize = 4;
/// 新しく受ける接続の速さ（1秒あたり）と、溜めておける数。超えたら、受けてすぐ切る
const ACCEPTS_PER_SECOND: f64 = 2.0;
const ACCEPT_BURST: f64 = 20.0;
/// ハンドシェイクのタイムアウト
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 答えを書くときのタイムアウト
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// 要求が来ないまま待つ長さ。catapult は新しいブロックをつないでいる相手全部に配り、統計も十数秒ごとに聞くので、
/// つないでいる catapult からは、これより長くは黙らない
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// 決まりを破った相手を受けない長さ（catapult の `defaultBanDuration`）
const BAN: Duration = Duration::from_secs(12 * 60 * 60);
/// 1本の接続で答える要求の数の速さ（1秒あたり）と、溜めておける数。catapult は1本で 3 秒に1つほど聞いてくる
const REQUESTS_PER_SECOND: f64 = 5.0;
const REQUEST_BURST: f64 = 50.0;
/// 1本の接続で返すバイト数の速さ（1秒あたり）と、溜めておける量
const BYTES_PER_SECOND: f64 = 4.0 * 1024.0 * 1024.0;
const BYTE_BURST: f64 = 32.0 * 1024.0 * 1024.0;
/// 全部の接続をあわせて答える要求の数と、返すバイト数の速さ（1秒あたり）と、溜めておける量
const TOTAL_REQUESTS_PER_SECOND: f64 = 30.0;
const TOTAL_REQUEST_BURST: f64 = 300.0;
const TOTAL_BYTES_PER_SECOND: f64 = 8.0 * 1024.0 * 1024.0;
const TOTAL_BYTE_BURST: f64 = 64.0 * 1024.0 * 1024.0;
/// 止める合図を見る間隔
const POLL: Duration = Duration::from_millis(200);

/// 答えるのに読むもの
pub trait Source: Sync {
    fn status(&self) -> Status;
    /// `Node_Discovery_Pull_Peers` の答え（つないでいるピアの `NetworkNode` の並び）
    fn peers(&self) -> Arc<Vec<u8>>;
    /// `height` のブロック。刈り込んで消したか、まだなければ `None`
    fn block(&self, height: u64) -> Result<Option<Vec<u8>>, String>;
    /// エポック `epoch` の証明。刈り込んで消したか、まだなければ `None`
    fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, String>;
}

/// 要求1つへの答え
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// この種類で、この本体を返す
    Reply(u32, Vec<u8>),
    /// 何も返さない（押し付けられたもの、形の合わない要求）
    Nothing,
    /// 押し付けられたブロック。前後に依らない確かめは済んでいる。何も返さない
    Pushed(Box<Block>, Vec<u8>),
    /// 相手が決まりを破ったので、切ってしばらく受けない。中身はわけ
    Close(String),
    /// こちらの都合（DB を読めないなど）で答えられないので、切る。相手は受けないことにしない
    Fail(String),
}

/// 要求に答えるもの
pub struct Responder<'a> {
    pub source: &'a dyn Source,
    pub env: &'a (dyn Env + Sync),
    pub parameters: &'static NetworkParameters,
    /// `Node_Discovery_Pull_Ping` で返す、自分の `NetworkNode`
    pub node: Vec<u8>,
    /// 押し付けられたブロックを入れる、チェーンの持ち主の受信箱。`None` なら読み捨てる
    pub pushes: Option<Sender<NodeEvent>>,
}

impl Responder<'_> {
    /// 種類 `request_type` で本体が `body` の要求に答える
    pub fn answer(&self, request_type: u32, body: &[u8]) -> Answer {
        // catapult と同じく、時刻合わせは受け取ってすぐの時刻を使う
        let received = self.network_time();
        match self.answer_inner(request_type, body, received) {
            Ok(answer) => answer,
            Err(error) => Answer::Fail(error),
        }
    }

    fn answer_inner(
        &self,
        request_type: u32,
        body: &[u8],
        received: u64,
    ) -> Result<Answer, String> {
        let reply = |body: Vec<u8>| Ok(Answer::Reply(request_type, body));
        // 本体のない要求で本体が付いていたら、catapult の `IsPacketValid` と同じく何も返さない
        let empty = body.is_empty();
        match request_type {
            packet_type::CHAIN_STATISTICS if empty => {
                let status = self.source.status();
                reply(
                    ChainStatistics {
                        height: status.height,
                        finalized_height: status.finalized.height,
                        score: status.score,
                    }
                    .encode()
                    .to_vec(),
                )
            }
            packet_type::BLOCK_HASHES => match BlockHashesRequest::decode(body) {
                Ok(request) => reply(self.hashes(request)?),
                Err(_) => Ok(Answer::Nothing),
            },
            packet_type::PULL_BLOCKS => match PullBlocksRequest::decode(body) {
                Ok(request) => reply(self.blocks(request)?),
                Err(_) => Ok(Answer::Nothing),
            },
            packet_type::PULL_BLOCK => match <[u8; 8]>::try_from(body) {
                Ok(height) => reply(self.block(u64::from_le_bytes(height))?),
                Err(_) => Ok(Answer::Nothing),
            },
            packet_type::FINALIZATION_STATISTICS if empty => {
                reply(self.source.status().finalized.to_bytes().to_vec())
            }
            packet_type::FINALIZATION_PROOF_AT_EPOCH => match <[u8; 4]>::try_from(body) {
                Ok(epoch) => Ok(Answer::Reply(
                    packet_type::PULL_FINALIZATION_PROOF,
                    self.proof_at_epoch(u32::from_le_bytes(epoch))?,
                )),
                Err(_) => Ok(Answer::Nothing),
            },
            packet_type::FINALIZATION_PROOF_AT_HEIGHT => match <[u8; 8]>::try_from(body) {
                Ok(height) => Ok(Answer::Reply(
                    packet_type::PULL_FINALIZATION_PROOF,
                    self.proof_at_height(u64::from_le_bytes(height))?,
                )),
                Err(_) => Ok(Answer::Nothing),
            },
            packet_type::NODE_DISCOVERY_PULL_PING if empty => reply(self.node.clone()),
            packet_type::NODE_DISCOVERY_PULL_PEERS if empty => reply(self.source.peers().to_vec()),
            packet_type::TIME_SYNC_NETWORK_TIME if empty => reply(
                NetworkTime {
                    receive: received,
                    send: self.network_time(),
                }
                .encode()
                .to_vec(),
            ),
            // 未承認のトランザクションと、集めている投票は持っていない
            packet_type::PULL_TRANSACTIONS
            | packet_type::PULL_PARTIAL_TRANSACTION_INFOS
            | packet_type::PULL_FINALIZATION_MESSAGES => reply(Vec::new()),
            packet_type::CHAIN_STATISTICS
            | packet_type::FINALIZATION_STATISTICS
            | packet_type::NODE_DISCOVERY_PULL_PING
            | packet_type::NODE_DISCOVERY_PULL_PEERS
            | packet_type::TIME_SYNC_NETWORK_TIME => Ok(Answer::Nothing),
            packet_type::PUSH_BLOCK => {
                let block = match Block::from_bytes(body) {
                    Ok(block) => block,
                    Err(error) => {
                        return Ok(Answer::Close(format!(
                            "押し付けられたブロックを読めません: {error}"
                        )));
                    }
                };
                if let Err(error) = verify_alone(self.parameters, &block) {
                    return Ok(Answer::Close(format!(
                        "押し付けられた高さ {} を弾きます: {error}",
                        block.height
                    )));
                }
                Ok(Answer::Pushed(Box::new(block), body.to_vec()))
            }
            // ほかの押し付けられたものは、今は読み捨てる
            packet_type::PUSH_TRANSACTIONS
            | packet_type::PUSH_PARTIAL_TRANSACTIONS
            | packet_type::PUSH_DETACHED_COSIGNATURES
            | packet_type::NODE_DISCOVERY_PUSH_PING
            | packet_type::NODE_DISCOVERY_PUSH_PEERS
            | packet_type::PUSH_FINALIZATION_MESSAGES => Ok(Answer::Nothing),
            _ => Ok(Answer::Close(format!(
                "知らない種類 {request_type:#x} の要求が来ました"
            ))),
        }
    }

    /// Nemesis からのミリ秒
    fn network_time(&self) -> u64 {
        let epoch = UNIX_EPOCH + self.parameters.epoch_adjustment;
        let elapsed = self
            .env
            .now()
            .duration_since(epoch)
            .unwrap_or_default()
            .as_millis();
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }

    /// catapult の `HeightRequestProcessor` と同じく、`height` から先端までに残っているブロックの数。
    /// 0 か先端より先なら `None`
    fn available(&self, height: u64) -> Option<u64> {
        let tip = self.source.status().height;
        (height != 0 && height <= tip).then(|| tip - height + 1)
    }

    fn hashes(&self, request: BlockHashesRequest) -> Result<Vec<u8>, String> {
        let Some(available) = self.available(request.height) else {
            return Ok(Vec::new());
        };
        let count = u64::from(request.num_hashes.min(PULL_HASHES)).min(available);
        let mut hashes = Vec::new();
        for height in request.height..request.height + count {
            // 刈り込んで消した高さからは答えられない
            let Some(bytes) = self.source.block(height)? else {
                break;
            };
            let block = Block::from_bytes(&bytes).map_err(|error| error.to_string())?;
            hashes.extend_from_slice(&block.hash().0);
        }
        Ok(hashes)
    }

    fn blocks(&self, request: PullBlocksRequest) -> Result<Vec<u8>, String> {
        let Some(available) = self.available(request.height) else {
            return Ok(Vec::new());
        };
        let count = u64::from(request.num_blocks.min(PULL_BLOCKS)).min(available);
        let max_bytes = request.num_response_bytes.min(MAX_RESPONSE_BYTES) as usize;
        let mut blocks = Vec::new();
        for height in request.height..request.height + count {
            let Some(bytes) = self.source.block(height)? else {
                break;
            };
            // catapult と同じく、少なくとも1つは返す
            if !blocks.is_empty() && blocks.len() + bytes.len() > max_bytes {
                break;
            }
            blocks.extend_from_slice(&bytes);
        }
        Ok(blocks)
    }

    /// 高さ 0 なら先端
    fn block(&self, height: u64) -> Result<Vec<u8>, String> {
        let tip = self.source.status().height;
        let height = if height == 0 { tip } else { height };
        if height > tip {
            return Ok(Vec::new());
        }
        Ok(self.source.block(height)?.unwrap_or_default())
    }

    fn proof_at_epoch(&self, epoch: u32) -> Result<Vec<u8>, String> {
        if epoch == 0 || epoch > self.source.status().finalized.round.epoch {
            return Ok(Vec::new());
        }
        Ok(self.source.proof(epoch)?.unwrap_or_default())
    }

    /// 高さがちょうど `height` の証明。エポックが進むと高さも進むので、二分探索で探す。途中のエポックの証明が
    /// なければ、見つからなかったことにする
    fn proof_at_height(&self, height: u64) -> Result<Vec<u8>, String> {
        let finalized = self.source.status().finalized;
        if height == 0 || height > finalized.height {
            return Ok(Vec::new());
        }
        let (mut low, mut high) = (1, finalized.round.epoch);
        while low <= high {
            let epoch = low + (high - low) / 2;
            let Some(proof) = self.source.proof(epoch)? else {
                return Ok(Vec::new());
            };
            let found = proof_header(&proof)
                .map_err(|error| error.to_string())?
                .height;
            match found.cmp(&height) {
                std::cmp::Ordering::Equal => return Ok(proof),
                std::cmp::Ordering::Less => low = epoch + 1,
                std::cmp::Ordering::Greater => high = epoch - 1,
            }
        }
        Ok(Vec::new())
    }
}

/// DB と、駆動役が出来事ごとに書く様子と一覧の答えから答える [`Source`]
pub struct DbSource<'a> {
    pub db: &'a Db,
    pub status: &'a RwLock<Status>,
    pub peers: &'a RwLock<Arc<Vec<u8>>>,
}

impl Source for DbSource<'_> {
    fn status(&self) -> Status {
        *self.status.read().expect("not poisoned")
    }

    fn peers(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.peers.read().expect("not poisoned"))
    }

    fn block(&self, height: u64) -> Result<Option<Vec<u8>>, String> {
        self.db.block(height).map_err(|error| error.to_string())
    }

    fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, String> {
        self.db.proof(epoch).map_err(|error| error.to_string())
    }
}

/// 受けている接続、しばらく受けない鍵、全体の速さの上限。待ち受けの外（チェーンの持ち主）からも、
/// [`Gate::ban`] で鍵を受けないことにできる
pub struct Gate {
    state: Mutex<GateState>,
    /// 全部の接続をあわせた、答える要求の数、返すバイト数、新しく受ける接続の数
    requests: Mutex<Bucket>,
    bytes: Mutex<Bucket>,
    accepts: Mutex<Bucket>,
    /// 同じアドレスから同時に受ける接続の数の上限と、ループバックとプライベートなアドレスを数えないか
    per_address: usize,
    exempt_local: bool,
}

#[derive(Default)]
struct GateState {
    open: Vec<Open>,
    banned: HashMap<PublicKey, Instant>,
}

struct Open {
    id: usize,
    /// 止めるときに `shutdown` して、読むのを待っているスレッドを起こすための写し
    socket: TcpStream,
    ip: IpAddr,
    /// ハンドシェイクが済むまでは `None`
    key: Option<PublicKey>,
}

impl Default for Gate {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::default(),
            requests: Mutex::new(Bucket::new(
                TOTAL_REQUEST_BURST,
                TOTAL_REQUESTS_PER_SECOND,
                now,
            )),
            bytes: Mutex::new(Bucket::new(TOTAL_BYTE_BURST, TOTAL_BYTES_PER_SECOND, now)),
            accepts: Mutex::new(Bucket::new(ACCEPT_BURST, ACCEPTS_PER_SECOND, now)),
            per_address: MAX_PER_ADDRESS,
            exempt_local: true,
        }
    }
}

impl Gate {
    /// 今受けている鍵 `key` の接続を切る。締め出さない（中核が押し付けを弾いたとき。規則の割れたハードフォークの
    /// 向こう側かもしれない）
    pub fn cut(&self, key: PublicKey) {
        let state = self.state.lock().expect("not poisoned");
        for open in state.open.iter().filter(|open| open.key == Some(key)) {
            let _ = open.socket.shutdown(Shutdown::Both);
        }
    }

    /// 鍵 `key` を [`BAN`] の長さだけ受けず、今受けているその鍵の接続も切る。状態を見ない確かめに落ちるものを
    /// 送ってきたとき
    pub fn ban(&self, key: PublicKey) {
        let mut state = self.state.lock().expect("not poisoned");
        state.banned.insert(key, Instant::now() + BAN);
        for open in state.open.iter().filter(|open| open.key == Some(key)) {
            let _ = open.socket.shutdown(Shutdown::Both);
        }
    }

    /// 全体の `bucket` から `amount` を使い、足りなければ返し終わるまでに待つ長さを返す
    fn take(bucket: &Mutex<Bucket>, amount: f64) -> Duration {
        bucket
            .lock()
            .expect("not poisoned")
            .take(amount, Instant::now())
    }
}

/// 1本の接続の終わり方
enum Ending {
    Closed,
    /// こちらの都合か、通信の失敗
    Failed(String),
    /// 決まりを破ったので、鍵をしばらく受けない
    Misbehaved(String),
}

/// `listener` で接続を受け、接続ごとのスレッドで `responder` が答える。受けている接続と上限は `gate` に持つ。
/// `stopping` が真になったら、受けた接続も切って、全部のスレッドが終わってから戻る
pub fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    responder: &Responder<'_>,
    gate: &Gate,
    stopping: &(dyn Fn() -> bool + Sync),
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    std::thread::scope(|scope| {
        let mut next = 0;
        while !stopping() {
            let (socket, address) = match listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL);
                    continue;
                }
                Err(error) => {
                    eprintln!("接続を受けられませんでした: {error}");
                    std::thread::sleep(POLL);
                    continue;
                }
            };
            // 受けすぎたら、TLS を始める前に切る（ハンドシェイクの手間をかけない）。切った接続は数えないので、
            // 一度に大量に来ても、借りが溜まって後の相手まで締め出すことはない
            let accepted = gate
                .accepts
                .lock()
                .expect("not poisoned")
                .try_take(1.0, Instant::now());
            if !accepted {
                eprintln!("{address} からの接続は、新しい接続が多すぎるので切ります");
                continue;
            }
            let mut locked = gate.state.lock().expect("not poisoned");
            if locked.open.len() >= MAX_CONNECTIONS {
                eprintln!(
                    "{address} からの接続は、もう {MAX_CONNECTIONS} 本受けているので切ります"
                );
                continue;
            }
            let ip = address.ip();
            let local = gate.exempt_local && is_local(ip);
            if !local && locked.open.iter().filter(|open| open.ip == ip).count() >= gate.per_address
            {
                eprintln!(
                    "{address} からの接続は、同じアドレスからもう {} 本受けているので切ります",
                    gate.per_address
                );
                continue;
            }
            let Ok(handle) = socket
                .set_nonblocking(false)
                .and_then(|()| socket.try_clone())
            else {
                continue;
            };
            let id = next;
            next += 1;
            locked.open.push(Open {
                id,
                socket: handle,
                ip,
                key: None,
            });
            drop(locked);
            let config = Arc::clone(&config);
            scope.spawn(move || {
                let started = Instant::now();
                let mut requests = BTreeMap::new();
                let ending = respond(socket, config, responder, gate, id, stopping, &mut requests);
                let mut locked = gate.state.lock().expect("not poisoned");
                let index = locked.open.iter().position(|open| open.id == id);
                let key = index.and_then(|index| locked.open.remove(index).key);
                // 同じノードの接続を突き合わせられるように、鍵の頭を出す
                let who = key.map_or_else(String::new, |key| {
                    format!("、鍵 {}…", &key.to_string()[..8])
                });
                let reason = match ending {
                    // 止めるときは、こちらから切って読めなくなる
                    _ if stopping() => "止めるので切りました".to_owned(),
                    Ending::Closed => "相手が閉じました".to_owned(),
                    Ending::Failed(error) => error,
                    Ending::Misbehaved(error) => match key {
                        Some(key) => {
                            locked.banned.insert(key, Instant::now() + BAN);
                            format!("{error}。この鍵は {} 時間受けません", BAN.as_secs() / 3600)
                        }
                        None => error,
                    },
                };
                drop(locked);
                let requests: Vec<String> = requests
                    .iter()
                    .map(|(request_type, count)| format!("{request_type:#x}×{count}"))
                    .collect();
                println!(
                    "{address} からの接続を終えました: {reason}（{:.1} 秒{who}、要求 {}）",
                    started.elapsed().as_secs_f64(),
                    if requests.is_empty() {
                        "なし".to_owned()
                    } else {
                        requests.join(" ")
                    }
                );
            });
        }
        for open in &gate.state.lock().expect("not poisoned").open {
            let _ = open.socket.shutdown(Shutdown::Both);
        }
    });
    Ok(())
}

/// 1本の接続で、相手が閉じるまで要求に答える。受けた要求の数を種類ごとに `requests` に数える
fn respond(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    responder: &Responder<'_>,
    gate: &Gate,
    id: usize,
    stopping: &(dyn Fn() -> bool + Sync),
    requests: &mut BTreeMap<u32, usize>,
) -> Ending {
    let failed = |error: &dyn std::fmt::Display| Ending::Failed(error.to_string());
    let address = match socket.peer_addr() {
        Ok(address) => address,
        Err(error) => return failed(&error),
    };
    // ポートが開いているかだけを確かめる相手は、TLS を始めずに閉じる。ハンドシェイクの失敗と分けて出す
    let started = socket
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .and_then(|()| socket.peek(&mut [0]));
    match started {
        Ok(0) => return Ending::Failed("TLS を始めずに閉じました".to_owned()),
        Ok(_) => {}
        Err(error) => return failed(&error),
    }
    let mut connection = match Connection::accept(socket, config, HANDSHAKE_TIMEOUT) {
        Ok(connection) => connection,
        Err(error) => return failed(&error),
    };
    let Some(key) = connection.peer_key() else {
        return Ending::Failed("相手の鍵を読めません".to_owned());
    };
    if let Err(reason) = admit(gate, id, key) {
        return Ending::Failed(reason);
    }
    println!("{address} から接続を受けました（鍵 {key}）");
    if let Err(error) = connection
        .set_read_timeout(Some(IDLE_TIMEOUT))
        .and_then(|()| connection.set_write_timeout(Some(WRITE_TIMEOUT)))
    {
        return failed(&error);
    }
    let now = Instant::now();
    let mut request_budget = Bucket::new(REQUEST_BURST, REQUESTS_PER_SECOND, now);
    let mut byte_budget = Bucket::new(BYTE_BURST, BYTES_PER_SECOND, now);
    loop {
        let (request_type, body) = match connection.receive_packet(MAX_REQUEST_BYTES) {
            Ok(packet) => packet,
            Err(RequestError::Io(error)) => {
                return match error.kind() {
                    std::io::ErrorKind::UnexpectedEof => Ending::Closed,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                        Ending::Failed(format!(
                            "要求が {} 秒来なかったので切りました",
                            IDLE_TIMEOUT.as_secs()
                        ))
                    }
                    _ => failed(&error),
                };
            }
            // 大きすぎるか、全長がヘッダーより短い
            Err(error @ (RequestError::TooLarge(_) | RequestError::InvalidSize(_))) => {
                return Ending::Misbehaved(error.to_string());
            }
            Err(error) => return failed(&error),
        };
        *requests.entry(request_type).or_default() += 1;
        throttle(
            request_budget
                .take(1.0, Instant::now())
                .max(Gate::take(&gate.requests, 1.0)),
            stopping,
        );
        let reply = match responder.answer(request_type, &body) {
            Answer::Reply(reply_type, reply) => (reply_type, reply),
            Answer::Nothing => continue,
            Answer::Pushed(block, bytes) => {
                if let Some(pushes) = &responder.pushes {
                    // 受信箱が閉じていれば先端の段階は終わっているので、捨ててよい
                    let _ = pushes.send(NodeEvent::Chain(ChainEvent::Pushed {
                        block,
                        bytes,
                        from: key,
                    }));
                }
                continue;
            }
            Answer::Close(reason) => return Ending::Misbehaved(reason),
            Answer::Fail(reason) => return Ending::Failed(reason),
        };
        let size = reply.1.len() as f64;
        throttle(
            byte_budget
                .take(size, Instant::now())
                .max(Gate::take(&gate.bytes, size)),
            stopping,
        );
        if let Err(error) = connection.send_packet(reply.0, &reply.1) {
            return failed(&error);
        }
    }
}

/// ハンドシェイクの済んだ接続 `id` を、相手の鍵 `key` で受けてよいか。よければ鍵を書いておく
fn admit(gate: &Gate, id: usize, key: PublicKey) -> Result<(), String> {
    let mut gate = gate.state.lock().expect("not poisoned");
    let now = Instant::now();
    gate.banned.retain(|_, until| *until > now);
    if gate.banned.contains_key(&key) {
        return Err(format!("鍵 {key} は、決まりを破ったのでしばらく受けません"));
    }
    let same = gate
        .open
        .iter()
        .filter(|open| open.key == Some(key))
        .count();
    if same >= MAX_PER_KEY {
        return Err(format!(
            "鍵 {key} からは、もう {MAX_PER_KEY} 本受けているので切ります"
        ));
    }
    if let Some(open) = gate.open.iter_mut().find(|open| open.id == id) {
        open.key = Some(key);
    }
    Ok(())
}

/// ループバックかプライベートなアドレス。インターネットから直には来ない（来るなら中継を通っていて、相手は
/// みな同じアドレスに見える）
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|ip| is_local(IpAddr::V4(ip)))
        }
    }
}

/// `delay` だけ待つ。止める合図が来たら、待つのをやめる
fn throttle(delay: Duration, stopping: &(dyn Fn() -> bool + Sync)) {
    let until = Instant::now() + delay;
    while !stopping() {
        let now = Instant::now();
        if now >= until {
            return;
        }
        std::thread::sleep((until - now).min(POLL));
    }
}

/// 速さの上限（トークンバケツ）。1秒に `rate` ずつ、`burst` まで溜まる
struct Bucket {
    level: f64,
    burst: f64,
    rate: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64, rate: f64, now: Instant) -> Self {
        Self {
            level: burst,
            burst,
            rate,
            last: now,
        }
    }

    /// 足りていれば `amount` を使って真を返す。足りなければ使わずに偽を返す
    fn try_take(&mut self, amount: f64, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.level = (self.level + elapsed * self.rate).min(self.burst);
        self.last = now;
        let enough = self.level >= amount;
        if enough {
            self.level -= amount;
        }
        enough
    }

    /// `amount` を使う。足りなければ借りておき、返し終わるまでに待つ長さを返す
    fn take(&mut self, amount: f64, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.level = (self.level + elapsed * self.rate).min(self.burst) - amount;
        self.last = now;
        if self.level >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.level / self.rate)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use heika_block::finalization::FinalizationRound;
    use heika_core::hash::Hash256;
    use heika_packet::pull_blocks_request;

    use heika_block::finalization::FinalizedBlockHeader;

    use super::*;

    /// 高さ `from` から `to` までの、高さだけ違うブロックと、エポックごとの証明（高さはエポックの 10 倍）
    struct Memory {
        blocks: BTreeMap<u64, Vec<u8>>,
        proofs: BTreeMap<u32, Vec<u8>>,
        status: Status,
    }

    /// 高さだけを入れた、トランザクションのない通常のブロック（署名は確かめないので空）
    fn block(height: u64) -> Vec<u8> {
        let mut bytes = vec![0; 376];
        bytes[..4].copy_from_slice(&376u32.to_le_bytes());
        bytes[108] = 1;
        bytes[109] = 0x98;
        bytes[110..112].copy_from_slice(&0x8143u16.to_le_bytes());
        bytes[112..120].copy_from_slice(&height.to_le_bytes());
        bytes
    }

    fn proof(epoch: u32) -> Vec<u8> {
        let header = FinalizedBlockHeader {
            round: FinalizationRound { epoch, point: 1 },
            height: u64::from(epoch) * 10,
            hash: Hash256([epoch as u8; 32]),
        };
        let mut proof = Vec::new();
        proof.extend_from_slice(&56u32.to_le_bytes());
        proof.extend_from_slice(&1u32.to_le_bytes());
        proof.extend_from_slice(&header.to_bytes());
        proof
    }

    fn memory(from: u64, to: u64, epochs: std::ops::RangeInclusive<u32>) -> Memory {
        let last = *epochs.end();
        Memory {
            blocks: (from..=to).map(|height| (height, block(height))).collect(),
            proofs: epochs.map(|epoch| (epoch, proof(epoch))).collect(),
            status: Status {
                height: to,
                score: (1 << 64) | 2,
                finalized: proof_header(&proof(last)).unwrap(),
            },
        }
    }

    impl Source for Memory {
        fn status(&self) -> Status {
            self.status
        }

        fn peers(&self) -> Arc<Vec<u8>> {
            Arc::new(b"peers".to_vec())
        }

        fn block(&self, height: u64) -> Result<Option<Vec<u8>>, String> {
            Ok(self.blocks.get(&height).cloned())
        }

        fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, String> {
            Ok(self.proofs.get(&epoch).cloned())
        }
    }

    /// 時刻を決めて返す [`Env`]
    struct FixedEnv(SystemTime);

    impl Env for FixedEnv {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn answer(source: &Memory, request_type: u32, body: &[u8]) -> Answer {
        let parameters = &NetworkParameters::TESTNET;
        let env = FixedEnv(parameters.epoch() + Duration::from_millis(1234));
        Responder {
            source,
            env: &env,
            parameters,
            node: b"node".to_vec(),
            pushes: None,
        }
        .answer(request_type, body)
    }

    fn reply(answer: Answer) -> Vec<u8> {
        match answer {
            Answer::Reply(_, body) => body,
            other => panic!("{other:?}"),
        }
    }

    fn hashes_request(height: u64, count: u32) -> Vec<u8> {
        [&height.to_le_bytes()[..], &count.to_le_bytes()].concat()
    }

    fn hash(height: u64) -> Vec<u8> {
        Block::from_bytes(&block(height)).unwrap().hash().0.to_vec()
    }

    #[test]
    fn answers_chain_and_finalization_statistics() {
        let source = memory(1, 30, 1..=2);
        let body = reply(answer(&source, packet_type::CHAIN_STATISTICS, &[]));
        assert_eq!(
            ChainStatistics::decode(&body).unwrap(),
            ChainStatistics {
                height: 30,
                finalized_height: 20,
                score: (1 << 64) | 2
            }
        );
        let body = reply(answer(&source, packet_type::FINALIZATION_STATISTICS, &[]));
        assert_eq!(FinalizedBlockHeader::from_bytes(&body).unwrap().height, 20);
        // 本体のない要求に本体が付いていたら、何も返さない
        assert_eq!(
            answer(&source, packet_type::CHAIN_STATISTICS, &[0]),
            Answer::Nothing
        );
    }

    #[test]
    fn answers_hashes_and_blocks_like_catapult() {
        let source = memory(1, 30, 1..=2);
        let body = reply(answer(
            &source,
            packet_type::BLOCK_HASHES,
            &hashes_request(28, 10),
        ));
        assert_eq!(body, [hash(28), hash(29), hash(30)].concat());
        // 0 か先端より先は、空で返す
        for height in [0, 31] {
            assert_eq!(
                reply(answer(
                    &source,
                    packet_type::BLOCK_HASHES,
                    &hashes_request(height, 10)
                )),
                b""
            );
        }
        let body = reply(answer(
            &source,
            packet_type::PULL_BLOCKS,
            &pull_blocks_request(29, 10, 1 << 20),
        ));
        assert_eq!(body, [block(29), block(30)].concat());
        // バイト数を超えても、少なくとも1つは返す
        let body = reply(answer(
            &source,
            packet_type::PULL_BLOCKS,
            &pull_blocks_request(10, 10, 1),
        ));
        assert_eq!(body, block(10));
        let size = block(10).len() as u32;
        let body = reply(answer(
            &source,
            packet_type::PULL_BLOCKS,
            &pull_blocks_request(10, 10, 2 * size),
        ));
        assert_eq!(body, [block(10), block(11)].concat());
        // 高さ 0 の `Pull_Block` は先端
        assert_eq!(
            reply(answer(
                &source,
                packet_type::PULL_BLOCK,
                &0u64.to_le_bytes()
            )),
            block(30)
        );
    }

    #[test]
    fn stops_at_pruned_blocks() {
        let source = memory(20, 30, 1..=2);
        assert_eq!(
            reply(answer(
                &source,
                packet_type::PULL_BLOCKS,
                &pull_blocks_request(10, 10, 1 << 20)
            )),
            b""
        );
        assert_eq!(
            reply(answer(
                &source,
                packet_type::BLOCK_HASHES,
                &hashes_request(19, 3)
            )),
            b""
        );
    }

    #[test]
    fn answers_proofs_by_epoch_and_height() {
        let source = memory(1, 50, 1..=4);
        let at_epoch = |epoch: u32| match answer(
            &source,
            packet_type::FINALIZATION_PROOF_AT_EPOCH,
            &epoch.to_le_bytes(),
        ) {
            Answer::Reply(packet_type::PULL_FINALIZATION_PROOF, body) => body,
            other => panic!("{other:?}"),
        };
        assert_eq!(at_epoch(3), proof(3));
        assert_eq!(at_epoch(0), b"");
        assert_eq!(at_epoch(5), b"");
        let at_height = |height: u64| {
            reply_of(answer(
                &source,
                packet_type::FINALIZATION_PROOF_AT_HEIGHT,
                &height.to_le_bytes(),
            ))
        };
        for epoch in 1..=4 {
            assert_eq!(at_height(u64::from(epoch) * 10), proof(epoch));
        }
        assert_eq!(at_height(25), b"");
        assert_eq!(at_height(50), b"");
    }

    fn reply_of(answer: Answer) -> Vec<u8> {
        match answer {
            Answer::Reply(packet_type::PULL_FINALIZATION_PROOF, body) => body,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn answers_ping_time_peers_and_empty_lists() {
        let source = memory(1, 10, 1..=1);
        assert_eq!(
            reply(answer(&source, packet_type::NODE_DISCOVERY_PULL_PING, &[])),
            b"node"
        );
        let time = NetworkTime::decode(&reply(answer(
            &source,
            packet_type::TIME_SYNC_NETWORK_TIME,
            &[],
        )))
        .unwrap();
        assert_eq!((time.receive, time.send), (1234, 1234));
        assert_eq!(
            reply(answer(&source, packet_type::NODE_DISCOVERY_PULL_PEERS, &[])),
            b"peers"
        );
        for request_type in [
            packet_type::PULL_TRANSACTIONS,
            packet_type::PULL_PARTIAL_TRANSACTION_INFOS,
            packet_type::PULL_FINALIZATION_MESSAGES,
        ] {
            assert_eq!(
                answer(&source, request_type, &[0; 12]),
                Answer::Reply(request_type, Vec::new())
            );
        }
    }

    /// `seed` から作った CA と、`seed + 1` から作ったノードで名乗る
    fn identity(seed: u8) -> heika_tls::Identity {
        use heika_cert::certificate::{Certificate, Template, Version};
        use heika_core::key::{PrivateKey, PublicKey};
        let now = SystemTime::now();
        let template = |subject| Template {
            subject,
            not_before: now - std::time::Duration::from_secs(60),
            not_after: now + std::time::Duration::from_secs(60 * 60),
            serial_number: &[1],
            version: Version::V1,
        };
        let ca_key = PrivateKey::from_bytes(&[seed; 32]);
        let node_key = PrivateKey::from_bytes(&[seed + 1; 32]);
        let ca = Certificate::self_signed(&ca_key, &template("CN=CA")).unwrap();
        let node = Certificate::issue(
            &ca,
            &ca_key,
            &PublicKey::from_private_key(&node_key),
            &template("CN=node"),
        )
        .unwrap();
        heika_tls::Identity::new(&[node, ca], &node_key).unwrap()
    }

    #[test]
    fn serves_over_tls_until_stopped() {
        let source = memory(1, 30, 1..=2);
        let parameters = &NetworkParameters::TESTNET;
        let env = FixedEnv(parameters.epoch());
        let responder = Responder {
            source: &source,
            env: &env,
            parameters,
            node: Vec::new(),
            pushes: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let config = Arc::new(heika_tls::server_config(&identity(1)));
        let stop = std::sync::atomic::AtomicBool::new(false);
        let stopping = || stop.load(std::sync::atomic::Ordering::SeqCst);
        let gate = Gate::default();
        std::thread::scope(|scope| {
            let server = scope.spawn(|| serve(listener, config, &responder, &gate, &stopping));
            let mut client = heika_peer_protocol::ClientConnection::connect(
                &address,
                &identity(3),
                std::time::Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(client.chain_statistics().unwrap().height, 30);
            assert_eq!(
                client.pull_blocks(29, 10, 1 << 20).unwrap(),
                [block(29), block(30)]
            );
            assert_eq!(client.finalization_statistics().unwrap().height, 20);
            let time = client.network_time().unwrap();
            assert_eq!((time.receive, time.send), (0, 0));
            // 相手がつないだままでも、止める合図で切って戻る
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            server.join().unwrap().unwrap();
            assert!(client.chain_statistics().is_err());
        });
    }

    #[test]
    fn a_bucket_lends_and_asks_to_wait_until_repaid() {
        let start = Instant::now();
        let mut bucket = Bucket::new(10.0, 5.0, start);
        assert_eq!(bucket.take(10.0, start), Duration::ZERO);
        // 2 足りないので、5 ずつ溜まるのを 0.4 秒待つ
        assert_eq!(bucket.take(2.0, start), Duration::from_millis(400));
        // 1 秒で 5 溜まって、借りた 2 を返して 3 残る
        assert_eq!(
            bucket.take(3.0, start + Duration::from_secs(1)),
            Duration::ZERO
        );
        // 長く空けても、溜まるのは 10 まで
        assert_eq!(
            bucket.take(11.0, start + Duration::from_secs(100)),
            Duration::from_millis(200)
        );
    }

    #[test]
    fn a_refused_take_does_not_borrow() {
        let start = Instant::now();
        let mut bucket = Bucket::new(2.0, 1.0, start);
        assert!(bucket.try_take(1.0, start));
        assert!(bucket.try_take(1.0, start));
        // 何度断っても借りは溜まらないので、1 秒後には 1 つ使える
        for _ in 0..1000 {
            assert!(!bucket.try_take(1.0, start));
        }
        assert!(bucket.try_take(1.0, start + Duration::from_secs(1)));
    }

    /// `gate` で `serve` を立て、そのアドレスで `run` を呼ぶ。テストはみな同じアドレスからつなぐので、アドレス
    /// ごとの上限は、`per_address` で決める
    fn with_server(per_address: usize, run: impl FnOnce(&str, &Gate)) {
        let source = memory(1, 30, 1..=2);
        let parameters = &NetworkParameters::TESTNET;
        let env = FixedEnv(parameters.epoch());
        let responder = Responder {
            source: &source,
            env: &env,
            parameters,
            node: Vec::new(),
            pushes: None,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let config = Arc::new(heika_tls::server_config(&identity(1)));
        let stop = std::sync::atomic::AtomicBool::new(false);
        let stopping = || stop.load(std::sync::atomic::Ordering::SeqCst);
        // テストはみなループバックからつなぐので、数えないことにしない
        let gate = Gate {
            per_address,
            exempt_local: false,
            ..Gate::default()
        };
        std::thread::scope(|scope| {
            let server = scope.spawn(|| serve(listener, config, &responder, &gate, &stopping));
            run(&address, &gate);
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            server.join().unwrap().unwrap();
        });
    }

    fn connect(address: &str, seed: u8) -> heika_peer_protocol::ClientConnection {
        heika_peer_protocol::ClientConnection::connect(
            address,
            &identity(seed),
            std::time::Duration::from_secs(5),
        )
        .unwrap()
    }

    #[test]
    fn refuses_more_connections_from_the_same_key() {
        with_server(MAX_CONNECTIONS, |address, _| {
            let mut kept: Vec<_> = (0..MAX_PER_KEY).map(|_| connect(address, 3)).collect();
            for connection in &mut kept {
                assert!(connection.chain_statistics().is_ok());
            }
            // TLS 1.3 ではハンドシェイクのあとで切られるので、要求が通らない
            assert!(connect(address, 3).chain_statistics().is_err());
            assert!(connect(address, 5).chain_statistics().is_ok());
        });
    }

    #[test]
    fn refuses_more_connections_from_the_same_address() {
        with_server(2, |address, _| {
            let mut kept = [connect(address, 3), connect(address, 5)];
            for connection in &mut kept {
                assert!(connection.chain_statistics().is_ok());
            }
            // TLS を始める前に切られるので、つなげない
            assert!(
                heika_peer_protocol::ClientConnection::connect(
                    address,
                    &identity(7),
                    std::time::Duration::from_secs(5)
                )
                .is_err()
            );
        });
    }

    #[test]
    fn local_addresses_are_not_counted_per_address() {
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.2",
            "::1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_local(local.parse().unwrap()), "{local}");
        }
        for public in ["8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!is_local(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn cuts_a_key_from_outside_without_banning_it() {
        with_server(MAX_CONNECTIONS, |address, gate| {
            let mut kept = connect(address, 3);
            assert!(kept.chain_statistics().is_ok());
            gate.cut(*identity(3).key());
            assert!(kept.chain_statistics().is_err());
            // 締め出していないので、つなぎ直せる
            assert!(connect(address, 3).chain_statistics().is_ok());
        });
    }

    #[test]
    fn bans_a_key_from_outside_and_closes_its_connections() {
        with_server(MAX_CONNECTIONS, |address, gate| {
            let mut kept = connect(address, 3);
            assert!(kept.chain_statistics().is_ok());
            gate.ban(*identity(3).key());
            assert!(kept.chain_statistics().is_err());
            assert!(connect(address, 3).chain_statistics().is_err());
            assert!(connect(address, 5).chain_statistics().is_ok());
        });
    }

    #[test]
    fn bans_a_key_that_breaks_the_rules() {
        with_server(MAX_CONNECTIONS, |address, _| {
            let mut connection = heika_tls::Connection::open(
                address,
                &identity(3),
                std::time::Duration::from_secs(5),
            )
            .unwrap();
            connection.send_packet(0x999, &[]).unwrap();
            assert!(connection.receive_packet(1024).is_err());
            // 切ったあとの片付けを待ってから、つなぎ直す
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(connect(address, 3).chain_statistics().is_err());
            assert!(connect(address, 5).chain_statistics().is_ok());
        });
    }

    #[test]
    fn ignores_pushes_and_closes_on_unknown_types() {
        let source = memory(1, 10, 1..=1);
        assert_eq!(
            answer(&source, packet_type::PUSH_TRANSACTIONS, &[0; 8]),
            Answer::Nothing
        );
        // 確かめを通らないブロックを押し付けたら切る（このブロックは署名者が 0）
        assert!(matches!(
            answer(&source, packet_type::PUSH_BLOCK, &block(11)),
            Answer::Close(reason) if reason.contains("高さ 11")
        ));
        assert!(matches!(answer(&source, 0x999, &[]), Answer::Close(_)));
    }
}
