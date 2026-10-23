//! 先端の段階の駆動役。中核（[`Chain`]）とピアの意思決定（[`Peers`]）の2つの状態機械に出来事を入れ、返ってきた
//! 指示を、スレッドとソケットで実際にする。受信箱は1本で、ピアのスレッド、つなぎに行くスレッド、時刻のスレッド、
//! 待ち受けが、そこに出来事を入れる。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heika_cert::certificate::Certificate;
use heika_cert::key::private_key_from_pem;
use heika_chain::chain::{Action, CHECKPOINT_EPOCHS, Chain, Keep, Notice, Outcome, Penalty};
use heika_chain::env::SystemEnv;
use heika_chain::event::{ChainEvent, PeerId};
use heika_chain::produce::Pending;
use heika_chain::store::{EXECUTOR_META, now_or_never};
use heika_chain::verify::nemesis_hash;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_mempool::partial::{PartialConfig, PartialPool, SharedPartialPool};
use heika_mempool::{Mempool, Rejected, SharedMempool};
use heika_packet::{NetworkNode, NodeRoles, NodeVersion, packet_type};
use heika_peer::book::{FIRST_TRIES, best};
use heika_peer::{Book, KnownPeer, PeerAction, PeerEvent, Peers, endpoint};
use heika_peer_protocol::ClientConnection;
use heika_rest::node::{
    ChainInfoJson, DelegationJson, DelegationStateJson, NodeInfoJson, UnlockedAccountJson,
};
use heika_state_transition::config::{ChainConfig, load_network_parameters};
use heika_state_transition::executor::persist::height_of_meta;
use heika_store_redb::Db;
use heika_tls::{ConnectError, Identity};
use heika_transaction::{Body, DetachedCosignature, Transaction};

use crate::catch_up;
use crate::config::{Manifest, Mode, NetworkType, NodeConfig};
use crate::delegated::{Delegated, DelegationState};
use crate::harvesters::{KeyPair, MemoryHarvesters};
use crate::keys::{others_can_read, read_private_key};
use crate::partials::{self, Incoming};
use crate::peer_thread::{self, NodeEvent, Request};
use crate::reader::DbReader;
use crate::recent::RecentTransactions;
use crate::serve::{DbSource, Gate, Responder, serve};
use crate::store::CachedStore;

/// 中核とピアの意思決定に `Tick` を入れる間隔
const TICK: Duration = Duration::from_secs(5);
/// つなぎに行くのを打ち切るまで
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 名乗るときの版。catapult は版を見ないが、ノードの一覧に出るので、互換にしている catapult の版に合わせる
const ANNOUNCED_VERSION: NodeVersion = NodeVersion(0x0100_0309);
/// catapult の `NodeRoles::IPv4`
const NODE_ROLE_IPV4: u32 = 0x40;
/// `roles` の API のビット。REST の口を立てるときに名乗る
const NODE_ROLE_API: u32 = 0x02;

/// ノードを動かせなかったわけ
pub type NodeError = Box<dyn std::error::Error + Send + Sync>;

/// 設定 `manifest` のノードを、`stopping` が真になるまで先端の段階で動かす。DB が空なら、ピアから Nemesis を
/// 取って始める
pub fn run(manifest: &Manifest, stopping: &(dyn Fn() -> bool + Sync)) -> Result<(), NodeError> {
    run_with(manifest, stopping, &MemoryHarvesters::new())
}

/// [`run`] と同じで、設定ファイルの鍵に、`memory` の鍵も足してハーベストする。`memory` は動かしたまま入れ替えられる
pub fn run_with(
    manifest: &Manifest,
    stopping: &(dyn Fn() -> bool + Sync),
    memory: &MemoryHarvesters,
) -> Result<(), NodeError> {
    let setup = Setup::new(&manifest.spec, memory)?;
    loop {
        catch_up_if_behind(&setup, stopping)?;
        if stopping() {
            return Ok(());
        }
        match follow(&setup, stopping)? {
            Outcome::Stopped => return Ok(()),
            Outcome::Behind { finalized } => {
                println!("確定（高さ {finalized}）まで遅れているので、追いつく段階に戻ります");
            }
        }
    }
}

/// 始めに一度だけ用意するもの
struct Setup<'a> {
    spec: &'a NodeConfig,
    parameters: &'static NetworkParameters,
    nemesis: Hash256,
    config: ChainConfig,
    identity: Arc<Identity>,
    /// 設定ファイルの鍵
    harvesters: Vec<KeyPair>,
    /// メモリだけで渡された鍵
    memory: &'a MemoryHarvesters,
}

impl<'a> Setup<'a> {
    fn new(spec: &'a NodeConfig, memory: &'a MemoryHarvesters) -> Result<Self, NodeError> {
        let parameters = network_parameters(spec)?;
        let nemesis = match &spec.network.nemesis_hash {
            Some(hash) => hash
                .parse()
                .map_err(|_| "network.nemesisHash が読めません")?,
            None => nemesis_hash(parameters.identifier).ok_or("知らないネットワークです")?,
        };
        Ok(Self {
            spec,
            parameters,
            nemesis,
            config: chain_config(spec)?,
            identity: Arc::new(load_identity(&spec.certificates.directory)?),
            harvesters: read_harvesters(spec)?,
            memory,
        })
    }

    /// メモリの鍵が入れ替わっていれば（`applied` は前に使った回数）、設定ファイルの鍵と合わせたものを返す
    fn harvesters_if_changed(&self, applied: Option<u64>) -> Option<(u64, Arc<Vec<KeyPair>>)> {
        let (version, memory) = self.memory.current();
        if applied == Some(version) {
            return None;
        }
        let copy = |key: &PrivateKey| PrivateKey::from_bytes(key.as_bytes());
        let keys: Vec<KeyPair> = self
            .harvesters
            .iter()
            .chain(memory.iter())
            .map(|(signing, vrf)| (copy(signing), copy(vrf)))
            .collect();
        if !keys.is_empty() || applied.is_some() {
            println!("{} 組の鍵でハーベストします", keys.len());
        }
        Some((version, Arc::new(keys)))
    }

    /// 住所録（しまったものと seed）
    fn book(&self, db: &Db) -> Result<Book, NodeError> {
        let now = Instant::now();
        let mut book = Book::load(known_peers(db)?, now, unix_now());
        if let Some(seed) = &self.spec.seed {
            book.insert(seed.clone(), now);
        }
        Ok(book)
    }
}

/// これまでに動かした残し方（`storage.mode`）を覚えておく、DB の meta の名前
const STORAGE_MODE_META: &str = "storage_mode";

/// これまでより重い残し方（たくさん残す）にはできない。消したものは戻らないので、黙って進むと名ばかりの
/// アーカイブなどになる。軽くするのは刈り込めばよいので通し、それからは軽いほうを覚える
fn check_storage_mode(db: &Db, mode: Mode) -> Result<(), NodeError> {
    let stored = db
        .meta(STORAGE_MODE_META)?
        .map(|bytes| {
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(Mode::parse)
                .ok_or("DB に覚えた storage.mode が読めません")
        })
        .transpose()?;
    if let Some(stored) = stored {
        if mode < stored {
            return Err(format!(
                "このデータは storage.mode: {} で動かしてきたので、{} にはできません（消したものは戻りません）。\
                 {} にするなら、dataDirectory を空にして最初から追いつき直してください",
                stored.as_str(),
                mode.as_str(),
                mode.as_str()
            )
            .into());
        }
        if mode == stored {
            return Ok(());
        }
    }
    let mut batch = db.batch()?;
    batch.put_meta(STORAGE_MODE_META, mode.as_str().as_bytes())?;
    batch.commit()?;
    Ok(())
}

/// どこにもつながらないときに、試し直すまで待つ
const RETRY_UNREACHABLE: Duration = Duration::from_secs(60);
/// 追いつく段階で、ブロックを取るピアとは別に、確定の証明を取るピアの数
const PROOF_PEERS: usize = 4;

/// 住所録のノードにつなぎ、実行した高さがピアの言う確定より低ければ（空の DB も）、追いつく段階で確定まで
/// まとめて実行する。どこにもつながらなければ、落とさずに間を空けて試し直す
fn catch_up_if_behind(
    setup: &Setup<'_>,
    stopping: &(dyn Fn() -> bool + Sync),
) -> Result<(), NodeError> {
    let spec = setup.spec;
    let mut db = Db::open(&spec.data_directory)?;
    db.set_min_free(spec.min_free_gigabytes * 1_000_000_000);
    check_storage_mode(&db, spec.storage.mode)?;
    let executed = match db.meta(EXECUTOR_META)? {
        Some(meta) => height_of_meta(&meta)?,
        None => 0,
    };
    let book = setup.book(&db)?;
    let known: BTreeMap<String, KnownPeer> = book.records().into_iter().collect();
    let mut addresses = best(&known, usize::MAX);
    if let Some(seed) = &spec.seed
        && !addresses.contains(seed)
    {
        addresses.push(seed.clone());
    }
    let mut peers = loop {
        let peers = catch_up::connect_any(
            &addresses[..addresses.len().min(FIRST_TRIES)],
            &setup.identity,
            spec.peers + PROOF_PEERS,
            CONNECT_TIMEOUT,
        );
        if !peers.is_empty() {
            break peers;
        }
        eprintln!(
            "住所録のノードにつながりません。{} 秒おいて試し直します",
            RETRY_UNREACHABLE.as_secs()
        );
        let until = Instant::now() + RETRY_UNREACHABLE;
        while Instant::now() < until {
            if stopping() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    let finalized = peers[0].connection.chain_statistics()?.finalized_height;
    if executed > 0 && executed >= finalized {
        println!(
            "実行した高さ {executed} が確定（高さ {finalized}）に届いているので、追いつく段階は飛ばします"
        );
        return Ok(());
    }
    // 1つに一覧を聞いて、外したピアの代わりの候補にする
    let own = *setup.identity.key();
    if let Ok(nodes) = peers[0].connection.peers() {
        for node in nodes {
            let address = endpoint(&node.host, node.port);
            if node.roles.contains(NodeRoles::PEER)
                && !node.host.is_empty()
                && node.identity_key != own
                && !addresses.contains(&address)
            {
                addresses.push(address);
            }
        }
    }
    // 住所録がまだ薄い（初めて動かしたときはシードだけ）なら、一覧から足りない分をつなぎ足す
    let want = spec.peers + PROOF_PEERS;
    if peers.len() < want {
        let more: Vec<String> = addresses
            .iter()
            .filter(|address| peers.iter().all(|peer| &peer.address != *address))
            .take(FIRST_TRIES)
            .cloned()
            .collect();
        peers.extend(catch_up::connect_any(
            &more,
            &setup.identity,
            want - peers.len(),
            CONNECT_TIMEOUT,
        ));
    }
    println!("追いつく段階に入ります（実行した高さ {executed}、確定 {finalized}）");
    // 証明を取るピアは、ブロックを取るピアを1つは残して、後ろから分ける
    let keep_for_blocks = peers.len().saturating_sub(PROOF_PEERS).max(1);
    let proof_peers = peers
        .split_off(keep_for_blocks)
        .into_iter()
        .map(|peer| peer.connection)
        .collect();
    let candidates = addresses
        .iter()
        .filter(|address| peers.iter().all(|peer| &peer.address != *address))
        .cloned()
        .collect();
    let connect = || -> Result<ClientConnection, NodeError> {
        addresses
            .iter()
            .find_map(|address| {
                ClientConnection::connect(address, &setup.identity, CONNECT_TIMEOUT).ok()
            })
            .ok_or_else(|| "証明を取るノードにつながりません".into())
    };
    let context = catch_up::Context {
        parameters: setup.parameters,
        nemesis: setup.nemesis,
        stopping,
        connect: &connect,
    };
    catch_up::execute(
        &mut db,
        setup.config.clone(),
        &context,
        catch_up::Source::Peers {
            discovered: catch_up::Discovered {
                peers,
                candidates,
                identity: Arc::clone(&setup.identity),
            },
            proof_peers,
            finalized,
        },
        keep(spec)?,
        catch_up::DEFAULT_SAVE_EVERY,
        None,
    )?;
    Ok(())
}

/// 先端の段階。止める合図か、確定まで遅れて追いつく段階が要るまで続ける
fn follow(setup: &Setup<'_>, stopping: &(dyn Fn() -> bool + Sync)) -> Result<Outcome, NodeError> {
    let spec = setup.spec;
    let (parameters, identity) = (setup.parameters, &setup.identity);
    let mut db = Db::open_with_cache(
        &spec.data_directory,
        spec.storage.cache.database_megabytes << 20,
    )?;
    db.set_min_free(spec.min_free_gigabytes * 1_000_000_000);
    let book = setup.book(&db)?;
    let store = CachedStore::new(Arc::new(db), spec.storage.cache.state_megabytes << 20);
    let mut chain = now_or_never(Chain::new(
        &store,
        &SystemEnv,
        setup.config.clone(),
        parameters,
        spec.storage.partial_state(),
    ))?;
    if let Some(keep) = keep(spec)? {
        chain.set_keep(keep);
    }
    if let Some(beneficiary) = &spec.beneficiary {
        let address: Address = beneficiary
            .trim()
            .parse()
            .map_err(|_| format!("beneficiary の {beneficiary} が、アドレスとして読めません"))?;
        chain.set_beneficiary(Some(address));
    }
    let mut delegated = match &spec.delegations {
        Some(config) => {
            let path = config
                .key
                .clone()
                .unwrap_or_else(|| spec.certificates.directory.join("tls.key"));
            let key = read_private_key(&path)
                .map_err(|error| format!("委任の鍵 {} を読めません: {error}", path.display()))?;
            Some(Delegated::open(
                key,
                parameters.identifier,
                config.max,
                &spec.data_directory,
                chain.height(),
            )?)
        }
        None => None,
    };
    let (mut applied, mut own) = setup
        .harvesters_if_changed(None)
        .expect("always returned the first time");
    chain.set_harvesters(combined(&own, delegated.as_ref()));
    let mempool = Arc::new(SharedMempool::new(Mempool::new(
        parameters,
        heika_mempool::Config::default(),
    )));
    chain.set_pending(Arc::clone(&mempool) as Arc<dyn Pending>);
    // 連署を待つアグリゲートボンデッド。揃ったら未承認の置き場に移す
    let partials = Arc::new(SharedPartialPool::new(PartialPool::new(
        parameters,
        PartialConfig::default(),
    )));
    let mut peers = Peers::new(book, parameters, *identity.key(), spec.peers);
    let announce = spec
        .listen
        .as_ref()
        .map(|listen| local_node(identity, listen, parameters))
        .transpose()?
        .map(Arc::new);
    let status = Arc::new(RwLock::new(chain.status()));
    let reply = RwLock::new(peers.reply());
    let gate = Gate::default();
    let (events, inbox) = mpsc::channel::<NodeEvent>();
    let done = std::sync::atomic::AtomicBool::new(false);
    // REST の口。駆動役が様子を書き、API のスレッドが読んで返す
    let api = if spec.rest.is_empty() {
        None
    } else {
        let node_public_key = match &delegated {
            Some(delegated) => delegated.public_key(),
            None => PublicKey::from_private_key(&read_private_key(
                &spec.certificates.directory.join("tls.key"),
            )?),
        };
        let snapshot = heika_api::Snapshot {
            node: api_node(identity, spec, parameters, &node_public_key),
            chain: api_chain(&chain.status()),
            unlocked: Default::default(),
            peers: Vec::new(),
            delegations: Vec::new(),
        };
        let shared: heika_api::Shared = Arc::new(RwLock::new(snapshot));
        refresh_api(&shared, &chain, &peers.reply(), delegated.as_ref());
        // 送ったトランザクションの行方を答えるための、直近のブロックの索引
        let recent = RecentTransactions::open(
            store.db(),
            parameters.generation_hash_seed,
            setup.config.max_transaction_lifetime,
            chain.height(),
        )?;
        Some((shared, Arc::new(RwLock::new(recent))))
    };
    let api_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let outcome = std::thread::scope(|scope| -> Result<Outcome, NodeError> {
        if let Some((shared, recent)) = &api {
            let addresses: Vec<String> =
                spec.rest.iter().map(|rest| rest.address.clone()).collect();
            let node = heika_api::Node {
                submit: submit(
                    parameters,
                    Arc::clone(&mempool),
                    Arc::clone(&status),
                    events.clone(),
                ),
                submit_partial: submit_partial(events.clone()),
                submit_cosignature: submit_cosignature(events.clone()),
                reader: Arc::new(DbReader::new(
                    store.shared_db(),
                    parameters.identifier,
                    setup.config.currency_mosaic_id,
                    parameters.generation_hash_seed,
                    Arc::clone(&mempool),
                    Arc::clone(recent),
                    Arc::clone(&partials),
                )),
            };
            let (shared, stop) = (Arc::clone(shared), Arc::clone(&api_stop));
            scope.spawn(move || {
                if let Err(error) = heika_api::serve(&addresses, shared, node, stop) {
                    eprintln!("{error}");
                }
            });
        }
        if let (Some(listen), Some(node)) = (&spec.listen, &announce) {
            let listener = std::net::TcpListener::bind(&listen.address)
                .map_err(|error| format!("{} で待ち受けられません: {error}", listen.address))?;
            let (status, reply, gate, done) = (&*status, &reply, &gate, &done);
            let (db, pushes, node) = (store.db(), events.clone(), node.to_vec());
            let (mempool, partials) = (&*mempool, &*partials);
            let server_config = Arc::new(heika_tls::server_config(identity));
            scope.spawn(move || {
                let source = DbSource {
                    db,
                    status,
                    peers: reply,
                };
                let responder = Responder {
                    source: &source,
                    env: &SystemEnv,
                    parameters,
                    node,
                    pushes: Some(pushes),
                    mempool: Some(mempool),
                    partials: Some(partials),
                };
                let stop = || stopping() || done.load(std::sync::atomic::Ordering::SeqCst);
                if let Err(error) = serve(listener, server_config, &responder, gate, &stop) {
                    eprintln!("待ち受けを止めました: {error}");
                }
            });
        }
        let ticker = events.clone();
        std::thread::spawn(move || {
            while ticker.send(NodeEvent::Chain(ChainEvent::Tick)).is_ok()
                && ticker.send(NodeEvent::Peer(PeerEvent::Tick)).is_ok()
            {
                std::thread::sleep(TICK);
            }
        });
        let mut senders: BTreeMap<PeerId, Sender<Request>> = BTreeMap::new();
        let (registrations, registered) = mpsc::channel::<(PeerId, Sender<Request>)>();
        // 次に未承認のトランザクションを頼むピアを選ぶための、前に頼んだピア
        let mut pull_from: Option<PeerId> = None;
        println!("高さ {} から先端を追います", chain.height());
        let result = (|| -> Result<Outcome, NodeError> {
            for event in &inbox {
                let mut pending = vec![event];
                while let Some(event) = pending.pop() {
                    match event {
                        NodeEvent::Chain(ChainEvent::Tick) if stopping() => {
                            println!("高さ {} で止めました", chain.height());
                            return Ok(Outcome::Stopped);
                        }
                        NodeEvent::Chain(ChainEvent::Tick) => {
                            if let Some((version, keys)) =
                                setup.harvesters_if_changed(Some(applied))
                            {
                                applied = version;
                                own = keys;
                                chain.set_harvesters(combined(&own, delegated.as_ref()));
                            }
                            mempool.lock().prune(network_now(parameters));
                            partials.lock().prune(network_now(parameters));
                            // catapult と同じく、ピアを順に1つずつ選んで、知らない未承認のトランザクションと、
                            // 連署を待つものを頼む
                            pull_from = next_peer(&senders, pull_from);
                            if let Some(peer) = pull_from {
                                let request = {
                                    let mempool = mempool.lock();
                                    Request::PullTransactions {
                                        min_deadline: network_now(parameters),
                                        min_fee_multiplier: mempool.min_fee_multiplier(),
                                        known: mempool.short_hashes(),
                                    }
                                };
                                let _ = senders[&peer].send(request);
                                let known = partials.lock().short_hash_pairs();
                                let _ = senders[&peer].send(Request::PullPartial {
                                    min_deadline: network_now(parameters),
                                    known,
                                });
                            }
                            if let Some(outcome) = now_or_never(chain.handle(ChainEvent::Tick))? {
                                return Ok(outcome);
                            }
                        }
                        NodeEvent::Chain(event) => {
                            if let Some(outcome) = now_or_never(chain.handle(event))? {
                                return Ok(outcome);
                            }
                        }
                        NodeEvent::Pulled { peer, transactions } => {
                            let (now, height) = (network_now(parameters), chain.height() + 1);
                            let added: Vec<Vec<u8>> = {
                                let mut mempool = mempool.lock();
                                transactions
                                    .into_iter()
                                    .filter(|bytes| mempool.add(bytes.clone(), now, height).is_ok())
                                    .collect()
                            };
                            if !added.is_empty() {
                                println!(
                                    "ピア {} から、未承認のトランザクション {} 件を受け付けました",
                                    peer.0,
                                    added.len()
                                );
                                // ほかのピアにも流す
                                pending.push(NodeEvent::Relay {
                                    transactions: Arc::new(added.concat()),
                                    except: Some(peer),
                                });
                            }
                        }
                        NodeEvent::PulledPartial { peer, pulled } => {
                            for incoming in Incoming::from_pulled(pulled) {
                                pending.push(NodeEvent::Partial {
                                    incoming,
                                    from: Some(peer),
                                });
                            }
                        }
                        NodeEvent::Partial { incoming, from } => {
                            let height = chain.height() + 1;
                            let handled = partials::handle(
                                &mut chain,
                                &partials,
                                &mempool,
                                incoming,
                                network_now(parameters),
                                height,
                            );
                            for (packet_type, body) in [
                                (packet_type::PUSH_PARTIAL_TRANSACTIONS, handled.partial),
                                (
                                    packet_type::PUSH_DETACHED_COSIGNATURES,
                                    handled.cosignatures,
                                ),
                            ] {
                                if body.is_empty() {
                                    continue;
                                }
                                let body = Arc::new(body);
                                for (id, sender) in &senders {
                                    if Some(*id) != from {
                                        let _ = sender.send(Request::Push {
                                            packet_type,
                                            body: Arc::clone(&body),
                                        });
                                    }
                                }
                            }
                            if !handled.completed.is_empty() {
                                pending.push(NodeEvent::Relay {
                                    transactions: Arc::new(handled.completed),
                                    except: None,
                                });
                            }
                        }
                        NodeEvent::Relay {
                            transactions,
                            except,
                        } => {
                            for (id, sender) in &senders {
                                if Some(*id) != except {
                                    let _ = sender
                                        .send(Request::Transactions(Arc::clone(&transactions)));
                                }
                            }
                        }
                        NodeEvent::Peer(event) => {
                            if let PeerEvent::Connected { id } = &event {
                                senders.extend(registered.try_iter());
                                pending.push(NodeEvent::Chain(ChainEvent::PeerAdded { peer: *id }));
                            }
                            peers.handle(event, Instant::now(), unix_now());
                        }
                    }
                    for action in chain.take_actions() {
                        match action {
                            Action::Command(id, command) => {
                                let sent = senders.get(&id).is_some_and(|sender| {
                                    sender.send(Request::Chain(command)).is_ok()
                                });
                                if !sent {
                                    pending.push(NodeEvent::Chain(ChainEvent::Failed {
                                        peer: id,
                                        error: "ピアのスレッドが終わっています".to_owned(),
                                        malformed: false,
                                    }));
                                }
                            }
                            // 命令の口を閉じると、ピアのスレッドが終わる
                            Action::Disconnect { peer, penalty } => {
                                senders.remove(&peer);
                                pending.push(NodeEvent::Peer(PeerEvent::Disconnected {
                                    id: peer,
                                    penalty,
                                }));
                            }
                            Action::WakeAt(at) => {
                                let events = events.clone();
                                std::thread::spawn(move || {
                                    if let Ok(wait) = at.duration_since(SystemTime::now()) {
                                        std::thread::sleep(wait);
                                    }
                                    let _ = events.send(NodeEvent::Chain(ChainEvent::Wake));
                                });
                            }
                            Action::RejectPush(key) => gate.cut(key),
                            Action::Notify(notice) => {
                                if notice.is_warning() {
                                    eprintln!("{notice}");
                                } else {
                                    println!("{notice}");
                                }
                                // 先端が進んだら、そこまでに届いた委任の要求を読み、取り込めるものを確かめ直す。
                                // 枝を取り替えたら、分かれ目から読み直す
                                let reached = match &notice {
                                    Notice::Accepted { height, .. }
                                    | Notice::Produced { height, .. } => Some(*height),
                                    Notice::Switched { common, new, .. } => {
                                        if let Some(delegated) = delegated.as_mut() {
                                            delegated.rewind(*common);
                                        }
                                        if let Some((_, recent)) = &api {
                                            write(recent).rewind(*common);
                                        }
                                        Some(new.height)
                                    }
                                    _ => None,
                                };
                                if let (Some(height), Some((_, recent))) = (reached, &api)
                                    && let Err(error) = write(recent).advance(store.db(), height)
                                {
                                    eprintln!(
                                        "入ったトランザクションの索引を作れませんでした: {error}"
                                    );
                                }
                                if let (Some(height), Some(delegated)) =
                                    (reached, delegated.as_mut())
                                {
                                    match delegated.advance(store.db(), height) {
                                        Ok(progress) => {
                                            if let Some(message) = progress.message {
                                                println!("{message}");
                                            }
                                            if progress.changed {
                                                chain.set_harvesters(combined(
                                                    &own,
                                                    Some(delegated),
                                                ));
                                            }
                                        }
                                        Err(error) => {
                                            eprintln!("委任の要求を読めませんでした: {error}")
                                        }
                                    }
                                }
                            }
                            Action::Included(hashes) => {
                                mempool.lock().tip_changed(
                                    &hashes,
                                    Vec::new(),
                                    network_now(parameters),
                                    chain.height() + 1,
                                );
                                let mut partials = partials.lock();
                                for hash in &hashes {
                                    partials.remove(hash);
                                }
                            }
                            Action::Restored(transactions) => mempool.lock().tip_changed(
                                &[],
                                transactions,
                                network_now(parameters),
                                chain.height() + 1,
                            ),
                            Action::Dropped(hash) => {
                                mempool.lock().remove(&hash);
                            }
                        }
                    }
                    for action in peers.take_actions() {
                        match action {
                            PeerAction::Connect { id, address } => connect_in_background(
                                id,
                                address,
                                Arc::clone(identity),
                                parameters,
                                events.clone(),
                                registrations.clone(),
                                announce.clone(),
                            ),
                            PeerAction::Ask { id, ask } => {
                                let sent = senders
                                    .get(&id)
                                    .is_some_and(|sender| sender.send(Request::Peer(ask)).is_ok());
                                if !sent {
                                    pending.push(NodeEvent::Peer(PeerEvent::Disconnected {
                                        id,
                                        penalty: Penalty::None,
                                    }));
                                }
                            }
                            PeerAction::Save(records) => save_known(store.db(), &records)?,
                        }
                    }
                }
                *status.write().expect("not poisoned") = chain.status();
                *reply.write().expect("not poisoned") = peers.reply();
                if let Some((shared, _)) = &api {
                    refresh_api(shared, &chain, &peers.reply(), delegated.as_ref());
                }
            }
            Ok(Outcome::Stopped)
        })();
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        api_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        result
    })?;
    save_known(store.db(), &peers.book().records())?;
    Ok(outcome)
}

pub(crate) fn network_parameters(
    spec: &NodeConfig,
) -> Result<&'static NetworkParameters, NodeError> {
    Ok(match spec.network.network_type {
        NetworkType::Mainnet => &NetworkParameters::MAINNET,
        NetworkType::Testnet => &NetworkParameters::TESTNET,
        NetworkType::Custom => {
            let resources = spec
                .network
                .resources
                .as_ref()
                .ok_or("network.resources がありません")?;
            Box::leak(Box::new(load_network_parameters(resources)?))
        }
    })
}

/// `resources` があればそこから読み、なければメインネットとテストネットは決め打ちの設定を使う
pub(crate) fn chain_config(spec: &NodeConfig) -> Result<ChainConfig, NodeError> {
    Ok(match (&spec.network.resources, spec.network.network_type) {
        (Some(resources), _) => ChainConfig::load(resources)?,
        (None, NetworkType::Mainnet) => ChainConfig::mainnet(),
        (None, NetworkType::Testnet) => ChainConfig::testnet(),
        (None, NetworkType::Custom) => return Err("network.resources がありません".into()),
    })
}

/// 残し方（`storage.mode`）を、中核の刈り込みの設定にする。`archive` なら刈り込まない
pub(crate) fn keep(spec: &NodeConfig) -> Result<Option<Keep>, NodeError> {
    let retention = spec.storage.retention();
    let (Some(state), Some(trie)) = (retention.state, retention.state_proofs) else {
        return Ok(None);
    };
    if u64::from(state.min(trie)) < CHECKPOINT_EPOCHS {
        return Err(format!("残すエポックは {CHECKPOINT_EPOCHS} 以上にしてください").into());
    }
    Ok(Some(Keep {
        state: state.into(),
        trie: trie.into(),
        history: retention.blocks_and_statements,
    }))
}

/// 証明書のフォルダーの `tls.crt`（ノードと CA の鎖）と `tls.key` から、名乗る身元を作る
fn load_identity(directory: &Path) -> Result<Identity, NodeError> {
    let read = |name: &str| {
        std::fs::read_to_string(directory.join(name))
            .map_err(|error| format!("{} を読めません: {error}", directory.join(name).display()))
    };
    let chain = Certificate::from_pem_chain(&read("tls.crt")?)?;
    let key = private_key_from_pem(&read("tls.key")?)?;
    Ok(Identity::new(&chain, &key)?)
}

/// ハーベストする鍵の組。持ち主のほかも読めるファイルなら、警告を出す（止めはしない）
fn read_harvesters(spec: &NodeConfig) -> Result<Vec<KeyPair>, NodeError> {
    let mut keys = Vec::new();
    for harvester in &spec.harvesters {
        for path in [&harvester.signer, &harvester.vrf] {
            if others_can_read(path)? {
                eprintln!(
                    "警告: 鍵のファイル {} は持ち主のほかも読めます（chmod 600 をおすすめします）",
                    path.display()
                );
            }
        }
        keys.push((
            read_private_key(&harvester.signer)?,
            read_private_key(&harvester.vrf)?,
        ));
    }
    Ok(keys)
}

/// API の `/node/info`。役割は、ピアと API と IPv4
fn api_node(
    identity: &Identity,
    spec: &NodeConfig,
    parameters: &NetworkParameters,
    node_public_key: &PublicKey,
) -> NodeInfoJson {
    let listen = spec.listen.as_ref();
    NodeInfoJson {
        version: ANNOUNCED_VERSION.0,
        public_key: identity.key().to_string(),
        network_generation_hash_seed: parameters.generation_hash_seed.to_string(),
        roles: NodeRoles::PEER.0 | NODE_ROLE_API | NODE_ROLE_IPV4,
        port: listen
            .and_then(|listen| listen.address.rsplit_once(':'))
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(7900),
        network_identifier: parameters.identifier.0,
        host: listen
            .and_then(|listen| listen.public_host.clone())
            .unwrap_or_default(),
        friendly_name: listen
            .and_then(|listen| listen.friendly_name.clone())
            .unwrap_or_default(),
        node_public_key: Some(node_public_key.to_string()),
    }
}

/// ピアに `Node_Discovery_Pull_Peers` で答えるもの（`reply`）を、REST の `/node/peers` の形にする
fn api_peers(reply: &[u8]) -> Vec<NodeInfoJson> {
    NetworkNode::decode_list(reply)
        .unwrap_or_default()
        .into_iter()
        .map(|node| NodeInfoJson {
            version: node.version.0,
            public_key: node.identity_key.to_string(),
            network_generation_hash_seed: node.network_generation_hash_seed.to_string(),
            roles: node.roles.0,
            port: node.port,
            network_identifier: node.network_identifier.0,
            host: node.host,
            friendly_name: node.friendly_name,
            node_public_key: None,
        })
        .collect()
}

/// API の `/chain/info`
fn api_chain(status: &heika_chain::chain::Status) -> ChainInfoJson {
    let finalized = &status.finalized;
    ChainInfoJson::new(
        status.height,
        status.score,
        finalized.round.epoch,
        finalized.round.point,
        finalized.height,
        finalized.hash.to_string(),
    )
}

/// API の様子を、チェーンと委任の今に書き換える
fn refresh_api(
    shared: &heika_api::Shared,
    chain: &Chain<'_, CachedStore>,
    peers: &[u8],
    delegated: Option<&Delegated>,
) {
    let mut snapshot = shared
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.chain = api_chain(&chain.status());
    snapshot.peers = api_peers(peers);
    let Some(delegated) = delegated else {
        return;
    };
    let hex = |key: &PublicKey| key.to_string();
    let statuses = delegated.statuses();
    snapshot.unlocked = UnlockedAccountJson {
        unlocked_account: statuses
            .iter()
            .filter(|status| status.state == DelegationState::Accepted)
            .map(|status| hex(&status.remote))
            .collect(),
    };
    snapshot.delegations = statuses
        .iter()
        .map(|status| {
            let (state, reason) = match &status.state {
                DelegationState::Accepted => (DelegationStateJson::Accepted, None),
                DelegationState::Waiting => (DelegationStateJson::Waiting, None),
                DelegationState::Rejected(reason) => {
                    (DelegationStateJson::Rejected, Some(reason.clone()))
                }
            };
            DelegationJson {
                main_public_key: status.main_account.as_ref().map(hex),
                remote_public_key: hex(&status.remote),
                height: status.height.map(|height| height.to_string()),
                state,
                reason,
            }
        })
        .collect();
}

/// 設定ファイルとメモリの自分の鍵に、引き受けている委任の鍵を足す
fn combined(own: &[KeyPair], delegated: Option<&Delegated>) -> Arc<Vec<KeyPair>> {
    let copy = |key: &PrivateKey| PrivateKey::from_bytes(key.as_bytes());
    let mut keys: Vec<KeyPair> = own
        .iter()
        .map(|(signing, vrf)| (copy(signing), copy(vrf)))
        .collect();
    if let Some(delegated) = delegated {
        keys.extend(delegated.keys());
    }
    Arc::new(keys)
}

/// 接続してきたピアに ping で返し、つないだピアに名乗る、自分の `NetworkNode`。鍵は CA の公開鍵
fn local_node(
    identity: &Identity,
    listen: &crate::config::Listen,
    parameters: &NetworkParameters,
) -> Result<Vec<u8>, NodeError> {
    let port = listen
        .address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .ok_or("listen.address にポートがありません")?;
    let node = NetworkNode {
        version: ANNOUNCED_VERSION,
        identity_key: *identity.key(),
        network_generation_hash_seed: parameters.generation_hash_seed,
        roles: NodeRoles(NodeRoles::PEER.0 | NODE_ROLE_IPV4),
        port,
        network_identifier: parameters.identifier,
        host: listen.public_host.clone().unwrap_or_default(),
        friendly_name: listen.friendly_name.clone().unwrap_or_default(),
    };
    Ok(node.encode().ok_or(
        "listen.publicHost と listen.friendlyName は、それぞれ 255 バイトまでにしてください",
    )?)
}

/// 別のスレッドでつなぎに行く。つながったら命令の口を `registrations` に入れてから、`Connected` を入れる
fn connect_in_background(
    id: PeerId,
    address: String,
    identity: Arc<Identity>,
    parameters: &'static NetworkParameters,
    events: Sender<NodeEvent>,
    registrations: Sender<(PeerId, Sender<Request>)>,
    announce: Option<Arc<Vec<u8>>>,
) {
    std::thread::spawn(move || {
        let event = match ClientConnection::connect(&address, &identity, CONNECT_TIMEOUT) {
            Ok(connection) => {
                let sender =
                    peer_thread::spawn(id, connection, parameters, events.clone(), announce);
                let _ = registrations.send((id, sender));
                PeerEvent::Connected { id }
            }
            Err(error) => PeerEvent::ConnectFailed {
                id,
                myself: matches!(error, ConnectError::Myself),
            },
        };
        let _ = events.send(NodeEvent::Peer(event));
    });
}

fn known_peers(db: &Db) -> Result<Vec<(String, KnownPeer)>, NodeError> {
    Ok(db
        .known_peers()?
        .into_iter()
        .filter_map(|(address, bytes)| Some((address, KnownPeer::from_bytes(&bytes)?)))
        .collect())
}

fn save_known(db: &Db, records: &[(String, KnownPeer)]) -> Result<(), NodeError> {
    let records: Vec<(String, Vec<u8>)> = records
        .iter()
        .map(|(address, record)| (address.clone(), record.to_bytes()))
        .collect();
    let mut batch = db.batch()?;
    batch.replace_known_peers(&records)?;
    batch.commit()?;
    Ok(())
}

/// REST で届いた連署を待つアグリゲートボンデッドを、駆動役に渡す口。状態に依る確かめは駆動役でするので、
/// ここでは読めるかと種類だけを見る（catapult の REST と同じく、受け付けたら 202 で答える）
fn submit_partial(relay: Sender<NodeEvent>) -> heika_api::Submit {
    Arc::new(move |bytes: Vec<u8>| {
        let transaction = Transaction::from_bytes(&bytes)
            .map_err(|error| format!("トランザクションとして読めません: {error}"))?;
        if !matches!(transaction.body, Body::AggregateBonded(_)) {
            return Err("アグリゲートボンデッドではありません".to_owned());
        }
        relay
            .send(NodeEvent::Partial {
                incoming: Incoming::Transactions(vec![bytes]),
                from: None,
            })
            .map_err(|_| "ノードが止まっています".to_owned())
    })
}

/// REST で届いた連署を、駆動役に渡す口。署名だけはここで確かめる
fn submit_cosignature(relay: Sender<NodeEvent>) -> heika_api::Submit {
    Arc::new(move |bytes: Vec<u8>| {
        let detached = DetachedCosignature::from_bytes(&bytes)
            .map_err(|error| format!("連署として読めません: {error}"))?;
        if !detached.verify() {
            return Err("連署の署名が、アグリゲートのハッシュに対して正しくありません".to_owned());
        }
        relay
            .send(NodeEvent::Partial {
                incoming: Incoming::Cosignatures(vec![detached]),
                from: None,
            })
            .map_err(|_| "ノードが止まっています".to_owned())
    })
}

/// REST で届いたトランザクションを、次のブロックに入れるつもりでメモリプールに入れ、受け付けたらピアに流す口
fn submit(
    parameters: &'static NetworkParameters,
    mempool: Arc<SharedMempool>,
    status: Arc<RwLock<heika_chain::chain::Status>>,
    relay: Sender<NodeEvent>,
) -> heika_api::Submit {
    Arc::new(move |bytes: Vec<u8>| {
        let height = status.read().expect("not poisoned").height + 1;
        let added = mempool
            .lock()
            .add(bytes.clone(), network_now(parameters), height);
        match added {
            Ok(hash) => {
                println!("REST から未承認のトランザクション {hash} を受け付けました");
                let _ = relay.send(NodeEvent::Relay {
                    transactions: Arc::new(bytes),
                    except: None,
                });
                Ok(())
            }
            // 前に受け付けたもの。もう流してある
            Err(Rejected::Known) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    })
}

/// `previous` の次のピア。最後まで来たら最初に戻る
fn next_peer(
    senders: &BTreeMap<PeerId, Sender<Request>>,
    previous: Option<PeerId>,
) -> Option<PeerId> {
    let after = previous.and_then(|previous| {
        senders
            .range((
                std::ops::Bound::Excluded(previous),
                std::ops::Bound::Unbounded,
            ))
            .next()
    });
    after
        .or_else(|| senders.iter().next())
        .map(|(peer, _)| *peer)
}

/// 書く側の鍵。読む側（API）が落ちていても書き続ける
fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Nemesis からのミリ秒。トランザクションの期限と同じ数え方
fn network_now(parameters: &NetworkParameters) -> u64 {
    SystemTime::now()
        .duration_since(parameters.epoch())
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_heavier_storage_mode_than_before() {
        let directory = std::env::temp_dir().join(format!("heika-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let db = Db::open(&directory).unwrap();
        // 初めては何でも通し、覚える
        check_storage_mode(&db, Mode::Full).unwrap();
        check_storage_mode(&db, Mode::Full).unwrap();
        // 重くはできない
        assert!(check_storage_mode(&db, Mode::Archive).is_err());
        // 軽くはでき、それからは軽いほうを覚える
        check_storage_mode(&db, Mode::Light).unwrap();
        assert!(check_storage_mode(&db, Mode::Full).is_err());
        drop(db);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
