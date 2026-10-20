//! 先端の段階の駆動役。中核（[`Chain`]）とピアの意思決定（[`Peers`]）の2つの状態機械に出来事を入れ、返ってきた
//! 指示を、スレッドとソケットで実際にする。受信箱は1本で、ピアのスレッド、つなぎに行くスレッド、時刻のスレッド、
//! 待ち受けが、そこに出来事を入れる。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heika_block::Block;
use heika_cert::certificate::Certificate;
use heika_cert::key::private_key_from_pem;
use heika_chain::chain::{Action, CHECKPOINT_EPOCHS, Chain, Keep, Outcome, Penalty};
use heika_chain::env::SystemEnv;
use heika_chain::event::{ChainEvent, PeerId};
use heika_chain::store::{BlockWrite, ChainStore, EXECUTOR_META, now_or_never};
use heika_chain::verify::nemesis_hash;
use heika_core::hash::Hash256;
use heika_core::key::PrivateKey;
use heika_core::network::NetworkParameters;
use heika_packet::{NetworkNode, NodeRoles, NodeVersion};
use heika_peer::{Book, KnownPeer, PeerAction, PeerEvent, Peers};
use heika_peer_protocol::ClientConnection;
use heika_state_transition::config::{ChainConfig, load_network_parameters};
use heika_state_transition::executor::Executor;
use heika_store_redb::Db;
use heika_tls::{ConnectError, Identity};

use crate::config::{Manifest, NetworkType, NodeConfig};
use crate::keys::{others_can_read, read_private_key};
use crate::peer_thread::{self, NodeEvent, Request};
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

/// ノードを動かせなかったわけ
pub type NodeError = Box<dyn std::error::Error + Send + Sync>;

/// 設定 `manifest` のノードを、`stopping` が真になるまで先端の段階で動かす。DB が空なら、ピアから Nemesis を
/// 取って始める
pub fn run(manifest: &Manifest, stopping: &(dyn Fn() -> bool + Sync)) -> Result<(), NodeError> {
    let spec = &manifest.spec;
    let parameters = network_parameters(spec)?;
    let nemesis = match &spec.network.nemesis_hash {
        Some(hash) => hash
            .parse()
            .map_err(|_| "network.nemesisHash が読めません")?,
        None => nemesis_hash(parameters.identifier).ok_or("知らないネットワークです")?,
    };
    let config = ChainConfig::load(&spec.network.resources)?;
    let identity = Arc::new(load_identity(&spec.certificates.directory)?);
    let harvesters = Arc::new(read_harvesters(spec)?);
    let mut db = Db::open_with_cache(
        &spec.data_directory,
        spec.storage.cache.database_megabytes << 20,
    )?;
    db.set_min_free(spec.min_free_gigabytes * 1_000_000_000);
    let now = Instant::now();
    let mut book = Book::load(known_peers(&db)?, now, unix_now());
    if let Some(seed) = &spec.seed {
        book.insert(seed.clone(), now);
    }
    if db.meta(EXECUTOR_META)?.is_none() {
        seed_nemesis(&db, &mut book, &identity, &config, parameters, nemesis)?;
    }
    let store = CachedStore::new(db, spec.storage.cache.state_megabytes << 20);
    let mut chain = now_or_never(Chain::new(
        &store,
        &SystemEnv,
        config,
        parameters,
        spec.storage.partial_state(),
    ))?;
    if let Some(keep) = keep(spec)? {
        chain.set_keep(keep);
    }
    chain.set_harvesters(harvesters);
    let mut peers = Peers::new(book, parameters, *identity.key(), spec.peers);
    let announce = spec
        .listen
        .as_ref()
        .map(|listen| local_node(&identity, listen, parameters))
        .transpose()?
        .map(Arc::new);
    let status = RwLock::new(chain.status());
    let reply = RwLock::new(peers.reply());
    let gate = Gate::default();
    let (events, inbox) = mpsc::channel::<NodeEvent>();
    let done = std::sync::atomic::AtomicBool::new(false);
    let outcome = std::thread::scope(|scope| -> Result<Outcome, NodeError> {
        if let (Some(listen), Some(node)) = (&spec.listen, &announce) {
            let listener = std::net::TcpListener::bind(&listen.address)
                .map_err(|error| format!("{} で待ち受けられません: {error}", listen.address))?;
            let (status, reply, gate, done) = (&status, &reply, &gate, &done);
            let (db, pushes, node) = (store.db(), events.clone(), node.to_vec());
            let server_config = Arc::new(heika_tls::server_config(&identity));
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
                        NodeEvent::Chain(event) => {
                            if let Some(outcome) = now_or_never(chain.handle(event))? {
                                return Ok(outcome);
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
                            Action::Notify(notice) if notice.is_warning() => eprintln!("{notice}"),
                            Action::Notify(notice) => println!("{notice}"),
                        }
                    }
                    for action in peers.take_actions() {
                        match action {
                            PeerAction::Connect { id, address } => connect_in_background(
                                id,
                                address,
                                Arc::clone(&identity),
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
            }
            Ok(Outcome::Stopped)
        })();
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        result
    })?;
    save_known(store.db(), &peers.book().records())?;
    match outcome {
        Outcome::Stopped => Ok(()),
        Outcome::Behind { finalized } => Err(format!(
            "確定（高さ {finalized}）まで遅れています。追いつく段階は、まだありません"
        )
        .into()),
    }
}

fn network_parameters(spec: &NodeConfig) -> Result<&'static NetworkParameters, NodeError> {
    Ok(match spec.network.network_type {
        NetworkType::Mainnet => &NetworkParameters::MAINNET,
        NetworkType::Testnet => &NetworkParameters::TESTNET,
        NetworkType::Custom => {
            Box::leak(Box::new(load_network_parameters(&spec.network.resources)?))
        }
    })
}

/// 残し方（`storage.mode`）を、中核の刈り込みの設定にする。`archive` なら刈り込まない
fn keep(spec: &NodeConfig) -> Result<Option<Keep>, NodeError> {
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
fn read_harvesters(spec: &NodeConfig) -> Result<Vec<(PrivateKey, PrivateKey)>, NodeError> {
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
    if !keys.is_empty() {
        println!("{} 組の鍵でハーベストします", keys.len());
    }
    Ok(keys)
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

/// 空の DB に、ピアから取った Nemesis を当てて書く。ハッシュが `nemesis` でなければ使わない
fn seed_nemesis(
    db: &Db,
    book: &mut Book,
    identity: &Identity,
    config: &ChainConfig,
    parameters: &NetworkParameters,
    nemesis: Hash256,
) -> Result<(), NodeError> {
    let now = Instant::now();
    let bytes = loop {
        let address = book
            .take(now)
            .ok_or("Nemesis を取れるノードがありません（seed を書いてください）")?;
        let pulled = ClientConnection::connect(&address, identity, CONNECT_TIMEOUT)
            .map_err(|error| error.to_string())
            .and_then(|mut connection| {
                connection
                    .pull_blocks(1, 1, 16 << 20)
                    .map_err(|error| error.to_string())
            });
        match pulled.map(|mut blocks| blocks.pop()) {
            Ok(Some(bytes)) => {
                // 取り終えたら住所録に戻し、先端の段階でまたつなげるようにする
                book.connected(&address, unix_now());
                book.release(&address);
                break bytes;
            }
            _ => book.failed(&address, now),
        }
    };
    let block = Block::from_bytes(&bytes)?;
    if block.hash() != nemesis {
        return Err("ピアの Nemesis のハッシュが、このネットワークのものと違います".into());
    }
    let mut executor = Executor::new(
        config.clone(),
        parameters.identifier,
        parameters.generation_hash_seed,
    );
    executor.apply(&block)?;
    if executor.state_hash() != block.state_hash {
        return Err("Nemesis の StateHash が合いません".into());
    }
    let statement = executor.take_statement();
    let changes = executor.take_changes();
    let state = changes
        .puts
        .into_iter()
        .map(|(key, value)| (key, Some(value)))
        .chain(changes.deletes.into_iter().map(|key| (key, None)))
        .collect();
    now_or_never(db.commit_block(BlockWrite {
        height: 1,
        hash: block.hash().0,
        bytes: &bytes,
        state,
        nodes: executor.take_node_changes(),
        statement: statement.to_bytes(),
        voters: Some((2, executor.voting_set(2).encode())),
        meta: executor.encode_meta(),
    }))?;
    println!("Nemesis から始めます");
    Ok(())
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
