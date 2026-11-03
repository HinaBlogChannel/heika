//! 確定（ファイナライズ）の証明が、自分の先端より先を指すとき。ピアの証明はブロックより先に届くことがある
//! （追いつく途中など）。catapult は、ここで先端と確定の高さの引き算が負になって、再起動するまで証明を頼まなく
//! なっていた（symbol/symbol#2202）。中核は、先に証明をしまって確定を上げ、ブロックが追いついたら確定の高さで
//! ハッシュを突き合わせ、次のエポックの証明も頼み続ける。

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use heika_block::Block;
use heika_block::finalization::message::FinalizationMessage;
use heika_block::finalization::proof::build_proof;
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_chain::chain::{Action, Chain, HarvestPlan, Notice};
use heika_chain::env::Env;
use heika_chain::event::{ChainEvent, PeerCommand, PeerId};
use heika_chain::memory::MemoryStore;
use heika_chain::nemesis::{NemesisProperties, generate};
use heika_chain::store::{BlockWrite, ChainStore, now_or_never};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier, NetworkParameters};
use heika_packet::ChainStatistics;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;
use heika_transaction::{Body, KeyLink, LinkAction, MosaicId, Transaction, VotingKeyLink};

const SEED: GenerationHashSeed = GenerationHashSeed([8; 32]);
const STAKE: u64 = 4_400_000_000_000_000;
/// 1エポックのブロックの数。エポック 2 は高さ 2 から 4、エポック 3 は 5 から 8
const GROUPING: u64 = 4;
/// 作るブロックの最後の高さ
const LAST: u64 = 7;

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32])
}

fn address(byte: u8) -> Address {
    Address::from_public_key(
        &PublicKey::from_private_key(&key(byte)),
        NetworkIdentifier::TESTNET,
    )
}

struct Clock(Cell<SystemTime>);

impl Env for Clock {
    fn now(&self) -> SystemTime {
        self.0.get()
    }
}

/// 投票の根の鍵 5 と、エポックごとの下の鍵 6（どのエポックも同じ鍵で済ませる）
const VOTER_ROOT: u8 = 5;
const VOTER_BOTTOM: u8 = 6;

/// 投票者がラウンド `round` で、高さ `height` からのハッシュ `hashes` に投票したメッセージ
fn vote(
    round: FinalizationRound,
    is_prevote: bool,
    height: u64,
    hashes: Vec<Hash256>,
) -> FinalizationMessage {
    let (root, bottom) = (key(VOTER_ROOT), key(VOTER_BOTTOM));
    FinalizationMessage::sign(round, is_prevote, height, hashes, |signed| {
        let bottom_public = PublicKey::from_private_key(&bottom).0;
        let epoch = u64::from(round.epoch).to_le_bytes();
        let mut out = [0; 192];
        out[..32].copy_from_slice(&PublicKey::from_private_key(&root).0);
        out[32..96].copy_from_slice(&root.sign(&[&bottom_public, &epoch]).0);
        out[96..128].copy_from_slice(&bottom_public);
        out[128..].copy_from_slice(&bottom.sign(&[signed]).0);
        Some(out)
    })
    .unwrap()
}

/// ラウンド `round` で、高さ `from` から先のハッシュ `hashes` の最後をファイナライズする証明
fn proof(
    round: FinalizationRound,
    from: u64,
    hashes: &[Hash256],
) -> (FinalizedBlockHeader, Vec<u8>) {
    let height = from + hashes.len() as u64 - 1;
    let header = FinalizedBlockHeader {
        round,
        height,
        hash: *hashes.last().unwrap(),
    };
    let messages = [
        vote(round, true, from, hashes.to_vec()),
        vote(round, false, height, vec![header.hash]),
    ];
    (header, build_proof(&header, &messages))
}

/// 鍵 1 が Nemesis の署名者、鍵 2 と 3 が半分ずつ持つ。鍵 2 は VRF の鍵 9 と投票の鍵を紐づけ、ただ1人の投票者
fn network() -> (ChainConfig, &'static NetworkParameters, Vec<u8>) {
    let signer = PublicKey::from_private_key(&key(1));
    let currency = MosaicId::generate(
        &Address::from_public_key(&signer, NetworkIdentifier::TESTNET),
        0,
    );
    let mut config = ChainConfig::testnet();
    config.nemesis_signer_public_key = signer;
    config.currency_mosaic_id = currency.0;
    config.harvesting_mosaic_id = currency.0;
    config.total_chain_importance = 2 * STAKE;
    config.max_harvester_balance = u64::MAX;
    config.finalization.voting_set_grouping = GROUPING;
    let mut parameters = NetworkParameters::TESTNET;
    parameters.generation_hash_seed = SEED;
    parameters.voting_set_grouping = GROUPING;
    let parameters: &'static NetworkParameters = Box::leak(Box::new(parameters));

    let hex: String = SEED.0.iter().map(|byte| format!("{byte:02X}")).collect();
    let text = format!(
        "[nemesis]\n\nnetworkIdentifier = testnet\nnemesisGenerationHashSeed = {hex}\n\n\
         [namespaces]\n\nsymbol = true\nsymbol.xym = true\n\n[namespace>symbol]\n\nduration = 0\n\n\
         [mosaics]\n\nsymbol:xym = true\n\n[mosaic>symbol:xym]\n\ndivisibility = 6\nduration = 0\n\
         supply = {}\nisTransferable = true\nisSupplyMutable = false\nisRestrictable = false\n\n\
         [distribution>symbol:xym]\n\n{} = {STAKE}\n{} = {STAKE}\n\n\
         [transactions]\n\ntransactionsDirectory =\n",
        2 * STAKE,
        address(2),
        address(3),
    );
    let link = |body| {
        let mut transaction = Transaction::new(
            PublicKey::from_private_key(&key(2)),
            NetworkIdentifier::TESTNET,
            0,
            1,
            body,
        );
        transaction.sign(&key(2), &SEED).unwrap();
        transaction.to_bytes()
    };
    let links = [
        link(Body::VrfKeyLink(KeyLink {
            linked_public_key: PublicKey::from_private_key(&key(9)),
            link_action: LinkAction::Link,
        })),
        link(Body::VotingKeyLink(VotingKeyLink {
            linked_public_key: PublicKey::from_private_key(&key(VOTER_ROOT)),
            start_epoch: 1,
            end_epoch: 100,
            link_action: LinkAction::Link,
        })),
    ];
    let properties = NemesisProperties::parse(&text).unwrap();
    let nemesis = generate(&properties, config.clone(), parameters, &key(1), &links).unwrap();
    (config, parameters, nemesis.block.as_bytes().to_vec())
}

fn seed(store: &MemoryStore, config: &ChainConfig, network: &NetworkParameters, nemesis: &[u8]) {
    let block = Block::from_bytes(nemesis).unwrap();
    let mut executor = Executor::new(
        config.clone(),
        network.identifier,
        network.generation_hash_seed,
    );
    executor.apply(&block).unwrap();
    assert_eq!(executor.state_hash(), block.state_hash);
    let statement = executor.take_statement();
    let changes = executor.take_changes();
    let state = changes
        .puts
        .into_iter()
        .map(|(key, value)| (key, Some(value)))
        .chain(changes.deletes.into_iter().map(|key| (key, None)))
        .collect();
    now_or_never(store.commit_block(BlockWrite {
        height: 1,
        hash: block.hash().0,
        bytes: nemesis,
        state,
        nodes: executor.take_node_changes(),
        statement: statement.to_bytes(),
        voters: Some((2, executor.voting_set(2).encode())),
        meta: executor.encode_meta(),
    }))
    .unwrap();
    // 投票者は鍵 2 だけ
    assert_eq!(executor.voting_set(2).voters.len(), 1);
}

/// 鍵 2 でハーベストして、高さ 2 から [`LAST`] までのブロックを作る
fn produce(
    config: &ChainConfig,
    parameters: &'static NetworkParameters,
    nemesis: &[u8],
) -> Vec<Vec<u8>> {
    let store = MemoryStore::default();
    seed(&store, config, parameters, nemesis);
    let clock = Clock(Cell::new(parameters.epoch() + Duration::from_secs(1)));
    let mut chain = now_or_never(Chain::new(
        &store,
        &clock,
        config.clone(),
        parameters,
        false,
    ))
    .unwrap();
    chain.set_harvesters(Arc::new(vec![(key(2), key(9))]));
    let peer = PeerId(0);
    let nemesis_hash = Block::from_bytes(nemesis).unwrap().hash();
    let mut produced = Vec::new();
    let mut run = |chain: &mut Chain<'_, MemoryStore>, first: ChainEvent| {
        let mut events = vec![first];
        while let Some(event) = events.pop() {
            assert!(now_or_never(chain.handle(event)).unwrap().is_none());
            for action in chain.take_actions() {
                match action {
                    Action::Command(_, PeerCommand::Push(bytes)) => produced.push(bytes.to_vec()),
                    // 偽のピアは Nemesis にいる
                    Action::Command(_, PeerCommand::Statistics) => {
                        events.push(ChainEvent::Statistics {
                            peer,
                            statistics: ChainStatistics {
                                height: 1,
                                finalized_height: 1,
                                score: 0,
                            },
                        })
                    }
                    Action::Command(_, PeerCommand::Finalized) => {
                        events.push(ChainEvent::Finalized {
                            peer,
                            header: FinalizedBlockHeader {
                                round: FinalizationRound { epoch: 1, point: 1 },
                                height: 1,
                                hash: nemesis_hash,
                            },
                        })
                    }
                    Action::Command(_, PeerCommand::PullProof { epoch }) => {
                        events.push(ChainEvent::Proof {
                            peer,
                            epoch,
                            proof: None,
                        })
                    }
                    Action::Notify(notice) if notice.is_warning() => panic!("{notice}"),
                    _ => {}
                }
            }
        }
    };
    run(&mut chain, ChainEvent::PeerAdded { peer });
    while chain.height() < LAST {
        run(&mut chain, ChainEvent::Tick);
        let HarvestPlan::Hit { timestamp, .. } = chain.harvest_plan() else {
            panic!("当たりを求めていません: {:?}", chain.harvest_plan());
        };
        clock.0.set(timestamp);
        run(&mut chain, ChainEvent::Wake);
    }
    assert_eq!(produced.len() as u64, LAST - 1);
    produced
}

/// 偽のピア。ブロック、言う確定、エポックごとの証明を持つ。`height` まで持っていると答える
struct FakePeer {
    blocks: Vec<Vec<u8>>,
    height: u64,
    finalized: FinalizedBlockHeader,
    proofs: HashMap<u32, Vec<u8>>,
    score: u128,
}

/// 追う側の中核を動かした結果
#[derive(Default)]
struct Ran {
    proof_requests: Vec<u32>,
    finalized: Vec<u64>,
    disconnected: bool,
}

impl FakePeer {
    const ID: PeerId = PeerId(0);

    fn run(&self, chain: &mut Chain<'_, MemoryStore>, first: ChainEvent) -> Ran {
        let peer = Self::ID;
        let mut ran = Ran::default();
        let mut events = vec![first];
        while let Some(event) = events.pop() {
            assert!(now_or_never(chain.handle(event)).unwrap().is_none());
            for action in chain.take_actions() {
                let answer = match action {
                    Action::Command(_, PeerCommand::Statistics) => ChainEvent::Statistics {
                        peer,
                        statistics: ChainStatistics {
                            height: self.height,
                            finalized_height: self.finalized.height,
                            score: self.score,
                        },
                    },
                    Action::Command(_, PeerCommand::Finalized) => ChainEvent::Finalized {
                        peer,
                        header: self.finalized,
                    },
                    Action::Command(_, PeerCommand::PullProof { epoch }) => {
                        ran.proof_requests.push(epoch);
                        ChainEvent::Proof {
                            peer,
                            epoch,
                            proof: self.proofs.get(&epoch).cloned(),
                        }
                    }
                    Action::Command(_, PeerCommand::PullBlocks { from, count }) => {
                        let through = (from + u64::from(count) - 1).min(self.height);
                        let blocks = (from..=through)
                            .map(|height| {
                                let bytes = self.blocks[height as usize - 2].clone();
                                (Block::from_bytes(&bytes).unwrap(), bytes)
                            })
                            .collect();
                        ChainEvent::Blocks {
                            peer,
                            from,
                            count,
                            blocks,
                        }
                    }
                    Action::Command(_, PeerCommand::PullHashes { from, count }) => {
                        let through = (from + u64::from(count) - 1).min(self.height);
                        let hashes = (from..=through).map(|height| self.hash(height).0).collect();
                        ChainEvent::Hashes {
                            peer,
                            from,
                            count,
                            hashes,
                        }
                    }
                    Action::Notify(Notice::Finalized { height, .. }) => {
                        ran.finalized.push(height);
                        continue;
                    }
                    Action::Disconnect { .. } => {
                        ran.disconnected = true;
                        continue;
                    }
                    _ => continue,
                };
                if !ran.disconnected {
                    events.push(answer);
                }
            }
        }
        ran
    }

    /// 高さ `height`（2 以上）のブロックのハッシュ
    fn hash(&self, height: u64) -> Hash256 {
        Block::from_bytes(&self.blocks[height as usize - 2])
            .unwrap()
            .hash()
    }
}

/// 作ったブロックを持つピアと、Nemesis だけの追う側
fn setup() -> (
    ChainConfig,
    &'static NetworkParameters,
    Vec<u8>,
    Vec<Vec<u8>>,
) {
    let (config, parameters, nemesis) = network();
    let blocks = produce(&config, parameters, &nemesis);
    (config, parameters, nemesis, blocks)
}

/// 追う側の時計。作ったブロックより後ろにして、未来のブロックとして弾かれないようにする
fn later_clock(blocks: &[Vec<u8>], parameters: &NetworkParameters) -> Clock {
    let last = Block::from_bytes(blocks.last().unwrap()).unwrap();
    Clock(Cell::new(
        parameters.epoch() + Duration::from_millis(last.timestamp) + Duration::from_secs(60),
    ))
}

#[test]
fn keeps_a_proof_ahead_of_the_tip_and_goes_on_requesting_proofs() {
    let (config, parameters, nemesis, blocks) = setup();
    let nemesis_hash = Block::from_bytes(&nemesis).unwrap().hash();
    let store = MemoryStore::default();
    seed(&store, &config, parameters, &nemesis);
    let clock = later_clock(&blocks, parameters);
    let mut chain = now_or_never(Chain::new(&store, &clock, config, parameters, false)).unwrap();

    // ピアはエポック 2 の最後の高さ 4 を確定しているが、まだブロックは渡さない（高さ 1 だと答える）
    let mut peer = FakePeer {
        blocks,
        height: 1,
        finalized: FinalizedBlockHeader {
            round: FinalizationRound { epoch: 1, point: 1 },
            height: 1,
            hash: nemesis_hash,
        },
        proofs: HashMap::new(),
        score: 0,
    };
    let hashes: Vec<Hash256> = std::iter::once(nemesis_hash)
        .chain((2..=GROUPING).map(|height| peer.hash(height)))
        .collect();
    let (header, epoch2) = proof(FinalizationRound { epoch: 2, point: 1 }, 1, &hashes);
    assert_eq!(header.height, GROUPING);
    peer.finalized = header;
    peer.proofs.insert(2, epoch2);

    // 証明が先に届く。投票者は Nemesis で決まっているので確かめられ、先端（1）より先の高さ 4 を確定にする
    let ran = peer.run(&mut chain, ChainEvent::PeerAdded { peer: FakePeer::ID });
    assert_eq!(ran.proof_requests, [2]);
    assert_eq!(ran.finalized, [GROUPING]);
    assert_eq!(chain.height(), 1);
    assert_eq!(chain.status().finalized, header);

    // 同じ確定をまた聞いても、頼み直さない
    let ran = peer.run(&mut chain, ChainEvent::Tick);
    assert!(ran.proof_requests.is_empty());

    // ピアがブロックを渡すようになると追いつき、確定の高さのブロックは証明と合う
    peer.height = LAST;
    peer.score = u128::MAX;
    let ran = peer.run(&mut chain, ChainEvent::Tick);
    assert!(!ran.disconnected);
    assert_eq!(chain.height(), LAST);
    assert_eq!(chain.tip().hash, peer.hash(LAST));

    // 先端が確定を越えたあとも、次のエポックの証明を頼む（catapult はここで止まっていた）
    let hashes: Vec<Hash256> = (GROUPING..=6).map(|height| peer.hash(height)).collect();
    let (header, epoch3) = proof(FinalizationRound { epoch: 3, point: 1 }, GROUPING, &hashes);
    peer.finalized = header;
    peer.proofs.insert(3, epoch3);
    let ran = peer.run(&mut chain, ChainEvent::Tick);
    assert_eq!(ran.proof_requests, [3]);
    assert_eq!(ran.finalized, [6]);
    assert_eq!(chain.status().finalized, header);
}

#[test]
fn rejects_a_block_that_differs_from_a_proof_ahead_of_the_tip() {
    let (config, parameters, nemesis, blocks) = setup();
    let nemesis_hash = Block::from_bytes(&nemesis).unwrap().hash();
    let store = MemoryStore::default();
    seed(&store, &config, parameters, &nemesis);
    let clock = later_clock(&blocks, parameters);
    let mut chain = now_or_never(Chain::new(&store, &clock, config, parameters, false)).unwrap();

    // 投票者が、ピアの枝にない高さ 4 のブロックを確定した
    let mut peer = FakePeer {
        blocks,
        height: 1,
        finalized: FinalizedBlockHeader {
            round: FinalizationRound { epoch: 1, point: 1 },
            height: 1,
            hash: nemesis_hash,
        },
        proofs: HashMap::new(),
        score: 0,
    };
    let mut hashes: Vec<Hash256> = std::iter::once(nemesis_hash)
        .chain((2..=GROUPING).map(|height| peer.hash(height)))
        .collect();
    *hashes.last_mut().unwrap() = Hash256([0xAB; 32]);
    let (header, epoch2) = proof(FinalizationRound { epoch: 2, point: 1 }, 1, &hashes);
    peer.finalized = header;
    peer.proofs.insert(2, epoch2);
    let ran = peer.run(&mut chain, ChainEvent::PeerAdded { peer: FakePeer::ID });
    assert_eq!(ran.finalized, [GROUPING]);

    // ピアの枝は確定の高さで証明と合わないので、その手前で止まる
    peer.height = LAST;
    peer.score = u128::MAX;
    let ran = peer.run(&mut chain, ChainEvent::Tick);
    assert!(ran.disconnected);
    assert_eq!(chain.height(), GROUPING - 1);
    assert_eq!(chain.status().finalized, header);
}
