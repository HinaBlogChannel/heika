//! 小さな Nemesis の上で、中核がハーベストする。偽のピアの高さを聞いたら当たりの時刻を求め
//! （[`Chain::harvest_plan`]）、時計がそこに来たらブロックを作って先端に足し、ピアに押し付ける。

use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use heika_block::Block;
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_chain::chain::{Action, Chain, HarvestPlan, Notice};
use heika_chain::env::Env;
use heika_chain::event::{ChainEvent, PeerCommand, PeerId};
use heika_chain::memory::MemoryStore;
use heika_chain::nemesis::{NemesisProperties, generate};
use heika_chain::store::{BlockWrite, ChainStore, now_or_never};
use heika_chain::verify::verify_alone;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier, NetworkParameters};
use heika_packet::ChainStatistics;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;
use heika_transaction::{Body, KeyLink, LinkAction, MosaicId, Transaction};

const SEED: GenerationHashSeed = GenerationHashSeed([7; 32]);
/// 1人が持つ量。当たりの時刻は importance の絶対の値で決まるので、実際のネットワークと同じくらいの合計
/// （約 90 億 XYM）に近い量を2人で分ける
const STAKE: u64 = 4_400_000_000_000_000;

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32])
}

fn address(byte: u8) -> Address {
    Address::from_public_key(
        &PublicKey::from_private_key(&key(byte)),
        NetworkIdentifier::TESTNET,
    )
}

/// 進めたり戻したりできる時計
struct Clock(Cell<SystemTime>);

impl Env for Clock {
    fn now(&self) -> SystemTime {
        self.0.get()
    }
}

/// 鍵 1 が Nemesis の署名者、鍵 2 と 3 が半分ずつ持ち、鍵 2 は VRF の鍵 9 を紐づけたテストネット
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
    // 1人で半分を持つので、ハーベストできる上限を外す
    config.max_harvester_balance = u64::MAX;
    let mut parameters = NetworkParameters::TESTNET;
    parameters.generation_hash_seed = SEED;
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
    let mut link = Transaction::new(
        PublicKey::from_private_key(&key(2)),
        NetworkIdentifier::TESTNET,
        0,
        1,
        Body::VrfKeyLink(KeyLink {
            linked_public_key: PublicKey::from_private_key(&key(9)),
            link_action: LinkAction::Link,
        }),
    );
    link.sign(&key(2), &SEED).unwrap();
    let properties = NemesisProperties::parse(&text).unwrap();
    let nemesis = generate(
        &properties,
        config.clone(),
        parameters,
        &key(1),
        &[link.to_bytes()],
    )
    .unwrap();
    (config, parameters, nemesis.block.as_bytes().to_vec())
}

/// Nemesis を当てて、保存に書く
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
}

#[test]
fn plans_a_hit_and_produces_when_the_clock_reaches_it() {
    let (config, parameters, nemesis) = network();
    let store = MemoryStore::default();
    seed(&store, &config, parameters, &nemesis);
    let clock = Clock(Cell::new(parameters.epoch() + Duration::from_secs(1)));
    let mut chain = now_or_never(Chain::new(&store, &clock, config, parameters, false)).unwrap();
    assert_eq!(chain.harvest_plan(), HarvestPlan::NotPlanned);
    chain.set_harvesters(Arc::new(vec![(key(2), key(9))]));

    // 偽のピアは Nemesis にいる（自分より先にはいない）
    let peer = PeerId(0);
    let nemesis_hash = Block::from_bytes(&nemesis).unwrap().hash();
    let answer = |command: PeerCommand| match command {
        PeerCommand::Statistics => Some(ChainEvent::Statistics {
            peer,
            statistics: ChainStatistics {
                height: 1,
                finalized_height: 1,
                score: 0,
            },
        }),
        PeerCommand::Finalized => Some(ChainEvent::Finalized {
            peer,
            header: FinalizedBlockHeader {
                round: FinalizationRound { epoch: 1, point: 1 },
                height: 1,
                hash: nemesis_hash,
            },
        }),
        PeerCommand::PullProof { epoch } => Some(ChainEvent::Proof {
            peer,
            epoch,
            proof: None,
        }),
        _ => None,
    };
    // 出来事を流し、ピアへの命令に答える。押し付けたブロックと、作った高さを返す
    let run = |chain: &mut Chain<'_, MemoryStore>, first: ChainEvent| {
        let (mut pushed, mut produced) = (Vec::new(), Vec::new());
        let mut events = vec![first];
        while let Some(event) = events.pop() {
            assert!(now_or_never(chain.handle(event)).unwrap().is_none());
            for action in chain.take_actions() {
                match action {
                    Action::Command(_, PeerCommand::Push(bytes)) => pushed.push(bytes),
                    Action::Command(_, command) => events.extend(answer(command)),
                    Action::Notify(Notice::Produced { height, .. }) => produced.push(height),
                    Action::Notify(notice) if notice.is_warning() => panic!("{notice}"),
                    _ => {}
                }
            }
        }
        (pushed, produced)
    };

    run(&mut chain, ChainEvent::PeerAdded { peer });
    let (pushed, _) = run(&mut chain, ChainEvent::Tick);
    let HarvestPlan::Hit { height, timestamp } = chain.harvest_plan() else {
        panic!("当たりを求めていません: {:?}", chain.harvest_plan());
    };
    assert_eq!(height, 2);
    assert!(pushed.is_empty(), "時刻の前に作りました");

    clock.0.set(timestamp);
    let (pushed, produced) = run(&mut chain, ChainEvent::Wake);
    assert_eq!(produced, [2]);
    assert_eq!(chain.height(), 2);
    assert_eq!(pushed.len(), 1);
    let block = Block::from_bytes(&pushed[0]).unwrap();
    verify_alone(parameters, &block).unwrap();
    assert_eq!(block.height, 2);
    assert_eq!(block.hash(), chain.tip().hash);
    assert_eq!(
        block.signer_public_key,
        PublicKey::from_private_key(&key(2))
    );
    // 先端が変わったので、次に求めるまでは予定がない
    assert_eq!(chain.harvest_plan(), HarvestPlan::NotPlanned);
    assert_eq!(chain.harvest_outlook(), None);

    // 求め直すと、直近のブロックが2つになったので、見込みも出る。作ったのは自分だけなので、自分で全部を作る見込み
    run(&mut chain, ChainEvent::Tick);
    assert!(matches!(
        chain.harvest_plan(),
        HarvestPlan::Hit { height: 3, .. }
    ));
    let outlook = chain.harvest_outlook().unwrap();
    assert_eq!(outlook.importance, STAKE);
    assert!(outlook.active_importance >= STAKE as f64);
    assert!(outlook.per_block > 0.0 && outlook.per_block <= 1.0);
    assert!(outlook.block_seconds > 0.0);
    let next = outlook.next.unwrap();
    assert!(next > 0.0 && next <= 1.0, "{next}");
}
