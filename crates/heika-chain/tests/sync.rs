//! 偽のピアから、メインネットのブロックを Nemesis から同期する。中核は IO を持たないので、ピアへの命令に
//! テストが答えれば、ピアも DB もなしに動かせる。
//!
//! ブロックはリポジトリに入れないので、ファイルと設定を渡したときだけ走らせる（heika-state-transition の
//! `tests/replay.rs` と同じファイル）。
//!
//! ```text
//! HEIKA_TEST_BLOCKS=mainnet-1-950000.blocks HEIKA_TEST_RESOURCES=/path/to/resources \
//!     cargo test --release -p heika-chain --test sync -- --ignored --nocapture
//! ```
//!
//! `HEIKA_TEST_SYNC_TO`（既定 20000）の高さまで進める。

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::SystemTime;

use heika_block::Block;
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_chain::chain::{Action, Chain};
use heika_chain::env::Env;
use heika_chain::event::{ChainEvent, PeerCommand, PeerId};
use heika_chain::memory::MemoryStore;
use heika_chain::store::{BlockWrite, ChainStore, now_or_never};
use heika_chain::verify::verify_alone;
use heika_core::network::NetworkParameters;
use heika_packet::ChainStatistics;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;

/// 今の時刻を返す時計（ブロックはどれも過去なので、未来のブロックとして待たない）
struct Clock;

impl Env for Clock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

fn read_blocks(path: &str, to: u64) -> Vec<Vec<u8>> {
    let mut file = BufReader::new(File::open(path).expect("HEIKA_TEST_BLOCKS を開けません"));
    let mut blocks = Vec::new();
    while (blocks.len() as u64) < to {
        let mut size = [0; 4];
        if file.read_exact(&mut size).is_err() {
            break;
        }
        let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
        bytes[..4].copy_from_slice(&size);
        file.read_exact(&mut bytes[4..])
            .expect("ブロックが途中で切れています");
        blocks.push(bytes);
    }
    blocks
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
#[ignore = "HEIKA_TEST_BLOCKS と HEIKA_TEST_RESOURCES を渡す"]
fn syncs_mainnet_from_a_fake_peer() {
    let path = std::env::var("HEIKA_TEST_BLOCKS").expect("HEIKA_TEST_BLOCKS がありません");
    let resources =
        std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    let to: u64 = std::env::var("HEIKA_TEST_SYNC_TO")
        .map(|to| to.parse().expect("HEIKA_TEST_SYNC_TO が数ではありません"))
        .unwrap_or(20_000);
    let network = &NetworkParameters::MAINNET;
    let config = ChainConfig::load(Path::new(&resources)).expect("設定を読めません");
    let blocks = read_blocks(&path, to);
    assert_eq!(blocks.len() as u64, to, "ファイルのブロックが足りません");
    let store = MemoryStore::default();
    seed(&store, &config, network, &blocks[0]);
    let started = std::time::Instant::now();
    let mut chain =
        now_or_never(Chain::new(&store, &Clock, config, network, false)).expect("始められません");

    // 偽のピア。確定は Nemesis のまま（証明は持っていない）。スコアは高いと言う
    let peer = PeerId(0);
    let nemesis = Block::from_bytes(&blocks[0]).unwrap();
    let statistics = ChainStatistics {
        height: to,
        finalized_height: 1,
        score: u128::MAX / 2,
    };
    let finalized = FinalizedBlockHeader {
        round: FinalizationRound { epoch: 1, point: 1 },
        height: 1,
        hash: nemesis.hash(),
    };
    let answer = |command: PeerCommand| -> Option<ChainEvent> {
        Some(match command {
            PeerCommand::Statistics => ChainEvent::Statistics { peer, statistics },
            PeerCommand::Finalized => ChainEvent::Finalized {
                peer,
                header: finalized,
            },
            PeerCommand::PullProof { epoch } => ChainEvent::Proof {
                peer,
                epoch,
                proof: None,
            },
            PeerCommand::PullHashes { from, count } => ChainEvent::Hashes {
                peer,
                from,
                count,
                hashes: (from..(from + u64::from(count)).min(to + 1))
                    .map(|height| {
                        Block::from_bytes(&blocks[height as usize - 1])
                            .unwrap()
                            .hash()
                            .0
                    })
                    .collect(),
            },
            PeerCommand::PullBlocks { from, count } => ChainEvent::Blocks {
                peer,
                from,
                count,
                blocks: (from..(from + u64::from(count)).min(to + 1))
                    .map(|height| {
                        let bytes = blocks[height as usize - 1].clone();
                        let block = Block::from_bytes(&bytes).unwrap();
                        verify_alone(network, &block).expect("状態を見ない確かめ");
                        (block, bytes)
                    })
                    .collect(),
            },
            PeerCommand::Push(_) => return None,
        })
    };

    let mut events = vec![ChainEvent::PeerAdded { peer }];
    let mut ticks = 0;
    while chain.height() < to {
        if events.is_empty() {
            ticks += 1;
            assert!(ticks < 100_000, "進みません（高さ {}）", chain.height());
            events.push(ChainEvent::Tick);
        }
        let event = events.remove(0);
        let outcome = now_or_never(chain.handle(event)).expect("中核が止まりました");
        assert!(outcome.is_none(), "先端の段階を抜けました");
        for action in chain.take_actions() {
            match action {
                Action::Command(_, command) => events.extend(answer(command)),
                Action::Disconnect { penalty, .. } => {
                    panic!("ピアを外しました（{penalty:?}、高さ {}）", chain.height())
                }
                Action::Notify(notice) if notice.is_warning() => {
                    panic!("{notice}（高さ {}）", chain.height())
                }
                _ => {}
            }
        }
    }
    let tip = Block::from_bytes(&blocks[to as usize - 1]).unwrap();
    assert_eq!(chain.tip().hash, tip.hash());
    assert!(chain.state_matches(), "先端の StateHash が合いません");
    eprintln!(
        "偽のピアから高さ {to} まで同期しました（Tick {ticks}、{:.0} 秒）",
        started.elapsed().as_secs_f64()
    );
}
