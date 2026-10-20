//! メインネットのブロックを Nemesis から当て直し、ブロックごとの StateHash と ReceiptsHash が合うか。
//!
//! ブロックはリポジトリに入れないので、ファイルと設定を渡したときだけ走らせる。ファイルは、ブロックのバイト列を
//! 高さの順に続けたもの（それぞれ先頭 4 バイトが自分の長さ）。
//!
//! ```text
//! HEIKA_TEST_BLOCKS=mainnet-1-950000.blocks HEIKA_TEST_RESOURCES=/path/to/resources \
//!     cargo test --release -p heika-state-transition --test replay -- --ignored --nocapture
//! ```
//!
//! `HEIKA_TEST_REPLAY_TO` を渡すと、その高さで止める。要るものだけを読む形の当て直しは、
//! `HEIKA_TEST_PARTIAL_FROM`（既定 100000）までを全部メモリに持つ形で当て、そこから切り替える。

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use heika_block::Block;
use heika_core::network::NetworkParameters;
use heika_core::patricia::SubCache;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::source::StateSource;
use heika_state_transition::executor::{ExecError, Executor, is_partial_row};

/// 読み足すのを繰り返す回数の上限
const MAX_RETRIES: usize = 8;

/// 保存の代わり。コミットした状態の行と木のノードを持つ
#[derive(Default)]
struct Memory {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    nodes: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Memory {
    /// 当てたブロックの、変わった行とノードを書く
    fn commit(&mut self, executor: &mut Executor) {
        let changes = executor.take_changes();
        for (key, value) in changes.puts {
            self.rows.insert(key, value);
        }
        for key in changes.deletes {
            self.rows.remove(&key);
        }
        for (key, node) in executor.take_node_changes() {
            match node {
                Some(node) => self.nodes.insert(key, node),
                None => self.nodes.remove(&key),
            };
        }
    }
}

impl StateSource for Memory {
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        Ok(self.rows.get(key).cloned())
    }

    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        Ok(self.nodes.get(key).cloned())
    }

    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError> {
        for (key, value) in self.rows.range(prefix.to_vec()..) {
            if !key.starts_with(prefix) {
                break;
            }
            visit(key, value);
        }
        Ok(())
    }
}

/// 環境変数の高さ。なければ `default`
fn height_from_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} が数ではありません"))
        })
        .unwrap_or(default)
}

fn setup() -> (String, ChainConfig) {
    let path = std::env::var("HEIKA_TEST_BLOCKS").expect("HEIKA_TEST_BLOCKS がありません");
    let resources =
        std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    let config = ChainConfig::load(Path::new(&resources)).expect("設定を読めません");
    (path, config)
}

/// 当てたあとの StateHash と ReceiptsHash を確かめる
fn check(executor: &mut Executor, block: &Block) {
    let height = block.height;
    assert_eq!(
        executor.state_hash(),
        block.state_hash,
        "高さ {height} の StateHash"
    );
    assert!(
        block.verify_receipts_hash(&executor.take_statement()),
        "高さ {height} の ReceiptsHash"
    );
}

/// ファイルから、ブロックのバイト列を1つずつ読む
fn blocks(path: &str) -> impl Iterator<Item = Vec<u8>> {
    let mut file = BufReader::new(File::open(path).expect("HEIKA_TEST_BLOCKS を開けません"));
    std::iter::from_fn(move || {
        let mut size = [0; 4];
        file.read_exact(&mut size).ok()?;
        let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
        bytes[..4].copy_from_slice(&size);
        file.read_exact(&mut bytes[4..])
            .expect("ブロックが途中で切れています");
        Some(bytes)
    })
}

#[test]
#[ignore = "HEIKA_TEST_BLOCKS と HEIKA_TEST_RESOURCES を渡す"]
fn replays_mainnet_blocks() {
    let path = std::env::var("HEIKA_TEST_BLOCKS").expect("HEIKA_TEST_BLOCKS がありません");
    let resources =
        std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    let to: u64 = std::env::var("HEIKA_TEST_REPLAY_TO")
        .map(|to| to.parse().expect("HEIKA_TEST_REPLAY_TO が数ではありません"))
        .unwrap_or(u64::MAX);
    let network = NetworkParameters::MAINNET;
    let config = ChainConfig::load(Path::new(&resources)).expect("設定を読めません");
    let mut executor = Executor::new(config, network.identifier, network.generation_hash_seed);
    let started = std::time::Instant::now();
    let mut last = 0;
    for bytes in blocks(&path) {
        let block = Block::from_bytes(&bytes).expect("ブロックを読めません");
        let height = block.height;
        if height > to {
            break;
        }
        assert_eq!(height, last + 1, "高さが続いていません");
        executor
            .apply(&block)
            .unwrap_or_else(|error| panic!("高さ {height} を当てられません: {error}"));
        check(&mut executor, &block);
        // しまわないので、変わった行とノードは捨てる
        executor.take_changes();
        executor.take_node_changes();
        last = height;
        if height.is_multiple_of(100_000) {
            eprintln!("高さ {height}（{:.0} 秒）", started.elapsed().as_secs_f64());
        }
    }
    assert!(last > 0, "ブロックがありません");
    eprintln!(
        "高さ {last} まで合いました（{:.0} 秒）",
        started.elapsed().as_secs_f64()
    );
}

#[test]
#[ignore = "HEIKA_TEST_BLOCKS と HEIKA_TEST_RESOURCES を渡す"]
fn replays_mainnet_blocks_reading_only_what_it_needs() {
    let (path, config) = setup();
    let from = height_from_env("HEIKA_TEST_PARTIAL_FROM", 100_000);
    let to = height_from_env("HEIKA_TEST_REPLAY_TO", from + 50_000);
    let network = NetworkParameters::MAINNET;
    let mut memory = Memory::default();
    let mut executor = Executor::new(
        config.clone(),
        network.identifier,
        network.generation_hash_seed,
    );
    let started = std::time::Instant::now();
    let mut blocks =
        blocks(&path).map(|bytes| Block::from_bytes(&bytes).expect("ブロックを読めません"));
    for block in blocks.by_ref() {
        executor
            .apply(&block)
            .unwrap_or_else(|error| panic!("高さ {} を当てられません: {error}", block.height));
        check(&mut executor, &block);
        memory.commit(&mut executor);
        if block.height == from {
            break;
        }
    }
    // 大きい表は読まずに、ハッシュロックは期限の来ていないものを選ぶために読んで、木は大きい表のもの以外を読んで戻す
    let mut meta = executor.encode_meta();
    let rows: Vec<(Vec<u8>, Vec<u8>)> = memory
        .rows
        .iter()
        .filter(|(key, _)| !is_partial_row(key) || key[0] == SubCache::HashLockInfo.index() as u8)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let nodes: Vec<(Vec<u8>, Vec<u8>)> = memory
        .nodes
        .iter()
        .filter(|(key, _)| !is_partial_row(&key[..1]))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mut executor = Executor::restore_partial(
        config,
        network.identifier,
        network.generation_hash_seed,
        rows,
        &meta,
    )
    .expect("要るものだけを読む形に戻せません");
    executor.restore_trees(nodes).expect("木を戻せません");
    executor
        .load_tree_roots(&memory)
        .expect("木の根を読めません");
    eprintln!(
        "高さ {from} から要るものだけを読みます（{:.0} 秒）",
        started.elapsed().as_secs_f64()
    );
    let mut retried = 0;
    let mut last = from;
    for block in blocks {
        let height = block.height;
        if height > to {
            break;
        }
        executor
            .load_wanted(&memory, &executor.wanted_for(&block))
            .expect("読めません");
        let mut retries = 0;
        loop {
            let applied = executor.apply(&block);
            executor.state_hash();
            let missed = executor.take_missed();
            if missed.is_empty() {
                applied.unwrap_or_else(|error| panic!("高さ {height} を当てられません: {error}"));
                break;
            }
            retries += 1;
            assert!(
                retries <= MAX_RETRIES,
                "高さ {height} で読み足しが終わりません"
            );
            executor
                .undo_attempt(&memory, &meta, &block)
                .expect("戻せません");
            executor.load_wanted(&memory, &missed).expect("読めません");
        }
        retried += usize::from(retries > 0);
        check(&mut executor, &block);
        memory.commit(&mut executor);
        meta = executor.encode_meta();
        last = height;
    }
    assert!(last > from, "切り替えたあとのブロックがありません");
    eprintln!(
        "高さ {last} まで合いました（読み足して当て直したブロック {retried}、{:.0} 秒）",
        started.elapsed().as_secs_f64()
    );
}
