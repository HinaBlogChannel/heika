//! メインネットのブロックを当て、ブロックごとに redb に書きながら、書いた DB から要るものだけを読んで続きを当てる。
//! 状態遷移の当て直し（heika-state-transition の `tests/replay.rs`）を、メモリの読み口の代わりに DB で。
//!
//! ブロックと設定と、DB を作るフォルダー（空のもの。大きくなるので、ルートのディスクでないところ）を渡したときだけ
//! 走らせる。`HEIKA_TEST_PARTIAL_FROM`（既定 20000）までを全部メモリに持つ形で当てて書き、そこから
//! `HEIKA_TEST_REPLAY_TO`（既定 +10000）までを、DB を 64 MB のキャッシュで包んで当てる。
//!
//! ```text
//! HEIKA_TEST_BLOCKS=mainnet-1-950000.blocks HEIKA_TEST_RESOURCES=/path/to/resources HEIKA_TEST_DATA=/path/to/empty \
//!     cargo test --release -p heika-store-redb --test replay -- --ignored --nocapture
//! ```

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use heika_block::Block;
use heika_core::network::NetworkParameters;
use heika_core::patricia::SubCache;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::source::CachedSource;
use heika_state_transition::executor::{Executor, is_partial_row};
use heika_store_redb::Db;

/// 何ブロックごとにコミットするか（全部メモリに持つ形のあいだ）
const COMMIT_EVERY: u64 = 1_000;
const MAX_RETRIES: usize = 8;

fn blocks(path: &str) -> impl Iterator<Item = Block> {
    let mut file = BufReader::new(File::open(path).expect("HEIKA_TEST_BLOCKS を開けません"));
    std::iter::from_fn(move || {
        let mut size = [0; 4];
        file.read_exact(&mut size).ok()?;
        let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
        bytes[..4].copy_from_slice(&size);
        file.read_exact(&mut bytes[4..])
            .expect("ブロックが途中で切れています");
        Some(Block::from_bytes(&bytes).expect("ブロックを読めません"))
    })
}

fn env_height(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} が数ではありません"))
        })
        .unwrap_or(default)
}

/// 当てたブロックの変わった行とノード（`None` は消えた）
type Writes = Vec<(Vec<u8>, Option<Vec<u8>>)>;

fn take_writes(executor: &mut Executor) -> (Writes, Writes) {
    let changes = executor.take_changes();
    let rows = changes
        .puts
        .into_iter()
        .map(|(key, value)| (key, Some(value)))
        .chain(changes.deletes.into_iter().map(|key| (key, None)))
        .collect();
    (rows, executor.take_node_changes())
}

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

#[test]
#[ignore = "HEIKA_TEST_BLOCKS、HEIKA_TEST_RESOURCES、HEIKA_TEST_DATA を渡す"]
fn replays_mainnet_blocks_through_redb() {
    let path = std::env::var("HEIKA_TEST_BLOCKS").expect("HEIKA_TEST_BLOCKS がありません");
    let resources =
        std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    let data = std::env::var("HEIKA_TEST_DATA").expect("HEIKA_TEST_DATA がありません");
    assert!(
        !Path::new(&data).join(heika_store_redb::FILE_NAME).exists(),
        "HEIKA_TEST_DATA には空のフォルダーを渡してください"
    );
    let from = env_height("HEIKA_TEST_PARTIAL_FROM", 20_000);
    let to = env_height("HEIKA_TEST_REPLAY_TO", from + 10_000);
    let network = NetworkParameters::MAINNET;
    let config = ChainConfig::load(Path::new(&resources)).expect("設定を読めません");
    let db = Db::open(Path::new(&data)).expect("DB を開けません");
    let mut executor = Executor::new(
        config.clone(),
        network.identifier,
        network.generation_hash_seed,
    );
    let mut blocks = blocks(&path);
    let mut batch = db.batch().unwrap();
    batch.start_history(1).unwrap();
    batch.start_trie(1).unwrap();
    for block in blocks.by_ref() {
        let height = block.height;
        executor
            .apply(&block)
            .unwrap_or_else(|error| panic!("高さ {height}: {error}"));
        check(&mut executor, &block);
        let (rows, nodes) = take_writes(&mut executor);
        batch.set_state_at(height, rows).unwrap();
        batch.set_trie_at(height, nodes).unwrap();
        if height.is_multiple_of(COMMIT_EVERY) || height == from {
            batch.put_meta("executor", &executor.encode_meta()).unwrap();
            batch.commit().unwrap();
            batch = db.batch().unwrap();
        }
        if height == from {
            break;
        }
    }
    drop(batch);
    // 大きい表は読まずに（ハッシュロックは期限の来ていないものを選ぶために読む）、木は大きい表のもの以外を読んで戻す
    let mut rows = Vec::new();
    let mut nodes = Vec::new();
    for cache in SubCache::ALL {
        let prefix = [cache.index() as u8];
        if !is_partial_row(&prefix) || cache == SubCache::HashLockInfo {
            db.for_each_state_row(&prefix, &mut |key, value| {
                rows.push((key.to_vec(), value.to_vec()))
            })
            .unwrap();
        }
        if !is_partial_row(&prefix) {
            db.for_each_trie_node(&prefix, &mut |key, value| {
                nodes.push((key.to_vec(), value.to_vec()))
            })
            .unwrap();
        }
    }
    let mut meta = db
        .meta("executor")
        .unwrap()
        .expect("実行の状態がありません");
    let mut executor = Executor::restore_partial(
        config,
        network.identifier,
        network.generation_hash_seed,
        rows,
        &meta,
    )
    .expect("要るものだけを読む形に戻せません");
    executor.restore_trees(nodes).expect("木を戻せません");
    let source = CachedSource::new(db, 64 << 20);
    executor
        .load_tree_roots(&source)
        .expect("木の根を読めません");
    let mut last = from;
    for block in blocks {
        let height = block.height;
        if height > to {
            break;
        }
        executor
            .load_wanted(&source, &executor.wanted_for(&block))
            .unwrap();
        let mut retries = 0;
        loop {
            let applied = executor.apply(&block);
            executor.state_hash();
            let missed = executor.take_missed();
            if missed.is_empty() {
                applied.unwrap_or_else(|error| panic!("高さ {height}: {error}"));
                break;
            }
            retries += 1;
            assert!(
                retries <= MAX_RETRIES,
                "高さ {height} で読み足しが終わりません"
            );
            executor.undo_attempt(&source, &meta).unwrap();
            executor.load_wanted(&source, &missed).unwrap();
        }
        check(&mut executor, &block);
        let (rows, nodes) = take_writes(&mut executor);
        meta = executor.encode_meta();
        let mut batch = source.inner().batch().unwrap();
        batch.set_state_at(height, rows.iter().cloned()).unwrap();
        batch.set_trie_at(height, nodes.iter().cloned()).unwrap();
        batch.put_meta("executor", &meta).unwrap();
        batch.commit_lazily().unwrap();
        source.record(rows, nodes);
        executor.release_loaded();
        last = height;
    }
    assert!(last > from, "切り替えたあとのブロックがありません");
    let stats = source.stats();
    eprintln!(
        "高さ {last} まで合いました（DB から要るものだけを読んで {} ブロック、キャッシュの外れ {}）",
        last - from,
        stats.misses
    );
}
