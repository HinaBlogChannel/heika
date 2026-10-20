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
//! `HEIKA_TEST_REPLAY_TO` を渡すと、その高さで止める。

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use heika_block::Block;
use heika_core::network::NetworkParameters;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;

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
        assert_eq!(
            executor.state_hash(),
            block.state_hash,
            "高さ {height} の StateHash"
        );
        assert!(
            block.verify_receipts_hash(&executor.take_statement()),
            "高さ {height} の ReceiptsHash"
        );
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
