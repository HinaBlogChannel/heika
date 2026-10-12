//! メインネットのノードから取ったブロックで、ブロックの読み込み、署名、ハッシュを確かめる。
//!
//! 実際のチェーンが正なので、公式ベクターでは確かめられない署名とハッシュのつながりをここで見る。
//! つなぐノードと名乗る証明書は、リポジトリに残さないように環境変数で渡す。
//!
//! ```sh
//! HEIKA_TEST_NODE=<ホスト>:<ポート> \
//! HEIKA_TEST_CLIENT_CERT=$PWD/node.full.crt.pem \
//! HEIKA_TEST_CLIENT_KEY=$PWD/node.key.pem \
//! cargo test -p heika-vectors --test mainnet -- --include-ignored
//! ```
//!
//! HEIKA_TEST_NODE がなければ、何も確かめずに成功する（CI ではそうなる）。
//! 同じ IP から違う証明書で次々につなぐとノードに嫌われるので、いつも同じ証明書を使う。

use std::env;
use std::fs;
use std::time::Duration;

use heika_block::{Block, BlockType};
use heika_cert::certificate::Certificate;
use heika_cert::key;
use heika_core::network::NetworkIdentifier;
use heika_p2p::Node;
use heika_tls::Identity;
use heika_transaction::{Content, scan};

const TIMEOUT: Duration = Duration::from_secs(30);

/// 取る高さの範囲。どれも決まった規則で選んでいる。
const RANGES: [(&str, u64, u32); 4] = [
    // Nemesis のブロックから。Nemesis は Importance のフッターを持ち、4.7 MB ある
    ("Nemesis とその次", 1, 3),
    // 最初の Importance ブロック（importanceGrouping = 720）の前後
    ("最初の Importance ブロック", 719, 3),
    // アグリゲートがバージョン 2 になったフォーク（strictAggregateTransactionHash、高さ 1,690,500）の直後
    ("バージョン 2 のフォーク", 1_690_500, 10),
    // アグリゲートがバージョン 3 になったフォーク（uniqueAggregateTransactionHash、高さ 4,759,100）の直後
    ("バージョン 3 のフォーク", 4_759_100, 12),
];

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("環境変数 {name} を指定してください"))
}

/// テストは crate のフォルダーで動くので、相対パスはそこから数える。
fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{path} を読めません: {error}"))
}

/// HEIKA_TEST_NODE がなければ None。CI のように、ほかの照合と一緒に `--include-ignored` で回したときのため。
fn connect() -> Option<Node> {
    let Ok(address) = env::var("HEIKA_TEST_NODE") else {
        eprintln!("HEIKA_TEST_NODE がないので、メインネットのブロックでの確認はしません");
        return None;
    };
    let chain_path = var("HEIKA_TEST_CLIENT_CERT");
    let key_path = var("HEIKA_TEST_CLIENT_KEY");
    let chain = Certificate::from_pem_chain(&read(&chain_path))
        .unwrap_or_else(|error| panic!("{chain_path}: {error}"));
    let key = key::private_key_from_pem(&read(&key_path))
        .unwrap_or_else(|error| panic!("{key_path}: {error}"));
    let identity = Identity::new(&chain, &key).unwrap();
    // ノードのアドレスは出さない
    let node = Node::connect(&address, &identity, TIMEOUT)
        .unwrap_or_else(|error| panic!("HEIKA_TEST_NODE につなげません: {error}"));
    Some(node)
}

#[test]
#[ignore = "環境変数で指定したメインネットのノードにつなぐ"]
fn mainnet_blocks_are_signed_chained_and_scannable() {
    let Some(mut node) = connect() else {
        return;
    };
    let (mut read, mut skipped) = (0, 0);
    for (name, start, count) in RANGES {
        let blocks = node
            .pull_blocks(start, count, 16 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        // ノードはバイト数の上限で切り詰めることがあるので、1件ずつ取り足す
        let mut blocks: Vec<Block> = blocks
            .iter()
            .map(|bytes| Block::from_bytes(bytes).unwrap_or_else(|error| panic!("{name}: {error}")))
            .collect();
        while (blocks.len() as u32) < count {
            let height = start + blocks.len() as u64;
            let more = node
                .pull_blocks(height, count - blocks.len() as u32, 16 * 1024 * 1024)
                .unwrap();
            assert!(
                !more.is_empty(),
                "{name}: 高さ {height} のブロックがありません"
            );
            blocks.extend(more.iter().map(|bytes| Block::from_bytes(bytes).unwrap()));
        }

        for (index, block) in blocks.iter().enumerate() {
            let height = start + index as u64;
            assert_eq!(block.height, height, "{name}");
            assert_eq!(
                block.network,
                NetworkIdentifier::MAINNET,
                "{name}: {height}"
            );
            assert!(block.verify_signature(), "{name}: 高さ {height} の署名");
            let expected_type = match height {
                1 => BlockType::Nemesis,
                height if height % 720 == 0 => BlockType::Importance,
                _ => BlockType::Normal,
            };
            assert_eq!(block.block_type, expected_type, "{name}: {height}");
            // 中のトランザクションは、どれも知っている種類とバージョンで、読む種類は読めるはず
            for transaction in block.transactions() {
                for scanned in scan(transaction).unwrap_or_else(|error| {
                    panic!("{name}: 高さ {height} のトランザクション: {error}")
                }) {
                    match scanned.content {
                        Content::Read(_) => read += 1,
                        Content::Skipped { .. } => skipped += 1,
                    }
                }
            }
            if index > 0 {
                assert_eq!(
                    block.previous_block_hash,
                    blocks[index - 1].hash(),
                    "{name}: 高さ {height} の PreviousBlockHash"
                );
            }
        }
    }
    // 走査が空回りしていないことを確かめる
    eprintln!("トランザクション: 読んだ {read} 件、飛ばした {skipped} 件");
    assert!(read > 0 && skipped > 0);
}
