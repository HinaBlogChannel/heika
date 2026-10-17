//! メインネットのノードから取ったブロックで、ブロックの読み込み、署名、ハッシュ、TransactionsHash、VRF の証明、難易度を確かめる。
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

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::time::Duration;

use heika_block::scoring::{BlockStatistic, difficulty};
use heika_block::{Block, BlockType};
use heika_cert::certificate::Certificate;
use heika_cert::key;
use heika_core::network::NetworkParameters;
use heika_p2p::Client;
use heika_tls::Identity;
use heika_transaction::{Body, LinkAction, Transaction, TransactionsHashCalculation, scan};

const MAINNET: NetworkParameters = NetworkParameters::MAINNET;
const TIMEOUT: Duration = Duration::from_secs(30);

/// 取る高さの範囲。どれも決まった規則で選んでいる。
const RANGES: [(&str, u64, u32); 4] = [
    // Nemesis のブロックから。Nemesis は Importance のフッターを持ち、4.7 MB ある
    ("Nemesis とその次", 1, 3),
    // 最初の Importance ブロック（importanceGrouping = 720）の前後
    ("最初の Importance ブロック", 719, 3),
    // アグリゲートがバージョン 2 になったフォーク（strictAggregateTransactionHash、高さ 1,690,500）の前後
    ("バージョン 2 のフォーク", 1_690_490, 20),
    // アグリゲートがバージョン 3 になったフォーク（uniqueAggregateTransactionHash、高さ 4,759,100）の前後
    ("バージョン 3 のフォーク", 4_759_090, 22),
];

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("環境変数 {name} を指定してください"))
}

/// テストは crate のフォルダーで動くので、相対パスはそこから数える。
fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{path} を読めません: {error}"))
}

/// HEIKA_TEST_NODE がなければ None。CI のように、ほかの照合と一緒に `--include-ignored` で回したときのため。
fn connect() -> Option<Client> {
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
    let node = Client::connect(&address, &identity, TIMEOUT)
        .unwrap_or_else(|error| panic!("HEIKA_TEST_NODE につなげません: {error}"));
    Some(node)
}

#[test]
#[ignore = "環境変数で指定したメインネットのノードにつなぐ"]
fn mainnet_blocks_are_signed_chained_proven_and_scannable() {
    let Some(mut node) = connect() else {
        return;
    };
    let mut types = BTreeMap::new();
    let mut aggregates = BTreeMap::new();
    let mut proven = 0;
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

        // 範囲の中で見えた VRF の鍵とリモートアカウントのリンク。範囲の外で付け替えられているかもしれないので、範囲ごとに作り直す
        let mut vrf_keys = HashMap::new();
        let mut main_accounts = HashMap::new();
        for (index, block) in blocks.iter().enumerate() {
            let height = start + index as u64;
            assert_eq!(block.height, height, "{name}");
            assert_eq!(block.network, MAINNET.identifier, "{name}: {height}");
            assert!(block.verify_signature(), "{name}: 高さ {height} の署名");
            assert_eq!(
                block.verify_transactions_hash(&MAINNET.generation_hash_seed),
                Ok(true),
                "{name}: 高さ {height} の TransactionsHash"
            );
            let expected_type = match height {
                1 => BlockType::Nemesis,
                height if height % MAINNET.importance_grouping == 0 => BlockType::Importance,
                _ => BlockType::Normal,
            };
            assert_eq!(block.block_type, expected_type, "{name}: {height}");
            // VRF の証明。Nemesis は署名者の鍵で generation hash seed を証明している。
            // ほかは、ハーベストした人の VRF の鍵がこの範囲でリンクされていれば、1つ前の generation hash で確かめる。
            // catapult と同じく、署名者がリモートアカウントなら、メインアカウントにリンクされた VRF の鍵を使う
            if height == 1 {
                assert!(
                    block
                        .verify_generation_hash_proof(
                            &block.signer_public_key,
                            &MAINNET.generation_hash_seed.0
                        )
                        .is_some(),
                    "{name}: Nemesis の VRF の証明"
                );
                proven += 1;
            } else if index > 0
                && let Some(vrf_public_key) = vrf_keys.get(
                    main_accounts
                        .get(&block.signer_public_key)
                        .unwrap_or(&block.signer_public_key),
                )
            {
                assert!(
                    block
                        .verify_generation_hash_proof(
                            vrf_public_key,
                            &blocks[index - 1].generation_hash().0
                        )
                        .is_some(),
                    "{name}: 高さ {height} の VRF の証明"
                );
                proven += 1;
            }
            // 中のトランザクションは、どれも知っている種類とバージョンで、中身まで読めるはず
            for transaction in block.transactions() {
                for scanned in scan(transaction).unwrap_or_else(|error| {
                    panic!("{name}: 高さ {height} のトランザクション: {error}")
                }) {
                    *types.entry(scanned.body.transaction_type()).or_insert(0) += 1;
                    match &scanned.body {
                        Body::VrfKeyLink(link) => match link.link_action {
                            LinkAction::Link => {
                                vrf_keys.insert(scanned.signer_public_key, link.linked_public_key);
                            }
                            LinkAction::Unlink => {
                                vrf_keys.remove(&scanned.signer_public_key);
                            }
                        },
                        Body::AccountKeyLink(link) => match link.link_action {
                            LinkAction::Link => {
                                main_accounts
                                    .insert(link.linked_public_key, scanned.signer_public_key);
                            }
                            LinkAction::Unlink => {
                                main_accounts.remove(&link.linked_public_key);
                            }
                        },
                        _ => {}
                    }
                }
                // 丸ごと読んでも同じバイト列に書き戻せて、署名と連署はチェーンが認めたとおり正しいはず。
                // 古いアグリゲートの署名の範囲と、中のトランザクションのハッシュの決まりもここで確かめる
                let decoded = Transaction::from_bytes(transaction).unwrap_or_else(|error| {
                    panic!("{name}: 高さ {height} のトランザクション: {error}")
                });
                assert_eq!(decoded.to_bytes(), transaction, "{name}: {height}");
                assert!(
                    decoded.verify(&MAINNET.generation_hash_seed),
                    "{name}: 高さ {height} のトランザクションの署名"
                );
                assert!(
                    decoded.verify_cosignatures(&MAINNET.generation_hash_seed),
                    "{name}: 高さ {height} の連署"
                );
                if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) =
                    &decoded.body
                {
                    let key = format!(
                        "バージョン {}（{:?}）",
                        aggregate.version().number(),
                        aggregate.transactions_hash_calculation()
                    );
                    *aggregates.entry(key).or_insert(0) += 1;
                    assert_eq!(
                        aggregate.version().number(),
                        MAINNET.aggregate_version(height),
                        "{name}: 高さ {height} のアグリゲートのバージョン"
                    );
                    if aggregate.transactions_hash_calculation()
                        == TransactionsHashCalculation::Unknown
                    {
                        assert!(
                            MAINNET.is_known_corrupt_aggregate(
                                &decoded.hash(&MAINNET.generation_hash_seed),
                                &aggregate.transactions_hash()
                            ),
                            "{name}: 高さ {height} の TransactionsHash"
                        );
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
    let types: Vec<_> = types
        .iter()
        .map(|(transaction_type, count)| format!("0x{transaction_type:04X}: {count}"))
        .collect();
    eprintln!("読んだトランザクションの種類: {}", types.join(", "));
    let aggregates: Vec<_> = aggregates
        .iter()
        .map(|(version, count)| format!("{version}: {count}"))
        .collect();
    eprintln!("読んだアグリゲート: {}", aggregates.join(", "));
    eprintln!("VRF の証明を確かめたブロック: {proven}");
    assert!(proven > 1);
    assert!(types.len() > 1);
}

/// 難易度を確かめる範囲。どれも決まった規則で選んでいる。直前の `maxDifficultyBlocks` 個も一緒に取る
const DIFFICULTY_RANGES: [(&str, u64, u32); 2] = [
    // 高さ 2 は直前が Nemesis だけなので既定値、そこから 60 個たまるまで
    ("Nemesis から", 1, 80),
    // アグリゲートがバージョン 3 になったフォーク（uniqueAggregateTransactionHash、高さ 4,759,100）の前後
    ("バージョン 3 のフォーク", 4_759_040, 82),
];

#[test]
#[ignore = "環境変数で指定したメインネットのノードにつなぐ"]
fn mainnet_difficulties_follow_the_previous_blocks() {
    let Some(mut node) = connect() else {
        return;
    };
    let mut checked = 0;
    for (name, start, count) in DIFFICULTY_RANGES {
        let mut blocks = Vec::new();
        while (blocks.len() as u32) < count {
            let height = start + blocks.len() as u64;
            let more = node
                .pull_blocks(height, count - blocks.len() as u32, 16 * 1024 * 1024)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(
                !more.is_empty(),
                "{name}: 高さ {height} のブロックがありません"
            );
            blocks.extend(more.iter().map(|bytes| Block::from_bytes(bytes).unwrap()));
        }
        let statistics: Vec<BlockStatistic> = blocks.iter().map(BlockStatistic::from).collect();
        // 範囲の初めのほうは直前のブロックが足りないので、Nemesis から取ったときだけ確かめる
        let first = if start == 1 {
            1
        } else {
            MAINNET.max_difficulty_blocks
        };
        for index in first..blocks.len() {
            assert_eq!(
                difficulty(&statistics[..index], &MAINNET),
                blocks[index].difficulty,
                "{name}: 高さ {} の難易度",
                blocks[index].height
            );
            checked += 1;
        }
    }
    eprintln!("難易度を確かめたブロック: {checked}");
    assert!(checked > 100);
}
