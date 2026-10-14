//! REST で取った JSON と、ノードから直接取ったバイナリを、heika-rest で行き来させて突き合わせる。
//!
//! - REST の JSON から組み直したバイト列が、バイナリと一致する
//! - バイナリを heika の型にして書いた JSON が、REST の JSON と一致する
//! - REST の値の確かめ（[`BlockInfo::verify`]、[`TransactionInfo::verify`] など）が通る
//! - REST のステートメントを集めて求めた ReceiptsHash が、バイナリのブロックのヘッダーと一致する
//!
//! つなぐノード、名乗る証明書、REST のオリジンは、リポジトリに残さないように環境変数で渡す。
//!
//! ```sh
//! HEIKA_TEST_REST=https://<ホスト>:3001 \
//! HEIKA_TEST_NODE=<ホスト>:<ポート> \
//! HEIKA_TEST_CLIENT_CERT=$PWD/peer/tls.crt \
//! HEIKA_TEST_CLIENT_KEY=$PWD/peer/tls.key \
//! cargo test -p heika-vectors --test rest_live -- --include-ignored
//! ```
//!
//! HEIKA_TEST_REST か HEIKA_TEST_NODE がなければ、何も確かめずに成功する（CI ではそうなる）。

use std::env;
use std::fs;
use std::time::Duration;

use heika_block::Block;
use heika_block::statement::{
    AddressResolutionStatement, MosaicResolutionStatement, TransactionStatement,
};
use heika_cert::certificate::Certificate;
use heika_cert::key;
use heika_core::merkle::{self, MerklePathNode};
use heika_p2p::Node;
use heika_rest::block::{BlockHeader, BlockInfo};
use heika_rest::merkle::MerkleProofInfo;
use heika_rest::statement::{
    ResolutionStatementInfo, ResolutionStatementJson, TransactionStatementInfo,
    TransactionStatementJson, block_statement,
};
use heika_rest::transaction::{TransactionInfo, TransactionJson};
use heika_tls::Identity;
use heika_transaction::{Body, Transaction};
use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(30);

/// 取る高さの範囲。どれも決まった規則で選んでいる。
const RANGES: [(&str, u64, u32); 3] = [
    // 最初の Importance ブロック（importanceGrouping = 720）の前後
    ("最初の Importance ブロック", 719, 3),
    // アグリゲートがバージョン 2 になったフォーク（高さ 1,690,500）の前後。バージョン 1 と 2 のアグリゲートがある
    ("バージョン 2 のフォーク", 1_690_490, 20),
    // アグリゲートがバージョン 3 になったフォーク（高さ 4,759,100）の前後
    ("バージョン 3 のフォーク", 4_759_090, 22),
];

/// REST の1ページの件数の上限
const PAGE_SIZE: usize = 100;

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("環境変数 {name} を指定してください"))
}

/// テストは crate のフォルダーで動くので、相対パスはそこから数える。
fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{path} を読めません: {error}"))
}

fn connect() -> Option<(Node, String)> {
    let (Ok(rest), Ok(address)) = (env::var("HEIKA_TEST_REST"), env::var("HEIKA_TEST_NODE")) else {
        eprintln!(
            "HEIKA_TEST_REST か HEIKA_TEST_NODE がないので、REST とバイナリの突き合わせはしません"
        );
        return None;
    };
    let chain_path = var("HEIKA_TEST_CLIENT_CERT");
    let key_path = var("HEIKA_TEST_CLIENT_KEY");
    let chain = Certificate::from_pem_chain(&read(&chain_path))
        .unwrap_or_else(|error| panic!("{chain_path}: {error}"));
    let key = key::private_key_from_pem(&read(&key_path))
        .unwrap_or_else(|error| panic!("{key_path}: {error}"));
    let identity = Identity::new(&chain, &key).unwrap();
    // ノードのアドレスと REST のオリジンは出さない
    let node = Node::connect(&address, &identity, TIMEOUT)
        .unwrap_or_else(|error| panic!("HEIKA_TEST_NODE につなげません: {error}"));
    Some((node, rest.trim_end_matches('/').to_owned()))
}

/// REST の `path` を取る。失敗したときは、オリジンを出さずに `path` だけを出す。
fn rest(origin: &str, path: &str) -> Value {
    let body = ureq::get(&format!("{origin}{path}"))
        .call()
        .and_then(|mut response| response.body_mut().read_to_string())
        .unwrap_or_else(|error| panic!("REST の {path}: {error}"));
    serde_json::from_str(&body).unwrap_or_else(|error| panic!("REST の {path}: {error}"))
}

/// 高さ `height` の承認済みのトランザクションを、ブロックの中の順にすべて取る。
fn transactions(origin: &str, height: u64, embedded: bool) -> Vec<Value> {
    pages(
        origin,
        &format!("/transactions/confirmed?height={height}&embedded={embedded}"),
    )
}

/// 検索の `path`（問い合わせ付き）を、ページを進めながらすべて取る。
fn pages(origin: &str, path: &str) -> Vec<Value> {
    let mut all = Vec::new();
    for page in 1.. {
        let path = format!("{path}&pageSize={PAGE_SIZE}&pageNumber={page}");
        let data = rest(origin, &path)["data"].as_array().unwrap().clone();
        let last = data.len() < PAGE_SIZE;
        all.extend(data);
        if last {
            break;
        }
    }
    all
}

fn pull(node: &mut Node, name: &str, start: u64, count: u32) -> Vec<(Vec<u8>, Block)> {
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
        blocks.extend(more.into_iter().map(|bytes| {
            let block = Block::from_bytes(&bytes).unwrap();
            (bytes, block)
        }));
    }
    blocks
}

/// REST の JSON から、heika-rest が書かない DB の項目を除く
fn without_database_fields(json: &Value) -> Value {
    let mut json = json.clone();
    if let Some(object) = json.as_object_mut() {
        object.remove("transactions");
    }
    json
}

#[test]
#[ignore = "環境変数で指定した REST とメインネットのノードにつなぐ"]
fn rest_json_round_trips_with_binary_blocks_and_transactions() {
    let Some((mut node, origin)) = connect() else {
        return;
    };
    let mut checked = (0, 0, 0);
    for (name, start, count) in RANGES {
        for (index, (_, block)) in pull(&mut node, name, start, count).iter().enumerate() {
            let height = start + index as u64;

            // ブロック：REST の値の確かめが通り、組み直したヘッダーが バイナリのものと同じハッシュになり、
            // バイナリのヘッダーから書いた JSON が REST の JSON と同じになる
            let json = rest(&origin, &format!("/blocks/{height}"));
            let info: BlockInfo = serde_json::from_value(json.clone()).unwrap();
            let rebuilt = info
                .verify()
                .unwrap_or_else(|error| panic!("{name}: 高さ {height} のブロック: {error}"));
            assert_eq!(rebuilt.hash(), block.hash(), "{name}: {height}");
            assert_eq!(
                serde_json::to_value(BlockHeader::from(block)).unwrap(),
                json["block"],
                "{name}: 高さ {height} のブロックの JSON"
            );
            checked.0 += 1;

            // トランザクション：ブロックの中の順に、1件ずつ突き合わせる
            let mut found = transactions(&origin, height, false);
            found.sort_by_key(|entry| entry["meta"]["index"].as_u64().unwrap());
            let bytes: Vec<&[u8]> = block.transactions().collect();
            assert_eq!(
                found.len(),
                bytes.len(),
                "{name}: 高さ {height} のトランザクションの数"
            );
            let mut aggregates = Vec::new();
            for (entry, bytes) in found.iter().zip(&bytes) {
                let transaction = Transaction::from_bytes(bytes).unwrap();
                let context = format!("{name}: 高さ {height} の {}", entry["meta"]["index"]);
                let info: TransactionInfo = serde_json::from_value(entry.clone()).unwrap();
                let full = if let Body::AggregateComplete(_) | Body::AggregateBonded(_) =
                    &transaction.body
                {
                    // 検索では中身がないので、外側だけを確かめてから、1件で取り直す
                    let header = info
                        .verify_aggregate_header()
                        .unwrap_or_else(|error| panic!("{context}: {error}"));
                    let hash = header.hash.to_string();
                    aggregates.push(info);
                    rest(&origin, &format!("/transactions/confirmed/{hash}"))
                } else {
                    entry.clone()
                };
                let info: TransactionInfo = serde_json::from_value(full.clone()).unwrap();
                assert_eq!(
                    info.transaction.to_bytes().unwrap(),
                    *bytes,
                    "{context}: 組み直したバイト列"
                );
                assert_eq!(
                    info.verify()
                        .unwrap_or_else(|error| panic!("{context}: {error}")),
                    transaction,
                    "{context}"
                );
                // バイナリのトランザクションから書いた JSON が、REST の JSON と同じになる
                let written = serde_json::to_value(TransactionJson::from(&transaction)).unwrap();
                assert_eq!(
                    without_database_fields(&written),
                    without_database_fields(&full["transaction"]),
                    "{context}: JSON"
                );
                if let (Some(written), Some(rest)) = (
                    written["transactions"].as_array(),
                    full["transaction"]["transactions"].as_array(),
                ) {
                    assert_eq!(
                        written.len(),
                        rest.len(),
                        "{context}: 中のトランザクションの数"
                    );
                    for (written, rest) in written.iter().zip(rest) {
                        assert_eq!(
                            written["transaction"], rest["transaction"],
                            "{context}: 中の JSON"
                        );
                    }
                }
                checked.1 += 1;
            }

            // embedded=true で平たく並んだ中のトランザクションを親ごとに集めると、1件で取ったときと同じく確かめられる
            if !aggregates.is_empty() {
                let flattened: Vec<TransactionInfo> = transactions(&origin, height, true)
                    .into_iter()
                    .map(|entry| serde_json::from_value(entry).unwrap())
                    .collect();
                for aggregate in &aggregates {
                    aggregate
                        .with_embedded(&flattened)
                        .and_then(|collected| collected.verify())
                        .unwrap_or_else(|error| {
                            panic!("{name}: 高さ {height} の平たく並んだもの: {error}")
                        });
                    checked.2 += 1;
                }
            }
        }
    }
    eprintln!(
        "突き合わせたブロック: {}、トランザクション: {}、平たく並んだものから集めたアグリゲート: {}",
        checked.0, checked.1, checked.2
    );
    assert!(checked.1 > 0 && checked.2 > 0);
}

#[test]
#[ignore = "環境変数で指定した REST とメインネットのノードにつなぐ"]
fn rest_statements_match_the_receipts_hash_of_binary_blocks() {
    let Some((mut node, origin)) = connect() else {
        return;
    };
    let mut checked = (0, 0);
    for (name, start, count) in RANGES {
        for (index, (_, block)) in pull(&mut node, name, start, count).iter().enumerate() {
            let height = start + index as u64;
            let context = format!("{name}: 高さ {height}");
            let transactions = pages(&origin, &format!("/statements/transaction?height={height}"));
            let addresses = pages(
                &origin,
                &format!("/statements/resolutions/address?height={height}"),
            );
            let mosaics = pages(
                &origin,
                &format!("/statements/resolutions/mosaic?height={height}"),
            );
            let transaction_infos: Vec<TransactionStatementInfo> = read_all(&transactions);
            let address_infos: Vec<ResolutionStatementInfo> = read_all(&addresses);
            let mosaic_infos: Vec<ResolutionStatementInfo> = read_all(&mosaics);

            // 3種類を catapult の並びにまとめると、バイナリのブロックの ReceiptsHash になる
            let statement = block_statement(&transaction_infos, &address_infos, &mosaic_infos)
                .unwrap_or_else(|error| panic!("{context}: {error}"));
            assert!(
                block.verify_receipts_hash(&statement),
                "{context}: ReceiptsHash"
            );
            checked.0 += 1;

            // 組み直したステートメントから書いた JSON が、REST の JSON と同じになる
            for entry in &transactions {
                let json: TransactionStatementJson =
                    serde_json::from_value(entry["statement"].clone()).unwrap();
                let rebuilt = TransactionStatement::try_from(&json).unwrap();
                assert_eq!(
                    serde_json::to_value(TransactionStatementJson::new(height, &rebuilt)).unwrap(),
                    entry["statement"],
                    "{context}: トランザクションのステートメントの JSON"
                );
            }
            for (entries, address) in [(&addresses, true), (&mosaics, false)] {
                for entry in entries {
                    let json: ResolutionStatementJson =
                        serde_json::from_value(entry["statement"].clone()).unwrap();
                    let written = if address {
                        ResolutionStatementJson::from_address(
                            height,
                            &AddressResolutionStatement::try_from(&json).unwrap(),
                        )
                    } else {
                        ResolutionStatementJson::from_mosaic(
                            height,
                            &MosaicResolutionStatement::try_from(&json).unwrap(),
                        )
                    };
                    assert_eq!(
                        serde_json::to_value(written).unwrap(),
                        entry["statement"],
                        "{context}: 解決のステートメントの JSON"
                    );
                }
            }

            // 最初のステートメントは、REST が返す Merkle の経路で ReceiptsHash に含まれることを示せる
            if let Some(first) = statement.transaction_statements.first() {
                let hash = first.hash();
                let proof: MerkleProofInfo = serde_json::from_value(rest(
                    &origin,
                    &format!("/blocks/{height}/statements/{hash}/merkle"),
                ))
                .unwrap();
                let path = Vec::<MerklePathNode>::try_from(&proof).unwrap();
                assert!(
                    merkle::verify_path(&hash, &path, &block.receipts_hash),
                    "{context}: ステートメントの Merkle の経路"
                );
                checked.1 += 1;
            }
        }
    }
    eprintln!(
        "ReceiptsHash を突き合わせたブロック: {}、Merkle の経路を確かめたステートメント: {}",
        checked.0, checked.1
    );
    assert!(checked.0 > 0 && checked.1 > 0);
}

fn read_all<T: serde::de::DeserializeOwned>(entries: &[Value]) -> Vec<T> {
    entries
        .iter()
        .map(|entry| serde_json::from_value(entry.clone()).unwrap())
        .collect()
}
