//! REST で取った JSON と、ノードから直接取ったバイナリを、heika-rest で行き来させて突き合わせる。
//!
//! - REST の JSON から組み直したバイト列が、バイナリと一致する
//! - バイナリを heika の型にして書いた JSON が、REST の JSON と一致する
//! - REST の値の確かめ（[`BlockInfo::verify`]、[`TransactionInfo::verify`] など）が通る
//! - REST のステートメントを集めて求めた ReceiptsHash が、バイナリのブロックのヘッダーと一致する
//! - REST の状態（アカウント、モザイク、ネームスペース、メタデータ）から組み直した状態のハッシュが、
//!   REST の状態の経路で、最新のブロックの9本の根につながる（これは REST だけで動き、HEIKA_TEST_REST だけでよい）
//! - アカウントの残高を、[`verify_balance`] で最新のブロックの StateHash まで確かめられる。
//!   まだ使われていないアドレスは、載っていないことを確かめられる（これも HEIKA_TEST_REST だけでよい）
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
use std::future::{Future, ready};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use heika_block::Block;
use heika_block::statement::{
    AddressResolutionStatement, MosaicResolutionStatement, TransactionStatement,
};
use heika_cert::certificate::Certificate;
use heika_cert::key;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::merkle::{self, MerklePathNode};
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_core::patricia::SubCache;
use heika_p2p::Node;
use heika_rest::balance::verify_balance;
use heika_rest::block::{BlockHeader, BlockInfo};
use heika_rest::merkle::{MerkleProofInfo, MerkleStateInfo};
use heika_rest::state::{AccountInfo, MetadataInfo, MosaicInfo, NamespaceInfo, RootNamespaceState};
use heika_rest::statement::{
    ResolutionStatementInfo, ResolutionStatementJson, TransactionStatementInfo,
    TransactionStatementJson, block_statement,
};
use heika_rest::transaction::{TransactionInfo, TransactionJson};
use heika_tls::Identity;
use heika_transaction::{Body, NamespaceId, Transaction};
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
///
/// 公開されている REST は問い合わせの数を絞っていて、多すぎると 429 を返すので、そのときは待つ時間を延ばしながら取り直す。
fn rest(origin: &str, path: &str) -> Value {
    let url = format!("{origin}{path}");
    let mut wait = Duration::from_secs(1);
    let body = loop {
        match ureq::get(&url)
            .call()
            .and_then(|mut response| response.body_mut().read_to_string())
        {
            Err(ureq::Error::StatusCode(429)) if wait <= Duration::from_secs(16) => {
                std::thread::sleep(wait);
                wait *= 2;
            }
            result => break result.unwrap_or_else(|error| panic!("REST の {path}: {error}")),
        }
    };
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

/// 状態の確かめに使う、REST のオリジンだけ。ノードにはつながない
fn rest_origin() -> Option<String> {
    let Ok(rest) = env::var("HEIKA_TEST_REST") else {
        eprintln!("HEIKA_TEST_REST がないので、状態の確かめはしません");
        return None;
    };
    Some(rest.trim_end_matches('/').to_owned())
}

/// 最新のブロックの9本の根と、状態のハッシュ、木のキー、状態の経路を取り、経路が根から状態のハッシュまでつながることを確かめる。
/// 状態は最新のものしか取れず、取るあいだにブロックが進むと根が変わるので、何度か取り直す。
fn assert_in_state_tree(
    origin: &str,
    context: &str,
    sub_cache: SubCache,
    fetch: impl Fn() -> (Hash256, Hash256, MerkleStateInfo),
) {
    let mut last = None;
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(3));
        }
        let height = rest(origin, "/chain/info")["height"]
            .as_str()
            .unwrap()
            .to_owned();
        let info: BlockInfo =
            serde_json::from_value(rest(origin, &format!("/blocks/{height}"))).unwrap();
        // 9本の根から求めた StateHash が、署名されたヘッダーの値と合う
        info.verify()
            .unwrap_or_else(|error| panic!("{context}: 高さ {height} のブロック: {error}"));
        let roots = info.sub_cache_merkle_roots().unwrap();
        let (state_hash, key, proof) = fetch();
        let result = proof.prove(&key, &roots[sub_cache.index()]);
        if result == Ok(Some(state_hash)) {
            return;
        }
        last = Some(result);
    }
    panic!("{context}: 状態の経路が、状態のハッシュまでつながりません: {last:?}");
}

#[test]
#[ignore = "環境変数で指定した REST につなぐ"]
fn rest_states_are_in_the_state_tree() {
    let Some(origin) = rest_origin() else {
        return;
    };
    let origin = origin.as_str();
    let merkle =
        |path: String| -> MerkleStateInfo { serde_json::from_value(rest(origin, &path)).unwrap() };
    let mut checked = [0; 4];

    // アカウント：Nemesis の署名者と、検索の最初のページ
    let nemesis = rest(origin, "/blocks/1");
    let network = NetworkParameters::from_identifier(NetworkIdentifier(
        nemesis["block"]["network"].as_u64().unwrap() as u8,
    ))
    .unwrap();
    let mut accounts = vec![
        nemesis["block"]["signerPublicKey"]
            .as_str()
            .unwrap()
            .to_owned(),
    ];
    for entry in rest(origin, "/accounts?pageSize=10")["data"]
        .as_array()
        .unwrap()
    {
        let address = Address::from_hex(entry["account"]["address"].as_str().unwrap()).unwrap();
        accounts.push(address.to_string());
    }
    for (index, account) in accounts.iter().enumerate() {
        assert_in_state_tree(
            origin,
            &format!("アカウント {index}"),
            SubCache::AccountState,
            || {
                let info: AccountInfo =
                    serde_json::from_value(rest(origin, &format!("/accounts/{account}"))).unwrap();
                let address = Address::from_hex(&info.account.address).unwrap();
                (
                    info.account.state_hash().unwrap(),
                    info.account.tree_key().unwrap(),
                    merkle(format!("/accounts/{address}/merkle")),
                )
            },
        );
        checked[0] += 1;
    }

    // モザイク：通貨と、検索の最初のページ
    let mut mosaics = vec![format!("{:016X}", network.currency_mosaic_id)];
    for entry in rest(origin, "/mosaics?pageSize=10")["data"]
        .as_array()
        .unwrap()
    {
        mosaics.push(entry["mosaic"]["id"].as_str().unwrap().to_owned());
    }
    for (index, id) in mosaics.iter().enumerate() {
        assert_in_state_tree(
            origin,
            &format!("モザイク {index}"),
            SubCache::Mosaic,
            || {
                let info: MosaicInfo =
                    serde_json::from_value(rest(origin, &format!("/mosaics/{id}"))).unwrap();
                (
                    info.mosaic.state_hash().unwrap(),
                    info.mosaic.tree_key().unwrap(),
                    merkle(format!("/mosaics/{id}/merkle")),
                )
            },
        );
        checked[1] += 1;
    }

    // ネームスペース：symbol と、ルートの検索の最初のページ
    let mut roots = vec![NamespaceId::from_full_name("symbol").unwrap().0];
    for entry in rest(origin, "/namespaces?registrationType=0&pageSize=10")["data"]
        .as_array()
        .unwrap()
    {
        if entry["meta"]["active"].as_bool().unwrap() {
            let level0 = entry["namespace"]["level0"].as_str().unwrap();
            roots.push(u64::from_str_radix(level0, 16).unwrap());
        }
    }
    roots.dedup();
    for (index, root) in roots.iter().enumerate() {
        assert_in_state_tree(
            origin,
            &format!("ネームスペース {index}"),
            SubCache::Namespace,
            || {
                let entries: Vec<NamespaceInfo> =
                    read_all(&pages(origin, &format!("/namespaces?level0={root:016X}")));
                let state = RootNamespaceState::collect(*root, &entries).unwrap();
                (
                    state.state_hash().unwrap(),
                    state.tree_key(),
                    merkle(format!("/namespaces/{root:016X}/merkle")),
                )
            },
        );
        checked[2] += 1;
    }

    // メタデータ：検索の最初のページ
    let metadata = rest(origin, "/metadata?pageSize=10")["data"]
        .as_array()
        .unwrap()
        .clone();
    for (index, entry) in metadata.iter().enumerate() {
        let hash = entry["metadataEntry"]["compositeHash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_in_state_tree(
            origin,
            &format!("メタデータ {index}"),
            SubCache::Metadata,
            || {
                let info: MetadataInfo =
                    serde_json::from_value(rest(origin, &format!("/metadata/{hash}"))).unwrap();
                (
                    info.metadata_entry.state_hash().unwrap(),
                    info.metadata_entry.tree_key().unwrap(),
                    merkle(format!("/metadata/{hash}/merkle")),
                )
            },
        );
        checked[3] += 1;
    }
    eprintln!(
        "状態の木で確かめたもの：アカウント {}、モザイク {}、ネームスペース {}、メタデータ {}",
        checked[0], checked[1], checked[2], checked[3]
    );
    assert!(checked.iter().all(|&count| count > 0));
}

/// REST の `path` を取る。404 なら `None`。429 なら、待つ時間を延ばしながら取り直す
fn rest_optional(origin: &str, path: &str) -> Option<Vec<u8>> {
    let url = format!("{origin}{path}");
    let mut wait = Duration::from_secs(1);
    loop {
        match ureq::get(&url)
            .call()
            .and_then(|mut response| response.body_mut().read_to_vec())
        {
            Err(ureq::Error::StatusCode(429)) if wait <= Duration::from_secs(16) => {
                std::thread::sleep(wait);
                wait *= 2;
            }
            Err(ureq::Error::StatusCode(404)) => return None,
            result => {
                return Some(result.unwrap_or_else(|error| panic!("REST の {path}: {error}")));
            }
        }
    }
}

/// 取ってくる関数はその場で答えるので、一度動かせば終わる
fn run<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("その場で答えたのに、待たされました"),
    }
}

#[test]
#[ignore = "環境変数で指定した REST につなぐ"]
fn rest_balances_are_verified_against_the_state_hash() {
    let Some(origin) = rest_origin() else {
        return;
    };
    let origin = origin.as_str();
    let fetch = |path: String| ready(Ok::<_, String>(rest_optional(origin, &path)));
    let pause = || {
        std::thread::sleep(Duration::from_secs(3));
        ready(())
    };

    // アカウント：Nemesis の署名者と、検索の最初のページ
    let nemesis = rest(origin, "/blocks/1");
    let network = NetworkIdentifier(nemesis["block"]["network"].as_u64().unwrap() as u8);
    let parameters = NetworkParameters::from_identifier(network).unwrap();
    let signer: PublicKey = nemesis["block"]["signerPublicKey"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut addresses = vec![Address::from_public_key(&signer, network)];
    for entry in rest(origin, "/accounts?pageSize=10")["data"]
        .as_array()
        .unwrap()
    {
        addresses.push(Address::from_hex(entry["account"]["address"].as_str().unwrap()).unwrap());
    }
    let mut mosaics = 0;
    for (index, address) in addresses.iter().enumerate() {
        let balance = run(verify_balance(address, fetch, pause))
            .unwrap_or_else(|error| panic!("アカウント {index}: {error}"));
        let account = balance.account.unwrap_or_else(|| {
            panic!("アカウント {index} が、チェーンに載っていないことになりました")
        });
        for mosaic in &account.mosaics {
            if mosaic.id == parameters.currency_mosaic_id {
                assert_eq!(mosaic.divisibility, Some(6), "アカウント {index} の XYM");
            }
            mosaics += 1;
        }
    }

    // まだ使われていないアドレス：決まった公開鍵から作る
    let unused = Address::from_public_key(&PublicKey([0x5A; 32]), network);
    let balance = run(verify_balance(&unused, fetch, pause))
        .unwrap_or_else(|error| panic!("使われていないアドレス: {error}"));
    assert!(
        balance.account.is_none(),
        "使われていないアドレスが、チェーンに載っていることになりました"
    );
    eprintln!(
        "残高を確かめたもの：アカウント {}、モザイク {mosaics}、使われていないアドレス 1",
        addresses.len()
    );
}
