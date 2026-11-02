//! REST からブロックを取り、組み直して（[`BlockInfo::assemble`]）、Nemesis から順に確かめて実行する（[`Replay`]）。
//! ブラウザのノード（examples/node-web）がすることを、ネイティブで確かめる。
//!
//! REST のオリジンは、リポジトリに残さないように環境変数で渡す。メインネットとテストネットは決め打ちの設定を使い、
//! プライベートなネットワークなら、その `resources` のフォルダーも渡す。
//!
//! ```sh
//! HEIKA_TEST_REST=http://127.0.0.1:13001 \
//! HEIKA_TEST_RESOURCES=~/privnet-a/heika1/resources \
//! HEIKA_TEST_REPLAY_TO=300 \
//! cargo test -p heika-vectors --test rest_replay -- --include-ignored --nocapture
//! ```
//!
//! HEIKA_TEST_REST がなければ、何もせずに成功する（CI ではそうなる）。

use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use heika_chain::verify::nemesis_hash;
use heika_core::hash::Hash256;
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_rest::block::BlockInfo;
use heika_rest::transaction::TransactionInfo;
use heika_state_transition::config::{ChainConfig, load_network_parameters};
use heika_store_redb::Db;
use heika_store_redb::replay::Replay;
use serde_json::Value;

/// REST の1ページの件数の上限
const PAGE_SIZE: usize = 100;

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

/// 検索の `path`（問い合わせ付き）を、ページを進めながらすべて取る
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

/// `from` から `to` までのブロックを、組み直したバイト列で取る
fn fetch(origin: &str, from: u64, to: u64) -> Vec<Vec<u8>> {
    let blocks: Vec<BlockInfo> = rest(
        origin,
        &format!(
            "/blocks?orderBy=height&offset={}&pageSize={PAGE_SIZE}",
            from - 1
        ),
    )["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|block| serde_json::from_value(block.clone()).unwrap())
        .take((to - from + 1) as usize)
        .collect();
    let found: Vec<TransactionInfo> = pages(
        origin,
        &format!("/transactions/confirmed?fromHeight={from}&toHeight={to}&embedded=true"),
    )
    .into_iter()
    .map(|entry| serde_json::from_value(entry).unwrap())
    .collect();
    blocks
        .iter()
        .map(|block| {
            block
                .assemble(&found)
                .unwrap_or_else(|error| panic!("高さ {} の組み直し: {error}", block.block.height))
        })
        .collect()
}

/// 消し忘れないように、終わったら消すフォルダー
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[ignore = "環境変数で指定した REST につなぐ"]
fn replays_blocks_fetched_from_rest_from_the_nemesis() {
    let Ok(origin) = env::var("HEIKA_TEST_REST") else {
        eprintln!("HEIKA_TEST_REST がないので、REST からの実行はしません");
        return;
    };
    let origin = origin.trim_end_matches('/').to_owned();
    let identifier = NetworkIdentifier(
        rest(&origin, "/node/info")["networkIdentifier"]
            .as_u64()
            .unwrap() as u8,
    );
    let (parameters, config): (&'static NetworkParameters, ChainConfig) =
        match env::var("HEIKA_TEST_RESOURCES") {
            Ok(resources) => (
                Box::leak(Box::new(
                    load_network_parameters(Path::new(&resources)).unwrap(),
                )),
                ChainConfig::load(Path::new(&resources)).unwrap(),
            ),
            Err(_) if identifier == NetworkIdentifier::MAINNET => {
                (&NetworkParameters::MAINNET, ChainConfig::mainnet())
            }
            Err(_) => (&NetworkParameters::TESTNET, ChainConfig::testnet()),
        };
    // プライベートなネットワーク（番号はテストネットと同じこともある）は、REST の言う Nemesis を信じる
    // （ここで確かめたいのは、そこから先）
    let custom = env::var("HEIKA_TEST_RESOURCES").is_ok();
    let nemesis = match nemesis_hash(identifier) {
        Some(hash) if !custom => hash,
        _ => rest(&origin, "/blocks/1")["meta"]["hash"]
            .as_str()
            .unwrap()
            .parse::<Hash256>()
            .unwrap(),
    };
    let tip: u64 = rest(&origin, "/chain/info")["height"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let to = env::var("HEIKA_TEST_REPLAY_TO")
        .map(|to| to.parse().unwrap())
        .unwrap_or(300)
        .min(tip);

    let dir = TempDir(env::temp_dir().join(format!("heika-rest-replay-{}", std::process::id())));
    let db = Db::open(&dir.0).unwrap();
    // 半分まで進めたら、開き直して続きから実行する
    let half = to / 2;
    for stop in [half, to] {
        let mut replay = Replay::open(&db, config.clone(), parameters, nemesis).unwrap();
        while replay.height() < stop {
            let from = replay.height() + 1;
            let upto = (from + PAGE_SIZE as u64 - 1).min(stop);
            for bytes in fetch(&origin, from, upto) {
                replay.push(bytes).unwrap_or_else(|error| panic!("{error}"));
            }
            replay.commit().unwrap();
        }
        assert_eq!(replay.committed(), stop);
        eprintln!(
            "高さ {stop} まで実行しました。StateHash {}",
            replay.state_hash().unwrap()
        );
    }
    let last: BlockInfo = serde_json::from_value(rest(&origin, &format!("/blocks/{to}"))).unwrap();
    assert_eq!(db.blocks_tip().unwrap(), to);
    assert_eq!(
        Replay::open(&db, config, parameters, nemesis)
            .unwrap()
            .state_hash(),
        Some(last.verify().unwrap().state_hash)
    );
}
