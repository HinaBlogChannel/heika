//! すんぼる草不可避に埋め込む、ブラウザから読める公開ノードの一覧を探す。
//! HTTPS（3001）の REST で、CORS が開いていて、確定した高さが遅れていないものを、種のノードから辿って全部集める。
//! 種と、除外したホストには問い合わせず、一覧にも入れない。画面には数だけ出す。
//!
//! 環境変数:
//! - `KUSA_SEED_MAINNET`, `KUSA_SEED_TESTNET`: 辿り始める REST の URL（片方だけでもよい）
//! - `KUSA_EXCLUDE`: 一覧に入れないホスト名（カンマ区切り）。自分のノードなど
//!
//! 使い方: `sunboru-kusa-discover <書き出す JSON>`

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

/// 同時に問い合わせる数
const WORKERS: usize = 16;
/// 辿るホストの上限
const MAX_HOSTS: usize = 3000;
/// CORS を確かめるときに名乗るオリジン
const ORIGIN: &str = "https://sunboru-kusa.invalid";
/// 確定した高さが、いちばん進んだノードからこれ以上遅れていれば外す（約1日）
const MAX_LAG: u64 = 2880;
/// `roles` の API のビット
const API_ROLE: u64 = 2;

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', ':'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// 200 で JSON を返したら、その中身と、CORS が開いているか
fn get(agent: &ureq::Agent, url: &str) -> Option<(Value, bool)> {
    let mut response = agent.get(url).header("Origin", ORIGIN).call().ok()?;
    if response.status() != 200 {
        return None;
    }
    let cors = response
        .headers()
        .get("access-control-allow-origin")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "*" || value == ORIGIN);
    let body = response.body_mut().read_to_string().ok()?;
    Some((serde_json::from_str(&body).ok()?, cors))
}

/// `/node/peers` から、同じネットワークで API の役割を持つホスト
fn api_hosts(peers: &Value, network: u64, seed_hash: &str) -> Vec<String> {
    peers
        .as_array()
        .into_iter()
        .flatten()
        .filter(|peer| {
            peer["roles"]
                .as_u64()
                .is_some_and(|roles| roles & API_ROLE != 0)
                && peer["networkIdentifier"].as_u64() == Some(network)
                && peer["networkGenerationHashSeed"]
                    .as_str()
                    .is_some_and(|hash| hash.eq_ignore_ascii_case(seed_hash))
        })
        .filter_map(|peer| peer["host"].as_str())
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect()
}

struct Probe {
    finalized: u64,
    peers: Vec<String>,
}

fn probe(agent: &ureq::Agent, host: &str, network: u64, seed_hash: &str) -> Option<Probe> {
    let base = format!("https://{host}:3001");
    let (info, cors) = get(agent, &format!("{base}/node/info"))?;
    if !cors
        || info["networkIdentifier"].as_u64() != Some(network)
        || !info["networkGenerationHashSeed"]
            .as_str()
            .is_some_and(|hash| hash.eq_ignore_ascii_case(seed_hash))
    {
        return None;
    }
    let (chain, _) = get(agent, &format!("{base}/chain/info"))?;
    let finalized = chain["latestFinalizedBlock"]["height"]
        .as_str()?
        .parse()
        .ok()?;
    let peers = get(agent, &format!("{base}/node/peers"))
        .map(|(peers, _)| api_hosts(&peers, network, seed_hash))
        .unwrap_or_default();
    Some(Probe { finalized, peers })
}

struct State {
    queue: VecDeque<String>,
    seen: HashSet<String>,
    found: Vec<(String, u64)>,
    active: usize,
}

struct Crawled {
    network: u64,
    probed: usize,
    answered: usize,
    urls: Vec<String>,
}

fn crawl(agent: &ureq::Agent, seed: &str, exclude: &HashSet<String>) -> Result<Crawled, String> {
    let seed = seed.trim().trim_end_matches('/');
    let (info, _) =
        get(agent, &format!("{seed}/node/info")).ok_or("種のノードの /node/info が読めません")?;
    let network = info["networkIdentifier"]
        .as_u64()
        .ok_or("種のノードのネットワークが分かりません")?;
    let seed_hash = info["networkGenerationHashSeed"]
        .as_str()
        .ok_or("種のノードの generation hash seed が分かりません")?
        .to_owned();
    let (peers, _) =
        get(agent, &format!("{seed}/node/peers")).ok_or("種のノードの /node/peers が読めません")?;

    // 除外するホストは、最初から見たことにして問い合わせない
    let mut seen: HashSet<String> = exclude.clone();
    let mut queue = VecDeque::new();
    for host in api_hosts(&peers, network, &seed_hash) {
        if seen.insert(host.clone()) {
            queue.push_back(host);
        }
    }
    let state = Mutex::new(State {
        queue,
        seen,
        found: Vec::new(),
        active: 0,
    });

    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                loop {
                    let host = {
                        let mut state = state.lock().unwrap();
                        match state.queue.pop_front() {
                            Some(host) => {
                                state.active += 1;
                                host
                            }
                            None if state.active == 0 => break,
                            None => {
                                drop(state);
                                std::thread::sleep(Duration::from_millis(50));
                                continue;
                            }
                        }
                    };
                    let result = probe(agent, &host, network, &seed_hash);
                    let mut state = state.lock().unwrap();
                    state.active -= 1;
                    if let Some(result) = result {
                        state.found.push((host, result.finalized));
                        for peer in result.peers {
                            if state.seen.len() < MAX_HOSTS && state.seen.insert(peer.clone()) {
                                state.queue.push_back(peer);
                            }
                        }
                    }
                }
            });
        }
    });

    let state = state.into_inner().unwrap();
    let newest = state
        .found
        .iter()
        .map(|(_, height)| *height)
        .max()
        .unwrap_or(0);
    let mut urls: Vec<String> = state
        .found
        .iter()
        .filter(|(_, height)| height + MAX_LAG >= newest)
        .map(|(host, _)| format!("https://{host}:3001"))
        .collect();
    urls.sort();
    Ok(Crawled {
        network,
        probed: state.seen.len() - exclude.len(),
        answered: state.found.len(),
        urls,
    })
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("書き出す JSON のパスを渡してください");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(8)))
        .http_status_as_error(false)
        .build()
        .into();

    let seeds: Vec<(&str, u64, String)> = [
        ("mainnet", 0x68, "KUSA_SEED_MAINNET"),
        ("testnet", 0x98, "KUSA_SEED_TESTNET"),
    ]
    .into_iter()
    .filter_map(|(name, network, key)| {
        std::env::var(key)
            .ok()
            .filter(|v| !v.is_empty())
            .map(|seed| (name, network, seed))
    })
    .collect();
    if seeds.is_empty() {
        eprintln!("KUSA_SEED_MAINNET か KUSA_SEED_TESTNET を設定してください");
        std::process::exit(2);
    }
    let mut exclude: HashSet<String> = std::env::var("KUSA_EXCLUDE")
        .unwrap_or_default()
        .split(',')
        .map(|host| host.trim().to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .collect();
    exclude.extend(seeds.iter().map(|(_, _, seed)| host_of(seed)));

    let mut result = json!({});
    for (name, network, seed) in &seeds {
        match crawl(&agent, seed, &exclude) {
            Ok(crawled) if crawled.network == *network => {
                println!(
                    "{name}: {} か所を調べ、{} か所が答え、{} か所を一覧に入れました",
                    crawled.probed,
                    crawled.answered,
                    crawled.urls.len()
                );
                result[*name] = json!(crawled.urls);
            }
            Ok(crawled) => {
                eprintln!(
                    "{name}: 種のノードのネットワークが違います（{}）",
                    crawled.network
                );
                std::process::exit(1);
            }
            Err(message) => {
                eprintln!("{name}: {message}");
                std::process::exit(1);
            }
        }
    }
    std::fs::write(&out, serde_json::to_string_pretty(&result).unwrap() + "\n")
        .expect("書き出せません");
}
