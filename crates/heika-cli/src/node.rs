//! ノードに TLS でつないで調べる。

use std::collections::HashSet;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Subcommand;
use heika_p2p::{NetworkNode, Node};
use heika_tls::Identity;

use crate::cert::{AnyPrivateKey, read_chain};
use crate::{Failure, read_secret};

/// 1つのノードにつなぐときと、1回の問い合わせを待つ時間
const TIMEOUT: Duration = Duration::from_secs(5);
/// 読み出しの速さを測るために取るブロックの数
const PROBE_BLOCKS: u32 = 100;
/// 測るブロックの高さを、最初のノードの確定した高さからどれだけ戻すか。
/// どのノードも同じ確定済みのブロックを返すので、比べられる
const PROBE_DEPTH: u64 = 1000;

#[derive(Subcommand)]
pub enum NodeCommand {
    /// 近くて速いノードを探す
    ///
    /// 最初のノードから、ほかのノードの一覧をもらう。そして1つずつ順につなぎ、
    /// 接続にかかる時間、高さ、確定済みのブロックを 100 件読むのにかかる時間を測る。
    /// 名乗るのは --client-cert の証明書で、ノードの秘密鍵は標準入力から読む。
    /// ノードを持っていなくても、heika cert ca と heika cert node で作った証明書でつなげる。
    Find {
        /// 最初につなぐノード
        #[arg(long, value_name = "HOST:PORT")]
        connect: String,
        /// 名乗る証明書のチェーン（ノード、CA の順の PEM）
        #[arg(long, value_name = "PATH")]
        client_cert: PathBuf,
        /// 測るノードの数の上限
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=100))]
        limit: u16,
    },
}

/// 1つのノードを測った結果。
struct Measurement {
    node: NetworkNode,
    address: String,
    connect: Duration,
    height: u64,
    pull: Duration,
}

pub fn run(command: NodeCommand) -> Result<(), Failure> {
    match command {
        NodeCommand::Find {
            connect,
            client_cert,
            limit,
        } => {
            let chain = read_chain(&client_cert)?;
            let AnyPrivateKey(key) = read_secret("ノードの秘密鍵", "node.key.pem")?;
            let identity = Identity::new(&chain, &key)
                .map_err(|error| format!("{}: {error}", client_cert.display()))?;
            drop(key);

            let mut seed = Node::connect(&connect, &identity, TIMEOUT)
                .map_err(|error| format!("{connect}: {error}"))?;
            let query = |error| format!("{connect}: {error}");
            let seed_info = seed.info().map_err(query)?;
            let statistics = seed.chain_statistics().map_err(query)?;
            let peers = seed.peers().map_err(query)?;
            drop(seed);
            let probe_height = statistics
                .finalized_height
                .saturating_sub(PROBE_DEPTH)
                .max(1);

            // 最初のノードも測る。同じネットワークで、名乗るホストがあるものだけを、重ならないように選ぶ
            let mut seen = HashSet::new();
            let candidates: Vec<(String, NetworkNode)> =
                std::iter::once((connect.clone(), seed_info.clone()))
                    .chain(
                        peers
                            .into_iter()
                            .filter(|node| {
                                node.network_identifier == seed_info.network_identifier
                                    && !node.host.is_empty()
                            })
                            .map(|node| (format!("{}:{}", node.host, node.port), node)),
                    )
                    .filter(|(_, node)| seen.insert(node.identity_key.0))
                    .take(limit.into())
                    .collect();

            outln!(
                "{} 台を測ります（確定済みの高さ {probe_height} から {PROBE_BLOCKS} ブロックを読む）",
                candidates.len()
            );
            let mut measurements = Vec::new();
            let mut failures = 0;
            for (address, node) in candidates {
                match measure(&address, &identity, probe_height) {
                    Ok(mut measurement) => {
                        measurement.node = node_or(measurement.node, node);
                        measurements.push(measurement);
                    }
                    Err(error) => {
                        failures += 1;
                        outln!("  {}: {}", printable(&address), without_controls(&error));
                    }
                }
            }

            let top = measurements.iter().map(|m| m.height).max().unwrap_or(0);
            measurements.sort_by_key(|m| m.pull);
            outln!();
            outln!("読み出し  接続    遅れ  バージョン  ロール            ノード");
            for m in &measurements {
                outln!(
                    "{:>6}ms {:>5}ms {:>5}  {:<10}  {:<16}  {} {}",
                    m.pull.as_millis(),
                    m.connect.as_millis(),
                    top - m.height,
                    m.node.version.to_string(),
                    m.node.roles.to_string(),
                    printable(&m.address),
                    printable(&m.node.friendly_name),
                );
            }
            outln!();
            outln!(
                "測れたノード: {}、測れなかったノード: {failures}。読み出しは {PROBE_BLOCKS} ブロックを読むのにかかった時間、遅れは一番高いノードとの高さの差",
                measurements.len()
            );
        }
    }
    Ok(())
}

/// 1つのノードにつないで測る。
fn measure(address: &str, identity: &Identity, probe_height: u64) -> Result<Measurement, String> {
    let started = Instant::now();
    let mut node = Node::connect(address, identity, TIMEOUT).map_err(|error| error.to_string())?;
    let connect = started.elapsed();
    let info = node.info().map_err(|error| error.to_string())?;
    let height = node
        .chain_statistics()
        .map_err(|error| error.to_string())?
        .height;
    let started = Instant::now();
    let blocks = node
        .pull_blocks(probe_height, PROBE_BLOCKS, 16 * 1024 * 1024)
        .map_err(|error| error.to_string())?;
    let pull = started.elapsed();
    if blocks.is_empty() {
        return Err(format!("高さ {probe_height} のブロックがありません"));
    }
    Ok(Measurement {
        node: info,
        address: address.to_owned(),
        connect,
        height,
        pull,
    })
}

/// つないだノード自身が名乗った情報を使い、名前が空なら一覧の情報で補う。
fn node_or(own: NetworkNode, listed: NetworkNode) -> NetworkNode {
    if own.friendly_name.is_empty() {
        NetworkNode {
            friendly_name: listed.friendly_name,
            ..own
        }
    } else {
        own
    }
}

/// ノードが名乗った文字列を、端末を壊さないように表示する。制御文字は置き換え、長すぎるものは切る。
fn printable(text: &str) -> String {
    const MAX_CHARS: usize = 48;
    let mut printable = without_controls(&text.chars().take(MAX_CHARS).collect::<String>());
    if text.chars().count() > MAX_CHARS {
        printable.push('…');
    }
    printable
}

/// 制御文字を置き換える。エラーの文にもノードが名乗った文字列が入りうるので、切らずにこれだけはする。
fn without_controls(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_control_characters_and_cuts_long_names() {
        assert_eq!(printable("node\x1b[2Jname"), "node?[2Jname");
        assert_eq!(printable(&"a".repeat(49)), format!("{}…", "a".repeat(48)));
        assert_eq!(
            without_controls(&format!("{}\n", "a".repeat(60))),
            format!("{}?", "a".repeat(60))
        );
    }
}
