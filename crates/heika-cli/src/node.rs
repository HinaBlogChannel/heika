//! ノードに TLS でつないで調べる。

use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Subcommand;
use heika_cert::certificate::Certificate;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_p2p::{NetworkNode, Node, NodeRoles};
use heika_tls::Identity;

use crate::cert::{AnyPrivateKey, read_chain};
use crate::tx::write_new;
use crate::{Failure, json, read_secret};

/// 1つのノードにつなぐときと、1回の問い合わせを待つ時間
const TIMEOUT: Duration = Duration::from_secs(5);
/// 読み出しの速さを測るために取るブロックの数
const PROBE_BLOCKS: u32 = 100;
/// 測るブロックの高さを、最初のノードの確定した高さからどれだけ戻すか。
/// どのノードも同じ確定済みのブロックを返すので、比べられる
const PROBE_DEPTH: u64 = 1000;
/// ブロックの目標間隔。メインネットもテストネットも、ネットワークの設定 blockGenerationTargetTime は 30s
const BLOCK_TIME: Duration = Duration::from_secs(30);
/// --peers-json に書くノードの、遅れの上限（ブロック）。遅れは目標間隔で換算した推定なので、
/// 実際のブロックの間隔のばらつきで、遅れていないノードにも数ブロックの遅れが出ることがある
const MAX_PEER_LAG: u64 = 5;

#[derive(Subcommand)]
pub enum NodeCommand {
    /// 近くて速いノードを探す
    ///
    /// 最初のノードから、ほかのノードの一覧をもらう。そして1つずつ順につなぎ、
    /// 接続にかかる時間、高さ、確定済みのブロックを 100 件読むのにかかる時間を測る。
    /// --crawl を付けると、測ったノードからも一覧をもらい、まだ見ていないノードをたどる。
    /// 名乗るのは --client-cert の証明書で、ノードの秘密鍵は標準入力から読む。
    /// ノードを持っていなくても、heika cert ca と heika cert node で作った証明書でつなげる。
    /// --peers-json を付けると、遅れがなく Peer のロールのあるノードを、読み出しの速い順に、
    /// catapult の peers-p2p.json の形式で書く。
    Find {
        /// 最初につなぐノード
        #[arg(long, value_name = "HOST:PORT")]
        connect: String,
        /// 名乗る証明書のチェーン（ノード、CA の順の PEM）
        #[arg(long, value_name = "PATH")]
        client_cert: PathBuf,
        /// 測るノードの数の上限
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
        /// 測ったノードからも一覧をもらい、まだ見ていないノードをたどる
        #[arg(long)]
        crawl: bool,
        /// 測ったノードを、catapult の peers-p2p.json の形式で書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        peers_json: Option<PathBuf>,
        /// --peers-json に書くノードの数の上限
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u16).range(1..=1000), requires = "peers_json")]
        peers_count: u16,
        /// 測った結果を、表の代わりに JSON で標準出力に出す。途中の経過は標準エラーに出す
        #[arg(long)]
        json: bool,
    },
    /// ノードあての委任の要求をブロックから拾い、今も有効かを出す
    ///
    /// 自分のノードに、ノード自身の証明書（--client-cert）で名乗ってつなぎ、ブロックを順に読む。
    /// 標準入力から読むノードの秘密鍵（node.key.pem）は、名乗るのにも、委任の要求を復号するのにも使う。
    /// 要求ごとに、走査した範囲で最後に見たメインアカウントのリンク（リモート、VRF、ノード）と比べ、
    /// 有効（3つとも合う）、無効（合わないものがある）、不明（走査した範囲でリンクを見ていない）に分ける。
    /// 知らない種類のトランザクションがあれば、結果が正しくないかもしれないので止める。
    Delegations {
        /// 走査するノード。自分のノードにする
        #[arg(long, value_name = "HOST:PORT")]
        connect: String,
        /// ノード自身の証明書のチェーン（node.full.crt.pem）
        #[arg(long, value_name = "PATH")]
        client_cert: PathBuf,
        /// 走査を始める高さ。ノードが委任を受け付け始めたころから
        #[arg(long, value_name = "HEIGHT")]
        from_height: u64,
        /// 走査を終える高さ。省略するとノードの今の高さ
        #[arg(long, value_name = "HEIGHT")]
        to_height: Option<u64>,
        /// ノードの harvesters.dat。渡すと、見つけた要求が入っているかを突き合わせる。読むだけで書き換えない
        #[arg(long, value_name = "PATH")]
        harvesters_dat: Option<PathBuf>,
        /// --harvesters-dat の今のファイルに、入っていない有効な委任と有効かわからない委任を足して書くファイル
        ///
        /// 今の項目は無効なものも含めてすべて残す。すでにあるファイルは上書きせず、ノードのファイルも書き換えない。
        /// ノードを止め、元のファイルを残したうえで置き換える。ノードに harvesters.dat がなければ、空のファイルを --harvesters-dat に渡す。
        #[arg(long, value_name = "PATH", requires = "harvesters_dat")]
        write_harvesters_dat: Option<PathBuf>,
    },
}

/// 1つのノードを測った結果。
struct Measurement {
    node: NetworkNode,
    /// TLS で出した CA の証明書の公開鍵。catapult が peers-p2p.json の publicKey と比べるのはこれ
    ca_key: PublicKey,
    address: String,
    connect: Duration,
    height: u64,
    /// 高さを問い合わせた時刻
    measured_at: Instant,
    pull: Duration,
}

pub fn run(command: NodeCommand) -> Result<(), Failure> {
    match command {
        NodeCommand::Delegations {
            connect,
            client_cert,
            from_height,
            to_height,
            harvesters_dat,
            write_harvesters_dat,
        } => crate::delegations::run(crate::delegations::Args {
            connect: &connect,
            client_cert: &client_cert,
            from_height,
            to_height,
            harvesters_dat: harvesters_dat.as_deref(),
            write_harvesters_dat: write_harvesters_dat.as_deref(),
        })?,
        NodeCommand::Find {
            connect,
            client_cert,
            limit,
            crawl,
            peers_json,
            peers_count,
            json,
        } => {
            // JSON を出すときは、標準出力を JSON だけにする
            let progress = |text: &str| -> Result<(), Failure> {
                if json {
                    eprintln!("{text}");
                } else {
                    outln!("{text}");
                }
                Ok(())
            };
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
            let network = seed_info.network_identifier;
            let mut seen = HashSet::from([connect.clone(), seed_info.identity_key.to_string()]);
            let mut queue = VecDeque::from([(connect.clone(), seed_info)]);
            enqueue(&mut queue, &mut seen, peers, network);

            progress(&format!(
                "確定済みの高さ {probe_height} から {PROBE_BLOCKS} ブロックを読んで測ります（上限 {limit} 台{}）",
                if crawl { "、一覧をたどる" } else { "" }
            ))?;
            let mut measurements = Vec::new();
            let mut failures = Vec::new();
            while let Some((address, node)) = queue.pop_front() {
                if measurements.len() + failures.len() >= usize::from(limit) {
                    break;
                }
                match measure(&address, &identity, probe_height, crawl) {
                    Ok((mut measurement, peers)) => {
                        measurement.node = node_or(measurement.node, node);
                        measurements.push(measurement);
                        enqueue(&mut queue, &mut seen, peers, network);
                    }
                    Err(error) => {
                        progress(&format!(
                            "  {}: {}",
                            printable(&address),
                            without_controls(&error)
                        ))?;
                        failures.push((address, error));
                    }
                }
                let done = measurements.len() + failures.len();
                if done % 50 == 0 {
                    progress(&format!(
                        "  {done} 台を測りました（残り {} 台が待っています）",
                        queue.len()
                    ))?;
                }
            }

            // 遅れは並べ替える前の順で計算するので、ノードと組にしてから並べ替える
            let tips = expected_heights(&measurements);
            let mut rows: Vec<(Measurement, u64)> = measurements
                .into_iter()
                .zip(tips)
                .map(|(m, tip)| {
                    let lag = tip.saturating_sub(m.height);
                    (m, lag)
                })
                .collect();
            rows.sort_by_key(|(m, _)| m.pull);
            if json {
                outln!(
                    "{}",
                    find_json(probe_height, &rows, &failures)
                        .render()
                        .trim_end()
                );
            } else {
                outln!();
                outln!("読み出し  接続    遅れ  バージョン  ロール            ノード");
                for (m, lag) in &rows {
                    outln!(
                        "{:>6}ms {:>5}ms {:>5}  {:<10}  {:<16}  {} {}",
                        m.pull.as_millis(),
                        m.connect.as_millis(),
                        lag,
                        m.node.version.to_string(),
                        m.node.roles.to_string(),
                        printable(&m.address),
                        printable(&m.node.friendly_name),
                    );
                }
                outln!();
                outln!(
                    "測れたノード: {}、測れなかったノード: {}。読み出しは {PROBE_BLOCKS} ブロックを読むのにかかった時間、遅れは、測った時刻をブロックの目標間隔でそろえたうえでの、一番進んでいるノードとの高さの差",
                    rows.len(),
                    failures.len()
                );
            }

            if let Some(path) = peers_json {
                // 自分のノードを載せると、catapult が自分につなごうとする
                let own_key = *chain[1].public_key();
                let peers: Vec<(&Measurement, Endpoint)> = rows
                    .iter()
                    .filter(|(m, lag)| {
                        m.node.roles.contains(NodeRoles::PEER)
                            && *lag <= MAX_PEER_LAG
                            && m.ca_key != own_key
                    })
                    .filter_map(|(m, _)| Some((m, Endpoint::parse(&m.address)?)))
                    .take(usize::from(peers_count))
                    .collect();
                if peers.is_empty() {
                    return Err(format!(
                        "Peer のロールがあり、遅れが {MAX_PEER_LAG} ブロック以下のノードがないので、{} は書きませんでした",
                        path.display()
                    )
                    .into());
                }
                write_new(&path, peers_p2p_json(&peers).as_bytes())?;
                progress(&format!(
                    "{} に {} 台を書きました。Peer のロールがあり、遅れが {MAX_PEER_LAG} ブロック以下のノードを、読み出しの速い順に選んでいます（自分のノードは除く）",
                    path.display(),
                    peers.len()
                ))?;
            }
        }
    }
    Ok(())
}

/// まだ見ていないノードを待ち行列に足す。同じネットワークで、名乗るホストがあるものだけを選ぶ。
/// 同じノードが別の名前で載っていることもあるので、アドレスと公開鍵の両方で重なりを除く。
fn enqueue(
    queue: &mut VecDeque<(String, NetworkNode)>,
    seen: &mut HashSet<String>,
    peers: Vec<NetworkNode>,
    network: NetworkIdentifier,
) {
    for node in peers {
        if node.network_identifier != network || node.host.is_empty() {
            continue;
        }
        let address = format!("{}:{}", node.host, node.port);
        let key = node.identity_key.to_string();
        if seen.contains(&address) || seen.contains(&key) {
            continue;
        }
        seen.insert(address.clone());
        seen.insert(key);
        queue.push_back((address, node));
    }
}

/// 1つのノードにつないで測る。`crawl` なら、そのノードが知っているほかのノードも返す。
fn measure(
    address: &str,
    identity: &Identity,
    probe_height: u64,
    crawl: bool,
) -> Result<(Measurement, Vec<NetworkNode>), String> {
    let started = Instant::now();
    let mut node = Node::connect(address, identity, TIMEOUT).map_err(|error| error.to_string())?;
    let connect = started.elapsed();
    let ca_key = ca_key(&node)?;
    let info = node.info().map_err(|error| error.to_string())?;
    let height = node
        .chain_statistics()
        .map_err(|error| error.to_string())?
        .height;
    let measured_at = Instant::now();
    let started = Instant::now();
    let blocks = node
        .pull_blocks(probe_height, PROBE_BLOCKS, 16 * 1024 * 1024)
        .map_err(|error| error.to_string())?;
    let pull = started.elapsed();
    if blocks.is_empty() {
        return Err(format!("高さ {probe_height} のブロックがありません"));
    }
    let peers = if crawl {
        node.peers().map_err(|error| error.to_string())?
    } else {
        Vec::new()
    };
    let measurement = Measurement {
        node: info,
        ca_key,
        address: address.to_owned(),
        connect,
        height,
        measured_at,
        pull,
    };
    Ok((measurement, peers))
}

/// 相手が TLS で出した、CA の証明書の公開鍵。接続できたなら、チェーンは catapult の条件で確かめてある。
fn ca_key(node: &Node) -> Result<PublicKey, String> {
    let certificates = node.peer_certificates();
    let ca = certificates
        .get(1)
        .ok_or_else(|| "CA の証明書がありません".to_owned())?;
    Certificate::from_der(ca)
        .map(|ca| *ca.public_key())
        .map_err(|error| format!("CA の証明書を読めません: {error}"))
}

/// `heika node find --json` の中身。表と同じものを、読み出しの速い順に並べる。
/// 時間はミリ秒、遅れはブロック。名前やエラーはノードが返したものなので、文字列としてエスケープするだけにする
fn find_json(
    probe_height: u64,
    rows: &[(Measurement, u64)],
    failures: &[(String, String)],
) -> json::Value {
    let nodes = rows
        .iter()
        .map(|(m, lag)| {
            json::Value::Object(vec![
                ("address", m.address.as_str().into()),
                ("name", m.node.friendly_name.as_str().into()),
                ("version", m.node.version.to_string().into()),
                (
                    "roles",
                    json::Value::Array(m.node.roles.names().into_iter().map(Into::into).collect()),
                ),
                ("height", m.height.into()),
                ("lag", (*lag).into()),
                ("connectMs", (m.connect.as_millis() as u64).into()),
                ("pullMs", (m.pull.as_millis() as u64).into()),
                ("nodePublicKey", m.node.identity_key.to_string().into()),
                ("caPublicKey", m.ca_key.to_string().into()),
            ])
        })
        .collect();
    let failures = failures
        .iter()
        .map(|(address, error)| {
            json::Value::Object(vec![
                ("address", address.as_str().into()),
                ("error", error.as_str().into()),
            ])
        })
        .collect();
    json::Value::Object(vec![
        ("probeHeight", probe_height.into()),
        ("probeBlocks", u64::from(PROBE_BLOCKS).into()),
        ("nodes", json::Value::Array(nodes)),
        ("failures", json::Value::Array(failures)),
    ])
}

/// peers-p2p.json の endpoint。つないだ `HOST:PORT` を分けたもの。
struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    /// `[::1]:7900` のように角かっこで囲んだ IPv6 のアドレスは、角かっこを外す。
    fn parse(address: &str) -> Option<Self> {
        let (host, port) = address.rsplit_once(':')?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        Some(Self {
            host: host.to_owned(),
            port: port.parse().ok()?,
        })
    }
}

/// catapult の peers-p2p.json（`config/PeersConfiguration.cpp` が読む形式）。
///
/// publicKey は TLS で確かめた CA の公開鍵、roles はノード自身が名乗ったロールにする。
/// IPv4 も IPv6 も名乗っていないノードは、catapult が IPv4 とみなす（`ionet/IpProtocol.cpp`）。
fn peers_p2p_json(peers: &[(&Measurement, Endpoint)]) -> String {
    let mut json = String::from("{\n  \"knownPeers\": [");
    for (i, (m, endpoint)) in peers.iter().enumerate() {
        json.push_str(if i == 0 { "\n" } else { ",\n" });
        write!(
            json,
            r#"    {{
      "publicKey": "{}",
      "endpoint": {{
        "host": {},
        "port": {}
      }},
      "metadata": {{
        "name": {},
        "roles": "{}"
      }}
    }}"#,
            m.ca_key,
            json::string(&endpoint.host),
            endpoint.port,
            json::string(&m.node.friendly_name),
            m.node.roles.to_config_value(),
        )
        .expect("writing to a String never fails");
    }
    json.push_str("\n  ]\n}\n");
    json
}

/// それぞれのノードを測った時刻に、一番進んでいるノードならどの高さにいたはずか。
///
/// 全部を測るには何分もかかり、そのあいだにもチェーンは進む。なので、ほかのノードの高さを
/// 測った時刻の差だけブロックの目標間隔で進めたり戻したりして、その時刻の高さに換算してから一番高いものをとる。
fn expected_heights(measurements: &[Measurement]) -> Vec<u64> {
    let blocks_between = |from: Instant, to: Instant| -> i128 {
        let blocks = |elapsed: Duration| (elapsed.as_millis() / BLOCK_TIME.as_millis()) as i128;
        if to >= from {
            blocks(to - from)
        } else {
            -blocks(from - to)
        }
    };
    measurements
        .iter()
        .map(|target| {
            measurements
                .iter()
                .map(|other| {
                    i128::from(other.height) + blocks_between(other.measured_at, target.measured_at)
                })
                .max()
                .map_or(target.height, |height| {
                    height.clamp(0, i128::from(u64::MAX)) as u64
                })
        })
        .collect()
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

    fn measurement(height: u64, measured_at: Instant) -> Measurement {
        Measurement {
            node: NetworkNode {
                version: heika_p2p::NodeVersion(0),
                identity_key: heika_core::key::PublicKey([0; 32]),
                network_generation_hash_seed: heika_core::network::GenerationHashSeed([0; 32]),
                roles: heika_p2p::NodeRoles(1),
                port: 7900,
                network_identifier: NetworkIdentifier::MAINNET,
                host: String::new(),
                friendly_name: String::new(),
            },
            ca_key: heika_core::key::PublicKey([0; 32]),
            address: String::new(),
            connect: Duration::ZERO,
            height,
            measured_at,
            pull: Duration::ZERO,
        }
    }

    #[test]
    fn compares_heights_at_the_same_time() {
        let start = Instant::now();
        // 1分後に2ブロック進んでいたノードと、3分後に2ブロックしか進んでいないノード
        let measurements = [
            measurement(100, start),
            measurement(102, start + Duration::from_secs(60)),
            measurement(102, start + Duration::from_secs(180)),
        ];
        assert_eq!(expected_heights(&measurements), [100, 102, 106]);
    }
    #[test]
    fn writes_find_results_that_a_json_parser_reads_back() {
        let mut m = measurement(100, Instant::now());
        m.address = "node.example:7900".to_owned();
        m.node.friendly_name = "name \"\x1b[2J".to_owned();
        m.connect = Duration::from_millis(12);
        m.pull = Duration::from_millis(345);
        let failures = [("down.example:7900".to_owned(), "timed out\n".to_owned())];
        let rendered = find_json(99_000, &[(m, 2)], &failures).render();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(json["probeHeight"], 99_000);
        assert_eq!(json["probeBlocks"], 100);
        let node = &json["nodes"][0];
        assert_eq!(node["address"], "node.example:7900");
        assert_eq!(node["name"], "name \"\x1b[2J");
        assert_eq!(node["height"], 100);
        assert_eq!(node["roles"], serde_json::json!(["Peer"]));
        assert_eq!(node["lag"], 2);
        assert_eq!(node["connectMs"], 12);
        assert_eq!(node["pullMs"], 345);
        assert_eq!(node["caPublicKey"], "0".repeat(64));
        assert_eq!(json["failures"][0]["error"], "timed out\n");
    }

    #[test]
    fn replaces_control_characters_and_cuts_long_names() {
        assert_eq!(printable("node\x1b[2Jname"), "node?[2Jname");
        assert_eq!(printable(&"a".repeat(49)), format!("{}…", "a".repeat(48)));
        assert_eq!(
            without_controls(&format!("{}\n", "a".repeat(60))),
            format!("{}?", "a".repeat(60))
        );
    }

    #[test]
    fn splits_endpoints() {
        let endpoint = Endpoint::parse("node.example:7900").unwrap();
        assert_eq!(
            (endpoint.host.as_str(), endpoint.port),
            ("node.example", 7900)
        );
        let endpoint = Endpoint::parse("[2001:db8::1]:7900").unwrap();
        assert_eq!(
            (endpoint.host.as_str(), endpoint.port),
            ("2001:db8::1", 7900)
        );
        assert!(Endpoint::parse("node.example").is_none());
        assert!(Endpoint::parse("node.example:port").is_none());
    }

    #[test]
    fn writes_peers_p2p_json() {
        let mut m = measurement(100, Instant::now());
        m.ca_key = PublicKey([0xab; 32]);
        m.node.roles = NodeRoles(0x43);
        m.node.friendly_name = "a\"b\\c\n".to_owned();
        let endpoint = Endpoint {
            host: "node.example".to_owned(),
            port: 7900,
        };
        let expected = format!(
            r#"{{
  "knownPeers": [
    {{
      "publicKey": "{}",
      "endpoint": {{
        "host": "node.example",
        "port": 7900
      }},
      "metadata": {{
        "name": "a\"b\\c\u000a",
        "roles": "Peer,Api,IPv4"
      }}
    }}
  ]
}}
"#,
            "AB".repeat(32)
        );
        assert_eq!(peers_p2p_json(&[(&m, endpoint)]), expected);
    }

    #[test]
    fn writes_names_and_hosts_that_a_json_parser_reads_back() {
        let names = [
            String::from("\"\\/"),
            (0..0x20).map(char::from).collect(),
            String::from("\u{7f}\u{85}\u{2028}\u{2029}"),
            String::from("ノード🎉"),
        ];
        let measurements: Vec<Measurement> = names
            .iter()
            .map(|name| {
                let mut m = measurement(100, Instant::now());
                m.node.friendly_name = name.clone();
                m
            })
            .collect();
        let peers: Vec<(&Measurement, Endpoint)> = measurements
            .iter()
            .zip(&names)
            .map(|(m, name)| {
                let endpoint = Endpoint {
                    host: name.clone(),
                    port: 7900,
                };
                (m, endpoint)
            })
            .collect();
        let json: serde_json::Value = serde_json::from_str(&peers_p2p_json(&peers)).unwrap();
        let known_peers = json["knownPeers"].as_array().unwrap();
        assert_eq!(known_peers.len(), names.len());
        for (peer, name) in known_peers.iter().zip(&names) {
            assert_eq!(peer["metadata"]["name"], name.as_str());
            assert_eq!(peer["endpoint"]["host"], name.as_str());
            assert_eq!(peer["endpoint"]["port"], 7900);
        }
    }
}
