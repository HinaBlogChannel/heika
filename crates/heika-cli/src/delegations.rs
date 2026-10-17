//! `heika node delegations`: ノードあての委任の要求をブロックから拾い、今も有効かを出す。

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use heika_block::Block;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::network::NetworkParameters;
use heika_harvesting::delegation::{DelegationTracker, LinkKind, Status};
use heika_harvesting::harvesters_dat;
use heika_p2p::Client;
use heika_tls::Identity;
use heika_transaction::scan;

use crate::cert::{AnyPrivateKey, read_chain};
use crate::{Failure, read_secret};

/// 1回の問い合わせを待つ時間。ブロックをまとめて取るので長めにする
const TIMEOUT: Duration = Duration::from_secs(30);
/// 1回に取るブロックの数とバイト数の上限。ノードは自分の設定でさらに切り詰める
const PULL_BLOCKS: u32 = 1000;
const PULL_BYTES: u32 = 16 * 1024 * 1024;
/// 接続が切れたとき、続けてつなぎ直す回数
const RECONNECTS: u32 = 3;
/// 進み具合を出す間隔（ブロック）
const PROGRESS_INTERVAL: u64 = 10_000;

pub struct Args<'a> {
    pub connect: &'a str,
    pub client_cert: &'a Path,
    pub from_height: u64,
    pub to_height: Option<u64>,
    pub harvesters_dat: Option<&'a Path>,
    /// 今の harvesters.dat（`harvesters_dat`）に、入っていない委任を足して書くファイル
    pub write_harvesters_dat: Option<&'a Path>,
}

pub fn run(args: Args) -> Result<(), Failure> {
    let chain = read_chain(args.client_cert)?;
    let AnyPrivateKey(key) = read_secret("ノードの秘密鍵", "node.key.pem")?;
    let identity = Identity::new(&chain, &key)
        .map_err(|error| format!("{}: {error}", args.client_cert.display()))?;
    // 走査を終えてから書けないとわかるのを避ける。書くときにも上書きしないように確かめる
    if let Some(path) = args.write_harvesters_dat
        && path.exists()
    {
        return Err(format!("{} はすでにあります。上書きはしません", path.display()).into());
    }
    // 壊れていれば走査に時間をかける前に止まれるように、先に読む
    let harvesters = match args.harvesters_dat {
        Some(path) => {
            let bytes = fs::read(path)
                .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
            let entries = harvesters_dat::read(&bytes, &key)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            Some(entries)
        }
        None => None,
    };
    let connect = |address: &str| {
        Client::connect(address, &identity, TIMEOUT).map_err(|error| format!("{address}: {error}"))
    };

    let mut node = connect(args.connect)?;
    let query = |error| format!("{}: {error}", args.connect);
    let info = node.info().map_err(query)?;
    let network = info.network_identifier;
    // 知っているネットワークなら、ノードが名乗るものではなく、heika が持っている値を使う
    let seed = NetworkParameters::from_identifier(network)
        .map_or(info.network_generation_hash_seed, |parameters| {
            parameters.generation_hash_seed
        });
    let height = node.chain_statistics().map_err(query)?.height;
    let to_height = args.to_height.unwrap_or(height);
    if args.from_height == 0 || args.from_height > to_height {
        return Err(format!(
            "走査する範囲が正しくありません（{} から {to_height} まで。ノードの高さは {height}）",
            args.from_height
        )
        .into());
    }
    eprintln!(
        "高さ {} から {to_height} まで、{} ブロックを走査します",
        args.from_height,
        to_height - args.from_height + 1
    );

    let mut tracker = DelegationTracker::new(&key, network);
    let mut next = args.from_height;
    let mut previous_hash: Option<Hash256> = None;
    let mut transactions = 0_u64;
    let mut reconnects = 0;
    while next <= to_height {
        let count = (to_height - next + 1).min(u64::from(PULL_BLOCKS)) as u32;
        let blocks = match node.pull_blocks(next, count, PULL_BYTES) {
            Ok(blocks) => {
                reconnects = 0;
                blocks
            }
            Err(error) if reconnects < RECONNECTS => {
                reconnects += 1;
                eprintln!(
                    "高さ {next} で失敗したので、つなぎ直します（{reconnects} 回目）: {error}"
                );
                node = connect(args.connect)?;
                continue;
            }
            Err(error) => return Err(format!("高さ {next}: {error}").into()),
        };
        if blocks.is_empty() {
            return Err(format!("高さ {next} のブロックがありません").into());
        }
        for bytes in blocks.iter().take((to_height - next + 1) as usize) {
            let block =
                Block::from_bytes(bytes).map_err(|error| format!("高さ {next}: {error}"))?;
            // ノードが返したブロックが、頼んだ高さから途切れずにつながっているか
            if block.height != next {
                return Err(format!(
                    "高さ {next} を頼んだのに、高さ {} が返りました",
                    block.height
                )
                .into());
            }
            if previous_hash.is_some_and(|hash| hash != block.previous_block_hash) {
                return Err(format!(
                    "高さ {next} のブロックが、1つ前のブロックとつながっていません"
                )
                .into());
            }
            // 中のトランザクションが、ヘッダーの TransactionsHash と合っているか。ヘッダーはブロックのハッシュで
            // 次のブロックとつながるので、これで中身もチェーンにつながる
            if !block
                .verify_transactions_hash(&seed)
                .map_err(|error| format!("高さ {next}: {error}"))?
            {
                return Err(format!(
                    "高さ {next} のブロックの中身が、ヘッダーの TransactionsHash と合いません"
                )
                .into());
            }
            previous_hash = Some(block.hash());
            for transaction in block.transactions() {
                transactions += 1;
                let scanned = scan(transaction).map_err(|error| format!("高さ {next}: {error}"))?;
                for scanned in &scanned {
                    tracker.observe(next, scanned);
                }
            }
            if next.is_multiple_of(PROGRESS_INTERVAL) {
                eprintln!("  高さ {next} まで走査しました");
            }
            next += 1;
        }
    }
    drop(node);

    let report = tracker.finish();
    let in_harvesters: Option<HashSet<_>> = harvesters.as_ref().map(|entries| {
        entries
            .iter()
            .map(|entry| entry.encrypted_payload)
            .collect()
    });
    let column = |payload| match &in_harvesters {
        None => "",
        Some(payloads) if payloads.contains(payload) => "入っている  ",
        Some(_) => "            ",
    };
    outln!(
        "高さ        状態  {}メインアカウント",
        if in_harvesters.is_some() {
            "harvesters.dat  "
        } else {
            ""
        }
    );
    for delegation in &report.delegations {
        outln!(
            "{:<10}  {}  {}{}{}",
            delegation.height,
            status_label(&delegation.status),
            column(&delegation.encrypted_payload),
            Address::from_public_key(&delegation.main_account, network),
            status_detail(&delegation.status),
        );
    }
    let count = |predicate: fn(&Status) -> bool| {
        report
            .delegations
            .iter()
            .filter(|delegation| predicate(&delegation.status))
            .count()
    };
    outln!();
    outln!(
        "{} ブロック、{transactions} 件のトランザクションを走査しました。このノードあての委任の要求: 有効 {}、無効 {}、不明 {}",
        to_height - args.from_height + 1,
        count(|status| matches!(status, Status::Active)),
        count(|status| matches!(status, Status::Inactive { .. })),
        count(|status| matches!(status, Status::Unknown { .. })),
    );
    outln!(
        "有効はリンクが3つとも要求と合っているもの、無効は合わないリンクがあるもの、不明は走査した範囲でリンクを見ていないものです。同じアカウントの要求が複数あるときは、最新のリンクに合うものだけが有効になります"
    );
    if let (Some(entries), Some(payloads)) = (&harvesters, &in_harvesters) {
        let found: HashSet<_> = report
            .delegations
            .iter()
            .map(|delegation| delegation.encrypted_payload)
            .collect();
        let missing = |predicate: fn(&Status) -> bool| {
            report
                .delegations
                .iter()
                .filter(|delegation| {
                    predicate(&delegation.status)
                        && !payloads.contains(&delegation.encrypted_payload)
                })
                .count()
        };
        outln!(
            "harvesters.dat の {} 件のうち、走査で見つけた要求にあるもの {}、ないもの {}",
            entries.len(),
            entries
                .iter()
                .filter(|entry| found.contains(&entry.encrypted_payload))
                .count(),
            entries
                .iter()
                .filter(|entry| !found.contains(&entry.encrypted_payload))
                .count(),
        );
        outln!(
            "harvesters.dat に入っていない要求: 有効 {}、不明 {}。有効なものは、harvesters.dat に入れればノードがまた使えます",
            missing(|status| matches!(status, Status::Active)),
            missing(|status| matches!(status, Status::Unknown { .. })),
        );
    }
    if report.undecryptable > 0 {
        outln!(
            "このノードあてなのに、ノードの鍵で復号できない要求が {} 件ありました。ノードも捨てるものです",
            report.undecryptable
        );
    }
    if report.namespace_recipients > 0 {
        outln!(
            "ネームスペースあての要求の形をしたメッセージが {} 件ありました。ネームスペースを解決できないので、このノードあてかはわかりません",
            report.namespace_recipients
        );
    }

    if let (Some(path), Some(current)) = (args.write_harvesters_dat, &harvesters) {
        let merged = harvesters_dat::merge(current, &report.delegations);
        let added = merged.len() - current.len();
        outln!();
        if added == 0 {
            outln!(
                "今の harvesters.dat に足す委任がないので、{} は書きませんでした",
                path.display()
            );
            return Ok(());
        }
        // ノードは1件でも復号できない項目があると起動しないので、書く前と書いたあとに全部を復号してみる
        let bytes = harvesters_dat::to_bytes(&merged);
        harvesters_dat::read(&bytes, &key).map_err(|error| format!("書く前の確認: {error}"))?;
        write_private(path, &bytes)?;
        let written = fs::read(path)
            .map_err(|error| format!("{} を読み直せませんでした: {error}", path.display()))?;
        let entries = harvesters_dat::read(&written, &key)
            .map_err(|error| format!("書いたあとの確認: {}: {error}", path.display()))?;
        if entries.len() != merged.len() {
            return Err(format!("{} を読み直すと、件数が合いません", path.display()).into());
        }
        outln!(
            "{} に {} 件を書きました（今の {} 件に、{added} 件を足しました）。どれもノードの鍵で復号できることを、書いたあとに確かめました",
            path.display(),
            merged.len(),
            current.len()
        );
        outln!(
            "ノードを止め、元の harvesters.dat を残したうえで、このファイルに置き換えてから起動してください。合わない委任は、ノードが起動したあとで外します"
        );
    }
    Ok(())
}

/// 委任の秘密鍵を暗号化したものを書く。すでにあるファイルは上書きせず、Unix では自分だけが読み書きできるようにする。
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}

fn status_label(status: &Status) -> &'static str {
    match status {
        Status::Active => "有効",
        Status::Inactive { .. } => "無効",
        Status::Unknown { .. } => "不明",
    }
}

/// 無効と不明のときに、どのリンクのせいかを添える。
fn status_detail(status: &Status) -> String {
    let names = |kinds: &[LinkKind]| {
        kinds
            .iter()
            .map(|kind| match kind {
                LinkKind::Remote => "リモート",
                LinkKind::Vrf => "VRF",
                LinkKind::Node => "ノード",
            })
            .collect::<Vec<_>>()
            .join("、")
    };
    match status {
        Status::Active => String::new(),
        Status::Inactive { mismatched } => format!("（{}のリンクが合わない）", names(mismatched)),
        Status::Unknown { unseen } => format!("（{}のリンクを見ていない）", names(unseen)),
    }
}
