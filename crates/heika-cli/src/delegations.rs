//! `heika node delegations`: ノードあての委任の要求をブロックから拾い、今も有効かを出す。

use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use heika_block::Block;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_harvesting::delegation::{DelegationTracker, LinkKind, Status};
use heika_p2p::Node;
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
}

pub fn run(args: Args) -> Result<(), Failure> {
    let chain = read_chain(args.client_cert)?;
    let AnyPrivateKey(key) = read_secret("ノードの秘密鍵", "node.key.pem")?;
    let identity = Identity::new(&chain, &key)
        .map_err(|error| format!("{}: {error}", args.client_cert.display()))?;
    let connect = |address: &str| {
        Node::connect(address, &identity, TIMEOUT).map_err(|error| format!("{address}: {error}"))
    };

    let mut node = connect(args.connect)?;
    let query = |error| format!("{}: {error}", args.connect);
    let network = node.info().map_err(query)?.network_identifier;
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
    outln!("高さ        状態  メインアカウント");
    for delegation in &report.delegations {
        outln!(
            "{:<10}  {}  {}{}",
            delegation.height,
            status_label(&delegation.status),
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
    Ok(())
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
