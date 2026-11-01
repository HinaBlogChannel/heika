//! Symbol を追いかけて、ロールアップの状態を 2 つ持つ。
//!
//! - `finalized`：ファイナライズされた Symbol のブロックまで。巻き戻らない
//! - `latest`：Symbol の先頭のブロックまで。`finalized` の写しに、ファイナライズされていないブロックを毎回実行し直して作る。
//!   Symbol で巻き戻りが起きても、次に作り直すときに直る

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use heika_core::address::Address;

use crate::rollup::{Deposit, Outcome, Rollup};
use crate::symbol::{Chain, Posted, Received};

#[derive(Clone)]
pub struct Views {
    pub finalized: Rollup,
    pub latest: Rollup,
}

/// どこを読むか。受け箱と、橋があれば預かり口座
#[derive(Clone, Copy)]
pub struct Sources<'a> {
    pub inbox: &'a Address,
    pub vault: Option<&'a Address>,
}

/// Symbol を 1 回見て、状態を進める。`finalized` の高さが進んだら、その高さとルートを出す
pub fn step(
    chain: &Chain,
    sources: Sources,
    finalized: &mut Rollup,
    views: &RwLock<Views>,
) -> Result<(), String> {
    let (tip, final_height) = chain.heights()?;
    advance_finalized(chain, sources, finalized, final_height)?;
    let mut latest = finalized.clone();
    if tip > latest.height {
        let from = latest.height + 1;
        apply(&mut latest, read(chain, sources, from, tip)?, false);
        latest.advance(tip, chain.block_time(tip)?);
    }
    *views.write().expect("not poisoned") = Views {
        finalized: finalized.clone(),
        latest,
    };
    Ok(())
}

/// `finalized` を、ファイナライズされた高さ `final_height` まで進める
pub fn advance_finalized(
    chain: &Chain,
    sources: Sources,
    finalized: &mut Rollup,
    final_height: u64,
) -> Result<(), String> {
    if final_height > finalized.height {
        let from = finalized.height + 1;
        apply(finalized, read(chain, sources, from, final_height)?, true);
        finalized.advance(final_height, chain.block_time(final_height)?);
        println!(
            "高さ {} までファイナライズ: ルート {}",
            finalized.height,
            finalized.state_root()
        );
    }
    Ok(())
}

/// 1 つの Symbol のブロックに載っていたもの
#[derive(Default)]
struct Board {
    timestamp: u64,
    deposits: Vec<Deposit>,
    transactions: Vec<Vec<u8>>,
}

/// 高さ `from` から `to` までに載ったものを、高さごとにまとめる
fn read(
    chain: &Chain,
    sources: Sources,
    from: u64,
    to: u64,
) -> Result<BTreeMap<u64, Board>, String> {
    let mut boards: BTreeMap<u64, Board> = BTreeMap::new();
    if let Some(vault) = sources.vault {
        for Received {
            height,
            timestamp,
            deposit,
        } in chain.deposits(vault, from, to)?
        {
            let board = boards.entry(height).or_default();
            board.timestamp = timestamp;
            board.deposits.push(deposit);
        }
    }
    for Posted {
        height,
        timestamp,
        bytes,
    } in chain.posted(sources.inbox, from, to)?
    {
        let board = boards.entry(height).or_default();
        board.timestamp = timestamp;
        board.transactions.push(bytes);
    }
    Ok(boards)
}

/// 高さの順に実行する。`report` なら、何が起きたかを出す
fn apply(rollup: &mut Rollup, boards: BTreeMap<u64, Board>, report: bool) {
    for (height, board) in boards {
        if report {
            for deposit in &board.deposits {
                println!(
                    "高さ {height}: {} に {} XYM を入金しました",
                    deposit.to,
                    xym(deposit.amount)
                );
            }
        }
        for outcome in rollup.apply(
            height,
            board.timestamp,
            &board.deposits,
            &board.transactions,
        ) {
            if !report {
                continue;
            }
            match outcome {
                Outcome::Executed(hash) => println!("高さ {height}: {hash} を入れました"),
                Outcome::Failed(hash, reason) => {
                    println!("高さ {height}: {hash} は実行できませんでした: {reason}")
                }
                Outcome::Skipped(reason) => {
                    println!("高さ {height}: 入れなかったもの: {reason}")
                }
                Outcome::Withdrawn(withdrawal) => println!(
                    "高さ {height}: 引き出し {} を受け付けました（{} XYM を {} へ）",
                    withdrawal.id,
                    xym(withdrawal.amount),
                    withdrawal.recipient
                ),
                Outcome::Refunded(hash, reason) => {
                    println!("高さ {height}: {hash} の引き出しは、送った人に返しました: {reason}")
                }
            }
        }
    }
}

/// XYM の最小単位を、小数点つきで書く
pub fn xym(amount: u64) -> String {
    format!("{}.{:06}", amount / 1_000_000, amount % 1_000_000)
}

/// 状態を共有する入れ物を作る
pub fn shared(rollup: &Rollup) -> Arc<RwLock<Views>> {
    Arc::new(RwLock::new(Views {
        finalized: rollup.clone(),
        latest: rollup.clone(),
    }))
}
