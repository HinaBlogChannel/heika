//! Symbol を追いかけて、ロールアップの状態を 2 つ持つ。
//!
//! - `finalized`：ファイナライズされた Symbol のブロックまで。巻き戻らない
//! - `latest`：Symbol の先頭のブロックまで。`finalized` の写しに、ファイナライズされていないブロックを毎回実行し直して作る。
//!   Symbol で巻き戻りが起きても、次に作り直すときに直る

use std::sync::{Arc, RwLock};

use heika_core::address::Address;

use crate::rollup::{Outcome, Rollup};
use crate::symbol::{Chain, Posted};

#[derive(Clone)]
pub struct Views {
    pub finalized: Rollup,
    pub latest: Rollup,
}

/// Symbol を 1 回見て、状態を進める。`finalized` の高さが進んだら、その高さとルートを出す
pub fn step(
    chain: &Chain,
    inbox: &Address,
    finalized: &mut Rollup,
    views: &RwLock<Views>,
) -> Result<(), String> {
    let (tip, final_height) = chain.heights()?;
    if final_height > finalized.height {
        let from = finalized.height + 1;
        apply(finalized, chain.posted(inbox, from, final_height)?, true);
        finalized.advance(final_height, chain.block_time(final_height)?);
        println!(
            "高さ {} までファイナライズ: ルート {}",
            finalized.height,
            finalized.state_root()
        );
    }
    let mut latest = finalized.clone();
    if tip > latest.height {
        let from = latest.height + 1;
        apply(&mut latest, chain.posted(inbox, from, tip)?, false);
        latest.advance(tip, chain.block_time(tip)?);
    }
    *views.write().expect("not poisoned") = Views {
        finalized: finalized.clone(),
        latest,
    };
    Ok(())
}

/// 載った順のものを、高さごとにまとめて実行する。`report` なら、入れなかったものの理由を出す
fn apply(rollup: &mut Rollup, posted: Vec<Posted>, report: bool) {
    let mut posted = posted.into_iter().peekable();
    while let Some(first) = posted.next() {
        let mut transactions = vec![first.bytes];
        while let Some(next) = posted.next_if(|next| next.height == first.height) {
            transactions.push(next.bytes);
        }
        for outcome in rollup.apply(first.height, first.timestamp, &transactions) {
            if !report {
                continue;
            }
            match outcome {
                Outcome::Executed(hash) => println!("高さ {}: {hash} を入れました", first.height),
                Outcome::Failed(hash, reason) => {
                    println!(
                        "高さ {}: {hash} は実行できませんでした: {reason}",
                        first.height
                    )
                }
                Outcome::Skipped(reason) => {
                    println!("高さ {}: 入れなかったもの: {reason}", first.height)
                }
            }
        }
    }
}

/// 状態を共有する入れ物を作る
pub fn shared(rollup: &Rollup) -> Arc<RwLock<Views>> {
    Arc::new(RwLock::new(Views {
        finalized: rollup.clone(),
        latest: rollup.clone(),
    }))
}
