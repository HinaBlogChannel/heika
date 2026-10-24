//! 連署を待つアグリゲートボンデッドを、駆動役で扱う。置き場（[`PartialPool`](heika_mempool::partial::PartialPool)）は状態を持たないので、受け付けたら
//! 中核（[`Chain::check_partial`]）に今の状態で聞き、結果で分ける。
//!
//! - ハッシュロックが確定して使えるようになっていない: 置き場から外す（catapult と同じく、受け付けない）
//! - 外側の署名者が連署できない人: 置き場から外す
//! - 連署できない人の連署がある: その連署だけを外して見直す（マルチシグが変わって古くなった連署など）
//! - 連署が足りない: 待つ。初めて受け付けたか、連署が増えたら、ほかのピアにも流す
//! - 揃った: 連署を付けて未承認の置き場に移し、ほかのピアに未承認のトランザクションとして流す
//!
//! 入ってくる道は、ピアからの押し付け、ピアから取ってきたもの、REST の3つで、どれも [`Incoming`] にして渡す。

use heika_chain::chain::Chain;
use heika_core::hash::Hash256;
use heika_mempool::SharedMempool;
use heika_mempool::partial::SharedPartialPool;
use heika_peer_protocol::PulledPartial;
use heika_state_transition::executor::PartialCheck;
use heika_transaction::{Body, Cosignature, DetachedCosignature, Transaction};

use crate::store::CachedStore;

/// 連署を外して見直す回数の上限。連署はアグリゲート1つに 15 個まで（`maxCosignaturesPerAggregate`）
const MAX_PASSES: usize = 16;

/// 入ってきた、連署を待つもの
#[derive(Debug)]
pub enum Incoming {
    /// アグリゲートボンデッド（連署が付いていてもよい）
    Transactions(Vec<Vec<u8>>),
    /// 切り離した連署
    Cosignatures(Vec<DetachedCosignature>),
}

impl Incoming {
    /// ピアから取ってきたものにする。知らなかったものは連署を付けたトランザクションに、知っていたものは
    /// 切り離した連署にする
    pub fn from_pulled(pulled: Vec<PulledPartial>) -> Vec<Self> {
        let mut transactions = Vec::new();
        let mut cosignatures = Vec::new();
        for info in pulled {
            let parsed: Vec<Cosignature> = info
                .cosignatures
                .iter()
                .filter_map(|bytes| Cosignature::from_bytes(bytes).ok())
                .collect();
            match info.transaction {
                Ok(bytes) => {
                    if let Some(stitched) = stitch(&bytes, &parsed) {
                        transactions.push(stitched);
                    }
                }
                Err(parent_hash) => {
                    cosignatures.extend(parsed.into_iter().map(|cosignature| DetachedCosignature {
                        cosignature,
                        parent_hash,
                    }))
                }
            }
        }
        vec![
            Self::Transactions(transactions),
            Self::Cosignatures(cosignatures),
        ]
    }
}

/// 連署を除いたトランザクション `bytes` に、連署を付ける
fn stitch(bytes: &[u8], cosignatures: &[Cosignature]) -> Option<Vec<u8>> {
    let mut transaction = Transaction::from_bytes(bytes).ok()?;
    let Body::AggregateBonded(aggregate) = &mut transaction.body else {
        return None;
    };
    for cosignature in cosignatures {
        aggregate.add_cosignature(*cosignature);
    }
    Some(transaction.to_bytes())
}

/// 扱った結果。駆動役が、ほかのピアに流す
#[derive(Default)]
pub struct Handled {
    /// 連署を待つものとして流すもの（`Push_Partial_Transactions` の本体）
    pub partial: Vec<u8>,
    /// 流す連署（`Push_Detached_Cosignatures` の本体）
    pub cosignatures: Vec<u8>,
    /// 揃って未承認の置き場に移したもの（`Push_Transactions` の本体）
    pub completed: Vec<u8>,
}

/// 入ってきたものを、今（Nemesis からのミリ秒 `now`）、次のブロックの高さ `height` のつもりで扱う
pub fn handle(
    chain: &mut Chain<'_, CachedStore>,
    pool: &SharedPartialPool,
    mempool: &SharedMempool,
    incoming: Incoming,
    now: u64,
    height: u64,
) -> Handled {
    let mut handled = Handled::default();
    match incoming {
        Incoming::Transactions(transactions) => {
            for bytes in transactions {
                let added = match pool.lock().add(&bytes, now, height) {
                    Ok(added) => added,
                    Err(error) => {
                        eprintln!("連署を待つトランザクションを受け付けませんでした: {error}");
                        continue;
                    }
                };
                if added.new {
                    println!("連署を待つトランザクション {} を受け付けました", added.hash);
                }
                let changed = added.new || !added.cosignatures.is_empty();
                settle(
                    chain,
                    pool,
                    mempool,
                    &added.hash,
                    changed,
                    now,
                    height,
                    &mut handled,
                );
            }
        }
        Incoming::Cosignatures(cosignatures) => {
            for detached in cosignatures {
                if pool.lock().add_cosignature(&detached).is_err() {
                    continue;
                }
                handled.cosignatures.extend_from_slice(&detached.to_bytes());
                settle(
                    chain,
                    pool,
                    mempool,
                    &detached.parent_hash,
                    false,
                    now,
                    height,
                    &mut handled,
                );
            }
        }
    }
    handled
}

/// 置き場の `hash` を、今の状態で確かめて分ける。`changed` なら、待つときにほかのピアに流す
#[allow(clippy::too_many_arguments)]
fn settle(
    chain: &mut Chain<'_, CachedStore>,
    pool: &SharedPartialPool,
    mempool: &SharedMempool,
    hash: &Hash256,
    changed: bool,
    now: u64,
    height: u64,
    handled: &mut Handled,
) {
    // 連署を外したら見直すので、連署の数だけ回れば足りる
    for _ in 0..MAX_PASSES {
        let Some(stitched) = pool.lock().stitched(hash) else {
            return;
        };
        let Ok(transaction) = Transaction::from_bytes(&stitched) else {
            pool.lock().remove(hash);
            return;
        };
        let check = match chain.check_partial(&transaction) {
            Ok(check) => check,
            Err(error) => {
                eprintln!("連署を待つトランザクション {hash} を確かめられません: {error}");
                return;
            }
        };
        match check {
            None => {
                pool.lock().remove(hash);
                eprintln!(
                    "連署を待つトランザクション {hash} を外しました: ハッシュロックが確定していないか、もう使えません"
                );
                return;
            }
            Some(PartialCheck::Ineligible(keys)) => {
                if keys.contains(&transaction.signer_public_key) {
                    pool.lock().remove(hash);
                    eprintln!(
                        "連署を待つトランザクション {hash} を外しました: 外側の署名者が連署できる人ではありません"
                    );
                    return;
                }
                let mut pool = pool.lock();
                for key in &keys {
                    pool.remove_cosignature(hash, key);
                }
            }
            Some(PartialCheck::Missing) => {
                if changed {
                    handled.partial.extend_from_slice(&stitched);
                }
                return;
            }
            Some(PartialCheck::Complete) => {
                pool.lock().remove(hash);
                match mempool.lock().add_completed(stitched.clone(), now, height) {
                    Ok(_) => {
                        println!(
                            "連署を待つトランザクション {hash} の連署が揃ったので、未承認のトランザクションにしました"
                        );
                        handled.completed.extend_from_slice(&stitched);
                    }
                    Err(error) => eprintln!(
                        "連署が揃ったトランザクション {hash} を、未承認の置き場が受け付けませんでした: {error}"
                    ),
                }
                return;
            }
        }
    }
}
