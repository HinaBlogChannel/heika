//! エポックの切り替えと、集まったメッセージからの確定。catapult の `FinalizationOrchestratorService` の
//! `calculateEpochStatus` と、`CreateFinalizer`。

use heika_block::finalization::FinalizedBlockHeader;
use heika_block::finalization::aggregator::MultiRoundAggregator;
use heika_block::finalization::proof::build_proof;
use heika_core::hash::Hash256;

/// 段取り役のエポックをどうするか
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochStatus {
    /// 今のエポックのまま進める
    Continue,
    /// エポックの最後のブロックが確定したが、手元のチェーンがまだそこに届いていないか、違うブロックを持っている。
    /// 追いつくまで投票しない
    Wait,
    /// このエポックに移る
    Advance(u32),
}

/// 段取り役がエポック `epoch` にいて、最後の確定が `finalized` のときにどうするか。`local_hash_at` は手元の
/// チェーンのその高さのブロックのハッシュ（まだなければ `None`）
pub fn epoch_status(
    epoch: u32,
    finalized: &FinalizedBlockHeader,
    voting_set_grouping: u64,
    local_hash_at: impl FnOnce(u64) -> Option<Hash256>,
) -> EpochStatus {
    let ahead = finalized.round.epoch > epoch;
    let epoch_end = match epoch {
        0 | 1 => 1,
        epoch => (u64::from(epoch) - 1) * voting_set_grouping,
    };
    if !ahead && finalized.height != epoch_end {
        return EpochStatus::Continue;
    }
    if local_hash_at(finalized.height) != Some(finalized.hash) {
        return EpochStatus::Wait;
    }
    EpochStatus::Advance(finalized.round.epoch + 1)
}

/// 集まったメッセージで確定したブロックと、その証明
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub header: FinalizedBlockHeader,
    pub proof: Vec<u8>,
}

/// best precommit があり、その高さが最後の確定（`finalized_height`）と違えば、確定して証明を組む。確定したら、
/// そのひとつ前のエポックまでのメッセージを捨てる（catapult の `CreateFinalizer`）
pub fn finalize(aggregator: &mut MultiRoundAggregator, finalized_height: u64) -> Option<Finalized> {
    let best = aggregator.best_precommit()?;
    if best.target.0 == finalized_height {
        return None;
    }
    let header = FinalizedBlockHeader {
        round: best.round,
        height: best.target.0,
        hash: best.target.1,
    };
    let proof = build_proof(&header, best.messages);
    aggregator.prune(header.round.epoch.saturating_sub(1));
    Some(Finalized { header, proof })
}

#[cfg(test)]
mod tests {
    use heika_block::finalization::FinalizationRound;
    use heika_block::finalization::proof::verify_proof;

    use super::*;
    use crate::stage::tests::{PARAMETERS, ROUND, aggregator, block_hash, chain, vote, voting_set};

    fn finalized(epoch: u32, height: u64) -> FinalizedBlockHeader {
        FinalizedBlockHeader {
            round: FinalizationRound { epoch, point: 5 },
            height,
            hash: block_hash(height, 0),
        }
    }

    #[test]
    fn moves_to_the_next_epoch_once_its_last_block_is_finalized_locally() {
        let local = |height| Some(block_hash(height, 0));
        // エポック 3 は高さ 20 で終わる（グループは 10）
        assert_eq!(
            epoch_status(3, &finalized(3, 15), 10, local),
            EpochStatus::Continue
        );
        assert_eq!(
            epoch_status(3, &finalized(3, 20), 10, local),
            EpochStatus::Advance(4)
        );
        // 手元が届いていない、違うブロックを持っている
        assert_eq!(
            epoch_status(3, &finalized(3, 20), 10, |_| None),
            EpochStatus::Wait
        );
        assert_eq!(
            epoch_status(3, &finalized(3, 20), 10, |height| Some(block_hash(
                height, 1
            ))),
            EpochStatus::Wait
        );
        // 確定がもっと先のエポックにある（追いついたあと）
        assert_eq!(
            epoch_status(3, &finalized(6, 52), 10, local),
            EpochStatus::Advance(7)
        );
    }

    #[test]
    fn finalizes_the_best_precommit_once() {
        let mut aggregator = aggregator();
        assert_eq!(finalize(&mut aggregator, 10), None);
        for seed in 1..=3 {
            aggregator
                .add(vote(seed, ROUND, true, 10, &chain(10, 14)))
                .unwrap();
            aggregator
                .add(vote(seed, ROUND, false, 14, &chain(14, 14)))
                .unwrap();
        }
        let done = finalize(&mut aggregator, 10).unwrap();
        assert_eq!(done.header.round, ROUND);
        assert_eq!(done.header.height, 14);
        assert_eq!(
            verify_proof(&done.proof, 3, &voting_set(), &PARAMETERS),
            Ok(done.header)
        );
        // 同じ高さはもう確定しない
        assert_eq!(finalize(&mut aggregator, 14), None);
        // 前のエポック（2）までを捨てるので、エポック 3 は残る
        assert_eq!(aggregator.len(), 1);
    }
}
