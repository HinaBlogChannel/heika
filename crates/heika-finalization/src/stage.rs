//! いつ prevote と precommit を出し、いつ次のラウンドに進むか。catapult の `FinalizationStageAdvancer`。
//!
//! - prevote: ラウンドを始めてから1ステップ経つか、ラウンドの結果がもう変わらない（completable）とき
//! - precommit: best prevote があり、それが前のラウンドまでの estimate の子孫で、ラウンドを始めてから2ステップ経つか
//!   completable のとき。precommit するのは best prevote
//! - 次のラウンド: completable のとき

use heika_block::finalization::FinalizationRound;
use heika_block::finalization::aggregator::MultiRoundAggregator;
use heika_block::finalization::round::{Candidate, RoundContext};

/// 1つのラウンドの進め方
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StageAdvancer {
    round: FinalizationRound,
    /// ラウンドを始めた時刻
    start: u64,
    step_duration: u64,
}

impl StageAdvancer {
    /// 時刻 `start` に始めたラウンド `round`
    pub fn new(round: FinalizationRound, start: u64, step_duration: u64) -> Self {
        Self {
            round,
            start,
            step_duration,
        }
    }

    pub fn round(&self) -> FinalizationRound {
        self.round
    }

    /// prevote を出してよいか
    pub fn can_send_prevote(&self, time: u64, aggregator: &MultiRoundAggregator) -> bool {
        self.is_elapsed(time, 1)
            || self
                .current(aggregator)
                .is_some_and(RoundContext::is_completable)
    }

    /// precommit を出してよければ、その先（best prevote）
    pub fn can_send_precommit(
        &self,
        time: u64,
        aggregator: &MultiRoundAggregator,
    ) -> Option<Candidate> {
        let round = self.current(aggregator)?;
        let best_prevote = round.best_prevote()?;
        // catapult はポイントを u32 のまま引く
        let previous = FinalizationRound {
            epoch: self.round.epoch,
            point: self.round.point.wrapping_sub(1),
        };
        let estimate = aggregator.find_estimate(previous);
        if !round.is_descendant(estimate, best_prevote) {
            return None;
        }
        (self.is_elapsed(time, 2) || round.is_completable()).then_some(best_prevote)
    }

    /// 次のラウンドに進んでよいか
    pub fn can_start_next_round(&self, aggregator: &MultiRoundAggregator) -> bool {
        self.current(aggregator)
            .is_some_and(RoundContext::is_completable)
    }

    fn current<'a>(&self, aggregator: &'a MultiRoundAggregator) -> Option<&'a RoundContext> {
        aggregator.round(self.round)
    }

    fn is_elapsed(&self, time: u64, steps: u64) -> bool {
        time >= self.start + steps * self.step_duration
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use heika_block::finalization::message::FinalizationMessage;
    use heika_block::finalization::proof::{ProofParameters, VotingSet};
    use heika_core::hash::Hash256;
    use heika_core::key::{PrivateKey, PublicKey};

    use super::*;

    pub const PARAMETERS: ProofParameters = ProofParameters {
        voting_set_grouping: 10,
        size: 10_000,
        threshold: 6_700,
        max_hashes_per_point: 256,
    };
    pub const STEP: u64 = 1000;
    pub const ROUND: FinalizationRound = FinalizationRound { epoch: 3, point: 2 };

    /// 高さ `height` のブロックのハッシュ。`fork` で別の枝にする
    pub fn block_hash(height: u64, fork: u8) -> Hash256 {
        let mut hash = [fork; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Hash256(hash)
    }

    /// 投票者 `seed`。根の鍵と下の鍵
    pub fn keys(seed: u8) -> (PrivateKey, PrivateKey) {
        (
            PrivateKey::from_bytes(&[seed; 32]),
            PrivateKey::from_bytes(&[seed ^ 0x80; 32]),
        )
    }

    /// 投票者 `seed` が署名したメッセージ。catapult のバイト列を組んでから読む
    pub fn vote(
        seed: u8,
        round: FinalizationRound,
        is_prevote: bool,
        height: u64,
        hashes: &[Hash256],
    ) -> FinalizationMessage {
        let (root, bottom) = keys(seed);
        let bottom_public = PublicKey::from_private_key(&bottom).0;
        let mut signed = Vec::new();
        signed.extend_from_slice(&1u32.to_le_bytes());
        signed.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        signed.extend_from_slice(&round.epoch.to_le_bytes());
        signed.extend_from_slice(&((round.point << 1) | u32::from(!is_prevote)).to_le_bytes());
        signed.extend_from_slice(&height.to_le_bytes());
        for hash in hashes {
            signed.extend_from_slice(&hash.0);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((200 + signed.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&PublicKey::from_private_key(&root).0);
        let epoch = u64::from(round.epoch).to_le_bytes();
        bytes.extend_from_slice(&root.sign(&[&bottom_public, &epoch]).0);
        bytes.extend_from_slice(&bottom_public);
        bytes.extend_from_slice(&bottom.sign(&[&signed]).0);
        bytes.extend_from_slice(&signed);
        FinalizationMessage::from_bytes(&bytes).unwrap()
    }

    /// 重み 40、30、30 の投票者 1、2、3。閾値は 67
    pub fn voting_set() -> Arc<VotingSet> {
        Arc::new(VotingSet {
            voters: [1, 2, 3]
                .into_iter()
                .zip([40, 30, 30])
                .map(|(seed, weight)| (PublicKey::from_private_key(&keys(seed).0).0, weight))
                .collect(),
        })
    }

    /// 高さ 10 が確定済みで、ラウンド `ROUND` まで集める
    pub fn aggregator() -> MultiRoundAggregator {
        let mut aggregator = MultiRoundAggregator::new(
            PARAMETERS,
            usize::MAX,
            FinalizationRound { epoch: 3, point: 1 },
            (10, block_hash(10, 0)),
        );
        aggregator.set_voting_set(3, voting_set());
        aggregator.set_max_round(ROUND);
        aggregator
    }

    pub fn chain(from: u64, through: u64) -> Vec<Hash256> {
        (from..=through).map(|at| block_hash(at, 0)).collect()
    }

    fn advancer() -> StageAdvancer {
        StageAdvancer::new(ROUND, 5000, STEP)
    }

    #[test]
    fn waits_at_the_start_of_a_round() {
        let aggregator = aggregator();
        let advancer = advancer();
        assert!(!advancer.can_send_prevote(5000, &aggregator));
        assert_eq!(advancer.can_send_precommit(5000, &aggregator), None);
        assert!(!advancer.can_start_next_round(&aggregator));
    }

    #[test]
    fn sends_a_prevote_after_one_step_or_when_completable() {
        let mut aggregator = aggregator();
        let advancer = advancer();
        assert!(!advancer.can_send_prevote(5999, &aggregator));
        assert!(advancer.can_send_prevote(6000, &aggregator));

        // 全員が prevote と precommit を出せば completable
        for seed in 1..=3 {
            aggregator
                .add(vote(seed, ROUND, true, 10, &chain(10, 14)))
                .unwrap();
        }
        assert!(!advancer.can_send_prevote(5000, &aggregator));
        for seed in 1..=3 {
            aggregator
                .add(vote(seed, ROUND, false, 14, &chain(14, 14)))
                .unwrap();
        }
        assert!(advancer.can_send_prevote(5000, &aggregator));
        assert!(advancer.can_start_next_round(&aggregator));
    }

    #[test]
    fn sends_a_precommit_only_for_a_descendant_of_the_previous_estimate() {
        let mut aggregator = aggregator();
        let advancer = advancer();
        // ラウンドがない、best prevote がない
        assert_eq!(advancer.can_send_precommit(7000, &aggregator), None);
        aggregator
            .add(vote(1, ROUND, true, 10, &chain(10, 14)))
            .unwrap();
        assert_eq!(advancer.can_send_precommit(7000, &aggregator), None);

        // best prevote は高さ 14。前のラウンドまでの estimate は確定済みの 10 で、その子孫
        for seed in 2..=3 {
            aggregator
                .add(vote(seed, ROUND, true, 10, &chain(10, 14)))
                .unwrap();
        }
        assert_eq!(advancer.can_send_precommit(6999, &aggregator), None);
        assert_eq!(
            advancer.can_send_precommit(7000, &aggregator),
            Some((14, block_hash(14, 0)))
        );
        assert!(!advancer.can_start_next_round(&aggregator));

        // 別の枝の上なら出さない
        let mut forked = MultiRoundAggregator::new(
            PARAMETERS,
            usize::MAX,
            FinalizationRound { epoch: 3, point: 1 },
            (10, block_hash(10, 1)),
        );
        forked.set_voting_set(3, voting_set());
        forked.set_max_round(ROUND);
        for seed in 1..=3 {
            forked
                .add(vote(seed, ROUND, true, 10, &chain(10, 14)))
                .unwrap();
        }
        assert_eq!(advancer.can_send_precommit(9000, &forked), None);
    }

    #[test]
    fn sends_a_precommit_before_two_steps_when_completable() {
        let mut aggregator = aggregator();
        let advancer = advancer();
        for seed in 1..=3 {
            aggregator
                .add(vote(seed, ROUND, true, 10, &chain(10, 14)))
                .unwrap();
            aggregator
                .add(vote(seed, ROUND, false, 14, &chain(14, 14)))
                .unwrap();
        }
        assert_eq!(
            advancer.can_send_precommit(5000, &aggregator),
            Some((14, block_hash(14, 0)))
        );
    }
}
