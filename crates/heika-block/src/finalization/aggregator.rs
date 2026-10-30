//! 投票のメッセージを集める。catapult の `chain::RoundMessageAggregator` と `chain::MultiRoundMessageAggregator`。
//!
//! [`RoundAggregator`] は1つのラウンドのメッセージを確かめて覚え、[`RoundContext`] で数える。
//! [`MultiRoundAggregator`] は、最小から最大のラウンドまでの [`RoundAggregator`] を並べて持つ。最大のラウンドは
//! 投票の段取り役が進め、最小のラウンドは、ファイナライズしたら前のエポックを捨てて進める。

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::FinalizationRound;
use super::message::FinalizationMessage;
use super::proof::{MessageError, ProofParameters, VotingSet};
use super::round::{Candidate, RoundContext};

/// 足せたメッセージの段階
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    Prevote,
    Precommit,
}

/// 1つのラウンドのメッセージ。catapult の `RoundMessageAggregator`
#[derive(Debug)]
pub struct RoundAggregator {
    epoch: u32,
    voters: Arc<VotingSet>,
    parameters: ProofParameters,
    /// 投票者を決めた高さ
    voting_set_height: u64,
    /// （投票者、prevote か）→（メッセージ、そのハッシュ）
    messages: BTreeMap<([u8; 32], bool), (FinalizationMessage, [u8; 32])>,
    round: RoundContext,
}

impl RoundAggregator {
    /// エポック `epoch` のラウンド。投票者は `voters`
    pub fn new(epoch: u32, voters: Arc<VotingSet>, parameters: ProofParameters) -> Self {
        let total = voters.total();
        // catapult は u64 のまま掛ける
        let threshold = total.wrapping_mul(parameters.threshold) / parameters.size;
        Self {
            epoch,
            voting_set_height: parameters.voting_set_end_height(epoch.saturating_sub(1).max(1)),
            voters,
            parameters,
            messages: BTreeMap::new(),
            round: RoundContext::new(total, threshold),
        }
    }

    /// 覚えているメッセージの数
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn round(&self) -> &RoundContext {
        &self.round
    }

    /// 覚えているメッセージ。投票者の鍵と段階の順
    pub fn messages(&self) -> impl Iterator<Item = &FinalizationMessage> {
        self.messages.values().map(|(message, _)| message)
    }

    /// 覚えているメッセージの短いハッシュ
    pub fn short_hashes(&self) -> impl Iterator<Item = u32> {
        self.messages
            .values()
            .map(|(_, hash)| u32::from_le_bytes(hash[..4].try_into().expect("4 bytes")))
    }

    /// 短いハッシュが `known` にないメッセージ。合わせて `max_size` バイトまで
    pub fn unknown_messages(
        &self,
        known: &BTreeSet<u32>,
        max_size: usize,
    ) -> Vec<&FinalizationMessage> {
        let mut size = 0;
        let mut out = Vec::new();
        for (message, hash) in self.messages.values() {
            if known.contains(&u32::from_le_bytes(hash[..4].try_into().expect("4 bytes"))) {
                continue;
            }
            size += message.size();
            if size > max_size {
                break;
            }
            out.push(message);
        }
        out
    }

    /// メッセージを確かめて足す。catapult の `RoundMessageAggregator::add` と同じ順で確かめる
    pub fn add(&mut self, message: FinalizationMessage) -> Result<Added, MessageError> {
        let count = message.hashes.len() as u64;
        if count == 0 || count > self.parameters.max_hashes_per_point {
            return Err(MessageError::InvalidHashes);
        }
        let last_height = message.last_height();
        // 投票者を決めた高さ以降のハッシュを1つも含まないものは数えない
        if self.voting_set_height > last_height {
            return Err(MessageError::InvalidHeight);
        }
        if message.is_prevote {
            let min = self
                .parameters
                .voting_set_end_height(message.round.epoch.saturating_sub(1).max(1));
            let max = self.parameters.voting_set_end_height(message.round.epoch);
            if message.height < min || last_height > max {
                return Err(MessageError::InvalidHashes);
            }
        } else if count != 1 {
            return Err(MessageError::InvalidHashes);
        }

        let key = (message.root_key(), message.is_prevote);
        let hash = message.hash();
        if let Some((_, existing)) = self.messages.get(&key) {
            return Err(if *existing == hash {
                MessageError::Redundant
            } else {
                MessageError::Conflicting
            });
        }
        // catapult の `ProcessMessage`。予約と版は読んだときに確かめてある
        let weight = self.voters.voters.get(&key.0).copied().unwrap_or(0);
        if weight == 0 {
            return Err(MessageError::Voter);
        }
        if !message.verify_signature() {
            return Err(MessageError::Signature);
        }
        let added = if message.is_prevote {
            self.round
                .accept_prevote(message.height, &message.hashes, weight);
            Added::Prevote
        } else {
            self.round
                .accept_precommit(message.height, message.hashes[0], weight);
            Added::Precommit
        };
        debug_assert_eq!(message.round.epoch, self.epoch);
        self.messages.insert(key, (message, hash));
        Ok(added)
    }
}

/// ファイナライズできたブロックと、その証明にするメッセージ。catapult の `BestPrecommitDescriptor`
#[derive(Debug)]
pub struct BestPrecommit<'a> {
    pub round: FinalizationRound,
    pub target: Candidate,
    pub messages: Vec<&'a FinalizationMessage>,
}

/// 足せなかったわけのうち、ラウンドごとの集計の前で弾いたもの
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiRoundError {
    /// 集めている範囲（最小から最大のラウンド）の外。catapult の `Failure_Invalid_Point`
    Round,
    /// そのエポックの投票者をまだ知らない
    NoVotingSet,
    Message(MessageError),
}

/// 最小から最大のラウンドまでのメッセージ。catapult の `MultiRoundMessageAggregator`
#[derive(Debug)]
pub struct MultiRoundAggregator {
    parameters: ProofParameters,
    /// 引かれたときに返すメッセージの、合わせた大きさの上限（`messageSynchronizationMaxResponseSize`）
    max_response_size: usize,
    min_round: FinalizationRound,
    max_round: FinalizationRound,
    /// 始めたときに最後にファイナライズしていたブロック。estimate がどのラウンドにもなければこれ
    previous_finalized: Candidate,
    voting_sets: BTreeMap<u32, Arc<VotingSet>>,
    rounds: BTreeMap<FinalizationRound, RoundAggregator>,
}

impl MultiRoundAggregator {
    /// 最後にファイナライズしたのが、ラウンド `round` のブロック `previous_finalized`。最小も最大も `round` から始める
    pub fn new(
        parameters: ProofParameters,
        max_response_size: usize,
        round: FinalizationRound,
        previous_finalized: Candidate,
    ) -> Self {
        Self {
            parameters,
            max_response_size,
            min_round: round,
            max_round: round,
            previous_finalized,
            voting_sets: BTreeMap::new(),
            rounds: BTreeMap::new(),
        }
    }

    pub fn min_round(&self) -> FinalizationRound {
        self.min_round
    }

    pub fn max_round(&self) -> FinalizationRound {
        self.max_round
    }

    /// 持っているラウンドの数
    pub fn len(&self) -> usize {
        self.rounds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rounds.is_empty()
    }

    /// エポック `epoch` の投票者を教える。そのエポックのメッセージは、教わるまで足せない
    pub fn set_voting_set(&mut self, epoch: u32, voters: Arc<VotingSet>) {
        self.voting_sets.insert(epoch, voters);
    }

    /// エポック `epoch` の投票者を知っているか
    pub fn has_voting_set(&self, epoch: u32) -> bool {
        self.voting_sets.contains_key(&epoch)
    }

    /// 集める範囲の最大を `round` にする。
    ///
    /// # Panics
    ///
    /// 最小より前にはできない（catapult も例外にする）
    pub fn set_max_round(&mut self, round: FinalizationRound) {
        assert!(
            round >= self.min_round,
            "集める範囲の最大を、最小より前にはできません"
        );
        self.max_round = round;
    }

    /// メッセージを足す。範囲の中なら、足せなくてもそのラウンドの集計は作る（catapult と同じ）
    pub fn add(&mut self, message: FinalizationMessage) -> Result<Added, MultiRoundError> {
        let round = message.round;
        if round < self.min_round || round > self.max_round {
            return Err(MultiRoundError::Round);
        }
        let aggregator = match self.rounds.entry(round) {
            alloc::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                let voters = self
                    .voting_sets
                    .get(&round.epoch)
                    .ok_or(MultiRoundError::NoVotingSet)?;
                entry.insert(RoundAggregator::new(
                    round.epoch,
                    voters.clone(),
                    self.parameters,
                ))
            }
        };
        aggregator.add(message).map_err(MultiRoundError::Message)
    }

    /// ラウンド `round` の数え方。まだメッセージがなければ `None`
    pub fn round(&self, round: FinalizationRound) -> Option<&RoundContext> {
        self.rounds.get(&round).map(RoundAggregator::round)
    }

    /// `round` かそれより前のラウンドのうち、いちばん新しい estimate。catapult の `findEstimate`
    pub fn find_estimate(&self, round: FinalizationRound) -> Candidate {
        self.rounds
            .range(..=round)
            .rev()
            .find_map(|(_, aggregator)| aggregator.round().estimate())
            .unwrap_or(self.previous_finalized)
    }

    /// best precommit のある、いちばん新しいラウンド。証明にするメッセージは、そのラウンドの全部
    /// （合わせて `max_response_size` まで）
    pub fn best_precommit(&self) -> Option<BestPrecommit<'_>> {
        self.rounds.iter().rev().find_map(|(round, aggregator)| {
            aggregator
                .round()
                .best_precommit()
                .map(|target| BestPrecommit {
                    round: *round,
                    target,
                    messages: aggregator.unknown_messages(&BTreeSet::new(), self.max_response_size),
                })
        })
    }

    /// 持っているメッセージ全部の短いハッシュ
    pub fn short_hashes(&self) -> Vec<u32> {
        self.rounds
            .values()
            .flat_map(RoundAggregator::short_hashes)
            .collect()
    }

    /// ラウンド `min` から `max` までのメッセージのうち、短いハッシュが `known` にないもの。合わせて
    /// `max_response_size` バイトまで
    pub fn unknown_messages(
        &self,
        min: FinalizationRound,
        max: FinalizationRound,
        known: &BTreeSet<u32>,
    ) -> Vec<&FinalizationMessage> {
        let mut size = 0;
        let mut out = Vec::new();
        for (round, aggregator) in &self.rounds {
            if *round < min || *round > max {
                continue;
            }
            for message in aggregator.unknown_messages(known, self.max_response_size) {
                size += message.size();
                if size > self.max_response_size {
                    return out;
                }
                out.push(message);
            }
        }
        out
    }

    /// エポック `epoch` より前のラウンドを捨て、最小をいちばん古く残ったラウンドにする（なければ最大）
    pub fn prune(&mut self, epoch: u32) {
        let keep = self
            .rounds
            .split_off(&FinalizationRound { epoch, point: 0 });
        self.rounds = keep;
        self.min_round = self.rounds.keys().next().copied().unwrap_or(self.max_round);
        self.voting_sets.retain(|known, _| *known >= epoch);
    }
}

#[cfg(test)]
mod tests {
    use heika_core::hash::Hash256;

    use super::super::message::testing::{Voter, block_hash, chain};
    use super::*;

    /// エポックは 10 ブロック。エポック 3 の prevote は高さ 10〜20
    const PARAMETERS: ProofParameters = ProofParameters {
        voting_set_grouping: 10,
        size: 10_000,
        threshold: 6_700,
        max_hashes_per_point: 256,
    };

    fn round(epoch: u32, point: u32) -> FinalizationRound {
        FinalizationRound { epoch, point }
    }

    /// 重み 40、30、30 の3人。閾値は 67
    fn voters() -> [Voter; 3] {
        [Voter::new(1), Voter::new(2), Voter::new(3)]
    }

    fn voting_set(voters: &[Voter]) -> Arc<VotingSet> {
        Arc::new(VotingSet {
            voters: voters
                .iter()
                .zip([40, 30, 30])
                .map(|(voter, weight)| (voter.key(), weight))
                .collect(),
        })
    }

    #[test]
    fn checks_messages_in_the_order_catapult_does() {
        let voters = voters();
        let [a, b, ..] = &voters;
        let mut aggregator = RoundAggregator::new(3, voting_set(&voters), PARAMETERS);
        let at = round(3, 1);
        assert_eq!(
            aggregator.add(a.message(at, true, 10, Vec::new())),
            Err(MessageError::InvalidHashes)
        );
        // 投票者を決めた高さ（10）より前で終わる
        assert_eq!(
            aggregator.add(a.message(at, false, 9, chain(9, 9))),
            Err(MessageError::InvalidHeight)
        );
        // prevote はエポックの中（10〜20）
        assert_eq!(
            aggregator.add(a.message(at, true, 15, chain(15, 21))),
            Err(MessageError::InvalidHashes)
        );
        assert_eq!(
            aggregator.add(a.message(at, false, 15, chain(15, 16))),
            Err(MessageError::InvalidHashes)
        );
        assert_eq!(
            aggregator.add(Voter::new(9).message(at, true, 10, chain(10, 15))),
            Err(MessageError::Voter)
        );
        let mut broken = b.message(at, true, 10, chain(10, 15));
        broken.hashes[5] = block_hash(15, 1);
        assert_eq!(aggregator.add(broken), Err(MessageError::Signature));
        assert!(aggregator.is_empty());

        let prevote = a.message(at, true, 10, chain(10, 15));
        assert_eq!(aggregator.add(prevote.clone()), Ok(Added::Prevote));
        assert_eq!(aggregator.add(prevote), Err(MessageError::Redundant));
        assert_eq!(
            aggregator.add(a.message(at, true, 10, chain(10, 14))),
            Err(MessageError::Conflicting)
        );
        assert_eq!(
            aggregator.add(a.message(at, false, 15, chain(15, 15))),
            Ok(Added::Precommit)
        );
        assert_eq!(aggregator.len(), 2);
        assert_eq!(
            aggregator.round().weights((12, block_hash(12, 0))).prevote,
            40
        );
    }

    #[test]
    fn finalizes_when_enough_weight_votes() {
        let voters = voters();
        let mut aggregator = RoundAggregator::new(3, voting_set(&voters), PARAMETERS);
        let at = round(3, 1);
        for voter in &voters[..2] {
            aggregator
                .add(voter.message(at, true, 10, chain(10, 15)))
                .unwrap();
        }
        assert_eq!(
            aggregator.round().best_prevote(),
            Some((15, block_hash(15, 0)))
        );
        assert_eq!(aggregator.round().best_precommit(), None);
        for voter in &voters[..2] {
            aggregator
                .add(voter.message(at, false, 14, chain(14, 14)))
                .unwrap();
        }
        // 40 + 30 = 70 で閾値の 67 を超える
        assert_eq!(
            aggregator.round().best_precommit(),
            Some((14, block_hash(14, 0)))
        );
    }

    #[test]
    fn hands_out_only_unknown_messages_up_to_the_size_limit() {
        let voters = voters();
        let mut aggregator = RoundAggregator::new(3, voting_set(&voters), PARAMETERS);
        let messages: Vec<_> = voters
            .iter()
            .map(|voter| voter.message(round(3, 1), true, 10, chain(10, 15)))
            .collect();
        for message in &messages {
            aggregator.add(message.clone()).unwrap();
        }
        let all = aggregator.unknown_messages(&BTreeSet::new(), usize::MAX);
        assert_eq!(all.len(), 3);
        let known: BTreeSet<u32> = [messages[0].short_hash()].into();
        let unknown = aggregator.unknown_messages(&known, usize::MAX);
        assert_eq!(unknown.len(), 2);
        assert!(!unknown.contains(&&messages[0]));
        // 1つ分と少しの大きさなら、1つだけ
        let one = aggregator.unknown_messages(&BTreeSet::new(), messages[0].size() + 1);
        assert_eq!(one.len(), 1);
        let short: BTreeSet<u32> = aggregator.short_hashes().collect();
        assert_eq!(
            short,
            messages
                .iter()
                .map(FinalizationMessage::short_hash)
                .collect()
        );
    }

    fn multi() -> MultiRoundAggregator {
        let mut aggregator =
            MultiRoundAggregator::new(PARAMETERS, usize::MAX, round(3, 1), (10, block_hash(10, 0)));
        let voters = voters();
        aggregator.set_voting_set(3, voting_set(&voters));
        aggregator.set_voting_set(4, voting_set(&voters));
        aggregator
    }

    #[test]
    fn accepts_only_rounds_between_min_and_max() {
        let [a, ..] = voters();
        let mut aggregator = multi();
        assert_eq!(
            (aggregator.min_round(), aggregator.max_round()),
            (round(3, 1), round(3, 1))
        );
        let prevote = |at| a.message(at, true, 10, chain(10, 15));
        assert_eq!(
            aggregator.add(prevote(round(3, 0))),
            Err(MultiRoundError::Round)
        );
        assert_eq!(
            aggregator.add(prevote(round(3, 2))),
            Err(MultiRoundError::Round)
        );
        aggregator.set_max_round(round(3, 3));
        assert_eq!(aggregator.add(prevote(round(3, 3))), Ok(Added::Prevote));
        assert_eq!(aggregator.add(prevote(round(3, 1))), Ok(Added::Prevote));
        // 足せなくても、そのラウンドの集計は作る
        assert_eq!(
            aggregator.add(a.message(round(3, 2), true, 10, Vec::new())),
            Err(MultiRoundError::Message(MessageError::InvalidHashes))
        );
        assert_eq!(aggregator.len(), 3);
        assert!(aggregator.round(round(3, 2)).unwrap().is_empty());
        // 投票者を知らないエポック
        aggregator.set_max_round(round(5, 1));
        assert_eq!(
            aggregator.add(a.message(round(5, 1), true, 40, chain(40, 41))),
            Err(MultiRoundError::NoVotingSet)
        );
    }

    #[test]
    #[should_panic(expected = "最小より前")]
    fn refuses_a_max_round_below_the_min() {
        multi().set_max_round(round(3, 0));
    }

    #[test]
    fn finds_the_estimate_and_best_precommit_in_the_newest_round_that_has_one() {
        let voters = voters();
        let mut aggregator = multi();
        aggregator.set_max_round(round(3, 4));
        assert_eq!(
            aggregator.find_estimate(round(3, 4)),
            (10, block_hash(10, 0))
        );
        assert!(aggregator.best_precommit().is_none());

        // ラウンド 1 で高さ 14 が確定、ラウンド 2 は prevote だけ
        for voter in &voters {
            aggregator
                .add(voter.message(round(3, 1), true, 10, chain(10, 15)))
                .unwrap();
            aggregator
                .add(voter.message(round(3, 1), false, 14, chain(14, 14)))
                .unwrap();
            aggregator
                .add(voter.message(round(3, 2), true, 14, chain(14, 18)))
                .unwrap();
        }
        let best = aggregator.best_precommit().unwrap();
        assert_eq!(
            (best.round, best.target),
            (round(3, 1), (14, block_hash(14, 0)))
        );
        assert_eq!(best.messages.len(), 6);
        // ラウンド 2 は estimate が best prevote の 18。ラウンド 4 から見ても、いちばん新しいのはラウンド 2
        assert_eq!(
            aggregator.find_estimate(round(3, 4)),
            (18, block_hash(18, 0))
        );
        assert_eq!(
            aggregator.find_estimate(round(3, 1)),
            (14, block_hash(14, 0))
        );
        assert_eq!(
            aggregator.find_estimate(round(3, 0)),
            (10, block_hash(10, 0))
        );
    }

    #[test]
    fn hands_out_unknown_messages_within_the_requested_rounds() {
        let voters = voters();
        let mut aggregator = multi();
        aggregator.set_max_round(round(4, 2));
        let mut messages = Vec::new();
        for (at, height) in [(round(3, 1), 10), (round(3, 2), 12), (round(4, 1), 20)] {
            for voter in &voters {
                let message = voter.message(at, true, height, chain(height, height + 2));
                aggregator.add(message.clone()).unwrap();
                messages.push(message);
            }
        }
        assert_eq!(aggregator.short_hashes().len(), 9);
        let all = BTreeSet::new();
        assert_eq!(
            aggregator
                .unknown_messages(round(3, 0), round(9, 0), &all)
                .len(),
            9
        );
        assert_eq!(
            aggregator
                .unknown_messages(round(3, 2), round(4, 1), &all)
                .len(),
            6
        );
        let known: BTreeSet<u32> = messages[..4]
            .iter()
            .map(FinalizationMessage::short_hash)
            .collect();
        assert_eq!(
            aggregator
                .unknown_messages(round(3, 0), round(9, 0), &known)
                .len(),
            5
        );

        let mut limited = MultiRoundAggregator::new(
            PARAMETERS,
            messages[0].size() * 2,
            round(3, 1),
            (10, Hash256([0; 32])),
        );
        limited.set_voting_set(3, voting_set(&voters));
        limited.set_max_round(round(3, 2));
        for message in &messages[..6] {
            limited.add(message.clone()).unwrap();
        }
        assert_eq!(
            limited
                .unknown_messages(round(3, 0), round(9, 0), &all)
                .len(),
            2
        );
    }

    #[test]
    fn prunes_epochs_before_the_given_one() {
        let voters = voters();
        let mut aggregator = multi();
        aggregator.prune(3);
        assert_eq!(aggregator.min_round(), round(3, 1));

        aggregator.set_max_round(round(4, 2));
        for (at, height) in [(round(3, 1), 10), (round(3, 2), 12), (round(4, 1), 20)] {
            aggregator
                .add(voters[0].message(at, true, height, chain(height, height + 2)))
                .unwrap();
        }
        aggregator.prune(3);
        assert_eq!((aggregator.len(), aggregator.min_round()), (3, round(3, 1)));
        aggregator.prune(4);
        assert_eq!((aggregator.len(), aggregator.min_round()), (1, round(4, 1)));
        assert!(!aggregator.has_voting_set(3));
        assert!(aggregator.has_voting_set(4));
        // 全部捨てると、最小は最大になる
        aggregator.prune(5);
        assert_eq!((aggregator.len(), aggregator.min_round()), (0, round(4, 2)));
    }
}
