//! prevote と precommit を出す順と、出したかどうか。catapult の `FinalizationOrchestrator`。
//!
//! [`Orchestrator::poll`] を時刻ごとに呼ぶ。出せるようになった段階のメッセージを [`MessageFactory`] に作らせ、
//! 出したことにする。作れなかった（鍵がない、このエポックの投票者でない）ときも、出したことにして進む。
//! precommit を出したあと、ラウンドの結果がもう変わらなくなったら、次のポイントに進む。
//!
//! 作ったメッセージは返すだけで、集計器には足さない。呼び出し側が足してピアに配る（catapult も、作ったメッセージは
//! ピアから届いたものと同じ口に入れる）。

use heika_block::finalization::FinalizationRound;
use heika_block::finalization::aggregator::MultiRoundAggregator;
use heika_block::finalization::message::FinalizationMessage;
use heika_block::finalization::round::Candidate;

use crate::stage::StageAdvancer;

/// どのラウンドまで進み、そのラウンドで何を出したか。catapult の `VotingStatus`（voting_status.dat）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VotingStatus {
    pub round: FinalizationRound,
    pub sent_prevote: bool,
    pub sent_precommit: bool,
}

impl VotingStatus {
    /// ラウンド `round` を、まだ何も出していないところから
    pub fn at(round: FinalizationRound) -> Self {
        Self {
            round,
            sent_prevote: false,
            sent_precommit: false,
        }
    }

    /// catapult の voting_status.dat の形。エポック u32、ポイント u32、prevote を出したか u8、precommit を出したか u8
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut out = [0; 10];
        out[..4].copy_from_slice(&self.round.epoch.to_le_bytes());
        out[4..8].copy_from_slice(&self.round.point.to_le_bytes());
        out[8] = u8::from(self.sent_prevote);
        out[9] = u8::from(self.sent_precommit);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 10] = bytes.try_into().ok()?;
        Some(Self {
            round: FinalizationRound {
                epoch: u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")),
                point: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            },
            sent_prevote: bytes[8] != 0,
            sent_precommit: bytes[9] != 0,
        })
    }
}

/// 投票のメッセージを作る。鍵がない、このラウンドの鍵がもうないときは `None`
pub trait MessageFactory {
    fn prevote(&mut self, round: FinalizationRound) -> Option<FinalizationMessage>;
    fn precommit(
        &mut self,
        round: FinalizationRound,
        target: Candidate,
    ) -> Option<FinalizationMessage>;
}

/// 鍵を持たない。何も作らず、段取りだけを進める
#[derive(Clone, Copy, Debug, Default)]
pub struct NoVotes;

impl MessageFactory for NoVotes {
    fn prevote(&mut self, _: FinalizationRound) -> Option<FinalizationMessage> {
        None
    }

    fn precommit(&mut self, _: FinalizationRound, _: Candidate) -> Option<FinalizationMessage> {
        None
    }
}

/// 投票の段取り役
#[derive(Debug)]
pub struct Orchestrator {
    status: VotingStatus,
    step_duration: u64,
    advancer: Option<StageAdvancer>,
}

impl Orchestrator {
    /// `status` から始める。最初の [`Orchestrator::poll`] では、出したかどうかを `status` のまま使う
    pub fn new(status: VotingStatus, step_duration: u64) -> Self {
        Self {
            status,
            step_duration,
            advancer: None,
        }
    }

    pub fn status(&self) -> VotingStatus {
        self.status
    }

    /// エポック `epoch` のポイント 1 に移る。同じエポックなら何もしない。
    ///
    /// # Panics
    ///
    /// エポックは戻せない（catapult も例外にする）
    pub fn set_epoch(&mut self, epoch: u32) {
        assert!(
            epoch >= self.status.round.epoch,
            "エポックは戻せません（{} → {epoch}）",
            self.status.round.epoch
        );
        if epoch == self.status.round.epoch {
            return;
        }
        self.status = VotingStatus::at(FinalizationRound { epoch, point: 1 });
        self.advancer = None;
    }

    /// 時刻 `time` に進められるだけ進め、作ったメッセージを返す。`eligible` は、メッセージの鍵がそのエポックの
    /// 投票者か
    pub fn poll(
        &mut self,
        time: u64,
        aggregator: &MultiRoundAggregator,
        factory: &mut dyn MessageFactory,
        eligible: &dyn Fn(&FinalizationMessage) -> bool,
    ) -> Vec<FinalizationMessage> {
        let mut sent = Vec::new();
        let advancer = *self
            .advancer
            .get_or_insert_with(|| StageAdvancer::new(self.status.round, time, self.step_duration));
        if !self.status.sent_prevote && advancer.can_send_prevote(time, aggregator) {
            sent.extend(factory.prevote(self.status.round).filter(|m| eligible(m)));
            self.status.sent_prevote = true;
        }
        if !self.status.sent_precommit
            && let Some(target) = advancer.can_send_precommit(time, aggregator)
        {
            sent.extend(
                factory
                    .precommit(self.status.round, target)
                    .filter(|m| eligible(m)),
            );
            self.status.sent_precommit = true;
        }
        if self.status.sent_precommit && advancer.can_start_next_round(aggregator) {
            let next = FinalizationRound {
                epoch: self.status.round.epoch,
                point: self.status.round.point + 1,
            };
            self.status = VotingStatus::at(next);
            self.advancer = Some(StageAdvancer::new(next, time, self.step_duration));
        }
        sent
    }
}

#[cfg(test)]
mod tests {
    use heika_block::finalization::round::Candidate;

    use super::*;
    use crate::stage::tests::{ROUND, STEP, aggregator, block_hash, chain, vote};

    /// 投票者 1 として作る。作ったものを数える
    #[derive(Default)]
    struct Voter {
        prevotes: Vec<FinalizationRound>,
        precommits: Vec<(FinalizationRound, Candidate)>,
    }

    impl MessageFactory for Voter {
        fn prevote(&mut self, round: FinalizationRound) -> Option<FinalizationMessage> {
            self.prevotes.push(round);
            Some(vote(1, round, true, 10, &chain(10, 14)))
        }

        fn precommit(
            &mut self,
            round: FinalizationRound,
            target: Candidate,
        ) -> Option<FinalizationMessage> {
            self.precommits.push((round, target));
            Some(vote(1, round, false, target.0, &[target.1]))
        }
    }

    fn everyone(round: FinalizationRound) -> Vec<FinalizationMessage> {
        (1..=3)
            .flat_map(|seed| {
                [
                    vote(seed, round, true, 10, &chain(10, 14)),
                    vote(seed, round, false, 14, &chain(14, 14)),
                ]
            })
            .collect()
    }

    #[test]
    fn sends_each_stage_once_and_moves_to_the_next_point() {
        let mut aggregator = aggregator();
        let mut orchestrator = Orchestrator::new(VotingStatus::at(ROUND), STEP);
        let mut voter = Voter::default();
        let anyone = |_: &FinalizationMessage| true;

        // 始めた時刻ではまだ出さない
        assert!(
            orchestrator
                .poll(0, &aggregator, &mut voter, &anyone)
                .is_empty()
        );
        // 1ステップで prevote。もう出さない
        let sent = orchestrator.poll(STEP, &aggregator, &mut voter, &anyone);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].is_prevote);
        assert!(
            orchestrator
                .poll(STEP, &aggregator, &mut voter, &anyone)
                .is_empty()
        );
        assert_eq!(voter.prevotes, [ROUND]);

        // 全員の票が揃うと precommit を出し、次のポイントへ
        for message in everyone(ROUND) {
            let _ = aggregator.add(message);
        }
        let sent = orchestrator.poll(STEP + 1, &aggregator, &mut voter, &anyone);
        assert_eq!(sent.len(), 1);
        assert_eq!(voter.precommits, [(ROUND, (14, block_hash(14, 0)))]);
        let next = FinalizationRound { epoch: 3, point: 3 };
        assert_eq!(orchestrator.status(), VotingStatus::at(next));
    }

    #[test]
    fn moves_on_without_keys() {
        let mut aggregator = aggregator();
        for message in everyone(ROUND) {
            aggregator.add(message).unwrap();
        }
        let mut orchestrator = Orchestrator::new(VotingStatus::at(ROUND), STEP);
        // completable なので、時間を待たずに1回で次のポイントまで進む
        assert!(
            orchestrator
                .poll(0, &aggregator, &mut NoVotes, &|_| true)
                .is_empty()
        );
        assert_eq!(
            orchestrator.status(),
            VotingStatus::at(FinalizationRound { epoch: 3, point: 3 })
        );
    }

    #[test]
    fn drops_messages_from_ineligible_keys_but_still_moves_on() {
        let mut aggregator = aggregator();
        for message in everyone(ROUND) {
            aggregator.add(message).unwrap();
        }
        let mut orchestrator = Orchestrator::new(VotingStatus::at(ROUND), STEP);
        let mut voter = Voter::default();
        assert!(
            orchestrator
                .poll(0, &aggregator, &mut voter, &|_| false)
                .is_empty()
        );
        assert_eq!(voter.prevotes.len(), 1);
        assert_eq!(voter.precommits.len(), 1);
        assert_eq!(orchestrator.status().round.point, 3);
    }

    #[test]
    fn keeps_what_was_sent_before_a_restart() {
        let mut aggregator = aggregator();
        let status = VotingStatus {
            round: ROUND,
            sent_prevote: true,
            sent_precommit: false,
        };
        let mut orchestrator = Orchestrator::new(status, STEP);
        let mut voter = Voter::default();
        for message in everyone(ROUND) {
            aggregator.add(message).unwrap();
        }
        orchestrator.poll(0, &aggregator, &mut voter, &|_| true);
        assert!(voter.prevotes.is_empty());
        assert_eq!(voter.precommits.len(), 1);
    }

    #[test]
    fn moves_to_a_later_epoch_only() {
        let mut orchestrator = Orchestrator::new(VotingStatus::at(ROUND), STEP);
        orchestrator.set_epoch(3);
        assert_eq!(orchestrator.status(), VotingStatus::at(ROUND));
        orchestrator.set_epoch(5);
        assert_eq!(
            orchestrator.status(),
            VotingStatus::at(FinalizationRound { epoch: 5, point: 1 })
        );
        let result = std::panic::catch_unwind(move || orchestrator.set_epoch(4));
        assert!(result.is_err());
    }

    #[test]
    fn writes_the_voting_status_like_catapult() {
        let status = VotingStatus {
            round: FinalizationRound {
                epoch: 0x0102,
                point: 7,
            },
            sent_prevote: true,
            sent_precommit: false,
        };
        assert_eq!(status.to_bytes(), [2, 1, 0, 0, 7, 0, 0, 0, 1, 0]);
        assert_eq!(VotingStatus::from_bytes(&status.to_bytes()), Some(status));
        assert_eq!(VotingStatus::from_bytes(&[0; 9]), None);
    }
}
