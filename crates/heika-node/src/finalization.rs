//! ファイナライズの投票を見る（`finalization.observe`）。投票はしない。
//!
//! 投票するピア（Voting のロール）から投票のメッセージを引いて集計器に入れ、鍵を持たない段取り役でラウンドを
//! 進める。集まったメッセージで確定したら、その証明を組み、ピアから届いた証明（中核の確かめた確定）と同じラウンドに
//! なったところで比べる。どちらもログに出すだけで、中核の確定には使わない。
//!
//! 集計を始めるのは、始めたときの中核の確定のラウンドから。エポックは、中核の確定がエポックの最後のブロックに
//! 届き、手元も同じブロックを持っていたら進める（catapult の投票ノードと同じ）。

use std::sync::Arc;

use heika_block::finalization::aggregator::{MultiRoundAggregator, MultiRoundError};
use heika_block::finalization::message::FinalizationMessage;
use heika_block::finalization::proof::{ProofParameters, VotingSet, verify_proof};
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_core::hash::Hash256;
use heika_finalization::Settings;
use heika_finalization::epoch::{EpochStatus, epoch_status, finalize};
use heika_finalization::orchestrator::{NoVotes, Orchestrator, VotingStatus};

/// 引かれたときに返すメッセージの大きさの上限。catapult の `messageSynchronizationMaxResponseSize` の既定（20MB）
const MAX_RESPONSE_SIZE: usize = 20 * 1024 * 1024;

/// 投票を見る
pub struct Observer {
    settings: Settings,
    parameters: ProofParameters,
    aggregator: MultiRoundAggregator,
    orchestrator: Orchestrator,
    /// 始めたときの中核の確定の高さ
    started_at: u64,
    /// 自分で数えて確定した、いちばん新しいもの
    observed: Option<FinalizedBlockHeader>,
    /// 届いた証明と比べ終えたラウンド
    compared: Option<FinalizationRound>,
    /// 足せなかったメッセージの数（ログを間引くため、まとめて出す）
    rejected: usize,
}

impl Observer {
    /// 中核の確定 `finalized` から始める
    pub fn new(
        finalized: &FinalizedBlockHeader,
        parameters: ProofParameters,
        settings: Settings,
    ) -> Self {
        let next = FinalizationRound {
            epoch: finalized.round.epoch,
            point: finalized.round.point + 1,
        };
        Self {
            settings,
            parameters,
            aggregator: MultiRoundAggregator::new(
                parameters,
                MAX_RESPONSE_SIZE,
                finalized.round,
                (finalized.height, finalized.hash),
            ),
            orchestrator: Orchestrator::new(VotingStatus::at(next), settings.step_duration),
            started_at: finalized.height,
            observed: None,
            compared: None,
            rejected: 0,
        }
    }

    /// 段取り役のいるラウンド
    pub fn round(&self) -> FinalizationRound {
        self.orchestrator.status().round
    }

    /// ピアに頼むもの。集めている範囲（最小、最大のラウンド）と、持っているメッセージの短いハッシュ
    pub fn request(&self) -> (FinalizationRound, FinalizationRound, Vec<u32>) {
        (
            self.aggregator.min_round(),
            self.aggregator.max_round(),
            self.aggregator.short_hashes(),
        )
    }

    /// ピアから引いたメッセージを足す。足せた数を返す。範囲の外のもの、同じものの重複は数えずに捨てる
    pub fn add(&mut self, messages: Vec<Vec<u8>>) -> usize {
        let mut added = 0;
        for bytes in messages {
            let Ok(message) = FinalizationMessage::from_bytes(&bytes) else {
                self.rejected += 1;
                continue;
            };
            match self.aggregator.add(message) {
                Ok(_) => added += 1,
                Err(
                    MultiRoundError::Round
                    | MultiRoundError::Message(
                        heika_block::finalization::proof::MessageError::Redundant,
                    ),
                ) => {}
                Err(_) => self.rejected += 1,
            }
        }
        added
    }

    /// 時刻 `now` に進める。`finalized` は中核の確定、`voters` はエポックの投票者、`hash_at` は手元のチェーンの
    /// その高さのブロックのハッシュ。ログに出すことを返す
    pub fn tick(
        &mut self,
        now: u64,
        finalized: &FinalizedBlockHeader,
        voters: impl Fn(u32) -> Option<VotingSet>,
        hash_at: impl FnOnce(u64) -> Option<Hash256>,
    ) -> Vec<String> {
        let mut notices = Vec::new();
        if self.rejected > 0 {
            notices.push(format!(
                "投票のメッセージ {} 件を足せませんでした",
                std::mem::take(&mut self.rejected)
            ));
        }
        match epoch_status(
            self.round().epoch,
            finalized,
            self.settings.voting_set_grouping,
            hash_at,
        ) {
            EpochStatus::Wait => return notices,
            EpochStatus::Advance(epoch) => self.orchestrator.set_epoch(epoch),
            EpochStatus::Continue => {}
        }
        let round = self.round();
        for epoch in self.aggregator.min_round().epoch..=round.epoch {
            if !self.aggregator.has_voting_set(epoch)
                && let Some(set) = voters(epoch)
            {
                self.aggregator.set_voting_set(epoch, Arc::new(set));
            }
        }
        if round > self.aggregator.max_round() {
            self.aggregator.set_max_round(round);
        }
        self.orchestrator
            .poll(now, &self.aggregator, &mut NoVotes, &|_| false);

        // 自分の前の確定（まだなければ、始めたときの中核の確定）から進んだら確定する。catapult は自分で組んだ証明を
        // しまうので、同じ高さを二度確定しない。ここではしまわないので、自分の確定と比べる
        let previous = self
            .observed
            .map_or(self.started_at, |observed| observed.height);
        if let Some(done) = finalize(&mut self.aggregator, previous) {
            let header = done.header;
            let verified = voters(header.round.epoch)
                .map(|set| verify_proof(&done.proof, header.round.epoch, &set, &self.parameters));
            notices.push(format!(
                "投票を数えて、エポック {} のポイント {} で、高さ {} を確定しました（証明 {} バイト{}）",
                header.round.epoch,
                header.round.point,
                header.height,
                done.proof.len(),
                match verified {
                    Some(Ok(_)) => "、確かめました",
                    Some(Err(_)) => "、確かめられません",
                    None => "",
                }
            ));
            self.observed = Some(header);
        }

        // 届いた証明が同じラウンドになったら比べる
        if let Some(observed) = self.observed
            && finalized.round == observed.round
            && self.compared != Some(observed.round)
        {
            self.compared = Some(observed.round);
            if (finalized.height, finalized.hash) == (observed.height, observed.hash) {
                notices.push(format!(
                    "エポック {} のポイント {} の確定は、届いた証明と一致しました",
                    observed.round.epoch, observed.round.point
                ));
            } else {
                notices.push(format!(
                    "エポック {} のポイント {} の確定が、届いた証明と違います（数えたのは高さ {}、証明は高さ {}）",
                    observed.round.epoch, observed.round.point, observed.height, finalized.height
                ));
            }
        }
        notices
    }

    /// 持っているメッセージの数
    pub fn messages(&self) -> usize {
        self.aggregator.short_hashes().len()
    }
}

#[cfg(test)]
mod tests {
    use heika_core::key::{PrivateKey, PublicKey};

    use super::*;

    /// エポックは 10 ブロック。エポック 3 は高さ 20 で終わる
    const PARAMETERS: ProofParameters = ProofParameters {
        voting_set_grouping: 10,
        size: 10_000,
        threshold: 6_700,
        max_hashes_per_point: 256,
    };
    const SETTINGS: Settings = Settings {
        step_duration: 1000,
        prevote_blocks_multiple: 4,
        max_hashes_per_point: 256,
        voting_set_grouping: 10,
    };

    fn round(epoch: u32, point: u32) -> FinalizationRound {
        FinalizationRound { epoch, point }
    }

    fn block_hash(height: u64) -> Hash256 {
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Hash256(hash)
    }

    fn header(round: FinalizationRound, height: u64) -> FinalizedBlockHeader {
        FinalizedBlockHeader {
            round,
            height,
            hash: block_hash(height),
        }
    }

    fn keys(seed: u8) -> (PrivateKey, PrivateKey) {
        (
            PrivateKey::from_bytes(&[seed; 32]),
            PrivateKey::from_bytes(&[seed ^ 0x80; 32]),
        )
    }

    /// 重み 40、30、30 の投票者 1、2、3。閾値は 67
    fn voters(_epoch: u32) -> Option<VotingSet> {
        Some(VotingSet {
            voters: [1, 2, 3]
                .into_iter()
                .zip([40, 30, 30])
                .map(|(seed, weight)| (PublicKey::from_private_key(&keys(seed).0).0, weight))
                .collect(),
        })
    }

    /// 投票者 `seed` が署名した、catapult の形のメッセージ。高さ `from` から `through` までのハッシュ
    fn vote(seed: u8, at: FinalizationRound, is_prevote: bool, from: u64, through: u64) -> Vec<u8> {
        let (root, bottom) = keys(seed);
        let bottom_public = PublicKey::from_private_key(&bottom).0;
        let mut signed = Vec::new();
        signed.extend_from_slice(&1u32.to_le_bytes());
        signed.extend_from_slice(&((through - from + 1) as u32).to_le_bytes());
        signed.extend_from_slice(&at.epoch.to_le_bytes());
        signed.extend_from_slice(&((at.point << 1) | u32::from(!is_prevote)).to_le_bytes());
        signed.extend_from_slice(&from.to_le_bytes());
        for height in from..=through {
            signed.extend_from_slice(&block_hash(height).0);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((200 + signed.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&PublicKey::from_private_key(&root).0);
        let epoch = u64::from(at.epoch).to_le_bytes();
        bytes.extend_from_slice(&root.sign(&[&bottom_public, &epoch]).0);
        bytes.extend_from_slice(&bottom_public);
        bytes.extend_from_slice(&bottom.sign(&[&signed]).0);
        bytes.extend_from_slice(&signed);
        bytes
    }

    /// 全員が、高さ `from` から `through` に prevote し、`through` に precommit する
    fn everyone(at: FinalizationRound, from: u64, through: u64) -> Vec<Vec<u8>> {
        (1..=3)
            .flat_map(|seed| {
                [
                    vote(seed, at, true, from, through),
                    vote(seed, at, false, through, through),
                ]
            })
            .collect()
    }

    fn local(height: u64) -> Option<Hash256> {
        Some(block_hash(height))
    }

    /// エポック 3 のポイント 1 で高さ 10 が確定したところから見始め、1回進めて、ポイント 2 まで集めるようにしたもの
    fn started() -> (Observer, FinalizedBlockHeader) {
        let finalized = header(round(3, 1), 10);
        let mut observer = Observer::new(&finalized, PARAMETERS, SETTINGS);
        assert_eq!(observer.round(), round(3, 2));
        assert!(observer.tick(0, &finalized, voters, local).is_empty());
        (observer, finalized)
    }

    #[test]
    fn asks_for_the_rounds_it_collects() {
        let (mut observer, _) = started();
        let (min, max, known) = observer.request();
        assert_eq!((min, max), (round(3, 1), round(3, 2)));
        assert!(known.is_empty());
        let messages = everyone(round(3, 2), 10, 14);
        assert_eq!(observer.add(messages.clone()), 6);
        assert_eq!(observer.messages(), 6);
        assert_eq!(observer.request().2.len(), 6);
        // 同じものはもう足さないが、足せなかったとも言わない
        assert_eq!(observer.add(messages), 0);
        let (_, finalized) = started();
        assert!(
            observer
                .tick(0, &finalized, voters, local)
                .iter()
                .all(|notice| !notice.contains("足せません"))
        );
    }

    #[test]
    fn reports_messages_it_could_not_add() {
        let (mut observer, finalized) = started();
        // 読めないもの、投票者でない鍵、集めていないラウンド（数えない）
        let messages = vec![
            vec![0; 10],
            vote(9, round(3, 2), true, 10, 14),
            vote(1, round(3, 5), true, 10, 14),
        ];
        assert_eq!(observer.add(messages), 0);
        let notices = observer.tick(0, &finalized, voters, local);
        assert_eq!(notices, ["投票のメッセージ 2 件を足せませんでした"]);
        assert!(observer.tick(0, &finalized, voters, local).is_empty());
    }

    #[test]
    fn finalizes_each_height_once_and_compares_with_the_arriving_proof() {
        let (mut observer, finalized) = started();
        observer.add(everyone(round(3, 2), 10, 14));
        let notices = observer.tick(0, &finalized, voters, local);
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("ポイント 2 で、高さ 14 を確定しました"));
        assert!(notices[0].contains("確かめました"));
        // 結果がもう変わらないので、次のポイントに進む
        assert_eq!(observer.round(), round(3, 3));
        // 同じ高さはもう確定しない。中核の確定が先に進んでいても
        assert!(observer.tick(1, &finalized, voters, local).is_empty());
        assert!(
            observer
                .tick(2, &header(round(3, 9), 18), voters, local)
                .is_empty()
        );

        // 届いた証明が同じラウンドになったら、1回だけ比べる
        let arrived = header(round(3, 2), 14);
        assert_eq!(
            observer.tick(3, &arrived, voters, local),
            ["エポック 3 のポイント 2 の確定は、届いた証明と一致しました"]
        );
        assert!(observer.tick(4, &arrived, voters, local).is_empty());
    }

    #[test]
    fn says_when_the_arriving_proof_differs() {
        let (mut observer, finalized) = started();
        observer.add(everyone(round(3, 2), 10, 14));
        observer.tick(0, &finalized, voters, local);
        let mut arrived = header(round(3, 2), 13);
        arrived.hash = block_hash(13);
        assert_eq!(
            observer.tick(1, &arrived, voters, local),
            [
                "エポック 3 のポイント 2 の確定が、届いた証明と違います（数えたのは高さ 14、証明は高さ 13）"
            ]
        );
    }

    #[test]
    fn moves_to_the_next_epoch_only_when_the_local_chain_has_its_last_block() {
        let (mut observer, _) = started();
        // エポック 3 の最後の高さ 20 が確定した
        let closed = header(round(3, 7), 20);
        assert!(observer.tick(0, &closed, voters, |_| None).is_empty());
        assert_eq!(observer.round(), round(3, 2));
        assert!(observer.tick(0, &closed, voters, local).is_empty());
        assert_eq!(observer.round(), round(4, 1));
        assert_eq!(observer.request().1, round(4, 1));

        // 新しいエポックの票も数える
        observer.add(everyone(round(4, 1), 20, 24));
        let notices = observer.tick(1, &closed, voters, local);
        assert!(notices[0].contains("エポック 4 のポイント 1 で、高さ 24 を確定しました"));
    }

    #[test]
    fn waits_without_voters() {
        let finalized = header(round(3, 1), 10);
        let mut observer = Observer::new(&finalized, PARAMETERS, SETTINGS);
        observer.tick(0, &finalized, |_| None, local);
        // 投票者を知らないエポックのメッセージは足せない
        assert_eq!(observer.add(everyone(round(3, 2), 10, 14)), 0);
        // あとで投票者がわかれば数える
        observer.tick(0, &finalized, voters, local);
        assert_eq!(observer.add(everyone(round(3, 2), 10, 14)), 6);
    }
}
