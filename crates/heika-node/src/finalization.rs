//! ファイナライズの投票（`finalization`）。`observe` なら見るだけ、`votingKeys` があれば投票もする。
//!
//! 投票するピア（Voting のロール）から投票のメッセージを引いて集計器に入れ、段取り役でラウンドを進める。鍵があれば
//! prevote と precommit を作り、投票状況をディスクに書いてから、集計器に足して投票するピアに配る。鍵がなければ
//! 何も作らずに進む。集まったメッセージで確定したら、その証明を組み、ピアから届いた証明（中核の確かめた確定）と
//! 同じラウンドになったところで比べる。どちらもログに出すだけで、中核の確定には使わない。
//!
//! 集計を始めるのは、始めたときの中核の確定のラウンドから。投票するときは、前に書いた投票状況があればそこから
//! 進める。エポックは、中核の確定がエポックの最後のブロックに届き、手元も同じブロックを持っていたら進める
//! （catapult の投票ノードと同じ）。

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use heika_block::finalization::aggregator::{MultiRoundAggregator, MultiRoundError};
use heika_block::finalization::message::FinalizationMessage;
use heika_block::finalization::proof::{MessageError, ProofParameters, VotingSet, verify_proof};
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_core::hash::Hash256;
use heika_finalization::Settings;
use heika_finalization::epoch::{EpochStatus, epoch_status, finalize};
use heika_finalization::orchestrator::{NoVotes, Orchestrator, VotingStatus};
use heika_finalization::signer::{Signer, VotingKeys};

use crate::voting::write_status;

/// 引かれたときに返すメッセージの大きさの上限。catapult の `messageSynchronizationMaxResponseSize` の既定（20MB）
const MAX_RESPONSE_SIZE: usize = 20 * 1024 * 1024;

/// 投票するときの鍵と、投票状況を書くデータのフォルダー
pub struct Voting {
    pub keys: Box<dyn VotingKeys + Send>,
    pub data_directory: PathBuf,
}

/// 進めるときに渡す、チェーンの様子
pub struct View<'a> {
    /// ネットワークの時刻（ミリ秒）
    pub now: u64,
    /// 中核の確定
    pub finalized: FinalizedBlockHeader,
    /// 手元のチェーンの先端の高さ
    pub chain_height: u64,
    /// エポックの投票者
    pub voters: &'a dyn Fn(u32) -> Option<VotingSet>,
    /// 手元のチェーンの、高さ `from` から `count` 個のブロックのハッシュ（あるだけ）
    pub hashes: &'a dyn Fn(u64, u64) -> Vec<Hash256>,
}

/// 進めた結果
#[derive(Debug, Default)]
pub struct Ticked {
    /// ログに出すこと
    pub notices: Vec<String>,
    /// 自分が作ったメッセージ（投票するピアに配る）
    pub outgoing: Vec<Vec<u8>>,
}

/// 投票を数える（鍵があれば投票もする）
pub struct Observer {
    settings: Settings,
    parameters: ProofParameters,
    aggregator: MultiRoundAggregator,
    orchestrator: Orchestrator,
    voting: Option<Voting>,
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
    /// 中核の確定 `finalized` から始める。投票するなら `voting` と、前に書いた投票状況 `status`
    pub fn new(
        finalized: &FinalizedBlockHeader,
        parameters: ProofParameters,
        settings: Settings,
        voting: Option<Voting>,
        status: Option<VotingStatus>,
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
            orchestrator: Orchestrator::new(
                status.unwrap_or(VotingStatus::at(next)),
                settings.step_duration,
            ),
            voting,
            started_at: finalized.height,
            observed: None,
            compared: None,
            rejected: 0,
        }
    }

    /// 投票するか（鍵を持っているか）
    pub fn is_voting(&self) -> bool {
        self.voting.is_some()
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

    /// ピアに引かれたときに返すもの。ラウンド `min` から `max` までのうち、短いハッシュが `known` にないもの
    pub fn unknown_to(
        &self,
        min: FinalizationRound,
        max: FinalizationRound,
        known: &HashSet<u32>,
    ) -> Vec<u8> {
        self.aggregator
            .unknown_messages(min, max, known)
            .into_iter()
            .flat_map(FinalizationMessage::to_bytes)
            .collect()
    }

    /// ピアから届いたメッセージを足し、新しく足せたもの（ほかの投票するピアに配る）を返す。範囲の外のもの、
    /// 同じものの重複は、足せなかったとは数えずに捨てる
    pub fn add(&mut self, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut added = Vec::new();
        for bytes in messages {
            let Ok(message) = FinalizationMessage::from_bytes(&bytes) else {
                self.rejected += 1;
                continue;
            };
            match self.aggregator.add(message) {
                Ok(_) => added.push(bytes),
                Err(MultiRoundError::Round | MultiRoundError::Message(MessageError::Redundant)) => {
                }
                Err(_) => self.rejected += 1,
            }
        }
        added
    }

    /// 進める
    pub fn tick(&mut self, view: &View, hash_at: impl FnOnce(u64) -> Option<Hash256>) -> Ticked {
        let mut ticked = Ticked::default();
        if self.rejected > 0 {
            ticked.notices.push(format!(
                "投票のメッセージ {} 件を足せませんでした",
                std::mem::take(&mut self.rejected)
            ));
        }
        let finalized = &view.finalized;
        match epoch_status(
            self.round().epoch,
            finalized,
            self.settings.voting_set_grouping,
            hash_at,
        ) {
            EpochStatus::Wait => return ticked,
            EpochStatus::Advance(epoch) => self.orchestrator.set_epoch(epoch),
            EpochStatus::Continue => {}
        }
        let round = self.round();
        for epoch in self.aggregator.min_round().epoch..=round.epoch {
            if !self.aggregator.has_voting_set(epoch)
                && let Some(set) = (view.voters)(epoch)
            {
                self.aggregator.set_voting_set(epoch, Arc::new(set));
            }
        }
        if round > self.aggregator.max_round() {
            self.aggregator.set_max_round(round);
        }
        self.poll(view, &mut ticked);

        // 自分の前の確定（まだなければ、始めたときの中核の確定）から進んだら確定する。catapult は自分で組んだ証明を
        // しまうので、同じ高さを二度確定しない。ここではしまわないので、自分の確定と比べる
        let previous = self
            .observed
            .map_or(self.started_at, |observed| observed.height);
        if let Some(done) = finalize(&mut self.aggregator, previous) {
            let header = done.header;
            let verified = (view.voters)(header.round.epoch)
                .map(|set| verify_proof(&done.proof, header.round.epoch, &set, &self.parameters));
            ticked.notices.push(format!(
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
                ticked.notices.push(format!(
                    "エポック {} のポイント {} の確定は、届いた証明と一致しました",
                    observed.round.epoch, observed.round.point
                ));
            } else {
                ticked.notices.push(format!(
                    "エポック {} のポイント {} の確定が、届いた証明と違います（数えたのは高さ {}、証明は高さ {}）",
                    observed.round.epoch, observed.round.point, observed.height, finalized.height
                ));
            }
        }
        ticked
    }

    /// 段取り役を進める。投票するなら、作ったメッセージを、投票状況を書いてから集計器に足して配る
    fn poll(&mut self, view: &View, ticked: &mut Ticked) {
        let Some(voting) = self.voting.as_mut() else {
            self.orchestrator
                .poll(view.now, &self.aggregator, &mut NoVotes, &|_| false);
            return;
        };
        let before = self.orchestrator.status();
        // prevote は、中核の確定と自分の確定の新しいほうのブロックから
        let finalized = match self.observed {
            Some(observed) if observed.round > view.finalized.round => observed,
            _ => view.finalized,
        };
        let mut signer = Signer {
            keys: voting.keys.as_mut(),
            settings: self.settings,
            finalized,
            chain_height: view.chain_height,
            hashes: view.hashes,
        };
        let eligible = |message: &FinalizationMessage| {
            (view.voters)(message.round.epoch)
                .is_some_and(|set| set.voters.contains_key(&message.root_key()))
        };
        let sent = self
            .orchestrator
            .poll(view.now, &self.aggregator, &mut signer, &eligible);
        let status = self.orchestrator.status();
        if status != before
            && let Err(error) = write_status(&voting.data_directory, &status)
        {
            // 書けなかったら配らない。起き直したときに、同じ段階をもう一度出しかねない
            ticked
                .notices
                .push(format!("投票状況を書けないので、投票を配りません: {error}"));
            return;
        }
        for message in sent {
            let (round, stage) = (
                message.round,
                if message.is_prevote {
                    "prevote"
                } else {
                    "precommit"
                },
            );
            ticked.notices.push(format!(
                "エポック {} のポイント {} の {stage} を出しました（高さ {} から {}）",
                round.epoch,
                round.point,
                message.height,
                message.last_height()
            ));
            let bytes = message.to_bytes();
            if let Err(error) = self.aggregator.add(message) {
                ticked
                    .notices
                    .push(format!("自分の {stage} を足せませんでした: {error:?}"));
            }
            ticked.outgoing.push(bytes);
        }
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

    fn hashes(from: u64, count: u64) -> Vec<Hash256> {
        (from..from + count).map(block_hash).collect()
    }

    /// 先端が高さ 30 のチェーンで進め、ログに出すことを返す
    fn tick(observer: &mut Observer, now: u64, finalized: &FinalizedBlockHeader) -> Vec<String> {
        observer.tick(&view(now, finalized), local).notices
    }

    fn view<'a>(now: u64, finalized: &FinalizedBlockHeader) -> View<'a> {
        View {
            now,
            finalized: *finalized,
            chain_height: 30,
            voters: &voters,
            hashes: &hashes,
        }
    }

    /// 手元のチェーンにまだブロックがないとして進める
    fn tick_without_blocks(
        observer: &mut Observer,
        now: u64,
        finalized: &FinalizedBlockHeader,
    ) -> Vec<String> {
        observer.tick(&view(now, finalized), |_| None).notices
    }

    /// エポック 3 のポイント 1 で高さ 10 が確定したところから見始め、1回進めて、ポイント 2 まで集めるようにしたもの
    fn started() -> (Observer, FinalizedBlockHeader) {
        let finalized = header(round(3, 1), 10);
        let mut observer = Observer::new(&finalized, PARAMETERS, SETTINGS, None, None);
        assert_eq!(observer.round(), round(3, 2));
        assert!(tick(&mut observer, 0, &finalized).is_empty());
        (observer, finalized)
    }

    #[test]
    fn asks_for_the_rounds_it_collects() {
        let (mut observer, _) = started();
        let (min, max, known) = observer.request();
        assert_eq!((min, max), (round(3, 1), round(3, 2)));
        assert!(known.is_empty());
        let messages = everyone(round(3, 2), 10, 14);
        assert_eq!(observer.add(messages.clone()).len(), 6);
        assert_eq!(observer.messages(), 6);
        assert_eq!(observer.request().2.len(), 6);
        // 同じものはもう足さないが、足せなかったとも言わない
        assert!(observer.add(messages).is_empty());
        let (_, finalized) = started();
        assert!(
            tick(&mut observer, 0, &finalized)
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
        assert!(observer.add(messages).is_empty());
        let notices = tick(&mut observer, 0, &finalized);
        assert_eq!(notices, ["投票のメッセージ 2 件を足せませんでした"]);
        assert!(tick(&mut observer, 0, &finalized).is_empty());
    }

    #[test]
    fn finalizes_each_height_once_and_compares_with_the_arriving_proof() {
        let (mut observer, finalized) = started();
        observer.add(everyone(round(3, 2), 10, 14));
        let notices = tick(&mut observer, 0, &finalized);
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("ポイント 2 で、高さ 14 を確定しました"));
        assert!(notices[0].contains("確かめました"));
        // 結果がもう変わらないので、次のポイントに進む
        assert_eq!(observer.round(), round(3, 3));
        // 同じ高さはもう確定しない。中核の確定が先に進んでいても
        assert!(tick(&mut observer, 1, &finalized).is_empty());
        assert!(tick(&mut observer, 2, &header(round(3, 9), 18)).is_empty());

        // 届いた証明が同じラウンドになったら、1回だけ比べる
        let arrived = header(round(3, 2), 14);
        assert_eq!(
            tick(&mut observer, 3, &arrived),
            ["エポック 3 のポイント 2 の確定は、届いた証明と一致しました"]
        );
        assert!(tick(&mut observer, 4, &arrived).is_empty());
    }

    #[test]
    fn says_when_the_arriving_proof_differs() {
        let (mut observer, finalized) = started();
        observer.add(everyone(round(3, 2), 10, 14));
        tick(&mut observer, 0, &finalized);
        let mut arrived = header(round(3, 2), 13);
        arrived.hash = block_hash(13);
        assert_eq!(
            tick(&mut observer, 1, &arrived),
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
        assert!(tick_without_blocks(&mut observer, 0, &closed).is_empty());
        assert_eq!(observer.round(), round(3, 2));
        assert!(tick(&mut observer, 0, &closed).is_empty());
        assert_eq!(observer.round(), round(4, 1));
        assert_eq!(observer.request().1, round(4, 1));

        // 新しいエポックの票も数える
        observer.add(everyone(round(4, 1), 20, 24));
        let notices = tick(&mut observer, 1, &closed);
        assert!(notices[0].contains("エポック 4 のポイント 1 で、高さ 24 を確定しました"));
    }

    #[test]
    fn waits_without_voters() {
        let finalized = header(round(3, 1), 10);
        let mut observer = Observer::new(&finalized, PARAMETERS, SETTINGS, None, None);
        observer.tick(
            &View {
                now: 0,
                finalized,
                chain_height: 30,
                voters: &|_| None,
                hashes: &hashes,
            },
            local,
        );
        // 投票者を知らないエポックのメッセージは足せない
        assert!(observer.add(everyone(round(3, 2), 10, 14)).is_empty());
        // あとで投票者がわかれば数える
        tick(&mut observer, 0, &finalized);
        assert_eq!(observer.add(everyone(round(3, 2), 10, 14)).len(), 6);
    }
}
