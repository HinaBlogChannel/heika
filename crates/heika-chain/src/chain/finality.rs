//! 確定（ファイナライズ）の証明を取って確かめ、確定を上げて刈り込む。

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// ピアの言う確定が自分の確かめたものより新しく、そのエポックの投票者が決まっていれば、証明を頼む
    pub(super) async fn on_finalized(&mut self, peer: PeerId, header: FinalizedBlockHeader) {
        if header.round <= self.finalized.round || self.proof_requested.covers(header.round) {
            return;
        }
        let epoch = header.round.epoch;
        // エポック E の投票者は、E - 1 の最後の高さまで実行すると決まる
        if !matches!(self.store.voters(epoch).await, Ok(Some(_))) {
            return;
        }
        self.proof_requested.request(peer, header.round);
        self.command(peer, PeerCommand::PullProof { epoch });
    }

    /// 確かめた確定より前のエポックで、まだしまっていないか、途中のポイントのままの証明があれば、古いほうから
    /// 1つ頼む。先端で新しいエポックの証明をしまうと、追いつく段階でしまったものとのあいだが抜けることがある。
    /// 先端の段階を離れていたあいだに終わったエポックは、途中のポイントの証明のままになっている
    pub(super) async fn backfill_proofs(&mut self) -> Result<(), ChainError> {
        if self.proof_requested.is_waiting() {
            return Ok(());
        }
        // ブロックを消した高さまでのエポックは、証明を突き合わせるブロックがないので取らない
        let blocks_from = self.store.blocks_from().await?;
        if blocks_from > 0 {
            let epoch = self.parameters.finalization_epoch(blocks_from) + 1;
            self.backfilled = self
                .backfilled
                .max(u32::try_from(epoch).unwrap_or(u32::MAX));
        }
        // エポックの最後の高さを指す証明がしまってあるエポックを飛ばして、最初の抜けを探す
        while self.backfilled < self.finalized.round.epoch && self.settled(self.backfilled).await? {
            self.backfilled += 1;
        }
        let epoch = self.backfilled;
        if epoch >= self.finalized.round.epoch
            || !matches!(self.store.voters(epoch).await, Ok(Some(_)))
        {
            return Ok(());
        }
        let Some(peer) = self.peers.keys().next().copied() else {
            return Ok(());
        };
        self.proof_requested
            .request(peer, FinalizationRound { epoch, point: 0 });
        self.command(peer, PeerCommand::PullProof { epoch });
        Ok(())
    }

    /// エポック `epoch` の、エポックの最後の高さを指す証明がしまってあるか
    pub(super) async fn settled(&self, epoch: u32) -> Result<bool, ChainError> {
        Ok(match self.store.proof(epoch).await? {
            Some(proof) => closes_epoch(
                &proof_header(&proof)?,
                self.config.finalization.voting_set_grouping,
            ),
            None => false,
        })
    }

    /// 証明を、実行して求めた投票者で確かめる。通れば確かめた確定を上げ、証明をしまい、古いチェックポイントを消す
    pub(super) async fn on_proof(
        &mut self,
        peer: PeerId,
        epoch: u32,
        proof: Option<Vec<u8>>,
    ) -> Result<(), ChainError> {
        self.proof_requested.answered(peer, epoch);
        let Some(proof) = proof else {
            return Ok(());
        };
        self.accept_proof(Some(peer), epoch, proof).await
    }

    /// 自分で投票を数えて組んだ証明。ピアの証明と同じに確かめてしまう。catapult も、自分で組んだ証明をしまって
    /// 確定を進めるので、catapult のいないネットワークでもエポックが進む
    pub(super) async fn on_own_proof(
        &mut self,
        epoch: u32,
        proof: Vec<u8>,
    ) -> Result<(), ChainError> {
        self.accept_proof(None, epoch, proof).await
    }

    /// 証明を確かめ、確定より先なら、しまって確定を上げる。`peer` はくれたピア（自分で組んだものなら `None`）
    async fn accept_proof(
        &mut self,
        peer: Option<PeerId>,
        epoch: u32,
        proof: Vec<u8>,
    ) -> Result<(), ChainError> {
        let voters = VotingSet::decode(
            &self
                .store
                .voters(epoch)
                .await?
                .ok_or("証明のエポックの投票者がありません")?,
        )
        .ok_or("投票者が読めません")?;
        let header = match verify_proof(
            &proof,
            epoch,
            &voters,
            &self.config.finalization.proof_parameters(),
        ) {
            Ok(header) => header,
            Err(error) => {
                match peer {
                    Some(peer) => self.drop_peer(
                        peer,
                        format!("ピア {} の証明が通らないので外します: {error}", peer.0),
                    ),
                    None => self.progress(format!(
                        "自分で数えたエポック {epoch} の証明が通りません: {error}"
                    )),
                }
                return Ok(());
            }
        };
        if header.round == self.finalized.round && header.hash != self.finalized.hash {
            return Err(format!(
                "エポック {} ポイント {} で、違うブロック（{} と {}）を指す証明がどちらも通りました。止めます",
                header.round.epoch, header.round.point, self.finalized.hash, header.hash
            )
            .into());
        }
        if header.round <= self.finalized.round {
            if header.round.epoch < self.finalized.round.epoch
                && let Some(peer) = peer
            {
                self.store_earlier(peer, epoch, &proof, &header).await?;
            }
            return Ok(());
        }
        if header.height <= self.tip.height
            && block_at(self.store, header.height).await?.hash() != header.hash
        {
            match peer {
                Some(peer) => {
                    self.progress(format!(
                        "確かめた証明が指す高さ {} のブロックが、自分の枝のものと違います。ピア {} と分かれ目を探します",
                        header.height, peer.0
                    ));
                    if matches!(self.sync, Sync::Idle) {
                        self.compare(peer);
                    }
                }
                None => self.progress(format!(
                    "自分で数えた証明が指す高さ {} のブロックが、自分の枝のものと違います",
                    header.height
                )),
            }
            return Ok(());
        }
        self.store.put_proof(epoch, &proof).await?;
        self.finalized = header;
        let pruned = self.prune(header.height).await?;
        self.notify(Notice::Finalized {
            epoch,
            point: header.round.point,
            height: header.height,
            peer,
            checkpoints: pruned.checkpoints,
            rows: self.keep.map(|_| pruned.rows),
            remaining: pruned.remaining,
        });
        Ok(())
    }

    /// 確定 `finalized` から [`CHECKPOINT_EPOCHS`] より下のチェックポイントと、刈り込むなら残す分より下の差分を消す
    /// （[`Keep::plan`]）
    pub(super) async fn prune(&self, finalized: u64) -> Result<crate::store::Pruned, ChainError> {
        let floor = self
            .store
            .checkpoint_at_or_below(finalized)
            .await?
            .map_or(0, |(height, _)| height);
        self.store
            .prune(Keep::plan(
                self.keep,
                &self.config,
                self.parameters,
                finalized,
                floor,
            ))
            .await
    }

    /// 抜けていたか、途中のポイントのままだった前のエポックの証明を、しまったものより先の高さを指し、手元の
    /// ブロックと合えばしまう。返事がどうであれ、そのエポックの取り直しは一度で終える（ピアも途中のポイントの
    /// 証明しか持っていなければ、頼み続けてしまう）
    pub(super) async fn store_earlier(
        &mut self,
        peer: PeerId,
        epoch: u32,
        proof: &[u8],
        header: &FinalizedBlockHeader,
    ) -> Result<(), ChainError> {
        if epoch == self.backfilled {
            self.backfilled += 1;
        }
        let stored = match self.store.proof(epoch).await? {
            Some(stored) => Some(proof_header(&stored)?.height),
            None => None,
        };
        if stored.is_some_and(|height| height >= header.height)
            || header.height > self.tip.height
            || header.height < self.store.blocks_from().await?
            || block_at(self.store, header.height).await?.hash() != header.hash
        {
            return Ok(());
        }
        self.store.put_proof(epoch, proof).await?;
        self.notify(Notice::EarlierProof {
            epoch,
            height: header.height,
            peer,
            partial: stored.is_some(),
        });
        Ok(())
    }
}

/// 頼んで返事を待っている証明と、頼んだピア。同じものを何度も頼まない。頼んだピアがそのエポックを返すか、
/// 頼んだピアが外れたら解く。ほかのピアの遅れた返事や、ほかのピアが外れたことでは解かない
#[derive(Debug, Default)]
pub(super) struct ProofRequest(Option<(PeerId, FinalizationRound)>);

impl ProofRequest {
    fn is_waiting(&self) -> bool {
        self.0.is_some()
    }

    /// `round` かそれより新しいラウンドを待っているか
    fn covers(&self, round: FinalizationRound) -> bool {
        self.0.is_some_and(|(_, requested)| requested >= round)
    }

    fn request(&mut self, peer: PeerId, round: FinalizationRound) {
        self.0 = Some((peer, round));
    }

    fn answered(&mut self, peer: PeerId, epoch: u32) {
        if self
            .0
            .is_some_and(|(requested, round)| requested == peer && round.epoch == epoch)
        {
            self.0 = None;
        }
    }

    pub(super) fn forget(&mut self, peer: PeerId) {
        if self.0.is_some_and(|(requested, _)| requested == peer) {
            self.0 = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_request_is_released_only_by_the_peer_asked() {
        let round = |epoch| FinalizationRound { epoch, point: 0 };
        let mut request = ProofRequest::default();
        request.request(PeerId(1), round(5));
        assert!(request.covers(round(5)));
        assert!(!request.covers(round(6)));

        // ほかのピアの返事や、違うエポックの返事、ほかのピアが外れたことでは解かない
        request.answered(PeerId(2), 5);
        request.answered(PeerId(1), 4);
        request.forget(PeerId(2));
        assert!(request.is_waiting());

        // 頼んだピアが外れたら、ほかのピアに頼み直せる
        request.forget(PeerId(1));
        assert!(!request.is_waiting());
        request.request(PeerId(2), round(5));
        // 外れたピアの遅れた返事は、頼み直したものを解かない
        request.answered(PeerId(1), 5);
        assert!(request.is_waiting());
        request.answered(PeerId(2), 5);
        assert!(!request.is_waiting());
    }
}
