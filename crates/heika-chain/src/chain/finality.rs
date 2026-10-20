//! 確定（ファイナライズ）の証明を取って確かめ、確定を上げて刈り込む。

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// ピアの言う確定が自分の確かめたものより新しく、そのエポックの投票者が決まっていれば、証明を頼む
    pub(super) async fn on_finalized(&mut self, peer: PeerId, header: FinalizedBlockHeader) {
        if header.round <= self.finalized.round
            || self
                .proof_requested
                .is_some_and(|requested| requested >= header.round)
        {
            return;
        }
        let epoch = header.round.epoch;
        // エポック E の投票者は、E - 1 の最後の高さまで実行すると決まる
        if !matches!(self.store.voters(epoch).await, Ok(Some(_))) {
            return;
        }
        self.proof_requested = Some(header.round);
        self.command(peer, PeerCommand::PullProof { epoch });
    }

    /// 確かめた確定より前のエポックで、まだしまっていないか、途中のポイントのままの証明があれば、古いほうから
    /// 1つ頼む。先端で新しいエポックの証明をしまうと、追いつく段階でしまったものとのあいだが抜けることがある。
    /// 先端の段階を離れていたあいだに終わったエポックは、途中のポイントの証明のままになっている
    pub(super) async fn backfill_proofs(&mut self) -> Result<(), ChainError> {
        if self.proof_requested.is_some() {
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
        self.proof_requested = Some(FinalizationRound { epoch, point: 0 });
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
        self.proof_requested = None;
        let Some(proof) = proof else {
            return Ok(());
        };
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
                self.drop_peer(
                    peer,
                    format!("ピア {} の証明が通らないので外します: {error}", peer.0),
                );
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
            if header.round.epoch < self.finalized.round.epoch {
                self.store_earlier(peer, epoch, &proof, &header).await?;
            }
            return Ok(());
        }
        if header.height <= self.tip.height
            && block_at(self.store, header.height).await?.hash() != header.hash
        {
            self.progress(format!(
                "確かめた証明が指す高さ {} のブロックが、自分の枝のものと違います。ピア {} と分かれ目を探します",
                header.height, peer.0
            ));
            if matches!(self.sync, Sync::Idle) {
                self.compare(peer);
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
        });
        Ok(())
    }

    /// 確定 `finalized` から [`CHECKPOINT_EPOCHS`] より下のチェックポイントと、刈り込むなら残す分より下の差分を消す。
    /// 確定より上に分かれ目があって巻き戻すときは、分かれ目以下で一番新しいチェックポイントまで戻るので、確定以下で
    /// 一番新しいチェックポイントより上は消さない
    pub(super) async fn prune(&self, finalized: u64) -> Result<crate::store::Pruned, ChainError> {
        let grouping = self.config.finalization.voting_set_grouping;
        let checkpoints_below = finalized.saturating_sub(CHECKPOINT_EPOCHS * grouping);
        let floor = self
            .store
            .checkpoint_at_or_below(finalized)
            .await?
            .map_or(0, |(height, _)| height);
        let bound = |epochs: u64| finalized.saturating_sub(epochs * grouping).min(floor);
        let history = self.keep.map(|keep| (bound(keep.state), bound(keep.trie)));
        let blocks = self.keep.filter(|keep| keep.history).map(|keep| {
            let through = bound(keep.state).saturating_sub(self.config.blocks_for_restart());
            let epoch =
                u32::try_from(self.parameters.finalization_epoch(through)).unwrap_or(u32::MAX);
            (through, epoch)
        });
        self.store
            .prune(Prune {
                checkpoints_below,
                history,
                blocks,
            })
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
