//! ピアの統計を見て先端の続きを取り、分かれていれば分かれ目を探して枝を取り替える。

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// 同期していなければ、スコアが自分より高いピアのうち一番高いものから、続きを取り始める
    pub(super) fn start_sync(&mut self) {
        if !matches!(self.sync, Sync::Idle) {
            return;
        }
        let score = self.executor.score().unwrap_or(0);
        let best = self
            .peers
            .iter()
            .filter_map(|(id, peer)| peer.statistics.map(|statistics| (*id, statistics)))
            .filter(|(_, statistics)| statistics.score > score)
            .max_by_key(|(_, statistics)| statistics.score);
        let Some((id, statistics)) = best else {
            return;
        };
        if statistics.height <= self.tip.height {
            self.progress(format!(
                "ピア {} はスコアが高いのに、先端が自分（高さ {}）より先にありません。分かれ目を探します",
                id.0, self.tip.height
            ));
            self.compare(id);
            return;
        }
        self.pull(id, &statistics);
    }

    /// 分かれ目を探し始める。確かめた確定の高さから（自分の先端まで）比べる
    pub(super) fn compare(&mut self, id: PeerId) {
        let from = self.finalized.height.clamp(1, self.tip.height);
        self.compare_from(id, from);
    }

    pub(super) fn compare_from(&mut self, id: PeerId, from: u64) {
        self.command(
            id,
            PeerCommand::PullHashes {
                from,
                count: PULL_HASHES,
            },
        );
        self.sync = Sync::Comparing { peer: id, from };
    }

    /// ピアのハッシュを自分のブロックと並べて、最初に違う高さを探す
    pub(super) async fn on_hashes(
        &mut self,
        peer: PeerId,
        from: u64,
        count: u32,
        hashes: &[[u8; 32]],
    ) -> Result<(), ChainError> {
        if !matches!(self.sync, Sync::Comparing { peer: syncing, from: expected } if syncing == peer && expected == from)
        {
            return Ok(());
        }
        self.sync = Sync::Idle;
        let Some(statistics) = self.peers.get(&peer).and_then(|entry| entry.statistics) else {
            return Ok(());
        };
        if hashes.is_empty() {
            self.drop_peer(
                peer,
                format!("ピア {} がハッシュを返さないので外します", peer.0),
            );
            return Ok(());
        }
        for (index, hash) in hashes.iter().enumerate() {
            let height = from + index as u64;
            if height > self.tip.height {
                // 自分の先端まで同じで、ピアはその先にいる。分かれていない
                self.pull(peer, &statistics);
                return Ok(());
            }
            if block_at(self.store, height).await?.hash().0 != *hash {
                if index == 0 {
                    self.drop_peer(
                        peer,
                        format!(
                            "ピア {} は、比べ始めた高さ {height} より下で分かれているので外します",
                            peer.0
                        ),
                    );
                    return Ok(());
                }
                let common = height - 1;
                self.progress(format!(
                    "ピア {} とは、高さ {common} のあとで分かれています。ピアの枝を取ります",
                    peer.0
                ));
                self.sync = Sync::Forking {
                    peer,
                    common,
                    blocks: Vec::new(),
                };
                self.pull_fork(peer, common + 1, &statistics);
                return Ok(());
            }
        }
        if hashes.len() == count as usize {
            self.compare_from(peer, from + hashes.len() as u64);
        } else {
            self.drop_peer(
                peer,
                format!(
                    "ピア {} の枝は自分の枝の途中で尽きたので、スコアについて嘘をついています。外します",
                    peer.0
                ),
            );
        }
        Ok(())
    }

    /// 枝のブロックを、ピアの先端まで `from` から頼む
    pub(super) fn pull_fork(&mut self, peer: PeerId, from: u64, statistics: &ChainStatistics) {
        let count = u32::try_from(statistics.height.saturating_sub(from) + 1)
            .unwrap_or(u32::MAX)
            .min(PULL_BLOCKS);
        self.command(peer, PeerCommand::PullBlocks { from, count });
    }

    pub(super) fn pull(&mut self, id: PeerId, statistics: &ChainStatistics) {
        let count = u32::try_from(statistics.height - self.tip.height)
            .unwrap_or(u32::MAX)
            .min(PULL_BLOCKS);
        self.command(
            id,
            PeerCommand::PullBlocks {
                from: self.tip.height + 1,
                count,
            },
        );
        self.sync = Sync::Extending { peer: id };
    }

    pub(super) async fn on_blocks(
        &mut self,
        peer: PeerId,
        from: u64,
        count: u32,
        blocks: Vec<(Block, Vec<u8>)>,
    ) -> Result<(), ChainError> {
        if let Sync::Forking {
            peer: syncing,
            common,
            blocks: collected,
        } = &mut self.sync
            && *syncing == peer
            && from == *common + 1 + collected.len() as u64
        {
            let common = *common;
            let received = blocks.len();
            collected.extend(blocks);
            let statistics = self.peers.get(&peer).and_then(|entry| entry.statistics);
            let next = common + 1 + collected.len() as u64;
            if let Some(statistics) = statistics
                && received == count as usize
                && received > 0
                && next <= statistics.height
            {
                self.pull_fork(peer, next, &statistics);
                return Ok(());
            }
            let Sync::Forking { blocks, .. } = std::mem::replace(&mut self.sync, Sync::Idle) else {
                unreachable!("matched above");
            };
            if self.too_far_in_future(peer, &blocks) {
                return Ok(());
            }
            return self.switch(peer, common, blocks).await;
        }
        if !matches!(self.sync, Sync::Extending { peer: syncing } if syncing == peer)
            || from != self.tip.height + 1
        {
            // 前に頼んだものの返事。今の同期には使わない
            return Ok(());
        }
        self.sync = Sync::Idle;
        let Some((first, _)) = blocks.first() else {
            return Ok(());
        };
        if first.previous_block_hash != self.tip.hash {
            self.progress(format!(
                "ピア {} の高さ {} は、自分の先端（{}）につながりません。分かれ目を探します",
                peer.0, first.height, self.tip.hash
            ));
            self.compare(peer);
            return Ok(());
        }
        if self.too_far_in_future(peer, &blocks) {
            return Ok(());
        }
        let received = blocks.len();
        for (block, bytes) in blocks {
            if let Err(error) = self.accept(&block, bytes, false).await {
                if is_invalid(&error) {
                    self.drop_peer(
                        peer,
                        format!(
                            "ピア {} の高さ {} を弾き、外します: {error}",
                            peer.0, block.height
                        ),
                    );
                } else {
                    // こちらの都合なので、ピアは罰さずに外し、間を空けてまた試す
                    self.notify(Notice::PeerDropped {
                        peer,
                        message: format!(
                            "ピア {} の高さ {} を受け入れられないので外します（こちらの都合）: {error}",
                            peer.0, block.height
                        ),
                    });
                    self.forget_peer(peer, Penalty::None);
                }
                return Ok(());
            }
        }
        // 切り詰められて、まだピアの先端に届いていなければ、続きを頼む
        let statistics = self.peers.get(&peer).and_then(|entry| entry.statistics);
        if let Some(statistics) = statistics
            && received < count as usize
            && statistics.height > self.tip.height
        {
            self.pull(peer, &statistics);
        }
        Ok(())
    }

    /// 受け取った枝の最後のブロックの時刻が、今のネットワーク時刻 + `maxBlockFutureTime` より先か（catapult の
    /// `BlockchainCheckConsumer`）。先なら枝ごと使わない。時計の合っているピアなら、少し待てば通るので外さない
    pub(super) fn too_far_in_future(&mut self, peer: PeerId, blocks: &[(Block, Vec<u8>)]) -> bool {
        let Some((last, _)) = blocks.last() else {
            return false;
        };
        let now = self
            .parameters
            .timestamp_at(self.env.now())
            .map_or(0, |now| now.0);
        let too_far = last.timestamp > now.saturating_add(self.config.max_block_future_time);
        if too_far {
            let (height, ahead) = (last.height, last.timestamp - now);
            self.notify(Notice::TooFarInFuture {
                peer,
                height,
                ahead,
            });
        }
        too_far
    }

    /// 分かれ目 `common` から先を、ピアの枝 `blocks` に取り替える。通らないか、スコアが元より高くならなければ、
    /// 元の枝に戻してピアを外す
    pub(super) async fn switch(
        &mut self,
        peer: PeerId,
        common: u64,
        blocks: Vec<(Block, Vec<u8>)>,
    ) -> Result<(), ChainError> {
        let (old_tip, old_score) = (self.tip, self.executor.score().unwrap_or(0));
        let mut originals = Vec::new();
        for height in common + 1..=old_tip.height {
            originals.push(
                self.store
                    .block(height)
                    .await?
                    .ok_or("元の枝のブロックがありません")?,
            );
        }
        // 外れる元の枝は、巻き戻しと同じコミットで孤立ブロックの表に残す。元の枝に戻したら、当て直すときに消える
        let orphans = originals
            .iter()
            .map(|bytes| {
                let block = Block::from_bytes(bytes)?;
                Ok((block.height, block.hash().0, bytes.as_slice()))
            })
            .collect::<Result<Vec<_>, ChainError>>()?;
        self.rewind(common, &orphans).await?;
        let mut failure = None;
        // 枝が正しくないか、スコアが高くないなら罰する。こちらの都合で取り替えられなかったなら罰さない
        let mut penalty = Penalty::Failure;
        for (block, bytes) in blocks {
            if let Err(error) = self.accept(&block, bytes, false).await {
                penalty = if is_invalid(&error) {
                    Penalty::Failure
                } else {
                    Penalty::None
                };
                failure = Some(format!("高さ {}: {error}", block.height));
                break;
            }
        }
        let new_score = self.executor.score().unwrap_or(0);
        if failure.is_none() && new_score > old_score {
            self.notify(Notice::Switched {
                common,
                old: old_tip,
                new: self.tip,
                peer,
            });
            return Ok(());
        }
        self.notify(Notice::PeerDropped {
            peer,
            message: format!(
                "ピア {} の枝に取り替えられないので、元の枝に戻してピアを外します: {}",
                peer.0,
                failure.unwrap_or_else(|| format!(
                    "スコアが {new_score} で、元の {old_score} より高くない"
                ))
            ),
        });
        self.rewind(common, &[]).await?;
        for bytes in originals {
            let block = Block::from_bytes(&bytes)?;
            self.accept(&block, bytes, false).await?;
        }
        self.forget_peer(peer, penalty);
        Ok(())
    }

    /// DB とメモリの状態を高さ `common` まで巻き戻す。DB の `common` より上のブロックは消え、`orphans` は
    /// 同じコミットで孤立ブロックの表に入る。チェックポイントが `common` より下なら、そこから `common` までの
    /// しまったブロックを当て直す
    pub(super) async fn rewind(
        &mut self,
        common: u64,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<(), ChainError> {
        let (checkpoint, meta) = self
            .store
            .checkpoint_at_or_below(common)
            .await?
            .ok_or("巻き戻せるチェックポイントがありません")?;
        let rows = self.store.changes_above(checkpoint).await?;
        let mut kept = Vec::new();
        for height in checkpoint + 1..=common {
            kept.push(
                self.store
                    .block(height)
                    .await?
                    .ok_or("当て直すブロックがありません")?,
            );
        }
        let grouping = self.config.finalization.voting_set_grouping;
        let voters_from = u32::try_from(common / grouping + 3)?;
        self.store.rollback(common, voters_from, orphans).await?;
        self.executor.revert(rows, &meta)?;
        let lifetime = self
            .config
            .max_transaction_lifetime
            .max(self.config.max_bonded_transaction_lifetime);
        let (parent, statistics, tip) =
            context(self.store, &mut self.executor, self.parameters, lifetime).await?;
        if self.executor.state_hash() != parent.state_hash {
            // 戻せなかったら、DB から丸ごと読み直す（遅いが確か）
            self.notify(Notice::Progress {
                message: "巻き戻した根が合わないので、DB から読み直します".to_owned(),
                warning: true,
            });
            let loaded = load_from(
                self.store,
                self.config.clone(),
                self.parameters,
                self.executor.is_partial(),
            )
            .await?;
            self.executor = loaded.executor;
        }
        self.generation_hash = parent.generation_hash();
        self.parent = parent;
        self.statistics = statistics;
        self.tip = tip;
        for bytes in kept {
            let block = Block::from_bytes(&bytes)?;
            self.accept(&block, bytes, false).await?;
        }
        Ok(())
    }
}
