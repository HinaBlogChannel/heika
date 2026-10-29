//! ブロックを確かめて当て、保存にコミットして先端にする。

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// 当てかけたブロックを、先端のチェックポイントまで戻し、読んでいなかった `missed` を読み足す（アカウントを
    /// 全部はメモリに持たないとき）
    pub(super) async fn undo_and_load(&mut self, missed: Wanted) -> Result<(), ChainError> {
        let meta = match self.store.checkpoint_at_or_below(self.tip.height).await? {
            Some((height, meta)) if height == self.tip.height => meta,
            _ => return Err("当て直すのに、先端のチェックポイントがありません".into()),
        };
        self.executor.undo_attempt(self.store, &meta)?;
        self.executor.load_wanted(self.store, &missed)?;
        Ok(())
    }

    /// 当てる途中で止まった状態を捨て、最後にコミットしたところから読み直す
    pub(super) async fn reload_executor(&mut self) -> Result<(), ChainError> {
        let loaded = load_from(
            self.store,
            self.config.clone(),
            self.parameters,
            self.executor.is_partial(),
        )
        .await?;
        self.executor = loaded.executor;
        Ok(())
    }

    /// 次のブロックを確かめて当て、DB に書いてコミットする。当てる途中で弾いたら、DB から状態を読み直す
    /// `pushed` なら、接続してきたピアが押し付けたもの（知らせに書くだけ）
    pub(super) async fn accept(
        &mut self,
        block: &Block,
        bytes: Vec<u8>,
        pushed: bool,
    ) -> Result<(), ChainError> {
        let tip = verify_link(Some(self.tip), block).map_err(invalid)?;
        if block.height == self.finalized.height && tip.hash != self.finalized.hash {
            return Err(invalid("ファイナライズされたブロックと違います"));
        }
        let expected = difficulty(self.statistics.make_contiguous(), self.parameters);
        if block.difficulty != expected {
            return Err(invalid(format!(
                "難易度が {} で、直前のブロックから求めた {expected} と合いません",
                block.difficulty
            )));
        }
        // アカウントを全部はメモリに持たないなら、要りそうなものを先に読む。足りなければ記録されるので、
        // 読んでから確かめ直すか、当てたものを戻して当て直す
        if self.executor.is_partial() {
            let wanted = self.executor.wanted_for(block);
            self.executor.load_wanted(self.store, &wanted)?;
        }
        let generation_hash = loop {
            let checked = self.executor.check_harvester(
                &self.parent,
                &self.generation_hash,
                block,
                self.parameters,
            );
            let missed = self.executor.take_missed();
            if missed.is_empty() {
                break checked.map_err(invalid)?;
            }
            self.executor.load_wanted(self.store, &missed)?;
        };
        let mut retries = 0;
        loop {
            let error = match self.apply(block, bytes.clone()).await {
                Ok(()) => break,
                Err(error) => error,
            };
            match error.downcast::<Missed>() {
                Ok(missed) if retries < MAX_RETRIES => {
                    retries += 1;
                    self.undo_and_load(missed.0).await?;
                }
                result => {
                    let error: ChainError = match result {
                        Ok(missed) => format!(
                            "{MAX_RETRIES} 回当て直しても、読んでいない状態が {} 個あります",
                            missed.0.len()
                        )
                        .into(),
                        Err(error) => error,
                    };
                    // 状態は途中まで当たっているので、最後にコミットしたところから読み直す
                    self.reload_executor().await?;
                    return Err(error);
                }
            }
        }
        if retries > 0 {
            self.progress(format!(
                "高さ {} は、読んでいない状態があったので {retries} 回当て直しました",
                block.height
            ));
        }
        self.advance(block, tip, generation_hash);
        self.notify(Notice::Accepted {
            height: block.height,
            transactions: block.transactions().count(),
            hash: tip.hash,
            pushed,
        });
        Ok(())
    }

    /// コミットしたブロック `block` を先端にする
    pub(super) fn advance(&mut self, block: &Block, tip: Tip, generation_hash: GenerationHash) {
        // 要るものだけを読む形なら、読み込んだものを手放す。ブロックをまたいで持つのは読み口のキャッシュ
        self.executor.release_loaded();
        if self.pending.is_some() && block.transactions().next().is_some() {
            let seed = &self.parameters.generation_hash_seed;
            let hashes = block
                .transactions()
                .filter_map(|bytes| Transaction::from_bytes(bytes).ok())
                .map(|transaction| transaction.hash(seed))
                .collect();
            self.actions.push(Action::Included(hashes));
        }
        self.parent = block.clone();
        self.generation_hash = generation_hash;
        self.tip = tip;
        self.statistics.push_back(BlockStatistic::from(block));
        if self.statistics.len() > self.parameters.max_difficulty_blocks {
            self.statistics.pop_front();
        }
        self.accepted_at.push_back((block.height, self.env.now()));
        if self.accepted_at.len() > 16 {
            self.accepted_at.pop_front();
        }
    }

    pub(super) async fn apply(&mut self, block: &Block, bytes: Vec<u8>) -> Result<(), ChainError> {
        let applied = self.executor.apply(block);
        let state_hash = self.executor.state_hash();
        // まだ読んでいないアカウントを引いていたら、結果は使えない（コミットせずに当て直す）
        let missed = self.executor.take_missed();
        if !missed.is_empty() {
            return Err(Box::new(Missed(missed)));
        }
        applied.map_err(invalid)?;
        if state_hash != block.state_hash {
            return Err(invalid("StateHash が合いません"));
        }
        let statement = self.executor.take_statement();
        if statement.merkle_hash() != block.receipts_hash {
            return Err(invalid("ReceiptsHash が合いません"));
        }
        self.commit(block, &bytes, statement).await
    }

    /// 当てたあとの状態の変化を、ブロック `block`（バイト列 `bytes`）とステートメントと一緒に DB に書いてコミットする
    pub(super) async fn commit(
        &mut self,
        block: &Block,
        bytes: &[u8],
        statement: BlockStatement,
    ) -> Result<(), ChainError> {
        let height = block.height;
        let changes = self.executor.take_changes();
        let state: Vec<(Vec<u8>, Option<Vec<u8>>)> = changes
            .puts
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .chain(changes.deletes.into_iter().map(|key| (key, None)))
            .collect();
        let nodes = self.executor.take_node_changes();
        // エポック E の投票者は、E - 1 の最後の高さ（高さ 1 か、区切りの倍数）の状態で決まる
        let grouping = self.config.finalization.voting_set_grouping;
        let next_epoch = if height == 1 {
            Some(2)
        } else if height.is_multiple_of(grouping) {
            u32::try_from(height / grouping + 2).ok()
        } else {
            None
        };
        let voters = next_epoch.map(|epoch| (epoch, self.executor.voting_set(epoch).encode()));
        self.store
            .commit_block(BlockWrite {
                height,
                hash: block.hash().0,
                bytes,
                state,
                nodes,
                statement: statement.to_bytes(),
                voters,
                meta: self.executor.encode_meta(),
            })
            .await
    }
}
