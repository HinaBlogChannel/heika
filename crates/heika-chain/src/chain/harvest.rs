//! ハーベストする。当たりの時刻を求め、時刻が来たらブロックを作って先端に足し、ピアに配る。

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// 自分の時計（UTC）の、Nemesis からのミリ秒
    pub(super) fn network_now(&self) -> u64 {
        let elapsed = self
            .env
            .now()
            .duration_since(self.parameters.epoch())
            .unwrap_or_default()
            .as_millis();
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }

    /// 時刻 `timestamp` のブロックを、自分の時計（UTC）で受け入れてよくなる時刻（`maxBlockFutureTime` だけ前）
    pub(super) fn due_at(&self, timestamp: u64) -> SystemTime {
        self.parameters.epoch()
            + Duration::from_millis(timestamp.saturating_sub(self.config.max_block_future_time))
    }

    /// ハーベストするなら、先端が変わったときに当たりの一番早い時刻を求め直し、その時刻のブロックを自分の時計
    /// （UTC）で受け入れてよくなったら作る（`docs/archive/tip.md` の「ハーベストするときの時刻」）。同期の途中は待つ
    pub(super) async fn harvest(&mut self) -> Result<(), ChainError> {
        if self.harvesters.is_empty() || !matches!(self.sync, Sync::Idle) {
            return Ok(());
        }
        // ピアの言う高さを聞いていて、どのピアも自分より先にいないときだけ作る。始めたばかりで統計がまだなら
        // 待つ（でないと、追いつく前の古い先端の上に、自分だけの枝を作ってしまう）
        let heard: Vec<u64> = self
            .peers
            .values()
            .filter_map(|peer| peer.statistics.map(|statistics| statistics.height))
            .collect();
        if heard.is_empty() || heard.iter().any(|&height| height > self.tip.height) {
            return Ok(());
        }
        let harvesters = Arc::clone(&self.harvesters);
        self.harvest_with(&harvesters).await
    }

    pub(super) async fn harvest_with(
        &mut self,
        harvesters: &[(PrivateKey, PrivateKey)],
    ) -> Result<(), ChainError> {
        if self
            .planned
            .as_ref()
            .is_none_or(|planned| planned.parent != self.tip.hash)
        {
            let slot = self.plan_harvest(harvesters)?;
            self.planned = Some(Planned {
                parent: self.tip.hash,
                slot,
            });
            if let Some((timestamp, _)) = slot {
                let seconds = (timestamp - self.parent.timestamp) / 1000;
                if seconds <= HARVEST_ANNOUNCE {
                    self.progress(format!(
                        "高さ {} の当たりは親から {seconds} 秒です",
                        self.tip.height + 1
                    ));
                }
                let due = self.due_at(timestamp);
                self.actions.push(Action::WakeAt(due));
            }
        }
        let Some((timestamp, harvester)) = self.planned.as_ref().and_then(|planned| planned.slot)
        else {
            return Ok(());
        };
        if self.due_at(timestamp) > self.env.now() {
            return Ok(());
        }
        // 作るのは1回だけ。通らなくても、次の先端で求め直す
        if let Some(planned) = &mut self.planned {
            planned.slot = None;
        }
        // 当たりの時刻が今より前なら（親が遅れて届いた、先端が古い）、今の時刻にする。どちらでも当たりで、
        // catapult も試す時刻（今）を付ける
        let timestamp = timestamp.max(self.network_now());
        let (signing, vrf_key) = &harvesters[harvester];
        self.produce_and_accept(timestamp, signing, vrf_key).await
    }

    /// 先端の上で作るブロックの親まわり（[`produce::Parent`] に要るもの）の写し
    pub(super) fn harvest_parent(&self) -> HarvestParent {
        HarvestParent {
            block: self.parent.clone(),
            recent: self.statistics.iter().copied().collect(),
            generation_hash: self.generation_hash,
            importance_hash: self.tip.importance_hash,
        }
    }

    /// 先端の上で、`harvesters` のうち当たりが一番早い時刻と鍵の番号。[`HARVEST_HORIZON`] までになければ `None`。
    /// 求められない鍵は、わけが変わったときだけ知らせる
    pub(super) fn plan_harvest(
        &mut self,
        harvesters: &[(PrivateKey, PrivateKey)],
    ) -> Result<Option<(u64, usize)>, ChainError> {
        let parent = self.harvest_parent();
        let context = parent.context();
        let until = parent.block.timestamp + HARVEST_HORIZON;
        let mut best: Option<(u64, usize)> = None;
        for (index, (signing, vrf_key)) in harvesters.iter().enumerate() {
            // アカウントを全部はメモリに持たないなら、引いたアカウントを読んで求め直す
            let mut retries = 0;
            let found = loop {
                let found = produce::earliest_hit(
                    &self.executor,
                    self.parameters,
                    &context,
                    signing,
                    vrf_key,
                    until,
                )
                .map_err(ChainError::from);
                let missed = self.executor.take_missed();
                if missed.is_empty() {
                    break found;
                }
                if retries == MAX_RETRIES {
                    break Err(format!(
                        "{MAX_RETRIES} 回読み足しても、読んでいない状態が {} 個あります",
                        missed.len()
                    )
                    .into());
                }
                retries += 1;
                self.executor.load_wanted(self.store, &missed)?;
            };
            match found {
                Ok(Some(timestamp)) => {
                    if best.is_none_or(|(earliest, _)| timestamp < earliest) {
                        best = Some((timestamp, index));
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let message = format!("鍵 {index} でハーベストできません: {error}");
                    if self.harvest_warning.as_ref() != Some(&message) {
                        self.notify(Notice::Progress {
                            message: message.clone(),
                            warning: true,
                        });
                        self.harvest_warning = Some(message);
                    }
                }
            }
        }
        Ok(best)
    }

    /// 先端の上に、時刻 `timestamp` のトランザクションのないブロックを作って先端に足し、つないでいるピアに配る。
    /// 作ったときの状態をそのまましまう（当て直さない）。作れなければ知らせ、当てかけていたら状態を戻す。しまえ
    /// なければ（DB の誤り）エラーを返す
    pub(super) async fn produce_and_accept(
        &mut self,
        timestamp: u64,
        signing: &PrivateKey,
        vrf_key: &PrivateKey,
    ) -> Result<(), ChainError> {
        let parent_timestamp = self.parent.timestamp;
        let height = self.tip.height + 1;
        let mut touched = false;
        let produced = self
            .try_produce(timestamp, signing, vrf_key, &mut touched)
            .await;
        let (block, tip, statement) = match produced {
            Ok(produced) => produced,
            Err(error) => {
                self.notify(Notice::Progress {
                    message: format!("高さ {height} のブロックを作れませんでした: {error}"),
                    warning: true,
                });
                if touched {
                    self.reload_executor().await?;
                }
                return Ok(());
            }
        };
        let bytes = block.as_bytes().to_vec();
        self.commit(&block, &bytes, statement).await?;
        self.advance(&block, tip, block.generation_hash());
        self.notify(Notice::Produced {
            height: block.height,
            hash: tip.hash,
            seconds: (block.timestamp - parent_timestamp) / 1000,
            peers: self.peers.len(),
        });
        // catapult は押し付けられたブロックを中継しないので、つないでいるピアの全部に配る。返事はない
        let bytes = Arc::new(bytes);
        for &id in self.peers.keys() {
            self.actions
                .push(Action::Command(id, PeerCommand::Push(Arc::clone(&bytes))));
        }
        Ok(())
    }

    /// [`Chain::produce_and_accept`] の、作って確かめるまで。状態に当て始めたら `touched` を立てる。返すのは、
    /// 作ったブロック、それを足した先端、ステートメント
    pub(super) async fn try_produce(
        &mut self,
        timestamp: u64,
        signing: &PrivateKey,
        vrf_key: &PrivateKey,
        touched: &mut bool,
    ) -> Result<(Block, Tip, BlockStatement), ChainError> {
        let parent = self.harvest_parent();
        let context = parent.context();
        let decisions = produce::Decisions {
            timestamp,
            transactions: Vec::new(),
            beneficiary: Address::from_public_key(
                &PublicKey::from_private_key(signing),
                self.parameters.identifier,
            ),
            fee_multiplier: 0,
        };
        let draft = produce::draft(self.parameters, &context, signing, vrf_key, &decisions)?;
        // アカウントを全部はメモリに持たないなら、要りそうなものを先に読み、足りなければ戻して読み足す
        if self.executor.is_partial() {
            let wanted = self.executor.wanted_for(&draft);
            self.executor.load_wanted(self.store, &wanted)?;
        }
        let mut retries = 0;
        loop {
            *touched = true;
            let produced = produce::produce_with_statement(
                &mut self.executor,
                self.parameters,
                &context,
                signing,
                vrf_key,
                &decisions,
            );
            let missed = self.executor.take_missed();
            if missed.is_empty() {
                let (block, statement) = produced?;
                let tip = verify_link(Some(self.tip), &block)?;
                return Ok((block, tip, statement));
            }
            if retries == MAX_RETRIES {
                return Err(format!(
                    "{MAX_RETRIES} 回作り直しても、読んでいない状態が {} 個あります",
                    missed.len()
                )
                .into());
            }
            retries += 1;
            self.undo_and_load(&draft, missed).await?;
        }
    }
}
