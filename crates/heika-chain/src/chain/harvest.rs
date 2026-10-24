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
        let heard = self
            .peers
            .values()
            .filter_map(|peer| peer.statistics.map(|statistics| statistics.height));
        if !ready_to_harvest(self.tip.height, self.finalized.height, heard) {
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
        self.broadcast(bytes);
        Ok(())
    }

    /// 足したブロックを、つないでいるピアの全部に押し付ける。返事はない。catapult と同じく、作ったものに加えて、
    /// 押し付けられて受け入れたものも流す（`DispatcherService` の `newBlockSinkSourceMask`）。押し付けてきた
    /// 相手にも送り返すことがあるが、相手はもう持っている高さとして捨てる
    pub(super) fn broadcast(&mut self, bytes: Vec<u8>) {
        let bytes = Arc::new(bytes);
        for &id in self.peers.keys() {
            self.actions
                .push(Action::Command(id, PeerCommand::Push(Arc::clone(&bytes))));
        }
    }

    /// [`Chain::produce_and_accept`] の、作って確かめるまで。状態に当て始めたら `touched` を立てる。返すのは、
    /// 作ったブロック、それを足した先端、ステートメント。
    ///
    /// 未承認の置き場があれば、その候補から [`produce::choose`] で選んで入れる。状態に依る確かめで弾かれた
    /// トランザクションは、[`Action::Dropped`] で知らせて外し、当てかけた状態を戻して選び直す
    pub(super) async fn try_produce(
        &mut self,
        timestamp: u64,
        signing: &PrivateKey,
        vrf_key: &PrivateKey,
        touched: &mut bool,
    ) -> Result<(Block, Tip, BlockStatement), ChainError> {
        let parent = self.harvest_parent();
        let context = parent.context();
        let mut candidates = self
            .pending
            .as_ref()
            .map_or_else(Vec::new, |pending| pending.candidates(timestamp));
        let beneficiary = self.beneficiary.unwrap_or_else(|| {
            Address::from_public_key(
                &PublicKey::from_private_key(signing),
                self.parameters.identifier,
            )
        });
        let signer = PublicKey::from_private_key(signing);
        let mut assemble = self.assemble.clone();
        let harvester = match &assemble {
            Some(_) => match self.executor.harvester_address(&signer) {
                Ok(address) => Some(Address(address)),
                Err(error) => {
                    self.executor.take_missed();
                    self.progress(format!(
                        "高さ {} は、トランザクションを直す口を使わずに作ります: {error}",
                        self.tip.height + 1
                    ));
                    assemble = None;
                    None
                }
            },
            None => None,
        };
        let mut drops = 0;
        loop {
            // 手数料の下限は、置き場が受け付けるときに絞っている
            let (chosen, fee_multiplier) = produce::choose(&candidates, 0);
            let chosen_bytes: Vec<Vec<u8>> = chosen
                .iter()
                .map(|candidate| candidate.bytes.clone())
                .collect();
            let transactions = match (&assemble, harvester) {
                (Some(assemble), Some(harvester)) => {
                    let shares = Address::from_public_key(&signer, self.parameters.identifier)
                        != beneficiary;
                    let slot = produce::Slot {
                        height: self.tip.height + 1,
                        timestamp,
                        signer,
                        harvester,
                        beneficiary,
                        fee_multiplier,
                        inflation: self.config.inflation_at(self.tip.height + 1),
                        beneficiary_percentage: if shares {
                            self.config.harvest_beneficiary_percentage
                        } else {
                            0
                        },
                    };
                    assemble.assemble(&slot, chosen_bytes)
                }
                _ => chosen_bytes,
            };
            let decisions = produce::Decisions {
                timestamp,
                transactions,
                beneficiary,
                fee_multiplier,
            };
            let draft = match produce::draft(
                self.parameters,
                &context,
                signing,
                vrf_key,
                &decisions,
            ) {
                Ok(draft) => draft,
                Err(error) if assemble.is_some() => {
                    self.progress(format!(
                        "高さ {} は、直したトランザクションで組めないので、直す前のもので作ります: {error}",
                        self.tip.height + 1
                    ));
                    assemble = None;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            // アカウントを全部はメモリに持たないなら、要りそうなものを先に読み、足りなければ戻して読み足す
            if self.executor.is_partial() {
                let wanted = self.executor.wanted_for(&draft);
                self.executor.load_wanted(self.store, &wanted)?;
            }
            let mut retries = 0;
            let produced = loop {
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
                    break produced;
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
            };
            let error = match produced {
                Ok((block, statement)) => {
                    let tip = verify_link(Some(self.tip), &block)?;
                    return Ok((block, tip, statement));
                }
                Err(error) => error,
            };
            // 弾かれたのが手数料で選んだものなら外して選び直す。直す口が足したものか、どれか分からなければ、
            // 口を使わずに組み直す
            let failed = self
                .executor
                .failed_transaction()
                .and_then(|index| decisions.transactions.get(index))
                .and_then(|bytes| chosen.iter().find(|candidate| &candidate.bytes == bytes));
            match failed {
                Some(failed) => {
                    if drops == MAX_DROPS {
                        return Err(
                            format!("{MAX_DROPS} 件外しても、まだ弾かれます: {error}").into()
                        );
                    }
                    drops += 1;
                    let hash = failed.hash();
                    self.progress(format!(
                        "高さ {} に入れようとしたトランザクション {hash} を外します: {error}",
                        self.tip.height + 1
                    ));
                    self.actions.push(Action::Dropped(hash));
                    candidates.retain(|candidate| candidate.hash() != hash);
                }
                None if assemble.is_some() => {
                    self.progress(format!(
                        "高さ {} は、直したトランザクションが弾かれたので、直す前のもので作ります: {error}",
                        self.tip.height + 1
                    ));
                    assemble = None;
                }
                None => return Err(error.into()),
            }
            if self.executor.is_partial() {
                self.undo_and_load(&draft, Wanted::default()).await?;
            } else {
                self.reload_executor().await?;
            }
        }
    }
}

/// ピアの言う高さ `heard` から、先端（高さ `tip`）の上でハーベストしてよいか。
///
/// 自分の確定（高さ `finalized`）より後ろのピアは、同じチェーンにいるとは言えない（古いところで止まったノードなど）
/// ので数えない。残りのピアの高さを1つ以上聞いていて、どれも自分より先にいないときだけ作る。始めたばかりで
/// 聞けていないなら待つ。でないと、追いつく前の古い先端の上に、自分だけの枝を作ってしまう
fn ready_to_harvest(tip: u64, finalized: u64, heard: impl Iterator<Item = u64>) -> bool {
    let mut same_chain = heard.filter(|&height| height >= finalized).peekable();
    same_chain.peek().is_some() && same_chain.all(|height| height <= tip)
}

#[cfg(test)]
mod tests {
    use super::ready_to_harvest;

    #[test]
    fn harvests_only_when_no_peer_on_the_chain_is_ahead() {
        let ready = |heights: &[u64]| ready_to_harvest(100, 90, heights.iter().copied());
        assert!(ready(&[100, 99]));
        // 先にいるピアがいれば、追いつくのを待つ
        assert!(!ready(&[100, 101]));
        // まだ聞けていなければ待つ
        assert!(!ready(&[]));
        // 確定より後ろの、古いところで止まったピアだけなら、聞けていないのと同じ
        assert!(!ready(&[10]));
        assert!(ready(&[10, 100]));
        assert!(!ready(&[10, 101]));
    }
}
