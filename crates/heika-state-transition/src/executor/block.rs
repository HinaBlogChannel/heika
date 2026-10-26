//! ブロックごとの処理（手数料、インフレ、期限切れ、Importance、手数料の倍率）。

use super::*;

impl Executor {
    pub(super) fn apply_block_notifications(
        &mut self,
        height: u64,
        block: &Block,
        total_fee: u64,
    ) -> Result<(), ExecError> {
        let harvester = self.add_public_key(&block.signer_public_key, height);
        let beneficiary = block.beneficiary_address.0;
        if harvester != beneficiary {
            self.add_address(beneficiary, height);
        }
        // Beneficiary
        let importance_height = self.config.importance_height(height);
        let forwarded_beneficiary = self.forwarded(&beneficiary)?;
        self.account_mut(&forwarded_beneficiary)?
            .try_update_bucket(importance_height, |bucket| bucket.beneficiary_count += 1);
        // MosaicSupplyInflation: インフレの分は通貨のモザイクの発行量にも足す
        let inflation = self.config.inflation_at(height);
        if inflation > 0 {
            let currency = self.config.currency_mosaic_id;
            self.touch(SubCache::Mosaic, &currency.to_le_bytes());
            self.mosaics
                .get_mut(&currency)
                .ok_or_else(|| invalid("通貨のモザイクがありません"))?
                .supply += inflation;
        }
        // HarvestFee
        let total = total_fee + inflation;
        let network_amount = total * self.config.harvest_network_percentage / 100;
        let beneficiary_amount =
            if self.config.harvest_beneficiary_percentage > 0 && harvester != beneficiary {
                total * self.config.harvest_beneficiary_percentage / 100
            } else {
                0
            };
        let harvester_amount = total - network_amount - beneficiary_amount;
        let currency = self.config.currency_mosaic_id;
        // レシートは、手数料を受け取ったアカウント（Remote ならメインのアカウント）ごとに出す。ハーベストした人には0でも出す
        let to = self.forwarded(&harvester)?;
        self.credit(&to, currency, harvester_amount)?;
        self.statement.add_receipt(ReceiptBody::HarvestFee(change(
            to,
            currency,
            harvester_amount,
        )));
        if network_amount > 0 {
            let sink = self.config.harvest_network_fee_sink.at(height).0;
            let to = self.forwarded(&sink)?;
            self.credit(&to, currency, network_amount)?;
            self.statement.add_receipt(ReceiptBody::HarvestFee(change(
                to,
                currency,
                network_amount,
            )));
        }
        if beneficiary_amount > 0 {
            let to = self.forwarded(&beneficiary)?;
            self.credit(&to, currency, beneficiary_amount)?;
            self.statement.add_receipt(ReceiptBody::HarvestFee(change(
                to,
                currency,
                beneficiary_amount,
            )));
        }
        if inflation > 0 {
            self.statement
                .add_receipt(ReceiptBody::Inflation(ReceiptMosaic {
                    mosaic_id: MosaicId(currency),
                    amount: inflation,
                }));
        }
        // ExpiredHashLockInfo: この高さで切れた、使われなかったロックはハーベストした人のものになる
        // どのロックがこの高さで切れるかは、木から外す予定（expiries）に入っている。全部のロックを見ると、
        // ロックが増えるほどブロックごとに重くなる
        let expired: Vec<(u64, u64)> = self
            .locks_due(height, SubCache::HashLockInfo)
            .iter()
            .filter_map(|key| self.hash_locks.get(key)?.last())
            .filter(|lock| lock.end_height == height && lock.status == LockStatus::Unused)
            .map(|lock| (lock.mosaic_id, lock.amount))
            .collect();
        if !expired.is_empty() {
            let to = self.forwarded(&harvester)?;
            let mut receipts = Vec::new();
            for (mosaic_id, amount) in expired {
                self.credit(&to, mosaic_id, amount)?;
                receipts.push(ReceiptBody::LockHashExpired(change(to, mosaic_id, amount)));
            }
            self.add_sorted_receipts(receipts);
        }
        // ExpiredSecretLockInfo: この高さで切れるロックを持つ履歴のうち、最後が使われていなければ持ち主に返す。
        // 決まった高さでは、処理しないか、最後の終わりがこの高さでなくても返す
        if self.config.skip_secret_lock_expirations.contains(&height) {
            // 触らないので、この高さで切れるものは木に残る
            let stale: Vec<[u8; 32]> = self
                .secret_locks
                .iter()
                .filter(|(_, history)| {
                    history.last().is_some_and(|lock| {
                        lock.status == LockStatus::Unused && lock.end_height == height
                    })
                })
                .map(|(key, _)| *key)
                .collect();
            self.stale_secret_locks.extend(stale);
        } else {
            // この高さで切れるものを持つ履歴は、どれも触ったことになり、木で見直される
            let touched: Vec<[u8; 32]> = self
                .stale_secret_locks
                .iter()
                .filter(|key| {
                    self.secret_locks[*key]
                        .iter()
                        .any(|lock| lock.end_height == height)
                })
                .copied()
                .collect();
            for key in touched {
                self.stale_secret_locks.remove(&key);
                self.touch(SubCache::SecretLockInfo, &key);
            }
            let forced = self.config.force_secret_lock_expirations.contains(&height);
            let refunds: Vec<([u8; 24], u64, u64)> = self
                .locks_due(height, SubCache::SecretLockInfo)
                .iter()
                .filter_map(|key| self.secret_locks.get(key))
                .filter(|history| history.iter().any(|lock| lock.end_height == height))
                .filter_map(|history| history.last())
                .filter(|lock| {
                    lock.status == LockStatus::Unused && (lock.end_height == height || forced)
                })
                .map(|lock| (lock.owner, lock.mosaic_id, lock.amount))
                .collect();
            let mut receipts = Vec::new();
            for (owner, mosaic_id, amount) in refunds {
                self.credit(&owner, mosaic_id, amount)?;
                receipts.push(ReceiptBody::LockSecretExpired(change(
                    owner, mosaic_id, amount,
                )));
            }
            self.add_sorted_receipts(receipts);
        }
        self.add_expiry_receipts(height);
        Ok(())
    }

    /// 期限切れのロックのレシート。catapult はレシートのバイト列の順に並べてから足す（`ExpiredLockInfoObserver`）
    pub(super) fn add_sorted_receipts(&mut self, receipts: Vec<ReceiptBody>) {
        let mut receipts: Vec<_> = receipts
            .into_iter()
            .map(|body| {
                (
                    heika_block::statement::Receipt { version: 1, body }.to_bytes(),
                    body,
                )
            })
            .collect();
        receipts.sort_by(|left, right| left.0.cmp(&right.0));
        for (_, body) in receipts {
            self.statement.add_receipt(body);
        }
    }

    /// モザイクとネームスペースの期限切れのレシート。catapult の `CreateCacheBlockTouchObserver` で、ID の順に出す。
    /// ネームスペースは、猶予に入る高さで期限切れ、猶予が明ける高さで消えたことになる
    pub(super) fn add_expiry_receipts(&mut self, height: u64) {
        let Some(candidates) = self.artifact_expiries.remove(&height) else {
            return;
        };
        let grace = self.config.namespace_grace_period;
        let (mut expired, mut deleted, mut mosaics) = (Vec::new(), Vec::new(), Vec::new());
        // 覚えたあとで期限が延びたり、持ち主が替わったりしたものもあるので、今の期限と照らす
        for artifact in candidates {
            match artifact {
                Artifact::Namespace(id) => {
                    let Some(root) = self.namespaces.get(&id).filter(|root| root.start < height)
                    else {
                        continue;
                    };
                    if root.end == height + grace {
                        expired.push(id);
                    }
                    if root.end == height {
                        deleted.push(id);
                    }
                }
                Artifact::Mosaic(id) => {
                    if self.mosaics.get(&id).is_some_and(|entry| {
                        entry.duration != 0 && entry.start_height + entry.duration == height
                    }) {
                        mosaics.push(id);
                    }
                }
            }
        }
        for id in expired {
            self.statement
                .add_receipt(ReceiptBody::NamespaceExpired(NamespaceId(id)));
        }
        for id in deleted {
            self.statement
                .add_receipt(ReceiptBody::NamespaceDeleted(NamespaceId(id)));
        }
        for id in mosaics {
            self.statement
                .add_receipt(ReceiptBody::MosaicExpired(MosaicId(id)));
        }
    }

    /// catapult の `NemesisSink`。Nemesis のあとは Nemesis の鍵で署名できない。国庫の再発行の高さでだけ、
    /// 設定にある署名を認める。ブロック、トランザクション、連署の署名のどれにも効く
    pub(super) fn check_nemesis_sink(
        &self,
        height: u64,
        signer: &PublicKey,
        signature: &heika_core::signature::Signature,
    ) -> Result<(), ExecError> {
        if *signer != self.config.nemesis_signer_public_key
            || (height == self.config.treasury_reissuance_height
                && self
                    .config
                    .treasury_reissuance_transaction_signatures
                    .contains(signature))
        {
            return Ok(());
        }
        Err(invalid(format!(
            "高さ {height} で Nemesis の鍵の署名 {signature} があります"
        )))
    }

    /// catapult の `EligibleHarvester` のうち、残高。ブロックのトランザクションを当てたあと、手数料を受け取る前の、
    /// リモートならメインのアカウントの残高が、minHarvesterBalance 以上 maxHarvesterBalance 以下であること。
    /// importance が 0 でないことは、当たりを確かめるときに済んでいる
    pub(super) fn check_harvester_balance(&self, signer: &PublicKey) -> Result<(), ExecError> {
        let mut address = self.address_of(signer);
        let account = self
            .accounts
            .get(&address)
            .ok_or_else(|| invalid("ブロックを出した人のアカウントがありません"))?;
        if account.account_type == AccountType::Remote {
            let main = account
                .linked
                .ok_or_else(|| invalid("Remote のアカウントにリンクがありません"))?;
            address = self.address_of(&PublicKey(main));
        }
        let balance = self.accounts.get(&address).map_or(0, |account| {
            account.balance(self.config.harvesting_mosaic_id)
        });
        let (min, max) = (
            self.config.min_harvester_balance,
            self.config.max_harvester_balance,
        );
        if !(min..=max).contains(&balance) {
            return Err(invalid(format!(
                "ブロックを出した人の残高 {balance} が {min}〜{max} の外です"
            )));
        }
        Ok(())
    }

    /// catapult の `ImportanceBlock`。大口のアカウントを見直したあとで数える。
    /// 投票できるのは、投票の鍵を持ち、残高が minVoterBalance 以上のアカウント。
    /// totalVotingBalanceCalculationFix からは、そのブロックのエポックに鍵があるものだけを数える（国庫の分は外さない）
    pub(super) fn check_importance_footer(
        &self,
        height: u64,
        footer: &heika_block::ImportanceFooter,
    ) -> Result<(), ExecError> {
        let actual = self.importance_footer(height);
        let expected = (
            footer.voting_eligible_accounts_count,
            footer.harvesting_eligible_accounts_count,
            footer.total_voting_balance,
        );
        if actual != expected {
            return Err(invalid(format!(
                "importance ブロックの足（投票できる数、ハーベストできる数、投票の残高の合計）が {expected:?} で、求めたものは {actual:?} です"
            )));
        }
        Ok(())
    }

    /// 今の状態で決まる importance ブロックの足（投票できる数、ハーベストできる数、投票の残高の合計）
    pub(super) fn importance_footer(&self, height: u64) -> (u32, u64, u64) {
        let epoch = if height < self.config.total_voting_balance_calculation_fix {
            None
        } else {
            let grouping = self.config.finalization.voting_set_grouping;
            Some(1 + u64::from(!height.is_multiple_of(grouping)) + height / grouping)
        };
        self.voting_footer(epoch)
    }

    /// 足を、`epoch` に投票の鍵を持つアカウントだけで数える。`None` ならエポックで絞らない（catapult のエポック 0）
    pub(super) fn voting_footer(&self, epoch: Option<u64>) -> (u32, u64, u64) {
        let finalization = &self.config.finalization;
        let mosaic = self.config.harvesting_mosaic_id;
        let (mut count, mut total) = (0u32, 0u64);
        // 投票の残高の下限は、大口の下限より高いので、大口の中を見れば足りる
        for address in &self.high_value {
            let Some(account) = self.accounts.get(address) else {
                continue;
            };
            let balance = account.balance(mosaic);
            if account.voting.is_empty() || balance < finalization.min_voter_balance {
                continue;
            }
            if let Some(epoch) = epoch
                && !account.voting.iter().any(|key| {
                    u64::from(key.start_epoch) <= epoch && epoch <= u64::from(key.end_epoch)
                })
            {
                continue;
            }
            count += 1;
            total += balance;
        }
        (count, self.high_value.len() as u64, total)
    }

    /// catapult の `HighValueAccountsUpdater::updateHarvestingAccounts`。触ったアカウントだけを見直す
    pub(super) fn update_high_value(&mut self) {
        let min = self.config.min_harvester_balance;
        let mosaic = self.config.harvesting_mosaic_id;
        for address in &self.touched {
            let Some(account) = self.accounts.get(address) else {
                continue;
            };
            if account.balance(mosaic) >= min {
                self.high_value.insert(*address);
                self.removed.remove(address);
            } else {
                let was = self.high_value.remove(address);
                if was || account.has_history() {
                    self.removed.insert(*address);
                }
            }
        }
    }

    /// catapult の `PosImportanceCalculator::recalculate`。
    pub(super) fn recalculate_importances(&mut self, importance_height: u64) {
        for set in [&self.high_value, &self.removed] {
            self.dirty_accounts.extend(set.iter().copied());
            self.unsaved_accounts.extend(set.iter().copied());
        }
        let grouping = self.config.importance_grouping;
        let previous = |count: u64| {
            let adjustment = grouping * count;
            if importance_height > adjustment {
                importance_height - adjustment
            } else {
                1
            }
        };
        let previous_height = if importance_height == 1 {
            0
        } else {
            previous(1)
        };
        // Activity_Bucket_History_Size - Rollback_Buffer_Size - 1
        let min_height = previous(4);
        let mosaic = self.config.harvesting_mosaic_id;
        let tci = u128::from(self.config.total_chain_importance);
        let percentage = u128::from(self.config.importance_activity_percentage);
        let min_balance = u128::from(self.config.min_harvester_balance);

        struct Summary {
            address: [u8; 24],
            balance: u128,
            fees: u64,
            beneficiaries: u32,
            previous_importance: u64,
        }
        let mut summaries = Vec::with_capacity(self.high_value.len());
        let mut active = 0u128;
        let mut total_fees = 0u64;
        let mut total_beneficiaries = 0u32;
        for address in &self.high_value {
            let account = &self.accounts[address];
            let mut summary = Summary {
                address: *address,
                balance: u128::from(account.balance(mosaic)),
                fees: 0,
                beneficiaries: 0,
                previous_importance: 0,
            };
            for bucket in &account.buckets {
                if bucket.start_height < min_height {
                    break;
                }
                summary.fees += bucket.total_fees_paid;
                summary.beneficiaries += bucket.beneficiary_count;
                if bucket.start_height == previous_height {
                    summary.previous_importance = bucket.raw_score;
                }
            }
            active += summary.balance;
            total_fees += summary.fees;
            total_beneficiaries += summary.beneficiaries;
            summaries.push(summary);
        }

        let mut parts = Vec::with_capacity(summaries.len());
        let mut total_activity = 0u64;
        for summary in &summaries {
            let stake = (tci * summary.balance * (100 - percentage) / (active * 100)) as u64;
            let mut fee = 0u128;
            if percentage > 0 && total_fees > 0 {
                fee = tci * u128::from(summary.fees) * (percentage * min_balance * 8)
                    / (u128::from(total_fees) * 1000)
                    / summary.balance;
            }
            let mut beneficiary = 0u128;
            if percentage > 0 && total_beneficiaries > 0 {
                beneficiary =
                    tci * u128::from(summary.beneficiaries) * (percentage * min_balance * 2)
                        / (u128::from(total_beneficiaries) * 1000)
                        / summary.balance;
            }
            let activity = (fee + beneficiary) as u64;
            total_activity = total_activity.wrapping_add(activity);
            parts.push((stake, activity));
        }

        let target_activity =
            self.config.total_chain_importance * self.config.importance_activity_percentage / 100;
        for (summary, (stake, activity)) in summaries.iter().zip(parts) {
            // 活動の点の掛け算は、catapult でも u64 のままで、あふれると折り返す
            let importance = match activity
                .wrapping_mul(target_activity)
                .checked_div(total_activity)
            {
                Some(share) => stake + share,
                None if percentage > 0 => {
                    stake * 100 / (100 - self.config.importance_activity_percentage)
                }
                None => stake,
            };
            let account = self
                .accounts
                .get_mut(&summary.address)
                .expect("high value account exists");
            // FinalizeAccountActivity: その高さの記録がなければ作って、点数を入れる
            if account.buckets[0].start_height < importance_height {
                account.push_bucket(Bucket {
                    start_height: importance_height,
                    ..Bucket::default()
                });
            }
            account.buckets[0].raw_score = importance;
            let effective = if importance_height == 1 {
                importance
            } else {
                importance.min(summary.previous_importance)
            };
            account.push_snapshot(Snapshot {
                importance: effective,
                height: importance_height,
            });
        }

        // processHighValueRemovedAccounts
        let removed = std::mem::take(&mut self.removed);
        for address in removed {
            let Some(account) = self.accounts.get_mut(&address) else {
                continue;
            };
            if account
                .buckets
                .iter()
                .any(|bucket| bucket.start_height == importance_height)
            {
                account.pop_bucket();
            }
            account.push_bucket(Bucket::default());
            account.push_snapshot(Snapshot::default());
            if account.has_history() {
                self.removed.insert(address);
            }
        }
    }

    /// catapult の `BlockStatisticObserver`。直近のブロックの手数料の倍率の中央値
    pub(super) fn update_dynamic_fee_multiplier(&mut self, fee_multiplier: u32) {
        let count = self.config.max_difficulty_blocks as usize;
        self.fee_multipliers.push_back(fee_multiplier);
        while self.fee_multipliers.len() > count {
            self.fee_multipliers.pop_front();
        }
        let mut values: Vec<u32> = self
            .fee_multipliers
            .iter()
            .copied()
            .filter(|&value| value != 0)
            .collect();
        values.resize(count, self.config.default_dynamic_fee_multiplier);
        let median = count / 2;
        values.select_nth_unstable(median);
        self.dynamic_fee_multiplier = values[median];
    }
}
