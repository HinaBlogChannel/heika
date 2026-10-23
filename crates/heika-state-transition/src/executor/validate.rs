//! トランザクションを当てる前に確かめる（catapult の validator のうち、通らないと状態が変わってしまうもの）。

use super::*;

impl Executor {
    /// トランザクションを当てる前の、トランザクション全体についての確かめ。catapult の `TransactionNotification`、
    /// `TransactionDeadlineNotification`、`TransactionFeeNotification` の validator
    pub(super) fn check_transaction(
        &self,
        height: u64,
        timestamp: u64,
        transaction: &Transaction,
        hash: &Hash256,
        size: u64,
        fee: u64,
    ) -> Result<(), ExecError> {
        // TransactionFee
        if fee > transaction.fee || transaction.fee > u64::from(u32::MAX) * size {
            return Err(invalid(format!(
                "トランザクション {hash} の手数料 {fee} が上限 {} に合いません",
                transaction.fee
            )));
        }
        // Deadline。Nemesis はハッシュを決め打ちしているので見ない
        let bonded = matches!(transaction.body, Body::AggregateBonded(_));
        if height > 1 {
            let lifetime = if bonded {
                self.config.max_bonded_transaction_lifetime
            } else {
                self.config.max_transaction_lifetime
            };
            if transaction.deadline < timestamp || transaction.deadline > timestamp + lifetime {
                return Err(invalid(format!(
                    "トランザクション {hash} の期限 {} がブロックの時刻 {timestamp} に合いません",
                    transaction.deadline
                )));
            }
        }
        // UniqueTransactionHash
        if self.recent_hashes.contains(&hash.0) {
            return Err(invalid(format!(
                "トランザクション {hash} はもう入っています"
            )));
        }
        // MultisigPermittedOperation: 連署者のいるアカウントは、外側で直接署名できない
        let signer = self.address_of(&transaction.signer_public_key);
        if self.is_multisig(&signer) {
            return Err(invalid(format!(
                "マルチシグの {} が直接署名しています",
                Address(signer)
            )));
        }
        // AggregateHashPresent: ボンデッドは、使っていない、切れていないハッシュロックがあること
        if bonded {
            let active = self
                .hash_locks
                .get(&hash.0)
                .and_then(|history| history.last())
                .is_some_and(|lock| lock.status == LockStatus::Unused && height < lock.end_height);
            if !active {
                return Err(invalid(format!(
                    "アグリゲート {hash} の生きているロックがありません"
                )));
            }
        }
        Ok(())
    }

    /// `deadline` が期限のトランザクションのハッシュを覚える
    pub(super) fn remember_hash(&mut self, deadline: u64, hash: [u8; 32]) {
        if self.recent_hashes.insert(hash) {
            self.hash_deadlines.entry(deadline).or_default().push(hash);
        }
    }

    /// 期限が `timestamp` より前のハッシュを捨てる。そういうトランザクションは期限の確かめで弾かれるので、
    /// 覚えていなくても二度入れにはならない（catapult はもっと長く覚えているが、弾くものは同じ）
    pub(super) fn forget_expired_hashes(&mut self, timestamp: u64) {
        let kept = self.hash_deadlines.split_off(&timestamp);
        for (_, hashes) in std::mem::replace(&mut self.hash_deadlines, kept) {
            for hash in hashes {
                self.recent_hashes.remove(&hash);
            }
        }
    }

    /// 実行したブロックのトランザクションのハッシュを覚え直す。途中から実行するときに、直前のブロックを
    /// 古い順に渡す（期限の上限はボンデッドの 48 時間なので、最後のブロックの時刻からそれだけさかのぼれば足りる）
    pub fn remember_transactions(&mut self, block: &Block) -> Result<(), ExecError> {
        for bytes in block.transactions() {
            let transaction = Transaction::from_bytes(bytes)
                .map_err(|error| invalid(format!("トランザクションが読めません: {error}")))?;
            let hash = transaction.hash(&self.generation_hash_seed);
            self.remember_hash(transaction.deadline, hash.0);
        }
        Ok(())
    }

    /// 連署者のいるアカウントか。catapult では、連署者でしかないアカウントもマルチシグの表に入る
    pub(super) fn is_multisig(&self, address: &[u8; 24]) -> bool {
        self.multisigs
            .get(address)
            .is_some_and(|entry| !entry.cosignatories.is_empty())
    }

    /// validator がするアドレスの解決。ステートメントには残さない。解決できなければそのまま
    pub(super) fn peek_address(&self, address: &UnresolvedAddress) -> [u8; 24] {
        match address.namespace_id().map(|id| self.alias_of(id.0)) {
            Some(Ok(Alias::Address(resolved))) => resolved,
            _ => address.0,
        }
    }

    /// アグリゲートの外側の署名者と連署者
    pub(super) fn cosigners(
        &self,
        transaction: &Transaction,
        aggregate: &Aggregate,
    ) -> BTreeSet<[u8; 24]> {
        std::iter::once(&transaction.signer_public_key)
            .chain(
                aggregate
                    .cosignatures()
                    .iter()
                    .map(|cosignature| &cosignature.signer_public_key),
            )
            .map(|key| self.address_of(key))
            .collect()
    }

    /// 中のトランザクションに要る署名者。署名者と、catapult の `additionalRequiredCosignatories`
    /// （メタデータの対象の持ち主、マルチシグに足す連署者）
    pub(super) fn required_signers(&self, inner: &EmbeddedTransaction) -> BTreeSet<[u8; 24]> {
        let mut required = BTreeSet::from([self.address_of(&inner.signer_public_key)]);
        match &inner.body {
            Body::AccountMetadata(metadata) => {
                required.insert(self.peek_address(&metadata.target_address));
            }
            Body::MosaicMetadata(metadata) => {
                required.insert(self.peek_address(&metadata.metadata.target_address));
            }
            Body::NamespaceMetadata(metadata) => {
                required.insert(self.peek_address(&metadata.metadata.target_address));
            }
            Body::MultisigAccountModification(modification) => {
                for address in modification.address_additions.iter() {
                    required.insert(self.peek_address(address));
                }
            }
            _ => {}
        }
        required
    }

    /// MultisigAggregateEligibleCosignatories: 連署者はみな、どれかの中のトランザクションに要る署名者か、
    /// （マルチシグをたどって）その連署者であること。中のトランザクションを当てる前の状態で見る
    pub(super) fn check_eligible_cosigners(
        &self,
        cosigners: &BTreeSet<[u8; 24]>,
        aggregate: &Aggregate,
    ) -> Result<(), ExecError> {
        let mut eligible = BTreeSet::new();
        for inner in aggregate.transactions() {
            for address in self.required_signers(inner) {
                self.mark_eligible(address, &mut eligible, 0);
            }
        }
        match cosigners
            .iter()
            .find(|address| !eligible.contains(*address))
        {
            Some(address) => Err(invalid(format!(
                "アグリゲートの連署者 {} は要りません",
                Address(*address)
            ))),
            None => Ok(()),
        }
    }

    pub(super) fn mark_eligible(
        &self,
        address: [u8; 24],
        eligible: &mut BTreeSet<[u8; 24]>,
        depth: usize,
    ) {
        match self.multisigs.get(&address) {
            Some(entry) if !entry.cosignatories.is_empty() => {
                // 輪になったマルチシグで止まらなくならないように（正しいチェーンでは深さは3まで）
                if depth < MAX_MULTISIG_WALK {
                    for cosignatory in &entry.cosignatories {
                        self.mark_eligible(*cosignatory, eligible, depth + 1);
                    }
                }
            }
            _ => {
                eligible.insert(address);
            }
        }
    }

    /// MultisigAggregateSufficientCosignatories: 中のトランザクションに要る署名者が、みな連署しているか、
    /// マルチシグなら連署者のうち要る数が（たどって）連署していること
    pub(super) fn check_sufficient_cosigners(
        &self,
        cosigners: &BTreeSet<[u8; 24]>,
        inner: &EmbeddedTransaction,
    ) -> Result<(), ExecError> {
        let operation = match &inner.body {
            Body::MultisigAccountModification(modification)
                if !modification.address_deletions.is_empty() =>
            {
                if modification.address_additions.is_empty() {
                    MultisigOperation::Removal
                } else {
                    MultisigOperation::Both
                }
            }
            _ => MultisigOperation::Normal,
        };
        for address in self.required_signers(inner) {
            if !self.is_satisfied(&address, operation, cosigners, 0) {
                return Err(invalid(format!("{} の連署が足りません", Address(address))));
            }
        }
        Ok(())
    }

    pub(super) fn is_satisfied(
        &self,
        address: &[u8; 24],
        operation: MultisigOperation,
        cosigners: &BTreeSet<[u8; 24]>,
        depth: usize,
    ) -> bool {
        let Some(entry) = self
            .multisigs
            .get(address)
            .filter(|entry| !entry.cosignatories.is_empty())
        else {
            return cosigners.contains(address);
        };
        if depth >= MAX_MULTISIG_WALK {
            return false;
        }
        let approvers = entry
            .cosignatories
            .iter()
            .filter(|cosignatory| self.is_satisfied(cosignatory, operation, cosigners, depth + 1))
            .count();
        let required = match operation {
            MultisigOperation::Normal => entry.min_approval,
            MultisigOperation::Removal => entry.min_removal,
            MultisigOperation::Both => entry.min_approval.max(entry.min_removal),
        };
        approvers as u64 >= u64::from(required)
    }

    /// RequiredMosaic: モザイクが生きていて、持ち主が `owner` であること
    pub(super) fn check_mosaic_owner(
        &self,
        height: u64,
        id: u64,
        owner: &[u8; 24],
    ) -> Result<&MosaicEntry, ExecError> {
        let entry = self
            .mosaics
            .get(&id)
            .filter(|entry| entry.is_active(height))
            .ok_or_else(|| invalid(format!("モザイク {id:016X} は生きていません")))?;
        if entry.owner != *owner {
            return Err(invalid(format!(
                "モザイク {id:016X} の持ち主は {} ではありません",
                Address(*owner)
            )));
        }
        Ok(entry)
    }

    /// RequiredNamespace: ネームスペースのルートが猶予を除いて生きていて、持ち主が `owner` であること
    pub(super) fn check_namespace_owner(
        &self,
        height: u64,
        id: u64,
        owner: &[u8; 24],
    ) -> Result<(), ExecError> {
        let root = self
            .namespace_paths
            .get(&id)
            .and_then(|path| self.namespaces.get(&path[0]))
            .ok_or_else(|| invalid(format!("ネームスペース {id:016X} がありません")))?;
        if !self.is_active_excluding_grace(root, height) {
            return Err(invalid(format!("ネームスペース {id:016X} は切れています")));
        }
        if root.owner != *owner {
            return Err(invalid(format!(
                "ネームスペース {id:016X} の持ち主は {} ではありません",
                Address(*owner)
            )));
        }
        Ok(())
    }

    pub(super) fn is_active_excluding_grace(&self, root: &RootNamespace, height: u64) -> bool {
        root.start <= height
            && (root.end == u64::MAX || height < root.end - self.config.namespace_grace_period)
    }

    /// ChildNamespaceAvailability: 親があり、深すぎず、ルートが猶予を除いて生きていて持ち主が `owner` で、
    /// その子がまだないこと。
    ///
    /// catapult は切れたネームスペースを、猶予のあともしばらく消さずに「ある」とみなす。ここでは、ルートが
    /// 猶予を含めて生きているものだけを「ある」とみなす。catapult が弾く子を通すことはあっても、通す子を弾くことはない
    pub(super) fn check_child_namespace(
        &self,
        height: u64,
        owner: &[u8; 24],
        id: u64,
        parent_id: u64,
    ) -> Result<(), ExecError> {
        let parent = self
            .namespace_paths
            .get(&parent_id)
            .ok_or_else(|| invalid("親のネームスペースがありません"))?;
        if parent.len() >= self.config.max_namespace_depth {
            return Err(invalid(format!(
                "ネームスペース {parent_id:016X} の下には作れません（深すぎる）"
            )));
        }
        self.check_namespace_owner(height, parent_id, owner)?;
        let exists = self
            .namespace_paths
            .get(&id)
            .and_then(|path| self.namespaces.get(&path[0]))
            .is_some_and(|root| root.start <= height && height < root.end);
        if exists {
            return Err(invalid(format!("ネームスペース {id:016X} はもうあります")));
        }
        Ok(())
    }

    /// 別名を付け外しできるか。RequiredNamespace、AliasAvailability、UnlinkAliased*Consistency
    pub(super) fn check_alias(
        &self,
        height: u64,
        owner: &[u8; 24],
        namespace_id: u64,
        action: AliasAction,
        alias: Alias,
    ) -> Result<(), ExecError> {
        self.check_namespace_owner(height, namespace_id, owner)?;
        let current = self.alias_of(namespace_id)?;
        let available = match action {
            AliasAction::Link => current == Alias::None,
            AliasAction::Unlink => current == alias,
        };
        if !available {
            return Err(invalid(format!(
                "ネームスペース {namespace_id:016X} の別名は {current:?} なので {action:?} できません"
            )));
        }
        Ok(())
    }
}

/// 連署を待つアグリゲートボンデッドを、今の状態で確かめた結果（catapult の `PtUpdater` の確かめ）
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartialCheck {
    /// 連署が揃った。未承認の置き場に移せる
    Complete,
    /// 連署が足りない。待つ
    Missing,
    /// 連署できない人（マルチシグをたどっても、どの中のトランザクションにも要らない）の公開鍵。外側の署名者の
    /// こともある
    Ineligible(Vec<PublicKey>),
}

impl Executor {
    /// アグリゲートボンデッド `hash` のハッシュロックが、確定していて、使われておらず、期限が来ていないか
    /// （catapult の `AggregateHashPresentValidator`）。今の先端の高さで見る
    pub fn hash_lock_ready(&self, hash: &Hash256) -> bool {
        let height = self.height;
        self.hash_locks
            .get(&hash.0)
            .and_then(|history| history.last())
            .is_some_and(|lock| lock.status == LockStatus::Unused && height < lock.end_height)
    }

    /// 連署を待つアグリゲートボンデッドを、今の状態で確かめる。連署できない人がいれば、それを返す。いなければ、
    /// 中のトランザクションに要る署名者がみな（マルチシグならたどって要る数だけ）連署しているか。
    /// ブロックの中と違い、中のトランザクションは当てずに、今の状態のまま見る（catapult と同じ）
    pub fn check_partial(&self, transaction: &Transaction) -> PartialCheck {
        let Body::AggregateBonded(aggregate) = &transaction.body else {
            return PartialCheck::Ineligible(vec![transaction.signer_public_key]);
        };
        let mut eligible = BTreeSet::new();
        for inner in aggregate.transactions() {
            for address in self.required_signers(inner) {
                self.mark_eligible(address, &mut eligible, 0);
            }
        }
        let ineligible: Vec<PublicKey> = std::iter::once(&transaction.signer_public_key)
            .chain(
                aggregate
                    .cosignatures()
                    .iter()
                    .map(|cosignature| &cosignature.signer_public_key),
            )
            .filter(|key| !eligible.contains(&self.address_of(key)))
            .copied()
            .collect();
        if !ineligible.is_empty() {
            return PartialCheck::Ineligible(ineligible);
        }
        let cosigners = self.cosigners(transaction, aggregate);
        if aggregate
            .transactions()
            .iter()
            .all(|inner| self.check_sufficient_cosigners(&cosigners, inner).is_ok())
        {
            PartialCheck::Complete
        } else {
            PartialCheck::Missing
        }
    }
}
