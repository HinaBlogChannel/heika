//! 中身を当てる前に確かめる validator（鍵のリンク、ロック、モザイク、マルチシグ、メタデータ、アカウントの制限）。
//! 弾いたら [`ExecError::Invalid`] で、規則の名前（catapult の validator の名前）を先に付ける。
//!
//! どれも、その中身を当てる前の状態で確かめる。ステートメントに解決を残さないよう、エイリアスは
//! [`Executor::peek_address`] と [`Executor::peek_mosaic`] で引く。
//! モザイクの制限（全体とアドレス）は、変更の確かめと、送金、ロック、取り上げでの効かせ方
//! （catapult の `MosaicRestrictionBalanceTransfer` と `MosaicRestrictionBalanceDebit`）を入れた。手数料と
//! 使用料の通貨は Restrictable でないので、全体の制限を持てず、見ない。

use std::collections::BTreeSet;

use heika_core::address::Address;
use heika_transaction::{
    Body, LinkAction, MosaicFlags, MosaicSupplyChangeAction, NamespaceRegistration,
    NamespaceRegistrationType, UnresolvedAddress,
};

use super::{
    Alias, ExecError, Executor, LockStatus, MosaicRestrictionEntry, RESTRICTION_BLOCK, invalid,
    mosaic_restriction_key, mosaic_restriction_type,
};
use crate::account::AccountType;

/// モザイクのアドレスの制限で、値がないことを表す値（`MosaicAddressRestriction::Sentinel_Removal_Value`）
const UNSET: u64 = u64::MAX;
/// アカウントの操作の制限の種類（AccountOperationRestriction）
const OPERATION_RESTRICTION: [u8; 2] = 0x4350u16.to_le_bytes();

impl Executor {
    /// 規則 `rule` が弾いた。中身は `detail`
    fn check(&self, rule: &'static str, detail: impl FnOnce() -> String) -> Result<(), ExecError> {
        Err(invalid(format!("{rule}: {}", detail())))
    }

    /// エイリアスなら、ステートメントに残さずに引く。引けなければそのまま
    pub(super) fn peek_mosaic(&self, id: u64) -> u64 {
        if id >> 63 == 0 {
            return id;
        }
        match self.alias_of(id) {
            Ok(Alias::Mosaic(mosaic_id)) => mosaic_id,
            _ => id,
        }
    }

    fn is_remote(&self, address: &[u8; 24]) -> bool {
        self.accounts.get(address).is_some_and(|account| {
            matches!(
                account.account_type,
                AccountType::Remote | AccountType::RemoteUnlinked
            )
        })
    }

    /// 外側のトランザクションについて。RemoteSender と、送り出しの操作の制限
    pub(super) fn check_transaction_rules(
        &mut self,
        signer: [u8; 24],
        kind: u16,
    ) -> Result<(), ExecError> {
        if self.is_remote(&signer) {
            self.check("RemoteSender", || format!("署名者 {}", hex(&signer)))?;
        }
        if !self.restriction_allows(&signer, 0x4004, &kind.to_le_bytes()) {
            self.check("OperationRestriction", || {
                format!("署名者 {}、種類 {kind:04X}", hex(&signer))
            })?;
        }
        Ok(())
    }

    /// 解決したあとのアドレスが、このネットワークのもので、チェックサムが合うか（catapult の `Address`）。
    /// 解決できないエイリアスは、そのままの値で確かめるので弾かれる
    fn check_address(&mut self, address: &UnresolvedAddress) -> Result<(), ExecError> {
        let resolved = Address(self.peek_address(address));
        if resolved.network() != self.network || !resolved.has_valid_checksum() {
            self.check("Address", || hex(&resolved.0))?;
        }
        Ok(())
    }

    /// ネームスペースを取るときの、予約された名前、期間の上限、子の数（catapult の `NamespaceReservedName`、
    /// `NamespaceDurationOverflow`、`RootNamespaceMaxChildren`）。持ち主と、子がもうないことは、当てるときに
    /// 確かめている
    fn check_namespace_registration(
        &mut self,
        height: u64,
        registration: &NamespaceRegistration,
    ) -> Result<(), ExecError> {
        let id = registration.id.0;
        match registration.registration_type {
            NamespaceRegistrationType::Root { duration } => {
                if height != 1 && self.config.reserved_root_namespace_ids.contains(&id) {
                    self.check("NamespaceReservedName", || format!("{id:016X}"))?;
                }
                // 生きているあいだ（猶予を含む）の延長は、延ばしたあとの終わり（猶予を含む）が、今の高さから上限の
                // 期間に猶予を足したものまで（catapult の `NamespaceLifetimeConstraints`）。猶予を過ぎていれば、
                // 高さに足してあふれないことだけ
                let overflows = height.checked_add(duration).is_none()
                    || self.namespaces.get(&id).is_some_and(|root| {
                        root.start <= height
                            && height < root.end
                            && root.end.checked_add(duration).is_none_or(|end| {
                                end > height
                                    .saturating_add(self.config.max_namespace_duration)
                                    .saturating_add(self.config.namespace_grace_period)
                            })
                    });
                if overflows {
                    self.check("NamespaceDurationOverflow", || {
                        format!("{id:016X} に {duration}")
                    })?;
                }
            }
            NamespaceRegistrationType::Child { parent_id } => {
                if height != 1
                    && self
                        .config
                        .reserved_root_namespace_ids
                        .contains(&parent_id.0)
                {
                    self.check("NamespaceReservedName", || {
                        format!("{:016X} の下の {id:016X}", parent_id.0)
                    })?;
                }
                let children = self
                    .namespace_paths
                    .get(&parent_id.0)
                    .and_then(|path| self.namespaces.get(&path[0]))
                    .map_or(0, |root| root.children.len());
                if children >= self.config.max_child_namespaces {
                    self.check("RootNamespaceMaxChildren", || {
                        format!("{:016X} の下の {id:016X}（子は {children}）", parent_id.0)
                    })?;
                }
            }
        }
        Ok(())
    }

    /// 中身を当てる前に。`signer` は中身の署名者
    pub(super) fn check_body_rules(
        &mut self,
        height: u64,
        signer: [u8; 24],
        body: &Body,
    ) -> Result<(), ExecError> {
        // アドレスを指すもの（catapult の `AccountAddressNotification`）。モザイクとネームスペースの使用料の
        // 受け取り先は設定の値で、ブロックの受け取り先は取るスレッドで確かめる。モザイクとネームスペースの
        // メタデータの相手は、catapult と同じく、持ち主かどうかだけを下で確かめる
        match body {
            Body::Transfer(transfer) => self.check_address(transfer.recipient_address())?,
            Body::SecretLock(lock) => self.check_address(&lock.recipient_address)?,
            Body::AccountMetadata(metadata) => {
                self.check_address(&metadata.target_address)?;
            }
            Body::MosaicSupplyRevocation(revocation) => {
                self.check_address(&revocation.source_address)?;
            }
            Body::MultisigAccountModification(modification) => {
                for address in modification.address_additions.iter() {
                    self.check_address(address)?;
                }
            }
            _ => {}
        }
        match body {
            Body::Transfer(transfer) => {
                let recipient = self.peek_address(transfer.recipient_address());
                self.check_interaction(signer, recipient)?;
                for (&id, &amount) in transfer.mosaics() {
                    self.check_mosaic_transfer(height, signer, recipient, id.0, amount)?;
                    self.check_mosaic_authorization(id.0, &[signer, recipient])?;
                }
            }
            Body::SecretLock(lock) => {
                let recipient = self.peek_address(&lock.recipient_address);
                self.check_interaction(signer, recipient)?;
                // 受け手への額 0 の送金の通知（受け手の側の確かめのため）
                self.check_mosaic_transfer(height, signer, recipient, lock.mosaic.mosaic_id.0, 0)?;
                // 送り手から引く通知と、受け手への額 0 の送金の通知
                self.check_mosaic_authorization(lock.mosaic.mosaic_id.0, &[signer, recipient])?;
                let key =
                    super::secret_lock_key(&lock.secret, &heika_core::address::Address(recipient));
                if !self
                    .config
                    .skip_secret_lock_uniqueness_checks
                    .contains(&height)
                    && self.lock_alive(
                        self.secret_locks
                            .get(&key.0)
                            .and_then(|h| h.last())
                            .map(|l| (l.status, l.end_height)),
                        height,
                    )
                {
                    self.check("SecretLockUniqueness", || format!("キー {}", hex(&key.0)))?;
                }
            }
            Body::HashLock(lock) => {
                self.check_mosaic_authorization(lock.mosaic.mosaic_id.0, &[signer])?;
                let mosaic_id = self.peek_mosaic(lock.mosaic.mosaic_id.0);
                if lock.mosaic.amount != self.config.locked_funds_per_aggregate
                    || mosaic_id != self.config.currency_mosaic_id
                {
                    self.check("HashLockMosaic", || {
                        format!("{mosaic_id:016X} を {}", lock.mosaic.amount)
                    })?;
                }
                if self.lock_alive(
                    self.hash_locks
                        .get(&lock.hash.0)
                        .and_then(|history| history.last())
                        .map(|lock| (lock.status, lock.end_height)),
                    height,
                ) {
                    self.check("HashLockUniqueness", || hex(&lock.hash.0))?;
                }
            }
            Body::AccountKeyLink(link) => {
                let remote = self.address_of(&link.linked_public_key);
                let main = self.accounts.get(&signer);
                match link.link_action {
                    LinkAction::Link => {
                        if main.is_some_and(|main| main.account_type != AccountType::Unlinked) {
                            self.check("AccountLinkAvailability", || hex(&signer))?;
                        }
                        // 公開鍵が分かっていないアカウントは、ないものとみなす
                        let taken = self.accounts.get(&remote).is_some_and(|remote| {
                            remote.public_key_height != 0
                                && remote.account_type != AccountType::RemoteUnlinked
                        });
                        if taken {
                            self.check("NewRemoteAccount", || hex(&remote))?;
                        }
                    }
                    LinkAction::Unlink => {
                        let linked = main.is_some_and(|main| {
                            main.account_type == AccountType::Main
                                && main.linked == Some(link.linked_public_key.0)
                        });
                        if !linked {
                            self.check("AccountLinkAvailability", || hex(&signer))?;
                        }
                    }
                }
            }
            Body::VrfKeyLink(link) | Body::NodeKeyLink(link) => {
                let current = self.accounts.get(&signer).and_then(|account| {
                    if matches!(body, Body::VrfKeyLink(_)) {
                        account.vrf
                    } else {
                        account.node
                    }
                });
                let valid = match link.link_action {
                    LinkAction::Link => current.is_none(),
                    LinkAction::Unlink => current == Some(link.linked_public_key.0),
                };
                if !valid {
                    self.check("KeyLink", || hex(&signer))?;
                }
            }
            Body::VotingKeyLink(link) => {
                if link.link_action == LinkAction::Link {
                    let voting = self.accounts.get(&signer).map(|account| &account.voting);
                    let count = voting.map_or(0, Vec::len);
                    let last_end = voting
                        .and_then(|keys| keys.iter().map(|key| key.end_epoch).max())
                        .unwrap_or(0);
                    if count >= 3 || link.start_epoch <= last_end {
                        self.check("VotingKeyLink", || {
                            format!("{} は鍵 {count} 個、最後の終わり {last_end}", hex(&signer))
                        })?;
                    }
                }
            }
            Body::MosaicDefinition(definition) => {
                if let Some(current) = self.mosaics.get(&definition.id.0).cloned() {
                    if current.divisibility ^ definition.divisibility
                        > self.config.max_mosaic_divisibility
                    {
                        self.check("MosaicDivisibility", || format!("{:016X}", definition.id.0))?;
                    }
                    let delta = definition.duration;
                    let too_long = delta != 0
                        && (delta > self.config.max_mosaic_duration
                            || current.duration == 0
                            || current
                                .duration
                                .checked_add(delta)
                                .is_none_or(|total| total > self.config.max_mosaic_duration));
                    if too_long {
                        self.check("MosaicDuration", || {
                            format!("{:016X} に {delta}", definition.id.0)
                        })?;
                    }
                } else {
                    if definition.divisibility > self.config.max_mosaic_divisibility {
                        self.check("MosaicDivisibilityNew", || {
                            format!(
                                "{:016X} の可分性 {}",
                                definition.id.0, definition.divisibility
                            )
                        })?;
                    }
                    if definition.duration > self.config.max_mosaic_duration {
                        self.check("MosaicDuration", || format!("{:016X}", definition.id.0))?;
                    }
                }
            }
            Body::MultisigAccountModification(modification) => {
                self.check_multisig_modification(signer, modification)?;
            }
            Body::NamespaceRegistration(registration) => {
                self.check_namespace_registration(height, registration)?;
            }
            Body::AccountMetadata(metadata) => {
                self.check_metadata_value(
                    signer,
                    metadata,
                    0,
                    heika_transaction::MetadataType::Account,
                )?;
            }
            Body::MosaicMetadata(metadata) => {
                let id = self.peek_mosaic(metadata.target_mosaic_id.0);
                let target = self.peek_address(&metadata.metadata.target_address);
                if self.check_mosaic_owner(height, id, &target).is_err() {
                    self.check("MetadataOwner", || format!("モザイク {id:016X}"))?;
                }
                self.check_metadata_value(
                    signer,
                    &metadata.metadata,
                    id,
                    heika_transaction::MetadataType::Mosaic,
                )?;
            }
            Body::NamespaceMetadata(metadata) => {
                let id = metadata.target_namespace_id.0;
                let target = self.peek_address(&metadata.metadata.target_address);
                if self.check_namespace_owner(height, id, &target).is_err() {
                    self.check("MetadataOwner", || format!("ネームスペース {id:016X}"))?;
                }
                self.check_metadata_value(
                    signer,
                    &metadata.metadata,
                    id,
                    heika_transaction::MetadataType::Namespace,
                )?;
            }
            Body::AccountAddressRestriction(restriction) => {
                let additions = restriction
                    .restriction_additions
                    .iter()
                    .map(|value| self.peek_address(value).to_vec())
                    .collect();
                let deletions = restriction
                    .restriction_deletions
                    .iter()
                    .map(|value| self.peek_address(value).to_vec())
                    .collect();
                self.check_restriction_modification(
                    signer,
                    restriction.restriction_flags.bits(),
                    additions,
                    deletions,
                )?;
            }
            Body::AccountMosaicRestriction(restriction) => {
                let additions = restriction
                    .restriction_additions
                    .iter()
                    .map(|value| self.peek_mosaic(value.0).to_le_bytes().to_vec())
                    .collect();
                let deletions = restriction
                    .restriction_deletions
                    .iter()
                    .map(|value| self.peek_mosaic(value.0).to_le_bytes().to_vec())
                    .collect();
                self.check_restriction_modification(
                    signer,
                    restriction.restriction_flags.bits(),
                    additions,
                    deletions,
                )?;
            }
            Body::AccountOperationRestriction(restriction) => {
                let values = |list: &[heika_transaction::TransactionType]| {
                    list.iter()
                        .map(|value| value.0.to_le_bytes().to_vec())
                        .collect()
                };
                self.check_restriction_modification(
                    signer,
                    restriction.restriction_flags.bits(),
                    values(&restriction.restriction_additions),
                    values(&restriction.restriction_deletions),
                )?;
            }
            Body::MosaicSupplyChange(change) => {
                // 増やすときは、持ち主がまだ持っていなければ、持てる種類に空きがあること
                if change.action == MosaicSupplyChangeAction::Increase {
                    let id = self.peek_mosaic(change.mosaic_id.0);
                    if self.mosaics_full(&signer, id) {
                        self.check("MaxMosaicsSupplyChange", || {
                            format!("{} が {id:016X} を増やす", hex(&signer))
                        })?;
                    }
                }
            }
            Body::MosaicSupplyRevocation(revocation) => {
                // 持っているアカウントから持ち主への送金の通知。アドレスの制限は見ない
                let source = self.peek_address(&revocation.source_address);
                // 受け手は持ち主なので、譲渡できるかは見なくても通る。持てる種類と、アカウントの制限
                let id = self.peek_mosaic(revocation.mosaic.mosaic_id.0);
                if revocation.mosaic.amount != 0 && self.mosaics_full(&signer, id) {
                    self.check("MaxMosaicsRevocation", || {
                        format!("{} が {id:016X} を取り上げる", hex(&signer))
                    })?;
                }
                if !self.restriction_allows(&signer, 0x0002, &id.to_le_bytes()) {
                    self.check("MosaicRestrictionRevocation", || {
                        format!("{} が {id:016X} を受け取れない", hex(&signer))
                    })?;
                }
                self.check_mosaic_authorization(revocation.mosaic.mosaic_id.0, &[source, signer])?;
            }
            Body::MosaicGlobalRestriction(restriction) => {
                self.check_global_restriction_modification(height, signer, restriction)?;
            }
            Body::MosaicAddressRestriction(restriction) => {
                self.check_address_restriction_modification(height, signer, restriction)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// モザイク `id` の全体の制限の規則を、（規則を見るモザイク、キー、値、種類）にして返す。参照するモザイクが 0 なら
    /// 自分を見る。制限がなければ空。自分を参照する規則があれば `None`（catapult の
    /// `GetMosaicGlobalRestrictionResolvedRules`）
    fn resolved_mosaic_rules(&self, id: u64) -> Option<Vec<(u64, u64, u64, u8)>> {
        let Some(MosaicRestrictionEntry::Global { rules, .. }) = self
            .mosaic_restrictions
            .get(&mosaic_restriction_key(id, &[0; 24]))
        else {
            return Some(Vec::new());
        };
        let mut resolved = Vec::new();
        for (&key, &(reference, value, restriction_type)) in rules {
            if reference == id {
                return None;
            }
            let mosaic = if reference == 0 { id } else { reference };
            resolved.push((mosaic, key, value, restriction_type));
        }
        Some(resolved)
    }

    /// `address` が、全体の制限の規則をみな満たすか（catapult の `EvaluateMosaicRestrictionResolvedRulesForAddress`）。
    /// アドレスの値がなければ、NE だけが満たす
    fn mosaic_rules_allow(&self, rules: &[(u64, u64, u64, u8)], address: &[u8; 24]) -> bool {
        rules
            .iter()
            .all(|&(mosaic, key, expected, restriction_type)| {
                let value = match self
                    .mosaic_restrictions
                    .get(&mosaic_restriction_key(mosaic, address))
                {
                    Some(MosaicRestrictionEntry::Address { values, .. }) => {
                        values.get(&key).copied().unwrap_or(UNSET)
                    }
                    _ => UNSET,
                };
                if value == UNSET {
                    return restriction_type == 2;
                }
                match restriction_type {
                    1 => expected == value,
                    2 => expected != value,
                    3 => value < expected,
                    4 => value <= expected,
                    5 => value > expected,
                    6 => value >= expected,
                    _ => false,
                }
            })
    }

    /// モザイクを動かすアカウント（送り手、受け手）が、そのモザイクの全体の制限を満たすか
    fn check_mosaic_authorization(
        &mut self,
        unresolved: u64,
        addresses: &[[u8; 24]],
    ) -> Result<(), ExecError> {
        let id = self.peek_mosaic(unresolved);
        let Some(rules) = self.resolved_mosaic_rules(id) else {
            return self.check("MosaicAuthorization", || {
                format!("{id:016X} の全体の制限が自分を参照しています")
            });
        };
        if rules.is_empty() {
            return Ok(());
        }
        for address in addresses {
            if !self.mosaic_rules_allow(&rules, address) {
                let address = *address;
                self.check("MosaicAuthorization", || {
                    format!("{} は {id:016X} を動かせない", hex(&address))
                })?;
            }
        }
        Ok(())
    }

    /// 制限を変えるモザイクが生きていて、持ち主が署名者で、Restrictable であること（catapult の `RequiredMosaic`）
    fn check_restrictable(
        &mut self,
        height: u64,
        signer: [u8; 24],
        id: u64,
    ) -> Result<(), ExecError> {
        let restrictable = self
            .check_mosaic_owner(height, id, &signer)
            .is_ok_and(|entry| entry.flags & MosaicFlags::RESTRICTABLE.bits() != 0);
        if !restrictable {
            self.check("MosaicRestrictable", || {
                format!("{id:016X} を {}", hex(&signer))
            })?;
        }
        Ok(())
    }

    /// モザイク `id` の全体の制限に、キー `key` の規則があること（catapult の `MosaicRestrictionRequired`）
    fn check_restriction_key(&mut self, id: u64, key: u64) -> Result<(), ExecError> {
        let exists = matches!(
            self.mosaic_restrictions.get(&mosaic_restriction_key(id, &[0; 24])),
            Some(MosaicRestrictionEntry::Global { rules, .. }) if rules.contains_key(&key)
        );
        if !exists {
            self.check("MosaicRestrictionKey", || {
                format!("{id:016X} のキー {key:016X}")
            })?;
        }
        Ok(())
    }

    /// 値の数の上限と、ないものを消さないこと（catapult の `Mosaic*RestrictionMaxValues`）。`entry` は変える前の
    /// 制限の値の数（なければ `None`）、`exists` はそのキーがあるか
    fn check_restriction_values(
        &mut self,
        entry: Option<usize>,
        exists: bool,
        delete: bool,
    ) -> Result<(), ExecError> {
        let valid = match entry {
            None => !delete,
            Some(count) => {
                !(delete && !exists)
                    && (delete || exists || count < self.config.max_mosaic_restriction_values)
            }
        };
        if !valid {
            self.check("MosaicRestrictionMaxValues", || {
                format!(
                    "値 {entry:?} 件、キーが{}",
                    if exists { "ある" } else { "ない" }
                )
            })?;
        }
        Ok(())
    }

    fn check_global_restriction_modification(
        &mut self,
        height: u64,
        signer: [u8; 24],
        restriction: &heika_transaction::MosaicGlobalRestriction,
    ) -> Result<(), ExecError> {
        let id = self.peek_mosaic(restriction.mosaic_id.0);
        let reference = self.peek_mosaic(restriction.reference_mosaic_id.0);
        let key = restriction.restriction_key;
        self.check_restrictable(height, signer, id)?;
        if restriction.reference_mosaic_id.0 != 0 {
            self.check_restriction_key(reference, key)?;
        }
        let (entry, rule) = match self
            .mosaic_restrictions
            .get(&mosaic_restriction_key(id, &[0; 24]))
        {
            Some(MosaicRestrictionEntry::Global { rules, .. }) => {
                (Some(rules.len()), rules.get(&key).copied())
            }
            _ => (None, None),
        };
        let previous_type = mosaic_restriction_type(restriction.previous_restriction_type);
        let previous_matches = match rule {
            Some(rule) => {
                rule == (
                    reference,
                    restriction.previous_restriction_value,
                    previous_type,
                )
            }
            None => restriction.previous_restriction_value == 0 && previous_type == 0,
        };
        if !previous_matches {
            self.check("MosaicRestrictionPrevious", || {
                format!("{id:016X} のキー {key:016X}: 今は {rule:?}")
            })?;
        }
        let delete = mosaic_restriction_type(restriction.new_restriction_type) == 0;
        self.check_restriction_values(entry, rule.is_some(), delete)
    }

    fn check_address_restriction_modification(
        &mut self,
        height: u64,
        signer: [u8; 24],
        restriction: &heika_transaction::MosaicAddressRestriction,
    ) -> Result<(), ExecError> {
        let id = self.peek_mosaic(restriction.mosaic_id.0);
        let target = self.peek_address(&restriction.target_address);
        let key = restriction.restriction_key;
        self.check_restrictable(height, signer, id)?;
        self.check_restriction_key(id, key)?;
        let (entry, value) = match self
            .mosaic_restrictions
            .get(&mosaic_restriction_key(id, &target))
        {
            Some(MosaicRestrictionEntry::Address { values, .. }) => (
                Some(values.len()),
                values.get(&key).copied().unwrap_or(UNSET),
            ),
            _ => (None, UNSET),
        };
        if restriction.previous_restriction_value != value {
            self.check("MosaicRestrictionPrevious", || {
                format!(
                    "{id:016X} のキー {key:016X}、{}: 今は {value:016X}",
                    hex(&target)
                )
            })?;
        }
        let delete = restriction.new_restriction_value == UNSET;
        self.check_restriction_values(entry, value != UNSET, delete)
    }

    fn lock_alive(&self, last: Option<(LockStatus, u64)>, height: u64) -> bool {
        last.is_some_and(|(status, end)| status == LockStatus::Unused && height < end)
    }

    /// RemoteInteraction と、アドレスの制限（相手の受け取りが送り手を、送り手の送り出しが相手を許すこと）。
    /// 自分とのやりとりは、アドレスの制限では見ない（catapult の `AddressInteractionValidator`）
    fn check_interaction(
        &mut self,
        sender: [u8; 24],
        recipient: [u8; 24],
    ) -> Result<(), ExecError> {
        if self.is_remote(&recipient) {
            self.check("RemoteInteraction", || hex(&recipient))?;
        }
        if sender == recipient {
            return Ok(());
        }
        if !self.restriction_allows(&recipient, 0x0001, &sender)
            || !self.restriction_allows(&sender, 0x4001, &recipient)
        {
            self.check("AddressRestriction", || {
                format!("{} → {}", hex(&sender), hex(&recipient))
            })?;
        }
        Ok(())
    }

    /// 譲渡（MosaicTransfer）、持てる種類（MaxMosaics）、受け手のモザイクの制限
    fn check_mosaic_transfer(
        &mut self,
        height: u64,
        sender: [u8; 24],
        recipient: [u8; 24],
        unresolved: u64,
        amount: u64,
    ) -> Result<(), ExecError> {
        let id = self.peek_mosaic(unresolved);
        if unresolved != self.config.currency_mosaic_id {
            let transferable = self
                .mosaics
                .get(&id)
                .filter(|mosaic| mosaic.is_active(height))
                .map(|mosaic| {
                    mosaic.flags & MosaicFlags::TRANSFERABLE.bits() != 0
                        || mosaic.owner == sender
                        || mosaic.owner == recipient
                });
            if transferable != Some(true) {
                self.check("MosaicTransfer", || {
                    format!("{id:016X} を {} → {}", hex(&sender), hex(&recipient))
                })?;
            }
        }
        if amount != 0 && self.mosaics_full(&recipient, id) {
            self.check("MaxMosaics", || hex(&recipient))?;
        }
        if !self.restriction_allows(&recipient, 0x0002, &id.to_le_bytes()) {
            self.check("MosaicRestriction", || {
                format!("{} が {id:016X} を受け取れない", hex(&recipient))
            })?;
        }
        Ok(())
    }

    /// `address` がモザイク `id` をまだ持っておらず、持てる種類が上限に達しているか（catapult の `MaxMosaics` の
    /// `CheckAccount`）
    fn mosaics_full(&self, address: &[u8; 24], id: u64) -> bool {
        self.accounts.get(address).is_some_and(|account| {
            !account.balances.contains_key(&id)
                && account.balances.len() >= self.config.max_mosaics_per_account
        })
    }

    /// アカウントの制限 `directional`（向きと種類）が `value` を許すか。一覧が空ならみな許す。
    /// 許可の一覧なら一覧にあるもの、拒否の一覧なら一覧にないものを許す
    fn restriction_allows(&self, address: &[u8; 24], directional: u16, value: &[u8]) -> bool {
        let Some(restriction) = self
            .account_restrictions
            .get(address)
            .and_then(|restrictions| restrictions.get(&directional))
        else {
            return true;
        };
        if restriction.values.is_empty() {
            return true;
        }
        let listed = restriction.values.contains(value);
        if restriction.descriptor & RESTRICTION_BLOCK != 0 {
            !listed
        } else {
            listed
        }
    }

    /// アカウントの制限の変更。足すものを先に、外すものをあとに1つずつ当てるとして確かめる
    fn check_restriction_modification(
        &mut self,
        signer: [u8; 24],
        flags: u16,
        additions: Vec<Vec<u8>>,
        deletions: Vec<Vec<u8>>,
    ) -> Result<(), ExecError> {
        let directional = flags & !RESTRICTION_BLOCK;
        let block = flags & RESTRICTION_BLOCK != 0;
        let restrictions = self.account_restrictions.get(&signer);
        let has_any = restrictions.is_some_and(|all| {
            all.values()
                .any(|restriction| !restriction.values.is_empty())
        });
        let current = restrictions.and_then(|all| all.get(&directional));
        let mut values: BTreeSet<Vec<u8>> = current.map(|r| r.values.clone()).unwrap_or_default();
        // まだ制限がなければ、空の拒否の一覧（catapult の AccountRestrictions の既定）
        let mut current_block = current.is_none_or(|r| r.descriptor & RESTRICTION_BLOCK != 0);
        let mut failure = None;
        let added: BTreeSet<_> = additions.iter().collect();
        if deletions.iter().any(|value| added.contains(value)) {
            failure = Some("足すものと外すものが重なる");
        } else if !deletions.is_empty() && !has_any {
            failure = Some("制限がないのに外す");
        } else if additions.len() + deletions.len() > self.config.max_account_restriction_values
            || values.len() + additions.len()
                > self.config.max_account_restriction_values + deletions.len()
        {
            failure = Some("数が多すぎる");
        }
        for (value, add) in additions
            .iter()
            .map(|value| (value, true))
            .chain(deletions.iter().map(|value| (value, false)))
        {
            if failure.is_some() {
                break;
            }
            if !values.is_empty() && current_block != block {
                failure = Some("許可と拒否を空にせずに切り替える");
            } else if add && values.contains(value) || !add && !values.contains(value) {
                failure = Some("足すものがもうあるか、外すものがない");
            } else if directional & 0x0001 != 0 && value.as_slice() == signer.as_slice() {
                failure = Some("自分のアドレス");
            } else if directional == 0x4004 {
                let operation = value.as_slice() == OPERATION_RESTRICTION;
                if !block && !add && operation
                    || !block && add && values.is_empty() && !operation
                    || block && add && operation
                {
                    failure = Some("操作の制限で自分を締め出す");
                }
            }
            if add {
                values.insert(value.clone());
            } else {
                values.remove(value);
            }
            // 1つ当てるごとに、種類が変わる（catapult の allow と block）。拒否なら拒否、許可でも空になれば拒否
            current_block = block || values.is_empty();
        }
        if let Some(failure) = failure {
            self.check("AccountRestrictionModification", || {
                format!("{} の {flags:04X}: {failure}", hex(&signer))
            })?;
        }
        Ok(())
    }

    /// メタデータの値。キーはまだなければ増減 = 長さ。あれば、前の長さ（伸ばすなら長さ − 増減、そうでなければ
    /// 送る値の長さ）が今の長さと同じ。縮めるときに送る値の長さが今の長さと同じであることも、これに含まれる
    fn check_metadata_value(
        &mut self,
        signer: [u8; 24],
        metadata: &heika_transaction::Metadata,
        target_id: u64,
        metadata_type: heika_transaction::MetadataType,
    ) -> Result<(), ExecError> {
        let target = self.peek_address(&metadata.target_address);
        let key = heika_transaction::MetadataKey {
            source_address: heika_core::address::Address(signer),
            target_address: heika_core::address::Address(target),
            scoped_metadata_key: metadata.scoped_metadata_key,
            target_id,
            metadata_type,
        };
        let size = metadata.value.len() as i64;
        let delta = i64::from(metadata.value_size_delta);
        let (valid, trimmable) = match self.metadata.get(&key.unique_key().0) {
            None => (delta == size, true),
            Some((_, current)) => {
                let previous = if delta > 0 { size - delta } else { size };
                // 縮めるときは、切り捨てる末尾が今の値と同じ（XOR して 0）でないと、元に戻せない
                // （catapult の `MetadataValue::canTrim`）。長さが合うときだけ見る
                let count = usize::try_from(-delta).unwrap_or(0);
                let trimmable = delta >= 0
                    || previous != current.len() as i64
                    || (count <= current.len()
                        && current[current.len() - count..]
                            == metadata.value[metadata.value.len() - count..]);
                (previous == current.len() as i64, trimmable)
            }
        };
        if !valid {
            self.check("MetadataValue", || format!("長さ {size}、増減 {delta}"))?;
        }
        if !trimmable {
            self.check("MetadataValueTrim", || format!("長さ {size}、増減 {delta}"))?;
        }
        Ok(())
    }

    /// マルチシグの連署者と設定の変更。連署者を変える前の状態で確かめる
    fn check_multisig_modification(
        &mut self,
        multisig: [u8; 24],
        modification: &heika_transaction::MultisigAccountModification,
    ) -> Result<(), ExecError> {
        let additions: Vec<_> = modification
            .address_additions
            .iter()
            .map(|address| self.peek_address(address))
            .collect();
        let deletions: Vec<_> = modification
            .address_deletions
            .iter()
            .map(|address| self.peek_address(address))
            .collect();
        for address in &additions {
            self.check_interaction(multisig, *address)?;
        }
        let entry = self.multisigs.get(&multisig);
        let cosignatories = entry
            .map(|entry| entry.cosignatories.clone())
            .unwrap_or_default();
        let mut failure = None;
        if cosignatories.is_empty() && !deletions.is_empty() {
            failure = Some("マルチシグでないのに外す");
        } else if additions
            .iter()
            .any(|address| cosignatories.contains(address))
            || deletions
                .iter()
                .any(|address| !cosignatories.contains(address))
        {
            failure = Some("足すものがもう連署者か、外すものが連署者でない");
        } else if cosignatories.len() + additions.len()
            > self.config.max_cosignatories_per_account + deletions.len()
        {
            failure = Some("連署者が多すぎる");
        } else if additions.iter().any(|address| {
            self.multisigs.get(address).is_some_and(|entry| {
                entry.multisigs.len() >= self.config.max_cosigned_accounts_per_account
            })
        }) {
            failure = Some("連署できるマルチシグが多すぎる");
        }
        // 設定
        let count = (cosignatories.len() + additions.len()).saturating_sub(deletions.len());
        let approval = i64::from(entry.map_or(0, |entry| entry.min_approval))
            + i64::from(modification.min_approval_delta);
        let removal = i64::from(entry.map_or(0, |entry| entry.min_removal))
            + i64::from(modification.min_removal_delta);
        if failure.is_none() {
            // 表から消える（最後の連署者を外す）か、マルチシグでないなら、どちらの増減も −1
            let valid = if count == 0 {
                modification.min_approval_delta == -1 && modification.min_removal_delta == -1
            } else {
                (1..=count as i64).contains(&approval) && (1..=count as i64).contains(&removal)
            };
            if !valid {
                failure = Some("承認と削除の数");
            }
        }
        // 深さと輪
        if failure.is_none() {
            let up = self.multisig_walk(multisig, true);
            for address in &additions {
                let down = self.multisig_walk(*address, false);
                if up.0 + down.0 + 1 > self.config.max_multisig_depth {
                    failure = Some("深すぎる");
                } else if up.1.intersection(&down.1).next().is_some() {
                    failure = Some("輪になる");
                }
            }
        }
        if let Some(failure) = failure {
            self.check("MultisigModification", || {
                format!("{}: {failure}", hex(&multisig))
            })?;
        }
        Ok(())
    }

    /// `start` から、上（連署しているマルチシグ）か下（連署者）へたどった段の数と、通ったアカウント（`start` を含む）
    fn multisig_walk(&self, start: [u8; 24], up: bool) -> (usize, BTreeSet<[u8; 24]>) {
        let mut seen = BTreeSet::from([start]);
        let mut level = vec![start];
        let mut depth = 0;
        while depth <= self.config.max_multisig_depth + 1 {
            let next: Vec<_> = level
                .iter()
                .filter_map(|address| self.multisigs.get(address))
                .flat_map(|entry| {
                    if up {
                        entry.multisigs.iter()
                    } else {
                        entry.cosignatories.iter()
                    }
                })
                .copied()
                .collect();
            if next.is_empty() {
                break;
            }
            depth += 1;
            seen.extend(next.iter().copied());
            level = next;
        }
        (depth, seen)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use heika_core::address::Address;
    use heika_core::key::PublicKey;
    use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
    use heika_transaction::{
        BoundedVec, KeyLink, Metadata, MetadataKey, MetadataType, MosaicRestrictionType,
        MultisigAccountModification, NamespaceId, UnresolvedAddress, UnresolvedMosaicId,
        VotingKeyLink,
    };

    use super::super::{AccountRestriction, LockStatus, MosaicEntry, new_account_restrictions};
    use super::*;
    use crate::account::{AccountState, VotingKey};
    use crate::config::{ChainConfig, FinalizationConfig, HeightDependentAddress};

    /// テストの設定（[`executor`]）の上限。メインネットと同じ値
    const MAX_MOSAICS_PER_ACCOUNT: usize = 1_000;
    const MAX_RESTRICTION_VALUES: usize = 100;
    const MAX_MOSAIC_RESTRICTION_VALUES: usize = 20;

    const CURRENCY: u64 = 0x6BED_913F_A202_23F8;
    const HEIGHT: u64 = 100;

    fn executor() -> Executor {
        let sink = HeightDependentAddress {
            before: Address([0; 24]),
            after: Address([0; 24]),
            fork_height: 0,
        };
        let config = ChainConfig {
            currency_mosaic_id: CURRENCY,
            harvesting_mosaic_id: CURRENCY,
            block_generation_target_time: 30,
            importance_grouping: 720,
            importance_activity_percentage: 5,
            max_difficulty_blocks: 60,
            default_dynamic_fee_multiplier: 100,
            total_chain_importance: 1,
            min_harvester_balance: 1,
            max_harvester_balance: u64::MAX,
            harvest_beneficiary_percentage: 25,
            harvest_network_percentage: 5,
            harvest_network_fee_sink: sink,
            mosaic_rental_fee: 0,
            mosaic_rental_fee_sink: sink,
            root_namespace_rental_fee_per_block: 0,
            child_namespace_rental_fee: 0,
            namespace_rental_fee_sink: sink,
            namespace_grace_period: 0,
            inflation: Vec::new(),
            skip_secret_lock_uniqueness_checks: Vec::new(),
            skip_secret_lock_expirations: Vec::new(),
            force_secret_lock_expirations: Vec::new(),
            total_voting_balance_calculation_fix: 0,
            nemesis_signer_public_key: PublicKey([0; 32]),
            treasury_reissuance_transaction_signatures: Vec::new(),
            treasury_reissuance_height: 0,
            max_block_future_time: 0,
            max_transaction_lifetime: 0,
            max_bonded_transaction_lifetime: 0,
            min_proof_size: 0,
            max_proof_size: 0,
            max_mosaic_atomic_units: u64::MAX,
            max_namespace_depth: 3,
            max_child_namespaces: 2,
            max_namespace_duration: 1000,
            max_mosaics_per_account: MAX_MOSAICS_PER_ACCOUNT,
            max_mosaic_duration: 3650 * 2880,
            max_mosaic_divisibility: 6,
            locked_funds_per_aggregate: 10_000_000,
            max_multisig_depth: 3,
            max_cosignatories_per_account: 25,
            max_cosigned_accounts_per_account: 25,
            max_account_restriction_values: MAX_RESTRICTION_VALUES,
            max_mosaic_restriction_values: MAX_MOSAIC_RESTRICTION_VALUES,
            reserved_root_namespace_ids: vec![NamespaceId::generate(None, b"nem").0],
            finalization: FinalizationConfig {
                voting_set_grouping: 1440,
                min_voter_balance: 1,
                size: 1,
                threshold: 1,
                max_hashes_per_point: 1,
                step_duration: 1,
                prevote_blocks_multiple: 1,
                treasury_reissuance_epoch: 0,
                ineligible_voters: Vec::new(),
            },
        };
        Executor::new(
            config,
            NetworkIdentifier::MAINNET,
            GenerationHashSeed([0; 32]),
        )
    }

    /// ネームスペースを指さないアドレス（先頭のバイトが偶数）
    fn address(n: u8) -> [u8; 24] {
        let mut address = [0; 24];
        address[0] = 0x68;
        address[1] = n;
        address
    }

    fn unresolved(addresses: &[[u8; 24]]) -> BoundedVec<UnresolvedAddress, { u8::MAX as usize }> {
        addresses
            .iter()
            .map(|address| UnresolvedAddress(*address))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// `check` を確かめて、弾いた規則の名前を返す
    fn rejected(
        executor: &mut Executor,
        check: impl FnOnce(&mut Executor) -> Result<(), ExecError>,
    ) -> Option<String> {
        match check(executor) {
            Err(ExecError::Invalid(what)) => Some(what.split(':').next().unwrap().to_owned()),
            Err(error) => panic!("{error}"),
            Ok(()) => None,
        }
    }

    fn set_restriction(
        executor: &mut Executor,
        owner: [u8; 24],
        directional: u16,
        block: bool,
        values: &[&[u8]],
    ) {
        let restrictions = executor
            .account_restrictions
            .entry(owner)
            .or_insert_with(new_account_restrictions);
        restrictions.insert(
            directional,
            AccountRestriction {
                descriptor: directional | if block { RESTRICTION_BLOCK } else { 0 },
                values: values.iter().map(|value| value.to_vec()).collect(),
            },
        );
    }

    #[test]
    fn checks_resolved_addresses() {
        let mut executor = executor();
        let valid = Address::from_public_key(&PublicKey([1; 32]), NetworkIdentifier::MAINNET);
        let mut bad_checksum = valid;
        bad_checksum.0[23] ^= 1;
        let other_network =
            Address::from_public_key(&PublicKey([1; 32]), NetworkIdentifier::TESTNET);
        // 別名がアドレスのネームスペースと、別名のないネームスペース
        for (id, alias) in [
            (0x8000_0000_0000_0001, Alias::Address(valid.0)),
            (0x8000_0000_0000_0002, Alias::None),
        ] {
            executor.namespaces.insert(
                id,
                super::super::RootNamespace {
                    owner: address(9),
                    start: 1,
                    end: u64::MAX,
                    alias,
                    children: Default::default(),
                },
            );
            executor.namespace_paths.insert(id, vec![id]);
        }
        let alias = |id| {
            UnresolvedAddress::from_namespace_id(
                heika_transaction::NamespaceId(id),
                NetworkIdentifier::MAINNET,
            )
        };
        for (name, target, expected) in [
            ("valid", UnresolvedAddress(valid.0), None),
            (
                "bad checksum",
                UnresolvedAddress(bad_checksum.0),
                Some("Address"),
            ),
            (
                "other network",
                UnresolvedAddress(other_network.0),
                Some("Address"),
            ),
            ("alias", alias(0x8000_0000_0000_0001), None),
            ("no alias", alias(0x8000_0000_0000_0002), Some("Address")),
            (
                "unknown namespace",
                alias(0x8000_0000_0000_0003),
                Some("Address"),
            ),
        ] {
            let body = Body::AccountMetadata(Metadata {
                target_address: target,
                scoped_metadata_key: 0,
                value_size_delta: 1,
                value: vec![1].try_into().unwrap(),
            });
            assert_eq!(
                rejected(&mut executor, |executor| {
                    executor.check_body_rules(HEIGHT, valid.0, &body)
                })
                .as_deref(),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn checks_only_the_owner_for_mosaic_and_namespace_metadata_targets() {
        let mut executor = executor();
        let owner = Address::from_public_key(&PublicKey([1; 32]), NetworkIdentifier::MAINNET);
        let mut bad_checksum = owner;
        bad_checksum.0[23] ^= 1;
        let id = 0x4000_0000_0000_0001;
        executor.namespaces.insert(
            id,
            super::super::RootNamespace {
                owner: owner.0,
                start: 1,
                end: u64::MAX,
                alias: Alias::None,
                children: Default::default(),
            },
        );
        executor.namespace_paths.insert(id, vec![id]);
        // 壊れたアドレスも、catapult と同じく、アドレスとしてではなく持ち主の食い違いとして落ちる
        for (target, expected) in [(owner, None), (bad_checksum, Some("MetadataOwner"))] {
            let body = Body::NamespaceMetadata(heika_transaction::NamespaceMetadata {
                metadata: Metadata {
                    target_address: UnresolvedAddress(target.0),
                    scoped_metadata_key: 0,
                    value_size_delta: 1,
                    value: vec![1].try_into().unwrap(),
                },
                target_namespace_id: heika_transaction::NamespaceId(id),
            });
            assert_eq!(
                rejected(&mut executor, |executor| {
                    executor.check_body_rules(HEIGHT, owner.0, &body)
                })
                .as_deref(),
                expected,
            );
        }
    }

    #[test]
    fn checks_namespace_registrations() {
        let mut executor = executor();
        let root = |id: u64, start, end, children: u64| super::super::RootNamespace {
            owner: address(1),
            start,
            end,
            alias: Alias::None,
            children: (0..children)
                .map(|child| (vec![id + 1 + child], Alias::None))
                .collect(),
        };
        // 生きているもの（終わり 600）、子が上限のもの、切れたもの
        executor.namespaces.insert(0x10, root(0x10, 1, 600, 0));
        executor.namespaces.insert(0x20, root(0x20, 1, 600, 2));
        executor.namespaces.insert(0x30, root(0x30, 1, 50, 0));
        for id in [0x10, 0x20, 0x30] {
            executor.namespace_paths.insert(id, vec![id]);
        }
        let nem = NamespaceId::generate(None, b"nem");
        let register = |id, registration_type| {
            Body::NamespaceRegistration(NamespaceRegistration {
                registration_type,
                id: NamespaceId(id),
                name: b"a".to_vec().try_into().unwrap(),
            })
        };
        let root_for = |id, duration| register(id, NamespaceRegistrationType::Root { duration });
        let child_of = |parent, id| {
            register(
                id,
                NamespaceRegistrationType::Child {
                    parent_id: NamespaceId(parent),
                },
            )
        };
        // HEIGHT は 100、上限の期間は 1000 なので、終わりは 1100 まで
        for (name, body, expected) in [
            ("new", root_for(0x40, 1000), None),
            (
                "new overflow",
                root_for(0x40, u64::MAX - 50),
                Some("NamespaceDurationOverflow"),
            ),
            ("extend", root_for(0x10, 500), None),
            (
                "extend too far",
                root_for(0x10, 501),
                Some("NamespaceDurationOverflow"),
            ),
            ("expired", root_for(0x30, 1000), None),
            (
                "reserved",
                root_for(nem.0, 10),
                Some("NamespaceReservedName"),
            ),
            (
                "under reserved",
                child_of(nem.0, 0x41),
                Some("NamespaceReservedName"),
            ),
            ("child", child_of(0x10, 0x42), None),
            (
                "too many children",
                child_of(0x20, 0x43),
                Some("RootNamespaceMaxChildren"),
            ),
        ] {
            assert_eq!(
                rejected(&mut executor, |executor| {
                    executor.check_body_rules(HEIGHT, address(1), &body)
                })
                .as_deref(),
                expected,
                "{name}"
            );
        }
        // 上限には猶予を足す
        executor.config.namespace_grace_period = 10;
        for (duration, expected) in [(510, None), (511, Some("NamespaceDurationOverflow"))] {
            assert_eq!(
                rejected(&mut executor, |executor| {
                    executor.check_body_rules(HEIGHT, address(1), &root_for(0x10, duration))
                })
                .as_deref(),
                expected,
                "{duration}"
            );
        }
        executor.config.namespace_grace_period = 0;
        // Nemesis では予約された名前も取れる
        assert_eq!(
            rejected(&mut executor, |executor| {
                executor.check_body_rules(1, address(1), &root_for(nem.0, 0))
            }),
            None
        );
    }

    #[test]
    fn rules_reject_with_their_name() {
        let executor = executor();
        assert_eq!(
            executor.check("MosaicTransfer", || "中身".to_owned()),
            Err(ExecError::Invalid("MosaicTransfer: 中身".to_owned()))
        );
    }

    #[test]
    fn remote_cannot_send_and_operation_restriction_limits_kinds() {
        let mut executor = executor();
        let mut remote = AccountState::new(address(1), 1);
        remote.account_type = AccountType::Remote;
        executor.accounts.insert(address(1), remote);
        assert_eq!(
            rejected(&mut executor, |e| e
                .check_transaction_rules(address(1), 0x4154))
            .as_deref(),
            Some("RemoteSender")
        );

        // 送金と、操作の制限だけを許す
        set_restriction(
            &mut executor,
            address(2),
            0x4004,
            false,
            &[&0x4154u16.to_le_bytes(), &OPERATION_RESTRICTION],
        );
        assert_eq!(
            rejected(&mut executor, |e| e
                .check_transaction_rules(address(2), 0x4154)),
            None
        );
        assert_eq!(
            rejected(&mut executor, |e| e
                .check_transaction_rules(address(2), 0x4152))
            .as_deref(),
            Some("OperationRestriction")
        );
    }

    #[test]
    fn address_restrictions_apply_to_both_sides() {
        let mut executor = executor();
        let (sender, other, recipient) = (address(1), address(2), address(3));
        let interact = |executor: &mut Executor, from, to| {
            rejected(executor, |e| e.check_interaction(from, to))
        };
        // 受け手は sender からだけ受け取る
        set_restriction(&mut executor, recipient, 0x0001, false, &[&sender]);
        assert_eq!(interact(&mut executor, sender, recipient), None);
        assert_eq!(
            interact(&mut executor, other, recipient).as_deref(),
            Some("AddressRestriction")
        );
        // 送り手が受け手への送り出しを拒む
        set_restriction(&mut executor, sender, 0x4001, true, &[&recipient]);
        assert_eq!(
            interact(&mut executor, sender, recipient).as_deref(),
            Some("AddressRestriction")
        );

        // 自分宛ては、自分の制限に関わらず通す
        set_restriction(&mut executor, other, 0x0001, false, &[&sender]);
        set_restriction(&mut executor, other, 0x4001, false, &[&sender]);
        assert_eq!(interact(&mut executor, other, other), None);

        let mut remote = AccountState::new(address(4), 1);
        remote.account_type = AccountType::RemoteUnlinked;
        executor.accounts.insert(address(4), remote);
        assert_eq!(
            interact(&mut executor, sender, address(4)).as_deref(),
            Some("RemoteInteraction")
        );
    }

    #[test]
    fn non_transferable_mosaics_move_only_to_or_from_the_owner() {
        let mut executor = executor();
        let (owner, alice, bob) = (address(1), address(2), address(3));
        let mosaic = 0x1234;
        executor.mosaics.insert(
            mosaic,
            MosaicEntry {
                supply: 10,
                start_height: 1,
                owner,
                revision: 1,
                flags: 0,
                divisibility: 0,
                duration: 0,
            },
        );
        let transfer = |executor: &mut Executor, from, to, id| {
            rejected(executor, |e| {
                e.check_mosaic_transfer(HEIGHT, from, to, id, 1)
            })
        };
        assert_eq!(transfer(&mut executor, owner, alice, mosaic), None);
        assert_eq!(transfer(&mut executor, alice, owner, mosaic), None);
        assert_eq!(
            transfer(&mut executor, alice, bob, mosaic).as_deref(),
            Some("MosaicTransfer")
        );

        executor.mosaics.get_mut(&mosaic).unwrap().flags = MosaicFlags::TRANSFERABLE.bits();
        assert_eq!(transfer(&mut executor, alice, bob, mosaic), None);
        // 期限の切れたモザイクと、ないモザイク。通貨は確かめない
        executor.mosaics.get_mut(&mosaic).unwrap().duration = 10;
        assert_eq!(
            transfer(&mut executor, alice, bob, mosaic).as_deref(),
            Some("MosaicTransfer")
        );
        assert_eq!(
            transfer(&mut executor, alice, bob, 0x5678).as_deref(),
            Some("MosaicTransfer")
        );
        assert_eq!(transfer(&mut executor, alice, bob, CURRENCY), None);
    }

    #[test]
    fn max_mosaics_counts_only_new_kinds_with_an_amount() {
        let mut executor = executor();
        let mut full = AccountState::new(address(1), 1);
        full.balances = (0..MAX_MOSAICS_PER_ACCOUNT as u64)
            .map(|id| (id, 1))
            .collect();
        executor.accounts.insert(address(1), full);
        // 持っている 5 と、持っていない 2000。どちらも譲渡できる
        for id in [5, 2000] {
            executor.mosaics.insert(
                id,
                MosaicEntry {
                    supply: 10,
                    start_height: 1,
                    owner: address(3),
                    revision: 1,
                    flags: MosaicFlags::TRANSFERABLE.bits(),
                    divisibility: 0,
                    duration: 0,
                },
            );
        }
        let transfer = |executor: &mut Executor, id, amount| {
            rejected(executor, |e| {
                e.check_mosaic_transfer(HEIGHT, address(2), address(1), id, amount)
            })
        };
        assert_eq!(transfer(&mut executor, CURRENCY, 0), None);
        assert_eq!(transfer(&mut executor, 5, 1), None);
        assert_eq!(
            transfer(&mut executor, 2000, 1).as_deref(),
            Some("MaxMosaics")
        );
        assert_eq!(
            transfer(&mut executor, CURRENCY, 1).as_deref(),
            Some("MaxMosaics")
        );
    }

    #[test]
    fn mosaic_supply_rules() {
        let mut executor = executor();
        let owner = address(1);
        let mut full = AccountState::new(owner, 1);
        full.balances = (0..MAX_MOSAICS_PER_ACCOUNT as u64)
            .map(|id| (id, 1))
            .collect();
        executor.accounts.insert(owner, full);
        let definition = |divisibility| {
            Body::MosaicDefinition(heika_transaction::MosaicDefinition {
                id: heika_transaction::MosaicId(3000),
                duration: 0,
                nonce: 0,
                flags: MosaicFlags::from_bits(0).unwrap(),
                divisibility,
            })
        };
        let change = |id, action| {
            Body::MosaicSupplyChange(heika_transaction::MosaicSupplyChange {
                mosaic_id: UnresolvedMosaicId(id),
                delta: 1,
                action,
            })
        };
        let revocation = |id, amount| {
            Body::MosaicSupplyRevocation(heika_transaction::MosaicSupplyRevocation {
                source_address: UnresolvedAddress(
                    Address::from_public_key(&PublicKey([2; 32]), NetworkIdentifier::MAINNET).0,
                ),
                mosaic: heika_transaction::UnresolvedMosaic {
                    mosaic_id: UnresolvedMosaicId(id),
                    amount,
                },
            })
        };
        for (name, body, expected) in [
            ("divisibility 6", definition(6), None),
            (
                "divisibility 7",
                definition(7),
                Some("MosaicDivisibilityNew"),
            ),
            // 持っている 5 は増やせる。持っていない 2000 は、減らすのだけ
            (
                "increase held",
                change(5, MosaicSupplyChangeAction::Increase),
                None,
            ),
            (
                "increase new",
                change(2000, MosaicSupplyChangeAction::Increase),
                Some("MaxMosaicsSupplyChange"),
            ),
            (
                "decrease new",
                change(2000, MosaicSupplyChangeAction::Decrease),
                None,
            ),
            ("revoke held", revocation(5, 1), None),
            (
                "revoke new",
                revocation(2000, 1),
                Some("MaxMosaicsRevocation"),
            ),
            ("revoke nothing", revocation(2000, 0), None),
        ] {
            assert_eq!(
                rejected(&mut executor, |e| e.check_body_rules(HEIGHT, owner, &body)).as_deref(),
                expected,
                "{name}"
            );
        }
        // 持ち主が、そのモザイクを受け取らない制限をかけている
        set_restriction(&mut executor, owner, 0x0002, true, &[&5u64.to_le_bytes()]);
        assert_eq!(
            rejected(&mut executor, |e| e.check_body_rules(
                HEIGHT,
                owner,
                &revocation(5, 1)
            ))
            .as_deref(),
            Some("MosaicRestrictionRevocation")
        );
    }

    #[test]
    fn account_restriction_modifications() {
        let owner = address(1);
        let other = || address(2).to_vec();
        // 弾いたら 1
        let check =
            |setup: &dyn Fn(&mut Executor), flags: u16, add: &[Vec<u8>], delete: &[Vec<u8>]| {
                let mut executor = executor();
                setup(&mut executor);
                let rule = rejected(&mut executor, |e| {
                    e.check_restriction_modification(owner, flags, add.to_vec(), delete.to_vec())
                });
                assert!(
                    rule.as_deref()
                        .is_none_or(|rule| rule == "AccountRestrictionModification")
                );
                u64::from(rule.is_some())
            };
        let none = |_: &mut Executor| {};
        let blocking_other = |executor: &mut Executor| {
            set_restriction(executor, owner, 0x0001, true, &[&address(2)]);
        };

        // 空の拒否の一覧に足す、あるものを外す。制限がまだなくても、いくつも足せる（テストネットの高さ 260）
        assert_eq!(check(&none, 0x8001, &[other()], &[]), 0);
        assert_eq!(
            check(&none, 0x8001, &[other(), address(3).to_vec()], &[]),
            0
        );
        assert_eq!(
            check(&none, 0x0001, &[other(), address(3).to_vec()], &[]),
            0
        );
        assert_eq!(check(&blocking_other, 0x8001, &[], &[other()]), 0);
        // 重なる、制限がないのに外す、もうある、ない、自分
        assert_eq!(check(&blocking_other, 0x8001, &[other()], &[other()]), 1);
        assert_eq!(check(&none, 0x8001, &[], &[other()]), 1);
        assert_eq!(check(&blocking_other, 0x8001, &[other()], &[]), 1);
        assert_eq!(
            check(&blocking_other, 0x8001, &[], &[address(3).to_vec()]),
            1
        );
        assert_eq!(check(&none, 0x8001, &[owner.to_vec()], &[]), 1);
        // 空でない拒否の一覧を、許可の一覧に切り替える
        assert_eq!(
            check(&blocking_other, 0x0001, &[address(3).to_vec()], &[]),
            1
        );
        // 多すぎる
        let many: Vec<_> = (3..=MAX_RESTRICTION_VALUES as u8 + 3)
            .map(|n| address(n).to_vec())
            .collect();
        assert_eq!(check(&none, 0x8001, &many, &[]), 1);

        // 操作の制限: 許可の一覧は操作の制限そのものから始める。拒否の一覧には入れられない
        let transfer = || 0x4154u16.to_le_bytes().to_vec();
        let operation = || OPERATION_RESTRICTION.to_vec();
        assert_eq!(check(&none, 0x4004, &[transfer()], &[]), 1);
        assert_eq!(check(&none, 0x4004, &[operation(), transfer()], &[]), 0);
        assert_eq!(check(&none, 0xC004, &[operation()], &[]), 1);
        assert_eq!(check(&none, 0xC004, &[transfer()], &[]), 0);
        let allowing_operation = |executor: &mut Executor| {
            set_restriction(executor, owner, 0x4004, false, &[&OPERATION_RESTRICTION]);
        };
        assert_eq!(check(&allowing_operation, 0x4004, &[], &[operation()]), 1);
    }

    #[test]
    fn metadata_value_size_follows_the_current_value() {
        let mut executor = executor();
        let (signer, target) = (address(1), address(2));
        // 今の値との XOR は、末尾の2バイトだけ 0 にする
        let metadata = |delta: i16, size: usize| {
            let mut value = vec![9; size];
            for byte in value.iter_mut().rev().take(2) {
                *byte = 0;
            }
            Metadata {
                target_address: UnresolvedAddress(target),
                scoped_metadata_key: 7,
                value_size_delta: delta,
                value: value.try_into().unwrap(),
            }
        };
        // 弾いたら 1。縮められないものは 2
        let check = |executor: &mut Executor, delta, size| {
            let rule = rejected(executor, |e| {
                e.check_metadata_value(signer, &metadata(delta, size), 0, MetadataType::Account)
            });
            match rule.as_deref() {
                None => 0,
                Some("MetadataValue") => 1,
                Some("MetadataValueTrim") => 2,
                Some(rule) => panic!("{rule}"),
            }
        };
        // まだない
        assert_eq!(check(&mut executor, 3, 3), 0);
        assert_eq!(check(&mut executor, 2, 3), 1);

        let key = MetadataKey {
            source_address: Address(signer),
            target_address: Address(target),
            scoped_metadata_key: 7,
            target_id: 0,
            metadata_type: MetadataType::Account,
        };
        executor
            .metadata
            .insert(key.unique_key().0, (key, vec![0; 5]));
        // 5 から 8 に伸ばす、同じ長さで変える、5 から 3 に縮める（送るのは今の長さ）
        assert_eq!(check(&mut executor, 3, 8), 0);
        assert_eq!(check(&mut executor, 3, 7), 1);
        assert_eq!(check(&mut executor, 0, 5), 0);
        assert_eq!(check(&mut executor, -2, 5), 0);
        assert_eq!(check(&mut executor, -2, 3), 1);
        // 切り捨てる末尾が、今の値と同じでない。今の長さより多くは縮められない
        assert_eq!(check(&mut executor, -3, 5), 2);
        assert_eq!(check(&mut executor, -6, 5), 2);
    }

    /// `multisig` に連署者 `cosignatories` を付けて、両方の向きをそろえる
    fn link_multisig(executor: &mut Executor, multisig: [u8; 24], cosignatories: &[[u8; 24]]) {
        let entry = executor
            .multisigs
            .get_or_insert_with(multisig, Default::default);
        entry.cosignatories.extend(cosignatories);
        entry.min_approval = cosignatories.len() as u32;
        entry.min_removal = cosignatories.len() as u32;
        for cosignatory in cosignatories {
            executor
                .multisigs
                .get_or_insert_with(*cosignatory, Default::default)
                .multisigs
                .insert(multisig);
        }
    }

    fn modify(
        executor: &mut Executor,
        multisig: [u8; 24],
        approval: i8,
        removal: i8,
        additions: &[[u8; 24]],
        deletions: &[[u8; 24]],
    ) -> u64 {
        let modification = MultisigAccountModification {
            min_removal_delta: removal,
            min_approval_delta: approval,
            address_additions: unresolved(additions),
            address_deletions: unresolved(deletions),
        };
        let rule = rejected(executor, |e| {
            e.check_multisig_modification(multisig, &modification)
        });
        assert!(
            rule.as_deref()
                .is_none_or(|rule| rule == "MultisigModification")
        );
        // 弾いたら 1
        u64::from(rule.is_some())
    }

    #[test]
    fn multisig_cosignatories_and_settings() {
        let mut executor = executor();
        let (a, b, c) = (address(1), address(2), address(3));
        // 新しく 2-of-2 にする
        assert_eq!(modify(&mut executor, a, 2, 1, &[b, c], &[]), 0);
        // マルチシグでないのに外す、承認の数が連署者より多い
        assert_eq!(modify(&mut executor, a, 0, 0, &[], &[b]), 1);
        assert_eq!(modify(&mut executor, a, 3, 1, &[b, c], &[]), 1);

        link_multisig(&mut executor, a, &[b, c]);
        // もう連署者、連署者でないものを外す
        assert_eq!(modify(&mut executor, a, 0, 0, &[b], &[]), 1);
        assert_eq!(modify(&mut executor, a, 0, 0, &[], &[address(4)]), 1);
        // 1人外して 1-of-1、最後まで外すなら両方 −1
        assert_eq!(modify(&mut executor, a, -1, -1, &[], &[c]), 0);
        assert_eq!(modify(&mut executor, a, -2, -2, &[], &[b, c]), 1);
        assert_eq!(modify(&mut executor, a, -1, -1, &[], &[b, c]), 0);
    }

    #[test]
    fn checks_partial_bonded_aggregates_against_the_multisig_and_the_lock() {
        use heika_core::hash::Hash256;
        use heika_core::signature::Signature;
        use heika_transaction::{
            Aggregate, Cosignature, EmbeddedTransaction, Transaction, Transfer,
        };

        use super::super::{HashLockInfo, PartialCheck};

        let mut executor = executor();
        let key = |n: u8| PublicKey([n; 32]);
        let (multisig, b, c) = (key(1), key(2), key(3));
        // 2-of-2 のマルチシグ。b が外側の署名者になって、マルチシグからの送金を出す
        let addresses = [multisig, b, c].map(|key| executor.address_of(&key));
        link_multisig(&mut executor, addresses[0], &addresses[1..]);
        let transfer = Body::Transfer(
            Transfer::new(
                UnresolvedAddress(addresses[1]),
                Default::default(),
                Vec::new(),
            )
            .unwrap(),
        );
        let inner = EmbeddedTransaction::new(multisig, executor.network, transfer);
        let bonded = |cosigners: &[PublicKey]| {
            let mut aggregate = Aggregate::new(vec![inner.clone()]).unwrap();
            for cosigner in cosigners {
                aggregate.add_cosignature(Cosignature {
                    signer_public_key: *cosigner,
                    signature: Signature([0; 64]),
                });
            }
            Transaction::new(b, executor.network, 0, 1, Body::AggregateBonded(aggregate))
        };
        assert_eq!(executor.check_partial(&bonded(&[])), PartialCheck::Missing);
        assert_eq!(
            executor.check_partial(&bonded(&[c])),
            PartialCheck::Complete
        );
        // 要らない人の連署
        assert_eq!(
            executor.check_partial(&bonded(&[c, key(4)])),
            PartialCheck::Ineligible(vec![key(4)])
        );

        // ハッシュロックは、使われておらず、期限が来ていないものだけ
        let hash = Hash256([7; 32]);
        assert!(!executor.hash_lock_ready(&hash));
        let lock = |status, end_height| HashLockInfo {
            owner: addresses[1],
            mosaic_id: 0,
            amount: 10_000_000,
            end_height,
            status,
        };
        executor.height = 10;
        executor
            .hash_locks
            .insert(hash.0, vec![lock(LockStatus::Unused, 11)]);
        assert!(executor.hash_lock_ready(&hash));
        executor
            .hash_locks
            .insert(hash.0, vec![lock(LockStatus::Unused, 10)]);
        assert!(!executor.hash_lock_ready(&hash));
        executor
            .hash_locks
            .insert(hash.0, vec![lock(LockStatus::Used, 11)]);
        assert!(!executor.hash_lock_ready(&hash));
    }

    #[test]
    fn multisig_depth_and_loops() {
        let mut executor = executor();
        let [a, b, c, d, e] = [1, 2, 3, 4, 5].map(address);
        // a ← b ← c（b は a の連署者、c は b の連署者）
        link_multisig(&mut executor, a, &[b]);
        link_multisig(&mut executor, b, &[c]);
        assert_eq!(executor.multisig_walk(c, true).0, 2);
        assert_eq!(executor.multisig_walk(a, false).0, 2);
        // c に、連署者のいない d を付けると深さ 3
        assert_eq!(modify(&mut executor, c, 1, 1, &[d], &[]), 0);
        // d に連署者 e がいると深さ 4
        link_multisig(&mut executor, d, &[e]);
        assert_eq!(modify(&mut executor, c, 1, 1, &[d], &[]), 1);
        // b に a を付けると輪になる
        assert_eq!(modify(&mut executor, b, 0, 0, &[a], &[]), 1);
    }

    #[test]
    fn key_links_need_a_free_slot_or_the_same_key() {
        let mut executor = executor();
        let signer = address(1);
        let mut account = AccountState::new(signer, 1);
        account.vrf = Some([9; 32]);
        account.voting = (0..3)
            .map(|n| VotingKey {
                key: [n; 32],
                start_epoch: u32::from(n) * 10 + 1,
                end_epoch: u32::from(n) * 10 + 10,
            })
            .collect();
        executor.accounts.insert(signer, account);
        let vrf = |key, link_action| {
            Body::VrfKeyLink(KeyLink {
                linked_public_key: PublicKey(key),
                link_action,
            })
        };
        let body = |executor: &mut Executor, body: Body| {
            rejected(executor, |e| e.check_body_rules(HEIGHT, signer, &body))
        };
        assert_eq!(body(&mut executor, vrf([9; 32], LinkAction::Unlink)), None);
        assert_eq!(
            body(&mut executor, vrf([8; 32], LinkAction::Unlink)).as_deref(),
            Some("KeyLink")
        );
        assert_eq!(
            body(&mut executor, vrf([8; 32], LinkAction::Link)).as_deref(),
            Some("KeyLink")
        );

        let voting = |start_epoch| {
            Body::VotingKeyLink(VotingKeyLink {
                linked_public_key: PublicKey([7; 32]),
                start_epoch,
                end_epoch: start_epoch + 9,
                link_action: LinkAction::Link,
            })
        };
        // もう3つある
        assert_eq!(
            body(&mut executor, voting(31)).as_deref(),
            Some("VotingKeyLink")
        );
        // 2つなら、最後の終わりより後から始まるものだけ
        executor.accounts.get_mut(&signer).unwrap().voting.pop();
        assert_eq!(
            body(&mut executor, voting(20)).as_deref(),
            Some("VotingKeyLink")
        );
        assert_eq!(body(&mut executor, voting(21)), None);
    }

    #[test]
    fn locks_are_alive_until_used_or_ended() {
        let executor = executor();
        assert!(executor.lock_alive(Some((LockStatus::Unused, HEIGHT + 1)), HEIGHT));
        assert!(!executor.lock_alive(Some((LockStatus::Unused, HEIGHT)), HEIGHT));
        assert!(!executor.lock_alive(Some((LockStatus::Used, HEIGHT + 1)), HEIGHT));
        assert!(!executor.lock_alive(None, HEIGHT));
    }

    fn restrictable_mosaic(executor: &mut Executor, id: u64, owner: [u8; 24]) {
        executor.mosaics.insert(
            id,
            MosaicEntry {
                supply: 10,
                start_height: 1,
                owner,
                revision: 1,
                flags: MosaicFlags::RESTRICTABLE.bits() | MosaicFlags::TRANSFERABLE.bits(),
                divisibility: 0,
                duration: 0,
            },
        );
    }

    /// 全体の制限の規則（キー → 参照するモザイク、値、種類）を置く
    fn set_global(executor: &mut Executor, id: u64, rules: &[(u64, u64, u64, u8)]) {
        executor.mosaic_restrictions.insert(
            mosaic_restriction_key(id, &[0; 24]),
            MosaicRestrictionEntry::Global {
                mosaic_id: id,
                rules: rules
                    .iter()
                    .map(|&(key, reference, value, kind)| (key, (reference, value, kind)))
                    .collect(),
            },
        );
    }

    fn set_address(executor: &mut Executor, id: u64, address: [u8; 24], values: &[(u64, u64)]) {
        executor.mosaic_restrictions.insert(
            mosaic_restriction_key(id, &address),
            MosaicRestrictionEntry::Address {
                mosaic_id: id,
                address,
                values: values.iter().copied().collect(),
            },
        );
    }

    fn global(
        id: u64,
        reference: u64,
        key: u64,
        previous: (u64, MosaicRestrictionType),
        new: (u64, MosaicRestrictionType),
    ) -> heika_transaction::MosaicGlobalRestriction {
        heika_transaction::MosaicGlobalRestriction {
            mosaic_id: UnresolvedMosaicId(id),
            reference_mosaic_id: UnresolvedMosaicId(reference),
            restriction_key: key,
            previous_restriction_value: previous.0,
            new_restriction_value: new.0,
            previous_restriction_type: previous.1,
            new_restriction_type: new.1,
        }
    }

    fn address_restriction(
        id: u64,
        key: u64,
        target: [u8; 24],
        previous: u64,
        new: u64,
    ) -> heika_transaction::MosaicAddressRestriction {
        heika_transaction::MosaicAddressRestriction {
            mosaic_id: UnresolvedMosaicId(id),
            restriction_key: key,
            previous_restriction_value: previous,
            new_restriction_value: new,
            target_address: UnresolvedAddress(target),
        }
    }

    #[test]
    fn mosaic_global_restriction_modifications() {
        use MosaicRestrictionType::{Eq, Ge, None as Unset};
        let mut executor = executor();
        let (owner, other) = (address(1), address(2));
        let (mosaic, reference) = (0x1234, 0x5678);
        restrictable_mosaic(&mut executor, mosaic, owner);
        let modify = |executor: &mut Executor, signer, restriction| {
            rejected(executor, |e| {
                e.check_global_restriction_modification(HEIGHT, signer, &restriction)
            })
        };
        let new_rule = global(mosaic, 0, 7, (0, Unset), (1, Eq));
        assert_eq!(modify(&mut executor, owner, new_rule), None);
        assert_eq!(
            modify(&mut executor, other, new_rule).as_deref(),
            Some("MosaicRestrictable")
        );
        executor.mosaics.get_mut(&mosaic).unwrap().flags = 0;
        assert_eq!(
            modify(&mut executor, owner, new_rule).as_deref(),
            Some("MosaicRestrictable")
        );
        restrictable_mosaic(&mut executor, mosaic, owner);
        // 制限がないのに消す
        assert_eq!(
            modify(
                &mut executor,
                owner,
                global(mosaic, 0, 7, (0, Unset), (0, Unset))
            )
            .as_deref(),
            Some("MosaicRestrictionMaxValues")
        );

        // 前の値は、参照するモザイク、値、種類のどれも合うこと。ないキーなら 0 と NONE
        set_global(&mut executor, mosaic, &[(7, 0, 1, 1)]);
        let update = |previous| global(mosaic, 0, 7, previous, (2, Ge));
        assert_eq!(modify(&mut executor, owner, update((1, Eq))), None);
        assert_eq!(
            modify(&mut executor, owner, update((2, Eq))).as_deref(),
            Some("MosaicRestrictionPrevious")
        );
        assert_eq!(
            modify(&mut executor, owner, update((1, Ge))).as_deref(),
            Some("MosaicRestrictionPrevious")
        );
        assert_eq!(
            modify(&mut executor, owner, global(mosaic, 0, 8, (1, Eq), (1, Eq))).as_deref(),
            Some("MosaicRestrictionPrevious")
        );
        assert_eq!(
            modify(
                &mut executor,
                owner,
                global(mosaic, 0, 7, (1, Eq), (0, Unset))
            ),
            None
        );
        // ないキーを消す
        assert_eq!(
            modify(
                &mut executor,
                owner,
                global(mosaic, 0, 8, (0, Unset), (0, Unset))
            )
            .as_deref(),
            Some("MosaicRestrictionMaxValues")
        );

        // 参照するモザイクの全体の制限に、同じキーがあること
        assert_eq!(
            modify(
                &mut executor,
                owner,
                global(mosaic, reference, 9, (0, Unset), (1, Eq))
            )
            .as_deref(),
            Some("MosaicRestrictionKey")
        );
        set_global(&mut executor, reference, &[(9, 0, 1, 1)]);
        assert_eq!(
            modify(
                &mut executor,
                owner,
                global(mosaic, reference, 9, (0, Unset), (1, Eq))
            ),
            None
        );

        // 値の数の上限は、新しいキーを足すときだけ
        let full: Vec<_> = (0..MAX_MOSAIC_RESTRICTION_VALUES as u64)
            .map(|key| (key, 0, 1, 1))
            .collect();
        set_global(&mut executor, mosaic, &full);
        assert_eq!(
            modify(
                &mut executor,
                owner,
                global(mosaic, 0, 100, (0, Unset), (1, Eq))
            )
            .as_deref(),
            Some("MosaicRestrictionMaxValues")
        );
        assert_eq!(
            modify(&mut executor, owner, global(mosaic, 0, 3, (1, Eq), (5, Ge))),
            None
        );
    }

    #[test]
    fn mosaic_address_restriction_modifications() {
        let mut executor = executor();
        let (owner, alice) = (address(1), address(2));
        let mosaic = 0x1234;
        restrictable_mosaic(&mut executor, mosaic, owner);
        let modify = |executor: &mut Executor, restriction| {
            rejected(executor, |e| {
                e.check_address_restriction_modification(HEIGHT, owner, &restriction)
            })
        };
        // 全体の制限に、そのキーがないとだめ
        assert_eq!(
            modify(
                &mut executor,
                address_restriction(mosaic, 7, alice, UNSET, 1)
            )
            .as_deref(),
            Some("MosaicRestrictionKey")
        );
        set_global(&mut executor, mosaic, &[(7, 0, 1, 1)]);
        assert_eq!(
            modify(
                &mut executor,
                address_restriction(mosaic, 7, alice, UNSET, 1)
            ),
            None
        );
        // ないときの前の値は 0 ではなく、値がないことを表す値
        assert_eq!(
            modify(&mut executor, address_restriction(mosaic, 7, alice, 0, 1)).as_deref(),
            Some("MosaicRestrictionPrevious")
        );
        assert_eq!(
            modify(
                &mut executor,
                address_restriction(mosaic, 7, alice, UNSET, UNSET)
            )
            .as_deref(),
            Some("MosaicRestrictionMaxValues")
        );
        set_address(&mut executor, mosaic, alice, &[(7, 1)]);
        assert_eq!(
            modify(
                &mut executor,
                address_restriction(mosaic, 7, alice, 1, UNSET)
            ),
            None
        );
        assert_eq!(
            modify(&mut executor, address_restriction(mosaic, 7, alice, 2, 3)).as_deref(),
            Some("MosaicRestrictionPrevious")
        );
    }

    #[test]
    fn mosaic_global_restrictions_authorize_both_sides() {
        let mut executor = executor();
        let (owner, alice, bob) = (address(1), address(2), address(3));
        let (mosaic, reference) = (0x1234, 0x5678);
        restrictable_mosaic(&mut executor, mosaic, owner);
        let moves = |executor: &mut Executor, addresses: &[[u8; 24]]| {
            rejected(executor, |e| {
                e.check_mosaic_authorization(mosaic, addresses)
            })
        };
        // 全体の制限がなければ、だれでも
        assert_eq!(moves(&mut executor, &[alice, bob]), None);

        // キー 7 が 5 以上（GE）。値がなければ満たさない
        set_global(&mut executor, mosaic, &[(7, 0, 5, 6)]);
        set_address(&mut executor, mosaic, alice, &[(7, 5)]);
        set_address(&mut executor, mosaic, bob, &[(7, 4)]);
        assert_eq!(moves(&mut executor, &[alice, alice]), None);
        assert_eq!(
            moves(&mut executor, &[alice, bob]).as_deref(),
            Some("MosaicAuthorization")
        );
        assert_eq!(
            moves(&mut executor, &[alice, address(4)]).as_deref(),
            Some("MosaicAuthorization")
        );

        // NE なら、値がないものは満たす
        set_global(&mut executor, mosaic, &[(7, 0, 4, 2)]);
        assert_eq!(moves(&mut executor, &[alice, address(4)]), None);
        assert_eq!(
            moves(&mut executor, &[alice, bob]).as_deref(),
            Some("MosaicAuthorization")
        );

        // 参照するモザイクのアドレスの制限で見る。自分を参照する規則は通らない
        set_global(&mut executor, mosaic, &[(7, reference, 1, 1)]);
        set_address(&mut executor, reference, alice, &[(7, 1)]);
        set_address(&mut executor, reference, bob, &[(7, 1)]);
        assert_eq!(moves(&mut executor, &[alice, bob]), None);
        set_global(&mut executor, mosaic, &[(7, mosaic, 1, 1)]);
        assert_eq!(
            moves(&mut executor, &[alice]).as_deref(),
            Some("MosaicAuthorization")
        );
    }
}
