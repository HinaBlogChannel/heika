//! ネームスペースの登録とエイリアス（namespace プラグイン）を当てる。

use heika_transaction::{AddressAlias, MosaicAlias, NamespaceRegistration};

use super::*;

impl Executor {
    pub(super) fn apply_namespace_registration(
        &mut self,
        height: u64,
        signer: [u8; 24],
        is_nemesis_signer: bool,
        registration: &NamespaceRegistration,
    ) -> Result<(), ExecError> {
        let sink = self.config.namespace_rental_fee_sink.at(height).0;
        self.add_address(sink, height);
        let id = registration.id.0;
        match registration.registration_type {
            NamespaceRegistrationType::Root { duration } => {
                if !is_nemesis_signer && duration != 0 {
                    let fee = self.config.root_namespace_rental_fee_per_block
                        * duration
                        * u64::from(self.dynamic_fee_multiplier);
                    self.transfer(&signer, &sink, self.config.currency_mosaic_id, fee)?;
                    let receipt =
                        transfer_receipt(signer, sink, self.config.currency_mosaic_id, fee);
                    self.statement
                        .add_receipt(ReceiptBody::NamespaceRentalFee(receipt));
                }
                self.register_root(height, signer, id, duration)?;
            }
            NamespaceRegistrationType::Child { parent_id } => {
                self.check_child_namespace(height, &signer, id, parent_id.0)?;
                if !is_nemesis_signer {
                    let fee = self.config.child_namespace_rental_fee
                        * u64::from(self.dynamic_fee_multiplier);
                    self.transfer(&signer, &sink, self.config.currency_mosaic_id, fee)?;
                    let receipt =
                        transfer_receipt(signer, sink, self.config.currency_mosaic_id, fee);
                    self.statement
                        .add_receipt(ReceiptBody::NamespaceRentalFee(receipt));
                }
                let mut path = self
                    .namespace_paths
                    .get(&parent_id.0)
                    .ok_or_else(|| invalid("親のネームスペースがありません"))?
                    .clone();
                path.push(id);
                self.touch(SubCache::Namespace, &path[0].to_le_bytes());
                self.namespaces
                    .get_mut(&path[0])
                    .expect("path points to a root")
                    .children
                    .insert(path[1..].to_vec(), Alias::None);
                self.namespace_paths.insert(id, path);
            }
        }
        Ok(())
    }

    pub(super) fn apply_mosaic_alias(
        &mut self,
        height: u64,
        signer: [u8; 24],
        alias: &MosaicAlias,
    ) -> Result<(), ExecError> {
        let value = match alias.alias_action {
            AliasAction::Link => Alias::Mosaic(alias.mosaic_id.0),
            AliasAction::Unlink => Alias::None,
        };
        let data = Alias::Mosaic(alias.mosaic_id.0);
        self.check_alias(
            height,
            &signer,
            alias.namespace_id.0,
            alias.alias_action,
            data,
        )?;
        self.set_alias(alias.namespace_id.0, value)?;
        Ok(())
    }

    pub(super) fn apply_address_alias(
        &mut self,
        height: u64,
        signer: [u8; 24],
        alias: &AddressAlias,
    ) -> Result<(), ExecError> {
        let value = match alias.alias_action {
            AliasAction::Link => Alias::Address(alias.address.0),
            AliasAction::Unlink => Alias::None,
        };
        let data = Alias::Address(alias.address.0);
        self.check_alias(
            height,
            &signer,
            alias.namespace_id.0,
            alias.alias_action,
            data,
        )?;
        // AddressAlias: 指すアカウントがあること
        if !self.accounts.contains_key(&alias.address.0) {
            return Err(invalid(format!(
                "別名の指す {} のアカウントがありません",
                alias.address
            )));
        }
        self.set_alias(alias.namespace_id.0, value)?;
        Ok(())
    }

    pub(super) fn register_root(
        &mut self,
        height: u64,
        owner: [u8; 24],
        id: u64,
        duration: u64,
    ) -> Result<(), ExecError> {
        let new_end = if duration == 0 {
            u64::MAX
        } else {
            height + duration + self.config.namespace_grace_period
        };
        // RootNamespaceAvailability: 期限なしは Nemesis だけ。期限なしのものは取り直せない。
        // 猶予のあいだも含めて生きているあいだは、持ち主しか更新できない
        if height != 1 && duration == 0 {
            return Err(invalid(format!(
                "ネームスペース {id:016X} を期限なしで取れるのは Nemesis だけです"
            )));
        }
        if let Some(root) = self.namespaces.get(&id) {
            if root.end == u64::MAX || duration == 0 {
                return Err(invalid(format!(
                    "ネームスペース {id:016X} は期限なしなので取り直せません"
                )));
            }
            if root.start <= height && height < root.end && root.owner != owner {
                return Err(invalid(format!(
                    "ネームスペース {id:016X} はほかの人のものです"
                )));
            }
        }
        self.touch(SubCache::Namespace, &id.to_le_bytes());
        if let Some(root) = self.namespaces.get_mut(&id)
            && root.start <= height
            && height < root.end
            && root.owner == owner
        {
            // 猶予のあいだも含めて、持ち主の更新は今の終わりに期間を足す。子と別名はそのまま
            if root.end != u64::MAX {
                root.end += duration;
                let end = root.end;
                self.expire_at(end, SubCache::Namespace, &id.to_le_bytes());
                self.schedule_namespace_receipts(id, end);
            }
            return Ok(());
        }
        // 新しく取るか、期限が切れたものや持ち主の替わるものを取り直す。前の子と別名は引き継がない
        if let Some(previous) = self.namespaces.remove(&id) {
            for path in previous.children.keys() {
                self.namespace_paths
                    .remove(path.last().expect("child paths are not empty"));
            }
        }
        self.namespaces.insert(
            id,
            RootNamespace {
                owner,
                start: height,
                end: new_end,
                alias: Alias::None,
                children: BTreeMap::new(),
            },
        );
        self.namespace_paths.insert(id, vec![id]);
        self.expire_at(new_end, SubCache::Namespace, &id.to_le_bytes());
        self.schedule_namespace_receipts(id, new_end);
        Ok(())
    }

    /// 猶予を含めて `end` で終わるルートのネームスペースの、期限切れと消えたときのレシートを出す高さを覚える
    pub(super) fn schedule_namespace_receipts(&mut self, id: u64, end: u64) {
        if end == u64::MAX {
            return;
        }
        for height in [end - self.config.namespace_grace_period, end] {
            self.artifact_expiries
                .entry(height)
                .or_default()
                .insert(Artifact::Namespace(id));
        }
    }
}
