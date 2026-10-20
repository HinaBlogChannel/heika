//! アカウントとモザイクの制限（restrictionaccount、restrictionmosaic プラグイン）を当てる。

use heika_transaction::{
    MosaicAddressRestriction, MosaicGlobalRestriction, TransactionType, UnresolvedMosaicId,
};

use super::*;

impl Executor {
    pub(super) fn apply_account_address_restriction(
        &mut self,
        signer: [u8; 24],
        restriction: &heika_transaction::AccountRestriction<UnresolvedAddress>,
    ) -> Result<(), ExecError> {
        let flags = restriction.restriction_flags.bits();
        let mut additions = Vec::new();
        for value in restriction.restriction_additions.iter() {
            additions.push(self.resolve_address(value)?.to_vec());
        }
        let mut deletions = Vec::new();
        for value in restriction.restriction_deletions.iter() {
            deletions.push(self.resolve_address(value)?.to_vec());
        }
        self.apply_account_restriction(signer, flags, additions, deletions);
        Ok(())
    }

    pub(super) fn apply_account_mosaic_restriction(
        &mut self,
        signer: [u8; 24],
        restriction: &heika_transaction::AccountRestriction<UnresolvedMosaicId>,
    ) -> Result<(), ExecError> {
        let flags = restriction.restriction_flags.bits();
        let mut additions = Vec::new();
        for value in restriction.restriction_additions.iter() {
            additions.push(self.resolve_mosaic(value.0)?.to_le_bytes().to_vec());
        }
        let mut deletions = Vec::new();
        for value in restriction.restriction_deletions.iter() {
            deletions.push(self.resolve_mosaic(value.0)?.to_le_bytes().to_vec());
        }
        self.apply_account_restriction(signer, flags, additions, deletions);
        Ok(())
    }

    pub(super) fn apply_account_operation_restriction(
        &mut self,
        signer: [u8; 24],
        restriction: &heika_transaction::AccountRestriction<TransactionType>,
    ) -> Result<(), ExecError> {
        let flags = restriction.restriction_flags.bits();
        let values = |list: &[heika_transaction::TransactionType]| {
            list.iter()
                .map(|value| value.0.to_le_bytes().to_vec())
                .collect()
        };
        self.apply_account_restriction(
            signer,
            flags,
            values(&restriction.restriction_additions),
            values(&restriction.restriction_deletions),
        );
        Ok(())
    }

    pub(super) fn apply_mosaic_global_restriction(
        &mut self,
        restriction: &MosaicGlobalRestriction,
    ) -> Result<(), ExecError> {
        let mosaic_id = self.resolve_mosaic(restriction.mosaic_id.0)?;
        let reference = self.resolve_mosaic(restriction.reference_mosaic_id.0)?;
        let key = mosaic_restriction_key(mosaic_id, &[0; 24]);
        self.touch(SubCache::MosaicRestriction, &key);
        let entry =
            self.mosaic_restrictions
                .entry(key)
                .or_insert_with(|| MosaicRestrictionEntry::Global {
                    mosaic_id,
                    rules: BTreeMap::new(),
                });
        let MosaicRestrictionEntry::Global { rules, .. } = entry else {
            return Err(invalid("全体の制限のキーがアドレスの制限です"));
        };
        let restriction_type = mosaic_restriction_type(restriction.new_restriction_type);
        if restriction_type == 0 {
            rules.remove(&restriction.restriction_key);
        } else {
            rules.insert(
                restriction.restriction_key,
                (
                    reference,
                    restriction.new_restriction_value,
                    restriction_type,
                ),
            );
        }
        if entry.is_empty() {
            self.mosaic_restrictions.remove(&key);
        }
        Ok(())
    }

    pub(super) fn apply_mosaic_address_restriction(
        &mut self,
        restriction: &MosaicAddressRestriction,
    ) -> Result<(), ExecError> {
        let mosaic_id = self.resolve_mosaic(restriction.mosaic_id.0)?;
        let address = self.resolve_address(&restriction.target_address)?;
        let key = mosaic_restriction_key(mosaic_id, &address);
        self.touch(SubCache::MosaicRestriction, &key);
        let entry = self.mosaic_restrictions.entry(key).or_insert_with(|| {
            MosaicRestrictionEntry::Address {
                mosaic_id,
                address,
                values: BTreeMap::new(),
            }
        });
        let MosaicRestrictionEntry::Address { values, .. } = entry else {
            return Err(invalid("アドレスの制限のキーが全体の制限です"));
        };
        if restriction.new_restriction_value == MOSAIC_RESTRICTION_REMOVAL {
            values.remove(&restriction.restriction_key);
        } else {
            values.insert(
                restriction.restriction_key,
                restriction.new_restriction_value,
            );
        }
        if entry.is_empty() {
            self.mosaic_restrictions.remove(&key);
        }
        Ok(())
    }

    /// catapult の `AccountRestrictionValueModificationObserver`。足すものを先に、外すものをあとに1つずつ
    pub(super) fn apply_account_restriction(
        &mut self,
        address: [u8; 24],
        flags: u16,
        additions: Vec<Vec<u8>>,
        deletions: Vec<Vec<u8>>,
    ) {
        self.touch(SubCache::AccountRestriction, &address);
        let directional = flags & !RESTRICTION_BLOCK;
        let block = flags & RESTRICTION_BLOCK != 0;
        let restrictions = self
            .account_restrictions
            .entry(address)
            .or_insert_with(new_account_restrictions);
        let restriction = restrictions
            .get_mut(&directional)
            .expect("all four directional flags exist");
        for (value, add) in additions
            .into_iter()
            .map(|value| (value, true))
            .chain(deletions.into_iter().map(|value| (value, false)))
        {
            if block {
                restriction.descriptor = directional | RESTRICTION_BLOCK;
            }
            if add {
                restriction.values.insert(value);
            } else {
                restriction.values.remove(&value);
            }
            if !block {
                restriction.descriptor = directional;
                if restriction.values.is_empty() {
                    restriction.descriptor |= RESTRICTION_BLOCK;
                }
            }
        }
        if restrictions
            .values()
            .all(|restriction| restriction.values.is_empty())
        {
            self.account_restrictions.remove(&address);
        }
    }
}
