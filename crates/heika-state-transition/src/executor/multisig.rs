//! マルチシグ（multisig プラグイン）を当てる。

use super::*;

impl Executor {
    pub(super) fn apply_multisig(
        &mut self,
        height: u64,
        multisig: [u8; 24],
        modification: &heika_transaction::MultisigAccountModification,
    ) -> Result<(), ExecError> {
        let mut additions = Vec::new();
        for address in modification.address_additions.iter() {
            let address = self.resolve_address(address)?;
            self.add_address(address, height);
            additions.push(address);
        }
        let mut deletions = Vec::new();
        for address in modification.address_deletions.iter() {
            deletions.push(self.resolve_address(address)?);
        }
        for address in std::iter::once(&multisig)
            .chain(&additions)
            .chain(&deletions)
        {
            self.touch(SubCache::Multisig, address);
        }
        let entry = self
            .multisigs
            .get_or_insert_with(multisig, Default::default);
        entry.min_approval = entry
            .min_approval
            .checked_add_signed(i32::from(modification.min_approval_delta))
            .ok_or_else(|| invalid("min approval"))?;
        entry.min_removal = entry
            .min_removal
            .checked_add_signed(i32::from(modification.min_removal_delta))
            .ok_or_else(|| invalid("min removal"))?;
        for address in &deletions {
            entry.cosignatories.remove(address);
        }
        for address in &additions {
            entry.cosignatories.insert(*address);
        }
        for address in deletions {
            let cosignatory = self.multisigs.get_or_insert_with(address, Default::default);
            cosignatory.multisigs.remove(&multisig);
            self.remove_multisig_if_empty(&address);
        }
        for address in additions {
            self.multisigs
                .get_or_insert_with(address, Default::default)
                .multisigs
                .insert(multisig);
        }
        self.remove_multisig_if_empty(&multisig);
        Ok(())
    }

    pub(super) fn remove_multisig_if_empty(&mut self, address: &[u8; 24]) {
        if self
            .multisigs
            .get(address)
            .is_some_and(|entry| entry.cosignatories.is_empty() && entry.multisigs.is_empty())
        {
            self.multisigs.remove(address);
        }
    }
}
