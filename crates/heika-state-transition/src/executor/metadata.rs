//! メタデータ（metadata プラグイン）を当てる。

use super::*;

impl Executor {
    /// catapult の `MetadataValueObserver`。値は前の値との XOR で届く
    pub(super) fn apply_metadata(
        &mut self,
        source: [u8; 24],
        metadata: &heika_transaction::Metadata,
        target_id: u64,
        metadata_type: MetadataType,
    ) -> Result<(), ExecError> {
        // 対象の持ち主のアカウントも作られる（AccountAddressNotification）
        let target = self.resolve_address(&metadata.target_address)?;
        self.add_address(target, self.height + 1);
        let key = MetadataKey {
            source_address: Address(source),
            target_address: Address(target),
            scoped_metadata_key: metadata.scoped_metadata_key,
            target_id,
            metadata_type,
        };
        let mut size = metadata.value.len() as i32;
        if metadata.value_size_delta < 0 {
            size += i32::from(metadata.value_size_delta);
        }
        let size = usize::try_from(size).map_err(|_| invalid("メタデータの長さ"))?;
        let update = &metadata.value[..size];
        let unique = key.unique_key().0;
        self.touch(SubCache::Metadata, &unique);
        match self.metadata.get_mut(&unique) {
            None => {
                self.metadata.insert(unique, (key, update.to_vec()));
            }
            Some(_) if size == 0 => {
                self.metadata.remove(&unique);
            }
            Some((_, value)) => {
                value.resize(size, 0);
                for (byte, delta) in value.iter_mut().zip(update) {
                    *byte ^= delta;
                }
            }
        }
        Ok(())
    }
}
