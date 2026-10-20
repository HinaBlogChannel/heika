//! 状態の木の葉と根。

use super::*;

impl Executor {
    /// 変わったアカウントの葉だけを置き直す。アカウントは消えないので、外すことはない
    pub(super) fn account_root(&mut self) -> Hash256 {
        let currency = self.config.currency_mosaic_id;
        let dirty = std::mem::take(&mut self.dirty_accounts);
        let accounts = &self.accounts;
        // アカウントがなければ葉を外す。前へ実行するだけならアカウントは消えないが、巻き戻すと消える
        let leaf = |address: &[u8; 24]| {
            (
                address_key(&Address(*address)),
                accounts
                    .get(address)
                    .map(|account| sha3(&account.to_state_bytes(currency))),
            )
        };
        // 葉の値はアカウントごとに決まるので、たくさんあれば並列に求める。importance を求め直す高さでは、大口が全部変わる
        let leaves: Vec<(Hash256, Option<Hash256>)> = if dirty.len() >= PARALLEL_LEAVES {
            let dirty: Vec<[u8; 24]> = dirty.into_iter().collect();
            dirty.par_iter().map(leaf).collect()
        } else {
            dirty.iter().map(leaf).collect()
        };
        let tree = &mut self.trees[SubCache::AccountState.index()];
        for (key, value) in leaves {
            match value {
                Some(value) => tree.set(key, value),
                None => tree.remove(&key),
            }
        }
        tree.root()
    }

    /// アカウント以外の木の、`key` の葉の値。木に入らなければ `None`
    pub(super) fn leaf(&self, cache: SubCache, key: &[u8]) -> Option<Hash256> {
        self.state_bytes(cache, key).map(|bytes| sha3(&bytes))
    }

    /// アカウント以外の木の、`key` の葉の値のもとになる、catapult の形のバイト列。木に入らなければ `None`
    pub(super) fn state_bytes(&self, cache: SubCache, key: &[u8]) -> Option<Vec<u8>> {
        let mut out = 1u16.to_le_bytes().to_vec();
        match cache {
            SubCache::Namespace => {
                let id = u64::from_le_bytes(key.try_into().ok()?);
                // 木に入るのは、猶予を含めた期限前のものだけ（catapult の `RootNamespaceHistory::isActive`）
                let root = self
                    .namespaces
                    .get(&id)
                    .filter(|root| root.start <= self.height && self.height < root.end)?;
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&root.owner);
                out.extend_from_slice(&root.start.to_le_bytes());
                out.extend_from_slice(&root.end.to_le_bytes());
                root.alias.encode(&mut out);
                out.extend_from_slice(&(root.children.len() as u64).to_le_bytes());
                for (path, alias) in &root.children {
                    out.push(path.len() as u8);
                    for id in path {
                        out.extend_from_slice(&id.to_le_bytes());
                    }
                    alias.encode(&mut out);
                }
            }
            SubCache::Mosaic => {
                // モザイクは期限が切れても木から外れない（catapult の `MosaicEntry::Is_Deactivation_Destructive` が false）
                let id = u64::from_le_bytes(key.try_into().ok()?);
                let entry = self.mosaics.get(&id)?;
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&entry.supply.to_le_bytes());
                out.extend_from_slice(&entry.start_height.to_le_bytes());
                out.extend_from_slice(&entry.owner);
                out.extend_from_slice(&entry.revision.to_le_bytes());
                out.push(entry.flags);
                out.push(entry.divisibility);
                out.extend_from_slice(&entry.duration.to_le_bytes());
            }
            SubCache::Multisig => {
                let entry = self.multisigs.get(&key.try_into().ok()?)?;
                out.extend_from_slice(&entry.min_approval.to_le_bytes());
                out.extend_from_slice(&entry.min_removal.to_le_bytes());
                out.extend_from_slice(key);
                for set in [&entry.cosignatories, &entry.multisigs] {
                    out.extend_from_slice(&(set.len() as u64).to_le_bytes());
                    for address in set {
                        out.extend_from_slice(address);
                    }
                }
            }
            SubCache::HashLockInfo => {
                // 木に入るのは、まだ使われておらず期限前のものだけ（catapult の `LockInfo::isActive`）
                let lock = self
                    .hash_locks
                    .get(&key.try_into().ok()?)?
                    .last()
                    .filter(|lock| {
                        lock.status == LockStatus::Unused && self.height < lock.end_height
                    })?;
                out.extend_from_slice(&lock.owner);
                out.extend_from_slice(&lock.mosaic_id.to_le_bytes());
                out.extend_from_slice(&lock.amount.to_le_bytes());
                out.extend_from_slice(&lock.end_height.to_le_bytes());
                out.push(lock.status as u8);
                out.extend_from_slice(key);
            }
            SubCache::SecretLockInfo => {
                let stale = self.stale_secret_locks.contains(key);
                let lock = self.secret_locks.get(key)?.last().filter(|lock| {
                    stale || (lock.status == LockStatus::Unused && self.height < lock.end_height)
                })?;
                out.extend_from_slice(&lock.owner);
                out.extend_from_slice(&lock.mosaic_id.to_le_bytes());
                out.extend_from_slice(&lock.amount.to_le_bytes());
                out.extend_from_slice(&lock.end_height.to_le_bytes());
                out.push(lock.status as u8);
                out.push(lock.hash_algorithm);
                out.extend_from_slice(&lock.secret);
                out.extend_from_slice(&lock.recipient);
            }
            SubCache::AccountRestriction => {
                let restrictions = self.account_restrictions.get(key)?;
                out.extend_from_slice(key);
                let used: Vec<_> = restrictions
                    .values()
                    .filter(|restriction| !restriction.values.is_empty())
                    .collect();
                out.extend_from_slice(&(used.len() as u64).to_le_bytes());
                for restriction in used {
                    out.extend_from_slice(&restriction.descriptor.to_le_bytes());
                    out.extend_from_slice(&(restriction.values.len() as u64).to_le_bytes());
                    for value in &restriction.values {
                        out.extend_from_slice(value);
                    }
                }
            }
            SubCache::Metadata => {
                let (key, value) = self.metadata.get(&key.try_into().ok()?)?;
                out.extend_from_slice(&key.source_address.0);
                out.extend_from_slice(&key.target_address.0);
                out.extend_from_slice(&key.scoped_metadata_key.to_le_bytes());
                out.extend_from_slice(&key.target_id.to_le_bytes());
                out.push(key.metadata_type as u8);
                out.extend_from_slice(&(value.len() as u16).to_le_bytes());
                out.extend_from_slice(value);
            }
            SubCache::MosaicRestriction => {
                out.extend_from_slice(&self.mosaic_restrictions.get(key)?.encode());
            }
            SubCache::AccountState => return None,
        }
        Some(out)
    }
}
