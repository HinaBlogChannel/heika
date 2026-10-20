//! 大きい状態の表（アカウント、マルチシグ、ハッシュロック、メタデータ）を全部はメモリに持たずに実行する
//! （`docs/archive/library.md` の「状態の置き場所」）。
//!
//! ブロックを当てる前に、要りそうなキーを読み込む（[`Executor::wanted_for`]）。当てている途中で、まだ読んで
//! いないキーを引いたら、表がそれを記録する。記録があったら、その実行はコミットせずに [`Executor::undo_attempt`]
//! で戻し、記録されたキーを読み込んでから当て直す。
//!
//! ハッシュロックは、期限がまだ来ていないロックを含むものだけを、いつもメモリに置く。期限の来る高さを覚えておく
//! 索引（`expiries`）を、メモリにあるものから組み直せるようにするため。期限の過ぎたものは、もう引かない。

use std::collections::BTreeSet;

use heika_block::Block;
use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::patricia::SubCache;
use heika_transaction::{Body, EmbeddedTransaction, MetadataKey, MetadataType, Transaction};

use heika_core::patricia::TreeNode;

use super::persist::row_key;
use super::source::StateSource;
use super::{ExecError, Executor, HashLockInfo};
use crate::account::AccountType;
use crate::config::ChainConfig;
use crate::table::Table;
use crate::tree::LazyTree;
use crate::tree::StateTree;
use crate::tree::{Position, ROOT, node_key};

/// 全部はメモリに持たない表の、キーの集まり
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Wanted {
    pub accounts: BTreeSet<[u8; 24]>,
    pub multisigs: BTreeSet<[u8; 24]>,
    pub hash_locks: BTreeSet<[u8; 32]>,
    pub metadata: BTreeSet<[u8; 32]>,
    /// 木のノード（木の番号、位置）。道から外れたもの（葉を外して合わせる兄弟など）
    pub nodes: BTreeSet<(u8, Position)>,
}

impl Wanted {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
            + self.multisigs.len()
            + self.hash_locks.len()
            + self.metadata.len()
            + self.nodes.len()
    }

    pub fn extend(&mut self, other: Wanted) {
        self.accounts.extend(other.accounts);
        self.multisigs.extend(other.multisigs);
        self.hash_locks.extend(other.hash_locks);
        self.metadata.extend(other.metadata);
        self.nodes.extend(other.nodes);
    }

    /// 保存の行のキー
    fn row_keys(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        let accounts = self
            .accounts
            .iter()
            .map(|key| row_key(SubCache::AccountState, key));
        let multisigs = self
            .multisigs
            .iter()
            .map(|key| row_key(SubCache::Multisig, key));
        let hash_locks = self
            .hash_locks
            .iter()
            .map(|key| row_key(SubCache::HashLockInfo, key));
        let metadata = self
            .metadata
            .iter()
            .map(|key| row_key(SubCache::Metadata, key));
        accounts.chain(multisigs).chain(hash_locks).chain(metadata)
    }
}

/// 全部はメモリに持たない表の番号
const PARTIAL: [SubCache; 4] = [
    SubCache::AccountState,
    SubCache::Multisig,
    SubCache::HashLockInfo,
    SubCache::Metadata,
];

/// 行のキー `key` が、全部はメモリに持たない表のものか
pub fn is_partial_row(key: &[u8]) -> bool {
    key.first().is_some_and(|cache| {
        PARTIAL
            .iter()
            .any(|partial| partial.index() == usize::from(*cache))
    })
}

impl Executor {
    /// 大きい表を全部はメモリに持たない形で戻す。`rows` は、全部メモリに持つ表の行と、ハッシュロックの行
    /// （期限の来ていないロックを含むものだけを持つ）。`meta` は木に入らない実行の状態。ほかは、要るときに
    /// [`Executor::load_wanted`] で読む
    pub fn restore_partial(
        config: ChainConfig,
        network: heika_core::network::NetworkIdentifier,
        generation_hash_seed: heika_core::network::GenerationHashSeed,
        rows: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
        meta: &[u8],
    ) -> Result<Self, ExecError> {
        // 投票者は大口のアカウントから探すので、大口より低い残高の投票者がいるネットワークでは全部が要る
        if config.finalization.min_voter_balance < config.min_harvester_balance {
            return Err(ExecError::Unsupported(
                "投票者の下限が大口の下限より低いネットワークでは、アカウントを全部メモリに持ちます"
                    .to_owned(),
            ));
        }
        let mut executor = Self::new(config, network, generation_hash_seed);
        executor.accounts = Table::partial();
        executor.multisigs = Table::partial();
        executor.hash_locks = Table::partial();
        executor.metadata = Table::partial();
        for cache in PARTIAL {
            executor.trees[cache.index()] = StateTree::Lazy(LazyTree::new());
        }
        executor.decode_meta(meta)?;
        let hash_lock = SubCache::HashLockInfo.index() as u8;
        for (key, value) in rows {
            if key.first() == Some(&hash_lock) {
                executor.load_row(&key, Some(&value))?;
                let id = <[u8; 32]>::try_from(&key[1..])
                    .map_err(|_| ExecError::Source("ハッシュロックのキー".to_owned()))?;
                if !executor.hash_lock_pending(&id) {
                    // 期限の過ぎたものは、まだ読んでいないことにする
                    executor.hash_locks.forget(&id);
                }
            } else if is_partial_row(&key) {
                return Err(ExecError::Invalid(
                    "全部はメモリに持たない表の行は渡さないでください".to_owned(),
                ));
            } else {
                executor.set_row(&key, Some(&value))?;
            }
        }
        // 行から戻したものは、根を求め直さなくてよい
        executor.dirty_rows.clear();
        executor.schedule_expiries();
        Ok(executor)
    }

    /// 大きい表を全部はメモリに持たない形か
    pub fn is_partial(&self) -> bool {
        !self.accounts.is_complete()
    }

    /// ハッシュロック `key` の中に、期限がまだ来ていないロックがあるか
    fn hash_lock_pending(&self, key: &[u8; 32]) -> bool {
        let height = self.height;
        self.hash_locks
            .peek(key)
            .is_some_and(|history: &Vec<HashLockInfo>| {
                history.iter().any(|lock| lock.end_height > height)
            })
    }

    /// 必要なノードだけを持つ木の根を、`source` から読む。戻したあと、根を求める前に呼ぶ
    pub fn load_tree_roots(&mut self, source: &dyn StateSource) -> Result<(), ExecError> {
        for cache in PARTIAL {
            self.load_node(source, cache, ROOT)?;
        }
        Ok(())
    }

    fn load_node(
        &mut self,
        source: &dyn StateSource,
        cache: SubCache,
        position: Position,
    ) -> Result<(), ExecError> {
        let Some(tree) = self.trees[cache.index()].as_lazy_mut() else {
            return Ok(());
        };
        if tree.is_loaded(&position) {
            return Ok(());
        }
        let node = source
            .node(&node_key(cache.index() as u8, &position))?
            .map(|bytes| {
                TreeNode::decode_all(&bytes)
                    .ok()
                    .and_then(|nodes| nodes.into_iter().next())
                    .ok_or_else(|| ExecError::Source("しまった木のノードが読めません".to_owned()))
            })
            .transpose()?;
        tree.load(position, node);
        Ok(())
    }

    /// `wanted` のうち、まだ読み込んでいないものを `source` から読む。行は、木の葉までの道のノードも読む。読んだ行の数
    pub fn load_wanted(
        &mut self,
        source: &dyn StateSource,
        wanted: &Wanted,
    ) -> Result<usize, ExecError> {
        let generation = self.height + 1;
        for cache in PARTIAL {
            if let Some(tree) = self.trees[cache.index()].as_lazy_mut() {
                tree.set_generation(generation);
            }
        }
        let mut loaded = 0;
        for key in wanted.row_keys() {
            let (cache, tree_key) = super::tree_key_of_row(&key);
            while let Some(next) = self.trees[cache.index()]
                .as_lazy_mut()
                .and_then(|tree| tree.next_on_path(&tree_key.0))
            {
                self.load_node(source, cache, next)?;
            }
            if self.is_row_loaded(&key) {
                continue;
            }
            let value = source.row(&key)?;
            self.load_row(&key, value.as_deref())?;
            loaded += 1;
        }
        for (cache, position) in &wanted.nodes {
            self.load_node(source, SubCache::ALL[usize::from(*cache)], *position)?;
        }
        // リモートの鍵のアカウントなら、リンクしたメインアカウントも要る（ハーベストの資格、手数料、Importance）
        let linked: BTreeSet<[u8; 24]> = wanted
            .accounts
            .iter()
            .filter_map(|address| self.accounts.peek(address))
            .filter(|account| account.account_type == AccountType::Remote)
            .filter_map(|account| account.linked)
            .map(|main| self.address_of(&PublicKey(main)))
            .filter(|address| !self.accounts.is_loaded(address))
            .collect();
        if !linked.is_empty() {
            let linked = Wanted {
                accounts: linked,
                ..Wanted::default()
            };
            loaded += self.load_wanted(source, &linked)?;
        }
        Ok(loaded)
    }

    fn is_row_loaded(&self, key: &[u8]) -> bool {
        let id = &key[1..];
        match SubCache::ALL.get(usize::from(key[0])) {
            Some(SubCache::AccountState) => {
                id.try_into().is_ok_and(|id| self.accounts.is_loaded(&id))
            }
            Some(SubCache::Multisig) => id.try_into().is_ok_and(|id| self.multisigs.is_loaded(&id)),
            Some(SubCache::HashLockInfo) => {
                id.try_into().is_ok_and(|id| self.hash_locks.is_loaded(&id))
            }
            Some(SubCache::Metadata) => id.try_into().is_ok_and(|id| self.metadata.is_loaded(&id)),
            _ => true,
        }
    }

    /// まだ読んでいないのに引かれたキー
    pub fn take_missed(&mut self) -> Wanted {
        let mut nodes = BTreeSet::new();
        for cache in PARTIAL {
            if let Some(tree) = self.trees[cache.index()].as_lazy_mut() {
                nodes.extend(
                    tree.take_missed()
                        .into_iter()
                        .map(|position| (cache.index() as u8, position)),
                );
            }
        }
        Wanted {
            accounts: self.accounts.take_missed(),
            multisigs: self.multisigs.take_missed(),
            hash_locks: self.hash_locks.take_missed(),
            metadata: self.metadata.take_missed(),
            nodes,
        }
    }

    /// `block` を確かめて当てるのに要りそうなキー。足りなければ当てる途中で記録されるので、ここは多くの
    /// ブロックで1回で済むためのもの
    pub fn wanted_for(&self, block: &Block) -> Wanted {
        let height = block.height;
        let mut wanted = Wanted::default();
        wanted.accounts.extend([
            self.address_of(&block.signer_public_key),
            block.beneficiary_address.0,
            self.config.harvest_network_fee_sink.at(height).0,
            self.config.mosaic_rental_fee_sink.at(height).0,
            self.config.namespace_rental_fee_sink.at(height).0,
        ]);
        // importance を求め直す高さと、importance ブロック（投票者も決まる）では、大口を全部たどる
        let grouping = self.config.importance_grouping;
        if height % grouping <= 1 {
            wanted.accounts.extend(self.high_value.iter().copied());
            wanted.accounts.extend(self.removed.iter().copied());
        }
        // この高さで期限の来るハッシュロック（いつもメモリにあるが、念のため）
        wanted
            .hash_locks
            .extend(self.locks_due(height, SubCache::HashLockInfo));
        for bytes in block.transactions() {
            let Ok(transaction) = Transaction::from_bytes(bytes) else {
                continue;
            };
            let signer = self.address_of(&transaction.signer_public_key);
            wanted.accounts.insert(signer);
            wanted.multisigs.insert(signer);
            match &transaction.body {
                Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
                    if matches!(transaction.body, Body::AggregateBonded(_)) {
                        wanted
                            .hash_locks
                            .insert(transaction.hash(&self.generation_hash_seed).0);
                    }
                    for cosignature in aggregate.cosignatures() {
                        let cosigner = self.address_of(&cosignature.signer_public_key);
                        wanted.accounts.insert(cosigner);
                        wanted.multisigs.insert(cosigner);
                    }
                    for inner in aggregate.transactions() {
                        self.want_body(inner, &mut wanted);
                    }
                }
                _ => self.want_inner_body(signer, &transaction.body, &mut wanted),
            }
        }
        wanted
    }

    fn want_body(&self, inner: &EmbeddedTransaction, wanted: &mut Wanted) {
        let signer = self.address_of(&inner.signer_public_key);
        wanted.accounts.insert(signer);
        wanted.multisigs.insert(signer);
        self.want_inner_body(signer, &inner.body, wanted);
    }

    fn want_inner_body(&self, signer: [u8; 24], body: &Body, wanted: &mut Wanted) {
        let metadata = |target, scoped, target_id, metadata_type| {
            MetadataKey {
                source_address: Address(signer),
                target_address: Address(target),
                scoped_metadata_key: scoped,
                target_id,
                metadata_type,
            }
            .unique_key()
            .0
        };
        match body {
            Body::Transfer(transfer) => {
                wanted
                    .accounts
                    .insert(self.peek_address(transfer.recipient_address()));
            }
            Body::HashLock(lock) => {
                wanted.hash_locks.insert(lock.hash.0);
            }
            Body::MultisigAccountModification(modification) => {
                for address in modification
                    .address_additions
                    .iter()
                    .chain(modification.address_deletions.iter())
                {
                    let address = self.peek_address(address);
                    wanted.accounts.insert(address);
                    wanted.multisigs.insert(address);
                }
            }
            Body::AccountMetadata(entry) => {
                let target = self.peek_address(&entry.target_address);
                wanted.accounts.insert(target);
                wanted.metadata.insert(metadata(
                    target,
                    entry.scoped_metadata_key,
                    0,
                    MetadataType::Account,
                ));
            }
            Body::MosaicMetadata(entry) => {
                let target = self.peek_address(&entry.metadata.target_address);
                wanted.accounts.insert(target);
                wanted.metadata.insert(metadata(
                    target,
                    entry.metadata.scoped_metadata_key,
                    self.peek_mosaic(entry.target_mosaic_id.0),
                    MetadataType::Mosaic,
                ));
            }
            Body::NamespaceMetadata(entry) => {
                let target = self.peek_address(&entry.metadata.target_address);
                wanted.accounts.insert(target);
                wanted.metadata.insert(metadata(
                    target,
                    entry.metadata.scoped_metadata_key,
                    entry.target_namespace_id.0,
                    MetadataType::Namespace,
                ));
            }
            _ => {}
        }
    }

    /// まだ読んでいないキーを引いて捨てる実行を、当てる前に戻す。`source` はまだ当てる前の状態
    /// （コミットしていない）、`checkpoint` は当てる前の高さの木に入らない実行の状態。直近のトランザクションの
    /// ハッシュは、`block` で足した分だけ外す（同じブロックをすぐ当て直すので、それで足りる）
    pub fn undo_attempt(
        &mut self,
        source: &dyn StateSource,
        checkpoint: &[u8],
        block: &Block,
    ) -> Result<(), ExecError> {
        // 木は、変える前のノードに戻す
        for cache in PARTIAL {
            if let Some(tree) = self.trees[cache.index()].as_lazy_mut() {
                tree.discard_changes();
            }
        }
        let accounts: BTreeSet<[u8; 24]> = self
            .touched
            .iter()
            .chain(self.unsaved_accounts.iter())
            .chain(self.dirty_accounts.iter())
            .copied()
            .collect();
        let rows: BTreeSet<Vec<u8>> = self
            .unsaved_rows
            .iter()
            .chain(self.dirty_rows.iter())
            .cloned()
            .collect();
        for key in accounts
            .iter()
            .map(|address| row_key(SubCache::AccountState, address))
            .chain(rows)
        {
            let value = source.row(&key)?;
            self.set_row(&key, value.as_deref())?;
        }
        for bytes in block.transactions() {
            let Ok(transaction) = Transaction::from_bytes(bytes) else {
                continue;
            };
            let hash = transaction.hash(&self.generation_hash_seed).0;
            self.recent_hashes.remove(&hash);
            if let Some(hashes) = self.hash_deadlines.get_mut(&transaction.deadline) {
                hashes.retain(|kept| *kept != hash);
            }
        }
        self.fee_multipliers.clear();
        self.high_value.clear();
        self.removed.clear();
        self.stale_secret_locks.clear();
        self.decode_meta(checkpoint)?;
        self.expiries.clear();
        self.artifact_expiries.clear();
        self.schedule_expiries();
        self.touched.clear();
        self.unsaved_accounts.clear();
        self.unsaved_rows.clear();
        self.statement = super::StatementBuilder::default();
        self.roots();
        self.forget_node_changes();
        self.take_missed();
        Ok(())
    }

    /// 要るものだけを読む形のとき、ブロックをコミットしたあとで、読み込んだ大きい表と木のノードを手放す。次に
    /// 要れば読み口から読む。ブロックをまたいで持っておくのは、読み口の側（[`super::source::CachedSource`]）。
    /// 期限の来ていないハッシュロックは、期限を処理するときに読み直さずに表をたどるので持っておく。変えてまだ
    /// しまっていないものも持っておく。手放した数
    pub fn release_loaded(&mut self) -> usize {
        if !self.is_partial() {
            return 0;
        }
        let (dirty, unsaved) = (&self.dirty_accounts, &self.unsaved_accounts);
        let mut released = self
            .accounts
            .release(|address| dirty.contains(address) || unsaved.contains(address));
        let changed = |cache: SubCache, key: &[u8]| {
            let row = row_key(cache, key);
            self.dirty_rows.contains(&row) || self.unsaved_rows.contains(&row)
        };
        let height = self.height;
        let pending: BTreeSet<[u8; 32]> = self
            .hash_locks
            .iter()
            .filter(|(_, history)| history.iter().any(|lock| lock.end_height > height))
            .map(|(key, _)| *key)
            .collect();
        released += self
            .multisigs
            .release(|key| changed(SubCache::Multisig, key));
        released += self
            .hash_locks
            .release(|key| pending.contains(key) || changed(SubCache::HashLockInfo, key));
        released += self
            .metadata
            .release(|key| changed(SubCache::Metadata, key));
        for cache in PARTIAL {
            if let Some(tree) = self.trees[cache.index()].as_lazy_mut() {
                released += tree.evict(0);
            }
        }
        released
    }
}
