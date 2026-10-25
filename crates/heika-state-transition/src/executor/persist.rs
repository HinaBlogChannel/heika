//! 実行している状態を DB の行にする、行から戻す。
//!
//! 行のキーは、9本の木の番号（[`SubCache::index`]）を1バイト先に付けた、状態のキー（アドレス、ID、ハッシュ）。
//! 値は、木の葉と違って、履歴（importance と活動の記録の全部、ロックの履歴）も含めて書く。戻すときに要るため。
//! 大口のアカウントの集まりや手数料の倍率など、木に入らない実行の状態は、別の1つの値にまとめる。

use std::collections::{BTreeMap, BTreeSet};

use heika_core::address::Address;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::patricia::SubCache;
use heika_transaction::{MetadataKey, MetadataType};

use crate::account::{AccountState, AccountType, BUCKETS, Bucket, SNAPSHOTS, Snapshot, VotingKey};
use heika_block::scoring::BlockStatistic;

use super::{
    AccountRestriction, Alias, ExecError, Executor, HashLockInfo, LockStatus, MosaicEntry,
    MosaicRestrictionEntry, MultisigEntry, RootNamespace, SecretLockInfo,
};
use crate::config::ChainConfig;

/// 書く行と消す行。
#[derive(Default, Debug)]
pub struct StateChanges {
    pub puts: Vec<(Vec<u8>, Vec<u8>)>,
    pub deletes: Vec<Vec<u8>>,
}

impl Executor {
    /// 前に書いてから変わったかもしれない行。今の値を書くか、なくなっていれば消す。
    pub fn take_changes(&mut self) -> StateChanges {
        let mut changes = StateChanges::default();
        for address in std::mem::take(&mut self.unsaved_accounts) {
            if let Some(account) = self.accounts.get(&address) {
                changes.puts.push((
                    row_key(SubCache::AccountState, &address),
                    encode_account(account),
                ));
            }
        }
        for row in std::mem::take(&mut self.unsaved_rows) {
            match self.encode_row(&row) {
                Some(value) => changes.puts.push((row, value)),
                None => changes.deletes.push(row),
            }
        }
        changes
    }

    /// アカウント以外の行の値。なければ `None`
    fn encode_row(&self, row: &[u8]) -> Option<Vec<u8>> {
        let (&cache, key) = row.split_first()?;
        let id = || key.try_into().ok().map(u64::from_le_bytes);
        let array = <[u8; 32]>::try_from(key).ok();
        let address = <[u8; 24]>::try_from(key).ok();
        Some(match SubCache::ALL[usize::from(cache)] {
            SubCache::Namespace => encode_namespace(self.namespaces.get(&id()?)?),
            SubCache::Mosaic => encode_mosaic(self.mosaics.get(&id()?)?),
            SubCache::Multisig => encode_multisig(self.multisigs.get(&address?)?),
            SubCache::HashLockInfo => encode_hash_locks(self.hash_locks.get(&array?)?),
            SubCache::SecretLockInfo => encode_secret_locks(self.secret_locks.get(&array?)?),
            SubCache::AccountRestriction => {
                encode_account_restrictions(self.account_restrictions.get(&address?)?)
            }
            SubCache::Metadata => {
                let (key, value) = self.metadata.get(&array?)?;
                encode_metadata(key, value)
            }
            SubCache::MosaicRestriction => self.mosaic_restrictions.get(&array?)?.encode(),
            SubCache::AccountState => return None,
        })
    }

    /// 行と、木に入らない実行の状態から戻す。木は、最初に根を求めるときに組み直す。
    pub fn restore(
        config: ChainConfig,
        network: NetworkIdentifier,
        generation_hash_seed: GenerationHashSeed,
        rows: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
        meta: &[u8],
    ) -> Result<Self, ExecError> {
        let mut executor = Self::from_rows(config, network, generation_hash_seed, rows)?;
        executor.decode_meta(meta)?;
        executor.schedule_expiries();
        Ok(executor)
    }

    /// 行だけから、`height` のあとの木を組めるように戻す。木に入らない実行の状態は戻らないので、続きは実行できない。
    /// 昔の高さの根を確かめるのに使う
    pub fn restore_rows(
        config: ChainConfig,
        network: NetworkIdentifier,
        generation_hash_seed: GenerationHashSeed,
        rows: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
        height: u64,
    ) -> Result<Self, ExecError> {
        let mut executor = Self::from_rows(config, network, generation_hash_seed, rows)?;
        executor.height = height;
        // 木は丸ごと組むだけで、ノードの変化は使わない
        for tree in &mut executor.trees {
            tree.track_node_changes(false);
        }
        // 大口のアカウントは行からわかる。投票者を探すのに使う
        let (mosaic, min) = (
            executor.config.harvesting_mosaic_id,
            executor.config.min_harvester_balance,
        );
        executor.high_value = executor
            .accounts
            .iter()
            .filter(|(_, account)| account.balance(mosaic) >= min)
            .map(|(address, _)| *address)
            .collect();
        // 期限切れの処理を飛ばした高さで切れて、木に残っているシークレットロックも行からわかる。最後のロックが
        // 使われないまま飛ばした高さで切れていて、そのあと height までに、ほかのロックの期限で見直されていないもの
        let skipped = &executor.config.skip_secret_lock_expirations;
        executor.stale_secret_locks = executor
            .secret_locks
            .iter()
            .filter(|(_, history)| {
                history.last().is_some_and(|last| {
                    last.status == LockStatus::Unused
                        && last.end_height <= height
                        && skipped.contains(&last.end_height)
                        && !history.iter().any(|lock| {
                            last.end_height < lock.end_height
                                && lock.end_height <= height
                                && !skipped.contains(&lock.end_height)
                        })
                })
            })
            .map(|(key, _)| *key)
            .collect();
        Ok(executor)
    }

    fn from_rows(
        config: ChainConfig,
        network: NetworkIdentifier,
        generation_hash_seed: GenerationHashSeed,
        rows: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, ExecError> {
        let mut executor = Self::new(config, network, generation_hash_seed);
        for (key, value) in rows {
            executor.set_row(&key, Some(&value))?;
        }
        Ok(executor)
    }

    /// 状態の行（[`row_key`] と値）を置き換えるか、`None` なら消す。根を求め直すものとして印を付ける
    pub(super) fn set_row(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), ExecError> {
        let (&cache, id) = key.split_first().ok_or_else(|| corrupt("空のキー"))?;
        let mut reader = Reader::new(value.unwrap_or_default());
        match cache as usize {
            index if index == SubCache::AccountState.index() => {
                let address = array(id)?;
                // 行から戻すときは、まだ読んでいないキーを引いたことにはしない
                let account = match value {
                    Some(_) => Some(decode_account(&mut reader)?),
                    None => None,
                };
                self.accounts.load(address, account);
                self.dirty_accounts.insert(address);
            }
            index if index == SubCache::Namespace.index() => {
                let root_id = u64::from_le_bytes(id.try_into().map_err(|_| corrupt("ID"))?);
                // 前の子の経路は消してから、新しいもので入れ直す
                if let Some(old) = self.namespaces.remove(&root_id) {
                    for path in old.children.keys() {
                        if let Some(last) = path.last() {
                            self.namespace_paths.remove(last);
                        }
                    }
                    self.namespace_paths.remove(&root_id);
                }
                if value.is_some() {
                    let root = decode_namespace(&mut reader)?;
                    self.namespace_paths.insert(root_id, vec![root_id]);
                    for path in root.children.keys() {
                        let mut full = vec![root_id];
                        full.extend_from_slice(path);
                        self.namespace_paths
                            .insert(*path.last().ok_or_else(|| corrupt("子の経路"))?, full);
                    }
                    self.namespaces.insert(root_id, root);
                }
            }
            index if index == SubCache::Mosaic.index() => {
                let mosaic_id = u64::from_le_bytes(id.try_into().map_err(|_| corrupt("ID"))?);
                match value {
                    Some(_) => {
                        self.mosaics.insert(mosaic_id, decode_mosaic(&mut reader)?);
                    }
                    None => {
                        self.mosaics.remove(&mosaic_id);
                    }
                }
            }
            index if index == SubCache::Multisig.index() => {
                load_or_remove(&mut self.multisigs, array(id)?, value, || {
                    decode_multisig(&mut reader)
                })?;
            }
            index if index == SubCache::HashLockInfo.index() => {
                load_or_remove(&mut self.hash_locks, array(id)?, value, || {
                    decode_hash_locks(&mut reader)
                })?;
            }
            index if index == SubCache::SecretLockInfo.index() => {
                set_or_remove(&mut self.secret_locks, array(id)?, value, || {
                    decode_secret_locks(&mut reader)
                })?;
            }
            index if index == SubCache::AccountRestriction.index() => {
                set_or_remove(&mut self.account_restrictions, array(id)?, value, || {
                    decode_account_restrictions(&mut reader)
                })?;
            }
            index if index == SubCache::Metadata.index() => {
                load_or_remove(&mut self.metadata, array(id)?, value, || {
                    decode_metadata(&mut reader)
                })?;
            }
            index if index == SubCache::MosaicRestriction.index() => {
                set_or_remove(&mut self.mosaic_restrictions, array(id)?, value, || {
                    decode_mosaic_restriction(&mut reader)
                })?;
            }
            _ => return Err(corrupt(format!("知らない木の番号 {cache}"))),
        }
        reader.finish()?;
        if cache as usize != SubCache::AccountState.index() {
            self.dirty_rows.insert(key.to_vec());
        }
        Ok(())
    }

    /// 全部はメモリに持たない表（アカウント、マルチシグ、ハッシュロック、メタデータ）に、保存から読んだ行を入れる。
    /// `None` は、読んだらなかった。根を求め直す印は付けない（値は保存と同じなので）
    pub(super) fn load_row(&mut self, key: &[u8], value: Option<&[u8]>) -> Result<(), ExecError> {
        let (&cache, id) = key.split_first().ok_or_else(|| corrupt("空のキー"))?;
        let mut reader = Reader::new(value.unwrap_or_default());
        match SubCache::ALL.get(usize::from(cache)) {
            Some(SubCache::AccountState) => {
                let account = value.map(|_| decode_account(&mut reader)).transpose()?;
                self.accounts.load(array(id)?, account);
            }
            Some(SubCache::Multisig) => {
                load_or_remove(&mut self.multisigs, array(id)?, value, || {
                    decode_multisig(&mut reader)
                })?;
            }
            Some(SubCache::HashLockInfo) => {
                load_or_remove(&mut self.hash_locks, array(id)?, value, || {
                    decode_hash_locks(&mut reader)
                })?;
            }
            Some(SubCache::Metadata) => {
                load_or_remove(&mut self.metadata, array(id)?, value, || {
                    decode_metadata(&mut reader)
                })?;
            }
            _ => return Err(corrupt(format!("全部メモリに持つ表の行です（{cache}）"))),
        }
        reader.finish()
    }

    /// 巻き戻した高さ c に、メモリの状態を戻す。`rows` は c より上で変わった行の c のときの値
    /// （保存の `changes_above` で、巻き戻す前に読む）、`checkpoint` は c のチェックポイント。
    /// 木のノードの変化は捨てる（DB の木のノードは巻き戻しで戻っている）。二度入れを弾くハッシュは空になるので、
    /// 呼ぶ側が直前のブロックから [`Executor::remember_transactions`] で覚え直す。
    /// 戻したあとで、根が c のブロックの StateHash と合うかを確かめること
    pub fn revert(
        &mut self,
        rows: impl IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
        checkpoint: &[u8],
    ) -> Result<(), ExecError> {
        for (key, value) in rows {
            self.set_row(&key, value.as_deref())?;
        }
        self.fee_multipliers.clear();
        self.high_value.clear();
        self.removed.clear();
        self.stale_secret_locks.clear();
        self.decode_meta(checkpoint)?;
        self.expiries.clear();
        self.artifact_expiries.clear();
        self.schedule_expiries();
        self.recent_hashes.clear();
        self.hash_deadlines.clear();
        self.touched.clear();
        self.unsaved_accounts.clear();
        self.unsaved_rows.clear();
        self.statement = super::StatementBuilder::default();
        self.last_statement = heika_block::statement::BlockStatement::default();
        self.roots();
        self.forget_node_changes();
        Ok(())
    }

    /// アカウント以外の、今ある行のキーを全部
    pub(super) fn rows_for_rebuild(&self) -> BTreeSet<Vec<u8>> {
        let mut rows = BTreeSet::new();
        rows.extend(
            self.namespaces
                .keys()
                .map(|id| row_key(SubCache::Namespace, &id.to_le_bytes())),
        );
        rows.extend(
            self.mosaics
                .keys()
                .map(|id| row_key(SubCache::Mosaic, &id.to_le_bytes())),
        );
        rows.extend(
            self.multisigs
                .keys()
                .map(|key| row_key(SubCache::Multisig, key)),
        );
        rows.extend(
            self.hash_locks
                .keys()
                .map(|key| row_key(SubCache::HashLockInfo, key)),
        );
        rows.extend(
            self.secret_locks
                .keys()
                .map(|key| row_key(SubCache::SecretLockInfo, key)),
        );
        rows.extend(
            self.account_restrictions
                .keys()
                .map(|key| row_key(SubCache::AccountRestriction, key)),
        );
        rows.extend(
            self.mosaic_restrictions
                .keys()
                .map(|key| row_key(SubCache::MosaicRestriction, key)),
        );
        rows.extend(
            self.metadata
                .keys()
                .map(|key| row_key(SubCache::Metadata, key)),
        );
        rows
    }

    /// 戻したあとで、これから期限が来るネームスペースとロックを覚え直す
    pub(super) fn schedule_expiries(&mut self) {
        let height = self.height;
        let mut due = Vec::new();
        for (id, root) in &self.namespaces {
            if root.end > height {
                due.push((root.end, SubCache::Namespace, id.to_le_bytes().to_vec()));
            }
        }
        // 期限切れのロックは、この予定から探す。シークレットロックは、最後でないロックの終わりでも見直すので、
        // 履歴のどのロックの終わりも覚える
        for (hash, history) in self.hash_locks.iter() {
            for lock in history.iter().filter(|lock| lock.end_height > height) {
                due.push((lock.end_height, SubCache::HashLockInfo, hash.to_vec()));
            }
        }
        for (key, history) in &self.secret_locks {
            for lock in history.iter().filter(|lock| lock.end_height > height) {
                due.push((lock.end_height, SubCache::SecretLockInfo, key.to_vec()));
            }
        }
        for (end, cache, key) in due {
            self.expire_at(end, cache, &key);
        }
        // 期限切れのレシート。ネームスペースは猶予に入る高さと明ける高さ、モザイクは期限の高さ
        let namespaces: Vec<(u64, u64)> = self
            .namespaces
            .iter()
            .filter(|(_, root)| root.end != u64::MAX && root.end > height)
            .map(|(&id, root)| (id, root.end))
            .collect();
        for (id, end) in namespaces {
            self.schedule_namespace_receipts(id, end);
        }
        let mosaics: Vec<u64> = self.mosaics.keys().copied().collect();
        for id in mosaics {
            self.schedule_mosaic_receipt(id);
        }
        self.artifact_expiries = self.artifact_expiries.split_off(&(height + 1));
    }

    /// 木に入らない実行の状態。行と一緒にコミットする
    pub fn encode_meta(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.last_importance_height.to_le_bytes());
        out.extend_from_slice(&self.dynamic_fee_multiplier.to_le_bytes());
        out.extend_from_slice(&self.nemesis);
        out.push(match self.implicit_funding {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
        out.extend_from_slice(&(self.fee_multipliers.len() as u32).to_le_bytes());
        for value in &self.fee_multipliers {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for set in [&self.high_value, &self.removed] {
            out.extend_from_slice(&(set.len() as u64).to_le_bytes());
            for address in set {
                out.extend_from_slice(address);
            }
        }
        // 後から足したもの。前の DB では、ここで終わっている
        out.extend_from_slice(&(self.stale_secret_locks.len() as u64).to_le_bytes());
        for key in &self.stale_secret_locks {
            out.extend_from_slice(key);
        }
        match self.score {
            None => out.push(0),
            Some((total, last)) => {
                out.push(1);
                out.extend_from_slice(&total.to_le_bytes());
                out.extend_from_slice(&last.timestamp.to_le_bytes());
                out.extend_from_slice(&last.difficulty.to_le_bytes());
            }
        }
        out
    }

    pub(super) fn decode_meta(&mut self, bytes: &[u8]) -> Result<(), ExecError> {
        let mut reader = Reader::new(bytes);
        self.height = reader.u64()?;
        self.last_importance_height = reader.u64()?;
        self.dynamic_fee_multiplier = reader.u32()?;
        self.nemesis = reader.array()?;
        self.implicit_funding = match reader.u8()? {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(corrupt("implicit funding")),
        };
        for _ in 0..reader.u32()? {
            self.fee_multipliers.push_back(reader.u32()?);
        }
        for set in [&mut self.high_value, &mut self.removed] {
            for _ in 0..reader.u64()? {
                set.insert(reader.array()?);
            }
        }
        if !reader.rest.is_empty() {
            for _ in 0..reader.u64()? {
                self.stale_secret_locks.insert(reader.array()?);
            }
        }
        // スコアがなければ、呼ぶ側がしまったブロックから求めて入れる
        self.score = None;
        if !reader.rest.is_empty() && reader.u8()? == 1 {
            let total = u128::from_le_bytes(reader.array()?);
            let timestamp = reader.u64()?;
            let difficulty = reader.u64()?;
            self.score = Some((
                total,
                BlockStatistic {
                    timestamp,
                    difficulty,
                },
            ));
        }
        reader.finish()
    }
}

/// [`Executor::encode_meta`] の、実行した高さ
pub fn height_of_meta(meta: &[u8]) -> Result<u64, ExecError> {
    Reader::new(meta).u64()
}

/// アカウントの行（[`row_key`] が [`SubCache::AccountState`] の行）の値を読む。ノードが、ブロックを作る外で
/// アカウントのリンクを確かめるときに使う
pub fn decode_account_row(value: &[u8]) -> Result<AccountState, ExecError> {
    let mut reader = Reader::new(value);
    let account = decode_account(&mut reader)?;
    reader.finish()?;
    Ok(account)
}

/// ロックと制限の行（[`row_key`] が `cache` と `key` の行）の値を、catapult の状態のバイト列（版の番号のあと）に
/// する。状態の木の葉と同じ形で、ロックは履歴の最後のもの。使ったものや期限を過ぎたものでも、行があれば返す
/// （catapult の REST と同じ。木に入るのは、まだ使っておらず期限前のものだけ）。ほかの `cache` は `None`
pub fn lock_or_restriction_state(
    cache: SubCache,
    key: &[u8],
    value: &[u8],
) -> Result<Option<Vec<u8>>, ExecError> {
    let mut reader = Reader::new(value);
    let mut out = Vec::new();
    match cache {
        SubCache::HashLockInfo => match decode_hash_locks(&mut reader)?.last() {
            Some(lock) => super::roots::hash_lock_state(&mut out, key, lock),
            None => return Ok(None),
        },
        SubCache::SecretLockInfo => match decode_secret_locks(&mut reader)?.last() {
            Some(lock) => super::roots::secret_lock_state(&mut out, lock),
            None => return Ok(None),
        },
        SubCache::AccountRestriction => {
            let restrictions = decode_account_restrictions(&mut reader)?;
            super::roots::account_restrictions_state(&mut out, key, &restrictions);
        }
        SubCache::MosaicRestriction => out = decode_mosaic_restriction(&mut reader)?.encode(),
        _ => return Ok(None),
    }
    reader.finish()?;
    Ok(Some(out))
}

/// 行のキー
pub fn row_key(cache: SubCache, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + key.len());
    out.push(cache.index() as u8);
    out.extend_from_slice(key);
    out
}

fn corrupt(what: impl Into<String>) -> ExecError {
    ExecError::Source(format!("しまった状態が読めません: {}", what.into()))
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ExecError> {
    bytes.try_into().map_err(|_| corrupt("キーの長さ"))
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8], ExecError> {
        if self.rest.len() < size {
            return Err(corrupt("途中で切れています"));
        }
        let (head, rest) = self.rest.split_at(size);
        self.rest = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ExecError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, ExecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ExecError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ExecError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ExecError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn option32(&mut self) -> Result<Option<[u8; 32]>, ExecError> {
        Ok(match self.u8()? {
            0 => None,
            _ => Some(self.array()?),
        })
    }

    fn finish(&self) -> Result<(), ExecError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(corrupt("後ろに余りがあります"))
        }
    }
}

fn put_option32(out: &mut Vec<u8>, value: &Option<[u8; 32]>) {
    match value {
        None => out.push(0),
        Some(key) => {
            out.push(1);
            out.extend_from_slice(key);
        }
    }
}

fn encode_account(account: &AccountState) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&account.address);
    out.extend_from_slice(&account.address_height.to_le_bytes());
    out.extend_from_slice(&account.public_key);
    out.extend_from_slice(&account.public_key_height.to_le_bytes());
    out.push(account.account_type as u8);
    put_option32(&mut out, &account.linked);
    put_option32(&mut out, &account.node);
    put_option32(&mut out, &account.vrf);
    out.push(account.voting.len() as u8);
    for voting in &account.voting {
        out.extend_from_slice(&voting.key);
        out.extend_from_slice(&voting.start_epoch.to_le_bytes());
        out.extend_from_slice(&voting.end_epoch.to_le_bytes());
    }
    for snapshot in &account.snapshots {
        out.extend_from_slice(&snapshot.importance.to_le_bytes());
        out.extend_from_slice(&snapshot.height.to_le_bytes());
    }
    for bucket in &account.buckets {
        out.extend_from_slice(&bucket.start_height.to_le_bytes());
        out.extend_from_slice(&bucket.total_fees_paid.to_le_bytes());
        out.extend_from_slice(&bucket.beneficiary_count.to_le_bytes());
        out.extend_from_slice(&bucket.raw_score.to_le_bytes());
    }
    out.extend_from_slice(&(account.balances.len() as u32).to_le_bytes());
    for (id, amount) in &account.balances {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&amount.to_le_bytes());
    }
    out
}

fn decode_account(reader: &mut Reader) -> Result<AccountState, ExecError> {
    let mut account = AccountState::new(reader.array()?, reader.u64()?);
    account.public_key = reader.array()?;
    account.public_key_height = reader.u64()?;
    account.account_type = match reader.u8()? {
        0 => AccountType::Unlinked,
        1 => AccountType::Main,
        2 => AccountType::Remote,
        3 => AccountType::RemoteUnlinked,
        _ => return Err(corrupt("アカウントの種類")),
    };
    account.linked = reader.option32()?;
    account.node = reader.option32()?;
    account.vrf = reader.option32()?;
    for _ in 0..reader.u8()? {
        account.voting.push(VotingKey {
            key: reader.array()?,
            start_epoch: reader.u32()?,
            end_epoch: reader.u32()?,
        });
    }
    for index in 0..SNAPSHOTS {
        account.snapshots[index] = Snapshot {
            importance: reader.u64()?,
            height: reader.u64()?,
        };
    }
    for index in 0..BUCKETS {
        account.buckets[index] = Bucket {
            start_height: reader.u64()?,
            total_fees_paid: reader.u64()?,
            beneficiary_count: reader.u32()?,
            raw_score: reader.u64()?,
        };
    }
    for _ in 0..reader.u32()? {
        account.balances.insert(reader.u64()?, reader.u64()?);
    }
    Ok(account)
}

fn encode_alias(out: &mut Vec<u8>, alias: &Alias) {
    alias.encode(out);
}

fn decode_alias(reader: &mut Reader) -> Result<Alias, ExecError> {
    Ok(match reader.u8()? {
        0 => Alias::None,
        1 => Alias::Mosaic(reader.u64()?),
        2 => Alias::Address(reader.array()?),
        _ => return Err(corrupt("別名")),
    })
}

fn encode_namespace(root: &RootNamespace) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&root.owner);
    out.extend_from_slice(&root.start.to_le_bytes());
    out.extend_from_slice(&root.end.to_le_bytes());
    encode_alias(&mut out, &root.alias);
    out.extend_from_slice(&(root.children.len() as u64).to_le_bytes());
    for (path, alias) in &root.children {
        out.push(path.len() as u8);
        for id in path {
            out.extend_from_slice(&id.to_le_bytes());
        }
        encode_alias(&mut out, alias);
    }
    out
}

fn decode_namespace(reader: &mut Reader) -> Result<RootNamespace, ExecError> {
    let owner = reader.array()?;
    let start = reader.u64()?;
    let end = reader.u64()?;
    let alias = decode_alias(reader)?;
    let mut children = BTreeMap::new();
    for _ in 0..reader.u64()? {
        let mut path = Vec::new();
        for _ in 0..reader.u8()? {
            path.push(reader.u64()?);
        }
        children.insert(path, decode_alias(reader)?);
    }
    Ok(RootNamespace {
        owner,
        start,
        end,
        alias,
        children,
    })
}

fn encode_mosaic(entry: &MosaicEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&entry.supply.to_le_bytes());
    out.extend_from_slice(&entry.start_height.to_le_bytes());
    out.extend_from_slice(&entry.owner);
    out.extend_from_slice(&entry.revision.to_le_bytes());
    out.push(entry.flags);
    out.push(entry.divisibility);
    out.extend_from_slice(&entry.duration.to_le_bytes());
    out
}

fn decode_mosaic(reader: &mut Reader) -> Result<MosaicEntry, ExecError> {
    Ok(MosaicEntry {
        supply: reader.u64()?,
        start_height: reader.u64()?,
        owner: reader.array()?,
        revision: reader.u32()?,
        flags: reader.u8()?,
        divisibility: reader.u8()?,
        duration: reader.u64()?,
    })
}

fn encode_multisig(entry: &MultisigEntry) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&entry.min_approval.to_le_bytes());
    out.extend_from_slice(&entry.min_removal.to_le_bytes());
    for set in [&entry.cosignatories, &entry.multisigs] {
        out.extend_from_slice(&(set.len() as u64).to_le_bytes());
        for address in set {
            out.extend_from_slice(address);
        }
    }
    out
}

fn decode_multisig(reader: &mut Reader) -> Result<MultisigEntry, ExecError> {
    let mut entry = MultisigEntry {
        min_approval: reader.u32()?,
        min_removal: reader.u32()?,
        ..MultisigEntry::default()
    };
    for set in [&mut entry.cosignatories, &mut entry.multisigs] {
        for _ in 0..reader.u64()? {
            set.insert(reader.array()?);
        }
    }
    Ok(entry)
}

fn encode_hash_locks(history: &[HashLockInfo]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(history.len() as u32).to_le_bytes());
    for lock in history {
        out.extend_from_slice(&lock.owner);
        out.extend_from_slice(&lock.mosaic_id.to_le_bytes());
        out.extend_from_slice(&lock.amount.to_le_bytes());
        out.extend_from_slice(&lock.end_height.to_le_bytes());
        out.push(lock.status as u8);
    }
    out
}

fn decode_hash_locks(reader: &mut Reader) -> Result<Vec<HashLockInfo>, ExecError> {
    let mut history = Vec::new();
    for _ in 0..reader.u32()? {
        history.push(HashLockInfo {
            owner: reader.array()?,
            mosaic_id: reader.u64()?,
            amount: reader.u64()?,
            end_height: reader.u64()?,
            status: match reader.u8()? {
                0 => LockStatus::Unused,
                1 => LockStatus::Used,
                _ => return Err(corrupt("ロックの状態")),
            },
        });
    }
    Ok(history)
}

fn decode_status(reader: &mut Reader) -> Result<LockStatus, ExecError> {
    match reader.u8()? {
        0 => Ok(LockStatus::Unused),
        1 => Ok(LockStatus::Used),
        _ => Err(corrupt("ロックの状態")),
    }
}

fn encode_secret_locks(history: &[SecretLockInfo]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(history.len() as u32).to_le_bytes());
    for lock in history {
        out.extend_from_slice(&lock.owner);
        out.extend_from_slice(&lock.mosaic_id.to_le_bytes());
        out.extend_from_slice(&lock.amount.to_le_bytes());
        out.extend_from_slice(&lock.end_height.to_le_bytes());
        out.push(lock.status as u8);
        out.push(lock.hash_algorithm);
        out.extend_from_slice(&lock.secret);
        out.extend_from_slice(&lock.recipient);
    }
    out
}

fn decode_secret_locks(reader: &mut Reader) -> Result<Vec<SecretLockInfo>, ExecError> {
    let mut history = Vec::new();
    for _ in 0..reader.u32()? {
        history.push(SecretLockInfo {
            owner: reader.array()?,
            mosaic_id: reader.u64()?,
            amount: reader.u64()?,
            end_height: reader.u64()?,
            status: decode_status(reader)?,
            hash_algorithm: reader.u8()?,
            secret: reader.array()?,
            recipient: reader.array()?,
        });
    }
    Ok(history)
}

fn encode_account_restrictions(restrictions: &BTreeMap<u16, AccountRestriction>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(restrictions.len() as u8);
    for (flags, restriction) in restrictions {
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&restriction.descriptor.to_le_bytes());
        out.extend_from_slice(&(restriction.values.len() as u32).to_le_bytes());
        for value in &restriction.values {
            out.extend_from_slice(&(value.len() as u16).to_le_bytes());
            out.extend_from_slice(value);
        }
    }
    out
}

fn decode_account_restrictions(
    reader: &mut Reader,
) -> Result<BTreeMap<u16, AccountRestriction>, ExecError> {
    let mut restrictions = BTreeMap::new();
    for _ in 0..reader.u8()? {
        let flags = reader.u16()?;
        let descriptor = reader.u16()?;
        let mut values = BTreeSet::new();
        for _ in 0..reader.u32()? {
            let size = reader.u16()? as usize;
            values.insert(reader.take(size)?.to_vec());
        }
        restrictions.insert(flags, AccountRestriction { descriptor, values });
    }
    Ok(restrictions)
}

fn encode_metadata(key: &MetadataKey, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&key.source_address.0);
    out.extend_from_slice(&key.target_address.0);
    out.extend_from_slice(&key.scoped_metadata_key.to_le_bytes());
    out.extend_from_slice(&key.target_id.to_le_bytes());
    out.push(key.metadata_type as u8);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
    out
}

fn decode_mosaic_restriction(reader: &mut Reader) -> Result<MosaicRestrictionEntry, ExecError> {
    let entry_type = reader.u8()?;
    let mosaic_id = reader.u64()?;
    Ok(match entry_type {
        0 => {
            let address = reader.array()?;
            let mut values = BTreeMap::new();
            for _ in 0..reader.u8()? {
                values.insert(reader.u64()?, reader.u64()?);
            }
            MosaicRestrictionEntry::Address {
                mosaic_id,
                address,
                values,
            }
        }
        1 => {
            let mut rules = BTreeMap::new();
            for _ in 0..reader.u8()? {
                let key = reader.u64()?;
                rules.insert(key, (reader.u64()?, reader.u64()?, reader.u8()?));
            }
            MosaicRestrictionEntry::Global { mosaic_id, rules }
        }
        _ => return Err(corrupt("モザイクの制限の種類")),
    })
}

fn decode_metadata(reader: &mut Reader) -> Result<(MetadataKey, Vec<u8>), ExecError> {
    let key = MetadataKey {
        source_address: Address(reader.array()?),
        target_address: Address(reader.array()?),
        scoped_metadata_key: reader.u64()?,
        target_id: reader.u64()?,
        metadata_type: match reader.u8()? {
            0 => MetadataType::Account,
            1 => MetadataType::Mosaic,
            2 => MetadataType::Namespace,
            _ => return Err(corrupt("メタデータの種類")),
        },
    };
    let size = reader.u16()? as usize;
    Ok((key, reader.take(size)?.to_vec()))
}

/// 行の値があれば読んで入れ、なければ消す
/// [`set_or_remove`] の、[`super::table::Table`] に行から戻すもの。まだ読んでいないキーを引いたことにはしない
fn load_or_remove<K: Ord + Copy, V>(
    table: &mut crate::table::Table<K, V>,
    key: K,
    value: Option<&[u8]>,
    decode: impl FnOnce() -> Result<V, ExecError>,
) -> Result<(), ExecError> {
    let value = match value {
        Some(_) => Some(decode()?),
        None => None,
    };
    table.load(key, value);
    Ok(())
}

fn set_or_remove<K: Ord, V>(
    map: &mut std::collections::BTreeMap<K, V>,
    key: K,
    value: Option<&[u8]>,
    decode: impl FnOnce() -> Result<V, ExecError>,
) -> Result<(), ExecError> {
    match value {
        Some(_) => {
            map.insert(key, decode()?);
        }
        None => {
            map.remove(&key);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_rows_read_back() {
        let mut account = AccountState::new([0x68; 24], 7);
        account.public_key = [1; 32];
        account.account_type = AccountType::Main;
        account.linked = Some([2; 32]);
        account.node = Some([3; 32]);
        account.vrf = Some([4; 32]);
        account.credit(0x6BED_913F_A202_23F8, 10_000);
        let row = encode_account(&account);
        assert_eq!(decode_account_row(&row).unwrap(), account);
        // 余りのある行は読まない
        assert!(decode_account_row(&[row, vec![0]].concat()).is_err());
    }
}
