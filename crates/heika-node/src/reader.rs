//! API の読み役（[`heika_api::Reader`]）。先端を追うあいだの DB を、API のスレッドから読む。
//!
//! 状態は、今の行を catapult の葉のバイト列にしてから REST の JSON にする（[`heika_rest::state`] の逆向き）。
//! 葉と同じバイト列から作るので、受け取った側が JSON から組み直したハッシュは、木の葉と合う。
//! ブロックの9本の根は DB にしまっていないので、その高さの木の根のノードを読んで求め直す。差分が残っていない高さの
//! ブロックは、根を出せないので返さない。
//!
//! 状態は、`?height=` で指定された高さのものも、DB に残した差分から引く（[`Db::at`]）。
//!
//! ネームスペースの行はルートごとなので、子の ID で引かれたら、どのルートの子かを ID から求められないぶん、
//! ネームスペースの行を全部見て探す。
//!
//! トランザクションの行方は、メモリプール、連署を待つものの置き場と、直近のブロックの索引（[`crate::recent`]）で答える。索引より古い
//! トランザクションは知らないことにする。

use std::sync::Arc;

use heika_api::{
    AliasTarget, KeyedStates, MetadataFilter, MetadataPosition, NamespaceFilter, PageRequest,
    PartialFilter, StateError, TransactionFilter,
};
use heika_block::Block;
use heika_block::statement::BlockStatement;
use heika_chain::store::EXECUTOR_META;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::merkle::{self, Position};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::patricia::{SubCache, TreeNode};
use heika_mempool::SharedMempool;
use heika_mempool::partial::SharedPartialPool;
use heika_rest::block::{BlockHeader, BlockInfo, BlockMeta};
use heika_rest::merkle::{MerklePathItem, MerkleProofInfo, MerkleStateInfo};
use heika_rest::node::TransactionFeesJson;
use heika_rest::send::TransactionStatus;
use heika_rest::state::{
    AccountJson, MetadataEntryJson, MosaicStateJson, MultisigGraphLevel, MultisigJson,
    NamespaceInfo, NamespaceNameJson, RootNamespaceState,
};
use heika_rest::transaction::{
    TransactionInfo, TransactionJson, TransactionMeta, transaction_position,
};
use heika_state_transition::executor::persist::{
    decode_account_row, height_of_meta, lock_or_restriction_state, row_key,
};
use heika_state_transition::tree::{EMPTY_ROOT, ROOT, node_key, walk};
use heika_store_redb::search::{
    METADATA_BY_SOURCE, METADATA_BY_TARGET, METADATA_BY_TARGET_ID, NAMESPACE_BY_ADDRESS,
    NAMESPACE_BY_MOSAIC, NAMESPACE_BY_OWNER, NamespaceRow, namespace_ids, row_key_of, row_yields,
};
use heika_store_redb::{At, Db, DbError, MetadataFields, Now, Searches};
use heika_transaction::{Body, Transaction};

use crate::recent::SharedRecent;

/// 手数料の倍率を見る、直近のブロックの数。catapult の REST の `numBlocksTransactionFeeStats` の既定値
const FEE_STATS_BLOCKS: u64 = 300;

/// アグリゲートのトランザクションの種類（完了と保留）
const AGGREGATE_TYPES: [u16; 2] = [0x4141, 0x4241];

pub struct DbReader {
    db: Arc<Db>,
    network: NetworkIdentifier,
    /// 通貨のモザイク。アカウントの葉では、これを先に並べる
    currency: u64,
    seed: GenerationHashSeed,
    mempool: Arc<SharedMempool>,
    recent: SharedRecent,
    partials: Arc<SharedPartialPool>,
}

impl DbReader {
    pub fn new(
        db: Arc<Db>,
        network: NetworkIdentifier,
        currency: u64,
        seed: GenerationHashSeed,
        mempool: Arc<SharedMempool>,
        recent: SharedRecent,
        partials: Arc<SharedPartialPool>,
    ) -> Self {
        Self {
            db,
            network,
            currency,
            seed,
            mempool,
            recent,
            partials,
        }
    }

    /// 直近のブロック（ハッシュの表を作っていれば、しまってある全部のブロック）に入った `hash` のトランザクションと、
    /// 入った高さと、ブロックの中の番号
    fn recent_transaction(
        &self,
        hash: &Hash256,
    ) -> Result<Option<(Transaction, u64, u32, Block)>, String> {
        let found = self
            .recent
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .find(hash);
        // 直近のブロックになければ、ハッシュの表（storage.search の transactions）から
        let found = match found {
            Some(found) => Some(found),
            None => self
                .db
                .transaction_location(hash)
                .map_err(|error| error.to_string())?,
        };
        let Some((height, index)) = found else {
            return Ok(None);
        };
        // 索引を引いたあとに枝を取り替えていれば、ブロックがないか、違うものが入っている
        let Some(block) = self.read_block(height)? else {
            return Ok(None);
        };
        let transaction = block
            .transactions()
            .nth(index as usize)
            .and_then(|bytes| Transaction::from_bytes(bytes).ok())
            .filter(|transaction| transaction.hash(&self.seed) == *hash);
        Ok(transaction.map(|transaction| (transaction, height, index, block)))
    }

    /// 承認されたトランザクションを REST の形にする。`block` は入ったブロック
    fn confirmed_info(
        &self,
        transaction: &Transaction,
        block: &Block,
        height: u64,
        index: u32,
        id: Option<String>,
    ) -> TransactionInfo {
        TransactionInfo {
            id,
            meta: TransactionMeta {
                height: Some(height.to_string()),
                hash: Some(transaction.hash(&self.seed).to_string()),
                merkle_component_hash: Some(
                    transaction.merkle_component_hash(&self.seed).to_string(),
                ),
                index: Some(index),
                aggregate_hash: None,
                timestamp: Some(block.timestamp.to_string()),
                fee_multiplier: Some(block.fee_multiplier),
            },
            transaction: TransactionJson::from(transaction),
        }
    }

    /// 連署を待つものを、集まった連署を付けて REST の形にする。承認されていないので高さは "0"
    fn partial_info(&self, hash: &Hash256) -> Option<TransactionInfo> {
        let bytes = self.partials.lock().stitched(hash)?;
        let transaction = Transaction::from_bytes(&bytes).ok()?;
        Some(TransactionInfo {
            id: None,
            meta: TransactionMeta {
                height: Some("0".to_owned()),
                hash: Some(hash.to_string()),
                merkle_component_hash: Some(
                    transaction.merkle_component_hash(&self.seed).to_string(),
                ),
                index: Some(0),
                aggregate_hash: None,
                timestamp: None,
                fee_multiplier: None,
            },
            transaction: TransactionJson::from(&transaction),
        })
    }

    /// `transaction` に `address` が関わるか。外側の署名者、中のトランザクションの署名者、連署者、送金の宛先
    fn involves(&self, transaction: &Transaction, address: &Address) -> bool {
        let of = |key: &heika_core::key::PublicKey| Address::from_public_key(key, self.network);
        if of(&transaction.signer_public_key) == *address {
            return true;
        }
        let (Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate)) =
            &transaction.body
        else {
            return false;
        };
        aggregate
            .cosignatures()
            .iter()
            .any(|cosignature| of(&cosignature.signer_public_key) == *address)
            || aggregate.transactions().iter().any(|inner| {
                of(&inner.signer_public_key) == *address
                    || matches!(&inner.body, Body::Transfer(transfer)
                        if transfer.recipient_address().0 == address.0)
            })
    }

    fn read_block(&self, height: u64) -> Result<Option<Block>, String> {
        let Some(bytes) = self.db.block(height).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        Block::from_bytes(&bytes)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    /// 実行した高さ
    fn executed(&self) -> Result<u64, String> {
        match self
            .db
            .meta(EXECUTOR_META)
            .map_err(|error| error.to_string())?
        {
            Some(meta) => height_of_meta(&meta).map_err(|error| error.to_string()),
            None => Ok(0),
        }
    }

    /// `at` の高さの状態を引く先と、その高さ（`None` なら今と、実行した高さ）
    fn view(&self, at: Option<u64>) -> Result<(View, u64), StateError> {
        let tip = self.executed()?;
        let Some(height) = at else {
            let now = self
                .db
                .now()
                .map_err(|error| StateError::Other(error.to_string()))?;
            return Ok((View::Now(Box::new(now)), tip));
        };
        // 実行した高さより上を引くと、DB は今の値を返してしまう
        if height > tip {
            return Err(StateError::Ahead { height, tip });
        }
        match self.db.at(height) {
            Ok(past) => Ok((View::At(Box::new(past)), height)),
            Err(DbError::NoHistory { .. } | DbError::NotIndexed { .. }) => {
                Err(StateError::NoHistory { height })
            }
            Err(error) => Err(StateError::Other(error.to_string())),
        }
    }

    /// 状態の行。なければ `None`
    fn row(&self, view: &View, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        match view {
            View::Now(now) => now.state(key),
            View::At(past) => past.state(key),
        }
        .map_err(|error| StateError::Other(error.to_string()))
    }

    /// 状態の行を `keys` の順に。なければ `None`。全部を同じ高さで読む
    fn rows(&self, view: &View, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.row(view, key)).collect()
    }

    /// マルチシグの状態。`addresses` のうち、あるものだけを渡した順に
    fn multisigs_in(
        &self,
        view: &View,
        addresses: &[Address],
    ) -> Result<Vec<MultisigJson>, StateError> {
        let keys: Vec<_> = addresses
            .iter()
            .map(|address| row_key(SubCache::Multisig, &address.0))
            .collect();
        let mut out = Vec::new();
        for (address, row) in addresses.iter().zip(self.rows(view, &keys)?) {
            let Some(row) = row else { continue };
            // 行はアドレスを除いたもの。葉と同じく、二つの数のあとに入れる
            let (counts, rest) = row
                .split_at_checked(8)
                .ok_or_else(|| StateError::Other("マルチシグの行が短すぎます".to_owned()))?;
            let mut bytes = 1u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(counts);
            bytes.extend_from_slice(&address.0);
            bytes.extend_from_slice(rest);
            out.push(MultisigJson::from_state_bytes(&bytes).map_err(|error| error.to_string())?);
        }
        Ok(out)
    }

    /// 高さ `height` の状態の木 `cache` の根。差分が残っていなければ `None`
    fn root_at(&self, cache: SubCache, height: u64) -> Result<Option<Hash256>, String> {
        match self
            .db
            .trie_node_at(&node_key(cache.index() as u8, &ROOT), height)
        {
            Ok(Some(bytes)) => Ok(Some(decode_node(&bytes)?.hash())),
            Ok(None) => Ok(Some(EMPTY_ROOT)),
            Err(DbError::NoHistory { .. } | DbError::NotIndexed { .. }) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// メタデータの検索で、検索表のどこをなめるか。並べ方と、決まった項目だけで作ったキーの頭。
/// 頭に入らなかった項目は、なめたあとで絞る
fn metadata_prefixes(filter: &MetadataFilter) -> Vec<Vec<u8>> {
    let kind = filter.metadata_type;
    let (source, target) = (filter.source.map(|a| a.0), filter.target.map(|a| a.0));
    let target_id = filter.target_id.map(u64::to_be_bytes);
    let scoped_key = filter.scoped_key.map(u64::to_be_bytes);
    // 前から順に、決まっているところまでを頭にする
    let prefix = |head: u8, parts: &[Option<&[u8]>]| {
        let mut out = vec![head];
        for part in parts {
            let Some(part) = part else { break };
            out.extend_from_slice(part);
        }
        out
    };
    let kind_byte = kind.map(|kind| [kind]);
    if let Some(source) = &source {
        return vec![prefix(
            METADATA_BY_SOURCE,
            &[
                Some(source),
                kind_byte.as_ref().map(|k| &k[..]),
                target.as_ref().map(|t| &t[..]),
                target_id.as_ref().map(|i| &i[..]),
                scoped_key.as_ref().map(|k| &k[..]),
            ],
        )];
    }
    if let Some(target) = &target {
        return vec![prefix(
            METADATA_BY_TARGET,
            &[
                Some(target),
                kind_byte.as_ref().map(|k| &k[..]),
                target_id.as_ref().map(|i| &i[..]),
                scoped_key.as_ref().map(|k| &k[..]),
            ],
        )];
    }
    // 対象からの並べ方は、モザイクとネームスペースのメタデータだけを持つ
    let by_target_id = |kind: u8| {
        prefix(
            METADATA_BY_TARGET_ID,
            &[
                Some(&[kind][..]),
                target_id.as_ref().map(|i| &i[..]),
                scoped_key.as_ref().map(|k| &k[..]),
            ],
        )
    };
    match kind {
        Some(kind @ (1 | 2)) => vec![by_target_id(kind)],
        None if target_id.is_some_and(|id| id != [0; 8]) => vec![by_target_id(1), by_target_id(2)],
        // ほかは、宛先からの並べ方を全部なめる（全部のメタデータが1回ずつ入っている）
        _ => vec![vec![METADATA_BY_TARGET]],
    }
}

fn matches(filter: &MetadataFilter, fields: &MetadataFields) -> bool {
    filter.source.is_none_or(|source| source.0 == fields.source)
        && filter.target.is_none_or(|target| target.0 == fields.target)
        && filter.scoped_key.is_none_or(|key| key == fields.scoped_key)
        && filter.target_id.is_none_or(|id| id == fields.target_id)
        && filter
            .metadata_type
            .is_none_or(|kind| kind == fields.metadata_type)
}

/// 検索表の候補 `key` が、昔の高さの状態 `past` で、その行から出るか
fn existed(past: &At, key: &[u8]) -> Result<bool, DbError> {
    let Some(row) = row_key_of(key) else {
        return Ok(false);
    };
    Ok(past
        .state(&row)?
        .is_some_and(|value| row_yields(key, &value)))
}

/// 承認されたトランザクションが、検索の絞り込みに合うか。catapult の REST の条件と同じく、宛先は送金、シークレットロック、
/// シークレットの証明の `recipientAddress`、モザイクと額は送金の `mosaics` のどれか（額はモザイクと別に、どれかが範囲に入る）
fn transaction_matches(filter: &TransactionFilter, transaction: &Transaction) -> bool {
    if let Some(key) = filter.signer
        && transaction.signer_public_key != key
    {
        return false;
    }
    if !filter.types.is_empty() && !filter.types.contains(&transaction.body.transaction_type()) {
        return false;
    }
    if let Some(recipient) = filter.recipient {
        let found = match &transaction.body {
            Body::Transfer(transfer) => transfer.recipient_address().0,
            Body::SecretLock(lock) => lock.recipient_address.0,
            Body::SecretProof(proof) => proof.recipient_address.0,
            _ => return false,
        };
        if found != recipient {
            return false;
        }
    }
    if let Some(mosaic) = filter.mosaic {
        let Body::Transfer(transfer) = &transaction.body else {
            return false;
        };
        let mosaics = transfer.mosaics();
        if !mosaics.keys().any(|id| id.0 == mosaic) {
            return false;
        }
        if let Some(from) = filter.from_amount
            && !mosaics.values().any(|&amount| amount >= from)
        {
            return false;
        }
        if let Some(to) = filter.to_amount
            && !mosaics.values().any(|&amount| amount <= to)
        {
            return false;
        }
    }
    true
}

/// 状態を引く先
enum View {
    /// 今の状態。開いた時点の高さで読む
    Now(Box<Now>),
    /// ある高さのブロックを実行したあとの状態
    At(Box<At>),
}

/// 行は、葉のバイト列からバージョンを除いたもの（モザイクとネームスペースは ID も除く）
fn state_bytes(id: &[u8], row: &[u8]) -> Vec<u8> {
    let mut bytes = 1u16.to_le_bytes().to_vec();
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(row);
    bytes
}

fn decode_node(bytes: &[u8]) -> Result<TreeNode, String> {
    TreeNode::decode_all(bytes)
        .ok()
        .and_then(|nodes| nodes.into_iter().next())
        .ok_or_else(|| "しまった木のノードが読めません".to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

impl heika_api::Reader for DbReader {
    fn accounts(
        &self,
        addresses: &[Address],
        at: Option<u64>,
    ) -> Result<Vec<AccountJson>, StateError> {
        let (view, _) = self.view(at)?;
        let keys: Vec<_> = addresses
            .iter()
            .map(|address| row_key(SubCache::AccountState, &address.0))
            .collect();
        let mut out = Vec::new();
        for row in self.rows(&view, &keys)?.into_iter().flatten() {
            let account = decode_account_row(&row).map_err(|error| error.to_string())?;
            out.push(
                AccountJson::from_state_bytes(&account.to_state_bytes(self.currency))
                    .map_err(|error| error.to_string())?,
            );
        }
        Ok(out)
    }

    fn mosaics(&self, ids: &[u64], at: Option<u64>) -> Result<Vec<MosaicStateJson>, StateError> {
        let (view, _) = self.view(at)?;
        let keys: Vec<_> = ids
            .iter()
            .map(|id| row_key(SubCache::Mosaic, &id.to_le_bytes()))
            .collect();
        let mut out = Vec::new();
        for (id, row) in ids.iter().zip(self.rows(&view, &keys)?) {
            let Some(row) = row else { continue };
            out.push(
                MosaicStateJson::from_state_bytes(&state_bytes(&id.to_le_bytes(), &row))
                    .map_err(|error| error.to_string())?,
            );
        }
        Ok(out)
    }

    fn multisigs(
        &self,
        addresses: &[Address],
        at: Option<u64>,
    ) -> Result<Vec<MultisigJson>, StateError> {
        let (view, _) = self.view(at)?;
        self.multisigs_in(&view, addresses)
    }

    fn lock_or_restriction_states(
        &self,
        cache: SubCache,
        keys: &[Vec<u8>],
        at: Option<u64>,
    ) -> Result<KeyedStates, StateError> {
        let (view, _) = self.view(at)?;
        let rows: Vec<_> = keys.iter().map(|key| row_key(cache, key)).collect();
        let mut out = Vec::new();
        for (key, row) in keys.iter().zip(self.rows(&view, &rows)?) {
            let Some(row) = row else { continue };
            let Some(state) = lock_or_restriction_state(cache, key, &row)
                .map_err(|error| StateError::Other(error.to_string()))?
            else {
                continue;
            };
            let mut bytes = 1u16.to_le_bytes().to_vec();
            bytes.extend_from_slice(&state);
            out.push((key.clone(), bytes));
        }
        Ok(out)
    }

    fn multisig_graph(
        &self,
        address: &Address,
        at: Option<u64>,
    ) -> Result<Option<Vec<MultisigGraphLevel>>, StateError> {
        let (view, _) = self.view(at)?;
        heika_api::multisig_graph(address, |addresses| self.multisigs_in(&view, addresses))
    }

    fn namespace(&self, id: u64, at: Option<u64>) -> Result<Option<NamespaceInfo>, StateError> {
        let (view, height) = self.view(at)?;
        let root_bytes = |root_id: u64, row: &[u8]| state_bytes(&root_id.to_le_bytes(), row);
        let mut found = self
            .row(&view, &row_key(SubCache::Namespace, &id.to_le_bytes()))?
            .map(|row| root_bytes(id, &row));
        if found.is_none() {
            // 子。ID のバイト列を含む行だけを読んで確かめる
            let needle = id.to_le_bytes();
            let mut rows = Vec::new();
            let mut keep = |key: &[u8], row: &[u8]| {
                if row.windows(8).any(|window| window == needle)
                    && let Ok(root_id) = key[1..].try_into().map(u64::from_le_bytes)
                {
                    rows.push(root_bytes(root_id, row));
                }
            };
            let prefix = [SubCache::Namespace.index() as u8];
            match view {
                View::Now(_) => self.db.for_each_state_row(&prefix, &mut keep),
                View::At(_) => self
                    .db
                    .state_rows_with_prefix_at(&prefix, height)
                    .map(|past| past.iter().for_each(|(key, row)| keep(key, row))),
            }
            .map_err(|error| error.to_string())?;
            found = rows.into_iter().find(|bytes| {
                RootNamespaceState::from_state_bytes(bytes)
                    .is_ok_and(|state| state.info(id, 0).is_ok_and(|info| info.is_some()))
            });
        }
        let Some(bytes) = found else {
            return Ok(None);
        };
        Ok(RootNamespaceState::from_state_bytes(&bytes)
            .and_then(|state| state.info(id, height))
            .map_err(|error| error.to_string())?)
    }

    fn metadata(
        &self,
        composite_hash: &Hash256,
        at: Option<u64>,
    ) -> Result<Option<MetadataEntryJson>, StateError> {
        let (view, _) = self.view(at)?;
        let Some(row) = self.row(&view, &row_key(SubCache::Metadata, &composite_hash.0))? else {
            return Ok(None);
        };
        Ok(Some(
            MetadataEntryJson::from_state_bytes(&state_bytes(&[], &row))
                .map_err(|error| error.to_string())?,
        ))
    }

    fn search_metadata(
        &self,
        filter: &MetadataFilter,
        page: PageRequest,
        after: Option<&MetadataPosition>,
        at: Option<u64>,
    ) -> Result<Option<Vec<MetadataEntryJson>>, StateError> {
        let searches = self.db.searches();
        let wanted = match at {
            None => Searches::METADATA,
            Some(_) => Searches::METADATA.union(Searches::PAST),
        };
        if !searches.contains(wanted) {
            return Ok(None);
        }
        let (view, _) = self.view(at)?;
        let mut prefixes = metadata_prefixes(filter);
        if page.descending {
            prefixes.reverse();
        }
        let after = after.map(|after| MetadataFields {
            source: after.source.0,
            target: after.target.0,
            scoped_key: after.scoped_key,
            target_id: after.target_id,
            metadata_type: after.metadata_type,
        });
        let mut skip = (page.number - 1) * page.size;
        let mut found = Vec::new();
        let mut failed = None;
        for prefix in prefixes {
            // 位置は、この並べ方のキーにして渡す
            let after = after.map(|after| after.search_key(prefix[0]));
            let mut visit = |key: &[u8]| {
                let Some(fields) = MetadataFields::from_search_key(key) else {
                    return true;
                };
                if !matches(filter, &fields) {
                    return true;
                }
                // 昔の高さでは、候補がその高さにあったかを状態の行で確かめる
                if let View::At(past) = &view {
                    match existed(past, key) {
                        Ok(true) => {}
                        Ok(false) => return true,
                        Err(error) => {
                            failed = Some(error);
                            return false;
                        }
                    }
                }
                if skip > 0 {
                    skip -= 1;
                    return true;
                }
                found.push(fields);
                found.len() < page.size
            };
            let after = after.as_deref();
            match view {
                View::Now(_) => {
                    self.db
                        .for_each_search_key(&prefix, after, page.descending, &mut visit)
                }
                View::At(_) => self.db.for_each_search_key_with_past(
                    &prefix,
                    after,
                    page.descending,
                    &mut visit,
                ),
            }
            .map_err(|error| error.to_string())?;
            if let Some(error) = failed {
                return Err(StateError::Other(error.to_string()));
            }
            if found.len() >= page.size {
                break;
            }
        }
        let mut entries = Vec::with_capacity(found.len());
        for fields in found {
            let Some(hash) = fields.composite_hash().map(Hash256) else {
                continue;
            };
            // 検索表を読んだあとに消えていれば、飛ばす
            if let Some(entry) = self.metadata(&hash, at)? {
                entries.push(entry);
            }
        }
        Ok(Some(entries))
    }

    fn search_namespaces(
        &self,
        filter: &NamespaceFilter,
        page: PageRequest,
        after: Option<&[u8]>,
        at: Option<u64>,
    ) -> Result<Option<Vec<(String, NamespaceInfo)>>, StateError> {
        let wanted = match at {
            None => Searches::NAMESPACES,
            Some(_) => Searches::NAMESPACES.union(Searches::PAST),
        };
        if !self.db.searches().contains(wanted) {
            return Ok(None);
        }
        let (view, height) = self.view(at)?;
        let root_row =
            |root: u64| self.row(&view, &row_key(SubCache::Namespace, &root.to_le_bytes()));
        // 決まっている項目から、なめる並べ方と頭を選ぶ。ルートだけ決まっていれば、その持ち主から
        let prefix = match (filter.owner, filter.level0, filter.alias_type) {
            (Some(owner), level0, _) => {
                let mut prefix = [&[NAMESPACE_BY_OWNER][..], &owner.0].concat();
                if let Some(root) = level0 {
                    prefix.extend_from_slice(&root.to_be_bytes());
                }
                prefix
            }
            (None, Some(root), _) => {
                let Some(row) = root_row(root)?.and_then(|row| NamespaceRow::from_row(root, &row))
                else {
                    return Ok(Some(Vec::new()));
                };
                [&[NAMESPACE_BY_OWNER][..], &row.owner, &root.to_be_bytes()].concat()
            }
            (None, None, Some(1)) => vec![NAMESPACE_BY_MOSAIC],
            (None, None, Some(2)) => vec![NAMESPACE_BY_ADDRESS],
            (None, None, _) => vec![NAMESPACE_BY_OWNER],
        };
        if after.is_some_and(|after| after.first() != prefix.first()) {
            return Err(StateError::Invalid(
                "offset is not a position of this search".to_owned(),
            ));
        }
        let mut skip = (page.number - 1) * page.size;
        let mut found = Vec::new();
        let mut failed = None;
        // 同じルートの行は続けて出るので、最後に読んだものを覚えておく
        let mut last_root: Option<(u64, Option<Vec<u8>>)> = None;
        let mut visit = |key: &[u8]| {
            let Some((root, id)) = namespace_ids(key) else {
                return true;
            };
            if filter.level0.is_some_and(|level0| level0 != root)
                || filter
                    .registration_type
                    .is_some_and(|kind| kind != u8::from(id != root))
            {
                return true;
            }
            if last_root.as_ref().is_none_or(|(last, _)| *last != root) {
                match root_row(root) {
                    Ok(row) => last_root = Some((root, row)),
                    Err(error) => {
                        failed = Some(error);
                        return false;
                    }
                }
            }
            let Some((_, Some(row))) = &last_root else {
                return true;
            };
            // 昔の高さでは、候補がその高さの行から出るかを確かめる。今の検索表は今の行と合っている
            if matches!(view, View::At(_)) && !row_yields(key, row) {
                return true;
            }
            let info = RootNamespaceState::from_state_bytes(&state_bytes(&root.to_le_bytes(), row))
                .ok()
                .and_then(|state| state.info(id, height).ok().flatten());
            let Some(info) = info else {
                return true;
            };
            if filter
                .alias_type
                .is_some_and(|kind| kind != info.namespace.alias.alias_type)
            {
                return true;
            }
            if skip > 0 {
                skip -= 1;
                return true;
            }
            found.push((hex(key), info));
            found.len() < page.size
        };
        match &view {
            View::Now(_) => {
                self.db
                    .for_each_search_key(&prefix, after, page.descending, &mut visit)
            }
            View::At(_) => {
                self.db
                    .for_each_search_key_with_past(&prefix, after, page.descending, &mut visit)
            }
        }
        .map_err(|error| error.to_string())?;
        if let Some(error) = failed {
            return Err(error);
        }
        Ok(Some(found))
    }

    fn namespace_names(&self, ids: &[u64]) -> Result<Option<Vec<NamespaceNameJson>>, String> {
        if !self.db.searches().contains(Searches::NAMESPACES) {
            return Ok(None);
        }
        // catapult の REST と同じく、頼まれた ID の分を並べ、その親の分を次に並べる
        let mut out: Vec<NamespaceNameJson> = Vec::new();
        let mut next: Vec<u64> = ids.to_vec();
        while !next.is_empty() {
            let mut parents = Vec::new();
            for id in next {
                let text = format!("{id:016X}");
                if out.iter().any(|name| name.id == text) {
                    continue;
                }
                let Some((parent, name)) = self
                    .db
                    .namespace_name(id)
                    .map_err(|error| error.to_string())?
                else {
                    continue;
                };
                out.push(NamespaceNameJson {
                    id: text,
                    name: String::from_utf8_lossy(&name).into_owned(),
                    parent_id: (parent != 0).then(|| format!("{parent:016X}")),
                });
                if parent != 0 {
                    parents.push(parent);
                }
            }
            next = parents;
        }
        Ok(Some(out))
    }

    fn alias_names(&self, target: AliasTarget) -> Result<Option<Vec<String>>, String> {
        if !self.db.searches().contains(Searches::NAMESPACES) {
            return Ok(None);
        }
        let prefix = match target {
            AliasTarget::Address(address) => [&[NAMESPACE_BY_ADDRESS][..], &address.0].concat(),
            AliasTarget::Mosaic(id) => [&[NAMESPACE_BY_MOSAIC][..], &id.to_be_bytes()].concat(),
        };
        let mut ids = Vec::new();
        self.db
            .for_each_search_key(&prefix, None, false, &mut |key| {
                ids.extend(namespace_ids(key));
                true
            })
            .map_err(|error| error.to_string())?;
        let height = self.executed()?;
        let mut names = Vec::new();
        for (root, id) in ids {
            // catapult の REST と同じく、今有効な（期限の高さが今より後の）ものだけ
            let row = self
                .db
                .state_row(&row_key(SubCache::Namespace, &root.to_le_bytes()))
                .map_err(|error| error.to_string())?
                .and_then(|row| NamespaceRow::from_row(root, &row));
            if row.is_none_or(|row| row.end <= height) {
                continue;
            }
            // ルートまでたどってつなぐ。どこかの名前を知らなければ出さない
            let mut parts = Vec::new();
            let mut at = id;
            let full = loop {
                let Some((parent, name)) = self
                    .db
                    .namespace_name(at)
                    .map_err(|error| error.to_string())?
                else {
                    break None;
                };
                parts.push(String::from_utf8_lossy(&name).into_owned());
                if parent == 0 {
                    parts.reverse();
                    break Some(parts.join("."));
                }
                at = parent;
            };
            if let Some(full) = full
                && !names.contains(&full)
            {
                names.push(full);
            }
        }
        Ok(Some(names))
    }

    fn state_path(
        &self,
        cache: SubCache,
        key: &Hash256,
        at: Option<u64>,
    ) -> Result<MerkleStateInfo, StateError> {
        let (view, _) = self.view(at)?;
        let nodes = walk(key, |position| {
            let key = node_key(cache.index() as u8, position);
            match &view {
                View::Now(_) => self.db.trie_node(&key),
                View::At(past) => past.trie_node(&key),
            }
            .map_err(|error| error.to_string())?
            .map(|bytes| decode_node(&bytes))
            .transpose()
        })?;
        let raw: Vec<u8> = nodes.iter().flat_map(TreeNode::encode).collect();
        Ok(MerkleStateInfo { raw: hex(&raw) })
    }

    fn block(&self, height: u64) -> Result<Option<BlockInfo>, String> {
        let Some(block) = self.read_block(height)? else {
            return Ok(None);
        };
        let mut roots = Vec::with_capacity(SubCache::ALL.len());
        for cache in SubCache::ALL {
            let Some(root) = self.root_at(cache, height)? else {
                return Ok(None);
            };
            roots.push(root.to_string());
        }
        let (mut total_fee, mut transactions, mut total_transactions) = (0u64, 0u32, 0u32);
        for transaction in block.transactions() {
            total_fee += u64::from(block.fee_multiplier) * transaction.len() as u64;
            transactions += 1;
            total_transactions += 1;
            let transaction_type = u16::from_le_bytes([transaction[110], transaction[111]]);
            if AGGREGATE_TYPES.contains(&transaction_type) {
                let embedded =
                    heika_transaction::scan(transaction).map_or(0, |scanned| scanned.len());
                total_transactions += embedded as u32;
            }
        }
        let statements_count = match self
            .db
            .statement(height)
            .map_err(|error| error.to_string())?
        {
            Some(bytes) => {
                let statement =
                    BlockStatement::from_bytes(&bytes).map_err(|error| error.to_string())?;
                (statement.transaction_statements.len()
                    + statement.address_resolution_statements.len()
                    + statement.mosaic_resolution_statements.len()) as u32
            }
            None => 0,
        };
        Ok(Some(BlockInfo {
            meta: BlockMeta {
                hash: block.hash().to_string(),
                generation_hash: block.generation_hash().to_string(),
                total_fee: total_fee.to_string(),
                state_hash_sub_cache_merkle_roots: roots,
                total_transactions_count: total_transactions,
                transactions_count: transactions,
                statements_count,
            },
            block: BlockHeader::from(&block),
        }))
    }

    fn transaction_status(&self, hash: &Hash256) -> Result<Option<TransactionStatus>, String> {
        let status = |group: &str, deadline: u64, height: u64| TransactionStatus {
            group: group.to_owned(),
            code: Some("Success".to_owned()),
            hash: hash.to_string(),
            deadline: Some(deadline.to_string()),
            height: Some(height.to_string()),
        };
        if let Some(deadline) = self.mempool.lock().deadline(hash) {
            return Ok(Some(status("unconfirmed", deadline, 0)));
        }
        if let Some(deadline) = self.partials.lock().deadline(hash) {
            return Ok(Some(status("partial", deadline, 0)));
        }
        Ok(self
            .recent_transaction(hash)?
            .map(|(transaction, height, _, _)| status("confirmed", transaction.deadline, height)))
    }

    fn search_transactions(
        &self,
        filter: &TransactionFilter,
        page: PageRequest,
        after: Option<(u64, u32)>,
    ) -> Result<Option<Vec<TransactionInfo>>, String> {
        // アドレス（署名者と宛先も、関わったアドレスに入る）があれば、アドレスの表から候補を取る。なければブロックを順に読む
        let indexed = filter
            .address
            .or(filter
                .signer
                .map(|key| Address::from_public_key(&key, self.network)))
            .map(|address| address.0)
            .or(filter.recipient);
        if indexed.is_some() && !self.db.searches().contains(Searches::TRANSACTIONS) {
            return Ok(None);
        }
        let heights = filter.from_height..=filter.to_height;
        let mut skip = (page.number - 1) * page.size;
        let mut out = Vec::new();
        let mut failed = None;
        // 候補の1件を確かめて、合えば足す。ページが埋まったら `false`
        let mut take = |block: &Block, height: u64, index: u32| -> bool {
            let Some(transaction) = block
                .transactions()
                .nth(index as usize)
                .and_then(|bytes| Transaction::from_bytes(bytes).ok())
            else {
                return true;
            };
            if !transaction_matches(filter, &transaction) {
                return true;
            }
            if skip > 0 {
                skip -= 1;
                return true;
            }
            out.push(self.confirmed_info(
                &transaction,
                block,
                height,
                index,
                Some(transaction_position(height, index)),
            ));
            out.len() < page.size
        };
        match indexed {
            Some(address) => {
                let mut cached: Option<(u64, Block)> = None;
                self.db
                    .for_each_address_transaction(
                        &address,
                        heights,
                        after,
                        page.descending,
                        &mut |height, index| {
                            if cached.as_ref().is_none_or(|(at, _)| *at != height) {
                                // 刈り込んだブロックの分は、索引に残っていても返せない
                                match self.read_block(height) {
                                    Ok(Some(block)) => cached = Some((height, block)),
                                    Ok(None) => return true,
                                    Err(error) => {
                                        failed = Some(error);
                                        return false;
                                    }
                                }
                            }
                            let Some((_, block)) = &cached else {
                                return true;
                            };
                            take(block, height, index)
                        },
                    )
                    .map_err(|error| error.to_string())?;
            }
            None => {
                self.db
                    .for_each_block(
                        heights,
                        after.map(|(height, _)| height),
                        page.descending,
                        &mut |height, bytes| {
                            let Ok(block) = Block::from_bytes(bytes) else {
                                return true;
                            };
                            let count = block.transactions().count() as u32;
                            let mut indexes: Vec<u32> = (0..count).collect();
                            if page.descending {
                                indexes.reverse();
                            }
                            for index in indexes {
                                // 続きのブロックでは、`after` より後のものだけ
                                if let Some((at, after_index)) = after
                                    && at == height
                                    && (if page.descending {
                                        index >= after_index
                                    } else {
                                        index <= after_index
                                    })
                                {
                                    continue;
                                }
                                if !take(&block, height, index) {
                                    return false;
                                }
                            }
                            true
                        },
                    )
                    .map_err(|error| error.to_string())?;
            }
        }
        if let Some(error) = failed {
            return Err(error);
        }
        Ok(Some(out))
    }

    fn confirmed_transaction(&self, hash: &Hash256) -> Result<Option<TransactionInfo>, String> {
        Ok(self
            .recent_transaction(hash)?
            .map(|(transaction, height, index, block)| {
                self.confirmed_info(&transaction, &block, height, index, None)
            }))
    }

    fn transaction_merkle(
        &self,
        height: u64,
        hash: &Hash256,
    ) -> Result<Option<MerkleProofInfo>, String> {
        let Some(block) = self.read_block(height)? else {
            return Ok(None);
        };
        let Some(index) = block.transactions().position(|bytes| {
            Transaction::from_bytes(bytes)
                .is_ok_and(|transaction| transaction.hash(&self.seed) == *hash)
        }) else {
            return Ok(None);
        };
        let leaves = block
            .merkle_leaves(&self.seed)
            .map_err(|error| error.to_string())?;
        let path = merkle::path(&leaves, index).ok_or("Merkle の経路を作れません")?;
        Ok(Some(MerkleProofInfo {
            merkle_path: path
                .into_iter()
                .map(|node| MerklePathItem {
                    position: match node.position {
                        Position::Left => "left",
                        Position::Right => "right",
                    }
                    .to_owned(),
                    hash: node.hash.to_string(),
                })
                .collect(),
        }))
    }

    fn transaction_fees(&self) -> Result<TransactionFeesJson, String> {
        let tip = self.db.blocks_tip().map_err(|error| error.to_string())?;
        let mut multipliers = Vec::new();
        for height in tip.saturating_sub(FEE_STATS_BLOCKS - 1).max(1)..=tip {
            if let Some(block) = self.read_block(height)? {
                multipliers.push(block.fee_multiplier);
            }
        }
        let min_fee_multiplier = self.mempool.lock().min_fee_multiplier();
        Ok(TransactionFeesJson::new(multipliers, min_fee_multiplier))
    }

    fn partial_transaction(&self, hash: &Hash256) -> Result<Option<TransactionInfo>, String> {
        Ok(self.partial_info(hash))
    }

    fn partial_transactions(&self, filter: &PartialFilter) -> Result<Vec<TransactionInfo>, String> {
        let hashes = self.partials.lock().hashes();
        Ok(hashes
            .iter()
            .filter_map(|hash| {
                let bytes = self.partials.lock().stitched(hash)?;
                let transaction = Transaction::from_bytes(&bytes).ok()?;
                let signer_ok = filter
                    .signer
                    .is_none_or(|signer| transaction.signer_public_key == signer);
                let address_ok = filter
                    .address
                    .is_none_or(|address| self.involves(&transaction, &address));
                (signer_ok && address_ok)
                    .then(|| self.partial_info(hash))
                    .flatten()
            })
            .collect())
    }

    fn network(&self) -> NetworkIdentifier {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heika_core::key::PublicKey;

    #[test]
    fn transaction_filters_follow_catapult_conditions() {
        let network = NetworkIdentifier::MAINNET;
        let mosaics = [(0xAAu64, 10u64), (0xBB, 3)]
            .into_iter()
            .map(|(id, amount)| (heika_transaction::UnresolvedMosaicId(id), amount))
            .collect();
        let transfer = Transaction::new(
            PublicKey([0x11; 32]),
            network,
            0,
            0,
            Body::Transfer(
                heika_transaction::Transfer::new(
                    heika_transaction::UnresolvedAddress([0x55; 24]),
                    mosaics,
                    Vec::new(),
                )
                .unwrap(),
            ),
        );
        let base = TransactionFilter {
            address: None,
            signer: None,
            recipient: None,
            types: Vec::new(),
            mosaic: None,
            from_amount: None,
            to_amount: None,
            from_height: 0,
            to_height: u64::MAX,
        };
        let matches = |filter: TransactionFilter| transaction_matches(&filter, &transfer);
        assert!(matches(base.clone()));
        assert!(matches(TransactionFilter {
            signer: Some(PublicKey([0x11; 32])),
            recipient: Some([0x55; 24]),
            types: vec![0x4141, 0x4154],
            ..base.clone()
        }));
        assert!(!matches(TransactionFilter {
            signer: Some(PublicKey([0x12; 32])),
            ..base.clone()
        }));
        assert!(!matches(TransactionFilter {
            recipient: Some([0x56; 24]),
            ..base.clone()
        }));
        assert!(!matches(TransactionFilter {
            types: vec![0x4141],
            ..base.clone()
        }));
        // 額は、モザイクと別に、どれかが範囲に入ればよい（catapult の MongoDB の条件と同じ）
        let by_mosaic = |mosaic, from_amount, to_amount| {
            matches(TransactionFilter {
                mosaic: Some(mosaic),
                from_amount,
                to_amount,
                ..base.clone()
            })
        };
        assert!(by_mosaic(0xAA, None, None));
        assert!(!by_mosaic(0xCC, None, None));
        assert!(by_mosaic(0xAA, Some(4), Some(9)));
        assert!(!by_mosaic(0xAA, Some(11), None));
    }

    fn filter() -> MetadataFilter {
        MetadataFilter::default()
    }

    #[test]
    fn picks_the_search_order_from_the_filter() {
        let (a, b) = (Address([0xAA; 24]), Address([0xBB; 24]));
        let head = |prefix: &[u8]| prefix.to_vec();
        // 送り主があれば送り主から。決まっている項目は、途中が抜けたらそこまで
        let source = MetadataFilter {
            source: Some(a),
            target: Some(b),
            ..filter()
        };
        assert_eq!(
            metadata_prefixes(&source),
            vec![[&[METADATA_BY_SOURCE][..], &a.0].concat()]
        );
        let source = MetadataFilter {
            metadata_type: Some(0),
            ..source
        };
        assert_eq!(
            metadata_prefixes(&source),
            vec![[&[METADATA_BY_SOURCE][..], &a.0, &[0], &b.0].concat()]
        );
        // 宛先から
        let target = MetadataFilter {
            target: Some(b),
            scoped_key: Some(7),
            ..filter()
        };
        assert_eq!(
            metadata_prefixes(&target),
            vec![[&[METADATA_BY_TARGET][..], &b.0].concat()]
        );
        // 対象からは、種類がなければモザイクとネームスペースの両方
        let target_id = MetadataFilter {
            target_id: Some(0x55),
            ..filter()
        };
        let id = 0x55u64.to_be_bytes();
        assert_eq!(
            metadata_prefixes(&target_id),
            vec![
                [&[METADATA_BY_TARGET_ID, 1][..], &id].concat(),
                [&[METADATA_BY_TARGET_ID, 2][..], &id].concat()
            ]
        );
        // アカウントのメタデータと、何も決まっていないときは、宛先からを全部
        for filter in [
            MetadataFilter {
                metadata_type: Some(0),
                ..filter()
            },
            MetadataFilter {
                target_id: Some(0),
                ..filter()
            },
            filter(),
        ] {
            assert_eq!(
                metadata_prefixes(&filter),
                vec![head(&[METADATA_BY_TARGET])]
            );
        }
        let fields = MetadataFields {
            source: a.0,
            target: b.0,
            scoped_key: 7,
            target_id: 0,
            metadata_type: 0,
        };
        assert!(matches(&target, &fields));
        assert!(!matches(&target_id, &fields));
    }
}
