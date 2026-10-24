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

use heika_api::{MetadataFilter, PageRequest, PartialFilter, StateError};
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
    AccountJson, MetadataEntryJson, MosaicStateJson, NamespaceInfo, RootNamespaceState,
};
use heika_rest::transaction::{TransactionInfo, TransactionJson, TransactionMeta};
use heika_state_transition::executor::persist::{decode_account_row, height_of_meta, row_key};
use heika_state_transition::tree::{EMPTY_ROOT, ROOT, node_key, walk};
use heika_store_redb::search::{METADATA_BY_SOURCE, METADATA_BY_TARGET, METADATA_BY_TARGET_ID};
use heika_store_redb::{At, Db, DbError, MetadataFields, Searches};
use heika_transaction::{Body, MetadataKey, MetadataType, Transaction};

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

    /// 直近のブロックに入った `hash` のトランザクションと、入った高さと、ブロックの中の番号
    fn recent_transaction(
        &self,
        hash: &Hash256,
    ) -> Result<Option<(Transaction, u64, u32)>, String> {
        let found = self
            .recent
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .find(hash);
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
        Ok(transaction.map(|transaction| (transaction, height, index)))
    }

    /// 連署を待つものを、集まった連署を付けて REST の形にする。承認されていないので高さは "0"
    fn partial_info(&self, hash: &Hash256) -> Option<TransactionInfo> {
        let bytes = self.partials.lock().stitched(hash)?;
        let transaction = Transaction::from_bytes(&bytes).ok()?;
        Some(TransactionInfo {
            meta: TransactionMeta {
                height: Some("0".to_owned()),
                hash: Some(hash.to_string()),
                merkle_component_hash: Some(
                    transaction.merkle_component_hash(&self.seed).to_string(),
                ),
                index: Some(0),
                aggregate_hash: None,
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
            return Ok((View::Now, tip));
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
            View::Now => self.db.state_row(key),
            View::At(past) => past.state(key),
        }
        .map_err(|error| StateError::Other(error.to_string()))
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

/// 1件を指すハッシュ（compositeHash）
fn composite_hash(fields: &MetadataFields) -> Option<Hash256> {
    let metadata_type = match fields.metadata_type {
        0 => MetadataType::Account,
        1 => MetadataType::Mosaic,
        2 => MetadataType::Namespace,
        _ => return None,
    };
    Some(
        MetadataKey {
            source_address: Address(fields.source),
            target_address: Address(fields.target),
            scoped_metadata_key: fields.scoped_key,
            target_id: fields.target_id,
            metadata_type,
        }
        .unique_key(),
    )
}

/// 状態を引く先
enum View {
    /// 今の状態
    Now,
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
    fn account(
        &self,
        address: &Address,
        at: Option<u64>,
    ) -> Result<Option<AccountJson>, StateError> {
        let (view, _) = self.view(at)?;
        let Some(row) = self.row(&view, &row_key(SubCache::AccountState, &address.0))? else {
            return Ok(None);
        };
        let account = decode_account_row(&row).map_err(|error| error.to_string())?;
        Ok(Some(
            AccountJson::from_state_bytes(&account.to_state_bytes(self.currency))
                .map_err(|error| error.to_string())?,
        ))
    }

    fn mosaic(&self, id: u64, at: Option<u64>) -> Result<Option<MosaicStateJson>, StateError> {
        let (view, _) = self.view(at)?;
        let Some(row) = self.row(&view, &row_key(SubCache::Mosaic, &id.to_le_bytes()))? else {
            return Ok(None);
        };
        Ok(Some(
            MosaicStateJson::from_state_bytes(&state_bytes(&id.to_le_bytes(), &row))
                .map_err(|error| error.to_string())?,
        ))
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
                View::Now => self.db.for_each_state_row(&prefix, &mut keep),
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
    ) -> Result<Option<Vec<MetadataEntryJson>>, String> {
        if !self.db.searches().contains(Searches::METADATA) {
            return Ok(None);
        }
        let mut prefixes = metadata_prefixes(filter);
        if page.descending {
            prefixes.reverse();
        }
        let mut skip = (page.number - 1) * page.size;
        let mut found = Vec::new();
        for prefix in prefixes {
            self.db
                .for_each_search_key(&prefix, page.descending, &mut |key| {
                    let Some(fields) = MetadataFields::from_search_key(key) else {
                        return true;
                    };
                    if !matches(filter, &fields) {
                        return true;
                    }
                    if skip > 0 {
                        skip -= 1;
                        return true;
                    }
                    found.push(fields);
                    found.len() < page.size
                })
                .map_err(|error| error.to_string())?;
            if found.len() >= page.size {
                break;
            }
        }
        let mut entries = Vec::with_capacity(found.len());
        for fields in found {
            let Some(hash) = composite_hash(&fields) else {
                continue;
            };
            // 検索表を読んだあとに消えていれば、飛ばす
            if let Some(entry) = self
                .metadata(&hash, None)
                .map_err(|error| error.to_string())?
            {
                entries.push(entry);
            }
        }
        Ok(Some(entries))
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
                View::Now => self.db.trie_node(&key),
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
            .map(|(transaction, height, _)| status("confirmed", transaction.deadline, height)))
    }

    fn confirmed_transaction(&self, hash: &Hash256) -> Result<Option<TransactionInfo>, String> {
        Ok(self
            .recent_transaction(hash)?
            .map(|(transaction, height, index)| TransactionInfo {
                meta: TransactionMeta {
                    height: Some(height.to_string()),
                    hash: Some(hash.to_string()),
                    merkle_component_hash: Some(
                        transaction.merkle_component_hash(&self.seed).to_string(),
                    ),
                    index: Some(index),
                    aggregate_hash: None,
                },
                transaction: TransactionJson::from(&transaction),
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
