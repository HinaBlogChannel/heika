//! API の読み役（[`heika_api::Reader`]）。先端を追うあいだの DB を、API のスレッドから読む。
//!
//! 状態は、今の行を catapult の葉のバイト列にしてから REST の JSON にする（[`heika_rest::state`] の逆向き）。
//! 葉と同じバイト列から作るので、受け取った側が JSON から組み直したハッシュは、木の葉と合う。
//! ブロックの9本の根は DB にしまっていないので、その高さの木の根のノードを読んで求め直す。差分が残っていない高さの
//! ブロックは、根を出せないので返さない。

use std::sync::Arc;

use heika_block::Block;
use heika_block::statement::BlockStatement;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::network::NetworkIdentifier;
use heika_core::patricia::{SubCache, TreeNode};
use heika_rest::block::{BlockHeader, BlockInfo, BlockMeta};
use heika_rest::merkle::MerkleStateInfo;
use heika_rest::state::{AccountJson, MosaicStateJson};
use heika_state_transition::executor::persist::{decode_account_row, row_key};
use heika_state_transition::tree::{EMPTY_ROOT, ROOT, node_key, walk};
use heika_store_redb::{Db, DbError};

/// アグリゲートのトランザクションの種類（完了と保留）
const AGGREGATE_TYPES: [u16; 2] = [0x4141, 0x4241];

pub struct DbReader {
    db: Arc<Db>,
    network: NetworkIdentifier,
    /// 通貨のモザイク。アカウントの葉では、これを先に並べる
    currency: u64,
}

impl DbReader {
    pub fn new(db: Arc<Db>, network: NetworkIdentifier, currency: u64) -> Self {
        Self {
            db,
            network,
            currency,
        }
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
    fn account(&self, address: &Address) -> Result<Option<AccountJson>, String> {
        let Some(row) = self
            .db
            .state_row(&row_key(SubCache::AccountState, &address.0))
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let account = decode_account_row(&row).map_err(|error| error.to_string())?;
        AccountJson::from_state_bytes(&account.to_state_bytes(self.currency))
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn mosaic(&self, id: u64) -> Result<Option<MosaicStateJson>, String> {
        let Some(row) = self
            .db
            .state_row(&row_key(SubCache::Mosaic, &id.to_le_bytes()))
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        // 行は、葉のバイト列からバージョンと ID を除いたもの
        let mut bytes = 1u16.to_le_bytes().to_vec();
        bytes.extend_from_slice(&id.to_le_bytes());
        bytes.extend_from_slice(&row);
        MosaicStateJson::from_state_bytes(&bytes)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn state_path(&self, cache: SubCache, key: &Hash256) -> Result<MerkleStateInfo, String> {
        let nodes = walk(key, |position| {
            self.db
                .trie_node(&node_key(cache.index() as u8, position))
                .map_err(|error| error.to_string())?
                .map(|bytes| decode_node(&bytes))
                .transpose()
        })?;
        let raw: Vec<u8> = nodes.iter().flat_map(TreeNode::encode).collect();
        Ok(MerkleStateInfo { raw: hex(&raw) })
    }

    fn block(&self, height: u64) -> Result<Option<BlockInfo>, String> {
        let Some(bytes) = self.db.block(height).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        let block = Block::from_bytes(&bytes).map_err(|error| error.to_string())?;
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

    fn network(&self) -> NetworkIdentifier {
        self.network
    }
}
