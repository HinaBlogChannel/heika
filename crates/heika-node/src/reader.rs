//! API の読み役（[`heika_api::Reader`]）。先端を追うあいだの DB を、API のスレッドから読む。
//!
//! 状態は、今の行を catapult の葉のバイト列にしてから REST の JSON にする（[`heika_rest::state`] の逆向き）。
//! 葉と同じバイト列から作るので、受け取った側が JSON から組み直したハッシュは、木の葉と合う。
//! ブロックの9本の根は DB にしまっていないので、その高さの木の根のノードを読んで求め直す。差分が残っていない高さの
//! ブロックは、根を出せないので返さない。
//!
//! トランザクションの行方は、メモリプールと、直近のブロックの索引（[`crate::recent`]）で答える。索引より古い
//! トランザクションは知らないことにする。

use std::sync::Arc;

use heika_block::Block;
use heika_block::statement::BlockStatement;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::merkle::{self, Position};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::patricia::{SubCache, TreeNode};
use heika_mempool::SharedMempool;
use heika_rest::block::{BlockHeader, BlockInfo, BlockMeta};
use heika_rest::merkle::{MerklePathItem, MerkleProofInfo, MerkleStateInfo};
use heika_rest::send::TransactionStatus;
use heika_rest::state::{AccountJson, MosaicStateJson};
use heika_rest::transaction::{TransactionInfo, TransactionJson, TransactionMeta};
use heika_state_transition::executor::persist::{decode_account_row, row_key};
use heika_state_transition::tree::{EMPTY_ROOT, ROOT, node_key, walk};
use heika_store_redb::{Db, DbError};
use heika_transaction::Transaction;

use crate::recent::SharedRecent;

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
}

impl DbReader {
    pub fn new(
        db: Arc<Db>,
        network: NetworkIdentifier,
        currency: u64,
        seed: GenerationHashSeed,
        mempool: Arc<SharedMempool>,
        recent: SharedRecent,
    ) -> Self {
        Self {
            db,
            network,
            currency,
            seed,
            mempool,
            recent,
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

    fn read_block(&self, height: u64) -> Result<Option<Block>, String> {
        let Some(bytes) = self.db.block(height).map_err(|error| error.to_string())? else {
            return Ok(None);
        };
        Block::from_bytes(&bytes)
            .map(Some)
            .map_err(|error| error.to_string())
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

    fn network(&self) -> NetworkIdentifier {
        self.network
    }
}
