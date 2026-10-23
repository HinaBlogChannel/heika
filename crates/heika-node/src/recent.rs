//! 直近のブロックに入ったトランザクションの索引。ハッシュから、入ったブロックの高さと、ブロックの中で何番目かを引く。
//!
//! 送ったばかりのトランザクションは、期限（`maxTransactionLifetime`）のうちにブロックに入るか、二度と入らないかの
//! どちらかなので、その長さの分だけ持てば、送金のあとの確かめに足りる。ディスクには何も書かず、起動したら DB の
//! 直近のブロックを読んで作り直す。ライトの残し方でも、ブロックは期限より長く（2エポック）残っている。
//! 先端が進んだら足し、枝を取り替えたら分かれ目より上を外す（[`crate::delegated::Delegated`] と同じ流れ）。

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use heika_block::Block;
use heika_core::hash::Hash256;
use heika_core::network::GenerationHashSeed;
use heika_store_redb::Db;
use heika_transaction::Transaction;

use crate::driver::NodeError;

/// 駆動役が書き、API の読み役が読む
pub type SharedRecent = Arc<RwLock<RecentTransactions>>;

pub struct RecentTransactions {
    seed: GenerationHashSeed,
    /// 持つ長さ（ミリ秒）。先端のブロックの時刻からこれより前のブロックは外す
    lifetime: u64,
    /// ハッシュから、高さとブロックの中の番号
    by_hash: HashMap<Hash256, (u64, u32)>,
    /// 高さごとの、ブロックの時刻と中のハッシュ
    blocks: BTreeMap<u64, (u64, Vec<Hash256>)>,
    /// 読み終えた高さ
    through: u64,
}

impl RecentTransactions {
    /// DB の先端 `tip` から遡って、`lifetime` の分のブロックを読む
    pub fn open(
        db: &Db,
        seed: GenerationHashSeed,
        lifetime: u64,
        tip: u64,
    ) -> Result<Self, NodeError> {
        let mut recent = Self {
            seed,
            lifetime,
            by_hash: HashMap::new(),
            blocks: BTreeMap::new(),
            through: tip,
        };
        let mut newest = None;
        for height in (1..=tip).rev() {
            let Some(block) = read_block(db, height)? else {
                break;
            };
            let newest = *newest.get_or_insert(block.timestamp);
            if block.timestamp + lifetime < newest {
                break;
            }
            recent.insert(&block);
        }
        Ok(recent)
    }

    /// `hash` のトランザクションが入った高さと、ブロックの中の番号
    pub fn find(&self, hash: &Hash256) -> Option<(u64, u32)> {
        self.by_hash.get(hash).copied()
    }

    /// 枝を取り替えた。分かれ目 `common` より上は、新しい枝で読み直す
    pub fn rewind(&mut self, common: u64) {
        for (_, (_, hashes)) in self.blocks.split_off(&(common + 1)) {
            for hash in hashes {
                self.by_hash.remove(&hash);
            }
        }
        self.through = self.through.min(common);
    }

    /// 先端が `tip` まで進んだ。まだ読んでいないブロックを足し、古くなったものを外す
    pub fn advance(&mut self, db: &Db, tip: u64) -> Result<(), NodeError> {
        for height in self.through + 1..=tip {
            if let Some(block) = read_block(db, height)? {
                self.insert(&block);
            }
        }
        self.through = self.through.max(tip);
        let Some(newest) = self.blocks.values().next_back().map(|(time, _)| *time) else {
            return Ok(());
        };
        while let Some(entry) = self.blocks.first_entry() {
            if entry.get().0 + self.lifetime >= newest {
                break;
            }
            for hash in entry.remove().1 {
                self.by_hash.remove(&hash);
            }
        }
        Ok(())
    }

    fn insert(&mut self, block: &Block) {
        // チェーンが認めたブロックなので、読めないトランザクションはない。読めなければ飛ばす
        let hashes: Vec<Hash256> = block
            .transactions()
            .filter_map(|bytes| Transaction::from_bytes(bytes).ok())
            .map(|transaction| transaction.hash(&self.seed))
            .collect();
        for (index, hash) in hashes.iter().enumerate() {
            self.by_hash.insert(*hash, (block.height, index as u32));
        }
        self.blocks.insert(block.height, (block.timestamp, hashes));
    }
}

fn read_block(db: &Db, height: u64) -> Result<Option<Block>, NodeError> {
    let Some(bytes) = db.block(height)? else {
        return Ok(None);
    };
    Block::from_bytes(&bytes)
        .map(Some)
        .map_err(|error| format!("高さ {height} のブロックが読めません: {error}").into())
}
