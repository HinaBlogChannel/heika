//! メモリの中だけの保存（[`ChainStore`] の2つ目の実装）。保存の口だけで先端の段階が動くことを確かめるのと、
//! ピアも redb もなしに中核を試すのに使う。小さいネットワーク向けで、全部をメモリに持つ。

use std::cell::RefCell;
use std::collections::BTreeMap;

use heika_core::patricia::SubCache;

use heika_state_transition::executor::ExecError;
use heika_state_transition::executor::source::StateSource;

use crate::ChainError;
use crate::store::{BlockWrite, ChainStore, Change, Prune, Pruned, StateRow};

/// メモリの中だけの保存。全部をメモリに持つので、小さいネットワークかテスト向け
#[derive(Default)]
pub struct MemoryStore {
    inner: RefCell<Inner>,
}

#[derive(Default)]
struct Inner {
    meta: Vec<u8>,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    nodes: BTreeMap<Vec<u8>, Vec<u8>>,
    /// 高さ → その高さのブロックで変わる前の、状態の行と木のノード。巻き戻しに使う
    undo: BTreeMap<u64, [Vec<Change>; 2]>,
    /// この高さより下には、`undo` がない
    history_from: u64,
    blocks: BTreeMap<u64, Vec<u8>>,
    blocks_from: u64,
    statements: BTreeMap<u64, Vec<u8>>,
    proofs: BTreeMap<u32, Vec<u8>>,
    voters: BTreeMap<u32, Vec<u8>>,
    checkpoints: BTreeMap<u64, Vec<u8>>,
    orphans: BTreeMap<(u64, [u8; 32]), Vec<u8>>,
}

impl MemoryStore {
    /// 外れた枝のブロックとしてしまったもの（高さ、ハッシュ）
    pub fn orphans(&self) -> Vec<(u64, [u8; 32])> {
        self.inner.borrow().orphans.keys().copied().collect()
    }
}

/// `rows` に `changes` を当て、変わる前の値を返す
fn apply(rows: &mut BTreeMap<Vec<u8>, Vec<u8>>, changes: Vec<Change>) -> Vec<Change> {
    changes
        .into_iter()
        .map(|(key, value)| {
            let before = match value {
                Some(value) => rows.insert(key.clone(), value),
                None => rows.remove(&key),
            };
            (key, before)
        })
        .collect()
}

impl ChainStore for MemoryStore {
    async fn load_state(&self) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError> {
        let inner = self.inner.borrow();
        let rows = |map: &BTreeMap<Vec<u8>, Vec<u8>>| {
            map.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        };
        Ok((inner.meta.clone(), rows(&inner.state), rows(&inner.nodes)))
    }

    async fn load_partial_state(
        &self,
    ) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError> {
        let inner = self.inner.borrow();
        let hash_lock = SubCache::HashLockInfo.index() as u8;
        let rows = inner
            .state
            .iter()
            .filter(|(key, _)| {
                key.first() == Some(&hash_lock)
                    || !heika_state_transition::executor::is_partial_row(key)
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let nodes = inner
            .nodes
            .iter()
            .filter(|(key, _)| !heika_state_transition::executor::is_partial_row(key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok((inner.meta.clone(), rows, nodes))
    }

    async fn block(&self, height: u64) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(self.inner.borrow().blocks.get(&height).cloned())
    }

    async fn blocks_from(&self) -> Result<u64, ChainError> {
        Ok(self.inner.borrow().blocks_from)
    }

    async fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(self.inner.borrow().proofs.get(&epoch).cloned())
    }

    async fn proofs_tip(&self) -> Result<u32, ChainError> {
        Ok(self
            .inner
            .borrow()
            .proofs
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0))
    }

    async fn voters(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(self.inner.borrow().voters.get(&epoch).cloned())
    }

    async fn put_proof(&self, epoch: u32, proof: &[u8]) -> Result<(), ChainError> {
        self.inner.borrow_mut().proofs.insert(epoch, proof.to_vec());
        Ok(())
    }

    async fn commit_block(&self, write: BlockWrite<'_>) -> Result<(), ChainError> {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        let state = apply(&mut inner.state, write.state);
        let nodes = apply(&mut inner.nodes, write.nodes);
        inner.undo.insert(write.height, [state, nodes]);
        inner.blocks.insert(write.height, write.bytes.to_vec());
        inner.orphans.remove(&(write.height, write.hash));
        inner.statements.insert(write.height, write.statement);
        if let Some((epoch, voters)) = write.voters {
            inner.voters.insert(epoch, voters);
        }
        inner.checkpoints.insert(write.height, write.meta.clone());
        inner.meta = write.meta;
        Ok(())
    }

    async fn prune(&self, prune: Prune) -> Result<Pruned, ChainError> {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        let kept = inner.checkpoints.split_off(&prune.checkpoints_below);
        let checkpoints = std::mem::replace(&mut inner.checkpoints, kept).len();
        let mut rows = 0;
        if let Some((state, trie)) = prune.history {
            for (height, [state_undo, node_undo]) in &mut inner.undo {
                if *height <= state {
                    rows += std::mem::take(state_undo).len() as u64;
                }
                if *height <= trie {
                    rows += std::mem::take(node_undo).len() as u64;
                }
            }
            let through = state.min(trie);
            inner.undo = inner.undo.split_off(&(through + 1));
            inner.history_from = inner.history_from.max(through + 1);
        }
        if let Some((through, epoch)) = prune.blocks {
            for table in [&mut inner.blocks, &mut inner.statements] {
                let kept = table.split_off(&(through + 1));
                rows += std::mem::replace(table, kept).len() as u64;
            }
            let kept = inner.proofs.split_off(&epoch);
            rows += std::mem::replace(&mut inner.proofs, kept).len() as u64;
            inner.blocks_from = inner.blocks_from.max(through + 1);
        }
        Ok(Pruned {
            checkpoints,
            rows,
            remaining: false,
        })
    }

    async fn checkpoint_at_or_below(
        &self,
        height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        Ok(self
            .inner
            .borrow()
            .checkpoints
            .range(..=height)
            .next_back()
            .map(|(height, meta)| (*height, meta.clone())))
    }

    async fn changes_above(&self, height: u64) -> Result<Vec<Change>, ChainError> {
        let inner = self.inner.borrow();
        if height < inner.history_from {
            return Err(format!(
                "高さ {height} の差分はありません（{} から）",
                inner.history_from
            )
            .into());
        }
        // 高さの順に見て、キーごとに最初の「変わる前」が `height` のときの値
        let mut rows = BTreeMap::new();
        for [state, _] in inner.undo.range(height + 1..).map(|(_, undo)| undo) {
            for (key, before) in state {
                rows.entry(key.clone()).or_insert_with(|| before.clone());
            }
        }
        Ok(rows.into_iter().collect())
    }

    async fn rollback(
        &self,
        height: u64,
        voters_from: u32,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<(), ChainError> {
        let mut inner = self.inner.borrow_mut();
        let inner = &mut *inner;
        let (checkpoint, meta) = inner
            .checkpoints
            .range(..=height)
            .next_back()
            .map(|(height, meta)| (*height, meta.clone()))
            .ok_or("巻き戻せるチェックポイントがありません")?;
        if checkpoint < inner.history_from {
            return Err(format!(
                "高さ {checkpoint} の差分はありません（{} から）",
                inner.history_from
            )
            .into());
        }
        // 新しい高さから順に、変わる前の値に戻す
        for (_, [state, nodes]) in inner.undo.split_off(&(checkpoint + 1)).into_iter().rev() {
            for (rows, undo) in [(&mut inner.state, state), (&mut inner.nodes, nodes)] {
                for (key, before) in undo.into_iter().rev() {
                    match before {
                        Some(value) => rows.insert(key, value),
                        None => rows.remove(&key),
                    };
                }
            }
        }
        inner.statements.split_off(&(checkpoint + 1));
        inner.checkpoints.split_off(&(checkpoint + 1));
        inner.blocks.split_off(&(height + 1));
        for (height, hash, block) in orphans {
            inner.orphans.insert((*height, *hash), block.to_vec());
        }
        inner.voters.split_off(&voters_from);
        inner.meta = meta;
        Ok(())
    }
}

impl StateSource for MemoryStore {
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        Ok(self.inner.borrow().state.get(key).cloned())
    }

    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        Ok(self.inner.borrow().nodes.get(key).cloned())
    }

    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError> {
        let inner = self.inner.borrow();
        for (key, value) in inner.state.range(prefix.to_vec()..) {
            if !key.starts_with(prefix) {
                break;
            }
            visit(key, value);
        }
        Ok(())
    }
}
