//! 中核（heika-chain）の保存の口 [`ChainStore`] を、[`Db`] で実装する。

use heika_chain::ChainError;
use heika_chain::store::{BlockWrite, ChainStore, EXECUTOR_META, Prune, Pruned};
use heika_core::patricia::SubCache;
use heika_state_transition::executor::is_partial_row;

use crate::{Change, Db, StateRow};

impl ChainStore for Db {
    async fn load_state(&self) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError> {
        let meta = self.meta(EXECUTOR_META)?.ok_or("まだ実行していません")?;
        Ok((meta, self.state_rows()?, self.trie_nodes()?))
    }

    async fn load_partial_state(
        &self,
    ) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError> {
        let meta = self.meta(EXECUTOR_META)?.ok_or("まだ実行していません")?;
        let mut rows = Vec::new();
        for cache in SubCache::ALL {
            // ハッシュロックは、期限の来ていないものを選ぶために読む
            if cache != SubCache::HashLockInfo && is_partial_row(&[cache.index() as u8]) {
                continue;
            }
            self.for_each_state_row(&[cache.index() as u8], &mut |key, value| {
                rows.push((key.to_vec(), value.to_vec()));
            })?;
        }
        // 大きい表の木は、必要なノードだけをあとで読む
        let mut nodes = Vec::new();
        for cache in SubCache::ALL {
            if is_partial_row(&[cache.index() as u8]) {
                continue;
            }
            self.for_each_trie_node(&[cache.index() as u8], &mut |key, value| {
                nodes.push((key.to_vec(), value.to_vec()));
            })?;
        }
        Ok((meta, rows, nodes))
    }

    async fn block(&self, height: u64) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(Db::block(self, height)?)
    }

    async fn blocks_from(&self) -> Result<u64, ChainError> {
        Ok(Db::blocks_from(self)?)
    }

    async fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(Db::proof(self, epoch)?)
    }

    async fn proofs_tip(&self) -> Result<u32, ChainError> {
        Ok(Db::proofs_tip(self)?)
    }

    async fn voters(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(Db::voters(self, epoch)?)
    }

    async fn put_proof(&self, epoch: u32, proof: &[u8]) -> Result<(), ChainError> {
        let mut batch = self.batch()?;
        batch.put_proof(epoch, proof)?;
        batch.commit()?;
        Ok(())
    }

    async fn commit_block(&self, write: BlockWrite<'_>) -> Result<(), ChainError> {
        let mut batch = self.batch()?;
        batch.put_block(write.height, write.bytes)?;
        batch.remove_orphan(write.height, &write.hash)?;
        batch.set_state_at(write.height, write.state)?;
        batch.set_trie_at(write.height, write.nodes)?;
        batch.put_statement(write.height, &write.statement)?;
        if let Some((epoch, voters)) = &write.voters {
            batch.put_voters(*epoch, voters)?;
        }
        batch.put_meta(EXECUTOR_META, &write.meta)?;
        batch.put_checkpoint(write.height, &write.meta)?;
        batch.commit()?;
        Ok(())
    }

    async fn prune(&self, prune: Prune) -> Result<Pruned, ChainError> {
        let checkpoints = self.prune_checkpoints(prune.checkpoints_below)?;
        let mut rows = 0;
        if let Some((state, trie)) = prune.history {
            rows += self.prune_state_history(state, |_| true)?.rows;
            rows += self.prune_trie_history(trie, |_| true)?.rows;
        }
        if let Some((through, epoch)) = prune.blocks {
            rows += self.prune_history(through, epoch)?;
        }
        Ok(Pruned { checkpoints, rows })
    }

    async fn checkpoint_at_or_below(
        &self,
        height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        Ok(Db::checkpoint_at_or_below(self, height)?)
    }

    async fn changes_above(&self, height: u64) -> Result<Vec<Change>, ChainError> {
        Ok(Db::changes_above(self, height)?)
    }

    async fn rollback(
        &self,
        height: u64,
        voters_from: u32,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<(), ChainError> {
        Db::rollback(self, height, voters_from, EXECUTOR_META, true, orphans)?;
        Ok(())
    }
}
