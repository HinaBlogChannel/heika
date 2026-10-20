//! 中核に渡す保存。[`Db`] を、読んだ状態を覚えておく [`CachedSource`] で包む。コミットで変わった行とノードは
//! キャッシュにも伝え、巻き戻したら空にする。

use heika_chain::ChainError;
use heika_chain::store::{BlockWrite, ChainStore, Change, Prune, Pruned, StateRow};
use heika_state_transition::executor::ExecError;
use heika_state_transition::executor::source::{CachedSource, StateSource};
use heika_store_redb::Db;

pub struct CachedStore {
    source: CachedSource<Db>,
}

impl CachedStore {
    /// `db` を包み、読んだ状態を `capacity` バイトまで覚える
    pub fn new(db: Db, capacity: usize) -> Self {
        Self {
            source: CachedSource::new(db, capacity),
        }
    }

    pub fn db(&self) -> &Db {
        self.source.inner()
    }

    pub fn into_db(self) -> Db {
        self.source.into_inner()
    }
}

impl StateSource for CachedStore {
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        self.source.row(key)
    }

    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        self.source.node(key)
    }

    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError> {
        self.source.for_each_row(prefix, visit)
    }
}

impl ChainStore for CachedStore {
    async fn load_state(&self) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError> {
        self.db().load_state().await
    }

    async fn load_partial_state(
        &self,
    ) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError> {
        self.db().load_partial_state().await
    }

    async fn block(&self, height: u64) -> Result<Option<Vec<u8>>, ChainError> {
        ChainStore::block(self.db(), height).await
    }

    async fn blocks_from(&self) -> Result<u64, ChainError> {
        ChainStore::blocks_from(self.db()).await
    }

    async fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError> {
        ChainStore::proof(self.db(), epoch).await
    }

    async fn proofs_tip(&self) -> Result<u32, ChainError> {
        ChainStore::proofs_tip(self.db()).await
    }

    async fn voters(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError> {
        ChainStore::voters(self.db(), epoch).await
    }

    async fn put_proof(&self, epoch: u32, proof: &[u8]) -> Result<(), ChainError> {
        self.db().put_proof(epoch, proof).await
    }

    async fn commit_block(&self, write: BlockWrite<'_>) -> Result<(), ChainError> {
        let (state, nodes) = (write.state.clone(), write.nodes.clone());
        self.db().commit_block(write).await?;
        self.source.record(state, nodes);
        Ok(())
    }

    async fn prune(&self, prune: Prune) -> Result<Pruned, ChainError> {
        ChainStore::prune(self.db(), prune).await
    }

    async fn checkpoint_at_or_below(
        &self,
        height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError> {
        ChainStore::checkpoint_at_or_below(self.db(), height).await
    }

    async fn changes_above(&self, height: u64) -> Result<Vec<Change>, ChainError> {
        ChainStore::changes_above(self.db(), height).await
    }

    async fn rollback(
        &self,
        height: u64,
        voters_from: u32,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<(), ChainError> {
        let rolled = ChainStore::rollback(self.db(), height, voters_from, orphans).await;
        // 失敗しても、どこまで戻ったかわからないので捨てる
        self.source.clear();
        rolled
    }
}
