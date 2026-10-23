//! 連署を待つアグリゲートボンデッドを、今の先端の状態で確かめる。置き場（heika-mempool の `partial`）は状態を
//! 持たないので、駆動役がここに聞く。

use heika_core::hash::Hash256;
use heika_state_transition::executor::PartialCheck;
use heika_transaction::Transaction;

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// `transaction`（連署を付けたもの）を確かめる。ハッシュロックが確定して使えるようになっていなければ `None`。
    /// 要るものだけをメモリに持つ形なら、要る行を読み込んでから見る。マルチシグをたどる途中で読んでいない行に
    /// 当たったら、読み足して見直す
    pub fn check_partial(
        &mut self,
        transaction: &Transaction,
    ) -> Result<Option<PartialCheck>, ChainError> {
        let hash: Hash256 = transaction.hash(&self.parameters.generation_hash_seed);
        let mut wanted = self.executor.wanted_for_transaction(transaction);
        for _ in 0..=MAX_RETRIES {
            self.executor.load_wanted(self.store, &wanted)?;
            let ready = self.executor.hash_lock_ready(&hash);
            let check = self.executor.check_partial(transaction);
            wanted = self.executor.take_missed();
            if wanted.is_empty() {
                return Ok(ready.then_some(check));
            }
        }
        Err(format!("アグリゲート {hash} を確かめるのに、{MAX_RETRIES} 回読み足しても読んでいない状態があります").into())
    }
}
