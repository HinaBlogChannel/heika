//! 中核（[`crate::Chain`]）が使う保存の口。中核は DB を直接呼ばず、ここを通す。
//!
//! 読み書きは粗い単位（1ブロックを当てて書く、確定のたびに刈り込む、巻き戻す）にして、それぞれ `async fn` にする。
//! ブラウザの IndexedDB のように待つものも、redb のようにその場で終わるものも、同じ口で扱える。ブロックの実行
//! そのものは、待たずにメモリの上で回す。

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::ChainError;

/// 保存の `meta` の、木に入らない実行の状態（[`heika_state_transition::executor::Executor::encode_meta`]）の名前
pub const EXECUTOR_META: &str = "executor";

/// 状態の行か木のノード（キー、値）
pub type StateRow = (Vec<u8>, Vec<u8>);

/// 変わった行かノード（キー、変わる前か後の値。`None` はない）
pub type Change = (Vec<u8>, Option<Vec<u8>>);

/// ブロック1つを当てたあとに、まとめて書くもの
pub struct BlockWrite<'a> {
    pub height: u64,
    pub hash: [u8; 32],
    pub bytes: &'a [u8],
    /// 変わった状態の行（`None` は消す）
    pub state: Vec<Change>,
    /// 変わった木のノード（`None` は消す）
    pub nodes: Vec<Change>,
    pub statement: Vec<u8>,
    /// このブロックで決まった投票者（エポック、投票者の表）
    pub voters: Option<(u32, Vec<u8>)>,
    /// 実行の状態（チェックポイントにもする）
    pub meta: Vec<u8>,
}

/// 確定を上げたときに消すもの
pub struct Prune {
    /// これより下のチェックポイント
    pub checkpoints_below: u64,
    /// 刈り込むなら、状態の差分、木のノードの差分を、それぞれこの高さ以下で消す
    pub history: Option<(u64, u64)>,
    /// ブロックとステートメントをこの高さ以下で、証明をこのエポックより前で消す
    pub blocks: Option<(u64, u32)>,
}

/// 消したもの
pub struct Pruned {
    pub checkpoints: usize,
    pub rows: u64,
}

/// 先端の段階が使う保存の口
#[allow(async_fn_in_trait)]
pub trait ChainStore {
    /// 実行の状態（木に入らないもの）、状態の行、木のノード。始めるときと、巻き戻しに失敗して読み直すときに使う
    async fn load_state(&self) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError>;
    /// [`ChainStore::load_state`] の、アカウントの行を除いたもの。アカウントを全部はメモリに持たないときに使う
    async fn load_partial_state(
        &self,
    ) -> Result<(Vec<u8>, Vec<StateRow>, Vec<StateRow>), ChainError>;
    async fn block(&self, height: u64) -> Result<Option<Vec<u8>>, ChainError>;
    /// 残っている一番低いブロックの高さ（刈り込んでいなければ 0）
    async fn blocks_from(&self) -> Result<u64, ChainError>;
    async fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError>;
    /// しまった一番新しい証明のエポック（なければ 0）
    async fn proofs_tip(&self) -> Result<u32, ChainError>;
    async fn voters(&self, epoch: u32) -> Result<Option<Vec<u8>>, ChainError>;
    async fn put_proof(&self, epoch: u32, proof: &[u8]) -> Result<(), ChainError>;
    /// ブロック1つ分を書いてコミットする。孤立ブロックの表にあれば外す
    async fn commit_block(&self, write: BlockWrite<'_>) -> Result<(), ChainError>;
    async fn prune(&self, prune: Prune) -> Result<Pruned, ChainError>;
    /// `height` 以下で一番新しいチェックポイント（高さ、実行の状態）
    async fn checkpoint_at_or_below(
        &self,
        height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, ChainError>;
    /// `height` より上で変わった状態の行の、`height` のときの値
    async fn changes_above(&self, height: u64) -> Result<Vec<Change>, ChainError>;
    /// `height` より上を消して `height` に戻す。投票者は `voters_from` から消し、外れた枝のブロックは孤立ブロックの
    /// 表にしまう
    async fn rollback(
        &self,
        height: u64,
        voters_from: u32,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<(), ChainError>;
}

/// その場で終わる保存（redb など）を使うときに、future を待たずに1回で進める。待つものだったらエラー
pub fn now_or_never<T>(
    future: impl Future<Output = Result<T, ChainError>>,
) -> Result<T, ChainError> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => Err("保存の口が、その場で終わらずに待ちました".into()),
    }
}
