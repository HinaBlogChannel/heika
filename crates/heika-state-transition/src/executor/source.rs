//! メモリにない状態を読む口。ブロックを当てる前と、当てて足りなかったときに、キーを指定して読むので同期にする
//! （ブラウザでは、OPFS を専用の Worker から同期で使う前提）。

use super::ExecError;

/// 今の状態の行と木のノードを読む口
pub trait StateSource {
    /// 状態の行 `key`（[`super::persist::row_key`]）。なければ `None`
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError>;
    /// 木のノード `key`（[`crate::tree::node_key`]）。なければ `None`
    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError>;
    /// キーが `prefix` で始まる状態の行を、キーの順に `visit` に渡す。全部を一度にメモリに置かない
    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError>;
}
