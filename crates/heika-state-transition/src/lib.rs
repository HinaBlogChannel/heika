//! Symbol の状態遷移。catapult と同じ規則でブロックを当て、9本の状態の木と StateHash を求める。
//!
//! IO は持たない。メモリにない状態は、差し込む状態の読み口から読む（これから写す）。

pub mod account;
pub mod config;
pub mod table;
pub mod tree;
