//! Symbol のチェーンを追う中核。運用者が設定で選んだ規則の上で、ピアから届いたブロックと証明を確かめて先端を
//! 進め、枝を取り替え、ハーベストする。IO は持たない（sans-IO）。出来事を受け取って指示を返し、時計と保存は差し込む。

pub mod chain;
pub mod env;
pub mod event;
pub mod memory;
pub mod produce;
pub mod store;
pub mod verify;

/// 中核の誤り。保存の口が返すものも、ここに入れて返す
pub type ChainError = Box<dyn std::error::Error + Send + Sync>;
