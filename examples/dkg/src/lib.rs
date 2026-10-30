//! Symbol を掲示板にして、ディーラーなしで FROST（Ed25519）の鍵を分けて作る（DKG）。
//!
//! - [`wire`]：掲示板に載せるもの（約束、暗号化した分け前、苦情、明かした分け前）
//! - [`board`]：掲示板を読んで、DKG がどこまで進んだかを決める。誰が読んでも同じ結論になる
//! - [`member`]：参加者。今の段階で自分が載せるものを作る
//! - [`sign`]：できた鍵で署名する
//! - [`symbol`]：Symbol のノードの REST で、掲示板を読み書きする。預かり口座のトランザクションを作る

pub mod board;
pub mod member;
pub mod sign;
pub mod symbol;
pub mod wire;

#[cfg(test)]
mod tests;
