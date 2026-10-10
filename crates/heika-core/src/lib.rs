//! Symbol の合意形成に関わる計算。ノードも同じ計算をしていて、間違えると合意から外れるもの。

mod hex;
pub mod key;

pub use hex::ParseHexError;
