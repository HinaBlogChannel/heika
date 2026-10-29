//! XYM を EVM に持っていく橋。
//!
//! - Symbol の側：預かり口座は、見張り役で分けて持つ Ed25519 の鍵を連署者にしたマルチシグ
//! - EVM の側：発行は、見張り役で分けて持つ secp256k1 の鍵の Schnorr の署名 1 つで認める
//!
//! どちらの鍵も FROST で分けて持ち、ROAST で署名する。

pub mod evm;
pub mod roast;
pub mod symbol;
