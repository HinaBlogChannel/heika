//! ネットワークの識別子。catapult の `model/NetworkIdentifier.h`。

use std::fmt;
use std::str::FromStr;

use crate::hex::{self, ParseHexError};

/// アドレスやエンティティの先頭に入る1バイト。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NetworkIdentifier(pub u8);

impl NetworkIdentifier {
    /// メインネット。アドレスは N から始まる。
    pub const MAINNET: Self = Self(0x68);
    /// テストネット。アドレスは T から始まる。
    pub const TESTNET: Self = Self(0x98);
}

/// ネットワークごとに決まる32バイト。catapult の `GenerationHashSeed`。
/// トランザクションの署名とハッシュに混ぜて、別のネットワークで使い回せないようにする。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationHashSeed(pub [u8; 32]);

impl fmt::Display for GenerationHashSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for GenerationHashSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenerationHashSeed({self})")
    }
}

impl FromStr for GenerationHashSeed {
    type Err = ParseHexError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        hex::decode(text).map(Self)
    }
}
