//! ネットワークの識別子。catapult の `model/NetworkIdentifier.h`。

/// アドレスやエンティティの先頭に入る1バイト。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NetworkIdentifier(pub u8);

impl NetworkIdentifier {
    /// メインネット。アドレスは N から始まる。
    pub const MAINNET: Self = Self(0x68);
    /// テストネット。アドレスは T から始まる。
    pub const TESTNET: Self = Self(0x98);
}
