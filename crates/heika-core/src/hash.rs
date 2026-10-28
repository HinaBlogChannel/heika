//! ハッシュ。

use core::fmt;
use core::str::FromStr;

use crate::hex::{self, ParseHexError};

/// 32バイトのハッシュ。catapult の `Hash256`。トランザクションやブロックのハッシュに使う。
/// 文字列にするときは、Symbol の慣習に合わせて大文字の16進にする。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({self})")
    }
}

impl FromStr for Hash256 {
    type Err = ParseHexError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        hex::decode(text).map(Self)
    }
}
