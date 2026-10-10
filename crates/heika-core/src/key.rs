//! 鍵。

use std::fmt;
use std::str::FromStr;

use crate::hex::{self, ParseHexError};

/// Ed25519 の公開鍵。catapult の `Key` と同じく、曲線上の点かどうかは確かめず32バイトとして扱う。
/// 文字列にするときは、Symbol の慣習に合わせて大文字の16進にする。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = ParseHexError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        hex::decode(text).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPPER: &str = "79AF37ED4A98EF6C79F8C26992EA55ECEF74865827A1BBB602374C8F4F13DA07";

    #[test]
    fn round_trips_through_upper_case_hex() {
        let key: PublicKey = UPPER.parse().unwrap();
        assert_eq!(key.0[..2], [0x79, 0xAF]);
        assert_eq!(key.to_string(), UPPER);
    }

    #[test]
    fn accepts_lower_case_and_displays_upper_case() {
        let key: PublicKey = UPPER.to_lowercase().parse().unwrap();
        assert_eq!(key.to_string(), UPPER);
    }

    #[test]
    fn debug_shows_hex() {
        let key: PublicKey = UPPER.parse().unwrap();
        assert_eq!(format!("{key:?}"), format!("PublicKey({UPPER})"));
    }

    #[test]
    fn rejects_a_short_key() {
        assert_eq!(
            UPPER[..62].parse::<PublicKey>(),
            Err(ParseHexError::InvalidLength {
                expected: 64,
                actual: 62
            })
        );
    }
}
