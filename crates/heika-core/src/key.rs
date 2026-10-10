//! 鍵。

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::SigningKey;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::hex::{self, ParseHexError};

/// Ed25519 の公開鍵。catapult の `Key` と同じく、曲線上の点かどうかは確かめず32バイトとして扱う。
/// 文字列にするときは、Symbol の慣習に合わせて大文字の16進にする。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// 秘密鍵から導出する。catapult の `crypto/KeyPair.cpp` と同じく、RFC 8032 の Ed25519（SHA-512）。
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        Self(
            SigningKey::from_bytes(&private_key.0)
                .verifying_key()
                .to_bytes(),
        )
    }
}

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

/// Ed25519 の秘密鍵（RFC 8032 のシード）。使い終わるとメモリを0で上書きする。
/// 中身が表示されたり、読むのにかかる時間から漏れたりしないように、
/// `Display` は持たず、16進との変換は定数時間で行う。
pub struct PrivateKey(Zeroizing<[u8; 32]>);

impl PrivateKey {
    /// 渡された暗号用の乱数で作る。
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.fill_bytes(&mut *bytes);
        Self(bytes)
    }

    /// OS の乱数で作る。
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *bytes)?;
        Ok(Self(bytes))
    }

    /// 大文字の16進にする。表示するつもりで呼ぶときだけ使う。
    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut buffer = Zeroizing::new([0; 64]);
        let text = base16ct::upper::encode_str(&*self.0, &mut *buffer)
            .expect("64 bytes hold 32 bytes of hex");
        Zeroizing::new(text.to_owned())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(..)")
    }
}

impl FromStr for PrivateKey {
    type Err = ParsePrivateKeyError;

    /// 大文字も小文字も受け付ける。
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // base16ct は短い入力でも読めた分だけ返すので、長さは先に確かめる
        if text.len() != 64 {
            return Err(ParsePrivateKeyError::InvalidLength);
        }
        let mut bytes = Zeroizing::new([0; 32]);
        base16ct::mixed::decode(text, &mut *bytes)
            .map_err(|_| ParsePrivateKeyError::InvalidCharacter)?;
        Ok(Self(bytes))
    }
}

/// 秘密鍵が読めなかった理由。秘密鍵の一部を漏らさないように、どこの何が悪かったかは含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePrivateKeyError {
    /// 16進で64文字になっていない
    InvalidLength,
    /// 16進の数字ではない文字が含まれている
    InvalidCharacter,
}

impl fmt::Display for ParsePrivateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("秘密鍵は16進で64文字のはずです"),
            Self::InvalidCharacter => f.write_str("秘密鍵に16進の数字ではない文字が含まれています"),
        }
    }
}

impl std::error::Error for ParsePrivateKeyError {}

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

    // 公式ベクター crypto/1.test-keys.json の最初の秘密鍵
    const PRIVATE: &str = "575DBB3062267EFF57C970A336EBBC8FBCFE12C5BD3ED7BC11EB0481D7704CED";

    #[test]
    fn private_key_round_trips_through_upper_case_hex() {
        let key: PrivateKey = PRIVATE.parse().unwrap();
        assert_eq!(*key.to_hex(), PRIVATE);
    }

    #[test]
    fn private_key_accepts_lower_case_and_writes_upper_case() {
        let key: PrivateKey = PRIVATE.to_lowercase().parse().unwrap();
        assert_eq!(*key.to_hex(), PRIVATE);
    }

    #[test]
    fn private_key_debug_hides_the_key() {
        let key: PrivateKey = PRIVATE.parse().unwrap();
        assert_eq!(format!("{key:?}"), "PrivateKey(..)");
    }

    #[test]
    fn private_key_rejects_a_short_key() {
        assert_eq!(
            PRIVATE[..62].parse::<PrivateKey>().unwrap_err(),
            ParsePrivateKeyError::InvalidLength
        );
    }

    #[test]
    fn private_key_error_does_not_reveal_the_key() {
        let typo = format!("{}G", &PRIVATE[..63]);
        let error = typo.parse::<PrivateKey>().unwrap_err();
        assert_eq!(error, ParsePrivateKeyError::InvalidCharacter);
        assert!(!error.to_string().contains('G'));
    }

    #[test]
    fn private_key_rejects_non_ascii_without_panicking() {
        // 「あ」は3バイトなので、バイト数では64になる
        let text = format!("{}あ", &PRIVATE[..61]);
        assert_eq!(
            text.parse::<PrivateKey>().unwrap_err(),
            ParsePrivateKeyError::InvalidCharacter
        );
    }

    #[test]
    fn derives_the_public_key_from_the_private_key() {
        let key: PrivateKey = PRIVATE.parse().unwrap();
        assert_eq!(
            PublicKey::from_private_key(&key).to_string(),
            "2E834140FD66CF87B254A693A2C7862C819217B676D3943267156625E816EC6F"
        );
    }

    /// 決まったバイト列を返すだけの乱数。テストで鍵を固定するのに使う。
    struct Replay<'a>(&'a [u8]);

    impl rand_core::TryRng for Replay<'_> {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let (head, rest) = self.0.split_at(dst.len());
            dst.copy_from_slice(head);
            self.0 = rest;
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Replay<'_> {}

    #[test]
    fn generates_from_the_given_rng() {
        let bytes = crate::hex::decode::<32>(PRIVATE).unwrap();
        let key = PrivateKey::generate_with_rng(&mut Replay(&bytes));
        assert_eq!(*key.to_hex(), PRIVATE);
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn generates_different_keys_from_the_os() {
        let first = PrivateKey::generate().unwrap();
        let second = PrivateKey::generate().unwrap();
        assert_ne!(*first.to_hex(), *second.to_hex());
    }
}
