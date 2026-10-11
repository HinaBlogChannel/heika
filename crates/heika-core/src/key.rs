//! 鍵。

use std::fmt;
use std::str::FromStr;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::ed25519;
use crate::hex::{self, ParseHexError};
use crate::signature::Signature;

/// Ed25519 の公開鍵。catapult の `Key` と同じく、曲線上の点かどうかは確かめず32バイトとして扱う。
/// 文字列にするときは、Symbol の慣習に合わせて大文字の16進にする。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    /// 秘密鍵から導出する。catapult の `crypto/KeyPair.cpp` と同じく、RFC 8032 の Ed25519（SHA-512）。
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        Self(ed25519::public_key(&private_key.0))
    }

    /// 署名を検証する。catapult の `crypto::Verify` と同じものだけを受け付ける。
    ///
    /// catapult と同じく、メッセージはいくつかに分けたまま渡せる。
    pub fn verify(&self, message: &[&[u8]], signature: &Signature) -> bool {
        ed25519::verify(&self.0, message, &signature.0)
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
    /// 32バイトのシードから作る。渡した側の配列は呼び出し側で消す。
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

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

    /// 32バイトのシードとして見る。PEM などに書き出すつもりで呼ぶときだけ使う。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 大文字の16進にする。表示するつもりで呼ぶときだけ使う。
    pub fn to_hex(&self) -> Zeroizing<String> {
        let mut buffer = Zeroizing::new([0; 64]);
        let text = base16ct::upper::encode_str(&*self.0, &mut *buffer)
            .expect("64 bytes hold 32 bytes of hex");
        Zeroizing::new(text.to_owned())
    }

    /// RFC 8032 の Ed25519 で署名する。catapult の `crypto::Sign` と同じ。
    ///
    /// catapult と同じく、メッセージはいくつかに分けたまま渡せる。
    pub fn sign(&self, message: &[&[u8]]) -> Signature {
        Signature(ed25519::sign(&self.0, message))
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

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1
    const PRIVATE: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";

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
            "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
        );
    }

    #[test]
    fn private_key_from_bytes_keeps_the_bytes() {
        let key = PrivateKey::from_bytes(&[0xAB; 32]);
        assert_eq!(*key.to_hex(), "AB".repeat(32));
    }

    /// RFC 8032 の 7.1 節にある Ed25519 のテスト 1 から 3。秘密鍵、公開鍵、メッセージ、署名
    const RFC_8032: [(&str, &str, &str, &str); 3] = [
        (
            PRIVATE,
            "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A",
            "",
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B",
        ),
        (
            "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB",
            "3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C",
            "72",
            "92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00",
        ),
        (
            "C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7",
            "FC51CD8E6218A1A38DA47ED00230F0580816ED13BA3303AC5DEB911548908025",
            "AF82",
            "6291D657DEEC24024827E69C3ABE01A30CE548A284743A445E3680D7DB5AC3AC18FF9B538D16F290AE67F760984DC6594A7C15E9716ED28DC027BECEEA1EC40A",
        ),
    ];

    fn message(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn signs_like_rfc_8032() {
        for (private_key, _, text, signature) in RFC_8032 {
            let key: PrivateKey = private_key.parse().unwrap();
            assert_eq!(key.sign(&[&message(text)]).to_string(), signature);
        }
    }

    #[test]
    fn verifies_rfc_8032_signatures() {
        for (_, public_key, text, signature) in RFC_8032 {
            let key: PublicKey = public_key.parse().unwrap();
            let signature: Signature = signature.parse().unwrap();
            assert!(key.verify(&[&message(text)], &signature));
            assert!(!key.verify(&[&message(text), b"!"], &signature));
        }
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
