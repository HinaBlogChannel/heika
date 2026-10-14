//! 公開鍵あての暗号化。catapult の `crypto/SharedKey.cpp` と `crypto/AesDecrypt.cpp`。
//!
//! 委任ハーベストの要求で、リモートアカウントと VRF の秘密鍵をノードに渡すのと、Transfer の暗号化したメッセージに使う。
//! 鍵共有は X25519 ではなく、Edwards 曲線の点のまま秘密鍵のスカラーを掛ける。

use std::fmt;

use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use heika_core::key::{PrivateKey, PublicKey};
use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// AES-GCM の認証タグの長さ。
pub const TAG_SIZE: usize = 16;
/// AES-GCM の初期化ベクトルの長さ。
pub const IV_SIZE: usize = 12;

/// 2つの鍵から導出した、AES-256-GCM の鍵。使い終わるとメモリを0で上書きする。
pub struct SharedKey(Zeroizing<[u8; 32]>);

impl SharedKey {
    /// 自分の秘密鍵と相手の公開鍵から導出する。catapult の `DeriveSharedKey`。
    ///
    /// 秘密鍵の SHA-512 の前半をクランプしたスカラーを相手の点に掛け、
    /// 圧縮した点を HKDF-HMAC-SHA256 にかける。相手の公開鍵は、署名の検証と同じく
    /// y が正規で、曲線上にあり、位数 L の部分群に入っているものだけを受け付ける。
    pub fn derive(
        private_key: &PrivateKey,
        other_public_key: &PublicKey,
    ) -> Result<Self, InvalidPublicKey> {
        let point = decode(&other_public_key.0).ok_or(InvalidPublicKey)?;
        let mut multiplier = Zeroizing::new([0; 32]);
        multiplier.copy_from_slice(&Sha512::digest(private_key.as_bytes())[..32]);
        let product = Zeroizing::new(point.mul_clamped(*multiplier));
        let shared_secret = Zeroizing::new(product.compress());
        Ok(Self(hkdf(shared_secret.as_bytes())))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedKey(..)")
    }
}

/// 暗号化する。catapult が読む並びの、認証タグ、初期化ベクトル、暗号文を続けたものを返す。
pub fn encrypt(key: &SharedKey, iv: &[u8; IV_SIZE], plaintext: &[u8]) -> Vec<u8> {
    let mut encrypted = vec![0; TAG_SIZE + IV_SIZE + plaintext.len()];
    let (head, ciphertext) = encrypted.split_at_mut(TAG_SIZE + IV_SIZE);
    ciphertext.copy_from_slice(plaintext);
    let tag = cipher(key)
        .encrypt_inout_detached(iv.into(), &[], ciphertext.into())
        .expect("the plaintext fits in AES-GCM");
    head[..TAG_SIZE].copy_from_slice(&tag);
    head[TAG_SIZE..].copy_from_slice(iv);
    encrypted
}

/// 復号する。catapult の `AesGcm256::TryDecrypt`。
pub fn decrypt(key: &SharedKey, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    if encrypted.len() < TAG_SIZE + IV_SIZE {
        return Err(DecryptError::TooShort);
    }
    let (tag, rest) = encrypted.split_at(TAG_SIZE);
    let (iv, ciphertext) = rest.split_at(IV_SIZE);
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher(key)
        .decrypt_inout_detached(
            iv.try_into().expect("split at IV_SIZE"),
            &[],
            plaintext.as_mut_slice().into(),
            tag.try_into().expect("split at TAG_SIZE"),
        )
        .map_err(|_| DecryptError::Failed)?;
    Ok(plaintext)
}

/// 相手の公開鍵あてに暗号化する。使い捨ての鍵を作って共有鍵を導出し、
/// その公開鍵に続けて、認証タグ、初期化ベクトル、暗号文を並べる。
/// catapult の `TryDecryptEd25199BlockCipher` で復号できる。
pub fn seal<R: CryptoRng + ?Sized>(
    rng: &mut R,
    recipient_public_key: &PublicKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, InvalidPublicKey> {
    let ephemeral_key = PrivateKey::generate_with_rng(rng);
    let mut iv = [0; IV_SIZE];
    rng.fill_bytes(&mut iv);
    let key = SharedKey::derive(&ephemeral_key, recipient_public_key)?;
    let mut sealed = PublicKey::from_private_key(&ephemeral_key).0.to_vec();
    sealed.extend_from_slice(&encrypt(&key, &iv, plaintext));
    Ok(sealed)
}

/// `seal` したものを、受け取る側の秘密鍵で復号する。
pub fn open(private_key: &PrivateKey, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let (ephemeral_public_key, encrypted) = sealed
        .split_first_chunk::<32>()
        .ok_or(DecryptError::TooShort)?;
    let key = SharedKey::derive(private_key, &PublicKey(*ephemeral_public_key))
        .map_err(|_| DecryptError::InvalidPublicKey)?;
    decrypt(&key, encrypted)
}

fn cipher(key: &SharedKey) -> Aes256Gcm {
    Aes256Gcm::new(key.as_bytes().into())
}

/// catapult の `Hkdf_Hmac_Sha256_32`。salt は32バイトの0、info は "catapult" で、32バイトだけ取り出す。
fn hkdf(shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let pseudo_random_key = hmac_sha256(&[0; 32], &[shared_secret]);
    hmac_sha256(&pseudo_random_key[..], &[b"catapult", &[1]])
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    for part in data {
        mac.update(part);
    }
    let mut output = Zeroizing::new([0; 32]);
    mac.finalize_into(
        (&mut output[..])
            .try_into()
            .expect("SHA-256 outputs 32 bytes"),
    );
    output
}

/// 公開鍵を曲線上の点にする。heika-core の署名の検証と同じ条件で、
/// catapult の `UnpackNegativeAndCheckSubgroup`。
fn decode(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    if !is_canonical(bytes) {
        return None;
    }
    CompressedEdwardsY(*bytes)
        .decompress()
        .filter(EdwardsPoint::is_torsion_free)
}

/// 符号のビットを除いた y が 2^255 - 19 より小さいか。catapult の `IsCanonicalKey`。
fn is_canonical(bytes: &[u8; 32]) -> bool {
    bytes[0] < 0xED || bytes[1..31].iter().any(|&byte| byte != 0xFF) || bytes[31] & 0x7F != 0x7F
}

/// 相手の公開鍵が、正規の形で書かれた、位数 L の部分群の点ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPublicKey;

impl fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("公開鍵が、鍵の共有に使える曲線上の点ではありません")
    }
}

impl std::error::Error for InvalidPublicKey {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    /// 認証タグや初期化ベクトルの長さに足りない
    TooShort,
    /// 先頭の使い捨ての公開鍵が、曲線上の点ではない
    InvalidPublicKey,
    /// 鍵が違うか、改ざんされている。どちらかは区別しない
    Failed,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("暗号文が短すぎます"),
            Self::InvalidPublicKey => f.write_str("使い捨ての公開鍵が曲線上の点ではありません"),
            Self::Failed => f.write_str("復号できませんでした。鍵が違うか、改ざんされています"),
        }
    }
}

impl std::error::Error for DecryptError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Replay;

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1 と 2 の秘密鍵
    const ALICE: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    const BOB: &str = "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB";

    fn key(text: &str) -> (PrivateKey, PublicKey) {
        let private_key: PrivateKey = text.parse().unwrap();
        let public_key = PublicKey::from_private_key(&private_key);
        (private_key, public_key)
    }

    #[test]
    fn both_sides_derive_the_same_key() {
        let (alice, alice_public) = key(ALICE);
        let (bob, bob_public) = key(BOB);
        let from_alice = SharedKey::derive(&alice, &bob_public).unwrap();
        let from_bob = SharedKey::derive(&bob, &alice_public).unwrap();
        assert_eq!(from_alice.as_bytes(), from_bob.as_bytes());
    }

    #[test]
    fn hkdf_matches_rfc_5869_with_catapult_parameters() {
        let secret = [0x42; 32];
        let mut expected = [0; 32];
        hkdf::Hkdf::<Sha256>::new(Some(&[0; 32]), &secret)
            .expand(b"catapult", &mut expected)
            .unwrap();
        assert_eq!(*hkdf(&secret), expected);
    }

    #[test]
    fn rejects_public_keys_that_are_not_usable_points() {
        let (alice, _) = key(ALICE);
        let mut order_two = [0xFF; 32];
        order_two[0] = 0xEC;
        order_two[31] = 0x7F;
        let mut non_canonical = [0xFF; 32];
        non_canonical[0] = 0xED;
        non_canonical[31] = 0x7F;
        let mut not_on_curve = [0; 32];
        not_on_curve[0] = 2;
        for (name, bytes) in [
            // y = -1 は位数 2 の点
            ("order two", order_two),
            // y = p は 0 の別の書き方
            ("non canonical", non_canonical),
            ("not on curve", not_on_curve),
        ] {
            assert_eq!(
                SharedKey::derive(&alice, &PublicKey(bytes)).unwrap_err(),
                InvalidPublicKey,
                "{name}"
            );
        }
    }

    #[test]
    fn encrypts_in_the_catapult_layout() {
        let (alice, _) = key(ALICE);
        let (_, bob_public) = key(BOB);
        let key = SharedKey::derive(&alice, &bob_public).unwrap();
        let iv = [7; IV_SIZE];
        let encrypted = encrypt(&key, &iv, b"hello");
        assert_eq!(encrypted.len(), TAG_SIZE + IV_SIZE + 5);
        assert_eq!(encrypted[TAG_SIZE..TAG_SIZE + IV_SIZE], iv);
        assert_eq!(*decrypt(&key, &encrypted).unwrap(), b"hello");
    }

    #[test]
    fn seals_with_the_given_rng_and_opens_with_the_recipient_key() {
        let (bob, bob_public) = key(BOB);
        let randomness = [0x11; 32 + IV_SIZE];
        let sealed = seal(&mut Replay(&randomness), &bob_public, b"secret").unwrap();
        let (_, ephemeral_public) = key(&"11".repeat(32));
        assert_eq!(sealed[..32], ephemeral_public.0);
        assert_eq!(
            sealed[32 + TAG_SIZE..32 + TAG_SIZE + IV_SIZE],
            [0x11; IV_SIZE]
        );
        assert_eq!(*open(&bob, &sealed).unwrap(), b"secret");
    }

    #[test]
    fn refuses_another_key_or_a_changed_byte() {
        let (_, bob_public) = key(BOB);
        let (alice, _) = key(ALICE);
        let randomness = [0x11; 32 + IV_SIZE];
        let sealed = seal(&mut Replay(&randomness), &bob_public, b"secret").unwrap();
        assert_eq!(open(&alice, &sealed).unwrap_err(), DecryptError::Failed);
        let (bob, _) = key(BOB);
        for index in [32, 32 + TAG_SIZE, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[index] ^= 1;
            assert_eq!(
                open(&bob, &changed).unwrap_err(),
                DecryptError::Failed,
                "byte {index}"
            );
        }
    }

    #[test]
    fn refuses_what_is_too_short() {
        let (bob, _) = key(BOB);
        assert_eq!(open(&bob, &[0; 31]).unwrap_err(), DecryptError::TooShort);
        let mut sealed = PublicKey::from_private_key(&bob).0.to_vec();
        sealed.extend_from_slice(&[0; TAG_SIZE + IV_SIZE - 1]);
        assert_eq!(open(&bob, &sealed).unwrap_err(), DecryptError::TooShort);
    }

    #[test]
    fn debug_hides_the_shared_key() {
        let (alice, _) = key(ALICE);
        let (_, bob_public) = key(BOB);
        let key = SharedKey::derive(&alice, &bob_public).unwrap();
        assert_eq!(format!("{key:?}"), "SharedKey(..)");
    }
}
