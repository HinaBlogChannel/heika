//! 使い方を誤ると鍵が漏れる、Ed25519 の中の部品（feature `hazmat`）。
//!
//! heika の署名と検証が使っているものを、そのまま出す。アダプター署名のような、RFC 8032 の決まりどおりでない署名を
//! 組むときに使う。ここのものを組み合わせて作った署名でも、検証は [`crate::key::PublicKey::verify`]（catapult と
//! 同じ検証）で確かめること。
//!
//! 気をつけること:
//! - 同じ秘密鍵で、違うメッセージに同じノンスを使うと、2つの署名から秘密鍵が求まる。ノンスは、メッセージと、
//!   署名に仕込むものすべてから決めるか、乱数で作る
//! - [`ExpandedKey::scalar`] は秘密鍵そのものと同じ。外に出さない
//! - 受け取った点は [`decode_point`] で確かめる。小さい位数の成分が混ざった点を使うと、catapult の検証を通らない

pub use curve25519_dalek;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroizing;

use crate::ed25519;
use crate::key::PrivateKey;

/// 秘密鍵（RFC 8032 のシード）を SHA-512 で広げたもの
pub struct ExpandedKey(ed25519::ExpandedKey);

impl ExpandedKey {
    pub fn new(key: &PrivateKey) -> Self {
        Self(ed25519::ExpandedKey::new(key.as_bytes()))
    }

    /// 前半をクランプしたスカラー。署名の `s = r + h·a` の `a`
    pub fn scalar(&self) -> &Scalar {
        &self.0.scalar
    }

    /// 後半。RFC 8032 では、ノンスを `H(prefix ‖ M)` で決めるのに使う
    pub fn prefix(&self) -> &[u8; 32] {
        &self.0.prefix
    }

    /// 公開鍵の点。[`crate::key::PublicKey::from_private_key`] と同じもの
    pub fn public_point(&self) -> EdwardsPoint {
        EdwardsPoint::mul_base(&self.0.scalar)
    }
}

/// 検証と同じハッシュ `h = H(R ‖ A ‖ M)`。`encoded_r` と `public_key` は圧縮した点のバイト列
pub fn challenge(encoded_r: &[u8; 32], public_key: &[u8; 32], message: &[&[u8]]) -> Scalar {
    ed25519::challenge(encoded_r, public_key, message)
}

/// 点に戻す。catapult が公開鍵に求めるのと同じく、正規形で、曲線上にあり、素数位数の部分群に入っている点だけを
/// 受け付ける。単位元は弾かないので、要るなら呼ぶ側で弾く
pub fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    ed25519::decode(bytes)
}

/// SHA-512。部分を順に続けたもの
pub fn sha512<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Zeroizing<[u8; 64]> {
    ed25519::sha512(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::PublicKey;

    #[test]
    fn rebuilds_the_rfc_8032_signature() {
        // ここの部品で RFC 8032 のとおりに組むと、heika の署名と同じものになる
        let key = PrivateKey::from_bytes(&[7; 32]);
        let message: &[u8] = b"message";
        let expanded = ExpandedKey::new(&key);
        let public_key = PublicKey::from_private_key(&key);
        assert_eq!(expanded.public_point().compress().to_bytes(), public_key.0);
        let r = Scalar::from_bytes_mod_order_wide(&sha512([&expanded.prefix()[..], message]));
        let encoded_r = EdwardsPoint::mul_base(&r).compress().to_bytes();
        let s = r + challenge(&encoded_r, &public_key.0, &[message]) * expanded.scalar();
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&encoded_r);
        signature[32..].copy_from_slice(s.as_bytes());
        assert_eq!(signature, key.sign(&[message]).0);
        assert!(decode_point(&public_key.0).is_some());
    }
}
