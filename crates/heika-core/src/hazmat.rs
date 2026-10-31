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
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
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

/// 小さい位数の点（位数が 8 の約数の点）8 個を、圧縮したバイト列と位数の組で返す。
///
/// 並びは位数の小さい順で、同じ位数の中ではバイト列の小さい順。8 個は位数 8 の巡回群をなし、単位元
/// `01 00…00` も含む。番号の振り方には決まったものがないので、点はバイト列で扱う。
pub fn small_order_points() -> [([u8; 32], u8); 8] {
    let mut points = curve25519_dalek::constants::EIGHT_TORSION.map(|point| {
        let order = [1u8, 2, 4, 8]
            .into_iter()
            .find(|&order| (point * Scalar::from(order)).is_identity())
            .expect("eight-torsion points have order dividing 8");
        (point.compress().to_bytes(), order)
    });
    points.sort_by_key(|&(bytes, order)| (order, bytes));
    points
}

/// 2 つの点を足す。どちらも正規形で曲線上にあればよく、素数位数の部分群に入っているかは問わない。
/// 結果は正規形の圧縮したバイト列。どちらかが点に戻せなければ `None`。
///
/// 公開鍵に小さい位数の点（単位元を除く）を足すと、catapult の検証が部分群の外の公開鍵を弾くので、
/// 誰も署名できない鍵になる。ただし、これは今の検証の決まりの下での話で、位数 8 を掛けてから比べる検証
/// （ZIP-215 など）では、元の鍵の持ち主が署名できる。小さい位数の点そのものなら、誰でも署名できる。
pub fn add_points(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let decode = |bytes: &[u8; 32]| {
        ed25519::is_canonical(bytes)
            .then(|| CompressedEdwardsY(*bytes).decompress())
            .flatten()
    };
    Some((decode(a)? + decode(b)?).compress().to_bytes())
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

    const IDENTITY: [u8; 32] = {
        let mut bytes = [0; 32];
        bytes[0] = 1;
        bytes
    };

    #[test]
    fn lists_the_eight_small_order_points() {
        let points = small_order_points();
        assert_eq!(points.map(|(_, order)| order), [1, 2, 4, 4, 8, 8, 8, 8]);
        assert_eq!(points[0].0, IDENTITY);
        // y = -1 が位数 2、y = 0 が位数 4
        let mut minus_one = [0xFF; 32];
        minus_one[0] = 0xEC;
        minus_one[31] = 0x7F;
        assert_eq!(points[1].0, minus_one);
        assert_eq!(points[2].0, [0; 32]);
        let mut zero_negative_x = [0; 32];
        zero_negative_x[31] = 0x80;
        assert_eq!(points[3].0, zero_negative_x);
        // 足しても 8 個の中に閉じている
        for (a, _) in points {
            for (b, _) in points {
                let sum = add_points(&a, &b).unwrap();
                assert!(points.iter().any(|&(point, _)| point == sum));
            }
        }
    }

    #[test]
    fn a_public_key_plus_a_small_order_point_cannot_sign() {
        let key = PrivateKey::from_bytes(&[7; 32]);
        let public_key = PublicKey::from_private_key(&key);
        let message: &[u8] = b"message";
        let signature = key.sign(&[message]);
        for (point, order) in small_order_points() {
            let shifted = add_points(&public_key.0, &point).unwrap();
            if order == 1 {
                assert_eq!(shifted, public_key.0);
                continue;
            }
            assert!(decode_point(&shifted).is_none());
            assert!(!PublicKey(shifted).verify(&[message], &signature));
            // 元に戻せる
            let back = add_points(
                &shifted,
                &(-CompressedEdwardsY(point).decompress().unwrap())
                    .compress()
                    .to_bytes(),
            );
            assert_eq!(back, Some(public_key.0));
        }
    }

    #[test]
    fn the_identity_plus_a_small_order_point_is_that_point() {
        for (point, _) in small_order_points() {
            assert_eq!(add_points(&IDENTITY, &point), Some(point));
        }
    }

    #[test]
    fn rejects_a_non_canonical_point() {
        // y = p は正規形でない（y = 0 と同じ点になる）
        let mut p = [0xFF; 32];
        p[0] = 0xED;
        p[31] = 0x7F;
        assert_eq!(add_points(&p, &IDENTITY), None);
        assert_eq!(add_points(&IDENTITY, &p), None);
    }
}
