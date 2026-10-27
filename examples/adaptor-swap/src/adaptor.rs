//! Ed25519 のアダプター署名。Symbol の連署（アグリゲートのハッシュへの Ed25519 の署名）に、秘密を1つ仕込む。
//!
//! ふつうの署名は `(R, s)`、`s = r + e·x`、`e = H(R ‖ X ‖ m)`。アダプター署名では、署名する鍵 `x` とは別の点
//! `T = tG` を選び、ハッシュには `R + T` を使う。
//!
//! - [`pre_sign`]: `ŝ = r + e·x`、`e = H(R + T ‖ X ‖ m)` を作る。`t` が足りないので、まだ正しい署名ではない
//! - [`verify_pre`]: 受け取った人は、`ŝ·G = R + e·X` で、`t` を足せば正しい署名になることを確かめられる
//! - [`complete`]: `t` を知る人だけが、`(R + T, ŝ + t)` という正しい署名にできる。Symbol から見れば、`X` の
//!   ふつうの Ed25519 の署名で、catapult の厳しめの検証もそのまま通る
//! - [`extract`]: 完成した署名がチェーンに出ると、`ŝ` を持つ人は `t = s − ŝ` を取り出せる
//!
//! 署名する鍵と、仕込む秘密は別のものでよい。交換では、署名する鍵は Symbol の連署者の鍵、仕込むのは相手の
//! チェーンの秘密の半分（の公開鍵）にする。
//!
//! 鍵を広げたスカラー、検証と同じハッシュ、catapult と同じ点の確かめは、heika-core の `hazmat` のものを使う。
//! heika の署名と検証と同じ部品なので、作った署名が heika と catapult の検証を通るかは、その部品の正しさに乗る。

use heika_core::hazmat::curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use heika_core::hazmat::curve25519_dalek::scalar::Scalar;
use heika_core::hazmat::{self, ExpandedKey};
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::signature::Signature;
use zeroize::Zeroizing;

/// 仕込む秘密 `t`（交換では、相手のチェーンの秘密の半分）
pub struct Secret(Zeroizing<Scalar>);

impl Secret {
    /// 新しく作る
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        getrandom::fill(&mut bytes[..])?;
        Ok(Self(Zeroizing::new(Scalar::from_bytes_mod_order_wide(
            &bytes,
        ))))
    }

    /// 公開する点 `tG`
    pub fn point(&self) -> Point {
        Point(EdwardsPoint::mul_base(&self.0).compress().to_bytes())
    }

    /// 2つの秘密の和。交換では、両方の半分がそろうと、相手のチェーンのお金を動かせる
    pub fn sum(&self, other: &Self) -> Self {
        Self(Zeroizing::new(*self.0 + *other.0))
    }
}

/// 公開する点。受け取ったら [`Point::is_valid`] で確かめる
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Point(pub [u8; 32]);

impl Point {
    /// 2つの点の和。秘密の和の点と同じになる
    pub fn sum(&self, other: &Self) -> Option<Self> {
        Some(Self(
            (self.decode()? + other.decode()?).compress().to_bytes(),
        ))
    }

    /// 正規形で、曲線上にあり、素数位数の部分群に入っていて、単位元でないか。小さい位数の成分が混ざった点を
    /// 仕込むと、完成した署名の `R + T` にもその成分が残り、catapult の検証で弾かれる
    pub fn is_valid(&self) -> bool {
        self.decode().is_some()
    }

    fn decode(&self) -> Option<EdwardsPoint> {
        decode_point(&self.0)
    }
}

/// アダプター署名。`nonce` は完成した署名にそのまま入る `R + T`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PreSignature {
    pub nonce: [u8; 32],
    pub s: [u8; 32],
}

/// `key` で `message` に、`adaptor`（`T`）を仕込んだアダプター署名を作る。`adaptor` が正しい点でなければ `None`。
///
/// ノンスは、RFC 8032 と同じく秘密鍵を広げた後半から決める。`T` も混ぜるので、同じメッセージに違う `T` を仕込んでも、
/// 同じノンスを使い回さない
pub fn pre_sign(key: &PrivateKey, message: &[u8], adaptor: &Point) -> Option<PreSignature> {
    let t = adaptor.decode()?;
    let expanded = ExpandedKey::new(key);
    let public_key = expanded.public_point().compress();
    let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&hazmat::sha512([
        &expanded.prefix()[..],
        &adaptor.0,
        message,
    ])));
    let nonce = (EdwardsPoint::mul_base(&r) + t).compress();
    let e = hazmat::challenge(nonce.as_bytes(), public_key.as_bytes(), &[message]);
    let s = *r + e * expanded.scalar();
    Some(PreSignature {
        nonce: nonce.to_bytes(),
        s: s.to_bytes(),
    })
}

/// `pre` が、`public_key` で `message` に `adaptor` を仕込んだアダプター署名か。`adaptor` の秘密を足せば、
/// `public_key` の正しい署名になる
pub fn verify_pre(
    public_key: &PublicKey,
    message: &[u8],
    adaptor: &Point,
    pre: &PreSignature,
) -> bool {
    let (Some(x), Some(t), Some(nonce)) = (
        hazmat::decode_point(&public_key.0),
        adaptor.decode(),
        CompressedEdwardsY(pre.nonce).decompress(),
    ) else {
        return false;
    };
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(pre.s)) else {
        return false;
    };
    let e = hazmat::challenge(&pre.nonce, &public_key.0, &[message]);
    EdwardsPoint::mul_base(&s) == nonce - t + e * x
}

/// 秘密 `secret` を足して、正しい署名にする
pub fn complete(pre: &PreSignature, secret: &Secret) -> Signature {
    let s = Scalar::from_bytes_mod_order(pre.s) + *secret.0;
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&pre.nonce);
    signature[32..].copy_from_slice(s.as_bytes());
    Signature(signature)
}

/// チェーンに出た署名 `signature` が `pre` を完成させたものなら、仕込まれた秘密を取り出す。取り出したものが
/// 仕込んだ点の秘密かは、呼ぶ側が [`Secret::point`] で確かめる
pub fn extract(pre: &PreSignature, signature: &Signature) -> Option<Secret> {
    if signature.0[..32] != pre.nonce {
        return None;
    }
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(
        signature.0[32..].try_into().expect("half of 64 bytes"),
    ))?;
    Some(Secret(Zeroizing::new(
        s - Scalar::from_bytes_mod_order(pre.s),
    )))
}

/// 仕込む点。catapult が公開鍵に求めるのと同じ確かめに加えて、単位元も弾く（`T` が単位元なら何も仕込まれない）
fn decode_point(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    hazmat::decode_point(bytes).filter(|point| *point != EdwardsPoint::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use heika_core::hazmat::curve25519_dalek::constants::EIGHT_TORSION;

    const MESSAGE: &[u8] = b"aggregate hash";

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn completes_into_a_signature_and_reveals_the_secret() {
        let signer = key(1);
        let public_key = PublicKey::from_private_key(&signer);
        let secret = Secret::generate().unwrap();
        let adaptor = secret.point();
        let pre = pre_sign(&signer, MESSAGE, &adaptor).unwrap();
        assert!(verify_pre(&public_key, MESSAGE, &adaptor, &pre));

        // 足りないままでは、ふつうの署名として通らない
        let mut unfinished = [0; 64];
        unfinished[..32].copy_from_slice(&pre.nonce);
        unfinished[32..].copy_from_slice(&pre.s);
        assert!(!public_key.verify(&[MESSAGE], &Signature(unfinished)));

        // 秘密を足すと、heika（catapult と同じ検証）で通る署名になる
        let signature = complete(&pre, &secret);
        assert!(public_key.verify(&[MESSAGE], &signature));

        // チェーンに出た署名から、秘密を取り出せる
        let revealed = extract(&pre, &signature).unwrap();
        assert_eq!(revealed.point(), adaptor);
    }

    #[test]
    fn checks_what_was_presigned() {
        let signer = key(1);
        let public_key = PublicKey::from_private_key(&signer);
        let adaptor = Secret::generate().unwrap().point();
        let other = Secret::generate().unwrap().point();
        let pre = pre_sign(&signer, MESSAGE, &adaptor).unwrap();
        assert!(!verify_pre(&public_key, b"other hash", &adaptor, &pre));
        assert!(!verify_pre(&public_key, MESSAGE, &other, &pre));
        assert!(!verify_pre(
            &PublicKey::from_private_key(&key(2)),
            MESSAGE,
            &adaptor,
            &pre
        ));
        // 違う秘密で完成させても、正しい署名にならない
        let wrong = complete(&pre, &Secret::generate().unwrap());
        assert!(!public_key.verify(&[MESSAGE], &wrong));
        // ほかの署名からは取り出さない
        let plain = signer.sign(&[MESSAGE]);
        assert!(extract(&pre, &plain).is_none());
    }

    #[test]
    fn small_order_components_do_not_pass_the_strict_check() {
        let secret = Secret::generate().unwrap();
        let point = EdwardsPoint::mul_base(&secret.0) + EIGHT_TORSION[1];
        let tainted = Point(point.compress().to_bytes());
        assert!(secret.point().is_valid());
        assert!(!tainted.is_valid());
        assert!(pre_sign(&key(1), MESSAGE, &tainted).is_none());
        assert!(!Point(EdwardsPoint::default().compress().to_bytes()).is_valid());

        // 確かめずに仕込んで完成させると、R + T に小さい位数の成分が残り、catapult と同じ検証で弾かれる
        let signer = key(1);
        let expanded = ExpandedKey::new(&signer);
        let r = Scalar::from_bytes_mod_order([3; 32]);
        let nonce = (EdwardsPoint::mul_base(&r) + point).compress();
        let public_key = PublicKey::from_private_key(&signer);
        let e = hazmat::challenge(nonce.as_bytes(), &public_key.0, &[MESSAGE]);
        let pre = PreSignature {
            nonce: nonce.to_bytes(),
            s: (r + e * expanded.scalar()).to_bytes(),
        };
        assert!(!public_key.verify(&[MESSAGE], &complete(&pre, &secret)));
    }

    #[test]
    fn halves_add_up() {
        let (a, b) = (Secret::generate().unwrap(), Secret::generate().unwrap());
        assert_eq!(a.point().sum(&b.point()), Some(a.sum(&b).point()));
    }
}
