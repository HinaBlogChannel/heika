//! Ed25519 の署名と検証。catapult の `crypto/Signer.cpp` と `crypto/CryptoUtils.cpp`。
//!
//! 署名は RFC 8032 そのまま。検証は catapult と同じものだけを受け付けるので、
//! ed25519-dalek の `verify` とも `verify_strict` とも少し違う。

use std::iter;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// 秘密鍵（RFC 8032 のシード）を SHA-512 で広げたもの。
struct ExpandedKey {
    /// 前半をクランプしたスカラー
    scalar: Zeroizing<Scalar>,
    /// 後半。nonce を作るのに使う
    prefix: Zeroizing<[u8; 32]>,
}

impl ExpandedKey {
    fn new(seed: &[u8; 32]) -> Self {
        let hash = sha512([&seed[..]]);
        let mut lower = Zeroizing::new([0; 32]);
        let mut prefix = Zeroizing::new([0; 32]);
        lower.copy_from_slice(&hash[..32]);
        prefix.copy_from_slice(&hash[32..]);
        lower[0] &= 0xF8;
        lower[31] &= 0x7F;
        lower[31] |= 0x40;
        Self {
            scalar: Zeroizing::new(Scalar::from_bytes_mod_order(*lower)),
            prefix,
        }
    }

    fn public_key(&self) -> CompressedEdwardsY {
        EdwardsPoint::mul_base(&self.scalar).compress()
    }
}

/// 署名する。
pub fn sign(seed: &[u8; 32], message: &[&[u8]]) -> [u8; 64] {
    let key = ExpandedKey::new(seed);
    let public_key = key.public_key();
    // r = H(prefix || M)
    let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&sha512(
        iter::once(&key.prefix[..]).chain(message.iter().copied()),
    )));
    let encoded_r = EdwardsPoint::mul_base(&r).compress();
    let h = challenge(encoded_r.as_bytes(), public_key.as_bytes(), message);
    // S = r + h * a
    let product = Zeroizing::new(h * *key.scalar);
    let s = *product + *r;
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(encoded_r.as_bytes());
    signature[32..].copy_from_slice(s.as_bytes());
    signature
}

/// 署名を検証する。catapult の `crypto::Verify` と同じものを受け付ける。
pub fn verify(public_key: &[u8; 32], message: &[&[u8]], signature: &[u8; 64]) -> bool {
    let (encoded_r, encoded_s) = signature.split_at(32);
    let encoded_r: &[u8; 32] = encoded_r.try_into().expect("half of 64 bytes");
    let encoded_s: [u8; 32] = encoded_s.try_into().expect("half of 64 bytes");
    // S は 0 より大きく、群の位数より小さくなければならない
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(encoded_s)) else {
        return false;
    };
    if s == Scalar::ZERO {
        return false;
    }
    // 全部 0 の公開鍵は既知の弱い鍵として弾く
    if *public_key == [0; 32] {
        return false;
    }
    let h = challenge(encoded_r, public_key, message);
    let Some(a) = decode(public_key) else {
        return false;
    };
    // R を復元せず、S * B - h * A を圧縮したものと比べる。
    // 計算した点は素数位数の部分群に入っていて正規形に圧縮されるので、R が正規形でなかったり、
    // 小さい位数の成分を持っていたりすると一致しない
    let expected_r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-a, &s);
    expected_r.compress().as_bytes() == encoded_r
}

/// h = H(R || A || M)。A は受け取ったバイト列のまま使う。
fn challenge(encoded_r: &[u8; 32], public_key: &[u8; 32], message: &[&[u8]]) -> Scalar {
    let parts = [&encoded_r[..], &public_key[..]];
    Scalar::from_bytes_mod_order_wide(&sha512(parts.into_iter().chain(message.iter().copied())))
}

/// 公開鍵を点に戻す。catapult の `UnpackNegativeAndCheckSubgroup` と同じく、
/// y が正規形で、曲線上にあり、素数位数の部分群に入っている点だけを受け付ける。
///
/// x が 0 なのに符号のビットが立っているものは、catapult も curve25519-dalek も受け付ける。
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

fn sha512<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Zeroizing<[u8; 64]> {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let mut output = Zeroizing::new([0; 64]);
    hasher.finalize_into(
        (&mut output[..])
            .try_into()
            .expect("SHA-512 outputs 64 bytes"),
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED;

    /// 単位元 (0, 1) の正規形
    const IDENTITY: [u8; 32] = point_with_y(1, 0);

    /// y の下位1バイトだけが違う点の符号。`high` は最上位バイトの符号のビット。
    const fn point_with_y(low: u8, high: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = low;
        bytes[31] = high;
        bytes
    }

    /// 2^255 - 19 + 1。y を法で縮めると単位元になる、正規形でない符号
    const NON_CANONICAL_IDENTITY: [u8; 32] = {
        let mut bytes = [0xFF; 32];
        bytes[0] = 0xEE;
        bytes[31] = 0x7F;
        bytes
    };

    fn signature(encoded_r: &[u8; 32], s: &Scalar) -> [u8; 64] {
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(encoded_r);
        signature[32..].copy_from_slice(s.as_bytes());
        signature
    }

    /// 秘密鍵を知っている人が、R の符号を好きに選んで S = h * a を作る。
    /// 計算した R は単位元になるので、R の符号が単位元の正規形のときだけ通るはず
    fn forge_with_identity_r(seed: &[u8; 32], encoded_r: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
        let key = ExpandedKey::new(seed);
        let public_key = key.public_key().to_bytes();
        let h = challenge(encoded_r, &public_key, &[b"heika"]);
        (public_key, signature(encoded_r, &(h * *key.scalar)))
    }

    #[test]
    fn verifies_a_signature_split_into_parts() {
        let seed = [7; 32];
        let public_key = ExpandedKey::new(&seed).public_key().to_bytes();
        let signature = sign(&seed, &[b"hei", b"ka"]);
        assert_eq!(signature, sign(&seed, &[b"heika"]));
        assert!(verify(&public_key, &[b"heika"], &signature));
        assert!(!verify(&public_key, &[b"heika!"], &signature));
    }

    #[test]
    fn accepts_the_identity_as_a_public_key() {
        // catapult は全部 0 の鍵しか弾かないので、単位元の鍵では S * B = R がそのまま通る
        let signature = signature(ED25519_BASEPOINT_COMPRESSED.as_bytes(), &Scalar::ONE);
        assert!(verify(&IDENTITY, &[b"heika"], &signature));
    }

    #[test]
    fn rejects_a_zero_s() {
        // 単位元の鍵なら、R も単位元にすれば S = 0 の検算は合う
        let signature = signature(&IDENTITY, &Scalar::ZERO);
        assert!(!verify(&IDENTITY, &[b"heika"], &signature));
    }

    #[test]
    fn rejects_an_s_not_less_than_the_group_order() {
        // L + 1 は L で縮めると 1 なので、縮めてから使うと通ってしまう
        let mut signature = signature(ED25519_BASEPOINT_COMPRESSED.as_bytes(), &Scalar::ONE);
        signature[32..].copy_from_slice(&[
            0xEE, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9,
            0xDE, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        assert!(!verify(&IDENTITY, &[b"heika"], &signature));
    }

    #[test]
    fn rejects_the_zero_public_key() {
        // 全部 0 は y = 0 の位数4の点なので、部分群の確認でも弾かれる。catapult に合わせて先に弾いている
        let signature = signature(ED25519_BASEPOINT_COMPRESSED.as_bytes(), &Scalar::ONE);
        assert!(!verify(&[0; 32], &[b"heika"], &signature));
    }

    #[test]
    fn rejects_a_non_canonical_public_key() {
        // y を縮めると単位元になるので、正規形かどうかを見ないと通ってしまう
        let signature = signature(ED25519_BASEPOINT_COMPRESSED.as_bytes(), &Scalar::ONE);
        assert!(!verify(&NON_CANONICAL_IDENTITY, &[b"heika"], &signature));
    }

    #[test]
    fn rejects_a_public_key_outside_the_main_subgroup() {
        // (0, -1) は位数2の点で、曲線上にはあるが素数位数の部分群には入っていない
        let mut order_two = [0xFF; 32];
        order_two[0] = 0xEC;
        order_two[31] = 0x7F;
        assert!(CompressedEdwardsY(order_two).decompress().is_some());
        assert_eq!(decode(&order_two), None);
    }

    #[test]
    fn accepts_the_identity_r_only_in_canonical_form() {
        let seed = [7; 32];
        let (public_key, canonical) = forge_with_identity_r(&seed, &IDENTITY);
        assert!(verify(&public_key, &[b"heika"], &canonical));
        // x = 0 なのに符号のビットが立っている単位元
        let (public_key, negative_zero) = forge_with_identity_r(&seed, &point_with_y(1, 0x80));
        assert!(!verify(&public_key, &[b"heika"], &negative_zero));
        let (public_key, non_canonical) = forge_with_identity_r(&seed, &NON_CANONICAL_IDENTITY);
        assert!(!verify(&public_key, &[b"heika"], &non_canonical));
    }

    #[test]
    fn accepts_a_public_key_with_a_negative_zero_x() {
        // 単位元に符号のビットを立てたもの。catapult の donna も curve25519-dalek も単位元として読む
        let negative_zero = point_with_y(1, 0x80);
        assert_eq!(decode(&negative_zero), Some(EdwardsPoint::default()));
    }

    #[test]
    fn checks_the_canonical_boundary() {
        // 2^255 - 20 は正規形、2^255 - 19 からは正規形ではない
        let mut p_minus_one = [0xFF; 32];
        p_minus_one[0] = 0xEC;
        p_minus_one[31] = 0x7F;
        assert!(is_canonical(&p_minus_one));
        let mut p = p_minus_one;
        p[0] = 0xED;
        assert!(!is_canonical(&p));
        // 符号のビットは数えない
        p_minus_one[31] = 0xFF;
        assert!(is_canonical(&p_minus_one));
    }
}
