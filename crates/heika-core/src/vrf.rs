//! ブロックを作る権利を示す VRF の証明。catapult の `crypto/Vrf.cpp`。
//!
//! IETF の draft-irtf-cfrg-vrf-05 の ECVRF-EDWARDS25519-SHA512-TAI で、
//! ハーベストする人は、1つ前のブロックの generation hash を VRF の秘密鍵で証明にし、
//! その証明から次の generation hash を求める。Nemesis のブロックは generation hash seed を証明にする。
//!
//! 検証は、catapult が計算を途中でやめずに続けるところも含めて同じにしている。
//! 結果が変わるのはハッシュの衝突を見つけたときだけだが、ノードと違うものを受け付けないようにするため。

use std::fmt;
use std::str::FromStr;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use zeroize::Zeroizing;

use crate::ed25519::{self, ExpandedKey};
use crate::hex::{self, ParseHexError};
use crate::key::{PrivateKey, PublicKey};

/// ECVRF-EDWARDS25519-SHA512-TAI の suite
const SUITE: u8 = 0x03;

/// VRF の証明。catapult の `crypto::VrfProof`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VrfProof {
    pub gamma: [u8; 32],
    pub verification_hash: [u8; 16],
    pub scalar: [u8; 32],
}

/// 証明から求めた64バイトのハッシュ。IETF の draft の beta。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProofHash(pub [u8; 64]);

impl ProofHash {
    /// 前半の32バイトを generation hash にする。catapult の `model::CalculateGenerationHash`。
    pub fn generation_hash(&self) -> GenerationHash {
        GenerationHash(self.0[..32].try_into().expect("half of 64 bytes"))
    }
}

impl fmt::Display for ProofHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for ProofHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProofHash({self})")
    }
}

/// ブロックごとの generation hash。catapult の `GenerationHash`。次のブロックの VRF の証明の元になる。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationHash(pub [u8; 32]);

impl fmt::Display for GenerationHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for GenerationHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenerationHash({self})")
    }
}

impl FromStr for GenerationHash {
    type Err = ParseHexError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        hex::decode(text).map(Self)
    }
}

/// `alpha` の証明を作る。catapult の `crypto::GenerateVrfProof`。
///
/// 作れないのは、`alpha` から点がどうしても作れなかったときと、gamma が単位元になったときだけで、
/// どちらもまず起きない。catapult はそのときに検証の通らない証明を返す。
pub fn prove(private_key: &PrivateKey, alpha: &[u8]) -> Option<VrfProof> {
    let key = ExpandedKey::new(private_key.as_bytes());
    let public_key = key.public_key().to_bytes();
    let h = map_to_point(&public_key, alpha)?;
    // gamma = x * h
    let gamma = scalar_mult(&key.scalar, &h);
    if gamma == EdwardsPoint::default().compress().to_bytes() {
        return None;
    }
    // k = H(秘密鍵を広げた後半 || h)
    let k = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&ed25519::sha512([
        &key.prefix[..],
        &h[..],
    ])));
    let k_times_b = EdwardsPoint::mul_base(&k).compress().to_bytes();
    let k_times_h = scalar_mult(&k, &h);
    let verification_hash = challenge(&h, &gamma, &k_times_b, &k_times_h);
    // s = k + c * x
    let product = Zeroizing::new(widen(&verification_hash) * *key.scalar);
    let scalar = (*product + *k).to_bytes();
    Some(VrfProof {
        gamma,
        verification_hash,
        scalar,
    })
}

/// `alpha` の証明の gamma だけを求める。生成ハッシュは gamma だけで決まるので（[`proof_hash`]）、当たりかどうかを
/// 見るだけなら、証明の残り（c と s）を作らなくてよい。[`prove`] の gamma と同じになる
pub fn gamma(private_key: &PrivateKey, alpha: &[u8]) -> Option<[u8; 32]> {
    let key = ExpandedKey::new(private_key.as_bytes());
    let h = map_to_point(&key.public_key().to_bytes(), alpha)?;
    let gamma = scalar_mult(&key.scalar, &h);
    (gamma != EdwardsPoint::default().compress().to_bytes()).then_some(gamma)
}

/// 証明を検証して、通れば証明のハッシュを返す。catapult の `crypto::VerifyVrfProof`。
pub fn verify(public_key: &PublicKey, alpha: &[u8], proof: &VrfProof) -> Option<ProofHash> {
    // gamma は正規形で、曲線上になければならない。部分群に入っているかはここでは見ない
    if !ed25519::is_canonical(&proof.gamma) || decompress(&proof.gamma).is_none() {
        return None;
    }
    let h = map_to_point(&public_key.0, alpha)?;
    // s は群の位数より小さくなければならない
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.scalar))?;
    let c = widen(&proof.verification_hash);
    // u = s * B - c * Y。catapult は公開鍵を点に戻せなくても止めずに、全部 0 を u にして続ける
    let u = match ed25519::decode(&public_key.0) {
        Some(y) => EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &-y, &s)
            .compress()
            .to_bytes(),
        None => [0; 32],
    };
    // v = s * h - c * gamma。catapult は一度圧縮したものを戻して足すので、それに合わせる。
    // gamma が部分群に入っていなければ、c * gamma は全部 0 を戻したものになる。
    // 確かめるだけで秘密は扱わないので、時間の一定でないかけ算でよい。h は余因子倍してあるので、いつも部分群に入る
    let h_point = decompress(&h).expect("a compressed point");
    let s_times_h = EdwardsPoint::vartime_multiscalar_mul([s], [h_point]);
    let c_times_gamma = match ed25519::decode(&proof.gamma) {
        Some(gamma) => EdwardsPoint::vartime_multiscalar_mul([c], [gamma]),
        None => decompress(&[0; 32]).expect("a compressed point"),
    };
    let v = (s_times_h - c_times_gamma).compress().to_bytes();
    (challenge(&h, &proof.gamma, &u, &v) == proof.verification_hash)
        .then(|| proof_hash(&proof.gamma))
}

/// gamma から証明のハッシュを求める。証明は検証しない。catapult の `crypto::GenerateVrfProofHash`。
pub fn proof_hash(gamma: &[u8; 32]) -> ProofHash {
    let gamma_times_eight = decompress(gamma)
        .map(|point| point.mul_by_cofactor().compress().to_bytes())
        .unwrap_or([0; 32]);
    let hash = ed25519::sha512([&[SUITE, 0x03][..], &gamma_times_eight[..]]);
    ProofHash(*hash)
}

/// 公開鍵と `alpha` から点を作る。catapult の `MapToKey`（try-and-increment）。
/// 256回試して作れなければ諦める。
fn map_to_point(public_key: &[u8; 32], alpha: &[u8]) -> Option<[u8; 32]> {
    (0..=u8::MAX).find_map(|counter| {
        let hash = ed25519::sha512([&[SUITE, 0x01][..], &public_key[..], alpha, &[counter]]);
        let candidate: [u8; 32] = hash[..32].try_into().expect("32 of 64 bytes");
        if !ed25519::is_canonical(&candidate) {
            return None;
        }
        decompress(&candidate).map(|point| point.mul_by_cofactor().compress().to_bytes())
    })
}

/// 証明の c。SHA-512(suite || 0x02 || h || gamma || u || v) の先頭16バイト。
fn challenge(h: &[u8; 32], gamma: &[u8; 32], u: &[u8; 32], v: &[u8; 32]) -> [u8; 16] {
    let hash = ed25519::sha512([&[SUITE, 0x02][..], &h[..], &gamma[..], &u[..], &v[..]]);
    hash[..16].try_into().expect("16 of 64 bytes")
}

/// 16バイトの c を、スカラーとして使えるように広げる。
fn widen(verification_hash: &[u8; 16]) -> Scalar {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(verification_hash);
    Scalar::from_bytes_mod_order(bytes)
}

/// 点を multiplier 倍して圧縮する。catapult の `ScalarMult` と同じく、点は部分群に入っていなければならず、
/// 入っていなければ全部 0 を返す。
fn scalar_mult(multiplier: &Scalar, point: &[u8; 32]) -> [u8; 32] {
    match ed25519::decode(point) {
        Some(point) => (multiplier * point).compress().to_bytes(),
        None => [0; 32],
    }
}

/// 正規形かどうかも部分群に入っているかも見ずに、点に戻す。catapult の `ge25519_unpack_*_vartime`。
fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::EIGHT_TORSION;

    fn bytes<const N: usize>(text: &str) -> [u8; N] {
        hex::decode(text).unwrap()
    }

    fn alpha(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    /// draft-irtf-cfrg-vrf-05 の ECVRF-EDWARDS25519-SHA512-TAI の例（A.4）。
    /// 秘密鍵、alpha、gamma、c、s、beta の順。
    const DRAFT_05: [[&str; 6]; 3] = [
        [
            "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60",
            "",
            "9275DF67A68C8745C0FF97B48201EE6DB447F7C93B23AE24CDC2400F52FDB08A",
            "1A6AC7EC71BF9C9C76E96EE4675EBFF6",
            "0625AF28718501047BFD87B810C2D2139B73C23BD69DE66360953A642C2A330A",
            "A64C292EC45F6B252828AFF9A02A0FE88D2FCC7F5FC61BB328F03F4C6C0657A9\
             D26EFB23B87647FF54F71CD51A6FA4C4E31661D8F72B41FF00AC4D2EEC2EA7B3",
        ],
        [
            "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB",
            "72",
            "84A63E74ECA8FDD64E9972DCDA1C6F33D03CE3CD4D333FD6CC789DB12B5A7B9D",
            "03F1CB6B2BF7CD81A2A20BACF6E1C04E",
            "59F2FA16D9119C73A45A97194B504FB9A5C8CF37F6DA85E03368D6882E511008",
            "CDDAA399BB9C56D3BE15792E43A6742FB72B1D248A7F24FD5CC585B232C26C93\
             4711393B4D97284B2BCCA588775B72DC0B0F4B5A195BC41F8D2B80B6981C784E",
        ],
        [
            "C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7",
            "AF82",
            "ACA8ADE9B7F03E2B149637629F95654C94FC9053C225EC21E5838F193AF2B727",
            "B84AD849B0039AD38B41513FE5A66CDD",
            "2367737A84B488D62486BD2FB110B4801A46BFCA770AF98E059158AC563B690F",
            "D938B2012F2551B0E13A49568612EFFCBDCA2AED5D1D3A13F47E180E01218916\
             E049837BD246F66D5058E56D3413DBBBAD964F5E9F160A81C9A1355DCD99B453",
        ],
    ];

    /// 正しい証明を1つ作って、検証が通ることを確かめてから返す。
    fn valid() -> (PublicKey, Vec<u8>, VrfProof) {
        let private_key = PrivateKey::from_bytes(&[7; 32]);
        let public_key = PublicKey::from_private_key(&private_key);
        let alpha = b"heika".to_vec();
        let proof = prove(&private_key, &alpha).unwrap();
        assert!(verify(&public_key, &alpha, &proof).is_some());
        (public_key, alpha, proof)
    }

    #[test]
    fn proves_and_verifies_like_draft_05() {
        for [secret, input, gamma, c, s, beta] in DRAFT_05 {
            let private_key = PrivateKey::from_bytes(&bytes(secret));
            let public_key = PublicKey::from_private_key(&private_key);
            let input = alpha(input);
            let proof = prove(&private_key, &input).unwrap();
            assert_eq!(
                proof,
                VrfProof {
                    gamma: bytes(gamma),
                    verification_hash: bytes(c),
                    scalar: bytes(s),
                },
                "{secret}"
            );
            let beta = ProofHash(bytes(beta));
            assert_eq!(verify(&public_key, &input, &proof), Some(beta), "{secret}");
            assert_eq!(proof_hash(&proof.gamma), beta, "{secret}");
        }
    }

    #[test]
    fn generation_hash_is_the_first_half() {
        let hash = ProofHash(std::array::from_fn(|index| index as u8));
        assert_eq!(
            hash.generation_hash(),
            GenerationHash(std::array::from_fn(|index| index as u8))
        );
    }

    #[test]
    fn rejects_another_key_or_alpha() {
        let (_, alpha, proof) = valid();
        let other = PublicKey::from_private_key(&PrivateKey::from_bytes(&[8; 32]));
        assert_eq!(verify(&other, &alpha, &proof), None);
        let (public_key, _, proof) = valid();
        assert_eq!(verify(&public_key, b"heika!", &proof), None);
    }

    #[test]
    fn rejects_a_changed_verification_hash_or_scalar() {
        let (public_key, alpha, mut proof) = valid();
        proof.verification_hash[0] ^= 1;
        assert_eq!(verify(&public_key, &alpha, &proof), None);
        let (public_key, alpha, mut proof) = valid();
        proof.scalar[0] ^= 1;
        assert_eq!(verify(&public_key, &alpha, &proof), None);
    }

    #[test]
    fn rejects_a_scalar_not_less_than_the_group_order() {
        // s + L は L で縮めると s なので、縮めてから使うと通ってしまう
        let (public_key, alpha, mut proof) = valid();
        let order: [u8; 32] = [
            0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9,
            0xDE, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0;
        for (byte, add) in proof.scalar.iter_mut().zip(order) {
            let sum = u16::from(*byte) + u16::from(add) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(verify(&public_key, &alpha, &proof), None);
    }

    #[test]
    fn rejects_a_gamma_off_the_curve() {
        let (public_key, alpha, mut proof) = valid();
        proof.gamma = (0..=u8::MAX)
            .map(|low| {
                let mut gamma = [0; 32];
                gamma[0] = low;
                gamma
            })
            .find(|gamma| decompress(gamma).is_none())
            .unwrap();
        assert_eq!(verify(&public_key, &alpha, &proof), None);
    }

    #[test]
    fn rejects_a_gamma_outside_the_main_subgroup() {
        // 位数2の点を足すと、曲線上にはあるが素数位数の部分群からは外れる
        let (public_key, alpha, mut proof) = valid();
        let gamma = decompress(&proof.gamma).unwrap() + EIGHT_TORSION[4];
        proof.gamma = gamma.compress().to_bytes();
        assert!(ed25519::decode(&proof.gamma).is_none());
        assert_eq!(verify(&public_key, &alpha, &proof), None);
    }

    #[test]
    fn gamma_is_the_gamma_of_the_proof() {
        let key = PrivateKey::from_bytes(&[7; 32]);
        for alpha in [&b""[..], &[1; 32], &[0xFF; 64]] {
            assert_eq!(
                gamma(&key, alpha),
                prove(&key, alpha).map(|proof| proof.gamma)
            );
        }
    }

    #[test]
    fn proof_hash_ignores_the_small_order_part_of_gamma() {
        // 8 倍してから求めるので、gamma に位数8までの点を足しても変わらない
        let (_, _, proof) = valid();
        let shifted = (decompress(&proof.gamma).unwrap() + EIGHT_TORSION[1])
            .compress()
            .to_bytes();
        assert_eq!(proof_hash(&shifted), proof_hash(&proof.gamma));
    }

    #[test]
    fn round_trips_a_generation_hash_through_hex() {
        let hash = GenerationHash([0xAB; 32]);
        assert_eq!(hash.to_string().parse(), Ok(hash));
    }
}
