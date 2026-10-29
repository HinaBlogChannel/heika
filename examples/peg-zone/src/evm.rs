//! EVM の側の署名を、コントラクト（contracts/src/FrostSecp256k1.sol）に渡す形にする。

use frost_secp256k1 as frost;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};

/// secp256k1 の位数（ビッグエンディアン）
const ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// コントラクトに登録する公開鍵。x 座標と、y の偶奇
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmKey {
    pub x: [u8; 32],
    pub parity: u8,
}

impl EvmKey {
    /// x 座標が位数以上の鍵は、コントラクトで確かめられない（ecrecover が受け付けない）ので `None`。
    /// 2¹²⁸ 回に 1 回ほどしか起きないが、起きたら鍵を作り直す
    pub fn new(key: &frost::VerifyingKey) -> Option<Self> {
        let bytes = key.serialize().ok()?;
        let (&prefix, x) = bytes.split_first()?;
        let x: [u8; 32] = x.try_into().ok()?;
        (x < ORDER).then_some(Self {
            x,
            parity: prefix - 2,
        })
    }
}

/// コントラクトに渡す署名。R は y 座標まで展開する
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmSignature {
    pub rx: [u8; 32],
    pub ry: [u8; 32],
    pub z: [u8; 32],
}

impl EvmSignature {
    pub fn new(signature: &frost::Signature) -> Option<Self> {
        // R（圧縮した 33 バイト）と z（32 バイト）
        let bytes = signature.serialize().ok()?;
        let (r, z) = bytes.split_at(33);
        let point = EncodedPoint::from_bytes(r).ok()?;
        let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&point))?;
        let point = point.to_encoded_point(false);
        Some(Self {
            rx: (*point.x()?).into(),
            ry: (*point.y()?).into(),
            z: z.try_into().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    use std::collections::BTreeMap;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// 決まった乱数で 2-of-3 の署名を作る。contracts/test/FrostSecp256k1.t.sol の定数と同じになること
    #[test]
    fn fixed_signature_matches_solidity_test() {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        let keys: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .take(2)
            .collect();
        let message = [0x42; 32];
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, key) in &keys {
            let (nonce, commitment) = frost::round1::commit(key.signing_share(), &mut rng);
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let package = frost::SigningPackage::new(commitments, &message);
        let shares: BTreeMap<_, _> = keys
            .iter()
            .map(|(id, key)| {
                (
                    *id,
                    frost::round2::sign(&package, &nonces[id], key).unwrap(),
                )
            })
            .collect();
        let signature = frost::aggregate(&package, &shares, &public).unwrap();
        public.verifying_key().verify(&message, &signature).unwrap();

        let key = EvmKey::new(public.verifying_key()).unwrap();
        let signature = EvmSignature::new(&signature).unwrap();
        let solidity = include_str!("../contracts/test/FrostSecp256k1.t.sol");
        for (name, value) in [
            ("PX", hex(&key.x)),
            ("PARITY", key.parity.to_string()),
            ("RX", hex(&signature.rx)),
            ("RY", hex(&signature.ry)),
            ("Z", hex(&signature.z)),
        ] {
            let value = if name == "PARITY" {
                value
            } else {
                format!("0x{value}")
            };
            assert!(
                solidity.contains(&format!(" {name} = {value};")),
                "{name} = {value}"
            );
        }
    }
}
