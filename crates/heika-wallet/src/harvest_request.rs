//! 委任ハーベストの要求。catapult の `extensions/harvesting/src/HarvestRequest.cpp` と、
//! transfer プラグインの `TransferMessageObserver`。
//!
//! ハーベストに使うリモートアカウントと VRF の秘密鍵を、ノードの公開鍵あてに暗号化して、
//! Transfer のメッセージに入れる。ノードは、自分の公開鍵のアドレスあての Transfer のうち、
//! メッセージが目印で始まるものを読み、自分の秘密鍵で復号してハーベストを始める。
//! 合意形成には関わらず、チェーンから見ればただのメッセージ。

use std::fmt;

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::cipher::{self, DecryptError, InvalidPublicKey};

/// メッセージの先頭の目印。catapult では u64 の `0xE201735761802AFE` をリトルエンディアンで書いたもの。
pub const MARKER: [u8; 8] = [0xFE, 0x2A, 0x80, 0x61, 0x57, 0x73, 0x01, 0xE2];

/// メッセージの長さ。目印、使い捨ての公開鍵、認証タグ、初期化ベクトル、秘密鍵2つの暗号文。
pub const MESSAGE_SIZE: usize = MARKER.len() + 32 + cipher::TAG_SIZE + cipher::IV_SIZE + 2 * 32;

/// ノードに預ける2つの秘密鍵。
pub struct HarvesterKeys {
    /// ブロックに署名するリモートアカウントの秘密鍵。AccountKeyLink で紐づけた公開鍵に対応する
    pub signing: PrivateKey,
    /// VRF の秘密鍵。VrfKeyLink で紐づけた公開鍵に対応する
    pub vrf: PrivateKey,
}

impl fmt::Debug for HarvesterKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HarvesterKeys(..)")
    }
}

/// 要求を送るアドレス。ノードの公開鍵（`node.key.pem` の鍵）のアドレスで、catapult の `TransferPlugin` が見張る。
pub fn recipient_address(node_public_key: &PublicKey, network: NetworkIdentifier) -> Address {
    Address::from_public_key(node_public_key, network)
}

/// 要求のメッセージを作る。使い捨ての鍵と初期化ベクトルは、渡された乱数で作る。
pub fn encode<R: CryptoRng + ?Sized>(
    rng: &mut R,
    node_public_key: &PublicKey,
    keys: &HarvesterKeys,
) -> Result<Vec<u8>, InvalidPublicKey> {
    let mut plaintext = Zeroizing::new([0; 64]);
    plaintext[..32].copy_from_slice(keys.signing.as_bytes());
    plaintext[32..].copy_from_slice(keys.vrf.as_bytes());
    let sealed = cipher::seal(rng, node_public_key, &*plaintext)?;
    let mut message = MARKER.to_vec();
    message.extend_from_slice(&sealed);
    Ok(message)
}

/// メッセージが要求の形をしているか。目印で始まり、長さが合っているかだけを見る。復号はしない。
pub fn is_harvest_request(message: &[u8]) -> bool {
    message.len() == MESSAGE_SIZE && message.starts_with(&MARKER)
}

/// ノードの秘密鍵で要求を復号する。ノードがすることと同じ。
pub fn decode(node_private_key: &PrivateKey, message: &[u8]) -> Result<HarvesterKeys, DecodeError> {
    if !is_harvest_request(message) {
        return Err(DecodeError::NotHarvestRequest);
    }
    let plaintext =
        cipher::open(node_private_key, &message[MARKER.len()..]).map_err(DecodeError::Decrypt)?;
    let (signing, vrf) = plaintext.split_at(32);
    Ok(HarvesterKeys {
        signing: PrivateKey::from_bytes(signing.try_into().expect("64 bytes are encrypted")),
        vrf: PrivateKey::from_bytes(vrf.try_into().expect("64 bytes are encrypted")),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 目印で始まっていないか、長さが合わない
    NotHarvestRequest,
    /// 復号できない
    Decrypt(DecryptError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotHarvestRequest => {
                f.write_str("委任ハーベストの要求のメッセージではありません")
            }
            Self::Decrypt(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Replay;

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1 から 3 の秘密鍵
    const NODE: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    const SIGNING: &str = "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB";
    const VRF: &str = "C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7";

    fn keys() -> HarvesterKeys {
        HarvesterKeys {
            signing: SIGNING.parse().unwrap(),
            vrf: VRF.parse().unwrap(),
        }
    }

    fn node() -> (PrivateKey, PublicKey) {
        let private_key: PrivateKey = NODE.parse().unwrap();
        let public_key = PublicKey::from_private_key(&private_key);
        (private_key, public_key)
    }

    fn message() -> Vec<u8> {
        let randomness = [0x11; 32 + cipher::IV_SIZE];
        encode(&mut Replay(&randomness), &node().1, &keys()).unwrap()
    }

    #[test]
    fn writes_the_marker_and_the_sealed_keys() {
        let message = message();
        assert_eq!(message.len(), 132);
        assert_eq!(message[..8], MARKER);
        let ephemeral: PrivateKey = "11".repeat(32).parse().unwrap();
        assert_eq!(message[8..40], PublicKey::from_private_key(&ephemeral).0);
        assert!(is_harvest_request(&message));
    }

    #[test]
    fn the_node_decodes_the_keys() {
        let decoded = decode(&node().0, &message()).unwrap();
        assert_eq!(decoded.signing.as_bytes(), keys().signing.as_bytes());
        assert_eq!(decoded.vrf.as_bytes(), keys().vrf.as_bytes());
    }

    #[test]
    fn another_key_cannot_decode() {
        let other: PrivateKey = SIGNING.parse().unwrap();
        assert_eq!(
            decode(&other, &message()).unwrap_err(),
            DecodeError::Decrypt(DecryptError::Failed)
        );
    }

    #[test]
    fn rejects_other_messages() {
        let message = message();
        let mut wrong_marker = message.clone();
        wrong_marker[7] = 0;
        for (name, bytes) in [
            ("wrong marker", wrong_marker),
            ("too short", message[..131].to_vec()),
            ("too long", [message.as_slice(), &[0]].concat()),
        ] {
            assert!(!is_harvest_request(&bytes), "{name}");
            assert_eq!(
                decode(&node().0, &bytes).unwrap_err(),
                DecodeError::NotHarvestRequest,
                "{name}"
            );
        }
    }

    #[test]
    fn refuses_a_node_key_that_is_not_a_usable_point() {
        let mut order_two = [0xFF; 32];
        order_two[0] = 0xEC;
        order_two[31] = 0x7F;
        let randomness = [0x11; 32 + cipher::IV_SIZE];
        assert_eq!(
            encode(&mut Replay(&randomness), &PublicKey(order_two), &keys()).unwrap_err(),
            InvalidPublicKey
        );
    }

    #[test]
    fn sends_to_the_address_of_the_node_key() {
        let public_key = node().1;
        assert_eq!(
            recipient_address(&public_key, NetworkIdentifier::MAINNET),
            Address::from_public_key(&public_key, NetworkIdentifier::MAINNET)
        );
    }

    #[test]
    fn debug_hides_the_keys() {
        assert_eq!(format!("{:?}", keys()), "HarvesterKeys(..)");
    }
}
