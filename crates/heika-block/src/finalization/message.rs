//! 投票のメッセージ。catapult の `model::FinalizationMessage`。
//!
//! ```text
//!   0  u32 Size  u32 Reserved（0）
//!   8  BmTreeSignature: [32] 根の公開鍵 [64] 根の署名 [32] 下の公開鍵 [64] 下の署名
//! 200  u32 Version（1）  u32 HashesCount  u32 Epoch  u32 PointStage（ポイント << 1 | precommit なら 1）
//! 216  u64 Height  [32] × HashesCount  高さ Height から続くブロックのハッシュ
//! ```
//!
//! 署名するのは 200 バイト目から後ろ。根の鍵は（下の公開鍵、u64 のエポック）に、下の鍵はメッセージに署名する。
//! メッセージのハッシュ（重複を見分けるもの）は、全体の SHA3-256。

use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::signature::Signature;
use sha3::{Digest, Sha3_256};

use super::FinalizationRound;
use super::proof::ProofError;

/// `BmTreeSignature`。（根の公開鍵、根の署名）、（下の公開鍵、下の署名）
pub(super) const SIGNATURE_SIZE: usize = 2 * (32 + 64);
/// 署名しない見出し。大きさ、予約、署名
pub(super) const MESSAGE_HEADER_SIZE: usize = 4 + 4 + SIGNATURE_SIZE;
/// 署名するところの、ハッシュより前。版、ハッシュの数、エポック、ポイントと段階、高さ
const SIGNED_HEADER_SIZE: usize = 4 + 4 + 4 + 4 + 8;

/// 投票のメッセージ1つ。ノードどうしが確定の前に配り合うもので、証明はこれを段階と高さとハッシュごとにまとめたもの
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationMessage {
    pub round: FinalizationRound,
    pub is_prevote: bool,
    /// 最初のハッシュのブロックの高さ
    pub height: u64,
    /// 高さ `height` から続くブロックのハッシュ
    pub hashes: Vec<Hash256>,
    pub(super) signature: [u8; SIGNATURE_SIZE],
}

impl FinalizationMessage {
    /// バイト列から読む。署名は確かめない（[`FinalizationMessage::verify_signature`]）。
    /// 予約が 0 でないものと、版が 1 でないものは、catapult も受け付けないので読まない
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let malformed = |what: &str| ProofError::Malformed(what.to_owned());
        if bytes.len() < MESSAGE_HEADER_SIZE + SIGNED_HEADER_SIZE {
            return Err(malformed("メッセージの長さ"));
        }
        let size = u32_at(bytes, 0) as usize;
        let version = u32_at(bytes, MESSAGE_HEADER_SIZE);
        let hashes_count = u32_at(bytes, MESSAGE_HEADER_SIZE + 4) as usize;
        if size != bytes.len()
            || size != MESSAGE_HEADER_SIZE + SIGNED_HEADER_SIZE + hashes_count * 32
        {
            return Err(malformed("メッセージの大きさ"));
        }
        if u32_at(bytes, 4) != 0 {
            return Err(malformed("メッセージの予約"));
        }
        if version != 1 {
            return Err(malformed("メッセージの版"));
        }
        let point_stage = u32_at(bytes, MESSAGE_HEADER_SIZE + 12);
        let hashes_at = MESSAGE_HEADER_SIZE + SIGNED_HEADER_SIZE;
        Ok(Self {
            round: FinalizationRound {
                epoch: u32_at(bytes, MESSAGE_HEADER_SIZE + 8),
                point: point_stage >> 1,
            },
            is_prevote: point_stage & 1 == 0,
            height: u64::from_le_bytes(
                bytes[MESSAGE_HEADER_SIZE + 16..hashes_at]
                    .try_into()
                    .expect("8 bytes"),
            ),
            hashes: bytes[hashes_at..]
                .as_chunks::<32>()
                .0
                .iter()
                .map(|hash| Hash256(*hash))
                .collect(),
            signature: bytes[8..MESSAGE_HEADER_SIZE].try_into().expect("signature"),
        })
    }

    /// catapult と同じバイト列
    pub fn to_bytes(&self) -> Vec<u8> {
        let signed = self.signed_part();
        let mut out = Vec::with_capacity(MESSAGE_HEADER_SIZE + signed.len());
        out.extend_from_slice(&((MESSAGE_HEADER_SIZE + signed.len()) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&signed);
        out
    }

    /// バイト列の長さ
    pub fn size(&self) -> usize {
        MESSAGE_HEADER_SIZE + SIGNED_HEADER_SIZE + self.hashes.len() * 32
    }

    /// 投票の鍵（BM ツリーの根の公開鍵）。[`super::proof::VotingSet`] の鍵と同じもの
    pub fn root_key(&self) -> [u8; 32] {
        self.signature[..32].try_into().expect("32 bytes")
    }

    /// 最後のハッシュのブロックの高さ
    pub fn last_height(&self) -> u64 {
        self.height + (self.hashes.len() as u64).saturating_sub(1)
    }

    /// catapult の `CalculateMessageHash`。バイト列全体の SHA3-256
    pub fn hash(&self) -> [u8; 32] {
        Sha3_256::digest(self.to_bytes()).into()
    }

    /// catapult の `utils::ToShortHash`。ハッシュの先頭4バイトを u32 として読んだもの
    pub fn short_hash(&self) -> u32 {
        u32::from_le_bytes(self.hash()[..4].try_into().expect("4 bytes"))
    }

    /// 根の鍵がこのエポックの下の鍵に、下の鍵がメッセージに署名しているか
    pub fn verify_signature(&self) -> bool {
        let root_key = PublicKey(self.root_key());
        let root_signature = Signature(self.signature[32..96].try_into().expect("64 bytes"));
        let bottom_key: [u8; 32] = self.signature[96..128].try_into().expect("32 bytes");
        let bottom_signature = Signature(self.signature[128..].try_into().expect("64 bytes"));
        let epoch = u64::from(self.round.epoch).to_le_bytes();
        root_key.verify(&[&bottom_key, &epoch], &root_signature)
            && PublicKey(bottom_key).verify(&[&self.signed_part()], &bottom_signature)
    }

    /// 署名するところ。版、ハッシュの数、エポック、ポイントと段階、高さ、ハッシュ
    pub(super) fn signed_part(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNED_HEADER_SIZE + self.hashes.len() * 32);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(self.hashes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.round.epoch.to_le_bytes());
        let point_stage = (self.round.point << 1) | u32::from(!self.is_prevote);
        out.extend_from_slice(&point_stage.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        for hash in &self.hashes {
            out.extend_from_slice(&hash.0);
        }
        out
    }
}

pub(super) fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes"))
}

/// テストで使う、投票者と、署名したメッセージ
#[cfg(test)]
pub(super) mod testing {
    use heika_core::key::PrivateKey;

    use super::*;

    /// 根の鍵と、エポックごとの下の鍵
    pub struct Voter {
        root: PrivateKey,
        bottom: PrivateKey,
    }

    impl Voter {
        pub fn new(seed: u8) -> Self {
            Self {
                root: PrivateKey::from_bytes(&[seed; 32]),
                bottom: PrivateKey::from_bytes(&[seed ^ 0x80; 32]),
            }
        }

        pub fn key(&self) -> [u8; 32] {
            PublicKey::from_private_key(&self.root).0
        }

        /// 署名するところ `signed` への `BmTreeSignature`
        pub fn sign(&self, round: FinalizationRound, signed: &[u8]) -> [u8; SIGNATURE_SIZE] {
            let bottom = PublicKey::from_private_key(&self.bottom).0;
            let epoch = u64::from(round.epoch).to_le_bytes();
            let mut out = [0; SIGNATURE_SIZE];
            out[..32].copy_from_slice(&self.key());
            out[32..96].copy_from_slice(&self.root.sign(&[&bottom, &epoch]).0);
            out[96..128].copy_from_slice(&bottom);
            out[128..].copy_from_slice(&self.bottom.sign(&[signed]).0);
            out
        }

        /// 署名したメッセージ
        pub fn message(
            &self,
            round: FinalizationRound,
            is_prevote: bool,
            height: u64,
            hashes: Vec<Hash256>,
        ) -> FinalizationMessage {
            let mut message = FinalizationMessage {
                round,
                is_prevote,
                height,
                hashes,
                signature: [0; SIGNATURE_SIZE],
            };
            message.signature = self.sign(round, &message.signed_part());
            message
        }
    }

    /// 高さ `height` のブロックのハッシュ。`fork` で別の枝にする
    pub fn block_hash(height: u64, fork: u8) -> Hash256 {
        let mut hash = [fork; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Hash256(hash)
    }

    /// 高さ `from` から `through` までの、枝 0 のハッシュ
    pub fn chain(from: u64, through: u64) -> Vec<Hash256> {
        (from..=through).map(|at| block_hash(at, 0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    const ROUND: FinalizationRound = FinalizationRound { epoch: 3, point: 2 };

    #[test]
    fn reads_writes_and_verifies_a_message() {
        let voter = Voter::new(1);
        let message = voter.message(ROUND, false, 10, chain(10, 12));
        let bytes = message.to_bytes();
        assert_eq!(bytes.len(), message.size());
        let read = FinalizationMessage::from_bytes(&bytes).unwrap();
        assert_eq!(read, message);
        assert_eq!(read.round, ROUND);
        assert!(!read.is_prevote);
        assert_eq!((read.height, read.last_height()), (10, 12));
        assert_eq!(read.root_key(), voter.key());
        assert!(read.verify_signature());
        assert_eq!(read.hash(), <[u8; 32]>::from(Sha3_256::digest(&bytes)));
        assert_eq!(
            read.short_hash(),
            u32::from_le_bytes(read.hash()[..4].try_into().unwrap())
        );

        // 署名したところを変えると通らない
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            !FinalizationMessage::from_bytes(&changed)
                .unwrap()
                .verify_signature()
        );
        // 別のエポックの下の鍵としては通らない
        let mut moved = message.clone();
        moved.round.epoch += 1;
        assert!(!moved.verify_signature());
    }

    #[test]
    fn refuses_bad_sizes_padding_and_versions() {
        let bytes = Voter::new(1)
            .message(ROUND, true, 10, chain(10, 12))
            .to_bytes();
        assert!(FinalizationMessage::from_bytes(&bytes[..bytes.len() - 32]).is_err());
        assert!(FinalizationMessage::from_bytes(&bytes[..100]).is_err());
        let mut padded = bytes.clone();
        padded[4] = 1;
        assert!(FinalizationMessage::from_bytes(&padded).is_err());
        let mut versioned = bytes.clone();
        versioned[MESSAGE_HEADER_SIZE] = 2;
        assert!(FinalizationMessage::from_bytes(&versioned).is_err());
    }
}
