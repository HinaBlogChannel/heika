//! ロック。catbuffer の `lock_hash/` と `lock_secret/`。

use heika_core::address::Address;
use heika_core::hash::Hash256;
use sha3::{Digest, Sha3_256};

use crate::bounded::BoundedVec;
use crate::mosaic::UnresolvedMosaic;
use crate::transfer::UnresolvedAddress;
use crate::{DecodeError, Reader};

/// アグリゲートボンデッドを送る前に、手数料の担保としてモザイクを預ける。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HashLock {
    pub mosaic: UnresolvedMosaic,
    /// 預ける期間（ブロック）
    pub duration: u64,
    /// アグリゲートボンデッドのハッシュ
    pub hash: Hash256,
}

impl HashLock {
    const SIZE: usize = UnresolvedMosaic::SIZE + 8 + 32;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.mosaic.encode(out);
        out.extend_from_slice(&self.duration.to_le_bytes());
        out.extend_from_slice(&self.hash.0);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            mosaic: UnresolvedMosaic::read(&mut reader),
            duration: reader.u64(),
            hash: Hash256(reader.array()),
        })
    }
}

/// シークレットロックとプルーフで、プルーフからシークレットを求めるハッシュ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockHashAlgorithm {
    Sha3_256,
    /// RIPEMD-160(SHA-256)
    Hash160,
    /// SHA-256(SHA-256)
    Hash256,
}

impl LockHashAlgorithm {
    fn to_byte(self) -> u8 {
        match self {
            Self::Sha3_256 => 0,
            Self::Hash160 => 1,
            Self::Hash256 => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, DecodeError> {
        match byte {
            0 => Ok(Self::Sha3_256),
            1 => Ok(Self::Hash160),
            2 => Ok(Self::Hash256),
            _ => Err(DecodeError::InvalidValue {
                field: "ハッシュの種類",
                value: byte.into(),
            }),
        }
    }
}

/// プルーフを示したら受取人に渡るように、モザイクをロックする。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecretLock {
    pub recipient_address: UnresolvedAddress,
    pub secret: Hash256,
    pub mosaic: UnresolvedMosaic,
    /// ロックする期間（ブロック）
    pub duration: u64,
    pub hash_algorithm: LockHashAlgorithm,
}

impl SecretLock {
    const SIZE: usize = 24 + 32 + UnresolvedMosaic::SIZE + 8 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.recipient_address.0);
        out.extend_from_slice(&self.secret.0);
        self.mosaic.encode(out);
        out.extend_from_slice(&self.duration.to_le_bytes());
        out.push(self.hash_algorithm.to_byte());
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            recipient_address: UnresolvedAddress(reader.array()),
            secret: Hash256(reader.array()),
            mosaic: UnresolvedMosaic::read(&mut reader),
            duration: reader.u64(),
            hash_algorithm: LockHashAlgorithm::from_byte(reader.u8())?,
        })
    }
}

/// プルーフを示して、シークレットロックしたモザイクを受取人に渡す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretProof {
    pub recipient_address: UnresolvedAddress,
    pub secret: Hash256,
    pub hash_algorithm: LockHashAlgorithm,
    pub proof: BoundedVec<u8, { u16::MAX as usize }>,
}

impl SecretProof {
    /// プルーフより前の部分。受取人、シークレット、プルーフの長さ、ハッシュの種類。
    const FIXED_SIZE: usize = 24 + 32 + 2 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.recipient_address.0);
        out.extend_from_slice(&self.secret.0);
        out.extend_from_slice(&(self.proof.len() as u16).to_le_bytes());
        out.push(self.hash_algorithm.to_byte());
        out.extend_from_slice(&self.proof);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::at_least(bytes, Self::FIXED_SIZE)?;
        let recipient_address = UnresolvedAddress(reader.array());
        let secret = Hash256(reader.array());
        let proof_size = reader.u16() as usize;
        let hash_algorithm = LockHashAlgorithm::from_byte(reader.u8())?;
        Ok(Self {
            recipient_address,
            secret,
            hash_algorithm,
            proof: reader
                .rest(proof_size)?
                .to_vec()
                .try_into()
                .expect("u16 length"),
        })
    }
}

/// チェーンに記録されたシークレットロックの1件を指すハッシュ。catapult の `CalculateSecretLockInfoHash` で、
/// シークレットと受取人のアドレスを続けた SHA3-256。受取人は、ネームスペースを解決したあとのアドレス。
pub fn secret_lock_key(secret: &Hash256, recipient: &Address) -> Hash256 {
    Hash256(
        Sha3_256::new()
            .chain_update(secret.0)
            .chain_update(recipient.0)
            .finalize()
            .into(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use crate::testing::{decode, round_trip};
    use crate::transfer::UnresolvedMosaicId;

    fn mosaic() -> UnresolvedMosaic {
        UnresolvedMosaic {
            mosaic_id: UnresolvedMosaicId(0x0102),
            amount: 10,
        }
    }

    #[test]
    fn hashes_the_secret_and_the_recipient() {
        let mut data = vec![0x11; 32];
        data.extend_from_slice(&[0x98; 24]);
        assert_eq!(
            secret_lock_key(&Hash256([0x11; 32]), &Address([0x98; 24])),
            Hash256(Sha3_256::digest(&data).into())
        );
    }

    #[test]
    fn writes_a_hash_lock_in_the_catbuffer_layout() {
        let body = round_trip(Body::HashLock(HashLock {
            mosaic: mosaic(),
            duration: 480,
            hash: Hash256([0xAB; 32]),
        }));
        assert_eq!(body[..8], 0x0102_u64.to_le_bytes());
        assert_eq!(body[8..16], 10_u64.to_le_bytes());
        assert_eq!(body[16..24], 480_u64.to_le_bytes());
        assert_eq!(body[24..], [0xAB; 32]);
    }

    #[test]
    fn rejects_an_undefined_hash_algorithm() {
        let lock = SecretLock {
            recipient_address: UnresolvedAddress([0x98; 24]),
            secret: Hash256([1; 32]),
            mosaic: mosaic(),
            duration: 1,
            hash_algorithm: LockHashAlgorithm::Hash256,
        };
        let mut body = round_trip(Body::SecretLock(lock));
        assert_eq!(body[body.len() - 1], 2);
        *body.last_mut().unwrap() = 3;
        assert_eq!(
            decode(0x4152, &body),
            Err(DecodeError::InvalidValue {
                field: "ハッシュの種類",
                value: 3
            })
        );
    }

    #[test]
    fn reads_a_proof_of_the_stated_size() {
        let proof = SecretProof {
            recipient_address: UnresolvedAddress([0x98; 24]),
            secret: Hash256([1; 32]),
            hash_algorithm: LockHashAlgorithm::Hash160,
            proof: vec![0xEE; 20].try_into().unwrap(),
        };
        let body = round_trip(Body::SecretProof(proof));
        assert_eq!(body[56..59], [20, 0, 1]);
        assert_eq!(body[59..], [0xEE; 20]);
        for broken in [&body[..body.len() - 1], &[body.as_slice(), &[0]].concat()] {
            assert_eq!(decode(0x4252, broken), Err(DecodeError::InvalidBodySize));
        }
    }
}
