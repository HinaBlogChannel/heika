//! ファイナライズ。catbuffer の `finalization/`。
//!
//! 投票でファイナライズされたブロックを、ラウンド（エポックとポイント）、高さ、ハッシュで示す。

use std::fmt;

use heika_core::hash::Hash256;

/// ファイナライズの投票のラウンド。catbuffer の `FinalizationRound`。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FinalizationRound {
    pub epoch: u32,
    pub point: u32,
}

/// ファイナライズされたブロック。catbuffer の `FinalizedBlockHeader`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FinalizedBlockHeader {
    pub round: FinalizationRound,
    pub height: u64,
    pub hash: Hash256,
}

impl FinalizedBlockHeader {
    /// ラウンド（エポック、ポイント）、高さ、ハッシュ。
    pub const SIZE: usize = 4 + 4 + 8 + 32;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[..4].copy_from_slice(&self.round.epoch.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.round.point.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.height.to_le_bytes());
        bytes[16..].copy_from_slice(&self.hash.0);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidFinalizedBlockHeaderSize> {
        let bytes: &[u8; Self::SIZE] = bytes
            .try_into()
            .map_err(|_| InvalidFinalizedBlockHeaderSize(bytes.len()))?;
        Ok(Self {
            round: FinalizationRound {
                epoch: u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")),
                point: u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")),
            },
            height: u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")),
            hash: Hash256(bytes[16..].try_into().expect("32 bytes")),
        })
    }
}

/// 長さが [`FinalizedBlockHeader::SIZE`] ではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidFinalizedBlockHeaderSize(pub usize);

impl fmt::Display for InvalidFinalizedBlockHeaderSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ファイナライズされたブロックは {} バイトですが、{} バイトでした",
            FinalizedBlockHeader::SIZE,
            self.0
        )
    }
}

impl std::error::Error for InvalidFinalizedBlockHeaderSize {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_round_height_and_hash_in_order() {
        let header = FinalizedBlockHeader {
            round: FinalizationRound {
                epoch: 0x0102,
                point: 3,
            },
            height: 0x0405,
            hash: Hash256([6; 32]),
        };
        let bytes = header.to_bytes();
        assert_eq!(
            bytes[..16],
            [2, 1, 0, 0, 3, 0, 0, 0, 5, 4, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(FinalizedBlockHeader::from_bytes(&bytes), Ok(header));
        assert_eq!(
            FinalizedBlockHeader::from_bytes(&bytes[..47]),
            Err(InvalidFinalizedBlockHeaderSize(47))
        );
    }
}
