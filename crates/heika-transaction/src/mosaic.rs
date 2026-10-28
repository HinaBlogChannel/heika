//! モザイク。catbuffer の `mosaic/` と、`types.cats` のモザイクの型。

use alloc::vec::Vec;

use heika_core::address::Address;
use sha3::{Digest, Sha3_256};

use crate::transfer::{UnresolvedAddress, UnresolvedMosaicId};
use crate::{DecodeError, Reader};

/// モザイクの ID。作った人のアドレスとノンスから決まる。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MosaicId(pub u64);

impl MosaicId {
    /// 作った人のアドレスとノンスから ID を求める。catapult の `GenerateMosaicId` と同じく、
    /// ノンスとアドレスを続けた SHA3-256 の先頭8バイトを、ネームスペースと見分ける最上位ビットを落として使う。
    pub fn generate(owner: &Address, nonce: u32) -> Self {
        let hash = Sha3_256::new()
            .chain_update(nonce.to_le_bytes())
            .chain_update(owner.0)
            .finalize();
        let id = u64::from_le_bytes(hash[..8].try_into().expect("8 bytes"));
        Self(id & !(1 << 63))
    }
}

/// まだ解決していないモザイクの ID と量。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UnresolvedMosaic {
    pub mosaic_id: UnresolvedMosaicId,
    pub amount: u64,
}

impl UnresolvedMosaic {
    pub(crate) const SIZE: usize = 8 + 8;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mosaic_id.0.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
    }

    pub(crate) fn read(reader: &mut Reader) -> Self {
        Self {
            mosaic_id: UnresolvedMosaicId(reader.u64()),
            amount: reader.u64(),
        }
    }
}

/// モザイクの性質。catbuffer の `MosaicFlags`。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct MosaicFlags(u8);

impl MosaicFlags {
    /// 発行量を変えられる
    pub const SUPPLY_MUTABLE: Self = Self(0x01);
    /// 作った人以外のあいだでも送れる
    pub const TRANSFERABLE: Self = Self(0x02);
    /// モザイクの制限をかけられる
    pub const RESTRICTABLE: Self = Self(0x04);
    /// 作った人が回収できる
    pub const REVOKABLE: Self = Self(0x08);
    const ALL: u8 = 0x0F;

    /// catapult の `MosaicFlagsValidator` と同じく、定義されていないビットが立っていれば `None`。
    pub fn from_bits(bits: u8) -> Option<Self> {
        (bits & !Self::ALL == 0).then_some(Self(bits))
    }

    pub fn bits(self) -> u8 {
        self.0
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for MosaicFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// モザイクを作る。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MosaicDefinition {
    pub id: MosaicId,
    /// 有効な期間（ブロック）。0なら期限がない
    pub duration: u64,
    pub nonce: u32,
    pub flags: MosaicFlags,
    /// 小数点以下の桁数
    pub divisibility: u8,
}

impl MosaicDefinition {
    const SIZE: usize = 8 + 8 + 4 + 1 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.0.to_le_bytes());
        out.extend_from_slice(&self.duration.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.push(self.flags.0);
        out.push(self.divisibility);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        let id = MosaicId(reader.u64());
        let duration = reader.u64();
        let nonce = reader.u32();
        let flags = reader.u8();
        let flags = MosaicFlags::from_bits(flags).ok_or(DecodeError::InvalidValue {
            field: "モザイクのフラグ",
            value: flags.into(),
        })?;
        Ok(Self {
            id,
            duration,
            nonce,
            flags,
            divisibility: reader.u8(),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MosaicSupplyChangeAction {
    Decrease,
    Increase,
}

/// モザイクの発行量を増やすか減らす。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MosaicSupplyChange {
    pub mosaic_id: UnresolvedMosaicId,
    pub delta: u64,
    pub action: MosaicSupplyChangeAction,
}

impl MosaicSupplyChange {
    const SIZE: usize = 8 + 8 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mosaic_id.0.to_le_bytes());
        out.extend_from_slice(&self.delta.to_le_bytes());
        out.push(match self.action {
            MosaicSupplyChangeAction::Decrease => 0,
            MosaicSupplyChangeAction::Increase => 1,
        });
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        let mosaic_id = UnresolvedMosaicId(reader.u64());
        let delta = reader.u64();
        let action = match reader.u8() {
            0 => MosaicSupplyChangeAction::Decrease,
            1 => MosaicSupplyChangeAction::Increase,
            action => {
                return Err(DecodeError::InvalidValue {
                    field: "発行量の増減",
                    value: action.into(),
                });
            }
        };
        Ok(Self {
            mosaic_id,
            delta,
            action,
        })
    }
}

/// 作った人が、ほかのアカウントからモザイクを回収する。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MosaicSupplyRevocation {
    pub source_address: UnresolvedAddress,
    pub mosaic: UnresolvedMosaic,
}

impl MosaicSupplyRevocation {
    const SIZE: usize = 24 + UnresolvedMosaic::SIZE;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source_address.0);
        self.mosaic.encode(out);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            source_address: UnresolvedAddress(reader.array()),
            mosaic: UnresolvedMosaic::read(&mut reader),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use crate::testing::{decode, round_trip};

    fn definition() -> MosaicDefinition {
        MosaicDefinition {
            id: MosaicId(0x0102_0304_0506_0708),
            duration: 0x1112_1314_1516_1718,
            nonce: 0x2122_2324,
            flags: MosaicFlags::TRANSFERABLE | MosaicFlags::REVOKABLE,
            divisibility: 6,
        }
    }

    #[test]
    fn writes_a_definition_in_the_catbuffer_layout() {
        let body = round_trip(Body::MosaicDefinition(definition()));
        assert_eq!(body[..8], 0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(body[8..16], 0x1112_1314_1516_1718_u64.to_le_bytes());
        assert_eq!(body[16..20], 0x2122_2324_u32.to_le_bytes());
        assert_eq!(body[20..], [0x0A, 6]);
    }

    #[test]
    fn rejects_undefined_flags() {
        let mut body = round_trip(Body::MosaicDefinition(definition()));
        body[20] = 0x10;
        assert_eq!(
            decode(0x414D, &body),
            Err(DecodeError::InvalidValue {
                field: "モザイクのフラグ",
                value: 0x10
            })
        );
        assert_eq!(
            MosaicFlags::from_bits(0x0F).map(MosaicFlags::bits),
            Some(0x0F)
        );
        assert!(
            MosaicFlags::from_bits(0x0F)
                .unwrap()
                .contains(MosaicFlags::REVOKABLE)
        );
    }

    #[test]
    fn round_trips_supply_changes_and_revocations() {
        let change = MosaicSupplyChange {
            mosaic_id: UnresolvedMosaicId(7),
            delta: 100,
            action: MosaicSupplyChangeAction::Decrease,
        };
        let mut body = round_trip(Body::MosaicSupplyChange(change));
        assert_eq!(body[16], 0);
        body[16] = 2;
        assert_eq!(
            decode(0x424D, &body),
            Err(DecodeError::InvalidValue {
                field: "発行量の増減",
                value: 2
            })
        );

        let revocation = MosaicSupplyRevocation {
            source_address: UnresolvedAddress([0x98; 24]),
            mosaic: UnresolvedMosaic {
                mosaic_id: UnresolvedMosaicId(7),
                amount: 5,
            },
        };
        let body = round_trip(Body::MosaicSupplyRevocation(revocation));
        assert_eq!(body.len(), 24 + 16);
        assert_eq!(
            decode(0x434D, &body[1..]),
            Err(DecodeError::InvalidBodySize)
        );
    }

    #[test]
    fn generates_an_id_without_the_namespace_bit() {
        let owner = Address([0x98; 24]);
        let id = MosaicId::generate(&owner, 0);
        assert_eq!(id.0 >> 63, 0);
        assert_eq!(MosaicId::generate(&owner, 0), id);
        assert_ne!(MosaicId::generate(&owner, 1), id);
    }
}
