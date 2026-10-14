//! 制限。catbuffer の `restriction_account/` と `restriction_mosaic/`。

use heika_core::address::Address;
use heika_core::hash::Hash256;
use sha3::{Digest, Sha3_256};

use crate::bounded::BoundedVec;
use crate::mosaic::MosaicId;
use crate::transfer::{UnresolvedAddress, UnresolvedMosaicId};
use crate::{DecodeError, Reader};

/// アカウントの制限の種類と向き。catbuffer の `AccountRestrictionFlags`。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct AccountRestrictionFlags(u16);

impl AccountRestrictionFlags {
    /// アドレスで制限する
    pub const ADDRESS: Self = Self(0x0001);
    /// モザイクで制限する
    pub const MOSAIC_ID: Self = Self(0x0002);
    /// トランザクションの種類で制限する
    pub const TRANSACTION_TYPE: Self = Self(0x0004);
    /// 送る側を制限する。なければ受け取る側
    pub const OUTGOING: Self = Self(0x4000);
    /// 並べたものを拒む。なければ並べたものだけを許す
    pub const BLOCK: Self = Self(0x8000);
    const ALL: u16 = 0xC007;

    /// 定義されていないビットが立っていれば `None`。
    /// どの組み合わせを受け付けるかは catapult の `AccountRestrictionFlagsValidator` が決めるので、ここでは確かめない。
    pub fn from_bits(bits: u16) -> Option<Self> {
        (bits & !Self::ALL == 0).then_some(Self(bits))
    }

    pub fn bits(self) -> u16 {
        self.0
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for AccountRestrictionFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// アカウントの制限に並べられる値。アドレス、モザイクの ID、トランザクションの種類。
pub(crate) trait AccountRestrictionValue: Copy {
    const SIZE: usize;
    fn encode(&self, out: &mut Vec<u8>);
    fn read(reader: &mut Reader) -> Self;
}

impl AccountRestrictionValue for UnresolvedAddress {
    const SIZE: usize = 24;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn read(reader: &mut Reader) -> Self {
        Self(reader.array())
    }
}

impl AccountRestrictionValue for UnresolvedMosaicId {
    const SIZE: usize = 8;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn read(reader: &mut Reader) -> Self {
        Self(reader.u64())
    }
}

/// トランザクションの種類。catbuffer の `TransactionType`。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TransactionType(pub u16);

impl AccountRestrictionValue for TransactionType {
    const SIZE: usize = 2;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }

    fn read(reader: &mut Reader) -> Self {
        Self(reader.u16())
    }
}

/// アカウントの制限を足す、または外す。並べる値の型だけが違う3種類に共通。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountRestriction<T> {
    pub restriction_flags: AccountRestrictionFlags,
    pub restriction_additions: BoundedVec<T, { u8::MAX as usize }>,
    pub restriction_deletions: BoundedVec<T, { u8::MAX as usize }>,
}

impl<T: Copy> AccountRestriction<T> {
    /// 値の並びより前の部分。フラグ、足す数と外す数、予約。
    const FIXED_SIZE: usize = 2 + 1 + 1 + 4;

    pub(crate) fn encode(&self, out: &mut Vec<u8>)
    where
        T: AccountRestrictionValue,
    {
        out.extend_from_slice(&self.restriction_flags.0.to_le_bytes());
        out.push(self.restriction_additions.len() as u8);
        out.push(self.restriction_deletions.len() as u8);
        out.extend_from_slice(&[0; 4]);
        for value in self
            .restriction_additions
            .iter()
            .chain(&*self.restriction_deletions)
        {
            value.encode(out);
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError>
    where
        T: AccountRestrictionValue,
    {
        let mut reader = Reader::at_least(bytes, Self::FIXED_SIZE)?;
        let flags = reader.u16();
        let restriction_flags =
            AccountRestrictionFlags::from_bits(flags).ok_or(DecodeError::InvalidValue {
                field: "アカウントの制限のフラグ",
                value: flags.into(),
            })?;
        let additions_count = reader.u8() as usize;
        let deletions_count = reader.u8() as usize;
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        reader.expect_remaining((additions_count + deletions_count) * T::SIZE)?;
        let mut read = |count| {
            (0..count)
                .map(|_| T::read(&mut reader))
                .collect::<Vec<_>>()
                .try_into()
                .expect("u8 count")
        };
        let restriction_additions = read(additions_count);
        let restriction_deletions = read(deletions_count);
        Ok(Self {
            restriction_flags,
            restriction_additions,
            restriction_deletions,
        })
    }
}

/// モザイクの制限で、アドレスの値と比べ方。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MosaicRestrictionType {
    /// 制限しない。制限を外すときに使う
    None,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl MosaicRestrictionType {
    fn to_byte(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Eq => 1,
            Self::Ne => 2,
            Self::Lt => 3,
            Self::Le => 4,
            Self::Gt => 5,
            Self::Ge => 6,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, DecodeError> {
        Ok(match byte {
            0 => Self::None,
            1 => Self::Eq,
            2 => Self::Ne,
            3 => Self::Lt,
            4 => Self::Le,
            5 => Self::Gt,
            6 => Self::Ge,
            _ => {
                return Err(DecodeError::InvalidValue {
                    field: "モザイクの制限の比べ方",
                    value: byte.into(),
                });
            }
        })
    }
}

/// モザイクの制限で、アドレスごとの値を決める。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MosaicAddressRestriction {
    pub mosaic_id: UnresolvedMosaicId,
    pub restriction_key: u64,
    pub previous_restriction_value: u64,
    pub new_restriction_value: u64,
    pub target_address: UnresolvedAddress,
}

impl MosaicAddressRestriction {
    const SIZE: usize = 8 + 8 + 8 + 8 + 24;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mosaic_id.0.to_le_bytes());
        out.extend_from_slice(&self.restriction_key.to_le_bytes());
        out.extend_from_slice(&self.previous_restriction_value.to_le_bytes());
        out.extend_from_slice(&self.new_restriction_value.to_le_bytes());
        out.extend_from_slice(&self.target_address.0);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            mosaic_id: UnresolvedMosaicId(reader.u64()),
            restriction_key: reader.u64(),
            previous_restriction_value: reader.u64(),
            new_restriction_value: reader.u64(),
            target_address: UnresolvedAddress(reader.array()),
        })
    }
}

/// モザイクの制限で、モザイク全体の条件を決める。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MosaicGlobalRestriction {
    pub mosaic_id: UnresolvedMosaicId,
    /// 条件を借りてくるモザイク。0なら `mosaic_id` 自身
    pub reference_mosaic_id: UnresolvedMosaicId,
    pub restriction_key: u64,
    pub previous_restriction_value: u64,
    pub new_restriction_value: u64,
    pub previous_restriction_type: MosaicRestrictionType,
    pub new_restriction_type: MosaicRestrictionType,
}

impl MosaicGlobalRestriction {
    const SIZE: usize = 8 + 8 + 8 + 8 + 8 + 1 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mosaic_id.0.to_le_bytes());
        out.extend_from_slice(&self.reference_mosaic_id.0.to_le_bytes());
        out.extend_from_slice(&self.restriction_key.to_le_bytes());
        out.extend_from_slice(&self.previous_restriction_value.to_le_bytes());
        out.extend_from_slice(&self.new_restriction_value.to_le_bytes());
        out.push(self.previous_restriction_type.to_byte());
        out.push(self.new_restriction_type.to_byte());
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            mosaic_id: UnresolvedMosaicId(reader.u64()),
            reference_mosaic_id: UnresolvedMosaicId(reader.u64()),
            restriction_key: reader.u64(),
            previous_restriction_value: reader.u64(),
            new_restriction_value: reader.u64(),
            previous_restriction_type: MosaicRestrictionType::from_byte(reader.u8())?,
            new_restriction_type: MosaicRestrictionType::from_byte(reader.u8())?,
        })
    }
}

/// 文字列からモザイクの制限のキーを作る。公式の SDK の `mosaic_restriction_generate_key` と同じく、
/// SHA3-256 の先頭8バイトをリトルエンディアンで読む。メタデータのキーと違い、最上位ビットは立てない。
pub fn mosaic_restriction_key(text: &str) -> u64 {
    let hash = Sha3_256::digest(text.as_bytes());
    u64::from_le_bytes(hash[..8].try_into().expect("8 of 32 bytes"))
}

/// チェーンに記録されたモザイクの制限の1件を指すハッシュ。catapult の `CreateMosaicRestrictionEntryKey` で、
/// モザイクの ID とアドレスを続けた SHA3-256。モザイク全体の制限なら、アドレスを24バイトの0にする。
/// ID とアドレスは、ネームスペースを解決したあとのもの。
pub fn mosaic_restriction_entry_key(mosaic_id: MosaicId, address: Option<&Address>) -> Hash256 {
    let address = address.map_or([0; 24], |address| address.0);
    Hash256(
        Sha3_256::new()
            .chain_update(mosaic_id.0.to_le_bytes())
            .chain_update(address)
            .finalize()
            .into(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use crate::testing::{decode, round_trip};

    fn restriction<T>(flags: AccountRestrictionFlags, additions: Vec<T>) -> AccountRestriction<T> {
        AccountRestriction {
            restriction_flags: flags,
            restriction_additions: additions.try_into().unwrap(),
            restriction_deletions: Vec::new().try_into().unwrap(),
        }
    }

    #[test]
    fn makes_restriction_keys_without_setting_the_high_bit() {
        // FIPS 202 の SHA3-256 の例。空の文字列のハッシュは A7FFC6F8BF1ED766 で始まる
        assert_eq!(mosaic_restriction_key(""), 0x66D7_1EBF_F8C6_FFA7);
        // "abc" のハッシュは 3A985DA74FE225B2 で始まる
        assert_eq!(mosaic_restriction_key("abc"), 0xB225_E24F_A75D_983A);
    }

    #[test]
    fn hashes_the_mosaic_id_and_the_address() {
        let mut data = 0x0102_u64.to_le_bytes().to_vec();
        data.extend_from_slice(&[0x98; 24]);
        assert_eq!(
            mosaic_restriction_entry_key(MosaicId(0x0102), Some(&Address([0x98; 24]))),
            Hash256(Sha3_256::digest(&data).into())
        );
        // モザイク全体の制限は、アドレスが0の制限と同じキーになる
        assert_eq!(
            mosaic_restriction_entry_key(MosaicId(0x0102), None),
            mosaic_restriction_entry_key(MosaicId(0x0102), Some(&Address([0; 24])))
        );
    }

    #[test]
    fn writes_each_kind_of_value() {
        let address = round_trip(Body::AccountAddressRestriction(restriction(
            AccountRestrictionFlags::ADDRESS | AccountRestrictionFlags::BLOCK,
            vec![UnresolvedAddress([0x98; 24])],
        )));
        assert_eq!(address[..8], [0x01, 0x80, 1, 0, 0, 0, 0, 0]);
        assert_eq!(address[8..], [0x98; 24]);

        let mosaic = round_trip(Body::AccountMosaicRestriction(restriction(
            AccountRestrictionFlags::MOSAIC_ID,
            vec![UnresolvedMosaicId(7)],
        )));
        assert_eq!(mosaic[8..], 7_u64.to_le_bytes());

        let operation = round_trip(Body::AccountOperationRestriction(restriction(
            AccountRestrictionFlags::TRANSACTION_TYPE | AccountRestrictionFlags::OUTGOING,
            vec![TransactionType(0x4154), TransactionType(0x4252)],
        )));
        assert_eq!(operation[..2], [0x04, 0x40]);
        assert_eq!(operation[8..], [0x54, 0x41, 0x52, 0x42]);
    }

    #[test]
    fn rejects_undefined_flags_and_reserved_bytes() {
        let body = round_trip(Body::AccountAddressRestriction(restriction(
            AccountRestrictionFlags::ADDRESS,
            vec![],
        )));
        // Sentinel（0x0008）は catapult の中だけで使い、トランザクションには書けない
        let mut flags = body.clone();
        flags[0] = 0x09;
        assert_eq!(
            decode(0x4150, &flags),
            Err(DecodeError::InvalidValue {
                field: "アカウントの制限のフラグ",
                value: 0x09
            })
        );
        let mut reserved = body;
        reserved[7] = 1;
        assert_eq!(decode(0x4150, &reserved), Err(DecodeError::NonZeroReserved));
    }

    #[test]
    fn rejects_an_undefined_mosaic_restriction_type() {
        let restriction = MosaicGlobalRestriction {
            mosaic_id: UnresolvedMosaicId(1),
            reference_mosaic_id: UnresolvedMosaicId(0),
            restriction_key: 2,
            previous_restriction_value: 3,
            new_restriction_value: 4,
            previous_restriction_type: MosaicRestrictionType::None,
            new_restriction_type: MosaicRestrictionType::Ge,
        };
        let mut body = round_trip(Body::MosaicGlobalRestriction(restriction));
        assert_eq!(body[40..], [0, 6]);
        body[41] = 7;
        assert_eq!(
            decode(0x4151, &body),
            Err(DecodeError::InvalidValue {
                field: "モザイクの制限の比べ方",
                value: 7
            })
        );

        let address = round_trip(Body::MosaicAddressRestriction(MosaicAddressRestriction {
            mosaic_id: UnresolvedMosaicId(1),
            restriction_key: 2,
            previous_restriction_value: 3,
            new_restriction_value: 4,
            target_address: UnresolvedAddress([0x98; 24]),
        }));
        assert_eq!(address[32..], [0x98; 24]);
    }
}
