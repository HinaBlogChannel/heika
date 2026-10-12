//! ネームスペース。catbuffer の `namespace/`。

use heika_core::address::Address;

use crate::bounded::BoundedVec;
use crate::mosaic::MosaicId;
use crate::{DecodeError, Reader};

/// ネームスペースの ID。名前と親の ID から決まる。最上位ビットは1。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NamespaceId(pub u64);

/// ルートか、どの親の下のサブネームスペースか。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NamespaceRegistrationType {
    /// ルートのネームスペース。持っておく期間（ブロック）を決める
    Root { duration: u64 },
    /// サブネームスペース。期間は親と同じ
    Child { parent_id: NamespaceId },
}

/// ネームスペースを取る、またはルートのネームスペースを延長する。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NamespaceRegistration {
    pub registration_type: NamespaceRegistrationType,
    pub id: NamespaceId,
    /// 名前。使える文字はネットワークが確かめる
    pub name: BoundedVec<u8, { u8::MAX as usize }>,
}

impl NamespaceRegistration {
    /// 名前より前の部分。期間か親の ID、ID、ルートかサブか、名前の長さ。
    const FIXED_SIZE: usize = 8 + 8 + 1 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let (duration_or_parent, registration_type) = match self.registration_type {
            NamespaceRegistrationType::Root { duration } => (duration, 0),
            NamespaceRegistrationType::Child { parent_id } => (parent_id.0, 1),
        };
        out.extend_from_slice(&duration_or_parent.to_le_bytes());
        out.extend_from_slice(&self.id.0.to_le_bytes());
        out.push(registration_type);
        out.push(self.name.len() as u8);
        out.extend_from_slice(&self.name);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::at_least(bytes, Self::FIXED_SIZE)?;
        // 先頭の8バイトが期間か親の ID かは、後ろのルートかサブかで決まる
        let duration_or_parent = reader.u64();
        let id = NamespaceId(reader.u64());
        let registration_type = match reader.u8() {
            0 => NamespaceRegistrationType::Root {
                duration: duration_or_parent,
            },
            1 => NamespaceRegistrationType::Child {
                parent_id: NamespaceId(duration_or_parent),
            },
            registration_type => {
                return Err(DecodeError::InvalidValue {
                    field: "ネームスペースのルートかサブか",
                    value: registration_type.into(),
                });
            }
        };
        let name_size = reader.u8() as usize;
        Ok(Self {
            registration_type,
            id,
            name: reader
                .rest(name_size)?
                .to_vec()
                .try_into()
                .expect("u8 length"),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AliasAction {
    Unlink,
    Link,
}

impl AliasAction {
    fn to_byte(self) -> u8 {
        match self {
            Self::Unlink => 0,
            Self::Link => 1,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, DecodeError> {
        match byte {
            0 => Ok(Self::Unlink),
            1 => Ok(Self::Link),
            _ => Err(DecodeError::InvalidValue {
                field: "エイリアスの操作",
                value: byte.into(),
            }),
        }
    }
}

/// ネームスペースをアドレスの別名にする、または外す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressAlias {
    pub namespace_id: NamespaceId,
    pub address: Address,
    pub alias_action: AliasAction,
}

impl AddressAlias {
    const SIZE: usize = 8 + 24 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace_id.0.to_le_bytes());
        out.extend_from_slice(&self.address.0);
        out.push(self.alias_action.to_byte());
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            namespace_id: NamespaceId(reader.u64()),
            address: Address(reader.array()),
            alias_action: AliasAction::from_byte(reader.u8())?,
        })
    }
}

/// ネームスペースをモザイクの別名にする、または外す。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MosaicAlias {
    pub namespace_id: NamespaceId,
    pub mosaic_id: MosaicId,
    pub alias_action: AliasAction,
}

impl MosaicAlias {
    const SIZE: usize = 8 + 8 + 1;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace_id.0.to_le_bytes());
        out.extend_from_slice(&self.mosaic_id.0.to_le_bytes());
        out.push(self.alias_action.to_byte());
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            namespace_id: NamespaceId(reader.u64()),
            mosaic_id: MosaicId(reader.u64()),
            alias_action: AliasAction::from_byte(reader.u8())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use crate::testing::{decode, round_trip};

    fn registration(registration_type: NamespaceRegistrationType) -> NamespaceRegistration {
        NamespaceRegistration {
            registration_type,
            id: NamespaceId(0x8000_0000_0000_0002),
            name: b"heika".to_vec().try_into().unwrap(),
        }
    }

    #[test]
    fn writes_the_duration_or_the_parent_in_the_same_place() {
        let root = round_trip(Body::NamespaceRegistration(registration(
            NamespaceRegistrationType::Root { duration: 365 },
        )));
        assert_eq!(root[..8], 365_u64.to_le_bytes());
        assert_eq!(root[16..18], [0, 5]);
        assert_eq!(root[18..], *b"heika");

        let child = round_trip(Body::NamespaceRegistration(registration(
            NamespaceRegistrationType::Child {
                parent_id: NamespaceId(0x8000_0000_0000_0001),
            },
        )));
        assert_eq!(child[..8], 0x8000_0000_0000_0001_u64.to_le_bytes());
        assert_eq!(child[16], 1);
    }

    #[test]
    fn rejects_an_undefined_registration_type() {
        let mut body = round_trip(Body::NamespaceRegistration(registration(
            NamespaceRegistrationType::Root { duration: 1 },
        )));
        body[16] = 2;
        assert_eq!(
            decode(0x414E, &body),
            Err(DecodeError::InvalidValue {
                field: "ネームスペースのルートかサブか",
                value: 2
            })
        );
    }

    #[test]
    fn round_trips_aliases() {
        let address = round_trip(Body::AddressAlias(AddressAlias {
            namespace_id: NamespaceId(0x8000_0000_0000_0001),
            address: Address([0x98; 24]),
            alias_action: AliasAction::Link,
        }));
        assert_eq!(address[8..32], [0x98; 24]);
        assert_eq!(address[32], 1);

        let mut mosaic = round_trip(Body::MosaicAlias(MosaicAlias {
            namespace_id: NamespaceId(0x8000_0000_0000_0001),
            mosaic_id: MosaicId(7),
            alias_action: AliasAction::Unlink,
        }));
        assert_eq!(mosaic[16], 0);
        mosaic[16] = 2;
        assert_eq!(
            decode(0x434E, &mosaic),
            Err(DecodeError::InvalidValue {
                field: "エイリアスの操作",
                value: 2
            })
        );
    }
}
