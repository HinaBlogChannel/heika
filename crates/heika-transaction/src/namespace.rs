//! ネームスペース。catbuffer の `namespace/`。

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use heika_core::address::Address;
use sha3::{Digest, Sha3_256};

use crate::bounded::BoundedVec;
use crate::mosaic::MosaicId;
use crate::{DecodeError, Reader};

/// ネームスペースの ID。名前と親の ID から決まる。最上位ビットは1。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NamespaceId(pub u64);

impl NamespaceId {
    /// 名前と親の ID から ID を求める。catapult の `GenerateNamespaceId` と同じく、
    /// 親の ID（ルートなら0）と名前を続けた SHA3-256 の先頭8バイトに、モザイクと見分ける最上位ビットを立てて使う。
    pub fn generate(parent_id: Option<NamespaceId>, name: &[u8]) -> Self {
        let parent_id = parent_id.map_or(0, |parent_id| parent_id.0);
        let hash = Sha3_256::new()
            .chain_update(parent_id.to_le_bytes())
            .chain_update(name)
            .finalize();
        let id = u64::from_le_bytes(hash[..8].try_into().expect("8 bytes"));
        Self(id | 1 << 63)
    }

    /// ドットで区切ったフルネームから ID を求める。公式の SDK の `generate_mosaic_alias_id` と同じく、
    /// [`NamespaceId::path`] の最後の ID。`symbol.xym` なら、通貨のモザイクに付いているネームスペースになる。
    pub fn from_full_name(full_name: &str) -> Result<Self, InvalidNamespaceName> {
        Ok(*Self::path(full_name)?
            .last()
            .expect("split yields at least one part"))
    }

    /// ドットで区切ったフルネームを、ルートから順の ID の並びにする。公式の SDK の `generate_namespace_path`。
    /// どの部分も [`is_valid_namespace_name`] を満たさなければならない。
    ///
    /// 名前の長さと深さの上限はネットワークの設定（`maxNameSize` と `maxNamespaceDepth`）で決まるので、ここでは確かめない。
    pub fn path(full_name: &str) -> Result<Vec<Self>, InvalidNamespaceName> {
        let mut parent = None;
        full_name
            .split('.')
            .map(|name| {
                if !is_valid_namespace_name(name.as_bytes()) {
                    return Err(InvalidNamespaceName(name.to_owned()));
                }
                let id = Self::generate(parent, name.as_bytes());
                parent = Some(id);
                Ok(id)
            })
            .collect()
    }
}

/// ネームスペースの名前として使えるか。catapult の `IsValidName` と同じく、空でなく、
/// 英小文字と数字と `-` と `_` だけで、最初は英小文字か数字でなければならない。
pub fn is_valid_namespace_name(name: &[u8]) -> bool {
    let is_alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    match name.split_first() {
        Some((first, rest)) => {
            is_alphanumeric(first)
                && rest
                    .iter()
                    .all(|byte| is_alphanumeric(byte) || *byte == b'-' || *byte == b'_')
        }
        None => false,
    }
}

/// フルネームに、ネームスペースの名前として使えない部分がある。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InvalidNamespaceName(pub String);

impl fmt::Display for InvalidNamespaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ネームスペースの名前として使えない部分があります: {:?}（英小文字、数字、- と _ だけで、英小文字か数字で始めます）",
            self.0
        )
    }
}

impl core::error::Error for InvalidNamespaceName {}

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

    #[test]
    fn finds_the_currency_namespace_from_its_full_name() {
        let symbol = NamespaceId::generate(None, b"symbol");
        let xym = NamespaceId::generate(Some(symbol), b"xym");
        // 通貨のモザイクに付いているネームスペースの ID は、チェーンに記録されているもの
        assert_eq!(xym, NamespaceId(0xE74B_99BA_41F4_AFEE));
        assert_eq!(NamespaceId::path("symbol.xym"), Ok(vec![symbol, xym]));
        assert_eq!(NamespaceId::from_full_name("symbol.xym"), Ok(xym));
        assert_eq!(NamespaceId::from_full_name("symbol"), Ok(symbol));
    }

    #[test]
    fn refuses_full_names_with_invalid_parts() {
        for (full_name, part) in [
            ("", ""),
            ("symbol.", ""),
            (".xym", ""),
            ("Symbol.xym", "Symbol"),
            ("symbol._xym", "_xym"),
            ("symbol.x ym", "x ym"),
        ] {
            assert_eq!(
                NamespaceId::path(full_name),
                Err(InvalidNamespaceName(part.to_owned())),
                "{full_name:?}"
            );
        }
    }

    #[test]
    fn checks_names_like_catapult() {
        for name in ["a", "0", "a-b_c", "9-", "heika_2026"] {
            assert!(is_valid_namespace_name(name.as_bytes()), "{name}");
        }
        for name in ["", "-a", "_a", "A", "a.b", "a b", "あ"] {
            assert!(!is_valid_namespace_name(name.as_bytes()), "{name}");
        }
    }

    fn registration(registration_type: NamespaceRegistrationType) -> NamespaceRegistration {
        NamespaceRegistration {
            registration_type,
            id: NamespaceId(0x8000_0000_0000_0002),
            name: b"heika".to_vec().try_into().unwrap(),
        }
    }

    #[test]
    fn generates_the_id_of_symbol_xym() {
        // ネットワークの通貨のモザイクに付いている、よく知られたネームスペース
        let symbol = NamespaceId::generate(None, b"symbol");
        assert_eq!(
            NamespaceId::generate(Some(symbol), b"xym"),
            NamespaceId(0xE74B_99BA_41F4_AFEE)
        );
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
