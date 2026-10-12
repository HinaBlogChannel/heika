//! メタデータ。catbuffer の `metadata/`。
//!
//! アカウント、モザイク、ネームスペースに、キーと値の組を付ける。値は差分で書く。
//! 3種類とも、対象の ID が途中に入るかどうかだけが違う。

use crate::bounded::BoundedVec;
use crate::namespace::NamespaceId;
use crate::transfer::{UnresolvedAddress, UnresolvedMosaicId};
use crate::{DecodeError, Reader};

/// 3種類のメタデータに共通の部分。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Metadata {
    /// メタデータを付ける対象の持ち主
    pub target_address: UnresolvedAddress,
    pub scoped_metadata_key: u64,
    /// 値の長さが、前の値からどれだけ変わるか
    pub value_size_delta: i16,
    /// 前の値との XOR。前の値がなければ、新しい値そのもの
    pub value: BoundedVec<u8, { u16::MAX as usize }>,
}

/// モザイクに付けるメタデータ。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MosaicMetadata {
    pub target_mosaic_id: UnresolvedMosaicId,
    pub metadata: Metadata,
}

/// ネームスペースに付けるメタデータ。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NamespaceMetadata {
    pub target_namespace_id: NamespaceId,
    pub metadata: Metadata,
}

impl Metadata {
    /// 対象の ID を除いた、値より前の部分。持ち主、キー、長さの差分、値の長さ。
    const FIXED_SIZE: usize = 24 + 8 + 2 + 2;

    /// 対象の ID があれば、キーと長さの差分のあいだに書く
    pub(crate) fn encode(&self, target_id: Option<u64>, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.target_address.0);
        out.extend_from_slice(&self.scoped_metadata_key.to_le_bytes());
        if let Some(target_id) = target_id {
            out.extend_from_slice(&target_id.to_le_bytes());
        }
        out.extend_from_slice(&self.value_size_delta.to_le_bytes());
        out.extend_from_slice(&(self.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.value);
    }

    /// `with_target_id` なら、対象の ID も読んで返す
    pub(crate) fn decode(
        bytes: &[u8],
        with_target_id: bool,
    ) -> Result<(Self, Option<u64>), DecodeError> {
        let target_size = if with_target_id { 8 } else { 0 };
        let mut reader = Reader::at_least(bytes, Self::FIXED_SIZE + target_size)?;
        let target_address = UnresolvedAddress(reader.array());
        let scoped_metadata_key = reader.u64();
        let target_id = with_target_id.then(|| reader.u64());
        let value_size_delta = reader.i16();
        let value_size = reader.u16() as usize;
        let value = reader.rest(value_size)?.to_vec();
        Ok((
            Self {
                target_address,
                scoped_metadata_key,
                value_size_delta,
                value: value.try_into().expect("u16 length"),
            },
            target_id,
        ))
    }
}

impl MosaicMetadata {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.metadata.encode(Some(self.target_mosaic_id.0), out);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (metadata, target_id) = Metadata::decode(bytes, true)?;
        Ok(Self {
            target_mosaic_id: UnresolvedMosaicId(target_id.expect("read with the id")),
            metadata,
        })
    }
}

impl NamespaceMetadata {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.metadata.encode(Some(self.target_namespace_id.0), out);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (metadata, target_id) = Metadata::decode(bytes, true)?;
        Ok(Self {
            target_namespace_id: NamespaceId(target_id.expect("read with the id")),
            metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use crate::testing::{decode, round_trip};

    fn metadata() -> Metadata {
        Metadata {
            target_address: UnresolvedAddress([0x98; 24]),
            scoped_metadata_key: 0x0102,
            value_size_delta: -2,
            value: b"abc".to_vec().try_into().unwrap(),
        }
    }

    #[test]
    fn writes_the_target_id_between_the_key_and_the_delta() {
        let account = round_trip(Body::AccountMetadata(metadata()));
        assert_eq!(account[32..36], [0xFE, 0xFF, 3, 0]);
        assert_eq!(account[36..], *b"abc");

        let mosaic = round_trip(Body::MosaicMetadata(MosaicMetadata {
            target_mosaic_id: UnresolvedMosaicId(0x0A0B),
            metadata: metadata(),
        }));
        let namespace = round_trip(Body::NamespaceMetadata(NamespaceMetadata {
            target_namespace_id: NamespaceId(0x0A0B),
            metadata: metadata(),
        }));
        for body in [mosaic, namespace] {
            assert_eq!(body[..32], account[..32]);
            assert_eq!(body[32..40], 0x0A0B_u64.to_le_bytes());
            assert_eq!(body[40..], account[32..]);
        }
    }

    #[test]
    fn rejects_a_value_of_another_size() {
        let body = round_trip(Body::AccountMetadata(metadata()));
        assert_eq!(
            decode(0x4144, &body[..body.len() - 1]),
            Err(DecodeError::InvalidBodySize)
        );
        // アカウントのメタデータを、対象の ID があるものとして読むと長さが合わない
        assert_eq!(decode(0x4244, &body), Err(DecodeError::InvalidBodySize));
    }
}
