//! メタデータ。catbuffer の `metadata/`。
//!
//! アカウント、モザイク、ネームスペースに、キーと値の組を付ける。値は差分で書く。
//! 3種類とも、対象の ID が途中に入るかどうかだけが違う。

use heika_core::address::Address;
use heika_core::hash::Hash256;
use sha3::{Digest, Sha3_256};

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

/// 文字列からメタデータのキーを作る。公式の SDK の `metadata_generate_key` と同じく、
/// SHA3-256 の先頭8バイトをリトルエンディアンで読み、最上位ビットを立てる（SDK v2 に合わせたもの）。
pub fn scoped_metadata_key(text: &str) -> u64 {
    let hash = Sha3_256::digest(text.as_bytes());
    u64::from_le_bytes(hash[..8].try_into().expect("8 of 32 bytes")) | 1 << 63
}

/// 前の値を新しい値に変えるときに、トランザクションに書く値。公式の SDK の `metadata_update_value`。
///
/// 短いほうの長さまでは2つの XOR で、そこから先は長いほうの値をそのまま続ける。
/// 前の値がなければ（空なら）新しい値そのもの。`value_size_delta` には、新しい値と前の値の長さの差を書く。
pub fn metadata_value_update(old_value: &[u8], new_value: &[u8]) -> Vec<u8> {
    let (shorter, longer) = if old_value.len() <= new_value.len() {
        (old_value, new_value)
    } else {
        (new_value, old_value)
    };
    let mut update: Vec<u8> = shorter.iter().zip(longer).map(|(a, b)| a ^ b).collect();
    update.extend_from_slice(&longer[shorter.len()..]);
    update
}

/// メタデータを付ける対象の種類。catapult の `model::MetadataType`。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum MetadataType {
    Account = 0,
    Mosaic = 1,
    Namespace = 2,
}

/// チェーンに記録されたメタデータの1件を指すキー。catapult の `state::MetadataKey`。
/// アドレスやモザイクの ID は、ネームスペースを解決したあとのもの。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MetadataKey {
    /// メタデータを付けた人
    pub source_address: Address,
    /// メタデータを付ける対象の持ち主
    pub target_address: Address,
    pub scoped_metadata_key: u64,
    /// モザイクやネームスペースの ID。アカウントのメタデータなら 0
    pub target_id: u64,
    pub metadata_type: MetadataType,
}

impl MetadataKey {
    /// 1件ごとに一意なハッシュ。catapult の `MetadataKey::uniqueKey` で、状態の中でメタデータを探すのに使う。
    /// 付けた人、対象の持ち主、キー、対象の ID、種類を続けた SHA3-256。
    pub fn unique_key(&self) -> Hash256 {
        Hash256(
            Sha3_256::new()
                .chain_update(self.source_address.0)
                .chain_update(self.target_address.0)
                .chain_update(self.scoped_metadata_key.to_le_bytes())
                .chain_update(self.target_id.to_le_bytes())
                .chain_update([self.metadata_type as u8])
                .finalize()
                .into(),
        )
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

    /// FIPS 202 の SHA3-256 の例。"abc" と空の文字列
    const SHA3_ABC: &str = "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532";
    const SHA3_EMPTY: &str = "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A";

    fn first_eight_bytes(hash: &str) -> u64 {
        let hash: Hash256 = hash.parse().unwrap();
        u64::from_le_bytes(hash.0[..8].try_into().unwrap())
    }

    #[test]
    fn makes_scoped_keys_with_the_high_bit_set() {
        // "abc" はもともと最上位ビットが立っている
        assert_eq!(scoped_metadata_key("abc"), first_eight_bytes(SHA3_ABC));
        assert_eq!(scoped_metadata_key("abc"), 0xB225_E24F_A75D_983A);
        // 空の文字列は立っていないので、立てる
        assert_eq!(first_eight_bytes(SHA3_EMPTY), 0x66D7_1EBF_F8C6_FFA7);
        assert_eq!(scoped_metadata_key(""), 0xE6D7_1EBF_F8C6_FFA7);
    }

    #[test]
    fn xors_the_overlap_and_keeps_the_rest_of_the_longer_value() {
        let old = [0x9A, 0xC7, 0x33];
        assert_eq!(metadata_value_update(&[], &old), old);
        assert_eq!(
            metadata_value_update(&old, &[0xD4, 0x60, 0x82]),
            [0x9A ^ 0xD4, 0xC7 ^ 0x60, 0x33 ^ 0x82]
        );
        // 短くするときは、前の値の残りを書いて消す
        assert_eq!(
            metadata_value_update(&old, &[0xD4]),
            [0x9A ^ 0xD4, 0xC7, 0x33]
        );
        assert_eq!(
            metadata_value_update(&old, &[0xD4, 0x60, 0x82, 0xF8]),
            [0x9A ^ 0xD4, 0xC7 ^ 0x60, 0x33 ^ 0x82, 0xF8]
        );
    }

    #[test]
    fn hashes_the_metadata_key_in_the_catapult_order() {
        let key = MetadataKey {
            source_address: Address([1; 24]),
            target_address: Address([2; 24]),
            scoped_metadata_key: 0x0304,
            target_id: 0x0506,
            metadata_type: MetadataType::Mosaic,
        };
        let mut data = vec![1; 24];
        data.extend_from_slice(&[2; 24]);
        data.extend_from_slice(&0x0304_u64.to_le_bytes());
        data.extend_from_slice(&0x0506_u64.to_le_bytes());
        data.push(1);
        assert_eq!(key.unique_key(), Hash256(Sha3_256::digest(&data).into()));
        // 種類だけが違っても別のキーになる
        let account = MetadataKey {
            metadata_type: MetadataType::Account,
            ..key
        };
        assert_ne!(account.unique_key(), key.unique_key());
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
