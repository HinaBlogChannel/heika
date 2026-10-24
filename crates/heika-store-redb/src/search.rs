//! 検索表。REST の検索（`/metadata?targetAddress=…` など）のために、今の状態の行を別の切り口で並べ直したもの。
//!
//! 表 `search` の1行は、キーだけで値はない。キーの先頭の1バイトで、どの並べ方かを分ける。
//! 状態の行が変わるたびに、前の値から出る行を消し、後の値から出る行を足す。巻き戻すときも、差分の前と後を
//! 入れ替えて同じことをするので、検索表のための差分は要らない。今の状態だけを映し、昔の高さの検索はできない。
//!
//! 作る検索は、DB の `meta` の `search` に覚える（[`Db::set_search`]）。途中で足せば、今の状態の行から作る。
//!
//! 昔の高さでも検索するなら（[`Searches::PAST`]）、今の検索表から消えたキーを表 `search_past` に残す。高さは持たない。
//! 高さ N の検索では、両方の表のキーを候補にし、高さ N の状態の行から本当にそのキーが出るかで確かめる
//! （[`Db::for_each_search_key_with_past`]）。いつからいつまであったかは、状態の差分が知っている。
//! 巻き戻しで余分なキーが残っても、確かめで落ちる。途中で足せば、状態の差分の前の値から作る。
//!
//! [`Db::set_search`]: crate::Db::set_search
//! [`Db::for_each_search_key_with_past`]: crate::Db::for_each_search_key_with_past

use heika_core::address::Address;
use heika_core::patricia::SubCache;
use heika_transaction::{MetadataKey, MetadataType};

/// 作る検索。ビットの組
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Searches(u8);

impl Searches {
    pub const NONE: Self = Self(0);
    /// メタデータを、送り主、宛先、対象（モザイクかネームスペース）から引く
    pub const METADATA: Self = Self(1);
    /// 作る検索を、昔の高さでも引けるようにする。状態の差分を全部残すアーカイブのためのもの
    pub const PAST: Self = Self(0x80);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub(crate) fn bits(self) -> u8 {
        self.0
    }

    pub(crate) fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// `PAST` を除いた、検索の種類だけ
    pub(crate) fn kinds(self) -> Self {
        Self(self.0 & !Self::PAST.0)
    }

    /// 検索ごとの、検索表のキーの先頭の1バイト
    pub(crate) fn prefixes(self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.contains(Self::METADATA) {
            out.extend([
                METADATA_BY_SOURCE,
                METADATA_BY_TARGET,
                METADATA_BY_TARGET_ID,
            ]);
        }
        out
    }
}

/// `(送り主, 種類, 宛先, 対象の ID, キー)`
pub const METADATA_BY_SOURCE: u8 = 1;
/// `(宛先, 種類, 対象の ID, キー, 送り主)`
pub const METADATA_BY_TARGET: u8 = 2;
/// `(種類, 対象の ID, キー, 宛先, 送り主)`。モザイクとネームスペースのメタデータだけ（アカウントのものは対象の ID がいつも 0）
pub const METADATA_BY_TARGET_ID: u8 = 3;

/// メタデータの1件を指す項目。compositeHash を作る材料
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataFields {
    pub source: [u8; 24],
    pub target: [u8; 24],
    pub scoped_key: u64,
    pub target_id: u64,
    pub metadata_type: u8,
}

impl MetadataFields {
    /// 状態の行の値（`execute::persist` の形。送り主、宛先、キー、対象の ID、種類、値の大きさ、値）から
    pub fn from_row(value: &[u8]) -> Option<Self> {
        if value.len() < 24 + 24 + 8 + 8 + 1 {
            return None;
        }
        let u64_at = |at: usize| u64::from_le_bytes(value[at..at + 8].try_into().expect("8 bytes"));
        Some(Self {
            source: value[..24].try_into().expect("24 bytes"),
            target: value[24..48].try_into().expect("24 bytes"),
            scoped_key: u64_at(48),
            target_id: u64_at(56),
            metadata_type: value[64],
        })
    }

    /// 検索表のキー。並べ方ごとに。ID は上位から書くので、キーの順は REST の16進の順と同じ
    pub fn search_keys(&self) -> Vec<Vec<u8>> {
        let key = |prefix: u8, parts: &[&[u8]]| {
            let mut out = vec![prefix];
            for part in parts {
                out.extend_from_slice(part);
            }
            out
        };
        let kind = [self.metadata_type];
        let (target_id, scoped_key) = (self.target_id.to_be_bytes(), self.scoped_key.to_be_bytes());
        let mut keys = vec![
            key(
                METADATA_BY_SOURCE,
                &[&self.source, &kind, &self.target, &target_id, &scoped_key],
            ),
            key(
                METADATA_BY_TARGET,
                &[&self.target, &kind, &target_id, &scoped_key, &self.source],
            ),
        ];
        if self.metadata_type != 0 {
            keys.push(key(
                METADATA_BY_TARGET_ID,
                &[&kind, &target_id, &scoped_key, &self.target, &self.source],
            ));
        }
        keys
    }

    /// 1件を指すハッシュ（compositeHash）。知らない種類なら `None`
    pub fn composite_hash(&self) -> Option<[u8; 32]> {
        let metadata_type = match self.metadata_type {
            0 => MetadataType::Account,
            1 => MetadataType::Mosaic,
            2 => MetadataType::Namespace,
            _ => return None,
        };
        let key = MetadataKey {
            source_address: Address(self.source),
            target_address: Address(self.target),
            scoped_metadata_key: self.scoped_key,
            target_id: self.target_id,
            metadata_type,
        };
        Some(key.unique_key().0)
    }

    /// 検索表のキーから。[`MetadataFields::search_keys`] の逆
    pub fn from_search_key(key: &[u8]) -> Option<Self> {
        let (&prefix, rest) = key.split_first()?;
        if rest.len() != 24 + 1 + 24 + 8 + 8 {
            return None;
        }
        let address = |at: usize| -> [u8; 24] { rest[at..at + 24].try_into().expect("24 bytes") };
        let id = |at: usize| u64::from_be_bytes(rest[at..at + 8].try_into().expect("8 bytes"));
        Some(match prefix {
            METADATA_BY_SOURCE => Self {
                source: address(0),
                metadata_type: rest[24],
                target: address(25),
                target_id: id(49),
                scoped_key: id(57),
            },
            METADATA_BY_TARGET => Self {
                target: address(0),
                metadata_type: rest[24],
                target_id: id(25),
                scoped_key: id(33),
                source: address(41),
            },
            METADATA_BY_TARGET_ID => Self {
                metadata_type: rest[0],
                target_id: id(1),
                scoped_key: id(9),
                target: address(17),
                source: address(41),
            },
            _ => return None,
        })
    }
}

/// 検索表のキー `key` が、どの状態の行から出たか。その行のキー
pub fn row_key_of(key: &[u8]) -> Option<Vec<u8>> {
    match *key.first()? {
        METADATA_BY_SOURCE | METADATA_BY_TARGET | METADATA_BY_TARGET_ID => {
            let fields = MetadataFields::from_search_key(key)?;
            let mut row = vec![SubCache::Metadata.index() as u8];
            row.extend_from_slice(&fields.composite_hash()?);
            Some(row)
        }
        _ => None,
    }
}

/// 状態の行 `key` の値 `value` から出る、検索表のキー
pub(crate) fn keys_of(searches: Searches, key: &[u8], value: Option<&[u8]>) -> Vec<Vec<u8>> {
    let Some(value) = value else {
        return Vec::new();
    };
    match key.first() {
        Some(&cache)
            if usize::from(cache) == SubCache::Metadata.index()
                && searches.contains(Searches::METADATA) =>
        {
            MetadataFields::from_row(value)
                .map(|fields| fields.search_keys())
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// キーが `prefix` で始まるものより後の、最初のキー。全部が 0xFF なら `None`
pub(crate) fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < 0xFF {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// 状態の行の木の番号のうち、`searches` で検索表に映すもの
pub(crate) fn caches(searches: Searches) -> Vec<u8> {
    let mut out = Vec::new();
    if searches.contains(Searches::METADATA) {
        out.push(SubCache::Metadata.index() as u8);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(metadata_type: u8) -> MetadataFields {
        MetadataFields {
            source: [0x68; 24],
            target: [0x69; 24],
            scoped_key: 0x0102_0304_0506_0708,
            target_id: if metadata_type == 0 { 0 } else { 0xAA },
            metadata_type,
        }
    }

    #[test]
    fn search_keys_go_back_to_the_fields() {
        for metadata_type in [0, 1, 2] {
            let fields = fields(metadata_type);
            let keys = fields.search_keys();
            // アカウントのメタデータは、対象からは引かない
            assert_eq!(keys.len(), if metadata_type == 0 { 2 } else { 3 });
            for key in keys {
                assert_eq!(MetadataFields::from_search_key(&key), Some(fields));
            }
        }
        assert_eq!(
            MetadataFields::from_search_key(&[METADATA_BY_SOURCE, 1]),
            None
        );
    }

    #[test]
    fn reads_the_fields_from_a_state_row() {
        let fields = fields(1);
        let mut row = Vec::new();
        row.extend_from_slice(&fields.source);
        row.extend_from_slice(&fields.target);
        row.extend_from_slice(&fields.scoped_key.to_le_bytes());
        row.extend_from_slice(&fields.target_id.to_le_bytes());
        row.push(1);
        row.extend_from_slice(&2u16.to_le_bytes());
        row.extend_from_slice(b"hi");
        assert_eq!(MetadataFields::from_row(&row), Some(fields));
        assert_eq!(MetadataFields::from_row(&row[..60]), None);

        let key = [SubCache::Metadata.index() as u8];
        assert_eq!(keys_of(Searches::METADATA, &key, Some(&row)).len(), 3);
        assert!(keys_of(Searches::NONE, &key, Some(&row)).is_empty());
        assert!(keys_of(Searches::METADATA, &[0], Some(&row)).is_empty());
        assert!(keys_of(Searches::METADATA, &key, None).is_empty());
    }
}
