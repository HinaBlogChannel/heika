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

use std::collections::BTreeSet;

use heika_block::statement::BlockStatement;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::patricia::SubCache;
use heika_transaction::{
    Body, LinkAction, MetadataKey, MetadataType, NamespaceId, NamespaceRegistrationType,
};

/// 作る検索。ビットの組
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Searches(u8);

impl Searches {
    pub const NONE: Self = Self(0);
    /// メタデータを、送り主、宛先、対象（モザイクかネームスペース）から引く
    pub const METADATA: Self = Self(1);
    /// ネームスペースを、持ち主と別名（アドレスかモザイク）から引く。名前の表（[`Db::namespace_name`]）も作る
    ///
    /// [`Db::namespace_name`]: crate::Db::namespace_name
    pub const NAMESPACES: Self = Self(2);
    /// トランザクションを、ハッシュから引く（[`Db::transaction_location`]）。ブロックから作る
    ///
    /// [`Db::transaction_location`]: crate::Db::transaction_location
    pub const TRANSACTIONS: Self = Self(4);
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
        if self.contains(Self::NAMESPACES) {
            out.extend([
                NAMESPACE_BY_OWNER,
                NAMESPACE_BY_ADDRESS,
                NAMESPACE_BY_MOSAIC,
            ]);
        }
        out
    }
}

/// `(持ち主, ルートの ID, ネームスペースの ID)`。ルートもその子も、持ち主はルートのもの
pub const NAMESPACE_BY_OWNER: u8 = 4;
/// `(別名のアドレス, ルートの ID, ネームスペースの ID)`
pub const NAMESPACE_BY_ADDRESS: u8 = 5;
/// `(別名のモザイクの ID, ルートの ID, ネームスペースの ID)`
pub const NAMESPACE_BY_MOSAIC: u8 = 6;

/// ネームスペースの状態の行（ルートごと）から読んだもの
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceRow {
    pub owner: [u8; 24],
    pub start: u64,
    pub end: u64,
    /// ルートと子の、ID と別名。ルートが先
    pub entries: Vec<(u64, Alias)>,
}

/// ネームスペースの別名
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alias {
    None,
    Mosaic(u64),
    Address([u8; 24]),
}

impl NamespaceRow {
    /// 状態の行の値（`execute::persist` の形。持ち主、始まりと終わりの高さ、別名、子の経路と別名）から
    pub fn from_row(root_id: u64, value: &[u8]) -> Option<Self> {
        let mut reader = RowReader(value);
        let owner = reader.take(24)?.try_into().ok()?;
        let start = reader.u64()?;
        let end = reader.u64()?;
        let mut entries = vec![(root_id, reader.alias()?)];
        for _ in 0..reader.u64()? {
            let depth = reader.take(1)?[0];
            let mut last = None;
            for _ in 0..depth {
                last = Some(reader.u64()?);
            }
            entries.push((last?, reader.alias()?));
        }
        reader.0.is_empty().then_some(Self {
            owner,
            start,
            end,
            entries,
        })
    }

    /// 検索表のキー
    pub fn search_keys(&self, root_id: u64) -> Vec<Vec<u8>> {
        let tail = |id: u64| [root_id.to_be_bytes(), id.to_be_bytes()].concat();
        let mut keys = Vec::new();
        for &(id, alias) in &self.entries {
            keys.push([&[NAMESPACE_BY_OWNER][..], &self.owner, &tail(id)].concat());
            match alias {
                Alias::None => {}
                Alias::Address(address) => {
                    keys.push([&[NAMESPACE_BY_ADDRESS][..], &address, &tail(id)].concat())
                }
                Alias::Mosaic(mosaic) => keys
                    .push([&[NAMESPACE_BY_MOSAIC][..], &mosaic.to_be_bytes(), &tail(id)].concat()),
            }
        }
        keys
    }
}

/// トランザクションの索引（[`Searches::TRANSACTIONS`]）を作るのに要る、ネットワークの値
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionNetwork {
    /// トランザクションのハッシュに入る
    pub generation_hash_seed: GenerationHashSeed,
    /// 公開鍵からアドレスを求める
    pub identifier: NetworkIdentifier,
    /// モザイクの定義とネームスペースの登録で、catapult が関わったアドレスに入れる使用料の受け取り先。catapult は
    /// 高さを渡さずに集めるので、受け取り先が替わる前のもの（`HeightDependentAddress::at(0)`）
    pub mosaic_rental_fee_sink: [u8; 24],
    pub namespace_rental_fee_sink: [u8; 24],
}

impl TransactionNetwork {
    const SIZE: usize = 32 + 1 + 24 + 24;

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::SIZE);
        out.extend_from_slice(&self.generation_hash_seed.0);
        out.push(self.identifier.0);
        out.extend_from_slice(&self.mosaic_rental_fee_sink);
        out.extend_from_slice(&self.namespace_rental_fee_sink);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == Self::SIZE).then(|| Self {
            generation_hash_seed: GenerationHashSeed(bytes[..32].try_into().expect("32 バイト")),
            identifier: NetworkIdentifier(bytes[32]),
            mosaic_rental_fee_sink: bytes[33..57].try_into().expect("24 バイト"),
            namespace_rental_fee_sink: bytes[57..].try_into().expect("24 バイト"),
        })
    }
}

/// ブロックの中の1つのトランザクション（アグリゲートの中は除く）の、索引に入れるもの
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexedTransaction {
    /// ブロックの中の番号（0 から）
    pub index: u32,
    pub hash: Hash256,
    /// 関わったアドレス（[`involved_addresses`]）
    pub addresses: BTreeSet<[u8; 24]>,
}

/// ブロック `block` のトランザクションの、索引に入れるもの。読めないものは飛ばす
pub(crate) fn indexed_transactions(
    block: &[u8],
    network: &TransactionNetwork,
) -> Vec<IndexedTransaction> {
    let Ok(block) = heika_block::Block::from_bytes(block) else {
        return Vec::new();
    };
    block
        .transactions()
        .enumerate()
        .filter_map(|(index, bytes)| {
            let transaction = heika_transaction::Transaction::from_bytes(bytes).ok()?;
            Some(IndexedTransaction {
                index: index as u32,
                hash: transaction.hash(&network.generation_hash_seed),
                addresses: involved_addresses(&transaction, network),
            })
        })
        .collect()
}

/// トランザクションが関わったアドレス。catapult の `model::ExtractAddresses` と同じく、トランザクションが出す
/// アカウントの登録の通知（`AccountAddressNotification` と `AccountPublicKeyNotification`）のアドレスを、解決する前の
/// まま集める。署名者と、中身ごとに決まった相手。アグリゲートは中のトランザクションの署名者と相手も入り、連署者は
/// 入らない（catapult は連署者の通知を出さない）
pub(crate) fn involved_addresses(
    transaction: &heika_transaction::Transaction,
    network: &TransactionNetwork,
) -> BTreeSet<[u8; 24]> {
    let mut out = BTreeSet::new();
    let signer = |key: &PublicKey| Address::from_public_key(key, network.identifier).0;
    out.insert(signer(&transaction.signer_public_key));
    match &transaction.body {
        Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
            for embedded in aggregate.transactions() {
                out.insert(signer(&embedded.signer_public_key));
                body_addresses(&embedded.body, network, &mut out);
            }
        }
        body => body_addresses(body, network, &mut out),
    }
    out
}

/// 中身ごとの、アカウントの登録の通知を出す相手（catapult のそれぞれのトランザクションのプラグイン）
fn body_addresses(body: &Body, network: &TransactionNetwork, out: &mut BTreeSet<[u8; 24]>) {
    match body {
        Body::Transfer(transfer) => {
            out.insert(transfer.recipient_address().0);
        }
        Body::SecretLock(lock) => {
            out.insert(lock.recipient_address.0);
        }
        // モザイクとネームスペースのメタデータは、相手の通知を出さない
        Body::AccountMetadata(metadata) => {
            out.insert(metadata.target_address.0);
        }
        Body::MosaicSupplyRevocation(revocation) => {
            out.insert(revocation.source_address.0);
        }
        Body::MultisigAccountModification(modification) => {
            out.extend(
                modification
                    .address_additions
                    .iter()
                    .map(|address| address.0),
            );
        }
        Body::AccountKeyLink(link) if link.link_action == LinkAction::Link => {
            out.insert(Address::from_public_key(&link.linked_public_key, network.identifier).0);
        }
        Body::MosaicDefinition(_) => {
            out.insert(network.mosaic_rental_fee_sink);
        }
        Body::NamespaceRegistration(_) => {
            out.insert(network.namespace_rental_fee_sink);
        }
        _ => {}
    }
}

/// `addresses` のうちエイリアスのものを、ブロックのステートメントの解決から、このトランザクション（ブロックの中の
/// 番号 `index`）で使った先のアドレスにする。catapult の `AddressExtractor` の `AddResolvedAddresses` と同じく、
/// このトランザクションの解決と、その前に最後に解決した先（このトランザクションの最初の解決が中の
/// トランザクションのものなら）を足す
pub(crate) fn resolved_addresses(
    statement: &BlockStatement,
    index: u32,
    addresses: &BTreeSet<[u8; 24]>,
) -> BTreeSet<[u8; 24]> {
    // catapult のトランザクションの番号は 1 から
    let primary_id = index + 1;
    let mut out = BTreeSet::new();
    for resolution in &statement.address_resolution_statements {
        if !addresses.contains(&resolution.unresolved.0) {
            continue;
        }
        let mut add_previous = true;
        for entry in resolution.entries.iter().rev() {
            let source = entry.source;
            if primary_id < source.primary_id {
                continue;
            }
            if primary_id == source.primary_id {
                out.insert(entry.resolved.0);
                if source.secondary_id == 0 {
                    add_previous = false;
                }
                continue;
            }
            if add_previous {
                out.insert(entry.resolved.0);
            }
            break;
        }
    }
    out
}

/// アドレスの索引のキー。アドレス、高さ、ブロックの中の番号（ビッグエンディアン）
pub(crate) fn address_key(address: &[u8; 24], height: u64, index: u32) -> [u8; 36] {
    let mut key = [0; 36];
    key[..24].copy_from_slice(address);
    key[24..32].copy_from_slice(&height.to_be_bytes());
    key[32..].copy_from_slice(&index.to_be_bytes());
    key
}

/// ブロック `block` のネームスペースの登録（アグリゲートの中も）から、ID、親の ID（ルートは 0）、名前。
/// ID が親と名前から決まるものと合うものだけを返すので、どのブロックから拾っても名前の表は正しい
pub(crate) fn names_in_block(block: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
    let Ok(block) = heika_block::Block::from_bytes(block) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for transaction in block.transactions() {
        // 中身を読むのは、登録とアグリゲートだけ
        let Some(kind) = transaction.get(110..112) else {
            continue;
        };
        if !matches!(
            u16::from_le_bytes([kind[0], kind[1]]),
            0x414E | 0x4141 | 0x4241
        ) {
            continue;
        }
        let Ok(scanned) = heika_transaction::scan(transaction) else {
            continue;
        };
        for scanned in scanned {
            let Body::NamespaceRegistration(registration) = scanned.body else {
                continue;
            };
            let parent = match registration.registration_type {
                NamespaceRegistrationType::Root { .. } => None,
                NamespaceRegistrationType::Child { parent_id } => Some(parent_id),
            };
            if NamespaceId::generate(parent, &registration.name) == registration.id {
                names.push((
                    registration.id.0,
                    parent.map_or(0, |parent| parent.0),
                    registration.name.to_vec(),
                ));
            }
        }
    }
    names
}

/// 状態の行を前から読む。足りなければ `None`
struct RowReader<'a>(&'a [u8]);

impl<'a> RowReader<'a> {
    fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(size)?;
        self.0 = rest;
        Some(head)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn alias(&mut self) -> Option<Alias> {
        Some(match self.take(1)?[0] {
            0 => Alias::None,
            1 => Alias::Mosaic(self.u64()?),
            2 => Alias::Address(self.take(24)?.try_into().ok()?),
            _ => return None,
        })
    }
}

/// ネームスペースの検索表のキーの、ルートの ID とネームスペースの ID（最後の 16 バイト）
pub fn namespace_ids(key: &[u8]) -> Option<(u64, u64)> {
    match *key.first()? {
        NAMESPACE_BY_OWNER | NAMESPACE_BY_ADDRESS | NAMESPACE_BY_MOSAIC if key.len() >= 17 => {
            let tail = &key[key.len() - 16..];
            Some((
                u64::from_be_bytes(tail[..8].try_into().expect("8 bytes")),
                u64::from_be_bytes(tail[8..].try_into().expect("8 bytes")),
            ))
        }
        _ => None,
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

    /// 並べ方 `prefix`（[`METADATA_BY_SOURCE`] など）での、検索表のキー。ID は上位から書くので、キーの順は REST の16進の順と同じ
    pub fn search_key(&self, prefix: u8) -> Vec<u8> {
        let kind = [self.metadata_type];
        let (target_id, scoped_key) = (self.target_id.to_be_bytes(), self.scoped_key.to_be_bytes());
        let parts: [&[u8]; 5] = match prefix {
            METADATA_BY_SOURCE => [&self.source, &kind, &self.target, &target_id, &scoped_key],
            METADATA_BY_TARGET => [&self.target, &kind, &target_id, &scoped_key, &self.source],
            _ => [&kind, &target_id, &scoped_key, &self.target, &self.source],
        };
        let mut out = vec![prefix];
        for part in parts {
            out.extend_from_slice(part);
        }
        out
    }

    /// 検索表に入れるキー。対象からの並べ方は、モザイクとネームスペースのメタデータだけ
    pub fn search_keys(&self) -> Vec<Vec<u8>> {
        let mut prefixes = vec![METADATA_BY_SOURCE, METADATA_BY_TARGET];
        if self.metadata_type != 0 {
            prefixes.push(METADATA_BY_TARGET_ID);
        }
        prefixes
            .into_iter()
            .map(|prefix| self.search_key(prefix))
            .collect()
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
        NAMESPACE_BY_OWNER | NAMESPACE_BY_ADDRESS | NAMESPACE_BY_MOSAIC => {
            let (root, _) = namespace_ids(key)?;
            let mut row = vec![SubCache::Namespace.index() as u8];
            row.extend_from_slice(&root.to_le_bytes());
            Some(row)
        }
        _ => None,
    }
}

/// 検索表のキー `key` が、その状態の行の値 `value` から出るか。昔の高さの候補を確かめる
pub fn row_yields(key: &[u8], value: &[u8]) -> bool {
    let Some(row) = row_key_of(key) else {
        return false;
    };
    let all = Searches(Searches::METADATA.0 | Searches::NAMESPACES.0);
    keys_of(all, &row, Some(value))
        .iter()
        .any(|yielded| yielded == key)
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
        Some(&cache)
            if usize::from(cache) == SubCache::Namespace.index()
                && searches.contains(Searches::NAMESPACES) =>
        {
            let Ok(root) = <[u8; 8]>::try_from(&key[1..]).map(u64::from_le_bytes) else {
                return Vec::new();
            };
            NamespaceRow::from_row(root, value)
                .map(|row| row.search_keys(root))
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
    if searches.contains(Searches::NAMESPACES) {
        out.push(SubCache::Namespace.index() as u8);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
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

    /// ルート 0xA1（持ち主 0x68、別名なし）に、子 [0xB2]（アドレスの別名）と [0xB2, 0xC3]（モザイクの別名）
    pub(crate) fn namespace_row() -> Vec<u8> {
        let mut row = vec![0x68; 24];
        row.extend_from_slice(&1u64.to_le_bytes());
        row.extend_from_slice(&100u64.to_le_bytes());
        row.push(0);
        row.extend_from_slice(&2u64.to_le_bytes());
        row.push(1);
        row.extend_from_slice(&0xB2u64.to_le_bytes());
        row.push(2);
        row.extend_from_slice(&[0x69; 24]);
        row.push(2);
        row.extend_from_slice(&0xB2u64.to_le_bytes());
        row.extend_from_slice(&0xC3u64.to_le_bytes());
        row.push(1);
        row.extend_from_slice(&0x6BEDu64.to_le_bytes());
        row
    }

    #[test]
    fn reads_a_namespace_row_and_its_search_keys() {
        let row = NamespaceRow::from_row(0xA1, &namespace_row()).unwrap();
        assert_eq!(row.owner, [0x68; 24]);
        assert_eq!(row.end, 100);
        assert_eq!(
            row.entries,
            vec![
                (0xA1, Alias::None),
                (0xB2, Alias::Address([0x69; 24])),
                (0xC3, Alias::Mosaic(0x6BED))
            ]
        );
        assert_eq!(NamespaceRow::from_row(0xA1, &namespace_row()[1..]), None);

        let mut key = vec![SubCache::Namespace.index() as u8];
        key.extend_from_slice(&0xA1u64.to_le_bytes());
        let keys = keys_of(Searches::NAMESPACES, &key, Some(&namespace_row()));
        // 持ち主から3つ、アドレスとモザイクの別名から1つずつ
        assert_eq!(keys.len(), 5);
        let prefixes: Vec<u8> = keys.iter().map(|key| key[0]).collect();
        assert_eq!(
            prefixes
                .iter()
                .filter(|&&p| p == NAMESPACE_BY_OWNER)
                .count(),
            3
        );
        for search_key in &keys {
            assert_eq!(row_key_of(search_key), Some(key.clone()));
            assert_eq!(namespace_ids(search_key).unwrap().0, 0xA1);
            assert!(row_yields(search_key, &namespace_row()));
        }
        let mosaic = keys
            .iter()
            .find(|key| key[0] == NAMESPACE_BY_MOSAIC)
            .unwrap();
        assert_eq!(namespace_ids(mosaic), Some((0xA1, 0xC3)));
        // 別名が外れた行からは出ない
        let mut unaliased = namespace_row();
        let len = unaliased.len();
        unaliased.truncate(len - 9);
        unaliased.push(0);
        assert!(!row_yields(mosaic, &unaliased));
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

    /// 試しのネットワーク。受け取り先は 0xA1 と 0xA2 で埋めたもの
    pub(crate) fn test_network() -> TransactionNetwork {
        TransactionNetwork {
            generation_hash_seed: GenerationHashSeed([0x77; 32]),
            identifier: NetworkIdentifier::MAINNET,
            mosaic_rental_fee_sink: [0xA1; 24],
            namespace_rental_fee_sink: [0xA2; 24],
        }
    }

    fn address_of(key: u8) -> [u8; 24] {
        Address::from_public_key(&PublicKey([key; 32]), NetworkIdentifier::MAINNET).0
    }

    fn transaction(signer: u8, body: Body) -> heika_transaction::Transaction {
        heika_transaction::Transaction::new(
            PublicKey([signer; 32]),
            NetworkIdentifier::MAINNET,
            0,
            0,
            body,
        )
    }

    fn transfer_to(recipient: [u8; 24]) -> Body {
        Body::Transfer(
            heika_transaction::Transfer::new(
                heika_transaction::UnresolvedAddress(recipient),
                Default::default(),
                Vec::new(),
            )
            .unwrap(),
        )
    }

    fn metadata(target: [u8; 24]) -> heika_transaction::Metadata {
        heika_transaction::Metadata {
            target_address: heika_transaction::UnresolvedAddress(target),
            scoped_metadata_key: 1,
            value_size_delta: 0,
            value: Vec::new().try_into().unwrap(),
        }
    }

    #[test]
    fn involved_addresses_follow_catapult_notifications() {
        let network = test_network();
        let set = |addresses: &[[u8; 24]]| addresses.iter().copied().collect::<BTreeSet<_>>();
        // 署名者と宛先
        assert_eq!(
            involved_addresses(&transaction(0x11, transfer_to([0x55; 24])), &network),
            set(&[address_of(0x11), [0x55; 24]])
        );
        // アカウントのメタデータは宛先が入り、モザイクのメタデータは入らない
        let account = Body::AccountMetadata(metadata([0x56; 24]));
        assert_eq!(
            involved_addresses(&transaction(0x11, account), &network),
            set(&[address_of(0x11), [0x56; 24]])
        );
        let mosaic = Body::MosaicMetadata(heika_transaction::MosaicMetadata {
            target_mosaic_id: heika_transaction::UnresolvedMosaicId(1),
            metadata: metadata([0x56; 24]),
        });
        assert_eq!(
            involved_addresses(&transaction(0x11, mosaic), &network),
            set(&[address_of(0x11)])
        );
        // 紐づけは、つなぐときだけ相手の鍵のアドレスが入る
        let link = |link_action| {
            Body::AccountKeyLink(heika_transaction::KeyLink {
                linked_public_key: PublicKey([0x22; 32]),
                link_action,
            })
        };
        assert_eq!(
            involved_addresses(&transaction(0x11, link(LinkAction::Link)), &network),
            set(&[address_of(0x11), address_of(0x22)])
        );
        assert_eq!(
            involved_addresses(&transaction(0x11, link(LinkAction::Unlink)), &network),
            set(&[address_of(0x11)])
        );
        // モザイクの定義は、使用料の受け取り先が入る
        let definition = Body::MosaicDefinition(heika_transaction::MosaicDefinition {
            id: heika_transaction::MosaicId(1),
            duration: 0,
            nonce: 0,
            flags: heika_transaction::MosaicFlags::SUPPLY_MUTABLE,
            divisibility: 0,
        });
        assert_eq!(
            involved_addresses(&transaction(0x11, definition), &network),
            set(&[address_of(0x11), [0xA1; 24]])
        );
        // アグリゲートは中の署名者と相手が入り、連署者は入らない
        let mut aggregate =
            heika_transaction::Aggregate::new(vec![heika_transaction::EmbeddedTransaction::new(
                PublicKey([0x33; 32]),
                NetworkIdentifier::MAINNET,
                transfer_to([0x57; 24]),
            )])
            .unwrap();
        aggregate.add_cosignature(heika_transaction::Cosignature {
            signer_public_key: PublicKey([0x44; 32]),
            signature: heika_core::signature::Signature([0; 64]),
        });
        assert_eq!(
            involved_addresses(
                &transaction(0x11, Body::AggregateComplete(aggregate)),
                &network
            ),
            set(&[address_of(0x11), address_of(0x33), [0x57; 24]])
        );
    }

    #[test]
    fn resolved_addresses_follow_the_address_extractor() {
        use heika_block::statement::{
            AddressResolutionStatement, BlockStatement, ReceiptSource, ResolutionEntry,
        };
        let alias = [0x99; 24];
        let entry = |primary_id, secondary_id, resolved: u8| ResolutionEntry {
            source: ReceiptSource {
                primary_id,
                secondary_id,
            },
            resolved: Address([resolved; 24]),
        };
        // 1番目で A に、3番目の中の2つ目で B に、5番目で C に解決した
        let statement = BlockStatement {
            transaction_statements: Vec::new(),
            address_resolution_statements: vec![AddressResolutionStatement {
                unresolved: heika_transaction::UnresolvedAddress(alias),
                entries: vec![entry(1, 0, 0xA), entry(3, 2, 0xB), entry(5, 0, 0xC)],
            }],
            mosaic_resolution_statements: Vec::new(),
        };
        let used: BTreeSet<_> = [alias, [0x55; 24]].into_iter().collect();
        let resolved = |index| {
            resolved_addresses(&statement, index, &used)
                .into_iter()
                .map(|address| address[0])
                .collect::<Vec<_>>()
        };
        // 番号は 0 から。自分の解決がなければ、前に最後に解決した先
        assert_eq!(resolved(0), vec![0xA]);
        assert_eq!(resolved(1), vec![0xA]);
        // 中のトランザクションで解決したなら、その前の解決も
        assert_eq!(resolved(2), vec![0xA, 0xB]);
        assert_eq!(resolved(3), vec![0xB]);
        // トランザクションそのもので解決したなら、それだけ
        assert_eq!(resolved(4), vec![0xC]);
        assert_eq!(resolved(9), vec![0xC]);
        // エイリアスを使っていなければ足さない
        let plain: BTreeSet<_> = [[0x55; 24]].into_iter().collect();
        assert!(resolved_addresses(&statement, 4, &plain).is_empty());
    }
}
