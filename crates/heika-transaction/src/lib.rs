//! Symbol のトランザクション。catbuffer の `schemas/symbol` のレイアウトで読み書きし、
//! catapult と同じ範囲に署名して、同じ方法でハッシュを取る。

use std::fmt;

use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::signature::Signature;
use sha3::{Digest, Sha3_256};

mod aggregate;
mod bounded;
mod lock;
mod metadata;
mod mosaic;
mod multisig;
mod namespace;
mod restriction;
mod scan;
mod transfer;

pub use aggregate::{Aggregate, Cosignature, EmbeddedTransaction, NestedAggregate};
pub use bounded::{BoundedVec, TooLong};
pub use lock::{HashLock, LockHashAlgorithm, SecretLock, SecretProof};
pub use metadata::{Metadata, MosaicMetadata, NamespaceMetadata};
pub use mosaic::{
    MosaicDefinition, MosaicFlags, MosaicId, MosaicSupplyChange, MosaicSupplyChangeAction,
    MosaicSupplyRevocation, UnresolvedMosaic,
};
pub use multisig::MultisigAccountModification;
pub use namespace::{
    AddressAlias, AliasAction, MosaicAlias, NamespaceId, NamespaceRegistration,
    NamespaceRegistrationType,
};
pub use restriction::{
    AccountRestriction, AccountRestrictionFlags, MosaicAddressRestriction, MosaicGlobalRestriction,
    MosaicRestrictionType, TransactionType,
};
pub use scan::{ScanError, Scanned, scan};
pub use transfer::{Transfer, TransferError, UnresolvedAddress, UnresolvedMosaicId};

/// 署名とハッシュの対象から外れる先頭の部分。catapult の `VerifiableEntity::Header_Size`。
/// サイズ、予約、署名、署名者の公開鍵、予約の順に並ぶ。
const UNSIGNED_HEADER_SIZE: usize = 4 + 4 + 64 + 32 + 4;

/// 署名の対象になるヘッダーの部分。バージョン、ネットワーク、種類、手数料、期限。
const SIGNED_HEADER_SIZE: usize = 1 + 1 + 2 + 8 + 8;

const HEADER_SIZE: usize = UNSIGNED_HEADER_SIZE + SIGNED_HEADER_SIZE;

/// トランザクション。catbuffer の `Transaction` に、種類ごとの本体が続く。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    /// 署名者の署名。署名する前は、catapult の SDK と同じく0で埋めておく。
    pub signature: Signature,
    pub signer_public_key: PublicKey,
    pub network: NetworkIdentifier,
    /// 手数料。通貨のモザイクの最小単位で数える。
    pub fee: u64,
    /// 期限。ネットワークのエポックからのミリ秒。
    pub deadline: u64,
    pub body: Body,
}

/// 種類ごとの本体。catbuffer の `schemas/symbol` にある25種類。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Body {
    /// 重要度を預けるリモートアカウントの公開鍵を紐づける。リモートハーベストと委任ハーベストに使う。
    AccountKeyLink(KeyLink),
    /// TLS の接続に使うノードの公開鍵を紐づける。委任ハーベストに使う。
    NodeKeyLink(KeyLink),
    /// ファイナライズの投票に使う公開鍵を、エポックの範囲を決めて紐づける。
    VotingKeyLink(VotingKeyLink),
    /// ハーベストで使う VRF の公開鍵を紐づける。
    VrfKeyLink(KeyLink),
    HashLock(HashLock),
    SecretLock(SecretLock),
    SecretProof(SecretProof),
    AccountMetadata(Metadata),
    MosaicMetadata(MosaicMetadata),
    NamespaceMetadata(NamespaceMetadata),
    MosaicDefinition(MosaicDefinition),
    MosaicSupplyChange(MosaicSupplyChange),
    MosaicSupplyRevocation(MosaicSupplyRevocation),
    MultisigAccountModification(MultisigAccountModification),
    AddressAlias(AddressAlias),
    MosaicAlias(MosaicAlias),
    NamespaceRegistration(NamespaceRegistration),
    /// 送受信できる相手のアドレスを制限する。
    AccountAddressRestriction(AccountRestriction<UnresolvedAddress>),
    /// 受け取れるモザイクを制限する。
    AccountMosaicRestriction(AccountRestriction<UnresolvedMosaicId>),
    /// 送れるトランザクションの種類を制限する。
    AccountOperationRestriction(AccountRestriction<TransactionType>),
    MosaicAddressRestriction(MosaicAddressRestriction),
    MosaicGlobalRestriction(MosaicGlobalRestriction),
    /// モザイクとメッセージを送る。
    Transfer(Transfer),
    /// 必要な署名がそろっているアグリゲート。
    AggregateComplete(Aggregate),
    /// 連署を後から集めるアグリゲート。送る前に HashLock が要る。
    AggregateBonded(Aggregate),
}

/// 公開鍵を紐づける、または紐づけを外すトランザクションに共通の本体。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyLink {
    pub linked_public_key: PublicKey,
    pub link_action: LinkAction,
}

/// 投票の公開鍵を紐づける、または紐づけを外す本体。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VotingKeyLink {
    pub linked_public_key: PublicKey,
    /// 投票に使う最初のエポック
    pub start_epoch: u32,
    /// 投票に使う最後のエポック
    pub end_epoch: u32,
    pub link_action: LinkAction,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkAction {
    Unlink,
    Link,
}

impl LinkAction {
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
            action => Err(DecodeError::InvalidLinkAction(action)),
        }
    }
}

impl Transaction {
    /// 署名していないトランザクションを作る。署名は0で埋める。
    pub fn new(
        signer_public_key: PublicKey,
        network: NetworkIdentifier,
        fee: u64,
        deadline: u64,
        body: Body,
    ) -> Self {
        Self {
            signature: Signature([0; 64]),
            signer_public_key,
            network,
            fee,
            deadline,
            body,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        self.body.encode(&mut body);
        let size = HEADER_SIZE + body.len();
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.signature.0);
        bytes.extend_from_slice(&self.signer_public_key.0);
        bytes.extend_from_slice(&[0; 4]);
        bytes.push(self.body.version());
        bytes.push(self.network.0);
        bytes.extend_from_slice(&self.body.transaction_type().to_le_bytes());
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&self.deadline.to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// バイト列から読む。書き戻したときに同じバイト列にならないものは弾く。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_SIZE {
            return Err(DecodeError::TooShort);
        }
        let mut reader = Reader(bytes);
        let size = reader.u32();
        if size as usize != bytes.len() {
            return Err(DecodeError::SizeMismatch {
                stated: size,
                actual: bytes.len(),
            });
        }
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        let signature = Signature(reader.array());
        let signer_public_key = PublicKey(reader.array());
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        let version = reader.u8();
        let network = NetworkIdentifier(reader.u8());
        let transaction_type = reader.u16();
        let fee = reader.u64();
        let deadline = reader.u64();
        let body = Body::decode(transaction_type, version, reader.0)?;
        Ok(Self {
            signature,
            signer_public_key,
            network,
            fee,
            deadline,
            body,
        })
    }

    /// 署名する。署名者の公開鍵は署名の対象に含まれるので、秘密鍵と合っていなければ弾く。
    pub fn sign(
        &mut self,
        private_key: &PrivateKey,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<(), SignError> {
        if PublicKey::from_private_key(private_key) != self.signer_public_key {
            return Err(SignError::KeyMismatch);
        }
        let bytes = self.to_bytes();
        self.signature = private_key.sign(&[&generation_hash_seed.0, self.signed_part(&bytes)]);
        Ok(())
    }

    /// 署名を検証する。catapult の `SignatureValidator` と同じく、
    /// generation hash seed に続けて、署名の対象の部分に署名されていることを確かめる。
    pub fn verify(&self, generation_hash_seed: &GenerationHashSeed) -> bool {
        let bytes = self.to_bytes();
        self.signer_public_key.verify(
            &[&generation_hash_seed.0, self.signed_part(&bytes)],
            &self.signature,
        )
    }

    /// 署名とハッシュの対象。catapult の `TransactionPlugin::dataBuffer`。
    ///
    /// ふつうはヘッダーの後半から最後まで。アグリゲートは、中のトランザクションのハッシュとそれらの長さまでで、
    /// 後ろの予約の4バイト（catapult の `Footer_Size`）と、中のトランザクションと連署は含まない。
    /// 中のトランザクションは、そのハッシュを通して署名される。
    fn signed_part<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        match self.body {
            Body::AggregateComplete(_) | Body::AggregateBonded(_) => {
                &bytes[UNSIGNED_HEADER_SIZE..HEADER_SIZE + aggregate::FIXED_SIZE - 4]
            }
            _ => &bytes[UNSIGNED_HEADER_SIZE..],
        }
    }

    /// ハッシュ。catapult の `model/EntityHasher.cpp` と同じく、署名を丸ごとと署名者の公開鍵、
    /// generation hash seed、署名の対象の部分を続けた SHA3-256。
    pub fn hash(&self, generation_hash_seed: &GenerationHashSeed) -> Hash256 {
        let bytes = self.to_bytes();
        let mut hasher = Sha3_256::new();
        hasher.update(self.signature.0);
        hasher.update(self.signer_public_key.0);
        hasher.update(generation_hash_seed.0);
        hasher.update(self.signed_part(&bytes));
        Hash256(hasher.finalize().into())
    }

    /// アグリゲートに `private_key` の連署を足す。
    ///
    /// 連署するのは外側の署名を含むハッシュなので、先に署名されていなければならない。
    /// catapult の `BasicAggregateCosignaturesValidator` と同じく、外側の署名者やすでに連署した鍵の連署は弾く。
    /// 誰の連署が要るかはマルチシグの設定で決まるので、ここでは確かめない。
    pub fn cosign(
        &mut self,
        private_key: &PrivateKey,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<(), CosignError> {
        if !Body::is_aggregate_type(self.body.transaction_type()) {
            return Err(CosignError::NotAggregate);
        }
        if self.signature == Signature([0; 64]) {
            return Err(CosignError::NotSigned);
        }
        let hash = self.hash(generation_hash_seed);
        let public_key = PublicKey::from_private_key(private_key);
        let signer_public_key = self.signer_public_key;
        let (Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate)) =
            &mut self.body
        else {
            unreachable!("the type is an aggregate");
        };
        if public_key == signer_public_key
            || aggregate
                .cosignatures()
                .iter()
                .any(|cosignature| cosignature.signer_public_key == public_key)
        {
            return Err(CosignError::Redundant);
        }
        aggregate.add_cosignature(Cosignature::sign(private_key, &hash));
        Ok(())
    }

    /// 連署をすべて検証する。アグリゲートでなければ連署はないので `true`。
    pub fn verify_cosignatures(&self, generation_hash_seed: &GenerationHashSeed) -> bool {
        let (Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate)) = &self.body
        else {
            return true;
        };
        let hash = self.hash(generation_hash_seed);
        aggregate
            .cosignatures()
            .iter()
            .all(|cosignature| cosignature.verify(&hash))
    }
}

impl Body {
    /// catbuffer の `TransactionType`。
    pub fn transaction_type(&self) -> u16 {
        match self {
            Self::AccountKeyLink(_) => 0x414C,
            Self::NodeKeyLink(_) => 0x424C,
            Self::VotingKeyLink(_) => 0x4143,
            Self::VrfKeyLink(_) => 0x4243,
            Self::HashLock(_) => 0x4148,
            Self::SecretLock(_) => 0x4152,
            Self::SecretProof(_) => 0x4252,
            Self::AccountMetadata(_) => 0x4144,
            Self::MosaicMetadata(_) => 0x4244,
            Self::NamespaceMetadata(_) => 0x4344,
            Self::MosaicDefinition(_) => 0x414D,
            Self::MosaicSupplyChange(_) => 0x424D,
            Self::MosaicSupplyRevocation(_) => 0x434D,
            Self::MultisigAccountModification(_) => 0x4155,
            Self::AddressAlias(_) => 0x424E,
            Self::MosaicAlias(_) => 0x434E,
            Self::NamespaceRegistration(_) => 0x414E,
            Self::AccountAddressRestriction(_) => 0x4150,
            Self::AccountMosaicRestriction(_) => 0x4250,
            Self::AccountOperationRestriction(_) => 0x4350,
            Self::MosaicAddressRestriction(_) => 0x4251,
            Self::MosaicGlobalRestriction(_) => 0x4151,
            Self::Transfer(_) => 0x4154,
            Self::AggregateComplete(_) => 0x4141,
            Self::AggregateBonded(_) => 0x4241,
        }
    }

    /// 種類ごとの構造のバージョン。どれも catbuffer の最新のものを書く。
    /// アグリゲートはバージョン 3 で、メインネットでは高さ 4,759,100 から、それより前のバージョンは使えない。
    /// ほかの種類は、どれもバージョン 1 しかない。
    pub fn version(&self) -> u8 {
        match self {
            Self::AggregateComplete(_) | Self::AggregateBonded(_) => 3,
            _ => 1,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::AccountKeyLink(link) | Self::NodeKeyLink(link) | Self::VrfKeyLink(link) => {
                link.encode(out)
            }
            Self::VotingKeyLink(link) => link.encode(out),
            Self::HashLock(lock) => lock.encode(out),
            Self::SecretLock(lock) => lock.encode(out),
            Self::SecretProof(proof) => proof.encode(out),
            Self::AccountMetadata(metadata) => metadata.encode(None, out),
            Self::MosaicMetadata(metadata) => metadata.encode(out),
            Self::NamespaceMetadata(metadata) => metadata.encode(out),
            Self::MosaicDefinition(definition) => definition.encode(out),
            Self::MosaicSupplyChange(change) => change.encode(out),
            Self::MosaicSupplyRevocation(revocation) => revocation.encode(out),
            Self::MultisigAccountModification(modification) => modification.encode(out),
            Self::AddressAlias(alias) => alias.encode(out),
            Self::MosaicAlias(alias) => alias.encode(out),
            Self::NamespaceRegistration(registration) => registration.encode(out),
            Self::AccountAddressRestriction(restriction) => restriction.encode(out),
            Self::AccountMosaicRestriction(restriction) => restriction.encode(out),
            Self::AccountOperationRestriction(restriction) => restriction.encode(out),
            Self::MosaicAddressRestriction(restriction) => restriction.encode(out),
            Self::MosaicGlobalRestriction(restriction) => restriction.encode(out),
            Self::Transfer(transfer) => transfer.encode(out),
            Self::AggregateComplete(aggregate) | Self::AggregateBonded(aggregate) => {
                aggregate.encode(out)
            }
        }
    }

    /// 種類とバージョンの組が catbuffer にあるか。中身の形はわかっても、Body として読めるとは限らない
    /// （アグリゲートのバージョン 1 と 2 は、読めるのは走査だけ）。
    pub(crate) fn is_known(transaction_type: u16, version: u8) -> bool {
        if Self::is_aggregate_type(transaction_type) {
            (1..=3).contains(&version)
        } else {
            version == 1 && Self::is_version_1_type(transaction_type)
        }
    }

    /// アグリゲート以外の23種類。どれもバージョン 1 だけがある。
    /// catbuffer の `schemas/symbol/transaction_type.cats` と、各スキーマの `TRANSACTION_VERSION` から書き起こした
    /// （symbol/symbol のコミット dbff03b4096622d1bc1fce611358e05cfa7b0296）
    fn is_version_1_type(transaction_type: u16) -> bool {
        matches!(
            transaction_type,
            0x414C
                | 0x424C
                | 0x4143
                | 0x4243
                | 0x4148
                | 0x4152
                | 0x4252
                | 0x4144
                | 0x4244
                | 0x4344
                | 0x414D
                | 0x424D
                | 0x434D
                | 0x4155
                | 0x424E
                | 0x434E
                | 0x414E
                | 0x4150
                | 0x4250
                | 0x4350
                | 0x4251
                | 0x4151
                | 0x4154
        )
    }

    fn decode(transaction_type: u16, version: u8, bytes: &[u8]) -> Result<Self, DecodeError> {
        let expected_version = if Self::is_aggregate_type(transaction_type) {
            3
        } else if Self::is_version_1_type(transaction_type) {
            1
        } else {
            return Err(DecodeError::UnknownType(transaction_type));
        };
        if version != expected_version {
            return Err(DecodeError::UnsupportedVersion {
                transaction_type,
                version,
            });
        }
        Ok(match transaction_type {
            0x414C => Self::AccountKeyLink(KeyLink::decode(bytes)?),
            0x424C => Self::NodeKeyLink(KeyLink::decode(bytes)?),
            0x4143 => Self::VotingKeyLink(VotingKeyLink::decode(bytes)?),
            0x4243 => Self::VrfKeyLink(KeyLink::decode(bytes)?),
            0x4148 => Self::HashLock(HashLock::decode(bytes)?),
            0x4152 => Self::SecretLock(SecretLock::decode(bytes)?),
            0x4252 => Self::SecretProof(SecretProof::decode(bytes)?),
            0x4144 => Self::AccountMetadata(Metadata::decode(bytes, false)?.0),
            0x4244 => Self::MosaicMetadata(MosaicMetadata::decode(bytes)?),
            0x4344 => Self::NamespaceMetadata(NamespaceMetadata::decode(bytes)?),
            0x414D => Self::MosaicDefinition(MosaicDefinition::decode(bytes)?),
            0x424D => Self::MosaicSupplyChange(MosaicSupplyChange::decode(bytes)?),
            0x434D => Self::MosaicSupplyRevocation(MosaicSupplyRevocation::decode(bytes)?),
            0x4155 => {
                Self::MultisigAccountModification(MultisigAccountModification::decode(bytes)?)
            }
            0x424E => Self::AddressAlias(AddressAlias::decode(bytes)?),
            0x434E => Self::MosaicAlias(MosaicAlias::decode(bytes)?),
            0x414E => Self::NamespaceRegistration(NamespaceRegistration::decode(bytes)?),
            0x4150 => Self::AccountAddressRestriction(AccountRestriction::decode(bytes)?),
            0x4250 => Self::AccountMosaicRestriction(AccountRestriction::decode(bytes)?),
            0x4350 => Self::AccountOperationRestriction(AccountRestriction::decode(bytes)?),
            0x4251 => Self::MosaicAddressRestriction(MosaicAddressRestriction::decode(bytes)?),
            0x4151 => Self::MosaicGlobalRestriction(MosaicGlobalRestriction::decode(bytes)?),
            0x4154 => Self::Transfer(Transfer::decode(bytes)?),
            0x4141 => Self::AggregateComplete(Aggregate::decode(bytes)?),
            _ => Self::AggregateBonded(Aggregate::decode(bytes)?),
        })
    }

    fn is_aggregate_type(transaction_type: u16) -> bool {
        matches!(transaction_type, 0x4141 | 0x4241)
    }
}

impl KeyLink {
    const SIZE: usize = 32 + 1;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.linked_public_key.0);
        out.push(self.link_action.to_byte());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            linked_public_key: PublicKey(reader.array()),
            link_action: LinkAction::from_byte(reader.u8())?,
        })
    }
}

impl VotingKeyLink {
    const SIZE: usize = 32 + 4 + 4 + 1;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.linked_public_key.0);
        out.extend_from_slice(&self.start_epoch.to_le_bytes());
        out.extend_from_slice(&self.end_epoch.to_le_bytes());
        out.push(self.link_action.to_byte());
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::exact(bytes, Self::SIZE)?;
        Ok(Self {
            linked_public_key: PublicKey(reader.array()),
            start_epoch: reader.u32(),
            end_epoch: reader.u32(),
            link_action: LinkAction::from_byte(reader.u8())?,
        })
    }
}

/// 長さを確かめ終えたバイト列を、先頭から順に読む。
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// 長さがちょうど `size` のときだけ読む
    fn exact(bytes: &'a [u8], size: usize) -> Result<Self, DecodeError> {
        if bytes.len() != size {
            return Err(DecodeError::InvalidBodySize);
        }
        Ok(Self(bytes))
    }

    /// 長さが `size` 以上のときだけ読む。残りは [`Reader::rest`] か [`Reader::expect_remaining`] で確かめる
    fn at_least(bytes: &'a [u8], size: usize) -> Result<Self, DecodeError> {
        if bytes.len() < size {
            return Err(DecodeError::InvalidBodySize);
        }
        Ok(Self(bytes))
    }

    /// 残りがちょうど `size` か
    fn expect_remaining(&self, size: usize) -> Result<(), DecodeError> {
        if self.0.len() != size {
            return Err(DecodeError::InvalidBodySize);
        }
        Ok(())
    }

    /// 残りがちょうど `size` なら、残りを全部返す
    fn rest(&mut self, size: usize) -> Result<&'a [u8], DecodeError> {
        self.expect_remaining(size)?;
        Ok(std::mem::take(&mut self.0))
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let (head, rest) = self.0.split_first_chunk().expect("length checked");
        self.0 = rest;
        *head
    }

    fn u8(&mut self) -> u8 {
        u8::from_le_bytes(self.array())
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    fn i16(&mut self) -> i16 {
        i16::from_le_bytes(self.array())
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// ヘッダーの長さに足りない
    TooShort,
    /// 先頭のサイズが、実際の長さと合わない
    SizeMismatch { stated: u32, actual: usize },
    /// 予約の部分が0ではない
    NonZeroReserved,
    /// 扱えない種類
    UnknownType(u16),
    /// 扱えないバージョン
    UnsupportedVersion { transaction_type: u16, version: u8 },
    /// 本体の長さが、種類に合わない
    InvalidBodySize,
    /// 紐づけの操作が、紐づけるか外すかのどちらでもない
    InvalidLinkAction(u8),
    /// 列挙型かフラグの値が、定義されていない
    InvalidValue { field: &'static str, value: u64 },
    /// モザイクが ID の昇順に並んでいない。同じ ID が2回出てくるものも含む
    UnsortedMosaics,
    /// アグリゲートの中にアグリゲートが入っている
    NestedAggregate,
    /// アグリゲートの中のトランザクションのハッシュが、中身と合わない
    TransactionsHashMismatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("トランザクションのヘッダーの長さに足りません"),
            Self::SizeMismatch { stated, actual } => write!(
                f,
                "サイズは {stated} バイトとありますが、実際は {actual} バイトでした"
            ),
            Self::NonZeroReserved => f.write_str("予約の部分が0ではありません"),
            Self::UnknownType(transaction_type) => {
                write!(
                    f,
                    "種類 0x{transaction_type:04X} のトランザクションは扱えません"
                )
            }
            Self::UnsupportedVersion {
                transaction_type,
                version,
            } => write!(
                f,
                "種類 0x{transaction_type:04X} のバージョン {version} は扱えません"
            ),
            Self::InvalidBodySize => f.write_str("本体の長さが種類に合いません"),
            Self::InvalidLinkAction(action) => {
                write!(
                    f,
                    "紐づけの操作 {action} は、紐づけるか外すかのどちらでもありません"
                )
            }
            Self::InvalidValue { field, value } => {
                write!(f, "{field}の値 {value} は定義されていません")
            }
            Self::UnsortedMosaics => f.write_str("モザイクが ID の昇順に並んでいません"),
            Self::NestedAggregate => f.write_str("アグリゲートの中にアグリゲートが入っています"),
            Self::TransactionsHashMismatch => {
                f.write_str("アグリゲートの中のトランザクションのハッシュが、中身と合いません")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// 秘密鍵が、署名者の公開鍵と合わない
    KeyMismatch,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMismatch => f.write_str("秘密鍵が署名者の公開鍵と合いません"),
        }
    }
}

impl std::error::Error for SignError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignError {
    /// アグリゲートではない
    NotAggregate,
    /// 外側の署名がまだない
    NotSigned,
    /// 外側の署名者か、すでに連署した鍵
    Redundant,
}

impl fmt::Display for CosignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAggregate => f.write_str("アグリゲートではないので連署できません"),
            Self::NotSigned => f.write_str("まだ署名されていないので連署できません"),
            Self::Redundant => {
                f.write_str("この鍵は署名者か、すでに連署しているので、連署を重ねられません")
            }
        }
    }
}

impl std::error::Error for CosignError {}

/// 種類ごとのモジュールのテストで使う。
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// `body` を入れたトランザクションを書いて読み戻し、同じ本体になることを確かめる。返すのは本体のバイト列
    pub fn round_trip(body: Body) -> Vec<u8> {
        let transaction = Transaction::new(
            PublicKey([0x11; 32]),
            NetworkIdentifier::TESTNET,
            0,
            0,
            body,
        );
        let bytes = transaction.to_bytes();
        assert_eq!(Transaction::from_bytes(&bytes).as_ref(), Ok(&transaction));
        bytes[HEADER_SIZE..].to_vec()
    }

    /// 本体のバイト列を、バージョン 1 の種類 `transaction_type` として読む
    pub fn decode(transaction_type: u16, body: &[u8]) -> Result<Body, DecodeError> {
        Body::decode(transaction_type, 1, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1
    const PRIVATE: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";

    fn private_key() -> PrivateKey {
        PRIVATE.parse().unwrap()
    }

    fn seed() -> GenerationHashSeed {
        GenerationHashSeed([0x5E; 32])
    }

    fn transaction(body: Body) -> Transaction {
        Transaction::new(
            PublicKey::from_private_key(&private_key()),
            NetworkIdentifier::TESTNET,
            0x0807_0605_0403_0201,
            0x1817_1615_1413_1211,
            body,
        )
    }

    fn vrf_key_link() -> Transaction {
        transaction(Body::VrfKeyLink(KeyLink {
            linked_public_key: PublicKey([0xAA; 32]),
            link_action: LinkAction::Link,
        }))
    }

    #[test]
    fn writes_the_catbuffer_layout() {
        let bytes = vrf_key_link().to_bytes();
        assert_eq!(bytes.len(), 161);
        assert_eq!(bytes[..8], [0xA1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bytes[8..72], [0; 64]);
        assert_eq!(
            bytes[72..104],
            PublicKey::from_private_key(&private_key()).0
        );
        assert_eq!(bytes[104..108], [0; 4]);
        assert_eq!(bytes[108..112], [0x01, 0x98, 0x43, 0x42]);
        assert_eq!(bytes[112..120], [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            bytes[120..128],
            [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
        assert_eq!(bytes[128..160], [0xAA; 32]);
        assert_eq!(bytes[160], 1);
    }

    #[test]
    fn round_trips_every_key_link() {
        let link = KeyLink {
            linked_public_key: PublicKey([0xAA; 32]),
            link_action: LinkAction::Unlink,
        };
        for (body, transaction_type) in [
            (Body::AccountKeyLink(link), [0x4C, 0x41]),
            (Body::NodeKeyLink(link), [0x4C, 0x42]),
            (Body::VrfKeyLink(link), [0x43, 0x42]),
        ] {
            let transaction = transaction(body);
            let bytes = transaction.to_bytes();
            assert_eq!(bytes[110..112], transaction_type);
            assert_eq!(bytes[160], 0);
            assert_eq!(Transaction::from_bytes(&bytes), Ok(transaction));
        }
    }

    #[test]
    fn writes_the_epochs_of_a_voting_key_link() {
        let link = VotingKeyLink {
            linked_public_key: PublicKey([0xAA; 32]),
            start_epoch: 0x0102,
            end_epoch: 0x0304,
            link_action: LinkAction::Link,
        };
        let transaction = transaction(Body::VotingKeyLink(link));
        let bytes = transaction.to_bytes();
        assert_eq!(bytes[110..112], [0x43, 0x41]);
        assert_eq!(bytes[HEADER_SIZE + 32..], [2, 1, 0, 0, 4, 3, 0, 0, 1]);
        assert_eq!(Transaction::from_bytes(&bytes), Ok(transaction));
    }

    #[test]
    fn rejects_a_short_header() {
        let bytes = vrf_key_link().to_bytes();
        assert_eq!(
            Transaction::from_bytes(&bytes[..HEADER_SIZE - 1]),
            Err(DecodeError::TooShort)
        );
    }

    #[test]
    fn rejects_a_wrong_size() {
        let mut bytes = vrf_key_link().to_bytes();
        bytes[0] = 0xA0;
        assert_eq!(
            Transaction::from_bytes(&bytes),
            Err(DecodeError::SizeMismatch {
                stated: 160,
                actual: 161
            })
        );
    }

    #[test]
    fn rejects_non_zero_reserved_bytes() {
        for offset in [4, 104] {
            let mut bytes = vrf_key_link().to_bytes();
            bytes[offset] = 1;
            assert_eq!(
                Transaction::from_bytes(&bytes),
                Err(DecodeError::NonZeroReserved),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_type() {
        let mut bytes = vrf_key_link().to_bytes();
        bytes[110..112].copy_from_slice(&0x4999u16.to_le_bytes());
        assert_eq!(
            Transaction::from_bytes(&bytes),
            Err(DecodeError::UnknownType(0x4999))
        );
    }

    #[test]
    fn rejects_an_unsupported_version() {
        let mut bytes = vrf_key_link().to_bytes();
        bytes[108] = 2;
        assert_eq!(
            Transaction::from_bytes(&bytes),
            Err(DecodeError::UnsupportedVersion {
                transaction_type: 0x4243,
                version: 2
            })
        );
    }

    #[test]
    fn rejects_a_body_of_the_wrong_size() {
        let mut bytes = vrf_key_link().to_bytes();
        bytes.push(0);
        bytes[0] = 162;
        assert_eq!(
            Transaction::from_bytes(&bytes),
            Err(DecodeError::InvalidBodySize)
        );
    }

    #[test]
    fn rejects_an_unknown_link_action() {
        let mut bytes = vrf_key_link().to_bytes();
        bytes[160] = 2;
        assert_eq!(
            Transaction::from_bytes(&bytes),
            Err(DecodeError::InvalidLinkAction(2))
        );
    }

    #[test]
    fn signs_the_seed_and_the_signed_part() {
        let mut transaction = vrf_key_link();
        transaction.sign(&private_key(), &seed()).unwrap();
        let bytes = transaction.to_bytes();
        let signature = private_key().sign(&[&seed().0, &bytes[108..]]);
        assert_eq!(transaction.signature, signature);
        assert!(transaction.verify(&seed()));
    }

    #[test]
    fn rejects_another_network_or_a_changed_field() {
        let mut transaction = vrf_key_link();
        transaction.sign(&private_key(), &seed()).unwrap();
        assert!(!transaction.verify(&GenerationHashSeed([0; 32])));
        let mut changed = transaction.clone();
        changed.fee += 1;
        assert!(!changed.verify(&seed()));
    }

    #[test]
    fn refuses_to_sign_with_another_key() {
        let mut transaction = vrf_key_link();
        let other = PrivateKey::from_bytes(&[1; 32]);
        assert_eq!(
            transaction.sign(&other, &seed()),
            Err(SignError::KeyMismatch)
        );
        assert_eq!(transaction.signature, Signature([0; 64]));
    }

    #[test]
    fn hashes_the_signature_the_signer_the_seed_and_the_signed_part() {
        let mut transaction = vrf_key_link();
        transaction.sign(&private_key(), &seed()).unwrap();
        let bytes = transaction.to_bytes();
        let mut hasher = Sha3_256::new();
        hasher.update(&bytes[8..104]);
        hasher.update(seed().0);
        hasher.update(&bytes[108..]);
        let expected = Hash256(hasher.finalize().into());
        assert_eq!(transaction.hash(&seed()), expected);
        assert_ne!(transaction.hash(&GenerationHashSeed([0; 32])), expected);
    }

    fn aggregate_complete() -> Transaction {
        let cosigner = PublicKey::from_private_key(&cosigner_key());
        let embedded = vrf_key_link().body;
        let aggregate = Aggregate::new(vec![EmbeddedTransaction::new(
            cosigner,
            NetworkIdentifier::TESTNET,
            embedded,
        )])
        .unwrap();
        transaction(Body::AggregateComplete(aggregate))
    }

    fn cosigner_key() -> PrivateKey {
        PrivateKey::from_bytes(&[7; 32])
    }

    #[test]
    fn cosigns_the_hash_of_a_signed_aggregate() {
        let mut transaction = aggregate_complete();
        transaction.sign(&private_key(), &seed()).unwrap();
        let hash = transaction.hash(&seed());
        transaction.cosign(&cosigner_key(), &seed()).unwrap();
        assert_eq!(transaction.hash(&seed()), hash);
        let Body::AggregateComplete(aggregate) = &transaction.body else {
            unreachable!()
        };
        assert_eq!(
            aggregate.cosignatures(),
            [Cosignature::sign(&cosigner_key(), &hash)]
        );
        assert!(transaction.verify_cosignatures(&seed()));
        assert!(!transaction.verify_cosignatures(&GenerationHashSeed([0; 32])));
    }

    #[test]
    fn refuses_to_cosign_an_unsigned_or_non_aggregate_transaction() {
        assert_eq!(
            aggregate_complete().cosign(&cosigner_key(), &seed()),
            Err(CosignError::NotSigned)
        );
        let mut transaction = vrf_key_link();
        transaction.sign(&private_key(), &seed()).unwrap();
        assert_eq!(
            transaction.cosign(&cosigner_key(), &seed()),
            Err(CosignError::NotAggregate)
        );
        assert!(transaction.verify_cosignatures(&seed()));
    }

    #[test]
    fn refuses_a_redundant_cosignature() {
        let mut transaction = aggregate_complete();
        transaction.sign(&private_key(), &seed()).unwrap();
        assert_eq!(
            transaction.cosign(&private_key(), &seed()),
            Err(CosignError::Redundant)
        );
        transaction.cosign(&cosigner_key(), &seed()).unwrap();
        assert_eq!(
            transaction.cosign(&cosigner_key(), &seed()),
            Err(CosignError::Redundant)
        );
    }
}
