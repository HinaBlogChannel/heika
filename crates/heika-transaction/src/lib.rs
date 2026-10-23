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
mod validate;

pub use aggregate::{
    Aggregate, AggregateVersion, Cosignature, DetachedCosignature, EmbeddedTransaction,
    NestedAggregate, TransactionsHashCalculation,
};
pub use bounded::{BoundedVec, TooLong};
pub use lock::{HashLock, LockHashAlgorithm, SecretLock, SecretProof, secret_lock_key};
pub use metadata::{
    Metadata, MetadataKey, MetadataType, MosaicMetadata, NamespaceMetadata, metadata_value_update,
    scoped_metadata_key,
};
pub use mosaic::{
    MosaicDefinition, MosaicFlags, MosaicId, MosaicSupplyChange, MosaicSupplyChangeAction,
    MosaicSupplyRevocation, UnresolvedMosaic,
};
pub use multisig::MultisigAccountModification;
pub use namespace::{
    AddressAlias, AliasAction, InvalidNamespaceName, MosaicAlias, NamespaceId,
    NamespaceRegistration, NamespaceRegistrationType, is_valid_namespace_name,
};
pub use restriction::{
    AccountRestriction, AccountRestrictionFlags, MosaicAddressRestriction, MosaicGlobalRestriction,
    MosaicRestrictionType, TransactionType, mosaic_restriction_entry_key, mosaic_restriction_key,
};
pub use scan::{ScanError, Scanned, scan};
pub use transfer::{Transfer, TransferError, UnresolvedAddress, UnresolvedMosaicId};
pub use validate::{Failure, Location, Problem};

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
    /// ヘッダーの2つの予約の部分。catapult は確かめず、署名にもハッシュにも入らないので、0 でなくてもブロックに
    /// 入りうる。書き戻して同じバイト列になるように、読んだ値を持っておく
    reserved: [u32; 2],
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
            reserved: [0; 2],
        }
    }

    /// バイト数。アグリゲートなら、今付いている連署も数える。
    pub fn size(&self) -> usize {
        self.to_bytes().len()
    }

    /// 手数料の倍率 `fee_multiplier` で、ブロックに入れてもらうのに要る手数料。
    /// catapult の `CalculateTransactionFee` と同じく、バイト数に倍率を掛けたもの。
    ///
    /// アグリゲートにこれから連署が付くなら、その数を `cosignature_count` に渡す。連署1つで104バイト増え、
    /// ノードは連署の付いたあとのバイト数で手数料を確かめる。公式の SDK の `calculate_transaction_fee` と同じ。
    pub fn fee_for(&self, fee_multiplier: u32, cosignature_count: usize) -> u64 {
        let size =
            self.size() as u64 + aggregate::COSIGNATURE_SIZE as u64 * cosignature_count as u64;
        size.saturating_mul(fee_multiplier.into())
    }

    /// 手数料から、ブロックに入れてもらえる倍率の上限を求める。catapult の `CalculateTransactionMaxFeeMultiplier`。
    /// ハーベストする人は、ブロックの倍率がこれ以下のときだけ、このトランザクションを入れられる。
    pub fn max_fee_multiplier(&self) -> u32 {
        u32::try_from(self.fee / self.size() as u64).unwrap_or(u32::MAX)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        self.body.encode(&mut body);
        let size = HEADER_SIZE + body.len();
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes.extend_from_slice(&self.reserved[0].to_le_bytes());
        bytes.extend_from_slice(&self.signature.0);
        bytes.extend_from_slice(&self.signer_public_key.0);
        bytes.extend_from_slice(&self.reserved[1].to_le_bytes());
        bytes.push(self.body.version());
        bytes.push(self.network.0);
        bytes.extend_from_slice(&self.body.transaction_type().to_le_bytes());
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&self.deadline.to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// バイト列から読む。書き戻したときに同じバイト列にならないものは弾く。
    /// catapult が確かめない予約の部分は、0 でなくても読み、その値のまま書き戻す。
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
        let reserved_before = reader.u32();
        let signature = Signature(reader.array());
        let signer_public_key = PublicKey(reader.array());
        let reserved = [reserved_before, reader.u32()];
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
            reserved,
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

    /// 署名するバイト列。generation hash seed に、署名の対象の部分を続けたもの。公式の SDK の `extract_signing_payload`。
    /// 秘密鍵を別の場所（ハードウェアや別のプロセス）に置いて署名するときは、これを Ed25519 で署名して
    /// [`Transaction::attach_signature`] で付ける。
    pub fn signing_payload(&self, generation_hash_seed: &GenerationHashSeed) -> Vec<u8> {
        let bytes = self.to_bytes();
        [&generation_hash_seed.0[..], self.signed_part(&bytes)].concat()
    }

    /// 別の場所で作った署名を付ける。公式の SDK の `attach_signature` と違い、署名者の公開鍵で
    /// 検証できない署名は付けない。
    pub fn attach_signature(
        &mut self,
        signature: Signature,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<(), SignError> {
        let mut signed = self.clone();
        signed.signature = signature;
        if !signed.verify(generation_hash_seed) {
            return Err(SignError::InvalidSignature);
        }
        self.signature = signature;
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
    /// ふつうはヘッダーの後半から最後まで。アグリゲートは、中のトランザクションのハッシュまでか
    /// （バージョン 2 まで）、それらの長さまで（バージョン 3）で、後ろの予約など（catapult の `Footer_Size`）と、
    /// 中のトランザクションと連署は含まない。中のトランザクションは、そのハッシュを通して署名される。
    fn signed_part<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        match &self.body {
            Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
                let end = HEADER_SIZE + aggregate::FIXED_SIZE - aggregate.version().footer_size();
                &bytes[UNSIGNED_HEADER_SIZE..end]
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

    /// ブロックの TransactionsHash の葉。catapult の `CalculateMerkleComponentHash`。
    ///
    /// ふつうはハッシュそのもの。アグリゲートは、ハッシュに連署者の公開鍵を並んだ順に続けた SHA3-256
    /// （aggregate プラグインの `merkleSupplementaryBuffers`）。連署はハッシュに入らないので、
    /// ブロックはこちらで連署の取り違えを防ぐ。
    ///
    /// Nemesis のブロックだけは、ヘッダーの TransactionsHash をこの値ではなく、トランザクションを丸ごとハッシュした葉で作っている。
    /// Nemesis では heika-block の `Block::merkle_leaves` を使う。
    pub fn merkle_component_hash(&self, generation_hash_seed: &GenerationHashSeed) -> Hash256 {
        let hash = self.hash(generation_hash_seed);
        let (Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate)) = &self.body
        else {
            return hash;
        };
        if aggregate.cosignatures().is_empty() {
            return hash;
        }
        let mut hasher = Sha3_256::new();
        hasher.update(hash.0);
        for cosignature in aggregate.cosignatures() {
            hasher.update(cosignature.signer_public_key.0);
        }
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
        let hash = self.hash_to_cosign(generation_hash_seed)?;
        self.add_cosignature(Cosignature::sign(private_key, &hash))
    }

    /// 切り離して集めた連署を、アグリゲートに付ける。[`Transaction::cosign`] と同じものを弾くほか、
    /// 連署したアグリゲートがこれでないものと、署名が正しくないものも弾く。
    pub fn attach_cosignature(
        &mut self,
        detached: &DetachedCosignature,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<(), CosignError> {
        let hash = self.hash_to_cosign(generation_hash_seed)?;
        if detached.parent_hash != hash {
            return Err(CosignError::OtherParent);
        }
        if !detached.verify() {
            return Err(CosignError::InvalidSignature);
        }
        self.add_cosignature(detached.cosignature)
    }

    /// 連署の対象になるハッシュ。署名したアグリゲートでなければ連署できない
    fn hash_to_cosign(
        &self,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<Hash256, CosignError> {
        if !Body::is_aggregate_type(self.body.transaction_type()) {
            return Err(CosignError::NotAggregate);
        }
        if self.signature == Signature([0; 64]) {
            return Err(CosignError::NotSigned);
        }
        Ok(self.hash(generation_hash_seed))
    }

    /// 外側の署名者やすでに連署した鍵でなければ、連署を足す
    fn add_cosignature(&mut self, cosignature: Cosignature) -> Result<(), CosignError> {
        let signer_public_key = self.signer_public_key;
        let (Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate)) =
            &mut self.body
        else {
            unreachable!("checked by hash_to_cosign");
        };
        if cosignature.signer_public_key == signer_public_key
            || aggregate
                .cosignatures()
                .iter()
                .any(|existing| existing.signer_public_key == cosignature.signer_public_key)
        {
            return Err(CosignError::Redundant);
        }
        aggregate.add_cosignature(cosignature);
        Ok(())
    }

    /// 連署を外して返す。アグリゲートでなければ空
    pub fn take_cosignatures(&mut self) -> Vec<Cosignature> {
        match &mut self.body {
            Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
                aggregate.take_cosignatures()
            }
            _ => Vec::new(),
        }
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

    /// 種類ごとの構造のバージョン。アグリゲートは [`AggregateVersion`] のとおりで、新しく作ればバージョン 3。
    /// ほかの種類は、どれもバージョン 1 しかない。
    pub fn version(&self) -> u8 {
        match self {
            Self::AggregateComplete(aggregate) | Self::AggregateBonded(aggregate) => {
                aggregate.version().number()
            }
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

    /// 種類とバージョンの組が catbuffer にあるか。
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
        if !Self::is_aggregate_type(transaction_type) && !Self::is_version_1_type(transaction_type)
        {
            return Err(DecodeError::UnknownType(transaction_type));
        }
        if !Self::is_known(transaction_type, version) {
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
            0x4141 => Self::AggregateComplete(Aggregate::decode(version, bytes)?),
            _ => Self::AggregateBonded(Aggregate::decode(version, bytes)?),
        })
    }

    fn is_aggregate_type(transaction_type: u16) -> bool {
        matches!(transaction_type, 0x4141 | 0x4241)
    }

    /// 単独で送れるか。メタデータの3種類とマルチシグの変更は、アグリゲートの中でしか使えない
    /// （catapult の `Only_Embeddable`）。単独で送ると、ノードは理由を返さずに捨てる。
    pub fn supports_top_level(&self) -> bool {
        !matches!(
            self,
            Self::AccountMetadata(_)
                | Self::MosaicMetadata(_)
                | Self::NamespaceMetadata(_)
                | Self::MultisigAccountModification(_)
        )
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
    /// 付けようとした署名が、署名者の公開鍵で検証できない
    InvalidSignature,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMismatch => f.write_str("秘密鍵が署名者の公開鍵と合いません"),
            Self::InvalidSignature => f.write_str("署名が、署名者の公開鍵で検証できません"),
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
    /// 切り離した連署が、別のアグリゲートへのもの
    OtherParent,
    /// 切り離した連署の署名が正しくない
    InvalidSignature,
}

impl fmt::Display for CosignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAggregate => f.write_str("アグリゲートではないので連署できません"),
            Self::NotSigned => f.write_str("まだ署名されていないので連署できません"),
            Self::Redundant => {
                f.write_str("この鍵は署名者か、すでに連署しているので、連署を重ねられません")
            }
            Self::OtherParent => f.write_str("別のアグリゲートへの連署なので、付けられません"),
            Self::InvalidSignature => f.write_str("連署の署名が正しくないので、付けられません"),
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
    fn keeps_non_zero_reserved_bytes_like_catapult() {
        let seed = seed();
        let mut signed = vrf_key_link();
        signed.sign(&private_key(), &seed).unwrap();
        for offset in [4, 104] {
            let mut bytes = signed.to_bytes();
            bytes[offset] = 1;
            let transaction = Transaction::from_bytes(&bytes).unwrap();
            assert_eq!(transaction.to_bytes(), bytes, "offset {offset}");
            // 署名にもハッシュにも入らない
            assert!(transaction.verify(&seed), "offset {offset}");
            assert_eq!(
                transaction.hash(&seed),
                signed.hash(&seed),
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
    fn calculates_the_fee_from_the_size() {
        let transaction = vrf_key_link();
        let size = transaction.to_bytes().len();
        assert_eq!(transaction.size(), size);
        assert_eq!(transaction.fee_for(100, 0), size as u64 * 100);
        // これから付く連署の分も数える
        assert_eq!(transaction.fee_for(100, 2), (size as u64 + 2 * 104) * 100);
        assert_eq!(transaction.fee_for(0, 2), 0);
    }

    #[test]
    fn counts_attached_cosignatures_in_the_size() {
        let mut transaction = aggregate_complete();
        transaction.sign(&private_key(), &seed()).unwrap();
        let before = transaction.fee_for(100, 1);
        transaction.cosign(&cosigner_key(), &seed()).unwrap();
        assert_eq!(transaction.fee_for(100, 0), before);
    }

    #[test]
    fn calculates_the_max_fee_multiplier() {
        let mut transaction = vrf_key_link();
        let size = transaction.size() as u64;
        transaction.fee = size * 100 + size - 1;
        assert_eq!(transaction.max_fee_multiplier(), 100);
        transaction.fee = 0;
        assert_eq!(transaction.max_fee_multiplier(), 0);
        // 倍率は u32 なので、それより大きければ上限に丸める
        transaction.fee = u64::MAX;
        assert_eq!(transaction.max_fee_multiplier(), u32::MAX);
    }

    #[test]
    fn attaches_a_detached_cosignature() {
        let mut transaction = aggregate_complete();
        transaction.sign(&private_key(), &seed()).unwrap();
        let hash = transaction.hash(&seed());
        let detached = DetachedCosignature::sign(&cosigner_key(), &hash);

        // 別のアグリゲートへの連署や、署名を壊したものは付けない
        let other = DetachedCosignature::sign(&cosigner_key(), &Hash256([0; 32]));
        assert_eq!(
            transaction.attach_cosignature(&other, &seed()),
            Err(CosignError::OtherParent)
        );
        let mut broken = detached;
        broken.cosignature.signature.0[0] ^= 1;
        assert_eq!(
            transaction.attach_cosignature(&broken, &seed()),
            Err(CosignError::InvalidSignature)
        );

        transaction.attach_cosignature(&detached, &seed()).unwrap();
        assert!(transaction.verify_cosignatures(&seed()));
        assert_eq!(
            transaction.attach_cosignature(&detached, &seed()),
            Err(CosignError::Redundant)
        );
        // 自分で連署したのと同じものになる
        let mut cosigned = aggregate_complete();
        cosigned.sign(&private_key(), &seed()).unwrap();
        cosigned.cosign(&cosigner_key(), &seed()).unwrap();
        assert_eq!(transaction, cosigned);
    }

    #[test]
    fn signs_the_payload_elsewhere_and_attaches_the_signature() {
        for mut transaction in [vrf_key_link(), aggregate_complete()] {
            let payload = transaction.signing_payload(&seed());
            assert_eq!(payload[..32], seed().0);
            let signature = private_key().sign(&[&payload]);

            let mut signed = transaction.clone();
            signed.sign(&private_key(), &seed()).unwrap();
            assert_eq!(signed.signature, signature);

            // 別のネットワークの署名や、壊した署名は付けない
            let other =
                private_key().sign(&[&transaction.signing_payload(&GenerationHashSeed([0; 32]))]);
            assert_eq!(
                transaction.attach_signature(other, &seed()),
                Err(SignError::InvalidSignature)
            );
            assert_eq!(transaction.signature, Signature([0; 64]));
            transaction.attach_signature(signature, &seed()).unwrap();
            assert_eq!(transaction, signed);
        }
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
    fn mixes_cosigners_into_the_merkle_component_hash() {
        let mut transaction = vrf_key_link();
        transaction.sign(&private_key(), &seed()).unwrap();
        assert_eq!(
            transaction.merkle_component_hash(&seed()),
            transaction.hash(&seed())
        );

        let mut transaction = aggregate_complete();
        transaction.sign(&private_key(), &seed()).unwrap();
        let hash = transaction.hash(&seed());
        assert_eq!(transaction.merkle_component_hash(&seed()), hash);
        transaction.cosign(&cosigner_key(), &seed()).unwrap();
        let cosigner = PublicKey::from_private_key(&cosigner_key());
        assert_eq!(
            transaction.merkle_component_hash(&seed()),
            Hash256(Sha3_256::digest([hash.0, cosigner.0].concat()).into())
        );
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
