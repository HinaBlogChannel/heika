//! トランザクション。`/transactions/{group}/{id}` と `/transactions/{group}` が返す `TransactionInfoDTO`。
//!
//! JSON から catbuffer のバイト列を組み直し、[`Transaction::from_bytes`] で読む。値として正しいか
//! （列挙の値、並び、長さ）は heika-transaction に任せ、ここでは JSON の形と、組み直したものから求めた値が
//! REST の `meta` と合うかを確かめる。
//!
//! アグリゲートは、ID かハッシュで1件取ったときだけ、中のトランザクションが `transactions` に入って返る。

use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_core::signature::Signature;
use heika_transaction::{
    AccountRestriction, AliasAction, Body, EmbeddedTransaction, LinkAction, LockHashAlgorithm,
    MosaicMetadata, MosaicRestrictionType, MosaicSupplyChangeAction, NamespaceMetadata,
    NamespaceRegistrationType, Transaction, TransactionsHashCalculation,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{RestError, hex, hex_array, hex_vec, number};

/// トランザクションのヘッダーのうち、署名と手数料と期限を除いた、中のトランザクションと共通の部分の大きさ
const EMBEDDED_HEADER_SIZE: usize = 4 + 4 + 32 + 4 + 1 + 1 + 2;

/// `TransactionInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TransactionInfo {
    pub meta: TransactionMeta,
    pub transaction: TransactionJson,
}

/// `TransactionMetaDTO` と `EmbeddedTransactionMetaDTO`。どちらの形でも読めるように、項目はどれも省けるようにする。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionMeta {
    /// 承認される前なら "0"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<String>,
    /// 中のトランザクションにはない
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_component_hash: Option<String>,
    /// ブロックの中か、アグリゲートの中で何番目か（0から）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,
    /// 中のトランザクションだけにある、親のアグリゲートのハッシュ
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_hash: Option<String>,
}

/// トランザクションの JSON。種類ごとの本体の項目は、どれか1つの種類のものだけが入る。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// 中のトランザクションにはない
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub signer_public_key: String,
    pub version: u8,
    pub network: u8,
    #[serde(rename = "type")]
    pub transaction_type: u16,
    /// 中のトランザクションにはない
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee: Option<String>,
    /// 中のトランザクションにはない
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<String>,
    #[serde(flatten)]
    pub body: BodyJson,
}

/// 25種類の本体の項目をまとめたもの。種類によって使う項目が違う。
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_action: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_epoch: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_epoch: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mosaic_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_algorithm: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scoped_metadata_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_mosaic_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_namespace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_size_delta: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divisibility: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_removal_delta: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_approval_delta: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_additions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_deletions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias_action: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_type: Option<u8>,
    /// ネームスペースの名前。16進ではなく、そのままの文字列
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restriction_flags: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restriction_additions: Option<Vec<RestrictionValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restriction_deletions: Option<Vec<RestrictionValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restriction_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_restriction_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_restriction_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference_mosaic_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_restriction_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_restriction_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mosaics: Option<Vec<MosaicJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cosignatures: Option<Vec<CosignatureJson>>,
    /// ID かハッシュで1件取ったときだけ入る、中のトランザクション
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<TransactionInfo>>,
}

/// アカウントの制限の値。アドレスとモザイクは16進の文字列、トランザクションの種類は数で返る。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RestrictionValue {
    Text(String),
    Number(u16),
}

/// `UnresolvedMosaic`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MosaicJson {
    pub id: String,
    pub amount: String,
}

/// `CosignatureDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignatureJson {
    pub version: String,
    pub signer_public_key: String,
    pub signature: String,
}

impl TransactionJson {
    /// catbuffer のバイト列を組み直す。アグリゲートは、中のトランザクションが入っていなければ組み直せない。
    pub fn to_bytes(&self) -> Result<Vec<u8>, RestError> {
        let signature = required(&self.signature, "signature")?;
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&hex_array::<64>(signature, "signature")?);
        bytes.extend_from_slice(&hex_array::<32>(
            &self.signer_public_key,
            "signerPublicKey",
        )?);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&[self.version, self.network]);
        bytes.extend_from_slice(&self.transaction_type.to_le_bytes());
        bytes.extend_from_slice(
            &number(required(&self.max_fee, "maxFee")?, "maxFee")?.to_le_bytes(),
        );
        bytes.extend_from_slice(
            &number(required(&self.deadline, "deadline")?, "deadline")?.to_le_bytes(),
        );
        bytes.extend_from_slice(&self.body.to_bytes(self.transaction_type)?);
        set_size(&mut bytes);
        Ok(bytes)
    }

    /// アグリゲートの中のトランザクションとして、バイト列を組み直す。
    pub fn to_embedded_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&hex_array::<32>(
            &self.signer_public_key,
            "signerPublicKey",
        )?);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&[self.version, self.network]);
        bytes.extend_from_slice(&self.transaction_type.to_le_bytes());
        debug_assert_eq!(bytes.len(), EMBEDDED_HEADER_SIZE);
        bytes.extend_from_slice(&self.body.to_bytes(self.transaction_type)?);
        set_size(&mut bytes);
        Ok(bytes)
    }
}

/// トランザクションに組み直す。
impl TryFrom<&TransactionJson> for Transaction {
    type Error = RestError;

    fn try_from(json: &TransactionJson) -> Result<Self, Self::Error> {
        Transaction::from_bytes(&json.to_bytes()?).map_err(RestError::InvalidTransaction)
    }
}

impl TransactionInfo {
    /// トランザクションを組み直し、REST が一緒に返した値と、組み直したものから求めた値が合うかを確かめる。
    ///
    /// 確かめるのは、署名と連署、ハッシュ（`meta.hash`）、承認されていれば Merkle の葉
    /// （`meta.merkleComponentHash`）。アグリゲートなら、中のトランザクションから求めた TransactionsHash と、
    /// その高さで使えるバージョンかどうかも確かめる（高さはここにある `meta.height` を信じる）。
    /// ブロックに入っていることは、Merkle の経路で別に確かめる。
    pub fn verify(&self) -> Result<Transaction, RestError> {
        let network =
            NetworkParameters::from_identifier(NetworkIdentifier(self.transaction.network))
                .ok_or(RestError::InvalidValue { field: "network" })?;
        let seed = &network.generation_hash_seed;
        let transaction = Transaction::try_from(&self.transaction)?;
        if !transaction.verify(seed) {
            return Err(RestError::Mismatch { field: "signature" });
        }
        if !transaction.verify_cosignatures(seed) {
            return Err(RestError::Mismatch {
                field: "cosignatures",
            });
        }
        let hash = transaction.hash(seed);
        if hash
            != Hash256(hex_array(
                required(&self.meta.hash, "meta.hash")?,
                "meta.hash",
            )?)
        {
            return Err(RestError::Mismatch { field: "meta.hash" });
        }
        let height = number(required(&self.meta.height, "meta.height")?, "meta.height")?;
        // 承認される前は、REST は Merkle の葉にもハッシュを入れる
        if height > 0 {
            let leaf = required(&self.meta.merkle_component_hash, "meta.merkleComponentHash")?;
            if transaction.merkle_component_hash(seed)
                != Hash256(hex_array(leaf, "meta.merkleComponentHash")?)
            {
                return Err(RestError::Mismatch {
                    field: "meta.merkleComponentHash",
                });
            }
        }
        if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) =
            &transaction.body
        {
            if height > 0 && aggregate.version().number() != network.aggregate_version(height) {
                return Err(RestError::Mismatch { field: "version" });
            }
            if aggregate.transactions_hash_calculation() == TransactionsHashCalculation::Unknown
                && !network.is_known_corrupt_aggregate(&hash, &aggregate.transactions_hash())
            {
                return Err(RestError::Mismatch {
                    field: "transactionsHash",
                });
            }
        }
        Ok(transaction)
    }
}

impl BodyJson {
    /// 種類ごとの本体のバイト列を組み直す。
    fn to_bytes(&self, transaction_type: u16) -> Result<Vec<u8>, RestError> {
        let mut out = Vec::new();
        match transaction_type {
            // AccountKeyLink、NodeKeyLink、VrfKeyLink
            0x414C | 0x424C | 0x4243 => {
                out.extend_from_slice(&self.hex::<32>(&self.linked_public_key, "linkedPublicKey")?);
                out.push(*required(&self.link_action, "linkAction")?);
            }
            // VotingKeyLink
            0x4143 => {
                out.extend_from_slice(&self.hex::<32>(&self.linked_public_key, "linkedPublicKey")?);
                out.extend_from_slice(&required(&self.start_epoch, "startEpoch")?.to_le_bytes());
                out.extend_from_slice(&required(&self.end_epoch, "endEpoch")?.to_le_bytes());
                out.push(*required(&self.link_action, "linkAction")?);
            }
            // HashLock
            0x4148 => {
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.extend_from_slice(&self.number(&self.amount, "amount")?);
                out.extend_from_slice(&self.number(&self.duration, "duration")?);
                out.extend_from_slice(&self.hex::<32>(&self.hash, "hash")?);
            }
            // SecretLock
            0x4152 => {
                out.extend_from_slice(
                    &self.hex::<24>(&self.recipient_address, "recipientAddress")?,
                );
                out.extend_from_slice(&self.hex::<32>(&self.secret, "secret")?);
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.extend_from_slice(&self.number(&self.amount, "amount")?);
                out.extend_from_slice(&self.number(&self.duration, "duration")?);
                out.push(*required(&self.hash_algorithm, "hashAlgorithm")?);
            }
            // SecretProof
            0x4252 => {
                let proof = hex_vec(required(&self.proof, "proof")?, "proof")?;
                out.extend_from_slice(
                    &self.hex::<24>(&self.recipient_address, "recipientAddress")?,
                );
                out.extend_from_slice(&self.hex::<32>(&self.secret, "secret")?);
                out.extend_from_slice(&length::<u16>(proof.len(), "proof")?.to_le_bytes());
                out.push(*required(&self.hash_algorithm, "hashAlgorithm")?);
                out.extend_from_slice(&proof);
            }
            // AccountMetadata、MosaicMetadata、NamespaceMetadata
            0x4144 | 0x4244 | 0x4344 => {
                out.extend_from_slice(&self.hex::<24>(&self.target_address, "targetAddress")?);
                out.extend_from_slice(&self.id(&self.scoped_metadata_key, "scopedMetadataKey")?);
                match transaction_type {
                    0x4244 => {
                        out.extend_from_slice(&self.id(&self.target_mosaic_id, "targetMosaicId")?)
                    }
                    0x4344 => out.extend_from_slice(
                        &self.id(&self.target_namespace_id, "targetNamespaceId")?,
                    ),
                    _ => {}
                }
                let value = hex_vec(required(&self.value, "value")?, "value")?;
                if self
                    .value_size
                    .is_some_and(|size| usize::from(size) != value.len())
                {
                    return Err(RestError::Mismatch { field: "valueSize" });
                }
                out.extend_from_slice(
                    &required(&self.value_size_delta, "valueSizeDelta")?.to_le_bytes(),
                );
                out.extend_from_slice(&length::<u16>(value.len(), "value")?.to_le_bytes());
                out.extend_from_slice(&value);
            }
            // MosaicDefinition
            0x414D => {
                out.extend_from_slice(&self.id(&self.id, "id")?);
                out.extend_from_slice(&self.number(&self.duration, "duration")?);
                out.extend_from_slice(&required(&self.nonce, "nonce")?.to_le_bytes());
                out.push(*required(&self.flags, "flags")?);
                out.push(*required(&self.divisibility, "divisibility")?);
            }
            // MosaicSupplyChange
            0x424D => {
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.extend_from_slice(&self.number(&self.delta, "delta")?);
                out.push(*required(&self.action, "action")?);
            }
            // MosaicSupplyRevocation
            0x434D => {
                out.extend_from_slice(&self.hex::<24>(&self.source_address, "sourceAddress")?);
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.extend_from_slice(&self.number(&self.amount, "amount")?);
            }
            // MultisigAccountModification
            0x4155 => {
                let additions = addresses(&self.address_additions, "addressAdditions")?;
                let deletions = addresses(&self.address_deletions, "addressDeletions")?;
                out.push(*required(&self.min_removal_delta, "minRemovalDelta")? as u8);
                out.push(*required(&self.min_approval_delta, "minApprovalDelta")? as u8);
                out.push(length::<u8>(additions.len(), "addressAdditions")?);
                out.push(length::<u8>(deletions.len(), "addressDeletions")?);
                out.extend_from_slice(&[0; 4]);
                for address in additions.iter().chain(&deletions) {
                    out.extend_from_slice(address);
                }
            }
            // AddressAlias
            0x424E => {
                out.extend_from_slice(&self.id(&self.namespace_id, "namespaceId")?);
                out.extend_from_slice(&self.hex::<24>(&self.address, "address")?);
                out.push(*required(&self.alias_action, "aliasAction")?);
            }
            // MosaicAlias
            0x434E => {
                out.extend_from_slice(&self.id(&self.namespace_id, "namespaceId")?);
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.push(*required(&self.alias_action, "aliasAction")?);
            }
            // NamespaceRegistration。ルートなら期間、サブなら親の ID を先頭に書く
            0x414E => {
                let registration_type = *required(&self.registration_type, "registrationType")?;
                match registration_type {
                    0 => out.extend_from_slice(&self.number(&self.duration, "duration")?),
                    1 => out.extend_from_slice(&self.id(&self.parent_id, "parentId")?),
                    _ => {
                        return Err(RestError::InvalidValue {
                            field: "registrationType",
                        });
                    }
                }
                let name = required(&self.name, "name")?.as_bytes();
                out.extend_from_slice(&self.id(&self.id, "id")?);
                out.push(registration_type);
                out.push(length::<u8>(name.len(), "name")?);
                out.extend_from_slice(name);
            }
            // AccountAddressRestriction、AccountMosaicRestriction、AccountOperationRestriction
            0x4150 | 0x4250 | 0x4350 => {
                let encode = |values: &Option<Vec<RestrictionValue>>, field| {
                    required(values, field)?
                        .iter()
                        .map(|value| restriction_value(transaction_type, value, field))
                        .collect::<Result<Vec<_>, _>>()
                };
                let additions = encode(&self.restriction_additions, "restrictionAdditions")?;
                let deletions = encode(&self.restriction_deletions, "restrictionDeletions")?;
                out.extend_from_slice(
                    &required(&self.restriction_flags, "restrictionFlags")?.to_le_bytes(),
                );
                out.push(length::<u8>(additions.len(), "restrictionAdditions")?);
                out.push(length::<u8>(deletions.len(), "restrictionDeletions")?);
                out.extend_from_slice(&[0; 4]);
                for value in additions.iter().chain(&deletions) {
                    out.extend_from_slice(value);
                }
            }
            // MosaicAddressRestriction
            0x4251 => {
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.extend_from_slice(&self.id(&self.restriction_key, "restrictionKey")?);
                out.extend_from_slice(
                    &self.number(&self.previous_restriction_value, "previousRestrictionValue")?,
                );
                out.extend_from_slice(
                    &self.number(&self.new_restriction_value, "newRestrictionValue")?,
                );
                out.extend_from_slice(&self.hex::<24>(&self.target_address, "targetAddress")?);
            }
            // MosaicGlobalRestriction
            0x4151 => {
                out.extend_from_slice(&self.id(&self.mosaic_id, "mosaicId")?);
                out.extend_from_slice(&self.id(&self.reference_mosaic_id, "referenceMosaicId")?);
                out.extend_from_slice(&self.id(&self.restriction_key, "restrictionKey")?);
                out.extend_from_slice(
                    &self.number(&self.previous_restriction_value, "previousRestrictionValue")?,
                );
                out.extend_from_slice(
                    &self.number(&self.new_restriction_value, "newRestrictionValue")?,
                );
                out.push(*required(
                    &self.previous_restriction_type,
                    "previousRestrictionType",
                )?);
                out.push(*required(&self.new_restriction_type, "newRestrictionType")?);
            }
            // Transfer。メッセージとモザイクは省かれることがある
            0x4154 => {
                let message = match &self.message {
                    Some(message) => hex_vec(message, "message")?,
                    None => Vec::new(),
                };
                let mosaics = self.mosaics.as_deref().unwrap_or_default();
                out.extend_from_slice(
                    &self.hex::<24>(&self.recipient_address, "recipientAddress")?,
                );
                out.extend_from_slice(&length::<u16>(message.len(), "message")?.to_le_bytes());
                out.push(length::<u8>(mosaics.len(), "mosaics")?);
                out.extend_from_slice(&[0; 1 + 4]);
                for mosaic in mosaics {
                    out.extend_from_slice(&hex_id(&mosaic.id, "mosaics.id")?);
                    out.extend_from_slice(&number(&mosaic.amount, "mosaics.amount")?.to_le_bytes());
                }
                out.extend_from_slice(&message);
            }
            // AggregateComplete、AggregateBonded
            0x4141 | 0x4241 => {
                let transactions = required(&self.transactions, "transactions")?;
                let mut embedded: Vec<_> = transactions.iter().collect();
                embedded.sort_by_key(|info| info.meta.index);
                let mut payload = Vec::new();
                for info in embedded {
                    payload.extend_from_slice(&info.transaction.to_embedded_bytes()?);
                    payload.resize(payload.len().next_multiple_of(8), 0);
                }
                out.extend_from_slice(
                    &self.hex::<32>(&self.transactions_hash, "transactionsHash")?,
                );
                out.extend_from_slice(&length::<u32>(payload.len(), "transactions")?.to_le_bytes());
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&payload);
                for cosignature in self.cosignatures.as_deref().unwrap_or_default() {
                    out.extend_from_slice(
                        &number(&cosignature.version, "cosignatures.version")?.to_le_bytes(),
                    );
                    out.extend_from_slice(&hex_array::<32>(
                        &cosignature.signer_public_key,
                        "cosignatures.signerPublicKey",
                    )?);
                    out.extend_from_slice(&hex_array::<64>(
                        &cosignature.signature,
                        "cosignatures.signature",
                    )?);
                }
            }
            _ => {
                return Err(RestError::InvalidValue { field: "type" });
            }
        }
        Ok(out)
    }

    fn hex<const N: usize>(
        &self,
        value: &Option<String>,
        field: &'static str,
    ) -> Result<[u8; N], RestError> {
        hex_array(required(value, field)?, field)
    }

    /// 16進で書かれた u64 の ID を、リトルエンディアンの8バイトにする
    fn id(&self, value: &Option<String>, field: &'static str) -> Result<[u8; 8], RestError> {
        hex_id(required(value, field)?, field)
    }

    /// 10進で書かれた u64 を、リトルエンディアンの8バイトにする
    fn number(&self, value: &Option<String>, field: &'static str) -> Result<[u8; 8], RestError> {
        Ok(number(required(value, field)?, field)?.to_le_bytes())
    }
}

fn required<'a, T>(value: &'a Option<T>, field: &'static str) -> Result<&'a T, RestError> {
    value.as_ref().ok_or(RestError::Missing { field })
}

/// REST は ID を上位から16進で書くので、読んでからリトルエンディアンに並べ直す
fn hex_id(text: &str, field: &'static str) -> Result<[u8; 8], RestError> {
    Ok(u64::from_be_bytes(hex_array(text, field)?).to_le_bytes())
}

fn addresses(
    values: &Option<Vec<String>>,
    field: &'static str,
) -> Result<Vec<[u8; 24]>, RestError> {
    required(values, field)?
        .iter()
        .map(|address| hex_array(address, field))
        .collect()
}

/// アカウントの制限の値を、種類ごとの長さのバイト列にする
fn restriction_value(
    transaction_type: u16,
    value: &RestrictionValue,
    field: &'static str,
) -> Result<Vec<u8>, RestError> {
    match (transaction_type, value) {
        (0x4150, RestrictionValue::Text(address)) => Ok(hex_array::<24>(address, field)?.to_vec()),
        (0x4250, RestrictionValue::Text(id)) => Ok(hex_id(id, field)?.to_vec()),
        (0x4350, RestrictionValue::Number(operation)) => Ok(operation.to_le_bytes().to_vec()),
        _ => Err(RestError::InvalidValue { field }),
    }
}

/// 長さを、書く型に収まる数にする
fn length<T: TryFrom<usize>>(length: usize, field: &'static str) -> Result<T, RestError> {
    T::try_from(length).map_err(|_| RestError::InvalidValue { field })
}

/// 先頭のサイズを、組み直したバイト列の長さにする
fn set_size(bytes: &mut [u8]) {
    let size = bytes.len() as u32;
    bytes[..4].copy_from_slice(&size.to_le_bytes());
}

/// 中のトランザクションなしで確かめた、アグリゲートの外側。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AggregateHeader {
    pub hash: Hash256,
    pub merkle_component_hash: Hash256,
    pub transactions_hash: Hash256,
    pub version: u8,
}

impl TransactionInfo {
    /// 検索で返る、中のトランザクションの入っていないアグリゲートを確かめる。
    ///
    /// 署名とハッシュは中のトランザクションに掛からず、TransactionsHash（バージョン 3 は中のトランザクションの
    /// 長さも）までに掛かるので、外側だけで確かめられる。長さは、REST が返す全体の `size` から求める。
    /// 確かめるのは、署名と連署、`meta.hash`、承認されていれば `meta.merkleComponentHash` とバージョン。
    /// 中のトランザクションが TransactionsHash と合うかは、集めてから [`TransactionInfo::with_embedded`] で確かめる。
    pub fn verify_aggregate_header(&self) -> Result<AggregateHeader, RestError> {
        let json = &self.transaction;
        if !matches!(json.transaction_type, 0x4141 | 0x4241) {
            return Err(RestError::InvalidValue { field: "type" });
        }
        let network = NetworkParameters::from_identifier(NetworkIdentifier(json.network))
            .ok_or(RestError::InvalidValue { field: "network" })?;
        let seed = &network.generation_hash_seed;
        let signature: [u8; 64] = hex_array(required(&json.signature, "signature")?, "signature")?;
        let signer: [u8; 32] = hex_array(&json.signer_public_key, "signerPublicKey")?;
        let transactions_hash: [u8; 32] = json
            .body
            .hex(&json.body.transactions_hash, "transactionsHash")?;
        let cosignatures = json.body.cosignatures.as_deref().unwrap_or_default();

        // 署名の対象。ヘッダーの後半、TransactionsHash、バージョン 3 なら中のトランザクションの長さ
        let mut signed = vec![json.version, json.network];
        signed.extend_from_slice(&json.transaction_type.to_le_bytes());
        signed.extend_from_slice(
            &number(required(&json.max_fee, "maxFee")?, "maxFee")?.to_le_bytes(),
        );
        signed.extend_from_slice(
            &number(required(&json.deadline, "deadline")?, "deadline")?.to_le_bytes(),
        );
        signed.extend_from_slice(&transactions_hash);
        if json.version >= 3 {
            let size = *required(&json.size, "size")? as usize;
            let payload_size = size
                .checked_sub(
                    TRANSACTION_HEADER_SIZE
                        + AGGREGATE_FIXED_SIZE
                        + COSIGNATURE_SIZE * cosignatures.len(),
                )
                .ok_or(RestError::InvalidValue { field: "size" })?;
            signed.extend_from_slice(&length::<u32>(payload_size, "size")?.to_le_bytes());
        }
        if !PublicKey(signer).verify(&[&seed.0, &signed], &Signature(signature)) {
            return Err(RestError::Mismatch { field: "signature" });
        }
        let hash = Hash256(
            Sha3_256::new()
                .chain_update(signature)
                .chain_update(signer)
                .chain_update(seed.0)
                .chain_update(&signed)
                .finalize()
                .into(),
        );
        if hash
            != Hash256(hex_array(
                required(&self.meta.hash, "meta.hash")?,
                "meta.hash",
            )?)
        {
            return Err(RestError::Mismatch { field: "meta.hash" });
        }

        let mut leaf = Sha3_256::new().chain_update(hash.0);
        for cosignature in cosignatures {
            if number(&cosignature.version, "cosignatures.version")? != 0 {
                return Err(RestError::InvalidValue {
                    field: "cosignatures.version",
                });
            }
            let key = PublicKey(hex_array(
                &cosignature.signer_public_key,
                "cosignatures.signerPublicKey",
            )?);
            let signature = Signature(hex_array(&cosignature.signature, "cosignatures.signature")?);
            if !key.verify(&[&hash.0], &signature) {
                return Err(RestError::Mismatch {
                    field: "cosignatures",
                });
            }
            leaf.update(key.0);
        }
        let merkle_component_hash = if cosignatures.is_empty() {
            hash
        } else {
            Hash256(leaf.finalize().into())
        };
        let height = number(required(&self.meta.height, "meta.height")?, "meta.height")?;
        if height > 0 {
            let expected = required(&self.meta.merkle_component_hash, "meta.merkleComponentHash")?;
            if merkle_component_hash != Hash256(hex_array(expected, "meta.merkleComponentHash")?) {
                return Err(RestError::Mismatch {
                    field: "meta.merkleComponentHash",
                });
            }
            if json.version != network.aggregate_version(height) {
                return Err(RestError::Mismatch { field: "version" });
            }
        }
        Ok(AggregateHeader {
            hash,
            merkle_component_hash,
            transactions_hash: Hash256(transactions_hash),
            version: json.version,
        })
    }

    /// `embedded=true` の検索で平たく並んで返った中のトランザクションから、このアグリゲートのものを
    /// （`meta.aggregateHash` で）集め、`meta.index` の順に `transactions` に入れたものを返す。
    /// 返したものを [`TransactionInfo::verify`] にかければ、中のトランザクションまで確かめられる。
    ///
    /// 集めたものの `meta.index` が0から抜けなく続いていなければ弾く。
    pub fn with_embedded(&self, entries: &[TransactionInfo]) -> Result<TransactionInfo, RestError> {
        let hash = Hash256(hex_array(
            required(&self.meta.hash, "meta.hash")?,
            "meta.hash",
        )?);
        let mut embedded = Vec::new();
        for entry in entries {
            let Some(parent) = &entry.meta.aggregate_hash else {
                continue;
            };
            if Hash256(hex_array(parent, "meta.aggregateHash")?) == hash {
                embedded.push(entry.clone());
            }
        }
        embedded.sort_by_key(|entry| entry.meta.index);
        if embedded
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.meta.index != Some(index as u32))
        {
            return Err(RestError::InvalidValue {
                field: "meta.index",
            });
        }
        let mut aggregate = self.clone();
        aggregate.transaction.body.transactions = Some(embedded);
        Ok(aggregate)
    }
}

/// 署名と手数料と期限を含めた、トランザクションのヘッダーの大きさ
const TRANSACTION_HEADER_SIZE: usize = 4 + 4 + 64 + 32 + 4 + 1 + 1 + 2 + 8 + 8;
/// アグリゲートの、中のトランザクションより前の部分。TransactionsHash、中のトランザクションの長さ、予約
const AGGREGATE_FIXED_SIZE: usize = 32 + 4 + 4;
/// 連署1つの大きさ。バージョン、公開鍵、署名
const COSIGNATURE_SIZE: usize = 8 + 32 + 64;

/// トランザクションを、REST が返す形にする。アグリゲートなら、ID かハッシュで1件取ったときと同じく、
/// 中のトランザクションを `transactions` に入れ、`meta` には何番目かだけを書く。
impl From<&Transaction> for TransactionJson {
    fn from(transaction: &Transaction) -> Self {
        Self {
            size: Some(transaction.size() as u32),
            signature: Some(transaction.signature.to_string()),
            signer_public_key: transaction.signer_public_key.to_string(),
            version: transaction.body.version(),
            network: transaction.network.0,
            transaction_type: transaction.body.transaction_type(),
            max_fee: Some(transaction.fee.to_string()),
            deadline: Some(transaction.deadline.to_string()),
            body: body_json(&transaction.body),
        }
    }
}

/// アグリゲートの中のトランザクションを、REST が返す形にする。署名、手数料、期限、大きさはない。
impl From<&EmbeddedTransaction> for TransactionJson {
    fn from(embedded: &EmbeddedTransaction) -> Self {
        Self {
            size: None,
            signature: None,
            signer_public_key: embedded.signer_public_key.to_string(),
            version: embedded.body.version(),
            network: embedded.network.0,
            transaction_type: embedded.body.transaction_type(),
            max_fee: None,
            deadline: None,
            body: body_json(&embedded.body),
        }
    }
}

/// 種類ごとの本体の項目を、catapult-rest と同じ書き方で埋める。
fn body_json(body: &Body) -> BodyJson {
    let mut json = BodyJson::default();
    let id = |value: u64| Some(format!("{value:016X}"));
    let decimal = |value: u64| Some(value.to_string());
    let address = |bytes: &[u8; 24]| Some(hex(bytes));
    match body {
        Body::AccountKeyLink(link) | Body::NodeKeyLink(link) | Body::VrfKeyLink(link) => {
            json.linked_public_key = Some(link.linked_public_key.to_string());
            json.link_action = Some(link_action(link.link_action));
        }
        Body::VotingKeyLink(link) => {
            json.linked_public_key = Some(link.linked_public_key.to_string());
            json.start_epoch = Some(link.start_epoch);
            json.end_epoch = Some(link.end_epoch);
            json.link_action = Some(link_action(link.link_action));
        }
        Body::HashLock(lock) => {
            json.mosaic_id = id(lock.mosaic.mosaic_id.0);
            json.amount = decimal(lock.mosaic.amount);
            json.duration = decimal(lock.duration);
            json.hash = Some(lock.hash.to_string());
        }
        Body::SecretLock(lock) => {
            json.recipient_address = address(&lock.recipient_address.0);
            json.secret = Some(lock.secret.to_string());
            json.mosaic_id = id(lock.mosaic.mosaic_id.0);
            json.amount = decimal(lock.mosaic.amount);
            json.duration = decimal(lock.duration);
            json.hash_algorithm = Some(hash_algorithm(lock.hash_algorithm));
        }
        Body::SecretProof(proof) => {
            json.recipient_address = address(&proof.recipient_address.0);
            json.secret = Some(proof.secret.to_string());
            json.hash_algorithm = Some(hash_algorithm(proof.hash_algorithm));
            json.proof = Some(hex(&proof.proof));
        }
        Body::AccountMetadata(metadata)
        | Body::MosaicMetadata(MosaicMetadata { metadata, .. })
        | Body::NamespaceMetadata(NamespaceMetadata { metadata, .. }) => {
            json.target_address = address(&metadata.target_address.0);
            json.scoped_metadata_key = id(metadata.scoped_metadata_key);
            json.value_size_delta = Some(metadata.value_size_delta);
            json.value_size = Some(metadata.value.len() as u16);
            json.value = Some(hex(&metadata.value));
            match body {
                Body::MosaicMetadata(mosaic) => {
                    json.target_mosaic_id = id(mosaic.target_mosaic_id.0)
                }
                Body::NamespaceMetadata(namespace) => {
                    json.target_namespace_id = id(namespace.target_namespace_id.0)
                }
                _ => {}
            }
        }
        Body::MosaicDefinition(definition) => {
            json.id = id(definition.id.0);
            json.duration = decimal(definition.duration);
            json.nonce = Some(definition.nonce);
            json.flags = Some(definition.flags.bits());
            json.divisibility = Some(definition.divisibility);
        }
        Body::MosaicSupplyChange(change) => {
            json.mosaic_id = id(change.mosaic_id.0);
            json.delta = decimal(change.delta);
            json.action = Some(match change.action {
                MosaicSupplyChangeAction::Decrease => 0,
                MosaicSupplyChangeAction::Increase => 1,
            });
        }
        Body::MosaicSupplyRevocation(revocation) => {
            json.source_address = address(&revocation.source_address.0);
            json.mosaic_id = id(revocation.mosaic.mosaic_id.0);
            json.amount = decimal(revocation.mosaic.amount);
        }
        Body::MultisigAccountModification(modification) => {
            json.min_removal_delta = Some(modification.min_removal_delta);
            json.min_approval_delta = Some(modification.min_approval_delta);
            json.address_additions = Some(
                modification
                    .address_additions
                    .iter()
                    .map(|address| hex(&address.0))
                    .collect(),
            );
            json.address_deletions = Some(
                modification
                    .address_deletions
                    .iter()
                    .map(|address| hex(&address.0))
                    .collect(),
            );
        }
        Body::AddressAlias(alias) => {
            json.namespace_id = id(alias.namespace_id.0);
            json.address = address(&alias.address.0);
            json.alias_action = Some(alias_action(alias.alias_action));
        }
        Body::MosaicAlias(alias) => {
            json.namespace_id = id(alias.namespace_id.0);
            json.mosaic_id = id(alias.mosaic_id.0);
            json.alias_action = Some(alias_action(alias.alias_action));
        }
        Body::NamespaceRegistration(registration) => {
            match registration.registration_type {
                NamespaceRegistrationType::Root { duration } => {
                    json.registration_type = Some(0);
                    json.duration = decimal(duration);
                }
                NamespaceRegistrationType::Child { parent_id } => {
                    json.registration_type = Some(1);
                    json.parent_id = id(parent_id.0);
                }
            }
            json.id = id(registration.id.0);
            json.name = Some(String::from_utf8_lossy(&registration.name).into_owned());
        }
        Body::AccountAddressRestriction(restriction) => {
            account_restriction(&mut json, restriction, |address| {
                RestrictionValue::Text(hex(&address.0))
            })
        }
        Body::AccountMosaicRestriction(restriction) => {
            account_restriction(&mut json, restriction, |mosaic| {
                RestrictionValue::Text(format!("{:016X}", mosaic.0))
            })
        }
        Body::AccountOperationRestriction(restriction) => {
            account_restriction(&mut json, restriction, |operation| {
                RestrictionValue::Number(operation.0)
            })
        }
        Body::MosaicAddressRestriction(restriction) => {
            json.mosaic_id = id(restriction.mosaic_id.0);
            json.restriction_key = id(restriction.restriction_key);
            json.previous_restriction_value = decimal(restriction.previous_restriction_value);
            json.new_restriction_value = decimal(restriction.new_restriction_value);
            json.target_address = address(&restriction.target_address.0);
        }
        Body::MosaicGlobalRestriction(restriction) => {
            json.mosaic_id = id(restriction.mosaic_id.0);
            json.reference_mosaic_id = id(restriction.reference_mosaic_id.0);
            json.restriction_key = id(restriction.restriction_key);
            json.previous_restriction_value = decimal(restriction.previous_restriction_value);
            json.new_restriction_value = decimal(restriction.new_restriction_value);
            json.previous_restriction_type = Some(mosaic_restriction_type(
                restriction.previous_restriction_type,
            ));
            json.new_restriction_type =
                Some(mosaic_restriction_type(restriction.new_restriction_type));
        }
        Body::Transfer(transfer) => {
            json.recipient_address = address(&transfer.recipient_address().0);
            json.mosaics = Some(
                transfer
                    .mosaics()
                    .iter()
                    .map(|(mosaic, amount)| MosaicJson {
                        id: format!("{:016X}", mosaic.0),
                        amount: amount.to_string(),
                    })
                    .collect(),
            );
            // catapult-rest は、空のメッセージを書かない
            if !transfer.message().is_empty() {
                json.message = Some(hex(transfer.message()));
            }
        }
        Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
            json.transactions_hash = Some(aggregate.transactions_hash().to_string());
            json.cosignatures = Some(
                aggregate
                    .cosignatures()
                    .iter()
                    .map(|cosignature| CosignatureJson {
                        version: "0".to_owned(),
                        signer_public_key: cosignature.signer_public_key.to_string(),
                        signature: cosignature.signature.to_string(),
                    })
                    .collect(),
            );
            json.transactions = Some(
                aggregate
                    .transactions()
                    .iter()
                    .enumerate()
                    .map(|(index, embedded)| TransactionInfo {
                        meta: TransactionMeta {
                            height: None,
                            hash: None,
                            merkle_component_hash: None,
                            index: Some(index as u32),
                            aggregate_hash: None,
                        },
                        transaction: TransactionJson::from(embedded),
                    })
                    .collect(),
            );
        }
    }
    json
}

fn account_restriction<T>(
    json: &mut BodyJson,
    restriction: &AccountRestriction<T>,
    value: impl Fn(&T) -> RestrictionValue,
) {
    json.restriction_flags = Some(restriction.restriction_flags.bits());
    json.restriction_additions = Some(
        restriction
            .restriction_additions
            .iter()
            .map(&value)
            .collect(),
    );
    json.restriction_deletions = Some(
        restriction
            .restriction_deletions
            .iter()
            .map(&value)
            .collect(),
    );
}

fn link_action(action: LinkAction) -> u8 {
    match action {
        LinkAction::Unlink => 0,
        LinkAction::Link => 1,
    }
}

fn alias_action(action: AliasAction) -> u8 {
    match action {
        AliasAction::Unlink => 0,
        AliasAction::Link => 1,
    }
}

fn hash_algorithm(algorithm: LockHashAlgorithm) -> u8 {
    match algorithm {
        LockHashAlgorithm::Sha3_256 => 0,
        LockHashAlgorithm::Hash160 => 1,
        LockHashAlgorithm::Hash256 => 2,
    }
}

fn mosaic_restriction_type(value: MosaicRestrictionType) -> u8 {
    match value {
        MosaicRestrictionType::None => 0,
        MosaicRestrictionType::Eq => 1,
        MosaicRestrictionType::Ne => 2,
        MosaicRestrictionType::Lt => 3,
        MosaicRestrictionType::Le => 4,
        MosaicRestrictionType::Gt => 5,
        MosaicRestrictionType::Ge => 6,
    }
}
