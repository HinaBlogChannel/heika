//! 送る前の検証。ノードが受け取ったトランザクションを、状態を見ずに確かめるところを、同じ規則で確かめる。
//!
//! catapult の stateless validator（`DEFINE_STATELESS_VALIDATOR`）と、パケットから取り出すときの
//! `IsSizeValid` のうち、heika の型やデコードで弾けないものを、ノードと同じ順に並べて返す。
//! 列挙型の値、予約の部分、モザイクの並び、アグリゲートの入れ子は、型とデコードで弾いているので出てこない。
//!
//! 署名はノードでも別の段階で確かめるので、ここでは確かめない。[`Transaction::verify`] と
//! [`Transaction::verify_cosignatures`] を使う。残高や期限のように、状態や時刻で決まることも確かめない。

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt;

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::{NetworkIdentifier, NetworkParameters};

use crate::aggregate::Aggregate;
use crate::metadata::Metadata;
use crate::mosaic::MosaicId;
use crate::namespace::{NamespaceId, NamespaceRegistrationType, is_valid_namespace_name};
use crate::restriction::{AccountRestrictionFlags, TransactionType};
use crate::transfer::UnresolvedAddress;
use crate::{Body, LinkAction, Transaction};

/// 見つかった問題と、その場所。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Problem {
    pub location: Location,
    pub failure: Failure,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.location {
            Location::Transaction => self.failure.fmt(f),
            Location::Embedded(index) => write!(f, "中の {} 件目: {}", index + 1, self.failure),
        }
    }
}

/// 問題のある場所。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Location {
    /// トランザクションそのもの。アグリゲートなら外側
    Transaction,
    /// アグリゲートの中の、0 から数えて何件目か
    Embedded(usize),
}

/// ノードに弾かれる理由。名前は catapult の結果の名前から `Failure_` と機能の名前を除いたもの。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Failure {
    /// アグリゲートの中でしか使えない種類を、単独で送ろうとしている。ノードは結果を返さずに捨てる
    TopLevelNotSupported,
    /// 署名者か、紐づける公開鍵が0
    ZeroPublicKey,
    WrongNetwork {
        expected: NetworkIdentifier,
        actual: NetworkIdentifier,
    },
    /// 手数料が、バイト数に u32 の最大値を掛けた額より大きい
    InvalidTransactionFee,
    /// 公開鍵が0のアカウントのアドレス
    ZeroAddress,
    /// 投票鍵の最初のエポックが0
    LinkStartEpochInvalid,
    /// 投票鍵のエポックの範囲が逆か、長さが設定の範囲の外
    InvalidLinkRange {
        start: u32,
        end: u32,
        min: u32,
        max: u32,
    },
    TransferMessageTooLarge {
        size: usize,
        max: usize,
    },
    /// 期間が0か上限（ブロック）より長い
    HashLockInvalidDuration {
        duration: u64,
        max: u64,
    },
    /// 期間が0か上限（ブロック）より長い
    SecretLockInvalidDuration {
        duration: u64,
        max: u64,
    },
    ProofSizeOutOfBounds {
        size: usize,
        min: usize,
        max: usize,
    },
    /// プルーフのハッシュがシークレットと合わない
    SecretMismatch,
    /// メタデータの値が空
    MetadataValueTooSmall,
    /// 値の長さの変化が、値の長さより大きい
    MetadataValueSizeDeltaTooLarge {
        delta: i16,
        size: usize,
    },
    MetadataValueTooLarge {
        size: usize,
        max: usize,
    },
    /// モザイクの ID が0
    MosaicInvalidId,
    /// モザイクの ID が、署名者のアドレスとノンスから求めたものと合わない
    MosaicIdMismatch {
        expected: MosaicId,
    },
    /// 発行量の増減が0
    MosaicInvalidSupplyChangeAmount,
    /// 一度に外す連署者が2人以上
    MultisigMultipleDeletes,
    /// 同じ連署者を2回足している
    MultisigRedundantModification,
    /// 同じアドレスを足して外している
    MultisigAccountInBothSets,
    /// ルートのネームスペースの期間（ブロック）が、0（無期限）でなく、設定の範囲の外
    NamespaceInvalidDuration {
        duration: u64,
        min: u64,
        max: u64,
    },
    /// 名前が空か長すぎるか、使えない文字がある
    NamespaceInvalidName,
    /// ネームスペースの ID が、親の ID と名前から求めたものと合わない
    NamespaceNameIdMismatch {
        expected: NamespaceId,
    },
    /// 制限の種類と向きの組み合わせが使えない
    AccountRestrictionInvalidFlags(AccountRestrictionFlags),
    /// 送れる種類の制限に、トランザクションの種類でない値を足している
    AccountRestrictionInvalidValue(TransactionType),
    AggregateNoTransactions,
    AggregateTooManyTransactions {
        count: usize,
        max: usize,
    },
    /// 連署が多すぎる。`count` は外側の署名者も数える
    AggregateTooManyCosignatures {
        count: usize,
        max: usize,
    },
    /// 同じアカウントが2回署名している。外側の署名者も数える
    AggregateRedundantCosignatures,
}

impl Failure {
    /// catapult の結果の名前と値。REST のトランザクションのステータスに出るもの。
    /// ノードが結果を返さずに捨てるものは `None`。
    pub fn result(&self) -> Option<(&'static str, u32)> {
        // 結果の値は、重大度 Failure（上位2ビットが 2）、機能のコード、番号を並べたもの
        let (name, facility, code) = match self {
            Self::TopLevelNotSupported => return None,
            Self::ZeroPublicKey => ("Failure_Core_Zero_Public_Key", 0x43, 12),
            Self::WrongNetwork { .. } => ("Failure_Core_Wrong_Network", 0x43, 6),
            Self::InvalidTransactionFee => ("Failure_Core_Invalid_Transaction_Fee", 0x43, 9),
            Self::ZeroAddress => ("Failure_Core_Zero_Address", 0x43, 11),
            Self::LinkStartEpochInvalid => ("Failure_Core_Link_Start_Epoch_Invalid", 0x43, 106),
            Self::InvalidLinkRange { .. } => ("Failure_Core_Invalid_Link_Range", 0x43, 104),
            Self::TransferMessageTooLarge { .. } => ("Failure_Transfer_Message_Too_Large", 0x54, 1),
            Self::HashLockInvalidDuration { .. } => ("Failure_LockHash_Invalid_Duration", 0x48, 6),
            Self::SecretLockInvalidDuration { .. } => {
                ("Failure_LockSecret_Invalid_Duration", 0x52, 8)
            }
            Self::ProofSizeOutOfBounds { .. } => {
                ("Failure_LockSecret_Proof_Size_Out_Of_Bounds", 0x52, 3)
            }
            Self::SecretMismatch => ("Failure_LockSecret_Secret_Mismatch", 0x52, 4),
            Self::MetadataValueTooSmall => ("Failure_Metadata_Value_Too_Small", 0x44, 1),
            Self::MetadataValueSizeDeltaTooLarge { .. } => {
                ("Failure_Metadata_Value_Size_Delta_Too_Large", 0x44, 3)
            }
            Self::MetadataValueTooLarge { .. } => ("Failure_Metadata_Value_Too_Large", 0x44, 2),
            Self::MosaicInvalidId => ("Failure_Mosaic_Invalid_Id", 0x4D, 106),
            Self::MosaicIdMismatch { .. } => ("Failure_Mosaic_Id_Mismatch", 0x4D, 6),
            Self::MosaicInvalidSupplyChangeAmount => {
                ("Failure_Mosaic_Invalid_Supply_Change_Amount", 0x4D, 105)
            }
            Self::MultisigMultipleDeletes => ("Failure_Multisig_Multiple_Deletes", 0x55, 2),
            Self::MultisigRedundantModification => {
                ("Failure_Multisig_Redundant_Modification", 0x55, 3)
            }
            Self::MultisigAccountInBothSets => ("Failure_Multisig_Account_In_Both_Sets", 0x55, 1),
            Self::NamespaceInvalidDuration { .. } => {
                ("Failure_Namespace_Invalid_Duration", 0x4E, 1)
            }
            Self::NamespaceInvalidName => ("Failure_Namespace_Invalid_Name", 0x4E, 2),
            Self::NamespaceNameIdMismatch { .. } => ("Failure_Namespace_Name_Id_Mismatch", 0x4E, 3),
            Self::AccountRestrictionInvalidFlags(_) => (
                "Failure_RestrictionAccount_Invalid_Restriction_Flags",
                0x50,
                1,
            ),
            Self::AccountRestrictionInvalidValue(_) => {
                ("Failure_RestrictionAccount_Invalid_Value", 0x50, 10)
            }
            Self::AggregateNoTransactions => ("Failure_Aggregate_No_Transactions", 0x41, 2),
            Self::AggregateTooManyTransactions { .. } => {
                ("Failure_Aggregate_Too_Many_Transactions", 0x41, 1)
            }
            Self::AggregateTooManyCosignatures { .. } => {
                ("Failure_Aggregate_Too_Many_Cosignatures", 0x41, 3)
            }
            Self::AggregateRedundantCosignatures => {
                ("Failure_Aggregate_Redundant_Cosignatures", 0x41, 4)
            }
        };
        Some((name, 0x8000_0000 | facility << 16 | code))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TopLevelNotSupported => {
                f.write_str("この種類はアグリゲートの中でしか使えません。単独で送ると、ノードは理由を返さずに捨てます")
            }
            Self::ZeroPublicKey => f.write_str("公開鍵が0です"),
            Self::WrongNetwork { expected, actual } => write!(
                f,
                "ネットワークが 0x{:02X} ですが、送り先は 0x{:02X} です",
                actual.0, expected.0
            ),
            Self::InvalidTransactionFee => {
                f.write_str("手数料が、バイト数に u32 の最大値を掛けた額より大きいです")
            }
            Self::ZeroAddress => f.write_str("公開鍵が0のアカウントのアドレスです"),
            Self::LinkStartEpochInvalid => f.write_str("投票鍵の最初のエポックが0です"),
            Self::InvalidLinkRange {
                start,
                end,
                min,
                max,
            } => write!(
                f,
                "投票鍵のエポックの範囲 {start}〜{end} は、{min}〜{max} エポックの長さでなければなりません"
            ),
            Self::TransferMessageTooLarge { size, max } => write!(
                f,
                "メッセージは {max} バイトまでですが、{size} バイトあります"
            ),
            Self::HashLockInvalidDuration { duration, max }
            | Self::SecretLockInvalidDuration { duration, max } => write!(
                f,
                "ロックの期間は 1〜{max} ブロックでなければなりませんが、{duration} ブロックです"
            ),
            Self::ProofSizeOutOfBounds { size, min, max } => write!(
                f,
                "プルーフは {min}〜{max} バイトでなければなりませんが、{size} バイトです"
            ),
            Self::SecretMismatch => f.write_str("プルーフのハッシュがシークレットと合いません"),
            Self::MetadataValueTooSmall => f.write_str("メタデータの値が空です"),
            Self::MetadataValueSizeDeltaTooLarge { delta, size } => write!(
                f,
                "値の長さの変化 {delta} が、値の長さ {size} バイトを超えています"
            ),
            Self::MetadataValueTooLarge { size, max } => write!(
                f,
                "メタデータの値は {max} バイトまでですが、{size} バイトあります"
            ),
            Self::MosaicInvalidId => f.write_str("モザイクの ID が0です"),
            Self::MosaicIdMismatch { expected } => write!(
                f,
                "モザイクの ID が、署名者のアドレスとノンスから求めた {:016X} と合いません",
                expected.0
            ),
            Self::MosaicInvalidSupplyChangeAmount => f.write_str("発行量の増減が0です"),
            Self::MultisigMultipleDeletes => {
                f.write_str("連署者は一度に1人しか外せません")
            }
            Self::MultisigRedundantModification => {
                f.write_str("同じ連署者を2回足しています")
            }
            Self::MultisigAccountInBothSets => {
                f.write_str("同じアドレスを、足すほうと外すほうの両方に入れています")
            }
            Self::NamespaceInvalidDuration { duration, min, max } => write!(
                f,
                "ネームスペースの期間は {min}〜{max} ブロックか、0（無期限）でなければなりませんが、{duration} ブロックです"
            ),
            Self::NamespaceInvalidName => f.write_str(
                "ネームスペースの名前が空か長すぎるか、英小文字、数字、`-`、`_` 以外の文字があります（最初は英小文字か数字）",
            ),
            Self::NamespaceNameIdMismatch { expected } => write!(
                f,
                "ネームスペースの ID が、親の ID と名前から求めた {:016X} と合いません",
                expected.0
            ),
            Self::AccountRestrictionInvalidFlags(flags) => write!(
                f,
                "制限のフラグ 0x{:04X} の組み合わせは使えません（モザイクは受け取る側だけ、トランザクションの種類は送る側だけ）",
                flags.bits()
            ),
            Self::AccountRestrictionInvalidValue(value) => write!(
                f,
                "0x{:04X} はトランザクションの種類ではありません",
                value.0
            ),
            Self::AggregateNoTransactions => f.write_str("アグリゲートの中が空です"),
            Self::AggregateTooManyTransactions { count, max } => write!(
                f,
                "アグリゲートの中は {max} 件までですが、{count} 件あります"
            ),
            Self::AggregateTooManyCosignatures { count, max } => write!(
                f,
                "署名は外側の署名者を含めて {max} 個までですが、{count} 個あります"
            ),
            Self::AggregateRedundantCosignatures => {
                f.write_str("同じアカウントが2回署名しています")
            }
        }
    }
}

impl Transaction {
    /// ノードが状態を見ずに弾くところがないか確かめる。ノードが確かめる順に並べて返し、なければ空。
    ///
    /// ノードは最初の1つで止めるので、REST のステータスに出るのは先頭のもの。ただし [`Failure::TopLevelNotSupported`] なら、
    /// ステータスには何も出ない。
    pub fn validate(&self, parameters: &NetworkParameters) -> Vec<Problem> {
        let mut checker = Checker {
            parameters,
            location: Location::Transaction,
            problems: Vec::new(),
        };
        if !self.body.supports_top_level() {
            checker.fail(Failure::TopLevelNotSupported);
        }
        checker.entity(&self.signer_public_key, self.network);
        // 送ったトランザクションでは手数料と最大手数料が同じなので、確かめるのは上限だけ
        if self.fee > u64::from(u32::MAX).saturating_mul(self.size() as u64) {
            checker.fail(Failure::InvalidTransactionFee);
        }
        checker.body(&self.body, &self.signer_public_key);
        checker.problems
    }
}

struct Checker<'a> {
    parameters: &'a NetworkParameters,
    location: Location,
    problems: Vec<Problem>,
}

impl Checker<'_> {
    fn fail(&mut self, failure: Failure) {
        self.problems.push(Problem {
            location: self.location,
            failure,
        });
    }

    /// 署名者の公開鍵と、ネットワーク（catapult の `ZeroPublicKey`、`Network`）。
    fn entity(&mut self, signer_public_key: &PublicKey, network: NetworkIdentifier) {
        self.public_key(signer_public_key);
        if network != self.parameters.identifier {
            self.fail(Failure::WrongNetwork {
                expected: self.parameters.identifier,
                actual: network,
            });
        }
    }

    fn public_key(&mut self, public_key: &PublicKey) {
        if public_key.0 == [0; 32] {
            self.fail(Failure::ZeroPublicKey);
        }
    }

    /// catapult の `ZeroAddress`。エイリアスはここでは解決しないので、0の公開鍵のアドレスそのものだけを弾く。
    fn address(&mut self, address: &UnresolvedAddress) {
        let zero = Address::from_public_key(&PublicKey([0; 32]), self.parameters.identifier);
        if address.0 == zero.0 {
            self.fail(Failure::ZeroAddress);
        }
    }

    /// 種類ごとの規則。catapult でそれぞれのプラグインが通知を出す順に確かめる。
    fn body(&mut self, body: &Body, signer_public_key: &PublicKey) {
        let parameters = self.parameters;
        match body {
            Body::AccountKeyLink(link) => {
                if link.link_action == LinkAction::Link {
                    self.public_key(&link.linked_public_key);
                }
            }
            Body::NodeKeyLink(_) | Body::VrfKeyLink(_) => {}
            Body::VotingKeyLink(link) => {
                let (min, max) = (
                    parameters.min_voting_key_lifetime,
                    parameters.max_voting_key_lifetime,
                );
                if link.start_epoch == 0 {
                    self.fail(Failure::LinkStartEpochInvalid);
                } else if link.end_epoch < link.start_epoch
                    || !(min..=max).contains(&(link.end_epoch - link.start_epoch).saturating_add(1))
                {
                    self.fail(Failure::InvalidLinkRange {
                        start: link.start_epoch,
                        end: link.end_epoch,
                        min,
                        max,
                    });
                }
            }
            Body::HashLock(lock) => {
                let max = parameters.blocks(parameters.max_hash_lock_duration);
                if lock.duration == 0 || lock.duration > max {
                    self.fail(Failure::HashLockInvalidDuration {
                        duration: lock.duration,
                        max,
                    });
                }
            }
            Body::SecretLock(lock) => {
                self.address(&lock.recipient_address);
                let max = parameters.blocks(parameters.max_secret_lock_duration);
                if lock.duration == 0 || lock.duration > max {
                    self.fail(Failure::SecretLockInvalidDuration {
                        duration: lock.duration,
                        max,
                    });
                }
            }
            Body::SecretProof(proof) => {
                let (min, max) = (parameters.min_proof_size, parameters.max_proof_size);
                if !(min..=max).contains(&proof.proof.len()) {
                    self.fail(Failure::ProofSizeOutOfBounds {
                        size: proof.proof.len(),
                        min,
                        max,
                    });
                } else if proof.hash_algorithm.secret(&proof.proof) != proof.secret {
                    self.fail(Failure::SecretMismatch);
                }
            }
            Body::AccountMetadata(metadata) => {
                self.address(&metadata.target_address);
                self.metadata(metadata);
            }
            Body::MosaicMetadata(metadata) => self.metadata(&metadata.metadata),
            Body::NamespaceMetadata(metadata) => self.metadata(&metadata.metadata),
            Body::MosaicDefinition(definition) => {
                let owner = Address::from_public_key(signer_public_key, parameters.identifier);
                let expected = MosaicId::generate(&owner, definition.nonce);
                if definition.id.0 == 0 {
                    self.fail(Failure::MosaicInvalidId);
                } else if definition.id != expected {
                    self.fail(Failure::MosaicIdMismatch { expected });
                }
            }
            Body::MosaicSupplyChange(change) => {
                if change.delta == 0 {
                    self.fail(Failure::MosaicInvalidSupplyChangeAmount);
                }
            }
            Body::MosaicSupplyRevocation(revocation) => self.address(&revocation.source_address),
            Body::MultisigAccountModification(modification) => {
                let additions = &modification.address_additions;
                let deletions = &modification.address_deletions;
                for address in additions.iter() {
                    self.address(address);
                }
                // どちらも空なら、catapult は通知を出さない
                let unique: BTreeSet<_> = additions.iter().map(|address| address.0).collect();
                if deletions.len() > 1 {
                    self.fail(Failure::MultisigMultipleDeletes);
                } else if unique.len() != additions.len() {
                    self.fail(Failure::MultisigRedundantModification);
                } else if deletions.iter().any(|address| unique.contains(&address.0)) {
                    self.fail(Failure::MultisigAccountInBothSets);
                }
            }
            Body::AddressAlias(_) | Body::MosaicAlias(_) => {}
            Body::NamespaceRegistration(registration) => {
                let parent_id = match registration.registration_type {
                    NamespaceRegistrationType::Root { duration } => {
                        let min = parameters.blocks(parameters.min_namespace_duration);
                        let max = parameters.blocks(parameters.max_namespace_duration);
                        if duration != 0 && !(min..=max).contains(&duration) {
                            self.fail(Failure::NamespaceInvalidDuration { duration, min, max });
                        }
                        None
                    }
                    NamespaceRegistrationType::Child { parent_id } => Some(parent_id),
                };
                let name = &registration.name;
                let expected = NamespaceId::generate(parent_id, name);
                if name.len() > parameters.max_namespace_name_size || !is_valid_namespace_name(name)
                {
                    self.fail(Failure::NamespaceInvalidName);
                } else if registration.id != expected {
                    self.fail(Failure::NamespaceNameIdMismatch { expected });
                }
            }
            Body::AccountAddressRestriction(restriction) => {
                self.restriction_flags(restriction.restriction_flags);
            }
            Body::AccountMosaicRestriction(restriction) => {
                self.restriction_flags(restriction.restriction_flags);
            }
            Body::AccountOperationRestriction(restriction) => {
                self.restriction_flags(restriction.restriction_flags);
                // catapult が確かめるのは足すほうだけで、最初の1つで止める
                if let Some(value) = restriction
                    .restriction_additions
                    .iter()
                    .find(|value| value.0 & 0xC000 != 0x4000)
                {
                    self.fail(Failure::AccountRestrictionInvalidValue(*value));
                }
            }
            Body::MosaicAddressRestriction(_) | Body::MosaicGlobalRestriction(_) => {}
            Body::Transfer(transfer) => {
                self.address(transfer.recipient_address());
                let size = transfer.message().len();
                if size > parameters.max_message_size {
                    self.fail(Failure::TransferMessageTooLarge {
                        size,
                        max: parameters.max_message_size,
                    });
                }
            }
            Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
                self.aggregate(aggregate, signer_public_key);
            }
        }
    }

    /// catapult の `MetadataSizes`。
    fn metadata(&mut self, metadata: &Metadata) {
        let size = metadata.value.len();
        if size == 0 {
            self.fail(Failure::MetadataValueTooSmall);
        } else if usize::from(metadata.value_size_delta.unsigned_abs()) > size {
            self.fail(Failure::MetadataValueSizeDeltaTooLarge {
                delta: metadata.value_size_delta,
                size,
            });
        } else if size > self.parameters.max_metadata_value_size {
            self.fail(Failure::MetadataValueTooLarge {
                size,
                max: self.parameters.max_metadata_value_size,
            });
        }
    }

    /// catapult の `AccountRestrictionFlags`。アドレスはどの向きでもよく、モザイクは受け取る側だけ、
    /// トランザクションの種類は送る側だけ。拒むか許すか（Block）は問わない。
    fn restriction_flags(&mut self, flags: AccountRestrictionFlags) {
        let kind = flags.bits()
            & !(AccountRestrictionFlags::OUTGOING.bits() | AccountRestrictionFlags::BLOCK.bits());
        let outgoing = flags.contains(AccountRestrictionFlags::OUTGOING);
        let valid = match kind {
            0x0001 => true,
            0x0002 => !outgoing,
            0x0004 => outgoing,
            _ => false,
        };
        if !valid {
            self.fail(Failure::AccountRestrictionInvalidFlags(flags));
        }
    }

    /// catapult の `BasicAggregateCosignatures` と、中のトランザクションそれぞれの規則。
    fn aggregate(&mut self, aggregate: &Aggregate, signer_public_key: &PublicKey) {
        let parameters = self.parameters;
        let count = aggregate.transactions().len();
        let signers: Vec<_> = core::iter::once(signer_public_key)
            .chain(
                aggregate
                    .cosignatures()
                    .iter()
                    .map(|cosignature| &cosignature.signer_public_key),
            )
            .map(|public_key| public_key.0)
            .collect();
        let unique: BTreeSet<_> = signers.iter().collect();
        if count == 0 {
            self.fail(Failure::AggregateNoTransactions);
        } else if count > parameters.max_transactions_per_aggregate {
            self.fail(Failure::AggregateTooManyTransactions {
                count,
                max: parameters.max_transactions_per_aggregate,
            });
        } else if signers.len() > parameters.max_cosignatures_per_aggregate {
            self.fail(Failure::AggregateTooManyCosignatures {
                count: signers.len(),
                max: parameters.max_cosignatures_per_aggregate,
            });
        } else if unique.len() != signers.len() {
            self.fail(Failure::AggregateRedundantCosignatures);
        }

        for (index, transaction) in aggregate.transactions().iter().enumerate() {
            self.location = Location::Embedded(index);
            self.entity(&transaction.signer_public_key, transaction.network);
            self.body(&transaction.body, &transaction.signer_public_key);
        }
        self.location = Location::Transaction;
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use heika_core::hash::Hash256;
    use heika_core::signature::Signature;

    use super::*;
    use crate::aggregate::{Cosignature, EmbeddedTransaction};
    use crate::lock::{HashLock, LockHashAlgorithm, SecretProof};
    use crate::mosaic::{
        MosaicDefinition, MosaicFlags, MosaicSupplyChange, MosaicSupplyChangeAction,
        UnresolvedMosaic,
    };
    use crate::multisig::MultisigAccountModification;
    use crate::namespace::NamespaceRegistration;
    use crate::restriction::AccountRestriction;
    use crate::transfer::{Transfer, UnresolvedMosaicId};
    use crate::{KeyLink, VotingKeyLink};

    const NETWORK: NetworkParameters = NetworkParameters::TESTNET;

    fn signer() -> PublicKey {
        PublicKey([0x11; 32])
    }

    fn transaction(body: Body) -> Transaction {
        Transaction::new(signer(), NETWORK.identifier, 0, 0, body)
    }

    /// トップレベルで送ったときに見つかる問題の、場所を除いたもの
    fn failures(body: Body) -> Vec<Failure> {
        transaction(body)
            .validate(&NETWORK)
            .into_iter()
            .map(|problem| {
                assert_eq!(problem.location, Location::Transaction);
                problem.failure
            })
            .collect()
    }

    fn transfer(recipient: [u8; 24], message: usize) -> Body {
        Body::Transfer(
            Transfer::new(
                UnresolvedAddress(recipient),
                BTreeMap::new(),
                vec![0; message],
            )
            .unwrap(),
        )
    }

    fn zero_address() -> [u8; 24] {
        Address::from_public_key(&PublicKey([0; 32]), NETWORK.identifier).0
    }

    fn metadata(value_size_delta: i16, value: usize) -> Metadata {
        Metadata {
            target_address: UnresolvedAddress([0x98; 24]),
            scoped_metadata_key: 1,
            value_size_delta,
            value: vec![0; value].try_into().unwrap(),
        }
    }

    #[test]
    fn accepts_a_plain_transfer() {
        assert_eq!(failures(transfer([0x98; 24], 1024)), []);
    }

    #[test]
    fn rejects_transfers_to_the_zero_address_and_long_messages() {
        assert_eq!(
            failures(transfer(zero_address(), 1025)),
            [
                Failure::ZeroAddress,
                Failure::TransferMessageTooLarge {
                    size: 1025,
                    max: 1024
                }
            ]
        );
    }

    #[test]
    fn checks_the_signer_the_network_and_the_fee_first() {
        let mut transaction = transaction(transfer([0x98; 24], 0));
        transaction.signer_public_key = PublicKey([0; 32]);
        transaction.network = NetworkIdentifier::MAINNET;
        transaction.fee = u64::from(u32::MAX) * transaction.size() as u64 + 1;
        let failures: Vec<_> = transaction
            .validate(&NETWORK)
            .into_iter()
            .map(|problem| problem.failure)
            .collect();
        assert_eq!(
            failures,
            [
                Failure::ZeroPublicKey,
                Failure::WrongNetwork {
                    expected: NetworkIdentifier::TESTNET,
                    actual: NetworkIdentifier::MAINNET
                },
                Failure::InvalidTransactionFee
            ]
        );
    }

    #[test]
    fn rejects_embeddable_only_types_at_the_top_level() {
        let body = Body::AccountMetadata(metadata(1, 1));
        assert_eq!(failures(body.clone()), [Failure::TopLevelNotSupported]);
        assert_eq!(Failure::TopLevelNotSupported.result(), None);

        // アグリゲートの中なら通る
        let embedded = EmbeddedTransaction::new(signer(), NETWORK.identifier, body);
        let aggregate = Aggregate::new(vec![embedded]).unwrap();
        assert_eq!(failures(Body::AggregateComplete(aggregate)), []);
    }

    #[test]
    fn checks_voting_key_ranges() {
        let link = |start_epoch, end_epoch| {
            Body::VotingKeyLink(VotingKeyLink {
                linked_public_key: PublicKey([0x22; 32]),
                start_epoch,
                end_epoch,
                link_action: LinkAction::Link,
            })
        };
        // テストネットは 28〜720 エポック
        assert_eq!(failures(link(1, 28)), []);
        assert_eq!(failures(link(0, 28)), [Failure::LinkStartEpochInvalid]);
        let range = |start, end| Failure::InvalidLinkRange {
            start,
            end,
            min: 28,
            max: 720,
        };
        assert_eq!(failures(link(1, 27)), [range(1, 27)]);
        assert_eq!(failures(link(1, 721)), [range(1, 721)]);
        assert_eq!(failures(link(10, 9)), [range(10, 9)]);
    }

    #[test]
    fn rejects_linking_the_zero_public_key() {
        let link = |link_action| {
            Body::AccountKeyLink(KeyLink {
                linked_public_key: PublicKey([0; 32]),
                link_action,
            })
        };
        assert_eq!(failures(link(LinkAction::Link)), [Failure::ZeroPublicKey]);
        assert_eq!(failures(link(LinkAction::Unlink)), []);
    }

    #[test]
    fn checks_lock_durations_in_blocks() {
        let lock = |duration| {
            Body::HashLock(HashLock {
                mosaic: UnresolvedMosaic {
                    mosaic_id: UnresolvedMosaicId(1),
                    amount: 10,
                },
                duration,
                hash: Hash256([0; 32]),
            })
        };
        assert_eq!(failures(lock(5_760)), []);
        assert_eq!(
            failures(lock(5_761)),
            [Failure::HashLockInvalidDuration {
                duration: 5_761,
                max: 5_760
            }]
        );
        assert_eq!(
            failures(lock(0)),
            [Failure::HashLockInvalidDuration {
                duration: 0,
                max: 5_760
            }]
        );
    }

    #[test]
    fn checks_proofs_against_secrets() {
        let proof = |proof: Vec<u8>, secret| {
            Body::SecretProof(SecretProof {
                recipient_address: UnresolvedAddress([0x98; 24]),
                secret,
                hash_algorithm: LockHashAlgorithm::Hash256,
                proof: proof.try_into().unwrap(),
            })
        };
        let secret = LockHashAlgorithm::Hash256.secret(b"proof");
        assert_eq!(failures(proof(b"proof".to_vec(), secret)), []);
        assert_eq!(
            failures(proof(b"other".to_vec(), secret)),
            [Failure::SecretMismatch]
        );
        assert_eq!(
            failures(proof(vec![0; 1025], secret)),
            [Failure::ProofSizeOutOfBounds {
                size: 1025,
                min: 0,
                max: 1024
            }]
        );
    }

    #[test]
    fn checks_metadata_sizes_in_order() {
        let embedded = |metadata| {
            let embedded = EmbeddedTransaction::new(
                signer(),
                NETWORK.identifier,
                Body::MosaicMetadata(crate::MosaicMetadata {
                    target_mosaic_id: UnresolvedMosaicId(1),
                    metadata,
                }),
            );
            let problems = transaction(Body::AggregateComplete(
                Aggregate::new(vec![embedded]).unwrap(),
            ))
            .validate(&NETWORK);
            problems
                .into_iter()
                .map(|problem| {
                    assert_eq!(problem.location, Location::Embedded(0));
                    problem.failure
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(embedded(metadata(-5, 0)), [Failure::MetadataValueTooSmall]);
        assert_eq!(
            embedded(metadata(-5, 4)),
            [Failure::MetadataValueSizeDeltaTooLarge { delta: -5, size: 4 }]
        );
        assert_eq!(
            embedded(metadata(1, 1025)),
            [Failure::MetadataValueTooLarge {
                size: 1025,
                max: 1024
            }]
        );
    }

    #[test]
    fn checks_mosaic_ids_against_the_signer() {
        let owner = Address::from_public_key(&signer(), NETWORK.identifier);
        let definition = |id| {
            Body::MosaicDefinition(MosaicDefinition {
                id,
                duration: 0,
                nonce: 7,
                flags: MosaicFlags::from_bits(0).unwrap(),
                divisibility: 0,
            })
        };
        let expected = MosaicId::generate(&owner, 7);
        assert_eq!(failures(definition(expected)), []);
        assert_eq!(
            failures(definition(MosaicId(0))),
            [Failure::MosaicInvalidId]
        );
        assert_eq!(
            failures(definition(MosaicId(1))),
            [Failure::MosaicIdMismatch { expected }]
        );
        let change = Body::MosaicSupplyChange(MosaicSupplyChange {
            mosaic_id: UnresolvedMosaicId(1),
            delta: 0,
            action: MosaicSupplyChangeAction::Increase,
        });
        assert_eq!(failures(change), [Failure::MosaicInvalidSupplyChangeAmount]);
    }

    #[test]
    fn checks_multisig_modifications() {
        let modification = |additions: Vec<[u8; 24]>, deletions: Vec<[u8; 24]>| {
            let addresses = |list: Vec<[u8; 24]>| {
                list.into_iter()
                    .map(UnresolvedAddress)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            };
            let body = Body::MultisigAccountModification(MultisigAccountModification {
                min_removal_delta: 0,
                min_approval_delta: 0,
                address_additions: addresses(additions),
                address_deletions: addresses(deletions),
            });
            let embedded = EmbeddedTransaction::new(signer(), NETWORK.identifier, body);
            transaction(Body::AggregateBonded(
                Aggregate::new(vec![embedded]).unwrap(),
            ))
            .validate(&NETWORK)
            .into_iter()
            .map(|problem| problem.failure)
            .collect::<Vec<_>>()
        };
        let (a, b, c) = ([0x98; 24], [0x99; 24], [0x9A; 24]);
        assert_eq!(modification(vec![a, b], vec![c]), []);
        assert_eq!(
            modification(vec![], vec![b, c]),
            [Failure::MultisigMultipleDeletes]
        );
        assert_eq!(
            modification(vec![a, a], vec![]),
            [Failure::MultisigRedundantModification]
        );
        assert_eq!(
            modification(vec![a], vec![a]),
            [Failure::MultisigAccountInBothSets]
        );
        assert_eq!(
            modification(vec![zero_address()], vec![]),
            [Failure::ZeroAddress]
        );
    }

    #[test]
    fn checks_namespace_names_ids_and_durations() {
        let root = |name: &[u8], id, duration| {
            Body::NamespaceRegistration(NamespaceRegistration {
                registration_type: NamespaceRegistrationType::Root { duration },
                id,
                name: name.to_vec().try_into().unwrap(),
            })
        };
        let id = NamespaceId::generate(None, b"heika");
        assert_eq!(failures(root(b"heika", id, 86_400)), []);
        // 0 は無期限で、範囲を問わない
        assert_eq!(failures(root(b"heika", id, 0)), []);
        assert_eq!(
            failures(root(b"heika", id, 86_399)),
            [Failure::NamespaceInvalidDuration {
                duration: 86_399,
                min: 86_400,
                max: 5_256_000
            }]
        );
        assert_eq!(
            failures(root(b"Heika", id, 0)),
            [Failure::NamespaceInvalidName]
        );
        assert_eq!(
            failures(root(&[b'a'; 65], id, 0)),
            [Failure::NamespaceInvalidName]
        );
        assert_eq!(
            failures(root(b"heika", NamespaceId(1), 0)),
            [Failure::NamespaceNameIdMismatch { expected: id }]
        );

        let child = Body::NamespaceRegistration(NamespaceRegistration {
            registration_type: NamespaceRegistrationType::Child { parent_id: id },
            id: NamespaceId::generate(Some(id), b"sub"),
            name: b"sub".to_vec().try_into().unwrap(),
        });
        assert_eq!(failures(child), []);
    }

    #[test]
    fn checks_account_restriction_flags_and_values() {
        let flags = |bits| AccountRestrictionFlags::from_bits(bits).unwrap();
        let mosaic = |bits| {
            Body::AccountMosaicRestriction(AccountRestriction {
                restriction_flags: flags(bits),
                restriction_additions: vec![UnresolvedMosaicId(1)].try_into().unwrap(),
                restriction_deletions: Vec::new().try_into().unwrap(),
            })
        };
        assert_eq!(failures(mosaic(0x8002)), []);
        assert_eq!(
            failures(mosaic(0x4002)),
            [Failure::AccountRestrictionInvalidFlags(flags(0x4002))]
        );
        let operation = |bits, value| {
            Body::AccountOperationRestriction(AccountRestriction {
                restriction_flags: flags(bits),
                restriction_additions: vec![TransactionType(0x4154), TransactionType(value)]
                    .try_into()
                    .unwrap(),
                restriction_deletions: Vec::new().try_into().unwrap(),
            })
        };
        assert_eq!(failures(operation(0x4004, 0x4141)), []);
        assert_eq!(
            failures(operation(0x0004, 0x8143)),
            [
                Failure::AccountRestrictionInvalidFlags(flags(0x0004)),
                Failure::AccountRestrictionInvalidValue(TransactionType(0x8143))
            ]
        );
        let address = Body::AccountAddressRestriction(AccountRestriction {
            restriction_flags: flags(0x0003),
            restriction_additions: Vec::new().try_into().unwrap(),
            restriction_deletions: Vec::new().try_into().unwrap(),
        });
        assert_eq!(
            failures(address),
            [Failure::AccountRestrictionInvalidFlags(flags(0x0003))]
        );
    }

    #[test]
    fn checks_aggregate_counts_and_cosigners() {
        let embedded =
            || EmbeddedTransaction::new(signer(), NETWORK.identifier, transfer([0x98; 24], 0));
        assert_eq!(
            failures(Body::AggregateComplete(Aggregate::new(Vec::new()).unwrap())),
            [Failure::AggregateNoTransactions]
        );
        assert_eq!(
            failures(Body::AggregateComplete(
                Aggregate::new(vec![embedded(); 101]).unwrap()
            )),
            [Failure::AggregateTooManyTransactions {
                count: 101,
                max: 100
            }]
        );

        let cosigned = |keys: &[u8]| {
            let mut aggregate = Aggregate::new(vec![embedded()]).unwrap();
            for key in keys {
                aggregate.add_cosignature(Cosignature {
                    signer_public_key: PublicKey([*key; 32]),
                    signature: Signature([0; 64]),
                });
            }
            failures(Body::AggregateComplete(aggregate))
        };
        assert_eq!(cosigned(&[0x22]), []);
        assert_eq!(cosigned(&[0x11]), [Failure::AggregateRedundantCosignatures]);
        let keys: Vec<u8> = (0x20..0x38).collect();
        assert_eq!(cosigned(&keys), []);
        let keys: Vec<u8> = (0x20..0x39).collect();
        assert_eq!(
            cosigned(&keys),
            [Failure::AggregateTooManyCosignatures { count: 26, max: 25 }]
        );
    }

    #[test]
    fn reports_where_in_the_aggregate_the_problem_is() {
        let mut wrong = EmbeddedTransaction::new(
            signer(),
            NetworkIdentifier::MAINNET,
            transfer([0x98; 24], 0),
        );
        let ok = EmbeddedTransaction::new(signer(), NETWORK.identifier, transfer([0x98; 24], 0));
        wrong.signer_public_key = PublicKey([0; 32]);
        let problems = transaction(Body::AggregateComplete(
            Aggregate::new(vec![ok, wrong]).unwrap(),
        ))
        .validate(&NETWORK);
        assert_eq!(
            problems,
            [
                Problem {
                    location: Location::Embedded(1),
                    failure: Failure::ZeroPublicKey
                },
                Problem {
                    location: Location::Embedded(1),
                    failure: Failure::WrongNetwork {
                        expected: NetworkIdentifier::TESTNET,
                        actual: NetworkIdentifier::MAINNET
                    }
                }
            ]
        );
        assert_eq!(problems[0].to_string(), "中の 2 件目: 公開鍵が0です");
    }

    #[test]
    fn gives_catapult_result_codes() {
        let result = |failure: Failure| failure.result().unwrap();
        assert_eq!(
            result(Failure::TransferMessageTooLarge { size: 0, max: 0 }),
            ("Failure_Transfer_Message_Too_Large", 0x8054_0001)
        );
        assert_eq!(
            result(Failure::ZeroPublicKey),
            ("Failure_Core_Zero_Public_Key", 0x8043_000C)
        );
        assert_eq!(
            result(Failure::MosaicInvalidId),
            ("Failure_Mosaic_Invalid_Id", 0x804D_006A)
        );
        assert_eq!(
            result(Failure::AggregateRedundantCosignatures),
            ("Failure_Aggregate_Redundant_Cosignatures", 0x8041_0004)
        );
    }
}
