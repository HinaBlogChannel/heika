//! `models/transactions.json`: トランザクションのバイト列と、その中身。
//! ここにある署名はレイアウトを試すための値で、検証は通らない。

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use heika_transaction::{
    AccountRestriction, AccountRestrictionFlags, AddressAlias, Aggregate, AliasAction, Body,
    Cosignature, EmbeddedTransaction, HashLock, KeyLink, LinkAction, LockHashAlgorithm, Metadata,
    MosaicAddressRestriction, MosaicAlias, MosaicDefinition, MosaicFlags, MosaicGlobalRestriction,
    MosaicId, MosaicMetadata, MosaicRestrictionType, MosaicSupplyChange, MosaicSupplyChangeAction,
    MosaicSupplyRevocation, MultisigAccountModification, NamespaceId, NamespaceMetadata,
    NamespaceRegistration, NamespaceRegistrationType, SecretLock, SecretProof, Transaction,
    TransactionType, Transfer, UnresolvedAddress, UnresolvedMosaic, UnresolvedMosaicId,
    VotingKeyLink, scan,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Vector {
    schema_name: String,
    test_name: String,
    payload: String,
    descriptor: Value,
}

/// 照合する種類。catbuffer の25種類で、アグリゲートは heika-transaction が書くバージョン 3 だけ。
/// それより前のアグリゲートは、走査（`scan`）だけが読む。
const SCHEMAS: [&str; 25] = [
    "AccountKeyLinkTransactionV1",
    "NodeKeyLinkTransactionV1",
    "VotingKeyLinkTransactionV1",
    "VrfKeyLinkTransactionV1",
    "HashLockTransactionV1",
    "SecretLockTransactionV1",
    "SecretProofTransactionV1",
    "AccountMetadataTransactionV1",
    "MosaicMetadataTransactionV1",
    "NamespaceMetadataTransactionV1",
    "MosaicDefinitionTransactionV1",
    "MosaicSupplyChangeTransactionV1",
    "MosaicSupplyRevocationTransactionV1",
    "MultisigAccountModificationTransactionV1",
    "AddressAliasTransactionV1",
    "MosaicAliasTransactionV1",
    "NamespaceRegistrationTransactionV1",
    "AccountAddressRestrictionTransactionV1",
    "AccountMosaicRestrictionTransactionV1",
    "AccountOperationRestrictionTransactionV1",
    "MosaicAddressRestrictionTransactionV1",
    "MosaicGlobalRestrictionTransactionV1",
    "TransferTransactionV1",
    "AggregateCompleteTransactionV3",
    "AggregateBondedTransactionV3",
];

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// チェックサムを確かめずに、39文字の Base32 を24バイトにする。
/// ネームスペースを指すアドレスにはチェックサムがないので、`Address` の `FromStr` は使えない。
fn from_base32(text: &str) -> [u8; 24] {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u64;
    let mut count = 0;
    let mut bytes = Vec::new();
    for character in format!("{text}A").bytes() {
        let value = ALPHABET.iter().position(|&c| c == character).unwrap() as u64;
        bits = bits << 5 | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            bytes.push((bits >> count) as u8);
        }
    }
    bytes[..24].try_into().unwrap()
}

fn text<'a>(descriptor: &'a Value, field: &str) -> &'a str {
    descriptor[field].as_str().unwrap()
}

/// SDK のベクターの読み方（`sdk/python/tests/vectors/catbuffer.py` の
/// `fixup_descriptor_common`）に合わせて、大文字の16進だけの文字列は16進、それ以外は UTF-8 として読む。
fn bytes(text: &str) -> Vec<u8> {
    if !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
    {
        from_hex(text)
    } else {
        text.as_bytes().to_vec()
    }
}

fn number(descriptor: &Value, field: &str) -> u64 {
    descriptor[field].as_u64().unwrap()
}

fn address(descriptor: &Value, field: &str) -> UnresolvedAddress {
    UnresolvedAddress(from_base32(text(descriptor, field)))
}

fn addresses(descriptor: &Value, field: &str) -> Vec<UnresolvedAddress> {
    descriptor[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|address| UnresolvedAddress(from_base32(address.as_str().unwrap())))
        .collect()
}

fn link_action(descriptor: &Value) -> LinkAction {
    match text(descriptor, "link_action") {
        "link" => LinkAction::Link,
        "unlink" => LinkAction::Unlink,
        action => panic!("link_action {action}"),
    }
}

fn alias_action(descriptor: &Value) -> AliasAction {
    match text(descriptor, "alias_action") {
        "link" => AliasAction::Link,
        "unlink" => AliasAction::Unlink,
        action => panic!("alias_action {action}"),
    }
}

fn key_link(descriptor: &Value) -> KeyLink {
    KeyLink {
        linked_public_key: text(descriptor, "linked_public_key").parse().unwrap(),
        link_action: link_action(descriptor),
    }
}

fn mosaic(descriptor: &Value) -> UnresolvedMosaic {
    UnresolvedMosaic {
        mosaic_id: UnresolvedMosaicId(number(descriptor, "mosaic_id")),
        amount: number(descriptor, "amount"),
    }
}

fn hash_algorithm(descriptor: &Value) -> LockHashAlgorithm {
    match text(descriptor, "hash_algorithm") {
        "sha3_256" => LockHashAlgorithm::Sha3_256,
        "hash_160" => LockHashAlgorithm::Hash160,
        "hash_256" => LockHashAlgorithm::Hash256,
        algorithm => panic!("hash_algorithm {algorithm}"),
    }
}

fn metadata(descriptor: &Value) -> Metadata {
    // SDK も、ネームスペースのメタデータの値 `ABC123` だけは、16進ではなく文字列として読む
    let value = text(descriptor, "value");
    let value = if descriptor["type"] == "namespace_metadata_transaction_v1" {
        value.as_bytes().to_vec()
    } else {
        bytes(value)
    };
    Metadata {
        target_address: address(descriptor, "target_address"),
        scoped_metadata_key: number(descriptor, "scoped_metadata_key"),
        value_size_delta: descriptor["value_size_delta"].as_i64().unwrap() as i16,
        value: value.try_into().unwrap(),
    }
}

/// フラグは、名前を空白で区切って並べてある
fn mosaic_flags(descriptor: &Value) -> MosaicFlags {
    text(descriptor, "flags")
        .split_whitespace()
        .fold(MosaicFlags::default(), |flags, name| {
            flags
                | match name {
                    "supply_mutable" => MosaicFlags::SUPPLY_MUTABLE,
                    "transferable" => MosaicFlags::TRANSFERABLE,
                    "restrictable" => MosaicFlags::RESTRICTABLE,
                    "revokable" => MosaicFlags::REVOKABLE,
                    "none" => MosaicFlags::default(),
                    _ => panic!("flags {name}"),
                }
        })
}

fn account_restriction<T>(
    descriptor: &Value,
    value: impl Fn(&Value) -> T,
) -> AccountRestriction<T> {
    let restriction_flags = text(descriptor, "restriction_flags")
        .split_whitespace()
        .map(|name| match name {
            "address" => AccountRestrictionFlags::ADDRESS,
            "mosaic_id" => AccountRestrictionFlags::MOSAIC_ID,
            "transaction_type" => AccountRestrictionFlags::TRANSACTION_TYPE,
            "outgoing" => AccountRestrictionFlags::OUTGOING,
            "block" => AccountRestrictionFlags::BLOCK,
            _ => panic!("restriction_flags {name}"),
        })
        .reduce(|flags, flag| flags | flag)
        .unwrap();
    let values = |field: &str| {
        descriptor[field]
            .as_array()
            .unwrap()
            .iter()
            .map(&value)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    };
    AccountRestriction {
        restriction_flags,
        restriction_additions: values("restriction_additions"),
        restriction_deletions: values("restriction_deletions"),
    }
}

/// catbuffer の `TransactionType` の名前
fn transaction_type(name: &str) -> TransactionType {
    TransactionType(match name {
        "account_key_link" => 0x414C,
        "node_key_link" => 0x424C,
        "aggregate_complete" => 0x4141,
        "aggregate_bonded" => 0x4241,
        "voting_key_link" => 0x4143,
        "vrf_key_link" => 0x4243,
        "hash_lock" => 0x4148,
        "secret_lock" => 0x4152,
        "secret_proof" => 0x4252,
        "account_metadata" => 0x4144,
        "mosaic_metadata" => 0x4244,
        "namespace_metadata" => 0x4344,
        "mosaic_definition" => 0x414D,
        "mosaic_supply_change" => 0x424D,
        "mosaic_supply_revocation" => 0x434D,
        "multisig_account_modification" => 0x4155,
        "address_alias" => 0x424E,
        "mosaic_alias" => 0x434E,
        "namespace_registration" => 0x414E,
        "account_address_restriction" => 0x4150,
        "account_mosaic_restriction" => 0x4250,
        "account_operation_restriction" => 0x4350,
        "mosaic_address_restriction" => 0x4251,
        "mosaic_global_restriction" => 0x4151,
        "transfer" => 0x4154,
        _ => panic!("transaction type {name}"),
    })
}

fn mosaic_restriction_type(descriptor: &Value, field: &str) -> MosaicRestrictionType {
    match text(descriptor, field) {
        "none" => MosaicRestrictionType::None,
        "eq" => MosaicRestrictionType::Eq,
        "ne" => MosaicRestrictionType::Ne,
        "lt" => MosaicRestrictionType::Lt,
        "le" => MosaicRestrictionType::Le,
        "gt" => MosaicRestrictionType::Gt,
        "ge" => MosaicRestrictionType::Ge,
        name => panic!("{field} {name}"),
    }
}

fn transfer(descriptor: &Value) -> Transfer {
    let mosaics = descriptor["mosaics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mosaic| {
            (
                UnresolvedMosaicId(mosaic["mosaic_id"].as_u64().unwrap()),
                mosaic["amount"].as_u64().unwrap(),
            )
        })
        .collect();
    let message = descriptor["message"]
        .as_str()
        .map(bytes)
        .unwrap_or_default();
    Transfer::new(address(descriptor, "recipient_address"), mosaics, message).unwrap()
}

fn public_key(descriptor: &Value, field: &str) -> PublicKey {
    descriptor[field]
        .as_str()
        .map_or(PublicKey([0; 32]), |text| text.parse().unwrap())
}

fn aggregate(descriptor: &Value) -> Aggregate {
    let transactions = descriptor["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|embedded| {
            // 中のトランザクションの署名者とネットワークは、descriptor にないときは0とテストネット
            let signer = public_key(embedded, "signer_public_key");
            EmbeddedTransaction::new(signer, NetworkIdentifier::TESTNET, body(embedded, &signer))
        })
        .collect();
    let mut aggregate = Aggregate::new(transactions).unwrap();
    for cosignature in descriptor["cosignatures"].as_array().unwrap() {
        assert_eq!(cosignature["version"].as_u64().unwrap_or(0), 0);
        aggregate.add_cosignature(Cosignature {
            signer_public_key: public_key(cosignature, "signer_public_key"),
            signature: text(cosignature, "signature").parse().unwrap(),
        });
    }
    assert_eq!(
        aggregate.transactions_hash().to_string(),
        text(descriptor, "transactions_hash")
    );
    aggregate
}

/// descriptor の種類から本体を組む。`signer` はモザイクの ID を求めるのに使う。
fn body(descriptor: &Value, signer: &PublicKey) -> Body {
    match text(descriptor, "type") {
        "account_key_link_transaction_v1" => Body::AccountKeyLink(key_link(descriptor)),
        "node_key_link_transaction_v1" => Body::NodeKeyLink(key_link(descriptor)),
        "voting_key_link_transaction_v1" => Body::VotingKeyLink(VotingKeyLink {
            linked_public_key: text(descriptor, "linked_public_key").parse().unwrap(),
            start_epoch: number(descriptor, "start_epoch") as u32,
            end_epoch: number(descriptor, "end_epoch") as u32,
            link_action: link_action(descriptor),
        }),
        "vrf_key_link_transaction_v1" => Body::VrfKeyLink(key_link(descriptor)),
        "hash_lock_transaction_v1" => Body::HashLock(HashLock {
            mosaic: mosaic(&descriptor["mosaic"]),
            duration: number(descriptor, "duration"),
            hash: text(descriptor, "hash").parse().unwrap(),
        }),
        "secret_lock_transaction_v1" => Body::SecretLock(SecretLock {
            recipient_address: address(descriptor, "recipient_address"),
            secret: text(descriptor, "secret").parse().unwrap(),
            mosaic: mosaic(&descriptor["mosaic"]),
            duration: number(descriptor, "duration"),
            hash_algorithm: hash_algorithm(descriptor),
        }),
        "secret_proof_transaction_v1" => Body::SecretProof(SecretProof {
            recipient_address: address(descriptor, "recipient_address"),
            secret: text(descriptor, "secret").parse().unwrap(),
            hash_algorithm: hash_algorithm(descriptor),
            proof: bytes(text(descriptor, "proof")).try_into().unwrap(),
        }),
        "account_metadata_transaction_v1" => Body::AccountMetadata(metadata(descriptor)),
        "mosaic_metadata_transaction_v1" => Body::MosaicMetadata(MosaicMetadata {
            target_mosaic_id: UnresolvedMosaicId(number(descriptor, "target_mosaic_id")),
            metadata: metadata(descriptor),
        }),
        "namespace_metadata_transaction_v1" => Body::NamespaceMetadata(NamespaceMetadata {
            target_namespace_id: NamespaceId(number(descriptor, "target_namespace_id")),
            metadata: metadata(descriptor),
        }),
        "mosaic_definition_transaction_v1" => {
            // ID は descriptor になく、SDK が署名者のアドレスとノンスから求めている
            let nonce = number(descriptor, "nonce") as u32;
            let owner = Address::from_public_key(signer, NetworkIdentifier::TESTNET);
            Body::MosaicDefinition(MosaicDefinition {
                id: MosaicId::generate(&owner, nonce),
                duration: number(descriptor, "duration"),
                nonce,
                flags: mosaic_flags(descriptor),
                divisibility: number(descriptor, "divisibility") as u8,
            })
        }
        "mosaic_supply_change_transaction_v1" => Body::MosaicSupplyChange(MosaicSupplyChange {
            mosaic_id: UnresolvedMosaicId(number(descriptor, "mosaic_id")),
            delta: number(descriptor, "delta"),
            action: match text(descriptor, "action") {
                "increase" => MosaicSupplyChangeAction::Increase,
                "decrease" => MosaicSupplyChangeAction::Decrease,
                action => panic!("action {action}"),
            },
        }),
        "mosaic_supply_revocation_transaction_v1" => {
            Body::MosaicSupplyRevocation(MosaicSupplyRevocation {
                source_address: address(descriptor, "source_address"),
                mosaic: mosaic(&descriptor["mosaic"]),
            })
        }
        "multisig_account_modification_transaction_v1" => {
            Body::MultisigAccountModification(MultisigAccountModification {
                min_removal_delta: descriptor["min_removal_delta"].as_i64().unwrap() as i8,
                min_approval_delta: descriptor["min_approval_delta"].as_i64().unwrap() as i8,
                address_additions: addresses(descriptor, "address_additions")
                    .try_into()
                    .unwrap(),
                address_deletions: addresses(descriptor, "address_deletions")
                    .try_into()
                    .unwrap(),
            })
        }
        "address_alias_transaction_v1" => Body::AddressAlias(AddressAlias {
            namespace_id: NamespaceId(number(descriptor, "namespace_id")),
            address: text(descriptor, "address").parse().unwrap(),
            alias_action: alias_action(descriptor),
        }),
        "mosaic_alias_transaction_v1" => Body::MosaicAlias(MosaicAlias {
            namespace_id: NamespaceId(number(descriptor, "namespace_id")),
            mosaic_id: MosaicId(number(descriptor, "mosaic_id")),
            alias_action: alias_action(descriptor),
        }),
        "namespace_registration_transaction_v1" => {
            Body::NamespaceRegistration(NamespaceRegistration {
                registration_type: match text(descriptor, "registration_type") {
                    "root" => NamespaceRegistrationType::Root {
                        duration: number(descriptor, "duration"),
                    },
                    "child" => NamespaceRegistrationType::Child {
                        parent_id: NamespaceId(number(descriptor, "parent_id")),
                    },
                    registration_type => panic!("registration_type {registration_type}"),
                },
                id: NamespaceId(number(descriptor, "id")),
                name: text(descriptor, "name")
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .unwrap(),
            })
        }
        "account_address_restriction_transaction_v1" => {
            Body::AccountAddressRestriction(account_restriction(descriptor, |address| {
                UnresolvedAddress(from_base32(address.as_str().unwrap()))
            }))
        }
        "account_mosaic_restriction_transaction_v1" => {
            Body::AccountMosaicRestriction(account_restriction(descriptor, |id| {
                UnresolvedMosaicId(id.as_u64().unwrap())
            }))
        }
        "account_operation_restriction_transaction_v1" => {
            Body::AccountOperationRestriction(account_restriction(descriptor, |name| {
                transaction_type(name.as_str().unwrap())
            }))
        }
        "mosaic_address_restriction_transaction_v1" => {
            Body::MosaicAddressRestriction(MosaicAddressRestriction {
                mosaic_id: UnresolvedMosaicId(number(descriptor, "mosaic_id")),
                restriction_key: number(descriptor, "restriction_key"),
                previous_restriction_value: number(descriptor, "previous_restriction_value"),
                new_restriction_value: number(descriptor, "new_restriction_value"),
                target_address: address(descriptor, "target_address"),
            })
        }
        "mosaic_global_restriction_transaction_v1" => {
            Body::MosaicGlobalRestriction(MosaicGlobalRestriction {
                mosaic_id: UnresolvedMosaicId(number(descriptor, "mosaic_id")),
                reference_mosaic_id: UnresolvedMosaicId(number(descriptor, "reference_mosaic_id")),
                restriction_key: number(descriptor, "restriction_key"),
                previous_restriction_value: number(descriptor, "previous_restriction_value"),
                new_restriction_value: number(descriptor, "new_restriction_value"),
                previous_restriction_type: mosaic_restriction_type(
                    descriptor,
                    "previous_restriction_type",
                ),
                new_restriction_type: mosaic_restriction_type(descriptor, "new_restriction_type"),
            })
        }
        "transfer_transaction_v1" => Body::Transfer(transfer(descriptor)),
        "aggregate_complete_transaction_v3" => Body::AggregateComplete(aggregate(descriptor)),
        "aggregate_bonded_transaction_v3" => Body::AggregateBonded(aggregate(descriptor)),
        name => panic!("type {name}"),
    }
}

fn expected(vector: &Vector) -> Transaction {
    let descriptor = &vector.descriptor;
    let signer_public_key: PublicKey = text(descriptor, "signer_public_key").parse().unwrap();
    let mut transaction = Transaction::new(
        signer_public_key,
        // ベクターはどれもテストネットのもので、descriptor には書かれていない
        NetworkIdentifier::TESTNET,
        descriptor["fee"].as_u64().unwrap(),
        descriptor["deadline"].as_u64().unwrap(),
        body(descriptor, &signer_public_key),
    );
    let signature: Signature = text(descriptor, "signature").parse().unwrap();
    transaction.signature = signature;
    transaction
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn reads_and_writes_transactions() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/transactions.json");
    for schema in SCHEMAS {
        let vectors: Vec<_> = vectors
            .iter()
            .filter(|vector| vector.schema_name == schema)
            .map(|vector| (vector, expected(vector)))
            .collect();
        assert!(!vectors.is_empty(), "{schema}");
        for (vector, expected) in &vectors {
            let payload = from_hex(&vector.payload);
            let transaction = Transaction::from_bytes(&payload).unwrap();
            assert_eq!(transaction, *expected, "{}", vector.test_name);
            assert_eq!(transaction.to_bytes(), payload, "{}", vector.test_name);
        }
        eprintln!("{schema}: {} vectors checked", vectors.len());
    }
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn scans_every_transaction() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/transactions.json");
    // 走査は、バージョン 1 と 2 のアグリゲートも含めて全部読める
    for vector in &vectors {
        let descriptor = &vector.descriptor;
        let scanned = scan(&from_hex(&vector.payload))
            .unwrap_or_else(|error| panic!("{}: {error}", vector.test_name));
        let bodies: Vec<_> = scanned.into_iter().map(|scanned| scanned.body).collect();
        let expected: Vec<_> = match descriptor["transactions"].as_array() {
            Some(transactions) => transactions
                .iter()
                .map(|embedded| body(embedded, &public_key(embedded, "signer_public_key")))
                .collect(),
            None => vec![body(
                descriptor,
                &public_key(descriptor, "signer_public_key"),
            )],
        };
        assert_eq!(bodies, expected, "{}", vector.test_name);
    }
    eprintln!("{} vectors scanned", vectors.len());
}
