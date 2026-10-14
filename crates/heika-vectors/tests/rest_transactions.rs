//! `models/transactions.json` のトランザクションを、REST が返す形の JSON にしてから heika-rest で組み直し、
//! 元のバイト列に戻ることを確かめる。
//!
//! JSON の形は、catapult-rest の `catapult-sdk/plugins` のスキーマと `server/messageFormattingRules.js` に合わせて、
//! ここで heika の型から書く。アドレスとハッシュとバイト列は16進、u64 は10進の文字列、ID は上位から書いた16進、
//! 小さい数と列挙は数、ネームスペースの名前はそのままの文字列。

use heika_rest::transaction::TransactionInfo;
use heika_transaction::{
    AccountRestriction, AliasAction, Body, EmbeddedTransaction, LinkAction, LockHashAlgorithm,
    MosaicRestrictionType, MosaicSupplyChangeAction, NamespaceRegistrationType, Transaction,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

#[derive(Deserialize)]
struct Vector {
    test_name: String,
    payload: String,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> Value {
    json!(
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    )
}

fn id(value: u64) -> Value {
    json!(format!("{value:016X}"))
}

fn decimal(value: u64) -> Value {
    json!(value.to_string())
}

fn link(action: LinkAction) -> Value {
    json!(match action {
        LinkAction::Unlink => 0,
        LinkAction::Link => 1,
    })
}

fn alias(action: AliasAction) -> Value {
    json!(match action {
        AliasAction::Unlink => 0,
        AliasAction::Link => 1,
    })
}

fn restriction_type(value: MosaicRestrictionType) -> Value {
    json!(match value {
        MosaicRestrictionType::None => 0,
        MosaicRestrictionType::Eq => 1,
        MosaicRestrictionType::Ne => 2,
        MosaicRestrictionType::Lt => 3,
        MosaicRestrictionType::Le => 4,
        MosaicRestrictionType::Gt => 5,
        MosaicRestrictionType::Ge => 6,
    })
}

fn account_restriction<T>(
    body: &mut Map<String, Value>,
    restriction: &AccountRestriction<T>,
    value: impl Fn(&T) -> Value,
) {
    body.insert(
        "restrictionFlags".into(),
        json!(restriction.restriction_flags.bits()),
    );
    body.insert(
        "restrictionAdditions".into(),
        restriction
            .restriction_additions
            .iter()
            .map(&value)
            .collect(),
    );
    body.insert(
        "restrictionDeletions".into(),
        restriction
            .restriction_deletions
            .iter()
            .map(&value)
            .collect(),
    );
}

/// 種類ごとの本体の項目
fn body_json(body: &Body, seed: &mut Map<String, Value>) {
    let b = seed;
    match body {
        Body::AccountKeyLink(l) | Body::NodeKeyLink(l) | Body::VrfKeyLink(l) => {
            b.insert("linkedPublicKey".into(), hex(&l.linked_public_key.0));
            b.insert("linkAction".into(), link(l.link_action));
        }
        Body::VotingKeyLink(l) => {
            b.insert("linkedPublicKey".into(), hex(&l.linked_public_key.0));
            b.insert("startEpoch".into(), json!(l.start_epoch));
            b.insert("endEpoch".into(), json!(l.end_epoch));
            b.insert("linkAction".into(), link(l.link_action));
        }
        Body::HashLock(l) => {
            b.insert("mosaicId".into(), id(l.mosaic.mosaic_id.0));
            b.insert("amount".into(), decimal(l.mosaic.amount));
            b.insert("duration".into(), decimal(l.duration));
            b.insert("hash".into(), hex(&l.hash.0));
        }
        Body::SecretLock(l) => {
            b.insert("recipientAddress".into(), hex(&l.recipient_address.0));
            b.insert("secret".into(), hex(&l.secret.0));
            b.insert("mosaicId".into(), id(l.mosaic.mosaic_id.0));
            b.insert("amount".into(), decimal(l.mosaic.amount));
            b.insert("duration".into(), decimal(l.duration));
            b.insert("hashAlgorithm".into(), hash_algorithm(l.hash_algorithm));
        }
        Body::SecretProof(p) => {
            b.insert("recipientAddress".into(), hex(&p.recipient_address.0));
            b.insert("secret".into(), hex(&p.secret.0));
            b.insert("hashAlgorithm".into(), hash_algorithm(p.hash_algorithm));
            b.insert("proof".into(), hex(&p.proof));
        }
        Body::AccountMetadata(m)
        | Body::MosaicMetadata(heika_transaction::MosaicMetadata { metadata: m, .. })
        | Body::NamespaceMetadata(heika_transaction::NamespaceMetadata { metadata: m, .. }) => {
            b.insert("targetAddress".into(), hex(&m.target_address.0));
            b.insert("scopedMetadataKey".into(), id(m.scoped_metadata_key));
            b.insert("valueSizeDelta".into(), json!(m.value_size_delta));
            b.insert("valueSize".into(), json!(m.value.len()));
            b.insert("value".into(), hex(&m.value));
            match body {
                Body::MosaicMetadata(mosaic) => {
                    b.insert("targetMosaicId".into(), id(mosaic.target_mosaic_id.0));
                }
                Body::NamespaceMetadata(namespace) => {
                    b.insert(
                        "targetNamespaceId".into(),
                        id(namespace.target_namespace_id.0),
                    );
                }
                _ => {}
            }
        }
        Body::MosaicDefinition(d) => {
            b.insert("id".into(), id(d.id.0));
            b.insert("duration".into(), decimal(d.duration));
            b.insert("nonce".into(), json!(d.nonce));
            b.insert("flags".into(), json!(d.flags.bits()));
            b.insert("divisibility".into(), json!(d.divisibility));
        }
        Body::MosaicSupplyChange(c) => {
            b.insert("mosaicId".into(), id(c.mosaic_id.0));
            b.insert("delta".into(), decimal(c.delta));
            b.insert(
                "action".into(),
                json!(match c.action {
                    MosaicSupplyChangeAction::Decrease => 0,
                    MosaicSupplyChangeAction::Increase => 1,
                }),
            );
        }
        Body::MosaicSupplyRevocation(r) => {
            b.insert("sourceAddress".into(), hex(&r.source_address.0));
            b.insert("mosaicId".into(), id(r.mosaic.mosaic_id.0));
            b.insert("amount".into(), decimal(r.mosaic.amount));
        }
        Body::MultisigAccountModification(m) => {
            b.insert("minRemovalDelta".into(), json!(m.min_removal_delta));
            b.insert("minApprovalDelta".into(), json!(m.min_approval_delta));
            b.insert(
                "addressAdditions".into(),
                m.address_additions.iter().map(|a| hex(&a.0)).collect(),
            );
            b.insert(
                "addressDeletions".into(),
                m.address_deletions.iter().map(|a| hex(&a.0)).collect(),
            );
        }
        Body::AddressAlias(a) => {
            b.insert("namespaceId".into(), id(a.namespace_id.0));
            b.insert("address".into(), hex(&a.address.0));
            b.insert("aliasAction".into(), alias(a.alias_action));
        }
        Body::MosaicAlias(a) => {
            b.insert("namespaceId".into(), id(a.namespace_id.0));
            b.insert("mosaicId".into(), id(a.mosaic_id.0));
            b.insert("aliasAction".into(), alias(a.alias_action));
        }
        Body::NamespaceRegistration(r) => {
            match r.registration_type {
                NamespaceRegistrationType::Root { duration } => {
                    b.insert("registrationType".into(), json!(0));
                    b.insert("duration".into(), decimal(duration));
                }
                NamespaceRegistrationType::Child { parent_id } => {
                    b.insert("registrationType".into(), json!(1));
                    b.insert("parentId".into(), id(parent_id.0));
                }
            }
            b.insert("id".into(), id(r.id.0));
            b.insert(
                "name".into(),
                json!(String::from_utf8(r.name.to_vec()).unwrap()),
            );
        }
        Body::AccountAddressRestriction(r) => account_restriction(b, r, |a| hex(&a.0)),
        Body::AccountMosaicRestriction(r) => account_restriction(b, r, |m| id(m.0)),
        Body::AccountOperationRestriction(r) => account_restriction(b, r, |t| json!(t.0)),
        Body::MosaicAddressRestriction(r) => {
            b.insert("mosaicId".into(), id(r.mosaic_id.0));
            b.insert("restrictionKey".into(), id(r.restriction_key));
            b.insert(
                "previousRestrictionValue".into(),
                decimal(r.previous_restriction_value),
            );
            b.insert(
                "newRestrictionValue".into(),
                decimal(r.new_restriction_value),
            );
            b.insert("targetAddress".into(), hex(&r.target_address.0));
        }
        Body::MosaicGlobalRestriction(r) => {
            b.insert("mosaicId".into(), id(r.mosaic_id.0));
            b.insert("referenceMosaicId".into(), id(r.reference_mosaic_id.0));
            b.insert("restrictionKey".into(), id(r.restriction_key));
            b.insert(
                "previousRestrictionValue".into(),
                decimal(r.previous_restriction_value),
            );
            b.insert(
                "newRestrictionValue".into(),
                decimal(r.new_restriction_value),
            );
            b.insert(
                "previousRestrictionType".into(),
                restriction_type(r.previous_restriction_type),
            );
            b.insert(
                "newRestrictionType".into(),
                restriction_type(r.new_restriction_type),
            );
        }
        Body::Transfer(t) => {
            b.insert("recipientAddress".into(), hex(&t.recipient_address().0));
            b.insert(
                "mosaics".into(),
                t.mosaics()
                    .iter()
                    .map(|(mosaic, amount)| json!({ "id": id(mosaic.0), "amount": decimal(*amount) }))
                    .collect(),
            );
            if !t.message().is_empty() {
                b.insert("message".into(), hex(t.message()));
            }
        }
        Body::AggregateComplete(a) | Body::AggregateBonded(a) => {
            b.insert("transactionsHash".into(), hex(&a.transactions_hash().0));
            b.insert(
                "cosignatures".into(),
                a.cosignatures()
                    .iter()
                    .map(|c| {
                        json!({
                            "version": "0",
                            "signerPublicKey": hex(&c.signer_public_key.0),
                            "signature": hex(&c.signature.0),
                        })
                    })
                    .collect(),
            );
            b.insert(
                "transactions".into(),
                a.transactions()
                    .iter()
                    .enumerate()
                    .map(|(index, embedded)| json!({ "meta": { "index": index }, "transaction": embedded_json(embedded) }))
                    .collect(),
            );
        }
    }
}

fn hash_algorithm(algorithm: LockHashAlgorithm) -> Value {
    json!(match algorithm {
        LockHashAlgorithm::Sha3_256 => 0,
        LockHashAlgorithm::Hash160 => 1,
        LockHashAlgorithm::Hash256 => 2,
    })
}

fn embedded_json(embedded: &EmbeddedTransaction) -> Value {
    let mut map = Map::new();
    map.insert("signerPublicKey".into(), hex(&embedded.signer_public_key.0));
    map.insert("version".into(), json!(embedded.body.version()));
    map.insert("network".into(), json!(embedded.network.0));
    map.insert("type".into(), json!(embedded.body.transaction_type()));
    body_json(&embedded.body, &mut map);
    Value::Object(map)
}

fn transaction_json(transaction: &Transaction) -> Value {
    let mut map = Map::new();
    map.insert("size".into(), json!(transaction.size()));
    map.insert("signature".into(), hex(&transaction.signature.0));
    map.insert(
        "signerPublicKey".into(),
        hex(&transaction.signer_public_key.0),
    );
    map.insert("version".into(), json!(transaction.body.version()));
    map.insert("network".into(), json!(transaction.network.0));
    map.insert("type".into(), json!(transaction.body.transaction_type()));
    map.insert("maxFee".into(), decimal(transaction.fee));
    map.insert("deadline".into(), decimal(transaction.deadline));
    body_json(&transaction.body, &mut map);
    json!({ "meta": { "height": "0" }, "transaction": map })
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn rebuilds_every_transaction_from_rest_json() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/transactions.json");
    let mut types = std::collections::BTreeSet::new();
    for vector in &vectors {
        let payload = from_hex(&vector.payload);
        // 中のトランザクションだけのベクターは、外側のトランザクションとしては読めないので飛ばす
        let Ok(transaction) = Transaction::from_bytes(&payload) else {
            continue;
        };
        let info: TransactionInfo = serde_json::from_value(transaction_json(&transaction))
            .unwrap_or_else(|error| panic!("{}: {error}", vector.test_name));
        let rebuilt = info
            .transaction
            .to_bytes()
            .unwrap_or_else(|error| panic!("{}: {error}", vector.test_name));
        assert_eq!(rebuilt, payload, "{}", vector.test_name);
        types.insert(transaction.body.transaction_type());
    }
    // 25種類すべて
    assert_eq!(types.len(), 25, "{types:X?}");
}
