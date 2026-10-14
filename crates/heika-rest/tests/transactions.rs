//! 自分で署名したトランザクションを REST の形の JSON にして読み、確かめる。

use std::collections::BTreeMap;

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_rest::RestError;
use heika_rest::transaction::TransactionInfo;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, Transaction, Transfer, UnresolvedMosaicId,
};
use serde_json::{Value, json};

const SEED: GenerationHashSeed = GenerationHashSeed::MAINNET;
/// アグリゲートがバージョン 3 になったあとの高さ
const HEIGHT: &str = "5000000";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn signer() -> PrivateKey {
    PrivateKey::from_bytes(&[3; 32])
}

fn cosigner() -> PrivateKey {
    PrivateKey::from_bytes(&[4; 32])
}

/// 署名者から cosigner への転送を、署名と連署の付いたアグリゲートに入れる
fn aggregate() -> Transaction {
    let recipient = Address::from_public_key(
        &PublicKey::from_private_key(&cosigner()),
        NetworkIdentifier::MAINNET,
    );
    let transfer = Transfer::new(
        recipient.into(),
        BTreeMap::from([(UnresolvedMosaicId(0x6BED_913F_A202_23F8), 1_000_000)]),
        b"\0heika".to_vec(),
    )
    .unwrap();
    let embedded = EmbeddedTransaction::new(
        PublicKey::from_private_key(&signer()),
        NetworkIdentifier::MAINNET,
        Body::Transfer(transfer),
    );
    let mut transaction = Transaction::new(
        PublicKey::from_private_key(&signer()),
        NetworkIdentifier::MAINNET,
        20_000,
        123_456,
        Body::AggregateComplete(Aggregate::new(vec![embedded]).unwrap()),
    );
    transaction.sign(&signer(), &SEED).unwrap();
    transaction.cosign(&cosigner(), &SEED).unwrap();
    transaction
}

fn json(transaction: &Transaction) -> Value {
    let Body::AggregateComplete(aggregate) = &transaction.body else {
        unreachable!()
    };
    let embedded = &aggregate.transactions()[0];
    let Body::Transfer(transfer) = &embedded.body else {
        unreachable!()
    };
    let cosignature = &aggregate.cosignatures()[0];
    json!({
        "meta": {
            "height": HEIGHT,
            "hash": transaction.hash(&SEED).to_string(),
            "merkleComponentHash": transaction.merkle_component_hash(&SEED).to_string(),
            "index": 0,
        },
        "transaction": {
            "size": transaction.size(),
            "signature": hex(&transaction.signature.0),
            "signerPublicKey": hex(&transaction.signer_public_key.0),
            "version": 3,
            "network": 104,
            "type": 0x4141,
            "maxFee": "20000",
            "deadline": "123456",
            "transactionsHash": aggregate.transactions_hash().to_string(),
            "cosignatures": [{
                "version": "0",
                "signerPublicKey": hex(&cosignature.signer_public_key.0),
                "signature": hex(&cosignature.signature.0),
            }],
            "transactions": [{
                "meta": { "height": HEIGHT, "index": 0 },
                "transaction": {
                    "signerPublicKey": hex(&embedded.signer_public_key.0),
                    "version": 1,
                    "network": 104,
                    "type": 0x4154,
                    "recipientAddress": hex(&transfer.recipient_address().0),
                    "mosaics": [{ "id": "6BED913FA20223F8", "amount": "1000000" }],
                    "message": hex(transfer.message()),
                },
            }],
        },
    })
}

fn read(json: &Value) -> TransactionInfo {
    serde_json::from_value(json.clone()).unwrap()
}

#[test]
fn verifies_an_aggregate_with_its_embedded_transactions() {
    let transaction = aggregate();
    assert_eq!(read(&json(&transaction)).verify(), Ok(transaction));
}

#[test]
fn refuses_changed_values() {
    let json = json(&aggregate());
    for (pointer, value, error) in [
        (
            "/transaction/maxFee",
            json!("20001"),
            RestError::Mismatch { field: "signature" },
        ),
        (
            "/transaction/cosignatures/0/signature",
            json!(hex(&[1; 64])),
            RestError::Mismatch {
                field: "cosignatures",
            },
        ),
        (
            "/meta/hash",
            json!(hex(&[0; 32])),
            RestError::Mismatch { field: "meta.hash" },
        ),
        (
            "/meta/merkleComponentHash",
            json!(hex(&[0; 32])),
            RestError::Mismatch {
                field: "meta.merkleComponentHash",
            },
        ),
        // バージョン 3 になる前の高さ
        (
            "/meta/height",
            json!("1000"),
            RestError::Mismatch { field: "version" },
        ),
        (
            "/transaction/network",
            json!(0x78),
            RestError::InvalidValue { field: "network" },
        ),
    ] {
        let mut changed = json.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_eq!(read(&changed).verify(), Err(error), "{pointer}");
    }
    // 中のトランザクションを書き換えると、書いてある TransactionsHash と合わなくなる
    let mut embedded = json.clone();
    embedded["transaction"]["transactions"][0]["transaction"]["mosaics"][0]["amount"] =
        json!("1000001");
    assert!(matches!(
        read(&embedded).verify(),
        Err(RestError::InvalidTransaction(_))
    ));
}

#[test]
fn accepts_an_unconfirmed_transaction_without_a_merkle_leaf_check() {
    // 承認される前は、REST は Merkle の葉にもハッシュを入れる
    let transaction = aggregate();
    let mut json = json(&transaction);
    json["meta"]["height"] = json!("0");
    json["meta"]["merkleComponentHash"] = json["meta"]["hash"].clone();
    assert_eq!(read(&json).verify(), Ok(transaction));
}

#[test]
fn needs_the_embedded_transactions_and_matching_value_types() {
    let json = json(&aggregate());
    let mut without = json.clone();
    without["transaction"]
        .as_object_mut()
        .unwrap()
        .remove("transactions");
    assert_eq!(
        read(&without).verify(),
        Err(RestError::Missing {
            field: "transactions"
        })
    );

    // アカウントの操作の制限の値は数で、16進の文字列ではない
    let restriction = json!({
        "meta": { "height": "0", "hash": hex(&[0; 32]) },
        "transaction": {
            "signature": hex(&[0; 64]),
            "signerPublicKey": hex(&[0; 32]),
            "version": 1,
            "network": 104,
            "type": 0x4350,
            "maxFee": "0",
            "deadline": "0",
            "restrictionFlags": 0x4004,
            "restrictionAdditions": ["4154"],
            "restrictionDeletions": [],
        },
    });
    assert_eq!(
        read(&restriction).transaction.to_bytes(),
        Err(RestError::InvalidValue {
            field: "restrictionAdditions"
        })
    );
}

/// 検索で返る形。中のトランザクションは入っていない
fn without_embedded(json: &Value) -> Value {
    let mut json = json.clone();
    json["transaction"]
        .as_object_mut()
        .unwrap()
        .remove("transactions");
    json
}

/// `embedded=true` の検索で、平たく並んで返る中のトランザクション
fn flattened(json: &Value, aggregate_hash: &str) -> Value {
    let mut entry = json["transaction"]["transactions"][0].clone();
    entry["meta"]["aggregateHash"] = json!(aggregate_hash);
    entry
}

#[test]
fn verifies_an_aggregate_without_its_embedded_transactions() {
    let transaction = aggregate();
    let json = json(&transaction);
    let header = read(&without_embedded(&json))
        .verify_aggregate_header()
        .unwrap();
    let Body::AggregateComplete(aggregate) = &transaction.body else {
        unreachable!()
    };
    assert_eq!(header.hash, transaction.hash(&SEED));
    assert_eq!(
        header.merkle_component_hash,
        transaction.merkle_component_hash(&SEED)
    );
    assert_eq!(header.transactions_hash, aggregate.transactions_hash());
    assert_eq!(header.version, 3);

    // 中のトランザクションの長さは署名に掛かるので、size を変えると署名が合わない
    let mut resized = without_embedded(&json);
    resized["transaction"]["size"] = json!(transaction.size() + 8);
    assert_eq!(
        read(&resized).verify_aggregate_header(),
        Err(RestError::Mismatch { field: "signature" })
    );
}

#[test]
fn collects_flattened_embedded_transactions_by_their_parent() {
    let transaction = aggregate();
    let json = json(&transaction);
    let hash = transaction.hash(&SEED).to_string();
    let header = read(&without_embedded(&json));
    let entries: Vec<TransactionInfo> = [
        flattened(&json, &hash),
        // 別のアグリゲートのものは集めない
        flattened(&json, &hex(&[0; 32])),
        // 外側のトランザクションも混ざって返る
        without_embedded(&json),
    ]
    .iter()
    .map(read)
    .collect();
    let collected = header.with_embedded(&entries).unwrap();
    assert_eq!(collected.verify(), Ok(transaction));

    // 抜けがあれば集めない
    let mut skipped = flattened(&json, &hash);
    skipped["meta"]["index"] = json!(1);
    assert_eq!(
        header.with_embedded(&[read(&skipped)]),
        Err(RestError::InvalidValue {
            field: "meta.index"
        })
    );
}
