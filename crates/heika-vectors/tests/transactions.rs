//! `models/transactions.json`: トランザクションのバイト列と、その中身。
//! ここにある署名はレイアウトを試すための値で、検証は通らない。

use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use heika_transaction::{
    Aggregate, Body, Cosignature, EmbeddedTransaction, KeyLink, LinkAction, Transaction, Transfer,
    UnresolvedAddress, UnresolvedMosaicId,
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

/// heika-transaction が扱う種類。アグリゲートはバージョン 3 で、中身がすべて扱える種類のものだけを照合する。
const SCHEMAS: [&str; 6] = [
    "AccountKeyLinkTransactionV1",
    "NodeKeyLinkTransactionV1",
    "VrfKeyLinkTransactionV1",
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

fn key_link(descriptor: &Value) -> KeyLink {
    KeyLink {
        linked_public_key: text(descriptor, "linked_public_key").parse().unwrap(),
        link_action: match text(descriptor, "link_action") {
            "link" => LinkAction::Link,
            "unlink" => LinkAction::Unlink,
            action => panic!("link_action {action}"),
        },
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
    Transfer::new(
        UnresolvedAddress(from_base32(text(descriptor, "recipient_address"))),
        mosaics,
        message,
    )
    .unwrap()
}

fn public_key(descriptor: &Value, field: &str) -> PublicKey {
    descriptor[field]
        .as_str()
        .map_or(PublicKey([0; 32]), |text| text.parse().unwrap())
}

fn aggregate(descriptor: &Value) -> Option<Aggregate> {
    let transactions = descriptor["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|embedded| {
            // 中のトランザクションの署名者とネットワークは、descriptor にないときは0とテストネット
            Some(EmbeddedTransaction::new(
                public_key(embedded, "signer_public_key"),
                NetworkIdentifier::TESTNET,
                body(embedded)?,
            ))
        })
        .collect::<Option<_>>()?;
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
    Some(aggregate)
}

/// descriptor の種類から本体を組む。heika-transaction が扱わない種類なら None。
fn body(descriptor: &Value) -> Option<Body> {
    Some(match text(descriptor, "type") {
        "account_key_link_transaction_v1" => Body::AccountKeyLink(key_link(descriptor)),
        "node_key_link_transaction_v1" => Body::NodeKeyLink(key_link(descriptor)),
        "vrf_key_link_transaction_v1" => Body::VrfKeyLink(key_link(descriptor)),
        "transfer_transaction_v1" => Body::Transfer(transfer(descriptor)),
        "aggregate_complete_transaction_v3" => Body::AggregateComplete(aggregate(descriptor)?),
        "aggregate_bonded_transaction_v3" => Body::AggregateBonded(aggregate(descriptor)?),
        _ => return None,
    })
}

fn expected(vector: &Vector) -> Option<Transaction> {
    let descriptor = &vector.descriptor;
    let body = body(descriptor)?;
    let signer_public_key: PublicKey = text(descriptor, "signer_public_key").parse().unwrap();
    let mut transaction = Transaction::new(
        signer_public_key,
        // ベクターはどれもテストネットのもので、descriptor には書かれていない
        NetworkIdentifier::TESTNET,
        descriptor["fee"].as_u64().unwrap(),
        descriptor["deadline"].as_u64().unwrap(),
        body,
    );
    let signature: Signature = text(descriptor, "signature").parse().unwrap();
    transaction.signature = signature;
    Some(transaction)
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn reads_and_writes_transactions() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/transactions.json");
    for schema in SCHEMAS {
        let vectors: Vec<_> = vectors
            .iter()
            .filter(|vector| vector.schema_name == schema)
            .filter_map(|vector| Some((vector, expected(vector)?)))
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
