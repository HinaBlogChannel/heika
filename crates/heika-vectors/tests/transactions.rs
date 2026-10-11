//! `models/transactions.json`: トランザクションのバイト列と、その中身。
//! ここにある署名はレイアウトを試すための値で、検証は通らない。

use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use heika_transaction::{Body, KeyLink, LinkAction, Transaction};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    schema_name: String,
    test_name: String,
    payload: String,
    descriptor: serde_json::Value,
}

/// heika-transaction が扱う種類。アグリゲートの中に入っているものは、まだ扱わない。
const SCHEMAS: [&str; 3] = [
    "AccountKeyLinkTransactionV1",
    "NodeKeyLinkTransactionV1",
    "VrfKeyLinkTransactionV1",
];

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn text<'a>(descriptor: &'a serde_json::Value, field: &str) -> &'a str {
    descriptor[field].as_str().unwrap()
}

fn expected(vector: &Vector) -> Transaction {
    let descriptor = &vector.descriptor;
    let link = KeyLink {
        linked_public_key: text(descriptor, "linked_public_key").parse().unwrap(),
        link_action: match text(descriptor, "link_action") {
            "link" => LinkAction::Link,
            "unlink" => LinkAction::Unlink,
            action => panic!("{}: link_action {action}", vector.test_name),
        },
    };
    let body = match vector.schema_name.as_str() {
        "AccountKeyLinkTransactionV1" => Body::AccountKeyLink(link),
        "NodeKeyLinkTransactionV1" => Body::NodeKeyLink(link),
        "VrfKeyLinkTransactionV1" => Body::VrfKeyLink(link),
        schema => panic!("{}: {schema}", vector.test_name),
    };
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
    transaction
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn reads_and_writes_key_links() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/transactions.json");
    let vectors: Vec<_> = vectors
        .iter()
        .filter(|vector| SCHEMAS.contains(&vector.schema_name.as_str()))
        .collect();
    assert!(!vectors.is_empty());
    for vector in &vectors {
        let payload = from_hex(&vector.payload);
        let transaction = Transaction::from_bytes(&payload).unwrap();
        assert_eq!(transaction, expected(vector), "{}", vector.test_name);
        assert_eq!(transaction.to_bytes(), payload, "{}", vector.test_name);
    }
    eprintln!("{} vectors checked", vectors.len());
}
