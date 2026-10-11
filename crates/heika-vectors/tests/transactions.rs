//! `models/transactions.json`: トランザクションのバイト列と、その中身。
//! ここにある署名はレイアウトを試すための値で、検証は通らない。

use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use heika_transaction::{
    Body, KeyLink, LinkAction, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId,
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

/// heika-transaction が扱う種類。アグリゲートの中に入っているものは、まだ扱わない。
const SCHEMAS: [&str; 4] = [
    "AccountKeyLinkTransactionV1",
    "NodeKeyLinkTransactionV1",
    "VrfKeyLinkTransactionV1",
    "TransferTransactionV1",
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

fn key_link(vector: &Vector) -> KeyLink {
    let descriptor = &vector.descriptor;
    KeyLink {
        linked_public_key: text(descriptor, "linked_public_key").parse().unwrap(),
        link_action: match text(descriptor, "link_action") {
            "link" => LinkAction::Link,
            "unlink" => LinkAction::Unlink,
            action => panic!("{}: link_action {action}", vector.test_name),
        },
    }
}

fn transfer(vector: &Vector) -> Transfer {
    let descriptor = &vector.descriptor;
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

fn expected(vector: &Vector) -> Transaction {
    let descriptor = &vector.descriptor;
    let body = match vector.schema_name.as_str() {
        "AccountKeyLinkTransactionV1" => Body::AccountKeyLink(key_link(vector)),
        "NodeKeyLinkTransactionV1" => Body::NodeKeyLink(key_link(vector)),
        "VrfKeyLinkTransactionV1" => Body::VrfKeyLink(key_link(vector)),
        "TransferTransactionV1" => Body::Transfer(transfer(vector)),
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
fn reads_and_writes_transactions() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/transactions.json");
    for schema in SCHEMAS {
        let vectors: Vec<_> = vectors
            .iter()
            .filter(|vector| vector.schema_name == schema)
            .collect();
        assert!(!vectors.is_empty(), "{schema}");
        for vector in &vectors {
            let payload = from_hex(&vector.payload);
            let transaction = Transaction::from_bytes(&payload).unwrap();
            assert_eq!(transaction, expected(vector), "{}", vector.test_name);
            assert_eq!(transaction.to_bytes(), payload, "{}", vector.test_name);
        }
        eprintln!("{schema}: {} vectors checked", vectors.len());
    }
}
