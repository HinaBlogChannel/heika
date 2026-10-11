//! `testdata/sdk-transactions.json`: 公式の Python SDK で署名したトランザクション。
//!
//! `models/transactions.json` の署名は検証が通らないので、署名する範囲とハッシュの取り方はこちらで照合する。
//! JSON は `scripts/generate-sdk-vectors.py` が決定的に作ったもので、作り直せば同じものが出る。
//! ネットワークは使わない。

use std::collections::HashMap;

use heika_core::key::PublicKey;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_transaction::{
    Body, KeyLink, LinkAction, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId,
};
use heika_wallet::bip39::Mnemonic;
use heika_wallet::slip10::{self, ExtendedKey};
use serde::Deserialize;

const VECTORS: &str = include_str!("../testdata/sdk-transactions.json");

#[derive(Deserialize)]
struct Document {
    mnemonic: String,
    networks: HashMap<String, Network>,
    transactions: Vec<Vector>,
}

#[derive(Deserialize)]
struct Network {
    identifier: u8,
    generation_hash_seed: String,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "type")]
    transaction_type: String,
    network: String,
    account: u32,
    signer_public_key: String,
    fee: u64,
    deadline: u64,
    linked_public_key: Option<String>,
    link_action: Option<String>,
    recipient_address: Option<String>,
    #[serde(default)]
    mosaics: Vec<Mosaic>,
    message: Option<String>,
    signature: String,
    hash: String,
    payload: String,
}

#[derive(Deserialize)]
struct Mosaic {
    mosaic_id: u64,
    amount: u64,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn body(vector: &Vector) -> Body {
    if vector.transaction_type == "transfer_transaction_v1" {
        let recipient = from_hex(vector.recipient_address.as_deref().unwrap());
        let mosaics = vector
            .mosaics
            .iter()
            .map(|mosaic| (UnresolvedMosaicId(mosaic.mosaic_id), mosaic.amount))
            .collect();
        let message = from_hex(vector.message.as_deref().unwrap());
        return Body::Transfer(
            Transfer::new(
                UnresolvedAddress(recipient.try_into().unwrap()),
                mosaics,
                message,
            )
            .unwrap(),
        );
    }
    let link = KeyLink {
        linked_public_key: vector
            .linked_public_key
            .as_deref()
            .unwrap()
            .parse()
            .unwrap(),
        link_action: match vector.link_action.as_deref().unwrap() {
            "link" => LinkAction::Link,
            "unlink" => LinkAction::Unlink,
            action => panic!("link_action {action}"),
        },
    };
    match vector.transaction_type.as_str() {
        "account_key_link_transaction_v1" => Body::AccountKeyLink(link),
        "node_key_link_transaction_v1" => Body::NodeKeyLink(link),
        "vrf_key_link_transaction_v1" => Body::VrfKeyLink(link),
        name => panic!("{name}"),
    }
}

#[test]
fn signs_and_hashes_like_the_sdk() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    let mnemonic: Mnemonic = document.mnemonic.parse().unwrap();
    let root = ExtendedKey::from_seed(mnemonic.to_seed("").unwrap().as_bytes());
    assert!(!document.transactions.is_empty());
    for (index, vector) in document.transactions.iter().enumerate() {
        let network = &document.networks[&vector.network];
        let identifier = NetworkIdentifier(network.identifier);
        let seed: GenerationHashSeed = network.generation_hash_seed.parse().unwrap();
        let private_key = root
            .derive_path(&slip10::symbol_path(identifier, vector.account))
            .private_key();
        let signer_public_key: PublicKey = vector.signer_public_key.parse().unwrap();
        assert_eq!(
            PublicKey::from_private_key(&private_key),
            signer_public_key,
            "vector {index}"
        );

        let mut transaction = Transaction::new(
            signer_public_key,
            identifier,
            vector.fee,
            vector.deadline,
            body(vector),
        );
        transaction.sign(&private_key, &seed).unwrap();
        assert_eq!(
            transaction.signature.to_string(),
            vector.signature,
            "vector {index}"
        );
        assert_eq!(
            transaction.hash(&seed).to_string(),
            vector.hash,
            "vector {index}"
        );
        let payload = from_hex(&vector.payload);
        assert_eq!(transaction.to_bytes(), payload, "vector {index}");
        assert_eq!(
            Transaction::from_bytes(&payload),
            Ok(transaction.clone()),
            "vector {index}"
        );
        assert!(transaction.verify(&seed), "vector {index}");
    }
    eprintln!("{} vectors checked", document.transactions.len());
}
