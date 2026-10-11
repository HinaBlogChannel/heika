//! `testdata/sdk-transactions.json`: 公式の Python SDK で署名したトランザクション。
//!
//! `models/transactions.json` の署名は検証が通らないので、署名する範囲とハッシュの取り方はこちらで照合する。
//! JSON は `scripts/generate-sdk-vectors.py` が決定的に作ったもので、作り直せば同じものが出る。
//! 委任ハーベストの要求のメッセージも、同じ JSON で照合する。
//! ネットワークは使わない。

use std::collections::HashMap;

use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, KeyLink, LinkAction, Transaction, Transfer,
    UnresolvedAddress, UnresolvedMosaicId,
};
use heika_wallet::bip39::Mnemonic;
use heika_wallet::harvest_request::{self, HarvesterKeys};
use heika_wallet::slip10::{self, ExtendedKey};
use serde::Deserialize;

const VECTORS: &str = include_str!("../testdata/sdk-transactions.json");

#[derive(Deserialize)]
struct Document {
    mnemonic: String,
    networks: HashMap<String, Network>,
    transactions: Vec<Vector>,
    harvest_requests: Vec<HarvestRequest>,
}

#[derive(Deserialize)]
struct Network {
    identifier: u8,
    generation_hash_seed: String,
}

#[derive(Deserialize)]
struct Vector {
    #[serde(flatten)]
    fields: Fields,
    network: String,
    account: u32,
    signer_public_key: String,
    fee: u64,
    deadline: u64,
    /// アグリゲートの中のトランザクション
    #[serde(default)]
    transactions: Vec<Embedded>,
    /// アグリゲートに連署するアカウント
    #[serde(default)]
    cosigners: Vec<u32>,
    signature: String,
    hash: String,
    payload: String,
}

#[derive(Deserialize)]
struct Embedded {
    #[serde(flatten)]
    fields: Fields,
    account: u32,
}

/// アグリゲートではない種類の本体。
#[derive(Deserialize)]
struct Fields {
    #[serde(rename = "type")]
    transaction_type: String,
    linked_public_key: Option<String>,
    link_action: Option<String>,
    recipient_address: Option<String>,
    #[serde(default)]
    mosaics: Vec<Mosaic>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct HarvestRequest {
    network: String,
    node_account: u32,
    signing_account: u32,
    vrf_account: u32,
    node_public_key: String,
    randomness: String,
    message: String,
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

fn body(fields: &Fields) -> Body {
    if fields.transaction_type == "transfer_transaction_v1" {
        let recipient = from_hex(fields.recipient_address.as_deref().unwrap());
        let mosaics = fields
            .mosaics
            .iter()
            .map(|mosaic| (UnresolvedMosaicId(mosaic.mosaic_id), mosaic.amount))
            .collect();
        let message = from_hex(fields.message.as_deref().unwrap());
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
        linked_public_key: fields
            .linked_public_key
            .as_deref()
            .unwrap()
            .parse()
            .unwrap(),
        link_action: match fields.link_action.as_deref().unwrap() {
            "link" => LinkAction::Link,
            "unlink" => LinkAction::Unlink,
            action => panic!("link_action {action}"),
        },
    };
    match fields.transaction_type.as_str() {
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
        let derive = |account| -> PrivateKey {
            root.derive_path(&slip10::symbol_path(identifier, account))
                .private_key()
        };
        let private_key = derive(vector.account);
        let signer_public_key: PublicKey = vector.signer_public_key.parse().unwrap();
        assert_eq!(
            PublicKey::from_private_key(&private_key),
            signer_public_key,
            "vector {index}"
        );

        let body = match vector.fields.transaction_type.as_str() {
            "aggregate_complete_transaction_v3" | "aggregate_bonded_transaction_v3" => {
                let transactions = vector
                    .transactions
                    .iter()
                    .map(|embedded| {
                        EmbeddedTransaction::new(
                            PublicKey::from_private_key(&derive(embedded.account)),
                            identifier,
                            body(&embedded.fields),
                        )
                    })
                    .collect();
                let aggregate = Aggregate::new(transactions).unwrap();
                if vector.fields.transaction_type == "aggregate_complete_transaction_v3" {
                    Body::AggregateComplete(aggregate)
                } else {
                    Body::AggregateBonded(aggregate)
                }
            }
            _ => body(&vector.fields),
        };
        let mut transaction = Transaction::new(
            signer_public_key,
            identifier,
            vector.fee,
            vector.deadline,
            body,
        );
        transaction.sign(&private_key, &seed).unwrap();
        let hash = transaction.hash(&seed);
        for &cosigner in &vector.cosigners {
            transaction.cosign(&derive(cosigner), &seed).unwrap();
        }
        assert!(transaction.verify_cosignatures(&seed), "vector {index}");
        assert_eq!(
            transaction.signature.to_string(),
            vector.signature,
            "vector {index}"
        );
        assert_eq!(hash.to_string(), vector.hash, "vector {index}");
        assert_eq!(transaction.hash(&seed), hash, "vector {index}");
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

/// 決まったバイト列を先頭から順に返す乱数。SDK に渡したものと同じ使い捨ての鍵と初期化ベクトルにする。
struct Replay<'a>(&'a [u8]);

impl rand_core::TryRng for Replay<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!("only fill_bytes is used")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!("only fill_bytes is used")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let (head, rest) = self.0.split_at(dst.len());
        dst.copy_from_slice(head);
        self.0 = rest;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Replay<'_> {}

#[test]
fn encodes_harvest_requests_like_the_sdk() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    let mnemonic: Mnemonic = document.mnemonic.parse().unwrap();
    let root = ExtendedKey::from_seed(mnemonic.to_seed("").unwrap().as_bytes());
    assert!(!document.harvest_requests.is_empty());
    for (index, vector) in document.harvest_requests.iter().enumerate() {
        let identifier = NetworkIdentifier(document.networks[&vector.network].identifier);
        let derive = |account| -> PrivateKey {
            root.derive_path(&slip10::symbol_path(identifier, account))
                .private_key()
        };
        let node = derive(vector.node_account);
        let node_public_key: PublicKey = vector.node_public_key.parse().unwrap();
        assert_eq!(
            PublicKey::from_private_key(&node),
            node_public_key,
            "vector {index}"
        );
        let keys = HarvesterKeys {
            signing: derive(vector.signing_account),
            vrf: derive(vector.vrf_account),
        };
        let randomness = from_hex(&vector.randomness);
        let message =
            harvest_request::encode(&mut Replay(&randomness), &node_public_key, &keys).unwrap();
        assert_eq!(message, from_hex(&vector.message), "vector {index}");

        let decoded = harvest_request::decode(&node, &message).unwrap();
        assert_eq!(
            decoded.signing.as_bytes(),
            keys.signing.as_bytes(),
            "vector {index}"
        );
        assert_eq!(
            decoded.vrf.as_bytes(),
            keys.vrf.as_bytes(),
            "vector {index}"
        );
    }
    eprintln!(
        "{} harvest requests checked",
        document.harvest_requests.len()
    );
}

#[test]
fn network_constants_match_the_sdk() {
    let document: Document = serde_json::from_str(VECTORS).unwrap();
    for (name, identifier, seed) in [
        (
            "mainnet",
            NetworkIdentifier::MAINNET,
            GenerationHashSeed::MAINNET,
        ),
        (
            "testnet",
            NetworkIdentifier::TESTNET,
            GenerationHashSeed::TESTNET,
        ),
    ] {
        let network = &document.networks[name];
        assert_eq!(NetworkIdentifier(network.identifier), identifier, "{name}");
        assert_eq!(seed.to_string(), network.generation_hash_seed, "{name}");
    }
}
