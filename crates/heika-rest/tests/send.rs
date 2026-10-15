//! 自分で署名したトランザクションとブロックを REST の形にして、入ったことを確かめる流れを通す。

use std::collections::{BTreeMap, HashMap};
use std::future::{Future, Ready, ready};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::merkle;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_rest::balance::{BalanceError, Mismatch, VerifyError};
use heika_rest::send::{announce_body, find_inclusion};
use heika_transaction::{Body, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId};
use serde_json::{Value, json};

mod common;
use common::block_json_with;

const XYM: u64 = 0x6BED_913F_A202_23F8;
const SEED: GenerationHashSeed = GenerationHashSeed::MAINNET;

/// `amount` を送る、署名したメインネットの送金
fn transfer(amount: u64) -> Transaction {
    let sender = PrivateKey::from_bytes(&[7; 32]);
    let recipient = Address::from_public_key(&PublicKey([9; 32]), NetworkIdentifier::MAINNET);
    let body = Transfer::new(
        UnresolvedAddress::from(recipient),
        BTreeMap::from([(UnresolvedMosaicId(XYM), amount)]),
        b"\0hello".to_vec(),
    )
    .unwrap();
    let mut transaction = Transaction::new(
        PublicKey::from_private_key(&sender),
        NetworkIdentifier::MAINNET,
        17_600,
        1_000_000,
        Body::Transfer(body),
    );
    transaction.sign(&sender, &SEED).unwrap();
    transaction
}

/// 3つのトランザクションが入った高さ 2000 のブロックを返す REST。`ours` は2番目に入れる
struct Rest(HashMap<String, Value>);

impl Rest {
    fn new(ours: &Transaction) -> Self {
        let leaves = [
            transfer(1).merkle_component_hash(&SEED),
            ours.merkle_component_hash(&SEED),
            transfer(3).merkle_component_hash(&SEED),
        ];
        let root = merkle::root(&leaves);
        let path: Vec<Value> = merkle::path(&leaves, 1)
            .unwrap()
            .iter()
            .map(|node| {
                json!({
                    "position": match node.position {
                        merkle::Position::Left => "left",
                        merkle::Position::Right => "right",
                    },
                    "hash": node.hash.to_string(),
                })
            })
            .collect();
        let hash = ours.hash(&SEED);
        Self(HashMap::from([
            (
                format!("/transactions/confirmed/{hash}"),
                json!({ "meta": { "height": "2000", "hash": hash.to_string() } }),
            ),
            (
                "/blocks/2000".to_owned(),
                block_json_with(2000, &[Hash256([0; 32]); 9], &root),
            ),
            (
                format!("/blocks/2000/transactions/{hash}/merkle"),
                json!({ "merklePath": path }),
            ),
        ]))
    }

    fn fetch(&self) -> impl FnMut(String) -> Ready<Result<Option<Vec<u8>>, String>> + '_ {
        |path| {
            ready(Ok(self
                .0
                .get(&path)
                .map(|value| value.to_string().into_bytes())))
        }
    }
}

/// 待たない future を、1回で終わらせる
fn run<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("待つことはない"),
    }
}

#[test]
fn announces_the_payload_in_hex() {
    let transaction = transfer(5);
    let body: Value = serde_json::from_str(&announce_body(&transaction)).unwrap();
    let payload = body["payload"].as_str().unwrap();
    assert_eq!(payload, common::hex(&transaction.to_bytes()));
}

#[test]
fn verifies_that_a_transaction_is_in_a_signed_block() {
    let ours = transfer(5);
    let rest = Rest::new(&ours);
    let inclusion = run(find_inclusion(&ours, &SEED, rest.fetch()))
        .unwrap()
        .expect("入っている");
    assert_eq!(inclusion.block.height, 2000);
}

#[test]
fn says_nothing_when_the_rest_does_not_know_it() {
    let ours = transfer(5);
    let rest = Rest(HashMap::new());
    assert!(
        run(find_inclusion(&ours, &SEED, rest.fetch()))
            .unwrap()
            .is_none()
    );
}

#[test]
fn refuses_a_path_that_does_not_reach_the_block() {
    // REST が、ほかのトランザクションの経路を、こちらのものとして返す
    let ours = transfer(5);
    let other = transfer(6);
    let mut rest = Rest::new(&other);
    let (hash, other_hash) = (ours.hash(&SEED), other.hash(&SEED));
    for (from, to) in [
        (
            format!("/transactions/confirmed/{other_hash}"),
            format!("/transactions/confirmed/{hash}"),
        ),
        (
            format!("/blocks/2000/transactions/{other_hash}/merkle"),
            format!("/blocks/2000/transactions/{hash}/merkle"),
        ),
    ] {
        let value = rest.0.remove(&from).unwrap();
        rest.0.insert(to, value);
    }
    let error = run(find_inclusion(&ours, &SEED, rest.fetch())).unwrap_err();
    assert!(matches!(
        error,
        BalanceError::Verify(VerifyError::Invalid {
            error: Mismatch::Rest(_),
            ..
        })
    ));
}

#[test]
fn refuses_a_block_of_another_network() {
    let mut ours = transfer(5);
    ours.network = NetworkIdentifier::TESTNET;
    let rest = Rest::new(&ours);
    let error = run(find_inclusion(&ours, &SEED, rest.fetch())).unwrap_err();
    assert!(matches!(
        error,
        BalanceError::Verify(VerifyError::WrongNetwork)
    ));
}
