//! 自分で署名したブロックと、自分で作った状態の木を REST の形にして、残高を確かめる流れを通す。

use std::collections::HashMap;
use std::future::{Future, Ready, ready};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use heika_block::Block;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::patricia::{self, SubCache, TreeNode};
use heika_core::vrf;
use heika_rest::balance::{
    BalanceError, Mismatch, MosaicParts, VerifiedBalance, VerifiedMosaic, VerifyError,
    account_paths, mosaic_paths, verify_balance, verify_balance_parts,
};
use heika_rest::block::BlockInfo;
use heika_rest::merkle::MerkleStateInfo;
use heika_rest::state::{AccountInfo, MosaicInfo};
use serde_json::{Value, json};

const XYM: u64 = 0x6BED_913F_A202_23F8;
const GONE: u64 = 0x0000_0000_0000_0001;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// メインネットの通常のブロックを、9本の根を `roots` にして組んで署名し、REST が返す形の JSON にする
fn block_json(height: u64, roots: &[Hash256; 9]) -> Value {
    let harvester = PrivateKey::from_bytes(&[3; 32]);
    let proof = vrf::prove(&PrivateKey::from_bytes(&[4; 32]), &[0x5A; 32]).unwrap();
    let state_hash = patricia::state_hash(roots);
    let mut bytes = vec![0; 376];
    bytes[..4].copy_from_slice(&376_u32.to_le_bytes());
    bytes[72..104].copy_from_slice(&PublicKey::from_private_key(&harvester).0);
    bytes[108] = 1;
    bytes[109] = 0x68;
    bytes[110..112].copy_from_slice(&0x8143_u16.to_le_bytes());
    bytes[112..120].copy_from_slice(&height.to_le_bytes());
    bytes[120..128].copy_from_slice(&123_456_u64.to_le_bytes());
    bytes[128..136].copy_from_slice(&100_000_000_000_000_u64.to_le_bytes());
    bytes[136..168].copy_from_slice(&proof.gamma);
    bytes[168..184].copy_from_slice(&proof.verification_hash);
    bytes[184..216].copy_from_slice(&proof.scalar);
    bytes[216..248].copy_from_slice(&[0x11; 32]);
    bytes[312..344].copy_from_slice(&state_hash.0);
    bytes[344] = 0x68;
    bytes[368..372].copy_from_slice(&100_u32.to_le_bytes());
    let signature = harvester.sign(&[&bytes[108..372]]);
    bytes[8..72].copy_from_slice(&signature.0);
    let block = Block::from_bytes(&bytes).unwrap();
    json!({
        "meta": {
            "hash": block.hash().to_string(),
            "generationHash": block.generation_hash().to_string(),
            "totalFee": "0",
            "stateHashSubCacheMerkleRoots": roots.iter().map(Hash256::to_string).collect::<Vec<_>>(),
            "totalTransactionsCount": 0,
            "transactionsCount": 0,
            "statementsCount": 0,
        },
        "block": {
            "size": 376,
            "signature": hex(&signature.0),
            "signerPublicKey": hex(&bytes[72..104]),
            "version": 1,
            "network": 104,
            "type": 0x8143,
            "height": height.to_string(),
            "timestamp": "123456",
            "difficulty": "100000000000000",
            "proofGamma": hex(&proof.gamma),
            "proofVerificationHash": hex(&proof.verification_hash),
            "proofScalar": hex(&proof.scalar),
            "previousBlockHash": hex(&[0x11; 32]),
            "transactionsHash": hex(&[0; 32]),
            "receiptsHash": hex(&[0; 32]),
            "stateHash": hex(&state_hash.0),
            "beneficiaryAddress": hex(&bytes[344..368]),
            "feeMultiplier": 100,
        },
    })
}

/// `key` の葉が1つだけの木の、REST の状態の経路の `raw` と、根
fn single_leaf(key: &Hash256, value: &Hash256) -> (String, Hash256) {
    let path = key
        .0
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0F])
        .collect();
    let leaf = TreeNode::Leaf {
        path,
        value: *value,
    };
    let mut raw = vec![0xFF, 64];
    raw.extend_from_slice(&key.0);
    raw.extend_from_slice(&value.0);
    (hex(&raw), leaf.hash())
}

fn address() -> Address {
    Address([0x68; 24])
}

fn account_json(mosaics: &[(u64, u64)]) -> Value {
    json!({
        "account": {
            "version": 1,
            "address": hex(&address().0),
            "addressHeight": "1",
            "publicKey": hex(&[0; 32]),
            "publicKeyHeight": "0",
            "accountType": 0,
            "supplementalPublicKeys": {},
            "importance": "0",
            "importanceHeight": "0",
            "activityBuckets": [],
            "mosaics": mosaics
                .iter()
                .map(|(id, amount)| json!({ "id": format!("{id:016X}"), "amount": amount.to_string() }))
                .collect::<Vec<_>>(),
        },
    })
}

fn xym_json() -> Value {
    json!({
        "mosaic": {
            "version": 1,
            "id": format!("{XYM:016X}"),
            "supply": "7842928625000000",
            "startHeight": "1",
            "ownerAddress": hex(&[0x68; 24]),
            "revision": 1,
            "flags": 2,
            "divisibility": 6,
            "duration": "0",
        },
    })
}

/// REST の答えを並べたもの。ないパスは 404
struct Rest(HashMap<String, Value>);

impl Rest {
    /// アカウントとモザイクの木がそれぞれ葉1つで、アカウントが `mosaics` を持っている状態
    fn new(height: u64, account: Option<Value>) -> Self {
        let mut answers = HashMap::new();
        let mut roots = [Hash256([0; 32]); 9];
        // アカウントがなければ、別のアカウントの葉が1つの木にして、ないことを経路で示す
        let (account_raw, account_root) = match &account {
            Some(json) => {
                let info: AccountInfo = serde_json::from_value(json.clone()).unwrap();
                single_leaf(
                    &patricia::address_key(&address()),
                    &info.account.state_hash().unwrap(),
                )
            }
            None => single_leaf(
                &patricia::address_key(&Address([0x69; 24])),
                &Hash256([7; 32]),
            ),
        };
        roots[SubCache::AccountState.index()] = account_root;
        let xym: MosaicInfo = serde_json::from_value(xym_json()).unwrap();
        let (mosaic_raw, mosaic_root) =
            single_leaf(&patricia::id_key(XYM), &xym.mosaic.state_hash().unwrap());
        roots[SubCache::Mosaic.index()] = mosaic_root;

        answers.insert(
            "/chain/info".to_owned(),
            json!({ "height": height.to_string() }),
        );
        answers.insert(format!("/blocks/{height}"), block_json(height, &roots));
        if let Some(json) = account {
            answers.insert(format!("/accounts/{}", address()), json);
        }
        answers.insert(
            format!("/accounts/{}/merkle", address()),
            json!({ "raw": account_raw }),
        );
        answers.insert(format!("/mosaics/{XYM:016X}"), xym_json());
        // 期限が切れて消えたモザイクも、同じ木の経路でないことを示せる
        for id in [XYM, GONE] {
            answers.insert(
                format!("/mosaics/{id:016X}/merkle"),
                json!({ "raw": mosaic_raw }),
            );
        }
        Self(answers)
    }

    fn fetch(&self, path: &str) -> Ready<Result<Option<Vec<u8>>, String>> {
        ready(Ok(self
            .0
            .get(path)
            .map(|value| serde_json::to_vec(value).unwrap())))
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Option<T> {
        self.0
            .get(path)
            .map(|value| serde_json::from_value(value.clone()).unwrap())
    }

    fn verify(&self, address: &Address) -> Result<VerifiedBalance, BalanceError<String>> {
        run(verify_balance(address, |path| self.fetch(&path), no_pause))
    }
}

fn no_pause() -> Ready<()> {
    ready(())
}

/// 取ってくる関数はすぐに答えを返すので、一度動かせば終わる
fn run<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("すぐに答えを返したのに、待たされました"),
    }
}

#[test]
fn verifies_balances_and_divisibility_against_the_state_hash() {
    let rest = Rest::new(1440, Some(account_json(&[(XYM, 1_234_567_890), (GONE, 5)])));
    let balance = rest.verify(&address()).unwrap();
    assert_eq!(balance.block.height, 1440);
    assert_eq!(
        balance.account.unwrap().mosaics,
        [
            VerifiedMosaic {
                id: XYM,
                amount: 1_234_567_890,
                divisibility: Some(6),
            },
            VerifiedMosaic {
                id: GONE,
                amount: 5,
                divisibility: None,
            },
        ]
    );
}

#[test]
fn proves_that_an_account_is_not_on_the_chain_yet() {
    let rest = Rest::new(1440, None);
    let balance = rest.verify(&address()).unwrap();
    assert!(balance.account.is_none());
}

#[test]
fn refuses_balances_that_are_not_in_the_state_tree() {
    let mut rest = Rest::new(1440, Some(account_json(&[(XYM, 1)])));
    // REST が残高を書き換えて返しても、葉と合わない
    rest.0.insert(
        format!("/accounts/{}", address()),
        account_json(&[(XYM, 1_000_000)]),
    );
    let error = rest.verify(&address()).unwrap_err();
    assert!(
        matches!(
            &error,
            BalanceError::Verify(VerifyError::Invalid {
                error: Mismatch::StateHash,
                ..
            })
        ),
        "{error:?}"
    );

    // REST がアカウントを隠しても、経路はあることを示している
    rest.0.remove(&format!("/accounts/{}", address()));
    let error = rest.verify(&address()).unwrap_err();
    assert!(
        matches!(
            &error,
            BalanceError::Verify(VerifyError::Invalid {
                error: Mismatch::UnexpectedPresence,
                ..
            })
        ),
        "{error:?}"
    );
}

#[test]
fn starts_over_when_the_chain_moves_while_fetching() {
    let old = Rest::new(1440, Some(account_json(&[(XYM, 1)])));
    let new = Rest::new(1441, Some(account_json(&[(XYM, 2)])));
    // 最初は古いブロックを返し、状態はもう新しくなっている
    let mut chain_info_calls = 0;
    let mut pauses = 0;
    let balance = run(verify_balance(
        &address(),
        |path| {
            if path == "/chain/info" {
                chain_info_calls += 1;
                if chain_info_calls == 1 {
                    return old.fetch(&path);
                }
            }
            if path == "/blocks/1440" {
                return old.fetch(&path);
            }
            new.fetch(&path)
        },
        || {
            pauses += 1;
            ready(())
        },
    ))
    .unwrap();
    assert_eq!(chain_info_calls, 2);
    assert_eq!(pauses, 1);
    assert_eq!(balance.block.height, 1441);
    assert_eq!(balance.account.unwrap().mosaics[0].amount, 2);
}

#[test]
fn refuses_an_address_of_another_network() {
    let rest = Rest::new(1440, None);
    let error = rest.verify(&Address([0x98; 24])).unwrap_err();
    assert!(
        matches!(error, BalanceError::Verify(VerifyError::WrongNetwork)),
        "{error:?}"
    );
}

#[test]
fn verifies_parts_fetched_by_the_caller() {
    let rest = Rest::new(1440, Some(account_json(&[(XYM, 7), (GONE, 5)])));
    let block: BlockInfo = rest.get("/blocks/1440").unwrap();
    let [account_path, account_merkle] = account_paths(&address());
    let account: AccountInfo = rest.get(&account_path).unwrap();
    let proof: MerkleStateInfo = rest.get(&account_merkle).unwrap();
    let parts = |id| {
        let [path, merkle] = mosaic_paths(id);
        MosaicParts {
            id,
            info: rest.get(&path),
            proof: rest.get(&merkle).unwrap(),
        }
    };

    let balance = verify_balance_parts(
        &address(),
        &block,
        Some(&account),
        &proof,
        &[parts(GONE), parts(XYM)],
    )
    .unwrap();
    // 渡した順ではなく、アカウントが持っている順に並ぶ
    let ids: Vec<u64> = balance
        .account
        .unwrap()
        .mosaics
        .iter()
        .map(|mosaic| mosaic.id)
        .collect();
    assert_eq!(ids, [XYM, GONE]);

    // 持っているモザイクの定義が足りなければ、確かめられない
    let error = verify_balance_parts(&address(), &block, Some(&account), &proof, &[parts(XYM)])
        .unwrap_err();
    assert_eq!(error, VerifyError::MissingMosaic(GONE));
}
