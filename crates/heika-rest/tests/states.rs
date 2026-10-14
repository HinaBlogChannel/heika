//! 状態の JSON から状態のバイト列を組み直し、状態の経路で確かめる。

use heika_core::hash::Hash256;
use heika_core::patricia::TreeNode;
use heika_rest::RestError;
use heika_rest::merkle::MerkleStateInfo;
use heika_rest::state::{AccountInfo, MetadataInfo, MosaicInfo, NamespaceInfo, RootNamespaceState};
use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn le(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// `key` の葉が1つだけの木を、REST の状態の経路の形にする。根はその葉のハッシュ
fn single_leaf_proof(key: &Hash256, value: &Hash256) -> (MerkleStateInfo, Hash256) {
    let path: Vec<u8> = key
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
    (MerkleStateInfo { raw: hex(&raw) }, leaf.hash())
}

fn account(high_value: bool) -> Value {
    let buckets: Vec<Value> = (0..5)
        .map(|index| {
            json!({
                "startHeight": (1000 - index * 180).to_string(),
                "totalFeesPaid": "10",
                "beneficiaryCount": index,
                "rawScore": "20",
            })
        })
        .collect();
    json!({
        "id": "6962CF6A2976BBB47C1054BC",
        "account": {
            "version": 1,
            "address": hex(&[0x68; 24]),
            "addressHeight": "1",
            "publicKey": hex(&[0x11; 32]),
            "publicKeyHeight": "2",
            "accountType": 1,
            "supplementalPublicKeys": {
                "linked": { "publicKey": hex(&[0x22; 32]) },
                "vrf": { "publicKey": hex(&[0x44; 32]) },
                "voting": { "publicKeys": [{ "publicKey": hex(&[0x55; 32]), "startEpoch": 3, "endEpoch": 4 }] },
            },
            "importance": if high_value { "123" } else { "0" },
            "importanceHeight": if high_value { "720" } else { "0" },
            "activityBuckets": if high_value { buckets } else { vec![] },
            "mosaics": [
                { "id": "6BED913FA20223F8", "amount": "1000" },
                { "id": "0000000000000001", "amount": "2" },
            ],
        },
    })
}

#[test]
fn rebuilds_the_account_state() {
    for high_value in [false, true] {
        let info: AccountInfo = serde_json::from_value(account(high_value)).unwrap();
        let mut expected = vec![1, 0];
        expected.extend_from_slice(&[0x68; 24]);
        expected.extend_from_slice(&le(1));
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&le(2));
        // 種類、形（大口なら 1）、鍵のビット（linked と vrf）、投票の鍵の数
        expected.extend_from_slice(&[1, u8::from(high_value), 0x05, 1]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&[0x44; 32]);
        expected.extend_from_slice(&[0x55; 32]);
        expected.extend_from_slice(&3_u32.to_le_bytes());
        expected.extend_from_slice(&4_u32.to_le_bytes());
        if high_value {
            expected.extend_from_slice(&le(123));
            expected.extend_from_slice(&le(720));
            for index in 0..5 {
                expected.extend_from_slice(&le(1000 - index * 180));
                expected.extend_from_slice(&le(10));
                expected.extend_from_slice(&(index as u32).to_le_bytes());
                expected.extend_from_slice(&le(20));
            }
        }
        expected.extend_from_slice(&2_u16.to_le_bytes());
        expected.extend_from_slice(&le(0x6BED_913F_A202_23F8));
        expected.extend_from_slice(&le(1000));
        expected.extend_from_slice(&le(1));
        expected.extend_from_slice(&le(2));
        assert_eq!(info.account.to_state_bytes().unwrap(), expected);

        let state_hash = info.account.state_hash().unwrap();
        assert_eq!(state_hash, Hash256(Sha3_256::digest(&expected).into()));
        let key = info.account.tree_key().unwrap();
        let (proof, root) = single_leaf_proof(&key, &state_hash);
        assert_eq!(proof.prove(&key, &root), Ok(Some(state_hash)));
    }
}

#[test]
fn refuses_a_high_value_account_without_five_buckets() {
    let mut json = account(true);
    json["account"]["activityBuckets"]
        .as_array_mut()
        .unwrap()
        .pop();
    let info: AccountInfo = serde_json::from_value(json).unwrap();
    assert_eq!(
        info.account.to_state_bytes(),
        Err(RestError::InvalidValue {
            field: "activityBuckets"
        })
    );
}

#[test]
fn rebuilds_the_mosaic_state() {
    let info: MosaicInfo = serde_json::from_value(json!({
        "id": "6962CF6A2976BBB47C1054BC",
        "mosaic": {
            "version": 1,
            "id": "6BED913FA20223F8",
            "supply": "7842928625000000",
            "startHeight": "1",
            "ownerAddress": hex(&[0x68; 24]),
            "revision": 1,
            "flags": 2,
            "divisibility": 6,
            "duration": "0",
        },
    }))
    .unwrap();
    let mut expected = vec![1, 0];
    expected.extend_from_slice(&le(0x6BED_913F_A202_23F8));
    expected.extend_from_slice(&le(7_842_928_625_000_000));
    expected.extend_from_slice(&le(1));
    expected.extend_from_slice(&[0x68; 24]);
    expected.extend_from_slice(&1_u32.to_le_bytes());
    expected.extend_from_slice(&[2, 6]);
    expected.extend_from_slice(&le(0));
    assert_eq!(info.mosaic.to_state_bytes().unwrap(), expected);
    assert_eq!(
        info.mosaic.tree_key(),
        Ok(heika_core::patricia::id_key(0x6BED_913F_A202_23F8))
    );
}

#[test]
fn rebuilds_the_metadata_state_and_checks_the_composite_hash() {
    let key = heika_transaction::MetadataKey {
        source_address: heika_core::address::Address([0x68; 24]),
        target_address: heika_core::address::Address([0x69; 24]),
        scoped_metadata_key: 0x8000_0000_0000_0001,
        target_id: 0,
        metadata_type: heika_transaction::MetadataType::Account,
    };
    let json = json!({
        "id": "6962CF6A2976BBB47C1054BC",
        "metadataEntry": {
            "version": 1,
            "compositeHash": key.unique_key().to_string(),
            "sourceAddress": hex(&[0x68; 24]),
            "targetAddress": hex(&[0x69; 24]),
            "scopedMetadataKey": "8000000000000001",
            "targetId": "0000000000000000",
            "metadataType": 0,
            "valueSize": 5,
            "value": hex(b"heika"),
        },
    });
    let info: MetadataInfo = serde_json::from_value(json.clone()).unwrap();
    let mut expected = vec![1, 0];
    expected.extend_from_slice(&[0x68; 24]);
    expected.extend_from_slice(&[0x69; 24]);
    expected.extend_from_slice(&le(0x8000_0000_0000_0001));
    expected.extend_from_slice(&le(0));
    expected.push(0);
    expected.extend_from_slice(&5_u16.to_le_bytes());
    expected.extend_from_slice(b"heika");
    assert_eq!(info.metadata_entry.to_state_bytes().unwrap(), expected);
    assert_eq!(
        info.metadata_entry.tree_key(),
        Ok(heika_core::patricia::hash_key(&key.unique_key()))
    );

    let mut other = json;
    other["metadataEntry"]["compositeHash"] = json!(hex(&[0; 32]));
    let info: MetadataInfo = serde_json::from_value(other).unwrap();
    assert_eq!(
        info.metadata_entry.tree_key(),
        Err(RestError::Mismatch {
            field: "compositeHash"
        })
    );
}

fn namespace(active: bool, levels: &[&str], alias: Value) -> Value {
    let mut namespace = json!({
        "version": 1,
        "registrationType": u8::from(levels.len() > 1),
        "depth": levels.len(),
        "level0": levels[0],
        "alias": alias,
        "parentId": "0000000000000000",
        "ownerAddress": hex(&[0x68; 24]),
        "startHeight": "1",
        "endHeight": "18446744073709551615",
    });
    if let Some(level) = levels.get(1) {
        namespace["level1"] = json!(level);
    }
    if let Some(level) = levels.get(2) {
        namespace["level2"] = json!(level);
    }
    json!({ "id": "6962CF6A2976BBB47C1054BC", "meta": { "active": active, "index": 0 }, "namespace": namespace })
}

#[test]
fn rebuilds_a_root_namespace_from_its_children() {
    const ROOT: &str = "A95F1F8A96159516";
    let root_id = 0xA95F_1F8A_9615_9516_u64;
    // REST が返す順はばらばらにしておく
    let entries: Vec<NamespaceInfo> = [
        namespace(true, &[ROOT, "0000000000000003"], json!({ "type": 0 })),
        namespace(
            true,
            &[ROOT, "0000000000000002", "0000000000000009"],
            json!({ "type": 2, "address": hex(&[0x69; 24]) }),
        ),
        namespace(true, &[ROOT], json!({ "type": 0 })),
        namespace(
            true,
            &[ROOT, "0000000000000002"],
            json!({ "type": 1, "mosaicId": "6BED913FA20223F8" }),
        ),
        // 履歴になったものと、別のルートのものは入れない
        namespace(false, &[ROOT, "0000000000000005"], json!({ "type": 0 })),
        namespace(true, &["0000000000000007"], json!({ "type": 0 })),
    ]
    .into_iter()
    .map(|json| serde_json::from_value(json).unwrap())
    .collect();
    let state = RootNamespaceState::collect(root_id, &entries).unwrap();

    let mut expected = vec![1, 0];
    expected.extend_from_slice(&le(root_id));
    expected.extend_from_slice(&[0x68; 24]);
    expected.extend_from_slice(&le(1));
    expected.extend_from_slice(&le(u64::MAX));
    expected.push(0);
    expected.extend_from_slice(&le(3));
    // 子は経路の辞書順。[2]、[2, 9]、[3]
    expected.push(1);
    expected.extend_from_slice(&le(2));
    expected.push(1);
    expected.extend_from_slice(&le(0x6BED_913F_A202_23F8));
    expected.push(2);
    expected.extend_from_slice(&le(2));
    expected.extend_from_slice(&le(9));
    expected.push(2);
    expected.extend_from_slice(&[0x69; 24]);
    expected.push(1);
    expected.extend_from_slice(&le(3));
    expected.push(0);
    assert_eq!(state.to_state_bytes().unwrap(), expected);
    assert_eq!(state.tree_key(), heika_core::patricia::id_key(root_id));

    assert_eq!(
        RootNamespaceState::collect(0x99, &entries),
        Err(RestError::Missing { field: "level0" })
    );
}
