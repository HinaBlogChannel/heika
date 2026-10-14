//! 自分で署名したブロックと、自分で求めた経路を、REST の JSON の形にして読み、確かめる。

use heika_block::Block;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::merkle::{self, MerklePathNode};
use heika_core::patricia::{self, TreeNode};
use heika_core::vrf;
use heika_rest::RestError;
use heika_rest::block::BlockInfo;
use heika_rest::merkle::{MerkleProofInfo, MerkleStateInfo};
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// メインネットのブロックのヘッダーを組んで署名し、REST が返す形の JSON にする。
/// `importance` なら Importance のブロックにして、フッターも付ける。
fn block_json(importance: bool) -> Value {
    let harvester = PrivateKey::from_bytes(&[3; 32]);
    let proof = vrf::prove(&PrivateKey::from_bytes(&[4; 32]), &[0x5A; 32]).unwrap();
    let roots: [Hash256; 9] = std::array::from_fn(|index| Hash256([index as u8 + 1; 32]));
    let state_hash = patricia::state_hash(&roots);

    let header_size = if importance { 424 } else { 376 };
    let block_type: u16 = if importance { 0x8243 } else { 0x8143 };
    let mut bytes = vec![0; header_size];
    bytes[..4].copy_from_slice(&(header_size as u32).to_le_bytes());
    bytes[72..104].copy_from_slice(&PublicKey::from_private_key(&harvester).0);
    bytes[108] = 1;
    bytes[109] = 0x68;
    bytes[110..112].copy_from_slice(&block_type.to_le_bytes());
    bytes[112..120].copy_from_slice(&1440_u64.to_le_bytes());
    bytes[120..128].copy_from_slice(&123_456_u64.to_le_bytes());
    bytes[128..136].copy_from_slice(&100_000_000_000_000_u64.to_le_bytes());
    bytes[136..168].copy_from_slice(&proof.gamma);
    bytes[168..184].copy_from_slice(&proof.verification_hash);
    bytes[184..216].copy_from_slice(&proof.scalar);
    bytes[216..248].copy_from_slice(&[0x11; 32]);
    bytes[312..344].copy_from_slice(&state_hash.0);
    bytes[344] = 0x68;
    bytes[368..372].copy_from_slice(&100_u32.to_le_bytes());
    if importance {
        bytes[372..376].copy_from_slice(&7_u32.to_le_bytes());
        bytes[376..384].copy_from_slice(&8_u64.to_le_bytes());
        bytes[384..392].copy_from_slice(&9_u64.to_le_bytes());
        bytes[392..424].copy_from_slice(&[0x22; 32]);
    }
    // 通常のブロックの最後のパディングは、署名に入らない
    let signed_end = if importance { 424 } else { 372 };
    let signature = harvester.sign(&[&bytes[108..signed_end]]);
    bytes[8..72].copy_from_slice(&signature.0);
    let block = Block::from_bytes(&bytes).unwrap();
    assert!(block.verify_signature());

    let mut header = json!({
        // 中のトランザクションも含めた大きさなので、ヘッダーより大きい
        "size": header_size + 1000,
        "signature": hex(&signature.0),
        "signerPublicKey": hex(&bytes[72..104]),
        "version": 1,
        "network": 104,
        "type": block_type,
        "height": "1440",
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
    });
    if importance {
        header["votingEligibleAccountsCount"] = json!(7);
        header["harvestingEligibleAccountsCount"] = json!("8");
        header["totalVotingBalance"] = json!("9");
        header["previousImportanceBlockHash"] = json!(hex(&[0x22; 32]));
    }
    json!({
        "id": "6962CF6A2976BBB47C1054BC",
        "meta": {
            "hash": block.hash().to_string(),
            "generationHash": block.generation_hash().to_string(),
            "totalFee": "0",
            "stateHashSubCacheMerkleRoots": roots.iter().map(Hash256::to_string).collect::<Vec<_>>(),
            "totalTransactionsCount": 0,
            "transactionsCount": 0,
            "statementsCount": 1,
        },
        "block": header,
    })
}

fn read(json: &Value) -> BlockInfo {
    serde_json::from_value(json.clone()).unwrap()
}

#[test]
fn verifies_a_block_rebuilt_from_rest() {
    for importance in [false, true] {
        let json = block_json(importance);
        let block = read(&json).verify().unwrap();
        assert_eq!(block.height, 1440);
        assert_eq!(block.fee_multiplier, 100);
        assert_eq!(block.importance_footer.is_some(), importance);
        assert_eq!(block.transactions().count(), 0);
        // 小文字の16進でも読める
        let mut lower = json.clone();
        lower["meta"]["hash"] = json!(json["meta"]["hash"].as_str().unwrap().to_lowercase());
        assert_eq!(read(&lower).verify(), Ok(block));
    }
}

#[test]
fn refuses_a_block_whose_values_do_not_match() {
    let json = block_json(false);
    for (pointer, value, field) in [
        ("/block/height", json!("1441"), "signature"),
        ("/block/feeMultiplier", json!(101), "signature"),
        ("/meta/hash", json!(hex(&[0; 32])), "meta.hash"),
        (
            "/meta/generationHash",
            json!(hex(&[0; 32])),
            "meta.generationHash",
        ),
        (
            "/meta/stateHashSubCacheMerkleRoots/0",
            json!(hex(&[0; 32])),
            "stateHash",
        ),
    ] {
        let mut changed = json.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_eq!(
            read(&changed).verify(),
            Err(RestError::Mismatch { field }),
            "{pointer}"
        );
    }
    let mut short = json.clone();
    short["block"]["proofScalar"] = json!("00");
    assert_eq!(
        read(&short).verify(),
        Err(RestError::InvalidHex {
            field: "proofScalar"
        })
    );
    let mut negative = json.clone();
    negative["block"]["height"] = json!("-1");
    assert_eq!(
        read(&negative).verify(),
        Err(RestError::InvalidNumber { field: "height" })
    );
    // Importance のブロックの種類なのに、フッターがない
    let mut missing = json;
    missing["block"]["type"] = json!(0x8243);
    assert!(matches!(
        read(&missing).verify(),
        Err(RestError::InvalidBlock(_))
    ));
}

#[test]
fn reads_a_merkle_path() {
    let leaves: Vec<_> = (0..5).map(|byte| Hash256([byte; 32])).collect();
    let root = merkle::root(&leaves);
    let path = merkle::path(&leaves, 3).unwrap();
    let json = json!({
        "merklePath": path.iter().map(|node| json!({
            "position": match node.position {
                merkle::Position::Left => "left",
                merkle::Position::Right => "right",
            },
            "hash": node.hash.to_string(),
        })).collect::<Vec<_>>(),
    });
    let info: MerkleProofInfo = serde_json::from_value(json.clone()).unwrap();
    let read = Vec::<MerklePathNode>::try_from(&info).unwrap();
    assert_eq!(read, path);
    assert!(merkle::verify_path(&leaves[3], &read, &root));

    let mut wrong = json;
    wrong["merklePath"][0]["position"] = json!("up");
    let info: MerkleProofInfo = serde_json::from_value(wrong).unwrap();
    assert_eq!(
        Vec::<MerklePathNode>::try_from(&info),
        Err(RestError::InvalidValue { field: "position" })
    );
}

#[test]
fn reads_state_tree_nodes_from_raw() {
    // 経路のない葉1つだけの木。`tree` は読まない
    let mut raw = vec![0xFF, 0];
    raw.extend_from_slice(&[0xAB; 32]);
    let json = json!({ "raw": hex(&raw), "tree": [{ "type": 255 }] });
    let info: MerkleStateInfo = serde_json::from_value(json).unwrap();
    assert_eq!(
        Vec::<TreeNode>::try_from(&info),
        Ok(vec![TreeNode::Leaf {
            path: vec![],
            value: Hash256([0xAB; 32])
        }])
    );
    let info = MerkleStateInfo {
        raw: "01".to_owned(),
    };
    assert!(matches!(
        Vec::<TreeNode>::try_from(&info),
        Err(RestError::InvalidTreeNodes(_))
    ));
}

#[test]
fn writes_the_rest_json_of_a_block_header() {
    for importance in [false, true] {
        let json = block_json(importance);
        let block = read(&json).verify().unwrap();
        let mut expected = json["block"].clone();
        // ヘッダーだけのブロックなので、大きさはヘッダーの大きさになる
        expected["size"] = serde_json::json!(block.as_bytes().len());
        assert_eq!(
            serde_json::to_value(heika_rest::block::BlockHeader::from(&block)).unwrap(),
            expected
        );
    }
}
