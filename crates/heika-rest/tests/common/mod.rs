//! テストで使う、REST が返す形の JSON

#![allow(dead_code)]

use heika_block::Block;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::patricia;
use heika_core::vrf;
use serde_json::{Value, json};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// メインネットの通常のブロックを、9本の根を `roots`、TransactionsHash を `transactions_hash` にして組んで署名し、
/// REST が返す形の JSON にする
pub fn block_json_with(height: u64, roots: &[Hash256; 9], transactions_hash: &Hash256) -> Value {
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
    bytes[248..280].copy_from_slice(&transactions_hash.0);
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
            "transactionsHash": hex(&transactions_hash.0),
            "receiptsHash": hex(&[0; 32]),
            "stateHash": hex(&state_hash.0),
            "beneficiaryAddress": hex(&bytes[344..368]),
            "feeMultiplier": 100,
        },
    })
}

/// トランザクションのないブロック
pub fn block_json(height: u64, roots: &[Hash256; 9]) -> Value {
    block_json_with(height, roots, &Hash256([0; 32]))
}
