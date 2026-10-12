//! `models/blocks.json`: ブロックのバイト列と、その中身。
//! ここにある署名はレイアウトを試すための値で、検証は通らない。

use heika_block::{Block, BlockType};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Vector {
    test_name: String,
    payload: String,
    descriptor: Value,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// 16進の文字列を、大文字にそろえて比べられるようにする。ベクターには小文字のものも混ざっている。
fn hex(descriptor: &Value, field: &str) -> String {
    descriptor[field].as_str().unwrap().to_uppercase()
}

fn number(descriptor: &Value, field: &str) -> u64 {
    descriptor[field].as_u64().unwrap()
}

#[test]
#[ignore = "ネットワークから公式ベクターを取ってくる"]
fn reads_blocks() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/blocks.json");
    assert_eq!(vectors.len(), 3);
    for vector in vectors {
        let name = &vector.test_name;
        let d = &vector.descriptor;
        let block = Block::from_bytes(&from_hex(&vector.payload))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let block_type = match d["type"].as_str().unwrap() {
            "normal_block_v1" => BlockType::Normal,
            "nemesis_block_v1" => BlockType::Nemesis,
            "importance_block_v1" => BlockType::Importance,
            other => panic!("{name}: {other}"),
        };
        assert_eq!(block.block_type, block_type, "{name}");
        assert_eq!(block.version, 1, "{name}");
        assert_eq!(block.signature.to_string(), hex(d, "signature"), "{name}");
        assert_eq!(
            block.signer_public_key.to_string(),
            hex(d, "signer_public_key"),
            "{name}"
        );
        assert_eq!(block.height, number(d, "height"), "{name}");
        assert_eq!(block.timestamp, number(d, "timestamp"), "{name}");
        assert_eq!(block.difficulty, number(d, "difficulty"), "{name}");
        let proof = &d["generation_hash_proof"];
        let proof_hex =
            |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02X}")).collect() };
        assert_eq!(
            proof_hex(&block.generation_hash_proof.gamma),
            hex(proof, "gamma"),
            "{name}"
        );
        assert_eq!(
            proof_hex(&block.generation_hash_proof.verification_hash),
            hex(proof, "verification_hash"),
            "{name}"
        );
        assert_eq!(
            proof_hex(&block.generation_hash_proof.scalar),
            hex(proof, "scalar"),
            "{name}"
        );
        for (actual, field) in [
            (block.previous_block_hash, "previous_block_hash"),
            (block.transactions_hash, "transactions_hash"),
            (block.receipts_hash, "receipts_hash"),
            (block.state_hash, "state_hash"),
        ] {
            assert_eq!(actual.to_string(), hex(d, field), "{name}: {field}");
        }
        assert_eq!(
            block.beneficiary_address.to_string(),
            d["beneficiary_address"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            u64::from(block.fee_multiplier),
            number(d, "fee_multiplier"),
            "{name}"
        );
        match &block.importance_footer {
            None => assert_eq!(block_type, BlockType::Normal, "{name}"),
            Some(footer) => {
                assert_eq!(
                    u64::from(footer.voting_eligible_accounts_count),
                    number(d, "voting_eligible_accounts_count"),
                    "{name}"
                );
                assert_eq!(
                    footer.harvesting_eligible_accounts_count,
                    number(d, "harvesting_eligible_accounts_count"),
                    "{name}"
                );
                assert_eq!(
                    footer.total_voting_balance,
                    number(d, "total_voting_balance"),
                    "{name}"
                );
                assert_eq!(
                    footer.previous_importance_block_hash.to_string(),
                    hex(d, "previous_importance_block_hash"),
                    "{name}"
                );
            }
        }

        // トランザクションは、件数と、それぞれの署名者で、切り分けた位置が合っているかを見る
        let transactions = d["transactions"].as_array().unwrap();
        assert_eq!(block.transactions().count(), transactions.len(), "{name}");
        for (bytes, transaction) in block.transactions().zip(transactions) {
            let signer: String = bytes[72..104].iter().map(|b| format!("{b:02X}")).collect();
            assert_eq!(signer, hex(transaction, "signer_public_key"), "{name}");
        }
    }
}
