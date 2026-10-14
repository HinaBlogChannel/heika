//! `models/other.json` のうち、ステートメント（`receipts.rs`）のほかの2つ。
//! 中身は文字列で書かれているので、読んだものは決まった値と比べる。

use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_core::hash::Hash256;
use heika_transaction::DetachedCosignature;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    schema_name: String,
    payload: String,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn payload(vectors: &[Vector], schema: &str) -> Vec<u8> {
    let vector = vectors
        .iter()
        .find(|vector| vector.schema_name == schema)
        .unwrap_or_else(|| panic!("{schema} がありません"));
    from_hex(&vector.payload)
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn reads_and_writes_the_other_models() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/other.json");

    // ベクターの署名はレイアウトを試すための値で、検証は通らない
    let bytes = payload(&vectors, "DetachedCosignature");
    let detached = DetachedCosignature::from_bytes(&bytes).unwrap();
    assert_eq!(detached.to_bytes()[..], bytes);
    assert_eq!(
        detached.cosignature.signer_public_key.to_string(),
        "67FA12789F80766D329C7F687C5C5F889A82F5E9C3E7996AE4FFE48C34299DE7"
    );
    assert_eq!(
        detached.parent_hash,
        "61E0F8B9AB2FE3E008DCE1380FECDAF5BCFB1851247BF990771154177A0B7E78"
            .parse::<Hash256>()
            .unwrap()
    );

    let bytes = payload(&vectors, "FinalizedBlockHeader");
    let header = FinalizedBlockHeader::from_bytes(&bytes).unwrap();
    assert_eq!(header.to_bytes()[..], bytes);
    assert_eq!(
        header.round,
        FinalizationRound {
            epoch: 0x3EA,
            point: 3
        }
    );
    assert_eq!(header.height, 0xAFF50);
    assert_eq!(
        header.hash,
        "F8E133571827948BA7D72EE62714893EC3E5C0279B44C46F528D2AED9AA28B95"
            .parse::<Hash256>()
            .unwrap()
    );
}
