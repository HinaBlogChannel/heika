//! `crypto/2.test-sign.json`: 秘密鍵でデータに署名し、その署名を検証する。

use heika_core::key::{PrivateKey, PublicKey};
use heika_core::signature::Signature;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    private_key: String,
    public_key: String,
    length: usize,
    data: String,
    signature: String,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn signs_and_verifies_data() {
    let vectors: Vec<Vector> = heika_vectors::fetch("crypto/2.test-sign.json");
    assert!(!vectors.is_empty());
    for (index, vector) in vectors.iter().enumerate() {
        let private_key: PrivateKey = vector.private_key.parse().unwrap();
        let public_key: PublicKey = vector.public_key.parse().unwrap();
        let data = from_hex(&vector.data);
        assert_eq!(data.len(), vector.length, "vector {index}");
        let signature = private_key.sign(&[&data]);
        assert_eq!(signature.to_string(), vector.signature, "vector {index}");
        let expected: Signature = vector.signature.parse().unwrap();
        assert!(public_key.verify(&[&data], &expected), "vector {index}");
    }
    eprintln!("{} vectors checked", vectors.len());
}
