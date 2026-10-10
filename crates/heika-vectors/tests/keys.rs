//! `crypto/1.test-keys.json`: 秘密鍵から公開鍵を導出する。

use heika_core::key::{PrivateKey, PublicKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn derives_public_keys_from_private_keys() {
    let vectors: Vec<Vector> = heika_vectors::fetch("crypto/1.test-keys.json");
    assert!(!vectors.is_empty());
    for (index, vector) in vectors.iter().enumerate() {
        let private_key: PrivateKey = vector.private_key.parse().unwrap();
        assert_eq!(*private_key.to_hex(), vector.private_key, "vector {index}");
        assert_eq!(
            PublicKey::from_private_key(&private_key).to_string(),
            vector.public_key,
            "vector {index}"
        );
    }
}
