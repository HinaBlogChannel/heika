//! `crypto/3.test-derive-hkdf.json` と `crypto/4.test-cipher.json`: 鍵の共有と AES-GCM。

use heika_core::key::{PrivateKey, PublicKey};
use heika_wallet::cipher::{self, SharedKey};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SharedKeyVector {
    private_key: String,
    other_public_key: String,
    shared_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherVector {
    private_key: String,
    other_public_key: String,
    tag: String,
    iv: String,
    cipher_text: String,
    clear_text: String,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn shared_key(private_key: &str, other_public_key: &str) -> SharedKey {
    let private_key: PrivateKey = private_key.parse().unwrap();
    let other_public_key: PublicKey = other_public_key.parse().unwrap();
    SharedKey::derive(&private_key, &other_public_key).unwrap()
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn derives_shared_keys() {
    let vectors: Vec<SharedKeyVector> = heika_vectors::fetch("crypto/3.test-derive-hkdf.json");
    assert!(!vectors.is_empty());
    for (index, vector) in vectors.iter().enumerate() {
        let key = shared_key(&vector.private_key, &vector.other_public_key);
        assert_eq!(
            key.as_bytes()[..],
            from_hex(&vector.shared_key),
            "vector {index}"
        );
    }
    eprintln!("{} vectors checked", vectors.len());
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn encrypts_and_decrypts() {
    let vectors: Vec<CipherVector> = heika_vectors::fetch("crypto/4.test-cipher.json");
    assert!(!vectors.is_empty());
    for (index, vector) in vectors.iter().enumerate() {
        let key = shared_key(&vector.private_key, &vector.other_public_key);
        let iv: [u8; cipher::IV_SIZE] = from_hex(&vector.iv).try_into().unwrap();
        let clear_text = from_hex(&vector.clear_text);
        let expected = [
            from_hex(&vector.tag),
            iv.to_vec(),
            from_hex(&vector.cipher_text),
        ]
        .concat();
        assert_eq!(
            cipher::encrypt(&key, &iv, &clear_text),
            expected,
            "vector {index}"
        );
        assert_eq!(
            *cipher::decrypt(&key, &expected).unwrap(),
            clear_text,
            "vector {index}"
        );
    }
    eprintln!("{} vectors checked", vectors.len());
}
