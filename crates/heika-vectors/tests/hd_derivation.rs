//! `crypto/6.test-hd-derivation.json`: ニーモニックからシードを作り、そこから鍵を導出する。

use heika_core::key::PublicKey;
use heika_wallet::bip39::Mnemonic;
use heika_wallet::slip10::ExtendedKey;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    public_net: Vec<Vector>,
    test_net: Vec<Vector>,
    /// SLIP-10 のテストベクターと同じシードで、パスも `[0, 1, 2]` のように短い組
    test_vectors: Vec<Vector>,
}

/// シードだけでニーモニックのない組もある。
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    mnemonic: Option<String>,
    passphrase: Option<String>,
    seed: String,
    root_public_key: String,
    child_accounts: Vec<ChildAccount>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChildAccount {
    path: Vec<u32>,
    public_key: String,
}

impl Vectors {
    fn all(&self) -> impl Iterator<Item = &Vector> {
        self.public_net
            .iter()
            .chain(&self.test_net)
            .chain(&self.test_vectors)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn public_key(key: &ExtendedKey) -> String {
    PublicKey::from_private_key(&key.private_key()).to_string()
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn derives_seeds_from_mnemonics() {
    let vectors: Vectors = heika_vectors::fetch("crypto/6.test-hd-derivation.json");
    let mut checked = 0;
    for (index, vector) in vectors.all().enumerate() {
        let (Some(phrase), Some(passphrase)) = (&vector.mnemonic, &vector.passphrase) else {
            continue;
        };
        let mnemonic: Mnemonic = phrase.parse().unwrap();
        assert_eq!(*mnemonic.to_phrase(), *phrase, "vector {index}");
        let seed = mnemonic.to_seed(passphrase).unwrap();
        assert_eq!(to_hex(seed.as_bytes()), vector.seed, "vector {index}");
        checked += 1;
    }
    assert_eq!(checked, 96);
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn derives_keys_from_seeds() {
    let vectors: Vectors = heika_vectors::fetch("crypto/6.test-hd-derivation.json");
    let mut checked = 0;
    for (index, vector) in vectors.all().enumerate() {
        let root = ExtendedKey::from_seed(&from_hex(&vector.seed));
        assert_eq!(public_key(&root), vector.root_public_key, "vector {index}");
        for child in &vector.child_accounts {
            assert_eq!(
                public_key(&root.derive_path(&child.path)),
                child.public_key,
                "vector {index} {:?}",
                child.path
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 424);
}
