//! `crypto/6.test-hd-derivation.json`: ニーモニックからシードを作り、そこから鍵を導出する。

use heika_wallet::bip39::Mnemonic;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    public_net: Vec<Vector>,
    test_net: Vec<Vector>,
}

/// シードだけでニーモニックのない組もある。
#[derive(Deserialize)]
struct Vector {
    mnemonic: Option<String>,
    passphrase: Option<String>,
    seed: String,
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn derives_seeds_from_mnemonics() {
    let vectors: Vectors = heika_vectors::fetch("crypto/6.test-hd-derivation.json");
    let mut checked = 0;
    for (index, vector) in vectors
        .public_net
        .iter()
        .chain(&vectors.test_net)
        .enumerate()
    {
        let (Some(phrase), Some(passphrase)) = (&vector.mnemonic, &vector.passphrase) else {
            continue;
        };
        let mnemonic: Mnemonic = phrase.parse().unwrap();
        assert_eq!(*mnemonic.to_phrase(), *phrase, "vector {index}");
        let seed = mnemonic.to_seed(passphrase).unwrap();
        let hex: String = seed
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();
        assert_eq!(hex, vector.seed, "vector {index}");
        checked += 1;
    }
    assert_eq!(checked, 96);
}
