//! `crypto/1.test-address.json`: 公開鍵から4種類のネットワークのアドレスを導出する。

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "address_Public")]
    public: String,
    #[serde(rename = "address_PublicTest")]
    public_test: String,
    #[serde(rename = "address_Private")]
    private: String,
    #[serde(rename = "address_PrivateTest")]
    private_test: String,
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn derives_addresses_for_every_network() {
    let vectors: Vec<Vector> = heika_vectors::fetch("crypto/1.test-address.json");
    assert!(!vectors.is_empty());
    for vector in &vectors {
        let public_key: PublicKey = vector.public_key.parse().unwrap();
        // Private と PrivateTest は今の catapult にはない識別子だが、ベクターには残っている
        for (network, expected) in [
            (NetworkIdentifier::MAINNET, &vector.public),
            (NetworkIdentifier::TESTNET, &vector.public_test),
            (NetworkIdentifier(0x78), &vector.private),
            (NetworkIdentifier(0xA8), &vector.private_test),
        ] {
            let address = Address::from_public_key(&public_key, network);
            assert_eq!(
                address.to_string(),
                *expected,
                "{public_key} on {network:?}"
            );
            assert_eq!(expected.parse::<Address>(), Ok(address));
        }
    }
}
