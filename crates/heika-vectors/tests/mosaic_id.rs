//! `crypto/5.test-mosaic-id.json`: 作った人のアドレスとノンスから、モザイク ID を求める。

use heika_core::address::Address;
use heika_transaction::MosaicId;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    #[serde(rename = "mosaicNonce")]
    nonce: u32,
    #[serde(rename = "address_Public")]
    public: String,
    #[serde(rename = "address_PublicTest")]
    public_test: String,
    #[serde(rename = "address_Private")]
    private: String,
    #[serde(rename = "address_PrivateTest")]
    private_test: String,
    #[serde(rename = "mosaicId_Public")]
    id_public: String,
    #[serde(rename = "mosaicId_PublicTest")]
    id_public_test: String,
    #[serde(rename = "mosaicId_Private")]
    id_private: String,
    #[serde(rename = "mosaicId_PrivateTest")]
    id_private_test: String,
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn generates_mosaic_ids_for_every_network() {
    let vectors: Vec<Vector> = heika_vectors::fetch("crypto/5.test-mosaic-id.json");
    assert!(!vectors.is_empty());
    for vector in &vectors {
        // アドレスにネットワークが入っているので、同じノンスでもネットワークごとに ID が変わる
        for (address, expected) in [
            (&vector.public, &vector.id_public),
            (&vector.public_test, &vector.id_public_test),
            (&vector.private, &vector.id_private),
            (&vector.private_test, &vector.id_private_test),
        ] {
            let owner: Address = address.parse().unwrap();
            let id = MosaicId::generate(&owner, vector.nonce);
            assert_eq!(
                format!("{:016X}", id.0),
                *expected,
                "{address} {}",
                vector.nonce
            );
        }
    }
}
