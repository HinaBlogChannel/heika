//! ブラウザで、決まった文字で始まる Symbol のアドレスを探す。

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use wasm_bindgen::prelude::*;

/// 見つかったアドレスと、その秘密鍵
#[wasm_bindgen(getter_with_clone)]
pub struct Found {
    pub address: String,
    pub private_key: String,
}

/// `prefix` で始まるメインネットのアドレスを、鍵を `attempts` 個まで作って探す。見つからなければ `None`。
#[wasm_bindgen]
pub fn search(prefix: &str, attempts: u32) -> Result<Option<Found>, JsError> {
    for _ in 0..attempts {
        let private_key =
            PrivateKey::generate().map_err(|error| JsError::new(&error.to_string()))?;
        let public_key = PublicKey::from_private_key(&private_key);
        let address = Address::from_public_key(&public_key, NetworkIdentifier::MAINNET).to_string();
        if address.starts_with(prefix) {
            return Ok(Some(Found {
                address,
                private_key: private_key.to_hex().to_string(),
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_an_address_that_matches_its_private_key() {
        // メインネットのアドレスは必ず N で始まる
        let found = search("N", 1).unwrap().unwrap();
        let bytes: [u8; 32] = core::array::from_fn(|index| {
            u8::from_str_radix(&found.private_key[index * 2..index * 2 + 2], 16).unwrap()
        });
        let public_key = PublicKey::from_private_key(&PrivateKey::from_bytes(&bytes));
        assert_eq!(
            Address::from_public_key(&public_key, NetworkIdentifier::MAINNET).to_string(),
            found.address
        );
    }

    #[test]
    fn gives_up_after_the_attempts() {
        // 2文字目は A から D なので、NZ では見つからない
        assert!(search("NZ", 100).unwrap().is_none());
    }
}
