//! ブラウザで、決まった文字で始まる Symbol のアドレスを探す。

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use wasm_bindgen::prelude::*;

/// アドレスに使われる Base32 の文字
const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

/// メインネットのアドレスの先頭になれるかを確かめる。なれなければ、その理由。
///
/// 1文字目はネットワークの番号で決まる N、2文字目は番号の残りの3ビットが0なので A から D のどれか。
pub fn check_prefix(prefix: &str) -> Result<(), String> {
    if let Some(character) = prefix
        .chars()
        .find(|character| !ALPHABET.contains(*character))
    {
        return Err(format!(
            "「{character}」はアドレスに使われない文字です（A〜Z と 2〜7）"
        ));
    }
    if !prefix.starts_with('N') {
        return Err("メインネットのアドレスは N で始まります".into());
    }
    if prefix.len() >= 2 && !"ABCD".contains(&prefix[1..2]) {
        return Err("2文字目は A、B、C、D のどれかです".into());
    }
    Ok(())
}

/// 見つかるまでに作る鍵の数の見込み（期待値）。2文字目は4通り、3文字目からは32通り。
pub fn expected_attempts(prefix: &str) -> f64 {
    match prefix.len() {
        0 | 1 => 1.0,
        length => 4.0 * 32_f64.powi(length as i32 - 2),
    }
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

    #[test]
    fn checks_the_prefix() {
        assert_eq!(check_prefix("NASYMBOL"), Ok(()));
        assert_eq!(check_prefix("N"), Ok(()));
        assert!(check_prefix("TA").is_err());
        assert!(check_prefix("NE").is_err());
        assert!(check_prefix("NA0").is_err());
    }

    #[test]
    fn expects_four_then_thirty_two_per_character() {
        assert_eq!(expected_attempts("N"), 1.0);
        assert_eq!(expected_attempts("NA"), 4.0);
        assert_eq!(expected_attempts("NAS"), 128.0);
    }
}
