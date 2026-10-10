//! Symbol の公式テストベクター（github.com/symbol/symbol の `tests/vectors`）との照合。
//! ベクターはこのリポジトリに含めず、コミットを固定した URL からテストのたびに取ってくる。
//!
//! `cargo test -p heika-vectors -- --ignored` で実行する。

use serde::de::DeserializeOwned;

/// ベクターを取ってくる symbol/symbol のコミット
pub const COMMIT: &str = "dbff03b4096622d1bc1fce611358e05cfa7b0296";

/// `tests/vectors/symbol/` からの相対パスで指定したベクターを取ってきて読む。
/// テストから使うので、取れなかったり読めなかったりしたら URL を付けて panic する。
pub fn fetch<T: DeserializeOwned>(path: &str) -> T {
    let url = format!(
        "https://raw.githubusercontent.com/symbol/symbol/{COMMIT}/tests/vectors/symbol/{path}"
    );
    let body = ureq::get(&url)
        .call()
        .and_then(|mut response| response.body_mut().read_to_string())
        .unwrap_or_else(|error| panic!("{url}: {error}"));
    serde_json::from_str(&body).unwrap_or_else(|error| panic!("{url}: {error}"))
}
