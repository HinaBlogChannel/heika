//! アプリの本体。画面（WebView）からは `invoke` でここのコマンドを呼ぶ。
//! 秘密鍵のように画面に出したくないものは、ここから外に出さない。

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use serde::Serialize;

/// 画面の下に出す、どこで動いているか
#[derive(Serialize)]
struct About {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
}

#[tauri::command]
fn about() -> About {
    About {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    }
}

/// 新しい秘密鍵を作って、そのアドレスだけを返す。秘密鍵は返さずに捨てる（drop で0に消える）。
#[tauri::command]
fn new_address(network: &str) -> Result<String, String> {
    let network = match network {
        "mainnet" => NetworkIdentifier::MAINNET,
        "testnet" => NetworkIdentifier::TESTNET,
        _ => return Err(format!("知らないネットワークです: {network}")),
    };
    let private_key = PrivateKey::generate().map_err(|error| error.to_string())?;
    let public_key = PublicKey::from_private_key(&private_key);
    Ok(Address::from_public_key(&public_key, network).to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![about, new_address])
        .run(tauri::generate_context!())
        .expect("Tauri のアプリを起動できませんでした");
}
