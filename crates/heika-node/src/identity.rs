//! ノードの鍵と証明書を作る。GUI のように、使う人が証明書を用意しないときに使う。
//!
//! catapult と同じく、自分で作った CA がノードの証明書を発行する2段にする。置くのは
//! [`crate::config::Certificates`] の `directory` に、ノードが読む `tls.crt`（ノード、CA の順）と `tls.key`、
//! それと証明書を作り直すときに要る `ca.key.pem`。鍵のファイルは持ち主だけが読めるようにする。
//!
//! 一度作ったら使い続ける。作り直すとノードの鍵が変わり、ほかのノードからは別のノードに見える。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};

use heika_cert::certificate::{Certificate, Template, Version};
use heika_cert::key::private_key_to_pem;
use heika_core::key::{PrivateKey, PublicKey};

use crate::driver::NodeError;

/// CA とノードの証明書の期間（日）。CLI の `heika cert ca` と `heika cert node` の既定と同じ
const CA_DAYS: u64 = 7300;
const NODE_DAYS: u64 = 375;

/// `directory` に `tls.crt` と `tls.key` がなければ、新しい CA とノードの鍵と証明書を作って置く。
/// あれば何もしない。作ったら真を返す。`name` は証明書の CN
pub fn ensure(directory: &Path, name: &str) -> Result<bool, NodeError> {
    if directory.join("tls.crt").exists() && directory.join("tls.key").exists() {
        return Ok(false);
    }
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("{} を作れません: {error}", directory.display()))?;
    let random = |what: &str| {
        PrivateKey::generate().map_err(|error| format!("{what}を作る乱数を取れません: {error}"))
    };
    let ca_key = random("CA の鍵")?;
    let node_key = random("ノードの鍵")?;
    let now = SystemTime::now();
    let days = |days: u64| now + Duration::from_secs(days * 24 * 60 * 60);
    let ca_serial = random("通し番号")?;
    let ca = Certificate::self_signed(
        &ca_key,
        &Template {
            subject: &format!("CN={name}-ca"),
            not_before: now,
            not_after: days(CA_DAYS),
            serial_number: &ca_serial.as_bytes()[..19],
            version: Version::V3,
        },
    )
    .map_err(|error| error.to_string())?;
    let node_serial = random("通し番号")?;
    let node = Certificate::issue(
        &ca,
        &ca_key,
        &PublicKey::from_private_key(&node_key),
        &Template {
            subject: &format!("CN={name}"),
            not_before: now,
            not_after: days(NODE_DAYS),
            serial_number: &node_serial.as_bytes()[..19],
            version: Version::V3,
        },
    )
    .map_err(|error| error.to_string())?;
    // 鍵を先に書く。証明書があって鍵がない形で残らないように、tls.crt は最後
    write(
        &directory.join("ca.key.pem"),
        &private_key_to_pem(&ca_key),
        true,
    )?;
    write(
        &directory.join("tls.key"),
        &private_key_to_pem(&node_key),
        true,
    )?;
    write(
        &directory.join("tls.crt"),
        &format!("{}\n{}\n", node.to_pem().trim_end(), ca.to_pem().trim_end()),
        false,
    )?;
    Ok(true)
}

/// 書く。`secret` なら持ち主だけが読めるようにする。途中で残った古いものは上書きする
fn write(path: &Path, contents: &str, secret: bool) -> Result<(), NodeError> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    options
        .open(path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(|error| format!("{} に書けません: {error}", path.display()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_an_identity_the_node_can_load_once() {
        let directory = std::env::temp_dir().join(format!("heika-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        assert!(ensure(&directory, "heika").unwrap());
        let chain = Certificate::from_pem_chain(
            &std::fs::read_to_string(directory.join("tls.crt")).unwrap(),
        )
        .unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].subject(), "CN=heika");
        assert_eq!(chain[1].subject(), "CN=heika-ca");
        heika_cert::certificate::check_catapult_chain(&chain).unwrap();
        let key = std::fs::read_to_string(directory.join("tls.key")).unwrap();
        // 2回目は何もしない
        assert!(!ensure(&directory, "heika").unwrap());
        assert_eq!(
            std::fs::read_to_string(directory.join("tls.key")).unwrap(),
            key
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
