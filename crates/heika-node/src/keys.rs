//! 鍵のファイルを読む。形は中身から見分ける。
//!
//! - PEM（`-----BEGIN PRIVATE KEY-----`、`heika key` や OpenSSL の作るもの）
//! - DER（PKCS#8 の 48 バイト）
//! - 16 進（64 文字。前後の空白は無視する）

use std::fmt;
use std::path::Path;

use heika_cert::key::{PRIVATE_KEY_DER_LENGTH, private_key_from_der, private_key_from_pem};
use heika_core::key::PrivateKey;
use zeroize::Zeroizing;

/// 鍵のファイルを読めなかったわけ。鍵の中身は出さない
#[derive(Debug)]
pub struct KeyFileError(String);

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyFileError {}

/// `path` の秘密鍵を読む
pub fn read_private_key(path: &Path) -> Result<PrivateKey, KeyFileError> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|error| {
        KeyFileError(format!(
            "鍵のファイル {} を読めません: {error}",
            path.display()
        ))
    })?);
    parse_private_key(&bytes)
        .map_err(|what| KeyFileError(format!("鍵のファイル {} は{what}", path.display())))
}

/// `path` を、持ち主のほか（グループやほかの人）も読めるか。読めるなら、使う側が警告を出す（ssh と違い、止めはしない）。
/// Unix のほかでは、いつも偽
pub fn others_can_read(path: &Path) -> std::io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o044 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(false)
    }
}

/// 鍵のファイルの中身を、形を見分けて読む。読めなければ、わけ（「〜」で始まる述語）を返す
fn parse_private_key(bytes: &[u8]) -> Result<PrivateKey, &'static str> {
    if bytes.len() == PRIVATE_KEY_DER_LENGTH && bytes.first() == Some(&0x30) {
        return private_key_from_der(bytes).map_err(|_| " DER として読めません");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "、PEM、DER、16 進のどれでもありません")?;
    let text = text.trim();
    if text.starts_with("-----BEGIN") {
        return private_key_from_pem(text).map_err(|_| " PEM として読めません");
    }
    if text.len() == 64 {
        return text.parse().map_err(|_| " 16 進として読めません");
    }
    Err("、PEM、DER、16 進のどれでもありません")
}

#[cfg(test)]
mod tests {
    use heika_cert::key::{private_key_to_der, private_key_to_pem};
    use heika_core::key::PublicKey;

    use super::*;

    #[test]
    fn reads_pem_der_and_hex_alike() {
        let key = PrivateKey::from_bytes(&[7; 32]);
        let public = PublicKey::from_private_key(&key);
        let pem = private_key_to_pem(&key);
        let der = private_key_to_der(&key);
        let hex = format!("{}\n", key.to_hex().as_str());
        for bytes in [pem.as_bytes(), &der[..], hex.as_bytes()] {
            let read = parse_private_key(bytes).unwrap();
            assert_eq!(PublicKey::from_private_key(&read), public);
        }
        assert!(parse_private_key(b"not a key").is_err());
        assert!(parse_private_key(&[0xFF; 48]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn tells_whether_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("heika-node-key-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        for (mode, expected) in [(0o600, false), (0o640, true), (0o604, true), (0o400, false)] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(others_can_read(&path).unwrap(), expected, "{mode:o}");
        }
        std::fs::remove_file(&path).unwrap();
    }
}
