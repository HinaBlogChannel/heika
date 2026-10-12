//! キーストア。ニーモニックや秘密鍵と、そこから使うアカウントをまとめて、パスフレーズで暗号化して持つ。
//!
//! 暗号化は [`crate::age`] の形式で、heika がなくても `age -d` で開ける。開いた中身は、メールのヘッダーのような
//! `キー: 値` の行のまとまりを空行で区切ったテキストで、秘密1つにつき1まとまりにする。
//!
//! ```text
//! Heika-Keystore-Version: 1
//! Secret-Type: Mnemonic
//! Secret: <単語> <単語> … <単語>
//! Account: mainnet 0 main
//! Account: testnet 0 test
//!
//! Heika-Keystore-Version: 1
//! Secret-Type: Private-Key
//! Secret: <秘密鍵の16進>
//! Account: mainnet cold
//! ```
//!
//! - ニーモニックのアカウントは、ネットワーク、公式ウォレットと同じパスの番号、ラベルの順。秘密鍵のアカウントは、ネットワークとラベル
//! - ラベルは行の残り全部で、空白を含められる。改行と制御文字は入れられない。ファイル全体で重ならない
//! - 知らないキーは読み飛ばすので、あとからキーを足せる
//! - ニーモニックは単語のまま入れる。パスフレーズを空にしたシードを入れると、あとから BIP39 のパスフレーズで
//!   別のウォレットを導出できなくなるため
//!
//! 秘密は、復号したバッファから参照で切り出して、消える型に直接読む。書くときは先に長さを数えて確保し、
//! バッファが引っ越して古い領域が消えずに残ることがないようにする。

use std::fmt;

use heika_core::key::PrivateKey;
use heika_core::network::NetworkIdentifier;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::age::{self, AgeError};
use crate::bip39::{InvalidPassphrase, Mnemonic};
use crate::slip10::{self, ExtendedKey};

const VERSION: &str = "1";

/// しまってある秘密。
pub enum Secret {
    Mnemonic(Mnemonic),
    PrivateKey(PrivateKey),
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mnemonic(_) => "Secret::Mnemonic(..)",
            Self::PrivateKey(_) => "Secret::PrivateKey(..)",
        })
    }
}

/// 秘密から使うアカウント。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub network: NetworkIdentifier,
    /// ニーモニックから導出するときの、アカウントの番号。秘密鍵なら `None`
    pub index: Option<u32>,
    pub label: String,
}

/// 秘密1つと、そのアカウント。
#[derive(Debug)]
pub struct Entry {
    pub secret: Secret,
    pub accounts: Vec<Account>,
}

#[derive(Debug, Default)]
pub struct Keystore {
    entries: Vec<Entry>,
}

impl Keystore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// 秘密を足す。アカウントのラベルが正しくないか、すでにあるものと重なるなら足さない。
    pub fn add(&mut self, entry: Entry) -> Result<(), KeystoreError> {
        check_accounts(&entry, self.accounts())?;
        self.entries.push(entry);
        Ok(())
    }

    /// すでにある秘密にアカウントを足す。
    pub fn add_account(&mut self, entry: usize, account: Account) -> Result<(), KeystoreError> {
        let target = self.entries.get(entry).ok_or(KeystoreError::Format)?;
        check_account(&target.secret, &account)?;
        if self
            .accounts()
            .any(|(_, other)| other.label == account.label)
        {
            return Err(KeystoreError::DuplicateLabel(account.label));
        }
        self.entries[entry].accounts.push(account);
        Ok(())
    }

    /// すべてのアカウントと、その秘密の番号。
    pub fn accounts(&self) -> impl Iterator<Item = (usize, &Account)> {
        self.entries
            .iter()
            .enumerate()
            .flat_map(|(index, entry)| entry.accounts.iter().map(move |account| (index, account)))
    }

    /// ラベルでアカウントを探し、その秘密鍵を求める。
    ///
    /// ニーモニックのアカウントは、`bip39_passphrase` を BIP39 のパスフレーズにして導出する。
    /// 公式ウォレットと同じ鍵になるのは空のときだけで、それ以外は同じ番号でも別の鍵（隠しウォレット）になる。
    /// 秘密鍵のアカウントには関係しない。
    pub fn private_key(
        &self,
        label: &str,
        bip39_passphrase: &str,
    ) -> Result<(&Account, PrivateKey), KeystoreError> {
        let (entry, account) = self
            .accounts()
            .find(|(_, account)| account.label == label)
            .ok_or_else(|| KeystoreError::UnknownLabel(label.to_owned()))?;
        let private_key = match &self.entries[entry].secret {
            Secret::PrivateKey(private_key) => PrivateKey::from_bytes(private_key.as_bytes()),
            Secret::Mnemonic(mnemonic) => {
                let seed = mnemonic
                    .to_seed(bip39_passphrase)
                    .map_err(KeystoreError::Bip39Passphrase)?;
                let index = account.index.expect("checked when added or read");
                ExtendedKey::from_seed(seed.as_bytes())
                    .derive_path(&slip10::symbol_path(account.network, index))
                    .private_key()
            }
        };
        Ok((account, private_key))
    }

    /// 開いた中身のテキスト。秘密が入るので、消えるようにして返す。
    pub fn to_text(&self) -> Zeroizing<Vec<u8>> {
        let mut parts: Vec<Zeroizing<String>> = Vec::new();
        for (index, entry) in self.entries.iter().enumerate() {
            if index > 0 {
                parts.push(Zeroizing::new("\n".to_owned()));
            }
            parts.push(Zeroizing::new(format!(
                "Heika-Keystore-Version: {VERSION}\n"
            )));
            let (secret_type, secret) = match &entry.secret {
                Secret::Mnemonic(mnemonic) => ("Mnemonic", mnemonic.to_phrase()),
                Secret::PrivateKey(private_key) => ("Private-Key", private_key.to_hex()),
            };
            parts.push(Zeroizing::new(format!("Secret-Type: {secret_type}\n")));
            parts.push(Zeroizing::new("Secret: ".to_owned()));
            parts.push(secret);
            parts.push(Zeroizing::new("\n".to_owned()));
            for account in &entry.accounts {
                let network = network_name(account.network);
                parts.push(Zeroizing::new(match account.index {
                    Some(index) => format!("Account: {network} {index} {}\n", account.label),
                    None => format!("Account: {network} {}\n", account.label),
                }));
            }
        }
        // 先に長さを数えて確保し、書くあいだにバッファが引っ越さないようにする
        let mut text = Zeroizing::new(Vec::with_capacity(
            parts.iter().map(|part| part.len()).sum(),
        ));
        for part in &parts {
            text.extend_from_slice(part.as_bytes());
        }
        text
    }

    /// 開いた中身のテキストを読む。
    pub fn from_text(text: &[u8]) -> Result<Self, KeystoreError> {
        let text = std::str::from_utf8(text).map_err(|_| KeystoreError::Format)?;
        let mut keystore = Self::new();
        // 秘密がまだないキーストアは空のテキスト
        if text.is_empty() {
            return Ok(keystore);
        }
        for block in text.split("\n\n") {
            let block = block.strip_suffix('\n').unwrap_or(block);
            let mut version = None;
            let mut secret_type = None;
            let mut secret = None;
            let mut accounts = Vec::new();
            for line in block.split('\n') {
                let (key, value) = line.split_once(": ").ok_or(KeystoreError::Format)?;
                let slot = match key {
                    "Heika-Keystore-Version" => &mut version,
                    "Secret-Type" => &mut secret_type,
                    "Secret" => &mut secret,
                    "Account" => {
                        accounts.push(value);
                        continue;
                    }
                    // 知らないキーは、あとの版で足したものとして読み飛ばす
                    _ => continue,
                };
                if slot.replace(value).is_some() {
                    return Err(KeystoreError::Format);
                }
            }
            match version {
                Some(VERSION) => {}
                Some(_) => return Err(KeystoreError::UnsupportedVersion),
                None => return Err(KeystoreError::Format),
            }
            let secret = secret.ok_or(KeystoreError::Format)?;
            let (secret, mnemonic) = match secret_type {
                Some("Mnemonic") => (
                    Secret::Mnemonic(secret.parse().map_err(|_| KeystoreError::InvalidSecret)?),
                    true,
                ),
                Some("Private-Key") => (
                    Secret::PrivateKey(secret.parse().map_err(|_| KeystoreError::InvalidSecret)?),
                    false,
                ),
                _ => return Err(KeystoreError::Format),
            };
            let accounts = accounts
                .into_iter()
                .map(|value| parse_account(value, mnemonic))
                .collect::<Result<_, _>>()?;
            keystore.add(Entry { secret, accounts })?;
        }
        Ok(keystore)
    }

    /// パスフレーズで暗号化する。
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        passphrase: &[u8],
        work_factor: u8,
    ) -> Vec<u8> {
        age::encrypt(rng, passphrase, work_factor, &self.to_text())
    }

    /// パスフレーズで開く。
    pub fn open(passphrase: &[u8], sealed: &[u8]) -> Result<Self, KeystoreError> {
        let text = age::decrypt(passphrase, sealed).map_err(KeystoreError::Age)?;
        Self::from_text(&text)
    }
}

fn parse_account(value: &str, mnemonic: bool) -> Result<Account, KeystoreError> {
    let (network, rest) = value.split_once(' ').ok_or(KeystoreError::Format)?;
    let network = match network {
        "mainnet" => NetworkIdentifier::MAINNET,
        "testnet" => NetworkIdentifier::TESTNET,
        _ => return Err(KeystoreError::Format),
    };
    let (index, label) = if mnemonic {
        let (index, label) = rest.split_once(' ').ok_or(KeystoreError::Format)?;
        // 先頭に 0 を付けた番号は、書き戻すと変わるので受け付けない
        if index.len() > 1 && index.starts_with('0') {
            return Err(KeystoreError::Format);
        }
        (
            Some(index.parse().map_err(|_| KeystoreError::Format)?),
            label,
        )
    } else {
        (None, rest)
    };
    Ok(Account {
        network,
        index,
        label: label.to_owned(),
    })
}

fn network_name(network: NetworkIdentifier) -> &'static str {
    match network {
        NetworkIdentifier::MAINNET => "mainnet",
        NetworkIdentifier::TESTNET => "testnet",
        _ => unreachable!("only mainnet and testnet accounts are accepted"),
    }
}

/// 足す秘密のアカウントが正しく、ラベルが互いにもすでにあるものとも重ならないか。
fn check_accounts<'a>(
    entry: &Entry,
    existing: impl Iterator<Item = (usize, &'a Account)>,
) -> Result<(), KeystoreError> {
    let mut labels: Vec<&str> = existing
        .map(|(_, account)| account.label.as_str())
        .collect();
    for account in &entry.accounts {
        check_account(&entry.secret, account)?;
        if labels.contains(&account.label.as_str()) {
            return Err(KeystoreError::DuplicateLabel(account.label.clone()));
        }
        labels.push(&account.label);
    }
    Ok(())
}

fn check_account(secret: &Secret, account: &Account) -> Result<(), KeystoreError> {
    if ![NetworkIdentifier::MAINNET, NetworkIdentifier::TESTNET].contains(&account.network) {
        return Err(KeystoreError::Format);
    }
    match (secret, account.index) {
        (Secret::Mnemonic(_), Some(index)) if index < 0x8000_0000 => {}
        (Secret::PrivateKey(_), None) => {}
        _ => return Err(KeystoreError::Format),
    }
    check_label(&account.label)
}

/// ラベルは1文字以上で、制御文字を含まず、前後に空白がない。
pub fn check_label(label: &str) -> Result<(), KeystoreError> {
    if label.is_empty() || label.trim() != label || label.chars().any(char::is_control) {
        return Err(KeystoreError::InvalidLabel(label.to_owned()));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// 暗号化を解けない（パスフレーズが違う、壊れている）
    Age(AgeError),
    /// 中身の形が正しくない
    Format,
    /// heika が知らない版のキーストア
    UnsupportedVersion,
    /// ニーモニックか秘密鍵として読めない
    InvalidSecret,
    /// ラベルに使えない文字がある
    InvalidLabel(String),
    /// 同じラベルのアカウントがすでにある
    DuplicateLabel(String),
    /// そのラベルのアカウントがない
    UnknownLabel(String),
    /// BIP39 のパスフレーズに使えない
    Bip39Passphrase(InvalidPassphrase),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Age(error) => write!(f, "{error}"),
            Self::Format => f.write_str("キーストアの中身の形が正しくありません"),
            Self::UnsupportedVersion => {
                f.write_str("この heika が知らない版のキーストアです。heika を新しくしてください")
            }
            Self::InvalidSecret => {
                f.write_str("キーストアの秘密を、ニーモニックか秘密鍵として読めません")
            }
            Self::InvalidLabel(_) => f.write_str(
                "ラベルは1文字以上で、制御文字を含まず、前後に空白がないものにしてください",
            ),
            Self::DuplicateLabel(label) => write!(f, "ラベル {label:?} のアカウントはもうあります"),
            Self::UnknownLabel(label) => write!(f, "ラベル {label:?} のアカウントはありません"),
            Self::Bip39Passphrase(error) => write!(f, "BIP39 のパスフレーズ: {error}"),
        }
    }
}

impl std::error::Error for KeystoreError {}

#[cfg(test)]
mod tests {
    use heika_core::key::PublicKey;

    use super::*;
    use crate::testing::Replay;

    /// 誰でも知っているテスト用のニーモニック
    const MNEMONIC: &str = "test test test test test test test test test test test junk";
    const PRIVATE_KEY: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";

    fn keystore() -> Keystore {
        let mut keystore = Keystore::new();
        keystore
            .add(Entry {
                secret: Secret::Mnemonic(MNEMONIC.parse().unwrap()),
                accounts: vec![
                    Account {
                        network: NetworkIdentifier::MAINNET,
                        index: Some(0),
                        label: "main".to_owned(),
                    },
                    Account {
                        network: NetworkIdentifier::TESTNET,
                        index: Some(3),
                        label: "テスト用 3".to_owned(),
                    },
                ],
            })
            .unwrap();
        keystore
            .add(Entry {
                secret: Secret::PrivateKey(PRIVATE_KEY.parse().unwrap()),
                accounts: vec![Account {
                    network: NetworkIdentifier::MAINNET,
                    index: None,
                    label: "cold".to_owned(),
                }],
            })
            .unwrap();
        keystore
    }

    #[test]
    fn writes_header_blocks() {
        let text = keystore().to_text();
        assert_eq!(
            std::str::from_utf8(&text).unwrap(),
            format!(
                "Heika-Keystore-Version: 1\nSecret-Type: Mnemonic\nSecret: {MNEMONIC}\nAccount: mainnet 0 main\nAccount: testnet 3 テスト用 3\n\nHeika-Keystore-Version: 1\nSecret-Type: Private-Key\nSecret: {PRIVATE_KEY}\nAccount: mainnet cold\n"
            )
        );
        // 先に確保したとおりで、書くあいだに引っ越していない
        assert_eq!(text.capacity(), text.len());
    }

    #[test]
    fn reads_back_what_it_writes() {
        assert_eq!(
            Keystore::from_text(&Keystore::new().to_text())
                .unwrap()
                .entries()
                .len(),
            0
        );
        let original = keystore();
        let read = Keystore::from_text(&original.to_text()).unwrap();
        assert_eq!(*read.to_text(), *original.to_text());
        let accounts: Vec<_> = read
            .accounts()
            .map(|(_, account)| account.clone())
            .collect();
        assert_eq!(accounts.len(), 3);
    }

    #[test]
    fn derives_keys_like_heika_key_derive() {
        let keystore = keystore();
        let (account, main) = keystore.private_key("main", "").unwrap();
        assert_eq!(account.index, Some(0));
        let seed = MNEMONIC.parse::<Mnemonic>().unwrap().to_seed("").unwrap();
        let expected = ExtendedKey::from_seed(seed.as_bytes())
            .derive_path(&slip10::symbol_path(NetworkIdentifier::MAINNET, 0))
            .private_key();
        assert_eq!(main.as_bytes(), expected.as_bytes());
        let (_, cold) = keystore.private_key("cold", "").unwrap();
        assert_eq!(*cold.to_hex(), PRIVATE_KEY);
        assert_ne!(
            PublicKey::from_private_key(&keystore.private_key("テスト用 3", "").unwrap().1),
            PublicKey::from_private_key(&main)
        );
        assert_eq!(
            keystore.private_key("none", "").unwrap_err(),
            KeystoreError::UnknownLabel("none".to_owned())
        );
        // BIP39 のパスフレーズを変えると、同じ番号でも別の鍵になる。秘密鍵のアカウントは変わらない
        let hidden = keystore.private_key("main", "hidden").unwrap().1;
        assert_ne!(hidden.as_bytes(), main.as_bytes());
        let seed = MNEMONIC
            .parse::<Mnemonic>()
            .unwrap()
            .to_seed("hidden")
            .unwrap();
        let expected = ExtendedKey::from_seed(seed.as_bytes())
            .derive_path(&slip10::symbol_path(NetworkIdentifier::MAINNET, 0))
            .private_key();
        assert_eq!(hidden.as_bytes(), expected.as_bytes());
        assert_eq!(
            *keystore.private_key("cold", "hidden").unwrap().1.to_hex(),
            PRIVATE_KEY
        );
    }

    #[test]
    fn skips_unknown_keys_and_rejects_broken_text() {
        let text = format!(
            "Heika-Keystore-Version: 1\nCreated: 2026-10-12\nSecret-Type: Private-Key\nSecret: {PRIVATE_KEY}\nAccount: testnet a b\n"
        );
        let read = Keystore::from_text(text.as_bytes()).unwrap();
        assert_eq!(read.accounts().next().unwrap().1.label, "a b");

        let valid =
            format!("Heika-Keystore-Version: 1\nSecret-Type: Private-Key\nSecret: {PRIVATE_KEY}\n");
        for (name, text, error) in [
            (
                "version",
                valid.replace("Version: 1", "Version: 2"),
                KeystoreError::UnsupportedVersion,
            ),
            (
                "no version",
                valid.replace("Heika-Keystore-Version: 1\n", ""),
                KeystoreError::Format,
            ),
            (
                "type",
                valid.replace("Private-Key", "Seed"),
                KeystoreError::Format,
            ),
            (
                "secret",
                valid.replace(PRIVATE_KEY, "00"),
                KeystoreError::InvalidSecret,
            ),
            (
                "twice",
                format!("{valid}Secret: {PRIVATE_KEY}\n"),
                KeystoreError::Format,
            ),
            (
                "no colon",
                format!("{valid}Account mainnet a\n"),
                KeystoreError::Format,
            ),
            (
                "network",
                format!("{valid}Account: devnet a\n"),
                KeystoreError::Format,
            ),
            (
                "index",
                format!("{valid}Account: mainnet 0 a\n")
                    .replace("Private-Key", "Mnemonic")
                    .replace(PRIVATE_KEY, MNEMONIC)
                    .replace("0 a", "00 a"),
                KeystoreError::Format,
            ),
            (
                "label",
                format!("{valid}Account: mainnet  a\n"),
                KeystoreError::InvalidLabel(" a".to_owned()),
            ),
            (
                "duplicate",
                format!("{valid}Account: mainnet a\nAccount: testnet a\n"),
                KeystoreError::DuplicateLabel("a".to_owned()),
            ),
        ] {
            assert_eq!(
                Keystore::from_text(text.as_bytes()).unwrap_err(),
                error,
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_labels_that_break_the_text() {
        for label in ["", " a", "a ", "a\nb", "a\u{7}"] {
            assert!(check_label(label).is_err(), "{label:?}");
        }
        assert!(check_label("メイン 1").is_ok());
    }

    #[test]
    fn seals_and_opens_with_a_passphrase() {
        let random = [7; 48];
        let sealed = keystore().seal(&mut Replay(&random), b"passphrase", 4);
        assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
        let opened = Keystore::open(b"passphrase", &sealed).unwrap();
        assert_eq!(*opened.to_text(), *keystore().to_text());
        assert_eq!(
            Keystore::open(b"wrong", &sealed).unwrap_err(),
            KeystoreError::Age(AgeError::NoMatch)
        );
    }
}
