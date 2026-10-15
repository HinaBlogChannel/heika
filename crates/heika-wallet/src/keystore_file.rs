//! キーストアのファイル。置き場所を決め、どこで落ちても壊れないように書く。
//!
//! CLI と GUI が同じファイルを同じやり方で読み書きするように、ここにまとめる。

use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rand_core::CryptoRng;

use crate::age;
use crate::keystore::{Keystore, KeystoreError};

/// キーストアのファイルの名前
pub const FILE_NAME: &str = "keystore.age";

/// キーストアを置く場所。OS ごとに、ユーザーのデータを置くところの下の heika。
///
/// Linux では `$XDG_DATA_HOME/heika/keystore.age`（なければ `~/.local/share` の下）、
/// macOS では `~/Library/Application Support/heika/keystore.age`、
/// Windows では `%LOCALAPPDATA%\heika\keystore.age`。
pub fn default_path() -> Result<PathBuf, KeystoreFileError> {
    let var = |name: &'static str| {
        env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or(KeystoreFileError::NoDataDirectory { variable: name })
    };
    let directory = if cfg!(windows) {
        var("LOCALAPPDATA")?
    } else if cfg!(target_os = "macos") {
        var("HOME")?.join("Library/Application Support")
    } else {
        match var("XDG_DATA_HOME") {
            Ok(directory) => directory,
            Err(_) => var("HOME")?.join(".local/share"),
        }
    };
    Ok(directory.join("heika").join(FILE_NAME))
}

/// 書き換える前の中身を残すファイル
pub fn backup_path(path: &Path) -> PathBuf {
    with_suffix(path, ".bak")
}

/// 書き換える前の中身を残したファイルを消して、消したことをフォルダーに書き込む
pub fn remove_backup(path: &Path) -> Result<(), KeystoreFileError> {
    let backup = backup_path(path);
    fs::remove_file(&backup).map_err(|error| KeystoreFileError::io("消せ", &backup, error))?;
    sync_directory(directory_of(path))
}

/// キーストアを書く。どこで落ちても、古いファイルか新しいファイルのどちらかが完全な形で残るようにする。
///
/// 同じフォルダーの一時ファイルに書いて同期し、読み戻して同じパスフレーズで開けることを確かめてから、
/// 前のファイルを [`backup_path`] に写し、一時ファイルを本来の名前に置き換えて、フォルダーも同期する。
pub fn save<R: CryptoRng + ?Sized>(
    rng: &mut R,
    path: &Path,
    keystore: &Keystore,
    passphrase: &str,
) -> Result<(), KeystoreFileError> {
    let directory = directory_of(path);
    create_private_directory(directory)?;
    let sealed = keystore.seal(rng, passphrase.as_bytes(), age::DEFAULT_WORK_FACTOR);

    let temporary = with_suffix(path, ".tmp");
    // 前に落ちたときの一時ファイルが残っていれば消す。本来のファイルではないので、消しても失うものはない
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(KeystoreFileError::io("消せ", &temporary, error)),
    }
    let mut file = create_secret_file(&temporary)?;
    file.write_all(&sealed)
        .and_then(|()| file.sync_all())
        .map_err(|error| KeystoreFileError::io("書け", &temporary, error))?;
    drop(file);

    let written = fs::read(&temporary)
        .map_err(|error| KeystoreFileError::io("読み戻せ", &temporary, error))?;
    let reopened =
        Keystore::open(passphrase.as_bytes(), &written).map_err(KeystoreFileError::Reopen)?;
    if *reopened.to_text() != *keystore.to_text() {
        return Err(KeystoreFileError::Mismatch);
    }

    if path.exists() {
        let backup = backup_path(path);
        fs::copy(path, &backup)
            .and_then(|_| OpenOptions::new().write(true).open(&backup)?.sync_all())
            .map_err(|error| KeystoreFileError::io("作れ", &backup, error))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| KeystoreFileError::io("置き換えられ", path, error))?;
    sync_directory(directory)
}

/// キーストアを置くフォルダー。ファイルの名前だけなら、今のフォルダー
fn directory_of(path: &Path) -> &Path {
    path.parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// キーストアのフォルダーを作る。Unix では自分だけが入れるようにする。
fn create_private_directory(directory: &Path) -> Result<(), KeystoreFileError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(directory)
        .map_err(|error| KeystoreFileError::io("作れ", directory, error))
}

/// 秘密を書くファイルを新しく作る。すでにあれば上書きしない。Unix では自分だけが読み書きできるようにする。
fn create_secret_file(path: &Path) -> Result<File, KeystoreFileError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(path)
        .map_err(|error| KeystoreFileError::io("作れ", path, error))
}

/// 置き換えたことをフォルダーに書き込む。Windows ではフォルダーを開いて同期できないので、何もしない
fn sync_directory(directory: &Path) -> Result<(), KeystoreFileError> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| KeystoreFileError::io("同期でき", directory, error))?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

#[derive(Debug)]
pub enum KeystoreFileError {
    /// ユーザーのデータを置くところを決める環境変数がない
    NoDataDirectory { variable: &'static str },
    /// ファイルかフォルダーを扱えなかった。`action` は「作れ」「書け」のような、「ませんでした」の前に来る言葉
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// 書いたキーストアを開き直せない
    Reopen(KeystoreError),
    /// 書いたキーストアの中身が、書こうとしたものと違う
    Mismatch,
}

impl KeystoreFileError {
    fn io(action: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            action,
            path: path.to_owned(),
            source,
        }
    }
}

impl fmt::Display for KeystoreFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDataDirectory { variable } => {
                write!(
                    f,
                    "{variable} がないので、キーストアを置く場所を決められません"
                )
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(f, "{} を{action}ませんでした: {source}", path.display()),
            Self::Reopen(error) => write!(f, "書いたキーストアを開き直せませんでした: {error}"),
            Self::Mismatch => f.write_str("書いたキーストアの中身が、書こうとしたものと違います"),
        }
    }
}

impl std::error::Error for KeystoreFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Reopen(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use heika_core::key::PrivateKey;
    use heika_core::network::NetworkIdentifier;

    use super::*;
    use crate::keystore::{Account, Entry, Secret};
    use crate::testing::Replay;

    #[test]
    fn writes_crash_safely_and_keeps_a_backup() {
        let directory = env::temp_dir().join(format!("heika-wallet-test-{}", std::process::id()));
        let path = directory.join("nested").join(FILE_NAME);
        save(&mut Replay(&[1; 64]), &path, &Keystore::new(), "first").unwrap();
        let first = fs::read(&path).unwrap();
        assert!(Keystore::open(b"first", &first).is_ok());
        assert!(!backup_path(&path).exists());
        assert!(!with_suffix(&path, ".tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }

        let mut keystore = Keystore::new();
        keystore
            .add(Entry {
                secret: Secret::PrivateKey(PrivateKey::from_bytes(&[1; 32])),
                accounts: vec![Account {
                    network: NetworkIdentifier::TESTNET,
                    index: None,
                    label: "a".to_owned(),
                }],
            })
            .unwrap();
        // 前に落ちたときの一時ファイルが残っていても書ける
        fs::write(with_suffix(&path, ".tmp"), b"broken").unwrap();
        save(&mut Replay(&[2; 64]), &path, &keystore, "second").unwrap();
        let backup = fs::read(backup_path(&path)).unwrap();
        assert_eq!(backup, first);
        let second = Keystore::open(b"second", &fs::read(&path).unwrap()).unwrap();
        assert_eq!(second.accounts().count(), 1);
        fs::remove_dir_all(&directory).unwrap();
    }
}
