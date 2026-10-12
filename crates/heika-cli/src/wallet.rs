//! `heika wallet`: ニーモニックや秘密鍵を、パスフレーズで暗号化したキーストアにしまって使う。
//!
//! キーストアは age 形式のファイル1つで、heika がなくても `age -d` で開ける。
//! パスフレーズは端末から聞く。標準入力は、取り込む秘密を渡すのに使う。

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_wallet::age;
use heika_wallet::keystore::{Account, Entry, Keystore, KeystoreError, Secret, check_label};
use zeroize::Zeroizing;

use crate::{Failure, Network, create_secret_file, read_secret, terminal, write_secret};

/// キーストアのファイルの名前
const FILE_NAME: &str = "keystore.age";

#[derive(Subcommand)]
pub enum WalletCommand {
    /// 空のキーストアを作る。パスフレーズは2回聞いて確かめる
    Init {
        #[command(flatten)]
        keystore: KeystoreArgs,
    },
    /// 標準入力から読んだニーモニックか秘密鍵を、最初のアカウントと一緒にしまう
    ///
    /// キーストアはバックアップの代わりにならない。ニーモニックは紙にも控えておく。
    Import {
        /// ニーモニックを読む
        #[arg(
            long,
            conflicts_with = "private_key",
            required_unless_present = "private_key"
        )]
        mnemonic: bool,
        /// 秘密鍵（16進）を読む
        #[arg(long)]
        private_key: bool,
        #[command(flatten)]
        account: AccountArgs,
        #[command(flatten)]
        keystore: KeystoreArgs,
    },
    /// しまってあるニーモニックから、アカウントを増やす
    Derive {
        /// 同じニーモニックのアカウントのラベル
        #[arg(long, value_name = "LABEL")]
        from: String,
        #[command(flatten)]
        account: AccountArgs,
        #[command(flatten)]
        keystore: KeystoreArgs,
    },
    /// アカウントのラベル、ネットワーク、公開鍵、アドレスを出す
    List {
        #[command(flatten)]
        keystore: KeystoreArgs,
        #[command(flatten)]
        expert: ExpertArgs,
    },
    /// アカウントの秘密鍵か、そのニーモニックをファイルに書き出す
    Export {
        #[arg(long, value_name = "LABEL")]
        label: String,
        /// 秘密鍵の代わりに、アカウントのもとのニーモニックを書く
        #[arg(long)]
        mnemonic: bool,
        /// 書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        #[command(flatten)]
        keystore: KeystoreArgs,
        #[command(flatten)]
        expert: ExpertArgs,
    },
}

#[derive(Args)]
pub struct AccountArgs {
    /// アカウントのラベル。キーストアの中で重ならないもの
    #[arg(long)]
    label: String,
    #[arg(long, value_enum)]
    network: Network,
    /// ニーモニックから導出するアカウントの番号。公式ウォレットと同じパスで導出する
    #[arg(long, value_name = "NUMBER", value_parser = clap::value_parser!(u32).range(..0x8000_0000))]
    account: Option<u32>,
}

/// キーストアの場所とパスフレーズ。
#[derive(Args)]
pub struct KeystoreArgs {
    /// キーストアのファイル。省略すると、Linux では ~/.local/share/heika/keystore.age
    /// （XDG_DATA_HOME があればその下）、macOS では ~/Library/Application Support/heika/keystore.age、
    /// Windows では %LOCALAPPDATA%\heika\keystore.age
    #[arg(long, value_name = "PATH")]
    keystore: Option<PathBuf>,
    /// パスフレーズを端末から聞く代わりに、このファイルの1行目から読む。スクリプトから動かすとき用
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct ExpertArgs {
    /// キーストアのパスフレーズに続けて、BIP39 のパスフレーズも聞く
    ///
    /// 空のままなら、ふつうのアカウント（公式ウォレットと同じ鍵）になる。何か入れると、
    /// ニーモニックのアカウントは同じ番号のまま別の鍵（隠しウォレット）になる。
    /// BIP39 のパスフレーズはどこにも保存しないので、忘れると取り戻せない
    #[arg(long, conflicts_with = "passphrase_file")]
    expert: bool,
}

/// 署名に使う鍵を、標準入力の代わりにキーストアから取るときの引数。
#[derive(Args)]
pub struct WalletKeyArgs {
    /// 標準入力から秘密鍵を読む代わりに、キーストアのこのアカウントの鍵を使う
    #[arg(long, value_name = "LABEL")]
    wallet_account: Option<String>,
    #[command(flatten)]
    keystore: KeystoreArgs,
    #[command(flatten)]
    expert: ExpertArgs,
}

impl WalletKeyArgs {
    /// `--wallet-account` があればキーストアから、なければ標準入力から秘密鍵を読む。
    /// キーストアのアカウントは、`network` と同じネットワークのものでなければならない。
    pub fn private_key(
        &self,
        network: Network,
        name: &str,
        example: &str,
    ) -> Result<PrivateKey, String> {
        let Some(label) = &self.wallet_account else {
            if self.keystore.keystore.is_some()
                || self.keystore.passphrase_file.is_some()
                || self.expert.expert
            {
                return Err(
                    "--keystore、--passphrase-file、--expert は --wallet-account と一緒に使ってください"
                        .to_owned(),
                );
            }
            let crate::cert::AnyPrivateKey(private_key) = read_secret(name, example)?;
            return Ok(private_key);
        };
        let (_, _, store) = self.keystore.open()?;
        let bip39_passphrase = self.expert.bip39_passphrase()?;
        let (account, private_key) = store
            .private_key(label, &bip39_passphrase)
            .map_err(|error| error.to_string())?;
        if account.network != NetworkIdentifier::from(network) {
            return Err(format!(
                "{label} は --network と違うネットワークのアカウントです"
            ));
        }
        Ok(private_key)
    }
}

pub fn run(command: WalletCommand) -> Result<(), Failure> {
    match command {
        WalletCommand::Init { keystore } => {
            let path = keystore.path()?;
            if path.exists() {
                return Err(format!("{} はすでにあります", path.display()).into());
            }
            let passphrase = keystore.new_passphrase()?;
            save(&path, &Keystore::new(), &passphrase)?;
            outln!("キーストアを作りました: {}", path.display());
        }
        WalletCommand::Import {
            mnemonic,
            private_key: _,
            account,
            keystore,
        } => {
            let secret = if mnemonic {
                Secret::Mnemonic(read_secret("ニーモニック", "alice.mnemonic")?)
            } else {
                let crate::cert::AnyPrivateKey(private_key) = read_secret("秘密鍵", "alice.key")?;
                Secret::PrivateKey(private_key)
            };
            let account = account.account(&secret)?;
            let (path, passphrase, mut store) = keystore.open()?;
            store
                .add(Entry {
                    secret,
                    accounts: vec![account.clone()],
                })
                .map_err(|error| error.to_string())?;
            save(&path, &store, &passphrase)?;
            describe(&store, &account.label, "")?;
            if mnemonic {
                outln!(
                    "キーストアはバックアップの代わりになりません。ニーモニックは紙にも控えておいてください"
                );
            }
        }
        WalletCommand::Derive {
            from,
            account,
            keystore,
        } => {
            let (path, passphrase, mut store) = keystore.open()?;
            let entry = store
                .accounts()
                .find(|(_, account)| account.label == from)
                .map(|(entry, _)| entry)
                .ok_or_else(|| KeystoreError::UnknownLabel(from.clone()).to_string())?;
            if !matches!(store.entries()[entry].secret, Secret::Mnemonic(_)) {
                return Err(
                    format!("{from} はニーモニックから導出したアカウントではありません").into(),
                );
            }
            let account = account.account(&store.entries()[entry].secret)?;
            store
                .add_account(entry, account.clone())
                .map_err(|error| error.to_string())?;
            save(&path, &store, &passphrase)?;
            describe(&store, &account.label, "")?;
        }
        WalletCommand::List { keystore, expert } => {
            let (_, _, store) = keystore.open()?;
            let bip39_passphrase = expert.bip39_passphrase()?;
            let labels: Vec<String> = store
                .accounts()
                .map(|(_, account)| account.label.clone())
                .collect();
            if labels.is_empty() {
                outln!("アカウントはまだありません");
            }
            for label in labels {
                describe(&store, &label, &bip39_passphrase)?;
            }
        }
        WalletCommand::Export {
            label,
            mnemonic,
            out,
            keystore,
            expert,
        } => {
            let (_, _, store) = keystore.open()?;
            if mnemonic {
                let (entry, _) = store
                    .accounts()
                    .find(|(_, account)| account.label == label)
                    .ok_or_else(|| KeystoreError::UnknownLabel(label.clone()).to_string())?;
                let Secret::Mnemonic(mnemonic) = &store.entries()[entry].secret else {
                    return Err(format!(
                        "{label} はニーモニックから導出したアカウントではありません"
                    )
                    .into());
                };
                write_secret(&out, &mnemonic.to_phrase())?;
                outln!("ニーモニックを {} に書きました", out.display());
            } else {
                let bip39_passphrase = expert.bip39_passphrase()?;
                let (_, private_key) = store
                    .private_key(&label, &bip39_passphrase)
                    .map_err(|error| error.to_string())?;
                write_secret(&out, &private_key.to_hex())?;
                outln!("秘密鍵を {} に書きました", out.display());
                outln!("公開鍵: {}", PublicKey::from_private_key(&private_key));
            }
        }
    }
    Ok(())
}

impl AccountArgs {
    fn account(&self, secret: &Secret) -> Result<Account, String> {
        check_label(&self.label).map_err(|error| error.to_string())?;
        let index = match (secret, self.account) {
            (Secret::Mnemonic(_), index) => Some(index.unwrap_or(0)),
            (Secret::PrivateKey(_), None) => None,
            (Secret::PrivateKey(_), Some(_)) => {
                return Err("秘密鍵のアカウントには --account を付けられません".to_owned());
            }
        };
        Ok(Account {
            network: NetworkIdentifier::from(self.network),
            index,
            label: self.label.clone(),
        })
    }
}

impl KeystoreArgs {
    fn path(&self) -> Result<PathBuf, String> {
        match &self.keystore {
            Some(path) => Ok(path.clone()),
            None => default_path(),
        }
    }

    /// キーストアを開く。キーストアのパスフレーズを聞いて（か、ファイルから読んで）、開いたものと一緒に返す。
    fn open(&self) -> Result<(PathBuf, Zeroizing<String>, Keystore), String> {
        let path = self.path()?;
        let sealed = fs::read(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                format!(
                    "{} がありません。heika wallet init で作ってください",
                    path.display()
                )
            } else {
                format!("{} を読めませんでした: {error}", path.display())
            }
        })?;
        let passphrase = self.passphrase("Passphrase: ")?;
        let keystore = Keystore::open(passphrase.as_bytes(), &sealed)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Ok((path, passphrase, keystore))
    }

    fn passphrase(&self, prompt: &str) -> Result<Zeroizing<String>, String> {
        match &self.passphrase_file {
            Some(path) => read_passphrase_file(path),
            None => terminal::prompt_line(prompt),
        }
    }

    /// 新しいパスフレーズを決める。端末からなら2回聞いて確かめる。
    fn new_passphrase(&self) -> Result<Zeroizing<String>, String> {
        let passphrase = self.passphrase("New passphrase: ")?;
        if passphrase.is_empty() {
            return Err("パスフレーズを空にはできません".to_owned());
        }
        if self.passphrase_file.is_none() {
            let again = terminal::prompt_line("Repeat passphrase: ")?;
            if *again != *passphrase {
                return Err("2回のパスフレーズが違います".to_owned());
            }
        }
        Ok(passphrase)
    }
}

impl ExpertArgs {
    /// `--expert` なら BIP39 のパスフレーズを聞く。空なら、ふつうのアカウントになる
    fn bip39_passphrase(&self) -> Result<Zeroizing<String>, String> {
        if !self.expert {
            return Ok(Zeroizing::new(String::new()));
        }
        let passphrase = terminal::prompt_line("BIP39 passphrase (optional): ")?;
        if !passphrase.is_empty() {
            eprintln!(
                "注意: BIP39 のパスフレーズを使ったので、ニーモニックのアカウントは公式ウォレットでは開けない鍵になります"
            );
        }
        Ok(passphrase)
    }
}

/// ファイルの1行目をパスフレーズにする。末尾の改行は含めない
fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
    let mut buffer = Zeroizing::new([0; 1024]);
    let mut length = 0;
    loop {
        if length == buffer.len() {
            return Err(format!(
                "{} はパスフレーズにしては長すぎます",
                path.display()
            ));
        }
        match file.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("{} を読めませんでした: {error}", path.display())),
        }
    }
    let text = std::str::from_utf8(&buffer[..length]).map_err(|_| {
        format!(
            "{} に UTF-8 として読めないバイトが含まれています",
            path.display()
        )
    })?;
    let line = text.split('\n').next().unwrap_or_default();
    let line = line.strip_suffix('\r').unwrap_or(line);
    let mut passphrase = Zeroizing::new(String::with_capacity(line.len()));
    passphrase.push_str(line);
    if passphrase.is_empty() {
        return Err(format!("{} の1行目が空です", path.display()));
    }
    Ok(passphrase)
}

/// アカウントの公開鍵とアドレスを出す
fn describe(store: &Keystore, label: &str, bip39_passphrase: &str) -> Result<(), Failure> {
    let (account, private_key) = store
        .private_key(label, bip39_passphrase)
        .map_err(|error| error.to_string())?;
    let public_key = PublicKey::from_private_key(&private_key);
    let network = if account.network == NetworkIdentifier::MAINNET {
        "mainnet"
    } else {
        "testnet"
    };
    let source = match account.index {
        Some(index) => format!("ニーモニックの {index} 番"),
        None => "秘密鍵".to_owned(),
    };
    outln!("{label}");
    outln!("  ネットワーク: {network}（{source}）");
    outln!("  公開鍵: {public_key}");
    outln!(
        "  アドレス: {}",
        Address::from_public_key(&public_key, account.network)
    );
    Ok(())
}

/// キーストアを置く場所。OS ごとに、ユーザーのデータを置くところの下の heika。
fn default_path() -> Result<PathBuf, String> {
    let var = |name| {
        env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let directory = if cfg!(windows) {
        var("LOCALAPPDATA").ok_or("LOCALAPPDATA がないので、--keystore で場所を指定してください")?
    } else if cfg!(target_os = "macos") {
        var("HOME")
            .ok_or("HOME がないので、--keystore で場所を指定してください")?
            .join("Library/Application Support")
    } else {
        match var("XDG_DATA_HOME") {
            Some(directory) => directory,
            None => var("HOME")
                .ok_or("HOME がないので、--keystore で場所を指定してください")?
                .join(".local/share"),
        }
    };
    Ok(directory.join("heika").join(FILE_NAME))
}

/// キーストアを書く。どこで落ちても、古いファイルか新しいファイルのどちらかが完全な形で残るようにする。
///
/// 同じフォルダーの一時ファイルに書いて同期し、読み戻して同じパスフレーズで開けることを確かめてから、
/// 前のファイルを `.bak` に写し、一時ファイルを本来の名前に置き換えて、フォルダーも同期する。
fn save(path: &Path, keystore: &Keystore, passphrase: &str) -> Result<(), String> {
    let directory = path
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    create_private_directory(directory)?;
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let sealed = keystore.seal(&mut rng, passphrase.as_bytes(), age::DEFAULT_WORK_FACTOR);

    let temporary = with_suffix(path, ".tmp");
    // 前に落ちたときの一時ファイルが残っていれば消す。本来のファイルではないので、消しても失うものはない
    match fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "{} を消せませんでした: {error}",
                temporary.display()
            ));
        }
    }
    let mut file = create_secret_file(&temporary)?;
    file.write_all(&sealed)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{} に書けませんでした: {error}", temporary.display()))?;
    drop(file);

    let written = fs::read(&temporary)
        .map_err(|error| format!("{} を読み戻せませんでした: {error}", temporary.display()))?;
    let reopened = Keystore::open(passphrase.as_bytes(), &written)
        .map_err(|error| format!("書いたキーストアを開き直せませんでした: {error}"))?;
    if *reopened.to_text() != *keystore.to_text() {
        return Err("書いたキーストアの中身が、書こうとしたものと違います".to_owned());
    }

    if path.exists() {
        let backup = with_suffix(path, ".bak");
        fs::copy(path, &backup)
            .and_then(|_| OpenOptions::new().write(true).open(&backup)?.sync_all())
            .map_err(|error| format!("{} を作れませんでした: {error}", backup.display()))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("{} に置き換えられませんでした: {error}", path.display()))?;
    sync_directory(directory)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// キーストアのフォルダーを作る。Unix では自分だけが入れるようにする。
fn create_private_directory(directory: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(directory)
        .map_err(|error| format!("{} を作れませんでした: {error}", directory.display()))
}

/// 置き換えたことをフォルダーに書き込む。Windows ではフォルダーを開いて同期できないので、何もしない
fn sync_directory(directory: &Path) -> Result<(), String> {
    #[cfg(unix)]
    fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("{} を同期できませんでした: {error}", directory.display()))?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

#[cfg(test)]
mod tests {
    use heika_wallet::bip39::Mnemonic;

    use super::*;

    #[test]
    fn writes_crash_safely_and_keeps_a_backup() {
        let directory = env::temp_dir().join(format!("heika-wallet-test-{}", std::process::id()));
        let path = directory.join("nested").join(FILE_NAME);
        save(&path, &Keystore::new(), "first").unwrap();
        let first = fs::read(&path).unwrap();
        assert!(Keystore::open(b"first", &first).is_ok());
        assert!(!with_suffix(&path, ".bak").exists());
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
        save(&path, &keystore, "second").unwrap();
        let backup = fs::read(with_suffix(&path, ".bak")).unwrap();
        assert_eq!(backup, first);
        let second = Keystore::open(b"second", &fs::read(&path).unwrap()).unwrap();
        assert_eq!(second.accounts().count(), 1);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn reads_the_first_line_of_a_passphrase_file() {
        let path = env::temp_dir().join(format!("heika-passphrase-test-{}", std::process::id()));
        fs::write(&path, "correct horse\r\nignored\n").unwrap();
        assert_eq!(*read_passphrase_file(&path).unwrap(), "correct horse");
        fs::write(&path, "\n").unwrap();
        assert!(read_passphrase_file(&path).is_err());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_an_account_number_for_a_private_key() {
        let args = AccountArgs {
            label: "a".to_owned(),
            network: Network::Testnet,
            account: Some(1),
        };
        let key = Secret::PrivateKey(PrivateKey::from_bytes(&[1; 32]));
        assert!(args.account(&key).is_err());
        let mnemonic = Secret::Mnemonic(
            "test test test test test test test test test test test junk"
                .parse::<Mnemonic>()
                .unwrap(),
        );
        assert_eq!(args.account(&mnemonic).unwrap().index, Some(1));
    }
}
