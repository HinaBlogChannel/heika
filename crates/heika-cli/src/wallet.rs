//! `heika wallet`: ニーモニックや秘密鍵を、パスフレーズで暗号化したキーストアにしまって使う。
//!
//! キーストアは age 形式のファイル1つで、heika がなくても `age -d` で開ける。
//! パスフレーズは端末から聞く。標準入力は、取り込む秘密を渡すのに使う。

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_wallet::bip39::{Mnemonic, WordCount};
use heika_wallet::keystore::{Account, Entry, Keystore, KeystoreError, Secret, check_label};
use heika_wallet::keystore_file;
use zeroize::Zeroizing;

use crate::{Failure, Network, Words, read_secret, terminal, write_secret};

#[derive(Subcommand)]
pub enum WalletCommand {
    /// 空のキーストアを作る。パスフレーズは2回聞いて確かめる
    Init {
        #[command(flatten)]
        keystore: KeystoreArgs,
    },
    /// 新しいニーモニックか秘密鍵を作って、最初のアカウントと一緒にしまう
    ///
    /// 作った秘密は、ファイルにも画面にも出さない。控えるときは、export で書き出すか、
    /// age -d でキーストアを開いて見る。キーストアはバックアップの代わりにならない。
    Add {
        /// ニーモニックを作る
        #[arg(
            long,
            conflicts_with = "private_key",
            required_unless_present = "private_key"
        )]
        mnemonic: bool,
        /// 秘密鍵を作る
        #[arg(long)]
        private_key: bool,
        /// ニーモニックの単語の数
        #[arg(long, value_enum, default_value_t = Words::W24, conflicts_with = "private_key")]
        words: Words,
        #[command(flatten)]
        account: AccountArgs,
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
    /// キーストアのパスフレーズを変える。新しいパスフレーズは2回聞いて確かめる
    ///
    /// 前のパスフレーズで開ける .bak を消すかは、端末で聞く。--new-passphrase-file のときは聞かずに残す。
    /// 消すと漏れたときの心配は減るが、新しいパスフレーズを忘れたときに戻せなくなる。
    /// また、ファイルを消しても、ディスクの上から読めなくなるとは限らない。
    ChangePassphrase {
        /// 新しいパスフレーズを、端末から聞く代わりにこのファイルの1行目から読む
        #[arg(long, value_name = "PATH")]
        new_passphrase_file: Option<PathBuf>,
        /// 前のパスフレーズで開ける .bak を、聞かずに消す
        #[arg(long, conflicts_with = "keep_backup")]
        remove_backup: bool,
        /// 前のパスフレーズで開ける .bak を、聞かずに残す
        #[arg(long)]
        keep_backup: bool,
        #[command(flatten)]
        keystore: KeystoreArgs,
    },
    /// アカウントのラベルを変える
    Rename {
        #[arg(long, value_name = "LABEL")]
        label: String,
        /// 新しいラベル。キーストアの中で重ならないもの
        #[arg(long, value_name = "LABEL")]
        new_label: String,
        #[command(flatten)]
        keystore: KeystoreArgs,
    },
    /// アカウントを消す
    ///
    /// ニーモニックや秘密鍵の最後のアカウントは、--with-secret を付けたときだけ、秘密ごと消す。
    /// 前の中身は .bak に残る。
    Remove {
        #[arg(long, value_name = "LABEL")]
        label: String,
        /// 最後のアカウントと一緒に、そのニーモニックか秘密鍵も消す
        #[arg(long)]
        with_secret: bool,
        #[command(flatten)]
        keystore: KeystoreArgs,
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
            let passphrase = new_passphrase(keystore.passphrase_file.as_deref())?;
            save(&path, &Keystore::new(), &passphrase)?;
            outln!("キーストアを作りました: {}", path.display());
        }
        WalletCommand::Add {
            mnemonic,
            private_key: _,
            words,
            account,
            keystore,
        } => {
            let secret = if mnemonic {
                Secret::Mnemonic(
                    Mnemonic::generate(WordCount::from(words))
                        .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?,
                )
            } else {
                Secret::PrivateKey(
                    PrivateKey::generate()
                        .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?,
                )
            };
            let account = account.account(&secret)?;
            let (path, passphrase, store) = keystore.open()?;
            add_entry(&path, &passphrase, store, secret, account)?;
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
            let (path, passphrase, store) = keystore.open()?;
            add_entry(&path, &passphrase, store, secret, account)?;
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
        WalletCommand::ChangePassphrase {
            new_passphrase_file,
            remove_backup,
            keep_backup,
            keystore,
        } => {
            let (path, passphrase, store) = keystore.open()?;
            let next = new_passphrase(new_passphrase_file.as_deref())?;
            if *next == *passphrase {
                return Err("前と同じパスフレーズです".to_owned().into());
            }
            let backup = keystore_file::backup_path(&path);
            // 書くと、前のファイルが .bak になる。消すかは、書く前に決めておく
            let remove_backup = if remove_backup || keep_backup || new_passphrase_file.is_some() {
                remove_backup
            } else {
                eprintln!(
                    "変えたあとも、前のパスフレーズで開ける {} が残ります。消すと漏れたときの心配は減りますが、新しいパスフレーズを忘れたときに戻せなくなります",
                    backup.display()
                );
                terminal::confirm("消しますか？ [y/N]: ")?
            };
            save(&path, &store, &next)?;
            outln!("パスフレーズを変えました: {}", path.display());
            if !remove_backup {
                outln!(
                    "前のパスフレーズで開ける {} を残しました。要らなくなったら消してください",
                    backup.display()
                );
                return Ok(());
            }
            keystore_file::remove_backup(&path).map_err(|error| {
                format!("{error}。前のパスフレーズで開けるかもしれないので、残っていれば手で消してください")
            })?;
            outln!(
                "前のパスフレーズで開ける {} を消しました。ただし、ファイルを消しても、ディスクの上から読めなくなるとは限りません",
                backup.display()
            );
        }
        WalletCommand::Rename {
            label,
            new_label,
            keystore,
        } => {
            let (path, passphrase, mut store) = keystore.open()?;
            store
                .rename_account(&label, &new_label)
                .map_err(|error| error.to_string())?;
            save(&path, &store, &passphrase)?;
            outln!("{label} を {new_label} に変えました");
        }
        WalletCommand::Remove {
            label,
            with_secret,
            keystore,
        } => {
            let (path, passphrase, mut store) = keystore.open()?;
            let (entry, _) = store
                .remove_account(&label)
                .map_err(|error| error.to_string())?;
            let kind = match store.entries()[entry].secret {
                Secret::Mnemonic(_) => "ニーモニック",
                Secret::PrivateKey(_) => "秘密鍵",
            };
            let last = store.entries()[entry].accounts.is_empty();
            if last && !with_secret {
                return Err(format!(
                    "{label} は、その{kind}の最後のアカウントです。{kind}ごと消すときは、控えがあるかを確かめてから --with-secret を付けてください"
                )
                .into());
            }
            if !last && with_secret {
                return Err(format!(
                    "{kind}にはほかのアカウントがあるので、--with-secret は付けられません"
                )
                .into());
            }
            if with_secret {
                store
                    .remove_entry(entry)
                    .map_err(|error| error.to_string())?;
            }
            save(&path, &store, &passphrase)?;
            if with_secret {
                outln!("{label} を、その{kind}ごと消しました");
            } else {
                outln!("{label} を消しました");
            }
            outln!(
                "前の中身は {} に残っています。残したくないときは、このファイルも消してください",
                keystore_file::backup_path(&path).display()
            );
        }
    }
    Ok(())
}

/// 秘密を最初のアカウントと一緒にキーストアに足して書く
fn add_entry(
    path: &Path,
    passphrase: &str,
    mut store: Keystore,
    secret: Secret,
    account: Account,
) -> Result<(), Failure> {
    let is_mnemonic = matches!(secret, Secret::Mnemonic(_));
    store
        .add(Entry {
            secret,
            accounts: vec![account.clone()],
        })
        .map_err(|error| error.to_string())?;
    save(path, &store, passphrase)?;
    describe(&store, &account.label, "")?;
    if is_mnemonic {
        outln!(
            "キーストアはバックアップの代わりになりません。ニーモニックは heika wallet export --mnemonic で書き出すか、age -d で開いて、紙にも控えておいてください"
        );
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
        let passphrase = self.passphrase("パスフレーズ: ")?;
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
}

/// 新しいパスフレーズを決める。`file` があればその1行目から読み、なければ端末から2回聞いて確かめる。
fn new_passphrase(file: Option<&Path>) -> Result<Zeroizing<String>, String> {
    let passphrase = match file {
        Some(path) => read_passphrase_file(path)?,
        None => terminal::prompt_line("新しいパスフレーズ: ")?,
    };
    if passphrase.is_empty() {
        return Err("パスフレーズを空にはできません".to_owned());
    }
    if file.is_none() {
        let again = terminal::prompt_line("もう一度: ")?;
        if *again != *passphrase {
            return Err("2回のパスフレーズが違います".to_owned());
        }
    }
    Ok(passphrase)
}

impl ExpertArgs {
    /// `--expert` なら BIP39 のパスフレーズを聞く。空なら、ふつうのアカウントになる
    fn bip39_passphrase(&self) -> Result<Zeroizing<String>, String> {
        if !self.expert {
            return Ok(Zeroizing::new(String::new()));
        }
        let passphrase = terminal::prompt_line("BIP39 のパスフレーズ（なければ Enter）: ")?;
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

/// キーストアを置く場所。--keystore がないときに使う
fn default_path() -> Result<PathBuf, String> {
    keystore_file::default_path()
        .map_err(|error| format!("{error}。--keystore で場所を指定してください"))
}

/// キーストアを、どこで落ちても壊れないように書く
fn save(path: &Path, keystore: &Keystore, passphrase: &str) -> Result<(), String> {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    keystore_file::save(&mut rng, path, keystore, passphrase).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_first_line_of_a_passphrase_file() {
        let path =
            std::env::temp_dir().join(format!("heika-passphrase-test-{}", std::process::id()));
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
