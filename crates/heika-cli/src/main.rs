#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_wallet::bip39::{Mnemonic, WordCount};
use zeroize::Zeroizing;

/// Symbol のピアプロトコルを話すためのツールキット。
#[derive(Parser)]
#[command(name = "heika", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 鍵とアドレス
    #[command(subcommand)]
    Key(KeyCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
    /// 公開鍵からアドレスを出す
    Address {
        /// 公開鍵（16進）
        public_key: PublicKey,
        #[arg(long, value_enum, default_value_t = Network::Mainnet)]
        network: Network,
    },
    /// 秘密鍵を作ってファイルに書き、公開鍵を出す
    Generate {
        /// 秘密鍵（16進）を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// ニーモニックを作ってファイルに書く
    Mnemonic {
        /// ニーモニックを書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// 単語の数
        #[arg(long, value_enum, default_value_t = Words::W24)]
        words: Words,
    },
    /// 標準入力から読んだ秘密鍵（16進）から公開鍵を出す
    PublicKey,
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
}

impl From<Network> for NetworkIdentifier {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Testnet => Self::TESTNET,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Words {
    #[value(name = "12")]
    W12,
    #[value(name = "15")]
    W15,
    #[value(name = "18")]
    W18,
    #[value(name = "21")]
    W21,
    #[value(name = "24")]
    W24,
}

impl From<Words> for WordCount {
    fn from(words: Words) -> Self {
        match words {
            Words::W12 => Self::Words12,
            Words::W15 => Self::Words15,
            Words::W18 => Self::Words18,
            Words::W21 => Self::Words21,
            Words::W24 => Self::Words24,
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Key(KeyCommand::Address {
            public_key,
            network,
        }) => println!("{}", Address::from_public_key(&public_key, network.into())),
        Command::Key(KeyCommand::Generate { out }) => {
            let private_key = PrivateKey::generate()
                .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
            write_secret(&out, &private_key.to_hex())?;
            println!("公開鍵: {}", PublicKey::from_private_key(&private_key));
        }
        Command::Key(KeyCommand::Mnemonic { out, words }) => {
            let word_count = WordCount::from(words);
            let mnemonic = Mnemonic::generate(word_count)
                .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
            write_secret(&out, &mnemonic.to_phrase())?;
            println!(
                "{}語のニーモニックを {} に書きました",
                word_count.get(),
                out.display()
            );
        }
        Command::Key(KeyCommand::PublicKey) => {
            let private_key = read_private_key()?;
            println!("{}", PublicKey::from_private_key(&private_key));
        }
    }
    Ok(())
}

/// 標準入力から秘密鍵を読む。前後の空白や改行は無視する。
///
/// 引数で受け取るとシェルの履歴や `/proc/<pid>/cmdline` に残るので、標準入力だけから読む。
/// 端末から打つと画面に出てしまうので、リダイレクトかパイプで渡されたときだけ受け付ける。
fn read_private_key() -> Result<PrivateKey, String> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err("秘密鍵はリダイレクトかパイプで渡してください（例: < alice.key）".into());
    }
    let mut input =
        unbuffered(stdin).map_err(|error| format!("標準入力を開けませんでした: {error}"))?;
    let mut buffer = Zeroizing::new([0; 256]);
    let mut length = 0;
    loop {
        if length == buffer.len() {
            return Err("秘密鍵にしては入力が長すぎます".into());
        }
        match input.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("標準入力を読めませんでした: {error}")),
        }
    }
    let text = str::from_utf8(&buffer[..length])
        .map_err(|_| "秘密鍵に16進の数字ではない文字が含まれています".to_string())?;
    text.trim().parse().map_err(|error| format!("{error}"))
}

/// `io::stdin()` はプロセス全体で共有するバッファを通して読み、その中身は消せないので、
/// 同じファイル記述子をバッファなしで読む。
#[cfg(unix)]
fn unbuffered(stdin: io::Stdin) -> io::Result<impl Read> {
    stdin.as_fd().try_clone_to_owned().map(File::from)
}

/// Unix 以外ではバッファを避ける方法を用意していないので、そのまま読む（build.rs で警告する）。
#[cfg(not(unix))]
fn unbuffered(stdin: io::Stdin) -> io::Result<impl Read> {
    Ok(stdin)
}

/// 秘密鍵やニーモニックを1行で書く。ほかのユーザーから読めないように、Unix では自分だけが読み書きできるファイルにする。
fn write_secret(path: &Path, secret: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("{} を作れませんでした: {error}", path.display()))?;
    // 改行を足すと String が領域を取り直して、0で上書きされない古い領域が残るので、分けて書く
    file.write_all(secret.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}
