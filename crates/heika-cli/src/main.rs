#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use heika_cert::key;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_wallet::bip39::{Mnemonic, WordCount};
use heika_wallet::slip10::{self, ExtendedKey};
use zeroize::Zeroizing;

/// Symbol のノード運営のための、鍵と証明書のツールキット。
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
    /// ノードの TLS の証明書
    #[command(subcommand)]
    Cert(cert::CertCommand),
    /// ハーベストのためのリンクと委任を、署名していないトランザクションに組んで書く
    ///
    /// 解除、紐づけ、委任の要求の順に、1つのアグリゲートにまとめる。
    /// --delegate を付けると、リモートアカウントと VRF の鍵をその場で作って紐づけ、委任先のノードに委任の要求を送る。
    /// 作った秘密鍵は委任の要求に暗号化して入れるだけで、どこにも保存しない。前の委任先が知っている鍵を使い回さないためである。
    /// 自分のノードでハーベストするなら、--link-remote と --link-vrf に、ノードに置く鍵の公開鍵を渡す。
    Harvesting(harvesting::HarvestingArgs),
    /// ノードに TLS でつないで調べる
    #[command(subcommand)]
    Node(node::NodeCommand),
    /// トランザクション
    #[command(subcommand)]
    Tx(tx::TxCommand),
    /// heika と依存のライセンスと、このバイナリのソース
    #[command(subcommand)]
    Legal(legal::LegalCommand),
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
    /// 標準入力から読んだニーモニックから Symbol のウォレットと同じパスで鍵を導出し、公開鍵とアドレスを出す
    ///
    /// パスは m/44'/<COIN>'/<ACCOUNT>'/0'/0' で、COIN はメインネットなら 4343、テストネットなら 1。
    ///
    /// パスフレーズは公式のデスクトップウォレットと同じく空にする
    Derive {
        /// アカウントの番号
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(..0x8000_0000))]
        account: u32,
        #[arg(long, value_enum, default_value_t = Network::Mainnet)]
        network: Network,
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
    /// 鍵を OpenSSL と同じ PEM にする
    ///
    /// 秘密鍵は標準入力から16進で読み、--out のファイルに書く。
    /// --public を付けると、引数の公開鍵（16進）を標準出力に書く。
    ToPem {
        /// 秘密鍵の PEM を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH", required_unless_present = "public")]
        out: Option<PathBuf>,
        /// 秘密鍵の代わりにこの公開鍵（16進）を PEM にする
        #[arg(long, value_name = "PUBLIC_KEY", conflicts_with = "out")]
        public: Option<PublicKey>,
    },
    /// OpenSSL と同じ PEM の鍵を16進にする
    ///
    /// 秘密鍵は標準入力から PEM で読み、--out のファイルに書く。PKCS#8 の v1 のほかに、公開鍵だけが付いた v2 も読める。
    /// --public を付けると、標準入力から公開鍵の PEM を読み、標準出力に書く。
    FromPem {
        /// 秘密鍵（16進）を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH", required_unless_present = "public")]
        out: Option<PathBuf>,
        /// 秘密鍵の代わりに公開鍵の PEM を読む
        #[arg(long, conflicts_with = "out")]
        public: bool,
    },
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
        // `| head` などで読み手が先に終わったときは、出せるだけ出したので成功にする
        Ok(()) | Err(Failure::BrokenPipe) => ExitCode::SUCCESS,
        Err(Failure::Message(message)) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
        Err(Failure::Code(code)) => ExitCode::from(code),
    }
}

/// `run` が途中で終わった理由。
///
/// 標準出力が閉じられたときも、その場で `process::exit` せずに `main` まで戻す。
/// そうしないと途中の秘密鍵などが drop されず、メモリが0で上書きされない。
enum Failure {
    Message(String),
    BrokenPipe,
    /// 結果はもう出したので、この終了コードで終わる
    Code(u8),
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

/// `println!` と違い、標準出力に書けなければ panic せずに `Failure` を返す。
macro_rules! outln {
    ($($arg:tt)*) => {
        writeln!(io::stdout(), $($arg)*).map_err(|error| {
            if error.kind() == io::ErrorKind::BrokenPipe {
                Failure::BrokenPipe
            } else {
                Failure::Message(format!("標準出力に書けませんでした: {error}"))
            }
        })?
    };
}

// `outln!` を使うので、マクロより後に置く
mod cert;
mod harvesting;
mod legal;
mod node;
mod tx;

fn run(command: Command) -> Result<(), Failure> {
    match command {
        Command::Cert(command) => cert::run(command)?,
        Command::Harvesting(args) => harvesting::run(args)?,
        Command::Legal(command) => legal::run(command)?,
        Command::Node(command) => node::run(command)?,
        Command::Tx(command) => tx::run(command)?,
        Command::Key(KeyCommand::Address {
            public_key,
            network,
        }) => outln!("{}", Address::from_public_key(&public_key, network.into())),
        Command::Key(KeyCommand::Derive { account, network }) => {
            let mnemonic: Mnemonic = read_secret("ニーモニック", "alice.mnemonic")?;
            let seed = mnemonic.to_seed("").expect("an empty passphrase is valid");
            let network = NetworkIdentifier::from(network);
            let path = slip10::symbol_path(network, account);
            let key = ExtendedKey::from_seed(seed.as_bytes()).derive_path(&path);
            let public_key = PublicKey::from_private_key(&key.private_key());
            let path: String = path.iter().map(|index| format!("/{index}'")).collect();
            outln!("パス: m{path}");
            outln!("公開鍵: {public_key}");
            outln!(
                "アドレス: {}",
                Address::from_public_key(&public_key, network)
            );
        }
        Command::Key(KeyCommand::Generate { out }) => {
            let private_key = PrivateKey::generate()
                .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
            write_secret(&out, &private_key.to_hex())?;
            outln!("公開鍵: {}", PublicKey::from_private_key(&private_key));
        }
        Command::Key(KeyCommand::Mnemonic { out, words }) => {
            let word_count = WordCount::from(words);
            let mnemonic = Mnemonic::generate(word_count)
                .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
            write_secret(&out, &mnemonic.to_phrase())?;
            outln!(
                "{}語のニーモニックを {} に書きました",
                word_count.get(),
                out.display()
            );
        }
        Command::Key(KeyCommand::PublicKey) => {
            let private_key: PrivateKey = read_secret("秘密鍵", "alice.key")?;
            outln!("{}", PublicKey::from_private_key(&private_key));
        }
        Command::Key(KeyCommand::ToPem { out, public }) => match (out, public) {
            (_, Some(public_key)) => outln!("{}", key::public_key_to_pem(&public_key)),
            (Some(out), None) => {
                let private_key: PrivateKey = read_secret("秘密鍵", "alice.key")?;
                write_secret(&out, &key::private_key_to_pem(&private_key))?;
                outln!("公開鍵: {}", PublicKey::from_private_key(&private_key));
            }
            (None, None) => unreachable!("clap requires --out or --public"),
        },
        Command::Key(KeyCommand::FromPem { out, public }) => match out {
            _ if public => {
                let PublicKeyPem(public_key) = read_secret("公開鍵の PEM", "ca.pubkey.pem")?;
                outln!("{public_key}");
            }
            Some(out) => {
                let PrivateKeyPem(private_key) = read_secret("秘密鍵の PEM", "ca.key.pem")?;
                write_secret(&out, &private_key.to_hex())?;
                outln!("公開鍵: {}", PublicKey::from_private_key(&private_key));
            }
            None => unreachable!("clap requires --out or --public"),
        },
    }
    Ok(())
}

/// `read_secret` で秘密鍵の PEM を読むための包み。
struct PrivateKeyPem(PrivateKey);

impl FromStr for PrivateKeyPem {
    type Err = key::ParseKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        key::private_key_from_pem(text).map(Self)
    }
}

/// `read_secret` で公開鍵の PEM を読むための包み。公開鍵は秘密ではないが、PEM は複数行なので標準入力から読む。
struct PublicKeyPem(PublicKey);

impl FromStr for PublicKeyPem {
    type Err = key::ParseKeyError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        key::public_key_from_pem(text).map(Self)
    }
}

/// 標準入力から秘密鍵やニーモニックを読む。前後の空白や改行は無視する。
///
/// 引数で受け取るとシェルの履歴や `/proc/<pid>/cmdline` に残るので、標準入力だけから読む。
/// 端末からは、Unix では打った文字を画面に出さずに読む。Unix 以外では画面に出てしまうので、
/// リダイレクトかパイプで渡されたときだけ受け付ける。
fn read_secret<T>(name: &str, example: &str) -> Result<T, String>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let stdin = io::stdin();
    let echo_off = if stdin.is_terminal() {
        Some(EchoOff::new(&stdin, name, example)?)
    } else {
        None
    };
    let mut input =
        unbuffered(stdin).map_err(|error| format!("標準入力を開けませんでした: {error}"))?;
    let mut buffer = Zeroizing::new([0; 1024]);
    let mut length = 0;
    loop {
        if length == buffer.len() {
            return Err(format!("{name}にしては入力が長すぎます"));
        }
        match input.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("標準入力を読めませんでした: {error}")),
        }
    }
    if echo_off.is_some() {
        drop(echo_off);
        // 最後に打った改行も画面に出ていないので、次の出力が同じ行に続かないようにする
        eprintln!();
    }
    let text = str::from_utf8(&buffer[..length])
        .map_err(|_| format!("{name}に UTF-8 として読めないバイトが含まれています"))?;
    text.trim().parse().map_err(|error| format!("{error}"))
}

/// 端末から秘密を読むあいだ、打った文字を画面に出さないようにする。drop すると元に戻す。
///
/// ISIG も切って、Ctrl-C で落ちないようにする。落ちると、文字を出さないままの端末が残るためである。
/// Ctrl-C は ^C の文字として入るので、そのまま終えれば読めない入力として弾かれる。
#[cfg(unix)]
struct EchoOff {
    fd: RawFd,
    original: libc::termios,
}

#[cfg(unix)]
impl EchoOff {
    fn new(stdin: &io::Stdin, name: &str, _example: &str) -> Result<Self, String> {
        let fd = stdin.as_raw_fd();
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: fd は開いている標準入力で、tcgetattr は成功したときに original を埋める
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(format!(
                "端末の設定を読めませんでした: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: tcgetattr が成功したので埋まっている
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ISIG);
        // SAFETY: hidden は tcgetattr で読んだものを書き換えた、有効な termios
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(format!(
                "端末の設定を変えられませんでした: {}",
                io::Error::last_os_error()
            ));
        }
        eprintln!(
            "{name}を貼り付けて、改行してから Ctrl-D で終えてください。打った文字は画面に出ません（やめるときは、何も入れずに Ctrl-D）"
        );
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: original は new で tcgetattr が読んだ、有効な termios
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

/// Unix 以外では文字を出さずに読む方法を用意していないので、端末からは受け付けない。
#[cfg(not(unix))]
struct EchoOff;

#[cfg(not(unix))]
impl EchoOff {
    fn new(_stdin: &io::Stdin, name: &str, example: &str) -> Result<Self, String> {
        Err(format!(
            "{name}はリダイレクトかパイプで渡してください（例: < {example}）"
        ))
    }
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
