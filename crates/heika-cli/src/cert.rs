//! `heika cert`: ノードの TLS の証明書。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use clap::{Args, Subcommand, ValueEnum};
use der::DateTime;
use heika_cert::certificate::{
    Certificate, ParseCertificateError, Template, Version, check_catapult_chain,
};
use heika_cert::key;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_tls::{ClientCertificate, Identity};

use crate::{Failure, Network, read_secret};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// shoestring と symbol-bootstrap の既定値
const CA_DAYS: u32 = 7300;
const NODE_DAYS: u32 = 375;
/// shoestring と symbol-bootstrap がノードの証明書に使う長さ
const SERIAL_NUMBER_LENGTH: usize = 19;

#[derive(Subcommand)]
pub enum CertCommand {
    /// 標準入力から読んだ CA の秘密鍵（PEM か16進）で、自己署名の CA の証明書を発行する
    Ca {
        #[command(flatten)]
        subject: SubjectArgs,
        /// 証明書（PEM）を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        #[command(flatten)]
        validity: ValidityArgs,
        /// X.509 のバージョン。3 なら shoestring と同じ拡張を付ける
        #[arg(long, value_enum, default_value_t = X509Version::V3)]
        x509_version: X509Version,
    },
    /// 標準入力から読んだ CA の秘密鍵（PEM か16進）で、公開鍵にノードの証明書を発行する
    ///
    /// 同じ公開鍵に発行し直せば更新に、新しい公開鍵に発行すれば鍵の交換になる。
    Node {
        /// CA の証明書（PEM）。issuer にはこの証明書の subject を使う
        #[arg(long, value_name = "PATH")]
        ca_cert: PathBuf,
        /// 証明書を発行する公開鍵（16進）
        #[arg(long, value_name = "PUBLIC_KEY")]
        public_key: PublicKey,
        #[command(flatten)]
        subject: SubjectArgs,
        /// 証明書（PEM）を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        #[command(flatten)]
        validity: ValidityArgs,
        /// X.509 のバージョン。3 なら shoestring と同じ拡張を付ける
        #[arg(long, value_enum, default_value_t = X509Version::V3)]
        x509_version: X509Version,
    },
    /// 証明書の中身を出す
    ///
    /// node.full.crt.pem のように2枚つないだものなら、catapult がつなぐときの条件も確かめる。
    /// 自己署名の証明書は CA の証明書とみなし、その公開鍵のアドレスも出す。
    ///
    /// --connect を付けると、ファイルの代わりにノードが実際に出している証明書を調べる。
    /// こちらも名乗る必要があるので、--client-cert のチェーンと、標準入力から読んだその秘密鍵（PEM か16進）を使う。
    /// TLS のハンドシェイクだけをして、こちらの証明書が受け付けられたかも確かめる。
    /// 同じ IP から短いあいだに違う証明書でつなぎ直すと、ノードにしばらく弾かれることがある。
    Show {
        /// 証明書のファイル（PEM）。何枚つないであってもよい
        #[arg(required_unless_present = "connect", conflicts_with = "connect")]
        path: Option<PathBuf>,
        /// 調べるノード（ホスト:ポート）
        #[arg(long, value_name = "HOST:PORT", requires = "client_cert")]
        connect: Option<String>,
        /// --connect で名乗る証明書のチェーン（ノード、CA の順の PEM）
        #[arg(long, value_name = "PATH", requires = "connect")]
        client_cert: Option<PathBuf>,
        /// --connect で、ハンドシェイクのあと切られないか待つ秒数
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = 3,
            requires = "connect"
        )]
        wait: u64,
        #[arg(long, value_enum, default_value_t = Network::Mainnet)]
        network: Network,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum X509Version {
    #[value(name = "1")]
    V1,
    #[value(name = "3")]
    V3,
}

impl From<X509Version> for Version {
    fn from(version: X509Version) -> Self {
        match version {
            X509Version::V1 => Self::V1,
            X509Version::V3 => Self::V3,
        }
    }
}

#[derive(Args)]
pub struct SubjectArgs {
    /// DN。RFC 4514 の形（CN=node,O=example）か、OpenSSL の -subj の形（/O=example/CN=node）。2つは書く順番が逆
    #[arg(long, value_name = "DN")]
    subject: String,
}

#[derive(Args)]
pub struct ValidityArgs {
    /// 有効期間の始まり（2026-10-11T00:00:00Z の形）。省略すると今
    #[arg(long, value_name = "TIME")]
    not_before: Option<Timestamp>,
    /// 有効期間の日数。省略すると CA は7300日、ノードは375日
    #[arg(long, conflicts_with = "not_after")]
    days: Option<u32>,
    /// 有効期間の終わり（2026-10-11T00:00:00Z の形）
    #[arg(long, value_name = "TIME")]
    not_after: Option<Timestamp>,
}

impl ValidityArgs {
    fn resolve(&self, default_days: u32) -> (SystemTime, SystemTime) {
        let not_before = self
            .not_before
            .map_or_else(SystemTime::now, |Timestamp(time)| time);
        let not_after = self.not_after.map_or_else(
            || not_before + DAY * self.days.unwrap_or(default_days),
            |Timestamp(time)| time,
        );
        (not_before, not_after)
    }
}

#[derive(Clone, Copy)]
struct Timestamp(SystemTime);

impl FromStr for Timestamp {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        DateTime::from_str(text)
            .map(|time| Self(time.to_system_time()))
            .map_err(|_| "時刻は 2026-10-11T00:00:00Z の形で書いてください".to_owned())
    }
}

/// `read_secret` で秘密鍵を PEM でも16進でも読むための包み。
struct AnyPrivateKey(PrivateKey);

impl FromStr for AnyPrivateKey {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.starts_with("-----BEGIN") {
            key::private_key_from_pem(text).map_err(|error| error.to_string())
        } else {
            text.parse()
                .map_err(|error: heika_core::key::ParsePrivateKeyError| error.to_string())
        }
        .map(Self)
    }
}

pub fn run(command: CertCommand) -> Result<(), Failure> {
    match command {
        CertCommand::Ca {
            subject,
            out,
            validity,
            x509_version,
        } => {
            let subject = subject.subject.as_str();
            let AnyPrivateKey(ca_key) = read_secret("CA の秘密鍵", "ca.key.pem")?;
            let serial_number = serial_number()?;
            let (not_before, not_after) = validity.resolve(CA_DAYS);
            let certificate = Certificate::self_signed(
                &ca_key,
                &Template {
                    subject,
                    not_before,
                    not_after,
                    serial_number: &serial_number,
                    version: x509_version.into(),
                },
            )
            .map_err(|error| error.to_string())?;
            write_new(&out, &certificate.to_pem())?;
            describe(&certificate)?;
        }
        CertCommand::Node {
            ca_cert,
            public_key,
            subject,
            out,
            validity,
            x509_version,
        } => {
            let ca = read_certificate(&ca_cert)?;
            let subject = subject.subject.as_str();
            let AnyPrivateKey(ca_key) = read_secret("CA の秘密鍵", "ca.key.pem")?;
            let serial_number = serial_number()?;
            let (not_before, not_after) = validity.resolve(NODE_DAYS);
            let certificate = Certificate::issue(
                &ca,
                &ca_key,
                &public_key,
                &Template {
                    subject,
                    not_before,
                    not_after,
                    serial_number: &serial_number,
                    version: x509_version.into(),
                },
            )
            .map_err(|error| error.to_string())?;
            write_new(&out, &certificate.to_pem())?;
            describe(&certificate)?;
        }
        CertCommand::Show {
            path,
            connect,
            client_cert,
            wait,
            network,
        } => match (path, connect, client_cert) {
            (Some(path), _, _) => {
                let certificates = read_chain(&path)?;
                show_chain(
                    &certificates.into_iter().map(Ok).collect::<Vec<_>>(),
                    network,
                )?;
            }
            (None, Some(address), Some(client_cert)) => {
                let chain = read_chain(&client_cert)?;
                let AnyPrivateKey(key) = read_secret("ノードの秘密鍵", "node.key.pem")?;
                let identity = Identity::new(&chain, &key)
                    .map_err(|error| format!("{}: {error}", client_cert.display()))?;
                let inspection = heika_tls::inspect(
                    &address,
                    &identity,
                    CONNECT_TIMEOUT,
                    Duration::from_secs(wait),
                )
                .map_err(|error| format!("{address}: {error}"))?;
                outln!("接続先: {address}");
                outln!();
                let certificates: Vec<_> = inspection
                    .peer_certificates
                    .iter()
                    .map(|der| Certificate::from_der(der))
                    .collect();
                show_chain(&certificates, network)?;
                outln!();
                match inspection.client_certificate {
                    ClientCertificate::Kept => {
                        outln!(
                            "こちらの証明書: 受け付けられました（{wait} 秒のあいだ切られませんでした）"
                        )
                    }
                    ClientCertificate::Rejected(alert) => {
                        outln!("こちらの証明書: 弾かれました（TLS のアラート: {alert}）")
                    }
                    ClientCertificate::Closed => {
                        outln!("こちらの証明書: わかりません（アラートなしで切られました）")
                    }
                    ClientCertificate::DataReceived => {
                        outln!("こちらの証明書: 受け付けられたようです（相手から何か届きました）")
                    }
                }
            }
            _ => unreachable!("clap requires a path or --connect with --client-cert"),
        },
    }
    Ok(())
}

/// 証明書を1枚ずつ出し、2枚以上なら catapult の条件も出す。
fn show_chain(
    certificates: &[Result<Certificate, ParseCertificateError>],
    network: Network,
) -> Result<(), Failure> {
    for (index, certificate) in certificates.iter().enumerate() {
        if index > 0 {
            outln!();
        }
        outln!("{}枚目", index + 1);
        let certificate = match certificate {
            Ok(certificate) => certificate,
            Err(error) => {
                outln!("読めません: {error}");
                continue;
            }
        };
        outln!("バージョン: v{}", certificate.version());
        let serial_number: String = certificate
            .serial_number()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect();
        outln!("シリアル番号: {serial_number}");
        describe(certificate)?;
        if certificate.is_self_signed() {
            outln!(
                "CA の公開鍵のアドレス: {}",
                Address::from_public_key(certificate.public_key(), network.into())
            );
        }
    }
    if certificates.len() > 1 {
        outln!();
        match certificates.iter().cloned().collect::<Result<Vec<_>, _>>() {
            Err(_) => outln!("catapult の条件: 満たしていません（読めない証明書がある）"),
            Ok(certificates) => match check_catapult_chain(&certificates) {
                Ok(()) => outln!(
                    "catapult の条件: 満たしています（2枚で、2枚目が自己署名、1枚目が2枚目の鍵で署名されている）"
                ),
                Err(reason) => outln!("catapult の条件: 満たしていません（{reason}）"),
            },
        }
    }
    Ok(())
}

fn read_certificate(path: &Path) -> Result<Certificate, String> {
    let pem = fs::read_to_string(path)
        .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
    Certificate::from_pem(&pem).map_err(|error| format!("{}: {error}", path.display()))
}

fn read_chain(path: &Path) -> Result<Vec<Certificate>, String> {
    let pem = fs::read_to_string(path)
        .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
    Certificate::from_pem_chain(&pem).map_err(|error| format!("{}: {error}", path.display()))
}

fn serial_number() -> Result<[u8; SERIAL_NUMBER_LENGTH], String> {
    let mut serial_number = [0; SERIAL_NUMBER_LENGTH];
    getrandom::fill(&mut serial_number)
        .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
    Ok(serial_number)
}

/// 秘密ではないものを1行足して書く。すでにあるファイルは上書きしない。
fn write_new(path: &Path, contents: &str) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| writeln!(file, "{contents}"))
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}

fn describe(certificate: &Certificate) -> Result<(), Failure> {
    outln!("subject: {}", certificate.subject());
    outln!("issuer: {}", certificate.issuer());
    outln!(
        "有効期間: {} から {} まで（{}）",
        format_time(certificate.not_before()),
        format_time(certificate.not_after()),
        remaining(certificate, SystemTime::now())
    );
    outln!("公開鍵: {}", certificate.public_key());
    Ok(())
}

fn remaining(certificate: &Certificate, now: SystemTime) -> String {
    let days = |duration: Duration| duration.as_secs() / DAY.as_secs();
    if let Ok(until) = certificate.not_before().duration_since(now) {
        format!("まだ有効ではありません。あと {} 日で有効", days(until))
    } else if let Ok(since) = now.duration_since(certificate.not_after()) {
        format!("期限切れです。{} 日前に切れました", days(since))
    } else {
        let left = certificate
            .not_after()
            .duration_since(now)
            .unwrap_or_default();
        format!("あと {} 日", days(left))
    }
}

fn format_time(time: SystemTime) -> String {
    DateTime::from_system_time(time)
        .map_or_else(|_| "（表せない時刻）".to_owned(), |time| time.to_string())
}
