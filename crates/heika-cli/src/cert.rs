//! `heika cert`: ノードの TLS の証明書。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use clap::{Args, Subcommand};
use der::DateTime;
use heika_cert::certificate::{Certificate, Template};
use heika_cert::key;
use heika_core::key::{PrivateKey, PublicKey};

use crate::{Failure, read_secret};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
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
    },
}

#[derive(Args)]
pub struct SubjectArgs {
    /// RFC 4514 の DN（CN=node,O=example など）。OpenSSL の -subj（/O=example/CN=node）とは書き方も順番も違う
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
        } => {
            let subject = subject.check()?;
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
        } => {
            let ca = read_certificate(&ca_cert)?;
            let subject = subject.check()?;
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
                },
            )
            .map_err(|error| error.to_string())?;
            write_new(&out, &certificate.to_pem())?;
            describe(&certificate)?;
        }
    }
    Ok(())
}

impl SubjectArgs {
    /// OpenSSL の書き方で渡されたら、RFC 4514 の書き方を案内する。
    fn check(&self) -> Result<&str, String> {
        if self.subject.starts_with('/') {
            return Err(format!(
                "--subject は RFC 4514 の形（CN=node,O=example など）で書いてください。\
                 OpenSSL の -subj の形（{}）とは区切りが違い、順番も逆です",
                self.subject
            ));
        }
        Ok(&self.subject)
    }
}

fn read_certificate(path: &Path) -> Result<Certificate, String> {
    let pem = fs::read_to_string(path)
        .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
    Certificate::from_pem(&pem).map_err(|error| format!("{}: {error}", path.display()))
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
        "有効期間: {} から {} まで",
        format_time(certificate.not_before()),
        format_time(certificate.not_after())
    );
    outln!("公開鍵: {}", certificate.public_key());
    Ok(())
}

fn format_time(time: SystemTime) -> String {
    DateTime::from_system_time(time)
        .map_or_else(|_| "（表せない時刻）".to_owned(), |time| time.to_string())
}
