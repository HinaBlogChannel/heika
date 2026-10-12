//! トランザクションを組んで、署名する。
//!
//! 組むことと署名することを分ける。組むのに要るのは公開されている情報だけで、
//! 秘密鍵は署名するときに標準入力から1つだけ読む。

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use heika_core::key::PublicKey;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::signature::Signature;
use heika_transaction::{Aggregate, Body, Cosignature, EmbeddedTransaction, Transaction};

use heika_cert::certificate::Certificate;
use heika_tls::{ClientCertificate, Identity};

use crate::cert::{AnyPrivateKey, CONNECT_TIMEOUT, read_chain};
use crate::{Failure, Network, read_secret, show};

const HOUR: Duration = Duration::from_secs(60 * 60);
/// ネットワークの設定 maxTransactionLifetime。メインネットもテストネットも 6h
const MAX_TRANSACTION_LIFETIME_HOURS: u64 = 6;
/// ネットワークの設定 maxCosignaturesPerAggregate。外側の署名も数える。メインネットもテストネットも 25
const MAX_COSIGNATURES_PER_AGGREGATE: usize = 25;
/// catapult の `ionet::PacketType::Push_Transactions`
const PUSH_TRANSACTIONS: u32 = 9;

#[derive(Subcommand)]
pub enum TxCommand {
    /// トランザクションの中身を、署名する前に確かめられる形で出す
    ///
    /// ファイルは、トランザクションのバイト列そのものか、それを16進で書いたテキスト。`-` なら標準入力から読む。
    /// 秘密鍵は使わない。署名があれば、それが正しいかも確かめる。
    Show {
        /// 出すトランザクションのファイル
        transaction: PathBuf,
    },
    /// 署名していないトランザクションに、標準入力から読んだ秘密鍵で署名する
    Sign {
        #[arg(long, value_enum)]
        network: Network,
        /// 署名するトランザクションのファイル
        unsigned: PathBuf,
        /// 署名したトランザクションを書くファイル（すでにあれば上書きしない）
        #[arg(long)]
        out: PathBuf,
    },
    /// 署名したアグリゲートに、標準入力から読んだ秘密鍵で連署する
    ///
    /// 連署するのは外側の署名を含むハッシュなので、先に heika tx sign で署名しておく。
    /// AggregateComplete だけを扱う。
    Cosign {
        #[arg(long, value_enum)]
        network: Network,
        /// 連署する、署名したトランザクションのファイル
        signed: PathBuf,
        /// 連署を足したトランザクションを書くファイル（すでにあれば上書きしない）
        #[arg(long)]
        out: PathBuf,
    },
    /// 署名したトランザクションを、ノードと TLS でつないで送る
    ///
    /// 送る前に、ネットワーク、署名と連署、期限を確かめる。名乗るのはノードの証明書で、ノードの秘密鍵は標準入力から読む。
    /// ノードは受け取ったことを返さないので、ブロックに入ったかは、表示するハッシュで別に確かめる。
    Announce {
        #[arg(long, value_enum)]
        network: Network,
        /// 送る、署名したトランザクションのファイル
        signed: PathBuf,
        /// 送り先のノード
        #[arg(long, value_name = "HOST:PORT")]
        connect: String,
        /// 名乗る証明書のチェーン（ノード、CA の順の PEM）
        #[arg(long, value_name = "PATH")]
        client_cert: PathBuf,
        /// 送ったあと、切られないか待つ秒数
        #[arg(long, default_value_t = 3)]
        wait: u64,
    },
}

/// 署名していないトランザクションを組んで書くコマンドに共通の引数。
#[derive(Args)]
pub struct Unsigned {
    /// 手数料は、トランザクションのバイト数にこれを掛けたもの
    #[arg(long, default_value_t = 100)]
    fee_multiplier: u64,
    /// 期限を今から何時間後にするか。ネットワークの設定 maxTransactionLifetime より先にはできない
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=MAX_TRANSACTION_LIFETIME_HOURS))]
    deadline_hours: u64,
    /// 署名していないトランザクションを書くファイル（すでにあれば上書きしない）
    #[arg(long)]
    out: PathBuf,
}

impl Unsigned {
    /// 本体をすべて signer の名前で1つの AggregateComplete に入れ、手数料と期限を付けて書く。
    pub fn write(
        &self,
        network: Network,
        signer: PublicKey,
        bodies: Vec<Body>,
    ) -> Result<(), Failure> {
        let identifier = NetworkIdentifier::from(network);
        let transactions = bodies
            .into_iter()
            .map(|body| EmbeddedTransaction::new(signer, identifier, body))
            .collect();
        let aggregate = Aggregate::new(transactions).expect("no aggregate is nested");

        let deadline = SystemTime::now() + self.deadline_hours as u32 * HOUR;
        let mut transaction = Transaction::new(
            signer,
            identifier,
            0,
            network_milliseconds(network, deadline)?,
            Body::AggregateComplete(aggregate),
        );
        let size = transaction.to_bytes().len() as u64;
        transaction.fee = size
            .checked_mul(self.fee_multiplier)
            .ok_or_else(|| "--fee-multiplier が大きすぎます".to_owned())?;
        write_new(&self.out, &transaction.to_bytes())?;

        outln!(
            "手数料: {} ({size} バイト × {})",
            transaction.fee,
            self.fee_multiplier
        );
        outln!("期限: {} 時間後", self.deadline_hours);
        Ok(())
    }
}

impl Network {
    pub(crate) fn generation_hash_seed(self) -> GenerationHashSeed {
        match self {
            Self::Mainnet => GenerationHashSeed::MAINNET,
            Self::Testnet => GenerationHashSeed::TESTNET,
        }
    }

    /// ネットワークのエポックの始まり。catapult の設定では epochAdjustment と呼ばれる。
    pub(crate) fn epoch(self) -> SystemTime {
        let seconds = match self {
            // 2021-03-16T00:06:25Z
            Self::Mainnet => 1_615_853_185,
            // 2022-10-31T21:07:47Z
            Self::Testnet => 1_667_250_467,
        };
        UNIX_EPOCH + Duration::from_secs(seconds)
    }
}

pub fn run(command: TxCommand) -> Result<(), Failure> {
    match command {
        TxCommand::Show { transaction } => {
            let bytes = read_transaction(&transaction)?;
            let transaction = Transaction::from_bytes(&bytes)
                .map_err(|error| format!("{}: {error}", transaction.display()))?;
            let description = show::describe(&transaction, SystemTime::now());
            outln!("{}", description.render().trim_end());
            show_missing_cosigners(&transaction)?;
        }
        TxCommand::Sign {
            network,
            unsigned,
            out,
        } => {
            let bytes = fs::read(&unsigned)
                .map_err(|error| format!("{} を読めませんでした: {error}", unsigned.display()))?;
            let mut transaction = Transaction::from_bytes(&bytes)
                .map_err(|error| format!("{}: {error}", unsigned.display()))?;
            if transaction.network != NetworkIdentifier::from(network) {
                return Err(format!(
                    "{} は --network と違うネットワークのトランザクションです",
                    unsigned.display()
                )
                .into());
            }
            if transaction.signature != Signature([0; 64]) {
                return Err(format!(
                    "{} はすでに署名されています。連署するなら heika tx cosign を使ってください",
                    unsigned.display()
                )
                .into());
            }
            let AnyPrivateKey(private_key) = read_secret("秘密鍵", "main.key")?;
            let seed = network.generation_hash_seed();
            transaction
                .sign(&private_key, &seed)
                .map_err(|error| error.to_string())?;
            write_new(&out, &transaction.to_bytes())?;
            // 何に署名したかが残るように、中身を出す。ハッシュも中に入っている
            let description = show::describe(&transaction, SystemTime::now());
            outln!("{}", description.render().trim_end());
            show_missing_cosigners(&transaction)?;
        }
        TxCommand::Cosign {
            network,
            signed,
            out,
        } => {
            let (_, mut transaction) = read_signed(&signed, network)?;
            if !matches!(transaction.body, Body::AggregateComplete(_)) {
                return Err(format!(
                    "{} は AggregateComplete ではないので連署できません",
                    signed.display()
                )
                .into());
            }
            if cosignatures(&transaction).len() + 1 >= MAX_COSIGNATURES_PER_AGGREGATE {
                return Err(format!(
                    "{} はもう署名と連署が {MAX_COSIGNATURES_PER_AGGREGATE} 件あります",
                    signed.display()
                )
                .into());
            }
            let AnyPrivateKey(private_key) = read_secret("秘密鍵", "cosigner.key")?;
            let cosigner = PublicKey::from_private_key(&private_key);
            let seed = network.generation_hash_seed();
            transaction
                .cosign(&private_key, &seed)
                .map_err(|error| error.to_string())?;
            drop(private_key);
            write_new(&out, &transaction.to_bytes())?;
            outln!("連署した公開鍵: {cosigner}");
            if !embedded_signers(&transaction).contains(&cosigner) {
                outln!(
                    "注意: 中のトランザクションの署名者ではありません。マルチシグの連署者でなければ、ノードで弾かれます"
                );
            }
            outln!("ハッシュ: {}", transaction.hash(&seed));
            show_missing_cosigners(&transaction)?;
        }
        TxCommand::Announce {
            network,
            signed,
            connect,
            client_cert,
            wait,
        } => {
            let (bytes, transaction) = read_signed(&signed, network)?;
            if matches!(transaction.body, Body::AggregateBonded(_)) {
                return Err(
                    format!("{} は AggregateBonded なので送れません", signed.display()).into(),
                );
            }
            let seed = network.generation_hash_seed();
            if !transaction.verify_cosignatures(&seed) {
                return Err(format!("{} の連署が正しくありません", signed.display()).into());
            }
            let now = SystemTime::now();
            if transaction.deadline <= network_milliseconds(network, now)? {
                return Err(format!("{} は期限が切れています", signed.display()).into());
            }
            let latest = now + MAX_TRANSACTION_LIFETIME_HOURS as u32 * HOUR;
            if transaction.deadline > network_milliseconds(network, latest)? {
                return Err(format!(
                    "{} は期限が {MAX_TRANSACTION_LIFETIME_HOURS} 時間より先です",
                    signed.display()
                )
                .into());
            }

            let chain = read_chain(&client_cert)?;
            let AnyPrivateKey(key) = read_secret("ノードの秘密鍵", "node.key.pem")?;
            let identity = Identity::new(&chain, &key)
                .map_err(|error| format!("{}: {error}", client_cert.display()))?;
            drop(key);
            let inspection = heika_tls::send(
                &connect,
                &identity,
                PUSH_TRANSACTIONS,
                &bytes,
                CONNECT_TIMEOUT,
                Duration::from_secs(wait),
            )
            .map_err(|error| format!("{connect}: {error}"))?;
            if let Some(Ok(ca)) = inspection
                .peer_certificates
                .get(1)
                .map(|der| Certificate::from_der(der))
            {
                outln!("送り先のノードの CA の公開鍵: {}", ca.public_key());
            }
            outln!("ハッシュ: {}", transaction.hash(&seed));
            show_missing_cosigners(&transaction)?;
            match inspection.client_certificate {
                ClientCertificate::Kept => {
                    outln!("送りました（{wait} 秒のあいだ切られませんでした）")
                }
                ClientCertificate::DataReceived => {
                    outln!("送りました（相手から何か届きました）")
                }
                ClientCertificate::Closed => {
                    outln!("送りましたが、アラートなしで切られたので、届いたかはわかりません")
                }
                ClientCertificate::Rejected(alert) => {
                    return Err(format!(
                        "こちらの証明書が弾かれたので、送れていません（TLS のアラート: {alert}）"
                    )
                    .into());
                }
            }
            outln!(
                "ノードは受け取ったことを返さないので、ブロックに入ったかはハッシュで確かめてください"
            );
        }
    }
    Ok(())
}

/// トランザクションのファイルを読む。中身が16進のテキストなら、バイト列に直す。`-` なら標準入力から読む
fn read_transaction(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = if path == Path::new("-") {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("標準入力を読めませんでした: {error}"))?;
        bytes
    } else {
        fs::read(path).map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?
    };
    Ok(from_hex_text(bytes))
}

/// 空白を除くと16進の文字だけなら、バイト列に直す。そうでなければそのまま返す。
/// バイト列そのものなら、先頭のサイズの上位のバイトが0なので、16進の文字だけにはならない。
fn from_hex_text(bytes: Vec<u8>) -> Vec<u8> {
    let text: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !text.is_empty() && text.len().is_multiple_of(2) && text.iter().all(u8::is_ascii_hexdigit) {
        return text
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16)
                    .expect("hex digits")
            })
            .collect();
    }
    bytes
}

/// 署名したトランザクションを読み、ネットワークと署名を確かめる。読んだバイト列も返す。
fn read_signed(path: &Path, network: Network) -> Result<(Vec<u8>, Transaction), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
    let transaction =
        Transaction::from_bytes(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    if transaction.network != NetworkIdentifier::from(network) {
        return Err(format!(
            "{} は --network と違うネットワークのトランザクションです",
            path.display()
        ));
    }
    if transaction.signature == Signature([0; 64]) {
        return Err(format!(
            "{} はまだ署名されていません。先に heika tx sign で署名してください",
            path.display()
        ));
    }
    if !transaction.verify(&network.generation_hash_seed()) {
        return Err(format!("{} の署名が正しくありません", path.display()));
    }
    Ok((bytes, transaction))
}

fn cosignatures(transaction: &Transaction) -> &[Cosignature] {
    match &transaction.body {
        Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
            aggregate.cosignatures()
        }
        _ => &[],
    }
}

/// 中のトランザクションの署名者。重なりは除き、出てきた順に並べる。
fn embedded_signers(transaction: &Transaction) -> Vec<PublicKey> {
    let mut signers = Vec::new();
    if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) = &transaction.body
    {
        for embedded in aggregate.transactions() {
            if !signers.contains(&embedded.signer_public_key) {
                signers.push(embedded.signer_public_key);
            }
        }
    }
    signers
}

/// 中のトランザクションの署名者のうち、署名も連署もしていない公開鍵を出す。
/// マルチシグのアカウントなら、代わりにその連署者が連署するので、足りないとは限らない。
fn show_missing_cosigners(transaction: &Transaction) -> Result<(), Failure> {
    let cosignatures = cosignatures(transaction);
    for public_key in embedded_signers(transaction) {
        if public_key == transaction.signer_public_key
            || cosignatures
                .iter()
                .any(|cosignature| cosignature.signer_public_key == public_key)
        {
            continue;
        }
        outln!("まだ連署していない、中のトランザクションの署名者: {public_key}");
    }
    Ok(())
}

/// ネットワークのエポックからのミリ秒。
fn network_milliseconds(network: Network, time: SystemTime) -> Result<u64, String> {
    let elapsed = time
        .duration_since(network.epoch())
        .map_err(|_| "時計がネットワークのエポックより前になっています".to_owned())?;
    u64::try_from(elapsed.as_millis()).map_err(|_| "時刻が大きすぎます".to_owned())
}

/// バイト列をそのまま書く。すでにあるファイルは上書きしない。
pub fn write_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents))
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hex_text_or_raw_bytes() {
        assert_eq!(from_hex_text(b"A1b2\n c3\n".to_vec()), [0xA1, 0xB2, 0xC3]);
        // 先頭のサイズの上位のバイトが0なので、バイト列そのものは16進の文字だけにはならない
        let raw = vec![0xA1, 0, 0, 0, 0x41];
        assert_eq!(from_hex_text(raw.clone()), raw);
        assert_eq!(from_hex_text(b"ABC".to_vec()), b"ABC");
        assert_eq!(from_hex_text(Vec::new()), Vec::<u8>::new());
    }
}
