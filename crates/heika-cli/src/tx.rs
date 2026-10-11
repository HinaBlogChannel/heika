//! トランザクションを組んで、署名する。
//!
//! 組むことと署名することを分ける。組むのに要るのは公開されている情報だけで、
//! 秘密鍵は署名するときに標準入力から1つだけ読む。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use heika_core::key::PublicKey;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::signature::Signature;
use heika_transaction::{Aggregate, Body, EmbeddedTransaction, Transaction};

use heika_cert::certificate::Certificate;
use heika_tls::{ClientCertificate, Identity};

use crate::cert::{AnyPrivateKey, CONNECT_TIMEOUT, read_chain};
use crate::{Failure, Network, read_secret};

const HOUR: Duration = Duration::from_secs(60 * 60);
/// ネットワークの設定 maxTransactionLifetime。メインネットもテストネットも 6h
const MAX_TRANSACTION_LIFETIME_HOURS: u64 = 6;
/// catapult の `ionet::PacketType::Push_Transactions`
const PUSH_TRANSACTIONS: u32 = 9;

#[derive(Subcommand)]
pub enum TxCommand {
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
    /// 署名したトランザクションを、ノードと TLS でつないで送る
    ///
    /// 送る前に、ネットワーク、署名、期限を確かめる。名乗るのはノードの証明書で、ノードの秘密鍵は標準入力から読む。
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
    fn generation_hash_seed(self) -> GenerationHashSeed {
        match self {
            Self::Mainnet => GenerationHashSeed::MAINNET,
            Self::Testnet => GenerationHashSeed::TESTNET,
        }
    }

    /// ネットワークのエポックの始まり。catapult の設定では epochAdjustment と呼ばれる。
    fn epoch(self) -> SystemTime {
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
                return Err(format!("{} はすでに署名されています", unsigned.display()).into());
            }
            let AnyPrivateKey(private_key) = read_secret("秘密鍵", "main.key")?;
            let seed = network.generation_hash_seed();
            transaction
                .sign(&private_key, &seed)
                .map_err(|error| error.to_string())?;
            write_new(&out, &transaction.to_bytes())?;
            outln!("ハッシュ: {}", transaction.hash(&seed));
        }
        TxCommand::Announce {
            network,
            signed,
            connect,
            client_cert,
            wait,
        } => {
            let bytes = fs::read(&signed)
                .map_err(|error| format!("{} を読めませんでした: {error}", signed.display()))?;
            let transaction = Transaction::from_bytes(&bytes)
                .map_err(|error| format!("{}: {error}", signed.display()))?;
            if transaction.network != NetworkIdentifier::from(network) {
                return Err(format!(
                    "{} は --network と違うネットワークのトランザクションです",
                    signed.display()
                )
                .into());
            }
            if transaction.signature == Signature([0; 64]) {
                return Err(format!("{} はまだ署名されていません", signed.display()).into());
            }
            let seed = network.generation_hash_seed();
            if !transaction.verify(&seed) {
                return Err(format!("{} の署名が正しくありません", signed.display()).into());
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

/// ネットワークのエポックからのミリ秒。
fn network_milliseconds(network: Network, time: SystemTime) -> Result<u64, String> {
    let elapsed = time
        .duration_since(network.epoch())
        .map_err(|_| "時計がネットワークのエポックより前になっています".to_owned())?;
    u64::try_from(elapsed.as_millis()).map_err(|_| "時刻が大きすぎます".to_owned())
}

/// バイト列をそのまま書く。すでにあるファイルは上書きしない。
fn write_new(path: &Path, contents: &[u8]) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents))
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}
