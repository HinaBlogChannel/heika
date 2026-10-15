//! トランザクションを組んで、署名する。
//!
//! 組むことと署名することを分ける。組むのに要るのは公開されている情報だけで、
//! 秘密鍵は署名するときに標準入力から1つだけ読む。

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::future::ready;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use clap::{ArgGroup, Args, Subcommand};
use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body, find_inclusion};
use heika_transaction::{
    Aggregate, AggregateVersion, Body, Cosignature, EmbeddedTransaction, Location, Transaction,
    Transfer, UnresolvedAddress, UnresolvedMosaicId,
};

use heika_cert::certificate::Certificate;
use heika_tls::{ClientCertificate, Identity};

use crate::cert::{AnyPrivateKey, CONNECT_TIMEOUT, read_chain};
use crate::rest::{Rest, block_on};
use crate::wallet::WalletKeyArgs;
use crate::{Failure, Network, read_secret, show};

const HOUR: Duration = Duration::from_secs(60 * 60);
/// `--deadline-hours` の上限。引数を読むときにはネットワークがまだわからないので、どのネットワークの
/// maxTransactionLifetime も超えない値を定数で持つ
const MAX_TRANSACTION_LIFETIME_HOURS: u64 = 6;
/// catapult の `ionet::PacketType::Push_Transactions`
const PUSH_TRANSACTIONS: u32 = 9;
/// ネットワークの通貨（XYM）の可分性。メインネットもテストネットも 6
const XYM_DIVISIBILITY: usize = 6;

#[derive(Subcommand)]
pub enum TxCommand {
    /// トランザクションの中身を、署名する前に確かめられる形で出す
    ///
    /// ファイルは、トランザクションのバイト列そのものか、それを16進で書いたテキスト。`-` なら標準入力から読む。
    /// 秘密鍵は使わない。署名があれば、それが正しいかも確かめる。
    Show {
        /// 出すトランザクションのファイル
        transaction: PathBuf,
        /// 表示と同じ項目を JSON で出す
        #[arg(long)]
        json: bool,
    },
    /// 署名していないトランザクションに、標準入力から読んだ秘密鍵か、キーストアのアカウントの鍵で署名する
    Sign {
        #[arg(long, value_enum)]
        network: Network,
        /// 署名するトランザクションのファイル
        unsigned: PathBuf,
        /// 署名したトランザクションを書くファイル（すでにあれば上書きしない）
        #[arg(long)]
        out: PathBuf,
        #[command(flatten)]
        key: WalletKeyArgs,
    },
    /// XYM を送る、署名していない送金を組んで書く
    ///
    /// 量は XYM の単位で書く（例: 1.5）。メッセージは暗号化しない平文なので、チェーンの上で誰でも読める。
    Transfer {
        #[arg(long, value_enum)]
        network: Network,
        /// 送る人の公開鍵
        #[arg(long)]
        signer: PublicKey,
        /// 宛先のアドレス
        #[arg(long)]
        to: Address,
        /// 送る XYM の量（例: 1.5）。小数点の下は6桁まで
        #[arg(long, value_parser = parse_xym)]
        amount: u64,
        /// 平文のメッセージ。チェーンの上で誰でも読める
        #[arg(long)]
        message: Option<String>,
        #[command(flatten)]
        unsigned: Unsigned,
    },
    /// 署名したアグリゲートに、標準入力から読んだ秘密鍵か、キーストアのアカウントの鍵で連署する
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
        #[command(flatten)]
        key: WalletKeyArgs,
    },
    /// 署名したトランザクションを、REST に渡すか、ノードと TLS でつないで送る
    ///
    /// 送る前に、ネットワーク、署名と連署、期限を確かめる。
    /// `--rest` なら REST に渡す。`--connect` ならノードに直接つなぎ、名乗るのはノードの証明書で、ノードの秘密鍵は標準入力から読む。
    /// どちらも受け取ったことしか返さないので、ブロックに入ったかは heika tx status で確かめる。
    #[command(group(ArgGroup::new("destination").required(true)))]
    Announce {
        #[arg(long, value_enum)]
        network: Network,
        /// 送る、署名したトランザクションのファイル
        signed: PathBuf,
        /// 渡す REST（例: https://symbol.example:3001）
        #[arg(long, value_name = "URL", group = "destination")]
        rest: Option<String>,
        /// 送り先のノード
        #[arg(
            long,
            value_name = "HOST:PORT",
            group = "destination",
            requires = "client_cert"
        )]
        connect: Option<String>,
        /// 名乗る証明書のチェーン（ノード、CA の順の PEM）。`--connect` のときに使う
        #[arg(long, value_name = "PATH", requires = "connect")]
        client_cert: Option<PathBuf>,
        /// `--connect` で送ったあと、切られないか待つ秒数
        #[arg(long, default_value_t = 3)]
        wait: u64,
    },
    /// 送ったトランザクションがブロックに入ったかを、REST に聞いて確かめる
    ///
    /// 入っていれば、ブロックの署名と StateHash、トランザクションからブロックの TransactionsHash への経路まで確かめる。
    /// 見つからなくても、入っていないことは確かめられない。期限を過ぎていれば、もう入ることはない。
    Status {
        #[arg(long, value_enum)]
        network: Network,
        /// 送った、署名したトランザクションのファイル
        signed: PathBuf,
        /// 問い合わせる REST（例: https://symbol.example:3001）
        #[arg(long, value_name = "URL")]
        rest: String,
    },
}

/// 署名していないトランザクションを組んで書くコマンドに共通の引数。
#[derive(Args)]
pub struct Unsigned {
    /// 手数料は、トランザクションのバイト数にこれを掛けたもの
    #[arg(long, default_value_t = 100)]
    fee_multiplier: u32,
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
        self.write_body(network, signer, Body::AggregateComplete(aggregate))
    }

    /// 本体を1つ、アグリゲートに入れずに、手数料と期限を付けて書く。ノードで弾かれるものは書かない
    pub fn write_body(
        &self,
        network: Network,
        signer: PublicKey,
        body: Body,
    ) -> Result<(), Failure> {
        let deadline = SystemTime::now() + self.deadline_hours as u32 * HOUR;
        let mut transaction = Transaction::new(
            signer,
            NetworkIdentifier::from(network),
            0,
            network_milliseconds(network, deadline)?,
            body,
        );
        let size = transaction.size();
        transaction.fee = transaction.fee_for(self.fee_multiplier, 0);
        check_sendable(&self.out, &transaction, network)?;
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

pub fn run(command: TxCommand) -> Result<(), Failure> {
    match command {
        TxCommand::Show { transaction, json } => {
            let bytes = read_transaction(&transaction)?;
            let transaction = Transaction::from_bytes(&bytes)
                .map_err(|error| format!("{}: {error}", transaction.display()))?;
            let description = show::describe(&transaction, SystemTime::now());
            if json {
                outln!("{}", description.to_json().render().trim_end());
            } else {
                outln!("{}", description.render().trim_end());
                show_missing_cosigners(&transaction)?;
            }
        }
        TxCommand::Sign {
            network,
            unsigned,
            out,
            key,
        } => {
            let bytes = fs::read(&unsigned)
                .map_err(|error| format!("{} を読めませんでした: {error}", unsigned.display()))?;
            let mut transaction = Transaction::from_bytes(&bytes)
                .map_err(|error| format!("{}: {error}", unsigned.display()))?;
            check_sendable(&unsigned, &transaction, network)?;
            if transaction.signature != Signature([0; 64]) {
                return Err(format!(
                    "{} はすでに署名されています。連署するなら heika tx cosign を使ってください",
                    unsigned.display()
                )
                .into());
            }
            let private_key = key.private_key(network, "秘密鍵", "main.key")?;
            let seed = network.parameters().generation_hash_seed;
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
            key,
        } => {
            let (_, mut transaction) = read_signed(&signed, network)?;
            if !matches!(transaction.body, Body::AggregateComplete(_)) {
                return Err(format!(
                    "{} は AggregateComplete ではないので連署できません",
                    signed.display()
                )
                .into());
            }
            let max_cosignatures = network.parameters().max_cosignatures_per_aggregate;
            if cosignatures(&transaction).len() + 1 >= max_cosignatures {
                return Err(format!(
                    "{} はもう署名と連署が {max_cosignatures} 件あります",
                    signed.display()
                )
                .into());
            }
            let private_key = key.private_key(network, "秘密鍵", "cosigner.key")?;
            let cosigner = PublicKey::from_private_key(&private_key);
            let seed = network.parameters().generation_hash_seed;
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
        TxCommand::Transfer {
            network,
            signer,
            to,
            amount,
            message,
            unsigned,
        } => {
            if to.network() != NetworkIdentifier::from(network) {
                return Err("宛先は --network と違うネットワークのアドレスです"
                    .to_owned()
                    .into());
            }
            let currency = network.parameters().currency_mosaic_id;
            // 平文のメッセージは、頭に 0 のバイトを付ける
            let message = message.map_or_else(Vec::new, |text| {
                let mut bytes = vec![0];
                bytes.extend_from_slice(text.as_bytes());
                bytes
            });
            let body = Transfer::new(
                UnresolvedAddress::from(to),
                BTreeMap::from([(UnresolvedMosaicId(currency), amount)]),
                message,
            )
            .map_err(|error| error.to_string())?;
            unsigned.write_body(network, signer, Body::Transfer(body))?;
        }
        TxCommand::Announce {
            network,
            signed,
            rest,
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
            let seed = network.parameters().generation_hash_seed;
            if !transaction.verify_cosignatures(&seed) {
                return Err(format!("{} の連署が正しくありません", signed.display()).into());
            }
            let now = SystemTime::now();
            if transaction.deadline <= network_milliseconds(network, now)? {
                return Err(format!("{} は期限が切れています", signed.display()).into());
            }
            let lifetime = network.parameters().max_transaction_lifetime;
            let latest = now + lifetime;
            if transaction.deadline > network_milliseconds(network, latest)? {
                return Err(format!(
                    "{} は期限が {} 時間より先です",
                    signed.display(),
                    lifetime.as_secs() / 3600
                )
                .into());
            }

            if let Some(url) = rest {
                let rest = Rest::new(&url);
                rest.put(ANNOUNCE_PATH, &announce_body(&transaction))?;
                outln!("ハッシュ: {}", transaction.hash(&seed));
                show_missing_cosigners(&transaction)?;
                outln!("{} に渡しました", rest.origin());
                outln!(
                    "REST は受け取ったことしか返さないので、ブロックに入ったかは heika tx status で確かめてください"
                );
                return Ok(());
            }
            let (Some(connect), Some(client_cert)) = (connect, client_cert) else {
                unreachable!("clap requires --rest or --connect with --client-cert");
            };
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
        TxCommand::Status {
            network,
            signed,
            rest,
        } => {
            let (_, transaction) = read_signed(&signed, network)?;
            let seed = network.parameters().generation_hash_seed;
            let rest = Rest::new(&rest);
            let found = block_on(find_inclusion(&transaction, &seed, |path| {
                ready(rest.get(&path))
            }))
            .map_err(|error| error.to_string())?;
            outln!("ハッシュ: {}", transaction.hash(&seed));
            match found {
                Some(inclusion) => {
                    let block = &inclusion.block;
                    let time = network
                        .parameters()
                        .time_of(heika_core::network::NetworkTimestamp(block.timestamp))
                        .map_or_else(
                            || format!("エポックから {} ミリ秒", block.timestamp),
                            show::utc,
                        );
                    outln!("ブロック #{} に入りました（{time}）", block.height);
                    outln!("ブロックのハッシュ: {}", block.hash());
                    outln!();
                    outln!("確かめたこと:");
                    outln!("  ブロックの署名と、9本の根から求めた StateHash");
                    outln!(
                        "  このトランザクションから、ブロックの TransactionsHash へ経路でつながること"
                    );
                    outln!("信じていること:");
                    outln!(
                        "  このブロックが正しいチェーンのものであること（{} を信じています）",
                        rest.origin()
                    );
                }
                None => {
                    outln!(
                        "{} には、ブロックに入ったものとして見えていません",
                        rest.origin()
                    );
                    let now = network_milliseconds(network, SystemTime::now())?;
                    if transaction.deadline <= now {
                        outln!("期限を過ぎているので、これから入ることはありません");
                    } else {
                        let minutes = (transaction.deadline - now).div_ceil(60_000);
                        outln!(
                            "期限まであと {minutes} 分です。それまでは、これから入ることがあります"
                        );
                        // 早く知るための目安。REST が言っているだけで、確かめたものではない
                        if let Ok(Some(body)) =
                            rest.get(&TransactionStatus::path(&transaction, &seed))
                            && let Ok(status) = TransactionStatus::from_slice(&body)
                        {
                            outln!(
                                "REST によると: {}{}（確かめたものではありません）",
                                status.group,
                                status
                                    .code
                                    .map(|code| format!(" {code}"))
                                    .unwrap_or_default()
                            );
                        }
                    }
                }
            }
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

/// 署名や送信に進めるかを確かめる。`--network` と同じネットワークで、今のネットワークに送れる形のもの。
/// アグリゲートのバージョン 3 より前は、チェーンにあるものを読むためだけに扱う。
fn check_sendable(path: &Path, transaction: &Transaction, network: Network) -> Result<(), String> {
    if transaction.network != NetworkIdentifier::from(network) {
        return Err(format!(
            "{} は --network と違うネットワークのトランザクションです",
            path.display()
        ));
    }
    if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) = &transaction.body
        && aggregate.version() != AggregateVersion::V3
    {
        return Err(format!(
            "{} は古いアグリゲート（バージョン {}）なので、今のネットワークには送れません",
            path.display(),
            aggregate.version().number()
        ));
    }
    let problems = transaction.validate(network.parameters());
    if !problems.is_empty() {
        let mut message = format!("{} はノードで弾かれます", path.display());
        for problem in problems {
            message.push_str("\n  ");
            if let Location::Embedded(index) = problem.location {
                message.push_str(&format!("中の {} 件目: ", index + 1));
            }
            message.push_str(&show::describe_failure(&problem.failure));
        }
        return Err(message);
    }
    Ok(())
}

/// 署名したトランザクションを読み、ネットワークと署名を確かめる。読んだバイト列も返す。
fn read_signed(path: &Path, network: Network) -> Result<(Vec<u8>, Transaction), String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("{} を読めませんでした: {error}", path.display()))?;
    let transaction =
        Transaction::from_bytes(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    check_sendable(path, &transaction, network)?;
    if transaction.signature == Signature([0; 64]) {
        return Err(format!(
            "{} はまだ署名されていません。先に heika tx sign で署名してください",
            path.display()
        ));
    }
    if !transaction.verify(&network.parameters().generation_hash_seed) {
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

/// XYM の量（`1.5` など）を、いちばん小さい単位の数にする
fn parse_xym(text: &str) -> Result<u64, String> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) || text.ends_with('.') {
        return Err("1.5 のように、数字と小数点で書いてください".to_owned());
    }
    if fraction.len() > XYM_DIVISIBILITY {
        return Err(format!("小数点の下は {XYM_DIVISIBILITY} 桁までです"));
    }
    let scaled = format!("{whole}{fraction:0<XYM_DIVISIBILITY$}");
    scaled.parse().map_err(|_| "量が大きすぎます".to_owned())
}

/// ネットワークのエポックからのミリ秒。
fn network_milliseconds(network: Network, time: SystemTime) -> Result<u64, String> {
    network
        .parameters()
        .timestamp_at(time)
        .map(|timestamp| timestamp.0)
        .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
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
    fn reads_xym_amounts_in_the_smallest_unit() {
        assert_eq!(parse_xym("1.5"), Ok(1_500_000));
        assert_eq!(parse_xym("0.000001"), Ok(1));
        assert_eq!(parse_xym("12"), Ok(12_000_000));
        assert_eq!(parse_xym("0"), Ok(0));
        for wrong in [
            "",
            ".5",
            "1.",
            "1.2.3",
            "-1",
            "1,000",
            " 1",
            "1e3",
            "0.0000001",
        ] {
            assert!(parse_xym(wrong).is_err(), "{wrong}");
        }
        assert!(parse_xym("18446744073709.551616").is_err());
    }

    #[test]
    fn the_deadline_limit_fits_every_network() {
        for network in [Network::Mainnet, Network::Testnet] {
            assert!(
                MAX_TRANSACTION_LIFETIME_HOURS as u32 * HOUR
                    <= network.parameters().max_transaction_lifetime
            );
        }
    }

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
