//! トランザクションを組んで、署名する。
//!
//! 組むことと署名することを分ける。組むのに要るのは公開されている情報だけで、
//! 秘密鍵は署名するときに標準入力から1つだけ読む。

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::signature::Signature;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, KeyLink, LinkAction, Transaction, Transfer,
};
use heika_wallet::harvest_request::{self, HarvesterKeys};

use crate::cert::AnyPrivateKey;
use crate::{Failure, Network, read_secret};

const HOUR: Duration = Duration::from_secs(60 * 60);

#[derive(Subcommand)]
pub enum TxCommand {
    /// ハーベストを委任する、署名していないトランザクションを書く
    ///
    /// リモートアカウントと VRF の鍵をその場で作り、古いリンクの解除、新しいリンク、
    /// 委任の要求を1つのアグリゲートにまとめる。作った秘密鍵は委任の要求に暗号化して入れるだけで、
    /// どこにも保存しない。前の委任先が知っている鍵を使い回さないためである。
    Delegate {
        #[arg(long, value_enum)]
        network: Network,
        /// メインアカウントの公開鍵
        #[arg(long)]
        signer: PublicKey,
        /// 委任先のノードの公開鍵（ノードの node.key.pem の公開鍵）
        #[arg(long)]
        node: PublicKey,
        /// いま紐づいているリモートアカウントの公開鍵。省略すると、紐づいていないものとして扱う
        #[arg(long, value_name = "PUBLIC_KEY")]
        unlink_remote: Option<PublicKey>,
        /// いま紐づいている VRF の公開鍵。省略すると、紐づいていないものとして扱う
        #[arg(long, value_name = "PUBLIC_KEY")]
        unlink_vrf: Option<PublicKey>,
        /// いま紐づいているノードの公開鍵。省略すると、紐づいていないものとして扱う
        #[arg(long, value_name = "PUBLIC_KEY")]
        unlink_node: Option<PublicKey>,
        /// 手数料は、トランザクションのバイト数にこれを掛けたもの
        #[arg(long, default_value_t = 100)]
        fee_multiplier: u64,
        /// 期限を今から何時間後にするか。ネットワークの設定 maxTransactionLifetime（メインネットもテストネットも 6h）より先にはできない
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=6))]
        deadline_hours: u64,
        /// 署名していないトランザクションを書くファイル（すでにあれば上書きしない）
        #[arg(long)]
        out: PathBuf,
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
        TxCommand::Delegate {
            network,
            signer,
            node,
            unlink_remote,
            unlink_vrf,
            unlink_node,
            fee_multiplier,
            deadline_hours,
            out,
        } => {
            let keys = HarvesterKeys {
                signing: generate()?,
                vrf: generate()?,
            };
            let remote = PublicKey::from_private_key(&keys.signing);
            let vrf = PublicKey::from_private_key(&keys.vrf);
            let identifier = NetworkIdentifier::from(network);
            let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
            let message = harvest_request::encode(&mut rng, &node, &keys)
                .map_err(|error| format!("--node の公開鍵は使えません: {error}"))?;
            drop(keys);

            let link = |action, linked_public_key| KeyLink {
                linked_public_key,
                link_action: action,
            };
            // 解除してから紐づける。同じ種類のリンクがあるところには紐づけられない
            let mut bodies = Vec::new();
            bodies.extend(
                unlink_remote.map(|key| Body::AccountKeyLink(link(LinkAction::Unlink, key))),
            );
            bodies.extend(unlink_vrf.map(|key| Body::VrfKeyLink(link(LinkAction::Unlink, key))));
            bodies.extend(unlink_node.map(|key| Body::NodeKeyLink(link(LinkAction::Unlink, key))));
            bodies.push(Body::AccountKeyLink(link(LinkAction::Link, remote)));
            bodies.push(Body::VrfKeyLink(link(LinkAction::Link, vrf)));
            bodies.push(Body::NodeKeyLink(link(LinkAction::Link, node)));
            let recipient = harvest_request::recipient_address(&node, identifier);
            bodies.push(Body::Transfer(
                Transfer::new(recipient.into(), Default::default(), message)
                    .expect("one message and no mosaics fit"),
            ));
            let transactions = bodies
                .into_iter()
                .map(|body| EmbeddedTransaction::new(signer, identifier, body))
                .collect();
            let aggregate = Aggregate::new(transactions).expect("no aggregate is nested");

            let deadline = SystemTime::now() + deadline_hours as u32 * HOUR;
            let mut transaction = Transaction::new(
                signer,
                identifier,
                0,
                network_milliseconds(network, deadline)?,
                Body::AggregateComplete(aggregate),
            );
            let size = transaction.to_bytes().len() as u64;
            transaction.fee = size
                .checked_mul(fee_multiplier)
                .ok_or_else(|| "--fee-multiplier が大きすぎます".to_owned())?;
            write_new(&out, &transaction.to_bytes())?;

            outln!("リモートアカウントの公開鍵: {remote}");
            outln!("VRF の公開鍵: {vrf}");
            outln!("委任先のノードの公開鍵: {node}");
            outln!("委任の要求を送るアドレス: {recipient}");
            outln!(
                "手数料: {} ({size} バイト × {fee_multiplier})",
                transaction.fee
            );
            outln!("期限: {deadline_hours} 時間後");
            outln!(
                "次に委任先を変えるときは、--unlink-remote {remote} --unlink-vrf {vrf} --unlink-node {node} を付けてください"
            );
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
    }
    Ok(())
}

fn generate() -> Result<PrivateKey, String> {
    PrivateKey::generate().map_err(|error| format!("OS の乱数を取れませんでした: {error}"))
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
