//! Symbol を掲示板にして EVM を動かすソブリンロールアップのノード。
//!
//! ```sh
//! evm-rollup run <ノードの設定> <genesis.json> <JSON-RPC の口> [リレーの鍵]
//! evm-rollup inbox <ノードの設定> <genesis.json>
//! evm-rollup bridge <ノードの設定> <元の genesis.json> <書き出す genesis.json>
//! evm-rollup send <ノードの設定> <宛先のアドレス> <XYM の最小単位の量> [メッセージ] < 秘密鍵
//! ```
//!
//! `run` は、Symbol のノードの REST を見て、受け箱に載った EVM のトランザクションを実行し、Ethereum の JSON-RPC で答える。
//! リレーの鍵があれば、`eth_sendRawTransaction` で受け取ったものを、その鍵で Symbol に載せる（手数料もその鍵が払う）。
//!
//! `inbox` は、受け箱のアドレスを出す。自分で Symbol に載せるなら、ここに宛てる。
//!
//! `bridge` は、橋の見張り役。見張り役に鍵を配って預かり口座を作り、それを書き込んだ genesis を書き出す。
//! あとは、ファイナライズされた引き出しを、預かり口座から払い続ける。
//!
//! `send` は、標準入力から読んだ秘密鍵で XYM を送る。預かり口座に入金したり、手数料を入れたりするのに使う。

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use evm_rollup::follow::{self, Sources, xym};
use evm_rollup::roast::{Holder, deal, receive, sign_together};
use evm_rollup::rollup::{Genesis, Rollup, WITHDRAW_ADDRESS, Withdrawal};
use evm_rollup::rpc::{self, Api, Relay};
use evm_rollup::symbol::Chain;
use evm_rollup::{envelope, vault};
use frost_core::keys::PublicKeyPackage;
use frost_ed25519::Ed25519Sha512;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_node::keys::{others_can_read, read_private_key};
use heika_transaction::{
    Body, Cosignature, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Symbol を見に行く間隔
const POLL: Duration = Duration::from_secs(2);

/// 見張り役の数
const WATCHERS: usize = 5;
/// 署名に要る見張り役の数
const THRESHOLD: u16 = 3;
/// ずっと黙っている見張り役。ROAST なので、黙る人がいても署名できる
const SILENT: usize = 4;
/// 手数料の予算（XYM の最小単位）。グループ鍵のアカウントに入れておき、払い出しの手数料を払う
const BUDGET: u64 = 20_000_000;
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3 * 60);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["run", config, genesis, listen] => {
            run(Path::new(config), Path::new(genesis), listen, None)
        }
        ["run", config, genesis, listen, key] => run(
            Path::new(config),
            Path::new(genesis),
            listen,
            Some(Path::new(key)),
        ),
        ["inbox", config, genesis] => inbox(Path::new(config), Path::new(genesis)),
        ["bridge", config, genesis, output] => {
            bridge(Path::new(config), Path::new(genesis), Path::new(output))
        }
        ["send", config, recipient, amount] => send(Path::new(config), recipient, amount, ""),
        ["send", config, recipient, amount, message] => {
            send(Path::new(config), recipient, amount, message)
        }
        _ => {
            eprintln!(
                "使い方: evm-rollup run <ノードの設定> <genesis.json> <JSON-RPC の口> [リレーの鍵]"
            );
            eprintln!("        evm-rollup inbox <ノードの設定> <genesis.json>");
            eprintln!(
                "        evm-rollup bridge <ノードの設定> <元の genesis.json> <書き出す genesis.json>"
            );
            eprintln!(
                "        evm-rollup send <ノードの設定> <宛先のアドレス> <XYM の最小単位の量> [メッセージ] < 秘密鍵"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn read_genesis(path: &Path) -> Result<Genesis, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let genesis: Genesis =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    genesis
        .check()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(genesis)
}

fn inbox(config: &Path, genesis: &Path) -> Result<(), String> {
    let chain = Chain::load(config)?;
    let genesis = read_genesis(genesis)?;
    println!(
        "{}",
        envelope::inbox(genesis.chain_id, chain.parameters.identifier)
    );
    Ok(())
}

fn run(config: &Path, genesis: &Path, listen: &str, key: Option<&Path>) -> Result<(), String> {
    let genesis = read_genesis(genesis)?;
    let inbox = envelope::inbox(genesis.chain_id, Chain::load(config)?.parameters.identifier);
    let relay = match key {
        Some(key) => {
            if others_can_read(key).unwrap_or(false) {
                eprintln!("{} は、持ち主のほかも読めます", key.display());
            }
            Some(Arc::new(Relay {
                chain: Chain::load(config)?,
                key: read_private_key(key).map_err(|error| error.to_string())?,
                inbox,
            }))
        }
        None => None,
    };
    let mut finalized = Rollup::new(&genesis);
    println!(
        "チェーン ID {}、Symbol の高さ {} の次から読みます。最初のルート {}",
        genesis.chain_id,
        genesis.start,
        finalized.state_root()
    );
    if let Some(vault) = &genesis.vault {
        println!("橋の預かり口座: {vault}");
        println!("引き出しの口: {WITHDRAW_ADDRESS}");
    }
    let views = follow::shared(&finalized);

    // Symbol を追いかける
    let chain = Chain::load(config)?;
    let following = Arc::clone(&views);
    thread::spawn(move || {
        let sources = Sources {
            inbox: &inbox,
            vault: genesis.vault.as_ref(),
        };
        loop {
            if let Err(error) = follow::step(&chain, sources, &mut finalized, &following) {
                eprintln!("Symbol を読めませんでした: {error}");
            }
            thread::sleep(POLL);
        }
    });

    serve(
        listen,
        Api {
            chain_id: genesis.chain_id,
            views,
            relay,
        },
    )
}

#[tokio::main]
async fn serve(listen: &str, api: Api) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("{listen}: {error}"))?;
    println!("JSON-RPC を {listen} で受けます");
    let app = Router::new().route("/", post(rpc::handle)).with_state(api);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|error| error.to_string())
}

/// 見張り役みんなで分けて持つ鍵（Ed25519）
struct Watchers {
    holders: Vec<Holder<Ed25519Sha512>>,
    public: Arc<PublicKeyPackage<Ed25519Sha512>>,
}

impl Watchers {
    fn deal() -> Result<Self, String> {
        let (shares, public) = deal::<Ed25519Sha512, _>(&[1; WATCHERS], THRESHOLD, &mut OsRng)
            .map_err(|error| error.to_string())?;
        let holders = shares
            .into_iter()
            .map(|shares| receive(shares).map(Holder::new))
            .collect::<Result<_, _>>()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            holders,
            public: Arc::new(public),
        })
    }

    fn key(&self) -> PublicKey {
        PublicKey(
            self.public
                .verifying_key()
                .serialize()
                .expect("a valid key")
                .try_into()
                .expect("32 bytes"),
        )
    }

    fn sign(&mut self, message: &[u8]) -> Result<heika_core::signature::Signature, String> {
        let signature = sign_together(
            &mut self.holders,
            &self.public,
            &[1; WATCHERS],
            THRESHOLD,
            message,
            &mut OsRng,
            |person, holder, package| (person != SILENT).then(|| holder.sign(package).ok())?,
        )
        .map_err(|_| "署名できる見張り役が足りません".to_owned())?;
        Ok(heika_core::signature::Signature(
            signature
                .serialize()
                .map_err(|error| error.to_string())?
                .try_into()
                .map_err(|_| "署名が 64 バイトではありません")?,
        ))
    }
}

/// 橋の見張り役。預かり口座を作って genesis を書き出し、あとは引き出しを払い続ける
fn bridge(config: &Path, genesis: &Path, output: &Path) -> Result<(), String> {
    let chain = Chain::load(config)?;
    let parameters = chain.parameters;
    let seed = &parameters.generation_hash_seed;
    let template = read_genesis(genesis)?;
    if template.vault.is_some() {
        return Err(format!(
            "{} には、もう預かり口座（vault）があります",
            genesis.display()
        ));
    }

    let mut watchers = Watchers::deal()?;
    let group = watchers.key();
    println!(
        "見張り役 {WATCHERS} 人に鍵を配りました（署名に要るのは {THRESHOLD} 人。{} 人目はずっと黙っています）",
        SILENT + 1
    );

    // 預かり口座の鍵は、作ってすぐ捨てる。それまでのあいだに、手数料の予算と、作るときの手数料を入れてもらう
    let vault_key = PrivateKey::generate().map_err(|error| error.to_string())?;
    let vault = PublicKey::from_private_key(&vault_key);
    let vault_address = chain.address(&vault);
    let fee_multiplier = chain.fee_multiplier()?;
    let needed = BUDGET + vault::setup(parameters, 0, fee_multiplier, vault, group, BUDGET).fee;
    println!("預かり口座: {vault_address}");
    println!(
        "このアドレスに {} XYM 以上を送ってください。届くのを待ちます",
        xym(needed)
    );
    while chain.balance(&vault_address)? < needed {
        thread::sleep(POLL);
    }
    let mut transaction = vault::setup(
        parameters,
        chain.deadline()?,
        fee_multiplier,
        vault,
        group,
        BUDGET,
    );
    transaction
        .sign(&vault_key, seed)
        .map_err(|error| error.to_string())?;
    drop(vault_key);
    let hash = transaction.hash(seed);
    let cosignature = Cosignature {
        signer_public_key: group,
        signature: watchers.sign(&hash.0)?,
    };
    let Body::AggregateComplete(aggregate) = &mut transaction.body else {
        unreachable!("預かり口座はアグリゲートで作る")
    };
    aggregate.add_cosignature(cosignature);
    chain.announce(&transaction)?;
    let height = chain.confirm(&transaction, CONFIRM_TIMEOUT)?;
    println!(
        "高さ {height} で、預かり口座を見張り役の鍵だけで動かせるようにしました（預かり口座の鍵は捨てました）"
    );

    // ロールアップは、預かり口座ができたブロックの次から読む。巻き戻らないように、ファイナライズを待つ
    while chain.heights()?.1 < height {
        thread::sleep(POLL);
    }
    let text = std::fs::read_to_string(genesis)
        .map_err(|error| format!("{}: {error}", genesis.display()))?;
    let mut json: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("{}: {error}", genesis.display()))?;
    json["start"] = height.into();
    json["vault"] = vault_address.to_string().into();
    let text = serde_json::to_string_pretty(&json).expect("json") + "\n";
    std::fs::write(output, text).map_err(|error| format!("{}: {error}", output.display()))?;
    let genesis = read_genesis(output)?;
    println!(
        "{} を書きました。ロールアップは、これで起動してください",
        output.display()
    );
    println!(
        "入金するときは、預かり口座へ、メッセージに入れる先の EVM のアドレス（0x…）を書いて XYM を送ってください"
    );
    println!(
        "引き出すときは、{WITHDRAW_ADDRESS} に、データに Symbol のアドレス（24 バイト）を入れて XYM を送ってください"
    );

    let inbox = envelope::inbox(genesis.chain_id, parameters.identifier);
    let sources = Sources {
        inbox: &inbox,
        vault: Some(&vault_address),
    };
    let mut payer = Payer {
        chain: &chain,
        vault,
        paid: chain.paid_withdrawals(&vault)?,
        sent: BTreeMap::new(),
    };
    let mut finalized = Rollup::new(&genesis);
    loop {
        let result = chain
            .heights()
            .and_then(|(_, final_height)| {
                follow::advance_finalized(&chain, sources, &mut finalized, final_height)
            })
            .and_then(|()| payer.pay(&finalized.withdrawals, &mut watchers));
        if let Err(error) = result {
            eprintln!("{error}");
        }
        thread::sleep(POLL);
    }
}

/// 引き出しを払う係
struct Payer<'a> {
    chain: &'a Chain,
    vault: PublicKey,
    /// もう払った引き出しの番号
    paid: BTreeSet<u64>,
    /// 払い出しを出したが、承認を見届けていない引き出しと、その期限。期限が過ぎるまでは、出し直さない
    /// （両方が承認されて 2 回払うことになるので）
    sent: BTreeMap<u64, u64>,
}

impl Payer<'_> {
    /// ファイナライズされた引き出しのうち、まだ払っていないものを払う
    fn pay(&mut self, withdrawals: &[Withdrawal], watchers: &mut Watchers) -> Result<(), String> {
        let parameters = self.chain.parameters;
        for withdrawal in withdrawals {
            let id = withdrawal.id;
            if self.paid.contains(&id) {
                continue;
            }
            if let Some(&deadline) = self.sent.get(&id) {
                if self.chain.now()? <= deadline {
                    continue;
                }
                // 前に出した払い出しの期限が過ぎた。承認されていれば、もう払ってある
                self.paid = self.chain.paid_withdrawals(&self.vault)?;
                if self.paid.contains(&id) {
                    self.sent.remove(&id);
                    continue;
                }
            }
            let mut transaction = vault::withdraw(
                parameters,
                self.chain.deadline()?,
                self.chain.fee_multiplier()?,
                self.vault,
                watchers.key(),
                withdrawal,
            );
            self.sent.insert(id, transaction.deadline);
            transaction.signature =
                watchers.sign(&transaction.signing_payload(&parameters.generation_hash_seed))?;
            self.chain.announce(&transaction)?;
            let height = self.chain.confirm(&transaction, CONFIRM_TIMEOUT)?;
            self.sent.remove(&id);
            self.paid.insert(id);
            println!(
                "引き出し {id} の {} XYM を、高さ {height} で {} に払いました",
                xym(withdrawal.amount),
                withdrawal.recipient
            );
        }
        Ok(())
    }
}

fn send(config: &Path, recipient: &str, amount: &str, message: &str) -> Result<(), String> {
    let chain = Chain::load(config)?;
    let parameters = chain.parameters;
    let recipient: Address = recipient
        .parse()
        .map_err(|_| format!("アドレスが読めません: {recipient}"))?;
    let amount: u64 = amount
        .parse()
        .map_err(|_| format!("量が読めません: {amount}"))?;
    let mut line = Zeroizing::new(String::new());
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let key: PrivateKey = line
        .trim()
        .parse()
        .map_err(|_| "標準入力の秘密鍵が読めません".to_owned())?;
    let message = if message.is_empty() {
        Vec::new()
    } else {
        [&[0][..], message.as_bytes()].concat()
    };
    let transfer = Transfer::new(
        UnresolvedAddress::from(recipient),
        [(UnresolvedMosaicId(parameters.currency_mosaic_id), amount)].into(),
        message,
    )
    .map_err(|error| error.to_string())?;
    let mut transaction = Transaction::new(
        PublicKey::from_private_key(&key),
        parameters.identifier,
        0,
        chain.deadline()?,
        Body::Transfer(transfer),
    );
    transaction.fee = transaction.fee_for(chain.fee_multiplier()?, 0);
    transaction
        .sign(&key, &parameters.generation_hash_seed)
        .map_err(|error| error.to_string())?;
    chain.announce(&transaction)?;
    let height = chain.confirm(&transaction, CONFIRM_TIMEOUT)?;
    println!("高さ {height} で承認されました");
    Ok(())
}
