//! XYM を EVM に持っていく橋の見張り役。見張り役はみなこのプロセスの中にいて、1 人はずっと黙っている。
//!
//! ```sh
//! peg-zone run <ノードの設定> <EVM の JSON-RPC>
//! peg-zone send <ノードの設定> <宛先のアドレス> <XYM の最小単位の量> [メッセージ] < 秘密鍵
//! ```
//!
//! `run` は、見張り役の鍵を配り、預かり口座を作り、EVM に wXYM を置いて、あとは見張り続ける。
//!
//! - 預かり口座への入金で、ファイナライズされたものを拾い、メッセージの EVM のアドレスに wXYM を発行する
//! - wXYM の Burn を拾い、預かり口座から Symbol のアドレスに送る
//! - 標準入力に `rotate` と打つと、見張り役を入れ替える（新しい鍵を配り、両方のチェーンで鍵を差し替える）
//!
//! `send` は、標準入力から読んだ秘密鍵で XYM を送る。預かり口座に入金したり、手数料を入れたりするのに使う。

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use frost_core::keys::PublicKeyPackage;
use frost_core::{Ciphersuite, Signature};
use frost_ed25519::Ed25519Sha512;
use frost_secp256k1::Secp256K1Sha256;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_transaction::{
    Body, Cosignature, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId,
};
use peg_zone::evm::{self, Burn, Evm, EvmKey, EvmSignature, key_digest, mint_digest};
use peg_zone::roast::{Holder, deal, receive, sign_together};
use peg_zone::symbol::{self, Chain, Withdrawal};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// 見張り役の数
const WATCHERS: usize = 5;
/// 署名に要る見張り役の数
const THRESHOLD: u16 = 3;
/// ずっと黙っている見張り役。ROAST なので、黙る人がいても署名できる
const SILENT: usize = 4;
/// 手数料の予算（XYM の最小単位）。グループ鍵のアカウントに入れておき、引き出しと入れ替えの手数料を払う
const BUDGET: u64 = 20_000_000;
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const POLL: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["run", config, rpc] => run(Path::new(config), rpc),
        ["send", config, recipient, amount] => send(Path::new(config), recipient, amount, ""),
        ["send", config, recipient, amount, message] => {
            send(Path::new(config), recipient, amount, message)
        }
        _ => {
            eprintln!("使い方: peg-zone run <ノードの設定> <EVM の JSON-RPC>");
            eprintln!(
                "        peg-zone send <ノードの設定> <宛先のアドレス> <XYM の最小単位の量> [メッセージ] < 秘密鍵"
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

/// 見張り役みんなで分けて持つ、1 つの曲線の鍵
struct Group<C: Ciphersuite> {
    holders: Vec<Holder<C>>,
    public: Arc<PublicKeyPackage<C>>,
}

impl<C: Ciphersuite> Group<C> {
    fn deal() -> Result<Self, String> {
        let (shares, public) = deal::<C, _>(&[1; WATCHERS], THRESHOLD, &mut OsRng)
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

    fn sign(&mut self, message: &[u8]) -> Result<Signature<C>, String> {
        sign_together(
            &mut self.holders,
            &self.public,
            &[1; WATCHERS],
            THRESHOLD,
            message,
            &mut OsRng,
            |person, holder, package| (person != SILENT).then(|| holder.sign(package).ok())?,
        )
        .map_err(|_| "署名できる見張り役が足りません".to_owned())
    }
}

/// 見張り役の鍵。Symbol の側（Ed25519）と EVM の側（secp256k1）
struct Watchers {
    symbol: Group<Ed25519Sha512>,
    evm: Group<Secp256K1Sha256>,
}

impl Watchers {
    fn deal() -> Result<Self, String> {
        loop {
            let watchers = Self {
                symbol: Group::deal()?,
                evm: Group::deal()?,
            };
            // x 座標が位数以上の鍵は、コントラクトで確かめられないので配り直す（めったに起きない）
            if watchers.evm_key().is_some() {
                return Ok(watchers);
            }
        }
    }

    fn symbol_key(&self) -> PublicKey {
        PublicKey(
            self.symbol
                .public
                .verifying_key()
                .serialize()
                .expect("a valid key")
                .try_into()
                .expect("32 bytes"),
        )
    }

    fn evm_key(&self) -> Option<EvmKey> {
        EvmKey::new(self.evm.public.verifying_key())
    }

    fn sign_symbol(&mut self, message: &[u8]) -> Result<heika_core::signature::Signature, String> {
        let signature = self.symbol.sign(message)?;
        Ok(heika_core::signature::Signature(
            signature
                .serialize()
                .map_err(|error| error.to_string())?
                .try_into()
                .map_err(|_| "署名が 64 バイトではありません")?,
        ))
    }

    fn sign_evm(&mut self, digest: &[u8; 32]) -> Result<EvmSignature, String> {
        let signature = self.evm.sign(digest)?;
        EvmSignature::new(&signature).ok_or_else(|| "署名の R が読めません".to_owned())
    }
}

/// アグリゲートに連署を足す
fn add_cosignature(transaction: &mut Transaction, cosignature: Cosignature) {
    let Body::AggregateComplete(aggregate) = &mut transaction.body else {
        unreachable!("アグリゲートだけに連署を足す")
    };
    aggregate.add_cosignature(cosignature);
}

fn run(config: &Path, rpc: &str) -> Result<(), String> {
    let chain = Chain::load(config)?;
    let parameters = chain.parameters;
    let seed = &parameters.generation_hash_seed;
    let evm = Evm::connect(rpc)?;
    let bytecode = read_bytecode()?;

    let mut watchers = Watchers::deal()?;
    let group = watchers.symbol_key();
    println!(
        "見張り役 {WATCHERS} 人に鍵を配りました（署名に要るのは {THRESHOLD} 人。{} 人目はずっと黙っています）",
        SILENT + 1
    );

    // 預かり口座の鍵は、作ってすぐ捨てる。それまでのあいだに、手数料の予算と、作るときの手数料を入れてもらう
    let vault_key = PrivateKey::generate().map_err(|error| error.to_string())?;
    let vault = PublicKey::from_private_key(&vault_key);
    let vault_address = chain.address(&vault);
    let fee_multiplier = chain.fee_multiplier()?;
    let needed = BUDGET + symbol::setup(parameters, 0, fee_multiplier, vault, group, BUDGET).fee;
    println!("預かり口座: {vault_address}");
    println!(
        "このアドレスに {} XYM 以上を送ってください。届くのを待ちます",
        xym(needed)
    );
    while chain.balance(&vault_address)? < needed {
        thread::sleep(POLL);
    }
    let mut transaction = symbol::setup(
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
        signature: watchers.sign_symbol(&hash.0)?,
    };
    add_cosignature(&mut transaction, cosignature);
    chain.announce(&transaction)?;
    let height = chain.confirm(&transaction, CONFIRM_TIMEOUT)?;
    println!(
        "高さ {height} で、預かり口座を見張り役の鍵だけで動かせるようにしました（預かり口座の鍵は捨てました）"
    );

    let contract = evm.deploy(&bytecode, &watchers.evm_key().expect("配るときに確かめた"))?;
    println!("wXYM: {}", evm::format_address(&contract));
    println!("入金するときは、メッセージに発行先の EVM のアドレス（0x…）を書いてください");
    println!("見張り役を入れ替えるときは、rotate と打ってください");

    let commands = commands();
    let mut watch = Watch {
        chain: &chain,
        evm: &evm,
        contract,
        vault,
        next_height: 1,
        next_block: 0,
        paid: chain.paid_burns(&vault)?,
        pending: BTreeMap::new(),
    };
    loop {
        if let Ok(command) = commands.try_recv() {
            match command.trim() {
                "rotate" => {
                    if let Err(error) = watch.rotate(&mut watchers) {
                        eprintln!("入れ替えられませんでした: {error}");
                    }
                }
                "" => {}
                other => eprintln!("知らないコマンドです: {other}"),
            }
        }
        if let Err(error) = watch.step(&mut watchers) {
            eprintln!("{error}");
        }
        thread::sleep(POLL);
    }
}

/// 標準入力の行
fn commands() -> mpsc::Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    receiver
}

/// 見張っているもの
struct Watch<'a> {
    chain: &'a Chain,
    evm: &'a Evm,
    contract: [u8; 20],
    vault: PublicKey,
    /// 次に入金を探す Symbol の高さ
    next_height: u64,
    /// 次に Burn を探す EVM のブロック
    next_block: u64,
    /// もう払った Burn の番号
    paid: BTreeSet<u64>,
    /// まだ払っていない Burn と、最後に出した引き出しの期限。期限が過ぎるまでは、出し直さない（両方が承認されて
    /// 2 回払うことになるので）
    pending: BTreeMap<u64, (Burn, Option<u64>)>,
}

impl Watch<'_> {
    fn step(&mut self, watchers: &mut Watchers) -> Result<(), String> {
        // ファイナライズされた入金だけを拾う。ロールバックで消えた入金に発行しないため
        let finalized = self.chain.finalized_height()?;
        if finalized >= self.next_height {
            let vault = self.chain.address(&self.vault);
            for deposit in self.chain.deposits(&vault, self.next_height, finalized)? {
                if self.evm.minted(&self.contract, &deposit.hash)? {
                    continue;
                }
                let digest = mint_digest(
                    self.evm.chain_id,
                    &self.contract,
                    &deposit.to,
                    deposit.amount,
                    &deposit.hash,
                );
                let signature = watchers.sign_evm(&digest)?;
                self.evm.mint(
                    &self.contract,
                    &deposit.to,
                    deposit.amount,
                    &deposit.hash,
                    &signature,
                )?;
                println!(
                    "高さ {} の入金で、{} に {} wXYM を発行しました",
                    deposit.height,
                    evm::format_address(&deposit.to),
                    xym(deposit.amount)
                );
            }
            self.next_height = finalized + 1;
        }

        let head = self.evm.block_number()?;
        if head >= self.next_block {
            for burn in self.evm.burns(&self.contract, self.next_block, head)? {
                if !self.paid.contains(&burn.id) {
                    self.pending.entry(burn.id).or_insert((burn, None));
                }
            }
            self.next_block = head + 1;
        }

        let now = self.chain.now()?;
        let ids: Vec<u64> = self.pending.keys().copied().collect();
        for id in ids {
            let (burn, deadline) = self.pending[&id].clone();
            if deadline.is_some_and(|deadline| now <= deadline) {
                continue;
            }
            if deadline.is_some() {
                // 前に出した引き出しの期限が過ぎた。承認されていれば、もう払ってある
                self.paid = self.chain.paid_burns(&self.vault)?;
                if self.paid.contains(&id) {
                    self.pending.remove(&id);
                    continue;
                }
            }
            let recipient = Address(burn.recipient);
            if recipient.network() != self.chain.parameters.identifier {
                eprintln!(
                    "Burn {id} の宛先は、このネットワークのアドレスではありません。払えません"
                );
                self.pending.remove(&id);
                continue;
            }
            let mut transaction = symbol::withdraw(
                self.chain.parameters,
                self.chain.deadline()?,
                self.chain.fee_multiplier()?,
                self.vault,
                watchers.symbol_key(),
                &Withdrawal {
                    id,
                    recipient,
                    amount: burn.amount,
                },
            );
            self.pending
                .insert(id, (burn.clone(), Some(transaction.deadline)));
            transaction.signature = watchers.sign_symbol(
                &transaction.signing_payload(&self.chain.parameters.generation_hash_seed),
            )?;
            self.chain.announce(&transaction)?;
            let height = self.chain.confirm(&transaction, CONFIRM_TIMEOUT)?;
            self.pending.remove(&id);
            self.paid.insert(id);
            println!(
                "Burn {id} の {} XYM を、高さ {height} で {recipient} に送りました",
                xym(burn.amount)
            );
        }
        Ok(())
    }

    /// 新しい見張り役に鍵を配り、両方のチェーンで鍵を差し替える
    fn rotate(&mut self, watchers: &mut Watchers) -> Result<(), String> {
        let mut new = Watchers::deal()?;
        println!("新しい見張り役 {WATCHERS} 人に鍵を配りました");

        // EVM：今の鍵で、新しい鍵に差し替える署名をする
        let key = new.evm_key().expect("配るときに確かめた");
        let epoch = self.evm.key_epoch(&self.contract)?;
        let digest = key_digest(self.evm.chain_id, &self.contract, epoch, &key);
        let signature = watchers.sign_evm(&digest)?;
        self.evm.change_key(&self.contract, &key, &signature)?;
        println!("wXYM の鍵を差し替えました");

        // Symbol：今のグループ鍵が署名し、新しいグループ鍵が連署者に加わることに同意する。手数料の予算も移す
        let parameters = self.chain.parameters;
        let seed = &parameters.generation_hash_seed;
        let (old, fresh) = (watchers.symbol_key(), new.symbol_key());
        let fee_multiplier = self.chain.fee_multiplier()?;
        let deadline = self.chain.deadline()?;
        let fee = symbol::rotate(
            parameters,
            deadline,
            fee_multiplier,
            self.vault,
            old,
            fresh,
            0,
        )
        .fee;
        let budget = self
            .chain
            .balance(&self.chain.address(&old))?
            .checked_sub(fee)
            .ok_or("今のグループ鍵のアカウントに、入れ替えの手数料がありません")?;
        let mut transaction = symbol::rotate(
            parameters,
            deadline,
            fee_multiplier,
            self.vault,
            old,
            fresh,
            budget,
        );
        transaction.signature = watchers.sign_symbol(&transaction.signing_payload(seed))?;
        let hash = transaction.hash(seed);
        let cosignature = Cosignature {
            signer_public_key: fresh,
            signature: new.sign_symbol(&hash.0)?,
        };
        add_cosignature(&mut transaction, cosignature);
        self.chain.announce(&transaction)?;
        let height = self.chain.confirm(&transaction, CONFIRM_TIMEOUT)?;
        println!(
            "高さ {height} で、預かり口座の連署者を新しい鍵に差し替えました（預かった XYM は動かしていません）"
        );
        *watchers = new;
        Ok(())
    }
}

/// `forge build` が作った wXYM の bytecode
fn read_bytecode() -> Result<String, String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/contracts/out/WrappedXym.sol/WrappedXym.json"
    );
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("{path}: {error}（contracts で forge build してください）"))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|error| format!("{path}: {error}"))?;
    json["bytecode"]["object"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{path} に bytecode がありません"))
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

fn xym(amount: u64) -> String {
    format!("{}.{:06}", amount / 1_000_000, amount % 1_000_000)
}
