//! 400 人で分けて持つアカウントから、ROAST で署名した送金を出す。署名者はみなこのプロセスの中のスレッドで、
//! 届くまでの遅れを散らし、黙る人、遅い人、嘘をつく人を混ぜる。
//!
//! ```sh
//! roast <ノードの設定> <受取人のアドレス> <XYM の最小単位の量>
//! ```
//!
//! ノードの設定は `heika experimental peer start` と同じもので、ネットワークと REST（最初の `rest` の口）を決める。
//! 起動すると、400 人で持つアカウントのアドレスを出して、XYM が届くのを待つ。届いたら署名して出し、承認を待つ。

use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use frost_ed25519::keys::{PublicKeyPackage, SecretShare};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Signature, SigningPackage};
use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_rest::node::TransactionFeesJson;
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body};
use heika_rest::state::AccountInfo;
use heika_transaction::{Body, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId};
use rand_core::{OsRng, RngCore};
use roast::{Commitments, Event, Holder, Reply, Roast, Shares, deal, receive, verify_shares};

/// 署名する人の数
const PEOPLE: usize = 400;
/// 1 人の重みの上限。重みは 1 からこれまでの乱数
const MAX_WEIGHT: u32 = 4;
/// コミットメントを出したあと黙る人の割合（百分率）
const SILENT_PERCENT: u32 = 20;
/// 遅い人の割合（百分率）
const SLOW_PERCENT: u32 = 10;
/// 正しくない分け前を返す人の数
const LIARS: usize = 8;
/// ふつうの人の返事が届くまでの遅れの上限
const DELAY: Duration = Duration::from_millis(300);
/// 遅い人の返事が届くまでの遅れの上限
const SLOW_DELAY: Duration = Duration::from_secs(5);
/// 送金の期限
const LIFETIME: Duration = Duration::from_secs(60 * 60);
/// 承認を待つ長さの上限
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3 * 60);

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
});

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [config, recipient, amount] = args.as_slice() else {
        eprintln!("使い方: roast <ノードの設定> <受取人のアドレス> <XYM の最小単位の量>");
        return ExitCode::from(2);
    };
    match run(config, recipient, amount) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(config: &str, recipient: &str, amount: &str) -> Result<(), String> {
    let context = Context::load(config)?;
    let recipient: Address = recipient
        .parse()
        .map_err(|_| format!("アドレスが読めません: {recipient}"))?;
    if recipient.network() != context.parameters.identifier {
        return Err("受取人のアドレスが、このネットワークのものではありません".into());
    }
    let amount: u64 = amount
        .parse()
        .map_err(|_| format!("量が読めません: {amount}"))?;

    // 重みと振る舞いを決め、ディーラーが配る
    let weights: Vec<u16> = (0..PEOPLE)
        .map(|_| (OsRng.next_u32() % MAX_WEIGHT + 1) as u16)
        .collect();
    let behaviors = behaviors();
    let total: u16 = weights.iter().sum();
    let threshold = (u32::from(total) * 2).div_ceil(3) as u16;
    let honest: u16 = weights
        .iter()
        .zip(&behaviors)
        .filter(|(_, behavior)| matches!(behavior, Behavior::Honest | Behavior::Slow))
        .map(|(weight, _)| weight)
        .sum();
    if honest < threshold {
        return Err("黙る人と嘘つきが多すぎて、署名できません。もう一度走らせてください".into());
    }
    let (shares, public) =
        deal(&weights, threshold, &mut OsRng).map_err(|error| error.to_string())?;
    let signer = PublicKey(
        public
            .verifying_key()
            .serialize()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "公開鍵が 32 バイトではありません")?,
    );
    let address = Address::from_public_key(&signer, context.parameters.identifier);
    println!(
        "{PEOPLE} 人（分け前 {total} 個、署名に要るのは {threshold} 個）で持つアカウント: {address}"
    );

    // 届いた XYM で、送金を作る
    let fee_multiplier = context.fee_multiplier()?;
    let mut transaction = transfer(&context, signer, recipient, amount)?;
    transaction.fee = transaction.fee_for(fee_multiplier, 0);
    let needed = amount + transaction.fee;
    println!(
        "このアドレスに {}.{:06} XYM 以上を送ってください。届くのを待ちます",
        needed / 1_000_000,
        needed % 1_000_000
    );
    context.wait_for_balance(&address, needed)?;
    // 待っているあいだに期限が近づくので、作り直す
    let mut transaction = transfer(&context, signer, recipient, amount)?;
    transaction.fee = transaction.fee_for(fee_multiplier, 0);
    let message = transaction.signing_payload(&context.parameters.generation_hash_seed);

    let started = Instant::now();
    let signature = sign(
        message,
        Arc::new(public),
        &weights,
        threshold,
        shares,
        &behaviors,
    )?;
    println!(
        "署名ができました（{:.1} 秒）",
        started.elapsed().as_secs_f64()
    );
    transaction.signature = heika_core::signature::Signature(
        signature
            .serialize()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "署名が 64 バイトではありません")?,
    );
    if !transaction.verify(&context.parameters.generation_hash_seed) {
        return Err("できた署名が、Symbol の署名として確かめられません".into());
    }
    context.announce(&transaction)?;
    println!(
        "送りました（{}）",
        transaction.hash(&context.parameters.generation_hash_seed)
    );
    context.confirm(&transaction)
}

/// 署名者の振る舞い
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    Honest,
    /// 返事が遅い
    Slow,
    /// コミットメントを出したあと、黙る
    Silent,
    /// 正しくない分け前を返す
    Liar,
}

fn behaviors() -> Vec<Behavior> {
    let mut behaviors: Vec<Behavior> = (0..PEOPLE)
        .map(|_| match OsRng.next_u32() % 100 {
            roll if roll < SILENT_PERCENT => Behavior::Silent,
            roll if roll < SILENT_PERCENT + SLOW_PERCENT => Behavior::Slow,
            _ => Behavior::Honest,
        })
        .collect();
    let mut liars = 0;
    while liars < LIARS {
        let person = OsRng.next_u32() as usize % PEOPLE;
        if behaviors[person] != Behavior::Liar {
            behaviors[person] = Behavior::Liar;
            liars += 1;
        }
    }
    behaviors
}

/// まとめ役に届くもの
enum Message {
    Ready(usize, Commitments),
    Shares {
        person: usize,
        session: usize,
        shares: Shares,
        commitments: Commitments,
    },
    /// 分け前を確かめ終わった
    Checked {
        person: usize,
        reply: Reply,
    },
}

/// 署名者に届く頼みごと
struct Request {
    session: usize,
    package: Arc<SigningPackage>,
}

/// 署名者をスレッドで動かし、まとめ役が署名を作るまで回す
fn sign(
    message: Vec<u8>,
    public: Arc<PublicKeyPackage>,
    weights: &[u16],
    threshold: u16,
    shares: Vec<Vec<SecretShare>>,
    behaviors: &[Behavior],
) -> Result<Signature, String> {
    let (inbox, messages) = mpsc::channel();
    let requests: Vec<Sender<Request>> = shares
        .into_iter()
        .zip(behaviors)
        .enumerate()
        .map(|(person, (shares, &behavior))| {
            let (request, requests) = mpsc::channel();
            let inbox = inbox.clone();
            thread::spawn(move || hold(person, shares, behavior, requests, inbox));
            request
        })
        .collect();
    let mut roast = Roast::new(message, public.clone(), weights, threshold);
    let mut sessions = 0;
    let mut excluded = 0;
    loop {
        let message = messages
            .recv()
            .map_err(|_| "署名者がみないなくなりました")?;
        let (person, reply) = match message {
            Message::Ready(person, commitments) => (person, Reply::Ready(commitments)),
            Message::Shares {
                person,
                session,
                shares,
                commitments,
            } => {
                // 確かめるのは重いので、まとめ役の外で並べて走らせ、終わったら自分あてに届けてもらう
                if let Some((current, package)) = roast.session_of(person)
                    && current == session
                {
                    let inbox = inbox.clone();
                    let public = public.clone();
                    rayon::spawn(move || {
                        let reply = if verify_shares(&package, &public, &shares) {
                            Reply::Signed {
                                session,
                                shares,
                                commitments,
                            }
                        } else {
                            Reply::Invalid { session }
                        };
                        let _ = inbox.send(Message::Checked { person, reply });
                    });
                }
                continue;
            }
            Message::Checked { person, reply } => (person, reply),
        };
        let events = roast
            .receive(person, reply)
            .map_err(|_| "嘘つきを外したら、署名できる人が足りなくなりました")?;
        for event in events {
            match event {
                Event::Started {
                    session,
                    members,
                    package,
                } => {
                    sessions += 1;
                    let count: u16 = members.iter().map(|&member| weights[member]).sum();
                    println!(
                        "組 {session}: {} 人（分け前 {count} 個）に署名を頼みます",
                        members.len()
                    );
                    for member in members {
                        let _ = requests[member].send(Request {
                            session,
                            package: package.clone(),
                        });
                    }
                }
                Event::Excluded { person } => {
                    excluded += 1;
                    println!("{person} 番の人が正しくない分け前を返したので、外します");
                }
                Event::Signed { session, signature } => {
                    println!(
                        "組 {session} の分け前がそろいました（作った組 {sessions} 個、外した人 {excluded} 人）"
                    );
                    return Ok(signature);
                }
            }
        }
    }
}

/// 1 人の署名者。配られた分け前を確かめ、コミットメントを出して、頼まれたら署名する
fn hold(
    person: usize,
    shares: Vec<SecretShare>,
    behavior: Behavior,
    requests: Receiver<Request>,
    inbox: Sender<Message>,
) {
    let Ok(keys) = receive(shares) else {
        eprintln!("{person} 番の人に配られた分け前が正しくありません");
        return;
    };
    let mut holder = Holder::new(keys);
    let delay = || {
        let limit = match behavior {
            Behavior::Slow => SLOW_DELAY,
            _ => DELAY,
        };
        thread::sleep(limit.mul_f64(f64::from(OsRng.next_u32()) / f64::from(u32::MAX)));
    };
    delay();
    if inbox
        .send(Message::Ready(person, holder.commit(&mut OsRng)))
        .is_err()
    {
        return;
    }
    while let Ok(request) = requests.recv() {
        if behavior == Behavior::Silent {
            return;
        }
        let Ok(mut shares) = holder.sign(&request.package) else {
            return;
        };
        if behavior == Behavior::Liar {
            for share in shares.values_mut() {
                let mut bytes = share.serialize();
                bytes[0] ^= 1;
                if let Ok(wrong) = SignatureShare::deserialize(&bytes) {
                    *share = wrong;
                }
            }
        }
        delay();
        let message = Message::Shares {
            person,
            session: request.session,
            shares,
            commitments: holder.commit(&mut OsRng),
        };
        if inbox.send(message).is_err() {
            return;
        }
    }
}

/// 400 人で持つアカウントから、`recipient` に `amount` を送る。手数料は 0 のまま
fn transfer(
    context: &Context,
    signer: PublicKey,
    recipient: Address,
    amount: u64,
) -> Result<Transaction, String> {
    let transfer = Transfer::new(
        UnresolvedAddress::from(recipient),
        [(
            UnresolvedMosaicId(context.parameters.currency_mosaic_id),
            amount,
        )]
        .into(),
        Vec::new(),
    )
    .expect("one mosaic and no message");
    Ok(Transaction::new(
        signer,
        context.parameters.identifier,
        0,
        context.now()? + LIFETIME.as_millis() as u64,
        Body::Transfer(transfer),
    ))
}

/// ノードの設定から決まるもの
struct Context {
    parameters: &'static NetworkParameters,
    /// ノードの REST（`http://127.0.0.1:3000` など）
    rest: String,
}

impl Context {
    fn load(config: &str) -> Result<Self, String> {
        let manifest = Manifest::load(Path::new(config)).map_err(|error| error.to_string())?;
        let parameters =
            driver::network_parameters(&manifest.spec).map_err(|error| error.to_string())?;
        let listen = &manifest
            .spec
            .rest
            .first()
            .ok_or("ノードの設定に rest がありません")?
            .address;
        Ok(Self {
            parameters,
            rest: format!("http://{}", listen.replace("0.0.0.0", "127.0.0.1")),
        })
    }

    /// ネットワークの時刻（エポックからのミリ秒）
    fn now(&self) -> Result<u64, String> {
        self.parameters
            .timestamp_at(SystemTime::now())
            .map(|timestamp| timestamp.0)
            .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
    }

    /// 直近のブロックの中央値。ノードの下限より低ければ下限
    fn fee_multiplier(&self) -> Result<u32, String> {
        let body = self
            .get("/network/fees/transaction")?
            .ok_or("手数料の倍率が取れません")?;
        let fees: TransactionFeesJson =
            serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        Ok(fees.median_fee_multiplier.max(fees.min_fee_multiplier))
    }

    /// `address` の XYM が `needed` 以上になるまで待つ
    fn wait_for_balance(&self, address: &Address, needed: u64) -> Result<(), String> {
        loop {
            if let Some(body) = self.get(&format!("/accounts/{address}"))? {
                let info: AccountInfo =
                    serde_json::from_slice(&body).map_err(|error| error.to_string())?;
                let balance: u64 = info
                    .account
                    .mosaics
                    .iter()
                    .filter(|mosaic| {
                        u64::from_str_radix(&mosaic.id, 16).ok()
                            == Some(self.parameters.currency_mosaic_id)
                    })
                    .filter_map(|mosaic| mosaic.amount.parse::<u64>().ok())
                    .sum();
                if balance >= needed {
                    return Ok(());
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    fn announce(&self, transaction: &Transaction) -> Result<(), String> {
        let response = AGENT
            .put(&format!("{}{ANNOUNCE_PATH}", self.rest))
            .header("Content-Type", "application/json")
            .send(announce_body(transaction))
            .map_err(|error| format!("REST に送れませんでした: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "REST が受け付けませんでした: {}",
                response.status()
            ));
        }
        Ok(())
    }

    /// 承認されるか弾かれるまで待つ
    fn confirm(&self, transaction: &Transaction) -> Result<(), String> {
        let path = TransactionStatus::path(transaction, &self.parameters.generation_hash_seed);
        let started = Instant::now();
        while started.elapsed() < CONFIRM_TIMEOUT {
            if let Some(body) = self.get(&path)? {
                let status = TransactionStatus::from_slice(&body)?;
                match (status.group.as_str(), status.height) {
                    ("confirmed", Some(height)) => {
                        println!("高さ {height} で承認されました");
                        return Ok(());
                    }
                    ("failed", _) => {
                        return Err(format!("弾かれました: {}", status.code.unwrap_or_default()));
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
        Err(format!(
            "{} 秒待っても承認されませんでした",
            CONFIRM_TIMEOUT.as_secs()
        ))
    }

    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let mut response = AGENT
            .get(&format!("{}{path}", self.rest))
            .call()
            .map_err(|error| format!("{path}: {error}"))?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .read_to_vec()
                .map(Some)
                .map_err(|error| format!("{path}: {error}")),
            404 => Ok(None),
            status => Err(format!("{path}: {status}")),
        }
    }
}
