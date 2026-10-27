//! 原子的な交換の Symbol 側を、プライベートネットで通しで動かす。Alice と Bob の両方を、この1つのプログラムが演じる。
//!
//! ```sh
//! adaptor-swap <ノードの設定> <Alice の鍵のファイル> <Bob の鍵のファイル> <XYM の最小単位の量> redeem|refund|both
//! ```
//!
//! - `redeem`: Bob が受け取る。Bob が出した連署から、Alice が `b` を取り出す
//! - `refund`: Bob が受け取らず、Alice が返金の窓が開くのを待って取り返す。Alice が出した連署から、Bob が `a` を取り出す
//! - `both`: `redeem` のあと、返金の窓が開くのを待って返金も出し、残高がなくて弾かれることを確かめる
//!
//! ノードの設定は `heika experimental peer start` と同じもので、ネットワークと REST（最初の `rest` の口）を決める。

use std::path::Path;
use std::process::ExitCode;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use adaptor_swap::adaptor::{self, Point, PreSignature, Secret};
use adaptor_swap::{payout, setup};
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_node::keys::{others_can_read, read_private_key};
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body};
use heika_rest::transaction::TransactionInfo;
use heika_transaction::{Body, Cosignature, DetachedCosignature, Transaction};

/// 手数料の倍率
const FEE_MULTIPLIER: u32 = 100;
/// 受け取りの期限。Bob はこれまでに受け取りを出す
const REDEEM_WINDOW: Duration = Duration::from_secs(3 * 60);
/// 受け取りの窓が閉じてから、返金の窓が開くまでの間
const GAP: Duration = Duration::from_secs(30);
/// 2-of-2 にするアグリゲートの期限
const SETUP_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// 承認を待つ長さの上限
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3 * 60);
/// 通らないはずのものが通らないことを見届ける長さ。ブロック（プライベートネットで 5 秒ほど）の十数個ぶん
const REFUSE_WAIT: Duration = Duration::from_secs(60);

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
});

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Redeem,
    Refund,
    Both,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [config, alice, bob, amount, mode] => match mode {
            "redeem" => run(config, alice, bob, amount, Mode::Redeem),
            "refund" => run(config, alice, bob, amount, Mode::Refund),
            "both" => run(config, alice, bob, amount, Mode::Both),
            _ => Err(format!("redeem か refund か both を書いてください: {mode}")),
        },
        _ => {
            eprintln!("使い方は src/main.rs の先頭か、README.md を見てください");
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

    /// 手数料を付けて外側に署名する。`cosignatures` は、あとから付く連署の数
    fn sign(
        &self,
        transaction: &mut Transaction,
        key: &PrivateKey,
        cosignatures: usize,
    ) -> Result<Hash256, String> {
        transaction.fee = transaction.fee_for(FEE_MULTIPLIER, cosignatures);
        let seed = &self.parameters.generation_hash_seed;
        transaction
            .sign(key, seed)
            .map_err(|error| error.to_string())?;
        Ok(transaction.hash(seed))
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

    /// 承認されるか弾かれるまで待ち、そのときの状態を返す
    fn wait(&self, transaction: &Transaction) -> Result<TransactionStatus, String> {
        self.settle(transaction, CONFIRM_TIMEOUT)?.ok_or_else(|| {
            format!(
                "{} 秒待っても承認されませんでした",
                CONFIRM_TIMEOUT.as_secs()
            )
        })
    }

    /// 承認されるか弾かれるまで、`timeout` まで待つ。決まらなければ `None`。heika のノードは、残高など状態に
    /// 依ることで外したトランザクションを `failed` にしない（catapult は未承認のうちに弾いて `failed` にする）ので、
    /// 通らないものは `None` になる
    fn settle(
        &self,
        transaction: &Transaction,
        timeout: Duration,
    ) -> Result<Option<TransactionStatus>, String> {
        let path = TransactionStatus::path(transaction, &self.parameters.generation_hash_seed);
        let started = Instant::now();
        while started.elapsed() < timeout {
            if let Some(body) = self.get(&path)? {
                let status = TransactionStatus::from_slice(&body)?;
                if status.group != "unconfirmed" {
                    return Ok(Some(status));
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
        Ok(None)
    }

    fn confirm(&self, transaction: &Transaction, what: &str) -> Result<(), String> {
        let status = self.wait(transaction)?;
        match (status.group.as_str(), &status.height) {
            ("confirmed", Some(height)) => {
                println!("    → {what}が高さ {height} で承認されました");
                Ok(())
            }
            _ => Err(format!(
                "{what}が弾かれました: {}",
                status.code.unwrap_or_default()
            )),
        }
    }

    /// 承認されたトランザクションを、連署ごと REST から読み直す
    fn confirmed(&self, hash: &Hash256) -> Result<Transaction, String> {
        let body = self
            .get(&format!("/transactions/confirmed/{hash}"))?
            .ok_or("承認されたトランザクションがありません")?;
        let info: TransactionInfo =
            serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        // TransactionInfo::verify は決め打ちのネットワークの seed で確かめるので、このネットワークの seed で確かめ直す
        let transaction =
            Transaction::try_from(&info.transaction).map_err(|error| error.to_string())?;
        let seed = &self.parameters.generation_hash_seed;
        if transaction.hash(seed) != *hash
            || !transaction.verify(seed)
            || !transaction.verify_cosignatures(seed)
        {
            return Err("REST が返したトランザクションが確かめられません".to_owned());
        }
        Ok(transaction)
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

    /// ネットワークの時刻が `at` を過ぎるまで待つ
    fn sleep_until(&self, at: u64) -> Result<(), String> {
        let now = self.now()?;
        if at > now {
            thread::sleep(Duration::from_millis(at - now));
        }
        Ok(())
    }
}

fn key(path: &str) -> Result<PrivateKey, String> {
    let path = Path::new(path);
    if others_can_read(path).unwrap_or(false) {
        eprintln!("{} は、持ち主のほかも読めます", path.display());
    }
    read_private_key(path).map_err(|error| error.to_string())
}

/// 画面に出す、点の先頭
fn short(point: &Point) -> String {
    point.0[..4]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
        + "…"
}

/// アダプター署名を完成させ、`signer` の連署としてアグリゲートに付ける。付けるときに、ふつうの連署と同じに
/// 署名を確かめる（catapult と同じ検証）
fn attach(
    transaction: &mut Transaction,
    signer: &PublicKey,
    pre: &PreSignature,
    secret: &Secret,
    context: &Context,
) -> Result<(), String> {
    let seed = &context.parameters.generation_hash_seed;
    let detached = DetachedCosignature {
        cosignature: Cosignature {
            signer_public_key: *signer,
            signature: adaptor::complete(pre, secret),
        },
        parent_hash: transaction.hash(seed),
    };
    transaction
        .attach_cosignature(&detached, seed)
        .map_err(|error| format!("完成させた連署が付けられません: {error}"))
}

/// チェーンに出たアグリゲートから、`signer` の連署を探して、仕込まれた秘密を取り出す
fn reveal(
    context: &Context,
    hash: &Hash256,
    signer: &PublicKey,
    pre: &PreSignature,
    expected: &Point,
) -> Result<Secret, String> {
    let transaction = context.confirmed(hash)?;
    let Body::AggregateComplete(aggregate) = &transaction.body else {
        return Err("アグリゲートではありません".to_owned());
    };
    let cosignature = aggregate
        .cosignatures()
        .iter()
        .find(|cosignature| cosignature.signer_public_key == *signer)
        .ok_or("連署が見つかりません")?;
    let secret = adaptor::extract(pre, &cosignature.signature)
        .ok_or("連署は、渡したアダプター署名を完成させたものではありません")?;
    if secret.point() != *expected {
        return Err("取り出した秘密が、仕込んだ点と合いません".to_owned());
    }
    Ok(secret)
}

fn run(
    config: &str,
    alice_file: &str,
    bob_file: &str,
    amount: &str,
    mode: Mode,
) -> Result<(), String> {
    let context = Context::load(config)?;
    let parameters = context.parameters;
    let network = parameters.identifier;
    let currency = parameters.currency_mosaic_id;
    let lifetime = parameters.max_transaction_lifetime.as_millis() as u64;
    let amount: u64 = amount
        .parse()
        .map_err(|_| format!("量は XYM の最小単位の整数で書いてください: {amount}"))?;
    let (alice, bob) = (key(alice_file)?, key(bob_file)?);
    let (alice_public, bob_public) = (
        PublicKey::from_private_key(&alice),
        PublicKey::from_private_key(&bob),
    );
    let generate = || Secret::generate().map_err(|error| error.to_string());

    println!(
        "1. 相手のチェーンの代わりに、2 人が秘密の半分 a、b を作り、公開する点 A、B を交換する"
    );
    let (a, b) = (generate()?, generate()?);
    let (big_a, big_b) = (a.point(), b.point());
    if !big_a.is_valid() || !big_b.is_valid() {
        return Err("受け取った点が正しくありません".to_owned());
    }
    let joint_point = big_a.sum(&big_b).ok_or("点を足せません")?;
    println!(
        "    A = {}、B = {}、A + B = {}（相手のチェーンでお金を置く先。a + b がそろうと動かせる）",
        short(&big_a),
        short(&big_b),
        short(&joint_point)
    );

    // 2-of-2 にするアカウントの鍵。2-of-2 にしたあとは、この鍵では何も署名できない
    let joint = PrivateKey::generate().map_err(|error| error.to_string())?;
    let joint_public = PublicKey::from_private_key(&joint);
    let now = context.now()?;
    let redeem_deadline = now + REDEEM_WINDOW.as_millis() as u64;
    // 返金は、受け取りの窓が閉じて GAP たってから入れられるようになる（期限の前の maxTransactionLifetime だけが窓）
    let refund_deadline = redeem_deadline + GAP.as_millis() as u64 + lifetime;

    println!("2. Alice が返金のアグリゲートを作って外側に署名し、Bob が A を仕込んだ連署を返す");
    let mut refund = payout(
        network,
        &alice_public,
        &joint_public,
        currency,
        amount,
        refund_deadline,
    );
    let refund_hash = context.sign(&mut refund, &alice, 1)?;
    let refund_pre = adaptor::pre_sign(&bob, &refund_hash.0, &big_a).ok_or("A を仕込めません")?;
    if !adaptor::verify_pre(&bob_public, &refund_hash.0, &big_a, &refund_pre) {
        return Err("Bob の返金の連署が確かめられません".to_owned());
    }
    println!(
        "    Alice は、a を足せば Bob の連署になることを確かめた（まだ出せない。窓が開くのは受け取りの窓が閉じたあと）"
    );

    println!(
        "3. Alice が、使い捨てのアカウントにちょうど {amount} を入れて、Alice と Bob の 2-of-2 にする"
    );
    let mut funding = setup(
        network,
        &alice_public,
        &bob_public,
        &joint_public,
        currency,
        amount,
        now + SETUP_LIFETIME.as_millis() as u64,
    );
    context.sign(&mut funding, &alice, 2)?;
    let seed = &parameters.generation_hash_seed;
    funding
        .cosign(&joint, seed)
        .map_err(|error| error.to_string())?;
    funding
        .cosign(&bob, seed)
        .map_err(|error| error.to_string())?;
    drop(joint);
    context.announce(&funding)?;
    context.confirm(&funding, "2-of-2 にするアグリゲート")?;

    println!("4. （相手のチェーンで、Bob が A + B にお金を置いたことにする）");

    println!(
        "5. Bob が受け取りのアグリゲートを作って外側に署名し、Alice が B を仕込んだ連署を返す"
    );
    let mut redeem = payout(
        network,
        &bob_public,
        &joint_public,
        currency,
        amount,
        redeem_deadline,
    );
    let redeem_hash = context.sign(&mut redeem, &bob, 1)?;
    let redeem_pre = adaptor::pre_sign(&alice, &redeem_hash.0, &big_b).ok_or("B を仕込めません")?;
    if !adaptor::verify_pre(&alice_public, &redeem_hash.0, &big_b, &redeem_pre) {
        return Err("Alice の受け取りの連署が確かめられません".to_owned());
    }
    println!("    Bob は、b を足せば Alice の連署になることを確かめた");

    if mode != Mode::Refund {
        println!("6. Bob が b で Alice の連署を完成させて、受け取りを出す");
        attach(&mut redeem, &alice_public, &redeem_pre, &b, &context)?;
        context.announce(&redeem)?;
        context.confirm(&redeem, "受け取り")?;
        println!("7. Alice が、チェーンに出た自分の連署から b を取り出す");
        let revealed = reveal(&context, &redeem_hash, &alice_public, &redeem_pre, &big_b)?;
        let sum = a.sum(&revealed).point();
        println!(
            "    取り出した b の点 = {}。a + b の点 = {}（A + B と{}）",
            short(&revealed.point()),
            short(&sum),
            if sum == joint_point {
                "同じ"
            } else {
                "違う"
            }
        );
        if sum != joint_point {
            return Err("a + b が A + B になりません".to_owned());
        }
        println!("    Alice は a + b をそろえたので、相手のチェーンのお金を動かせる");
    }

    if mode != Mode::Redeem {
        let opens = refund_deadline - lifetime;
        let wait = opens.saturating_sub(context.now()?) / 1000;
        println!(
            "{}. 返金の窓が開くまで待つ（あと約 {wait} 秒）",
            if mode == Mode::Refund { 6 } else { 8 }
        );
        context.sleep_until(opens + 5_000)?;
        println!("    Alice が a で Bob の連署を完成させて、返金を出す");
        attach(&mut refund, &bob_public, &refund_pre, &a, &context)?;
        context.announce(&refund)?;
        if mode == Mode::Both {
            match context.settle(&refund, REFUSE_WAIT)? {
                Some(status) if status.group == "confirmed" => {
                    return Err("受け取りのあとに返金が通りました".to_owned());
                }
                Some(status) => println!(
                    "    → 返金は弾かれました（{}）",
                    status.code.unwrap_or_default()
                ),
                None => println!(
                    "    → 返金は {} 秒たっても承認されません",
                    REFUSE_WAIT.as_secs()
                ),
            }
            println!("    受け取りで残高が空になったので、返金は通らない");
        } else {
            context.confirm(&refund, "返金")?;
            println!("7. Bob が、チェーンに出た自分の連署から a を取り出す");
            let revealed = reveal(&context, &refund_hash, &bob_public, &refund_pre, &big_a)?;
            let sum = b.sum(&revealed).point();
            println!(
                "    取り出した a の点 = {}。a + b の点 = {}（A + B と{}）",
                short(&revealed.point()),
                short(&sum),
                if sum == joint_point {
                    "同じ"
                } else {
                    "違う"
                }
            );
            if sum != joint_point {
                return Err("a + b が A + B になりません".to_owned());
            }
            println!("    Bob は a + b をそろえたので、相手のチェーンに置いたお金を取り戻せる");
        }
    }
    Ok(())
}
