//! 預けない交換を試す。どのサブコマンドも、heika のノードの設定から、ネットワークと REST（この PC の中の
//! ノードの口）を決める。
//!
//! ```sh
//! intent-dex board <ノードの設定>
//! intent-dex mint  <ノードの設定> <鍵のファイル> <発行量>
//! intent-dex order <ノードの設定> <メイカーの鍵のファイル> <出すモザイク>:<量> <欲しいモザイク>:<量> <手数料の XYM の最小単位>
//! intent-dex solve <ノードの設定> <在庫の鍵のファイル> <受け取るモザイク> <出すモザイク> <受け取る量>/<出す量> <1回に出す上限>
//! ```
//!
//! モザイクは 16 進の ID か、`xym`（通貨のモザイク）で書く。量は最小単位で書く。

use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::thread;
use std::time::{Duration, SystemTime};

use heika_chain::produce::{Assemble, Slot};
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_node::harvesters::MemoryHarvesters;
use heika_node::keys::{others_can_read, read_private_key};
use heika_rest::send::{ANNOUNCE_PATH, announce_body};
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, MosaicDefinition, MosaicFlags, MosaicId,
    MosaicSupplyChange, MosaicSupplyChangeAction, Transaction, Transfer, UnresolvedAddress,
    UnresolvedMosaicId,
};
use intent_dex::{Amount, Desk, Order, Solver, board};

/// 止める合図を受けた
static STOP: AtomicBool = AtomicBool::new(false);
/// 自分で出すトランザクションの手数料の倍率
const FEE_MULTIPLIER: u32 = 100;
/// 注文の期限。メイカーは、これを過ぎた注文を出し直す
const ORDER_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
/// 掲示板を読み直す間
const POLL: Duration = Duration::from_secs(10);
/// 掲示板から読む、新しい順の送金の数
const PAGE_SIZE: u32 = 100;

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into()
});

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["board", config] => context(config).map(|context| {
            println!("{}", board(context.parameters));
        }),
        ["mint", config, key, supply] => mint(config, key, supply),
        ["order", config, key, give, get, tip] => order(config, key, give, get, tip),
        ["solve", config, key, buys, sells, price, max_lot] => {
            solve(config, key, buys, sells, price, max_lot)
        }
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
    manifest: Manifest,
    parameters: &'static NetworkParameters,
    /// ノードの REST（`http://127.0.0.1:3000` など）
    rest: String,
}

fn context(config: &str) -> Result<Context, String> {
    let manifest = Manifest::load(Path::new(config)).map_err(|error| error.to_string())?;
    let parameters =
        driver::network_parameters(&manifest.spec).map_err(|error| error.to_string())?;
    let listen = &manifest
        .spec
        .rest
        .first()
        .ok_or("ノードの設定に rest がありません")?
        .address;
    let rest = format!("http://{}", listen.replace("0.0.0.0", "127.0.0.1"));
    Ok(Context {
        manifest,
        parameters,
        rest,
    })
}

fn key(path: &str) -> Result<PrivateKey, String> {
    let path = Path::new(path);
    if others_can_read(path).unwrap_or(false) {
        eprintln!("{} は、持ち主のほかも読めます", path.display());
    }
    read_private_key(path).map_err(|error| error.to_string())
}

fn mosaic(text: &str, parameters: &NetworkParameters) -> Result<UnresolvedMosaicId, String> {
    if text == "xym" {
        return Ok(UnresolvedMosaicId(parameters.currency_mosaic_id));
    }
    u64::from_str_radix(text, 16)
        .map(UnresolvedMosaicId)
        .map_err(|_| format!("モザイクは 16 進の ID か xym で書いてください: {text}"))
}

fn number(text: &str, what: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|_| format!("{what}は 0 以上の整数で書いてください: {text}"))
}

fn amount(text: &str, parameters: &NetworkParameters) -> Result<Amount, String> {
    let (id, amount) = text
        .split_once(':')
        .ok_or_else(|| format!("<モザイク>:<量> で書いてください: {text}"))?;
    Ok(Amount {
        mosaic: mosaic(id, parameters)?,
        amount: number(amount, "量")?,
    })
}

fn now(parameters: &NetworkParameters) -> Result<u64, String> {
    parameters
        .timestamp_at(SystemTime::now())
        .map(|timestamp| timestamp.0)
        .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
}

/// `key` で署名して、手数料を [`FEE_MULTIPLIER`] で付けて送る
fn announce(
    context: &Context,
    key: &PrivateKey,
    body: Body,
    lifetime: Duration,
) -> Result<Transaction, String> {
    let parameters = context.parameters;
    let deadline = now(parameters)? + lifetime.as_millis() as u64;
    let mut transaction = Transaction::new(
        PublicKey::from_private_key(key),
        parameters.identifier,
        0,
        deadline,
        body,
    );
    transaction.fee = transaction.fee_for(FEE_MULTIPLIER, 0);
    transaction
        .sign(key, &parameters.generation_hash_seed)
        .map_err(|error| error.to_string())?;
    AGENT
        .put(&format!("{}{ANNOUNCE_PATH}", context.rest))
        .header("Content-Type", "application/json")
        .send(announce_body(&transaction))
        .map_err(|error| format!("REST に送れませんでした: {error}"))?;
    Ok(transaction)
}

/// 試すためのモザイクを作る。発行量を変えられ、ほかの人にも送れる、小数点以下のないモザイク
fn mint(config: &str, key_file: &str, supply: &str) -> Result<(), String> {
    let context = context(config)?;
    let parameters = context.parameters;
    let key = key(key_file)?;
    let supply = number(supply, "発行量")?;
    let owner = PublicKey::from_private_key(&key);
    let address = Address::from_public_key(&owner, parameters.identifier);
    let nonce = u32::try_from(now(parameters)? % u64::from(u32::MAX)).unwrap_or(0);
    let id = MosaicId::generate(&address, nonce);
    let embedded = |body| EmbeddedTransaction::new(owner, parameters.identifier, body);
    let aggregate = Aggregate::new(vec![
        embedded(Body::MosaicDefinition(MosaicDefinition {
            id,
            duration: 0,
            nonce,
            flags: MosaicFlags::SUPPLY_MUTABLE | MosaicFlags::TRANSFERABLE,
            divisibility: 0,
        })),
        embedded(Body::MosaicSupplyChange(MosaicSupplyChange {
            mosaic_id: UnresolvedMosaicId(id.0),
            delta: supply,
            action: MosaicSupplyChangeAction::Increase,
        })),
    ])
    .expect("no nested aggregates");
    let transaction = announce(
        &context,
        &key,
        Body::AggregateComplete(aggregate),
        ORDER_LIFETIME,
    )?;
    println!(
        "モザイク {:016X} を {supply} 作るトランザクションを送りました（{}）",
        id.0,
        transaction.hash(&parameters.generation_hash_seed)
    );
    Ok(())
}

/// 注文を作って、掲示板に出す
fn order(config: &str, key_file: &str, give: &str, get: &str, tip: &str) -> Result<(), String> {
    let context = context(config)?;
    let parameters = context.parameters;
    let maker = key(key_file)?;
    let p = PrivateKey::generate().map_err(|error| error.to_string())?;
    let deadline = now(parameters)? + ORDER_LIFETIME.as_millis() as u64;
    let order = Order::new(
        parameters,
        &maker,
        p,
        amount(give, parameters)?,
        amount(get, parameters)?,
        number(tip, "手数料の XYM")?,
        FEE_MULTIPLIER,
        deadline,
    );
    order
        .terms(parameters)
        .ok_or("出すものと欲しいものは、違うモザイクで、どちらも 1 以上にしてください")?;
    let message = order.to_message();
    let body = Transfer::new(
        UnresolvedAddress::from(board(parameters)),
        Default::default(),
        message,
    )
    .map_err(|error| format!("{error:?}"))?;
    let posted = announce(&context, &maker, Body::Transfer(body), ORDER_LIFETIME)?;
    println!(
        "注文 {} を、掲示板 {} に出しました（送金 {}、P {}）",
        order.hash(parameters),
        board(parameters),
        posted.hash(&parameters.generation_hash_seed),
        order.p_address(parameters)
    );
    Ok(())
}

/// 約定させるノードを動かす
fn solve(
    config: &str,
    key_file: &str,
    buys: &str,
    sells: &str,
    price: &str,
    max_lot: &str,
) -> Result<(), String> {
    let context = context(config)?;
    let parameters = context.parameters;
    let (wanted, per) = price
        .split_once('/')
        .ok_or("値段は <受け取る量>/<出す量> で書いてください")?;
    let desk = Desk::new(
        key(key_file)?,
        parameters,
        mosaic(buys, parameters)?,
        mosaic(sells, parameters)?,
        (number(wanted, "受け取る量")?, number(per, "出す量")?),
        number(max_lot, "1回に出す上限")?,
    );
    println!(
        "在庫 {} で、{:016X} を {wanted}/{per} 以上で受け取り、{:016X} を 1 回 {} まで出します",
        desk.address(),
        desk.buys.0,
        desk.sells.0,
        desk.max_lot
    );
    let solver = Arc::new(Solver::new(desk));
    watch_signals();
    let polling = {
        let solver = Arc::clone(&solver);
        let rest = context.rest.clone();
        thread::spawn(move || poll(&rest, parameters, &solver))
    };
    let result = driver::run_with_assemble(
        &context.manifest,
        &|| STOP.load(Ordering::Relaxed),
        &MemoryHarvesters::new(),
        Arc::new(Logged { solver, parameters }),
    )
    .map_err(|error| error.to_string());
    STOP.store(true, Ordering::Relaxed);
    let _ = polling.join();
    result
}

/// 止めるまで、掲示板の注文を読み直す
fn poll(rest: &str, parameters: &'static NetworkParameters, solver: &Solver) {
    while !STOP.load(Ordering::Relaxed) {
        match open_orders(rest, parameters) {
            Ok(orders) => solver.replace(orders),
            Err(error) => eprintln!("注文を読めませんでした: {error}"),
        }
        for _ in 0..POLL.as_secs() {
            if STOP.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

/// `path` を取る。404 なら None
fn get(rest: &str, path: &str) -> Result<Option<Vec<u8>>, String> {
    match AGENT
        .get(&format!("{rest}{path}"))
        .call()
        .and_then(|mut response| response.body_mut().read_to_vec())
    {
        Ok(body) => Ok(Some(body)),
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(error) => Err(format!("{path}: {error}")),
    }
}

/// 掲示板の新しい注文のうち、期限が残っていて、まだ約定しておらず、P が乗っ取られていないもの
fn open_orders(
    rest: &str,
    parameters: &'static NetworkParameters,
) -> Result<Vec<Arc<Order>>, String> {
    let path = format!(
        "/transactions/confirmed?address={}&order=desc&pageSize={PAGE_SIZE}",
        board(parameters)
    );
    let Some(body) = get(rest, &path)? else {
        return Ok(Vec::new());
    };
    let page: serde_json::Value =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    let now = now(parameters)?;
    let mut orders = Vec::new();
    for item in page["data"].as_array().into_iter().flatten() {
        let Some(message) = item["transaction"]["message"].as_str().and_then(hex) else {
            continue;
        };
        let Some(order) = Order::from_message(parameters, &message) else {
            continue;
        };
        if order.transaction.deadline <= now {
            continue;
        }
        let p = order.p_address(parameters);
        let filled = format!("/transactions/confirmed/{}", order.hash(parameters));
        let multisig = format!("/account/{p}/multisig");
        let restricted = format!("/restrictions/account/{p}");
        if get(rest, &filled)?.is_some()
            || get(rest, &multisig)?.is_some()
            || get(rest, &restricted)?.is_some()
        {
            continue;
        }
        orders.push(Arc::new(order));
    }
    Ok(orders)
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// 約定させるたびに、高さと注文を出す
struct Logged {
    solver: Arc<Solver>,
    parameters: &'static NetworkParameters,
}

impl Assemble for Logged {
    fn assemble(&self, slot: &Slot, chosen: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let Some((order, filled)) = self.solver.pick(slot) else {
            return chosen;
        };
        if let Some(terms) = order.terms(self.parameters) {
            println!(
                "高さ {} で注文 {} を約定させます（{:016X} を {} 受け取り、{:016X} を {} 出す）",
                slot.height,
                order.hash(self.parameters),
                terms.give.mosaic.0,
                terms.give.amount,
                terms.get.mosaic.0,
                terms.get.amount
            );
        }
        filled.into_iter().chain(chosen).collect()
    }
}

/// SIGINT と SIGTERM で印を立てる
#[cfg(unix)]
fn watch_signals() {
    extern "C" fn on_stop(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }
    // SAFETY: 印を立てるだけの、シグナルの中で呼んでよい処理
    unsafe {
        libc::signal(
            libc::SIGINT,
            on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            on_stop as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
}

#[cfg(not(unix))]
fn watch_signals() {}
