//! アカウントを REST から取って、ブロックの StateHash まで確かめて出す。

use std::future::{Future, ready};
use std::io::{self, Write};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, Thread};
use std::time::Duration;

use clap::Subcommand;
use heika_core::address::Address;
use heika_core::network::{NetworkParameters, NetworkTimestamp};
use heika_rest::balance::{VerifiedBalance, VerifiedMosaic, verify_balance};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

use crate::Failure;
use crate::json::Value;
use crate::show::utc;

/// REST の1回の問い合わせを待つ時間
const TIMEOUT: Duration = Duration::from_secs(10);
/// 根が合わなかったときに、取り直すまでにおく間。REST の DB がノードに追いつくのを待つ
const RETRY_PAUSE: Duration = Duration::from_secs(3);

#[derive(Subcommand)]
pub enum AccountCommand {
    /// アカウントの残高を、REST の最新のブロックの StateHash まで確かめて出す
    ///
    /// ブロックの署名と、9本の根から求めた StateHash を確かめる。そのうえで、アカウントの状態と、
    /// 持っているモザイクの定義（可分性）が、状態の経路でその根につながることを確かめる。
    /// まだチェーンに載っていないアカウントは、載っていないことを状態の経路で確かめる。
    /// 信じたままなのは、そのブロックが正しいチェーンのものかどうかで、そこは REST を信じる。
    Show {
        /// アドレス
        address: Address,
        /// 問い合わせる REST（例: https://symbol.example:3001）
        #[arg(long, value_name = "URL")]
        rest: String,
        /// 結果を JSON で出す
        #[arg(long)]
        json: bool,
    },
}

pub fn run(command: AccountCommand) -> Result<(), Failure> {
    let AccountCommand::Show {
        address,
        rest,
        json,
    } = command;
    let origin = rest.trim_end_matches('/');
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .tls_config(tls)
        .build()
        .into();
    // 問い合わせはその場で終えて、済んだ future を返す
    let fetch = |path: String| {
        ready(
            match agent
                .get(&format!("{origin}{path}"))
                .call()
                .and_then(|mut response| response.body_mut().read_to_vec())
            {
                Ok(body) => Ok(Some(body)),
                Err(ureq::Error::StatusCode(404)) => Ok(None),
                Err(error) => Err(format!("REST の {path} を取れませんでした: {error}")),
            },
        )
    };
    let pause = || {
        thread::sleep(RETRY_PAUSE);
        ready(())
    };
    let balance =
        block_on(verify_balance(&address, fetch, pause)).map_err(|error| error.to_string())?;
    let network = NetworkParameters::from_identifier(balance.block.network)
        .ok_or_else(|| "知らないネットワークのブロックです".to_owned())?;
    if json {
        write_json(&balance, network)?;
    } else {
        write_text(&balance, network, origin)?;
    }
    Ok(())
}

/// future を、このスレッドで終わるまで動かす。待たされたら、起こされるまで眠る
fn block_on<T>(future: impl Future<Output = T>) -> T {
    struct Unpark(Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
    }
}

fn write_text(
    balance: &VerifiedBalance,
    network: &NetworkParameters,
    origin: &str,
) -> Result<(), Failure> {
    let block = &balance.block;
    outln!("アドレス: {}", balance.address);
    outln!("高さ: {}（{}）", block.height, block_time(balance, network));
    outln!("ブロックのハッシュ: {}", block.hash());
    match &balance.account {
        None => outln!("残高: まだチェーンに載っていません"),
        Some(account) if account.mosaics.is_empty() => outln!("残高: なし"),
        Some(account) => {
            outln!("残高:");
            for mosaic in &account.mosaics {
                outln!("  {}: {}", name(mosaic, network), amount(mosaic));
            }
        }
    }
    outln!();
    outln!("確かめたこと:");
    outln!("  ブロックの署名と、9本の根から求めた StateHash");
    match &balance.account {
        None => outln!("  アカウントが状態の木にないこと"),
        Some(_) => {
            outln!("  アカウントと、持っているモザイクの定義が、状態の経路で根につながること")
        }
    }
    outln!("信じていること:");
    outln!("  このブロックが正しいチェーンのものであること（{origin} を信じています）");
    Ok(())
}

fn write_json(balance: &VerifiedBalance, network: &NetworkParameters) -> Result<(), Failure> {
    let block = &balance.block;
    let mosaics = balance.account.as_ref().map_or(Vec::new(), |account| {
        account
            .mosaics
            .iter()
            .map(|mosaic| {
                let mut entry = vec![
                    ("id", Value::Text(format!("{:016X}", mosaic.id))),
                    // 2^53 を超えることがあるので、文字列にする
                    ("amount", Value::Text(mosaic.amount.to_string())),
                ];
                if let Some(divisibility) = mosaic.divisibility {
                    entry.push(("divisibility", Value::Number(divisibility.into())));
                }
                Value::Object(entry)
            })
            .collect()
    });
    let value = Value::Object(vec![
        ("address", Value::Text(balance.address.to_string())),
        (
            "status",
            Value::Text(if balance.account.is_some() {
                "on_chain".to_owned()
            } else {
                "not_on_chain".to_owned()
            }),
        ),
        ("height", Value::Text(block.height.to_string())),
        ("blockHash", Value::Text(block.hash().to_string())),
        ("blockTime", Value::Text(block_time(balance, network))),
        ("mosaics", Value::Array(mosaics)),
    ]);
    write!(io::stdout(), "{}", value.render()).map_err(|error| {
        if error.kind() == io::ErrorKind::BrokenPipe {
            Failure::BrokenPipe
        } else {
            Failure::Message(format!("標準出力に書けませんでした: {error}"))
        }
    })
}

fn block_time(balance: &VerifiedBalance, network: &NetworkParameters) -> String {
    let timestamp = balance.block.timestamp;
    network
        .time_of(NetworkTimestamp(timestamp))
        .map_or_else(|| format!("エポックから {timestamp} ミリ秒"), utc)
}

fn name(mosaic: &VerifiedMosaic, network: &NetworkParameters) -> String {
    if mosaic.id == network.currency_mosaic_id {
        "XYM".to_owned()
    } else {
        format!("0x{:016X}", mosaic.id)
    }
}

/// 可分性の桁で区切った量。定義がもうなければ、整数の量のまま出す
fn amount(mosaic: &VerifiedMosaic) -> String {
    mosaic.decimal().unwrap_or_else(|| {
        format!(
            "{}（定義がもうないので、可分性がわかりません）",
            mosaic.amount
        )
    })
}
