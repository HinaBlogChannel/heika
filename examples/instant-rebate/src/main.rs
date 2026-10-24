//! 即時還元をするノード。`heika experimental peer start` と同じに動かし、作るブロックに還元を入れる。
//!
//! ```sh
//! instant-rebate <ノードの設定> <受取先の鍵のファイル> <返す千分率>
//! ```

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use heika_chain::produce::{Assemble, Slot};
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_node::harvesters::MemoryHarvesters;
use heika_node::keys::{others_can_read, read_private_key};
use heika_transaction::{Body, Transaction};
use instant_rebate::Rebate;

/// 止める合図を受けた
static STOP: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [config, key, permille] = args.as_slice() else {
        eprintln!("使い方: instant-rebate <ノードの設定> <受取先の鍵のファイル> <返す千分率>");
        return ExitCode::from(2);
    };
    match run(Path::new(config), Path::new(key), permille) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(config: &Path, key: &Path, permille: &str) -> Result<(), String> {
    let permille: u64 = permille
        .parse()
        .ok()
        .filter(|permille| *permille <= 1000)
        .ok_or("返す千分率は 0 から 1000 で書いてください")?;
    let manifest = Manifest::load(config).map_err(|error| error.to_string())?;
    let parameters =
        driver::network_parameters(&manifest.spec).map_err(|error| error.to_string())?;
    if others_can_read(key).unwrap_or(false) {
        eprintln!("{} は、持ち主のほかも読めます", key.display());
    }
    let rebate = Rebate::new(
        read_private_key(key).map_err(|error| error.to_string())?,
        parameters,
        permille,
    );
    let configured = manifest
        .spec
        .beneficiary
        .as_deref()
        .and_then(|address| address.trim().parse().ok());
    if configured != Some(rebate.beneficiary()) {
        return Err("設定の beneficiary を、受取先の鍵のアドレスにしてください".into());
    }
    println!("委任してくれた人のブロックで、受取先の分の {permille}‰ を返します");
    watch_signals();
    driver::run_with_assemble(
        &manifest,
        &|| STOP.load(Ordering::Relaxed),
        &MemoryHarvesters::new(),
        Arc::new(Logged { rebate, parameters }),
    )
    .map_err(|error| error.to_string())
}

/// 還元を入れるたびに、高さと額とハッシュを出す
struct Logged {
    rebate: Rebate,
    parameters: &'static NetworkParameters,
}

impl Assemble for Logged {
    fn assemble(&self, slot: &Slot, chosen: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let Some(rebate) = self.rebate.rebate(slot, &chosen) else {
            return chosen;
        };
        if let Ok(paid) = Transaction::from_bytes(&rebate)
            && let Body::Transfer(transfer) = &paid.body
        {
            let amount: u64 = transfer.mosaics().values().sum();
            println!(
                "高さ {} に還元 {}.{:06} XYM を入れます（{}）",
                slot.height,
                amount / 1_000_000,
                amount % 1_000_000,
                paid.hash(&self.parameters.generation_hash_seed)
            );
        }
        std::iter::once(rebate).chain(chosen).collect()
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
