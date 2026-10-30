//! Symbol を掲示板にして EVM を動かすソブリンロールアップのノード。
//!
//! ```sh
//! evm-rollup run <ノードの設定> <genesis.json> <JSON-RPC の口> [リレーの鍵]
//! evm-rollup inbox <ノードの設定> <genesis.json>
//! ```
//!
//! `run` は、Symbol のノードの REST を見て、受け箱に載った EVM のトランザクションを実行し、Ethereum の JSON-RPC で答える。
//! リレーの鍵があれば、`eth_sendRawTransaction` で受け取ったものを、その鍵で Symbol に載せる（手数料もその鍵が払う）。
//!
//! `inbox` は、受け箱のアドレスを出す。自分で Symbol に載せるなら、ここに宛てる。

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use axum::Router;
use axum::routing::post;
use evm_rollup::envelope;
use evm_rollup::follow;
use evm_rollup::rollup::{Genesis, Rollup};
use evm_rollup::rpc::{self, Api, Relay};
use evm_rollup::symbol::Chain;
use heika_node::keys::{others_can_read, read_private_key};

/// Symbol を見に行く間隔
const POLL: Duration = Duration::from_secs(2);

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
        _ => {
            eprintln!(
                "使い方: evm-rollup run <ノードの設定> <genesis.json> <JSON-RPC の口> [リレーの鍵]"
            );
            eprintln!("        evm-rollup inbox <ノードの設定> <genesis.json>");
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
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
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
    let views = follow::shared(&finalized);

    // Symbol を追いかける
    let chain = Chain::load(config)?;
    let following = Arc::clone(&views);
    thread::spawn(move || {
        loop {
            if let Err(error) = follow::step(&chain, &inbox, &mut finalized, &following) {
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
