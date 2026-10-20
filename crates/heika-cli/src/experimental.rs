//! 試験的な機能。コマンドの形も、設定の中身も、断りなく変わる。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Subcommand;
use heika_node::config::Manifest;

#[derive(Subcommand)]
pub enum ExperimentalCommand {
    /// ピアとしてネットワークに入るノード
    #[command(subcommand)]
    Peer(PeerCommand),
}

#[derive(Subcommand)]
pub enum PeerCommand {
    /// 設定ファイル（apiVersion: heika.hinablogchannel.github.io/v1alpha1、kind: Peer の YAML）のとおりにノードを
    /// 動かす。前で動き、SIGINT か SIGTERM で、今のブロックを書き終えてから止まる
    Start {
        #[arg(long)]
        config: PathBuf,
    },
}

/// 止める合図を受けた
static STOP: AtomicBool = AtomicBool::new(false);

pub fn run(command: ExperimentalCommand) -> Result<(), String> {
    match command {
        ExperimentalCommand::Peer(PeerCommand::Start { config }) => {
            let manifest = Manifest::load(&config).map_err(|error| error.to_string())?;
            if !manifest.metadata.name.is_empty() {
                println!("{} を動かします", manifest.metadata.name);
            }
            watch_signals();
            heika_node::driver::run(&manifest, &|| STOP.load(Ordering::Relaxed))
                .map_err(|error| error.to_string())
        }
    }
}

/// SIGINT と SIGTERM で印を立てる。SIGHUP は受けない（nohup で流したものが止まらないように）
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
