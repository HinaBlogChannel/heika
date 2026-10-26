//! 試験的な機能。コマンドの形も、設定の中身も、断りなく変わる。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Subcommand;
use heika_chain::nemesis::{NemesisProperties, generate};
use heika_core::key::PrivateKey;
use heika_core::network::NetworkIdentifier;
use heika_node::config::{Manifest, NetworkType};
use heika_node::harvesters::MemoryHarvesters;
use heika_state_transition::config::{ChainConfig, load_network_parameters};

use crate::read_secret;
use crate::wallet::HarvestKeystoreArgs;

#[derive(Subcommand)]
pub enum ExperimentalCommand {
    /// ピアとしてネットワークに入るノード
    #[command(subcommand)]
    Peer(PeerCommand),
    /// Nemesis のブロックを作り、ノードが最初に読む seed フォルダーを書く。入力は catapult の
    /// catapult.tools.nemgen と同じ nemesis.properties で、同じブロックができる。ただし Nemesis の秘密鍵は
    /// properties に書かず、標準入力で渡す
    Nemgen {
        /// ネットワークの設定（config-network.properties など）のある resources フォルダー
        #[arg(long)]
        resources: PathBuf,
        /// nemesis.properties。transactionsDirectory は、今いるフォルダーから数える
        #[arg(long)]
        nemesis: PathBuf,
        /// seed を書くフォルダー。もうあれば書かない
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum PeerCommand {
    /// 設定ファイル（apiVersion: heika.hinablogchannel.github.io/v1alpha1、kind: Peer の YAML）のとおりにノードを
    /// 動かす。前で動き、SIGINT か SIGTERM で、今のブロックを書き終えてから止まる
    Start {
        #[arg(long)]
        config: PathBuf,
        /// キーストアのこのアカウントから導出したリモートと VRF の鍵で、ハーベストする。鍵はノードのメモリにだけ置き、
        /// ディスクには書かない。先に heika harvesting --link-derived で紐づけておく
        #[arg(long, value_name = "LABEL")]
        harvest: Option<String>,
        #[command(flatten)]
        keystore: HarvestKeystoreArgs,
    },
    /// 止めたノードの DB を、設定の残し方（storage.mode）で刈り込んで、新しいフォルダーに写す。アーカイブから
    /// ライトの DB を作るときや、刈り込んでも縮まないファイルを詰め直すときに使う。写しを data に置き換えて使う
    Copy {
        #[arg(long)]
        config: PathBuf,
        /// 写しを作るフォルダー。DB がもうあれば写さない
        #[arg(long)]
        to: PathBuf,
    },
}

/// 止める合図を受けた
static STOP: AtomicBool = AtomicBool::new(false);

pub fn run(command: ExperimentalCommand) -> Result<(), String> {
    match command {
        ExperimentalCommand::Peer(PeerCommand::Start {
            config,
            harvest,
            keystore,
        }) => {
            let manifest = Manifest::load(&config).map_err(|error| error.to_string())?;
            let memory = MemoryHarvesters::new();
            if let Some(label) = &harvest {
                let derived = keystore.derive(label)?;
                let expected = match manifest.spec.network.network_type {
                    NetworkType::Mainnet => Some(NetworkIdentifier::MAINNET),
                    NetworkType::Testnet => Some(NetworkIdentifier::TESTNET),
                    NetworkType::Custom => None,
                };
                if expected.is_some_and(|network| network != derived.network) {
                    return Err(format!(
                        "{label} は、設定のネットワークと違うネットワークのアカウントです"
                    ));
                }
                memory.replace(vec![(derived.keys.signing, derived.keys.vrf)]);
                println!("{label} から導出した鍵を、ノードのメモリにだけ渡してハーベストします");
            }
            if !manifest.metadata.name.is_empty() {
                println!("{} を動かします", manifest.metadata.name);
            }
            watch_signals();
            heika_node::offer_source(&crate::legal::SOURCE);
            heika_node::driver::run_with(&manifest, &|| STOP.load(Ordering::Relaxed), &memory)
                .map_err(|error| error.to_string())
        }
        ExperimentalCommand::Peer(PeerCommand::Copy { config, to }) => {
            let manifest = Manifest::load(&config).map_err(|error| error.to_string())?;
            heika_node::copy::copy_pruned(&manifest, &to).map_err(|error| error.to_string())
        }
        ExperimentalCommand::Nemgen {
            resources,
            nemesis,
            out,
        } => nemgen(&resources, &nemesis, &out),
    }
}

fn nemgen(resources: &Path, nemesis: &Path, out: &Path) -> Result<(), String> {
    if out.exists() {
        return Err(format!("{} はもうあります", out.display()));
    }
    let text = fs::read_to_string(nemesis)
        .map_err(|error| format!("{} を読めません: {error}", nemesis.display()))?;
    let properties = NemesisProperties::parse(&text).map_err(|error| error.to_string())?;
    let config = ChainConfig::load(resources).map_err(|error| error.to_string())?;
    let parameters = load_network_parameters(resources).map_err(|error| error.to_string())?;
    let additional = match &properties.transactions_directory {
        Some(directory) => read_transactions(Path::new(directory))?,
        None => Vec::new(),
    };
    let signer: PrivateKey = read_secret("Nemesis の秘密鍵", "nemesis.key")?;
    let built = generate(&properties, config, &parameters, &signer, &additional)
        .map_err(|error| error.to_string())?;
    for (path, bytes) in built.seed_files(&properties.generation_hash_seed) {
        let path = out.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("{} を作れません: {error}", parent.display()))?;
        }
        fs::write(&path, bytes)
            .map_err(|error| format!("{} を書けません: {error}", path.display()))?;
    }
    let block = &built.block;
    let footer = block.importance_footer.as_ref();
    println!("Nemesis を {} に書きました", out.display());
    println!("ハッシュ: {}", block.hash());
    println!(
        "トランザクション: {} 件（追加 {} 件）",
        block.transactions().count(),
        additional.len()
    );
    if let Some(footer) = footer {
        println!(
            "ハーベストできるアカウント: {}、投票できるアカウント: {}",
            footer.harvesting_eligible_accounts_count, footer.voting_eligible_accounts_count
        );
    }
    Ok(())
}

/// 追加のトランザクションを、フォルダーのファイル名の順に読む（nemgen と同じ）。1ファイルに1件
fn read_transactions(directory: &Path) -> Result<Vec<Vec<u8>>, String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("{} を読めません: {error}", directory.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("{} を読めません: {error}", directory.display()))?;
        paths.push(entry.path());
    }
    paths.sort();
    paths
        .iter()
        .map(|path| {
            fs::read(path).map_err(|error| format!("{} を読めません: {error}", path.display()))
        })
        .collect()
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
