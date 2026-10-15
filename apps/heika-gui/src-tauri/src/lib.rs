//! アプリの本体。画面（WebView）からは `invoke` でここのコマンドを呼ぶ。
//! 秘密鍵のように画面に出したくないものは、ここから外に出さない。
//! 例外は、作ったばかりのニーモニックの単語で、紙に控えてもらうために一度だけ画面に出す。
//!
//! キーストアを開いたり書いたりすると scrypt で1秒ほどかかるので、そういうコマンドは async にして、
//! 別のスレッドで動かす。画面の描画を止めないため。

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_wallet::bip39::{Mnemonic, WordCount};
use heika_wallet::keystore::{Account, Entry, Keystore, Secret};
use heika_wallet::keystore_file;
use serde::Serialize;
use tauri::Manager;
use zeroize::Zeroizing;

/// 画面の下に出す、どこで動いているか
#[derive(Serialize)]
struct About {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
}

#[tauri::command]
fn about() -> About {
    About {
        version: env!("CARGO_PKG_VERSION"),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
    }
}

/// 本体が覚えていること。コマンドをまたいで使う
struct Session {
    /// キーストアのファイル。デスクトップでは CLI と同じ場所
    path: PathBuf,
    /// 作って画面に出したが、まだしまっていないニーモニック
    pending: Option<Mnemonic>,
    /// 開いているキーストア。パスフレーズは覚えない
    keystore: Option<Keystore>,
}

#[derive(Clone)]
struct Wallet(Arc<Mutex<Session>>);

impl Wallet {
    fn lock(&self) -> MutexGuard<'_, Session> {
        // ほかのコマンドが途中で panic しても、中身は壊れた形にならないので、そのまま使う
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// 起動したときに、どの画面から始めるか
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Start {
    /// キーストアがまだない。ようこそ画面から
    Welcome,
    /// キーストアがある。パスフレーズを聞く
    Unlock { path: String },
    /// もう開いている
    Accounts,
}

#[tauri::command]
fn start(wallet: tauri::State<'_, Wallet>) -> Start {
    let session = wallet.lock();
    if session.keystore.is_some() {
        Start::Accounts
    } else if session.path.exists() {
        Start::Unlock {
            path: session.path.display().to_string(),
        }
    } else {
        Start::Welcome
    }
}

/// 新しいニーモニックを作って、単語と、確かめるときに聞く位置を返す
#[derive(Serialize)]
struct NewMnemonic {
    words: Vec<String>,
    /// 0 から数えた位置。小さい順
    quiz: Vec<usize>,
}

#[tauri::command]
fn new_mnemonic(wallet: tauri::State<'_, Wallet>) -> Result<NewMnemonic, String> {
    let mnemonic = Mnemonic::generate(WordCount::Words24).map_err(random_error)?;
    let phrase = mnemonic.to_phrase();
    let words: Vec<String> = phrase.split(' ').map(str::to_owned).collect();
    let quiz = quiz_positions(words.len(), 3)?;
    wallet.lock().pending = Some(mnemonic);
    Ok(NewMnemonic { words, quiz })
}

/// 重ならない位置を `count` 個、小さい順に選ぶ
fn quiz_positions(length: usize, count: usize) -> Result<Vec<usize>, String> {
    let mut positions = Vec::with_capacity(count);
    while positions.len() < count {
        let mut byte = [0];
        getrandom::fill(&mut byte).map_err(random_error)?;
        // 偏らないように、length の倍数に収まらない値は捨てる
        let limit = 256 - 256 % length;
        let position = usize::from(byte[0]);
        if position < limit && !positions.contains(&(position % length)) {
            positions.push(position % length);
        }
    }
    positions.sort_unstable();
    Ok(positions)
}

/// 画面に出すアカウント
#[derive(Serialize)]
struct AccountView {
    label: String,
    network: &'static str,
    /// 「ニーモニックの 0 番」「秘密鍵」
    source: String,
    address: String,
}

/// 作ったばかりのニーモニックをしまって、キーストアを作る
#[tauri::command]
async fn create_wallet(
    wallet: tauri::State<'_, Wallet>,
    network: String,
    passphrase: String,
) -> Result<Vec<AccountView>, String> {
    let passphrase = Zeroizing::new(passphrase);
    let network = parse_network(&network)?;
    let wallet = wallet.inner().clone();
    run_blocking(move || {
        // しまえないとわかっているなら、ニーモニックを取り出さずに残しておく
        check_new(&wallet, &passphrase)?;
        let mnemonic = wallet
            .lock()
            .pending
            .take()
            .ok_or("しまうニーモニックがありません。最初からやり直してください")?;
        create(&wallet, Secret::Mnemonic(mnemonic), network, &passphrase)
    })
    .await
}

/// 単語から戻して、キーストアを作る
#[tauri::command]
async fn restore_wallet(
    wallet: tauri::State<'_, Wallet>,
    words: String,
    network: String,
    passphrase: String,
) -> Result<Vec<AccountView>, String> {
    let words = Zeroizing::new(words);
    let words = Zeroizing::new(words.to_lowercase());
    let passphrase = Zeroizing::new(passphrase);
    let network = parse_network(&network)?;
    let mnemonic: Mnemonic = words
        .parse()
        .map_err(|error| format!("単語を読めません: {error}"))?;
    let wallet = wallet.inner().clone();
    run_blocking(move || create(&wallet, Secret::Mnemonic(mnemonic), network, &passphrase)).await
}

/// 秘密鍵を取り込んで、キーストアを作る
#[tauri::command]
async fn import_private_key(
    wallet: tauri::State<'_, Wallet>,
    private_key: String,
    network: String,
    passphrase: String,
) -> Result<Vec<AccountView>, String> {
    let private_key = Zeroizing::new(private_key);
    let passphrase = Zeroizing::new(passphrase);
    let network = parse_network(&network)?;
    let private_key: PrivateKey = private_key
        .trim()
        .parse()
        .map_err(|error| format!("秘密鍵を読めません: {error}"))?;
    let wallet = wallet.inner().clone();
    run_blocking(move || {
        create(
            &wallet,
            Secret::PrivateKey(private_key),
            network,
            &passphrase,
        )
    })
    .await
}

/// キーストアを作って書き、開いたままにする。もうファイルがあれば上書きしない
fn create(
    wallet: &Wallet,
    secret: Secret,
    network: NetworkIdentifier,
    passphrase: &str,
) -> Result<Vec<AccountView>, String> {
    let path = check_new(wallet, passphrase)?;
    let (index, label) = match secret {
        Secret::Mnemonic(_) => (Some(0), "メイン"),
        Secret::PrivateKey(_) => (None, "取り込んだ鍵"),
    };
    let mut keystore = Keystore::new();
    keystore
        .add(Entry {
            secret,
            accounts: vec![Account {
                network,
                index,
                label: label.to_owned(),
            }],
        })
        .map_err(|error| error.to_string())?;
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    keystore_file::save(&mut rng, &path, &keystore, passphrase)
        .map_err(|error| error.to_string())?;
    let accounts = describe(&keystore)?;
    wallet.lock().keystore = Some(keystore);
    Ok(accounts)
}

/// キーストアを新しく作れるか確かめて、書く場所を返す
fn check_new(wallet: &Wallet, passphrase: &str) -> Result<PathBuf, String> {
    if passphrase.is_empty() {
        return Err("パスフレーズを空にはできません".to_owned());
    }
    let path = wallet.lock().path.clone();
    if path.exists() {
        return Err(format!("{} はもうあります", path.display()));
    }
    Ok(path)
}

/// キーストアをパスフレーズで開く
#[tauri::command]
async fn unlock(
    wallet: tauri::State<'_, Wallet>,
    passphrase: String,
) -> Result<Vec<AccountView>, String> {
    let passphrase = Zeroizing::new(passphrase);
    let wallet = wallet.inner().clone();
    run_blocking(move || {
        let path = wallet.lock().path.clone();
        let sealed = std::fs::read(&path)
            .map_err(|error| format!("{} を読めません: {error}", path.display()))?;
        let keystore =
            Keystore::open(passphrase.as_bytes(), &sealed).map_err(|error| error.to_string())?;
        let accounts = describe(&keystore)?;
        wallet.lock().keystore = Some(keystore);
        Ok(accounts)
    })
    .await
}

/// 開いているキーストアのアカウント
#[tauri::command]
fn accounts(wallet: tauri::State<'_, Wallet>) -> Result<Vec<AccountView>, String> {
    match &wallet.lock().keystore {
        Some(keystore) => describe(keystore),
        None => Err("キーストアを開いていません".to_owned()),
    }
}

/// キーストアを閉じる。秘密は drop で0に消える
#[tauri::command]
fn lock(wallet: tauri::State<'_, Wallet>) {
    let mut session = wallet.lock();
    session.keystore = None;
    session.pending = None;
}

fn describe(keystore: &Keystore) -> Result<Vec<AccountView>, String> {
    keystore
        .accounts()
        .map(|(_, account)| {
            let (_, private_key) = keystore
                .private_key(&account.label, "")
                .map_err(|error| error.to_string())?;
            let public_key = PublicKey::from_private_key(&private_key);
            Ok(AccountView {
                label: account.label.clone(),
                network: if account.network == NetworkIdentifier::MAINNET {
                    "mainnet"
                } else {
                    "testnet"
                },
                source: match account.index {
                    Some(index) => format!("ニーモニックの {index} 番"),
                    None => "秘密鍵".to_owned(),
                },
                address: Address::from_public_key(&public_key, account.network).to_string(),
            })
        })
        .collect()
}

fn parse_network(network: &str) -> Result<NetworkIdentifier, String> {
    match network {
        "mainnet" => Ok(NetworkIdentifier::MAINNET),
        "testnet" => Ok(NetworkIdentifier::TESTNET),
        _ => Err(format!("知らないネットワークです: {network}")),
    }
}

fn random_error(error: getrandom::Error) -> String {
    format!("OS の乱数を取れませんでした: {error}")
}

/// 時間のかかる処理を、画面のスレッドを止めないように別のスレッドで動かす
async fn run_blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|error| format!("処理が途中で止まりました: {error}"))?
}

/// キーストアを置く場所。デスクトップでは CLI と同じファイルを使い、スマホではアプリのデータの場所に置く
fn keystore_path(app: &tauri::App) -> Result<PathBuf, String> {
    if cfg!(mobile) {
        app.path()
            .app_data_dir()
            .map(|directory| directory.join(keystore_file::FILE_NAME))
            .map_err(|error| error.to_string())
    } else {
        keystore_file::default_path().map_err(|error| error.to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let path = keystore_path(app)?;
            app.manage(Wallet(Arc::new(Mutex::new(Session {
                path,
                pending: None,
                keystore: None,
            }))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            about,
            start,
            new_mnemonic,
            create_wallet,
            restore_wallet,
            import_private_key,
            unlock,
            accounts,
            lock,
        ])
        .run(tauri::generate_context!())
        .expect("Tauri のアプリを起動できませんでした");
}
