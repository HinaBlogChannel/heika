//! 残高を問い合わせる REST の設定と、残高を確かめるコマンド。
//!
//! REST の答えはそのまま出さずに、heika-rest でブロックの署名と StateHash まで確かめてから出す。
//! 信じたままなのは、そのブロックが正しいチェーンのものかどうかで、そこは設定した REST を信じる。
//! なので、どの REST を信じるかは使う人に決めてもらい、最初は空にしておく。
//!
//! 問い合わせは ureq（同期）で、tokio の作業スレッドを止めないように spawn_blocking に投げる。
//! HTTPS の相手は OS のルート証明書で確かめる。Android では、OS の確かめ方を使うには Java 側の部品と初期化が要るので、
//! 代わりに OS が持っているルート証明書のファイルを読む。失効は確かめないが、残高はブロックの署名から確かめているので、
//! TLS が守るのは、どの REST に問い合わせているかまで。

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use heika_core::address::Address;
use heika_core::network::{NetworkParameters, NetworkTimestamp};
use heika_rest::balance::{BalanceError, VerifyError, verify_balance};
use serde::{Deserialize, Serialize};
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

/// REST の1回の問い合わせを待つ時間
const TIMEOUT: Duration = Duration::from_secs(10);
/// 根が合わなかったときに、取り直すまでにおく間。REST の DB がノードに追いつくのを待つ
const RETRY_PAUSE: Duration = Duration::from_secs(3);

/// 覚えておく設定。秘密は入れない。前の版で書いたファイルに項目がなくても読めるようにする
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// 残高を問い合わせる REST のオリジン（`https://ホスト:3001`）
    pub rest: Option<String>,
    /// 金額を隠す（人前で開くとき）
    pub hide_amounts: bool,
    /// ホームに出すアカウントのアドレス。最後に選んだもの
    pub account: Option<String>,
}

/// 設定と、それを書くファイル
pub struct Config {
    path: PathBuf,
    settings: Mutex<Settings>,
}

impl Config {
    /// ファイルから読む。なければ、読めなければ、空の設定から始める
    pub fn load(path: PathBuf) -> Self {
        let settings = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self {
            path,
            settings: Mutex::new(settings),
        }
    }

    fn get(&self) -> Settings {
        self.settings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// 一時ファイルに書いてから置き換える
    fn save(&self, settings: Settings) -> Result<(), String> {
        let write = || -> std::io::Result<()> {
            if let Some(directory) = self.path.parent() {
                fs::create_dir_all(directory)?;
            }
            let mut temporary = self.path.clone().into_os_string();
            temporary.push(".tmp");
            fs::write(&temporary, serde_json::to_vec_pretty(&settings)?)?;
            fs::rename(&temporary, &self.path)
        };
        write().map_err(|error| format!("{} に書けませんでした: {error}", self.path.display()))?;
        *self
            .settings
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = settings;
        Ok(())
    }
}

#[tauri::command]
pub fn settings(config: tauri::State<'_, Config>) -> Settings {
    config.get()
}

/// 設定をまとめて書く。REST のオリジンは確かめて、空なら消す
#[tauri::command]
pub fn save_settings(
    config: tauri::State<'_, Config>,
    settings: Settings,
) -> Result<Settings, String> {
    let rest = match settings.rest.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(rest) => Some(check_origin(rest)?),
    };
    let settings = Settings { rest, ..settings };
    config.save(settings.clone())?;
    Ok(settings)
}

/// `https://` か、自分のマシンの中だけを通る `http://` だけを受け付ける
fn check_origin(text: &str) -> Result<String, String> {
    let origin = text.trim_end_matches('/');
    let (scheme, rest) = origin
        .split_once("://")
        .ok_or("https:// から始めてください")?;
    // ホストは、ポートかパスの前まで。IPv6 は [ ] で囲まれている
    let host = match rest.strip_prefix('[') {
        Some(inner) => inner.split(']').next().unwrap_or(""),
        None => rest.split([':', '/']).next().unwrap_or(""),
    };
    if host.is_empty() || origin.chars().any(char::is_whitespace) {
        return Err("URL を読めません".to_owned());
    }
    match scheme {
        "https" => Ok(origin.to_owned()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "::1") => Ok(origin.to_owned()),
        "http" => Err(
            "http:// は、このマシンの中（localhost）だけにしてください。ほかは https:// にします"
                .to_owned(),
        ),
        _ => Err("https:// から始めてください".to_owned()),
    }
}

/// 画面に出す残高
#[derive(Serialize)]
pub struct BalanceView {
    address: String,
    /// まだチェーンに載っていなければ false。載っていないことも確かめてある
    on_chain: bool,
    height: String,
    block_hash: String,
    /// ブロックの時刻。Unix 時刻のミリ秒
    block_time: Option<u64>,
    /// 問い合わせた REST
    rest: String,
    mosaics: Vec<MosaicView>,
}

#[derive(Serialize)]
pub struct MosaicView {
    /// 16進の ID
    id: String,
    /// ネットワークの通貨（XYM）か
    currency: bool,
    /// 可分性の桁で区切った量。定義がもうなく、可分性がわからなければ None
    amount: Option<String>,
    /// 可分性を考えない、整数の量
    raw: String,
}

/// 残高を確かめられなかったわけ。画面は `kind` で、何をすればいいかを出し分ける
#[derive(Debug, Serialize)]
pub struct Failure {
    kind: FailureKind,
    /// くわしいエラー
    detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    /// REST につながらない
    Unreachable,
    /// REST の答えが読めない。Symbol の REST でなさそう
    Unreadable,
    /// REST のネットワークが、アドレスのと違う
    WrongNetwork,
    /// REST のノードが状態のハッシュを使っていないので、確かめられない
    Unsupported,
    /// 取り直しても、答えがブロックの StateHash と合わない
    Mismatch,
    Other,
}

impl Failure {
    fn other(detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Other,
            detail: detail.into(),
        }
    }
}

impl From<BalanceError<String>> for Failure {
    fn from(error: BalanceError<String>) -> Self {
        let kind = match &error {
            BalanceError::Fetch(_) => FailureKind::Unreachable,
            BalanceError::NotFound { .. } | BalanceError::Json { .. } => FailureKind::Unreadable,
            BalanceError::Verify(VerifyError::WrongNetwork) => FailureKind::WrongNetwork,
            BalanceError::Verify(VerifyError::NoStateHash) => FailureKind::Unsupported,
            BalanceError::Verify(VerifyError::MissingMosaic(_) | VerifyError::Invalid { .. }) => {
                FailureKind::Mismatch
            }
        };
        Self {
            kind,
            detail: error.to_string(),
        }
    }
}

/// `address` の残高を、設定した REST から取って確かめる
#[tauri::command]
pub async fn balance(
    config: tauri::State<'_, Config>,
    address: String,
) -> Result<BalanceView, Failure> {
    let origin = config
        .get()
        .rest
        .ok_or_else(|| Failure::other("残高を問い合わせる REST を、設定で決めてください"))?;
    let address: Address = address
        .trim()
        .parse()
        .map_err(|error| Failure::other(format!("アドレスを読めません: {error}")))?;
    let agent = Arc::new(agent());
    let fetch = {
        let origin = origin.clone();
        move |path: String| {
            let agent = Arc::clone(&agent);
            let origin = origin.clone();
            async move {
                tauri::async_runtime::spawn_blocking(move || get(&agent, &origin, &path))
                    .await
                    .map_err(|error| format!("問い合わせが途中で止まりました: {error}"))?
            }
        }
    };
    let pause = || async {
        // 眠るだけなので、止まっても困らない
        let _ = tauri::async_runtime::spawn_blocking(|| std::thread::sleep(RETRY_PAUSE)).await;
    };
    let balance = verify_balance(&address, fetch, pause).await?;

    let network = NetworkParameters::from_identifier(balance.block.network);
    let block_time = network
        .and_then(|network| network.time_of(NetworkTimestamp(balance.block.timestamp)))
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok());
    let currency = network.map(|network| network.currency_mosaic_id);
    let mosaics = balance.account.as_ref().map_or(Vec::new(), |account| {
        account
            .mosaics
            .iter()
            .map(|mosaic| MosaicView {
                id: format!("{:016X}", mosaic.id),
                currency: Some(mosaic.id) == currency,
                amount: mosaic.decimal(),
                raw: mosaic.amount.to_string(),
            })
            .collect()
    });
    Ok(BalanceView {
        address: balance.address.to_string(),
        on_chain: balance.account.is_some(),
        height: balance.block.height.to_string(),
        block_hash: balance.block.hash().to_string(),
        block_time,
        rest: origin,
        mosaics,
    })
}

/// HTTPS では、OS のルート証明書で相手を確かめる
fn agent() -> ureq::Agent {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .root_certs(root_certs())
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .tls_config(tls)
        .build()
        .into()
}

#[cfg(not(target_os = "android"))]
fn root_certs() -> RootCerts {
    RootCerts::PlatformVerifier
}

/// Android のルート証明書の置き場所。あるほうのうち、前のものを使う。
/// Android 14 からは、OS とは別に更新される Conscrypt の中にある
#[cfg(target_os = "android")]
const ANDROID_ROOTS: [&str; 2] = [
    "/apex/com.android.conscrypt/cacerts",
    "/system/etc/security/cacerts",
];

#[cfg(target_os = "android")]
fn root_certs() -> RootCerts {
    let roots = ANDROID_ROOTS
        .iter()
        .map(std::path::Path::new)
        .find(|directory| directory.is_dir())
        .map(load_roots)
        .unwrap_or_default();
    RootCerts::Specific(Arc::new(roots))
}

/// `directory` の中のファイルから、PEM の証明書を読む。
/// Android のファイルは、証明書の中身を人が読める形にした文の後ろに PEM が続く。読めないファイルは飛ばす
#[cfg(any(target_os = "android", test))]
fn load_roots(directory: &std::path::Path) -> Vec<ureq::tls::Certificate<'static>> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| fs::read(entry.ok()?.path()).ok())
        .flat_map(|bytes| {
            ureq::tls::parse_pem(&bytes)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(certificate)) => Some(certificate),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// REST の `path` を取る。404 なら None
fn get(agent: &ureq::Agent, origin: &str, path: &str) -> Result<Option<Vec<u8>>, String> {
    match agent
        .get(&format!("{origin}{path}"))
        .call()
        .and_then(|mut response| response.body_mut().read_to_vec())
    {
        Ok(body) => Ok(Some(body)),
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(error) => Err(format!("REST の {path} を取れませんでした: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use ureq::tls::Certificate;

    use super::*;

    #[test]
    fn accepts_https_and_local_http_only() {
        assert_eq!(
            check_origin("https://symbol.example:3001/").unwrap(),
            "https://symbol.example:3001"
        );
        assert!(check_origin("http://localhost:3000").is_ok());
        assert!(check_origin("http://127.0.0.1:3000").is_ok());
        assert!(check_origin("http://[::1]:3000").is_ok());
        assert!(check_origin("http://symbol.example:3000").is_err());
        assert!(check_origin("http://localhost.example:3000").is_err());
        assert!(check_origin("symbol.example:3001").is_err());
        assert!(check_origin("ftp://symbol.example").is_err());
        assert!(check_origin("https://").is_err());
        assert!(check_origin("https://a b").is_err());
    }

    #[test]
    fn reads_android_style_root_files() {
        let pem = include_bytes!("../../../../crates/heika-cert/testdata/openssl-v3-ca.pem");
        let directory = std::env::temp_dir().join(format!("heika-roots-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        // Android のファイルは、`openssl x509 -text` の出力のような文の後ろに PEM が続く
        let mut android = b"Certificate:\n    Data:\n        Version: 3 (0x2)\n".to_vec();
        android.extend_from_slice(pem);
        fs::write(directory.join("5ad8a5d6.0"), android).unwrap();
        fs::write(
            directory.join("broken.0"),
            b"-----BEGIN CERTIFICATE-----\n!!\n",
        )
        .unwrap();
        fs::write(directory.join("empty.0"), b"").unwrap();

        let roots = load_roots(&directory);
        fs::remove_dir_all(&directory).unwrap();
        let expected = Certificate::from_pem(pem).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].der(), expected.der());
        assert!(load_roots(&directory).is_empty());
    }

    #[test]
    fn tells_what_went_wrong() {
        let kind = |error| Failure::from(error).kind;
        assert_eq!(
            kind(BalanceError::Fetch("timed out".to_owned())),
            FailureKind::Unreachable
        );
        assert_eq!(
            kind(BalanceError::NotFound {
                path: "/chain/info".to_owned()
            }),
            FailureKind::Unreadable
        );
        assert_eq!(
            kind(BalanceError::Verify(VerifyError::WrongNetwork)),
            FailureKind::WrongNetwork
        );
        assert_eq!(
            kind(BalanceError::Verify(VerifyError::NoStateHash)),
            FailureKind::Unsupported
        );
        assert_eq!(
            kind(BalanceError::Verify(VerifyError::MissingMosaic(1))),
            FailureKind::Mismatch
        );
    }
}
