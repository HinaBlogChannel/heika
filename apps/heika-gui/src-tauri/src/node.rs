//! ノード（試験的）。デスクトップだけ。
//!
//! ノードはウォレットとは別のプロセスで動かす。鍵を持つウォレットと、外とやりとりするノードを分けるため。
//! 別の実行ファイルは配らずに、このアプリの実行ファイルを `--node <設定ファイル>` で起動し直す
//! （[`run_child_if_asked`]）。子は標準入力が閉じたら、今のブロックを書き終えてから止まる。親が落ちても
//! 標準入力は閉じるので、子だけが残ることはない。
//!
//! 設定ファイル（YAML）は使う人には見せずに、ここで書く。ネットワークとシードは、設定した REST の
//! `/node/info`（そのノードを最初のつなぎ先にする）と `/node/peers`（つながらなければ代わりに使う）から決める。
//! ノードの鍵と証明書は、最初に起動したときに作って使い続ける。待ち受けるのは、この PC の中（127.0.0.1:7900）だけ。
//!
//! 子の出力は、管ではなく設定ファイルの隣の `node.log` に書かせ、親はそれを読んで進み具合を出す。管にすると、
//! 親が落ちたときに子が書けなくなって（EPIPE）、止める合図より先に落ちてしまう。

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::rest;

/// 子として起動するときの引数
const NODE_ARGUMENT: &str = "--node";
/// 待ち受けるアドレス。変えたいときは、書いた設定ファイルを手で直す（起動のたびに書き直さない）
const LISTEN: &str = "127.0.0.1:7900";
/// 証明書の CN
const NAME: &str = "heika";

/// `--node <設定ファイル>` で起動されたなら、ノードとして動いて真を返す。標準入力が閉じたら止める
pub fn run_child_if_asked() -> bool {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(NODE_ARGUMENT.as_ref()) {
        return false;
    }
    let Some(config) = args.next() else {
        eprintln!("{NODE_ARGUMENT} のあとに設定ファイルを渡してください");
        std::process::exit(2);
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    std::thread::spawn(|| {
        // 親は何も書かない。閉じる（EOF）か、読めなくなったら止める合図
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
        STOP.store(true, Ordering::Relaxed);
    });
    let result = heika_node::config::Manifest::load(Path::new(&config))
        .map_err(|error| error.to_string())
        .and_then(|manifest| {
            heika_node::driver::run(&manifest, &|| STOP.load(Ordering::Relaxed))
                .map_err(|error| error.to_string())
        });
    if let Err(error) = result {
        eprintln!("ノードが止まりました: {error}");
        std::process::exit(1);
    }
    true
}

/// 残し方。画面では軽い順に並べる
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Light,
    Full,
    Archive,
}

impl Mode {
    fn parse(name: &str) -> Option<Self> {
        [Self::Light, Self::Full, Self::Archive]
            .into_iter()
            .find(|mode| mode.as_str() == name)
    }

    /// 画面の名前
    fn label(self) -> &'static str {
        match self {
            Self::Light => "ライト",
            Self::Full => "フル",
            Self::Archive => "アーカイブ",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Full => "full",
            Self::Archive => "archive",
        }
    }
}

/// 画面に出す、ノードの様子
#[derive(Clone, Default, Serialize)]
pub struct Status {
    pub state: State,
    pub mode: Option<Mode>,
    pub network: Option<&'static str>,
    /// 追いつく段階の、実行した高さと目標の高さ
    pub height: Option<u64>,
    pub target: Option<u64>,
    /// 子が最後に出した行
    pub last_line: Option<String>,
    /// 起動できなかったか、止まったわけ
    pub error: Option<String>,
    /// これまでに動かした残し方。あれば選ばせずに、これで起動する
    pub saved: Option<Mode>,
}

#[derive(Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Stopped,
    /// REST に聞いて、設定を書いている
    Preparing,
    CatchingUp,
    /// 先端を追っている
    Following,
    Stopping,
}

/// 動かしている子
struct Running {
    child: Child,
    /// 閉じると子が止まる
    stdin: ChildStdin,
}

#[derive(Default)]
pub struct Node {
    status: Arc<Mutex<Status>>,
    running: Mutex<Option<Running>>,
}

impl Node {
    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 子に止まってもらい、止まるのを待つ。アプリを閉じるときにも呼ぶ
    pub fn stop_and_wait(&self) {
        let running = self
            .running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(Running { mut child, stdin }) = running else {
            return;
        };
        self.status().state = State::Stopping;
        drop(stdin);
        let _ = child.wait();
        self.status().state = State::Stopped;
    }
}

/// ノードの置き場所（アプリのデータの場所の下）
pub struct Paths {
    pub root: PathBuf,
}

#[tauri::command]
pub fn node_status(node: tauri::State<'_, Arc<Node>>, paths: tauri::State<'_, Paths>) -> Status {
    let mut status = node.status().clone();
    status.saved = last_saved(&paths.root);
    status
}

/// これまでに書いた設定ファイルの、ネットワークごとの残し方。新しく書いたものから
fn saved_modes(root: &Path) -> Vec<(String, Mode)> {
    let mut saved: Vec<(std::time::SystemTime, String, Mode)> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path().join("node.yaml");
            let modified = path.metadata().ok()?.modified().ok()?;
            let manifest = heika_node::config::Manifest::load(&path).ok()?;
            let mode = Mode::parse(manifest.spec.storage.mode.as_str())?;
            Some((
                modified,
                entry.file_name().to_string_lossy().into_owned(),
                mode,
            ))
        })
        .collect();
    saved.sort_by_key(|(modified, _, _)| std::cmp::Reverse(*modified));
    saved
        .into_iter()
        .map(|(_, network, mode)| (network, mode))
        .collect()
}

/// 最後に動かした残し方
fn last_saved(root: &Path) -> Option<Mode> {
    saved_modes(root).first().map(|(_, mode)| *mode)
}

#[tauri::command]
pub async fn node_start(
    mode: Mode,
    node: tauri::State<'_, Arc<Node>>,
    config: tauri::State<'_, rest::Config>,
    paths: tauri::State<'_, Paths>,
) -> Result<(), String> {
    {
        let mut status = node.status();
        if status.state != State::Stopped {
            return Err("ノードはもう動いています".to_owned());
        }
        *status = Status {
            state: State::Preparing,
            mode: Some(mode),
            ..Status::default()
        };
    }
    let prepared = prepare(mode, &config, &paths.root).await;
    let node = Arc::clone(&node);
    let result = prepared.and_then(|(network, manifest)| {
        node.status().network = Some(network);
        spawn(&node, &manifest)
    });
    if let Err(error) = &result {
        let mut status = node.status();
        status.state = State::Stopped;
        status.error = Some(error.clone());
    }
    result
}

#[tauri::command]
pub async fn node_stop(node: tauri::State<'_, Arc<Node>>) -> Result<(), String> {
    let node = Arc::clone(&node);
    tauri::async_runtime::spawn_blocking(move || node.stop_and_wait())
        .await
        .map_err(|error| error.to_string())
}

/// `/node/info` と `/node/peers` の、使うところ
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeInfo {
    #[serde(default)]
    host: String,
    port: u16,
    network_identifier: u8,
    roles: u32,
}

/// catapult の NodeRoles の Peer
const ROLE_PEER: u32 = 1;

/// REST に聞いてネットワークとシードを決め、鍵と証明書がなければ作り、設定ファイルを書く
async fn prepare(
    mode: Mode,
    config: &rest::Config,
    root: &Path,
) -> Result<(&'static str, PathBuf), String> {
    let client = config.client().map_err(|failure| failure.detail)?;
    let get = |path: &'static str| {
        let client = client.clone();
        async move {
            let bytes = client
                .get(path.to_owned())
                .await?
                .ok_or_else(|| format!("REST の {path} がありません"))?;
            Ok::<_, String>(bytes)
        }
    };
    let info: NodeInfo = serde_json::from_slice(&get("/node/info").await?)
        .map_err(|error| format!("REST の /node/info が読めません: {error}"))?;
    let network = match info.network_identifier {
        0x68 => "mainnet",
        0x98 => "testnet",
        other => return Err(format!("知らないネットワークです（{other}）")),
    };
    // REST の後ろのノードを最初のつなぎ先にする。名乗るホストがなければ、ピアの一覧から選ぶ
    let seed = if info.host.is_empty() || info.roles & ROLE_PEER == 0 {
        let peers: Vec<NodeInfo> = serde_json::from_slice(&get("/node/peers").await?)
            .map_err(|error| format!("REST の /node/peers が読めません: {error}"))?;
        peers
            .into_iter()
            .find(|peer| {
                !peer.host.is_empty()
                    && peer.roles & ROLE_PEER != 0
                    && peer.network_identifier == info.network_identifier
            })
            .map(|peer| (peer.host, peer.port))
            .ok_or("REST から、つなぐノードが見つかりません")?
    } else {
        (info.host, info.port)
    };
    let root = root.to_owned();
    tauri::async_runtime::spawn_blocking(move || {
        // 一度動かしたネットワークは、同じ残し方でしか起動しない。変えるのは、需要が出てから
        if let Some((_, saved)) = saved_modes(&root)
            .into_iter()
            .find(|(saved, _)| saved == network)
            && saved != mode
        {
            return Err(format!(
                "{network} は{}で動かしてきたので、{}では起動しません",
                saved.label(),
                mode.label()
            ));
        }
        let directory = root.join(network);
        let certificates = root.join("identity");
        heika_node::identity::ensure(&certificates, NAME).map_err(|error| error.to_string())?;
        let path = directory.join("node.yaml");
        let manifest = manifest(network, mode, &directory, &certificates, &seed);
        std::fs::create_dir_all(&directory)
            .and_then(|()| std::fs::write(&path, manifest))
            .map_err(|error| format!("{} に書けません: {error}", path.display()))?;
        Ok((network, path))
    })
    .await
    .map_err(|error| error.to_string())?
}

/// 設定ファイルの中身。文字列は JSON の形で書く（YAML としても読める）
fn manifest(
    network: &str,
    mode: Mode,
    directory: &Path,
    certificates: &Path,
    seed: &(String, u16),
) -> String {
    let quote = |text: &str| serde_json::to_string(text).expect("a string");
    let path = |path: &Path| quote(&path.display().to_string());
    // IPv6 のアドレスは [] で囲む
    let host = if seed.0.contains(':') {
        format!("[{}]", seed.0)
    } else {
        seed.0.clone()
    };
    format!(
        "apiVersion: {api}\nkind: Peer\nmetadata:\n  name: heika-gui\nspec:\n  network:\n    type: {network}\n  \
         dataDirectory: {data}\n  certificates:\n    directory: {certificates}\n  seed: {seed}\n  \
         listen:\n    address: {listen}\n  storage:\n    mode: {mode}\n",
        api = heika_node::config::API_VERSION,
        data = path(&directory.join("data")),
        certificates = path(certificates),
        seed = quote(&format!("{host}:{}", seed.1)),
        listen = quote(LISTEN),
        mode = mode.as_str(),
    )
}

/// 自分をノードとして起動し、出す行を読んで様子を覚える
fn spawn(node: &Arc<Node>, manifest: &Path) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let log_path = manifest.with_file_name("node.log");
    let log = File::create(&log_path)
        .map_err(|error| format!("{} を作れません: {error}", log_path.display()))?;
    let log_for_errors = log.try_clone().map_err(|error| error.to_string())?;
    let mut command = Command::new(executable);
    command
        .arg(NODE_ARGUMENT)
        .arg(manifest)
        .stdin(Stdio::piped())
        .stdout(log)
        .stderr(log_for_errors);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // コンソールの窓を出さない（CREATE_NO_WINDOW）
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("ノードを起動できません: {error}"))?;
    let stdin = child.stdin.take().expect("piped");
    node.status().state = State::CatchingUp;
    *node
        .running
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Running { child, stdin });
    // 子の書いた行を、子が止まるまで追って読む
    let reader = File::open(&log_path).map_err(|error| error.to_string())?;
    let status = Arc::clone(&node.status);
    let followed = Arc::clone(node);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                // 書きかけの行は、続きが来るまで待つ
                Ok(read) if read > 0 && line.ends_with('\n') => {
                    let mut status = status
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    read_line(&mut status, line.trim_end());
                }
                Ok(read) => {
                    if read > 0 {
                        // 読みかけた分は捨てずに、次に読む位置を戻す
                        let _ = reader.seek_relative(-(read as i64));
                    }
                    let stopped = followed
                        .running
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .is_none();
                    if stopped {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(_) => return,
            }
        }
    });
    // 子が自分で止まった（エラーなど）ら、止まったことにする
    let watched = Arc::clone(node);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let mut running = watched
                .running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(current) = running.as_mut() else {
                return;
            };
            if let Ok(Some(exit)) = current.child.try_wait() {
                running.take();
                let mut status = watched.status();
                status.state = State::Stopped;
                if !exit.success() {
                    status.error = status.last_line.clone();
                }
                return;
            }
        }
    });
    Ok(())
}

/// 子の1行から、様子を読み取る
fn read_line(status: &mut Status, line: &str) {
    if let Some((height, target)) = progress(line) {
        status.height = Some(height);
        status.target = Some(target);
        if status.state == State::Following {
            status.state = State::CatchingUp;
        }
    } else if line.contains("先端を追います") {
        status.state = State::Following;
    } else if line.contains("追いつく段階に") {
        status.state = State::CatchingUp;
    }
    if status.state != State::Stopping || line.contains("止め") {
        status.last_line = Some(line.to_owned());
    }
}

/// 追いつく段階の「高さ 123 / 456（...）」
fn progress(line: &str) -> Option<(u64, u64)> {
    let rest = line.strip_prefix("高さ ")?;
    let (height, rest) = rest.split_once(" / ")?;
    let target: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((height.parse().ok()?, target.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_progress_lines() {
        assert_eq!(
            progress("高さ 241561 / 5879024（538 ブロック/秒）"),
            Some((241_561, 5_879_024))
        );
        assert_eq!(progress("高さ 1 から 5879024 まで実行します"), None);
        let mut status = Status::default();
        read_line(&mut status, "高さ 300000 から先端を追います");
        assert!(status.state == State::Following);
    }

    #[test]
    fn writes_a_manifest_the_node_reads() {
        let text = manifest(
            "testnet",
            Mode::Light,
            Path::new("/data/testnet"),
            Path::new("/data/identity"),
            &("node.example".to_owned(), 7900),
        );
        let manifest = heika_node::config::Manifest::parse(&text).unwrap();
        assert_eq!(manifest.spec.seed.as_deref(), Some("node.example:7900"));
        assert_eq!(manifest.spec.network.resources, None);
        assert_eq!(manifest.spec.listen.unwrap().address, LISTEN);
    }
}
