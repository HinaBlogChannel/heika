//! ノード（試験的）。デスクトップと Android。
//!
//! デスクトップでは、ノードはウォレットとは別のプロセスで動かす。鍵を持つウォレットと、外とやりとりする
//! ノードを分けるため。別の実行ファイルは配らずに、このアプリの実行ファイルを `--node <設定ファイル>` で
//! 起動し直す（[`run_child_if_asked`]）。子は標準入力が閉じたら、今のブロックを書き終えてから止まる。親が
//! 落ちても標準入力は閉じるので、子だけが残ることはない。
//!
//! Android のアプリは実行ファイルではない（Java から読み込まれるライブラリ）ので、起動し直せない。ノードは
//! アプリのプロセスの中のスレッドで動かし、そのあいだはフォアグラウンドサービス（tauri-plugin-heika-node-service）
//! でプロセスが止められないようにして、通知に様子を出す。
//!
//! 設定ファイル（YAML）は使う人には見せずに、ここで書く。ネットワークとシードは、設定した REST の
//! `/node/info`（そのノードを最初のつなぎ先にする）と `/node/peers`（つながらなければ代わりに使う）から決める。
//! ノードの鍵と証明書は、最初に起動したときに作って使い続ける。待ち受けるのは、この PC の中（127.0.0.1:7900）だけ。
//! REST も、この PC の中（[`rest::OWN_REST`]）だけで立て、設定で選べば、ウォレットが残高や送金をそこで確かめる。
//!
//! ノードの出力は、設定ファイルの隣の `node.log` に書かせ、それを読んで進み具合を出す。デスクトップで管に
//! すると、親が落ちたときに子が書けなくなって（EPIPE）、止める合図より先に落ちてしまう。Android では、
//! プロセスの標準出力と標準エラー出力を、そのファイルに向け直す。

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
#[cfg(desktop)]
use std::process::{Child, ChildStdin, Command, Stdio};
#[cfg(desktop)]
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use heika_node::harvesters::{KeyPair, MemoryHarvesters};
use serde::{Deserialize, Serialize};
#[cfg(desktop)]
use zeroize::Zeroizing;

use crate::rest;

/// 子として起動するときの引数
#[cfg(desktop)]
const NODE_ARGUMENT: &str = "--node";
/// 待ち受けるアドレス。変えたいときは、書いた設定ファイルを手で直す（起動のたびに書き直さない）
const LISTEN: &str = "127.0.0.1:7900";
/// 証明書の CN
const NAME: &str = "heika";

/// `--node <設定ファイル>` で起動されたなら、ノードとして動いて真を返す。標準入力の `harvesters` の行
/// （[`heika_node::harvesters`]）でハーベストの鍵を入れ替え、標準入力が閉じたら止める
#[cfg(desktop)]
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
    static HARVESTERS: LazyLock<MemoryHarvesters> = LazyLock::new(MemoryHarvesters::new);
    std::thread::spawn(|| {
        // 閉じる（EOF）か、読めなくなったら止める合図
        heika_node::harvesters::read_input(std::io::stdin().lock(), &HARVESTERS);
        STOP.store(true, Ordering::Relaxed);
    });
    let result = heika_node::config::Manifest::load(Path::new(&config))
        .map_err(|error| error.to_string())
        .and_then(|manifest| {
            heika_node::driver::run_with(&manifest, &|| STOP.load(Ordering::Relaxed), &HARVESTERS)
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

    /// DB と、v0.12.0 までの設定ファイルに書いた名前
    fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Full => "full",
            Self::Archive => "archive",
        }
    }

    /// 設定ファイルに書く名前
    fn name(self) -> &'static str {
        match self {
            Self::Light => "Light",
            Self::Full => "Full",
            Self::Archive => "Archive",
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
    /// 鍵を渡して、ハーベストしているアカウントのアドレス
    pub harvesting: Option<String>,
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
#[cfg(desktop)]
struct Running {
    child: Child,
    /// 閉じると子が止まる
    stdin: ChildStdin,
}

/// 動かしているスレッド
#[cfg(target_os = "android")]
struct Running {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
    harvesters: Arc<MemoryHarvesters>,
}

/// 通知（Android のフォアグラウンドサービス）に伝えること
pub enum Notice {
    Start(String),
    Update(String),
    Stop,
}

/// 通知を出すもの。デスクトップでは置かない
type Notifier = Box<dyn Fn(Notice) + Send + Sync>;

#[derive(Default)]
pub struct Node {
    status: Arc<Mutex<Status>>,
    running: Mutex<Option<Running>>,
    notifier: Mutex<Option<Notifier>>,
}

impl Node {
    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 子が動いているか（止めている途中も含む）
    pub fn is_running(&self) -> bool {
        self.running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    /// 様子を通知に出すものを置く（Android）
    #[cfg_attr(desktop, allow(dead_code))]
    pub fn set_notifier(&self, notifier: Notifier) {
        *self
            .notifier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(notifier);
    }

    fn notify(&self, notice: Notice) {
        if let Some(notifier) = &*self
            .notifier
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            notifier(notice);
        }
    }

    /// 動いているノードのネットワーク（`mainnet` か `testnet`）。止まっていれば `None`
    pub fn network(&self) -> Option<&'static str> {
        let status = self.status();
        matches!(status.state, State::CatchingUp | State::Following)
            .then_some(status.network)
            .flatten()
    }

    /// 動いているノードに、ハーベストの鍵をメモリだけで渡す（前のものと入れ替える）。`account` は画面に出す
    /// アドレス。空にすると、ハーベストをやめる
    pub fn set_harvesters(
        &self,
        keys: Vec<KeyPair>,
        account: Option<String>,
    ) -> Result<(), String> {
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let running = running.as_mut().ok_or("ノードが動いていません")?;
        #[cfg(desktop)]
        {
            use std::io::Write;
            // 鍵が入るので、引っ越さないように先に確保する
            let mut line = Zeroizing::new(String::with_capacity(16 + keys.len() * 130));
            line.push_str("harvesters");
            for (signing, vrf) in &keys {
                line.push(' ');
                line.push_str(&signing.to_hex());
                line.push(' ');
                line.push_str(&vrf.to_hex());
            }
            line.push('\n');
            running
                .stdin
                .write_all(line.as_bytes())
                .and_then(|()| running.stdin.flush())
                .map_err(|error| format!("ノードに鍵を渡せません: {error}"))?;
        }
        #[cfg(target_os = "android")]
        running.harvesters.replace(keys);
        self.status().harvesting = account;
        Ok(())
    }

    /// ノードに止まってもらい、止まるのを待つ。アプリを閉じるときにも呼ぶ
    pub fn stop_and_wait(&self) {
        let running = self
            .running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(running) = running else {
            return;
        };
        self.status().state = State::Stopping;
        #[cfg(desktop)]
        {
            let Running { mut child, stdin } = running;
            drop(stdin);
            let _ = child.wait();
        }
        #[cfg(target_os = "android")]
        {
            running.stop.store(true, Ordering::Relaxed);
            let _ = running.thread.join();
        }
        let mut status = self.status();
        status.state = State::Stopped;
        status.harvesting = None;
        drop(status);
        self.notify(Notice::Stop);
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
            let mode = saved_mode(&std::fs::read_to_string(&path).ok()?)?;
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

/// 書いた設定ファイルの残し方。v0.12.0 までに書いたもの（`mode: light` のような小文字）は今のノードには
/// 読めないので、自分で書いた形として `mode:` の行から読む（次に起動するときに今の形で書き直す）
fn saved_mode(text: &str) -> Option<Mode> {
    if let Ok(manifest) = heika_node::config::Manifest::parse(text) {
        return Mode::parse(manifest.spec.storage.mode.as_str());
    }
    let value = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("mode:"))?
        .trim();
    Mode::parse(value)
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

/// 追いつく段階の DB のキャッシュ。ノードの既定（16 GiB）は、サーバーで速く追いつくためのもので、ウォレットの横で
/// 動かすには大きすぎる。Android では、メモリが足りなくなってプロセスごと捨てられていた。小さいと追いつくのは遅くなる
const CACHE: &str = "    cache:\n      catchUp: 512Mi\n";

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
    // REST はこの PC の中だけなので、ほかのノードには Api を名乗らない（ノードの既定では、REST の口があれば名乗る）
    format!(
        "apiVersion: {api}\nkind: Peer\nmetadata:\n  name: heika-gui\nspec:\n  network:\n    type: {network}\n  \
         dataDirectory: {data}\n  certificates:\n    directory: {certificates}\n  seed: {seed}\n  \
         listen:\n    address: {listen}\n    roles: [Peer]\n  storage:\n    mode: {mode}\n{CACHE}  rest:\n    - address: {rest}\n",
        api = heika_node::config::API_VERSION,
        data = path(&directory.join("data")),
        certificates = path(certificates),
        seed = quote(&format!("{host}:{}", seed.1)),
        listen = quote(LISTEN),
        rest = quote(rest::OWN_REST),
        mode = mode.name(),
        // network はフォルダーの名前にも使う小文字（`mainnet` か `testnet`）
        network = if network == "mainnet" {
            "Mainnet"
        } else {
            "Testnet"
        },
    )
}

/// 自分をノードとして起動し、出す行を読んで様子を覚える
#[cfg(desktop)]
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
    follow_log(node, &log_path)?;
    // 子が自分で止まった（エラーなど）ら、止まったことにする
    let watched = Arc::clone(node);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
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
                status.harvesting = None;
                if !exit.success() {
                    status.error = status.last_line.clone();
                }
                return;
            }
        }
    });
    Ok(())
}

/// ノードをこのプロセスの中のスレッドで動かし、フォアグラウンドサービスを始める
#[cfg(target_os = "android")]
fn spawn(node: &Arc<Node>, manifest_path: &Path) -> Result<(), String> {
    let manifest =
        heika_node::config::Manifest::load(manifest_path).map_err(|error| error.to_string())?;
    let log_path = manifest_path.with_file_name("node.log");
    let log = File::create(&log_path)
        .map_err(|error| format!("{} を作れません: {error}", log_path.display()))?;
    redirect_output(&log)?;
    let stop = Arc::new(AtomicBool::new(false));
    let harvesters = Arc::new(MemoryHarvesters::new());
    node.status().state = State::CatchingUp;
    node.notify(Notice::Start("起動しています".to_owned()));
    {
        // スレッドがすぐ終わっても、覚える前に「止まった」を書かれないように、覚え終えるまで握っておく
        let mut running = node
            .running
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let finished = Arc::clone(node);
        let stopping = Arc::clone(&stop);
        let memory = Arc::clone(&harvesters);
        let thread = std::thread::spawn(move || {
            let result = heika_node::driver::run_with(
                &manifest,
                &|| stopping.load(Ordering::Relaxed),
                &memory,
            );
            if let Err(error) = &result {
                eprintln!("ノードが止まりました: {error}");
            }
            // 止める合図で止まったなら、待っている stop_and_wait が後始末をする
            let ours = finished
                .running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .is_some();
            if ours {
                let mut status = finished.status();
                status.state = State::Stopped;
                status.harvesting = None;
                status.error = result.err().map(|error| error.to_string());
                drop(status);
                finished.notify(Notice::Stop);
            }
        });
        *running = Some(Running {
            stop,
            thread,
            harvesters,
        });
    }
    follow_log(node, &log_path)
}

/// このプロセスの標準出力と標準エラー出力を `log` に向け直す。ノードは println! で様子を書くので
#[cfg(target_os = "android")]
fn redirect_output(log: &File) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let _ = std::io::stdout().flush();
    for target in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: 開いているファイルの記述子を、標準出力と標準エラー出力の番号に複製するだけ
        if unsafe { libc::dup2(log.as_raw_fd(), target) } < 0 {
            return Err(format!(
                "ノードの出力をファイルに向けられません: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// ノードの書いた行を、ノードが止まるまで追って読み、様子を覚える。通知も、ときどき変える
fn follow_log(node: &Arc<Node>, log_path: &Path) -> Result<(), String> {
    /// 通知を変える間隔の下限
    const NOTIFY_EVERY: Duration = Duration::from_secs(5);
    let reader = File::open(log_path).map_err(|error| error.to_string())?;
    let followed = Arc::clone(node);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut notified = Instant::now();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                // 書きかけの行は、続きが来るまで待つ
                Ok(read) if read > 0 && line.ends_with('\n') => {
                    let notice = {
                        let mut status = followed.status();
                        read_line(&mut status, line.trim_end());
                        notice_text(&status)
                    };
                    if notified.elapsed() >= NOTIFY_EVERY
                        && let Some(text) = notice
                    {
                        notified = Instant::now();
                        followed.notify(Notice::Update(text));
                    }
                }
                Ok(read) => {
                    if read > 0 {
                        // 読みかけた分は捨てずに、次に読む位置を戻す
                        let _ = reader.seek_relative(-(read as i64));
                    }
                    if !followed.is_running() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(_) => return,
            }
        }
    });
    Ok(())
}

/// 通知に出す、今の様子
fn notice_text(status: &Status) -> Option<String> {
    match status.state {
        State::CatchingUp => status.height.zip(status.target).map(|(height, target)| {
            format!("確定したところまで追いかけています（高さ {height} / {target}）")
        }),
        State::Following => Some(match status.height {
            Some(height) => format!("最新を追っています（高さ {height} まで追いつきました）"),
            None => "最新を追っています".to_owned(),
        }),
        _ => None,
    }
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
        assert_eq!(manifest.spec.rest[0].address, rest::OWN_REST);
        // この PC の中だけの REST があっても、Peer だけを名乗る
        assert_eq!(manifest.spec.roles().0, ROLE_PEER);
        assert_eq!(manifest.spec.listen.unwrap().address, LISTEN);
        assert_eq!(manifest.spec.storage.mode, heika_node::config::Mode::Light);
        assert_eq!(
            manifest.spec.storage.cache.catch_up,
            heika_node::config::ByteSize(512 << 20)
        );
        assert_eq!(
            manifest.spec.network.network_type,
            heika_node::config::NetworkType::Testnet
        );
        assert_eq!(saved_mode(&text), Some(Mode::Light));
    }

    #[test]
    fn reads_the_mode_of_a_manifest_written_before_capitalized_values() {
        let old = manifest(
            "mainnet",
            Mode::Archive,
            Path::new("/data/mainnet"),
            Path::new("/data/identity"),
            &("node.example".to_owned(), 7900),
        )
        .replace("type: Mainnet", "type: mainnet")
        .replace("mode: Archive", "mode: archive");
        assert!(heika_node::config::Manifest::parse(&old).is_err());
        assert_eq!(saved_mode(&old), Some(Mode::Archive));
    }
}
