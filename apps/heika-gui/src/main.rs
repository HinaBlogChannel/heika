//! 画面。中身の計算はしないで、Tauri の `invoke` でアプリの本体（src-tauri）に頼み、返ってきたものを出すだけにする。
//! 秘密鍵は本体の中にしまい、ここには出さない。作ったばかりのニーモニックの単語だけは、紙に控えてもらうために出す。

use std::time::Duration;

use leptos::ev::SubmitEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// Tauri の `invoke`。tauri.conf.json の `withGlobalTauri` で `window.__TAURI__` に出ている
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], catch)]
    async fn invoke(command: &str, args: JsValue) -> Result<JsValue, JsValue>;

    /// クリップボードに書く。WebView の外には出さない
    #[wasm_bindgen(js_namespace = ["navigator", "clipboard"], js_name = writeText)]
    fn write_clipboard(text: &str) -> JsValue;

    type Date;
    #[wasm_bindgen(constructor)]
    fn new(milliseconds: f64) -> Date;
    #[wasm_bindgen(method, js_name = toLocaleString)]
    fn to_locale_string(this: &Date, locale: &str) -> String;
    #[wasm_bindgen(static_method_of = Date)]
    fn now() -> f64;
}

/// 本体のコマンドを呼ぶ。本体が返したエラーは文字列で届く。
/// 引数の名前は、Tauri が Rust の snake_case を JavaScript の camelCase で受け取るので、camelCase で渡す
async fn call<T: DeserializeOwned>(command: &str, args: impl Serialize) -> Result<T, String> {
    let args = serde_wasm_bindgen::to_value(&args).map_err(|error| error.to_string())?;
    let value = invoke(command, args)
        .await
        .map_err(|error| error.as_string().unwrap_or_else(|| format!("{error:?}")))?;
    serde_wasm_bindgen::from_value(value).map_err(|error| error.to_string())
}

/// 残高を確かめる。確かめられなかったら、本体が付けたわけの種類と一緒に返す
async fn check_balance(address: String) -> Result<BalanceView, BalanceFailure> {
    let args = serde_wasm_bindgen::to_value(&BalanceArgs { address })
        .map_err(|error| BalanceFailure::other(error.to_string()))?;
    match invoke("balance", args).await {
        Ok(value) => serde_wasm_bindgen::from_value(value)
            .map_err(|error| BalanceFailure::other(error.to_string())),
        Err(error) => Err(
            serde_wasm_bindgen::from_value(error.clone()).unwrap_or_else(|_| {
                BalanceFailure::other(error.as_string().unwrap_or_else(|| format!("{error:?}")))
            }),
        ),
    }
}

#[derive(Serialize)]
struct NoArgs {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateArgs {
    network: String,
    passphrase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    words: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

#[derive(Serialize)]
struct UnlockArgs {
    passphrase: String,
}

#[derive(Serialize)]
struct BalanceArgs {
    address: String,
}

#[derive(Serialize)]
struct SettingsArgs {
    settings: Settings,
}

/// 本体が覚えている設定
#[derive(Clone, Default, Serialize, Deserialize)]
struct Settings {
    rest: Option<String>,
    hide_amounts: bool,
    account: Option<String>,
}

/// 本体の `balance` が返す、確かめた残高
#[derive(Clone, Deserialize)]
struct BalanceView {
    on_chain: bool,
    height: String,
    block_hash: String,
    block_time: Option<f64>,
    rest: String,
    mosaics: Vec<MosaicView>,
}

#[derive(Clone, Deserialize)]
struct MosaicView {
    id: String,
    currency: bool,
    amount: Option<String>,
    raw: String,
}

/// 本体の `balance` が返す、確かめられなかったわけ
#[derive(Clone, Deserialize)]
struct BalanceFailure {
    kind: FailureKind,
    detail: String,
}

#[derive(Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Unreachable,
    Unreadable,
    WrongNetwork,
    Unsupported,
    Mismatch,
    Other,
}

impl BalanceFailure {
    fn other(detail: String) -> Self {
        Self {
            kind: FailureKind::Other,
            detail,
        }
    }
}

/// 本体の `about` が返すもの
#[derive(Clone, Deserialize)]
struct About {
    version: String,
    os: String,
    arch: String,
}

/// 本体の `start` が返す、最初に出す画面
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Start {
    Welcome,
    Unlock { path: String },
    Accounts,
}

/// 本体の `new_mnemonic` が返すもの
#[derive(Clone, Deserialize)]
struct NewMnemonic {
    words: Vec<String>,
    quiz: Vec<usize>,
}

#[derive(Clone, Deserialize)]
struct AccountView {
    label: String,
    network: String,
    source: String,
    address: String,
}

/// キーストアにしまう秘密を、どこから持ってきたか
#[derive(Clone)]
enum Source {
    /// 本体で作ったニーモニック。単語は本体が覚えている
    New,
    Words(String),
    PrivateKey(String),
}

#[derive(Clone)]
enum Screen {
    Loading,
    Welcome,
    ShowWords(NewMnemonic),
    Quiz(NewMnemonic),
    Restore,
    ImportKey,
    Passphrase(Source),
    Unlock(String),
    /// ここからはキーストアを開いたあと。メニューを出す
    Home,
    Accounts,
    Settings,
}

impl Screen {
    /// キーストアを開いたあとの画面か
    fn inside(&self) -> bool {
        matches!(self, Self::Home | Self::Accounts | Self::Settings)
    }
}

/// どの画面からも使うもの
#[derive(Clone, Copy)]
struct Ctx {
    screen: RwSignal<Screen>,
    error: RwSignal<Option<String>>,
    /// 本体の返事を待っているあいだは、ボタンを押せなくする
    busy: RwSignal<bool>,
    /// 開いているキーストアのアカウント
    accounts: RwSignal<Vec<AccountView>>,
    settings: RwSignal<Settings>,
}

impl Ctx {
    fn go(self, screen: Screen) {
        self.error.set(None);
        self.screen.set(screen);
    }

    /// 本体のコマンドを呼び、うまくいったら `then` に渡す。失敗したらエラーを出す
    fn run<T: DeserializeOwned + 'static>(
        self,
        command: &'static str,
        args: impl Serialize + 'static,
        then: impl FnOnce(T) + 'static,
    ) {
        self.error.set(None);
        self.busy.set(true);
        spawn_local(async move {
            let result = call(command, args).await;
            self.busy.set(false);
            match result {
                Ok(value) => then(value),
                Err(error) => self.error.set(Some(error)),
            }
        });
    }

    /// キーストアを開いたあと。アカウントと設定を覚えて、ホームに出る
    fn enter(self, accounts: Vec<AccountView>) {
        self.accounts.set(accounts);
        self.run("settings", NoArgs {}, move |settings| {
            self.settings.set(settings);
            self.go(Screen::Home);
        });
    }

    /// 設定を変えて、本体に覚えてもらう
    fn save(self, change: impl FnOnce(&mut Settings)) {
        let mut settings = self.settings.get_untracked();
        change(&mut settings);
        self.run("save_settings", SettingsArgs { settings }, move |saved| {
            self.settings.set(saved)
        });
    }

    /// ホームに出すアカウント。最後に選んだものがなければ、最初のもの
    fn current(self) -> Option<AccountView> {
        let accounts = self.accounts.get();
        let chosen = self.settings.get().account;
        accounts
            .iter()
            .find(|account| Some(&account.address) == chosen.as_ref())
            .or(accounts.first())
            .cloned()
    }

    /// 本体に、どの画面から始めるか聞く
    fn restart(self) {
        self.run("start", NoArgs {}, move |start| match start {
            Start::Welcome => self.go(Screen::Welcome),
            Start::Unlock { path } => self.go(Screen::Unlock(path)),
            Start::Accounts => {
                self.run("accounts", NoArgs {}, move |accounts| self.enter(accounts))
            }
        });
    }
}

fn main() {
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    let ctx = Ctx {
        screen: RwSignal::new(Screen::Loading),
        error: RwSignal::new(None),
        busy: RwSignal::new(false),
        accounts: RwSignal::new(Vec::new()),
        settings: RwSignal::new(Settings::default()),
    };
    ctx.restart();

    let (about, set_about) = signal(None::<Result<About, String>>);
    spawn_local(async move {
        set_about.set(Some(call("about", NoArgs {}).await));
    });

    let footer = move || match about.get() {
        None => String::new(),
        Some(Ok(about)) => format!(
            "heika-gui {}（{} / {}）",
            about.version, about.os, about.arch
        ),
        Some(Err(error)) => format!("本体とつながりません: {error}"),
    };
    view! {
        <div class="shell" class:inside=move || ctx.screen.with(Screen::inside)>
            {move || ctx.screen.with(Screen::inside).then(|| menu(ctx))}
            <main>
                <h1>"heika"</h1>
                // 画面が変わるたびに section を作り直して、ふわっと出す
                {move || view! { <section class="screen">{match ctx.screen.get() {
                    Screen::Loading => view! { <p class="lead">"本体に問い合わせています…"</p> }.into_any(),
                    Screen::Welcome => welcome(ctx).into_any(),
                    Screen::ShowWords(mnemonic) => show_words(ctx, mnemonic).into_any(),
                    Screen::Quiz(mnemonic) => quiz(ctx, mnemonic).into_any(),
                    Screen::Restore => restore(ctx).into_any(),
                    Screen::ImportKey => import_key(ctx).into_any(),
                    Screen::Passphrase(source) => passphrase(ctx, source).into_any(),
                    Screen::Unlock(path) => unlock(ctx, path).into_any(),
                    Screen::Home => home(ctx).into_any(),
                    Screen::Accounts => accounts_view(ctx).into_any(),
                    Screen::Settings => settings_view(ctx).into_any(),
                }}</section> }}
                {move || ctx.error.get().map(|error| view! { <p class="error">{error}</p> })}
                // 版はふだんの画面には出さず、設定と、開く前の画面にだけ出す。つながらないときはいつも出す
                {move || {
                    let quiet = matches!(ctx.screen.get(), Screen::Home | Screen::Accounts)
                        && matches!(about.get(), Some(Ok(_)));
                    (!quiet).then(|| view! { <footer>{footer}</footer> })
                }}
            </main>
        </div>
    }
}

/// キーストアを開いたあとのメニュー。スマホでは下のタブ、広い画面では左の列になる（style.css）
fn menu(ctx: Ctx) -> impl IntoView {
    let item = move |screen: Screen, label: &'static str, icon: &'static str| {
        let target = screen.clone();
        let active =
            move || std::mem::discriminant(&ctx.screen.get()) == std::mem::discriminant(&target);
        view! {
            <button class="item" class:active=active aria-label=label on:click=move |_| ctx.go(screen.clone())>
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d=icon /></svg>
                <span>{label}</span>
            </button>
        }
    };
    view! {
        <nav class="menu glass">
            <p class="brand">"heika"</p>
            {item(Screen::Home, "ホーム", ICON_HOME)}
            {item(Screen::Accounts, "アカウント", ICON_ACCOUNTS)}
            {item(Screen::Settings, "設定", ICON_SETTINGS)}
        </nav>
    }
}

// メニューのアイコン。24 の枠に、線だけで描く
const ICON_HOME: &str = "M4 11 12 4l8 7M6 9.5V20h12V9.5M10 20v-5h4v5";
const ICON_ACCOUNTS: &str = "M5 6h14v12H5zM5 10h14M8 14h4";
const ICON_SETTINGS: &str = "M4 7h10M18 7h2M4 17h4M12 17h8M16 5v4M10 15v4";
const ICON_EYE: &str =
    "M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12zM12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z";
const ICON_EYE_OFF: &str = "M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12zM4 20 20 4";
/// 確かめた残高に添える、チェックの入った盾
const ICON_VERIFIED: &str = "M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6l-7-3zM9 12l2 2 4-4";

fn welcome(ctx: Ctx) -> impl IntoView {
    let create = move |_| {
        ctx.run("new_mnemonic", NoArgs {}, move |mnemonic| {
            ctx.go(Screen::ShowWords(mnemonic))
        })
    };
    view! {
        <p class="lead">"はじめまして。財布をどう用意するか選んでください。"</p>
        <div class="choices">
            <button class="choice glass" on:click=create disabled=move || ctx.busy.get()>
                <span class="index">"01"</span>
                <span class="title">"新しく作る"</span>
                <span class="desc">"24個の英単語を作ります。紙に書いて控えてもらいます。"</span>
            </button>
            <button class="choice glass" on:click=move |_| ctx.go(Screen::Restore)>
                <span class="index">"02"</span>
                <span class="title">"単語から戻す"</span>
                <span class="desc">"ほかのウォレットで控えた単語から、同じアカウントを戻します。"</span>
            </button>
            <button class="quiet" on:click=move |_| ctx.go(Screen::ImportKey)>"秘密鍵を取り込む（くわしい人向け）"</button>
        </div>
    }
}

fn show_words(ctx: Ctx, mnemonic: NewMnemonic) -> impl IntoView {
    let written = RwSignal::new(false);
    let words = mnemonic
        .words
        .iter()
        .enumerate()
        .map(|(index, word)| view! { <li><span class="number">{index + 1}</span>{word.clone()}</li> })
        .collect_view();
    view! {
        <p class="lead">"この24個の単語を、順番どおりに紙に書いてください。"</p>
        <ol class="words glass">{words}</ol>
        <ul class="notes">
            <li>"この単語を知っている人は、誰でもあなたのお金を動かせます。人に見せないでください。"</li>
            <li>"パソコンが壊れたり、パスフレーズを忘れたりしたときに戻せるのは、この単語だけです。"</li>
            <li>"写真やメモ帳のファイルより、紙のほうが安全です。"</li>
        </ul>
        <label class="check">
            <input type="checkbox" bind:checked=written />
            "紙に書きました"
        </label>
        <div class="row">
            <button on:click=move |_| ctx.go(Screen::Welcome)>"やめる"</button>
            <button
                class="primary"
                disabled=move || !written.get()
                on:click=move |_| ctx.go(Screen::Quiz(mnemonic.clone()))
            >"次へ"</button>
        </div>
    }
}

fn quiz(ctx: Ctx, mnemonic: NewMnemonic) -> impl IntoView {
    let answers: Vec<RwSignal<String>> = mnemonic
        .quiz
        .iter()
        .map(|_| RwSignal::new(String::new()))
        .collect();
    let fields = mnemonic
        .quiz
        .iter()
        .zip(&answers)
        .map(|(position, answer)| {
            let answer = *answer;
            view! {
                <label class="field">
                    {format!("{} 番目の単語", position + 1)}
                    <input type="text" autocomplete="off" autocapitalize="off" spellcheck="false" bind:value=answer />
                </label>
            }
        })
        .collect_view();
    let back = mnemonic.clone();
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let correct = mnemonic
            .quiz
            .iter()
            .zip(&answers)
            .all(|(position, answer)| {
                answer.get_untracked().trim().to_lowercase() == mnemonic.words[*position]
            });
        if correct {
            ctx.go(Screen::Passphrase(Source::New));
        } else {
            ctx.error
                .set(Some("違う単語があります。紙を見直してください".to_owned()));
        }
    };
    view! {
        <p class="lead">"書き写せているか確かめます。紙を見て答えてください。"</p>
        <form on:submit=submit>
            {fields}
            <div class="row">
                <button type="button" on:click=move |_| ctx.go(Screen::ShowWords(back.clone()))>"単語をもう一度見る"</button>
                <button type="submit" class="primary">"次へ"</button>
            </div>
        </form>
    }
}

fn restore(ctx: Ctx) -> impl IntoView {
    let words = RwSignal::new(String::new());
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let text = words.get_untracked();
        let count = text.split_whitespace().count();
        if ![12, 15, 18, 21, 24].contains(&count) {
            ctx.error
                .set(Some(format!("単語が {count} 個です。12個か24個のはずです")));
            return;
        }
        ctx.go(Screen::Passphrase(Source::Words(text)));
    };
    view! {
        <p class="lead">"控えた単語を、順番どおりに空白で区切って入れてください。"</p>
        <form on:submit=submit>
            <textarea class="secret" rows="5" autocomplete="off" autocapitalize="off" spellcheck="false" bind:value=words></textarea>
            <div class="row">
                <button type="button" on:click=move |_| ctx.go(Screen::Welcome)>"戻る"</button>
                <button type="submit" class="primary">"次へ"</button>
            </div>
        </form>
    }
}

fn import_key(ctx: Ctx) -> impl IntoView {
    let key = RwSignal::new(String::new());
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        ctx.go(Screen::Passphrase(Source::PrivateKey(key.get_untracked())));
    };
    view! {
        <p class="lead">"秘密鍵（64文字の16進）を入れてください。"</p>
        <form on:submit=submit>
            <input type="password" class="secret" autocomplete="off" bind:value=key />
            <div class="row">
                <button type="button" on:click=move |_| ctx.go(Screen::Welcome)>"戻る"</button>
                <button type="submit" class="primary">"次へ"</button>
            </div>
        </form>
    }
}

fn passphrase(ctx: Ctx, source: Source) -> impl IntoView {
    let network = RwSignal::new("testnet".to_owned());
    let first = RwSignal::new(String::new());
    let second = RwSignal::new(String::new());
    let backup = match source {
        Source::PrivateKey(_) => "秘密鍵の控え",
        _ => "紙に書いた単語",
    };
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let passphrase = first.get_untracked();
        if passphrase.is_empty() {
            ctx.error
                .set(Some("パスフレーズを入れてください".to_owned()));
            return;
        }
        if passphrase != second.get_untracked() {
            ctx.error
                .set(Some("2回のパスフレーズが違います".to_owned()));
            return;
        }
        let mut args = CreateArgs {
            network: network.get_untracked(),
            passphrase,
            words: None,
            private_key: None,
        };
        let command = match source.clone() {
            Source::New => "create_wallet",
            Source::Words(words) => {
                args.words = Some(words);
                "restore_wallet"
            }
            Source::PrivateKey(key) => {
                args.private_key = Some(key);
                "import_private_key"
            }
        };
        ctx.run(command, args, move |accounts| ctx.enter(accounts));
    };
    view! {
        <p class="lead">"このパソコンにしまうときのパスフレーズを決めてください。"</p>
        <p class="hint">{format!("忘れると、{backup}からしか戻せません。")}</p>
        <form on:submit=submit>
            <label class="field">
                "ネットワーク"
                <select bind:value=network>
                    <option value="testnet">"テストネット"</option>
                    <option value="mainnet">"メインネット"</option>
                </select>
            </label>
            <label class="field">
                "パスフレーズ"
                <input type="password" autocomplete="new-password" bind:value=first />
            </label>
            <label class="field">
                "もう一度"
                <input type="password" autocomplete="new-password" bind:value=second />
            </label>
            <div class="row">
                <button type="button" on:click=move |_| ctx.go(Screen::Welcome)>"最初に戻る"</button>
                <button type="submit" class="primary" disabled=move || ctx.busy.get()>
                    {move || if ctx.busy.get() { "しまっています…" } else { "しまう" }}
                </button>
            </div>
        </form>
    }
}

fn unlock(ctx: Ctx, path: String) -> impl IntoView {
    let passphrase = RwSignal::new(String::new());
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let args = UnlockArgs {
            passphrase: passphrase.get_untracked(),
        };
        ctx.run("unlock", args, move |accounts| ctx.enter(accounts));
    };
    view! {
        <p class="lead">"パスフレーズを入れて、キーストアを開いてください。"</p>
        <p class="hint path">{path}</p>
        <form on:submit=submit>
            <input type="password" autocomplete="current-password" bind:value=passphrase />
            <div class="row">
                <button type="submit" class="primary" disabled=move || ctx.busy.get()>
                    {move || if ctx.busy.get() { "開いています…" } else { "開く" }}
                </button>
            </div>
        </form>
    }
}

fn accounts_view(ctx: Ctx) -> impl IntoView {
    let items = move || {
        let current = ctx.current().map(|account| account.address);
        ctx.accounts
            .get()
            .into_iter()
            .map(|account| {
                let address = account.address.clone();
                let selected = Some(&account.address) == current.as_ref();
                let choose = move |_| {
                    let address = address.clone();
                    ctx.save(move |settings| settings.account = Some(address));
                    ctx.go(Screen::Home);
                };
                view! {
                    <li>
                        <button class="card glass" class:selected=selected on:click=choose>
                            <span class="row">
                                <strong>{account.label}</strong>
                                <span class="badge">{account.network}</span>
                                <span class="hint">{account.source}</span>
                            </span>
                            <span class="address">{spaced(&account.address)}</span>
                        </button>
                    </li>
                }
            })
            .collect_view()
    };
    view! {
        <p class="lead">"ホームに出すアカウントを選んでください。"</p>
        <ul class="accounts">{items}</ul>
    }
}

/// 残高を確かめているところ
#[derive(Clone)]
enum Check {
    Loading,
    /// 問い合わせる REST を決めていない
    NoRest,
    Done(BalanceView),
    /// 確かめられなかった。数字は出さない
    Failed(BalanceFailure),
}

/// ホーム。選んでいるアカウントの残高
fn home(ctx: Ctx) -> impl IntoView {
    match ctx.current() {
        Some(account) => balance_view(ctx, account).into_any(),
        None => view! { <p class="lead">"アカウントがありません。"</p> }.into_any(),
    }
}

fn balance_view(ctx: Ctx, account: AccountView) -> impl IntoView {
    let check = RwSignal::new(Check::Loading);
    let address = account.address.clone();
    let refresh = move || {
        let address = address.clone();
        if ctx.settings.get_untracked().rest.is_none() {
            check.set(Check::NoRest);
            return;
        }
        check.set(Check::Loading);
        spawn_local(async move {
            check.set(match check_balance(address).await {
                Ok(balance) => Check::Done(balance),
                Err(error) => Check::Failed(error),
            });
        });
    };
    refresh();
    let copied = RwSignal::new(false);
    let copy = {
        let address = account.address.clone();
        move |_| {
            write_clipboard(&address);
            copied.set(true);
            set_timeout(move || copied.set(false), Duration::from_secs(2));
        }
    };
    let hidden = move || ctx.settings.get().hide_amounts;
    let toggle = move |_| ctx.save(|settings| settings.hide_amounts = !settings.hide_amounts);
    view! {
        <div class="row heading">
            <button class="quiet account" on:click=move |_| ctx.go(Screen::Accounts)>
                <strong>{account.label.clone()}</strong>
            </button>
            <span class="badge">{account.network.clone()}</span>
            <button
                class="quiet eye"
                aria-label=move || if hidden() { "金額を出す" } else { "金額を隠す" }
                on:click=toggle
            >
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d=move || if hidden() { ICON_EYE_OFF } else { ICON_EYE } /></svg>
            </button>
        </div>
        <p class="address">
            {spaced(&account.address)}
            <button class="quiet copy" on:click=copy>{move || if copied.get() { "コピーしました" } else { "コピー" }}</button>
        </p>
        {move || match check.get() {
            Check::Loading => view! {
                <div class="balance">
                    <p class="amount pending">"確かめています…"</p>
                    <p class="hint">"ブロックの署名を確かめ、状態の経路をたどっています。"</p>
                </div>
            }.into_any(),
            Check::NoRest => view! {
                <div class="balance">
                    <p class="lead">"残高を問い合わせる REST を、まだ決めていません。"</p>
                    <button class="primary" on:click=move |_| ctx.go(Screen::Settings)>"設定する"</button>
                </div>
            }.into_any(),
            Check::Failed(failure) => failed(ctx, failure, &account.network).into_any(),
            Check::Done(balance) => verified(balance, hidden()).into_any(),
        }}
        <div class="row">
            <button class="primary" on:click=move |_| refresh() disabled=move || matches!(check.get(), Check::Loading)>"確かめ直す"</button>
        </div>
    }
}

/// 確かめられなかったとき。何が起きて、何をすればいいかを出し、元のエラーはくわしくに回す
fn failed(ctx: Ctx, failure: BalanceFailure, network: &str) -> impl IntoView {
    let (title, advice) = match failure.kind {
        FailureKind::Unreachable => (
            "REST につながりませんでした",
            "設定の URL が合っているか、ネットにつながっているかを見てください。少し待って確かめ直すと、通ることもあります。".to_owned(),
        ),
        FailureKind::Unreadable => (
            "REST の答えを読めませんでした",
            "設定の URL が、Symbol の REST（ふつうはポート 3001）を指しているかを見てください。".to_owned(),
        ),
        FailureKind::WrongNetwork => (
            "ネットワークが違います",
            format!("このアカウントは {network} のものですが、設定の REST は別のネットワークのものです。{network} の REST にしてください。"),
        ),
        FailureKind::Unsupported => (
            "この REST では確かめられません",
            "この REST のノードは、残高を確かめるのに要る状態のハッシュを出していません。別の REST にしてください。".to_owned(),
        ),
        FailureKind::Mismatch => (
            "REST の答えが、ブロックと合いませんでした",
            "何度か取り直しても合いませんでした。この REST の答えは信じないほうが安全です。別の REST を試してください。".to_owned(),
        ),
        FailureKind::Other => ("確かめられませんでした", String::new()),
    };
    let settings = failure.kind != FailureKind::Other;
    view! {
        <div class="balance">
            <p class="stamp failed">{title}</p>
            <p class="hint">{format!("{advice}確かめられない数字は出しません。")}</p>
            {settings.then(|| view! {
                <button on:click=move |_| ctx.go(Screen::Settings)>"設定を開く"</button>
            })}
            <details>
                <summary>"くわしく"</summary>
                <p class="address small">{failure.detail}</p>
            </details>
        </div>
    }
}

/// 確かめた残高と、何を確かめて何を信じたか
/// `hidden` なら、金額の代わりに伏せ字を出す
fn verified(balance: BalanceView, hidden: bool) -> impl IntoView {
    let currency = balance.mosaics.iter().find(|mosaic| mosaic.currency);
    // 通貨を持っていなければ 0。XYM の可分性は 6
    let amount = currency
        .and_then(|mosaic| mosaic.amount.clone())
        .unwrap_or_else(|| "0.000000".to_owned());
    let (whole, fraction) = match amount.split_once('.') {
        _ if hidden => (MASK.to_owned(), String::new()),
        Some((whole, fraction)) => (group(whole), format!(".{fraction}")),
        None => (group(&amount), String::new()),
    };
    // 定義の期限が切れてもうチェーンにないモザイクは、使えないので畳んで奥にしまう。
    // 小数点の位置もわからないので、いちばん小さい単位の数のまま出す
    let (others, expired): (Vec<_>, Vec<_>) = balance
        .mosaics
        .iter()
        .filter(|mosaic| !mosaic.currency)
        .partition(|mosaic| mosaic.amount.is_some());
    let row = |mosaic: &MosaicView| {
        let value = match &mosaic.amount {
            _ if hidden => MASK.to_owned(),
            Some(amount) => grouped(amount),
            None => group(&mosaic.raw),
        };
        view! {
            <li>
                <span class="id">{format!("0x{}", mosaic.id)}</span>
                <span class="value">{value}</span>
            </li>
        }
    };
    let expired = (!expired.is_empty()).then(|| {
        view! {
            <details class="expired">
                <summary>{format!("期限の切れたモザイク {} 件", expired.len())}</summary>
                <p class="hint note">"定義の期限が切れて、もうチェーンにないモザイクです。送ることも受け取ることもできません。小数点の位置がわからないので、いちばん小さい単位の数のまま出しています。"</p>
                <ul class="mosaics">{expired.into_iter().map(row).collect_view()}</ul>
            </details>
        }
    });
    let others = others.into_iter().map(row).collect_view();
    let when = balance.block_time.map(|time| {
        let minutes = ((Date::now() - time) / 60_000.0).max(0.0) as u64;
        let ago = if minutes == 0 {
            "1分以内".to_owned()
        } else {
            format!("{minutes}分前")
        };
        format!("{}（{ago}）", Date::new(time).to_locale_string("ja-JP"))
    });
    let (stamp, what) = if balance.on_chain {
        (
            "ブロックの署名から、この残高まで確かめました",
            "アカウントと、持っているモザイクの定義が、状態の経路でその根につながること",
        )
    } else {
        (
            "ブロックの署名から、まだ載っていないことまで確かめました",
            "アカウントが、状態の木にないこと",
        )
    };
    view! {
        <div class="balance">
            <p class="amount">
                <span class="whole">{whole}</span>
                <span class="fraction">{fraction}</span>
                <span class="unit">"XYM"</span>
                <span class="mark" role="img" title=stamp aria-label=stamp>
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d=ICON_VERIFIED /></svg>
                </span>
            </p>
            {(!balance.on_chain).then(|| view! {
                <p class="hint">"まだチェーンに載っていないアドレスです。一度も受け取っていなければ、こうなります。"</p>
            })}
            <ul class="mosaics">{others}</ul>
            {expired}
        </div>
        <div class="verified glass">
            <p class="hint">{format!("高さ {} のブロック", group(&balance.height))}{when.map(|when| format!(" ・ {when}"))}</p>
            <details>
                <summary>"くわしく"</summary>
                <p class="stamp">{stamp}</p>
                <p class="label">"確かめたこと"</p>
                <ul class="notes">
                    <li>"ブロックの署名と、9本の根から求めた StateHash"</li>
                    <li>{what}</li>
                </ul>
                <p class="label">"信じていること"</p>
                <ul class="notes">
                    <li>{format!("このブロックが正しいチェーンのものであること。そこは {} を信じています", balance.rest)}</li>
                </ul>
                <p class="label">"ブロックのハッシュ"</p>
                <p class="address small">{balance.block_hash}</p>
            </details>
        </div>
    }
}

/// アドレスを6文字ずつ区切って読みやすくする。コピーするのは区切らないもの
fn spaced(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    chars
        .chunks(6)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// 隠した金額
const MASK: &str = "••••••";

/// 整数の部分を3桁ごとに区切る
fn group(digits: &str) -> String {
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// 小数点のある量の、整数の部分を区切る
fn grouped(amount: &str) -> String {
    match amount.split_once('.') {
        Some((whole, fraction)) => format!("{}.{fraction}", group(whole)),
        None => group(amount),
    }
}

fn settings_view(ctx: Ctx) -> impl IntoView {
    let rest = RwSignal::new(ctx.settings.get_untracked().rest.unwrap_or_default());
    let saved = RwSignal::new(false);
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let value = rest.get_untracked();
        ctx.save(move |settings| settings.rest = Some(value));
        saved.set(true);
    };
    let close = move |_| ctx.run("lock", NoArgs {}, move |()| ctx.restart());
    view! {
        <p class="lead">"残高を問い合わせる REST"</p>
        <p class="hint">
            "残高は、この REST から取ったものを、ブロックの署名と StateHash まで確かめてから出します。"
            "ただ、そのブロックが正しいチェーンのものかどうかは、この REST を信じることになります。"
            "自分のノードか、信じられる人のノードにしてください。"
        </p>
        <form on:submit=submit>
            <label class="field">
                "URL"
                <input type="url" placeholder="https://ホスト:3001" autocomplete="off" autocapitalize="off" spellcheck="false" bind:value=rest on:input=move |_| saved.set(false) />
            </label>
            <div class="row">
                <button type="submit" class="primary" disabled=move || ctx.busy.get()>"決める"</button>
                {move || (saved.get() && !ctx.busy.get() && ctx.error.get().is_none()).then(|| view! { <span class="hint">"覚えました"</span> })}
            </div>
        </form>
        <p class="lead section">"キーストア"</p>
        <p class="hint">"閉じると、もう一度パスフレーズを聞きます。"</p>
        <div class="row">
            <button on:click=close>"閉じる"</button>
        </div>
    }
}
