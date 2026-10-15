//! 画面。中身の計算はしないで、Tauri の `invoke` でアプリの本体（src-tauri）に頼み、返ってきたものを出すだけにする。
//! 秘密鍵は本体の中にしまい、ここには出さない。作ったばかりのニーモニックの単語だけは、紙に控えてもらうために出す。

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
struct RestArgs {
    rest: String,
}

/// 本体の `settings` が返すもの
#[derive(Clone, Deserialize)]
struct Settings {
    rest: Option<String>,
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
    Accounts(Vec<AccountView>),
    Balance(AccountView),
    /// 決めたら戻る画面
    Settings(Box<Screen>),
}

/// どの画面からも使うもの
#[derive(Clone, Copy)]
struct Ctx {
    screen: RwSignal<Screen>,
    error: RwSignal<Option<String>>,
    /// 本体の返事を待っているあいだは、ボタンを押せなくする
    busy: RwSignal<bool>,
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

    /// 開いているキーストアのアカウントの一覧に戻る
    fn accounts(self) {
        self.run("accounts", NoArgs {}, move |accounts| {
            self.go(Screen::Accounts(accounts))
        });
    }

    /// 本体に、どの画面から始めるか聞く
    fn restart(self) {
        self.run("start", NoArgs {}, move |start| match start {
            Start::Welcome => self.go(Screen::Welcome),
            Start::Unlock { path } => self.go(Screen::Unlock(path)),
            Start::Accounts => self.accounts(),
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
    };
    ctx.restart();

    let (about, set_about) = signal(None::<Result<About, String>>);
    spawn_local(async move {
        set_about.set(Some(call("about", NoArgs {}).await));
    });

    view! {
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
                Screen::Accounts(accounts) => accounts_view(ctx, accounts).into_any(),
                Screen::Balance(account) => balance_view(ctx, account).into_any(),
                Screen::Settings(back) => settings_view(ctx, *back).into_any(),
            }}</section> }}
            {move || ctx.error.get().map(|error| view! { <p class="error">{error}</p> })}
            <footer>
                {move || match about.get() {
                    None => String::new(),
                    Some(Ok(about)) => format!("heika-gui {}（{} / {}）", about.version, about.os, about.arch),
                    Some(Err(error)) => format!("本体とつながりません: {error}"),
                }}
            </footer>
        </main>
    }
}

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
        ctx.run(command, args, move |accounts| {
            ctx.go(Screen::Accounts(accounts))
        });
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
        ctx.run("unlock", args, move |accounts| {
            ctx.go(Screen::Accounts(accounts))
        });
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

fn accounts_view(ctx: Ctx, accounts: Vec<AccountView>) -> impl IntoView {
    let back = accounts.clone();
    let items = accounts
        .into_iter()
        .map(|account| {
            let open = account.clone();
            view! {
                <li>
                    <button class="card glass" on:click=move |_| ctx.go(Screen::Balance(open.clone()))>
                        <span class="row">
                            <strong>{account.label}</strong>
                            <span class="badge">{account.network}</span>
                            <span class="hint">{account.source}</span>
                        </span>
                        <span class="address">{account.address}</span>
                    </button>
                </li>
            }
        })
        .collect_view();
    let close = move |_| ctx.run("lock", NoArgs {}, move |()| ctx.restart());
    view! {
        <p class="lead">"アカウントを選ぶと、残高を確かめます。"</p>
        <ul class="accounts">{items}</ul>
        <div class="row">
            <button on:click=close>"閉じる"</button>
            <button on:click=move |_| ctx.go(Screen::Settings(Box::new(Screen::Accounts(back.clone()))))>"設定"</button>
        </div>
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
    Failed(String),
}

fn balance_view(ctx: Ctx, account: AccountView) -> impl IntoView {
    let check = RwSignal::new(Check::Loading);
    let address = account.address.clone();
    let refresh = move || {
        let address = address.clone();
        check.set(Check::Loading);
        spawn_local(async move {
            let next = match call::<Settings>("settings", NoArgs {}).await {
                Ok(Settings { rest: None }) => Check::NoRest,
                Ok(_) => match call("balance", BalanceArgs { address }).await {
                    Ok(balance) => Check::Done(balance),
                    Err(error) => Check::Failed(error),
                },
                Err(error) => Check::Failed(error),
            };
            check.set(next);
        });
    };
    refresh();
    let copied = RwSignal::new(false);
    let copy = {
        let address = account.address.clone();
        move |_| {
            write_clipboard(&address);
            copied.set(true);
        }
    };
    let settings = {
        let account = account.clone();
        move |_| ctx.go(Screen::Settings(Box::new(Screen::Balance(account.clone()))))
    };
    view! {
        <div class="row heading">
            <strong>{account.label.clone()}</strong>
            <span class="badge">{account.network.clone()}</span>
        </div>
        <p class="address">
            {account.address.clone()}
            <button class="quiet copy" on:click=copy>{move || if copied.get() { "写しました" } else { "写す" }}</button>
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
                    <button class="primary" on:click=settings.clone()>"設定する"</button>
                </div>
            }.into_any(),
            Check::Failed(error) => view! {
                <div class="balance">
                    <p class="amount pending">"確かめられませんでした"</p>
                    <p class="hint">"確かめられない数字は出しません。"</p>
                    <p class="error">{error}</p>
                </div>
            }.into_any(),
            Check::Done(balance) => verified(balance).into_any(),
        }}
        <div class="row">
            <button on:click=move |_| ctx.accounts()>"戻る"</button>
            <button class="primary" on:click=move |_| refresh() disabled=move || matches!(check.get(), Check::Loading)>"確かめ直す"</button>
        </div>
    }
}

/// 確かめた残高と、何を確かめて何を信じたか
fn verified(balance: BalanceView) -> impl IntoView {
    let currency = balance.mosaics.iter().find(|mosaic| mosaic.currency);
    // 通貨を持っていなければ 0。XYM の可分性は 6
    let amount = currency
        .and_then(|mosaic| mosaic.amount.clone())
        .unwrap_or_else(|| "0.000000".to_owned());
    let (whole, fraction) = match amount.split_once('.') {
        Some((whole, fraction)) => (group(whole), format!(".{fraction}")),
        None => (group(&amount), String::new()),
    };
    let others = balance
        .mosaics
        .iter()
        .filter(|mosaic| !mosaic.currency)
        .map(|mosaic| {
            let value = match &mosaic.amount {
                Some(amount) => grouped(amount),
                // 定義がもうなく、小数点の位置がわからない
                None => format!("{}（桁不明）", group(&mosaic.raw)),
            };
            view! {
                <li>
                    <span class="id">{format!("0x{}", mosaic.id)}</span>
                    <span class="value">{value}</span>
                </li>
            }
        })
        .collect_view();
    let when = balance.block_time.map(|time| {
        let minutes = ((Date::now() - time) / 60_000.0).max(0.0) as u64;
        let ago = if minutes == 0 {
            "1分以内".to_owned()
        } else {
            format!("{minutes}分前")
        };
        format!("{}（{ago}）", Date::new(time).to_locale_string("ja-JP"))
    });
    let what = if balance.on_chain {
        "アカウントと、持っているモザイクの定義が、状態の経路でその根につながること"
    } else {
        "アカウントが、状態の木にないこと"
    };
    view! {
        <div class="balance">
            <p class="amount">
                <span class="whole">{whole}</span>
                <span class="fraction">{fraction}</span>
                <span class="unit">"XYM"</span>
            </p>
            {(!balance.on_chain).then(|| view! {
                <p class="hint">"まだチェーンに載っていないアドレスです。一度も受け取っていなければ、こうなります。"</p>
            })}
            <ul class="mosaics">{others}</ul>
        </div>
        <div class="verified glass">
            <p class="stamp">"確かめました"</p>
            <p class="hint">{format!("高さ {} のブロック", group(&balance.height))}{when.map(|when| format!(" ・ {when}"))}</p>
            <details>
                <summary>"くわしく"</summary>
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

fn settings_view(ctx: Ctx, back: Screen) -> impl IntoView {
    let rest = RwSignal::new(String::new());
    spawn_local(async move {
        if let Ok(Settings {
            rest: Some(current),
        }) = call::<Settings>("settings", NoArgs {}).await
        {
            rest.set(current);
        }
    });
    let back_after_save = back.clone();
    let submit = move |event: SubmitEvent| {
        event.prevent_default();
        let back = back_after_save.clone();
        let args = RestArgs {
            rest: rest.get_untracked(),
        };
        ctx.run("set_rest", args, move |_: Settings| ctx.go(back));
    };
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
                <input type="url" placeholder="https://ホスト:3001" autocomplete="off" autocapitalize="off" spellcheck="false" bind:value=rest />
            </label>
            <div class="row">
                <button type="button" on:click=move |_| ctx.go(back.clone())>"戻る"</button>
                <button type="submit" class="primary" disabled=move || ctx.busy.get()>"決める"</button>
            </div>
        </form>
    }
}
