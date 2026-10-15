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

    /// 本体に、どの画面から始めるか聞く
    fn restart(self) {
        self.run("start", NoArgs {}, move |start| match start {
            Start::Welcome => self.go(Screen::Welcome),
            Start::Unlock { path } => self.go(Screen::Unlock(path)),
            Start::Accounts => self.run("accounts", NoArgs {}, move |accounts| {
                self.go(Screen::Accounts(accounts))
            }),
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
            {move || match ctx.screen.get() {
                Screen::Loading => view! { <p class="lead">"本体に問い合わせています…"</p> }.into_any(),
                Screen::Welcome => welcome(ctx).into_any(),
                Screen::ShowWords(mnemonic) => show_words(ctx, mnemonic).into_any(),
                Screen::Quiz(mnemonic) => quiz(ctx, mnemonic).into_any(),
                Screen::Restore => restore(ctx).into_any(),
                Screen::ImportKey => import_key(ctx).into_any(),
                Screen::Passphrase(source) => passphrase(ctx, source).into_any(),
                Screen::Unlock(path) => unlock(ctx, path).into_any(),
                Screen::Accounts(accounts) => accounts_view(ctx, accounts).into_any(),
            }}
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
            <button class="primary" on:click=create disabled=move || ctx.busy.get()>"新しく作る"</button>
            <p class="hint">"24個の英単語を作ります。紙に書いて控えてもらいます。"</p>
            <button on:click=move |_| ctx.go(Screen::Restore)>"単語から戻す"</button>
            <p class="hint">"ほかのウォレットで控えた単語から、同じアカウントを戻します。"</p>
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
        <ol class="words">{words}</ol>
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
    let items = accounts
        .into_iter()
        .map(|account| {
            view! {
                <li class="card">
                    <div class="row">
                        <strong>{account.label}</strong>
                        <span class="badge">{account.network}</span>
                        <span class="hint">{account.source}</span>
                    </div>
                    <p class="address">{account.address}</p>
                </li>
            }
        })
        .collect_view();
    let close = move |_| ctx.run("lock", NoArgs {}, move |()| ctx.restart());
    view! {
        <ul class="accounts">{items}</ul>
        <div class="row">
            <button on:click=close>"閉じる"</button>
        </div>
    }
}
