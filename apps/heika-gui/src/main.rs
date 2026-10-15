//! 画面。中身の計算はしないで、Tauri の `invoke` でアプリの本体（src-tauri）に頼み、返ってきたものを出すだけにする。
//! 秘密鍵は本体の中で作って捨て、ここには公開してよいものしか来ない。

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

/// 本体のコマンドを呼ぶ。本体が返したエラーは文字列で届く
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
struct NewAddressArgs {
    network: String,
}

/// 本体の `about` が返すもの
#[derive(Clone, Deserialize)]
struct About {
    version: String,
    os: String,
    arch: String,
}

fn main() {
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    let (about, set_about) = signal(None::<Result<About, String>>);
    spawn_local(async move {
        set_about.set(Some(call("about", NoArgs {}).await));
    });

    let (network, set_network) = signal("testnet".to_owned());
    let (address, set_address) = signal(None::<Result<String, String>>);
    let generate = move |_| {
        let network = network.get_untracked();
        spawn_local(async move {
            set_address.set(Some(call("new_address", NewAddressArgs { network }).await));
        });
    };

    view! {
        <main>
            <h1>"heika"</h1>
            <p class="lead">"GUI のたたき台。画面は WebView、計算は Rust の本体でしています。"</p>
            <section class="card">
                <div class="row">
                    <select on:change=move |event| set_network.set(event_target_value(&event))>
                        <option value="testnet" selected>"テストネット"</option>
                        <option value="mainnet">"メインネット"</option>
                    </select>
                    <button class="primary" on:click=generate>"アドレスを作ってみる"</button>
                </div>
                {move || match address.get() {
                    None => view! { <p class="lead">"秘密鍵は本体の中で作って、すぐ捨てます。"</p> }.into_any(),
                    Some(Ok(address)) => view! { <p class="address">{address}</p> }.into_any(),
                    Some(Err(error)) => view! { <p class="error">{error}</p> }.into_any(),
                }}
            </section>
            <footer>
                {move || match about.get() {
                    None => "本体に問い合わせています…".to_owned(),
                    Some(Ok(about)) => format!("heika-gui {}（{} / {}）", about.version, about.os, about.arch),
                    Some(Err(error)) => format!("本体とつながりません: {error}"),
                }}
            </footer>
        </main>
    }
}
