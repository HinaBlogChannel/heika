//! 画面。DB を持つ Worker を立て、REST のオリジンを渡して同期させ、進み具合を見せる。

use js_sys::Array;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use web_sys::{MessageEvent, Worker};

/// trunk が Worker のバイナリから作る読み込み用のスクリプト。ビルドごとの印を付けて、前の版をキャッシュから読まない
const WORKER_SCRIPT: &str = concat!("./worker_loader.js?v=", env!("NODE_WEB_BUILD"));
/// 入れたオリジンを覚えておく localStorage のキー
const ORIGINS_KEY: &str = "node-web/origins";
/// 画面に残す注意の数
const WARNINGS: usize = 5;

fn main() {
    leptos::mount::mount_to_body(App);
}

/// DB を持つ Worker のようす
#[derive(Clone, PartialEq)]
enum Phase {
    Starting,
    Waiting,
    Ready,
}

/// 同期の進み具合
#[derive(Clone, PartialEq, Default)]
struct Progress {
    network: String,
    height: f64,
    /// 確定した高さ。止まったあとは `None`
    target: Option<f64>,
    rate: f64,
    state_hash: String,
    size: f64,
    /// 確定した先の先端を追っている
    tip: bool,
}

/// バイト数を、読みやすい単位にする
fn bytes(value: f64) -> String {
    match value {
        value if value < 1024.0 => format!("{value:.0} B"),
        value if value < 1024.0 * 1024.0 => format!("{:.1} KiB", value / 1024.0),
        value if value < 1024.0 * 1024.0 * 1024.0 => format!("{:.1} MiB", value / 1024.0 / 1024.0),
        value => format!("{:.2} GiB", value / 1024.0 / 1024.0 / 1024.0),
    }
}

/// 3桁ごとに区切る
fn group(value: f64) -> String {
    let digits = format!("{:.0}", value.max(0.0));
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// 秒を、読みやすい単位にする
fn duration(seconds: f64) -> String {
    match seconds {
        seconds if !seconds.is_finite() => "—".into(),
        seconds if seconds < 60.0 => format!("{seconds:.0} 秒"),
        seconds if seconds < 3600.0 => format!("{:.0} 分", seconds / 60.0),
        seconds if seconds < 86400.0 => format!("{:.1} 時間", seconds / 3600.0),
        seconds => format!("{:.1} 日", seconds / 86400.0),
    }
}

fn storage() -> Option<web_sys::Storage> {
    window().local_storage().ok().flatten()
}

#[component]
fn App() -> impl IntoView {
    let phase = RwSignal::new(Phase::Starting);
    let running = RwSignal::new(false);
    let status = RwSignal::new(String::new());
    let progress = RwSignal::new(None::<Progress>);
    let warnings = RwSignal::new(Vec::<String>::new());
    let failure = RwSignal::new(None::<String>);
    let origins = RwSignal::new(
        storage()
            .and_then(|storage| storage.get_item(ORIGINS_KEY).ok().flatten())
            .unwrap_or_default(),
    );

    let worker = match Worker::new(WORKER_SCRIPT) {
        Ok(worker) => Some(worker),
        Err(error) => {
            failure.set(Some(format!("Worker を立てられません: {error:?}")));
            None
        }
    };
    if let Some(worker) = &worker {
        let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
            let message: Array = event.data().unchecked_into();
            let number = |index| message.get(index).as_f64().unwrap_or(0.0);
            let text = |index| message.get(index).as_string().unwrap_or_default();
            match text(0).as_str() {
                "waiting" => phase.set(Phase::Waiting),
                "ready" => phase.set(Phase::Ready),
                "status" => status.set(text(1)),
                "progress" => progress.set(Some(Progress {
                    network: text(1),
                    height: number(2),
                    target: message.get(3).as_f64(),
                    rate: number(4),
                    state_hash: text(5),
                    size: number(6),
                    tip: false,
                })),
                "tip" => progress.update(|progress| {
                    *progress = Some(Progress {
                        network: text(1),
                        height: number(2),
                        target: Some(number(3)),
                        rate: 0.0,
                        size: number(4),
                        state_hash: text(5),
                        tip: true,
                    });
                }),
                "warning" => warnings.update(|warnings| {
                    warnings.push(text(1));
                    if warnings.len() > WARNINGS {
                        warnings.remove(0);
                    }
                }),
                "imported" => {
                    running.set(false);
                    progress.set(None);
                    status.set(format!(
                        "{} の DB を読み込みました（先端の高さ {}）。「同期する」で、ここから続けます",
                        text(1),
                        group(number(2))
                    ));
                }
                "stopped" => {
                    running.set(false);
                    status.set("止めました".into());
                }
                _ => {
                    running.set(false);
                    failure.set(Some(text(1)));
                }
            }
        });
        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        // 画面があるあいだ Worker は動き続けるので、放さない
        onmessage.forget();
    }
    let worker = StoredValue::new_local(worker);
    let send = move |parts: &[JsValue]| {
        worker.with_value(|worker| {
            if let Some(worker) = worker {
                let _ = worker.post_message(&parts.iter().collect::<Array>());
            }
        });
    };

    let start = move |_| {
        let text = origins.get_untracked();
        if let Some(storage) = storage() {
            let _ = storage.set_item(ORIGINS_KEY, &text);
        }
        failure.set(None);
        warnings.set(Vec::new());
        running.set(true);
        send(&["sync".into(), text.into()]);
    };
    let import = move |event: web_sys::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        failure.set(None);
        warnings.set(Vec::new());
        running.set(true);
        status.set("DB を読み込んでいます".into());
        send(&["import".into(), file.into()]);
        input.set_value("");
    };
    let stop = move |_| {
        status.set("今の区切りを書いてから止めます…".into());
        send(&["stop".into()]);
    };

    view! {
        <main class="screen">
            <h1>"heika"</h1>
            <p class="lead">"ブラウザの中で、チェーンを確かめながら同期する"</p>
            <p class="hint">
                "公開されている REST からブロックを取り、Nemesis から順に、署名、難易度、VRF、状態のハッシュまで確かめて実行します。"
                "REST の答えは信じないので、どの REST から取っても、間違ったものは弾かれます。"
                "DB はブラウザの中（OPFS）に置き、閉じても続きから始めます。"
            </p>

            {move || match phase.get() {
                Phase::Starting => view! { <p class="state">"DB を用意しています…"</p> }.into_any(),
                Phase::Waiting => view! {
                    <section class="glass panel">
                        <p class="state">"ほかのタブが同期しています"</p>
                        <p class="hint">"そのタブを閉じると、ここが引き継ぎます。"</p>
                    </section>
                }.into_any(),
                Phase::Ready => view! {
                    <section class="glass panel">
                        <label class="field">
                            "REST のオリジン（1 行に 1 つ。取る区切りごとに順に使います）"
                            <textarea
                                rows="3"
                                spellcheck="false"
                                placeholder="https://example.com:3001"
                                prop:value=move || origins.get()
                                on:input=move |event| origins.set(event_target_value(&event))
                                disabled=move || running.get()
                            ></textarea>
                        </label>
                        <div class="row">
                            <Show
                                when=move || running.get()
                                fallback=move || view! { <button class="primary" on:click=start>"同期する"</button> }
                            >
                                <button on:click=stop>"止める"</button>
                            </Show>
                        </div>
                        <details class="import">
                            <summary>"手元のノードの DB から始める"</summary>
                            <p class="hint">
                                "heika のノードの DB（データのフォルダーの heika.redb）を読み込み、その先端から同期を続けます。"
                                "ライトの残し方の写し（heika experimental peer copy）が小さくて向いています。"
                                "読み込んだところまでの履歴は確かめずに信じるので、自分のノードの DB を使ってください。"
                                "続きのブロックが先端につながらなければ、同期で弾かれます。"
                            </p>
                            <input type="file" on:change=import disabled=move || running.get() />
                        </details>
                    </section>
                }.into_any(),
            }}

            <Show when=move || progress.get().is_some() || running.get() || failure.get().is_some() || !status.get().is_empty()>
                <section class="glass panel">
                    <p class="state">{move || status.get()}</p>
                    {move || progress.get().map(|progress| {
                        let remaining = progress.target.map(|target| (target - progress.height).max(0.0));
                        view! {
                            <dl class="facts">
                                <dt>"ネットワーク"</dt>
                                <dd>{progress.network.clone()}</dd>
                                <dt>{if progress.tip { "先端の高さ" } else { "確かめて書いた高さ" }}</dt>
                                <dd>{match progress.target {
                                    Some(target) => format!("{} / {}", group(progress.height), group(target)),
                                    None => group(progress.height),
                                }}</dd>
                                <Show when=move || !progress.tip>
                                    <dt>"速さ"</dt>
                                    <dd>{format!("{:.0} ブロック/秒", progress.rate)}</dd>
                                </Show>
                                <dt>"残り"</dt>
                                <dd>{match remaining {
                                    Some(blocks) if progress.tip => format!("先端を追っています（REST の先端まで {} ブロック）", group(blocks)),
                                    Some(0.0) => "追いつきました".to_owned(),
                                    Some(blocks) if progress.rate > 0.0 => format!("{} ブロック、およそ {}", group(blocks), duration(blocks / progress.rate)),
                                    Some(blocks) => format!("{} ブロック", group(blocks)),
                                    None => "—".to_owned(),
                                }}</dd>
                                <dt>{if progress.tip { "先端のブロック" } else { "StateHash" }}</dt>
                                <dd class="hash">
                                    <span class="verified">"確かめた"</span>
                                    " "
                                    {progress.state_hash.clone()}
                                </dd>
                                <dt>"DB の大きさ"</dt>
                                <dd>{bytes(progress.size)}</dd>
                            </dl>
                            {progress.target.map(|target| view! {
                                <progress max=target.to_string() value=progress.height.to_string()></progress>
                            })}
                        }
                    })}
                    {move || failure.get().map(|reason| view! {
                        <p class="state failed">"止まりました"</p>
                        <p class="hint path">{reason}</p>
                    })}
                    <Show when=move || !warnings.get().is_empty()>
                        <ul class="notes warnings">
                            <For each=move || warnings.get() key=|warning| warning.clone() let:warning>
                                <li class="path">{warning}</li>
                            </For>
                        </ul>
                    </Show>
                </section>
            </Show>

            <ul class="notes">
                <li>"確定した高さまではまとめて確かめながら進め、その先はネイティブの heika と同じ中核で、枝の取り替えもしながら先端を追います。"</li>
                <li>"別のタブでこのページを開くと、こちらを閉じるまで待ちます。"</li>
                <li>"DB はこのブラウザのこのサイトの中だけにあり、サイトのデータを消すと消えます。"</li>
            </ul>
        </main>
    }
}
