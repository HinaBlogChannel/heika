//! 画面。先頭の文字を受け取り、コアの数だけ Worker を立てて探させ、試した数と見つかったアドレスを出す。

use js_sys::Array;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use web_sys::{MessageEvent, Worker};
use web_vanitygen::{check_prefix, expected_attempts};

/// trunk が Worker のバイナリから作る読み込み用のスクリプト
const WORKER_SCRIPT: &str = "./worker_loader.js";

fn main() {
    leptos::mount::mount_to_body(App);
}

fn now() -> f64 {
    window()
        .performance()
        .map_or(0.0, |performance| performance.now())
}

/// 3桁ごとに区切る
fn group(value: f64) -> String {
    let digits = format!("{:.0}", value.max(0.0));
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
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
        seconds if seconds < 86400.0 * 365.0 => format!("{:.1} 日", seconds / 86400.0),
        seconds => format!("{} 年", group(seconds / 86400.0 / 365.0)),
    }
}

#[component]
fn App() -> impl IntoView {
    let prefix = RwSignal::new(String::from("NA"));
    let running = RwSignal::new(false);
    let tried = RwSignal::new(0_u64);
    let started = RwSignal::new(0.0_f64);
    let elapsed = RwSignal::new(0.0_f64);
    let found = RwSignal::new(None::<(String, String)>);
    // 探しはじめたときの先頭の文字。見つかったアドレスの、一致したところを目立たせるのに使う
    let searched = RwSignal::new(String::new());
    let failure = RwSignal::new(None::<String>);
    let workers = StoredValue::new_local(Vec::<Worker>::new());
    let cores = window().navigator().hardware_concurrency().max(1.0) as usize;

    let stop = move || {
        workers.update_value(|workers| {
            for worker in workers.drain(..) {
                worker.terminate();
            }
        });
        running.set(false);
    };

    let start = move || {
        stop();
        let prefix = prefix.get_untracked();
        if let Err(message) = check_prefix(&prefix) {
            failure.set(Some(message));
            return;
        }
        failure.set(None);
        found.set(None);
        searched.set(prefix.clone());
        tried.set(0);
        started.set(now());
        elapsed.set(0.0);
        for _ in 0..cores {
            let worker = match Worker::new(WORKER_SCRIPT) {
                Ok(worker) => worker,
                Err(error) => {
                    failure.set(Some(format!("Worker を立てられません: {error:?}")));
                    stop();
                    return;
                }
            };
            let sender = worker.clone();
            let prefix = prefix.clone();
            let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
                let data = event.data();
                // WASM を読み終えた Worker に、先頭の文字を渡して探させる
                if data.as_string().as_deref() == Some("ready") {
                    if sender.post_message(&JsValue::from_str(&prefix)).is_err() {
                        failure.set(Some("Worker に先頭の文字を渡せません".into()));
                        stop();
                    }
                    return;
                }
                if let Some(count) = data.as_f64() {
                    tried.update(|tried| *tried += count as u64);
                    elapsed.set((now() - started.get_untracked()) / 1000.0);
                    return;
                }
                let message: Array = data.unchecked_into();
                let text = |index| message.get(index).as_string().unwrap_or_default();
                match text(0).as_str() {
                    "found" => found.set(Some((text(1), text(2)))),
                    _ => failure.set(Some(format!("{:?}", message.get(1)))),
                }
                stop();
            });
            worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
            // Worker を止めたあとは呼ばれないので、閉じ込めた値ごと残しておく
            onmessage.forget();
            workers.update_value(|workers| workers.push(worker));
        }
        running.set(true);
    };

    let rate = move || {
        let seconds = elapsed.get();
        if seconds > 0.0 {
            tried.get() as f64 / seconds
        } else {
            0.0
        }
    };
    let expected = move || expected_attempts(&prefix.get());

    // 見込みの数だけ試したときに見つかっている確率は 1 - 1/e で約 63%。試した数からの、見つかっているはずの確率
    let chance = move || 1.0 - (-(tried.get() as f64) / expected_attempts(&searched.get())).exp();
    let started_searching = move || running.get() || tried.get() > 0;

    view! {
        <main class="card">
            <header>
                <p class="eyebrow">"Symbol vanity address"</p>
                <h1>"web-vanitygen"</h1>
                <p class="lead">"好きな文字で始まる Symbol のアドレスを、ブラウザの中だけで探します。"</p>
            </header>
            <form on:submit=move |event| {
                event.prevent_default();
                if running.get_untracked() { stop() } else { start() }
            }>
                <input
                    prop:value=move || prefix.get()
                    on:input=move |event| prefix.set(event_target_value(&event).to_uppercase())
                    prop:disabled=move || running.get()
                    placeholder="NASYMBOL"
                    spellcheck="false"
                    autocomplete="off"
                    aria-label="アドレスの先頭"
                />
                <button type="submit" class:running=move || running.get()>
                    {move || if running.get() { "止める" } else { "探す" }}
                </button>
            </form>
            {move || failure.get().map(|message| view! { <p class="failure">{message}</p> })}
            <dl class="stats">
                <div>
                    <dt>"試した鍵"</dt>
                    <dd class="big">{move || group(tried.get() as f64)}</dd>
                </div>
                <div>
                    <dt>"速さ"</dt>
                    <dd>{move || group(rate())} <small>" 個/秒"</small></dd>
                    <dd class="sub">{format!("Worker {cores} 個")}</dd>
                </div>
                <div>
                    <dt>"見込み"</dt>
                    <dd>{move || group(expected())} <small>" 個"</small></dd>
                    <dd class="sub">{move || {
                        let rate = rate();
                        if rate > 0.0 { format!("{}くらい", duration(expected() / rate)) } else { "—".into() }
                    }}</dd>
                </div>
            </dl>
            <Show when=started_searching>
                <div class="chance">
                    <div class="bar"><span style:width=move || format!("{:.1}%", chance() * 100.0)></span></div>
                    <p>{move || format!("いま見つかっているはずの確率 {:.0}%", chance() * 100.0)}</p>
                </div>
            </Show>
            {move || found.get().map(|(address, private_key)| {
                let matched = searched.get_untracked().len().min(address.len());
                let (head, rest) = address.split_at(matched);
                view! {
                    <section class="found">
                        <h2>"見つかった"</h2>
                        <p class="address"><mark>{head.to_owned()}</mark>{rest.to_owned()}</p>
                        <details>
                            <summary>"秘密鍵を見る"</summary>
                            <p class="secret">{private_key}</p>
                            <p class="warning">"この鍵を知っている人は、このアドレスの資産を動かせます。人に見せないでください。"</p>
                        </details>
                    </section>
                }
            })}
            <footer class="note">
                <p>
                    "鍵はこのページの中で作り、どこにも送りません。保存もしないので、閉じると消えます。"
                    "本物の資産を入れるアドレスなら、ネットワークを切ったパソコンで作るのがおすすめです。"
                </p>
                <p>"Made with " <a href="https://github.com/HinaBlogChannel/heika">"heika"</a> " · Rust + WebAssembly"</p>
            </footer>
        </main>
    }
}
