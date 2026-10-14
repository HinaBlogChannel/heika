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

    view! {
        <main>
            <h1>"web-vanitygen"</h1>
            <p class="lead">"好きな文字で始まる Symbol のアドレスを、ブラウザの中だけで探します。"</p>
            <form on:submit=move |event| {
                event.prevent_default();
                if running.get_untracked() { stop() } else { start() }
            }>
                <input
                    prop:value=move || prefix.get()
                    on:input=move |event| prefix.set(event_target_value(&event).to_uppercase())
                    prop:disabled=move || running.get()
                    spellcheck="false"
                    autocomplete="off"
                />
                <button type="submit">{move || if running.get() { "止める" } else { "探す" }}</button>
            </form>
            {move || failure.get().map(|message| view! { <p class="failure">{message}</p> })}
            <dl>
                <dt>"試した鍵"</dt>
                <dd>{move || group(tried.get() as f64)}</dd>
                <dt>"速さ"</dt>
                <dd>{move || format!("{} 個/秒（Worker {cores} 個）", group(rate()))}</dd>
                <dt>"見込み"</dt>
                <dd>{move || {
                    let rate = rate();
                    let time = if rate > 0.0 { duration(expected() / rate) } else { "—".into() };
                    format!("{} 個、{time}くらい", group(expected()))
                }}</dd>
            </dl>
            {move || found.get().map(|(address, private_key)| view! {
                <section class="found">
                    <h2>"見つかった"</h2>
                    <p class="address">{address}</p>
                    <details>
                        <summary>"秘密鍵を見る"</summary>
                        <p class="secret">{private_key}</p>
                    </details>
                </section>
            })}
            <p class="note">
                "鍵はこのページの中で作り、どこにも送りません。保存もしないので、閉じると消えます。"
                "本物の資産を入れるアドレスなら、ネットワークを切ったパソコンで作るのがおすすめです。"
            </p>
        </main>
    }
}
