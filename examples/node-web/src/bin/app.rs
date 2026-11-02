//! 画面。DB を持つ Worker を立て、OPFS に残っているか、ほかのタブと取り合わないか、書き読みの速さを見せる。

use js_sys::Array;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use web_sys::{MessageEvent, Worker};

/// trunk が Worker のバイナリから作る読み込み用のスクリプト
const WORKER_SCRIPT: &str = "./worker_loader.js";

fn main() {
    leptos::mount::mount_to_body(App);
}

/// Worker の今のようす
#[derive(Clone, PartialEq)]
enum Phase {
    Starting,
    Waiting,
    Ready,
    Failed(String),
}

/// DB を開いたときの値
#[derive(Clone, PartialEq)]
struct Opened {
    count: f64,
    open_ms: f64,
}

/// 書き読みを測った結果
#[derive(Clone, PartialEq)]
struct Bench {
    blocks: f64,
    write_ms: f64,
    read_ms: f64,
}

/// バイト数を、読みやすい単位にする
fn bytes(value: f64) -> String {
    match value {
        value if value < 1024.0 => format!("{value:.0} B"),
        value if value < 1024.0 * 1024.0 => format!("{:.1} KiB", value / 1024.0),
        value => format!("{:.1} MiB", value / 1024.0 / 1024.0),
    }
}

#[component]
fn App() -> impl IntoView {
    let phase = RwSignal::new(Phase::Starting);
    let opened = RwSignal::new(None::<Opened>);
    let tip = RwSignal::new(0.0_f64);
    let size = RwSignal::new(0.0_f64);
    let bench = RwSignal::new(None::<Bench>);
    let measuring = RwSignal::new(false);

    let worker = match Worker::new(WORKER_SCRIPT) {
        Ok(worker) => Some(worker),
        Err(error) => {
            phase.set(Phase::Failed(format!("Worker を立てられません: {error:?}")));
            None
        }
    };
    if let Some(worker) = &worker {
        let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
            let message: Array = event.data().unchecked_into();
            let number = |index| message.get(index).as_f64().unwrap_or(0.0);
            match message.get(0).as_string().as_deref() {
                Some("waiting") => phase.set(Phase::Waiting),
                Some("opened") => {
                    opened.set(Some(Opened {
                        count: number(1),
                        open_ms: number(2),
                    }));
                    tip.set(number(3));
                    size.set(number(4));
                    phase.set(Phase::Ready);
                }
                Some("bench") => {
                    bench.set(Some(Bench {
                        blocks: number(1),
                        write_ms: number(2),
                        read_ms: number(3),
                    }));
                    tip.set(number(4));
                    size.set(number(5));
                    measuring.set(false);
                }
                _ => {
                    measuring.set(false);
                    let reason = message.get(1).as_string().unwrap_or_default();
                    phase.set(Phase::Failed(reason));
                }
            }
        });
        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
        // 画面があるあいだ Worker は動き続けるので、放さない
        onmessage.forget();
    }
    let worker = StoredValue::new_local(worker);

    let measure = move |_| {
        measuring.set(true);
        worker.with_value(|worker| {
            if let Some(worker) = worker {
                let _ = worker.post_message(&"bench".into());
            }
        });
    };

    view! {
        <main class="screen">
            <h1>"heika"</h1>
            <p class="lead">"ブラウザの中に、ノードの DB を置く"</p>
            <p class="hint">
                "OPFS（ブラウザの中の、このサイトだけのファイル）に redb を置き、Web Worker から同期で読み書きします。"
                "DB を持つ Worker は、Web Locks でこのサイトに1つだけにしています。"
            </p>

            <section class="glass panel">
                {move || match phase.get() {
                    Phase::Starting => view! { <p class="state">"DB を開いています…"</p> }.into_any(),
                    Phase::Waiting => view! {
                        <p class="state">"ほかのタブがこの DB を使っています"</p>
                        <p class="hint">"そのタブを閉じると、ここが引き継いで開きます。"</p>
                    }.into_any(),
                    Phase::Failed(reason) => view! {
                        <p class="state failed">"開けませんでした"</p>
                        <p class="hint path">{reason}</p>
                    }.into_any(),
                    Phase::Ready => view! {
                        <p class="state ok">"開きました"</p>
                        <dl class="facts">
                            <dt>"開いた回数"</dt>
                            <dd>{move || opened.get().map(|opened| format!("{:.0} 回目", opened.count))}</dd>
                            <dt>"開くのにかかった時間"</dt>
                            <dd>{move || opened.get().map(|opened| format!("{:.1} ms", opened.open_ms))}</dd>
                            <dt>"ブロックの高さ"</dt>
                            <dd>{move || format!("{:.0}", tip.get())}</dd>
                            <dt>"ファイルの大きさ"</dt>
                            <dd>{move || bytes(size.get())}</dd>
                        </dl>
                        <p class="hint">"再読み込みして回数が増えていれば、DB はブラウザに残っています。"</p>
                    }.into_any(),
                }}
            </section>

            <Show when=move || phase.get() == Phase::Ready>
                <section class="glass panel">
                    <p class="state">"書き読みの速さ"</p>
                    <p class="hint">"4 KiB のバイト列を、ブロックの代わりに 1,000 個書いて、全部読み戻します。"</p>
                    {move || bench.get().map(|bench| view! {
                        <dl class="facts">
                            <dt>"書く（1 回のコミット）"</dt>
                            <dd>{format!("{:.0} ms（1 個あたり {:.2} ms）", bench.write_ms, bench.write_ms / bench.blocks)}</dd>
                            <dt>"読む"</dt>
                            <dd>{format!("{:.0} ms（1 個あたり {:.3} ms）", bench.read_ms, bench.read_ms / bench.blocks)}</dd>
                        </dl>
                    })}
                    <div class="row">
                        <button class="primary" on:click=measure disabled=move || measuring.get()>
                            {move || if measuring.get() { "測っています…" } else { "測る" }}
                        </button>
                    </div>
                </section>
            </Show>

            <ul class="notes">
                <li>"別のタブでこのページを開くと、こちらを閉じるまで待ちます。"</li>
                <li>"データはこのブラウザのこのサイトの中だけにあり、サイトのデータを消すと消えます。"</li>
            </ul>
        </main>
    }
}
