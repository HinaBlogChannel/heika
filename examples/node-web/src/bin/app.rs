//! 画面。DB を持つ Worker を立て、REST のオリジンを渡して同期させ、進み具合を見せる。

use js_sys::Array;
use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use web_sys::{MessageEvent, Worker};

/// trunk が Worker のバイナリから作る読み込み用のスクリプト。ビルドごとの印を付けて、前の版をキャッシュから読まない
const WORKER_SCRIPT: &str = concat!("./worker_loader.js?v=", env!("NODE_WEB_BUILD"));
/// 入れたオリジンを覚えておく localStorage のキー
const ORIGINS_KEY: &str = "node-web/origins";
/// ブロックを出す REST を覚えておく localStorage のキー。鍵は覚えない
const SUBMIT_KEY: &str = "node-web/submit";
/// 自分のネットワークの設定を覚えておく localStorage のキー。並びは Worker に渡す順
const CUSTOM_KEYS: [&str; 4] = [
    "node-web/custom/config-network",
    "node-web/custom/config-inflation",
    "node-web/custom/config-finalization",
    "node-web/custom/nemesis",
];
/// 自分のネットワークの設定ファイルの名前。並びは [`CUSTOM_KEYS`] の頭の3つと同じ
const CUSTOM_FILES: [&str; 3] = [
    "config-network.properties",
    "config-inflation.properties",
    "config-finalization.properties",
];
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

/// ハーベストの見込み（Worker の `meter`）
#[derive(Clone, PartialEq)]
struct Meter {
    /// 親のブロックの時刻（UNIX のミリ秒）
    parent: f64,
    /// 次の当たりの時刻。1時間先までになければ `None`
    hit: Option<f64>,
    /// 次の当たりで、ほかのだれにも先を越されない見込み（同じ秒に並ぶものは半々）
    next: Option<f64>,
    per_block: f64,
    block_seconds: f64,
    importance: f64,
    active: f64,
}

/// 届いた委任1件
#[derive(Clone, PartialEq)]
struct Delegation {
    height: f64,
    main_account: String,
    used: bool,
    reason: String,
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

/// 割合を、小さいものも読める桁で
fn percent(value: f64) -> String {
    let value = value * 100.0;
    match value {
        value if value >= 10.0 => format!("{value:.0}%"),
        value if value >= 0.1 => format!("{value:.1}%"),
        value => format!("{value:.4}%"),
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
    let remembered = |key| {
        storage()
            .and_then(|storage| storage.get_item(key).ok().flatten())
            .unwrap_or_default()
    };
    let origins = RwSignal::new(remembered(ORIGINS_KEY));
    // ハーベスト。鍵はこのページのメモリにだけ置き、Worker に渡すだけ
    let harvesting = RwSignal::new(false);
    let signing = RwSignal::new(String::new());
    let vrf = RwSignal::new(String::new());
    let submit = RwSignal::new(remembered(SUBMIT_KEY));
    // 自分のネットワーク。設定ファイルの中身3つと Nemesis のハッシュ。秘密ではないので覚えておく
    let custom = CUSTOM_KEYS.map(|key| RwSignal::new(remembered(key)));
    let plan = RwSignal::new(None::<String>);
    let node_key = RwSignal::new(String::new());
    let delegations = RwSignal::new(Vec::<Delegation>::new());
    let meter = RwSignal::new(None::<Meter>);
    // メーターを動かす時計。見込みがあるあいだだけ、画面の中で進める
    let clock = RwSignal::new(js_sys::Date::now());
    set_interval(
        move || {
            if meter.get_untracked().is_some() {
                clock.set(js_sys::Date::now());
            }
        },
        std::time::Duration::from_millis(250),
    );
    let harvested = RwSignal::new(Vec::<String>::new());

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
                "ready" => {
                    node_key.set(text(1));
                    phase.set(Phase::Ready);
                }
                "delegations" => {
                    let rows: Array = message.get(1).unchecked_into();
                    delegations.set(
                        rows.iter()
                            .map(|row| {
                                let row: Array = row.unchecked_into();
                                Delegation {
                                    height: row.get(0).as_f64().unwrap_or(0.0),
                                    main_account: row.get(1).as_string().unwrap_or_default(),
                                    used: row.get(2).as_bool().unwrap_or(false),
                                    reason: row.get(3).as_string().unwrap_or_default(),
                                }
                            })
                            .collect(),
                    );
                }
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
                "plan" => plan.set(Some(text(1))),
                "meter" => meter.set(message.get(1).as_f64().map(|parent| Meter {
                    parent,
                    hit: message.get(2).as_f64(),
                    next: message.get(3).as_f64(),
                    per_block: number(4),
                    block_seconds: number(5),
                    importance: number(6),
                    active: number(7),
                })),
                "harvested" => harvested.update(|harvested| {
                    harvested.push(text(1));
                    if harvested.len() > WARNINGS {
                        harvested.remove(0);
                    }
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
        plan.set(None);
        harvested.set(Vec::new());
        delegations.set(Vec::new());
        meter.set(None);
        let harvest = if harvesting.get_untracked() {
            let targets = submit.get_untracked();
            if let Some(storage) = storage() {
                let _ = storage.set_item(SUBMIT_KEY, &targets);
            }
            [signing.get_untracked(), vrf.get_untracked(), targets]
                .into_iter()
                .map(JsValue::from)
                .collect::<Array>()
                .into()
        } else {
            JsValue::NULL
        };
        let texts = custom.map(|text| text.get_untracked());
        if let Some(storage) = storage() {
            for (key, text) in CUSTOM_KEYS.iter().zip(&texts) {
                let _ = storage.set_item(key, text);
            }
        }
        let custom = if texts.iter().all(|text| text.trim().is_empty()) {
            JsValue::NULL
        } else {
            texts
                .into_iter()
                .map(JsValue::from)
                .collect::<Array>()
                .into()
        };
        running.set(true);
        send(&["sync".into(), text.into(), harvest, custom]);
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
    // 選んだファイルを、名前で3つの設定に振り分けて読む
    let load_custom = move |event: web_sys::Event| {
        let input: web_sys::HtmlInputElement = event_target(&event);
        let Some(files) = input.files() else {
            return;
        };
        for file in (0..files.length()).filter_map(|index| files.get(index)) {
            let Some(index) = CUSTOM_FILES.iter().position(|name| file.name() == *name) else {
                failure.set(Some(format!(
                    "{} は使いません。{} を選んでください",
                    file.name(),
                    CUSTOM_FILES.join("、")
                )));
                continue;
            };
            wasm_bindgen_futures::spawn_local(async move {
                match wasm_bindgen_futures::JsFuture::from(file.text()).await {
                    Ok(text) => custom[index].set(text.as_string().unwrap_or_default()),
                    Err(error) => {
                        failure.set(Some(format!("{} を読めません: {error:?}", file.name())))
                    }
                }
            });
        }
        input.set_value("");
    };
    let clear_custom = move |_| {
        for text in custom {
            text.set(String::new());
        }
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
                            <summary>"ハーベストする"</summary>
                            <p class="hint">
                                "先端を追うあいだ、当たりの時刻が来たらブロックを作り、heika のノードの REST（PUT /blocks）に出します。catapult の REST には出せません。"
                                "このブラウザのノードの公開鍵に委任してもらうと、届いた委任でハーベストします。"
                            </p>
                            <Show when=move || !node_key.get().is_empty()>
                                <dl class="facts">
                                    <dt>"ノードの公開鍵"</dt>
                                    <dd class="hash">{move || node_key.get()}</dd>
                                </dl>
                                <p class="hint">
                                    "委任は、この公開鍵を委任先にして送ります（heika の CLI なら heika harvesting --delegate 公開鍵）。"
                                    "このブラウザが持つ鍵は、読み出せない形でしまってあり、ページからも中身は読めません。サイトのデータを消すと鍵も消えるので、委任をやり直すことになります。"
                                </p>
                            </Show>
                            <label class="check">
                                <input
                                    type="checkbox"
                                    prop:checked=move || harvesting.get()
                                    on:change=move |event| harvesting.set(event_target_checked(&event))
                                    disabled=move || running.get()
                                />
                                " ハーベストする"
                            </label>
                            <p class="hint">
                                "鍵を直接入れてもハーベストできます（委任と合わせて使えます）。ハーベストに紐づけた署名の鍵（リモートの鍵）と VRF の鍵で、このページのメモリにだけ置き、保存しません。"
                            </p>
                            <label class="field">
                                "署名の鍵（16 進の秘密鍵。委任だけなら空のまま）"
                                <input
                                    type="password"
                                    autocomplete="off"
                                    spellcheck="false"
                                    prop:value=move || signing.get()
                                    on:input=move |event| signing.set(event_target_value(&event))
                                    disabled=move || running.get() || !harvesting.get()
                                />
                            </label>
                            <label class="field">
                                "VRF の鍵（16 進の秘密鍵）"
                                <input
                                    type="password"
                                    autocomplete="off"
                                    spellcheck="false"
                                    prop:value=move || vrf.get()
                                    on:input=move |event| vrf.set(event_target_value(&event))
                                    disabled=move || running.get() || !harvesting.get()
                                />
                            </label>
                            <label class="field">
                                "ブロックを出す heika の REST（1 行に 1 つ）"
                                <textarea
                                    rows="2"
                                    spellcheck="false"
                                    placeholder="https://example.com:3001"
                                    prop:value=move || submit.get()
                                    on:input=move |event| submit.set(event_target_value(&event))
                                    disabled=move || running.get() || !harvesting.get()
                                ></textarea>
                            </label>
                        </details>
                        <details class="import">
                            <summary>"自分のネットワーク"</summary>
                            <p class="hint">
                                "メインネットとテストネットのほか（プライベートなネットワークなど）を同期するときに入れます。"
                                "ノードの resources フォルダーにある3つの設定ファイルと、Nemesis のブロックのハッシュです。"
                                "何で確かめるかを REST に決めさせないため、ルールは REST からもらわず、ここで入れたものを使います。"
                            </p>
                            <input
                                type="file"
                                multiple
                                accept=".properties"
                                on:change=load_custom
                                disabled=move || running.get()
                            />
                            <dl class="facts">
                                {CUSTOM_FILES.iter().enumerate().map(|(index, name)| view! {
                                    <dt>{*name}</dt>
                                    <dd>{move || if custom[index].get().trim().is_empty() { "まだです" } else { "読み込みました" }}</dd>
                                }).collect_view()}
                            </dl>
                            <label class="field">
                                "Nemesis のブロックのハッシュ（16 進）"
                                <input
                                    type="text"
                                    spellcheck="false"
                                    prop:value=move || custom[3].get()
                                    on:input=move |event| custom[3].set(event_target_value(&event))
                                    disabled=move || running.get()
                                />
                            </label>
                            <div class="row">
                                <button on:click=clear_custom disabled=move || running.get()>"外す"</button>
                            </div>
                        </details>
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
                    {move || plan.get().map(|plan| view! {
                        <dl class="facts">
                            <dt>"ハーベスト"</dt>
                            <dd>{plan}</dd>
                        </dl>
                    })}
                    {move || meter.get().map(|meter| {
                        let now = clock.get();
                        let every = meter.block_seconds / meter.per_block.max(f64::MIN_POSITIVE);
                        view! {
                            <div class="meter">
                                {meter.hit.map(|hit| {
                                    let span = (hit - meter.parent).max(1.0);
                                    let left = ((hit - now) / 1000.0).max(0.0);
                                    view! {
                                        <p class="meter-label">
                                            {if left > 0.0 {
                                                format!("当たりまで あと {left:.0} 秒（親から {:.0} 秒）", span / 1000.0)
                                            } else {
                                                format!("当たりの時刻です（親から {:.0} 秒）", span / 1000.0)
                                            }}
                                        </p>
                                        <progress max=span.to_string() value=(now - meter.parent).clamp(0.0, span).to_string()></progress>
                                        <p class="hint">
                                            {format!(
                                                "この当たりで作れる見込み: {}（ほかのだれにも先を越されない見込み。同じ秒に並べば半々）",
                                                percent(meter.next.unwrap_or(0.0))
                                            )}
                                        </p>
                                    }
                                })}
                                <dl class="facts">
                                    <dt>"1 ブロックあたり"</dt>
                                    <dd>{format!("{}、平均でおよそ {} に 1 回", percent(meter.per_block), duration(every))}</dd>
                                    <dt>"ハーベストしている量"</dt>
                                    <dd>{format!(
                                        "見積もり {} XYM 相当のうち、自分 {} XYM 相当",
                                        group(meter.active),
                                        group(meter.importance)
                                    )}</dd>
                                </dl>
                            </div>
                        }
                    })}
                    <Show when=move || !delegations.get().is_empty()>
                        <ul class="notes">
                            <For
                                each=move || delegations.get()
                                key=|delegation| (delegation.height.to_bits(), delegation.main_account.clone(), delegation.reason.clone())
                                let:delegation
                            >
                                <li class="path">
                                    {format!(
                                        "高さ {} の委任（{}）: {}",
                                        group(delegation.height),
                                        if delegation.main_account.is_empty() { "メインアカウント不明".to_owned() } else { delegation.main_account.clone() },
                                        if delegation.used { "ハーベストに使っています".to_owned() } else { delegation.reason.clone() },
                                    )}
                                </li>
                            </For>
                        </ul>
                    </Show>
                    <Show when=move || !harvested.get().is_empty()>
                        <ul class="notes">
                            <For each=move || harvested.get() key=|line| line.clone() let:line>
                                <li class="path">{line}</li>
                            </For>
                        </ul>
                    </Show>
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
