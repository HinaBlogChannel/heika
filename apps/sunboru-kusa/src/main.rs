//! すんぼる草不可避。送り先のアドレスに決まった額（既定は 10 XYM）以上を送るたびに、畑に何かが1つ生える。
//! 鍵は扱わない。REST から送金の履歴を読んで描くだけ。

mod field;
mod rest;

use std::str::FromStr;

use field::{Kind, Plant, Stage};
use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

/// 作者の受け取り用のアドレス。ビルドするときに環境変数 `KUSA_TARGET` で入れる。なければ、遊ぶ人が自分で決める
const DEFAULT_TARGET: &str = match option_env!("KUSA_TARGET") {
    Some(target) => target,
    None => "",
};
/// 数える最低額（XYM）。ビルドするときに環境変数 `KUSA_MIN_XYM` で決める。遊ぶ人もくわしい設定で変えられる
const DEFAULT_MIN: &str = match option_env!("KUSA_MIN_XYM") {
    Some(min) => min,
    None => "10",
};
/// ブラウザから読める公開ノードの一覧（`discover` で作り、ビルドするときに `KUSA_NODES` で渡す）。
/// `{"mainnet": [URL…], "testnet": [URL…]}`。渡さなければ空で、遊ぶ人が REST を決める
const NODES: &str = include_str!(concat!(env!("OUT_DIR"), "/nodes.json"));
/// 公開ノードから選ぶときに、確定した高さを比べる数
const CANDIDATES: usize = 3;
/// キャッシュの形や生え方を変えたら上げる。古いキャッシュは使わない
const RULES: u32 = 1;
/// 1ページに取る件数
const PAGE_SIZE: u32 = 100;
/// 読み直す間隔（ミリ秒）。ブロックは30秒ごとだが、送ったばかりの芽を早く見せる
const POLL_MS: u32 = 5000;

#[wasm_bindgen(inline_js = r#"
export async function fetch_text(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.text();
}
export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function png(svg, scale) {
  const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const canvas = document.createElement('canvas');
    canvas.width = image.width * scale;
    canvas.height = image.height * scale;
    const context = canvas.getContext('2d');
    context.imageSmoothingEnabled = false;
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    return await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  } finally {
    URL.revokeObjectURL(url);
  }
}
function download(blob) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'sunboru-kusa.png';
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 10000);
}
export async function save_png(svg) {
  download(await png(svg, 4));
}
export async function share_png(svg, text, url) {
  const blob = await png(svg, 4);
  const file = new File([blob], 'sunboru-kusa.png', { type: 'image/png' });
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({ files: [file], text, url });
      return;
    } catch (error) {
      if (error.name === 'AbortError') return;
    }
  }
  download(blob);
  window.open('https://twitter.com/intent/tweet?text=' + encodeURIComponent(text) + '&url=' + encodeURIComponent(url), '_blank', 'noopener');
}
export async function copy_text(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    return false;
  }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn fetch_text(url: &str) -> Result<JsValue, JsValue>;
    async fn sleep(ms: u32) -> JsValue;
    async fn save_png(svg: &str) -> JsValue;
    async fn share_png(svg: &str, text: &str, url: &str) -> JsValue;
    async fn copy_text(text: &str) -> JsValue;
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn load_item(key: &str) -> Option<String> {
    storage()?.get_item(key).ok()?
}

fn save_item(key: &str, value: &str) {
    if let Some(storage) = storage() {
        let _ = storage.set_item(key, value);
    }
}

fn query(name: &str) -> Option<String> {
    let search = web_sys::window()?.location().search().ok()?;
    web_sys::UrlSearchParams::new_with_str(&search)
        .ok()?
        .get(name)
        .filter(|v| !v.is_empty())
}

/// このページの URL から、問い合わせの部分を落としたもの。シェアするときにアドレスを載せない
fn page_url() -> String {
    web_sys::window()
        .and_then(|window| {
            let location = window.location();
            Some(format!(
                "{}{}",
                location.origin().ok()?,
                location.pathname().ok()?
            ))
        })
        .unwrap_or_default()
}

async fn get(url: &str) -> Result<Option<Value>, String> {
    let text = fetch_text(url).await.map_err(|error| {
        format!(
            "{url} を読めませんでした（{}）",
            error.as_string().unwrap_or_else(|| format!("{error:?}"))
        )
    })?;
    match text.as_string() {
        None => Ok(None),
        Some(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|error| format!("{url} の JSON が読めません（{error}）")),
    }
}

fn parse_address(text: &str, what: &str) -> Result<Address, String> {
    let cleaned: String = text
        .trim()
        .chars()
        .filter(|c| *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    Address::from_str(&cleaned).map_err(|_| format!("{what}が、正しいアドレスではありません"))
}

/// 埋め込んだ一覧から、そのネットワークのノードをいくつか選び、確定した高さがいちばん進んだものを使う。
/// 1か所が止まっていたり遅れていたりしても困らないようにする
async fn pick_node(network: u8) -> Result<String, String> {
    let name = match network {
        0x68 => "mainnet",
        0x98 => "testnet",
        _ => return Err(
            "このネットワークの公開ノードは知りません。くわしい設定で REST の URL を入れてください"
                .into(),
        ),
    };
    let nodes: Value = serde_json::from_str(NODES).unwrap_or(Value::Null);
    let mut urls: Vec<String> = nodes[name]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|u| u.as_str().map(str::to_owned))
        .collect();
    if urls.is_empty() {
        return Err(
            "公開ノードの一覧がありません。くわしい設定で REST の URL を入れてください".into(),
        );
    }
    // 毎回ちがうノードに分散させる
    for index in (1..urls.len()).rev() {
        let other = (js_sys::Math::random() * (index + 1) as f64) as usize;
        urls.swap(index, other.min(index));
    }
    let mut best: Option<(u64, String)> = None;
    let mut answered = 0;
    // 答えたノードが CANDIDATES に届くか、試すのが多くなりすぎたらやめる
    for url in urls.into_iter().take(CANDIDATES * 3) {
        if answered >= CANDIDATES {
            break;
        }
        if let Ok(Some(info)) = get(&format!("{url}/chain/info")).await
            && let Some(height) = rest::finalized_height(&info)
        {
            answered += 1;
            if best.as_ref().is_none_or(|(best, _)| height > *best) {
                best = Some((height, url));
            }
        }
    }
    best.map(|(_, url)| url).ok_or_else(|| {
        "公開ノードにつながりません。少し待つか、くわしい設定で REST の URL を入れてください".into()
    })
}

/// 開いている畑。入力が変わるまで使い回して、問い合わせを減らす
#[derive(Clone)]
struct Session {
    /// 開いたときの入力。変わったら開き直す
    inputs: String,
    rest: String,
    currency: u64,
    target: Address,
    player: Address,
    min: u64,
    /// ブラウザに覚えておくときのキー
    key: String,
    /// 自分の公開鍵。まだ一度も署名していなければ None
    signer: Option<String>,
    /// 最後に送金の履歴を読んだときの、チェーンの高さ
    height: u64,
    /// ブロックに入ったが、まだ確定していない分。高さが変わらなければ使い回す
    growing: Vec<[u8; 32]>,
}

/// 読んだ結果
struct Update {
    /// 前に数えた、確定した分
    known: Vec<[u8; 32]>,
    /// 今回新しく確定した分
    new: Vec<[u8; 32]>,
    growing: Vec<[u8; 32]>,
    /// 送ったばかりで、まだブロックに入っていない分
    sprouts: Vec<[u8; 32]>,
    note: Option<String>,
}

fn inputs_key(rest: &str, target: &str, player: &str, min: &str) -> String {
    [rest, target, player, min].map(str::trim).join("\n")
}

async fn open(
    rest_url: &str,
    target: &str,
    player: &str,
    min_text: &str,
) -> Result<Session, String> {
    let min = rest::parse_xym(min_text)
        .filter(|min| *min > 0)
        .ok_or("数える最低額は、0 より大きい XYM の額（小数は6桁まで）にしてください")?;
    let target_address = parse_address(target, "送り先")?;
    let player_address = parse_address(player, "自分のアドレス")?;
    if target_address.network() != player_address.network() {
        return Err("送り先と自分のアドレスのネットワークが違います".into());
    }
    let rest = match rest_url.trim().trim_end_matches('/') {
        "" => pick_node(player_address.network().0).await?,
        given => given.to_owned(),
    };
    let properties = get(&format!("{rest}/network/properties"))
        .await?
        .ok_or("ネットワークの設定が見つかりません")?;
    let currency = rest::currency_mosaic_id(&properties).ok_or("通貨のモザイクが分かりません")?;
    let network = rest::generation_hash_seed(&properties).unwrap_or_else(|| rest.clone());
    Ok(Session {
        inputs: inputs_key(rest_url, target, player, min_text),
        key: format!(
            "kusa:{RULES}:{network}:{}:{}:{min}",
            target_address.to_hex(),
            player_address.to_hex()
        ),
        rest,
        currency,
        target: target_address,
        player: player_address,
        min,
        signer: None,
        height: 0,
        growing: Vec::new(),
    })
}

/// ブラウザに覚えておいた、確定した分と、どの高さまで数えたか
fn cached(key: &str) -> (Vec<[u8; 32]>, u64) {
    let cache = load_item(key).and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let seeds = cache
        .as_ref()
        .and_then(|cache| cache["seeds"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|seed| seed.as_str().and_then(hex32))
        .collect();
    let counted = cache
        .as_ref()
        .and_then(|cache| cache["height"].as_u64())
        .unwrap_or(0);
    (seeds, counted)
}

/// 公開鍵（16進）のアドレス
fn address_of(key: &str, network: NetworkIdentifier) -> Option<Address> {
    Some(Address::from_public_key(&PublicKey(hex32(key)?), network))
}

/// 畑を読み直す。チェーンの高さが変わったときだけ送金の履歴を読み、送ったばかりの分は毎回見る
async fn refresh(session: &mut Session) -> Result<Update, String> {
    let rest = session.rest.clone();
    let target_hex = session.target.to_hex();
    let info = get(&format!("{rest}/chain/info"))
        .await?
        .ok_or("チェーンの高さが分かりません")?;
    let finalized = rest::finalized_height(&info).ok_or("確定した高さが分かりません")?;
    let height = rest::chain_height(&info).unwrap_or(finalized);
    let (known, counted) = cached(&session.key);

    let mut note = None;
    if session.signer.is_none() {
        match get(&format!("{rest}/accounts/{}", session.player)).await? {
            None => note = Some("このアカウントは、まだチェーンに載っていません".to_owned()),
            Some(account) => session.signer = rest::public_key(&account),
        }
        if note.is_none() && session.signer.is_none() {
            note = Some("このアカウントは、まだ一度も送金していません".to_owned());
        }
    }

    let mut new = Vec::new();
    if let Some(signer) = session.signer.clone()
        && (height != session.height || counted < finalized)
    {
        let mut growing = Vec::new();
        for page in 1.. {
            let url = format!(
                "{rest}/transactions/confirmed?recipientAddress={}&signerPublicKey={signer}&embedded=true&order=asc&pageSize={PAGE_SIZE}&pageNumber={page}&fromHeight={}",
                session.target,
                counted + 1
            );
            let body = get(&url).await?.unwrap_or(Value::Null);
            let (sends, entries) = rest::sends(
                &body,
                &target_hex,
                |key: &str| key.eq_ignore_ascii_case(&signer),
                session.currency,
                session.min,
            );
            for send in sends {
                if send.height <= finalized {
                    new.push(send.seed)
                } else {
                    growing.push(send.seed)
                }
            }
            if entries == 0 || page >= 1000 {
                break;
            }
        }
        let all: Vec<String> = known.iter().chain(&new).map(hex).collect();
        save_item(
            &session.key,
            &json!({ "height": finalized.max(counted), "seeds": all }).to_string(),
        );
        session.growing = growing;
        session.height = height;
    }

    // 送ったばかりの分。初めての送金ではまだ公開鍵が分からないので、署名者の公開鍵からアドレスを作って自分か確かめる
    let (network, player) = (session.player.network(), session.player);
    let url = format!(
        "{rest}/transactions/unconfirmed?recipientAddress={}&embedded=true&pageSize={PAGE_SIZE}",
        session.target
    );
    let body = get(&url).await?.unwrap_or(Value::Null);
    let (pending, _) = rest::sends(
        &body,
        &target_hex,
        |key: &str| address_of(key, network) == Some(player),
        session.currency,
        session.min,
    );
    let sprouts: Vec<[u8; 32]> = pending
        .into_iter()
        .map(|send| send.seed)
        .filter(|seed| {
            !session.growing.contains(seed) && !known.contains(seed) && !new.contains(seed)
        })
        .collect();
    if !sprouts.is_empty() {
        note = None;
    }
    Ok(Update {
        known,
        new,
        growing: session.growing.clone(),
        sprouts,
        note,
    })
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    (text.len() == 64).then_some(out)
}

fn tally(plants: &[Plant]) -> String {
    let mut counts: Vec<(Kind, usize)> = Vec::new();
    for plant in plants {
        match counts.iter_mut().find(|(kind, _)| *kind == plant.kind) {
            Some((_, count)) => *count += 1,
            None => counts.push((plant.kind, 1)),
        }
    }
    // 草の仲間から順に、いつも同じ並びで出す
    counts.sort_by_key(|(kind, _)| *kind as u8);
    counts
        .iter()
        .map(|(kind, count)| format!("{} {count}", kind.name()))
        .collect::<Vec<_>>()
        .join("、")
}

#[component]
fn App() -> impl IntoView {
    let saved = load_item("kusa:inputs")
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or(Value::Null);
    let initial = |name: &str, default: &str| {
        query(name)
            .or_else(|| saved[name].as_str().map(str::to_owned))
            .unwrap_or_else(|| default.to_owned())
    };
    let rest_url = RwSignal::new(initial("rest", ""));
    let target = RwSignal::new(initial("to", DEFAULT_TARGET));
    let player = RwSignal::new(initial("me", ""));
    let min = RwSignal::new(initial("min", DEFAULT_MIN));
    let plants = RwSignal::new(Vec::<Plant>::new());
    let status = RwSignal::new(String::new());
    let busy = StoredValue::new(false);
    let session = StoredValue::new_local(None::<Session>);

    // 畑を読み直す。quiet なら「読んでいます」を出さない（5秒ごとの読み直し）
    let run = move |quiet: bool| {
        let (rest_text, target_text, player_text, min_text) = (
            rest_url.get_untracked(),
            target.get_untracked(),
            player.get_untracked(),
            min.get_untracked(),
        );
        if busy.get_value() || player_text.trim().is_empty() || target_text.trim().is_empty() {
            return;
        }
        busy.set_value(true);
        if !quiet {
            status.set("読んでいます…".into());
        }
        save_item(
            "kusa:inputs",
            &json!({ "rest": rest_text, "to": target_text, "me": player_text, "min": min_text })
                .to_string(),
        );
        spawn_local(async move {
            let inputs = inputs_key(&rest_text, &target_text, &player_text, &min_text);
            let reused = session
                .get_value()
                .filter(|session| session.inputs == inputs);
            let opened = match reused {
                Some(session) => Ok(session),
                None => open(&rest_text, &target_text, &player_text, &min_text).await,
            };
            let result = match opened {
                Ok(mut opened) => refresh(&mut opened).await.map(|update| (opened, update)),
                Err(message) => Err(message),
            };
            match result {
                Err(message) => {
                    // 次の読み直しで、ノードを選ぶところからやり直す
                    session.set_value(None);
                    status.set(message);
                }
                Ok((opened, update)) => {
                    session.set_value(Some(opened));
                    let mut shown: Vec<Plant> = update
                        .known
                        .iter()
                        .map(|seed| Plant::new(seed, Stage::Grown))
                        .collect();
                    if !update.new.is_empty() {
                        // 覚えていなければ、最初から順に生やして振り返る。覚えていれば新しい分だけ
                        if update.known.is_empty() {
                            status.set("思い出しています…".into());
                        }
                        plants.set(shown.clone());
                        let pause = (6000 / update.new.len() as u32).clamp(20, 150);
                        for seed in &update.new {
                            shown.push(Plant::new(seed, Stage::Grown));
                            plants.set(shown.clone());
                            sleep(pause).await;
                        }
                    }
                    shown.extend(
                        update
                            .growing
                            .iter()
                            .map(|seed| Plant::new(seed, Stage::Growing)),
                    );
                    shown.extend(
                        update
                            .sprouts
                            .iter()
                            .map(|seed| Plant::new(seed, Stage::Sprout)),
                    );
                    plants.set(shown);
                    let mut notes = Vec::new();
                    if !update.sprouts.is_empty() {
                        notes.push(format!(
                            "芽が {} つ出ました（ブロック待ち）",
                            update.sprouts.len()
                        ));
                    }
                    if !update.growing.is_empty() {
                        notes.push(format!(
                            "{} つ育ちかけです（確定待ち）",
                            update.growing.len()
                        ));
                    }
                    notes.extend(update.note);
                    status.set(notes.join("。"));
                }
            }
            busy.set_value(false);
        });
    };

    // 入力が変わったら、打ち終わるのを少し待ってから読む。開いたときに覚えていた入力があれば、すぐ読む
    let typed = StoredValue::new(0u64);
    Effect::new(move |_| {
        player.track();
        target.track();
        min.track();
        rest_url.track();
        let id = typed.get_value() + 1;
        typed.set_value(id);
        spawn_local(async move {
            sleep(if id == 1 { 0 } else { 700 }).await;
            if typed.get_value() == id {
                run(false);
            }
        });
    });
    // 開いているあいだは、ときどき読み直して、送ったばかりの芽や、育った分を出す
    spawn_local(async move {
        loop {
            sleep(POLL_MS).await;
            let hidden = web_sys::window()
                .and_then(|window| window.document())
                .is_some_and(|document| document.hidden());
            if !hidden {
                run(true);
            }
        }
    });

    let count =
        move || plants.with(|p| p.iter().filter(|plant| plant.stage == Stage::Grown).count());
    let share_text = move || {
        format!(
            "すんぼる草不可避で {} 本生えました #すんぼる草不可避",
            count()
        )
    };
    let save = move |_| {
        let svg = plants.with(|p| field::svg(p, true));
        spawn_local(async move {
            save_png(&svg).await;
        });
    };
    let share = move |_| {
        let svg = plants.with(|p| field::svg(p, true));
        let text = share_text();
        spawn_local(async move {
            share_png(&svg, &text, &page_url()).await;
        });
    };

    let copied = RwSignal::new(false);
    let copy = move |_| {
        let text: String = target
            .get_untracked()
            .trim()
            .chars()
            .filter(|c| *c != '-')
            .collect();
        spawn_local(async move {
            if copy_text(&text).await.as_bool() == Some(true) {
                copied.set(true);
                sleep(2000).await;
                copied.set(false);
            }
        });
    };
    let min_label = move || {
        rest::parse_xym(&min.get())
            .map(rest::format_xym)
            .unwrap_or_else(|| min.get())
    };
    let grown = move || {
        plants.with(|p| {
            p.iter()
                .filter(|plant| plant.stage == Stage::Grown)
                .copied()
                .collect::<Vec<_>>()
        })
    };

    view! {
        <main>
            <header>
                <h1>"すんぼる草不可避"</h1>
                <p class="tagline">"送金で生えます"</p>
            </header>
            <section class="send">
                {move || if target.with(|t| t.trim().is_empty()) {
                    view! { <p class="hint">"送り先が決まっていません。くわしい設定で、送り先のアドレスを入れてください"</p> }.into_any()
                } else {
                    view! {
                        <p class="hint">{move || format!("ここへ {} XYM 以上を送るたびに、1つ生えます", min_label())}</p>
                        <div class="address">
                            <code>{move || target.get().trim().to_owned()}</code>
                            <button type="button" on:click=copy>{move || if copied.get() { "コピーしました" } else { "コピー" }}</button>
                        </div>
                    }.into_any()
                }}
            </section>
            <section class="field" inner_html=move || plants.with(|p| field::svg(p, false))></section>
            <p class="count">{move || if count() == 0 { String::new() } else { format!("{} 本 ・ {}", count(), tally(&grown())) }}</p>
            <p class="status">{move || status.get()}</p>
            <div class="buttons">
                <button on:click=save disabled=move || count() == 0>"画像を保存"</button>
                <button on:click=share disabled=move || count() == 0>"シェア"</button>
            </div>
            <form on:submit=move |event| { event.prevent_default(); run(false); }>
                <label>"自分のアドレス（入れると畑が出ます）"
                    <input prop:value=move || player.get() on:input=move |e| player.set(event_target_value(&e)) placeholder="N… または T…" spellcheck="false"/>
                </label>
                <details>
                    <summary>"くわしい設定"</summary>
                    <label>"送り先のアドレス"
                        <input prop:value=move || target.get() on:input=move |e| target.set(event_target_value(&e)) placeholder="N… または T…" spellcheck="false"/>
                    </label>
                    <label>"数える最低額（XYM）"
                        <input prop:value=move || min.get() on:input=move |e| min.set(event_target_value(&e)) inputmode="decimal" spellcheck="false"/>
                    </label>
                    <label>"REST の URL（空なら公開ノードから選びます）"
                        <input prop:value=move || rest_url.get() on:input=move |e| rest_url.set(event_target_value(&e)) placeholder="https://…:3001" spellcheck="false"/>
                    </label>
                </details>
            </form>
            <footer>
                <p>{move || format!(
                    "自分のアドレスから送り先へ {} XYM 以上を送るたびに、畑に何かが1つ生えます。送ってすぐに芽が出て、ブロックに入ると育ち、確定すると生えそろいます。何が生えるかは、送金のハッシュで決まります。珍しいものに優劣はありません。",
                    min_label(),
                )}</p>
                <p>"払う義務はありません。送り先は自由に変えられて、テストネットや自分のプライベートネットでも遊べます。鍵は使わず、REST から送金の履歴を読むだけです。"</p>
                <p>"シェアする画像と文には、アドレスを入れません。"</p>
            </footer>
        </main>
    }
}

fn main() {
    leptos::mount::mount_to_body(App);
}
