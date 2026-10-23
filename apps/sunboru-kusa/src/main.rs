//! すんぼる草不可避。送り先のアドレスに決まった額（既定は 10 XYM）以上を送るたびに、畑に何かが1つ生える。
//! 鍵は扱わない。REST から送金の履歴を読んで描くだけ。

mod field;
mod rest;

use std::str::FromStr;

use field::{Kind, Plant};
use heika_core::address::Address;
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
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn fetch_text(url: &str) -> Result<JsValue, JsValue>;
    async fn sleep(ms: u32) -> JsValue;
    async fn save_png(svg: &str) -> JsValue;
    async fn share_png(svg: &str, text: &str, url: &str) -> JsValue;
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

/// 読んできた結果
struct Loaded {
    /// キャッシュにあった、前に数えた分
    known: Vec<[u8; 32]>,
    /// 今回新しく数えた、確定した分
    new: Vec<[u8; 32]>,
    /// まだ確定していない分
    growing: Vec<[u8; 32]>,
    message: Option<String>,
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

async fn load(rest_url: &str, target: &str, player: &str, min: &str) -> Result<Loaded, String> {
    let min = rest::parse_xym(min)
        .filter(|min| *min > 0)
        .ok_or("数える最低額は、0 より大きい XYM の額（小数は6桁まで）にしてください")?;
    let target = parse_address(target, "送り先")?;
    let player = parse_address(player, "自分のアドレス")?;
    if target.network() != player.network() {
        return Err("送り先と自分のアドレスのネットワークが違います".into());
    }
    let chosen;
    let rest_url = match rest_url.trim().trim_end_matches('/') {
        "" => {
            chosen = pick_node(player.network().0).await?;
            chosen.as_str()
        }
        given => given,
    };
    let properties = get(&format!("{rest_url}/network/properties"))
        .await?
        .ok_or("ネットワークの設定が見つかりません")?;
    let currency = rest::currency_mosaic_id(&properties).ok_or("通貨のモザイクが分かりません")?;
    let network = rest::generation_hash_seed(&properties).unwrap_or_else(|| rest_url.to_owned());
    let info = get(&format!("{rest_url}/chain/info"))
        .await?
        .ok_or("チェーンの高さが分かりません")?;
    let finalized = rest::finalized_height(&info).ok_or("確定した高さが分かりません")?;

    let key = format!(
        "kusa:{RULES}:{network}:{}:{}:{min}",
        target.to_hex(),
        player.to_hex()
    );
    let cached = load_item(&key).and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let known: Vec<[u8; 32]> = cached
        .as_ref()
        .and_then(|cache| cache["seeds"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|seed| seed.as_str().and_then(hex32))
        .collect();
    let counted = cached
        .as_ref()
        .and_then(|cache| cache["height"].as_u64())
        .unwrap_or(0);

    let Some(account) = get(&format!("{rest_url}/accounts/{player}")).await? else {
        return Ok(Loaded {
            known,
            new: Vec::new(),
            growing: Vec::new(),
            message: Some("このアカウントは、まだチェーンに載っていません".into()),
        });
    };
    let Some(signer) = rest::public_key(&account) else {
        return Ok(Loaded {
            known,
            new: Vec::new(),
            growing: Vec::new(),
            message: Some("このアカウントは、まだ一度も送金していません".into()),
        });
    };

    let mut new = Vec::new();
    let mut growing = Vec::new();
    for page in 1.. {
        let url = format!(
            "{rest_url}/transactions/confirmed?recipientAddress={target}&signerPublicKey={signer}&embedded=true&order=asc&pageSize={PAGE_SIZE}&pageNumber={page}&fromHeight={}",
            counted + 1
        );
        let body = get(&url).await?.unwrap_or(Value::Null);
        let (sends, entries) = rest::sends(&body, &target.to_hex(), &signer, currency, min);
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
        &key,
        &json!({ "height": finalized.max(counted), "seeds": all }).to_string(),
    );
    Ok(Loaded {
        known,
        new,
        growing,
        message: None,
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
    let initial = |name: &str| {
        query(name)
            .or_else(|| saved[name].as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let rest_url = RwSignal::new(initial("rest"));
    let target = RwSignal::new(
        query("to")
            .or_else(|| saved["to"].as_str().map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_TARGET.into()),
    );
    let player = RwSignal::new(initial("me"));
    let min = RwSignal::new(
        query("min")
            .or_else(|| saved["min"].as_str().map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_MIN.into()),
    );
    let plants = RwSignal::new(Vec::<Plant>::new());
    let status = RwSignal::new(String::new());
    let busy = RwSignal::new(false);

    let look = move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        status.set("読んでいます…".into());
        let (rest_text, target_text, player_text, min_text) = (
            rest_url.get_untracked(),
            target.get_untracked(),
            player.get_untracked(),
            min.get_untracked(),
        );
        save_item(
            "kusa:inputs",
            &json!({ "rest": rest_text, "to": target_text, "me": player_text, "min": min_text })
                .to_string(),
        );
        spawn_local(async move {
            match load(&rest_text, &target_text, &player_text, &min_text).await {
                Err(message) => status.set(message),
                Ok(loaded) => {
                    let mut shown: Vec<Plant> = loaded
                        .known
                        .iter()
                        .map(|seed| Plant::new(seed, false))
                        .collect();
                    // キャッシュがなければ、最初から順に生やして振り返る。あれば新しい分だけ
                    let replay = loaded.known.is_empty();
                    plants.set(shown.clone());
                    let fresh = loaded.new.len();
                    status.set(if replay && fresh > 0 {
                        "思い出しています…".into()
                    } else {
                        String::new()
                    });
                    let pause = (6000 / fresh.max(1) as u32).clamp(20, 150);
                    for seed in &loaded.new {
                        shown.push(Plant::new(seed, false));
                        plants.set(shown.clone());
                        sleep(pause).await;
                    }
                    shown.extend(loaded.growing.iter().map(|seed| Plant::new(seed, true)));
                    plants.set(shown);
                    status.set(match loaded.message {
                        Some(message) => message,
                        None if !loaded.growing.is_empty() => format!(
                            "{} つは、まだ育ちかけです（確定待ち）",
                            loaded.growing.len()
                        ),
                        None => String::new(),
                    });
                }
            }
            busy.set(false);
        });
    };

    // URL に自分のアドレスがあって、送り先も決まっていれば、すぐに畑を見る（自分のブックマーク用）
    if query("me").is_some() && !target.get_untracked().trim().is_empty() {
        look(());
    }

    let count = move || plants.with(|p| p.iter().filter(|plant| !plant.growing).count());
    let share_text = move || {
        format!(
            "すんぼる草不可避で {} 本生えました #すんぼる草不可避",
            count()
        )
    };
    let save = move |_| {
        let svg = plants.with(|p| field::svg(p));
        spawn_local(async move {
            save_png(&svg).await;
        });
    };
    let share = move |_| {
        let svg = plants.with(|p| field::svg(p));
        let text = share_text();
        spawn_local(async move {
            share_png(&svg, &text, &page_url()).await;
        });
    };

    view! {
        <main>
            <header>
                <h1>"すんぼる草不可避"</h1>
                <p class="tagline">"送金で生えます"</p>
            </header>
            <section class="field" inner_html=move || plants.with(|p| field::svg(p))></section>
            <p class="count">{move || if plants.with(Vec::is_empty) { String::new() } else { format!("{} 本 ・ {}", count(), plants.with(|p| tally(p))) }}</p>
            <p class="status">{move || status.get()}</p>
            <div class="buttons">
                <button on:click=save disabled=move || plants.with(Vec::is_empty)>"画像を保存"</button>
                <button on:click=share disabled=move || plants.with(Vec::is_empty)>"シェア"</button>
            </div>
            <form on:submit=move |event| { event.prevent_default(); look(()); }>
                <label>"自分のアドレス"
                    <input prop:value=move || player.get() on:input=move |e| player.set(event_target_value(&e)) placeholder="N… または T…" spellcheck="false"/>
                </label>
                <button class="primary" type="submit" disabled=move || busy.get()>"畑を見る"</button>
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
                    "自分のアドレスから送り先へ {} XYM 以上を送るたびに、畑に何かが1つ生えます。何が生えるかは、送金のハッシュで決まります。珍しいものに優劣はありません。",
                    rest::parse_xym(&min.get()).map(rest::format_xym).unwrap_or_else(|| min.get()),
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
