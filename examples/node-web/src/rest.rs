//! 公開されている REST（catapult の REST でも heika の REST でもよい）から、ブロックを取って組み直す。
//!
//! REST の答えは信じない。組み直したバイト列は、[`heika_store_redb::replay::Replay`] が署名、TransactionsHash、
//! 難易度、VRF、StateHash まで確かめてから使う。REST が間違ったものを返しても、弾かれるだけになる。

use heika_chain::verify::nemesis_hash;
use heika_core::hash::Hash256;
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_rest::block::BlockInfo;
use heika_rest::transaction::TransactionInfo;
use heika_state_transition::config::ChainConfig;
use js_sys::Promise;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Response, WorkerGlobalScope};

/// REST の1ページの件数の上限（catapult の REST の既定）
pub const PAGE_SIZE: u64 = 100;

/// 同期するネットワーク。今はメインネットとテストネットだけ
pub struct Network {
    pub name: &'static str,
    pub parameters: &'static NetworkParameters,
    pub config: ChainConfig,
    /// ここから始まるチェーンだけを受け入れる
    pub nemesis: Hash256,
}

impl Network {
    /// REST の `/node/info` の答えから決める。generation hash seed まで合わなければ、知らないネットワークにする
    pub fn from_node_info(info: &Value) -> Result<Self, String> {
        let identifier = info["networkIdentifier"]
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .map(NetworkIdentifier)
            .ok_or("/node/info に networkIdentifier がありません")?;
        let (name, parameters, config) = match identifier {
            NetworkIdentifier::MAINNET => (
                "mainnet",
                &NetworkParameters::MAINNET,
                ChainConfig::mainnet(),
            ),
            NetworkIdentifier::TESTNET => (
                "testnet",
                &NetworkParameters::TESTNET,
                ChainConfig::testnet(),
            ),
            _ => return Err("メインネットとテストネットのほかには、まだ対応していません".into()),
        };
        let seed = info["networkGenerationHashSeed"]
            .as_str()
            .unwrap_or_default();
        if !seed.eq_ignore_ascii_case(&parameters.generation_hash_seed.to_string()) {
            return Err(format!(
                "{name} とは generation hash seed が違うネットワークです"
            ));
        }
        Ok(Self {
            name,
            parameters,
            config,
            nemesis: nemesis_hash(identifier).ok_or("Nemesis のハッシュを知りません")?,
        })
    }
}

/// 取れなかったわけ
#[derive(Debug)]
pub enum FetchError {
    /// つながらない、答えが読めないなど。ほかの REST で取り直せばよい
    Unavailable(String),
    /// 答えは読めたが、組み直せない。その REST が正しくないものを返した
    Malformed(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) | Self::Malformed(reason) => f.write_str(reason),
        }
    }
}

fn scope() -> WorkerGlobalScope {
    js_sys::global().unchecked_into()
}

/// `milliseconds` ミリ秒待つ
pub async fn sleep(milliseconds: i32) {
    let promise = Promise::new(&mut |resolve, _| {
        let _ =
            scope().set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, milliseconds);
    });
    let _ = JsFuture::from(promise).await;
}

/// `origin` の `path` を JSON で取る。混んでいる（429）ときは、待つ時間を延ばしながら取り直す
pub async fn get_json(origin: &str, path: &str) -> Result<Value, FetchError> {
    let unavailable = |reason: String| FetchError::Unavailable(format!("{path}: {reason}"));
    let js = |error: JsValue| {
        error
            .as_string()
            .or_else(|| js_sys::Error::from(error).message().as_string())
            .unwrap_or_default()
    };
    let mut wait = 1000;
    loop {
        let response: Response = JsFuture::from(scope().fetch_with_str(&format!("{origin}{path}")))
            .await
            .map_err(|error| unavailable(js(error)))?
            .unchecked_into();
        if response.status() == 429 && wait <= 16_000 {
            sleep(wait).await;
            wait *= 2;
            continue;
        }
        if !response.ok() {
            return Err(unavailable(format!("HTTP {}", response.status())));
        }
        let text = JsFuture::from(response.text().map_err(|error| unavailable(js(error)))?)
            .await
            .map_err(|error| unavailable(js(error)))?
            .as_string()
            .unwrap_or_default();
        return serde_json::from_str(&text).map_err(|error| unavailable(error.to_string()));
    }
}

/// 確定した高さ。そこまでは巻き戻らないので、巻き戻しを持たない [`heika_store_redb::replay::Replay`] で進めてよい
pub async fn finalized_height(origin: &str) -> Result<u64, FetchError> {
    let info = get_json(origin, "/chain/info").await?;
    info["latestFinalizedBlock"]["height"]
        .as_str()
        .and_then(|height| height.parse().ok())
        .ok_or_else(|| FetchError::Malformed("/chain/info の確定した高さが読めません".into()))
}

/// `from` から `to` まで（[`PAGE_SIZE`] 個まで）のブロックを取り、組み直したバイト列で返す。
/// ブロックは高さの順の一覧で、トランザクションは高さの範囲の検索でまとめて取る
pub async fn fetch_blocks(origin: &str, from: u64, to: u64) -> Result<Vec<Vec<u8>>, FetchError> {
    let malformed = |reason: String| FetchError::Malformed(reason);
    let count = (to + 1).saturating_sub(from).min(PAGE_SIZE);
    let page = get_json(
        origin,
        &format!(
            "/blocks?orderBy=height&order=asc&offset={}&pageSize={PAGE_SIZE}",
            from - 1
        ),
    )
    .await?;
    let blocks: Vec<BlockInfo> = serde_json::from_value(page["data"].clone())
        .map_err(|error| malformed(format!("/blocks: {error}")))?;
    let blocks: Vec<BlockInfo> = blocks.into_iter().take(count as usize).collect();
    let last = from + blocks.len() as u64 - 1;
    if blocks.is_empty() {
        return Err(malformed(format!("高さ {from} からのブロックがありません")));
    }

    let mut found: Vec<TransactionInfo> = Vec::new();
    for number in 1.. {
        let page = get_json(
            origin,
            &format!(
                "/transactions/confirmed?fromHeight={from}&toHeight={last}&embedded=true&pageSize={PAGE_SIZE}&pageNumber={number}"
            ),
        )
        .await?;
        let data: Vec<TransactionInfo> = serde_json::from_value(page["data"].clone())
            .map_err(|error| malformed(format!("/transactions/confirmed: {error}")))?;
        let done = (data.len() as u64) < PAGE_SIZE;
        found.extend(data);
        if done {
            break;
        }
    }

    blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let height = from + index as u64;
            if block.block.height != height.to_string() {
                return Err(malformed(format!(
                    "高さ {height} のところに高さ {} のブロックがあります",
                    block.block.height
                )));
            }
            block
                .assemble(&found)
                .map_err(|error| malformed(format!("高さ {height} を組み直せません: {error}")))
        })
        .collect()
}
