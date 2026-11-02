//! 公開されている REST（catapult の REST でも heika の REST でもよい）から、ブロックを取って組み直す。
//!
//! REST の答えは信じない。組み直したバイト列は、[`heika_store_redb::replay::Replay`] が署名、TransactionsHash、
//! 難易度、VRF、StateHash まで確かめてから使う。REST が間違ったものを返しても、弾かれるだけになる。

use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_chain::verify::nemesis_hash;
use heika_core::hash::Hash256;
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_packet::ChainStatistics;
use heika_rest::block::BlockInfo;
use heika_rest::finalization::FinalizationProof;
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
    // 先端より先を頼まれたら、空で返す
    if blocks.is_empty() {
        return Ok(Vec::new());
    }
    let last = from + blocks.len() as u64 - 1;

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

/// `/chain/info` の、高さ、確定した高さ、スコアと、確定したブロック
pub async fn chain_info(
    origin: &str,
) -> Result<(ChainStatistics, FinalizedBlockHeader), FetchError> {
    let info = get_json(origin, "/chain/info").await?;
    let malformed = || FetchError::Malformed("/chain/info が読めません".into());
    let number = |value: &Value| value.as_str().and_then(|text| text.parse::<u64>().ok());
    let finalized = &info["latestFinalizedBlock"];
    let header = FinalizedBlockHeader {
        round: FinalizationRound {
            epoch: finalized["finalizationEpoch"]
                .as_u64()
                .and_then(|epoch| u32::try_from(epoch).ok())
                .ok_or_else(malformed)?,
            point: finalized["finalizationPoint"]
                .as_u64()
                .and_then(|point| u32::try_from(point).ok())
                .ok_or_else(malformed)?,
        },
        height: number(&finalized["height"]).ok_or_else(malformed)?,
        hash: finalized["hash"]
            .as_str()
            .and_then(|hash| hash.parse().ok())
            .ok_or_else(malformed)?,
    };
    let statistics = ChainStatistics {
        height: number(&info["height"]).ok_or_else(malformed)?,
        finalized_height: header.height,
        score: (u128::from(number(&info["scoreHigh"]).ok_or_else(malformed)?) << 64)
            | u128::from(number(&info["scoreLow"]).ok_or_else(malformed)?),
    };
    Ok((statistics, header))
}

/// `from` から `count` 個（[`PAGE_SIZE`] まで）のブロックのハッシュ。先端より先は返らない
pub async fn fetch_hashes(
    origin: &str,
    from: u64,
    count: u32,
) -> Result<Vec<[u8; 32]>, FetchError> {
    let page = get_json(
        origin,
        &format!(
            "/blocks?orderBy=height&order=asc&offset={}&pageSize={PAGE_SIZE}",
            from - 1
        ),
    )
    .await?;
    let blocks: Vec<BlockInfo> = serde_json::from_value(page["data"].clone())
        .map_err(|error| FetchError::Malformed(format!("/blocks: {error}")))?;
    blocks
        .iter()
        .take(count as usize)
        .map(|block| {
            block
                .meta
                .hash
                .parse::<Hash256>()
                .map(|hash| hash.0)
                .map_err(|_| FetchError::Malformed("/blocks のハッシュが読めません".into()))
        })
        .collect()
}

/// エポック `epoch` のファイナライズの証明を、ノードが返すバイナリの形で。まだなければ `None`
pub async fn fetch_proof(origin: &str, epoch: u32) -> Result<Option<Vec<u8>>, FetchError> {
    let path = format!("/finalization/proof/epoch/{epoch}");
    let proof = match get_json(origin, &path).await {
        Ok(proof) => proof,
        Err(FetchError::Unavailable(reason)) if reason.ends_with("HTTP 404") => return Ok(None),
        Err(error) => return Err(error),
    };
    let proof: FinalizationProof = serde_json::from_value(proof)
        .map_err(|error| FetchError::Malformed(format!("{path}: {error}")))?;
    proof
        .to_bytes()
        .map(Some)
        .map_err(|error| FetchError::Malformed(format!("{path}: {error}")))
}

/// 作ったブロックを、heika のノードの REST（`PUT /blocks`）に出す。catapult の REST には、この口はない。
/// 受け取られても、足すかはそのノードのチェーンがあとで決める
pub async fn put_block(origin: &str, block: &[u8]) -> Result<(), FetchError> {
    let unavailable = |reason: String| FetchError::Unavailable(format!("PUT /blocks: {reason}"));
    let js = |error: JsValue| {
        error
            .as_string()
            .or_else(|| js_sys::Error::from(error).message().as_string())
            .unwrap_or_default()
    };
    let headers = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &headers,
        &"Content-Type".into(),
        &"application/octet-stream".into(),
    );
    let init = web_sys::RequestInit::new();
    init.set_method("PUT");
    init.set_headers(&headers);
    init.set_body(&js_sys::Uint8Array::from(block));
    let response: Response =
        JsFuture::from(scope().fetch_with_str_and_init(&format!("{origin}/blocks"), &init))
            .await
            .map_err(|error| unavailable(js(error)))?
            .unchecked_into();
    if response.ok() {
        return Ok(());
    }
    // heika は断ったわけを JSON の message に入れる
    let status = response.status();
    let text = match response.text() {
        Ok(promise) => JsFuture::from(promise)
            .await
            .ok()
            .and_then(|text| text.as_string())
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    let message = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|body| body["message"].as_str().map(str::to_owned))
        .unwrap_or_default();
    Err(unavailable(
        format!("HTTP {status} {message}").trim_end().to_owned(),
    ))
}

/// 未承認のトランザクションを取って組み直す。アグリゲートは、平たく並んで返る中のトランザクションをまとめて入れる。
/// 組み直せないもの（ページの境目で中のトランザクションが切れたものなど）は飛ばす。中身は確かめないので、使う側が
/// 確かめる（[`heika_mempool::Mempool::add`] は署名と規則を確かめる）
pub async fn fetch_unconfirmed(origin: &str, max_pages: u32) -> Result<Vec<Vec<u8>>, FetchError> {
    let mut found: Vec<TransactionInfo> = Vec::new();
    for number in 1..=max_pages {
        let page = get_json(
            origin,
            &format!(
                "/transactions/unconfirmed?embedded=true&pageSize={PAGE_SIZE}&pageNumber={number}"
            ),
        )
        .await?;
        let data: Vec<TransactionInfo> =
            serde_json::from_value(page["data"].clone()).map_err(|error| {
                FetchError::Malformed(format!("/transactions/unconfirmed: {error}"))
            })?;
        let done = (data.len() as u64) < PAGE_SIZE;
        found.extend(data);
        if done {
            break;
        }
    }
    Ok(found
        .iter()
        .filter(|entry| entry.meta.aggregate_hash.is_none())
        .filter_map(|entry| {
            if matches!(entry.transaction.transaction_type, 0x4141 | 0x4241) {
                entry
                    .with_embedded(&found)
                    .ok()?
                    .transaction
                    .to_bytes()
                    .ok()
            } else {
                entry.transaction.to_bytes().ok()
            }
        })
        .collect())
}
