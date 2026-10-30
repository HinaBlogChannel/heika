//! Ethereum の JSON-RPC のうち、cast や wallet が送金とコントラクトの呼び出しに使う分だけ。
//!
//! 状態を引くときのブロックは、`latest`（と `pending`）なら Symbol の先頭まで、`safe` と `finalized` なら
//! ファイナライズされたところまで。過去の高さの状態は持っていない。

use std::sync::{Arc, RwLock};

use alloy_consensus::{EMPTY_OMMER_ROOT_HASH, EMPTY_ROOT_HASH, Transaction as _};
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use axum::Json;
use axum::extract::State;
use heika_core::address::Address as SymbolAddress;
use heika_core::key::PrivateKey;
use revm::context::result::ExecutionResult;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::follow::Views;
use crate::rollup::{self, Call, GAS_LIMIT, Receipt, Rollup};
use crate::symbol::Chain;

/// Symbol に載せる係
pub struct Relay {
    pub chain: Chain,
    pub key: PrivateKey,
    pub inbox: SymbolAddress,
}

#[derive(Clone)]
pub struct Api {
    pub chain_id: u64,
    pub views: Arc<RwLock<Views>>,
    pub relay: Option<Arc<Relay>>,
}

struct Failure {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl Failure {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    fn params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }
}

/// 1 件でも、まとめて（配列）でも受け付ける
pub async fn handle(State(api): State<Api>, Json(request): Json<Value>) -> Json<Value> {
    match request {
        Value::Array(requests) => {
            let mut responses = Vec::new();
            for request in requests {
                responses.push(one(&api, request).await);
            }
            Json(Value::Array(responses))
        }
        request => Json(one(&api, request).await),
    }
}

async fn one(api: &Api, request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request["method"].as_str().unwrap_or_default().to_owned();
    let params = match &request["params"] {
        Value::Array(params) => params.clone(),
        _ => Vec::new(),
    };
    let result = if method == "eth_sendRawTransaction" {
        send_raw(api, &params).await
    } else {
        call(api, &method, &params)
    };
    match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(failure) => {
            let mut error = json!({"code": failure.code, "message": failure.message});
            if let Some(data) = failure.data {
                error["data"] = data;
            }
            json!({"jsonrpc": "2.0", "id": id, "error": error})
        }
    }
}

fn call(api: &Api, method: &str, params: &[Value]) -> Result<Value, Failure> {
    let views = api.views.read().expect("not poisoned").clone();
    match method {
        "eth_chainId" => Ok(quantity(api.chain_id)),
        "net_version" => Ok(json!(api.chain_id.to_string())),
        "net_listening" => Ok(json!(true)),
        "web3_clientVersion" => Ok(json!(concat!(
            "heika-evm-rollup/",
            env!("CARGO_PKG_VERSION")
        ))),
        "eth_syncing" => Ok(json!(false)),
        "eth_accounts" => Ok(json!([])),
        "eth_blockNumber" => Ok(quantity(views.latest.height)),
        "eth_gasPrice" => Ok(quantity(views.latest.base_fee())),
        "eth_maxPriorityFeePerGas" | "eth_blobBaseFee" => Ok(quantity(0)),
        "eth_feeHistory" => {
            let count = number(params.first()).unwrap_or(1).clamp(1, 1024);
            Ok(json!({
                "oldestBlock": quantity(views.latest.height.saturating_sub(count - 1)),
                "baseFeePerGas": vec![quantity(views.latest.base_fee()); count as usize + 1],
                "gasUsedRatio": vec![0.0; count as usize],
                "reward": vec![vec![quantity(0); reward_count(params)]; count as usize],
            }))
        }
        "eth_getBalance" => {
            let address = address(params.first())?;
            Ok(json!(format!(
                "{:#x}",
                view(&views, params.get(1))?.account(&address).balance
            )))
        }
        "eth_getTransactionCount" => {
            let address = address(params.first())?;
            Ok(quantity(
                view(&views, params.get(1))?.account(&address).nonce,
            ))
        }
        "eth_getCode" => {
            let address = address(params.first())?;
            Ok(json!(view(&views, params.get(1))?.code(&address)))
        }
        "eth_getStorageAt" => {
            let address = address(params.first())?;
            let slot: U256 = params
                .get(1)
                .and_then(|slot| serde_json::from_value(slot.clone()).ok())
                .ok_or_else(|| Failure::params("slot が読めません"))?;
            let value = view(&views, params.get(2))?.storage(&address, slot);
            Ok(json!(B256::from(value)))
        }
        "eth_call" => {
            let rollup = view(&views, params.get(1))?;
            match rollup
                .call(call_of(params.first())?)
                .map_err(|error| Failure::new(-32000, error))?
            {
                ExecutionResult::Success { output, .. } => Ok(json!(output.into_data())),
                failed => Err(failure_of(failed)),
            }
        }
        "eth_estimateGas" => {
            let rollup = view(&views, params.get(1))?;
            match rollup
                .call(call_of(params.first())?)
                .map_err(|error| Failure::new(-32000, error))?
            {
                // 呼び出しの先でガスを 63/64 しか渡せないぶんなどを、多めに見込む
                result @ ExecutionResult::Success { .. } => {
                    Ok(quantity((result.tx_gas_used() * 13 / 10).min(1 << 24)))
                }
                failed => Err(failure_of(failed)),
            }
        }
        "eth_getBlockByNumber" => {
            let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
            let (rollup, height) = match params.first().and_then(Value::as_str) {
                Some("safe" | "finalized") => (&views.finalized, views.finalized.height),
                Some("earliest") => (&views.latest, 0),
                Some("latest" | "pending") | None => (&views.latest, views.latest.height),
                Some(_) => (
                    &views.latest,
                    number(params.first()).ok_or_else(|| Failure::params("高さが読めません"))?,
                ),
            };
            Ok(block_json(rollup, height, full).unwrap_or(Value::Null))
        }
        "eth_getTransactionReceipt" => {
            let hash = hash(params.first())?;
            Ok(views
                .latest
                .receipt(&hash)
                .map(|receipt| receipt_json(&views.latest, &hash, receipt))
                .unwrap_or(Value::Null))
        }
        "eth_getTransactionByHash" => {
            let hash = hash(params.first())?;
            Ok(views
                .latest
                .receipt(&hash)
                .map(|receipt| transaction_json(&views.latest, receipt))
                .unwrap_or(Value::Null))
        }
        _ => Err(Failure::new(-32601, format!("{method} はありません"))),
    }
}

/// 確かめてから、リレーの鍵で Symbol に載せる。ハッシュは EVM のトランザクションのもの
async fn send_raw(api: &Api, params: &[Value]) -> Result<Value, Failure> {
    let bytes: Bytes = params
        .first()
        .and_then(|bytes| serde_json::from_value(bytes.clone()).ok())
        .ok_or_else(|| Failure::params("トランザクションが読めません"))?;
    let (envelope, _) =
        rollup::decode(&bytes, api.chain_id).map_err(|error| Failure::new(-32000, error))?;
    let relay = api
        .relay
        .clone()
        .ok_or_else(|| Failure::new(-32000, "このノードはリレーの鍵を持っていません"))?;
    tokio::task::spawn_blocking(move || relay.chain.post(&relay.key, &relay.inbox, &bytes))
        .await
        .map_err(|error| Failure::new(-32000, error.to_string()))?
        .map_err(|error| Failure::new(-32000, error))?;
    Ok(json!(envelope.tx_hash()))
}

/// ブロックの指定から、どちらの状態で答えるか
fn view<'a>(views: &'a Views, tag: Option<&Value>) -> Result<&'a Rollup, Failure> {
    let tag = match tag {
        Some(Value::Object(object)) => object.get("blockNumber"),
        tag => tag,
    };
    match tag.and_then(Value::as_str) {
        None | Some("latest" | "pending") => Ok(&views.latest),
        Some("safe" | "finalized") => Ok(&views.finalized),
        Some(_) => match number(tag) {
            Some(height) if height >= views.latest.height => Ok(&views.latest),
            Some(height) if height == views.finalized.height => Ok(&views.finalized),
            _ => Err(Failure::new(
                -32000,
                "過去の高さの状態は持っていません（latest か finalized を使ってください）",
            )),
        },
    }
}

fn block_json(rollup: &Rollup, height: u64, full: bool) -> Option<Value> {
    let block = rollup.block(height)?;
    let receipts: Vec<&Receipt> = block
        .transactions
        .iter()
        .filter_map(|hash| rollup.receipt(hash))
        .collect();
    let gas_used: u64 = receipts.iter().map(|receipt| receipt.gas_used).sum();
    let mut bloom = Bloom::default();
    for receipt in &receipts {
        bloom.accrue_bloom(&receipt.bloom());
    }
    let transactions: Vec<Value> = if full {
        receipts
            .iter()
            .map(|receipt| transaction_json(rollup, receipt))
            .collect()
    } else {
        block.transactions.iter().map(|hash| json!(hash)).collect()
    };
    let parent = height
        .checked_sub(1)
        .and_then(|parent| rollup.block_hash(parent))
        .unwrap_or_default();
    Some(json!({
        "number": quantity(height),
        "hash": rollup.block_hash(height)?,
        "parentHash": parent,
        "timestamp": quantity(block.timestamp),
        "stateRoot": block.state_root,
        "transactionsRoot": EMPTY_ROOT_HASH,
        "receiptsRoot": EMPTY_ROOT_HASH,
        "sha3Uncles": EMPTY_OMMER_ROOT_HASH,
        "logsBloom": bloom,
        "miner": Address::ZERO,
        "difficulty": quantity(0),
        "totalDifficulty": quantity(0),
        "mixHash": B256::ZERO,
        "nonce": "0x0000000000000000",
        "gasLimit": quantity(GAS_LIMIT),
        "gasUsed": quantity(gas_used),
        "baseFeePerGas": quantity(block.base_fee),
        "extraData": "0x",
        "size": quantity(0),
        "uncles": [],
        "transactions": transactions,
    }))
}

fn transaction_json(rollup: &Rollup, receipt: &Receipt) -> Value {
    let mut value = serde_json::to_value(&receipt.envelope).unwrap_or_else(|_| json!({}));
    value["hash"] = json!(receipt.envelope.tx_hash());
    value["from"] = json!(receipt.from);
    value["blockNumber"] = quantity(receipt.height);
    value["blockHash"] = json!(rollup.block_hash(receipt.height));
    value["transactionIndex"] = quantity(receipt.index);
    value["gasPrice"] = json!(format!("{:#x}", receipt.effective_gas_price));
    value
}

fn receipt_json(rollup: &Rollup, hash: &B256, receipt: &Receipt) -> Value {
    let block_hash = rollup.block_hash(receipt.height);
    // ログの番号は、ブロックの中で通して数える
    let before: usize = rollup
        .block(receipt.height)
        .map(|block| {
            block
                .transactions
                .iter()
                .take(receipt.index as usize)
                .filter_map(|hash| rollup.receipt(hash))
                .map(|receipt| receipt.logs.len())
                .sum()
        })
        .unwrap_or_default();
    let logs: Vec<Value> = receipt
        .logs
        .iter()
        .enumerate()
        .map(|(index, log)| {
            json!({
                "address": log.address,
                "topics": log.topics(),
                "data": log.data.data,
                "blockNumber": quantity(receipt.height),
                "blockHash": block_hash,
                "transactionHash": hash,
                "transactionIndex": quantity(receipt.index),
                "logIndex": quantity((before + index) as u64),
                "removed": false,
            })
        })
        .collect();
    json!({
        "transactionHash": hash,
        "transactionIndex": quantity(receipt.index),
        "blockHash": block_hash,
        "blockNumber": quantity(receipt.height),
        "from": receipt.from,
        "to": receipt.envelope.to(),
        "cumulativeGasUsed": quantity(receipt.cumulative_gas_used),
        "gasUsed": quantity(receipt.gas_used),
        "effectiveGasPrice": format!("{:#x}", receipt.effective_gas_price),
        "contractAddress": receipt.contract_address,
        "logs": logs,
        "logsBloom": receipt.bloom(),
        "status": quantity(u64::from(receipt.success)),
        "type": quantity(u64::from(receipt.envelope.tx_type() as u8)),
    })
}

fn failure_of(result: ExecutionResult) -> Failure {
    match result {
        ExecutionResult::Revert { output, .. } => Failure {
            code: 3,
            message: "execution reverted".to_owned(),
            data: Some(json!(output)),
        },
        ExecutionResult::Halt { reason, .. } => Failure::new(-32000, format!("{reason:?}")),
        ExecutionResult::Success { .. } => Failure::new(-32000, "成功しています"),
    }
}

fn call_of(value: Option<&Value>) -> Result<Call, Failure> {
    let value = value.ok_or_else(|| Failure::params("呼び出しの中身がありません"))?;
    let gas: Option<U256> = field(value, "gas")?;
    Ok(Call {
        from: field(value, "from")?,
        to: field(value, "to")?,
        gas: gas.map(|gas| gas.saturating_to()),
        value: field(value, "value")?,
        input: match field(value, "input")? {
            Some(input) => Some(input),
            None => field(value, "data")?,
        },
    })
}

/// `value` の欄 `name`。なければ（null も）`None`
fn field<T: DeserializeOwned>(value: &Value, name: &str) -> Result<Option<T>, Failure> {
    value
        .get(name)
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value(value.clone())
                .map_err(|_| Failure::params(format!("{name} が読めません")))
        })
        .transpose()
}

fn reward_count(params: &[Value]) -> usize {
    params.get(2).and_then(Value::as_array).map_or(0, Vec::len)
}

fn address(value: Option<&Value>) -> Result<Address, Failure> {
    value
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .ok_or_else(|| Failure::params("アドレスが読めません"))
}

fn hash(value: Option<&Value>) -> Result<B256, Failure> {
    value
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .ok_or_else(|| Failure::params("ハッシュが読めません"))
}

/// `0x` で始まる 16 進か、10 進の数
fn number(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => match text.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => text.parse().ok(),
        },
        _ => None,
    }
}

fn quantity(value: u64) -> Value {
    json!(format!("{value:#x}"))
}
