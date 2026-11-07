//! Symbol の側。受け箱に宛てた EVM のトランザクションを、ブロックの中の順に読む。リレーとして、受け取ったものを載せる。
//! 橋があれば、預かり口座への入金も読む。
//!
//! 読むのはノードの REST（catapult の REST と同じ検索）なので、heika のノードなら、設定の `storage.search` に
//! `Transactions` を入れておく。

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_rest::block::BlockInfo;
use heika_rest::node::{ChainInfoJson, TransactionFeesJson};
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body};
use heika_rest::state::AccountInfo;
use heika_rest::transaction::TransactionInfo;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, Transaction, Transfer, UnresolvedAddress,
};
use serde::Deserialize;

use crate::envelope;
use crate::rollup::Deposit;
use crate::vault;

/// 載せるトランザクションの期限。Symbol の上限は 6 時間だが、署名にかかる時間を見込んでも 1 時間で足りる
const LIFETIME: Duration = Duration::from_secs(60 * 60);

/// 送金の種類（`TRANSFER`）
const TRANSFER_TYPE: u16 = 0x4154;

/// 検索の 1 ページの件数
const PAGE_SIZE: usize = 100;

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
});

/// 受け箱に載った EVM のトランザクション 1 件
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posted {
    pub height: u64,
    /// ブロックの Unix 時刻（秒）
    pub timestamp: u64,
    /// EIP-2718 の形のバイト列（読めるかどうかは、まだ確かめていない）
    pub bytes: Vec<u8>,
}

/// 預かり口座への入金 1 つと、それが入ったブロック
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    pub height: u64,
    /// ブロックの Unix 時刻（秒）
    pub timestamp: u64,
    pub deposit: Deposit,
}

/// Symbol のノードの REST
pub struct Chain {
    pub parameters: &'static NetworkParameters,
    /// `http://127.0.0.1:3000` など
    rest: String,
}

#[derive(Deserialize)]
struct Page {
    data: Vec<TransactionInfo>,
}

impl Chain {
    /// `heika peer start` と同じ設定から、ネットワークと REST（最初の `rest` の口）を決める
    pub fn load(config: &Path) -> Result<Self, String> {
        let manifest = Manifest::load(config).map_err(|error| error.to_string())?;
        let parameters =
            driver::network_parameters(&manifest.spec).map_err(|error| error.to_string())?;
        let listen = &manifest
            .spec
            .rest
            .first()
            .ok_or("ノードの設定に rest がありません")?
            .address;
        Ok(Self {
            parameters,
            rest: format!("http://{}", listen.replace("0.0.0.0", "127.0.0.1")),
        })
    }

    /// 先頭の高さと、ファイナライズされた高さ
    pub fn heights(&self) -> Result<(u64, u64), String> {
        let info: ChainInfoJson = self.json("/chain/info")?;
        let number = |text: &str| {
            text.parse()
                .map_err(|_| format!("高さが読めません: {text}"))
        };
        Ok((
            number(&info.height)?,
            number(&info.latest_finalized_block.height)?,
        ))
    }

    /// 高さ `height` のブロックの Unix 時刻（秒）
    pub fn block_time(&self, height: u64) -> Result<u64, String> {
        let info: BlockInfo = self.json(&format!("/blocks/{height}"))?;
        let timestamp: u64 = info
            .block
            .timestamp
            .parse()
            .map_err(|_| format!("時刻が読めません: {}", info.block.timestamp))?;
        Ok(self.unix_time(timestamp))
    }

    fn unix_time(&self, timestamp: u64) -> u64 {
        self.parameters.epoch_adjustment.as_secs() + timestamp / 1000
    }

    /// 高さ `from` から `to` までに受け箱 `inbox` に載った EVM のトランザクションを、載った順に
    pub fn posted(&self, inbox: &Address, from: u64, to: u64) -> Result<Vec<Posted>, String> {
        // 外側のトランザクション（アグリゲートなら、そのハッシュ）ごとに、メッセージを順に集める
        let mut groups: Vec<(String, Posted, Vec<Vec<u8>>)> = Vec::new();
        for info in self.search(&format!(
            "recipientAddress={inbox}&type={TRANSFER_TYPE}&embedded=true&fromHeight={from}&toHeight={to}"
        ))? {
            let meta = &info.meta;
            let (Some(key), Some(height), Some(timestamp), Some(message)) = (
                meta.aggregate_hash.as_ref().or(meta.hash.as_ref()),
                meta.height.as_deref().and_then(|height| height.parse().ok()),
                meta.timestamp
                    .as_deref()
                    .and_then(|timestamp| timestamp.parse().ok()),
                info.transaction.body.message.as_deref().and_then(hex),
            ) else {
                continue;
            };
            match groups.last_mut() {
                Some((last, _, messages)) if last == key => messages.push(message),
                _ => groups.push((
                    key.clone(),
                    Posted {
                        height,
                        timestamp: self.unix_time(timestamp),
                        bytes: Vec::new(),
                    },
                    vec![message],
                )),
            }
        }
        Ok(groups
            .into_iter()
            .map(|(_, mut posted, messages)| {
                posted.bytes = envelope::unwrap(messages.iter().map(Vec::as_slice));
                posted
            })
            .filter(|posted| !posted.bytes.is_empty())
            .collect())
    }

    /// 高さ `from` から `to` までの、預かり口座 `vault` への XYM の入金。メッセージに EVM のアドレスがないもの、
    /// XYM が入っていないものは飛ばす（預かり口座には入るが、ロールアップには入らない）
    pub fn deposits(&self, vault: &Address, from: u64, to: u64) -> Result<Vec<Received>, String> {
        let mut received = Vec::new();
        for info in self.search(&format!(
            "recipientAddress={vault}&type={TRANSFER_TYPE}&embedded=true&fromHeight={from}&toHeight={to}"
        ))? {
            let meta = &info.meta;
            let body = &info.transaction.body;
            let (Some(height), Some(timestamp), Some(to)) = (
                meta.height.as_deref().and_then(|height| height.parse().ok()),
                meta.timestamp
                    .as_deref()
                    .and_then(|timestamp| timestamp.parse().ok()),
                body.message
                    .as_deref()
                    .and_then(hex)
                    .and_then(|message| vault::evm_recipient(&message)),
            ) else {
                continue;
            };
            let amount = body
                .mosaics
                .iter()
                .flatten()
                .filter(|mosaic| {
                    u64::from_str_radix(&mosaic.id, 16).ok()
                        == Some(self.parameters.currency_mosaic_id)
                })
                .filter_map(|mosaic| mosaic.amount.parse::<u64>().ok())
                .fold(0u64, u64::saturating_add);
            if amount > 0 {
                received.push(Received {
                    height,
                    timestamp: self.unix_time(timestamp),
                    deposit: Deposit {
                        to: to.into(),
                        amount,
                    },
                });
            }
        }
        Ok(received)
    }

    /// 預かり口座 `vault` から、もう払った引き出しの番号
    pub fn paid_withdrawals(&self, vault: &PublicKey) -> Result<BTreeSet<u64>, String> {
        Ok(self
            .search(&format!(
                "signerPublicKey={vault}&embedded=true&type={TRANSFER_TYPE}"
            ))?
            .iter()
            .filter_map(|info| info.transaction.body.message.as_deref())
            .filter_map(|message| vault::withdrawal_id(&hex(message)?))
            .collect())
    }

    pub fn address(&self, key: &PublicKey) -> Address {
        Address::from_public_key(key, self.parameters.identifier)
    }

    /// ネットワークの時刻（エポックからのミリ秒）
    pub fn now(&self) -> Result<u64, String> {
        self.parameters
            .timestamp_at(SystemTime::now())
            .map(|timestamp| timestamp.0)
            .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
    }

    /// 今から [`LIFETIME`] 後の期限
    pub fn deadline(&self) -> Result<u64, String> {
        self.parameters
            .timestamp_at(SystemTime::now() + LIFETIME)
            .map(|timestamp| timestamp.0)
            .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
    }

    /// `address` の XYM。まだ誰も知らないアカウントなら 0
    pub fn balance(&self, address: &Address) -> Result<u64, String> {
        let Some(body) = self.get(&format!("/accounts/{address}"))? else {
            return Ok(0);
        };
        let info: AccountInfo = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        Ok(info
            .account
            .mosaics
            .iter()
            .filter(|mosaic| {
                u64::from_str_radix(&mosaic.id, 16).ok() == Some(self.parameters.currency_mosaic_id)
            })
            .filter_map(|mosaic| mosaic.amount.parse::<u64>().ok())
            .sum())
    }

    /// 承認されるか弾かれるまで、`timeout` だけ待つ。承認された高さを返す
    pub fn confirm(&self, transaction: &Transaction, timeout: Duration) -> Result<u64, String> {
        let path = TransactionStatus::path(transaction, &self.parameters.generation_hash_seed);
        let started = Instant::now();
        while started.elapsed() < timeout {
            if let Some(body) = self.get(&path)? {
                let status = TransactionStatus::from_slice(&body)?;
                match (status.group.as_str(), status.height) {
                    ("confirmed", Some(height)) => {
                        return height
                            .parse()
                            .map_err(|_| format!("承認された高さが読めません: {height}"));
                    }
                    ("failed", _) => {
                        return Err(format!("弾かれました: {}", status.code.unwrap_or_default()));
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!(
            "{} 秒待っても承認されませんでした",
            timeout.as_secs()
        ))
    }

    /// `transaction`（EIP-2718 の形）を受け箱に載せる。リレーの鍵 `key` で署名し、手数料も払う
    pub fn post(
        &self,
        key: &PrivateKey,
        inbox: &Address,
        transaction: &[u8],
    ) -> Result<Hash256, String> {
        let parameters = self.parameters;
        let parts = envelope::wrap(
            transaction,
            parameters.max_message_size,
            parameters.max_transactions_per_aggregate,
        )
        .ok_or("大きすぎて Symbol のトランザクション 1 つに収まりません")?;
        let signer = PublicKey::from_private_key(key);
        let mut bodies = parts.into_iter().map(|message| {
            Body::Transfer(
                Transfer::new(UnresolvedAddress::from(*inbox), BTreeMap::new(), message)
                    .expect("no mosaics and a short message"),
            )
        });
        let body = if bodies.len() == 1 {
            bodies.next().expect("one part")
        } else {
            let embedded = bodies
                .map(|body| EmbeddedTransaction::new(signer, parameters.identifier, body))
                .collect();
            Body::AggregateComplete(Aggregate::new(embedded).expect("not nested"))
        };
        let mut transaction =
            Transaction::new(signer, parameters.identifier, 0, self.deadline()?, body);
        transaction.fee = transaction.fee_for(self.fee_multiplier()?, 0);
        transaction
            .sign(key, &parameters.generation_hash_seed)
            .map_err(|error| error.to_string())?;
        self.announce(&transaction)?;
        Ok(transaction.hash(&parameters.generation_hash_seed))
    }

    /// 直近のブロックの中央値。ノードの下限より低ければ下限
    pub fn fee_multiplier(&self) -> Result<u32, String> {
        let fees: TransactionFeesJson = self.json("/network/fees/transaction")?;
        Ok(fees.median_fee_multiplier.max(fees.min_fee_multiplier))
    }

    /// 承認されたトランザクションを、古いものから全部
    fn search(&self, query: &str) -> Result<Vec<TransactionInfo>, String> {
        let mut found = Vec::new();
        for number in 1.. {
            let page: Page = self.json(&format!(
                "/transactions/confirmed?{query}&order=asc&pageSize={PAGE_SIZE}&pageNumber={number}"
            ))?;
            let last = page.data.len() < PAGE_SIZE;
            found.extend(page.data);
            if last {
                break;
            }
        }
        Ok(found)
    }

    pub fn announce(&self, transaction: &Transaction) -> Result<(), String> {
        let response = AGENT
            .put(&format!("{}{ANNOUNCE_PATH}", self.rest))
            .header("Content-Type", "application/json")
            .send(announce_body(transaction))
            .map_err(|error| format!("REST に送れませんでした: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "REST が受け付けませんでした: {}",
                response.status()
            ));
        }
        Ok(())
    }

    fn json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let body = self.get(path)?.ok_or_else(|| format!("{path}: 404"))?;
        serde_json::from_slice(&body).map_err(|error| format!("{path}: {error}"))
    }

    /// 見つからなければ `None`
    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let mut response = AGENT
            .get(&format!("{}{path}", self.rest))
            .call()
            .map_err(|error| format!("{path}: {error}"))?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .read_to_vec()
                .map(Some)
                .map_err(|error| format!("{path}: {error}")),
            404 => Ok(None),
            501 => Err(format!(
                "{path}: 501（heika のノードなら、設定の storage.search に Transactions を入れてください）"
            )),
            status => Err(format!("{path}: {status}")),
        }
    }
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}
