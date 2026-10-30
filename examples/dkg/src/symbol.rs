//! Symbol の側。掲示板を読み書きし、預かり口座のトランザクションを作る。
//!
//! 掲示板は、受け箱（[`wire::inbox`]）に宛てた転送のメッセージ。読むのはノードの REST（catapult の REST と同じ検索）
//! なので、heika のノードなら、設定の `storage.search` に `Transactions` を入れておく。
//!
//! 掲示板に載せるのは中継役（リレー）。参加者は自分の鍵で中身に署名するので、誰が載せても同じ。手数料は中継役が払う。
//! 参加者が自分で載せてもいい。
//!
//! 預かり口座のトランザクションも、署名して手数料を払うのは中継役。預かり口座の中のトランザクションには、
//! 預かり口座の連署者（グループ鍵）が連署する。

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_core::signature::Signature;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_rest::node::{ChainInfoJson, TransactionFeesJson};
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body};
use heika_rest::transaction::TransactionInfo;
use heika_transaction::{
    Aggregate, Body, Cosignature, EmbeddedTransaction, MultisigAccountModification, Transaction,
    Transfer, UnresolvedAddress, UnresolvedMosaicId,
};
use serde::Deserialize;

use crate::wire::PREFIX;

/// トランザクションの期限
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

/// `bytes` を、メッセージ 1 つに `max_message` バイトまでのメッセージに分ける。`max_parts` 個を超えるなら `None`
pub fn wrap(bytes: &[u8], max_message: usize, max_parts: usize) -> Option<Vec<Vec<u8>>> {
    let room = max_message
        .checked_sub(PREFIX.len())
        .filter(|room| *room > 0)?;
    let parts: Vec<Vec<u8>> = bytes
        .chunks(room)
        .map(|chunk| [PREFIX, chunk].concat())
        .collect();
    (!parts.is_empty() && parts.len() <= max_parts).then_some(parts)
}

/// 同じ Symbol のトランザクションの中のメッセージを、順につなげる。[`PREFIX`] のないものは飛ばす
pub fn unwrap<'a>(messages: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    messages
        .into_iter()
        .filter_map(|message| message.strip_prefix(PREFIX))
        .flatten()
        .copied()
        .collect()
}

/// 通貨（XYM）だけの送金
fn transfer(parameters: &NetworkParameters, recipient: Address, amount: u64) -> Body {
    Body::Transfer(
        Transfer::new(
            UnresolvedAddress::from(recipient),
            [(UnresolvedMosaicId(parameters.currency_mosaic_id), amount)].into(),
            Vec::new(),
        )
        .expect("one mosaic"),
    )
}

/// 連署者を足す・外すのと、承認と削除に要る数を変えるの
fn multisig(additions: &[Address], deletions: &[Address], delta: i8) -> Body {
    let addresses = |addresses: &[Address]| {
        addresses
            .iter()
            .copied()
            .map(UnresolvedAddress::from)
            .collect::<Vec<_>>()
            .try_into()
            .expect("one address")
    };
    Body::MultisigAccountModification(MultisigAccountModification {
        min_removal_delta: delta,
        min_approval_delta: delta,
        address_additions: addresses(additions),
        address_deletions: addresses(deletions),
    })
}

/// 中継役 `relay` が署名して手数料を払うアグリゲート。手数料は `cosignatures` 個の連署のぶんまで見込む。
///
/// catapult は、アグリゲートの署名者も連署者の 1 人に数え、どれかの中のトランザクションに要る署名者であることを求める
/// （`MultisigAggregateEligibleCosignatoriesValidator`）。中継役が中で何もしないなら、中継役から中継役への、
/// 中身のない転送に署名させる
fn aggregate(
    parameters: &NetworkParameters,
    relay: PublicKey,
    deadline: u64,
    fee_multiplier: u32,
    cosignatures: usize,
    mut transactions: Vec<(PublicKey, Body)>,
) -> Transaction {
    if !transactions.iter().any(|(signer, _)| *signer == relay) {
        let own = Address::from_public_key(&relay, parameters.identifier);
        let empty = Transfer::new(UnresolvedAddress::from(own), BTreeMap::new(), Vec::new())
            .expect("no mosaics and no message");
        transactions.insert(0, (relay, Body::Transfer(empty)));
    }
    let transactions = transactions
        .into_iter()
        .map(|(signer, body)| EmbeddedTransaction::new(signer, parameters.identifier, body))
        .collect();
    let mut transaction = Transaction::new(
        relay,
        parameters.identifier,
        0,
        deadline,
        Body::AggregateComplete(Aggregate::new(transactions).expect("not nested")),
    );
    transaction.fee = transaction.fee_for(fee_multiplier, cosignatures);
    transaction
}

/// 預かり口座 `vault` に `amount` を入れ、`committee` だけを連署者にした 1-of-1 のマルチシグにする。
/// 預かり口座の鍵と `committee` が連署する（連署者に加わるには、加わる側の同意が要る）
pub fn setup(
    parameters: &NetworkParameters,
    (deadline, fee_multiplier): (u64, u32),
    relay: PublicKey,
    vault: PublicKey,
    committee: PublicKey,
    amount: u64,
) -> Transaction {
    let vault_address = Address::from_public_key(&vault, parameters.identifier);
    let committee = Address::from_public_key(&committee, parameters.identifier);
    aggregate(
        parameters,
        relay,
        deadline,
        fee_multiplier,
        2,
        vec![
            (relay, transfer(parameters, vault_address, amount)),
            (vault, multisig(&[committee], &[], 1)),
        ],
    )
}

/// 預かり口座の連署者を、`old` から `new` に差し替える。`old`（今の連署者）と `new`（加わる側の同意）が連署する
pub fn rotate(
    parameters: &NetworkParameters,
    (deadline, fee_multiplier): (u64, u32),
    relay: PublicKey,
    vault: PublicKey,
    old: PublicKey,
    new: PublicKey,
) -> Transaction {
    let old = Address::from_public_key(&old, parameters.identifier);
    let new = Address::from_public_key(&new, parameters.identifier);
    aggregate(
        parameters,
        relay,
        deadline,
        fee_multiplier,
        2,
        vec![(vault, multisig(&[new], &[old], 0))],
    )
}

/// 預かり口座から `recipient` に送る。預かり口座の連署者が連署する
pub fn spend(
    parameters: &NetworkParameters,
    (deadline, fee_multiplier): (u64, u32),
    relay: PublicKey,
    vault: PublicKey,
    recipient: Address,
    amount: u64,
) -> Transaction {
    aggregate(
        parameters,
        relay,
        deadline,
        fee_multiplier,
        1,
        vec![(vault, transfer(parameters, recipient, amount))],
    )
}

/// 預かり口座の鍵そのもので、預かり口座から送る（マルチシグになったあとは、弾かれるはず）
pub fn direct(
    parameters: &NetworkParameters,
    (deadline, fee_multiplier): (u64, u32),
    vault: PublicKey,
    recipient: Address,
    amount: u64,
) -> Transaction {
    let mut transaction = Transaction::new(
        vault,
        parameters.identifier,
        0,
        deadline,
        transfer(parameters, recipient, amount),
    );
    transaction.fee = transaction.fee_for(fee_multiplier, 0);
    transaction
}

/// アグリゲートに連署を足す
pub fn cosign(transaction: &mut Transaction, signer: PublicKey, signature: Signature) {
    let Body::AggregateComplete(aggregate) = &mut transaction.body else {
        panic!("not an aggregate");
    };
    aggregate.add_cosignature(Cosignature {
        signer_public_key: signer,
        signature,
    });
}

/// ノードの REST
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
    /// `heika experimental peer start` と同じ設定から、ネットワークと REST（最初の `rest` の口）を決める
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

    pub fn address(&self, key: &PublicKey) -> Address {
        Address::from_public_key(key, self.parameters.identifier)
    }

    /// 今から 1 時間後の期限と、手数料の倍率（直近のブロックの中央値。ノードの下限より低ければ下限）
    pub fn terms(&self) -> Result<(u64, u32), String> {
        let deadline = self
            .parameters
            .timestamp_at(SystemTime::now() + LIFETIME)
            .ok_or("時計がネットワークのエポックより前になっています")?;
        let fees: TransactionFeesJson = self.json("/network/fees/transaction")?;
        Ok((
            deadline.0,
            fees.median_fee_multiplier.max(fees.min_fee_multiplier),
        ))
    }

    /// ファイナライズされた高さ
    pub fn finalized_height(&self) -> Result<u64, String> {
        let info: ChainInfoJson = self.json("/chain/info")?;
        info.latest_finalized_block
            .height
            .parse()
            .map_err(|_| "ファイナライズされた高さが読めません".to_owned())
    }

    /// 高さ `from` から `to` までに受け箱 `inbox` に載ったものを、載った順に（高さと中身）
    pub fn posted(
        &self,
        inbox: &Address,
        from: u64,
        to: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, String> {
        // 外側のトランザクション（アグリゲートなら、そのハッシュ）ごとに、メッセージを順に集める
        let mut groups: Vec<(String, u64, Vec<Vec<u8>>)> = Vec::new();
        for info in self.search(&format!(
            "recipientAddress={inbox}&type={TRANSFER_TYPE}&embedded=true&fromHeight={from}&toHeight={to}"
        ))? {
            let meta = &info.meta;
            let (Some(key), Some(height), Some(message)) = (
                meta.aggregate_hash.as_ref().or(meta.hash.as_ref()),
                meta.height.as_deref().and_then(|height| height.parse().ok()),
                info.transaction.body.message.as_deref().and_then(hex),
            ) else {
                continue;
            };
            match groups.last_mut() {
                Some((last, _, messages)) if last == key => messages.push(message),
                _ => groups.push((key.clone(), height, vec![message])),
            }
        }
        Ok(groups
            .into_iter()
            .map(|(_, height, messages)| (height, unwrap(messages.iter().map(Vec::as_slice))))
            .filter(|(_, bytes)| !bytes.is_empty())
            .collect())
    }

    /// `bytes` を受け箱 `inbox` に載せる。中継役の鍵 `relay` で署名し、手数料も払う
    pub fn post(
        &self,
        relay: &PrivateKey,
        inbox: &Address,
        bytes: &[u8],
    ) -> Result<Hash256, String> {
        let parameters = self.parameters;
        let parts = wrap(
            bytes,
            parameters.max_message_size,
            parameters.max_transactions_per_aggregate,
        )
        .ok_or("大きすぎて Symbol のトランザクション 1 つに収まりません")?;
        let signer = PublicKey::from_private_key(relay);
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
        let (deadline, fee_multiplier) = self.terms()?;
        let mut transaction = Transaction::new(signer, parameters.identifier, 0, deadline, body);
        transaction.fee = transaction.fee_for(fee_multiplier, 0);
        transaction
            .sign(relay, &parameters.generation_hash_seed)
            .map_err(|error| error.to_string())?;
        self.announce(&transaction)?;
        Ok(transaction.hash(&parameters.generation_hash_seed))
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

    /// 承認されるか弾かれるまで、`timeout` だけ待つ。承認された高さを返す。弾かれたら、その理由を `Err` で返す
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

    fn json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let body = self.get(path)?.ok_or_else(|| format!("{path}: 404"))?;
        serde_json::from_slice(&body).map_err(|error| format!("{path}: {error}"))
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_unwraps() {
        let bytes: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let parts = wrap(&bytes, 1024, 100).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.len() <= 1024));
        assert_eq!(unwrap(parts.iter().map(Vec::as_slice)), bytes);
        assert!(wrap(&[0; 1021], 1024, 1).is_none());
        assert!(wrap(&[], 1024, 100).is_none());
    }
}
