//! XYM を送る。下書きを作って画面で確かめてもらい、署名して REST に渡し、ブロックに入ったかを追う。
//!
//! 送ったものの控えはメモリにだけ置き、ディスクには書かない。BIP39 のパスフレーズで開く隠しアカウントの送金が
//! ファイルに残ると、隠しアカウントがあることを否認できなくなるため。キーストアを閉じるか、アプリを終えると消える。
//! 控えが要るのは期限（2時間）まで。それを過ぎたものは、もうブロックに入らないので、残高を見ればわかる。
//!
//! 入ったことは、ブロックの TransactionsHash への経路で確かめる。入っていないことは1つの REST からは確かめられないので、
//! 期限までは「待っている」とし、REST の transactionStatus は目安として添えるだけにする。

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use heika_core::address::Address;
use heika_core::network::{NetworkParameters, NetworkTimestamp};
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body, find_inclusion};
use heika_transaction::{Body, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId};
use serde::{Deserialize, Serialize};

use crate::Wallet;
use crate::rest::{Client, Config, Failure};

/// 期限。今から2時間後
pub(crate) const LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
/// XYM の可分性。メインネットもテストネットも 6
const XYM_DIVISIBILITY: u8 = 6;

/// 手数料の倍率。トランザクションのバイト数に掛ける
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Speed {
    Slow,
    Normal,
    Fast,
}

impl Speed {
    pub(crate) fn multiplier(self) -> u32 {
        match self {
            Self::Slow => 10,
            Self::Normal => 25,
            Self::Fast => 100,
        }
    }
}

/// 下書きと、送ったものの控え
#[derive(Default)]
pub struct Outbox(Mutex<Boxes>);

#[derive(Default)]
struct Boxes {
    /// 画面で確かめてもらっている下書き。署名する前
    draft: Option<Draft>,
    sent: Vec<Sent>,
}

struct Draft {
    /// 署名する鍵の、キーストアのラベル
    label: String,
    transaction: Transaction,
    recipient: Address,
    amount: u64,
}

struct Sent {
    transaction: Transaction,
    recipient: Address,
    amount: u64,
    /// 渡した REST
    client: Client,
    /// 入ったことを確かめたブロック
    included: Option<Included>,
}

#[derive(Clone, Copy, Serialize)]
struct Included {
    height: u64,
    /// ブロックの時刻。Unix 時刻のミリ秒
    block_time: Option<u64>,
}

impl Outbox {
    fn lock(&self) -> MutexGuard<'_, Boxes> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// キーストアを閉じたときに、下書きも控えも消す
    pub fn clear(&self) {
        *self.lock() = Boxes::default();
    }
}

/// 画面で確かめてもらう下書き
#[derive(Serialize)]
pub struct DraftView {
    from: String,
    to: String,
    network: &'static str,
    amount: String,
    fee: String,
    total: String,
    /// 期限。Unix 時刻のミリ秒
    deadline: u64,
    message: String,
    rest: String,
}

/// 送金の下書きを作る。署名はまだしない
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn prepare_send(
    wallet: tauri::State<'_, Wallet>,
    config: tauri::State<'_, Config>,
    outbox: tauri::State<'_, Outbox>,
    from: String,
    to: String,
    amount: String,
    message: String,
    speed: Speed,
) -> Result<DraftView, String> {
    let client = config.client().map_err(|failure| failure.detail)?;
    let from: Address = from.parse().map_err(|error| format!("{error}"))?;
    let (label, signer) = crate::find_account(&wallet.lock(), &from)?;
    let network = NetworkParameters::from_identifier(from.network())
        .ok_or("知らないネットワークのアカウントです")?;

    if to.trim().is_empty() {
        return Err("宛先のアドレスを入れてください".to_owned());
    }
    if amount.trim().is_empty() {
        return Err("送る量を入れてください".to_owned());
    }
    // 区切りや空白を付けて書いても読めるようにする
    let to: String = to
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase();
    let recipient: Address = to
        .parse()
        .map_err(|error| format!("宛先のアドレスを読めません: {error}"))?;
    if recipient.network() != from.network() {
        return Err("宛先は、このアカウントと違うネットワークのアドレスです".to_owned());
    }
    let amount = heika_wallet::amount::parse(amount.trim(), XYM_DIVISIBILITY)
        .map_err(|error| error.to_string())?;
    if amount == 0 {
        return Err("0 XYM は送れません".to_owned());
    }
    {
        let boxes = outbox.lock();
        let now = network_now(network)?;
        if boxes.sent.iter().any(|sent| {
            sent.included.is_none()
                && sent.transaction.deadline > now
                && sent.transaction.signer_public_key == signer
                && sent.recipient == recipient
                && sent.amount == amount
        }) {
            return Err(
                "同じ宛先に同じ量を送った前の送金の結果が、まだ出ていません。二重に払わないように、結果が出るか、期限を過ぎるまで待ってください"
                    .to_owned(),
            );
        }
    }

    // 平文のメッセージは、頭に 0 のバイトを付ける
    let message_bytes = if message.is_empty() {
        Vec::new()
    } else {
        let mut bytes = vec![0];
        bytes.extend_from_slice(message.as_bytes());
        bytes
    };
    let body = Transfer::new(
        UnresolvedAddress::from(recipient),
        BTreeMap::from([(UnresolvedMosaicId(network.currency_mosaic_id), amount)]),
        message_bytes,
    )
    .map_err(|error| error.to_string())?;
    let deadline = network
        .timestamp_at(SystemTime::now() + LIFETIME)
        .ok_or("時計がネットワークのエポックより前になっています")?;
    let mut transaction =
        Transaction::new(signer, from.network(), 0, deadline.0, Body::Transfer(body));
    transaction.fee = transaction.fee_for(speed.multiplier(), 0);
    if let Some(problem) = transaction.validate(network).first() {
        return Err(format!("ノードで弾かれる形です: {}", problem.failure));
    }

    let view = DraftView {
        from: from.to_string(),
        to: recipient.to_string(),
        network: network_name(network),
        amount: xym(amount),
        fee: xym(transaction.fee),
        total: xym(amount.saturating_add(transaction.fee)),
        deadline: unix_millis(network, deadline.0).unwrap_or_default(),
        message,
        rest: client.origin().to_owned(),
    };
    outbox.lock().draft = Some(Draft {
        label,
        transaction,
        recipient,
        amount,
    });
    Ok(view)
}

/// 下書きに署名して REST に渡す。返すのはトランザクションのハッシュ
#[tauri::command]
pub async fn send(
    wallet: tauri::State<'_, Wallet>,
    config: tauri::State<'_, Config>,
    outbox: tauri::State<'_, Outbox>,
) -> Result<String, String> {
    let client = config.client().map_err(|failure| failure.detail)?;
    let Draft {
        label,
        mut transaction,
        recipient,
        amount,
    } = outbox
        .lock()
        .draft
        .take()
        .ok_or("送る下書きがありません。もう一度入れてください")?;
    let network = NetworkParameters::from_identifier(transaction.network)
        .ok_or("知らないネットワークです")?;
    if transaction.deadline <= network_now(network)? {
        return Err("下書きの期限が切れました。もう一度入れてください".to_owned());
    }
    {
        let session = wallet.lock();
        let keystore = session
            .keystore
            .as_ref()
            .ok_or("キーストアを開いていません")?;
        let (_, private_key) = keystore
            .private_key(&label, "")
            .map_err(|error| error.to_string())?;
        transaction
            .sign(&private_key, &network.generation_hash_seed)
            .map_err(|error| error.to_string())?;
    }
    client
        .put(ANNOUNCE_PATH, announce_body(&transaction))
        .await?;
    let hash = transaction.hash(&network.generation_hash_seed).to_string();
    outbox.lock().sent.push(Sent {
        transaction,
        recipient,
        amount,
        client,
        included: None,
    });
    Ok(hash)
}

/// 送ったものの、画面に出す形
#[derive(Serialize)]
pub struct SentView {
    hash: String,
    to: String,
    amount: String,
    state: SentState,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SentState {
    /// ブロックに入ったことを、経路で確かめた
    Included(Included),
    /// まだ見えていない。期限までは、これから入ることがある
    Waiting {
        /// 期限。Unix 時刻のミリ秒
        deadline: u64,
        /// REST の transactionStatus。確かめたものではない
        hint: Option<String>,
    },
    /// 期限を過ぎても見えていない。もう入ることはない
    Expired,
}

/// `address` から送ったものと、それぞれがブロックに入ったか。新しいものから
#[tauri::command]
pub async fn outbox(
    outbox: tauri::State<'_, Outbox>,
    address: String,
) -> Result<Vec<SentView>, Failure> {
    let address: Address = address
        .parse()
        .map_err(|error| Failure::other(format!("アドレスを読めません: {error}")))?;
    let network = NetworkParameters::from_identifier(address.network())
        .ok_or_else(|| Failure::other("知らないネットワークのアカウントです"))?;
    let seed = network.generation_hash_seed;
    // 問い合わせのあいだは控えを離しておく
    let pending: Vec<(usize, Transaction, Client)> = outbox
        .lock()
        .sent
        .iter()
        .enumerate()
        .filter(|(_, sent)| {
            sent.included.is_none()
                && Address::from_public_key(&sent.transaction.signer_public_key, address.network())
                    == address
        })
        .map(|(index, sent)| (index, sent.transaction.clone(), sent.client.clone()))
        .collect();
    let mut hints = Vec::new();
    for (index, transaction, client) in pending {
        match find_inclusion(&transaction, &seed, |path| client.get(path)).await? {
            Some(inclusion) => {
                let included = Included {
                    height: inclusion.block.height,
                    block_time: unix_millis(network, inclusion.block.timestamp),
                };
                if let Some(sent) = outbox.lock().sent.get_mut(index) {
                    sent.included = Some(included);
                }
            }
            None => {
                let status = client
                    .get(TransactionStatus::path(&transaction, &seed))
                    .await
                    .ok()
                    .flatten()
                    .and_then(|body| TransactionStatus::from_slice(&body).ok());
                hints.push((index, status));
            }
        }
    }

    let now = network_now(network).map_err(Failure::other)?;
    let boxes = outbox.lock();
    Ok(boxes
        .sent
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, sent)| {
            Address::from_public_key(&sent.transaction.signer_public_key, address.network())
                == address
        })
        .map(|(index, sent)| SentView {
            hash: sent.transaction.hash(&seed).to_string(),
            to: sent.recipient.to_string(),
            amount: xym(sent.amount),
            state: match sent.included {
                Some(included) => SentState::Included(included),
                None if sent.transaction.deadline <= now => SentState::Expired,
                None => SentState::Waiting {
                    deadline: unix_millis(network, sent.transaction.deadline).unwrap_or_default(),
                    hint: hints
                        .iter()
                        .find(|(hinted, _)| *hinted == index)
                        .and_then(|(_, status)| status.as_ref())
                        .map(describe_status),
                },
            },
        })
        .collect())
}

/// REST の transactionStatus を、人が読める一言にする
fn describe_status(status: &TransactionStatus) -> String {
    match (status.group.as_str(), status.code.as_deref()) {
        ("unconfirmed", _) => "ノードが受け取り、ブロックに入るのを待っています".to_owned(),
        ("confirmed", _) => "ブロックに入ったと言っています".to_owned(),
        ("failed", Some("Failure_Core_Insufficient_Balance")) => {
            "残高が足りないので弾いたと言っています".to_owned()
        }
        ("failed", Some(code)) => format!("弾いたと言っています（{code}）"),
        (group, _) => group.to_owned(),
    }
}

pub(crate) fn network_now(network: &NetworkParameters) -> Result<u64, String> {
    network
        .timestamp_at(SystemTime::now())
        .map(|timestamp| timestamp.0)
        .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
}

pub(crate) fn unix_millis(network: &NetworkParameters, timestamp: u64) -> Option<u64> {
    let time = network.time_of(NetworkTimestamp(timestamp))?;
    u64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_millis()).ok()
}

pub(crate) fn network_name(network: &NetworkParameters) -> &'static str {
    if network.identifier == NetworkParameters::MAINNET.identifier {
        "mainnet"
    } else {
        "testnet"
    }
}

/// いちばん小さい単位の量を、XYM の桁で区切る
pub(crate) fn xym(amount: u64) -> String {
    let digits = format!("{amount:07}");
    let (whole, fraction) = digits.split_at(digits.len() - usize::from(XYM_DIVISIBILITY));
    format!("{whole}.{fraction}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_xym_with_six_decimals() {
        assert_eq!(xym(0), "0.000000");
        assert_eq!(xym(1), "0.000001");
        assert_eq!(xym(1_500_000), "1.500000");
        assert_eq!(xym(u64::MAX), "18446744073709.551615");
    }
}
