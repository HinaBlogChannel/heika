//! このノードでブロックを作る（ハーベスト）。開いているアカウントの、キーストアの `Harvest-Secret` から導出した
//! リモートと VRF の鍵を、動いているノードにメモリだけで渡す。
//!
//! 鍵はディスクに書かない。ノードは止めるまで鍵を持ち、キーストアを閉じても渡したままにする。ノードを止めたら、
//! また開いて渡し直す。
//!
//! チェーンのリンクがまだなければ、AccountKeyLink と VrfKeyLink を1つのアグリゲートにして送る。ほかの鍵が
//! リンクされていれば、外してからリンクする（同じアグリゲートの中で、順に効く）。リンクは、REST の答えを
//! StateHash まで確かめて見る。

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_rest::balance::{VerifiedAccount, verify_balance};
use heika_rest::send::{ANNOUNCE_PATH, announce_body};
use heika_state_transition::config::ChainConfig;
use heika_transaction::{Aggregate, Body, EmbeddedTransaction, KeyLink, LinkAction, Transaction};
use heika_wallet::harvest_request::HarvesterKeys;
use serde::Serialize;

use crate::node::Node;
use crate::rest::{Client, Config, Failure};
use crate::send::{self, Speed};
use crate::{Session, Wallet};

/// 作り直しの番号。鍵が漏れたときに上げるもので、今は 0 だけを使う
const ROTATION: u32 = 0;

/// 画面で確かめてもらっている、リンクの下書き
#[derive(Default)]
pub struct LinkDraft(Mutex<Option<Draft>>);

struct Draft {
    /// 署名する鍵の、キーストアのラベル
    label: String,
    transaction: Transaction,
}

impl LinkDraft {
    fn lock(&self) -> MutexGuard<'_, Option<Draft>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// キーストアを閉じたときに消す
    pub fn clear(&self) {
        *self.lock() = None;
    }
}

/// チェーンのリンクが、導出した鍵とどうなっているか
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Linked {
    None,
    /// 導出した鍵がリンクされている
    Ours,
    /// ほかの鍵がリンクされている（ほかのウォレットや、委任など）
    Other,
}

/// ハーベストできるかの様子
#[derive(Serialize)]
pub struct HarvestView {
    remote: Linked,
    vrf: Linked,
    /// 重要度の今の値。0 なら当たらない
    importance: String,
    balance: String,
    min_balance: String,
    enough_balance: bool,
    /// 確かめたブロックの高さ
    height: String,
    rest: String,
}

/// 確かめたアカウントの状態と、導出した鍵の公開鍵
struct Checked {
    view: HarvestView,
    remote_linked: Option<PublicKey>,
    vrf_linked: Option<PublicKey>,
    remote: PublicKey,
    vrf: PublicKey,
}

/// `address` のアカウントで、このノードでハーベストできるかを確かめる
#[tauri::command]
pub async fn harvest_check(
    wallet: tauri::State<'_, Wallet>,
    config: tauri::State<'_, Config>,
    address: String,
) -> Result<HarvestView, String> {
    check(&wallet, &config, &address)
        .await
        .map(|checked| checked.view)
        .map_err(|failure| failure.detail)
}

async fn check(wallet: &Wallet, config: &Config, address: &str) -> Result<Checked, Failure> {
    let client = config.client()?;
    let address: Address = address
        .parse()
        .map_err(|error| Failure::other(format!("アドレスを読めません: {error}")))?;
    let (_, keys) = derive(&wallet.lock(), &address).map_err(Failure::other)?;
    let remote = PublicKey::from_private_key(&keys.signing);
    let vrf = PublicKey::from_private_key(&keys.vrf);
    drop(keys);

    let balance = verify_balance(&address, |path| client.get(path), pause).await?;
    let network = NetworkParameters::from_identifier(address.network())
        .ok_or_else(|| Failure::other("知らないネットワークのアカウントです"))?;
    let min_balance = min_harvester_balance(address.network());
    let account: Option<&VerifiedAccount> = balance.account.as_ref();
    let linked = |key: Option<&heika_rest::state::PublicKeyJson>| -> Result<_, Failure> {
        key.map(|key| key.public_key.parse::<PublicKey>())
            .transpose()
            .map_err(|_| Failure::other("REST のリンクの公開鍵を読めません"))
    };
    let keys = account.map(|account| &account.state.supplemental_public_keys);
    let remote_linked = linked(keys.and_then(|keys| keys.linked.as_ref()))?;
    let vrf_linked = linked(keys.and_then(|keys| keys.vrf.as_ref()))?;
    let currency = account
        .and_then(|account| {
            account
                .mosaics
                .iter()
                .find(|mosaic| mosaic.id == network.currency_mosaic_id)
        })
        .map_or(0, |mosaic| mosaic.amount);
    let state = |linked: Option<PublicKey>, ours: PublicKey| match linked {
        None => Linked::None,
        Some(key) if key == ours => Linked::Ours,
        Some(_) => Linked::Other,
    };
    Ok(Checked {
        view: HarvestView {
            remote: state(remote_linked, remote),
            vrf: state(vrf_linked, vrf),
            importance: account.map_or("0".to_owned(), |account| account.state.importance.clone()),
            balance: send::xym(currency),
            min_balance: send::xym(min_balance),
            enough_balance: currency >= min_balance,
            height: balance.block.height.to_string(),
            rest: client.origin().to_owned(),
        },
        remote_linked,
        vrf_linked,
        remote,
        vrf,
    })
}

/// リンクの下書きの、画面に出す形
#[derive(Serialize)]
pub struct LinkDraftView {
    /// することを、順に一言ずつ
    actions: Vec<&'static str>,
    network: &'static str,
    fee: String,
    /// 期限。Unix 時刻のミリ秒
    deadline: u64,
    rest: String,
    check: HarvestView,
}

/// 導出した鍵をリンクするアグリゲートの下書きを作る。署名はまだしない
#[tauri::command]
pub async fn prepare_harvest_link(
    wallet: tauri::State<'_, Wallet>,
    config: tauri::State<'_, Config>,
    drafts: tauri::State<'_, LinkDraft>,
    address: String,
) -> Result<LinkDraftView, String> {
    let checked = check(&wallet, &config, &address)
        .await
        .map_err(|failure| failure.detail)?;
    let address: Address = address.parse().map_err(|error| format!("{error}"))?;
    let (label, signer) = crate::find_account(&wallet.lock(), &address)?;
    let network = NetworkParameters::from_identifier(address.network())
        .ok_or("知らないネットワークのアカウントです")?;

    let mut actions = Vec::new();
    let mut embedded = Vec::new();
    let mut link = |body: fn(KeyLink) -> Body,
                    current: Option<PublicKey>,
                    ours: PublicKey,
                    names: [&'static str; 2]| {
        if current == Some(ours) {
            return;
        }
        if let Some(other) = current {
            actions.push(names[0]);
            embedded.push(EmbeddedTransaction::new(
                signer,
                address.network(),
                body(KeyLink {
                    linked_public_key: other,
                    link_action: LinkAction::Unlink,
                }),
            ));
        }
        actions.push(names[1]);
        embedded.push(EmbeddedTransaction::new(
            signer,
            address.network(),
            body(KeyLink {
                linked_public_key: ours,
                link_action: LinkAction::Link,
            }),
        ));
    };
    link(
        Body::AccountKeyLink,
        checked.remote_linked,
        checked.remote,
        [
            "今リンクされているリモートの鍵を外す",
            "このノード用のリモートの鍵をリンクする",
        ],
    );
    link(
        Body::VrfKeyLink,
        checked.vrf_linked,
        checked.vrf,
        [
            "今リンクされている VRF の鍵を外す",
            "このノード用の VRF の鍵をリンクする",
        ],
    );
    if embedded.is_empty() {
        return Err("もうリンクしてあります".to_owned());
    }

    let aggregate = Aggregate::new(embedded).map_err(|error| error.to_string())?;
    let deadline = network
        .timestamp_at(SystemTime::now() + send::LIFETIME)
        .ok_or("時計がネットワークのエポックより前になっています")?;
    let mut transaction = Transaction::new(
        signer,
        address.network(),
        0,
        deadline.0,
        Body::AggregateComplete(aggregate),
    );
    // 急ぐものではないので、REST のノードが受け付けるいちばん安いものにする
    let client = config.client().map_err(|failure| failure.detail)?;
    let speed = Speed::cheapest_accepted(&client).await?;
    transaction.fee = transaction.fee_for(speed.multiplier(), 0);
    if let Some(problem) = transaction.validate(network).first() {
        return Err(format!("ノードで弾かれる形です: {}", problem.failure));
    }
    let view = LinkDraftView {
        actions,
        network: send::network_name(network),
        fee: send::xym(transaction.fee),
        deadline: send::unix_millis(network, deadline.0).unwrap_or_default(),
        rest: checked.view.rest.clone(),
        check: checked.view,
    };
    *drafts.lock() = Some(Draft { label, transaction });
    Ok(view)
}

/// リンクの下書きに署名して REST に渡す。返すのはトランザクションのハッシュ。入ったかは [`harvest_check`] で見る
#[tauri::command]
pub async fn send_harvest_link(
    wallet: tauri::State<'_, Wallet>,
    config: tauri::State<'_, Config>,
    drafts: tauri::State<'_, LinkDraft>,
) -> Result<String, String> {
    let client: Client = config.client().map_err(|failure| failure.detail)?;
    let Draft {
        label,
        mut transaction,
    } = drafts
        .lock()
        .take()
        .ok_or("送る下書きがありません。もう一度やり直してください")?;
    let network = NetworkParameters::from_identifier(transaction.network)
        .ok_or("知らないネットワークです")?;
    if transaction.deadline <= send::network_now(network)? {
        return Err("下書きの期限が切れました。もう一度やり直してください".to_owned());
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
    Ok(transaction.hash(&network.generation_hash_seed).to_string())
}

/// `address` のアカウントの鍵を、動いているノードに渡す。ノードは止めるまでその鍵でハーベストする
#[tauri::command]
pub fn harvest_start(
    wallet: tauri::State<'_, Wallet>,
    node: tauri::State<'_, Arc<Node>>,
    address: String,
) -> Result<(), String> {
    let address: Address = address
        .parse()
        .map_err(|error| format!("アドレスを読めません: {error}"))?;
    let network = NetworkParameters::from_identifier(address.network())
        .ok_or("知らないネットワークのアカウントです")?;
    if node.network() != Some(send::network_name(network)) {
        return Err(
            "ノードが動いていないか、このアカウントと違うネットワークで動いています".to_owned(),
        );
    }
    let (_, keys) = derive(&wallet.lock(), &address)?;
    node.set_harvesters(vec![(keys.signing, keys.vrf)], Some(address.to_string()))
}

/// ノードに渡した鍵を消して、ハーベストをやめる
#[tauri::command]
pub fn harvest_stop(node: tauri::State<'_, Arc<Node>>) -> Result<(), String> {
    node.set_harvesters(Vec::new(), None)
}

/// 開いているキーストアから、`address` のアカウントのハーベストの鍵を導出する
fn derive(session: &Session, address: &Address) -> Result<(String, HarvesterKeys), String> {
    let (label, _) = crate::find_account(session, address)?;
    let keystore = session
        .keystore
        .as_ref()
        .ok_or("キーストアを開いていません")?;
    let keys = keystore
        .harvester_keys(&label, "", ROTATION)
        .map_err(|error| error.to_string())?
        .ok_or("キーストアにハーベストの秘密がありません。キーストアを開き直してください")?;
    Ok((label, keys))
}

/// ハーベストに要る残高（いちばん小さい単位）
fn min_harvester_balance(network: NetworkIdentifier) -> u64 {
    if network == NetworkIdentifier::MAINNET {
        ChainConfig::mainnet().min_harvester_balance
    } else {
        ChainConfig::testnet().min_harvester_balance
    }
}

/// 根が合わなかったときに、取り直すまでおく間
async fn pause() {
    // 眠るだけなので、止まっても困らない
    let _ = tauri::async_runtime::spawn_blocking(|| {
        std::thread::sleep(std::time::Duration::from_secs(3))
    })
    .await;
}
