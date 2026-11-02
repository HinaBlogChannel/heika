//! ブラウザのノードへの委任ハーベスト。
//!
//! - ノードの鍵は、初めて使うときに作る。秘密鍵は X25519 の鍵にして、Web Crypto に読み出せない鍵（non-extractable な
//!   `CryptoKey`）として渡し、IndexedDB にしまう。元の秘密鍵は、その場で捨てる。ページの JS からも鍵の中身は読めず、
//!   ブラウザに「この鍵で X25519 をして」と頼むだけになる
//! - 委任の要求（ノードの公開鍵のアドレスあての Transfer）は、REST の検索で探す。REST は信じない。読み出した鍵は、
//!   自分で確かめた状態のリンク（リモート、VRF、ノード）と合うときだけ使う（[`heika_harvesting::unlocked::check`]）。
//!   REST が要求を隠せば委任を受け損ねるが、偽の委任を受けることはない
//! - 読み出したリモートと VRF の鍵は、メモリにだけ置く。開くたびに、チェーンの要求から読み直す

use std::collections::HashMap;

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_core::patricia::SubCache;
use heika_harvesting::delegation::LinkKind;
use heika_harvesting::unlocked::{self, AccountLinks, Rejection};
use heika_state_transition::account::AccountType;
use heika_state_transition::executor::persist::{decode_account_row, row_key};
use heika_store_redb::Db;
use heika_wallet::{cipher, harvest_request};
use js_sys::{Array, Promise, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CryptoKey, IdbDatabase, IdbRequest, IdbTransactionMode, SubtleCrypto, WorkerGlobalScope,
};

use crate::rest::{self, FetchError, PAGE_SIZE};

const DATABASE: &str = "heika-node-web";
const STORE: &str = "keys";
const NODE: &str = "node";
/// X25519 の秘密鍵を PKCS #8 で包む頭（RFC 8410）
const PKCS8: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

fn js(error: JsValue) -> String {
    error
        .as_string()
        .or_else(|| js_sys::Error::from(error).message().as_string())
        .unwrap_or_default()
}

fn scope() -> WorkerGlobalScope {
    js_sys::global().unchecked_into()
}

/// IndexedDB の要求が終わるのを待つ
async fn finished(request: &IdbRequest) -> Result<JsValue, JsValue> {
    let promise = Promise::new(&mut |resolve, reject| {
        let done = request.clone();
        let failed = request.clone();
        let onsuccess = Closure::once_into_js(move || {
            let _ = resolve.call1(&JsValue::NULL, &done.result().unwrap_or(JsValue::NULL));
        });
        let onerror = Closure::once_into_js(move || {
            let error = failed
                .error()
                .ok()
                .flatten()
                .map_or_else(|| "IndexedDB".into(), |error| error.message());
            let _ = reject.call1(&JsValue::NULL, &error.into());
        });
        request.set_onsuccess(Some(onsuccess.unchecked_ref()));
        request.set_onerror(Some(onerror.unchecked_ref()));
    });
    JsFuture::from(promise).await
}

async fn database() -> Result<IdbDatabase, JsValue> {
    let factory = scope()
        .indexed_db()?
        .ok_or_else(|| JsValue::from_str("IndexedDB がありません"))?;
    let opening = factory.open_with_u32(DATABASE, 1)?;
    let upgrading = opening.clone();
    let onupgradeneeded = Closure::once_into_js(move || {
        if let Ok(result) = upgrading.result() {
            let _ = result
                .unchecked_into::<IdbDatabase>()
                .create_object_store(STORE);
        }
    });
    opening.set_onupgradeneeded(Some(onupgradeneeded.unchecked_ref()));
    Ok(finished(&opening).await?.unchecked_into())
}

async fn load_node_key() -> Result<JsValue, JsValue> {
    let db = database().await?;
    let result = async {
        let store = db.transaction_with_str(STORE)?.object_store(STORE)?;
        finished(&store.get(&NODE.into())?).await
    }
    .await;
    db.close();
    result
}

async fn store_node_key(record: &JsValue) -> Result<(), JsValue> {
    let db = database().await?;
    let result = async {
        let transaction = db.transaction_with_str_and_mode(STORE, IdbTransactionMode::Readwrite)?;
        finished(
            &transaction
                .object_store(STORE)?
                .put_with_key(record, &NODE.into())?,
        )
        .await?;
        Ok(())
    }
    .await;
    db.close();
    result
}

fn subtle() -> Result<SubtleCrypto, JsValue> {
    Ok(scope().crypto()?.subtle())
}

fn x25519_algorithm() -> js_sys::Object {
    let algorithm = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&algorithm, &"name".into(), &"X25519".into());
    algorithm
}

/// X25519 の秘密鍵を、読み出せない `CryptoKey` にする
async fn import_private(scalar: &[u8; 32]) -> Result<JsValue, JsValue> {
    let mut der = zeroize::Zeroizing::new([0u8; 48]);
    der[..16].copy_from_slice(&PKCS8);
    der[16..].copy_from_slice(scalar);
    let data = Uint8Array::from(&der[..]);
    let promise = subtle()?.import_key_with_object(
        "pkcs8",
        &data,
        &x25519_algorithm(),
        false,
        &Array::of1(&"deriveBits".into()),
    );
    data.fill(0, 0, 48);
    JsFuture::from(promise?).await
}

/// `key` と相手の X25519 の公開鍵 `public_key` の X25519
async fn x25519(key: &JsValue, public_key: &[u8; 32]) -> Result<Vec<u8>, JsValue> {
    let subtle = subtle()?;
    let other = JsFuture::from(subtle.import_key_with_object(
        "raw",
        &Uint8Array::from(&public_key[..]),
        &x25519_algorithm(),
        true,
        &Array::new(),
    )?)
    .await?;
    let algorithm = x25519_algorithm();
    js_sys::Reflect::set(&algorithm, &"public".into(), &other)?;
    let bits = JsFuture::from(subtle.derive_bits_with_object(
        &algorithm,
        key.unchecked_ref::<CryptoKey>(),
        256,
    )?)
    .await?;
    Ok(Uint8Array::new(&bits).to_vec())
}

/// ノードの鍵。公開鍵と、読み出せない X25519 の鍵
#[derive(Clone)]
pub struct NodeKey {
    pub public_key: PublicKey,
    key: JsValue,
}

impl NodeKey {
    /// しまってある鍵を読む。なければ作ってしまう
    pub async fn load_or_create() -> Result<Self, String> {
        let stored = load_node_key()
            .await
            .map_err(|error| format!("IndexedDB を読めません: {}", js(error)))?;
        let record = if stored.is_null() || stored.is_undefined() {
            let private_key =
                PrivateKey::generate().map_err(|error| format!("鍵の乱数を作れません: {error}"))?;
            let public_key = PublicKey::from_private_key(&private_key);
            let scalar = cipher::x25519_private_key(&private_key);
            drop(private_key);
            let key = import_private(&scalar).await.map_err(|error| {
                format!(
                    "ノードの鍵を作れません（このブラウザは X25519 に対応していないかもしれません）: {}",
                    js(error)
                )
            })?;
            drop(scalar);
            let record = js_sys::Object::new();
            let _ = js_sys::Reflect::set(
                &record,
                &"publicKey".into(),
                &Uint8Array::from(&public_key.0[..]),
            );
            let _ = js_sys::Reflect::set(&record, &"key".into(), &key);
            store_node_key(&record)
                .await
                .map_err(|error| format!("ノードの鍵をしまえません: {}", js(error)))?;
            record.into()
        } else {
            stored
        };
        let public_key = js_sys::Reflect::get(&record, &"publicKey".into())
            .ok()
            .map(|value| Uint8Array::new(&value).to_vec())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or("しまってあるノードの鍵が読めません")?;
        let key = js_sys::Reflect::get(&record, &"key".into())
            .map_err(|_| "しまってあるノードの鍵が読めません")?;
        Ok(Self {
            public_key: PublicKey(public_key),
            key,
        })
    }

    /// 委任の要求を開く
    async fn open(&self, message: &[u8]) -> Result<harvest_request::HarvesterKeys, String> {
        let ephemeral =
            harvest_request::x25519_ephemeral_key(message).map_err(|error| error.to_string())?;
        let shared = x25519(&self.key, &ephemeral)
            .await
            .map_err(|error| format!("X25519 ができません: {}", js(error)))?;
        let shared = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(shared).map_err(|_| "X25519 の結果の長さが違います")?,
        );
        harvest_request::decode_x25519(&shared, message).map_err(|error| error.to_string())
    }
}

/// 届いた委任1件の様子
#[derive(Clone, Debug, PartialEq)]
pub struct DelegationStatus {
    /// 要求が入っていたブロックの高さ
    pub height: u64,
    /// メインアカウントのアドレス。わからなければ `None`
    pub main_account: Option<Address>,
    /// ハーベストに使っているか。使っていなければ、わけ
    pub state: Result<(), String>,
}

/// 開いた要求1件
struct Opened {
    height: u64,
    keys: Result<(PrivateKey, PrivateKey), String>,
}

/// 届いた委任。開いたものはメモリにだけ置き、開き直さない
#[derive(Default)]
pub struct Delegations {
    opened: HashMap<Vec<u8>, Opened>,
}

/// 探す要求の数の上限（新しいものから）
const MAX_REQUESTS: usize = 3 * PAGE_SIZE as usize;
/// 一度にハーベストに使う委任の数の上限。catapult の `maxUnlockedAccounts` の既定に合わせる
pub const MAX_DELEGATIONS: usize = 5;

impl Delegations {
    /// `origin` の REST で、ノードのアドレスあての要求を探し、まだ開いていないものを開く
    pub async fn refresh(
        &mut self,
        origin: &str,
        node: &NodeKey,
        network: NetworkIdentifier,
    ) -> Result<(), FetchError> {
        let address = harvest_request::recipient_address(&node.public_key, network);
        let mut found = Vec::new();
        for number in 1.. {
            let page = rest::get_json(
                origin,
                &format!(
                    "/transactions/confirmed?recipientAddress={address}&type=16724&embedded=true&order=desc&pageSize={PAGE_SIZE}&pageNumber={number}"
                ),
            )
            .await?;
            let data = page["data"].as_array().cloned().unwrap_or_default();
            let done = (data.len() as u64) < PAGE_SIZE;
            for entry in data {
                let message = entry["transaction"]["message"]
                    .as_str()
                    .and_then(decode_hex);
                let height = entry["meta"]["height"]
                    .as_str()
                    .and_then(|height| height.parse::<u64>().ok());
                if let (Some(message), Some(height)) = (message, height)
                    && harvest_request::is_harvest_request(&message)
                {
                    found.push((height, message));
                }
            }
            if done || found.len() >= MAX_REQUESTS {
                break;
            }
        }
        for (height, message) in found {
            if self.opened.contains_key(&message) {
                continue;
            }
            let keys = node
                .open(&message)
                .await
                .map(|keys| (keys.signing, keys.vrf));
            self.opened.insert(message, Opened { height, keys });
        }
        Ok(())
    }

    /// 開いた要求を、`db` の今の状態で確かめる。ハーベストに使う鍵と、要求ごとの様子を、新しい要求から返す
    pub fn check(
        &self,
        db: &Db,
        node: &NodeKey,
        network: NetworkIdentifier,
    ) -> (Vec<(PrivateKey, PrivateKey)>, Vec<DelegationStatus>) {
        let lookup = |public_key: &PublicKey| account_links(db, network, public_key);
        let mut entries: Vec<&Opened> = self.opened.values().collect();
        entries.sort_by_key(|opened| std::cmp::Reverse(opened.height));
        let mut statuses = Vec::new();
        // 状態と合ったものの、statuses での番号と鍵
        let mut eligible = Vec::new();
        // 同じリモートの鍵の要求が何度も届いたら、新しいものだけを見る
        let mut seen = Vec::new();
        for opened in entries {
            let (signing, vrf) = match &opened.keys {
                Ok(keys) => keys,
                Err(error) => {
                    statuses.push(DelegationStatus {
                        height: opened.height,
                        main_account: None,
                        state: Err(format!("開けません: {error}")),
                    });
                    continue;
                }
            };
            let remote = PublicKey::from_private_key(signing);
            if seen.contains(&remote) {
                continue;
            }
            seen.push(remote);
            let vrf_public = PublicKey::from_private_key(vrf);
            let main_of_remote = lookup(&remote)
                .filter(|links| links.remote)
                .and_then(|links| links.linked);
            let main_account = main_of_remote.map(|main| Address::from_public_key(&main, network));
            match unlocked::check(&remote, &vrf_public, &node.public_key, lookup) {
                Ok(found) => {
                    statuses.push(DelegationStatus {
                        height: opened.height,
                        main_account,
                        state: Ok(()),
                    });
                    eligible.push(((statuses.len() - 1, (signing, vrf)), found));
                }
                Err(rejection) => statuses.push(DelegationStatus {
                    height: opened.height,
                    main_account,
                    state: Err(match rejection {
                        Rejection::NoMainAccount => {
                            "リモートの鍵がメインアカウントに紐づいていません".to_owned()
                        }
                        Rejection::Mismatched(kinds) => format!(
                            "メインアカウントの{}の紐づけが、要求と合いません",
                            kinds
                                .iter()
                                .map(|kind| match kind {
                                    LinkKind::Remote => "リモート",
                                    LinkKind::Vrf => "VRF",
                                    LinkKind::Node => "ノード",
                                })
                                .collect::<Vec<_>>()
                                .join("と")
                        ),
                    }),
                }),
            }
        }
        let chosen = unlocked::choose(eligible, MAX_DELEGATIONS);
        for (index, status) in statuses.iter_mut().enumerate() {
            if status.state.is_ok() && !chosen.iter().any(|((chosen, _), _)| *chosen == index) {
                status.state = Err(format!(
                    "重要度の大きい {MAX_DELEGATIONS} 件に入らないので、空きを待っています"
                ));
            }
        }
        let keys = chosen
            .into_iter()
            .map(|((_, (signing, vrf)), _)| {
                (
                    PrivateKey::from_bytes(signing.as_bytes()),
                    PrivateKey::from_bytes(vrf.as_bytes()),
                )
            })
            .collect();
        (keys, statuses)
    }
}

/// 公開鍵のアカウントの、委任を確かめるのに要る状態
fn account_links(
    db: &Db,
    network: NetworkIdentifier,
    public_key: &PublicKey,
) -> Option<AccountLinks> {
    let address = Address::from_public_key(public_key, network);
    let row = db
        .state_row(&row_key(SubCache::AccountState, &address.0))
        .ok()??;
    let account = decode_account_row(&row).ok()?;
    Some(AccountLinks {
        remote: account.account_type == AccountType::Remote,
        linked: account.linked.map(PublicKey),
        vrf: account.vrf.map(PublicKey),
        node: account.node.map(PublicKey),
        importance: account.snapshots[0].importance,
    })
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}
