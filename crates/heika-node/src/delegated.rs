//! ほかの人の委任ハーベストを引き受ける。catapult の transfer プラグインの `TransferMessageObserver` と、harvesting 拡張の
//! `UnlockedAccountsUpdater` と `UnlockedAccountsStorage` に合わせている。
//!
//! - 委任の要求は、委任の鍵のアドレスあてのメッセージで届く。確定したブロックだけを、高さの順に読む。確定していれば
//!   巻き戻しを考えなくてよい
//! - 引き受けるかどうかは、そのときのチェーンの状態のリンクで決める（[`heika_harvesting::unlocked`]）。確定が進むたびに
//!   引き受けているものも確かめ直し、合わなくなったものは外す
//! - 引き受けている要求は、暗号化したまま `harvesters.dat`（catapult と同じ形）に、どこまで読んだかは
//!   `harvesters.height` にしまう。初めて動かしたときは、それより前の要求は読まない

use std::path::{Path, PathBuf};

use heika_block::Block;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_core::patricia::SubCache;
use heika_harvesting::delegation::{DelegationTracker, ENCRYPTED_PAYLOAD_SIZE};
use heika_harvesting::unlocked::{self, AccountLinks, Eligible};
use heika_state_transition::account::AccountType;
use heika_state_transition::executor::persist::{decode_account_row, row_key};
use heika_store_redb::Db;
use heika_wallet::harvest_request;

use crate::driver::NodeError;
use crate::harvesters::KeyPair;

type Payload = [u8; ENCRYPTED_PAYLOAD_SIZE];

/// 引き受けている委任1件
struct Accepted {
    payload: Payload,
    signing: PrivateKey,
    vrf: PrivateKey,
}

/// 委任の引き受け
pub struct Delegated {
    key: PrivateKey,
    public_key: PublicKey,
    network: NetworkIdentifier,
    max: usize,
    file: PathBuf,
    height_file: PathBuf,
    accepted: Vec<Accepted>,
    /// 要求を読み終えた高さ
    through: u64,
}

/// 確定をどこまで読んだかの結果。`changed` なら、ハーベストする鍵を入れ替える
pub struct Progress {
    pub changed: bool,
    pub message: Option<String>,
}

fn decrypt(key: &PrivateKey, payload: &Payload) -> Option<Accepted> {
    let message = [&harvest_request::MARKER[..], payload].concat();
    let keys = harvest_request::decode(key, &message).ok()?;
    Some(Accepted {
        payload: *payload,
        signing: keys.signing,
        vrf: keys.vrf,
    })
}

/// catapult での要求の識別子（暗号化した中身の先頭の32バイト、使い捨ての公開鍵）
fn identifier(payload: &Payload) -> &[u8] {
    &payload[..32]
}

impl Delegated {
    /// `data_directory` の `harvesters.dat` と `harvesters.height` を読む。なければ、`finalized` から先の要求を読む
    pub fn open(
        key: PrivateKey,
        network: NetworkIdentifier,
        max: usize,
        data_directory: &Path,
        finalized: u64,
    ) -> Result<Self, NodeError> {
        let file = data_directory.join("harvesters.dat");
        let height_file = data_directory.join("harvesters.height");
        let mut accepted = Vec::new();
        match std::fs::read(&file) {
            Ok(bytes) => {
                if !bytes.len().is_multiple_of(ENCRYPTED_PAYLOAD_SIZE) {
                    return Err(format!(
                        "{} が壊れています（大きさ {}）",
                        file.display(),
                        bytes.len()
                    )
                    .into());
                }
                for chunk in bytes.chunks(ENCRYPTED_PAYLOAD_SIZE) {
                    let payload: Payload = chunk.try_into().expect("chunks of the payload size");
                    match decrypt(&key, &payload) {
                        Some(entry) => accepted.push(entry),
                        // 委任の鍵を替えたときなど。catapult は起動しないが、ここでは外して続ける
                        None => eprintln!(
                            "警告: {} に、委任の鍵で復号できない委任があったので外します",
                            file.display()
                        ),
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{} を読めません: {error}", file.display()).into()),
        }
        let through = match std::fs::read_to_string(&height_file) {
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|_| format!("{} が読めません", height_file.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("委任の要求は、確定した高さ {finalized} より後に届いたものから読みます");
                finalized
            }
            Err(error) => {
                return Err(format!("{} を読めません: {error}", height_file.display()).into());
            }
        };
        let public_key = PublicKey::from_private_key(&key);
        println!(
            "委任を引き受けます（上限 {max} 件、要求の届け先 {}）",
            harvest_request::recipient_address(&public_key, network)
        );
        Ok(Self {
            key,
            public_key,
            network,
            max,
            file,
            height_file,
            accepted,
            through,
        })
    }

    /// 引き受けている委任の鍵の組
    pub fn keys(&self) -> Vec<KeyPair> {
        let copy = |key: &PrivateKey| PrivateKey::from_bytes(key.as_bytes());
        self.accepted
            .iter()
            .map(|entry| (copy(&entry.signing), copy(&entry.vrf)))
            .collect()
    }

    /// 確定が `finalized` まで進んだ。新しい要求を読み、引き受けているものと合わせて、今の状態で確かめ直す
    pub fn finalized(&mut self, db: &Db, finalized: u64) -> Result<Progress, NodeError> {
        if finalized <= self.through {
            return Ok(Progress {
                changed: false,
                message: None,
            });
        }
        let mut tracker = DelegationTracker::new(&self.key, self.network);
        let mut missing = 0;
        for height in self.through + 1..=finalized {
            let Some(bytes) = db.block(height)? else {
                missing += 1;
                continue;
            };
            let block = Block::from_bytes(&bytes)
                .map_err(|error| format!("高さ {height} のブロックが読めません: {error}"))?;
            for transaction in block.transactions() {
                // チェーンが認めたトランザクションなので、読めない種類は委任の要求ではない
                for scanned in heika_transaction::scan(transaction).unwrap_or_default() {
                    tracker.observe(height, &scanned);
                }
            }
        }
        let report = tracker.finish();
        let previous: Vec<Payload> = self.accepted.iter().map(|entry| entry.payload).collect();
        let mut candidates: Vec<Accepted> = std::mem::take(&mut self.accepted);
        for delegation in report.delegations {
            let known = candidates.iter().any(|entry| {
                identifier(&entry.payload) == identifier(&delegation.encrypted_payload)
            });
            if !known && let Some(entry) = decrypt(&self.key, &delegation.encrypted_payload) {
                candidates.push(entry);
            }
        }
        let lookup = |public_key: &PublicKey| self.account_links(db, public_key);
        let eligible: Vec<(Accepted, Eligible)> = candidates
            .into_iter()
            .filter_map(|entry| {
                let remote = PublicKey::from_private_key(&entry.signing);
                let vrf = PublicKey::from_private_key(&entry.vrf);
                unlocked::check(&remote, &vrf, &self.public_key, lookup)
                    .ok()
                    .map(|eligible| (entry, eligible))
            })
            .collect();
        let chosen = unlocked::choose(eligible, self.max);
        self.accepted = chosen.into_iter().map(|(entry, _)| entry).collect();
        self.through = finalized;
        let after: Vec<Payload> = self.accepted.iter().map(|entry| entry.payload).collect();
        let changed = after != previous;
        if changed {
            self.save()?;
        }
        std::fs::write(&self.height_file, format!("{finalized}\n"))
            .map_err(|error| format!("{} を書けません: {error}", self.height_file.display()))?;
        let message = (changed || missing > 0).then(|| {
            let mut text = format!("委任 {} 件でハーベストします", self.accepted.len());
            if missing > 0 {
                text.push_str(&format!(
                    "（ブロックのない高さ {missing} か所の要求は読めませんでした）"
                ));
            }
            text
        });
        Ok(Progress { changed, message })
    }

    fn account_links(&self, db: &Db, public_key: &PublicKey) -> Option<AccountLinks> {
        let address = Address::from_public_key(public_key, self.network);
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

    /// 書きかけで落ちても壊さないように、別のファイルに書いてから置き換える
    fn save(&self) -> Result<(), NodeError> {
        let bytes: Vec<u8> = self
            .accepted
            .iter()
            .flat_map(|entry| entry.payload)
            .collect();
        let temporary = self.file.with_extension("dat.new");
        std::fs::write(&temporary, &bytes)
            .and_then(|()| std::fs::rename(&temporary, &self.file))
            .map_err(|error| format!("{} を書けません: {error}", self.file.display()).into())
    }
}
