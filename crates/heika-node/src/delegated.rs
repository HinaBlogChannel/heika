//! ほかの人の委任ハーベストを引き受ける。catapult の transfer プラグインの `TransferMessageObserver` と、harvesting 拡張の
//! `UnlockedAccountsUpdater` と `UnlockedAccountsStorage` に合わせている。
//!
//! - 委任の要求は、委任の鍵のアドレスあてのメッセージで届く。catapult と同じく、先端に足したブロックを高さの順に読む。
//!   委任する人を、確定まで待たせないため
//! - 引き受けるかどうかは、そのときのチェーンの状態のリンクで決める（[`heika_harvesting::unlocked`]）。ブロックを足すたびに、
//!   引き受けているものも確かめ直し、合わなくなったものは外す。リンクと要求の入ったブロックが巻き戻れば、リンクも
//!   なくなるので、ここで外れる。枝を取り替えたら、分かれ目から読み直す
//! - 取り込める委任は、暗号化したまま `harvesters.dat`（catapult と同じ形）に、どこまで読んだかは `harvesters.height`
//!   にしまう。上限を超えた分も残しておき、空きができたら重要度の大きい順に使う。初めて動かしたときは、
//!   それより前の要求は読まない
//! - 届いた要求ごとに、引き受けたか、なぜ引き受けなかったかを覚えておき、API で委任した人に見せる

use std::path::{Path, PathBuf};

use heika_block::Block;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_core::patricia::SubCache;
use heika_harvesting::delegation::{DelegationTracker, ENCRYPTED_PAYLOAD_SIZE, LinkKind};
use heika_harvesting::unlocked::{self, AccountLinks, Rejection};
use heika_state_transition::account::AccountType;
use heika_state_transition::executor::persist::{decode_account_row, row_key};
use heika_store_redb::Db;
use heika_wallet::harvest_request;

use crate::driver::NodeError;
use crate::harvesters::KeyPair;

type Payload = [u8; ENCRYPTED_PAYLOAD_SIZE];

/// 覚えておく、引き受けなかった要求の数
const MAX_REJECTED: usize = 64;

/// 取り込める委任1件
struct Candidate {
    payload: Payload,
    signing: PrivateKey,
    vrf: PrivateKey,
    /// 要求が入っていたブロックの高さ。`harvesters.dat` から読んだものはわからない
    height: Option<u64>,
}

/// 委任の今の様子
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DelegationState {
    /// 引き受けて、ハーベストしている
    Accepted,
    /// 取り込めるが、上限を超えているので空きを待っている
    Waiting,
    /// 引き受けなかった。わけを添える
    Rejected(String),
}

/// 届いた委任1件の様子
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationStatus {
    /// メインアカウント。リンクから辿れなかったときは、要求を送った人
    pub main_account: Option<PublicKey>,
    /// 要求に入っていたリモートの鍵
    pub remote: PublicKey,
    /// 要求が入っていたブロックの高さ
    pub height: Option<u64>,
    pub state: DelegationState,
}

/// 委任の引き受け
pub struct Delegated {
    key: PrivateKey,
    public_key: PublicKey,
    network: NetworkIdentifier,
    max: usize,
    file: PathBuf,
    height_file: PathBuf,
    /// 取り込める委任。重要度の大きい順で、先頭の `max` 件でハーベストする
    candidates: Vec<Candidate>,
    /// 届いた要求ごとの様子。取り込めるものと、最近の引き受けなかったもの
    statuses: Vec<DelegationStatus>,
    /// 要求を読み終えた高さ
    through: u64,
}

/// ブロックを読んだ結果。`changed` なら、ハーベストする鍵を入れ替える
pub struct Progress {
    pub changed: bool,
    pub message: Option<String>,
}

fn decrypt(key: &PrivateKey, payload: &Payload, height: Option<u64>) -> Option<Candidate> {
    let message = [&harvest_request::MARKER[..], payload].concat();
    let keys = harvest_request::decode(key, &message).ok()?;
    Some(Candidate {
        payload: *payload,
        signing: keys.signing,
        vrf: keys.vrf,
        height,
    })
}

/// catapult での要求の識別子（暗号化した中身の先頭の32バイト、使い捨ての公開鍵）
fn identifier(payload: &Payload) -> &[u8] {
    &payload[..32]
}

fn reason(rejection: &Rejection) -> String {
    match rejection {
        Rejection::NoMainAccount => {
            "リモートの鍵のアカウントが、メインアカウントにリンクしていません（AccountKeyLink がまだブロックに入っていないか、外した）".to_owned()
        }
        Rejection::Mismatched(kinds) => {
            let names: Vec<&str> = kinds
                .iter()
                .map(|kind| match kind {
                    LinkKind::Remote => "AccountKeyLink がリモートの鍵",
                    LinkKind::Vrf => "VrfKeyLink が VRF の鍵",
                    LinkKind::Node => "NodeKeyLink がこのノードの委任の鍵",
                })
                .collect();
            format!("メインアカウントの {}になっていません", names.join("、"))
        }
    }
}

impl Delegated {
    /// `data_directory` の `harvesters.dat` と `harvesters.height` を読む。なければ、高さ `tip` より後の要求を読む
    pub fn open(
        key: PrivateKey,
        network: NetworkIdentifier,
        max: usize,
        data_directory: &Path,
        tip: u64,
    ) -> Result<Self, NodeError> {
        let file = data_directory.join("harvesters.dat");
        let height_file = data_directory.join("harvesters.height");
        let mut candidates = Vec::new();
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
                    match decrypt(&key, &payload, None) {
                        Some(entry) => candidates.push(entry),
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
                println!("委任の要求は、高さ {tip} より後に届いたものから読みます");
                tip
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
            candidates,
            statuses: Vec::new(),
            through,
        })
    }

    /// 委任の鍵の公開鍵。委任する人は、NodeKeyLink をこれに向け、要求をこれのアドレスに送る
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// 引き受けている委任の鍵の組
    pub fn keys(&self) -> Vec<KeyPair> {
        let copy = |key: &PrivateKey| PrivateKey::from_bytes(key.as_bytes());
        self.candidates
            .iter()
            .take(self.max)
            .map(|entry| (copy(&entry.signing), copy(&entry.vrf)))
            .collect()
    }

    /// 届いた要求ごとの様子。引き受けているもの、待っているもの、最近の引き受けなかったものの順
    pub fn statuses(&self) -> Vec<DelegationStatus> {
        self.statuses.clone()
    }

    /// 枝を取り替えた。分かれ目 `common` より上の要求は、新しい枝で読み直す
    pub fn rewind(&mut self, common: u64) {
        self.through = self.through.min(common);
    }

    /// 先端が `tip` まで進んだ。新しい要求を読み、取り込めるものと合わせて、今の状態で確かめ直す
    pub fn advance(&mut self, db: &Db, tip: u64) -> Result<Progress, NodeError> {
        let mut tracker = DelegationTracker::new(&self.key, self.network);
        let mut missing = 0;
        for height in self.through + 1..=tip {
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
        let previous: Vec<Payload> = self
            .candidates
            .iter()
            .take(self.max)
            .map(|entry| entry.payload)
            .collect();
        let mut pool: Vec<(Candidate, Option<PublicKey>)> = std::mem::take(&mut self.candidates)
            .into_iter()
            .map(|entry| (entry, None))
            .collect();
        for delegation in report.delegations {
            let known = pool.iter().any(|(entry, _)| {
                identifier(&entry.payload) == identifier(&delegation.encrypted_payload)
            });
            if !known
                && let Some(entry) = decrypt(
                    &self.key,
                    &delegation.encrypted_payload,
                    Some(delegation.height),
                )
            {
                pool.push((entry, Some(delegation.main_account)));
            }
        }

        let lookup = |public_key: &PublicKey| self.account_links(db, public_key);
        let mut eligible = Vec::new();
        let mut rejected = Vec::new();
        for (entry, sender) in pool {
            let remote = PublicKey::from_private_key(&entry.signing);
            let vrf = PublicKey::from_private_key(&entry.vrf);
            match unlocked::check(&remote, &vrf, &self.public_key, lookup) {
                Ok(found) => eligible.push((entry, found)),
                Err(rejection) => rejected.push(DelegationStatus {
                    // 前に引き受けていたものなら、そのときに辿れたメインアカウントを引き継ぐ
                    main_account: sender.or_else(|| {
                        self.statuses
                            .iter()
                            .find(|status| status.remote == remote)
                            .and_then(|status| status.main_account)
                    }),
                    remote,
                    height: entry.height,
                    state: DelegationState::Rejected(reason(&rejection)),
                }),
            }
        }
        let ordered = unlocked::choose(eligible, usize::MAX);
        let mut statuses: Vec<DelegationStatus> = ordered
            .iter()
            .enumerate()
            .map(|(index, (entry, found))| DelegationStatus {
                main_account: Some(found.main_account),
                remote: PublicKey::from_private_key(&entry.signing),
                height: entry.height,
                state: if index < self.max {
                    DelegationState::Accepted
                } else {
                    DelegationState::Waiting
                },
            })
            .collect();
        // 前に引き受けなかったもので、今回また読んだものでないものも、しばらく覚えておく
        let old_rejected: Vec<DelegationStatus> = self
            .statuses
            .iter()
            .filter(|status| matches!(status.state, DelegationState::Rejected(_)))
            .filter(|old| !rejected.iter().any(|new| new.remote == old.remote))
            .cloned()
            .collect();
        // 取り込めるようになったリモートの鍵は、引き受けなかったものから外す
        let usable: Vec<PublicKey> = statuses.iter().map(|status| status.remote).collect();
        statuses.extend(
            rejected
                .into_iter()
                .chain(old_rejected)
                .filter(|status| !usable.contains(&status.remote))
                .take(MAX_REJECTED),
        );
        self.candidates = ordered.into_iter().map(|(entry, _)| entry).collect();
        self.statuses = statuses;
        self.through = tip;

        let now: Vec<Payload> = self
            .candidates
            .iter()
            .take(self.max)
            .map(|entry| entry.payload)
            .collect();
        let changed = now != previous;
        self.save()?;
        std::fs::write(&self.height_file, format!("{tip}\n"))
            .map_err(|error| format!("{} を書けません: {error}", self.height_file.display()))?;
        let message = (changed || missing > 0).then(|| {
            let mut text = format!("委任 {} 件でハーベストします", now.len());
            let waiting = self.candidates.len().saturating_sub(self.max);
            if waiting > 0 {
                text.push_str(&format!("（上限を超えて待っているもの {waiting} 件）"));
            }
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
            .candidates
            .iter()
            .flat_map(|entry| entry.payload)
            .collect();
        let temporary = self.file.with_extension("dat.new");
        std::fs::write(&temporary, &bytes)
            .and_then(|()| std::fs::rename(&temporary, &self.file))
            .map_err(|error| format!("{} を書けません: {error}", self.file.display()).into())
    }
}
