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
//! - 届いた要求ごとに、引き受けたか、なぜ引き受けなかったかを覚えておき、API で委任した人に見せる。止めても消えないように
//!   `delegations.yaml` にしまい、起動したら読み戻す

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
use serde::{Deserialize, Serialize};

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

/// `delegations.yaml` の1件。[`DelegationStatus`] を、鍵を16進にして書く
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedStatus {
    main_account: Option<String>,
    remote: String,
    height: Option<u64>,
    state: SavedState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SavedState {
    Accepted,
    Waiting,
    Rejected,
}

impl From<&DelegationStatus> for SavedStatus {
    fn from(status: &DelegationStatus) -> Self {
        let (state, reason) = match &status.state {
            DelegationState::Accepted => (SavedState::Accepted, None),
            DelegationState::Waiting => (SavedState::Waiting, None),
            DelegationState::Rejected(reason) => (SavedState::Rejected, Some(reason.clone())),
        };
        Self {
            main_account: status.main_account.map(|key| key.to_string()),
            remote: status.remote.to_string(),
            height: status.height,
            state,
            reason,
        }
    }
}

impl SavedStatus {
    fn restore(self) -> Option<DelegationStatus> {
        let main_account = match self.main_account {
            Some(text) => Some(text.parse().ok()?),
            None => None,
        };
        Some(DelegationStatus {
            main_account,
            remote: self.remote.parse().ok()?,
            height: self.height,
            state: match self.state {
                SavedState::Accepted => DelegationState::Accepted,
                SavedState::Waiting => DelegationState::Waiting,
                SavedState::Rejected => DelegationState::Rejected(self.reason.unwrap_or_default()),
            },
        })
    }
}

/// 委任の引き受け
pub struct Delegated {
    key: PrivateKey,
    public_key: PublicKey,
    network: NetworkIdentifier,
    max: usize,
    file: PathBuf,
    height_file: PathBuf,
    status_file: PathBuf,
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
    /// `data_directory` の `harvesters.dat`、`harvesters.height`、`delegations.yaml` を読む。なければ、高さ `tip` より後の
    /// 要求を読む
    pub fn open(
        key: PrivateKey,
        network: NetworkIdentifier,
        max: usize,
        data_directory: &Path,
        tip: u64,
    ) -> Result<Self, NodeError> {
        let file = data_directory.join("harvesters.dat");
        let height_file = data_directory.join("harvesters.height");
        let status_file = data_directory.join("delegations.yaml");
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
        let statuses = read_statuses(&status_file);
        // `harvesters.dat` には高さがないので、しまった様子から戻す
        for entry in &mut candidates {
            let remote = PublicKey::from_private_key(&entry.signing);
            entry.height = statuses
                .iter()
                .find(|status| status.remote == remote)
                .and_then(|status| status.height);
        }
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
            status_file,
            candidates,
            statuses,
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
        self.save_statuses()?;
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

    fn save_statuses(&self) -> Result<(), NodeError> {
        let saved: Vec<SavedStatus> = self.statuses.iter().map(SavedStatus::from).collect();
        let text = serde_norway::to_string(&saved)
            .map_err(|error| format!("委任の様子を書き出せません: {error}"))?;
        write_replacing(&self.status_file, text.as_bytes())
    }

    fn save(&self) -> Result<(), NodeError> {
        let bytes: Vec<u8> = self
            .candidates
            .iter()
            .flat_map(|entry| entry.payload)
            .collect();
        write_replacing(&self.file, &bytes)
    }
}

/// 書きかけで落ちても壊さないように、別のファイルに書いてから置き換える
fn write_replacing(path: &Path, bytes: &[u8]) -> Result<(), NodeError> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    std::fs::write(&temporary, bytes)
        .and_then(|()| std::fs::rename(&temporary, path))
        .map_err(|error| format!("{} を書けません: {error}", path.display()).into())
}

/// しまった様子。見せるためだけのものなので、なかったり読めなかったりしたら、空から始める（次にブロックを足したときに
/// 作り直す。引き受けなかったものは、そこで忘れる）
fn read_statuses(path: &Path) -> Vec<DelegationStatus> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            eprintln!("警告: {} を読めません: {error}", path.display());
            return Vec::new();
        }
    };
    match serde_norway::from_str::<Vec<SavedStatus>>(&text) {
        Ok(saved) => saved.into_iter().filter_map(SavedStatus::restore).collect(),
        Err(error) => {
            eprintln!(
                "警告: {} が読めないので、委任の様子を空から始めます: {error}",
                path.display()
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use heika_wallet::harvest_request::HarvesterKeys;

    use super::*;

    /// 決まったバイト列を返す乱数
    struct Replay<'a>(&'a [u8]);

    impl rand_core::TryRng for Replay<'_> {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let (head, rest) = self.0.split_at(dst.len());
            dst.copy_from_slice(head);
            self.0 = rest;
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Replay<'_> {}

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn statuses_survive_a_restart() {
        let directory =
            std::env::temp_dir().join(format!("heika-delegated-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let node = key(1);
        let keys = HarvesterKeys {
            signing: key(2),
            vrf: key(3),
        };
        let message = harvest_request::encode(
            &mut Replay(&[4; 64]),
            &PublicKey::from_private_key(&node),
            &keys,
        )
        .unwrap();
        std::fs::write(
            directory.join("harvesters.dat"),
            &message[harvest_request::MARKER.len()..],
        )
        .unwrap();
        std::fs::write(directory.join("harvesters.height"), "10\n").unwrap();
        let open = || {
            Delegated::open(
                PrivateKey::from_bytes(node.as_bytes()),
                NetworkIdentifier::TESTNET,
                5,
                &directory,
                10,
            )
            .unwrap()
        };

        // しまった様子がなければ、空から始める
        let mut delegated = open();
        assert!(delegated.statuses().is_empty());
        assert_eq!(delegated.candidates[0].height, None);
        let remote = PublicKey::from_private_key(&keys.signing);
        delegated.statuses = vec![
            DelegationStatus {
                main_account: Some(PublicKey::from_private_key(&key(5))),
                remote,
                height: Some(7),
                state: DelegationState::Accepted,
            },
            DelegationStatus {
                main_account: None,
                remote: PublicKey::from_private_key(&key(6)),
                height: Some(8),
                state: DelegationState::Rejected("わけ".to_owned()),
            },
        ];
        delegated.save_statuses().unwrap();

        // 起動し直しても、様子と、要求が入っていた高さが戻る
        let reopened = open();
        assert_eq!(reopened.statuses(), delegated.statuses());
        assert_eq!(reopened.candidates[0].height, Some(7));

        // 読めなければ、空から始める（委任そのものは harvesters.dat から読む）
        std::fs::write(directory.join("delegations.yaml"), "- [壊れている").unwrap();
        let broken = open();
        assert!(broken.statuses().is_empty());
        assert_eq!(broken.keys().len(), 1);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
