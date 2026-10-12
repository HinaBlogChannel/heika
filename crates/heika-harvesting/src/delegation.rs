//! ノードあての委任の要求をブロックから拾い、今も有効かを確かめる。
//!
//! catapult の transfer プラグインの `TransferMessageObserver` と、harvesting 拡張の `UnlockedAccountsUpdater` に合わせている。
//!
//! - 要求は、ノードの公開鍵のアドレスあての Transfer で、メッセージが目印で始まり、長さが合うもの。要求したのは Transfer の署名者
//! - ノードは、要求の中のリモートと VRF の公開鍵と、自分の公開鍵が、メインアカウントのリンクと合っているときだけ取り込む。
//!   取り込んだあとも同じことを確かめ直し、合わなくなったものは外す
//!
//! ここでは、走査したトランザクションを高さの順に渡してもらい、アカウントごとのリンクの付け替えを追う。
//! 最後に、要求ごとに、走査した範囲で最後に見たリンクと比べる。走査した範囲にリンクのトランザクションがなければ、
//! それより前に張ったリンクのままかもしれないので、わからないものとする。
//!
//! catapult は宛先をネームスペースから解決してから比べるが、解決にはチェーンの状態が要るので、
//! ネームスペースあての要求は拾わずに数えるだけにする。

use std::collections::{HashMap, HashSet};

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_transaction::{Body, Content, KeyLink, LinkAction, Scanned};
use heika_wallet::harvest_request;

/// 暗号化したままの要求の中身。harvesters.dat にはこれを並べる
pub const ENCRYPTED_PAYLOAD_SIZE: usize =
    harvest_request::MESSAGE_SIZE - harvest_request::MARKER.len();

/// メインアカウントのリンクの種類。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkKind {
    /// AccountKeyLink。リモートアカウント
    Remote,
    /// VrfKeyLink
    Vrf,
    /// NodeKeyLink
    Node,
}

/// ノードあての委任の要求1件と、今も有効か。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delegation {
    /// 要求が入っていたブロックの高さ
    pub height: u64,
    /// 要求したメインアカウント
    pub main_account: PublicKey,
    /// 要求に入っていたリモートアカウントの公開鍵
    pub remote: PublicKey,
    /// 要求に入っていた VRF の公開鍵
    pub vrf: PublicKey,
    /// 暗号化したままの要求の中身。先頭の32バイトが、catapult での要求の識別子になる
    pub encrypted_payload: [u8; ENCRYPTED_PAYLOAD_SIZE],
    pub status: Status,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Status {
    /// 3つのリンクが、どれも要求と合っている
    Active,
    /// 要求と合わないリンクがある。ノードは取り込まないか、取り込んでも外す
    Inactive { mismatched: Vec<LinkKind> },
    /// 合わないリンクはないが、走査した範囲でリンクのトランザクションを見ていない種類がある
    Unknown { unseen: Vec<LinkKind> },
}

/// 走査を終えた結果。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Report {
    /// 見つけた要求。同じ中身のものは、最初の1件だけ
    pub delegations: Vec<Delegation>,
    /// ネームスペースあての、要求の形をしたメッセージの数。このノードあてかはわからない
    pub namespace_recipients: usize,
    /// このノードあてで要求の形をしているのに、ノードの鍵で復号できなかったものの数。ノードも捨てる
    pub undecryptable: usize,
}

/// 走査したトランザクションを受け取って、委任の要求とリンクを追う。
pub struct DelegationTracker<'a> {
    node_private_key: &'a PrivateKey,
    node_public_key: PublicKey,
    recipient: Address,
    delegations: Vec<Delegation>,
    seen_payloads: HashSet<[u8; ENCRYPTED_PAYLOAD_SIZE]>,
    links: HashMap<PublicKey, Links>,
    namespace_recipients: usize,
    undecryptable: usize,
}

/// アカウントのリンクの、走査した範囲で最後に見た状態。None はまだ見ていない、Some(None) は外した
#[derive(Default)]
struct Links {
    remote: Option<Option<PublicKey>>,
    vrf: Option<Option<PublicKey>>,
    node: Option<Option<PublicKey>>,
}

impl<'a> DelegationTracker<'a> {
    /// `node_private_key` は、ノードの `node.key.pem` の秘密鍵。要求はこの公開鍵のアドレスに届き、この鍵で復号する
    pub fn new(node_private_key: &'a PrivateKey, network: NetworkIdentifier) -> Self {
        let node_public_key = PublicKey::from_private_key(node_private_key);
        Self {
            node_private_key,
            node_public_key,
            recipient: harvest_request::recipient_address(&node_public_key, network),
            delegations: Vec::new(),
            seen_payloads: HashSet::new(),
            links: HashMap::new(),
            namespace_recipients: 0,
            undecryptable: 0,
        }
    }

    /// 高さ `height` のブロックで走査したトランザクションを1件渡す。ブロックの順、ブロックの中の順に渡す
    pub fn observe(&mut self, height: u64, scanned: &Scanned) {
        let Content::Read(body) = &scanned.content else {
            return;
        };
        let signer = scanned.signer_public_key;
        match body {
            Body::AccountKeyLink(link) => {
                self.links.entry(signer).or_default().remote = Some(linked(link))
            }
            Body::VrfKeyLink(link) => {
                self.links.entry(signer).or_default().vrf = Some(linked(link))
            }
            Body::NodeKeyLink(link) => {
                self.links.entry(signer).or_default().node = Some(linked(link))
            }
            Body::Transfer(transfer) => {
                let message = transfer.message();
                if !harvest_request::is_harvest_request(message) {
                    return;
                }
                let recipient = transfer.recipient_address().0;
                // 先頭の1バイトの最下位ビットが1なら、ネームスペースあて
                if recipient[0] & 1 == 1 {
                    self.namespace_recipients += 1;
                } else if recipient == self.recipient.0 {
                    self.request(height, signer, message);
                }
            }
            Body::AggregateComplete(_) | Body::AggregateBonded(_) => {}
        }
    }

    fn request(&mut self, height: u64, main_account: PublicKey, message: &[u8]) {
        let encrypted_payload: [u8; ENCRYPTED_PAYLOAD_SIZE] = message
            [harvest_request::MARKER.len()..]
            .try_into()
            .expect("is_harvest_request checks the size");
        if !self.seen_payloads.insert(encrypted_payload) {
            return;
        }
        // 復号した秘密鍵は、公開鍵を出したらすぐに捨てる
        let Ok(keys) = harvest_request::decode(self.node_private_key, message) else {
            self.undecryptable += 1;
            return;
        };
        self.delegations.push(Delegation {
            height,
            main_account,
            remote: PublicKey::from_private_key(&keys.signing),
            vrf: PublicKey::from_private_key(&keys.vrf),
            encrypted_payload,
            // 走査を終えてから決める
            status: Status::Unknown { unseen: Vec::new() },
        });
    }

    /// 走査を終えて、要求ごとに、最後に見たリンクと比べる
    pub fn finish(self) -> Report {
        let no_links = Links::default();
        let delegations = self
            .delegations
            .into_iter()
            .map(|delegation| {
                let links = self
                    .links
                    .get(&delegation.main_account)
                    .unwrap_or(&no_links);
                let mut mismatched = Vec::new();
                let mut unseen = Vec::new();
                for (kind, last, expected) in [
                    (LinkKind::Remote, links.remote, delegation.remote),
                    (LinkKind::Vrf, links.vrf, delegation.vrf),
                    (LinkKind::Node, links.node, self.node_public_key),
                ] {
                    match last {
                        None => unseen.push(kind),
                        Some(linked) if linked != Some(expected) => mismatched.push(kind),
                        Some(_) => {}
                    }
                }
                let status = if !mismatched.is_empty() {
                    Status::Inactive { mismatched }
                } else if !unseen.is_empty() {
                    Status::Unknown { unseen }
                } else {
                    Status::Active
                };
                Delegation {
                    status,
                    ..delegation
                }
            })
            .collect();
        Report {
            delegations,
            namespace_recipients: self.namespace_recipients,
            undecryptable: self.undecryptable,
        }
    }
}

/// リンクのトランザクションのあとに、紐づいている公開鍵。外したなら None
fn linked(link: &KeyLink) -> Option<PublicKey> {
    match link.link_action {
        LinkAction::Link => Some(link.linked_public_key),
        LinkAction::Unlink => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use heika_transaction::{Transfer, UnresolvedAddress};
    use heika_wallet::harvest_request::HarvesterKeys;

    use super::*;
    use crate::testing::Replay;

    const NETWORK: NetworkIdentifier = NetworkIdentifier::MAINNET;

    fn private_key(seed: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[seed; 32])
    }

    fn public_key(seed: u8) -> PublicKey {
        PublicKey::from_private_key(&private_key(seed))
    }

    fn scanned(signer: PublicKey, body: Body) -> Scanned {
        Scanned {
            signer_public_key: signer,
            network: NETWORK,
            aggregate_signer: None,
            content: Content::Read(body),
        }
    }

    fn transfer(recipient: [u8; 24], message: Vec<u8>) -> Body {
        Body::Transfer(
            Transfer::new(UnresolvedAddress(recipient), BTreeMap::new(), message).unwrap(),
        )
    }

    /// ノードの鍵の公開鍵あての、リモート `remote` と VRF `vrf` の要求のメッセージ
    fn message(node: &PrivateKey, remote: u8, vrf: u8, randomness: u8) -> Vec<u8> {
        let keys = HarvesterKeys {
            signing: private_key(remote),
            vrf: private_key(vrf),
        };
        let randomness = [randomness; 32 + 12];
        harvest_request::encode(
            &mut Replay(&randomness),
            &PublicKey::from_private_key(node),
            &keys,
        )
        .unwrap()
    }

    fn request(node: &PrivateKey, main: u8, remote: u8, vrf: u8, randomness: u8) -> Scanned {
        let recipient =
            harvest_request::recipient_address(&PublicKey::from_private_key(node), NETWORK);
        scanned(
            public_key(main),
            transfer(recipient.0, message(node, remote, vrf, randomness)),
        )
    }

    fn link(signer: u8, body: fn(KeyLink) -> Body, linked: Option<PublicKey>) -> Scanned {
        let link = KeyLink {
            linked_public_key: linked.unwrap_or(public_key(0)),
            link_action: if linked.is_some() {
                LinkAction::Link
            } else {
                LinkAction::Unlink
            },
        };
        scanned(public_key(signer), body(link))
    }

    /// メインアカウント `main` が、リモート `remote`、VRF `vrf`、ノード `node` にリンクする3件
    fn links(main: u8, remote: u8, vrf: u8, node: PublicKey) -> [Scanned; 3] {
        [
            link(main, Body::AccountKeyLink, Some(public_key(remote))),
            link(main, Body::VrfKeyLink, Some(public_key(vrf))),
            link(main, Body::NodeKeyLink, Some(node)),
        ]
    }

    #[test]
    fn classifies_requests_by_the_last_links() {
        let node = private_key(100);
        let node_public = PublicKey::from_private_key(&node);
        let mut tracker = DelegationTracker::new(&node, NETWORK);
        // 1: リンクしてから要求する、よくある委任
        for scanned in links(1, 11, 21, node_public) {
            tracker.observe(10, &scanned);
        }
        tracker.observe(10, &request(&node, 1, 11, 21, 1));
        // 2: 要求したあとで、別のリモートにリンクし直した
        for scanned in links(2, 12, 22, node_public) {
            tracker.observe(11, &scanned);
        }
        tracker.observe(11, &request(&node, 2, 12, 22, 2));
        tracker.observe(20, &link(2, Body::AccountKeyLink, Some(public_key(13))));
        // 3: ノードのリンクを外した
        for scanned in links(3, 14, 24, node_public) {
            tracker.observe(12, &scanned);
        }
        tracker.observe(12, &request(&node, 3, 14, 24, 3));
        tracker.observe(21, &link(3, Body::NodeKeyLink, None));
        // 4: 走査した範囲にリンクがない
        tracker.observe(13, &request(&node, 4, 15, 25, 4));

        let report = tracker.finish();
        let statuses: Vec<_> = report
            .delegations
            .iter()
            .map(|delegation| (delegation.height, delegation.status.clone()))
            .collect();
        assert_eq!(
            statuses,
            [
                (10, Status::Active),
                (
                    11,
                    Status::Inactive {
                        mismatched: vec![LinkKind::Remote]
                    }
                ),
                (
                    12,
                    Status::Inactive {
                        mismatched: vec![LinkKind::Node]
                    }
                ),
                (
                    13,
                    Status::Unknown {
                        unseen: vec![LinkKind::Remote, LinkKind::Vrf, LinkKind::Node]
                    }
                ),
            ]
        );
        let first = &report.delegations[0];
        assert_eq!(first.main_account, public_key(1));
        assert_eq!(first.remote, public_key(11));
        assert_eq!(first.vrf, public_key(21));
        assert_eq!(first.encrypted_payload[..], message(&node, 11, 21, 1)[8..]);
    }

    #[test]
    fn a_node_link_to_another_node_makes_the_request_inactive() {
        let node = private_key(100);
        let mut tracker = DelegationTracker::new(&node, NETWORK);
        for scanned in links(1, 11, 21, public_key(101)) {
            tracker.observe(10, &scanned);
        }
        tracker.observe(10, &request(&node, 1, 11, 21, 1));
        assert_eq!(
            tracker.finish().delegations[0].status,
            Status::Inactive {
                mismatched: vec![LinkKind::Node]
            }
        );
    }

    #[test]
    fn ignores_other_recipients_and_counts_what_it_cannot_use() {
        let node = private_key(100);
        let other = private_key(101);
        let mut tracker = DelegationTracker::new(&node, NETWORK);
        // ほかのノードあて
        tracker.observe(10, &request(&other, 1, 11, 21, 1));
        // 要求の形をしていないメッセージ
        let recipient =
            harvest_request::recipient_address(&PublicKey::from_private_key(&node), NETWORK);
        tracker.observe(
            10,
            &scanned(public_key(1), transfer(recipient.0, b"hello".to_vec())),
        );
        // ネームスペースあて
        let mut namespace = [0; 24];
        namespace[0] = NETWORK.0 | 1;
        tracker.observe(
            10,
            &scanned(
                public_key(1),
                transfer(namespace, message(&node, 11, 21, 2)),
            ),
        );
        // このノードあてだが、ほかのノードの鍵で暗号化してある
        tracker.observe(
            10,
            &scanned(
                public_key(1),
                transfer(recipient.0, message(&other, 11, 21, 3)),
            ),
        );
        // 中身を読まなかったトランザクション
        tracker.observe(
            10,
            &Scanned {
                content: Content::Skipped {
                    transaction_type: 0x414D,
                },
                ..scanned(public_key(1), transfer(recipient.0, Vec::new()))
            },
        );

        let report = tracker.finish();
        assert!(report.delegations.is_empty());
        assert_eq!(report.namespace_recipients, 1);
        assert_eq!(report.undecryptable, 1);
    }

    #[test]
    fn keeps_only_the_first_of_identical_requests() {
        let node = private_key(100);
        let mut tracker = DelegationTracker::new(&node, NETWORK);
        tracker.observe(10, &request(&node, 1, 11, 21, 1));
        tracker.observe(20, &request(&node, 1, 11, 21, 1));
        // 中身が同じでも、暗号化に使った乱数が違えば別の要求になる
        tracker.observe(30, &request(&node, 1, 11, 21, 2));
        let heights: Vec<_> = tracker
            .finish()
            .delegations
            .iter()
            .map(|delegation| delegation.height)
            .collect();
        assert_eq!(heights, [10, 30]);
    }
}
