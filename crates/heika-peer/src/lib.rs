//! ピアについての意思決定。何か所につないでおくか、次にどこにつなぐか、外したピアをどれだけ罰するか、名乗りと
//! 知っているノードの一覧をいつ聞くか、ほかのノードに一覧として何を答えるか。
//!
//! IO は持たない（sans-IO）。駆動役が出来事（[`PeerEvent`]）を [`Peers::handle`] に入れ、返ってきた指示
//! （[`PeerAction`]）を実際にする。時刻も駆動役が渡す。チェーンの中核（heika-chain の `Chain`）とは別の状態機械で、
//! 中核がピアを外す（`Action::Disconnect`）と、駆動役がその罰をここに伝える。

pub mod book;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use heika_chain::chain::Penalty;
use heika_chain::event::PeerId;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_packet::{NetworkNode, NodeRoles};

pub use book::{Book, KnownPeer, endpoint};

/// つないでいるピアの1つに知っているノードの一覧を聞き、住所録をしまう間隔
pub const BOOK_EVERY: Duration = Duration::from_secs(10 * 60);

/// 駆動役からの出来事。`now` は今の時刻、`unix` はその UNIX 秒
#[derive(Debug)]
pub enum PeerEvent {
    /// 決まった間隔で入れる。足りなければつなぎに行き、ときどき一覧を聞き直す
    Tick,
    /// 頼んだ [`PeerAction::Connect`] がつながった
    Connected { id: PeerId },
    /// 頼んだ [`PeerAction::Connect`] がつながらなかった。`myself` なら、つないだ先が自分だった
    ConnectFailed { id: PeerId, myself: bool },
    /// ピアを外した。`penalty` は中核が決めた罰（通信に失敗しただけなら [`Penalty::None`]）
    Disconnected { id: PeerId, penalty: Penalty },
    /// 駆動役が自分の都合（入れ替えなど）でピアを外した。罰さない
    Released { id: PeerId },
    /// ピア自身の名乗り
    Info { id: PeerId, node: NetworkNode },
    /// ピアの知っているノードの一覧
    Nodes { id: PeerId, nodes: Vec<NetworkNode> },
}

/// ピアに聞くこと
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ask {
    /// ピア自身の名乗り（ping）
    Info,
    /// ピアの知っているノードの一覧
    Peers,
}

/// 駆動役への指示
#[derive(Debug, PartialEq, Eq)]
pub enum PeerAction {
    /// `address` につなぎ、つながったら `id` で呼ぶ。結果は [`PeerEvent::Connected`] か [`PeerEvent::ConnectFailed`]
    Connect { id: PeerId, address: String },
    /// ピア `id` に聞く。答えは [`PeerEvent::Info`] か [`PeerEvent::Nodes`]
    Ask { id: PeerId, ask: Ask },
    /// 住所録をしまう
    Save(Vec<(String, KnownPeer)>),
}

/// つないでいるピア
struct Connected {
    address: String,
    /// 名乗り。ほかのノードに教えてよいものだけ
    node: Option<NetworkNode>,
}

/// ピアについての意思決定
pub struct Peers {
    book: Book,
    parameters: &'static NetworkParameters,
    own_key: PublicKey,
    /// つないでおきたい数
    want: usize,
    /// つなぎに行っているアドレス
    connecting: BTreeMap<PeerId, String>,
    connected: BTreeMap<PeerId, Connected>,
    next_id: usize,
    /// `Node_Discovery_Pull_Peers` の答え（つないでいるピアの名乗りを並べたもの）
    reply: Arc<Vec<u8>>,
    /// 最後に一覧を聞き、住所録をしまった時刻と、次に聞くピアを選ぶための数
    book_at: Option<Instant>,
    round: usize,
    actions: Vec<PeerAction>,
}

impl Peers {
    /// 住所録 `book` から始め、`want` か所につないでおく。`own_key` は自分の鍵（一覧から自分を外す）
    pub fn new(
        book: Book,
        parameters: &'static NetworkParameters,
        own_key: PublicKey,
        want: usize,
    ) -> Self {
        Self {
            book,
            parameters,
            own_key,
            want,
            connecting: BTreeMap::new(),
            connected: BTreeMap::new(),
            next_id: 0,
            reply: Arc::new(Vec::new()),
            book_at: None,
            round: 0,
            actions: Vec::new(),
        }
    }

    /// 始めるときにもうつないであるピア（追いつく段階から引き継いだものなど）を、新しい番号で入れる
    pub fn adopt(&mut self, address: String, now: Instant, unix: u64) -> PeerId {
        let id = self.new_id();
        self.book.insert_in_use(&address, now);
        self.book.connected(&address, unix);
        self.connected.insert(
            id,
            Connected {
                address,
                node: None,
            },
        );
        self.actions.push(PeerAction::Ask { id, ask: Ask::Info });
        id
    }

    pub fn book(&self) -> &Book {
        &self.book
    }

    /// つないでいるピアの数
    pub fn len(&self) -> usize {
        self.connected.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connected.is_empty()
    }

    /// ほかのノードに `Node_Discovery_Pull_Peers` で答えるもの
    pub fn reply(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.reply)
    }

    /// 駆動役にまだ渡していない指示
    pub fn take_actions(&mut self) -> Vec<PeerAction> {
        std::mem::take(&mut self.actions)
    }

    /// 出来事を1つ受け取る。指示は [`Peers::take_actions`] で受け取る
    pub fn handle(&mut self, event: PeerEvent, now: Instant, unix: u64) {
        match event {
            PeerEvent::Tick => {
                if self.connected.len() + self.connecting.len() < self.want
                    && let Some(address) = self.book.take(now)
                {
                    let id = self.new_id();
                    self.connecting.insert(id, address.clone());
                    self.actions.push(PeerAction::Connect { id, address });
                }
                self.refresh_book(now);
            }
            PeerEvent::Connected { id } => {
                if let Some(address) = self.connecting.remove(&id) {
                    self.book.connected(&address, unix);
                    self.connected.insert(
                        id,
                        Connected {
                            address,
                            node: None,
                        },
                    );
                    self.actions.push(PeerAction::Ask { id, ask: Ask::Info });
                    // 知っているノードが、つないでおきたい数に足りなければ、すぐ一覧も聞く
                    if self.book.known() <= self.want {
                        self.actions.push(PeerAction::Ask {
                            id,
                            ask: Ask::Peers,
                        });
                    }
                }
            }
            PeerEvent::ConnectFailed { id, myself } => {
                if let Some(address) = self.connecting.remove(&id) {
                    if myself {
                        self.book.ban(&address, now, unix);
                    } else {
                        self.book.failed(&address, now);
                    }
                }
            }
            PeerEvent::Disconnected { id, penalty } => {
                if let Some(peer) = self.forget(id) {
                    match penalty {
                        Penalty::None => self.book.failed(&peer.address, now),
                        // 規則と状態で合わないものを返したので、通信の失敗より長く空ける
                        Penalty::Failure => {
                            self.book.failed(&peer.address, now);
                            self.book.failed(&peer.address, now);
                        }
                        Penalty::Ban => self.book.ban(&peer.address, now, unix),
                    }
                }
            }
            PeerEvent::Released { id } => {
                if let Some(peer) = self.forget(id) {
                    self.book.release(&peer.address);
                }
            }
            PeerEvent::Info { id, node } => {
                let listable = self.listable(&node);
                if let Some(peer) = self.connected.get_mut(&id)
                    && listable
                {
                    peer.node = Some(node);
                    self.rebuild_reply();
                }
            }
            PeerEvent::Nodes { nodes, .. } => {
                let addresses: Vec<String> = nodes
                    .iter()
                    .filter(|node| self.listable(node))
                    .take(book::MAX_LISTED)
                    .map(|node| endpoint(&node.host, node.port))
                    .collect();
                for address in addresses {
                    self.book.insert(address, now);
                }
            }
        }
    }

    fn new_id(&mut self) -> PeerId {
        let id = PeerId(self.next_id);
        self.next_id += 1;
        id
    }

    fn forget(&mut self, id: PeerId) -> Option<Connected> {
        let peer = self.connected.remove(&id)?;
        if peer.node.is_some() {
            self.rebuild_reply();
        }
        Some(peer)
    }

    /// ほかのノードに教えたり、住所録に足したりしてよいノードか。同じネットワークで、Peer の役割を持ち、
    /// ホストを名乗っていて、自分でないもの
    fn listable(&self, node: &NetworkNode) -> bool {
        node.roles.contains(NodeRoles::PEER)
            && !node.host.is_empty()
            && node.network_generation_hash_seed == self.parameters.generation_hash_seed
            && node.network_identifier == self.parameters.identifier
            && node.identity_key != self.own_key
    }

    fn rebuild_reply(&mut self) {
        let reply: Vec<u8> = self
            .connected
            .values()
            .filter_map(|peer| peer.node.as_ref())
            .filter_map(NetworkNode::encode)
            .flatten()
            .collect();
        self.reply = Arc::new(reply);
    }

    /// 前に聞いてから [`BOOK_EVERY`] たっていれば、つないでいるピアの1つ（順に回す）に一覧を聞き、住所録を
    /// しまう。始めの1回は時刻を覚えるだけ（始めるときにしまってある）
    fn refresh_book(&mut self, now: Instant) {
        let Some(at) = self.book_at else {
            self.book_at = Some(now);
            return;
        };
        if now.saturating_duration_since(at) < BOOK_EVERY {
            return;
        }
        self.book_at = Some(now);
        self.actions.push(PeerAction::Save(self.book.records()));
        if self.connected.is_empty() {
            return;
        }
        let index = self.round % self.connected.len();
        self.round += 1;
        if let Some(&id) = self.connected.keys().nth(index) {
            self.actions.push(PeerAction::Ask {
                id,
                ask: Ask::Peers,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use heika_core::network::NetworkIdentifier;
    use heika_packet::NodeVersion;

    use super::*;

    const NETWORK: &NetworkParameters = &NetworkParameters::MAINNET;

    fn node(key: u8, host: &str) -> NetworkNode {
        NetworkNode {
            version: NodeVersion(0x0100_0309),
            identity_key: PublicKey([key; 32]),
            network_generation_hash_seed: NETWORK.generation_hash_seed,
            roles: NodeRoles::PEER,
            port: 7900,
            network_identifier: NETWORK.identifier,
            host: host.to_owned(),
            friendly_name: String::new(),
        }
    }

    fn peers(addresses: &[&str], want: usize, start: Instant) -> Peers {
        let book = Book::new(addresses.iter().map(|a| a.to_string()).collect(), start);
        Peers::new(book, NETWORK, PublicKey([0; 32]), want)
    }

    #[test]
    fn connects_one_at_a_time_up_to_the_wanted_number() {
        let start = Instant::now();
        let mut peers = peers(&["a:7900", "b:7900", "c:7900"], 2, start);
        peers.handle(PeerEvent::Tick, start, 1);
        let actions = peers.take_actions();
        let [PeerAction::Connect { id: first, .. }] = actions[..] else {
            panic!("{actions:?}")
        };
        peers.handle(PeerEvent::Connected { id: first }, start, 1);
        assert_eq!(
            peers.take_actions(),
            [PeerAction::Ask {
                id: first,
                ask: Ask::Info
            }]
        );
        peers.handle(PeerEvent::Tick, start, 1);
        let actions = peers.take_actions();
        let [PeerAction::Connect { id: second, .. }] = actions[..] else {
            panic!("{actions:?}")
        };
        peers.handle(PeerEvent::Connected { id: second }, start, 1);
        peers.take_actions();
        // 足りているので、もうつなぎに行かない
        peers.handle(PeerEvent::Tick, start, 1);
        assert!(peers.take_actions().is_empty());
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn asks_for_a_list_at_once_when_it_knows_too_few() {
        let start = Instant::now();
        let mut peers = peers(&["seed:7900"], 4, start);
        peers.handle(PeerEvent::Tick, start, 1);
        let actions = peers.take_actions();
        let [PeerAction::Connect { id, .. }] = actions[..] else {
            panic!("{actions:?}")
        };
        peers.handle(PeerEvent::Connected { id }, start, 1);
        assert_eq!(
            peers.take_actions(),
            [
                PeerAction::Ask { id, ask: Ask::Info },
                PeerAction::Ask {
                    id,
                    ask: Ask::Peers
                }
            ]
        );
    }

    #[test]
    fn penalties_decide_when_to_try_again() {
        let start = Instant::now();
        let mut peers = peers(&["none:7900", "failure:7900", "ban:7900"], 3, start);
        let mut ids = BTreeMap::new();
        for _ in 0..3 {
            peers.handle(PeerEvent::Tick, start, 1);
            for action in peers.take_actions() {
                if let PeerAction::Connect { id, address } = action {
                    peers.handle(PeerEvent::Connected { id }, start, 1);
                    ids.insert(address, id);
                }
            }
            peers.take_actions();
        }
        for (address, penalty) in [
            ("none:7900", Penalty::None),
            ("failure:7900", Penalty::Failure),
            ("ban:7900", Penalty::Ban),
        ] {
            let id = ids[address];
            peers.handle(PeerEvent::Disconnected { id, penalty }, start, 1);
        }
        // 通信の失敗は 1 回ぶん（1 分）、規則に合わないものは 2 回ぶん（2 分）空け、ban は試さない
        let take = |peers: &mut Peers, after: u64| {
            let mut fresh = Book::load(peers.book.records(), start, 1);
            std::iter::from_fn(|| fresh.take(start + Duration::from_secs(after)))
                .collect::<Vec<_>>()
        };
        assert!(take(&mut peers, 59).is_empty());
        assert_eq!(take(&mut peers, 60), ["none:7900"]);
        assert_eq!(take(&mut peers, 120).len(), 2);
        assert!(!take(&mut peers, 3600).contains(&"ban:7900".to_owned()));
    }

    #[test]
    fn answers_with_listable_peers_and_learns_addresses() {
        let start = Instant::now();
        let mut peers = peers(&[], 0, start);
        let id = peers.adopt("a:7900".to_owned(), start, 1);
        peers.take_actions();
        // 別のネットワークのものは教えない
        let mut other = node(2, "b");
        other.network_identifier = NetworkIdentifier::TESTNET;
        peers.handle(PeerEvent::Info { id, node: other }, start, 1);
        assert!(peers.reply().is_empty());
        peers.handle(
            PeerEvent::Info {
                id,
                node: node(1, "a"),
            },
            start,
            1,
        );
        assert_eq!(*peers.reply(), node(1, "a").encode().unwrap());
        // 一覧からは、自分とホストのないものを外して足す
        peers.handle(
            PeerEvent::Nodes {
                id,
                nodes: vec![node(0, "me"), node(3, ""), node(4, "c"), node(5, "::1")],
            },
            start,
            1,
        );
        assert_eq!(peers.book().known(), 3);
        // 外したら、答えからも外す
        peers.handle(PeerEvent::Released { id }, start, 1);
        assert!(peers.reply().is_empty());
    }

    #[test]
    fn asks_for_lists_and_saves_the_book_now_and_then() {
        let start = Instant::now();
        let mut peers = peers(&[], 0, start);
        let id = peers.adopt("a:7900".to_owned(), start, 1);
        peers.take_actions();
        peers.handle(PeerEvent::Tick, start, 1);
        assert!(peers.take_actions().is_empty());
        peers.handle(PeerEvent::Tick, start + BOOK_EVERY, 1);
        let actions = peers.take_actions();
        assert!(matches!(actions[0], PeerAction::Save(_)));
        assert_eq!(
            actions[1],
            PeerAction::Ask {
                id,
                ask: Ask::Peers
            }
        );
    }
}
