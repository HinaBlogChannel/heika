//! 中核（[`crate::chain::Chain`]）への出来事と、ピアに頼むこと。

use std::sync::Arc;

use heika_block::Block;
use heika_block::finalization::FinalizedBlockHeader;
use heika_core::key::PublicKey;
use heika_packet::ChainStatistics;

/// 1回に頼むブロックの数の上限（catapult の既定の `maxBlocksPerSyncAttempt`）
pub const PULL_BLOCKS: u32 = 360;
/// 1回に頼むハッシュの数の上限（catapult の既定の `maxHashesPerSyncAttempt`）
pub const PULL_HASHES: u32 = 370;
/// 1回に頼むブロックのバイト数の上限
pub const PULL_BYTES: u32 = 16 * 1024 * 1024;

/// ピアの番号。外したピアの番号は使い回さない
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct PeerId(pub usize);

/// ピアに頼むこと（[`crate::chain::Action::Command`]）。駆動役が実際に送り、返事を [`ChainEvent`] で返す
#[derive(Debug)]
pub enum PeerCommand {
    Statistics,
    PullBlocks {
        from: u64,
        count: u32,
    },
    PullHashes {
        from: u64,
        count: u32,
    },
    /// ピアの最新のファイナライズ
    Finalized,
    PullProof {
        epoch: u32,
    },
    /// 作ったブロックを押し付ける。返事はなく、失敗したときだけ `ChainEvent::Failed` を返す
    Push(Arc<Vec<u8>>),
}

/// チェーンの持ち主の受信箱
pub enum ChainEvent {
    Statistics {
        peer: PeerId,
        statistics: ChainStatistics,
    },
    /// 頼んだ範囲のブロック。前後に依らない確かめは済んでいる。ノードは数を切り詰めることがある
    Blocks {
        peer: PeerId,
        from: u64,
        count: u32,
        blocks: Vec<(Block, Vec<u8>)>,
    },
    /// 頼んだ高さからのブロックのハッシュ
    Hashes {
        peer: PeerId,
        from: u64,
        count: u32,
        hashes: Vec<[u8; 32]>,
    },
    /// ピアの言う最新のファイナライズ（エポック、ポイント、高さ、ハッシュ）
    Finalized {
        peer: PeerId,
        header: FinalizedBlockHeader,
    },
    /// 頼んだエポックの証明。まだなければ `None`
    Proof {
        peer: PeerId,
        epoch: u32,
        proof: Option<Vec<u8>>,
    },
    /// 頼んだことができなかった。`malformed` なら、状態を見ない確かめに落ちるもの（形、署名）が返ってきた。
    /// そうでなければ、通信に失敗した
    Failed {
        peer: PeerId,
        error: String,
        malformed: bool,
    },
    /// 駆動役が新しいピア `peer` とやりとりを始めた
    PeerAdded { peer: PeerId },
    /// 駆動役が自分の都合（入れ替えなど）でピア `peer` を外した
    PeerLost { peer: PeerId },
    /// 頼んだ時刻（[`crate::chain::Action::WakeAt`]）になった
    Wake,
    /// 接続してきたピアが押し付けたブロック。前後に依らない確かめは済んでいる。`from` は押し付けた相手の鍵。
    /// REST（`PUT /blocks`）で届いたものは `None` で、弾いても罰さない
    Pushed {
        block: Box<Block>,
        bytes: Vec<u8>,
        from: Option<PublicKey>,
    },
    /// 決まった間隔で入れる。ピアに統計を聞き直し、押し付けのまとめを出す
    Tick,
}
