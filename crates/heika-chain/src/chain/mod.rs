//! チェーンの持ち主。実行の状態と DB を持ち、Tick ごとにピアの統計を聞いて、スコアが自分より高く先に進んでいる
//! ピアから続きを取り、確かめて当て、ブロックごとに（索引もその場で）durable にコミットする。
//!
//! 同期は1度に1つのピアとだけ（catapult の `CompareChains` と同じ）。続きが自分の先端につながらないか、スコアが
//! 高いのに先にいないピアとは、ブロックのハッシュを並べて分かれ目を探し、ピアの枝を取って、自分の状態を分かれ目まで
//! 巻き戻して当てる。スコアが元より高くならなければ、元の枝に戻す（`docs/archive/tip.md`）。
//!
//! Tick ごとにピアの最新のファイナライズも聞き、自分の確かめたものより新しければ、そのエポックの証明を取って、
//! 実行して求めた投票者で確かめる。通れば、指すブロックが手元にあればハッシュを比べ（違えば分かれ目を探す）、
//! 確かめた確定を上げて証明をしまい、確定より [`CHECKPOINT_EPOCHS`] エポック下より古いチェックポイントを1つを
//! 残して消す。刈り込むなら（[`Keep`]）、そのときに差分も消す。分かれ目を探すのは、確かめた確定の高さから。
//! 同じラウンドで違うブロックを指す証明が2つ通ったら、止める。

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use heika_block::Block;
use heika_block::finalization::proof::{VotingSet, closes_epoch, proof_header, verify_proof};
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_block::scoring::{BlockStatistic, difficulty};
use heika_block::statement::BlockStatement;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_core::vrf::GenerationHash;
use heika_packet::ChainStatistics;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::source::StateSource;
use heika_state_transition::executor::{Executor, Wanted};

use crate::ChainError;
use crate::env::Env;
use crate::event::{ChainEvent, PULL_BLOCKS, PULL_HASHES, PeerCommand, PeerId};
use crate::produce;
use crate::store::{BlockWrite, ChainStore, Prune};
use crate::verify::{Tip, verify_link};

mod accept;
mod finality;
mod harvest;
mod push;
mod sync;

/// 答えるときに読む、チェーンの様子。中核は出来事を1つ済ませるたびに [`Chain::status`] で作り直す
#[derive(Clone, Copy, Debug)]
pub struct Status {
    /// 実行した先端の高さ
    pub height: u64,
    /// 先端までのスコア。わからなければ 0
    pub score: u128,
    /// 確かめた一番新しいファイナライズ
    pub finalized: FinalizedBlockHeader,
}

/// 確かめた確定より何エポック下までのチェックポイントを残すか（それより古いものは1つを残して消す）。
/// 確定より下には巻き戻らないので、余裕を見て2エポック
pub const CHECKPOINT_EPOCHS: u64 = 2;

/// 刈り込みで、ファイナライズより何エポック下まで差分を残すか。状態と木のノードとで別々。
/// 巻き戻しに使う差分が要るので、どちらも [`CHECKPOINT_EPOCHS`] 以上にする
#[derive(Clone, Copy, Debug)]
pub struct Keep {
    pub state: u64,
    pub trie: u64,
    /// ブロック、ステートメント、ファイナライズの証明も、状態の差分の境から再開に要る分（
    /// [`ChainConfig::blocks_for_restart`]）を引いたところより前を消す
    pub history: bool,
}

/// DB の実行した先端の状態を戻したもの
pub struct Loaded {
    pub executor: Executor,
    /// 実行した最後のブロック
    pub parent: Block,
    /// 難易度を求めるのに要る、直前のブロックの統計（古い順、`maxDifficultyBlocks` まで）
    pub statistics: VecDeque<BlockStatistic>,
    pub tip: Tip,
}

/// 保存の口 `store` の、実行した先端の状態を、書かずに戻す。二度入れを弾くハッシュも、直前のブロックから覚え直す
///
/// `partial` なら、アカウントの表を全部はメモリに持たない（[`Executor::restore_partial`]）
pub async fn load_from<S: ChainStore + StateSource>(
    store: &S,
    config: ChainConfig,
    parameters: &NetworkParameters,
    partial: bool,
) -> Result<Loaded, ChainError> {
    let lifetime = config
        .max_transaction_lifetime
        .max(config.max_bonded_transaction_lifetime);
    let mut executor = if partial {
        let (meta, rows, nodes) = store.load_partial_state().await?;
        let mut executor = Executor::restore_partial(
            config,
            parameters.identifier,
            parameters.generation_hash_seed,
            rows,
            &meta,
        )?;
        executor.restore_trees(nodes)?;
        executor.load_tree_roots(store)?;
        executor
    } else {
        let (meta, rows, nodes) = store.load_state().await?;
        let mut executor = Executor::restore(
            config,
            parameters.identifier,
            parameters.generation_hash_seed,
            rows,
            &meta,
        )?;
        executor.restore_trees(nodes)?;
        executor
    };
    let parent = block_at(store, executor.height()).await?;
    if executor.state_hash() != parent.state_hash {
        // 行から木を組み直すには、アカウントが全部要る
        if partial {
            return Err("しまった木の根が StateHash と合いません".into());
        }
        executor.rebuild_trees();
    }
    // ここから先の木のノードの変化を、ブロックごとに書く
    executor.forget_node_changes();
    let (parent, statistics, tip) = context(store, &mut executor, parameters, lifetime).await?;
    Ok(Loaded {
        executor,
        parent,
        statistics,
        tip,
    })
}

async fn block_at<S: ChainStore>(store: &S, height: u64) -> Result<Block, ChainError> {
    Ok(Block::from_bytes(
        &store
            .block(height)
            .await?
            .ok_or("実行した高さのブロックがありません")?,
    )?)
}

/// 実行の状態の高さで、親のブロック、難易度の統計、Tip を DB から読み、二度入れを弾くハッシュを直前の
/// ブロックから覚え直す
async fn context<S: ChainStore>(
    store: &S,
    executor: &mut Executor,
    parameters: &NetworkParameters,
    lifetime: u64,
) -> Result<(Block, VecDeque<BlockStatistic>, Tip), ChainError> {
    let height = executor.height();
    let parent = block_at(store, height).await?;
    let mut recent = Vec::new();
    for height in (1..=height).rev() {
        let block = block_at(store, height).await?;
        if recent
            .first()
            .is_some_and(|last: &Block| block.timestamp + lifetime < last.timestamp)
        {
            break;
        }
        recent.push(block);
    }
    for block in recent.iter().rev() {
        executor.remember_transactions(block)?;
    }
    let from = height
        .saturating_sub(parameters.max_difficulty_blocks as u64 - 1)
        .max(1);
    let mut statistics = VecDeque::new();
    for height in from..=height {
        statistics.push_back(BlockStatistic::from(&block_at(store, height).await?));
    }
    let importance_height =
        (height / parameters.importance_grouping * parameters.importance_grouping).max(1);
    let tip = Tip {
        height,
        hash: parent.hash(),
        importance_hash: block_at(store, importance_height).await?.hash(),
    };
    Ok((parent, statistics, tip))
}

struct Peer {
    statistics: Option<ChainStatistics>,
    /// 頼んで返事を待っている数
    pending: usize,
}

enum Sync {
    Idle,
    /// 自分の先端の続きを取っている
    Extending {
        peer: PeerId,
    },
    /// 分かれ目を探している。`from` から自分とピアのハッシュを比べる
    Comparing {
        peer: PeerId,
        from: u64,
    },
    /// 分かれ目 `common` から先の、ピアの枝を取っている
    Forking {
        peer: PeerId,
        common: u64,
        blocks: Vec<(Block, Vec<u8>)>,
    },
}

impl Sync {
    fn peer(&self) -> Option<PeerId> {
        match self {
            Self::Idle => None,
            Self::Extending { peer }
            | Self::Comparing { peer, .. }
            | Self::Forking { peer, .. } => Some(*peer),
        }
    }
}

/// ピアを外すときの罰。catapult と同じく、締め出すのは、どの規則から見ても壊れているものを返したときだけ
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Penalty {
    /// 通信に失敗したか、こちらの都合。間を空けてまた試してよい
    None,
    /// こちらの規則と状態で合わないものを返した。失敗を数え、間を長く空ける
    Failure,
    /// 状態を見ない確かめに落ちるもの（形、署名）を返した。しばらく締め出す
    Ban,
}

/// チェーンの持ち主から、駆動役（ピアとのやりとりを実際にするもの）への指示。[`Chain::take_actions`] で受け取る
#[derive(Debug)]
pub enum Action {
    /// このピアに頼む。返事は [`ChainEvent`] で [`Chain::handle`] に入れる。頼めなかったら `ChainEvent::Failed` を入れる
    Command(PeerId, PeerCommand),
    /// このピアとのやりとりをやめる。どれだけ罰するかは `penalty`
    Disconnect { peer: PeerId, penalty: Penalty },
    /// この時刻になったら [`ChainEvent::Wake`] を入れる
    WakeAt(SystemTime),
    /// この鍵が押し付けたブロックは、こちらの規則と状態で合わなかった。今の接続を切るが、締め出さない
    /// （規則の割れたハードフォークのあいだ、向こう側は別の規則に従っているだけかもしれない）
    RejectPush(PublicKey),
    /// 使う側に知らせること（画面やログに出すかは使う側が決める）
    Notify(Notice),
}

/// 先端の段階で起きたこと。`Display` は CLI に出す文
#[derive(Clone, Debug)]
pub enum Notice {
    /// 先端にブロックを足した。`pushed` なら、接続してきたピアが押し付けたもの
    Accepted {
        height: u64,
        transactions: usize,
        hash: Hash256,
        pushed: bool,
    },
    /// 分かれ目 `common` から先を、ピアの枝に取り替えた
    Switched {
        common: u64,
        old: Tip,
        new: Tip,
        peer: PeerId,
    },
    /// 証明を確かめて確定を上げた。`rows` は刈り込んで消した差分の行（刈り込まないなら `None`）
    Finalized {
        epoch: u32,
        point: u32,
        height: u64,
        peer: PeerId,
        checkpoints: usize,
        rows: Option<u64>,
    },
    /// 抜けていたか、途中のポイントのままだった前のエポックの証明をしまった
    EarlierProof {
        epoch: u32,
        height: u64,
        peer: PeerId,
        partial: bool,
    },
    /// ピアの枝の時刻が今より `ahead` ミリ秒先なので、今は使わない
    TooFarInFuture {
        peer: PeerId,
        height: u64,
        ahead: u64,
    },
    /// ピアの言う確定が自分の先端より1エポック以上先にある。追いつく段階に戻る
    Behind {
        peer: PeerId,
        finalized: u64,
        tip: u64,
    },
    /// ハーベストして、親から `seconds` 秒の高さ `height` のブロックを作り、先端に足した
    Produced {
        height: u64,
        hash: Hash256,
        seconds: u64,
        peers: usize,
    },
    /// ピアを外した。`message` はわけを含む文
    PeerDropped { peer: PeerId, message: String },
    /// そのほかの経過。`warning` なら、うまくいかなかったこと
    Progress { message: String, warning: bool },
}

impl Notice {
    /// うまくいかなかったことか（CLI は標準エラーに出す）
    pub fn is_warning(&self) -> bool {
        match self {
            Self::PeerDropped { .. } => true,
            Self::Progress { warning, .. } => *warning,
            _ => false,
        }
    }
}

impl fmt::Display for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted {
                height,
                transactions,
                hash,
                pushed,
            } => write!(
                f,
                "高さ {height} を受け入れました（トランザクション {transactions} 件、ハッシュ {hash}{}）",
                if *pushed {
                    "、押し付けで届いたもの"
                } else {
                    ""
                }
            ),
            Self::Produced {
                height,
                hash,
                seconds,
                peers,
            } => write!(
                f,
                "高さ {height} のブロックを作りました（親から {seconds} 秒、ハッシュ {hash}）。{peers} か所のピアに配ります"
            ),
            Self::Switched {
                common,
                old,
                new,
                peer,
            } => write!(
                f,
                "枝を取り替えました: 分かれ目 {common}、深さ {}、元の先端 {}（高さ {}）→ 新しい先端 {}（高さ {}）、ピア {}",
                old.height - common,
                old.hash,
                old.height,
                new.hash,
                new.height,
                peer.0
            ),
            Self::Finalized {
                epoch,
                point,
                height,
                peer,
                checkpoints,
                rows,
            } => {
                write!(
                    f,
                    "エポック {epoch} ポイント {point} の証明を確かめました: 高さ {height} をファイナライズ（ピア {}、消したチェックポイント {checkpoints}",
                    peer.0
                )?;
                if let Some(rows) = rows {
                    write!(f, "、消した差分 {rows} 行")?;
                }
                write!(f, "）")
            }
            Self::EarlierProof {
                epoch,
                height,
                peer,
                partial,
            } => write!(
                f,
                "{}エポック {epoch} の証明を確かめてしまいました（高さ {height}、ピア {}）",
                if *partial {
                    "途中のポイントのままだった"
                } else {
                    "抜けていた"
                },
                peer.0
            ),
            Self::TooFarInFuture {
                peer,
                height,
                ahead,
            } => write!(
                f,
                "ピア {} の高さ {height} は、時刻が今より {ahead} ミリ秒先なので、今は使いません",
                peer.0
            ),
            Self::Behind {
                peer,
                finalized,
                tip,
            } => write!(
                f,
                "ピア {} の言う確定（高さ {finalized}）が、自分の先端（高さ {tip}）より1エポック以上先にあります。追いつく段階に戻ります",
                peer.0
            ),
            Self::PeerDropped { message, .. } | Self::Progress { message, .. } => {
                f.write_str(message)
            }
        }
    }
}

/// 押し付けの数を知らせる間隔
const PUSH_REPORT: Duration = Duration::from_secs(60);

/// ハーベストの当たりを、親からどれだけ先まで探すか（ミリ秒）
const HARVEST_HORIZON: u64 = 60 * 60 * 1000;
/// 当たりがこれより近ければ（秒）、求めたことを知らせる
const HARVEST_ANNOUNCE: u64 = 120;

/// ハーベストの予定。先端 `parent` の上で求めた、当たりの一番早い時刻と鍵の番号（なければ `None`）
struct Planned {
    parent: Hash256,
    slot: Option<(u64, usize)>,
}

/// 作るブロックの親まわりの写し。[`produce::Parent`] はこれを借りる
struct HarvestParent {
    block: Block,
    recent: Vec<BlockStatistic>,
    generation_hash: GenerationHash,
    importance_hash: Hash256,
}

impl HarvestParent {
    fn context(&self) -> produce::Parent<'_> {
        produce::Parent {
            block: &self.block,
            generation_hash: self.generation_hash,
            recent: &self.recent,
            importance_hash: self.importance_hash,
        }
    }
}

/// 押し付けられたブロックをどう扱ったかの数
#[derive(Default)]
struct PushCounts {
    /// 数え始めた時刻
    since: Option<SystemTime>,
    /// 先端の次として使った
    used: u64,
    /// 先端の次として試したが、弾いた
    rejected: u64,
    /// もう持っている高さ
    known: u64,
    /// そのうち、受け入れてからどれだけ遅れて届いたかがわかったものの、遅れの合計と数
    late_total: Duration,
    late_count: u32,
    /// 先端の次だが、同期の途中だった
    syncing: u64,
    /// 先端の次だが、自分の先端につながらない（枝が違う）
    unlinked: u64,
    /// 先端の次より先の高さ
    ahead: u64,
    /// 時刻がまだ来ていないので、来るまで持った
    held: u64,
    /// そのうち、時刻が来て受け入れた（`used` とは別に数える）
    used_late: u64,
    /// そのうち、時刻が来て試したが、弾いた（`rejected` とは別に数える）
    rejected_late: u64,
    /// 時刻がまだ来ていないが、もう 1 つ持っていたので捨てた
    future: u64,
}

impl PushCounts {
    fn total(&self) -> u64 {
        self.used
            + self.rejected
            + self.known
            + self.syncing
            + self.unlinked
            + self.ahead
            + self.held
            + self.future
    }
}

impl fmt::Display for PushCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "押し付けられたブロック {}: 使った {}、弾いた {}、もう持っていた {}",
            self.total(),
            self.used,
            self.rejected,
            self.known
        )?;
        if self.late_count > 0 {
            write!(
                f,
                "（受け入れてから平均 {:.1} 秒あと）",
                (self.late_total / self.late_count).as_secs_f64()
            )?;
        }
        write!(
            f,
            "、時刻が来るまで持った {}（来て受け入れた {}、弾いた {}）、もう持っていたので捨てた {}、同期の途中 {}、つながらない {}、先の高さ {}",
            self.held,
            self.used_late,
            self.rejected_late,
            self.future,
            self.syncing,
            self.unlinked,
            self.ahead
        )
    }
}

/// アカウントを全部はメモリに持たないときに、1ブロックで読み足して当て直す回数の上限
const MAX_RETRIES: usize = 8;
/// 当てる途中で、まだ読んでいない状態のキーを引いた
#[derive(Debug)]
struct Missed(Wanted);

impl fmt::Display for Missed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "読んでいない状態が {} 個あります", self.0.len())
    }
}

impl std::error::Error for Missed {}

/// ブロックが正しくないので弾いた（DB を読めないなど、こちらの都合で受け入れられなかったのではない）。送って
/// きた相手を罰してよいのは、これのときだけ
#[derive(Debug)]
struct Invalid(ChainError);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Invalid {}

fn invalid(error: impl Into<ChainError>) -> ChainError {
    Box::new(Invalid(error.into()))
}

fn is_invalid(error: &ChainError) -> bool {
    error.downcast_ref::<Invalid>().is_some()
}

/// 先端の段階が終わったわけ
pub enum Outcome {
    /// 止める合図で止めた
    Stopped,
    /// ピアの言う確定が、自分の先端より1エポック以上先にある。追いつく段階でまとめて進める
    Behind { finalized: u64 },
}

/// チェーンの持ち主
pub struct Chain<'a, S: ChainStore + StateSource> {
    store: &'a S,
    env: &'a dyn Env,
    config: ChainConfig,
    parameters: &'static NetworkParameters,
    executor: Executor,
    parent: Block,
    generation_hash: GenerationHash,
    statistics: VecDeque<BlockStatistic>,
    tip: Tip,
    peers: BTreeMap<PeerId, Peer>,
    sync: Sync,
    /// 確かめた一番新しいファイナライズ。そこより下は分かれていない
    finalized: FinalizedBlockHeader,
    /// 頼んで返事を待っている証明のラウンド。同じものを何度も頼まない
    proof_requested: Option<FinalizationRound>,
    /// ここより前のエポックの証明は、しまってあるか、取り直しを一度頼んだ。抜けを探すのはここから
    backfilled: u32,
    /// 刈り込むなら、残す差分
    keep: Option<Keep>,
    /// 押し付けられたブロックをどう扱ったかの数。1 分ごとに知らせて 0 に戻す
    pushes: PushCounts,
    /// 押し付けられた、先端の次につながるが時刻のまだ来ていないブロック。時刻が来たら受け入れる（
    /// `docs/archive/tip.md` の「未来のブロックは、受け入れずに手元に持つ」）
    held: Option<(Block, Vec<u8>, PublicKey)>,
    /// 最近受け入れた高さと時刻。押し付けがどれだけ遅れて届いたかを測る
    accepted_at: VecDeque<(u64, SystemTime)>,
    /// ハーベストする鍵（署名の鍵、VRF の鍵）。空ならハーベストしない
    harvesters: Arc<Vec<(PrivateKey, PrivateKey)>>,
    /// 今の先端の上での、ハーベストの予定
    planned: Option<Planned>,
    /// 最後に知らせた、ハーベストできないわけ。同じものは繰り返さない
    harvest_warning: Option<String>,
    /// 駆動役にまだ渡していない指示
    actions: Vec<Action>,
}

impl<'a, S: ChainStore + StateSource> Chain<'a, S> {
    /// `partial` なら、アカウントの表を全部はメモリに持たず、ブロックごとに要る分だけ読む
    pub async fn new(
        store: &'a S,
        env: &'a dyn Env,
        config: ChainConfig,
        parameters: &'static NetworkParameters,
        partial: bool,
    ) -> Result<Self, ChainError> {
        let loaded = load_from(store, config.clone(), parameters, partial).await?;
        // 追いつく段階で確かめてしまった、一番新しい証明。なければ Nemesis
        let finalized = match store.proofs_tip().await? {
            0 => FinalizedBlockHeader {
                round: FinalizationRound { epoch: 1, point: 1 },
                height: 1,
                hash: block_at(store, 1).await?.hash(),
            },
            epoch => proof_header(
                &store
                    .proof(epoch)
                    .await?
                    .ok_or("しまった証明がありません")?,
            )?,
        };
        Ok(Self {
            finalized,
            proof_requested: None,
            backfilled: 1,
            store,
            env,
            config,
            parameters,
            generation_hash: loaded.parent.generation_hash(),
            executor: loaded.executor,
            parent: loaded.parent,
            statistics: loaded.statistics,
            tip: loaded.tip,
            peers: BTreeMap::new(),
            sync: Sync::Idle,
            keep: None,
            pushes: PushCounts::default(),
            accepted_at: VecDeque::new(),
            held: None,
            harvesters: Arc::new(Vec::new()),
            planned: None,
            harvest_warning: None,
            actions: Vec::new(),
        })
    }

    /// 先端の段階で、`keys`（署名の鍵、VRF の鍵。リモートならリモートの鍵）でハーベストする
    pub fn set_harvesters(&mut self, keys: Arc<Vec<(PrivateKey, PrivateKey)>>) {
        self.harvesters = keys;
    }

    /// 確定を上げるたびに、残す分より下の差分を消す
    pub fn set_keep(&mut self, keep: Keep) {
        self.keep = Some(keep);
    }

    /// 実行した高さ
    pub fn height(&self) -> u64 {
        self.tip.height
    }

    /// 実行した先端
    pub fn tip(&self) -> Tip {
        self.tip
    }

    /// 接続してきたピアに答えるときの様子
    pub fn status(&self) -> Status {
        Status {
            height: self.tip.height,
            score: self.executor.score().unwrap_or(0),
            finalized: self.finalized,
        }
    }

    /// メモリの状態の根が、先端のブロックの StateHash と合うか
    pub fn state_matches(&mut self) -> bool {
        self.executor.state_hash() == self.parent.state_hash
    }

    /// ピアなしで、先端の次のブロック `block` を確かめて当て、コミットする（調べもの用）。知らせは指示に積む
    pub async fn extend_offline(
        &mut self,
        block: &Block,
        bytes: Vec<u8>,
    ) -> Result<(), ChainError> {
        self.accept(block, bytes, false).await
    }

    /// 分かれ目 `common` から先を、ピアなしで枝 `blocks` に取り替えてみる（`switch-check`）。取り替えたら真、
    /// 通らないかスコアが高くなくて元の枝に戻したら偽
    pub async fn switch_offline(
        &mut self,
        common: u64,
        blocks: Vec<(Block, Vec<u8>)>,
    ) -> Result<bool, ChainError> {
        let before = self.tip.hash;
        self.switch(PeerId(usize::MAX), common, blocks).await?;
        // ピアはいないので、知らせのほかの指示は捨てる
        self.actions
            .retain(|action| matches!(action, Action::Notify(_)));
        Ok(self.tip.hash != before)
    }

    /// ピア `id` とやりとりを始めたことを知らせる。ほかのノードに教えるために、名乗りを聞く
    pub fn add_peer(&mut self, id: PeerId) {
        self.peers.insert(
            id,
            Peer {
                statistics: None,
                pending: 0,
            },
        );
    }

    /// 駆動役にまだ渡していない指示を受け取る
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// 出来事を1つ受け取って進める。先端の段階を終えるなら、そのわけを返す。指示は [`Chain::take_actions`] で受け取る
    pub async fn handle(&mut self, event: ChainEvent) -> Result<Option<Outcome>, ChainError> {
        let outcome = self.handle_event(event).await?;
        if outcome.is_none() {
            self.harvest().await?;
        }
        Ok(outcome)
    }

    async fn handle_event(&mut self, event: ChainEvent) -> Result<Option<Outcome>, ChainError> {
        match event {
            ChainEvent::Tick => {
                self.report_pushes();
                self.accept_held().await?;
                let idle: Vec<PeerId> = self
                    .peers
                    .iter()
                    .filter(|(_, peer)| peer.pending == 0)
                    .map(|(id, _)| *id)
                    .collect();
                for id in idle {
                    self.command(id, PeerCommand::Statistics);
                    self.command(id, PeerCommand::Finalized);
                }
                self.backfill_proofs().await?;
            }
            ChainEvent::Statistics { peer, statistics } => {
                self.answered(peer);
                if let Some(entry) = self.peers.get_mut(&peer) {
                    entry.statistics = Some(statistics);
                }
                // 1ブロックずつコミットする先端の段階では遅いので、まとめて書く追いつく段階に戻る。確定は
                // ピアの言うものだが、追いつく段階は終わりに証明を確かめる
                let grouping = self.config.finalization.voting_set_grouping;
                if matches!(self.sync, Sync::Idle)
                    && statistics.finalized_height > self.tip.height + grouping
                {
                    self.notify(Notice::Behind {
                        peer,
                        finalized: statistics.finalized_height,
                        tip: self.tip.height,
                    });
                    return Ok(Some(Outcome::Behind {
                        finalized: statistics.finalized_height,
                    }));
                }
                self.start_sync();
            }
            ChainEvent::Blocks {
                peer,
                from,
                count,
                blocks,
            } => {
                self.answered(peer);
                self.on_blocks(peer, from, count, blocks).await?;
            }
            ChainEvent::Hashes {
                peer,
                from,
                count,
                hashes,
            } => {
                self.answered(peer);
                self.on_hashes(peer, from, count, &hashes).await?;
            }
            ChainEvent::Finalized { peer, header } => {
                self.answered(peer);
                self.on_finalized(peer, header).await;
            }
            ChainEvent::Proof { peer, epoch, proof } => {
                self.answered(peer);
                self.on_proof(peer, epoch, proof).await?;
            }
            ChainEvent::Failed {
                peer,
                error,
                malformed,
            } => {
                self.notify(Notice::PeerDropped {
                    peer,
                    message: format!("ピア {} を外します: {error}", peer.0),
                });
                let penalty = if malformed {
                    Penalty::Ban
                } else {
                    Penalty::None
                };
                self.forget_peer(peer, penalty);
            }
            ChainEvent::PeerAdded { peer } => {
                self.add_peer(peer);
                self.progress(format!(
                    "ピア {} をつなぎました（{} か所）",
                    peer.0,
                    self.peers.len()
                ));
                self.command(peer, PeerCommand::Statistics);
                self.command(peer, PeerCommand::Finalized);
            }
            ChainEvent::PeerLost { peer } => self.forget_peer(peer, Penalty::None),
            ChainEvent::Pushed { block, bytes, from } => {
                self.on_pushed(*block, bytes, from).await?;
            }
            ChainEvent::Wake => self.accept_held().await?,
        }
        Ok(None)
    }

    /// ピアから返事が1つ来た
    fn answered(&mut self, id: PeerId) {
        if let Some(entry) = self.peers.get_mut(&id) {
            entry.pending = entry.pending.saturating_sub(1);
        }
    }

    /// ピアに頼む。頼めなかったら、駆動役が `ChainEvent::Failed` で知らせる
    fn command(&mut self, id: PeerId, command: PeerCommand) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.pending += 1;
        self.actions.push(Action::Command(id, command));
    }

    /// こちらの規則と状態で合わないものを返したピアを外し、わけ `message` を知らせる（[`Penalty::Failure`]）
    fn drop_peer(&mut self, id: PeerId, message: String) {
        self.notify(Notice::PeerDropped { peer: id, message });
        self.forget_peer(id, Penalty::Failure);
    }

    /// ピアを外す（わけはもう知らせてある）
    fn forget_peer(&mut self, id: PeerId, penalty: Penalty) {
        if self.peers.remove(&id).is_some() {
            self.actions.push(Action::Disconnect { peer: id, penalty });
            if self.peers.is_empty() {
                self.notify(Notice::Progress {
                    message: "つないでいるピアがなくなりました".to_owned(),
                    warning: true,
                });
            }
        }
        if self.sync.peer() == Some(id) {
            self.sync = Sync::Idle;
        }
    }

    fn notify(&mut self, notice: Notice) {
        self.actions.push(Action::Notify(notice));
    }

    fn progress(&mut self, message: String) {
        self.notify(Notice::Progress {
            message,
            warning: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_read_like_the_old_log_lines() {
        let finalized = |rows| Notice::Finalized {
            epoch: 4082,
            point: 17,
            height: 5_876_316,
            peer: PeerId(2),
            checkpoints: 0,
            rows,
        };
        assert_eq!(
            finalized(Some(524)).to_string(),
            "エポック 4082 ポイント 17 の証明を確かめました: 高さ 5876316 をファイナライズ（ピア 2、消したチェックポイント 0、消した差分 524 行）"
        );
        assert_eq!(
            finalized(None).to_string(),
            "エポック 4082 ポイント 17 の証明を確かめました: 高さ 5876316 をファイナライズ（ピア 2、消したチェックポイント 0）"
        );
        let tip = |height, byte| Tip {
            height,
            hash: Hash256([byte; 32]),
            importance_hash: Hash256([0; 32]),
        };
        let switched = Notice::Switched {
            common: 10,
            old: tip(11, 0xAA),
            new: tip(12, 0xBB),
            peer: PeerId(1),
        };
        assert_eq!(
            switched.to_string(),
            format!(
                "枝を取り替えました: 分かれ目 10、深さ 1、元の先端 {}（高さ 11）→ 新しい先端 {}（高さ 12）、ピア 1",
                "AA".repeat(32),
                "BB".repeat(32)
            )
        );
        assert!(!switched.is_warning());
        let dropped = Notice::PeerDropped {
            peer: PeerId(3),
            message: "ピア 3 を外します: 切れました".to_owned(),
        };
        assert!(dropped.is_warning());
        assert_eq!(dropped.to_string(), "ピア 3 を外します: 切れました");
    }
}
