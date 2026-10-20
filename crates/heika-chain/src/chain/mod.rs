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

    /// 同期していなければ、スコアが自分より高いピアのうち一番高いものから、続きを取り始める
    fn start_sync(&mut self) {
        if !matches!(self.sync, Sync::Idle) {
            return;
        }
        let score = self.executor.score().unwrap_or(0);
        let best = self
            .peers
            .iter()
            .filter_map(|(id, peer)| peer.statistics.map(|statistics| (*id, statistics)))
            .filter(|(_, statistics)| statistics.score > score)
            .max_by_key(|(_, statistics)| statistics.score);
        let Some((id, statistics)) = best else {
            return;
        };
        if statistics.height <= self.tip.height {
            self.progress(format!(
                "ピア {} はスコアが高いのに、先端が自分（高さ {}）より先にありません。分かれ目を探します",
                id.0, self.tip.height
            ));
            self.compare(id);
            return;
        }
        self.pull(id, &statistics);
    }

    /// 分かれ目を探し始める。確かめた確定の高さから（自分の先端まで）比べる
    fn compare(&mut self, id: PeerId) {
        let from = self.finalized.height.clamp(1, self.tip.height);
        self.compare_from(id, from);
    }

    /// ピアの言う確定が自分の確かめたものより新しく、そのエポックの投票者が決まっていれば、証明を頼む
    async fn on_finalized(&mut self, peer: PeerId, header: FinalizedBlockHeader) {
        if header.round <= self.finalized.round
            || self
                .proof_requested
                .is_some_and(|requested| requested >= header.round)
        {
            return;
        }
        let epoch = header.round.epoch;
        // エポック E の投票者は、E - 1 の最後の高さまで実行すると決まる
        if !matches!(self.store.voters(epoch).await, Ok(Some(_))) {
            return;
        }
        self.proof_requested = Some(header.round);
        self.command(peer, PeerCommand::PullProof { epoch });
    }

    /// 確かめた確定より前のエポックで、まだしまっていないか、途中のポイントのままの証明があれば、古いほうから
    /// 1つ頼む。先端で新しいエポックの証明をしまうと、追いつく段階でしまったものとのあいだが抜けることがある。
    /// 先端の段階を離れていたあいだに終わったエポックは、途中のポイントの証明のままになっている
    async fn backfill_proofs(&mut self) -> Result<(), ChainError> {
        if self.proof_requested.is_some() {
            return Ok(());
        }
        // ブロックを消した高さまでのエポックは、証明を突き合わせるブロックがないので取らない
        let blocks_from = self.store.blocks_from().await?;
        if blocks_from > 0 {
            let epoch = self.parameters.finalization_epoch(blocks_from) + 1;
            self.backfilled = self
                .backfilled
                .max(u32::try_from(epoch).unwrap_or(u32::MAX));
        }
        // エポックの最後の高さを指す証明がしまってあるエポックを飛ばして、最初の抜けを探す
        while self.backfilled < self.finalized.round.epoch && self.settled(self.backfilled).await? {
            self.backfilled += 1;
        }
        let epoch = self.backfilled;
        if epoch >= self.finalized.round.epoch
            || !matches!(self.store.voters(epoch).await, Ok(Some(_)))
        {
            return Ok(());
        }
        let Some(peer) = self.peers.keys().next().copied() else {
            return Ok(());
        };
        self.proof_requested = Some(FinalizationRound { epoch, point: 0 });
        self.command(peer, PeerCommand::PullProof { epoch });
        Ok(())
    }

    /// エポック `epoch` の、エポックの最後の高さを指す証明がしまってあるか
    async fn settled(&self, epoch: u32) -> Result<bool, ChainError> {
        Ok(match self.store.proof(epoch).await? {
            Some(proof) => closes_epoch(
                &proof_header(&proof)?,
                self.config.finalization.voting_set_grouping,
            ),
            None => false,
        })
    }

    /// 証明を、実行して求めた投票者で確かめる。通れば確かめた確定を上げ、証明をしまい、古いチェックポイントを消す
    async fn on_proof(
        &mut self,
        peer: PeerId,
        epoch: u32,
        proof: Option<Vec<u8>>,
    ) -> Result<(), ChainError> {
        self.proof_requested = None;
        let Some(proof) = proof else {
            return Ok(());
        };
        let voters = VotingSet::decode(
            &self
                .store
                .voters(epoch)
                .await?
                .ok_or("証明のエポックの投票者がありません")?,
        )
        .ok_or("投票者が読めません")?;
        let header = match verify_proof(
            &proof,
            epoch,
            &voters,
            &self.config.finalization.proof_parameters(),
        ) {
            Ok(header) => header,
            Err(error) => {
                self.drop_peer(
                    peer,
                    format!("ピア {} の証明が通らないので外します: {error}", peer.0),
                );
                return Ok(());
            }
        };
        if header.round == self.finalized.round && header.hash != self.finalized.hash {
            return Err(format!(
                "エポック {} ポイント {} で、違うブロック（{} と {}）を指す証明がどちらも通りました。止めます",
                header.round.epoch, header.round.point, self.finalized.hash, header.hash
            )
            .into());
        }
        if header.round <= self.finalized.round {
            if header.round.epoch < self.finalized.round.epoch {
                self.store_earlier(peer, epoch, &proof, &header).await?;
            }
            return Ok(());
        }
        if header.height <= self.tip.height
            && block_at(self.store, header.height).await?.hash() != header.hash
        {
            self.progress(format!(
                "確かめた証明が指す高さ {} のブロックが、自分の枝のものと違います。ピア {} と分かれ目を探します",
                header.height, peer.0
            ));
            if matches!(self.sync, Sync::Idle) {
                self.compare(peer);
            }
            return Ok(());
        }
        self.store.put_proof(epoch, &proof).await?;
        self.finalized = header;
        let pruned = self.prune(header.height).await?;
        self.notify(Notice::Finalized {
            epoch,
            point: header.round.point,
            height: header.height,
            peer,
            checkpoints: pruned.checkpoints,
            rows: self.keep.map(|_| pruned.rows),
        });
        Ok(())
    }

    /// 確定 `finalized` から [`CHECKPOINT_EPOCHS`] より下のチェックポイントと、刈り込むなら残す分より下の差分を消す。
    /// 確定より上に分かれ目があって巻き戻すときは、分かれ目以下で一番新しいチェックポイントまで戻るので、確定以下で
    /// 一番新しいチェックポイントより上は消さない
    async fn prune(&self, finalized: u64) -> Result<super::store::Pruned, ChainError> {
        let grouping = self.config.finalization.voting_set_grouping;
        let checkpoints_below = finalized.saturating_sub(CHECKPOINT_EPOCHS * grouping);
        let floor = self
            .store
            .checkpoint_at_or_below(finalized)
            .await?
            .map_or(0, |(height, _)| height);
        let bound = |epochs: u64| finalized.saturating_sub(epochs * grouping).min(floor);
        let history = self.keep.map(|keep| (bound(keep.state), bound(keep.trie)));
        let blocks = self.keep.filter(|keep| keep.history).map(|keep| {
            let through = bound(keep.state).saturating_sub(self.config.blocks_for_restart());
            let epoch =
                u32::try_from(self.parameters.finalization_epoch(through)).unwrap_or(u32::MAX);
            (through, epoch)
        });
        self.store
            .prune(Prune {
                checkpoints_below,
                history,
                blocks,
            })
            .await
    }

    /// 抜けていたか、途中のポイントのままだった前のエポックの証明を、しまったものより先の高さを指し、手元の
    /// ブロックと合えばしまう。返事がどうであれ、そのエポックの取り直しは一度で終える（ピアも途中のポイントの
    /// 証明しか持っていなければ、頼み続けてしまう）
    async fn store_earlier(
        &mut self,
        peer: PeerId,
        epoch: u32,
        proof: &[u8],
        header: &FinalizedBlockHeader,
    ) -> Result<(), ChainError> {
        if epoch == self.backfilled {
            self.backfilled += 1;
        }
        let stored = match self.store.proof(epoch).await? {
            Some(stored) => Some(proof_header(&stored)?.height),
            None => None,
        };
        if stored.is_some_and(|height| height >= header.height)
            || header.height > self.tip.height
            || header.height < self.store.blocks_from().await?
            || block_at(self.store, header.height).await?.hash() != header.hash
        {
            return Ok(());
        }
        self.store.put_proof(epoch, proof).await?;
        self.notify(Notice::EarlierProof {
            epoch,
            height: header.height,
            peer,
            partial: stored.is_some(),
        });
        Ok(())
    }

    fn compare_from(&mut self, id: PeerId, from: u64) {
        self.command(
            id,
            PeerCommand::PullHashes {
                from,
                count: PULL_HASHES,
            },
        );
        self.sync = Sync::Comparing { peer: id, from };
    }

    /// ピアのハッシュを自分のブロックと並べて、最初に違う高さを探す
    async fn on_hashes(
        &mut self,
        peer: PeerId,
        from: u64,
        count: u32,
        hashes: &[[u8; 32]],
    ) -> Result<(), ChainError> {
        if !matches!(self.sync, Sync::Comparing { peer: syncing, from: expected } if syncing == peer && expected == from)
        {
            return Ok(());
        }
        self.sync = Sync::Idle;
        let Some(statistics) = self.peers.get(&peer).and_then(|entry| entry.statistics) else {
            return Ok(());
        };
        if hashes.is_empty() {
            self.drop_peer(
                peer,
                format!("ピア {} がハッシュを返さないので外します", peer.0),
            );
            return Ok(());
        }
        for (index, hash) in hashes.iter().enumerate() {
            let height = from + index as u64;
            if height > self.tip.height {
                // 自分の先端まで同じで、ピアはその先にいる。分かれていない
                self.pull(peer, &statistics);
                return Ok(());
            }
            if block_at(self.store, height).await?.hash().0 != *hash {
                if index == 0 {
                    self.drop_peer(
                        peer,
                        format!(
                            "ピア {} は、比べ始めた高さ {height} より下で分かれているので外します",
                            peer.0
                        ),
                    );
                    return Ok(());
                }
                let common = height - 1;
                self.progress(format!(
                    "ピア {} とは、高さ {common} のあとで分かれています。ピアの枝を取ります",
                    peer.0
                ));
                self.sync = Sync::Forking {
                    peer,
                    common,
                    blocks: Vec::new(),
                };
                self.pull_fork(peer, common + 1, &statistics);
                return Ok(());
            }
        }
        if hashes.len() == count as usize {
            self.compare_from(peer, from + hashes.len() as u64);
        } else {
            self.drop_peer(
                peer,
                format!(
                    "ピア {} の枝は自分の枝の途中で尽きたので、スコアについて嘘をついています。外します",
                    peer.0
                ),
            );
        }
        Ok(())
    }

    /// 枝のブロックを、ピアの先端まで `from` から頼む
    fn pull_fork(&mut self, peer: PeerId, from: u64, statistics: &ChainStatistics) {
        let count = u32::try_from(statistics.height.saturating_sub(from) + 1)
            .unwrap_or(u32::MAX)
            .min(PULL_BLOCKS);
        self.command(peer, PeerCommand::PullBlocks { from, count });
    }

    fn pull(&mut self, id: PeerId, statistics: &ChainStatistics) {
        let count = u32::try_from(statistics.height - self.tip.height)
            .unwrap_or(u32::MAX)
            .min(PULL_BLOCKS);
        self.command(
            id,
            PeerCommand::PullBlocks {
                from: self.tip.height + 1,
                count,
            },
        );
        self.sync = Sync::Extending { peer: id };
    }

    async fn on_blocks(
        &mut self,
        peer: PeerId,
        from: u64,
        count: u32,
        blocks: Vec<(Block, Vec<u8>)>,
    ) -> Result<(), ChainError> {
        if let Sync::Forking {
            peer: syncing,
            common,
            blocks: collected,
        } = &mut self.sync
            && *syncing == peer
            && from == *common + 1 + collected.len() as u64
        {
            let common = *common;
            let received = blocks.len();
            collected.extend(blocks);
            let statistics = self.peers.get(&peer).and_then(|entry| entry.statistics);
            let next = common + 1 + collected.len() as u64;
            if let Some(statistics) = statistics
                && received == count as usize
                && received > 0
                && next <= statistics.height
            {
                self.pull_fork(peer, next, &statistics);
                return Ok(());
            }
            let Sync::Forking { blocks, .. } = std::mem::replace(&mut self.sync, Sync::Idle) else {
                unreachable!("matched above");
            };
            if self.too_far_in_future(peer, &blocks) {
                return Ok(());
            }
            return self.switch(peer, common, blocks).await;
        }
        if !matches!(self.sync, Sync::Extending { peer: syncing } if syncing == peer)
            || from != self.tip.height + 1
        {
            // 前に頼んだものの返事。今の同期には使わない
            return Ok(());
        }
        self.sync = Sync::Idle;
        let Some((first, _)) = blocks.first() else {
            return Ok(());
        };
        if first.previous_block_hash != self.tip.hash {
            self.progress(format!(
                "ピア {} の高さ {} は、自分の先端（{}）につながりません。分かれ目を探します",
                peer.0, first.height, self.tip.hash
            ));
            self.compare(peer);
            return Ok(());
        }
        if self.too_far_in_future(peer, &blocks) {
            return Ok(());
        }
        let received = blocks.len();
        for (block, bytes) in blocks {
            if let Err(error) = self.accept(&block, bytes, false).await {
                if is_invalid(&error) {
                    self.drop_peer(
                        peer,
                        format!(
                            "ピア {} の高さ {} を弾き、外します: {error}",
                            peer.0, block.height
                        ),
                    );
                } else {
                    // こちらの都合なので、ピアは罰さずに外し、間を空けてまた試す
                    self.notify(Notice::PeerDropped {
                        peer,
                        message: format!(
                            "ピア {} の高さ {} を受け入れられないので外します（こちらの都合）: {error}",
                            peer.0, block.height
                        ),
                    });
                    self.forget_peer(peer, Penalty::None);
                }
                return Ok(());
            }
        }
        // 切り詰められて、まだピアの先端に届いていなければ、続きを頼む
        let statistics = self.peers.get(&peer).and_then(|entry| entry.statistics);
        if let Some(statistics) = statistics
            && received < count as usize
            && statistics.height > self.tip.height
        {
            self.pull(peer, &statistics);
        }
        Ok(())
    }

    /// 押し付けられたブロック。先端の次で先端につながり、同期の途中でないときだけ使う。時刻がまだ来ていなければ
    /// （テストネットもメインネットも、ネットワークの時刻は UTC より数秒進んでいる）、来るまで1つだけ持っておく。
    /// ほかのもの（もう持っている高さ、枝の先、先の高さ）は、統計を聞いて追うのに任せる。弾いたら、押し付けた
    /// 鍵 `from` を待ち受けでしばらく受けない
    async fn on_pushed(
        &mut self,
        block: Block,
        bytes: Vec<u8>,
        from: PublicKey,
    ) -> Result<(), ChainError> {
        let height = block.height;
        if height <= self.tip.height {
            let now = self.env.now();
            let late = self
                .accepted_at
                .iter()
                .find(|(accepted, _)| *accepted == height)
                .and_then(|(_, at)| now.duration_since(*at).ok());
            self.pushes.known += 1;
            if let Some(late) = late {
                self.pushes.late_total += late;
                self.pushes.late_count += 1;
            }
            return Ok(());
        }
        if height > self.tip.height + 1 {
            self.pushes.ahead += 1;
            return Ok(());
        }
        if block.previous_block_hash != self.tip.hash {
            self.pushes.unlinked += 1;
            return Ok(());
        }
        // 時刻がまだなら、同期の途中でも持っておく（受け入れるのは、時刻が来て同期を終えてから）
        if let Some(due) = self.not_yet(&block) {
            // 同じ高さのものをもう持っていれば、先に届いた方を残す
            if self.held.is_some() {
                self.pushes.future += 1;
            } else {
                self.pushes.held += 1;
                self.held = Some((block, bytes, from));
                self.actions.push(Action::WakeAt(due));
            }
            return Ok(());
        }
        if !matches!(self.sync, Sync::Idle) {
            self.pushes.syncing += 1;
            return Ok(());
        }
        match self.accept(&block, bytes, true).await {
            Ok(()) => self.pushes.used += 1,
            Err(error) => {
                self.pushes.rejected += 1;
                self.reject_push(height, from, &error);
            }
        }
        Ok(())
    }

    /// 自分の時計（UTC）で、`block` の時刻がまだ来ていない（`maxBlockFutureTime` を引いても先にある）なら、
    /// 受け入れてよくなる時刻
    fn not_yet(&self, block: &Block) -> Option<SystemTime> {
        let due = self.due_at(block.timestamp);
        (due > self.env.now()).then_some(due)
    }

    /// 自分の時計（UTC）の、Nemesis からのミリ秒
    fn network_now(&self) -> u64 {
        let elapsed = self
            .env
            .now()
            .duration_since(self.parameters.epoch())
            .unwrap_or_default()
            .as_millis();
        u64::try_from(elapsed).unwrap_or(u64::MAX)
    }

    /// 時刻 `timestamp` のブロックを、自分の時計（UTC）で受け入れてよくなる時刻（`maxBlockFutureTime` だけ前）
    fn due_at(&self, timestamp: u64) -> SystemTime {
        self.parameters.epoch()
            + Duration::from_millis(timestamp.saturating_sub(self.config.max_block_future_time))
    }

    /// ハーベストするなら、先端が変わったときに当たりの一番早い時刻を求め直し、その時刻のブロックを自分の時計
    /// （UTC）で受け入れてよくなったら作る（`docs/archive/tip.md` の「ハーベストするときの時刻」）。同期の途中は待つ
    async fn harvest(&mut self) -> Result<(), ChainError> {
        if self.harvesters.is_empty() || !matches!(self.sync, Sync::Idle) {
            return Ok(());
        }
        // ピアの言う高さを聞いていて、どのピアも自分より先にいないときだけ作る。始めたばかりで統計がまだなら
        // 待つ（でないと、追いつく前の古い先端の上に、自分だけの枝を作ってしまう）
        let heard: Vec<u64> = self
            .peers
            .values()
            .filter_map(|peer| peer.statistics.map(|statistics| statistics.height))
            .collect();
        if heard.is_empty() || heard.iter().any(|&height| height > self.tip.height) {
            return Ok(());
        }
        let harvesters = Arc::clone(&self.harvesters);
        self.harvest_with(&harvesters).await
    }

    async fn harvest_with(
        &mut self,
        harvesters: &[(PrivateKey, PrivateKey)],
    ) -> Result<(), ChainError> {
        if self
            .planned
            .as_ref()
            .is_none_or(|planned| planned.parent != self.tip.hash)
        {
            let slot = self.plan_harvest(harvesters)?;
            self.planned = Some(Planned {
                parent: self.tip.hash,
                slot,
            });
            if let Some((timestamp, _)) = slot {
                let seconds = (timestamp - self.parent.timestamp) / 1000;
                if seconds <= HARVEST_ANNOUNCE {
                    self.progress(format!(
                        "高さ {} の当たりは親から {seconds} 秒です",
                        self.tip.height + 1
                    ));
                }
                let due = self.due_at(timestamp);
                self.actions.push(Action::WakeAt(due));
            }
        }
        let Some((timestamp, harvester)) = self.planned.as_ref().and_then(|planned| planned.slot)
        else {
            return Ok(());
        };
        if self.due_at(timestamp) > self.env.now() {
            return Ok(());
        }
        // 作るのは1回だけ。通らなくても、次の先端で求め直す
        if let Some(planned) = &mut self.planned {
            planned.slot = None;
        }
        // 当たりの時刻が今より前なら（親が遅れて届いた、先端が古い）、今の時刻にする。どちらでも当たりで、
        // catapult も試す時刻（今）を付ける
        let timestamp = timestamp.max(self.network_now());
        let (signing, vrf_key) = &harvesters[harvester];
        self.produce_and_accept(timestamp, signing, vrf_key).await
    }

    /// 先端の上で作るブロックの親まわり（[`produce::Parent`] に要るもの）の写し
    fn harvest_parent(&self) -> HarvestParent {
        HarvestParent {
            block: self.parent.clone(),
            recent: self.statistics.iter().copied().collect(),
            generation_hash: self.generation_hash,
            importance_hash: self.tip.importance_hash,
        }
    }

    /// 先端の上で、`harvesters` のうち当たりが一番早い時刻と鍵の番号。[`HARVEST_HORIZON`] までになければ `None`。
    /// 求められない鍵は、わけが変わったときだけ知らせる
    fn plan_harvest(
        &mut self,
        harvesters: &[(PrivateKey, PrivateKey)],
    ) -> Result<Option<(u64, usize)>, ChainError> {
        let parent = self.harvest_parent();
        let context = parent.context();
        let until = parent.block.timestamp + HARVEST_HORIZON;
        let mut best: Option<(u64, usize)> = None;
        for (index, (signing, vrf_key)) in harvesters.iter().enumerate() {
            // アカウントを全部はメモリに持たないなら、引いたアカウントを読んで求め直す
            let mut retries = 0;
            let found = loop {
                let found = produce::earliest_hit(
                    &self.executor,
                    self.parameters,
                    &context,
                    signing,
                    vrf_key,
                    until,
                )
                .map_err(ChainError::from);
                let missed = self.executor.take_missed();
                if missed.is_empty() {
                    break found;
                }
                if retries == MAX_RETRIES {
                    break Err(format!(
                        "{MAX_RETRIES} 回読み足しても、読んでいない状態が {} 個あります",
                        missed.len()
                    )
                    .into());
                }
                retries += 1;
                self.executor.load_wanted(self.store, &missed)?;
            };
            match found {
                Ok(Some(timestamp)) => {
                    if best.is_none_or(|(earliest, _)| timestamp < earliest) {
                        best = Some((timestamp, index));
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let message = format!("鍵 {index} でハーベストできません: {error}");
                    if self.harvest_warning.as_ref() != Some(&message) {
                        self.notify(Notice::Progress {
                            message: message.clone(),
                            warning: true,
                        });
                        self.harvest_warning = Some(message);
                    }
                }
            }
        }
        Ok(best)
    }

    /// 先端の上に、時刻 `timestamp` のトランザクションのないブロックを作って先端に足し、つないでいるピアに配る。
    /// 作ったときの状態をそのまましまう（当て直さない）。作れなければ知らせ、当てかけていたら状態を戻す。しまえ
    /// なければ（DB の誤り）エラーを返す
    async fn produce_and_accept(
        &mut self,
        timestamp: u64,
        signing: &PrivateKey,
        vrf_key: &PrivateKey,
    ) -> Result<(), ChainError> {
        let parent_timestamp = self.parent.timestamp;
        let height = self.tip.height + 1;
        let mut touched = false;
        let produced = self
            .try_produce(timestamp, signing, vrf_key, &mut touched)
            .await;
        let (block, tip, statement) = match produced {
            Ok(produced) => produced,
            Err(error) => {
                self.notify(Notice::Progress {
                    message: format!("高さ {height} のブロックを作れませんでした: {error}"),
                    warning: true,
                });
                if touched {
                    self.reload_executor().await?;
                }
                return Ok(());
            }
        };
        let bytes = block.as_bytes().to_vec();
        self.commit(&block, &bytes, statement).await?;
        self.advance(&block, tip, block.generation_hash());
        self.notify(Notice::Produced {
            height: block.height,
            hash: tip.hash,
            seconds: (block.timestamp - parent_timestamp) / 1000,
            peers: self.peers.len(),
        });
        // catapult は押し付けられたブロックを中継しないので、つないでいるピアの全部に配る。返事はない
        let bytes = Arc::new(bytes);
        for &id in self.peers.keys() {
            self.actions
                .push(Action::Command(id, PeerCommand::Push(Arc::clone(&bytes))));
        }
        Ok(())
    }

    /// [`Chain::produce_and_accept`] の、作って確かめるまで。状態に当て始めたら `touched` を立てる。返すのは、
    /// 作ったブロック、それを足した先端、ステートメント
    async fn try_produce(
        &mut self,
        timestamp: u64,
        signing: &PrivateKey,
        vrf_key: &PrivateKey,
        touched: &mut bool,
    ) -> Result<(Block, Tip, BlockStatement), ChainError> {
        let parent = self.harvest_parent();
        let context = parent.context();
        let decisions = produce::Decisions {
            timestamp,
            transactions: Vec::new(),
            beneficiary: Address::from_public_key(
                &PublicKey::from_private_key(signing),
                self.parameters.identifier,
            ),
            fee_multiplier: 0,
        };
        let draft = produce::draft(self.parameters, &context, signing, vrf_key, &decisions)?;
        // アカウントを全部はメモリに持たないなら、要りそうなものを先に読み、足りなければ戻して読み足す
        if self.executor.is_partial() {
            let wanted = self.executor.wanted_for(&draft);
            self.executor.load_wanted(self.store, &wanted)?;
        }
        let mut retries = 0;
        loop {
            *touched = true;
            let produced = produce::produce_with_statement(
                &mut self.executor,
                self.parameters,
                &context,
                signing,
                vrf_key,
                &decisions,
            );
            let missed = self.executor.take_missed();
            if missed.is_empty() {
                let (block, statement) = produced?;
                let tip = verify_link(Some(self.tip), &block)?;
                return Ok((block, tip, statement));
            }
            if retries == MAX_RETRIES {
                return Err(format!(
                    "{MAX_RETRIES} 回作り直しても、読んでいない状態が {} 個あります",
                    missed.len()
                )
                .into());
            }
            retries += 1;
            self.undo_and_load(&draft, missed).await?;
        }
    }

    /// 当てかけた `block` を、先端のチェックポイントまで戻し、読んでいなかった `missed` を読み足す（アカウントを
    /// 全部はメモリに持たないとき）
    async fn undo_and_load(&mut self, block: &Block, missed: Wanted) -> Result<(), ChainError> {
        let meta = match self.store.checkpoint_at_or_below(self.tip.height).await? {
            Some((height, meta)) if height == self.tip.height => meta,
            _ => return Err("当て直すのに、先端のチェックポイントがありません".into()),
        };
        self.executor.undo_attempt(self.store, &meta, block)?;
        self.executor.load_wanted(self.store, &missed)?;
        Ok(())
    }

    /// 当てる途中で止まった状態を捨て、最後にコミットしたところから読み直す
    async fn reload_executor(&mut self) -> Result<(), ChainError> {
        let loaded = load_from(
            self.store,
            self.config.clone(),
            self.parameters,
            self.executor.is_partial(),
        )
        .await?;
        self.executor = loaded.executor;
        Ok(())
    }

    /// 持っている未来のブロックが、まだ先端の次につながり、時刻が来ていれば受け入れる。つながらなくなって
    /// いれば捨てる。時刻がまだなら、もう一度起こしてもらう
    async fn accept_held(&mut self) -> Result<(), ChainError> {
        let Some((block, _, _)) = &self.held else {
            return Ok(());
        };
        if block.height != self.tip.height + 1 || block.previous_block_hash != self.tip.hash {
            self.held = None;
            return Ok(());
        }
        if let Some(due) = self.not_yet(block) {
            self.actions.push(Action::WakeAt(due));
            return Ok(());
        }
        // 同期の途中なら、次の Tick で試す
        if !matches!(self.sync, Sync::Idle) {
            return Ok(());
        }
        let (block, bytes, from) = self.held.take().expect("checked above");
        match self.accept(&block, bytes, true).await {
            Ok(()) => self.pushes.used_late += 1,
            Err(error) => {
                self.pushes.rejected_late += 1;
                self.reject_push(block.height, from, &error);
            }
        }
        Ok(())
    }

    /// 押し付けられた高さ `height` を弾いたことを知らせる。ブロックが規則に合わなければ、押し付けた鍵 `from` の
    /// 接続を切る（締め出さない）。先端につながるブロックしか試さないので、同じ規則のノードのものなら通る
    fn reject_push(&mut self, height: u64, from: PublicKey, error: &ChainError) {
        if !is_invalid(error) {
            self.notify(Notice::Progress {
                message: format!(
                    "押し付けられた高さ {height} を受け入れられませんでした（こちらの都合）: {error}"
                ),
                warning: true,
            });
            return;
        }
        self.notify(Notice::Progress {
            message: format!(
                "押し付けられた高さ {height} を弾き、鍵 {from} の接続を切ります: {error}"
            ),
            warning: true,
        });
        self.actions.push(Action::RejectPush(from));
    }

    /// 押し付けの数を、前に知らせてから 1 分たっていれば知らせて 0 に戻す
    fn report_pushes(&mut self) {
        let now = self.env.now();
        let due = now
            .duration_since(self.pushes.since.unwrap_or(now))
            .is_ok_and(|elapsed| elapsed >= PUSH_REPORT);
        if self.pushes.since.is_none() {
            self.pushes.since = Some(now);
        }
        if !due {
            return;
        }
        let counts = std::mem::take(&mut self.pushes);
        self.pushes.since = Some(now);
        if counts.total() > 0 {
            self.progress(counts.to_string());
        }
    }

    /// 受け取った枝の最後のブロックの時刻が、今のネットワーク時刻 + `maxBlockFutureTime` より先か（catapult の
    /// `BlockchainCheckConsumer`）。先なら枝ごと使わない。時計の合っているピアなら、少し待てば通るので外さない
    fn too_far_in_future(&mut self, peer: PeerId, blocks: &[(Block, Vec<u8>)]) -> bool {
        let Some((last, _)) = blocks.last() else {
            return false;
        };
        let now = self
            .parameters
            .timestamp_at(self.env.now())
            .map_or(0, |now| now.0);
        let too_far = last.timestamp > now.saturating_add(self.config.max_block_future_time);
        if too_far {
            let (height, ahead) = (last.height, last.timestamp - now);
            self.notify(Notice::TooFarInFuture {
                peer,
                height,
                ahead,
            });
        }
        too_far
    }

    /// 分かれ目 `common` から先を、ピアの枝 `blocks` に取り替える。通らないか、スコアが元より高くならなければ、
    /// 元の枝に戻してピアを外す
    async fn switch(
        &mut self,
        peer: PeerId,
        common: u64,
        blocks: Vec<(Block, Vec<u8>)>,
    ) -> Result<(), ChainError> {
        let (old_tip, old_score) = (self.tip, self.executor.score().unwrap_or(0));
        let mut originals = Vec::new();
        for height in common + 1..=old_tip.height {
            originals.push(
                self.store
                    .block(height)
                    .await?
                    .ok_or("元の枝のブロックがありません")?,
            );
        }
        // 外れる元の枝は、巻き戻しと同じコミットで孤立ブロックの表に残す。元の枝に戻したら、当て直すときに消える
        let orphans = originals
            .iter()
            .map(|bytes| {
                let block = Block::from_bytes(bytes)?;
                Ok((block.height, block.hash().0, bytes.as_slice()))
            })
            .collect::<Result<Vec<_>, ChainError>>()?;
        self.rewind(common, &orphans).await?;
        let mut failure = None;
        // 枝が正しくないか、スコアが高くないなら罰する。こちらの都合で取り替えられなかったなら罰さない
        let mut penalty = Penalty::Failure;
        for (block, bytes) in blocks {
            if let Err(error) = self.accept(&block, bytes, false).await {
                penalty = if is_invalid(&error) {
                    Penalty::Failure
                } else {
                    Penalty::None
                };
                failure = Some(format!("高さ {}: {error}", block.height));
                break;
            }
        }
        let new_score = self.executor.score().unwrap_or(0);
        if failure.is_none() && new_score > old_score {
            self.notify(Notice::Switched {
                common,
                old: old_tip,
                new: self.tip,
                peer,
            });
            return Ok(());
        }
        self.notify(Notice::PeerDropped {
            peer,
            message: format!(
                "ピア {} の枝に取り替えられないので、元の枝に戻してピアを外します: {}",
                peer.0,
                failure.unwrap_or_else(|| format!(
                    "スコアが {new_score} で、元の {old_score} より高くない"
                ))
            ),
        });
        self.rewind(common, &[]).await?;
        for bytes in originals {
            let block = Block::from_bytes(&bytes)?;
            self.accept(&block, bytes, false).await?;
        }
        self.forget_peer(peer, penalty);
        Ok(())
    }

    /// DB とメモリの状態を高さ `common` まで巻き戻す。DB の `common` より上のブロックは消え、`orphans` は
    /// 同じコミットで孤立ブロックの表に入る。チェックポイントが `common` より下なら、そこから `common` までの
    /// しまったブロックを当て直す
    async fn rewind(
        &mut self,
        common: u64,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<(), ChainError> {
        let (checkpoint, meta) = self
            .store
            .checkpoint_at_or_below(common)
            .await?
            .ok_or("巻き戻せるチェックポイントがありません")?;
        let rows = self.store.changes_above(checkpoint).await?;
        let mut kept = Vec::new();
        for height in checkpoint + 1..=common {
            kept.push(
                self.store
                    .block(height)
                    .await?
                    .ok_or("当て直すブロックがありません")?,
            );
        }
        let grouping = self.config.finalization.voting_set_grouping;
        let voters_from = u32::try_from(common / grouping + 3)?;
        self.store.rollback(common, voters_from, orphans).await?;
        self.executor.revert(rows, &meta)?;
        let lifetime = self
            .config
            .max_transaction_lifetime
            .max(self.config.max_bonded_transaction_lifetime);
        let (parent, statistics, tip) =
            context(self.store, &mut self.executor, self.parameters, lifetime).await?;
        if self.executor.state_hash() != parent.state_hash {
            // 戻せなかったら、DB から丸ごと読み直す（遅いが確か）
            self.notify(Notice::Progress {
                message: "巻き戻した根が合わないので、DB から読み直します".to_owned(),
                warning: true,
            });
            let loaded = load_from(
                self.store,
                self.config.clone(),
                self.parameters,
                self.executor.is_partial(),
            )
            .await?;
            self.executor = loaded.executor;
        }
        self.generation_hash = parent.generation_hash();
        self.parent = parent;
        self.statistics = statistics;
        self.tip = tip;
        for bytes in kept {
            let block = Block::from_bytes(&bytes)?;
            self.accept(&block, bytes, false).await?;
        }
        Ok(())
    }

    /// 次のブロックを確かめて当て、DB に書いてコミットする。当てる途中で弾いたら、DB から状態を読み直す
    /// `pushed` なら、接続してきたピアが押し付けたもの（知らせに書くだけ）
    async fn accept(
        &mut self,
        block: &Block,
        bytes: Vec<u8>,
        pushed: bool,
    ) -> Result<(), ChainError> {
        let tip = verify_link(Some(self.tip), block).map_err(invalid)?;
        if block.height == self.finalized.height && tip.hash != self.finalized.hash {
            return Err(invalid("ファイナライズされたブロックと違います"));
        }
        let expected = difficulty(self.statistics.make_contiguous(), self.parameters);
        if block.difficulty != expected {
            return Err(invalid(format!(
                "難易度が {} で、直前のブロックから求めた {expected} と合いません",
                block.difficulty
            )));
        }
        // アカウントを全部はメモリに持たないなら、要りそうなものを先に読む。足りなければ記録されるので、
        // 読んでから確かめ直すか、当てたものを戻して当て直す
        if self.executor.is_partial() {
            let wanted = self.executor.wanted_for(block);
            self.executor.load_wanted(self.store, &wanted)?;
        }
        let generation_hash = loop {
            let checked = self.executor.check_harvester(
                &self.parent,
                &self.generation_hash,
                block,
                self.parameters,
            );
            let missed = self.executor.take_missed();
            if missed.is_empty() {
                break checked.map_err(invalid)?;
            }
            self.executor.load_wanted(self.store, &missed)?;
        };
        let mut retries = 0;
        loop {
            let error = match self.apply(block, bytes.clone()).await {
                Ok(()) => break,
                Err(error) => error,
            };
            match error.downcast::<Missed>() {
                Ok(missed) if retries < MAX_RETRIES => {
                    retries += 1;
                    self.undo_and_load(block, missed.0).await?;
                }
                result => {
                    let error: ChainError = match result {
                        Ok(missed) => format!(
                            "{MAX_RETRIES} 回当て直しても、読んでいない状態が {} 個あります",
                            missed.0.len()
                        )
                        .into(),
                        Err(error) => error,
                    };
                    // 状態は途中まで当たっているので、最後にコミットしたところから読み直す
                    self.reload_executor().await?;
                    return Err(error);
                }
            }
        }
        if retries > 0 {
            self.progress(format!(
                "高さ {} は、読んでいない状態があったので {retries} 回当て直しました",
                block.height
            ));
        }
        self.advance(block, tip, generation_hash);
        self.notify(Notice::Accepted {
            height: block.height,
            transactions: block.transactions().count(),
            hash: tip.hash,
            pushed,
        });
        Ok(())
    }

    /// コミットしたブロック `block` を先端にする
    fn advance(&mut self, block: &Block, tip: Tip, generation_hash: GenerationHash) {
        // 要るものだけを読む形なら、読み込んだものを手放す。ブロックをまたいで持つのは読み口のキャッシュ
        self.executor.release_loaded();
        self.parent = block.clone();
        self.generation_hash = generation_hash;
        self.tip = tip;
        self.statistics.push_back(BlockStatistic::from(block));
        if self.statistics.len() > self.parameters.max_difficulty_blocks {
            self.statistics.pop_front();
        }
        self.accepted_at.push_back((block.height, self.env.now()));
        if self.accepted_at.len() > 16 {
            self.accepted_at.pop_front();
        }
    }

    async fn apply(&mut self, block: &Block, bytes: Vec<u8>) -> Result<(), ChainError> {
        let applied = self.executor.apply(block);
        let state_hash = self.executor.state_hash();
        // まだ読んでいないアカウントを引いていたら、結果は使えない（コミットせずに当て直す）
        let missed = self.executor.take_missed();
        if !missed.is_empty() {
            return Err(Box::new(Missed(missed)));
        }
        applied.map_err(invalid)?;
        if state_hash != block.state_hash {
            return Err(invalid("StateHash が合いません"));
        }
        let statement = self.executor.take_statement();
        if statement.merkle_hash() != block.receipts_hash {
            return Err(invalid("ReceiptsHash が合いません"));
        }
        self.commit(block, &bytes, statement).await
    }

    /// 当てたあとの状態の変化を、ブロック `block`（バイト列 `bytes`）とステートメントと一緒に DB に書いてコミットする
    async fn commit(
        &mut self,
        block: &Block,
        bytes: &[u8],
        statement: BlockStatement,
    ) -> Result<(), ChainError> {
        let height = block.height;
        let changes = self.executor.take_changes();
        let state: Vec<(Vec<u8>, Option<Vec<u8>>)> = changes
            .puts
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .chain(changes.deletes.into_iter().map(|key| (key, None)))
            .collect();
        let nodes = self.executor.take_node_changes();
        // エポック E の投票者は、E - 1 の最後の高さ（高さ 1 か、区切りの倍数）の状態で決まる
        let grouping = self.config.finalization.voting_set_grouping;
        let next_epoch = if height == 1 {
            Some(2)
        } else if height.is_multiple_of(grouping) {
            u32::try_from(height / grouping + 2).ok()
        } else {
            None
        };
        let voters = next_epoch.map(|epoch| (epoch, self.executor.voting_set(epoch).encode()));
        self.store
            .commit_block(BlockWrite {
                height,
                hash: block.hash().0,
                bytes,
                state,
                nodes,
                statement: statement.to_bytes(),
                voters,
                meta: self.executor.encode_meta(),
            })
            .await
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
