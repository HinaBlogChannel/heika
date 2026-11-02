//! 取ってきたブロックを、Nemesis から順に確かめて実行し、まとめて書く。スレッドを使わないので、ブラウザ（wasm）でも動く。
//!
//! heika-node の追いつく段階（`catch_up`）と同じ確かめを、1つのスレッドで順にする。取る、実行する、書くを重ねない
//! ので遅いが、どこからブロックを取るか（P2P、REST、手元のファイル）は呼ぶ側が決められる。
//!
//! 確かめること（どれも、実行した状態から求めた値とブロックが合うか）:
//! - 前後に依らないところ（[`verify_alone`]）: 署名、TransactionsHash、トランザクションの署名と連署
//! - つながり（[`verify_link`]）と、高さ 1 が決めた Nemesis であること
//! - 難易度、ブロックを出した人の当たりと VRF の証明
//! - 当てたあとの StateHash と ReceiptsHash
//!
//! [`Replay::push`] で当てたものは、[`Replay::commit`] するまで DB に残らない。途中で弾いたら、その [`Replay`] は
//! 捨てて、[`Replay::open`] で最後のコミットから開き直す。
//!
//! 残し方（[`Keep`]）を渡せば、ノードの追いつく段階と同じく刈り込みながら進む。目標の高さ（[`Replay::set_target`]）から
//! 残す分を引いたところより下では状態と木の差分を書かず、コミットのたびに、古いブロック、ステートメント、
//! チェックポイント、差分を少しずつ（1回 2 秒まで）消す。

use std::collections::VecDeque;
use std::fmt;

use heika_block::Block;
use heika_block::scoring::{BlockStatistic, difficulty};
use heika_chain::chain::Keep;
use heika_chain::store::{ChainStore, EXECUTOR_META, now_or_never};
use heika_chain::verify::{Tip, verify_alone, verify_link};
use heika_core::hash::Hash256;
use heika_core::network::NetworkParameters;
use heika_core::vrf;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;

use crate::{Batch, Db, DbError};

/// [`Replay`] が止まったわけ
#[derive(Debug)]
pub enum ReplayError {
    /// 高さ `height` のブロックを確かめて弾いた。取ってきたところが正しくないか、組み直しを間違えた
    Invalid { height: u64, reason: String },
    /// DB か実行器の誤り。ブロックのせいではない
    Failed(String),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { height, reason } => write!(f, "高さ {height}: {reason}"),
            Self::Failed(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<DbError> for ReplayError {
    fn from(error: DbError) -> Self {
        Self::Failed(error.to_string())
    }
}

fn failed(error: impl fmt::Display) -> ReplayError {
    ReplayError::Failed(error.to_string())
}

/// 順に実行していくもの。DB の実行した高さから始まる
pub struct Replay<'a> {
    db: &'a Db,
    parameters: &'static NetworkParameters,
    nemesis: Hash256,
    executor: Executor,
    /// 実行した最後のブロック。まだ何も実行していなければ `None`
    parent: Option<Block>,
    tip: Option<Tip>,
    /// 難易度を求める、直前のブロックの統計（古い順、`maxDifficultyBlocks` まで）
    statistics: VecDeque<BlockStatistic>,
    /// 書きかけ。最初に当てたときに作り、コミットで閉じる
    batch: Option<Batch>,
    /// 最後にコミットした高さ
    committed: u64,
    config: ChainConfig,
    /// 刈り込むなら、残す分。`None` なら全部残す（アーカイブ）
    keep: Option<Keep>,
    /// 状態と木のそれぞれ、この高さ以下では差分を書かない
    quiet_through: [Option<u64>; 2],
    /// この高さ以下ではステートメントを書かない
    statements_through: Option<u64>,
    /// [`Replay::set_target`] で知らされた目標
    target: u64,
}

impl<'a> Replay<'a> {
    /// `db` の、最後にコミットした高さから続ける。空の DB なら、次は Nemesis（ハッシュが `nemesis` のもの）
    pub fn open(
        db: &'a Db,
        config: ChainConfig,
        parameters: &'static NetworkParameters,
        nemesis: Hash256,
        keep: Option<Keep>,
    ) -> Result<Self, ReplayError> {
        let seed = parameters.generation_hash_seed;
        let lifetime = config
            .max_transaction_lifetime
            .max(config.max_bonded_transaction_lifetime);
        let mut executor = match db.meta(EXECUTOR_META)? {
            Some(meta) => Executor::restore(
                config.clone(),
                parameters.identifier,
                seed,
                db.state_rows()?,
                &meta,
            )
            .map_err(failed)?,
            None => Executor::new(config.clone(), parameters.identifier, seed),
        };
        let start = executor.height();
        let stored = |height: u64| -> Result<Block, ReplayError> {
            let bytes = db
                .block(height)?
                .ok_or_else(|| failed(format!("実行した高さ {height} のブロックがありません")))?;
            Block::from_bytes(&bytes).map_err(failed)
        };

        // 同じトランザクションの二度入れを弾くハッシュはしまっていないので、期限が残っているかもしれない直前の
        // ブロックから覚え直す
        let mut recent: Vec<Block> = Vec::new();
        for height in (1..=start).rev() {
            let block = stored(height)?;
            if recent
                .first()
                .is_some_and(|last| block.timestamp + lifetime < last.timestamp)
            {
                break;
            }
            recent.push(block);
        }
        for block in recent.iter().rev() {
            executor.remember_transactions(block).map_err(failed)?;
        }

        let window = parameters.max_difficulty_blocks;
        let mut statistics = VecDeque::with_capacity(window);
        for height in start.saturating_sub(window as u64 - 1).max(1)..=start {
            statistics.push_back(BlockStatistic::from(&stored(height)?));
        }
        let parent = (start > 0).then(|| stored(start)).transpose()?;
        let tip = match &parent {
            None => None,
            Some(block) => {
                let grouping = parameters.importance_grouping;
                let importance_height = (block.height / grouping * grouping).max(1);
                let importance_hash = if importance_height == block.height {
                    block.hash()
                } else {
                    stored(importance_height)?.hash()
                };
                Some(Tip {
                    height: block.height,
                    hash: block.hash(),
                    importance_hash,
                })
            }
        };

        // 木を戻す。しまった木のノードがあれば、そこから戻して根を確かめる。まだ残していなければ、今の木を全部書いて
        // から残し始める
        let mut batch = db.batch()?;
        batch.start_history(start)?;
        let trie_started = db.trie_started()?;
        if trie_started && start > 0 {
            executor.restore_trees(db.trie_nodes()?).map_err(failed)?;
            let expected = parent.as_ref().map(|block| block.state_hash);
            if Some(executor.state_hash()) != expected {
                executor.rebuild_trees();
            }
        }
        executor.roots();
        if trie_started {
            executor.forget_node_changes();
        } else {
            batch.start_trie(start)?;
            let nodes = executor
                .all_nodes()
                .ok_or_else(|| failed("全部のノードを持たない木から、ノードを全部は書けません"))?;
            batch.set_trie_at(start, nodes.iter().map(|(key, node)| (key, Some(node))))?;
        }
        batch.commit()?;

        Ok(Self {
            db,
            parameters,
            nemesis,
            executor,
            parent,
            tip,
            statistics,
            batch: None,
            committed: start,
            config,
            keep,
            quiet_through: [None; 2],
            statements_through: None,
            target: 0,
        })
    }

    /// これから実行する目標の高さ（ふつうは確定した高さ）を知らせる。刈り込むなら、目標から残す分を引いたところより
    /// 下では差分を書かないようにする。そこまでの差分は消す扱いにする（DB の差分の始まりを上げる）ので、目標は確定した
    /// 高さより上にしない。書きかけがあれば、次のコミットのあとで当てる（redb は書く側が1つだけなので）
    pub fn set_target(&mut self, target: u64) -> Result<(), ReplayError> {
        self.target = self.target.max(target);
        if self.batch.is_none() {
            self.apply_target()?;
        }
        Ok(())
    }

    /// [`Replay::set_target`] の目標から、差分を書かない高さを決めて当てる。書きかけがないときに呼ぶ
    fn apply_target(&mut self) -> Result<(), ReplayError> {
        let Some(keep) = self.keep else {
            return Ok(());
        };
        let grouping = self.parameters.voting_set_grouping;
        let state = self.target.saturating_sub(keep.state * grouping);
        let trie = self.target.saturating_sub(keep.trie * grouping);
        if self.quiet_through == [Some(state), Some(trie)] {
            return Ok(());
        }
        // 差分の始まりを上げてから、それより下を書かないようにする。残りの差分を消すのは commit のたびに少しずつ
        self.db.prune_state_history(state, |_| false)?;
        self.db.prune_trie_history(trie, |_| false)?;
        self.quiet_through = [Some(state), Some(trie)];
        if keep.history {
            self.statements_through = Some(state.saturating_sub(self.config.blocks_for_restart()));
        }
        Ok(())
    }

    /// 実行した高さ（コミットしていない分も含む）
    pub fn height(&self) -> u64 {
        self.executor.height()
    }

    /// 最後にコミットした高さ
    pub fn committed(&self) -> u64 {
        self.committed
    }

    /// 実行した最後のブロックの StateHash。まだ何も実行していなければ `None`
    pub fn state_hash(&self) -> Option<Hash256> {
        self.parent.as_ref().map(|block| block.state_hash)
    }

    /// 次の高さのブロック `bytes` を確かめて当てる。コミットするまで DB には残らない。
    ///
    /// 弾いたら、この `Replay` は途中まで当たった状態なので捨て、[`Replay::open`] で開き直す
    pub fn push(&mut self, bytes: Vec<u8>) -> Result<(), ReplayError> {
        let height = self.executor.height() + 1;
        let invalid = |reason: String| ReplayError::Invalid { height, reason };
        let block = Block::from_bytes(&bytes).map_err(|error| invalid(error.to_string()))?;
        if block.height != height {
            return Err(invalid(format!("高さが {} です", block.height)));
        }
        verify_alone(self.parameters, &block).map_err(|error| invalid(error.to_string()))?;
        let tip = verify_link(self.tip, &block).map_err(|error| invalid(error.to_string()))?;
        if height == 1 && tip.hash != self.nemesis {
            return Err(invalid("決めた Nemesis と違います".into()));
        }

        // 実行する前に、1つ前のブロックのあとの状態で、難易度とブロックを出した人を確かめる。Nemesis は信じる
        if let Some(parent) = &self.parent {
            let expected = difficulty(self.statistics.make_contiguous(), self.parameters);
            if block.difficulty != expected {
                return Err(invalid(format!(
                    "難易度が {} で、直前のブロックから求めた {expected} と合いません",
                    block.difficulty
                )));
            }
            let key = self
                .executor
                .check_hit(parent, &block, self.parameters)
                .map_err(|error| invalid(error.to_string()))?;
            let alpha = parent.generation_hash();
            if vrf::verify(&key, &alpha.0, &block.generation_hash_proof).is_none() {
                return Err(invalid("ブロックを出した人: VRF の証明が通りません".into()));
            }
        }

        self.executor
            .apply(&block)
            .map_err(|error| invalid(error.to_string()))?;
        let state_hash = self.executor.state_hash();
        if state_hash != block.state_hash {
            return Err(invalid(format!(
                "StateHash が {state_hash} で、ブロックの {} と合いません",
                block.state_hash
            )));
        }
        let statement = self.executor.take_statement();
        if statement.merkle_hash() != block.receipts_hash {
            return Err(invalid("ReceiptsHash が合いません".into()));
        }

        let changes = self.executor.take_changes();
        let state = changes
            .puts
            .into_iter()
            .map(|(key, value)| (key, Some(value)))
            .chain(changes.deletes.into_iter().map(|key| (key, None)));
        let nodes = self.executor.take_node_changes();
        let grouping = self.parameters.voting_set_grouping;
        // エポック E の投票者は、E - 1 の最後の高さ（高さ 1 か、区切りの倍数）の状態で決まる
        let next_epoch = if height == 1 {
            Some(2)
        } else if height.is_multiple_of(grouping) {
            u32::try_from(height / grouping + 2).ok()
        } else {
            None
        };
        let batch = match &mut self.batch {
            Some(batch) => batch,
            None => {
                let mut batch = self.db.batch()?;
                batch.quiet_through = self.quiet_through;
                self.batch.insert(batch)
            }
        };
        batch.put_block(height, &bytes)?;
        batch.set_state_at(height, state)?;
        batch.set_trie_at(height, nodes)?;
        if self
            .statements_through
            .is_none_or(|through| height > through)
        {
            batch.put_statement(height, &statement.to_bytes())?;
        }
        if let Some(epoch) = next_epoch {
            batch.put_voters(epoch, &self.executor.voting_set(epoch).encode())?;
        }

        self.statistics.push_back(BlockStatistic::from(&block));
        if self.statistics.len() > self.parameters.max_difficulty_blocks {
            self.statistics.pop_front();
        }
        self.tip = Some(tip);
        self.parent = Some(block);
        Ok(())
    }

    /// ここまで当てたものを書く。書き終えたら、次に開いたときはここから続く
    pub fn commit(&mut self) -> Result<(), ReplayError> {
        let Some(mut batch) = self.batch.take() else {
            return Ok(());
        };
        let height = self.executor.height();
        let meta = self.executor.encode_meta();
        batch.put_meta(EXECUTOR_META, &meta)?;
        batch.put_checkpoint(height, &meta)?;
        batch.commit()?;
        self.committed = height;
        // コミットした高さを確定とみなして、残す分より古いものを消す。消しきれなければ次のコミットで続ける
        let plan = Keep::plan(self.keep, &self.config, self.parameters, height, height);
        now_or_never(ChainStore::prune(self.db, plan)).map_err(failed)?;
        self.apply_target()
    }
}
