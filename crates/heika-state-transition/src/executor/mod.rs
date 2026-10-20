//! ブロックを実行して、状態を進める。catapult の observer を、状態の木に効くところだけ移したもの。
//!
//! 今はメモリの中だけで持ち、根は求めるたびに葉から組み直す。まだ移していないトランザクションの種類や
//! 状態が出てきたら、黙って進めずに [`ExecError::Unsupported`] で止める。
//!
//! 1つのブロックの中の順番は catapult の `NotificationPublisher` と `CoreSystem` の observer に合わせる。
//! トランザクションを順に、最後にブロックそのもの。ブロックのあとに、大口のアカウントの更新、importance の計算し直し、
//! 手数料の倍率の更新。

mod partial;
pub use partial::{Wanted, is_partial_row};
pub mod persist;
mod rules;
pub mod source;
mod statement;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

use heika_block::scoring::{BlockStatistic, NEMESIS_CHAIN_SCORE, block_score};
use heika_block::statement::{
    BalanceChange, BalanceTransfer, BlockStatement, Mosaic as ReceiptMosaic, ReceiptBody,
};
use heika_block::{Block, BlockType};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_core::patricia::{SubCache, TreeNode, address_key, hash_key, id_key, state_hash};
use heika_core::vrf::GenerationHash;
use heika_transaction::{
    Aggregate, AliasAction, Body, EmbeddedTransaction, LinkAction, MetadataKey, MetadataType,
    MosaicFlags, MosaicId, MosaicSupplyChangeAction, NamespaceId, NamespaceRegistrationType,
    Transaction, UnresolvedAddress, secret_lock_key,
};
use rayon::prelude::*;
use sha3::{Digest, Sha3_256};

use crate::account::{AccountState, AccountType, Bucket, Snapshot, VotingKey};
use crate::config::ChainConfig;
use crate::table::Table;
use crate::tree::PatriciaTree;
use crate::tree::StateTree;
use statement::StatementBuilder;

/// 実行できなかったわけ。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ExecError {
    /// まだ移していない
    Unsupported(String),
    /// チェーンにあるはずのないこと（残高が足りない、知らない ID など）。移し方が間違っている
    Invalid(String),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "まだ移していません: {what}"),
            Self::Invalid(what) => write!(f, "合いません: {what}"),
        }
    }
}

impl std::error::Error for ExecError {}

fn invalid(what: impl Into<String>) -> ExecError {
    ExecError::Invalid(what.into())
}

/// ネームスペースの別名
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Alias {
    None,
    Mosaic(u64),
    Address([u8; 24]),
}

impl Alias {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::None => out.push(0),
            Self::Mosaic(id) => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
            }
            Self::Address(address) => {
                out.push(2);
                out.extend_from_slice(address);
            }
        }
    }
}

/// ルートのネームスペースの、今の持ち主のもの。catapult の `RootNamespace`。
#[derive(Clone, Debug)]
struct RootNamespace {
    owner: [u8; 24],
    start: u64,
    /// 猶予を含めた終わり。期限がなければ u64::MAX
    end: u64,
    alias: Alias,
    /// ルートを除いた経路 → 別名
    children: BTreeMap<Vec<u64>, Alias>,
}

/// 期限切れのレシートを出すもの。並びはレシートを出す順（ID の順）
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Artifact {
    Namespace(u64),
    Mosaic(u64),
}

/// catapult の `MosaicEntry`。
#[derive(Clone, Debug)]
struct MosaicEntry {
    supply: u64,
    start_height: u64,
    owner: [u8; 24],
    revision: u32,
    flags: u8,
    divisibility: u8,
    duration: u64,
}

impl MosaicEntry {
    /// catapult の `MosaicDefinition::isActive`。期間 0 は期限なし
    fn is_active(&self, height: u64) -> bool {
        self.duration == 0
            || (self.start_height <= height && height < self.start_height + self.duration)
    }
}

/// catapult の `MultisigEntry`。
#[derive(Clone, Debug, Default)]
struct MultisigEntry {
    min_approval: u32,
    min_removal: u32,
    cosignatories: BTreeSet<[u8; 24]>,
    multisigs: BTreeSet<[u8; 24]>,
}

/// 連署の数を数えるときの、トランザクションの種類。連署者を外すだけなら min removal、足しもするなら大きいほう
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MultisigOperation {
    Normal,
    Removal,
    Both,
}

/// マルチシグを連署者へたどる深さの上限。正しいチェーンでは `maxMultisigDepth`（3）までしかない
const MAX_MULTISIG_WALK: usize = 8;

/// モザイクのフラグの全部（catapult の `MosaicFlags::All`）
const MOSAIC_FLAGS_ALL: u8 = 0x0F;

/// アカウントの制限の1種類。catapult の `AccountRestriction`。
#[derive(Clone, Debug)]
struct AccountRestriction {
    /// 向き（Outgoing）と種類に、Block の印を合わせたもの
    descriptor: u16,
    values: BTreeSet<Vec<u8>>,
}

/// Block の印
const RESTRICTION_BLOCK: u16 = 0x8000;

/// catapult の `AccountRestrictions`。向きと種類の4つ（ブロックの印を除いたフラグ）ごとに持つ
fn new_account_restrictions() -> BTreeMap<u16, AccountRestriction> {
    [0x0001, 0x0002, 0x4001, 0x4004]
        .into_iter()
        .map(|flags| {
            (
                flags,
                AccountRestriction {
                    descriptor: flags | RESTRICTION_BLOCK,
                    values: BTreeSet::new(),
                },
            )
        })
        .collect()
}

/// ロックの状態。catapult の `LockInfo` の `Status`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockStatus {
    Unused = 0,
    Used = 1,
}

/// catapult の `HashLockInfo`。同じハッシュのものは履歴として並び、葉にするのは最後のもの
#[derive(Clone, Debug)]
struct HashLockInfo {
    owner: [u8; 24],
    mosaic_id: u64,
    amount: u64,
    end_height: u64,
    status: LockStatus,
}

/// catapult の `SecretLockInfo`。キーはシークレットと受取人から求めたハッシュ
#[derive(Clone, Debug)]
struct SecretLockInfo {
    owner: [u8; 24],
    mosaic_id: u64,
    amount: u64,
    end_height: u64,
    status: LockStatus,
    hash_algorithm: u8,
    secret: [u8; 32],
    recipient: [u8; 24],
}

/// catapult の `MosaicRestrictionEntry`。キーはモザイクとアドレスから求めたハッシュ（全体の制限ではアドレスが0）
#[derive(Clone, Debug, PartialEq)]
enum MosaicRestrictionEntry {
    /// アドレスごとの値。キー → 値
    Address {
        mosaic_id: u64,
        address: [u8; 24],
        values: BTreeMap<u64, u64>,
    },
    /// モザイク全体の決まり。キー → （条件を借りるモザイク、値、比べ方）
    Global {
        mosaic_id: u64,
        rules: BTreeMap<u64, (u64, u64, u8)>,
    },
}

impl MosaicRestrictionEntry {
    /// catapult の `MosaicRestrictionEntrySerializer` の形。版の番号は付けない
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Address {
                mosaic_id,
                address,
                values,
            } => {
                out.push(0);
                out.extend_from_slice(&mosaic_id.to_le_bytes());
                out.extend_from_slice(address);
                out.push(values.len() as u8);
                for (key, value) in values {
                    out.extend_from_slice(&key.to_le_bytes());
                    out.extend_from_slice(&value.to_le_bytes());
                }
            }
            Self::Global { mosaic_id, rules } => {
                out.push(1);
                out.extend_from_slice(&mosaic_id.to_le_bytes());
                out.push(rules.len() as u8);
                for (key, (reference, value, restriction_type)) in rules {
                    out.extend_from_slice(&key.to_le_bytes());
                    out.extend_from_slice(&reference.to_le_bytes());
                    out.extend_from_slice(&value.to_le_bytes());
                    out.push(*restriction_type);
                }
            }
        }
        out
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Address { values, .. } => values.is_empty(),
            Self::Global { rules, .. } => rules.is_empty(),
        }
    }
}

/// catapult の `CreateMosaicRestrictionEntryKey`
fn mosaic_restriction_key(mosaic_id: u64, address: &[u8; 24]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(mosaic_id.to_le_bytes());
    hasher.update(address);
    hasher.finalize().into()
}

/// アドレスの制限で、値を消すことを表す値（catapult の `Sentinel_Removal_Value`）
const MOSAIC_RESTRICTION_REMOVAL: u64 = u64::MAX;

/// 実行している状態。
pub struct Executor {
    config: ChainConfig,
    network: NetworkIdentifier,
    /// 実行した最後の高さ
    height: u64,
    accounts: Table<[u8; 24], AccountState>,
    /// このブロックで触ったアカウント。大口かどうかを見直す
    touched: BTreeSet<[u8; 24]>,
    /// 前に根を求めてから変わったかもしれないアカウント
    dirty_accounts: BTreeSet<[u8; 24]>,
    /// 9本の木。SubCache の順
    trees: [StateTree; 9],
    /// 前に DB に書いてから変わったかもしれないアカウント
    unsaved_accounts: BTreeSet<[u8; 24]>,
    /// アカウント以外で、前に根を求めてから変わったかもしれない行（[`persist::row_key`]）
    dirty_rows: BTreeSet<Vec<u8>>,
    /// アカウント以外で、前に DB に書いてから変わったかもしれない行
    unsaved_rows: BTreeSet<Vec<u8>>,
    /// 期限が来て木から外れる高さ → 行。書き換えなしで木が変わるので、その高さで根を求め直す
    expiries: BTreeMap<u64, Vec<Vec<u8>>>,
    /// 期限切れのレシートが出るかもしれない高さ → ネームスペースとモザイク。その高さで今の期限と照らす
    artifact_expiries: BTreeMap<u64, BTreeSet<Artifact>>,
    high_value: BTreeSet<[u8; 24]>,
    /// 大口から外れたが、履歴が残っているもの
    removed: BTreeSet<[u8; 24]>,
    last_importance_height: u64,
    namespaces: BTreeMap<u64, RootNamespace>,
    /// ネームスペースの ID → ルートからの経路
    namespace_paths: HashMap<u64, Vec<u64>>,
    mosaics: BTreeMap<u64, MosaicEntry>,
    multisigs: Table<[u8; 24], MultisigEntry>,
    account_restrictions: BTreeMap<[u8; 24], BTreeMap<u16, AccountRestriction>>,
    hash_locks: Table<[u8; 32], Vec<HashLockInfo>>,
    secret_locks: BTreeMap<[u8; 32], Vec<SecretLockInfo>>,
    /// 1件を指すハッシュ → (キー、値)
    metadata: Table<[u8; 32], (MetadataKey, Vec<u8>)>,
    mosaic_restrictions: BTreeMap<[u8; 32], MosaicRestrictionEntry>,
    generation_hash_seed: heika_core::network::GenerationHashSeed,
    /// 最近のブロックの手数料の倍率。新しいものが後ろ
    fee_multipliers: VecDeque<u32>,
    /// レンタル料に掛ける倍率。1つ前のブロックのあとで求めたもの
    dynamic_fee_multiplier: u32,
    nemesis: [u8; 24],
    /// Nemesis の最初の送金のときに、送り手に残高がなかったか（catapult の `NemesisFundingObserver`）
    implicit_funding: Option<bool>,
    /// 期限切れの処理を飛ばした高さ（`skipSecretLockExpirations`）で切れたシークレットロック。
    /// catapult の木は書き換えたものだけを見直すので、次にそのキーに触れるまで、切れたまま木に残る
    stale_secret_locks: BTreeSet<[u8; 32]>,
    /// ジェネシスからのチェーンのスコア（catapult の `ChainScore`）と、最後のブロック。ピアと比べてどの枝を取るかを決める。
    /// 前の DB の実行の状態にはないので、そのときは `None` で、[`Executor::set_score`] で入れる
    score: Option<(u128, BlockStatistic)>,
    /// 期限が過ぎていないトランザクションのハッシュ（catapult の `HashCache`）。同じトランザクションの二度入れを弾く。
    /// 状態の木に入らないので、しまわない。途中から実行するときは [`Executor::remember_transactions`] で作り直す
    recent_hashes: HashSet<[u8; 32]>,
    /// 期限 → その期限のハッシュ。ブロックの時刻より前の期限のものは、もう入りえないので捨てる
    hash_deadlines: BTreeMap<u64, Vec<[u8; 32]>>,
    /// 実行しているブロックのステートメント
    statement: StatementBuilder,
    /// 最後に実行したブロックのステートメント
    last_statement: BlockStatement,
    /// ブロックを作っているところ（[`Executor::apply_produced`]）。importance ブロックの足を比べずに求める
    producing: bool,
    /// 作っているブロックの importance ブロックの足（投票できる数、ハーベストできる数、投票の残高の合計）
    produced_footer: Option<(u32, u64, u64)>,
    /// 当てている（弾いたなら、弾いた）トランザクションが、ブロックの何件目か（0から）。作るときに外すものを決める
    current_transaction: Option<usize>,
}

/// 作るブロックを当てて求めた、ヘッダーに書くもの
pub struct Produced {
    pub state_hash: Hash256,
    pub receipts_hash: Hash256,
    /// importance ブロックの足（投票できる数、ハーベストできる数、投票の残高の合計）。importance ブロックでなければ `None`
    pub footer: Option<(u32, u64, u64)>,
    pub statement: BlockStatement,
}

impl Executor {
    pub fn new(
        config: ChainConfig,
        network: NetworkIdentifier,
        generation_hash_seed: heika_core::network::GenerationHashSeed,
    ) -> Self {
        Self {
            config,
            network,
            height: 0,
            accounts: Table::complete(),
            touched: BTreeSet::new(),
            dirty_accounts: BTreeSet::new(),
            trees: Default::default(),
            unsaved_accounts: BTreeSet::new(),
            dirty_rows: BTreeSet::new(),
            unsaved_rows: BTreeSet::new(),
            expiries: BTreeMap::new(),
            artifact_expiries: BTreeMap::new(),
            high_value: BTreeSet::new(),
            removed: BTreeSet::new(),
            last_importance_height: 0,
            namespaces: BTreeMap::new(),
            namespace_paths: HashMap::new(),
            mosaics: BTreeMap::new(),
            multisigs: Table::complete(),
            account_restrictions: BTreeMap::new(),
            hash_locks: Table::complete(),
            secret_locks: BTreeMap::new(),
            metadata: Table::complete(),
            mosaic_restrictions: BTreeMap::new(),
            generation_hash_seed,
            fee_multipliers: VecDeque::new(),
            dynamic_fee_multiplier: 0,
            nemesis: [0; 24],
            implicit_funding: None,
            stale_secret_locks: BTreeSet::new(),
            score: Some((
                0,
                BlockStatistic {
                    timestamp: 0,
                    difficulty: 0,
                },
            )),
            recent_hashes: HashSet::new(),
            hash_deadlines: BTreeMap::new(),
            statement: StatementBuilder::default(),
            last_statement: BlockStatement::default(),
            producing: false,
            current_transaction: None,
            produced_footer: None,
        }
    }

    /// 実行した最後の高さ。
    pub fn height(&self) -> u64 {
        self.height
    }

    /// ジェネシスからのチェーンのスコア。前の DB から戻してまだ入れていなければ `None`
    pub fn score(&self) -> Option<u128> {
        self.score.map(|(total, _)| total)
    }

    /// 前の DB から戻したときに、しまったブロックから求めたスコアと、最後のブロックを入れる
    pub fn set_score(&mut self, total: u128, last: BlockStatistic) {
        self.score = Some((total, last));
    }

    /// 次の高さのブロックを実行する。ブロックそのものは確かめてあること。
    pub fn apply(&mut self, block: &Block) -> Result<(), ExecError> {
        let height = self.height + 1;
        if block.height != height {
            return Err(invalid(format!("高さ {height} のはずが {}", block.height)));
        }
        let nemesis = block.block_type == BlockType::Nemesis;
        if nemesis {
            self.nemesis = self.address_of(&block.signer_public_key);
        }
        let harvest_sink = self.config.harvest_network_fee_sink.at(height).0;
        self.forget_expired_hashes(block.timestamp);
        let mut total_fee = 0u64;
        for (index, bytes) in block.transactions().enumerate() {
            // ステートメントの元は、トランザクションの何件目か（1から）
            let primary = index as u32 + 1;
            self.current_transaction = Some(index);
            self.statement.set_source(primary, 0);
            if nemesis {
                // Nemesis では、どのエンティティの前にも手数料の受け取り先のアカウントを作る
                self.add_address(harvest_sink, height);
            }
            let transaction = Transaction::from_bytes(bytes)
                .map_err(|error| invalid(format!("トランザクションが読めません: {error}")))?;
            if !nemesis {
                self.check_nemesis_sink(
                    height,
                    &transaction.signer_public_key,
                    &transaction.signature,
                )?;
                if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) =
                    &transaction.body
                {
                    for cosignature in aggregate.cosignatures() {
                        self.check_nemesis_sink(
                            height,
                            &cosignature.signer_public_key,
                            &cosignature.signature,
                        )?;
                    }
                }
            }
            let size = bytes.len() as u64;
            let fee = u64::from(block.fee_multiplier) * size;
            total_fee += fee;
            self.apply_transaction(height, block.timestamp, primary, &transaction, size, fee)?;
        }
        self.current_transaction = None;
        if nemesis {
            self.add_address(harvest_sink, height);
        }
        self.statement.set_source(0, 0);
        if !nemesis {
            self.check_nemesis_sink(height, &block.signer_public_key, &block.signature)?;
            self.check_harvester_balance(&block.signer_public_key)?;
        }
        self.apply_block_notifications(height, block, total_fee)?;
        self.update_high_value();
        let importance_height = self.config.importance_height(height + 1);
        if importance_height != self.last_importance_height {
            self.recalculate_importances(importance_height);
            self.last_importance_height = importance_height;
        }
        if block.block_type == BlockType::Importance {
            if self.producing {
                self.produced_footer = Some(self.importance_footer(height));
            } else if let Some(footer) = &block.importance_footer {
                self.check_importance_footer(height, footer)?;
            }
        }
        self.update_dynamic_fee_multiplier(block.fee_multiplier);
        if let Some((total, last)) = &mut self.score {
            let current = BlockStatistic::from(block);
            *total = if nemesis {
                NEMESIS_CHAIN_SCORE
            } else {
                *total + u128::from(block_score(last, &current))
            };
            *last = current;
        }
        self.unsaved_accounts.extend(self.touched.iter().copied());
        self.dirty_accounts.append(&mut self.touched);
        self.height = height;
        self.last_statement = self.statement.take();
        Ok(())
    }

    /// 作るブロックを当てて、ヘッダーに書く StateHash、ReceiptsHash、importance ブロックの足を求める。
    /// ブロックのそれらは見ない（0 のままでよい）。どれも状態を変えないので、当てたあとの状態は、求めたものを書いた
    /// ブロックを実行したあとのものと同じ。通らなければ状態は途中のままなので、捨てて戻し直すこと
    /// 最後の [`Executor::apply`] がトランザクションを当てているところで弾いたなら、それがブロックの何件目か（0から）
    pub fn failed_transaction(&self) -> Option<usize> {
        self.current_transaction
    }

    pub fn apply_produced(&mut self, block: &Block) -> Result<Produced, ExecError> {
        self.producing = true;
        let applied = self.apply(block);
        self.producing = false;
        applied?;
        let statement = self.take_statement();
        Ok(Produced {
            state_hash: self.state_hash(),
            receipts_hash: statement.merkle_hash(),
            footer: self.produced_footer.take(),
            statement,
        })
    }

    /// 最後に実行したブロックのステートメント。この Merkle の根が、ブロックの ReceiptsHash になる
    pub fn take_statement(&mut self) -> BlockStatement {
        std::mem::take(&mut self.last_statement)
    }

    /// 9本の木の根。アカウントは変わったものだけ、ほかは葉を並べ直して、変わった道だけを計算し直す。
    pub fn roots(&mut self) -> [Hash256; 9] {
        let mut roots = [crate::tree::EMPTY_ROOT; 9];
        roots[SubCache::AccountState.index()] = self.account_root();
        let due = self.expiries.split_off(&(self.height + 1));
        for (_, rows) in std::mem::replace(&mut self.expiries, due) {
            self.dirty_rows.extend(rows);
        }
        for row in std::mem::take(&mut self.dirty_rows) {
            let cache = SubCache::ALL[usize::from(row[0])];
            let key = tree_key(cache, &row[1..]);
            match self.leaf(cache, &row[1..]) {
                Some(value) => self.trees[cache.index()].set(key, value),
                None => self.trees[cache.index()].remove(&key),
            }
        }
        for cache in SubCache::ALL {
            if cache != SubCache::AccountState {
                roots[cache.index()] = self.trees[cache.index()].root();
            }
        }
        roots
    }

    /// しまった木のノードから9本の木を戻す。行から組み直すと全部の葉とノードのハッシュを求め直すが、
    /// こちらはハッシュをほとんど求めない。戻したあとで、根がブロックの StateHash と合うかを確かめること
    pub fn restore_trees(
        &mut self,
        nodes: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
    ) -> Result<(), ExecError> {
        let mut grouped: [Vec<_>; 9] = Default::default();
        for (key, bytes) in nodes {
            let (cache, position) = crate::tree::parse_node_key(&key)
                .filter(|(cache, _)| usize::from(*cache) < 9)
                .ok_or_else(|| {
                    ExecError::Invalid("しまった木のノードのキーが読めません".to_owned())
                })?;
            let node = TreeNode::decode_all(&bytes)
                .ok()
                .and_then(|nodes| nodes.into_iter().next())
                .ok_or_else(|| ExecError::Invalid("しまった木のノードが読めません".to_owned()))?;
            grouped[usize::from(cache)].push((position, node));
        }
        for (tree, nodes) in self.trees.iter_mut().zip(grouped) {
            // 必要なノードだけを持つ木は、全部を組み直さない
            if tree.as_lazy_mut().is_none() {
                *tree = StateTree::Full(PatriciaTree::from_nodes(nodes));
            }
        }
        self.dirty_accounts.clear();
        self.dirty_rows.clear();
        Ok(())
    }

    /// 木を捨てて、行から組み直すことにする。[`Executor::restore_trees`] の根が合わなかったとき
    pub fn rebuild_trees(&mut self) {
        self.trees = Default::default();
        // 全部のノードが変わったことになるので、覚えない。組んだら DB に合わせて [`Executor::forget_node_changes`] する
        for tree in &mut self.trees {
            tree.track_node_changes(false);
        }
        self.dirty_accounts = self.accounts.keys().copied().collect();
        self.dirty_rows = self.rows_for_rebuild();
    }

    /// 前に呼んでから変わった、9本の木のノード。キー（[`crate::tree::node_key`]）と、
    /// 今のノードのバイト列か、なくなったら `None`。[`Executor::roots`] のあとで呼ぶ
    pub fn take_node_changes(&mut self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut changes = Vec::new();
        for (index, tree) in self.trees.iter_mut().enumerate() {
            for (position, node) in tree.take_node_changes() {
                changes.push((
                    crate::tree::node_key(index as u8, &position),
                    node.as_ref().map(TreeNode::encode),
                ));
            }
        }
        changes
    }

    /// 木の組み直しなどで溜まったノードの変化を捨てて、これからの変化を覚える。DB にあるものと同じ木のとき
    pub fn forget_node_changes(&mut self) {
        for tree in &mut self.trees {
            tree.forget_node_changes();
            tree.track_node_changes(true);
        }
    }

    /// 9本の木のノードを全部。[`Executor::roots`] のあとで呼ぶ。必要なノードだけを持つ木があれば `None`
    pub fn all_nodes(&mut self) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut nodes = Vec::new();
        self.forget_node_changes();
        for (index, tree) in self.trees.iter_mut().enumerate() {
            for (position, node) in tree.as_full_mut()?.nodes() {
                nodes.push((crate::tree::node_key(index as u8, &position), node.encode()));
            }
        }
        Some(nodes)
    }

    /// 行（[`persist::row_key`]）の、木の番号と木のキーと、木にある葉の値。[`Executor::roots`] のあとで呼ぶ
    pub fn leaf_of_row(&self, row: &[u8]) -> (SubCache, Hash256, Option<Hash256>) {
        let (cache, key) = tree_key_of_row(row);
        let value = self.trees[cache.index()]
            .as_full()
            .and_then(|tree| tree.get(&key));
        (cache, key, value)
    }

    /// 行の、木の葉の値のもとになる catapult の形のバイト列。この SHA3-256 が葉の値になる。
    /// 木の中を見ないので、行だけから戻した状態でも使える。木に入らなければ `None`
    pub fn state_bytes_of_row(&self, row: &[u8]) -> Option<Vec<u8>> {
        let cache = SubCache::ALL[usize::from(row[0])];
        if cache == SubCache::AccountState {
            let account = self.accounts.get(&<[u8; 24]>::try_from(&row[1..]).ok()?)?;
            Some(account.to_state_bytes(self.config.currency_mosaic_id))
        } else {
            self.state_bytes(cache, &row[1..])
        }
    }

    /// 行の葉への経路。[`Executor::roots`] のあとで呼ぶ。必要なノードだけを持つ木なら `None`
    pub fn path_of_row(&mut self, row: &[u8]) -> Option<Vec<TreeNode>> {
        let (cache, key, _) = self.leaf_of_row(row);
        Some(self.trees[cache.index()].as_full_mut()?.path(&key))
    }

    /// `block` を出したアカウントに、その資格があるか。1つ前のブロック `parent` のあとの状態で、実行する前に呼ぶ。
    /// catapult の `BlockchainProcessor` の `CheckGenerationHash` と `BlockHitPredicate`:
    ///
    /// 1. 署名者のアカウントが、公開鍵で見つかる
    /// 2. 署名者がリモートならメインアカウントの、VRF の鍵で、`parent_generation_hash` の証明が通る
    /// 3. 証明から出た generation hash で当たりになる。importance は、リモートならメインアカウントの、
    ///    その高さの importance の高さのもの。違う高さのものしかなければ 0
    ///
    /// 通れば、このブロックの generation hash を返す。
    pub fn check_harvester(
        &self,
        parent: &Block,
        parent_generation_hash: &GenerationHash,
        block: &Block,
        parameters: &heika_core::network::NetworkParameters,
    ) -> Result<GenerationHash, ExecError> {
        let forwarded = self.harvester(&block.signer_public_key)?;
        // VRF の鍵がなければ、catapult は0の鍵で確かめるので通らない
        let vrf_key = PublicKey(forwarded.vrf.unwrap_or([0; 32]));
        let proof_hash = heika_core::vrf::verify(
            &vrf_key,
            &parent_generation_hash.0,
            &block.generation_hash_proof,
        )
        .ok_or_else(|| harvester_error("VRF の証明が通りません"))?;
        let generation_hash = proof_hash.generation_hash();
        let importance = self.importance_of(forwarded, block.height);
        if !heika_block::scoring::is_hit(parent, block, importance, parameters) {
            return Err(harvester_error("当たりではありません"));
        }
        Ok(generation_hash)
    }

    /// `block` を出したアカウント（リモートならメインアカウント）の、そのブロックの高さで使う Importance
    pub fn harvester_importance(&self, block: &Block) -> Result<u64, ExecError> {
        self.signer_importance(&block.signer_public_key, block.height)
    }

    /// `signer` が高さ `height` のブロックを出すときに使う Importance（リモートならメインアカウントのもの）
    pub fn signer_importance(&self, signer: &PublicKey, height: u64) -> Result<u64, ExecError> {
        Ok(self.importance_of(self.harvester(signer)?, height))
    }

    /// `signer` の鍵でブロックを出すアカウント。リモートなら、リンクしたメインアカウント
    fn harvester(&self, signer: &PublicKey) -> Result<&AccountState, ExecError> {
        let account = self
            .accounts
            .get(&self.address_of(signer))
            .filter(|account| account.public_key_height != 0 && account.public_key == signer.0)
            .ok_or_else(|| harvester_error("署名者のアカウントがありません"))?;
        Ok(match account.account_type {
            AccountType::Remote => {
                let main = account
                    .linked
                    .ok_or_else(|| harvester_error("リモートなのにメインアカウントがありません"))?;
                self.accounts
                    .get(&self.address_of(&PublicKey(main)))
                    .ok_or_else(|| harvester_error("メインアカウントがありません"))?
            }
            _ => account,
        })
    }

    /// `account` の、高さ `height` のブロックで使う Importance。最後のスナップショットがその高さのものでなければ 0
    fn importance_of(&self, account: &AccountState, height: u64) -> u64 {
        let snapshot = account.snapshots[0];
        if snapshot.height == self.config.importance_height(height) {
            snapshot.importance
        } else {
            0
        }
    }

    /// 大口のアカウント（収穫モザイクの残高が minHarvesterBalance 以上）の残高の合計。catapult が Importance を
    /// 求めるときの `ActiveHarvestingMosaics`（ハーベストしているかに依らない）
    pub fn harvesting_stake(&self) -> u128 {
        let mosaic = self.config.harvesting_mosaic_id;
        self.high_value
            .iter()
            .filter_map(|address| self.accounts.get(address))
            .map(|account| u128::from(account.balance(mosaic)))
            .sum()
    }

    /// 今の状態で決まる、エポック `epoch` の投票者。catapult の `FinalizationContext` の作り方と同じで、
    /// 投票の鍵を持ち、収穫モザイクの残高が minVoterBalance 以上のアカウントの、そのエポックの鍵と残高。
    /// 今の高さが `epoch` の1つ前のエポックの最後の高さのときに呼ぶ
    pub fn voting_set(&self, epoch: u32) -> heika_block::finalization::proof::VotingSet {
        let config = &self.config.finalization;
        let mosaic = self.config.harvesting_mosaic_id;
        let mut set = heika_block::finalization::proof::VotingSet::default();
        // 投票者は大口のアカウントに入っている。大口の閾値のほうが低いので
        let candidates: Box<dyn Iterator<Item = &[u8; 24]>> =
            if config.min_voter_balance >= self.config.min_harvester_balance {
                Box::new(self.high_value.iter())
            } else {
                Box::new(self.accounts.keys())
            };
        for address in candidates {
            let Some(account) = self.accounts.get(address) else {
                continue;
            };
            let balance = account.balance(mosaic);
            if account.voting.is_empty() || balance < config.min_voter_balance {
                continue;
            }
            let Some(key) = account
                .voting
                .iter()
                .find(|key| key.start_epoch <= epoch && epoch <= key.end_epoch)
            else {
                continue;
            };
            if config.treasury_reissuance_epoch <= epoch
                && config.ineligible_voters.contains(address)
            {
                continue;
            }
            set.voters.insert(key.key, balance);
        }
        set
    }

    /// 根から求めた StateHash。
    pub fn state_hash(&mut self) -> Hash256 {
        state_hash(&self.roots())
    }

    /// アカウント以外の行が変わったかもしれないことを覚える
    fn touch(&mut self, cache: SubCache, key: &[u8]) {
        let row = persist::row_key(cache, key);
        self.dirty_rows.insert(row.clone());
        self.unsaved_rows.insert(row);
    }

    /// `height` で期限が来ると覚えた、木 `cache` のロックのキー。ロックを作るたびに、その終わりの高さで覚えている
    fn locks_due(&self, height: u64, cache: SubCache) -> BTreeSet<[u8; 32]> {
        let index = cache.index() as u8;
        self.expiries
            .get(&height)
            .map_or_else(BTreeSet::new, |rows| {
                rows.iter()
                    .filter(|row| row.first() == Some(&index))
                    .filter_map(|row| row[1..].try_into().ok())
                    .collect()
            })
    }

    /// `height` で期限が来て、木から外れることを覚える
    fn expire_at(&mut self, height: u64, cache: SubCache, key: &[u8]) {
        if height != u64::MAX {
            self.expiries
                .entry(height)
                .or_default()
                .push(persist::row_key(cache, key));
        }
    }

    // region: アカウント

    fn address_of(&self, public_key: &PublicKey) -> [u8; 24] {
        Address::from_public_key(public_key, self.network).0
    }

    /// catapult の `AccountStateCacheDelta::addAccount(address)`
    fn add_address(&mut self, address: [u8; 24], height: u64) {
        self.accounts
            .get_or_insert_with(address, || AccountState::new(address, height));
        self.touched.insert(address);
    }

    /// catapult の `AccountStateCacheDelta::addAccount(publicKey)`
    fn add_public_key(&mut self, public_key: &PublicKey, height: u64) -> [u8; 24] {
        let address = self.address_of(public_key);
        self.add_address(address, height);
        let account = self.accounts.get_mut(&address).expect("just added");
        if account.public_key_height == 0 {
            account.public_key = public_key.0;
            account.public_key_height = height;
        }
        address
    }

    fn account_mut(&mut self, address: &[u8; 24]) -> Result<&mut AccountState, ExecError> {
        self.touched.insert(*address);
        self.accounts
            .get_mut(address)
            .ok_or_else(|| invalid(format!("アカウント {} がありません", Address(*address))))
    }

    /// Remote のアカウントなら、そのメインのアカウント。catapult の `ProcessForwardedAccountState`
    fn forwarded(&mut self, address: &[u8; 24]) -> Result<[u8; 24], ExecError> {
        let account = self.account_mut(address)?;
        if account.account_type != AccountType::Remote {
            return Ok(*address);
        }
        let main_key = account
            .linked
            .ok_or_else(|| invalid("Remote のアカウントにリンクがありません"))?;
        let main = self.address_of(&PublicKey(main_key));
        self.account_mut(&main)?;
        Ok(main)
    }

    fn credit(&mut self, address: &[u8; 24], mosaic_id: u64, amount: u64) -> Result<(), ExecError> {
        self.account_mut(address)?.credit(mosaic_id, amount);
        Ok(())
    }

    fn debit(&mut self, address: &[u8; 24], mosaic_id: u64, amount: u64) -> Result<(), ExecError> {
        if !self.account_mut(address)?.debit(mosaic_id, amount) {
            return Err(invalid(format!(
                "{} のモザイク {mosaic_id:016X} が {amount} に足りません",
                Address(*address)
            )));
        }
        Ok(())
    }

    fn transfer(
        &mut self,
        from: &[u8; 24],
        to: &[u8; 24],
        mosaic_id: u64,
        amount: u64,
    ) -> Result<(), ExecError> {
        self.debit(from, mosaic_id, amount)?;
        self.credit(to, mosaic_id, amount)
    }

    // endregion

    // region: 解決

    /// モザイクの ID を解決する。ネームスペースだったら、ステートメントに残す（catapult の observer の `Resolvers`）。
    /// ネームスペースがないか、モザイクの別名でなければ、そのままの値を使う（catapult の `BuildResolver` は、どの
    /// 解決もできなければ、解決する前の値をそのまま返す。テストネットの高さ 2,672,377）
    fn resolve_mosaic(&mut self, id: u64) -> Result<u64, ExecError> {
        if id >> 63 == 0 {
            return Ok(id);
        }
        let resolved = match self.alias_of(id) {
            Ok(Alias::Mosaic(mosaic_id)) => mosaic_id,
            _ => id,
        };
        self.statement.add_mosaic_resolution(id, resolved);
        Ok(resolved)
    }

    /// アドレスを解決する。ネームスペースだったら、ステートメントに残す。解決できなければ、モザイクと同じに
    /// そのままの値を使う
    fn resolve_address(&mut self, address: &UnresolvedAddress) -> Result<[u8; 24], ExecError> {
        let Some(id) = address.namespace_id() else {
            return Ok(address.0);
        };
        let resolved = match self.alias_of(id.0) {
            Ok(Alias::Address(resolved)) => resolved,
            _ => address.0,
        };
        self.statement.add_address_resolution(address, resolved);
        Ok(resolved)
    }

    fn alias_of(&self, namespace_id: u64) -> Result<Alias, ExecError> {
        let path = self
            .namespace_paths
            .get(&namespace_id)
            .ok_or_else(|| invalid(format!("ネームスペース {namespace_id:016X} がありません")))?;
        let root = &self.namespaces[&path[0]];
        Ok(if path.len() == 1 {
            root.alias
        } else {
            root.children[&path[1..]]
        })
    }

    fn set_alias(&mut self, namespace_id: u64, alias: Alias) -> Result<(), ExecError> {
        let path = self
            .namespace_paths
            .get(&namespace_id)
            .ok_or_else(|| invalid(format!("ネームスペース {namespace_id:016X} がありません")))?
            .clone();
        self.touch(SubCache::Namespace, &path[0].to_le_bytes());
        let root = self
            .namespaces
            .get_mut(&path[0])
            .expect("path points to a root");
        if path.len() == 1 {
            root.alias = alias;
        } else {
            *root
                .children
                .get_mut(&path[1..])
                .expect("path points to a child") = alias;
        }
        Ok(())
    }

    // endregion

    // region: トランザクション

    fn apply_transaction(
        &mut self,
        height: u64,
        timestamp: u64,
        primary: u32,
        transaction: &Transaction,
        size: u64,
        fee: u64,
    ) -> Result<(), ExecError> {
        let hash = transaction.hash(&self.generation_hash_seed);
        self.check_transaction(height, timestamp, transaction, &hash, size, fee)?;
        self.remember_hash(transaction.deadline, hash.0);
        let signer = self.add_public_key(&transaction.signer_public_key, height);
        self.check_transaction_rules(signer, transaction.body.transaction_type())?;
        // TransactionFeeActivity
        if fee > 0 {
            let importance_height = self.config.importance_height(height);
            self.account_mut(&signer)?
                .try_update_bucket(importance_height, |bucket| bucket.total_fees_paid += fee);
        }
        // 手数料は、totalVotingBalanceCalculationFix より前は中身の前に、そこからは中身のあとに引く（catapult の
        // `BasicNotificationPublisher`）。どちらも残高が足りなければ弾くので、順番で通るかどうかが変わる
        let currency = self.config.currency_mosaic_id;
        let fee_first = height < self.config.total_voting_balance_calculation_fix;
        if fee_first {
            self.debit(&signer, currency, fee)?;
        }
        match &transaction.body {
            Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => {
                let cosigners = self.cosigners(transaction, aggregate);
                self.check_eligible_cosigners(&cosigners, aggregate)?;
                if matches!(transaction.body, Body::AggregateBonded(_)) {
                    // CompletedAggregate: 預けてあったものを持ち主に返す
                    self.touch(SubCache::HashLockInfo, &hash.0);
                    let lock = self
                        .hash_locks
                        .get_mut(&hash.0)
                        .and_then(|history| history.last_mut())
                        .ok_or_else(|| {
                            invalid(format!("アグリゲート {hash} のロックがありません"))
                        })?;
                    lock.status = LockStatus::Used;
                    let (owner, mosaic_id, amount) = (lock.owner, lock.mosaic_id, lock.amount);
                    self.credit(&owner, mosaic_id, amount)?;
                    self.statement
                        .add_receipt(ReceiptBody::LockHashCompleted(change(
                            owner, mosaic_id, amount,
                        )));
                }
                // 連署者の公開鍵は、アカウントの状態には入らない
                for (index, inner) in aggregate.transactions().iter().enumerate() {
                    // 中のトランザクションは、元の2つ目の番号を1から振る
                    self.statement.set_source(primary, index as u32 + 1);
                    // 中のトランザクションごとに、その前までを当てた状態で、要る署名者が連署しているか
                    self.check_sufficient_cosigners(&cosigners, inner)?;
                    let inner_signer = self.add_public_key(&inner.signer_public_key, height);
                    self.apply_body(height, inner_signer, &inner.signer_public_key, &inner.body)?;
                }
            }
            body => self.apply_body(height, signer, &transaction.signer_public_key, body)?,
        }
        if !fee_first {
            self.debit(&signer, currency, fee)?;
        }
        Ok(())
    }

    // region: 確かめる（catapult の validator のうち、通らないと状態が変わってしまうもの）

    /// トランザクションを当てる前の、トランザクション全体についての確かめ。catapult の `TransactionNotification`、
    /// `TransactionDeadlineNotification`、`TransactionFeeNotification` の validator
    fn check_transaction(
        &self,
        height: u64,
        timestamp: u64,
        transaction: &Transaction,
        hash: &Hash256,
        size: u64,
        fee: u64,
    ) -> Result<(), ExecError> {
        // TransactionFee
        if fee > transaction.fee || transaction.fee > u64::from(u32::MAX) * size {
            return Err(invalid(format!(
                "トランザクション {hash} の手数料 {fee} が上限 {} に合いません",
                transaction.fee
            )));
        }
        // Deadline。Nemesis はハッシュを決め打ちしているので見ない
        let bonded = matches!(transaction.body, Body::AggregateBonded(_));
        if height > 1 {
            let lifetime = if bonded {
                self.config.max_bonded_transaction_lifetime
            } else {
                self.config.max_transaction_lifetime
            };
            if transaction.deadline < timestamp || transaction.deadline > timestamp + lifetime {
                return Err(invalid(format!(
                    "トランザクション {hash} の期限 {} がブロックの時刻 {timestamp} に合いません",
                    transaction.deadline
                )));
            }
        }
        // UniqueTransactionHash
        if self.recent_hashes.contains(&hash.0) {
            return Err(invalid(format!(
                "トランザクション {hash} はもう入っています"
            )));
        }
        // MultisigPermittedOperation: 連署者のいるアカウントは、外側で直接署名できない
        let signer = self.address_of(&transaction.signer_public_key);
        if self.is_multisig(&signer) {
            return Err(invalid(format!(
                "マルチシグの {} が直接署名しています",
                Address(signer)
            )));
        }
        // AggregateHashPresent: ボンデッドは、使っていない、切れていないハッシュロックがあること
        if bonded {
            let active = self
                .hash_locks
                .get(&hash.0)
                .and_then(|history| history.last())
                .is_some_and(|lock| lock.status == LockStatus::Unused && height < lock.end_height);
            if !active {
                return Err(invalid(format!(
                    "アグリゲート {hash} の生きているロックがありません"
                )));
            }
        }
        Ok(())
    }

    /// `deadline` が期限のトランザクションのハッシュを覚える
    fn remember_hash(&mut self, deadline: u64, hash: [u8; 32]) {
        if self.recent_hashes.insert(hash) {
            self.hash_deadlines.entry(deadline).or_default().push(hash);
        }
    }

    /// 期限が `timestamp` より前のハッシュを捨てる。そういうトランザクションは期限の確かめで弾かれるので、
    /// 覚えていなくても二度入れにはならない（catapult はもっと長く覚えているが、弾くものは同じ）
    fn forget_expired_hashes(&mut self, timestamp: u64) {
        let kept = self.hash_deadlines.split_off(&timestamp);
        for (_, hashes) in std::mem::replace(&mut self.hash_deadlines, kept) {
            for hash in hashes {
                self.recent_hashes.remove(&hash);
            }
        }
    }

    /// 実行したブロックのトランザクションのハッシュを覚え直す。途中から実行するときに、直前のブロックを
    /// 古い順に渡す（期限の上限はボンデッドの 48 時間なので、最後のブロックの時刻からそれだけさかのぼれば足りる）
    pub fn remember_transactions(&mut self, block: &Block) -> Result<(), ExecError> {
        for bytes in block.transactions() {
            let transaction = Transaction::from_bytes(bytes)
                .map_err(|error| invalid(format!("トランザクションが読めません: {error}")))?;
            let hash = transaction.hash(&self.generation_hash_seed);
            self.remember_hash(transaction.deadline, hash.0);
        }
        Ok(())
    }

    /// 連署者のいるアカウントか。catapult では、連署者でしかないアカウントもマルチシグの表に入る
    fn is_multisig(&self, address: &[u8; 24]) -> bool {
        self.multisigs
            .get(address)
            .is_some_and(|entry| !entry.cosignatories.is_empty())
    }

    /// validator がするアドレスの解決。ステートメントには残さない。解決できなければそのまま
    fn peek_address(&self, address: &UnresolvedAddress) -> [u8; 24] {
        match address.namespace_id().map(|id| self.alias_of(id.0)) {
            Some(Ok(Alias::Address(resolved))) => resolved,
            _ => address.0,
        }
    }

    /// アグリゲートの外側の署名者と連署者
    fn cosigners(&self, transaction: &Transaction, aggregate: &Aggregate) -> BTreeSet<[u8; 24]> {
        std::iter::once(&transaction.signer_public_key)
            .chain(
                aggregate
                    .cosignatures()
                    .iter()
                    .map(|cosignature| &cosignature.signer_public_key),
            )
            .map(|key| self.address_of(key))
            .collect()
    }

    /// 中のトランザクションに要る署名者。署名者と、catapult の `additionalRequiredCosignatories`
    /// （メタデータの対象の持ち主、マルチシグに足す連署者）
    fn required_signers(&self, inner: &EmbeddedTransaction) -> BTreeSet<[u8; 24]> {
        let mut required = BTreeSet::from([self.address_of(&inner.signer_public_key)]);
        match &inner.body {
            Body::AccountMetadata(metadata) => {
                required.insert(self.peek_address(&metadata.target_address));
            }
            Body::MosaicMetadata(metadata) => {
                required.insert(self.peek_address(&metadata.metadata.target_address));
            }
            Body::NamespaceMetadata(metadata) => {
                required.insert(self.peek_address(&metadata.metadata.target_address));
            }
            Body::MultisigAccountModification(modification) => {
                for address in modification.address_additions.iter() {
                    required.insert(self.peek_address(address));
                }
            }
            _ => {}
        }
        required
    }

    /// MultisigAggregateEligibleCosignatories: 連署者はみな、どれかの中のトランザクションに要る署名者か、
    /// （マルチシグをたどって）その連署者であること。中のトランザクションを当てる前の状態で見る
    fn check_eligible_cosigners(
        &self,
        cosigners: &BTreeSet<[u8; 24]>,
        aggregate: &Aggregate,
    ) -> Result<(), ExecError> {
        let mut eligible = BTreeSet::new();
        for inner in aggregate.transactions() {
            for address in self.required_signers(inner) {
                self.mark_eligible(address, &mut eligible, 0);
            }
        }
        match cosigners
            .iter()
            .find(|address| !eligible.contains(*address))
        {
            Some(address) => Err(invalid(format!(
                "アグリゲートの連署者 {} は要りません",
                Address(*address)
            ))),
            None => Ok(()),
        }
    }

    fn mark_eligible(&self, address: [u8; 24], eligible: &mut BTreeSet<[u8; 24]>, depth: usize) {
        match self.multisigs.get(&address) {
            Some(entry) if !entry.cosignatories.is_empty() => {
                // 輪になったマルチシグで止まらなくならないように（正しいチェーンでは深さは3まで）
                if depth < MAX_MULTISIG_WALK {
                    for cosignatory in &entry.cosignatories {
                        self.mark_eligible(*cosignatory, eligible, depth + 1);
                    }
                }
            }
            _ => {
                eligible.insert(address);
            }
        }
    }

    /// MultisigAggregateSufficientCosignatories: 中のトランザクションに要る署名者が、みな連署しているか、
    /// マルチシグなら連署者のうち要る数が（たどって）連署していること
    fn check_sufficient_cosigners(
        &self,
        cosigners: &BTreeSet<[u8; 24]>,
        inner: &EmbeddedTransaction,
    ) -> Result<(), ExecError> {
        let operation = match &inner.body {
            Body::MultisigAccountModification(modification)
                if !modification.address_deletions.is_empty() =>
            {
                if modification.address_additions.is_empty() {
                    MultisigOperation::Removal
                } else {
                    MultisigOperation::Both
                }
            }
            _ => MultisigOperation::Normal,
        };
        for address in self.required_signers(inner) {
            if !self.is_satisfied(&address, operation, cosigners, 0) {
                return Err(invalid(format!("{} の連署が足りません", Address(address))));
            }
        }
        Ok(())
    }

    fn is_satisfied(
        &self,
        address: &[u8; 24],
        operation: MultisigOperation,
        cosigners: &BTreeSet<[u8; 24]>,
        depth: usize,
    ) -> bool {
        let Some(entry) = self
            .multisigs
            .get(address)
            .filter(|entry| !entry.cosignatories.is_empty())
        else {
            return cosigners.contains(address);
        };
        if depth >= MAX_MULTISIG_WALK {
            return false;
        }
        let approvers = entry
            .cosignatories
            .iter()
            .filter(|cosignatory| self.is_satisfied(cosignatory, operation, cosigners, depth + 1))
            .count();
        let required = match operation {
            MultisigOperation::Normal => entry.min_approval,
            MultisigOperation::Removal => entry.min_removal,
            MultisigOperation::Both => entry.min_approval.max(entry.min_removal),
        };
        approvers as u64 >= u64::from(required)
    }

    /// RequiredMosaic: モザイクが生きていて、持ち主が `owner` であること
    fn check_mosaic_owner(
        &self,
        height: u64,
        id: u64,
        owner: &[u8; 24],
    ) -> Result<&MosaicEntry, ExecError> {
        let entry = self
            .mosaics
            .get(&id)
            .filter(|entry| entry.is_active(height))
            .ok_or_else(|| invalid(format!("モザイク {id:016X} は生きていません")))?;
        if entry.owner != *owner {
            return Err(invalid(format!(
                "モザイク {id:016X} の持ち主は {} ではありません",
                Address(*owner)
            )));
        }
        Ok(entry)
    }

    /// RequiredNamespace: ネームスペースのルートが猶予を除いて生きていて、持ち主が `owner` であること
    fn check_namespace_owner(
        &self,
        height: u64,
        id: u64,
        owner: &[u8; 24],
    ) -> Result<(), ExecError> {
        let root = self
            .namespace_paths
            .get(&id)
            .and_then(|path| self.namespaces.get(&path[0]))
            .ok_or_else(|| invalid(format!("ネームスペース {id:016X} がありません")))?;
        if !self.is_active_excluding_grace(root, height) {
            return Err(invalid(format!("ネームスペース {id:016X} は切れています")));
        }
        if root.owner != *owner {
            return Err(invalid(format!(
                "ネームスペース {id:016X} の持ち主は {} ではありません",
                Address(*owner)
            )));
        }
        Ok(())
    }

    fn is_active_excluding_grace(&self, root: &RootNamespace, height: u64) -> bool {
        root.start <= height
            && (root.end == u64::MAX || height < root.end - self.config.namespace_grace_period)
    }

    /// ChildNamespaceAvailability: 親があり、深すぎず、ルートが猶予を除いて生きていて持ち主が `owner` で、
    /// その子がまだないこと。
    ///
    /// catapult は切れたネームスペースを、猶予のあともしばらく消さずに「ある」とみなす。ここでは、ルートが
    /// 猶予を含めて生きているものだけを「ある」とみなす。catapult が弾く子を通すことはあっても、通す子を弾くことはない
    fn check_child_namespace(
        &self,
        height: u64,
        owner: &[u8; 24],
        id: u64,
        parent_id: u64,
    ) -> Result<(), ExecError> {
        let parent = self
            .namespace_paths
            .get(&parent_id)
            .ok_or_else(|| invalid("親のネームスペースがありません"))?;
        if parent.len() >= self.config.max_namespace_depth {
            return Err(invalid(format!(
                "ネームスペース {parent_id:016X} の下には作れません（深すぎる）"
            )));
        }
        self.check_namespace_owner(height, parent_id, owner)?;
        let exists = self
            .namespace_paths
            .get(&id)
            .and_then(|path| self.namespaces.get(&path[0]))
            .is_some_and(|root| root.start <= height && height < root.end);
        if exists {
            return Err(invalid(format!("ネームスペース {id:016X} はもうあります")));
        }
        Ok(())
    }

    /// 別名を付け外しできるか。RequiredNamespace、AliasAvailability、UnlinkAliased*Consistency
    fn check_alias(
        &self,
        height: u64,
        owner: &[u8; 24],
        namespace_id: u64,
        action: AliasAction,
        alias: Alias,
    ) -> Result<(), ExecError> {
        self.check_namespace_owner(height, namespace_id, owner)?;
        let current = self.alias_of(namespace_id)?;
        let available = match action {
            AliasAction::Link => current == Alias::None,
            AliasAction::Unlink => current == alias,
        };
        if !available {
            return Err(invalid(format!(
                "ネームスペース {namespace_id:016X} の別名は {current:?} なので {action:?} できません"
            )));
        }
        Ok(())
    }

    // endregion

    /// 中身を確かめて当てる
    fn apply_body(
        &mut self,
        height: u64,
        signer: [u8; 24],
        signer_key: &PublicKey,
        body: &Body,
    ) -> Result<(), ExecError> {
        self.check_body_rules(height, signer, body)?;
        self.apply_checked_body(height, signer, signer_key, body)
    }

    /// 確かめた中身を当てる
    fn apply_checked_body(
        &mut self,
        height: u64,
        signer: [u8; 24],
        signer_key: &PublicKey,
        body: &Body,
    ) -> Result<(), ExecError> {
        let is_nemesis_signer = height == 1 && signer == self.nemesis;
        match body {
            Body::Transfer(transfer) => {
                let recipient = self.resolve_address(transfer.recipient_address())?;
                self.add_address(recipient, height);
                for (&id, &amount) in transfer.mosaics() {
                    let id = self.resolve_mosaic(id.0)?;
                    if is_nemesis_signer {
                        let funding = match self.implicit_funding {
                            Some(funding) => funding,
                            None => {
                                let funding = self.accounts[&signer].balance(id) == 0;
                                self.implicit_funding = Some(funding);
                                funding
                            }
                        };
                        if funding {
                            self.credit(&signer, id, amount)?;
                        }
                    }
                    self.transfer(&signer, &recipient, id, amount)?;
                }
            }
            Body::MosaicDefinition(definition) => {
                let id = definition.id.0;
                // MosaicId: ID は持ち主と nonce から決まる
                if MosaicId::generate(&Address(signer), definition.nonce) != definition.id {
                    return Err(invalid(format!(
                        "モザイク {id:016X} は {} の nonce {} のものではありません",
                        Address(signer),
                        definition.nonce
                    )));
                }
                // MosaicFlags: Revokable は国庫の再発行の高さから
                let flags = definition.flags.bits();
                let all = if height < self.config.treasury_reissuance_height {
                    MOSAIC_FLAGS_ALL & !MosaicFlags::REVOKABLE.bits()
                } else {
                    MOSAIC_FLAGS_ALL
                };
                if flags > all {
                    return Err(invalid(format!("モザイク {id:016X} のフラグ {flags:#X}")));
                }
                // MosaicAvailability: 作り直せるのは、生きていて持ち主が同じで、何か変わり、発行量が 0 のとき
                if let Some(current) = self.mosaics.get(&id) {
                    if !current.is_active(height) || current.owner != signer {
                        return Err(invalid(format!(
                            "モザイク {id:016X} は作り直せません（生きていないか、持ち主が違う）"
                        )));
                    }
                    let changes = flags != 0
                        || definition.divisibility != 0
                        || (current.duration != 0 && definition.duration != 0);
                    if !changes || current.supply != 0 {
                        return Err(invalid(format!(
                            "モザイク {id:016X} は作り直せません（変わらないか、発行量が残っている）"
                        )));
                    }
                }
                let sink = self.config.mosaic_rental_fee_sink.at(height).0;
                self.add_address(sink, height);
                if !is_nemesis_signer {
                    let fee =
                        self.config.mosaic_rental_fee * u64::from(self.dynamic_fee_multiplier);
                    self.transfer(&signer, &sink, self.config.currency_mosaic_id, fee)?;
                    let receipt =
                        transfer_receipt(signer, sink, self.config.currency_mosaic_id, fee);
                    self.statement
                        .add_receipt(ReceiptBody::MosaicRentalFee(receipt));
                }
                let entry = match self.mosaics.remove(&id) {
                    Some(current) => MosaicEntry {
                        supply: 0,
                        start_height: current.start_height,
                        owner: signer,
                        revision: current.revision + 1,
                        flags: current.flags ^ definition.flags.bits(),
                        divisibility: current.divisibility ^ definition.divisibility,
                        duration: current.duration + definition.duration,
                    },
                    None => MosaicEntry {
                        supply: 0,
                        start_height: height,
                        owner: signer,
                        revision: 1,
                        flags: definition.flags.bits(),
                        divisibility: definition.divisibility,
                        duration: definition.duration,
                    },
                };
                self.mosaics.insert(id, entry);
                self.schedule_mosaic_receipt(id);
                self.touch(SubCache::Mosaic, &id.to_le_bytes());
            }
            Body::MosaicSupplyChange(change) => {
                let id = self.resolve_mosaic(change.mosaic_id.0)?;
                // RequiredMosaic と MosaicSupplyChangeAllowed
                let entry = self.check_mosaic_owner(height, id, &signer)?;
                let owned = self
                    .accounts
                    .get(&signer)
                    .map_or(0, |account| account.balance(id));
                let mutable = entry.flags & MosaicFlags::SUPPLY_MUTABLE.bits() != 0;
                if !mutable && owned != entry.supply {
                    return Err(invalid(format!(
                        "モザイク {id:016X} の発行量は、持ち主が全部持っていないと変えられません"
                    )));
                }
                let allowed = match change.action {
                    MosaicSupplyChangeAction::Increase => entry
                        .supply
                        .checked_add(change.delta)
                        .is_some_and(|supply| supply <= self.config.max_mosaic_atomic_units),
                    MosaicSupplyChangeAction::Decrease => owned >= change.delta,
                };
                if !allowed {
                    return Err(invalid(format!(
                        "モザイク {id:016X} の発行量を {} 変えられません",
                        change.delta
                    )));
                }
                self.touch(SubCache::Mosaic, &id.to_le_bytes());
                let entry = self
                    .mosaics
                    .get_mut(&id)
                    .ok_or_else(|| invalid(format!("モザイク {id:016X} がありません")))?;
                let owner = entry.owner;
                match change.action {
                    MosaicSupplyChangeAction::Increase => {
                        entry.supply += change.delta;
                        self.credit(&owner, id, change.delta)?;
                    }
                    MosaicSupplyChangeAction::Decrease => {
                        entry.supply -= change.delta;
                        self.debit(&owner, id, change.delta)?;
                    }
                }
            }
            Body::MosaicSupplyRevocation(revocation) => {
                // 発行量は変えず、持っているアカウントから持ち主へ移す
                let source = self.resolve_address(&revocation.source_address)?;
                let id = self.resolve_mosaic(revocation.mosaic.mosaic_id.0)?;
                // RequiredMosaic: 持ち主が、Revokable のモザイクだけ（Nemesis の署名者はフラグを問わない）
                let entry = self.check_mosaic_owner(height, id, &signer)?;
                if signer != self.nemesis && entry.flags & MosaicFlags::REVOKABLE.bits() == 0 {
                    return Err(invalid(format!("モザイク {id:016X} は取り上げられません")));
                }
                self.transfer(&source, &signer, id, revocation.mosaic.amount)?;
            }
            Body::NamespaceRegistration(registration) => {
                let sink = self.config.namespace_rental_fee_sink.at(height).0;
                self.add_address(sink, height);
                let id = registration.id.0;
                match registration.registration_type {
                    NamespaceRegistrationType::Root { duration } => {
                        if !is_nemesis_signer && duration != 0 {
                            let fee = self.config.root_namespace_rental_fee_per_block
                                * duration
                                * u64::from(self.dynamic_fee_multiplier);
                            self.transfer(&signer, &sink, self.config.currency_mosaic_id, fee)?;
                            let receipt =
                                transfer_receipt(signer, sink, self.config.currency_mosaic_id, fee);
                            self.statement
                                .add_receipt(ReceiptBody::NamespaceRentalFee(receipt));
                        }
                        self.register_root(height, signer, id, duration)?;
                    }
                    NamespaceRegistrationType::Child { parent_id } => {
                        self.check_child_namespace(height, &signer, id, parent_id.0)?;
                        if !is_nemesis_signer {
                            let fee = self.config.child_namespace_rental_fee
                                * u64::from(self.dynamic_fee_multiplier);
                            self.transfer(&signer, &sink, self.config.currency_mosaic_id, fee)?;
                            let receipt =
                                transfer_receipt(signer, sink, self.config.currency_mosaic_id, fee);
                            self.statement
                                .add_receipt(ReceiptBody::NamespaceRentalFee(receipt));
                        }
                        let mut path = self
                            .namespace_paths
                            .get(&parent_id.0)
                            .ok_or_else(|| invalid("親のネームスペースがありません"))?
                            .clone();
                        path.push(id);
                        self.touch(SubCache::Namespace, &path[0].to_le_bytes());
                        self.namespaces
                            .get_mut(&path[0])
                            .expect("path points to a root")
                            .children
                            .insert(path[1..].to_vec(), Alias::None);
                        self.namespace_paths.insert(id, path);
                    }
                }
            }
            Body::MosaicAlias(alias) => {
                let value = match alias.alias_action {
                    AliasAction::Link => Alias::Mosaic(alias.mosaic_id.0),
                    AliasAction::Unlink => Alias::None,
                };
                let data = Alias::Mosaic(alias.mosaic_id.0);
                self.check_alias(
                    height,
                    &signer,
                    alias.namespace_id.0,
                    alias.alias_action,
                    data,
                )?;
                self.set_alias(alias.namespace_id.0, value)?;
            }
            Body::AddressAlias(alias) => {
                let value = match alias.alias_action {
                    AliasAction::Link => Alias::Address(alias.address.0),
                    AliasAction::Unlink => Alias::None,
                };
                let data = Alias::Address(alias.address.0);
                self.check_alias(
                    height,
                    &signer,
                    alias.namespace_id.0,
                    alias.alias_action,
                    data,
                )?;
                // AddressAlias: 指すアカウントがあること
                if !self.accounts.contains_key(&alias.address.0) {
                    return Err(invalid(format!(
                        "別名の指す {} のアカウントがありません",
                        alias.address
                    )));
                }
                self.set_alias(alias.namespace_id.0, value)?;
            }
            Body::MultisigAccountModification(modification) => {
                self.apply_multisig(height, signer, modification)?;
            }
            Body::AccountKeyLink(link) => {
                let remote_key = link.linked_public_key;
                match link.link_action {
                    LinkAction::Link => {
                        let remote = self.add_public_key(&remote_key, height);
                        let main = self.account_mut(&signer)?;
                        main.linked = Some(remote_key.0);
                        main.account_type = AccountType::Main;
                        let remote = self.account_mut(&remote)?;
                        remote.linked = Some(signer_key.0);
                        remote.account_type = AccountType::Remote;
                    }
                    LinkAction::Unlink => {
                        let remote = self.address_of(&remote_key);
                        let main = self.account_mut(&signer)?;
                        main.linked = None;
                        main.account_type = AccountType::Unlinked;
                        let remote = self.account_mut(&remote)?;
                        remote.linked = None;
                        remote.account_type = AccountType::RemoteUnlinked;
                    }
                }
            }
            Body::VrfKeyLink(link) | Body::NodeKeyLink(link) => {
                let value = match link.link_action {
                    LinkAction::Link => Some(link.linked_public_key.0),
                    LinkAction::Unlink => None,
                };
                let account = self.account_mut(&signer)?;
                if matches!(body, Body::VrfKeyLink(_)) {
                    account.vrf = value;
                } else {
                    account.node = value;
                }
            }
            Body::VotingKeyLink(link) => {
                let key = VotingKey {
                    key: link.linked_public_key.0,
                    start_epoch: link.start_epoch,
                    end_epoch: link.end_epoch,
                };
                let voting = &mut self.account_mut(&signer)?.voting;
                match link.link_action {
                    LinkAction::Link => {
                        let at =
                            voting.partition_point(|other| other.start_epoch < key.start_epoch);
                        voting.insert(at, key);
                    }
                    LinkAction::Unlink => {
                        let at = voting
                            .iter()
                            .position(|other| *other == key)
                            .ok_or_else(|| invalid("外す投票の鍵がありません"))?;
                        voting.remove(at);
                    }
                }
            }
            Body::AccountMetadata(metadata) => {
                self.apply_metadata(signer, metadata, 0, MetadataType::Account)?;
            }
            Body::MosaicMetadata(metadata) => {
                let id = self.resolve_mosaic(metadata.target_mosaic_id.0)?;
                self.apply_metadata(signer, &metadata.metadata, id, MetadataType::Mosaic)?;
            }
            Body::NamespaceMetadata(metadata) => {
                let id = metadata.target_namespace_id.0;
                self.apply_metadata(signer, &metadata.metadata, id, MetadataType::Namespace)?;
            }
            Body::HashLock(lock) => {
                let mosaic_id = self.resolve_mosaic(lock.mosaic.mosaic_id.0)?;
                self.debit(&signer, mosaic_id, lock.mosaic.amount)?;
                self.statement
                    .add_receipt(ReceiptBody::LockHashCreated(change(
                        signer,
                        mosaic_id,
                        lock.mosaic.amount,
                    )));
                self.hash_locks
                    .get_or_insert_with(lock.hash.0, Vec::new)
                    .push(HashLockInfo {
                        owner: signer,
                        mosaic_id,
                        amount: lock.mosaic.amount,
                        end_height: height + lock.duration,
                        status: LockStatus::Unused,
                    });
                self.touch(SubCache::HashLockInfo, &lock.hash.0);
                self.expire_at(height + lock.duration, SubCache::HashLockInfo, &lock.hash.0);
            }
            Body::SecretLock(lock) => {
                let recipient = self.resolve_address(&lock.recipient_address)?;
                self.add_address(recipient, height);
                let mosaic_id = self.resolve_mosaic(lock.mosaic.mosaic_id.0)?;
                self.debit(&signer, mosaic_id, lock.mosaic.amount)?;
                self.statement
                    .add_receipt(ReceiptBody::LockSecretCreated(change(
                        signer,
                        mosaic_id,
                        lock.mosaic.amount,
                    )));
                let key = secret_lock_key(&lock.secret, &Address(recipient));
                self.secret_locks
                    .entry(key.0)
                    .or_default()
                    .push(SecretLockInfo {
                        owner: signer,
                        mosaic_id,
                        amount: lock.mosaic.amount,
                        end_height: height + lock.duration,
                        status: LockStatus::Unused,
                        hash_algorithm: hash_algorithm_byte(lock.hash_algorithm),
                        secret: lock.secret.0,
                        recipient,
                    });
                self.touch(SubCache::SecretLockInfo, &key.0);
                self.stale_secret_locks.remove(&key.0);
                self.expire_at(height + lock.duration, SubCache::SecretLockInfo, &key.0);
            }
            Body::SecretProof(proof) => {
                // ProofSecret: 証明の長さと、そのハッシュがシークレットになること
                let size = proof.proof.len() as u64;
                if size < self.config.min_proof_size || size > self.config.max_proof_size {
                    return Err(invalid(format!("証明の長さ {size} が範囲の外です")));
                }
                if proof.hash_algorithm.secret(&proof.proof) != proof.secret {
                    return Err(invalid(format!(
                        "証明がシークレット {} に合いません",
                        proof.secret
                    )));
                }
                let recipient = self.resolve_address(&proof.recipient_address)?;
                let key = secret_lock_key(&proof.secret, &Address(recipient));
                // Proof: ロックが生きていて（使っていない、切れていない）、ハッシュの種類が同じこと
                let algorithm = hash_algorithm_byte(proof.hash_algorithm);
                let usable = self
                    .secret_locks
                    .get(&key.0)
                    .and_then(|history| history.last())
                    .is_some_and(|lock| {
                        lock.status == LockStatus::Unused
                            && height < lock.end_height
                            && lock.hash_algorithm == algorithm
                    });
                if !usable {
                    return Err(invalid(format!(
                        "シークレットロック {key} は生きていないか、ハッシュの種類が違います"
                    )));
                }
                self.touch(SubCache::SecretLockInfo, &key.0);
                self.stale_secret_locks.remove(&key.0);
                let lock = self
                    .secret_locks
                    .get_mut(&key.0)
                    .and_then(|history| history.last_mut())
                    .ok_or_else(|| invalid(format!("シークレットロック {key} がありません")))?;
                lock.status = LockStatus::Used;
                let (to, mosaic_id, amount) = (lock.recipient, lock.mosaic_id, lock.amount);
                self.credit(&to, mosaic_id, amount)?;
                self.statement
                    .add_receipt(ReceiptBody::LockSecretCompleted(change(
                        to, mosaic_id, amount,
                    )));
            }
            Body::AccountAddressRestriction(restriction) => {
                let flags = restriction.restriction_flags.bits();
                let mut additions = Vec::new();
                for value in restriction.restriction_additions.iter() {
                    additions.push(self.resolve_address(value)?.to_vec());
                }
                let mut deletions = Vec::new();
                for value in restriction.restriction_deletions.iter() {
                    deletions.push(self.resolve_address(value)?.to_vec());
                }
                self.apply_account_restriction(signer, flags, additions, deletions);
            }
            Body::AccountMosaicRestriction(restriction) => {
                let flags = restriction.restriction_flags.bits();
                let mut additions = Vec::new();
                for value in restriction.restriction_additions.iter() {
                    additions.push(self.resolve_mosaic(value.0)?.to_le_bytes().to_vec());
                }
                let mut deletions = Vec::new();
                for value in restriction.restriction_deletions.iter() {
                    deletions.push(self.resolve_mosaic(value.0)?.to_le_bytes().to_vec());
                }
                self.apply_account_restriction(signer, flags, additions, deletions);
            }
            Body::AccountOperationRestriction(restriction) => {
                let flags = restriction.restriction_flags.bits();
                let values = |list: &[heika_transaction::TransactionType]| {
                    list.iter()
                        .map(|value| value.0.to_le_bytes().to_vec())
                        .collect()
                };
                self.apply_account_restriction(
                    signer,
                    flags,
                    values(&restriction.restriction_additions),
                    values(&restriction.restriction_deletions),
                );
            }
            Body::MosaicGlobalRestriction(restriction) => {
                let mosaic_id = self.resolve_mosaic(restriction.mosaic_id.0)?;
                let reference = self.resolve_mosaic(restriction.reference_mosaic_id.0)?;
                let key = mosaic_restriction_key(mosaic_id, &[0; 24]);
                self.touch(SubCache::MosaicRestriction, &key);
                let entry = self.mosaic_restrictions.entry(key).or_insert_with(|| {
                    MosaicRestrictionEntry::Global {
                        mosaic_id,
                        rules: BTreeMap::new(),
                    }
                });
                let MosaicRestrictionEntry::Global { rules, .. } = entry else {
                    return Err(invalid("全体の制限のキーがアドレスの制限です"));
                };
                let restriction_type = mosaic_restriction_type(restriction.new_restriction_type);
                if restriction_type == 0 {
                    rules.remove(&restriction.restriction_key);
                } else {
                    rules.insert(
                        restriction.restriction_key,
                        (
                            reference,
                            restriction.new_restriction_value,
                            restriction_type,
                        ),
                    );
                }
                if entry.is_empty() {
                    self.mosaic_restrictions.remove(&key);
                }
            }
            Body::MosaicAddressRestriction(restriction) => {
                let mosaic_id = self.resolve_mosaic(restriction.mosaic_id.0)?;
                let address = self.resolve_address(&restriction.target_address)?;
                let key = mosaic_restriction_key(mosaic_id, &address);
                self.touch(SubCache::MosaicRestriction, &key);
                let entry = self.mosaic_restrictions.entry(key).or_insert_with(|| {
                    MosaicRestrictionEntry::Address {
                        mosaic_id,
                        address,
                        values: BTreeMap::new(),
                    }
                });
                let MosaicRestrictionEntry::Address { values, .. } = entry else {
                    return Err(invalid("アドレスの制限のキーが全体の制限です"));
                };
                if restriction.new_restriction_value == MOSAIC_RESTRICTION_REMOVAL {
                    values.remove(&restriction.restriction_key);
                } else {
                    values.insert(
                        restriction.restriction_key,
                        restriction.new_restriction_value,
                    );
                }
                if entry.is_empty() {
                    self.mosaic_restrictions.remove(&key);
                }
            }
            other => {
                let name = format!("{other:?}");
                let name = name.split(['(', ' ', '{']).next().unwrap_or("?");
                return Err(ExecError::Unsupported(name.to_owned()));
            }
        }
        Ok(())
    }

    fn register_root(
        &mut self,
        height: u64,
        owner: [u8; 24],
        id: u64,
        duration: u64,
    ) -> Result<(), ExecError> {
        let new_end = if duration == 0 {
            u64::MAX
        } else {
            height + duration + self.config.namespace_grace_period
        };
        // RootNamespaceAvailability: 期限なしは Nemesis だけ。期限なしのものは取り直せない。
        // 猶予のあいだも含めて生きているあいだは、持ち主しか更新できない
        if height != 1 && duration == 0 {
            return Err(invalid(format!(
                "ネームスペース {id:016X} を期限なしで取れるのは Nemesis だけです"
            )));
        }
        if let Some(root) = self.namespaces.get(&id) {
            if root.end == u64::MAX || duration == 0 {
                return Err(invalid(format!(
                    "ネームスペース {id:016X} は期限なしなので取り直せません"
                )));
            }
            if root.start <= height && height < root.end && root.owner != owner {
                return Err(invalid(format!(
                    "ネームスペース {id:016X} はほかの人のものです"
                )));
            }
        }
        self.touch(SubCache::Namespace, &id.to_le_bytes());
        if let Some(root) = self.namespaces.get_mut(&id)
            && root.start <= height
            && height < root.end
            && root.owner == owner
        {
            // 猶予のあいだも含めて、持ち主の更新は今の終わりに期間を足す。子と別名はそのまま
            if root.end != u64::MAX {
                root.end += duration;
                let end = root.end;
                self.expire_at(end, SubCache::Namespace, &id.to_le_bytes());
                self.schedule_namespace_receipts(id, end);
            }
            return Ok(());
        }
        // 新しく取るか、期限が切れたものや持ち主の替わるものを取り直す。前の子と別名は引き継がない
        if let Some(previous) = self.namespaces.remove(&id) {
            for path in previous.children.keys() {
                self.namespace_paths
                    .remove(path.last().expect("child paths are not empty"));
            }
        }
        self.namespaces.insert(
            id,
            RootNamespace {
                owner,
                start: height,
                end: new_end,
                alias: Alias::None,
                children: BTreeMap::new(),
            },
        );
        self.namespace_paths.insert(id, vec![id]);
        self.expire_at(new_end, SubCache::Namespace, &id.to_le_bytes());
        self.schedule_namespace_receipts(id, new_end);
        Ok(())
    }

    /// 猶予を含めて `end` で終わるルートのネームスペースの、期限切れと消えたときのレシートを出す高さを覚える
    fn schedule_namespace_receipts(&mut self, id: u64, end: u64) {
        if end == u64::MAX {
            return;
        }
        for height in [end - self.config.namespace_grace_period, end] {
            self.artifact_expiries
                .entry(height)
                .or_default()
                .insert(Artifact::Namespace(id));
        }
    }

    /// モザイクの期限切れのレシートを出す高さを覚える。期限のないものは何もしない
    fn schedule_mosaic_receipt(&mut self, id: u64) {
        let Some(entry) = self.mosaics.get(&id).filter(|entry| entry.duration != 0) else {
            return;
        };
        self.artifact_expiries
            .entry(entry.start_height + entry.duration)
            .or_default()
            .insert(Artifact::Mosaic(id));
    }

    fn apply_multisig(
        &mut self,
        height: u64,
        multisig: [u8; 24],
        modification: &heika_transaction::MultisigAccountModification,
    ) -> Result<(), ExecError> {
        let mut additions = Vec::new();
        for address in modification.address_additions.iter() {
            let address = self.resolve_address(address)?;
            self.add_address(address, height);
            additions.push(address);
        }
        let mut deletions = Vec::new();
        for address in modification.address_deletions.iter() {
            deletions.push(self.resolve_address(address)?);
        }
        for address in std::iter::once(&multisig)
            .chain(&additions)
            .chain(&deletions)
        {
            self.touch(SubCache::Multisig, address);
        }
        let entry = self
            .multisigs
            .get_or_insert_with(multisig, Default::default);
        entry.min_approval = entry
            .min_approval
            .checked_add_signed(i32::from(modification.min_approval_delta))
            .ok_or_else(|| invalid("min approval"))?;
        entry.min_removal = entry
            .min_removal
            .checked_add_signed(i32::from(modification.min_removal_delta))
            .ok_or_else(|| invalid("min removal"))?;
        for address in &deletions {
            entry.cosignatories.remove(address);
        }
        for address in &additions {
            entry.cosignatories.insert(*address);
        }
        for address in deletions {
            let cosignatory = self.multisigs.get_or_insert_with(address, Default::default);
            cosignatory.multisigs.remove(&multisig);
            self.remove_multisig_if_empty(&address);
        }
        for address in additions {
            self.multisigs
                .get_or_insert_with(address, Default::default)
                .multisigs
                .insert(multisig);
        }
        self.remove_multisig_if_empty(&multisig);
        Ok(())
    }

    /// catapult の `MetadataValueObserver`。値は前の値との XOR で届く
    fn apply_metadata(
        &mut self,
        source: [u8; 24],
        metadata: &heika_transaction::Metadata,
        target_id: u64,
        metadata_type: MetadataType,
    ) -> Result<(), ExecError> {
        // 対象の持ち主のアカウントも作られる（AccountAddressNotification）
        let target = self.resolve_address(&metadata.target_address)?;
        self.add_address(target, self.height + 1);
        let key = MetadataKey {
            source_address: Address(source),
            target_address: Address(target),
            scoped_metadata_key: metadata.scoped_metadata_key,
            target_id,
            metadata_type,
        };
        let mut size = metadata.value.len() as i32;
        if metadata.value_size_delta < 0 {
            size += i32::from(metadata.value_size_delta);
        }
        let size = usize::try_from(size).map_err(|_| invalid("メタデータの長さ"))?;
        let update = &metadata.value[..size];
        let unique = key.unique_key().0;
        self.touch(SubCache::Metadata, &unique);
        match self.metadata.get_mut(&unique) {
            None => {
                self.metadata.insert(unique, (key, update.to_vec()));
            }
            Some(_) if size == 0 => {
                self.metadata.remove(&unique);
            }
            Some((_, value)) => {
                value.resize(size, 0);
                for (byte, delta) in value.iter_mut().zip(update) {
                    *byte ^= delta;
                }
            }
        }
        Ok(())
    }

    /// catapult の `AccountRestrictionValueModificationObserver`。足すものを先に、外すものをあとに1つずつ
    fn apply_account_restriction(
        &mut self,
        address: [u8; 24],
        flags: u16,
        additions: Vec<Vec<u8>>,
        deletions: Vec<Vec<u8>>,
    ) {
        self.touch(SubCache::AccountRestriction, &address);
        let directional = flags & !RESTRICTION_BLOCK;
        let block = flags & RESTRICTION_BLOCK != 0;
        let restrictions = self
            .account_restrictions
            .entry(address)
            .or_insert_with(new_account_restrictions);
        let restriction = restrictions
            .get_mut(&directional)
            .expect("all four directional flags exist");
        for (value, add) in additions
            .into_iter()
            .map(|value| (value, true))
            .chain(deletions.into_iter().map(|value| (value, false)))
        {
            if block {
                restriction.descriptor = directional | RESTRICTION_BLOCK;
            }
            if add {
                restriction.values.insert(value);
            } else {
                restriction.values.remove(&value);
            }
            if !block {
                restriction.descriptor = directional;
                if restriction.values.is_empty() {
                    restriction.descriptor |= RESTRICTION_BLOCK;
                }
            }
        }
        if restrictions
            .values()
            .all(|restriction| restriction.values.is_empty())
        {
            self.account_restrictions.remove(&address);
        }
    }

    fn remove_multisig_if_empty(&mut self, address: &[u8; 24]) {
        if self
            .multisigs
            .get(address)
            .is_some_and(|entry| entry.cosignatories.is_empty() && entry.multisigs.is_empty())
        {
            self.multisigs.remove(address);
        }
    }

    // endregion

    // region: ブロック

    fn apply_block_notifications(
        &mut self,
        height: u64,
        block: &Block,
        total_fee: u64,
    ) -> Result<(), ExecError> {
        let harvester = self.add_public_key(&block.signer_public_key, height);
        let beneficiary = block.beneficiary_address.0;
        if harvester != beneficiary {
            self.add_address(beneficiary, height);
        }
        // Beneficiary
        let importance_height = self.config.importance_height(height);
        let forwarded_beneficiary = self.forwarded(&beneficiary)?;
        self.account_mut(&forwarded_beneficiary)?
            .try_update_bucket(importance_height, |bucket| bucket.beneficiary_count += 1);
        // MosaicSupplyInflation: インフレの分は通貨のモザイクの発行量にも足す
        let inflation = self.config.inflation_at(height);
        if inflation > 0 {
            let currency = self.config.currency_mosaic_id;
            self.touch(SubCache::Mosaic, &currency.to_le_bytes());
            self.mosaics
                .get_mut(&currency)
                .ok_or_else(|| invalid("通貨のモザイクがありません"))?
                .supply += inflation;
        }
        // HarvestFee
        let total = total_fee + inflation;
        let network_amount = total * self.config.harvest_network_percentage / 100;
        let beneficiary_amount =
            if self.config.harvest_beneficiary_percentage > 0 && harvester != beneficiary {
                total * self.config.harvest_beneficiary_percentage / 100
            } else {
                0
            };
        let harvester_amount = total - network_amount - beneficiary_amount;
        let currency = self.config.currency_mosaic_id;
        // レシートは、手数料を受け取ったアカウント（Remote ならメインのアカウント）ごとに出す。ハーベストした人には0でも出す
        let to = self.forwarded(&harvester)?;
        self.credit(&to, currency, harvester_amount)?;
        self.statement.add_receipt(ReceiptBody::HarvestFee(change(
            to,
            currency,
            harvester_amount,
        )));
        if network_amount > 0 {
            let sink = self.config.harvest_network_fee_sink.at(height).0;
            let to = self.forwarded(&sink)?;
            self.credit(&to, currency, network_amount)?;
            self.statement.add_receipt(ReceiptBody::HarvestFee(change(
                to,
                currency,
                network_amount,
            )));
        }
        if beneficiary_amount > 0 {
            let to = self.forwarded(&beneficiary)?;
            self.credit(&to, currency, beneficiary_amount)?;
            self.statement.add_receipt(ReceiptBody::HarvestFee(change(
                to,
                currency,
                beneficiary_amount,
            )));
        }
        if inflation > 0 {
            self.statement
                .add_receipt(ReceiptBody::Inflation(ReceiptMosaic {
                    mosaic_id: MosaicId(currency),
                    amount: inflation,
                }));
        }
        // ExpiredHashLockInfo: この高さで切れた、使われなかったロックはハーベストした人のものになる
        // どのロックがこの高さで切れるかは、木から外す予定（expiries）に入っている。全部のロックを見ると、
        // ロックが増えるほどブロックごとに重くなる
        let expired: Vec<(u64, u64)> = self
            .locks_due(height, SubCache::HashLockInfo)
            .iter()
            .filter_map(|key| self.hash_locks.get(key)?.last())
            .filter(|lock| lock.end_height == height && lock.status == LockStatus::Unused)
            .map(|lock| (lock.mosaic_id, lock.amount))
            .collect();
        if !expired.is_empty() {
            let to = self.forwarded(&harvester)?;
            let mut receipts = Vec::new();
            for (mosaic_id, amount) in expired {
                self.credit(&to, mosaic_id, amount)?;
                receipts.push(ReceiptBody::LockHashExpired(change(to, mosaic_id, amount)));
            }
            self.add_sorted_receipts(receipts);
        }
        // ExpiredSecretLockInfo: この高さで切れるロックを持つ履歴のうち、最後が使われていなければ持ち主に返す。
        // 決まった高さでは、処理しないか、最後の終わりがこの高さでなくても返す
        if self.config.skip_secret_lock_expirations.contains(&height) {
            // 触らないので、この高さで切れるものは木に残る
            let stale: Vec<[u8; 32]> = self
                .secret_locks
                .iter()
                .filter(|(_, history)| {
                    history.last().is_some_and(|lock| {
                        lock.status == LockStatus::Unused && lock.end_height == height
                    })
                })
                .map(|(key, _)| *key)
                .collect();
            self.stale_secret_locks.extend(stale);
        } else {
            // この高さで切れるものを持つ履歴は、どれも触ったことになり、木で見直される
            let touched: Vec<[u8; 32]> = self
                .stale_secret_locks
                .iter()
                .filter(|key| {
                    self.secret_locks[*key]
                        .iter()
                        .any(|lock| lock.end_height == height)
                })
                .copied()
                .collect();
            for key in touched {
                self.stale_secret_locks.remove(&key);
                self.touch(SubCache::SecretLockInfo, &key);
            }
            let forced = self.config.force_secret_lock_expirations.contains(&height);
            let refunds: Vec<([u8; 24], u64, u64)> = self
                .locks_due(height, SubCache::SecretLockInfo)
                .iter()
                .filter_map(|key| self.secret_locks.get(key))
                .filter(|history| history.iter().any(|lock| lock.end_height == height))
                .filter_map(|history| history.last())
                .filter(|lock| {
                    lock.status == LockStatus::Unused && (lock.end_height == height || forced)
                })
                .map(|lock| (lock.owner, lock.mosaic_id, lock.amount))
                .collect();
            let mut receipts = Vec::new();
            for (owner, mosaic_id, amount) in refunds {
                self.credit(&owner, mosaic_id, amount)?;
                receipts.push(ReceiptBody::LockSecretExpired(change(
                    owner, mosaic_id, amount,
                )));
            }
            self.add_sorted_receipts(receipts);
        }
        self.add_expiry_receipts(height);
        Ok(())
    }

    /// 期限切れのロックのレシート。catapult はレシートのバイト列の順に並べてから足す（`ExpiredLockInfoObserver`）
    fn add_sorted_receipts(&mut self, receipts: Vec<ReceiptBody>) {
        let mut receipts: Vec<_> = receipts
            .into_iter()
            .map(|body| {
                (
                    heika_block::statement::Receipt { version: 1, body }.to_bytes(),
                    body,
                )
            })
            .collect();
        receipts.sort_by(|left, right| left.0.cmp(&right.0));
        for (_, body) in receipts {
            self.statement.add_receipt(body);
        }
    }

    /// モザイクとネームスペースの期限切れのレシート。catapult の `CreateCacheBlockTouchObserver` で、ID の順に出す。
    /// ネームスペースは、猶予に入る高さで期限切れ、猶予が明ける高さで消えたことになる
    fn add_expiry_receipts(&mut self, height: u64) {
        let Some(candidates) = self.artifact_expiries.remove(&height) else {
            return;
        };
        let grace = self.config.namespace_grace_period;
        let (mut expired, mut deleted, mut mosaics) = (Vec::new(), Vec::new(), Vec::new());
        // 覚えたあとで期限が延びたり、持ち主が替わったりしたものもあるので、今の期限と照らす
        for artifact in candidates {
            match artifact {
                Artifact::Namespace(id) => {
                    let Some(root) = self.namespaces.get(&id).filter(|root| root.start < height)
                    else {
                        continue;
                    };
                    if root.end == height + grace {
                        expired.push(id);
                    }
                    if root.end == height {
                        deleted.push(id);
                    }
                }
                Artifact::Mosaic(id) => {
                    if self.mosaics.get(&id).is_some_and(|entry| {
                        entry.duration != 0 && entry.start_height + entry.duration == height
                    }) {
                        mosaics.push(id);
                    }
                }
            }
        }
        for id in expired {
            self.statement
                .add_receipt(ReceiptBody::NamespaceExpired(NamespaceId(id)));
        }
        for id in deleted {
            self.statement
                .add_receipt(ReceiptBody::NamespaceDeleted(NamespaceId(id)));
        }
        for id in mosaics {
            self.statement
                .add_receipt(ReceiptBody::MosaicExpired(MosaicId(id)));
        }
    }

    /// catapult の `NemesisSink`。Nemesis のあとは Nemesis の鍵で署名できない。国庫の再発行の高さでだけ、
    /// 設定にある署名を認める。ブロック、トランザクション、連署の署名のどれにも効く
    fn check_nemesis_sink(
        &self,
        height: u64,
        signer: &PublicKey,
        signature: &heika_core::signature::Signature,
    ) -> Result<(), ExecError> {
        if *signer != self.config.nemesis_signer_public_key
            || (height == self.config.treasury_reissuance_height
                && self
                    .config
                    .treasury_reissuance_transaction_signatures
                    .contains(signature))
        {
            return Ok(());
        }
        Err(invalid(format!(
            "高さ {height} で Nemesis の鍵の署名 {signature} があります"
        )))
    }

    /// catapult の `EligibleHarvester` のうち、残高。ブロックのトランザクションを当てたあと、手数料を受け取る前の、
    /// リモートならメインのアカウントの残高が、minHarvesterBalance 以上 maxHarvesterBalance 以下であること。
    /// importance が 0 でないことは、当たりを確かめるときに済んでいる
    fn check_harvester_balance(&self, signer: &PublicKey) -> Result<(), ExecError> {
        let mut address = self.address_of(signer);
        let account = self
            .accounts
            .get(&address)
            .ok_or_else(|| invalid("ブロックを出した人のアカウントがありません"))?;
        if account.account_type == AccountType::Remote {
            let main = account
                .linked
                .ok_or_else(|| invalid("Remote のアカウントにリンクがありません"))?;
            address = self.address_of(&PublicKey(main));
        }
        let balance = self.accounts.get(&address).map_or(0, |account| {
            account.balance(self.config.harvesting_mosaic_id)
        });
        let (min, max) = (
            self.config.min_harvester_balance,
            self.config.max_harvester_balance,
        );
        if !(min..=max).contains(&balance) {
            return Err(invalid(format!(
                "ブロックを出した人の残高 {balance} が {min}〜{max} の外です"
            )));
        }
        Ok(())
    }

    /// catapult の `ImportanceBlock`。大口のアカウントを見直したあとで数える。
    /// 投票できるのは、投票の鍵を持ち、残高が minVoterBalance 以上のアカウント。
    /// totalVotingBalanceCalculationFix からは、そのブロックのエポックに鍵があるものだけを数える（国庫の分は外さない）
    fn check_importance_footer(
        &self,
        height: u64,
        footer: &heika_block::ImportanceFooter,
    ) -> Result<(), ExecError> {
        let actual = self.importance_footer(height);
        let expected = (
            footer.voting_eligible_accounts_count,
            footer.harvesting_eligible_accounts_count,
            footer.total_voting_balance,
        );
        if actual != expected {
            return Err(invalid(format!(
                "importance ブロックの足（投票できる数、ハーベストできる数、投票の残高の合計）が {expected:?} で、求めたものは {actual:?} です"
            )));
        }
        Ok(())
    }

    /// 今の状態で決まる importance ブロックの足（投票できる数、ハーベストできる数、投票の残高の合計）
    fn importance_footer(&self, height: u64) -> (u32, u64, u64) {
        let finalization = &self.config.finalization;
        let epoch = if height < self.config.total_voting_balance_calculation_fix {
            None
        } else {
            let grouping = finalization.voting_set_grouping;
            Some(1 + u64::from(!height.is_multiple_of(grouping)) + height / grouping)
        };
        let mosaic = self.config.harvesting_mosaic_id;
        let (mut count, mut total) = (0u32, 0u64);
        // 投票の残高の下限は、大口の下限より高いので、大口の中を見れば足りる
        for address in &self.high_value {
            let Some(account) = self.accounts.get(address) else {
                continue;
            };
            let balance = account.balance(mosaic);
            if account.voting.is_empty() || balance < finalization.min_voter_balance {
                continue;
            }
            if let Some(epoch) = epoch
                && !account.voting.iter().any(|key| {
                    u64::from(key.start_epoch) <= epoch && epoch <= u64::from(key.end_epoch)
                })
            {
                continue;
            }
            count += 1;
            total += balance;
        }
        (count, self.high_value.len() as u64, total)
    }

    /// catapult の `HighValueAccountsUpdater::updateHarvestingAccounts`。触ったアカウントだけを見直す
    fn update_high_value(&mut self) {
        let min = self.config.min_harvester_balance;
        let mosaic = self.config.harvesting_mosaic_id;
        for address in &self.touched {
            let Some(account) = self.accounts.get(address) else {
                continue;
            };
            if account.balance(mosaic) >= min {
                self.high_value.insert(*address);
                self.removed.remove(address);
            } else {
                let was = self.high_value.remove(address);
                if was || account.has_history() {
                    self.removed.insert(*address);
                }
            }
        }
    }

    /// catapult の `PosImportanceCalculator::recalculate`。
    fn recalculate_importances(&mut self, importance_height: u64) {
        for set in [&self.high_value, &self.removed] {
            self.dirty_accounts.extend(set.iter().copied());
            self.unsaved_accounts.extend(set.iter().copied());
        }
        let grouping = self.config.importance_grouping;
        let previous = |count: u64| {
            let adjustment = grouping * count;
            if importance_height > adjustment {
                importance_height - adjustment
            } else {
                1
            }
        };
        let previous_height = if importance_height == 1 {
            0
        } else {
            previous(1)
        };
        // Activity_Bucket_History_Size - Rollback_Buffer_Size - 1
        let min_height = previous(4);
        let mosaic = self.config.harvesting_mosaic_id;
        let tci = u128::from(self.config.total_chain_importance);
        let percentage = u128::from(self.config.importance_activity_percentage);
        let min_balance = u128::from(self.config.min_harvester_balance);

        struct Summary {
            address: [u8; 24],
            balance: u128,
            fees: u64,
            beneficiaries: u32,
            previous_importance: u64,
        }
        let mut summaries = Vec::with_capacity(self.high_value.len());
        let mut active = 0u128;
        let mut total_fees = 0u64;
        let mut total_beneficiaries = 0u32;
        for address in &self.high_value {
            let account = &self.accounts[address];
            let mut summary = Summary {
                address: *address,
                balance: u128::from(account.balance(mosaic)),
                fees: 0,
                beneficiaries: 0,
                previous_importance: 0,
            };
            for bucket in &account.buckets {
                if bucket.start_height < min_height {
                    break;
                }
                summary.fees += bucket.total_fees_paid;
                summary.beneficiaries += bucket.beneficiary_count;
                if bucket.start_height == previous_height {
                    summary.previous_importance = bucket.raw_score;
                }
            }
            active += summary.balance;
            total_fees += summary.fees;
            total_beneficiaries += summary.beneficiaries;
            summaries.push(summary);
        }

        let mut parts = Vec::with_capacity(summaries.len());
        let mut total_activity = 0u64;
        for summary in &summaries {
            let stake = (tci * summary.balance * (100 - percentage) / (active * 100)) as u64;
            let mut fee = 0u128;
            if percentage > 0 && total_fees > 0 {
                fee = tci * u128::from(summary.fees) * (percentage * min_balance * 8)
                    / (u128::from(total_fees) * 1000)
                    / summary.balance;
            }
            let mut beneficiary = 0u128;
            if percentage > 0 && total_beneficiaries > 0 {
                beneficiary =
                    tci * u128::from(summary.beneficiaries) * (percentage * min_balance * 2)
                        / (u128::from(total_beneficiaries) * 1000)
                        / summary.balance;
            }
            let activity = (fee + beneficiary) as u64;
            total_activity = total_activity.wrapping_add(activity);
            parts.push((stake, activity));
        }

        let target_activity =
            self.config.total_chain_importance * self.config.importance_activity_percentage / 100;
        for (summary, (stake, activity)) in summaries.iter().zip(parts) {
            // 活動の点の掛け算は、catapult でも u64 のままで、あふれると折り返す
            let importance = match activity
                .wrapping_mul(target_activity)
                .checked_div(total_activity)
            {
                Some(share) => stake + share,
                None if percentage > 0 => {
                    stake * 100 / (100 - self.config.importance_activity_percentage)
                }
                None => stake,
            };
            let account = self
                .accounts
                .get_mut(&summary.address)
                .expect("high value account exists");
            // FinalizeAccountActivity: その高さの記録がなければ作って、点数を入れる
            if account.buckets[0].start_height < importance_height {
                account.push_bucket(Bucket {
                    start_height: importance_height,
                    ..Bucket::default()
                });
            }
            account.buckets[0].raw_score = importance;
            let effective = if importance_height == 1 {
                importance
            } else {
                importance.min(summary.previous_importance)
            };
            account.push_snapshot(Snapshot {
                importance: effective,
                height: importance_height,
            });
        }

        // processHighValueRemovedAccounts
        let removed = std::mem::take(&mut self.removed);
        for address in removed {
            let Some(account) = self.accounts.get_mut(&address) else {
                continue;
            };
            if account
                .buckets
                .iter()
                .any(|bucket| bucket.start_height == importance_height)
            {
                account.pop_bucket();
            }
            account.push_bucket(Bucket::default());
            account.push_snapshot(Snapshot::default());
            if account.has_history() {
                self.removed.insert(address);
            }
        }
    }

    /// catapult の `BlockStatisticObserver`。直近のブロックの手数料の倍率の中央値
    fn update_dynamic_fee_multiplier(&mut self, fee_multiplier: u32) {
        let count = self.config.max_difficulty_blocks as usize;
        self.fee_multipliers.push_back(fee_multiplier);
        while self.fee_multipliers.len() > count {
            self.fee_multipliers.pop_front();
        }
        let mut values: Vec<u32> = self
            .fee_multipliers
            .iter()
            .copied()
            .filter(|&value| value != 0)
            .collect();
        values.resize(count, self.config.default_dynamic_fee_multiplier);
        let median = count / 2;
        values.select_nth_unstable(median);
        self.dynamic_fee_multiplier = values[median];
    }

    // endregion

    // region: 根

    /// 変わったアカウントの葉だけを置き直す。アカウントは消えないので、外すことはない
    fn account_root(&mut self) -> Hash256 {
        let currency = self.config.currency_mosaic_id;
        let dirty = std::mem::take(&mut self.dirty_accounts);
        let accounts = &self.accounts;
        // アカウントがなければ葉を外す。前へ実行するだけならアカウントは消えないが、巻き戻すと消える
        let leaf = |address: &[u8; 24]| {
            (
                address_key(&Address(*address)),
                accounts
                    .get(address)
                    .map(|account| sha3(&account.to_state_bytes(currency))),
            )
        };
        // 葉の値はアカウントごとに決まるので、たくさんあれば並列に求める。importance を求め直す高さでは、大口が全部変わる
        let leaves: Vec<(Hash256, Option<Hash256>)> = if dirty.len() >= PARALLEL_LEAVES {
            let dirty: Vec<[u8; 24]> = dirty.into_iter().collect();
            dirty.par_iter().map(leaf).collect()
        } else {
            dirty.iter().map(leaf).collect()
        };
        let tree = &mut self.trees[SubCache::AccountState.index()];
        for (key, value) in leaves {
            match value {
                Some(value) => tree.set(key, value),
                None => tree.remove(&key),
            }
        }
        tree.root()
    }

    /// アカウント以外の木の、`key` の葉の値。木に入らなければ `None`
    fn leaf(&self, cache: SubCache, key: &[u8]) -> Option<Hash256> {
        self.state_bytes(cache, key).map(|bytes| sha3(&bytes))
    }

    /// アカウント以外の木の、`key` の葉の値のもとになる、catapult の形のバイト列。木に入らなければ `None`
    fn state_bytes(&self, cache: SubCache, key: &[u8]) -> Option<Vec<u8>> {
        let mut out = 1u16.to_le_bytes().to_vec();
        match cache {
            SubCache::Namespace => {
                let id = u64::from_le_bytes(key.try_into().ok()?);
                // 木に入るのは、猶予を含めた期限前のものだけ（catapult の `RootNamespaceHistory::isActive`）
                let root = self
                    .namespaces
                    .get(&id)
                    .filter(|root| root.start <= self.height && self.height < root.end)?;
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&root.owner);
                out.extend_from_slice(&root.start.to_le_bytes());
                out.extend_from_slice(&root.end.to_le_bytes());
                root.alias.encode(&mut out);
                out.extend_from_slice(&(root.children.len() as u64).to_le_bytes());
                for (path, alias) in &root.children {
                    out.push(path.len() as u8);
                    for id in path {
                        out.extend_from_slice(&id.to_le_bytes());
                    }
                    alias.encode(&mut out);
                }
            }
            SubCache::Mosaic => {
                // モザイクは期限が切れても木から外れない（catapult の `MosaicEntry::Is_Deactivation_Destructive` が false）
                let id = u64::from_le_bytes(key.try_into().ok()?);
                let entry = self.mosaics.get(&id)?;
                out.extend_from_slice(&id.to_le_bytes());
                out.extend_from_slice(&entry.supply.to_le_bytes());
                out.extend_from_slice(&entry.start_height.to_le_bytes());
                out.extend_from_slice(&entry.owner);
                out.extend_from_slice(&entry.revision.to_le_bytes());
                out.push(entry.flags);
                out.push(entry.divisibility);
                out.extend_from_slice(&entry.duration.to_le_bytes());
            }
            SubCache::Multisig => {
                let entry = self.multisigs.get(&key.try_into().ok()?)?;
                out.extend_from_slice(&entry.min_approval.to_le_bytes());
                out.extend_from_slice(&entry.min_removal.to_le_bytes());
                out.extend_from_slice(key);
                for set in [&entry.cosignatories, &entry.multisigs] {
                    out.extend_from_slice(&(set.len() as u64).to_le_bytes());
                    for address in set {
                        out.extend_from_slice(address);
                    }
                }
            }
            SubCache::HashLockInfo => {
                // 木に入るのは、まだ使われておらず期限前のものだけ（catapult の `LockInfo::isActive`）
                let lock = self
                    .hash_locks
                    .get(&key.try_into().ok()?)?
                    .last()
                    .filter(|lock| {
                        lock.status == LockStatus::Unused && self.height < lock.end_height
                    })?;
                out.extend_from_slice(&lock.owner);
                out.extend_from_slice(&lock.mosaic_id.to_le_bytes());
                out.extend_from_slice(&lock.amount.to_le_bytes());
                out.extend_from_slice(&lock.end_height.to_le_bytes());
                out.push(lock.status as u8);
                out.extend_from_slice(key);
            }
            SubCache::SecretLockInfo => {
                let stale = self.stale_secret_locks.contains(key);
                let lock = self.secret_locks.get(key)?.last().filter(|lock| {
                    stale || (lock.status == LockStatus::Unused && self.height < lock.end_height)
                })?;
                out.extend_from_slice(&lock.owner);
                out.extend_from_slice(&lock.mosaic_id.to_le_bytes());
                out.extend_from_slice(&lock.amount.to_le_bytes());
                out.extend_from_slice(&lock.end_height.to_le_bytes());
                out.push(lock.status as u8);
                out.push(lock.hash_algorithm);
                out.extend_from_slice(&lock.secret);
                out.extend_from_slice(&lock.recipient);
            }
            SubCache::AccountRestriction => {
                let restrictions = self.account_restrictions.get(key)?;
                out.extend_from_slice(key);
                let used: Vec<_> = restrictions
                    .values()
                    .filter(|restriction| !restriction.values.is_empty())
                    .collect();
                out.extend_from_slice(&(used.len() as u64).to_le_bytes());
                for restriction in used {
                    out.extend_from_slice(&restriction.descriptor.to_le_bytes());
                    out.extend_from_slice(&(restriction.values.len() as u64).to_le_bytes());
                    for value in &restriction.values {
                        out.extend_from_slice(value);
                    }
                }
            }
            SubCache::Metadata => {
                let (key, value) = self.metadata.get(&key.try_into().ok()?)?;
                out.extend_from_slice(&key.source_address.0);
                out.extend_from_slice(&key.target_address.0);
                out.extend_from_slice(&key.scoped_metadata_key.to_le_bytes());
                out.extend_from_slice(&key.target_id.to_le_bytes());
                out.push(key.metadata_type as u8);
                out.extend_from_slice(&(value.len() as u16).to_le_bytes());
                out.extend_from_slice(value);
            }
            SubCache::MosaicRestriction => {
                out.extend_from_slice(&self.mosaic_restrictions.get(key)?.encode());
            }
            SubCache::AccountState => return None,
        }
        Some(out)
    }

    // endregion
}

/// アカウントの葉の値を並列に求める、変わったアカウントの数の下限。普通のブロックでは数十なので、並列にしない
const PARALLEL_LEAVES: usize = 512;

/// 行（[`persist::row_key`]）の、木の番号と木のキー
pub fn tree_key_of_row(row: &[u8]) -> (SubCache, Hash256) {
    let cache = SubCache::ALL[usize::from(row[0])];
    let key = if cache == SubCache::AccountState {
        address_key(&Address(row[1..].try_into().expect("address")))
    } else {
        tree_key(cache, &row[1..])
    };
    (cache, key)
}

/// アカウントのモザイクが増えたか減ったレシートの本体
fn change(address: [u8; 24], mosaic_id: u64, amount: u64) -> BalanceChange {
    BalanceChange {
        mosaic: ReceiptMosaic {
            mosaic_id: MosaicId(mosaic_id),
            amount,
        },
        target_address: Address(address),
    }
}

/// モザイクが動いたレシートの本体
fn transfer_receipt(from: [u8; 24], to: [u8; 24], mosaic_id: u64, amount: u64) -> BalanceTransfer {
    BalanceTransfer {
        mosaic: ReceiptMosaic {
            mosaic_id: MosaicId(mosaic_id),
            amount,
        },
        sender_address: Address(from),
        recipient_address: Address(to),
    }
}

/// 行のキーから、木のキー
fn tree_key(cache: SubCache, key: &[u8]) -> Hash256 {
    match key.len() {
        8 => id_key(u64::from_le_bytes(key.try_into().expect("8 bytes"))),
        24 => address_key(&Address(key.try_into().expect("24 bytes"))),
        _ => {
            debug_assert!(!matches!(cache, SubCache::Namespace | SubCache::Mosaic));
            hash_key(&Hash256(key.try_into().expect("32 bytes")))
        }
    }
}

/// catapult の `MosaicRestrictionType` の値
fn mosaic_restriction_type(restriction_type: heika_transaction::MosaicRestrictionType) -> u8 {
    use heika_transaction::MosaicRestrictionType as Type;
    match restriction_type {
        Type::None => 0,
        Type::Eq => 1,
        Type::Ne => 2,
        Type::Lt => 3,
        Type::Le => 4,
        Type::Gt => 5,
        Type::Ge => 6,
    }
}

/// catapult の `LockHashAlgorithm` の値
fn hash_algorithm_byte(algorithm: heika_transaction::LockHashAlgorithm) -> u8 {
    match algorithm {
        heika_transaction::LockHashAlgorithm::Sha3_256 => 0,
        heika_transaction::LockHashAlgorithm::Hash160 => 1,
        heika_transaction::LockHashAlgorithm::Hash256 => 2,
    }
}

fn sha3(bytes: &[u8]) -> Hash256 {
    Hash256(Sha3_256::digest(bytes).into())
}

fn harvester_error(what: &str) -> ExecError {
    ExecError::Invalid(format!("ブロックを出した人: {what}"))
}
