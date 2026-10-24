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
pub use validate::PartialCheck;
pub mod persist;
mod rules;
pub mod source;
mod statement;

mod accounts;
mod block;
mod link;
mod lock;
mod metadata;
mod mosaic;
mod multisig;
mod namespace;
mod resolve;
mod restriction;
mod roots;
mod transfer;
mod validate;

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
    /// この実装が扱わないもの（知らない種類のトランザクション、扱わない設定）
    Unsupported(String),
    /// ブロックが規則に合わない（残高が足りない、知らない ID、validator が弾いたなど）
    Invalid(String),
    /// 状態の読み口（[`source::StateSource`]）から読めなかった。ブロックのせいではない
    Source(String),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "扱いません: {what}"),
            Self::Invalid(what) => write!(f, "規則に合いません: {what}"),
            Self::Source(what) => write!(f, "状態を読めません: {what}"),
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
        // 前に弾いたときの何件目かを、トランザクションを当てる前に弾いたときに残さない
        self.current_transaction = None;
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
                    ExecError::Source("しまった木のノードのキーが読めません".to_owned())
                })?;
            let node = TreeNode::decode_all(&bytes)
                .ok()
                .and_then(|nodes| nodes.into_iter().next())
                .ok_or_else(|| ExecError::Source("しまった木のノードが読めません".to_owned()))?;
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
        let vrf_key = self.check_hit(parent, block, parameters)?;
        let proof_hash = heika_core::vrf::verify(
            &vrf_key,
            &parent_generation_hash.0,
            &block.generation_hash_proof,
        )
        .ok_or_else(|| harvester_error("VRF の証明が通りません"))?;
        Ok(proof_hash.generation_hash())
    }

    /// [`Executor::check_harvester`] のうち、状態を見るところ（1 と 3）。VRF の証明はまだ確かめずに、証明の gamma から
    /// 出る generation hash で当たりかを見る。通れば、証明を確かめるのに使う VRF の鍵を返す。
    ///
    /// 証明は状態に依らないので、呼んだ側が別に（別のスレッドなどで）[`heika_core::vrf::verify`] で確かめる。
    /// 確かめ終えるまで、このブロックは確かめたことにならない
    pub fn check_hit(
        &self,
        parent: &Block,
        block: &Block,
        parameters: &heika_core::network::NetworkParameters,
    ) -> Result<PublicKey, ExecError> {
        let forwarded = self.harvester(&block.signer_public_key)?;
        let importance = self.importance_of(forwarded, block.height);
        if !heika_block::scoring::is_hit(parent, block, importance, parameters) {
            return Err(harvester_error("当たりではありません"));
        }
        // VRF の鍵がなければ、catapult は0の鍵で確かめるので通らない
        Ok(PublicKey(forwarded.vrf.unwrap_or([0; 32])))
    }

    /// `block` を出したアカウント（リモートならメインアカウント）の、そのブロックの高さで使う Importance
    pub fn harvester_importance(&self, block: &Block) -> Result<u64, ExecError> {
        self.signer_importance(&block.signer_public_key, block.height)
    }

    /// `signer` が高さ `height` のブロックを出すときに使う Importance（リモートならメインアカウントのもの）
    pub fn signer_importance(&self, signer: &PublicKey, height: u64) -> Result<u64, ExecError> {
        Ok(self.importance_of(self.harvester(signer)?, height))
    }

    /// `signer` の鍵でブロックを出したときに、報酬を受け取るアカウントのアドレス（リモートならメインアカウント）
    pub fn harvester_address(&self, signer: &PublicKey) -> Result<[u8; 24], ExecError> {
        Ok(self.harvester(signer)?.address)
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
                self.apply_transfer(height, signer, is_nemesis_signer, transfer)?;
            }
            Body::MosaicDefinition(definition) => {
                self.apply_mosaic_definition(height, signer, is_nemesis_signer, definition)?;
            }
            Body::MosaicSupplyChange(change) => {
                self.apply_mosaic_supply_change(height, signer, change)?;
            }
            Body::MosaicSupplyRevocation(revocation) => {
                self.apply_mosaic_supply_revocation(height, signer, revocation)?;
            }
            Body::NamespaceRegistration(registration) => {
                self.apply_namespace_registration(height, signer, is_nemesis_signer, registration)?;
            }
            Body::MosaicAlias(alias) => {
                self.apply_mosaic_alias(height, signer, alias)?;
            }
            Body::AddressAlias(alias) => {
                self.apply_address_alias(height, signer, alias)?;
            }
            Body::MultisigAccountModification(modification) => {
                self.apply_multisig(height, signer, modification)?;
            }
            Body::AccountKeyLink(link) => {
                self.apply_account_key_link(height, signer, signer_key, link)?;
            }
            Body::VrfKeyLink(link) | Body::NodeKeyLink(link) => {
                self.apply_vrf_or_node_key_link(signer, body, link)?;
            }
            Body::VotingKeyLink(link) => {
                self.apply_voting_key_link(signer, link)?;
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
                self.apply_hash_lock(height, signer, lock)?;
            }
            Body::SecretLock(lock) => {
                self.apply_secret_lock(height, signer, lock)?;
            }
            Body::SecretProof(proof) => {
                self.apply_secret_proof(height, proof)?;
            }
            Body::AccountAddressRestriction(restriction) => {
                self.apply_account_address_restriction(signer, restriction)?;
            }
            Body::AccountMosaicRestriction(restriction) => {
                self.apply_account_mosaic_restriction(signer, restriction)?;
            }
            Body::AccountOperationRestriction(restriction) => {
                self.apply_account_operation_restriction(signer, restriction)?;
            }
            Body::MosaicGlobalRestriction(restriction) => {
                self.apply_mosaic_global_restriction(restriction)?;
            }
            Body::MosaicAddressRestriction(restriction) => {
                self.apply_mosaic_address_restriction(restriction)?;
            }
            other => {
                let name = format!("{other:?}");
                let name = name.split(['(', ' ', '{']).next().unwrap_or("?");
                return Err(ExecError::Unsupported(name.to_owned()));
            }
        }
        Ok(())
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
