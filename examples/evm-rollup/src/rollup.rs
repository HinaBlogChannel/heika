//! ロールアップの状態。Symbol のブロックの中の順に、EVM のトランザクションを 1 件ずつ revm で実行する。
//!
//! - ロールアップのブロックは、Symbol のブロックと 1 対 1 で、高さも同じ。EVM のトランザクションがなければ空のブロック
//! - 読めない、署名が合わない、チェーン ID が違う、nonce が合わない、などのトランザクションは、入らなかったことにする
//!   （誰が実行しても同じ）
//! - 署名と nonce が合っていれば、必ずレシートを出す。払えない（max fee が basefee に届かない、残高が足りない）などで
//!   実行できなければ、失敗（status 0、ガス 0）にして、nonce は使ったことにする
//! - basefee は、1 件ごとに決める。時間あたりに使われたガスが目標より多いほど、指数で上がり、時間がたつと下がる
//!   （[`base_fee`]）。払った basefee は燃える。同じ Symbol のブロックに入った人どうしで、ガスの枠を取り合わない
//! - blob 付きのトランザクション（type 3）は入れない。blob を置く層がないので
//!
//! 橋（genesis に預かり口座 `vault` があるとき）：
//!
//! - 預かり口座への XYM の入金は、その Symbol のブロックの最初に、メッセージに書いた EVM のアドレスに入れる。
//!   ロールアップの中の通貨は XYM で、XYM の最小単位（10^-6）が 10^12 wei にあたる（18 桁にそろえる）
//! - [`WITHDRAW_ADDRESS`] に XYM を送るトランザクションは、引き出し。データに Symbol のアドレス（24 バイト）を入れる。
//!   送った XYM はそこに残り、誰も動かせない（燃える）。橋の見張り役が、ファイナライズされてから預かり口座から払う
//! - 宛先の Symbol のアドレスが読めない（チェックサムが合わない、ネットワークが違う）ときは、送った人に返す

use std::collections::{BTreeMap, HashMap};

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction as _, TxEnvelope, TxType};
use alloy_eips::Decodable2718;
use alloy_primitives::{Address, B256, Bloom, Bytes, Log, TxKind, U256, keccak256};
use alloy_trie::TrieAccount;
use alloy_trie::root::{state_root_unsorted, storage_root_unhashed};
use heika_core::address::Address as SymbolAddress;
use revm::context::either::Either;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, TxEnv};
use revm::database::{AccountState, CacheDB, EmptyDB};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};
use serde::{Deserialize, Deserializer};

/// ブロックの `gasLimit` として見せる値。資源は basefee で抑えるので、ブロックの合計の上限ではない。
/// 1 件ごとの上限は、revm の既定（EIP-7825 の 2^24）
pub const GAS_LIMIT: u64 = 30_000_000;

/// 1 秒あたりに使われてよいガスの目標
pub const TARGET_GAS_PER_SECOND: u64 = 1_000_000;

/// basefee の下限（1 gwei）
pub const MIN_BASE_FEE: u64 = 1_000_000_000;

/// 目標を超えたガスがこれだけたまると、basefee が e 倍になる。目標の 2 倍で使われ続けると、12 秒で約 12.5% 上がる
/// （Ethereum の EIP-1559 と同じくらい）
pub const BASE_FEE_UPDATE_FRACTION: u64 = 100_000_000;

/// たまったガスの上限。ここで basefee は約 1 gwei × e^23（1 ガスあたり約 10 ETH）になり、もう誰も払えない
const MAX_EXCESS: u64 = 23 * BASE_FEE_UPDATE_FRACTION;

/// 目標を超えて使われたガスが `excess` だけたまっているときの basefee。EIP-4844 の `fake_exponential` と同じ計算
pub fn base_fee(excess: u64) -> u64 {
    let (factor, numerator, denominator) = (
        u128::from(MIN_BASE_FEE),
        u128::from(excess.min(MAX_EXCESS)),
        u128::from(BASE_FEE_UPDATE_FRACTION),
    );
    let mut output = 0;
    let mut accumulator = factor * denominator;
    let mut i = 1;
    while accumulator > 0 {
        output += accumulator;
        accumulator = accumulator * numerator / (denominator * i);
        i += 1;
    }
    u64::try_from(output / denominator).unwrap_or(u64::MAX)
}

/// 目標を超えて使われたガスと、最後に見た時刻
#[derive(Clone, Copy, Debug, Default)]
struct Excess {
    gas: u64,
    /// Unix 時刻（秒）
    time: u64,
}

impl Excess {
    /// `time` までの時間ぶん、目標のガスを差し引く
    fn at(self, time: u64) -> Self {
        let elapsed = time.saturating_sub(self.time);
        Self {
            gas: self
                .gas
                .saturating_sub(TARGET_GAS_PER_SECOND.saturating_mul(elapsed)),
            time: time.max(self.time),
        }
    }
}

/// 引き出しの口。ここに XYM を送ると、橋が Symbol で払う。`58594d` は ASCII の `XYM`。
/// 置いてあるコード（[`WITHDRAW_CODE`]）が、形の合わない引き出しを revert する
pub const WITHDRAW_ADDRESS: Address =
    alloy_primitives::address!("000000000000000000000000000000000058594d");

/// XYM の最小単位 1 つぶんの wei
pub const WEI_PER_MICRO_XYM: u64 = 1_000_000_000_000;

/// [`WITHDRAW_ADDRESS`] のコード。次のどれかに当てはまれば revert する：
///
/// - コントラクトから呼ばれた（`CALLER != ORIGIN`）。引き出しは外側のトランザクションでしか拾わないので、
///   コントラクトの中から送られた XYM は、払われないまま燃えてしまう
/// - データが 24 バイト（Symbol のアドレス）ではない
/// - 送る量が 0、または XYM の最小単位（10^12 wei）で割り切れない
///
/// ```text
/// ORIGIN CALLER EQ  CALLDATASIZE PUSH1 24 EQ AND  CALLVALUE ISZERO ISZERO AND
/// PUSH5 10^12 CALLVALUE MOD ISZERO AND  PUSH1 28 JUMPI  PUSH0 PUSH0 REVERT  JUMPDEST STOP
/// ```
pub const WITHDRAW_CODE: [u8; 30] = [
    0x32, 0x33, 0x14, 0x36, 0x60, 0x18, 0x14, 0x16, 0x34, 0x15, 0x15, 0x16, 0x64, 0xe8, 0xd4, 0xa5,
    0x10, 0x00, 0x34, 0x06, 0x15, 0x16, 0x60, 0x1c, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x00,
];

/// ロールアップの始まり
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    pub chain_id: u64,
    /// この Symbol の高さの次のブロックから読む
    pub start: u64,
    /// 橋の預かり口座。あれば、ここへの入金をロールアップに入れ、引き出しを受け付ける
    #[serde(default, deserialize_with = "symbol_address")]
    pub vault: Option<SymbolAddress>,
    /// 最初の口座。geth の genesis の `alloc` と同じ形。橋があるときは、残高を置けない
    /// （預かった XYM より多い XYM ができてしまうので）
    #[serde(default)]
    pub alloc: BTreeMap<Address, GenesisAccount>,
}

impl Genesis {
    /// 橋があるのに、預かっていない残高を置いていないか
    pub fn check(&self) -> Result<(), String> {
        if self.vault.is_some()
            && self
                .alloc
                .values()
                .any(|account| !account.balance.is_zero())
        {
            return Err("預かり口座（vault）があるときは、alloc に残高を置けません".to_owned());
        }
        Ok(())
    }
}

fn symbol_address<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SymbolAddress>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|text| text.parse().map_err(serde::de::Error::custom))
        .transpose()
}

/// 預かり口座への入金 1 つ
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    /// 入れる先（メッセージに書いてあったもの）
    pub to: Address,
    /// XYM の最小単位
    pub amount: u64,
}

/// 引き出し 1 つ。橋がファイナライズされてから払う
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    /// 0 から順に振る番号。橋が Symbol で払うときにメッセージに入れて、同じ引き出しで 2 回払わないようにする
    pub id: u64,
    pub height: u64,
    /// 引き出しのトランザクションのハッシュ
    pub transaction: B256,
    pub recipient: SymbolAddress,
    /// XYM の最小単位
    pub amount: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct GenesisAccount {
    /// wei
    pub balance: U256,
    #[serde(default)]
    pub nonce: u64,
    #[serde(default)]
    pub code: Bytes,
    #[serde(default)]
    pub storage: BTreeMap<U256, U256>,
}

/// EVM のトランザクションが 1 件以上入ったブロック
#[derive(Clone, Debug)]
pub struct Block {
    /// Unix 時刻（秒）
    pub timestamp: u64,
    /// ブロックの最初のトランザクションの basefee
    pub base_fee: u64,
    pub transactions: Vec<B256>,
    pub state_root: B256,
}

/// トランザクション 1 件の行き先
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// 実行した（revert も含む）
    Executed(B256),
    /// 署名と nonce は合っていたが、実行できなかった。レシートは失敗で、nonce は使ったことにする
    Failed(B256, String),
    /// 入らなかった。レシートはない
    Skipped(String),
    /// 引き出しを受け付けた
    Withdrawn(Withdrawal),
    /// 引き出しの宛先が読めなかったので、送った人に返した（レシートは成功のまま）
    Refunded(B256, String),
}

/// 入ったトランザクションと、その結果
#[derive(Clone, Debug)]
pub struct Receipt {
    pub envelope: TxEnvelope,
    pub from: Address,
    pub height: u64,
    pub index: u64,
    pub success: bool,
    pub gas_used: u64,
    /// 1 ガスあたりに払った値段（basefee と優先料の和）。実行できなかったものは 0
    pub effective_gas_price: u128,
    pub cumulative_gas_used: u64,
    pub logs: Vec<Log>,
    pub contract_address: Option<Address>,
}

impl Receipt {
    pub fn bloom(&self) -> Bloom {
        let mut bloom = Bloom::default();
        for log in &self.logs {
            bloom.accrue_log(log);
        }
        bloom
    }
}

#[derive(Clone)]
pub struct Rollup {
    pub chain_id: u64,
    db: CacheDB<EmptyDB>,
    genesis_root: B256,
    /// 実行し終えた Symbol の高さ
    pub height: u64,
    /// `height` のブロックの Unix 時刻（秒）
    pub timestamp: u64,
    excess: Excess,
    blocks: BTreeMap<u64, Block>,
    receipts: HashMap<B256, Receipt>,
    vault: Option<SymbolAddress>,
    /// 受け付けた引き出し。番号の順
    pub withdrawals: Vec<Withdrawal>,
}

impl Rollup {
    pub fn new(genesis: &Genesis) -> Self {
        let mut db = CacheDB::new(EmptyDB::default());
        for (address, account) in &genesis.alloc {
            let code = Bytecode::new_raw(account.code.clone());
            db.insert_account_info(
                *address,
                AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: code.hash_slow(),
                    code: Some(code),
                    ..Default::default()
                },
            );
            for (slot, value) in &account.storage {
                db.insert_account_storage(*address, *slot, *value)
                    .expect("in memory");
            }
        }
        if genesis.vault.is_some() && !genesis.alloc.contains_key(&WITHDRAW_ADDRESS) {
            let code = Bytecode::new_raw(Bytes::from_static(&WITHDRAW_CODE));
            db.insert_account_info(
                WITHDRAW_ADDRESS,
                AccountInfo {
                    code_hash: code.hash_slow(),
                    code: Some(code),
                    ..Default::default()
                },
            );
        }
        let mut rollup = Self {
            chain_id: genesis.chain_id,
            db,
            genesis_root: B256::ZERO,
            height: genesis.start,
            timestamp: 0,
            excess: Excess::default(),
            blocks: BTreeMap::new(),
            receipts: HashMap::new(),
            vault: genesis.vault,
            withdrawals: Vec::new(),
        };
        rollup.genesis_root = rollup.state_root();
        rollup
    }

    /// Symbol の高さ `height` のブロックを実行する。`deposits` は、そのブロックで預かり口座に入った入金で、最初に入れる。
    /// `transactions` は、ブロックの中の順の EVM のトランザクション
    pub fn apply(
        &mut self,
        height: u64,
        timestamp: u64,
        deposits: &[Deposit],
        transactions: &[Vec<u8>],
    ) -> Vec<Outcome> {
        assert!(height > self.height, "高さは増えていく");
        self.height = height;
        self.timestamp = timestamp;
        let deposited = self.vault.is_some() && !deposits.is_empty();
        if deposited {
            for deposit in deposits {
                let mut info = self.account(&deposit.to);
                info.balance += U256::from(deposit.amount) * U256::from(WEI_PER_MICRO_XYM);
                self.db.insert_account_info(deposit.to, info);
            }
        }
        if transactions.is_empty() {
            if deposited {
                let state_root = self.state_root();
                self.blocks.insert(
                    height,
                    Block {
                        timestamp,
                        base_fee: self.base_fee(),
                        transactions: Vec::new(),
                        state_root,
                    },
                );
            }
            return Vec::new();
        }
        self.excess = self.excess.at(timestamp);
        let first_base_fee = base_fee(self.excess.gas);
        let mut evm = Context::mainnet()
            .with_db(std::mem::take(&mut self.db))
            .modify_cfg_chained(|cfg| cfg.chain_id = self.chain_id)
            .build_mainnet();
        let mut outcomes = Vec::new();
        let mut included = Vec::new();
        let mut cumulative_gas_used = 0;
        for bytes in transactions {
            let (envelope, from) = match decode(bytes, self.chain_id) {
                Ok(decoded) => decoded,
                Err(reason) => {
                    outcomes.push(Outcome::Skipped(reason));
                    continue;
                }
            };
            let database = &mut evm.ctx.journaled_state.database;
            let nonce = database
                .cache
                .accounts
                .get(&from)
                .map_or(0, |account| account.info.nonce);
            if envelope.nonce() != nonce || nonce == u64::MAX {
                outcomes.push(Outcome::Skipped(format!(
                    "nonce が合いません（{} を待っています）",
                    nonce
                )));
                continue;
            }
            let hash = *envelope.tx_hash();
            let base_fee = base_fee(self.excess.gas);
            evm.set_block(block_env(height, timestamp, base_fee));
            let receipt = match evm.transact_commit(tx_env(&envelope, from)) {
                Ok(result) => {
                    let gas_used = result.tx_gas_used();
                    self.excess.gas = self.excess.gas.saturating_add(gas_used).min(MAX_EXCESS);
                    cumulative_gas_used += gas_used;
                    outcomes.push(Outcome::Executed(hash));
                    if result.is_success()
                        && let Some(vault) = self.vault
                        && envelope.to() == Some(WITHDRAW_ADDRESS)
                    {
                        let database = &mut evm.ctx.journaled_state.database;
                        outcomes.push(match withdrawal(&vault, &envelope) {
                            Ok((recipient, amount)) => {
                                let withdrawal = Withdrawal {
                                    id: self.withdrawals.len() as u64,
                                    height,
                                    transaction: hash,
                                    recipient,
                                    amount,
                                };
                                self.withdrawals.push(withdrawal.clone());
                                Outcome::Withdrawn(withdrawal)
                            }
                            Err(reason) => {
                                // 燃やさずに、送った人に返す
                                let value = envelope.value();
                                database
                                    .load_account(WITHDRAW_ADDRESS)
                                    .expect("in memory")
                                    .info
                                    .balance -= value;
                                database.load_account(from).expect("in memory").info.balance +=
                                    value;
                                Outcome::Refunded(hash, reason)
                            }
                        });
                    }
                    Receipt {
                        from,
                        height,
                        index: included.len() as u64,
                        success: result.is_success(),
                        gas_used,
                        effective_gas_price: effective_gas_price(&envelope, base_fee),
                        cumulative_gas_used,
                        contract_address: result.created_address(),
                        logs: result.into_logs(),
                        envelope,
                    }
                }
                Err(error) => {
                    // 実行できなくても nonce は進める。同じものを載せ直されても、もう通らない
                    let account = evm
                        .ctx
                        .journaled_state
                        .database
                        .load_account(from)
                        .expect("in memory");
                    account.info.nonce += 1;
                    if account.account_state == AccountState::NotExisting {
                        account.account_state = AccountState::Touched;
                    }
                    outcomes.push(Outcome::Failed(hash, error.to_string()));
                    Receipt {
                        from,
                        height,
                        index: included.len() as u64,
                        success: false,
                        gas_used: 0,
                        effective_gas_price: 0,
                        cumulative_gas_used,
                        contract_address: None,
                        logs: Vec::new(),
                        envelope,
                    }
                }
            };
            self.receipts.insert(hash, receipt);
            included.push(hash);
        }
        self.db = evm.ctx.journaled_state.database;
        if !included.is_empty() || deposited {
            let state_root = self.state_root();
            self.blocks.insert(
                height,
                Block {
                    timestamp,
                    base_fee: first_base_fee,
                    transactions: included,
                    state_root,
                },
            );
        }
        outcomes
    }

    /// 今の basefee（最後に見た Symbol のブロックの時刻で）
    pub fn base_fee(&self) -> u64 {
        base_fee(self.excess.at(self.timestamp).gas)
    }

    /// Symbol の高さを進める。EVM のトランザクションのない空のブロック
    pub fn advance(&mut self, height: u64, timestamp: u64) {
        if height > self.height {
            self.height = height;
            self.timestamp = timestamp;
        }
    }

    /// 状態のルート。Ethereum と同じ Merkle Patricia Trie で求める。空の口座は入れない（EIP-161）
    pub fn state_root(&self) -> B256 {
        state_root_unsorted(
            self.db
                .cache
                .accounts
                .iter()
                .filter_map(|(address, account)| {
                    if account.account_state == AccountState::NotExisting {
                        return None;
                    }
                    let storage_root = storage_root_unhashed(
                        account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(|(slot, value)| (B256::from(*slot), *value)),
                    );
                    let trie = TrieAccount {
                        nonce: account.info.nonce,
                        balance: account.info.balance,
                        storage_root,
                        code_hash: account.info.code_hash,
                    };
                    (trie != TrieAccount::default()).then(|| (keccak256(address), trie))
                }),
        )
    }

    /// 高さ `height` のブロック。空のブロックなら、トランザクションはなく、ルートは直前のもの
    pub fn block(&self, height: u64) -> Option<Block> {
        if height > self.height {
            return None;
        }
        if let Some(block) = self.blocks.get(&height) {
            return Some(block.clone());
        }
        let state_root = self
            .blocks
            .range(..height)
            .next_back()
            .map_or(self.genesis_root, |(_, block)| block.state_root);
        Some(Block {
            timestamp: if height == self.height {
                self.timestamp
            } else {
                0
            },
            base_fee: self.base_fee(),
            transactions: Vec::new(),
            state_root,
        })
    }

    /// ブロックのハッシュ。Symbol のブロックのハッシュではなく、チェーン ID と高さとルートから作る
    pub fn block_hash(&self, height: u64) -> Option<B256> {
        let block = self.block(height)?;
        Some(keccak256(
            [
                &self.chain_id.to_be_bytes()[..],
                &height.to_be_bytes(),
                block.state_root.as_slice(),
            ]
            .concat(),
        ))
    }

    pub fn receipt(&self, hash: &B256) -> Option<&Receipt> {
        self.receipts.get(hash)
    }

    pub fn account(&self, address: &Address) -> AccountInfo {
        self.db
            .cache
            .accounts
            .get(address)
            .map(|account| account.info.clone())
            .unwrap_or_default()
    }

    pub fn code(&self, address: &Address) -> Bytes {
        let hash = self.account(address).code_hash;
        self.db
            .cache
            .contracts
            .get(&hash)
            .map(|code| code.original_bytes())
            .unwrap_or_default()
    }

    pub fn storage(&self, address: &Address, slot: U256) -> U256 {
        self.db
            .cache
            .accounts
            .get(address)
            .and_then(|account| account.storage.get(&slot).copied())
            .unwrap_or_default()
    }

    /// 状態を変えずに実行する（`eth_call` と `eth_estimateGas`）
    pub fn call(&self, call: Call) -> Result<ExecutionResult, String> {
        let mut evm = Context::mainnet()
            .with_db(self.db.clone())
            .with_block(block_env(self.height + 1, self.timestamp, 0))
            .modify_cfg_chained(|cfg| {
                cfg.chain_id = self.chain_id;
                cfg.disable_nonce_check = true;
            })
            .build_mainnet();
        let tx = TxEnv {
            caller: call.from.unwrap_or_default(),
            gas_limit: call.gas.unwrap_or(1 << 24).min(1 << 24),
            kind: call.to.map_or(TxKind::Create, TxKind::Call),
            value: call.value.unwrap_or_default(),
            data: call.input.unwrap_or_default(),
            chain_id: Some(self.chain_id),
            ..Default::default()
        };
        evm.transact(tx)
            .map(|result| result.result)
            .map_err(|error| error.to_string())
    }
}

/// 引き出しのトランザクションから、宛先の Symbol のアドレスと量（XYM の最小単位）を読む。
/// 形（24 バイト、量が割り切れる）は [`WITHDRAW_CODE`] が確かめてあるので、ここではアドレスの中身を確かめる
fn withdrawal(
    vault: &SymbolAddress,
    envelope: &TxEnvelope,
) -> Result<(SymbolAddress, u64), String> {
    let bytes: [u8; 24] = envelope
        .input()
        .as_ref()
        .try_into()
        .map_err(|_| "データが 24 バイトではありません".to_owned())?;
    let recipient = SymbolAddress(bytes);
    if recipient.network() != vault.network() {
        return Err("宛先が、預かり口座と同じネットワークのアドレスではありません".to_owned());
    }
    if !recipient.has_valid_checksum() {
        return Err("宛先のアドレスのチェックサムが合いません".to_owned());
    }
    let amount = envelope.value() / U256::from(WEI_PER_MICRO_XYM);
    let amount = u64::try_from(amount).map_err(|_| "量が大きすぎます".to_owned())?;
    Ok((recipient, amount))
}

/// `eth_call` の中身
#[derive(Clone, Debug, Default)]
pub struct Call {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas: Option<u64>,
    pub value: Option<U256>,
    pub input: Option<Bytes>,
}

/// 1 ガスあたりに払う値段。EIP-1559 なら basefee に優先料を足し、max fee で抑える
fn effective_gas_price(envelope: &TxEnvelope, base_fee: u64) -> u128 {
    let base_fee = u128::from(base_fee);
    match envelope.max_priority_fee_per_gas() {
        Some(priority) => envelope
            .max_fee_per_gas()
            .min(base_fee.saturating_add(priority)),
        None => envelope.max_fee_per_gas(),
    }
}

fn block_env(height: u64, timestamp: u64, base_fee: u64) -> BlockEnv {
    BlockEnv {
        number: U256::from(height),
        timestamp: U256::from(timestamp),
        gas_limit: GAS_LIMIT,
        basefee: base_fee,
        difficulty: U256::ZERO,
        prevrandao: Some(B256::ZERO),
        ..Default::default()
    }
}

/// EIP-2718 の形のバイト列を読み、署名者を割り出す。チェーン ID が違うもの、blob 付きのものは入れない
pub fn decode(bytes: &[u8], chain_id: u64) -> Result<(TxEnvelope, Address), String> {
    let envelope = TxEnvelope::decode_2718_exact(bytes).map_err(|error| error.to_string())?;
    if !matches!(
        envelope.tx_type(),
        TxType::Legacy | TxType::Eip2930 | TxType::Eip1559 | TxType::Eip7702
    ) {
        return Err(format!("この種類は入れません: {}", envelope.tx_type()));
    }
    if envelope.chain_id().is_some_and(|id| id != chain_id) {
        return Err("チェーン ID が違います".to_owned());
    }
    let from = envelope
        .recover_signer()
        .map_err(|error| error.to_string())?;
    Ok((envelope, from))
}

fn tx_env(envelope: &TxEnvelope, from: Address) -> TxEnv {
    TxEnv {
        tx_type: envelope.tx_type() as u8,
        caller: from,
        gas_limit: envelope.gas_limit(),
        gas_price: envelope.max_fee_per_gas(),
        gas_priority_fee: envelope.max_priority_fee_per_gas(),
        kind: envelope.kind(),
        value: envelope.value(),
        data: envelope.input().clone(),
        nonce: envelope.nonce(),
        chain_id: envelope.chain_id(),
        access_list: envelope.access_list().cloned().unwrap_or_default(),
        authorization_list: envelope
            .authorization_list()
            .unwrap_or_default()
            .iter()
            .cloned()
            .map(Either::Left)
            .collect(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// anvil の 1 つ目の開発用の鍵のアドレス（誰でも知っている鍵）
    const FROM: Address = alloy_primitives::address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    /// チェーン ID 1337 で、`FROM` から 0x…dEaD に 1 ETH 送る（max fee 2 gwei、優先料 0、nonce 0）。`cast mktx` で作った
    const TRANSFER: &str = "02f8708205398080847735940082520894000000000000000000000000000000000000dead880de0b6b3a764000080c080a090f96471f9e5820dd26a764d3bbf4a53dbb830757da1a5f120f9c57b23aa432da046fc6f07e390a4816a32cbc85c469492f05c84a001dac243a78c3a3781c28fcb";

    /// 同じ送金で、max fee が 0 のもの（nonce 0）
    const FREE_TRANSFER: &str = "02f86c82053980808082520894000000000000000000000000000000000000dead880de0b6b3a764000080c001a00742819e5bfe80791bdc27f82245159becec102cb91e533e82da1192739f5db6a0331d6e44b26ffdec73edb6f8d8cb984b253d0675660ed040d934780a64682dc9";

    fn executed(outcome: &Outcome) -> B256 {
        match outcome {
            Outcome::Executed(hash) => *hash,
            other => panic!("実行されていません: {other:?}"),
        }
    }

    fn genesis() -> Genesis {
        serde_json::from_str(GENESIS).unwrap()
    }

    /// `anvil --init`（Shanghai、basefee 0）に、`FROM` だけ 1000 ETH の genesis を渡したときの、anvil の本当の最初の状態。
    /// anvil は、genesis の口座のほかに、開発用の口座と CREATE2 のデプロイヤーを足す（`anvil_dumpState` で見たもの）
    const GENESIS: &str = r#"{
        "chainId": 1337,
        "start": 10,
        "alloc": {
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266": {"balance": "0x3635c9adc5dea00000"},
            "0x14dc79964da2c08b23698b3d3cc7ca32193d9955": {"balance": "0x21e19e0c9bab2400000"},
            "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65": {"balance": "0x21e19e0c9bab2400000"},
            "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f": {"balance": "0x21e19e0c9bab2400000"},
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc": {"balance": "0x21e19e0c9bab2400000"},
            "0x70997970c51812dc3a010c7d01b50e0d17dc79c8": {"balance": "0x21e19e0c9bab2400000"},
            "0x90f79bf6eb2c4f870365e785982e1f101e93b906": {"balance": "0x21e19e0c9bab2400000"},
            "0x976ea74026e726554db657fa54763abd0c3a0aa9": {"balance": "0x21e19e0c9bab2400000"},
            "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc": {"balance": "0x21e19e0c9bab2400000"},
            "0xa0ee7a142d267c1f36714e4a8f75612f20a79720": {"balance": "0x21e19e0c9bab2400000"},
            "0x4e59b44847b379578588920ca78fbf26c0b4956c": {
                "balance": "0x0",
                "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3"
            }
        }
    }"#;

    /// 同じ最初の状態から同じトランザクションを実行すると、anvil のブロック 1 と同じルートになる。
    ///
    /// anvil は basefee 1 gwei（`--base-fee 1000000000`）で動かし、coinbase は `anvil_setCoinbase` で開発用の口座
    /// （0x7099…）にしておく。anvil は、手数料 0 で触った空の coinbase をルートに残すが、EIP-161 では触った空の口座は
    /// 消える（こちらはルートに入れない）。中身のある口座を coinbase にすれば、どちらの決まりでも同じになる
    #[test]
    fn state_root_matches_anvil() {
        let mut rollup = Rollup::new(&genesis());
        assert_eq!(rollup.base_fee(), MIN_BASE_FEE);
        let transfer = alloy_primitives::hex::decode(TRANSFER).unwrap();
        let outcomes = rollup.apply(11, 1_700_000_000, &[], &[transfer]);
        let hash = executed(&outcomes[0]);
        assert_eq!(
            hash.to_string(),
            "0x48c836b61a4a8a6582bdf5a932fd5ae8db07aea1f61649055fb47a82bcb9be0c"
        );
        assert_eq!(
            rollup.state_root().to_string(),
            "0x5cfd7e097d87c395876598cf671936738b8af7d257a6c2455fe13fa864a8dfc3"
        );
        let receipt = rollup.receipt(&hash).unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(receipt.effective_gas_price, 1_000_000_000);
        // 1 ETH と、燃えた basefee（21000 ガス × 1 gwei）
        assert_eq!(
            rollup.account(&FROM).balance,
            U256::from(998_999_979_000_000_000_000u128)
        );
        assert_eq!(rollup.account(&FROM).nonce, 1);
    }

    /// 払えないもの（max fee が basefee に届かない）は失敗になり、nonce は進む。同じものをもう一度載せても入らない。
    /// 読めないものも入らない
    #[test]
    fn fails_unpaid_and_skips_replays_and_garbage() {
        let mut rollup = Rollup::new(&genesis());
        let free = alloy_primitives::hex::decode(FREE_TRANSFER).unwrap();
        let before = rollup.account(&FROM).balance;
        let outcomes = rollup.apply(11, 0, &[], &[free.clone(), free, vec![1, 2, 3]]);
        let Outcome::Failed(hash, _) = &outcomes[0] else {
            panic!("失敗になっていません: {:?}", outcomes[0]);
        };
        assert!(matches!(outcomes[1], Outcome::Skipped(_)));
        assert!(matches!(outcomes[2], Outcome::Skipped(_)));
        let receipt = rollup.receipt(hash).unwrap();
        assert!(!receipt.success);
        assert_eq!(receipt.gas_used, 0);
        assert_eq!(rollup.account(&FROM).nonce, 1);
        assert_eq!(rollup.account(&FROM).balance, before);
        assert_eq!(rollup.block(11).unwrap().transactions, vec![*hash]);
        // nonce 0 のものは、もう通らない
        let paid = alloy_primitives::hex::decode(TRANSFER).unwrap();
        assert!(matches!(
            rollup.apply(12, 0, &[], &[paid])[0],
            Outcome::Skipped(_)
        ));
    }

    /// basefee は、使われたガスがたまると上がり、時間がたつと下がる
    #[test]
    fn base_fee_rises_and_decays() {
        assert_eq!(base_fee(0), MIN_BASE_FEE);
        // e 倍のあたり
        let e = base_fee(BASE_FEE_UPDATE_FRACTION);
        assert!((2_718_000_000..2_719_000_000).contains(&e), "{e}");
        assert!(base_fee(2 * BASE_FEE_UPDATE_FRACTION) > e);
        // 上限で止まる
        assert_eq!(base_fee(u64::MAX), base_fee(MAX_EXCESS));
        let excess = Excess {
            gas: 5 * TARGET_GAS_PER_SECOND,
            time: 100,
        };
        assert_eq!(excess.at(102).gas, 3 * TARGET_GAS_PER_SECOND);
        assert_eq!(excess.at(200).gas, 0);
        // 時計が戻っても増えない
        assert_eq!(excess.at(50).gas, excess.gas);
    }

    /// チェーン ID が違うものは入らない
    #[test]
    fn refuses_other_chains() {
        let mut genesis = genesis();
        genesis.chain_id = 1;
        let mut rollup = Rollup::new(&genesis);
        let transfer = alloy_primitives::hex::decode(TRANSFER).unwrap();
        assert!(matches!(
            rollup.apply(11, 0, &[], &[transfer])[0],
            Outcome::Skipped(_)
        ));
    }

    /// 空のブロックは、直前のルートを引き継ぐ
    #[test]
    fn empty_blocks_keep_the_root() {
        let mut rollup = Rollup::new(&genesis());
        let root = rollup.state_root();
        rollup.advance(12, 5);
        assert_eq!(rollup.block(12).unwrap().state_root, root);
        assert_eq!(rollup.block(11).unwrap().state_root, root);
        assert!(rollup.block(13).is_none());
    }

    /// 橋のテストで、引き出しの宛先にする Symbol のアドレス
    fn symbol_recipient() -> SymbolAddress {
        SymbolAddress::from_public_key(
            &heika_core::key::PublicKey([1; 32]),
            heika_core::network::NetworkIdentifier::TESTNET,
        )
    }

    fn bridged() -> Genesis {
        Genesis {
            chain_id: 1337,
            start: 10,
            vault: Some(SymbolAddress::from_public_key(
                &heika_core::key::PublicKey([2; 32]),
                heika_core::network::NetworkIdentifier::TESTNET,
            )),
            alloc: BTreeMap::new(),
        }
    }

    /// 以下は、チェーン ID 1337 で、`FROM` から [`WITHDRAW_ADDRESS`] に送る引き出し（max fee 2 gwei、優先料 0、
    /// ガス 50000）。データは [`symbol_recipient`] の 24 バイト。`cast mktx` で作った。
    ///
    /// nonce 0、1.5 XYM
    const WITHDRAW: &str = "02f8888205398080847735940082c35094000000000000000000000000000000000058594d8814d1120d7b1600009898a991d03cba797aed52a061e6bf2f7f238d8a85cf8e8a85c001a0f981e5435f090006361001cd13c918c444cfc8f73e1db2beb03f6ed2333b573aa04815f8d663ea1615437df1b4acd293f147e7e58387de686ae9efe9c4df1d0bdc";
    /// nonce 1、1.5 XYM。宛先の最後のバイト（チェックサム）を 1 ビット変えたもの
    const WITHDRAW_BAD_CHECKSUM: &str = "02f8888205390180847735940082c35094000000000000000000000000000000000058594d8814d1120d7b1600009898a991d03cba797aed52a061e6bf2f7f238d8a85cf8e8a84c080a058fa5f46b12801625784baab002d417d5558fcc233f542f032c4cab96d7a8cdba036ea99efbe629af7f0c114a4d6f4c8fad7b478adb5450c42f483f487c2fdc2f7";
    /// nonce 2、1.5 XYM と 1 wei（XYM の最小単位で割り切れない）
    const WITHDRAW_DUST: &str = "02f8888205390280847735940082c35094000000000000000000000000000000000058594d8814d1120d7b1600019898a991d03cba797aed52a061e6bf2f7f238d8a85cf8e8a85c001a0641b096391c10f14e4a2b89b34ef7cd72fc1e393e015112e30abd88c8b7e268aa01327c3634313eab87b9c191192bec23a04a54422921c7dc5f7aee1faa2be1e6f";
    /// nonce 3、1 XYM。宛先が 23 バイトしかない
    const WITHDRAW_SHORT: &str = "02f8878205390380847735940082c35094000000000000000000000000000000000058594d880de0b6b3a76400009798a991d03cba797aed52a061e6bf2f7f238d8a85cf8e8ac001a0472d5c59429788d1dca3aa14ad11361117abb649439eb86c7a64204ebe18265fa036b5f20cf40a1e4c59f0d9505db6c2e634d4124f7f4a3e0f1596ba28069d6fe4";

    fn xym(amount: u64) -> U256 {
        U256::from(amount) * U256::from(WEI_PER_MICRO_XYM)
    }

    /// 入金は、トランザクションがなくてもブロックの状態を変える
    #[test]
    fn deposits_change_the_root() {
        let mut rollup = Rollup::new(&bridged());
        let root = rollup.state_root();
        let deposit = Deposit {
            to: FROM,
            amount: 10_000_000,
        };
        assert!(rollup.apply(11, 0, &[deposit], &[]).is_empty());
        assert_eq!(rollup.account(&FROM).balance, xym(10_000_000));
        let block = rollup.block(11).unwrap();
        assert_ne!(block.state_root, root);
        assert_eq!(block.state_root, rollup.state_root());
        assert!(block.transactions.is_empty());
    }

    /// 橋がなければ、入金は入れない
    #[test]
    fn deposits_need_a_vault() {
        let mut rollup = Rollup::new(&genesis());
        let before = rollup.account(&FROM).balance;
        rollup.apply(
            11,
            0,
            &[Deposit {
                to: FROM,
                amount: 1,
            }],
            &[],
        );
        assert_eq!(rollup.account(&FROM).balance, before);
    }

    /// 入金したばかりの XYM で、同じブロックの中で引き出せる。宛先の読めない引き出しは返し、
    /// 形の合わない引き出しは [`WITHDRAW_CODE`] が revert する
    #[test]
    fn withdraws_refunds_and_reverts() {
        let mut rollup = Rollup::new(&bridged());
        let deposit = Deposit {
            to: FROM,
            amount: 10_000_000,
        };
        let transactions: Vec<Vec<u8>> = [
            WITHDRAW,
            WITHDRAW_BAD_CHECKSUM,
            WITHDRAW_DUST,
            WITHDRAW_SHORT,
        ]
        .iter()
        .map(|hex| alloy_primitives::hex::decode(hex).unwrap())
        .collect();
        let outcomes = rollup.apply(11, 0, &[deposit], &transactions);
        assert_eq!(outcomes.len(), 6, "{outcomes:?}");

        // 受け付けた
        let hash = executed(&outcomes[0]);
        let Outcome::Withdrawn(withdrawal) = &outcomes[1] else {
            panic!("受け付けていません: {:?}", outcomes[1]);
        };
        assert_eq!(
            *withdrawal,
            Withdrawal {
                id: 0,
                height: 11,
                transaction: hash,
                recipient: symbol_recipient(),
                amount: 1_500_000,
            }
        );
        assert_eq!(rollup.withdrawals, vec![withdrawal.clone()]);

        // 返した
        executed(&outcomes[2]);
        assert!(
            matches!(outcomes[3], Outcome::Refunded(..)),
            "{:?}",
            outcomes[3]
        );

        // revert した（ガスは払う）
        for outcome in &outcomes[4..] {
            let hash = executed(outcome);
            assert!(!rollup.receipt(&hash).unwrap().success);
        }

        // 燃えたのは、受け付けた 1.5 XYM だけ
        assert_eq!(rollup.account(&WITHDRAW_ADDRESS).balance, xym(1_500_000));
        let balance = rollup.account(&FROM).balance;
        assert!(
            balance < xym(8_500_000) && balance > xym(8_490_000),
            "{balance}"
        );
        assert_eq!(rollup.account(&FROM).nonce, 4);
    }

    /// 橋があるときは、genesis で残高を置けない
    #[test]
    fn bridged_genesis_has_no_free_balance() {
        let mut genesis = bridged();
        assert!(genesis.check().is_ok());
        genesis.alloc.insert(
            FROM,
            GenesisAccount {
                balance: U256::from(1),
                ..Default::default()
            },
        );
        assert!(genesis.check().is_err());
        assert!(self::genesis().check().is_ok());
    }

    /// コントラクトの中から引き出しの口に送ると、revert する（外側のトランザクションしか拾わないので、払われずに燃えてしまう）
    #[test]
    fn contracts_cannot_withdraw() {
        // 受け取ったデータと XYM を、そのまま `target` に送るコントラクト。送れなければ revert する
        let forwarder = |target: Address| {
            let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x34, 0x73];
            code.extend_from_slice(target.as_slice());
            code.extend_from_slice(&[0x5a, 0xf1, 0x60, 0x26, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x00]);
            GenesisAccount {
                code: code.into(),
                ..Default::default()
            }
        };
        let forwarder_address =
            alloy_primitives::address!("00000000000000000000000000000000000f0f0f");
        // 送り先がふつうのアドレスなら、ちゃんと送れる（コントラクトが正しく作れているか）
        let control_address =
            alloy_primitives::address!("00000000000000000000000000000000000c0c0c");
        let mut genesis = bridged();
        genesis
            .alloc
            .insert(forwarder_address, forwarder(WITHDRAW_ADDRESS));
        genesis.alloc.insert(
            control_address,
            forwarder(alloy_primitives::address!(
                "000000000000000000000000000000000000dEaD"
            )),
        );
        let mut rollup = Rollup::new(&genesis);
        let deposit = Deposit {
            to: FROM,
            amount: 10_000_000,
        };
        rollup.apply(11, 0, &[deposit], &[]);
        let call = |to| Call {
            from: Some(FROM),
            to: Some(to),
            value: Some(xym(1_500_000)),
            input: Some(symbol_recipient().0.to_vec().into()),
            ..Default::default()
        };
        assert!(rollup.call(call(WITHDRAW_ADDRESS)).unwrap().is_success());
        assert!(!rollup.call(call(forwarder_address)).unwrap().is_success());
        assert!(rollup.call(call(control_address)).unwrap().is_success());
    }
}
