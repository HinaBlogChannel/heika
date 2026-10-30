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

use std::collections::{BTreeMap, HashMap};

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction as _, TxEnvelope, TxType};
use alloy_eips::Decodable2718;
use alloy_primitives::{Address, B256, Bloom, Bytes, Log, TxKind, U256, keccak256};
use alloy_trie::TrieAccount;
use alloy_trie::root::{state_root_unsorted, storage_root_unhashed};
use revm::context::either::Either;
use revm::context::result::ExecutionResult;
use revm::context::{BlockEnv, TxEnv};
use revm::database::{AccountState, CacheDB, EmptyDB};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};
use serde::Deserialize;

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

/// ロールアップの始まり
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Genesis {
    pub chain_id: u64,
    /// この Symbol の高さの次のブロックから読む
    pub start: u64,
    /// 最初の口座。geth の genesis の `alloc` と同じ形
    pub alloc: BTreeMap<Address, GenesisAccount>,
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
        let mut rollup = Self {
            chain_id: genesis.chain_id,
            db,
            genesis_root: B256::ZERO,
            height: genesis.start,
            timestamp: 0,
            excess: Excess::default(),
            blocks: BTreeMap::new(),
            receipts: HashMap::new(),
        };
        rollup.genesis_root = rollup.state_root();
        rollup
    }

    /// Symbol の高さ `height` のブロックを実行する。`transactions` は、ブロックの中の順の EVM のトランザクション
    pub fn apply(&mut self, height: u64, timestamp: u64, transactions: &[Vec<u8>]) -> Vec<Outcome> {
        assert!(height > self.height, "高さは増えていく");
        self.height = height;
        self.timestamp = timestamp;
        if transactions.is_empty() {
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
        if !included.is_empty() {
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
        let outcomes = rollup.apply(11, 1_700_000_000, &[transfer]);
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
        let outcomes = rollup.apply(11, 0, &[free.clone(), free, vec![1, 2, 3]]);
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
            rollup.apply(12, 0, &[paid])[0],
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
            rollup.apply(11, 0, &[transfer])[0],
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
}
