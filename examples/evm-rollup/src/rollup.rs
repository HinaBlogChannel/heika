//! ロールアップの状態。Symbol のブロックの中の順に、EVM のトランザクションを 1 件ずつ revm で実行する。
//!
//! - ロールアップのブロックは、Symbol のブロックと 1 対 1 で、高さも同じ。EVM のトランザクションがなければ空のブロック
//! - 読めない、署名が合わない、nonce が合わない、などのトランザクションは、入らなかったことにする（誰が実行しても同じ）
//! - ガスの値段は 0 でいい。スパムは、Symbol に載せるときの XYM の手数料で防ぐ。計算の重さは、ブロックのガスの合計の
//!   上限（[`GAS_LIMIT`]）で抑える
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

/// Symbol のブロック 1 つで使えるガスの合計。1 件ごとの上限は、revm の既定（EIP-7825 の 2^24）
pub const GAS_LIMIT: u64 = 30_000_000;

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
    pub transactions: Vec<B256>,
    pub state_root: B256,
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
            blocks: BTreeMap::new(),
            receipts: HashMap::new(),
        };
        rollup.genesis_root = rollup.state_root();
        rollup
    }

    /// Symbol の高さ `height` のブロックを実行する。`transactions` は、ブロックの中の順の EVM のトランザクション。
    /// 入れたトランザクションのハッシュと、入れなかったものの理由を返す
    pub fn apply(
        &mut self,
        height: u64,
        timestamp: u64,
        transactions: &[Vec<u8>],
    ) -> Vec<Result<B256, String>> {
        assert!(height > self.height, "高さは増えていく");
        self.height = height;
        self.timestamp = timestamp;
        if transactions.is_empty() {
            return Vec::new();
        }
        let mut evm = Context::mainnet()
            .with_db(std::mem::take(&mut self.db))
            .with_block(block_env(height, timestamp))
            .modify_cfg_chained(|cfg| cfg.chain_id = self.chain_id)
            .build_mainnet();
        let mut outcomes = Vec::new();
        let mut included = Vec::new();
        let mut cumulative_gas_used = 0;
        for bytes in transactions {
            let outcome = (|| {
                let (envelope, from) = decode(bytes, self.chain_id)?;
                // Symbol の手数料は大きさで決まり、計算の重さでは決まらない。重いものを並べられないように、
                // Ethereum と同じく、ブロックの残りのガスを超えるものは入れない
                if cumulative_gas_used + envelope.gas_limit() > GAS_LIMIT {
                    return Err("ブロックのガスの上限を超えます".to_owned());
                }
                let result = evm
                    .transact_commit(tx_env(&envelope, from))
                    .map_err(|error| error.to_string())?;
                let hash = *envelope.tx_hash();
                cumulative_gas_used += result.tx_gas_used();
                self.receipts.insert(
                    hash,
                    Receipt {
                        from,
                        height,
                        index: included.len() as u64,
                        success: result.is_success(),
                        gas_used: result.tx_gas_used(),
                        cumulative_gas_used,
                        contract_address: result.created_address(),
                        logs: result.into_logs(),
                        envelope,
                    },
                );
                included.push(hash);
                Ok(hash)
            })();
            outcomes.push(outcome);
        }
        self.db = evm.ctx.journaled_state.database;
        if !included.is_empty() {
            let state_root = self.state_root();
            self.blocks.insert(
                height,
                Block {
                    timestamp,
                    transactions: included,
                    state_root,
                },
            );
        }
        outcomes
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
            .with_block(block_env(self.height + 1, self.timestamp))
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

fn block_env(height: u64, timestamp: u64) -> BlockEnv {
    BlockEnv {
        number: U256::from(height),
        timestamp: U256::from(timestamp),
        gas_limit: GAS_LIMIT,
        basefee: 0,
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

    /// チェーン ID 1337 で、`FROM` から 0x…dEaD に 1 ETH 送る（ガスの値段 0、nonce 0）。`cast mktx` で作った
    const TRANSFER: &str = "02f86c82053980808082520894000000000000000000000000000000000000dead880de0b6b3a764000080c001a00742819e5bfe80791bdc27f82245159becec102cb91e533e82da1192739f5db6a0331d6e44b26ffdec73edb6f8d8cb984b253d0675660ed040d934780a64682dc9";

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
    /// anvil の coinbase は、`anvil_setCoinbase` で開発用の口座（0x7099…）にしておく。anvil は、手数料 0 で触った空の
    /// coinbase をルートに残すが、EIP-161 では触った空の口座は消える（こちらはルートに入れない）。中身のある口座を coinbase に
    /// すれば、どちらの決まりでも同じになる
    #[test]
    fn state_root_matches_anvil() {
        let mut rollup = Rollup::new(&genesis());
        let transfer = alloy_primitives::hex::decode(TRANSFER).unwrap();
        let outcomes = rollup.apply(11, 1_700_000_000, &[transfer]);
        assert_eq!(
            outcomes[0].as_ref().unwrap().to_string(),
            "0xfd08b576f7811eca175983748c192339e732b1e20a8fd3f96ec2d8a2ec588d10"
        );
        assert_eq!(
            rollup.state_root().to_string(),
            "0x697241eaa3c20af6653ebfbd2654d6d33982cf32e6c39a4cfe01af5a591c52da"
        );
        let receipt = rollup.receipt(outcomes[0].as_ref().unwrap()).unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(rollup.account(&FROM).nonce, 1);
    }

    /// 同じものをもう一度載せても、nonce が合わないので入らない。読めないものも入らない
    #[test]
    fn skips_replays_and_garbage() {
        let mut rollup = Rollup::new(&genesis());
        let transfer = alloy_primitives::hex::decode(TRANSFER).unwrap();
        let outcomes = rollup.apply(11, 0, &[transfer.clone(), transfer, vec![1, 2, 3]]);
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1].is_err());
        assert!(outcomes[2].is_err());
        assert_eq!(rollup.block(11).unwrap().transactions.len(), 1);
    }

    /// チェーン ID が違うものは入らない
    #[test]
    fn refuses_other_chains() {
        let mut genesis = genesis();
        genesis.chain_id = 1;
        let mut rollup = Rollup::new(&genesis);
        let transfer = alloy_primitives::hex::decode(TRANSFER).unwrap();
        assert!(rollup.apply(11, 0, &[transfer])[0].is_err());
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
