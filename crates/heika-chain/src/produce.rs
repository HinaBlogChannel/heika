//! ブロックを作る。
//!
//! ハーベスターが選ぶもの（[`Decisions`]: 時刻、入れるトランザクション、受け取り先、手数料の倍率）を受け取り、
//! それ以外はすべて親のブロックと親のあとの状態から求める。種類、高さ、難易度、VRF の証明、PreviousBlockHash、
//! TransactionsHash、PreviousImportanceBlockHash は組むときに、StateHash、ReceiptsHash、importance ブロックの足は
//! 組みかけのブロックを実行して（[`Executor::apply_produced`]）、署名は最後に入れる。
//!
//! 当たりかどうか（VRF の証明と、選んだ時刻での hit と target）は、実行する前に、受け入れるときと同じ
//! [`Executor::check_harvester`] で確かめる。当たりでないブロックは作らない。
//!
//! 入れるトランザクションは、未承認のものから [`Candidate`] にして [`choose`] で選ぶ。状態に依る確かめは、
//! 作ってみて弾かれたもの（[`Executor::failed_transaction`]）を外して選び直すことでする。

use std::fmt;

use heika_block::scoring::{self, BlockStatistic};
use heika_block::statement::BlockStatement;
use heika_block::{Block, BlockType};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_core::vrf::{self, GenerationHash};
use heika_transaction::Transaction;

use crate::verify::{
    MAX_TRANSACTIONS_PER_BLOCK, Tip, VerifyError, verify_next, verify_transaction,
};
use heika_state_transition::executor::{ExecError, Executor};

/// 通常のブロックのヘッダーの長さ（末尾の 4 バイトは0のパディング）
const NORMAL_HEADER_SIZE: usize = 376;
/// importance ブロックのヘッダーの長さ（足を含む）
const IMPORTANCE_HEADER_SIZE: usize = 424;
/// 署名の範囲の始まり（バージョンから）
const SIGNED_FROM: usize = 108;
/// 通常のブロックの署名の範囲の終わり（パディングを除く）
const NORMAL_SIGNED_TO: usize = 372;
/// ブロックの版
const BLOCK_VERSION: u8 = 1;

/// ハーベスターが選ぶもの。正しい答えはなく、ほかのものはここから決まる
pub struct Decisions {
    /// Nemesis からのミリ秒
    pub timestamp: u64,
    /// 入れるトランザクション（署名したもの）を、入れる順に
    pub transactions: Vec<Vec<u8>>,
    pub beneficiary: Address,
    pub fee_multiplier: u32,
}

/// 親のブロックと、そこまでのチェーンから決まるもの
pub struct Parent<'a> {
    pub block: &'a Block,
    pub generation_hash: GenerationHash,
    /// 直前のブロック（親を含む）を古い順に、難易度を求めるのに要る数（`maxDifficultyBlocks`）まで
    pub recent: &'a [BlockStatistic],
    /// 親までで最後の importance ブロック（なければ Nemesis）のハッシュ
    pub importance_hash: Hash256,
}

/// 作れなかったわけ
#[derive(Debug)]
pub enum ProduceError {
    /// VRF の証明が作れなかった（まず起きない）
    Proof,
    /// 当たりでないか、ハーベストできない。または組んだブロックが実行できない
    Exec(ExecError),
    /// 組んだバイト列が読めない（組み方の誤り）
    Encode(String),
    /// 組んだブロックが、受け取ったブロックと同じ確かめを通らない（組み方の誤り）。catapult はこのうちの多くで、
    /// 送った相手を ban する
    Verify(VerifyError),
}

impl fmt::Display for ProduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof => write!(f, "VRF の証明が作れません"),
            Self::Exec(error) => write!(f, "{error}"),
            Self::Encode(what) => write!(f, "組んだブロックが読めません: {what}"),
            Self::Verify(error) => write!(f, "組んだブロックが確かめを通りません: {error}"),
        }
    }
}

impl std::error::Error for ProduceError {}

impl From<ExecError> for ProduceError {
    fn from(error: ExecError) -> Self {
        Self::Exec(error)
    }
}

/// 入れるかもしれない未承認のトランザクション
#[derive(Clone, Debug)]
pub struct Candidate {
    pub bytes: Vec<u8>,
    /// 最大手数料を大きさで割ったもの。ブロックの手数料の倍率がこれ以下なら入れられる
    pub fee_multiplier: u32,
    /// ブロックの件数の上限に数える数（アグリゲートは中身も）
    count: usize,
    hash: Hash256,
}

impl Candidate {
    /// 高さ `height` のブロックに入れるとして、前後に依らない確かめ（署名、連署、規則）をする。通らないものを
    /// 入れると、ブロックごと通らない
    pub fn new(
        parameters: &NetworkParameters,
        height: u64,
        bytes: Vec<u8>,
    ) -> Result<Self, VerifyError> {
        let count = verify_transaction(parameters, height, 0, &bytes)?;
        let transaction = Transaction::from_bytes(&bytes)
            .map_err(|error| VerifyError::Transaction(error.to_string()))?;
        let fee_multiplier =
            u32::try_from(transaction.fee / bytes.len() as u64).unwrap_or(u32::MAX);
        Ok(Self {
            hash: transaction.hash(&parameters.generation_hash_seed),
            bytes,
            fee_multiplier,
            count,
        })
    }

    pub fn hash(&self) -> Hash256 {
        self.hash
    }
}

/// 候補から、手数料の合計（ブロックの倍率 × 大きさの合計）が一番大きくなるものを選ぶ（catapult の
/// `maximize-fee`）。倍率の高い順に並べ、ブロックの倍率はその先頭の最後のものの倍率にする。合計が同じなら多く
/// 入れる。`min_fee_multiplier` より低いものと、件数の上限を超える分は入れない。選んだもの（入れる順）と、
/// ブロックの手数料の倍率を返す
pub fn choose(candidates: &[Candidate], min_fee_multiplier: u32) -> (Vec<Candidate>, u32) {
    let mut sorted: Vec<&Candidate> = candidates
        .iter()
        .filter(|candidate| candidate.fee_multiplier >= min_fee_multiplier)
        .collect();
    sorted.sort_by(|a, b| {
        b.fee_multiplier
            .cmp(&a.fee_multiplier)
            .then(a.hash.0.cmp(&b.hash.0))
    });
    let (mut best, mut best_fee) = (0, 0u128);
    let (mut size, mut count) = (0u128, 0);
    for (index, candidate) in sorted.iter().enumerate() {
        count += candidate.count;
        if count > MAX_TRANSACTIONS_PER_BLOCK {
            break;
        }
        size += candidate.bytes.len() as u128;
        let fee = u128::from(candidate.fee_multiplier) * size;
        if fee >= best_fee {
            (best, best_fee) = (index + 1, fee);
        }
    }
    let chosen: Vec<Candidate> = sorted[..best].iter().map(|&c| c.clone()).collect();
    let fee_multiplier = chosen.last().map_or(0, |last| last.fee_multiplier);
    (chosen, fee_multiplier)
}

/// `parent` のあとのブロックを、`signing`（リモートならリモートの鍵）と `vrf` の鍵で作る。
/// `executor` は親のあとの状態で、返したときは作ったブロックを実行したあとの状態になっている。
/// 通らなければ途中の状態なので、捨てて戻し直すこと
pub fn produce(
    executor: &mut Executor,
    parameters: &NetworkParameters,
    parent: &Parent,
    signing: &PrivateKey,
    vrf_key: &PrivateKey,
    decisions: &Decisions,
) -> Result<Block, ProduceError> {
    produce_with_statement(executor, parameters, parent, signing, vrf_key, decisions)
        .map(|(block, _)| block)
}

/// [`produce`] と同じに作り、作ったブロックを実行したときのステートメントも返す（実行し直さずにしまうのに使う）
pub fn produce_with_statement(
    executor: &mut Executor,
    parameters: &NetworkParameters,
    parent: &Parent,
    signing: &PrivateKey,
    vrf_key: &PrivateKey,
    decisions: &Decisions,
) -> Result<(Block, BlockStatement), ProduceError> {
    let proof = vrf::prove(vrf_key, &parent.generation_hash.0).ok_or(ProduceError::Proof)?;
    let (mut bytes, block_type) = assemble(parameters, parent, signing, &proof, decisions)?;
    let candidate = decode(&bytes)?;

    // 受け入れるときと同じに、親のあとの状態で当たりかを確かめてから当てる
    executor.check_harvester(
        parent.block,
        &parent.generation_hash,
        &candidate,
        parameters,
    )?;
    let produced = executor.apply_produced(&candidate)?;
    bytes[280..312].copy_from_slice(&produced.receipts_hash.0);
    bytes[312..344].copy_from_slice(&produced.state_hash.0);
    if let Some((voting, harvesting, balance)) = produced.footer {
        bytes[372..376].copy_from_slice(&voting.to_le_bytes());
        bytes[376..384].copy_from_slice(&harvesting.to_le_bytes());
        bytes[384..392].copy_from_slice(&balance.to_le_bytes());
    }
    let signed_to = match block_type {
        BlockType::Importance => IMPORTANCE_HEADER_SIZE,
        _ => NORMAL_SIGNED_TO,
    };
    let signature = signing.sign(&[&bytes[SIGNED_FROM..signed_to]]);
    bytes[8..72].copy_from_slice(&signature.0);
    let block = decode(&bytes)?;

    // 送る前に、受け取ったブロックと同じに確かめる（tip.md の「不正なブロックへの罰」）
    let tip = Tip {
        height: parent.block.height,
        hash: parent.block.hash(),
        importance_hash: parent.importance_hash,
    };
    verify_next(parameters, Some(tip), &block).map_err(ProduceError::Verify)?;
    Ok((block, produced.statement))
}

/// [`produce`] が実行する前の、署名と実行して求めるもののないブロック。作る前に、実行に要る状態を読むのに使う
pub fn draft(
    parameters: &NetworkParameters,
    parent: &Parent,
    signing: &PrivateKey,
    vrf_key: &PrivateKey,
    decisions: &Decisions,
) -> Result<Block, ProduceError> {
    let proof = vrf::prove(vrf_key, &parent.generation_hash.0).ok_or(ProduceError::Proof)?;
    let (bytes, _) = assemble(parameters, parent, signing, &proof, decisions)?;
    decode(&bytes)
}

/// `parent` のあとで、`signing` と `vrf_key` のハーベスターが当たりになる一番早い時刻（親から秒の刻み）を、
/// `until` まで探す。生成ハッシュは VRF の gamma だけで決まって時刻に依らないので、gamma は1回だけ求め、
/// 的が経過秒について増える一方なのを使って二分探索する。鍵がリンクしたものかは、作るとき（[`produce`]）に確かめる
pub fn earliest_hit(
    executor: &Executor,
    parameters: &NetworkParameters,
    parent: &Parent,
    signing: &PrivateKey,
    vrf_key: &PrivateKey,
    until: u64,
) -> Result<Option<u64>, ProduceError> {
    let gamma = vrf::gamma(vrf_key, &parent.generation_hash.0).ok_or(ProduceError::Proof)?;
    let hit = scoring::hit(&vrf::proof_hash(&gamma).generation_hash());
    let importance = executor.signer_importance(
        &PublicKey::from_private_key(signing),
        parent.block.height + 1,
    )?;
    let seconds = scoring::earliest_hit_seconds(
        hit,
        scoring::difficulty(parent.recent, parameters),
        importance,
        until.saturating_sub(parent.block.timestamp) / 1000,
        parameters,
    );
    Ok(seconds.map(|seconds| parent.block.timestamp + seconds * 1000))
}

/// 署名と、実行して求めるもの（StateHash、ReceiptsHash、importance ブロックの足）のほかを書いたバイト列
fn assemble(
    parameters: &NetworkParameters,
    parent: &Parent,
    signing: &PrivateKey,
    proof: &vrf::VrfProof,
    decisions: &Decisions,
) -> Result<(Vec<u8>, BlockType), ProduceError> {
    let height = parent.block.height + 1;
    let block_type = if height.is_multiple_of(parameters.importance_grouping) {
        BlockType::Importance
    } else {
        BlockType::Normal
    };
    let header_size = match block_type {
        BlockType::Importance => IMPORTANCE_HEADER_SIZE,
        _ => NORMAL_HEADER_SIZE,
    };
    let mut bytes = vec![0u8; header_size];
    bytes[72..104].copy_from_slice(&PublicKey::from_private_key(signing).0);
    bytes[108] = BLOCK_VERSION;
    bytes[109] = parameters.identifier.0;
    bytes[110..112].copy_from_slice(&block_type_code(block_type).to_le_bytes());
    bytes[112..120].copy_from_slice(&height.to_le_bytes());
    bytes[120..128].copy_from_slice(&decisions.timestamp.to_le_bytes());
    bytes[128..136].copy_from_slice(&scoring::difficulty(parent.recent, parameters).to_le_bytes());
    bytes[136..168].copy_from_slice(&proof.gamma);
    bytes[168..184].copy_from_slice(&proof.verification_hash);
    bytes[184..216].copy_from_slice(&proof.scalar);
    bytes[216..248].copy_from_slice(&parent.block.hash().0);
    bytes[344..368].copy_from_slice(&decisions.beneficiary.0);
    bytes[368..372].copy_from_slice(&decisions.fee_multiplier.to_le_bytes());
    if block_type == BlockType::Importance {
        bytes[392..424].copy_from_slice(&parent.importance_hash.0);
    }
    // トランザクションは 8 バイトの境目にそろえ、最後のものの後ろは埋めない
    for (index, transaction) in decisions.transactions.iter().enumerate() {
        bytes.extend_from_slice(transaction);
        if index + 1 < decisions.transactions.len() {
            bytes.resize(bytes.len().next_multiple_of(8), 0);
        }
    }
    let size =
        u32::try_from(bytes.len()).map_err(|_| ProduceError::Encode("大きすぎます".into()))?;
    bytes[0..4].copy_from_slice(&size.to_le_bytes());

    let candidate = decode(&bytes)?;
    let transactions_hash = candidate
        .calculate_transactions_hash(&parameters.generation_hash_seed)
        .map_err(|error| ProduceError::Encode(error.to_string()))?;
    bytes[248..280].copy_from_slice(&transactions_hash.0);
    Ok((bytes, block_type))
}

fn decode(bytes: &[u8]) -> Result<Block, ProduceError> {
    Block::from_bytes(bytes).map_err(|error| ProduceError::Encode(error.to_string()))
}

/// catapult の `Entity_Type_Block_*`
fn block_type_code(block_type: BlockType) -> u16 {
    match block_type {
        BlockType::Nemesis => 0x8043,
        BlockType::Normal => 0x8143,
        BlockType::Importance => 0x8243,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(fee_multiplier: u32, size: usize, tag: u8) -> Candidate {
        Candidate {
            bytes: vec![0; size],
            fee_multiplier,
            count: 1,
            hash: Hash256([tag; 32]),
        }
    }

    #[test]
    fn chooses_the_prefix_with_the_largest_total_fee() {
        // 倍率 100 の小さいものだけより、倍率 50 まで下げて大きいものも入れるほうが多い
        let candidates = [
            candidate(50, 1000, 1),
            candidate(100, 200, 2),
            candidate(10, 100, 3),
        ];
        let (chosen, multiplier) = choose(&candidates, 0);
        let tags: Vec<u8> = chosen.iter().map(|c| c.hash.0[0]).collect();
        assert_eq!((tags, multiplier), (vec![2, 1], 50));
        // 下限より低いものは入れない
        let (chosen, multiplier) = choose(&candidates, 60);
        assert_eq!((chosen.len(), multiplier), (1, 100));
        // 候補がなければ空で、倍率は 0
        assert_eq!(choose(&[], 0).1, 0);
    }

    #[test]
    fn stops_at_the_transaction_count_limit() {
        let candidates: Vec<_> = (0..MAX_TRANSACTIONS_PER_BLOCK + 5)
            .map(|index| Candidate {
                hash: Hash256([0; 32].map(|_: u8| (index % 251) as u8)),
                ..candidate(100, 100, 0)
            })
            .collect();
        assert_eq!(choose(&candidates, 0).0.len(), MAX_TRANSACTIONS_PER_BLOCK);
    }
}
