//! ファイナライズの証明を確かめる。catapult の `chain::VerifyFinalizationProof` と同じ手順。
//!
//! 証明（`FinalizationProof`）は、見出しのあとに、メッセージの組が並ぶ。組は同じ段階（prevote か precommit）、
//! 同じ高さから始まる同じハッシュの並びに、投票者ごとの署名を並べたもの。組と署名から1つずつメッセージを組み直し、
//! 集計器（`RoundMessageAggregator`）に足していく。
//!
//! - 1つでも足せないメッセージがあれば、証明全体を捨てる。同じ投票者が同じ段階に2つ出す（二重投票でも、同じものの重複でも）
//!   ことも、足せないうちに入る
//! - 全部足せたら、prevote と precommit の重みがどちらも閾値を超えたいちばん高いブロックが、見出しの言うものと
//!   同じかを見る
//!
//! 投票者とその重みは、証明の外から渡す。エポック E の投票者は、E − 1 の最後の高さの状態で決まる。

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::signature::Signature;
use sha3::{Digest, Sha3_256};

use super::{FinalizationRound, FinalizedBlockHeader};

/// 証明を確かめるのに要る、ネットワークの設定（config-network.properties の `[chain]` と `[finalization]`）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofParameters {
    /// `votingSetGrouping`。エポックの長さ（ブロック）
    pub voting_set_grouping: u64,
    /// `size`。閾値は、重みの合計 × `threshold` / `size`
    pub size: u64,
    /// `threshold`
    pub threshold: u64,
    /// `maxHashesPerPoint`。1つのメッセージに入れられるハッシュの数
    pub max_hashes_per_point: u64,
}

impl ProofParameters {
    /// エポック `epoch` の最後の高さ。次のエポックの投票者は、この高さの状態で決まる。
    /// catapult の `CalculateVotingSetEndHeight`
    pub fn voting_set_end_height(&self, epoch: u32) -> u64 {
        if epoch == 1 {
            1
        } else {
            (u64::from(epoch) - 1) * self.voting_set_grouping
        }
    }
}

/// エポックの投票者。投票の鍵（根の公開鍵）→ 重み
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct VotingSet {
    pub voters: BTreeMap<[u8; 32], u64>,
}

impl VotingSet {
    /// 重みの合計
    pub fn total(&self) -> u64 {
        self.voters.values().sum()
    }

    /// しまう形。投票者の数 u32 と、（鍵 [32]、重み u64）の並び
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.voters.len() * 40);
        out.extend_from_slice(&(self.voters.len() as u32).to_le_bytes());
        for (key, weight) in &self.voters {
            out.extend_from_slice(key);
            out.extend_from_slice(&weight.to_le_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let rest = bytes.get(4..)?;
        if rest.len() != count * 40 {
            return None;
        }
        let voters = rest
            .as_chunks::<40>()
            .0
            .iter()
            .map(|chunk| {
                (
                    chunk[..32].try_into().expect("32 bytes"),
                    u64::from_le_bytes(chunk[32..].try_into().expect("8 bytes")),
                )
            })
            .collect();
        Some(Self { voters })
    }
}

/// 証明を確かめられなかった理由。catapult の `VerifyFinalizationProofResult` と `RoundMessageAggregatorAddResult` に近い
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// 形が読めない
    Malformed(String),
    Version(u32),
    Epoch {
        expected: u32,
        actual: u32,
    },
    /// `index` 番目のメッセージ（組の順、署名の順に数える）を足せなかった
    Message {
        index: usize,
        reason: MessageError,
    },
    /// 閾値を超えた precommit がない
    NoPrecommit,
    /// 閾値を超えたいちばん高いブロックが、証明の言うものと違う
    Mismatch {
        height: u64,
        hash: Hash256,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// ハッシュの数が0か、多すぎる。prevote の範囲がエポックの外。precommit のハッシュが1つでない
    InvalidHashes,
    /// 最後のハッシュの高さが、投票者を決めた高さより前
    InvalidHeight,
    /// 同じ投票者が、同じ段階に違うメッセージを出している（二重投票）
    Conflicting,
    /// 同じ投票者が、同じ段階に同じメッセージを2回出している
    Redundant,
    /// 投票者ではない
    Voter,
    Signature,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "証明の形が読めません: {what}"),
            Self::Version(version) => write!(f, "知らない版の証明です（{version}）"),
            Self::Epoch { expected, actual } => {
                write!(f, "エポック {expected} の証明のはずが、{actual} です")
            }
            Self::Message { index, reason } => {
                write!(f, "{index} 番目のメッセージを足せません: {reason:?}")
            }
            Self::NoPrecommit => write!(f, "閾値を超えた precommit がありません"),
            Self::Mismatch { height, hash } => write!(
                f,
                "閾値を超えたいちばん高いブロックは、高さ {height} の {hash} で、証明の言うものと違います"
            ),
        }
    }
}

impl std::error::Error for ProofError {}

const PROOF_HEADER_SIZE: usize = 8 + FinalizedBlockHeader::SIZE;
/// `FinalizationMessageGroup` の見出し。大きさ、ハッシュの数、署名の数、段階、高さ
const GROUP_HEADER_SIZE: usize = 4 + 4 + 4 + 4 + 8;
/// `BmTreeSignature`。（根の公開鍵、根の署名）、（下の公開鍵、下の署名）
const SIGNATURE_SIZE: usize = 2 * (32 + 64);
/// `FinalizationMessage` のうち、署名しない見出し。大きさ、予約、署名
const MESSAGE_HEADER_SIZE: usize = 4 + 4 + SIGNATURE_SIZE;

/// 証明の見出し。大きさと版だけを確かめ、投票の署名と重みはまだ確かめない
pub fn proof_header(proof: &[u8]) -> Result<FinalizedBlockHeader, ProofError> {
    let malformed = |what: &str| ProofError::Malformed(what.to_owned());
    if proof.len() < PROOF_HEADER_SIZE {
        return Err(malformed("見出しより短い"));
    }
    if u32_at(proof, 0) as usize != proof.len() {
        return Err(malformed("大きさが合わない"));
    }
    let version = u32_at(proof, 4);
    if version != 1 {
        return Err(ProofError::Version(version));
    }
    FinalizedBlockHeader::from_bytes(&proof[8..PROOF_HEADER_SIZE]).map_err(|_| malformed("見出し"))
}

/// 証明が、エポックの最後の高さ（[`ProofParameters::voting_set_end_height`]）を指しているか。
/// エポックの途中のポイントの証明は、エポックが終わると最後のものに替わる
pub fn closes_epoch(header: &FinalizedBlockHeader, voting_set_grouping: u64) -> bool {
    match u64::from(header.round.epoch) {
        1 => header.height == 1,
        epoch => header.height == (epoch - 1) * voting_set_grouping,
    }
}

/// エポック `epoch` の証明を、投票者 `voters` で確かめる。確かめられたら、ファイナライズされたブロック
pub fn verify_proof(
    proof: &[u8],
    epoch: u32,
    voters: &VotingSet,
    parameters: &ProofParameters,
) -> Result<FinalizedBlockHeader, ProofError> {
    let malformed = |what: &str| ProofError::Malformed(what.to_owned());
    let header = proof_header(proof)?;
    if header.round.epoch != epoch {
        return Err(ProofError::Epoch {
            expected: epoch,
            actual: header.round.epoch,
        });
    }

    let mut aggregator = Aggregator::new(epoch, voters, parameters);
    let mut index = 0;
    let mut offset = PROOF_HEADER_SIZE;
    while offset < proof.len() {
        let group = proof
            .get(offset..)
            .filter(|rest| rest.len() >= GROUP_HEADER_SIZE);
        let group = group.ok_or_else(|| malformed("組の見出し"))?;
        let group_size = u32_at(group, 0) as usize;
        let hashes_count = u32_at(group, 4) as usize;
        let signatures_count = u32_at(group, 8) as usize;
        let stage = u32_at(group, 12);
        let height = u64::from_le_bytes(group[16..24].try_into().expect("8 bytes"));
        let real_size = GROUP_HEADER_SIZE + hashes_count * 32 + signatures_count * SIGNATURE_SIZE;
        if group_size != real_size || group.len() < group_size {
            return Err(malformed("組の大きさ"));
        }
        let is_prevote = match stage {
            0 => true,
            1 => false,
            _ => return Err(malformed("組の段階")),
        };
        let hashes = &group[GROUP_HEADER_SIZE..GROUP_HEADER_SIZE + hashes_count * 32];
        let signatures = &group[GROUP_HEADER_SIZE + hashes_count * 32..group_size];
        for signature in signatures.as_chunks::<SIGNATURE_SIZE>().0 {
            let message = Message {
                round: header.round,
                is_prevote,
                height,
                hashes,
                signature,
            };
            aggregator
                .add(&message)
                .map_err(|reason| ProofError::Message { index, reason })?;
            index += 1;
        }
        // 最後でない組は8バイトの境界までそろえてある（catapult の `ContiguousEntityContainer`）
        offset += group_size;
        if offset < proof.len() {
            offset = offset.next_multiple_of(8);
        }
    }

    let (best_height, best_hash) = aggregator
        .round
        .best_precommit()
        .ok_or(ProofError::NoPrecommit)?;
    if best_height != header.height || best_hash != header.hash {
        return Err(ProofError::Mismatch {
            height: best_height,
            hash: best_hash,
        });
    }
    Ok(header)
}

/// 投票のメッセージ1つ。catapult の `FinalizationMessage`。ノードどうしが確定の前に配り合うもので、証明は
/// これを段階と高さとハッシュごとにまとめたもの
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationMessage {
    pub round: FinalizationRound,
    pub is_prevote: bool,
    /// 最初のハッシュのブロックの高さ
    pub height: u64,
    /// 高さ `height` から続くブロックのハッシュ
    pub hashes: Vec<Hash256>,
    signature: [u8; SIGNATURE_SIZE],
}

impl FinalizationMessage {
    /// バイト列から読む。署名は確かめない（[`FinalizationMessage::verify_signature`]）
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        let malformed = |what: &str| ProofError::Malformed(what.to_owned());
        if bytes.len() < MESSAGE_HEADER_SIZE + 24 {
            return Err(malformed("メッセージの長さ"));
        }
        let size = u32_at(bytes, 0) as usize;
        let version = u32_at(bytes, MESSAGE_HEADER_SIZE);
        let hashes_count = u32_at(bytes, MESSAGE_HEADER_SIZE + 4) as usize;
        if size != bytes.len() || size != MESSAGE_HEADER_SIZE + 24 + hashes_count * 32 {
            return Err(malformed("メッセージの大きさ"));
        }
        if version != 1 {
            return Err(malformed("メッセージの版"));
        }
        let point_stage = u32_at(bytes, MESSAGE_HEADER_SIZE + 12);
        let is_prevote = point_stage & 1 == 0;
        let hashes_at = MESSAGE_HEADER_SIZE + 24;
        Ok(Self {
            round: FinalizationRound {
                epoch: u32_at(bytes, MESSAGE_HEADER_SIZE + 8),
                point: point_stage >> 1,
            },
            is_prevote,
            height: u64::from_le_bytes(
                bytes[MESSAGE_HEADER_SIZE + 16..hashes_at]
                    .try_into()
                    .expect("8 bytes"),
            ),
            hashes: bytes[hashes_at..]
                .as_chunks::<32>()
                .0
                .iter()
                .map(|hash| Hash256(*hash))
                .collect(),
            signature: bytes[8..MESSAGE_HEADER_SIZE].try_into().expect("signature"),
        })
    }

    /// 投票の鍵（BM ツリーの根の公開鍵）。[`VotingSet`] の鍵と同じもの
    pub fn root_key(&self) -> [u8; 32] {
        self.signature[..32].try_into().expect("32 bytes")
    }

    /// 根の鍵がこのエポックの下の鍵に、下の鍵がメッセージに署名しているか
    pub fn verify_signature(&self) -> bool {
        let hashes: Vec<u8> = self.hashes.iter().flat_map(|hash| hash.0).collect();
        let message = Message {
            round: self.round,
            is_prevote: self.is_prevote,
            height: self.height,
            hashes: &hashes,
            signature: &self.signature,
        };
        message.verify_signature(&message.signed_part())
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes"))
}

/// 組と署名から組み直した1つのメッセージ
struct Message<'a> {
    round: FinalizationRound,
    is_prevote: bool,
    height: u64,
    hashes: &'a [u8],
    signature: &'a [u8; SIGNATURE_SIZE],
}

impl Message<'_> {
    fn hashes_count(&self) -> u64 {
        (self.hashes.len() / 32) as u64
    }

    fn signed_part(&self) -> Vec<u8> {
        signed_part(self.round, self.is_prevote, self.height, self.hashes)
    }

    /// catapult の `CalculateMessageHash`。メッセージ全体の SHA3-256
    fn hash(&self, signed_part: &[u8]) -> [u8; 32] {
        let size = (MESSAGE_HEADER_SIZE + signed_part.len()) as u32;
        let mut hasher = Sha3_256::new();
        hasher.update(size.to_le_bytes());
        hasher.update(0u32.to_le_bytes());
        hasher.update(self.signature);
        hasher.update(signed_part);
        hasher.finalize().into()
    }

    fn root_key(&self) -> [u8; 32] {
        self.signature[..32].try_into().expect("32 bytes")
    }

    /// 2段の Bellare-Miner の署名。根の鍵が（下の鍵、エポック）に、下の鍵がメッセージに署名している
    fn verify_signature(&self, signed_part: &[u8]) -> bool {
        let root_key = PublicKey(self.root_key());
        let root_signature = Signature(self.signature[32..96].try_into().expect("64 bytes"));
        let bottom_key: [u8; 32] = self.signature[96..128].try_into().expect("32 bytes");
        let bottom_signature = Signature(self.signature[128..].try_into().expect("64 bytes"));
        let epoch = u64::from(self.round.epoch).to_le_bytes();
        root_key.verify(&[&bottom_key, &epoch], &root_signature)
            && PublicKey(bottom_key).verify(&[signed_part], &bottom_signature)
    }
}

/// メッセージの署名するところ。版、ハッシュの数、ステップ（エポック、ポイントと段階）、高さ、ハッシュ
fn signed_part(round: FinalizationRound, is_prevote: bool, height: u64, hashes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + hashes.len());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&((hashes.len() / 32) as u32).to_le_bytes());
    out.extend_from_slice(&round.epoch.to_le_bytes());
    let point_stage = (round.point << 1) | u32::from(!is_prevote);
    out.extend_from_slice(&point_stage.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(hashes);
    out
}

/// catapult の `RoundMessageAggregator`
struct Aggregator<'a> {
    epoch: u32,
    voters: &'a VotingSet,
    parameters: &'a ProofParameters,
    /// 投票者を決めた高さ
    voting_set_height: u64,
    /// （投票者、prevote か）→ メッセージのハッシュ
    messages: HashMap<([u8; 32], bool), [u8; 32]>,
    round: RoundContext,
}

impl<'a> Aggregator<'a> {
    fn new(epoch: u32, voters: &'a VotingSet, parameters: &'a ProofParameters) -> Self {
        let total = voters.total();
        // catapult は u64 のまま掛ける
        let threshold = total.wrapping_mul(parameters.threshold) / parameters.size;
        Self {
            epoch,
            voters,
            parameters,
            voting_set_height: parameters.voting_set_end_height(epoch.saturating_sub(1).max(1)),
            messages: HashMap::new(),
            round: RoundContext::new(threshold),
        }
    }

    fn add(&mut self, message: &Message) -> Result<(), MessageError> {
        let count = message.hashes_count();
        if count == 0 || count > self.parameters.max_hashes_per_point {
            return Err(MessageError::InvalidHashes);
        }
        let last_height = message.height + count - 1;
        if self.voting_set_height > last_height {
            return Err(MessageError::InvalidHeight);
        }
        if message.is_prevote {
            let min = self
                .parameters
                .voting_set_end_height(self.epoch.saturating_sub(1).max(1));
            let max = self.parameters.voting_set_end_height(self.epoch);
            if message.height < min || last_height > max {
                return Err(MessageError::InvalidHashes);
            }
        } else if count != 1 {
            return Err(MessageError::InvalidHashes);
        }

        let signed_part = message.signed_part();
        let key = (message.root_key(), message.is_prevote);
        let hash = message.hash(&signed_part);
        if let Some(existing) = self.messages.get(&key) {
            return Err(if *existing == hash {
                MessageError::Redundant
            } else {
                MessageError::Conflicting
            });
        }
        // catapult の `ProcessMessage`。予約と版は組み直したときに 0 と 1 にしてある
        let weight = self
            .voters
            .voters
            .get(&message.root_key())
            .copied()
            .unwrap_or(0);
        if weight == 0 {
            return Err(MessageError::Voter);
        }
        if !message.verify_signature(&signed_part) {
            return Err(MessageError::Signature);
        }
        self.messages.insert(key, hash);
        let hashes: Vec<Hash256> = message
            .hashes
            .as_chunks::<32>()
            .0
            .iter()
            .map(|hash| Hash256(*hash))
            .collect();
        if message.is_prevote {
            self.round.accept_prevote(message.height, &hashes, weight);
        } else {
            self.round
                .accept_precommit(message.height, hashes[0], weight);
        }
        Ok(())
    }
}

type Candidate = (u64, Hash256);

#[derive(Clone, Copy, Default, Debug)]
struct Weights {
    prevote: u64,
    precommit: u64,
}

/// catapult の `RoundContext` と `FinalizationHashTree`
struct RoundContext {
    threshold: u64,
    /// （高さ、ハッシュ）の順。いちばん高いものから探す
    candidates: BTreeMap<(u64, [u8; 32]), Weights>,
    /// 子 → 親。最初に足した枝のつながりを使う
    parents: HashMap<Candidate, Option<Candidate>>,
    /// 先に届いた precommit で、まだその prevote がないもの
    pending_precommits: HashMap<Candidate, u64>,
}

impl RoundContext {
    fn new(threshold: u64) -> Self {
        Self {
            threshold,
            candidates: BTreeMap::new(),
            parents: HashMap::new(),
            pending_precommits: HashMap::new(),
        }
    }

    fn best_precommit(&self) -> Option<Candidate> {
        self.candidates
            .iter()
            .rev()
            .find(|(_, weights)| {
                weights.prevote >= self.threshold && weights.precommit >= self.threshold
            })
            .map(|((height, hash), _)| (*height, Hash256(*hash)))
    }

    /// 自分を含めて、根へたどる
    fn ancestors(&self, key: Candidate) -> Vec<Candidate> {
        let mut out = Vec::new();
        let mut current = self.parents.contains_key(&key).then_some(key);
        while let Some(node) = current {
            out.push(node);
            current = self.parents[&node];
        }
        out
    }

    fn accept_prevote(&mut self, height: u64, hashes: &[Hash256], weight: u64) {
        let mut parent = None;
        for (index, hash) in hashes.iter().enumerate() {
            let key = (height + index as u64, *hash);
            self.parents.entry(key).or_insert(parent);
            parent = Some(key);
        }
        for (index, hash) in hashes.iter().enumerate() {
            let key = (height + index as u64, *hash);
            self.candidates.entry((key.0, key.1.0)).or_default().prevote += weight;
            if let Some(pending) = self.pending_precommits.remove(&key) {
                for ancestor in self.ancestors(key) {
                    self.candidates
                        .get_mut(&(ancestor.0, ancestor.1.0))
                        .expect("ancestors are candidates")
                        .precommit += pending;
                }
            }
        }
    }

    fn accept_precommit(&mut self, height: u64, hash: Hash256, weight: u64) {
        let ancestors = self.ancestors((height, hash));
        if ancestors.is_empty() {
            *self.pending_precommits.entry((height, hash)).or_default() += weight;
            return;
        }
        for ancestor in ancestors {
            self.candidates
                .get_mut(&(ancestor.0, ancestor.1.0))
                .expect("ancestors are candidates")
                .precommit += weight;
        }
    }
}

#[cfg(test)]
mod tests {
    use heika_core::key::PrivateKey;

    use super::*;

    /// エポックは 10 ブロック。エポック 3 の prevote は高さ 10〜20
    const PARAMETERS: ProofParameters = ProofParameters {
        voting_set_grouping: 10,
        size: 10_000,
        threshold: 6_700,
        max_hashes_per_point: 256,
    };
    const EPOCH: u32 = 3;
    const ROUND: FinalizationRound = FinalizationRound {
        epoch: EPOCH,
        point: 2,
    };

    /// 根の鍵と、エポックごとの下の鍵
    struct Voter {
        root: PrivateKey,
        bottom: PrivateKey,
    }

    impl Voter {
        fn new(seed: u8) -> Self {
            Self {
                root: PrivateKey::from_bytes(&[seed; 32]),
                bottom: PrivateKey::from_bytes(&[seed ^ 0x80; 32]),
            }
        }

        fn key(&self) -> [u8; 32] {
            PublicKey::from_private_key(&self.root).0
        }

        /// `BmTreeSignature`
        fn sign(&self, round: FinalizationRound, signed: &[u8]) -> Vec<u8> {
            let bottom = PublicKey::from_private_key(&self.bottom).0;
            let epoch = u64::from(round.epoch).to_le_bytes();
            let mut out = Vec::with_capacity(SIGNATURE_SIZE);
            out.extend_from_slice(&self.key());
            out.extend_from_slice(&self.root.sign(&[&bottom, &epoch]).0);
            out.extend_from_slice(&bottom);
            out.extend_from_slice(&self.bottom.sign(&[signed]).0);
            out
        }
    }

    /// 高さ `height` のブロックのハッシュ。`fork` で別の枝にする
    fn block_hash(height: u64, fork: u8) -> Hash256 {
        let mut hash = [fork; 32];
        hash[..8].copy_from_slice(&height.to_le_bytes());
        Hash256(hash)
    }

    struct Group<'a> {
        is_prevote: bool,
        height: u64,
        hashes: Vec<Hash256>,
        voters: Vec<&'a Voter>,
    }

    fn prevote(height: u64, through: u64, voters: Vec<&Voter>) -> Group<'_> {
        Group {
            is_prevote: true,
            height,
            hashes: (height..=through).map(|at| block_hash(at, 0)).collect(),
            voters,
        }
    }

    fn precommit(height: u64, voters: Vec<&Voter>) -> Group<'_> {
        Group {
            is_prevote: false,
            height,
            hashes: vec![block_hash(height, 0)],
            voters,
        }
    }

    /// catapult と同じ形の証明を組む。最後でない組は8バイトの境界までそろえる
    fn build(header: &FinalizedBlockHeader, groups: &[Group]) -> Vec<u8> {
        let mut body = Vec::new();
        for (index, group) in groups.iter().enumerate() {
            let hashes: Vec<u8> = group.hashes.iter().flat_map(|hash| hash.0).collect();
            let signed = signed_part(header.round, group.is_prevote, group.height, &hashes);
            let size = GROUP_HEADER_SIZE + hashes.len() + group.voters.len() * SIGNATURE_SIZE;
            body.extend_from_slice(&(size as u32).to_le_bytes());
            body.extend_from_slice(&(group.hashes.len() as u32).to_le_bytes());
            body.extend_from_slice(&(group.voters.len() as u32).to_le_bytes());
            body.extend_from_slice(&u32::from(!group.is_prevote).to_le_bytes());
            body.extend_from_slice(&group.height.to_le_bytes());
            body.extend_from_slice(&hashes);
            for voter in &group.voters {
                body.extend_from_slice(&voter.sign(header.round, &signed));
            }
            if index + 1 < groups.len() {
                body.resize(body.len().next_multiple_of(8), 0);
            }
        }
        let size = PROOF_HEADER_SIZE + body.len();
        let mut proof = Vec::with_capacity(size);
        proof.extend_from_slice(&(size as u32).to_le_bytes());
        proof.extend_from_slice(&1u32.to_le_bytes());
        proof.extend_from_slice(&header.to_bytes());
        proof.extend_from_slice(&body);
        proof
    }

    fn header_at(height: u64) -> FinalizedBlockHeader {
        FinalizedBlockHeader {
            round: ROUND,
            height,
            hash: block_hash(height, 0),
        }
    }

    /// 重み 40、30、30 の3人。閾値は 67
    fn voters() -> [Voter; 3] {
        [Voter::new(1), Voter::new(2), Voter::new(3)]
    }

    fn voting_set(voters: &[Voter], weights: &[u64]) -> VotingSet {
        VotingSet {
            voters: voters
                .iter()
                .zip(weights)
                .map(|(voter, weight)| (voter.key(), *weight))
                .collect(),
        }
    }

    fn verify(proof: &[u8], voters: &[Voter]) -> Result<FinalizedBlockHeader, ProofError> {
        verify_proof(
            proof,
            EPOCH,
            &voting_set(voters, &[40, 30, 30]),
            &PARAMETERS,
        )
    }

    #[test]
    fn reads_and_verifies_a_single_message() {
        let voter = Voter::new(1);
        let hashes: Vec<u8> = (10..=12).flat_map(|at| block_hash(at, 0).0).collect();
        let signed = signed_part(ROUND, false, 10, &hashes);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MESSAGE_HEADER_SIZE + signed.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&voter.sign(ROUND, &signed));
        bytes.extend_from_slice(&signed);
        let message = FinalizationMessage::from_bytes(&bytes).unwrap();
        assert_eq!(message.round, ROUND);
        assert!(!message.is_prevote);
        assert_eq!(message.height, 10);
        assert_eq!(
            message.hashes,
            (10..=12).map(|at| block_hash(at, 0)).collect::<Vec<_>>()
        );
        assert_eq!(message.root_key(), voter.key());
        assert!(message.verify_signature());

        // 署名したところを変えると通らない。大きさが合わなければ読まない
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            !FinalizationMessage::from_bytes(&changed)
                .unwrap()
                .verify_signature()
        );
        assert!(FinalizationMessage::from_bytes(&bytes[..bytes.len() - 32]).is_err());
    }

    #[test]
    fn accepts_a_proof_with_enough_weight() {
        let voters = voters();
        let [a, b, c] = &voters;
        let header = header_at(15);
        let proof = build(
            &header,
            &[prevote(10, 15, vec![a, b, c]), precommit(15, vec![a, b, c])],
        );
        assert_eq!(verify(&proof, &voters), Ok(header));
        assert_eq!(proof_header(&proof), Ok(header));
        // 40 + 30 = 70 で閾値の 67 を超える
        let proof = build(
            &header,
            &[prevote(10, 15, vec![a, b]), precommit(15, vec![a, b])],
        );
        assert_eq!(verify(&proof, &voters), Ok(header));
    }

    #[test]
    fn counts_a_precommit_that_comes_before_its_prevote() {
        let voters = voters();
        let [a, b, c] = &voters;
        let header = header_at(15);
        let proof = build(
            &header,
            &[precommit(15, vec![a, b, c]), prevote(10, 15, vec![a, b, c])],
        );
        assert_eq!(verify(&proof, &voters), Ok(header));
    }

    #[test]
    fn rejects_too_little_weight() {
        let voters = voters();
        let [a, b, c] = &voters;
        // 30 + 30 = 60
        let proof = build(
            &header_at(15),
            &[prevote(10, 15, vec![b, c]), precommit(15, vec![b, c])],
        );
        assert_eq!(verify(&proof, &voters), Err(ProofError::NoPrecommit));
        // prevote は足りても、precommit が足りない
        let proof = build(
            &header_at(15),
            &[prevote(10, 15, vec![a, b, c]), precommit(15, vec![a])],
        );
        assert_eq!(verify(&proof, &voters), Err(ProofError::NoPrecommit));
    }

    #[test]
    fn rejects_a_header_that_is_not_the_best_precommit() {
        let voters = voters();
        let [a, b, c] = &voters;
        let proof = build(
            &header_at(14),
            &[prevote(10, 15, vec![a, b, c]), precommit(15, vec![a, b, c])],
        );
        assert_eq!(
            verify(&proof, &voters),
            Err(ProofError::Mismatch {
                height: 15,
                hash: block_hash(15, 0)
            })
        );
    }

    #[test]
    fn rejects_double_and_repeated_votes() {
        let voters = voters();
        let [a, b, c] = &voters;
        let header = header_at(15);
        let mut forked = prevote(10, 15, vec![a]);
        forked.hashes[5] = block_hash(15, 1);
        let proof = build(
            &header,
            &[
                prevote(10, 15, vec![a, b, c]),
                forked,
                precommit(15, vec![a, b, c]),
            ],
        );
        assert_eq!(
            verify(&proof, &voters),
            Err(ProofError::Message {
                index: 3,
                reason: MessageError::Conflicting
            })
        );
        let proof = build(
            &header,
            &[
                prevote(10, 15, vec![a, b, c, a]),
                precommit(15, vec![a, b, c]),
            ],
        );
        assert_eq!(
            verify(&proof, &voters),
            Err(ProofError::Message {
                index: 3,
                reason: MessageError::Redundant
            })
        );
    }

    #[test]
    fn rejects_strangers_and_broken_signatures() {
        let voters = voters();
        let [a, b, c] = &voters;
        let stranger = Voter::new(9);
        let header = header_at(15);
        let proof = build(
            &header,
            &[prevote(10, 15, vec![a, &stranger]), precommit(15, vec![a])],
        );
        assert_eq!(
            verify(&proof, &voters),
            Err(ProofError::Message {
                index: 1,
                reason: MessageError::Voter
            })
        );
        let mut proof = build(
            &header,
            &[prevote(10, 15, vec![a, b, c]), precommit(15, vec![a, b, c])],
        );
        // 最初のメッセージの下の署名の最後のバイト
        let last = PROOF_HEADER_SIZE + GROUP_HEADER_SIZE + 6 * 32 + SIGNATURE_SIZE - 1;
        proof[last] ^= 1;
        assert_eq!(
            verify(&proof, &voters),
            Err(ProofError::Message {
                index: 0,
                reason: MessageError::Signature
            })
        );
    }

    #[test]
    fn rejects_hashes_outside_the_epoch() {
        let voters = voters();
        let [a, ..] = &voters;
        let header = header_at(15);
        // エポック 3 の prevote は高さ 10〜20
        for group in [prevote(9, 15, vec![a]), prevote(15, 21, vec![a])] {
            let proof = build(&header, &[group]);
            assert_eq!(
                verify(&proof, &voters),
                Err(ProofError::Message {
                    index: 0,
                    reason: MessageError::InvalidHashes
                })
            );
        }
        // precommit のハッシュは1つ
        let mut group = precommit(15, vec![a]);
        group.hashes.push(block_hash(16, 0));
        assert_eq!(
            verify(&build(&header, &[group]), &voters),
            Err(ProofError::Message {
                index: 0,
                reason: MessageError::InvalidHashes
            })
        );
        // 投票者を決めた高さ（10）より前で終わる
        let proof = build(&header, &[precommit(9, vec![a])]);
        assert_eq!(
            verify(&proof, &voters),
            Err(ProofError::Message {
                index: 0,
                reason: MessageError::InvalidHeight
            })
        );
    }

    #[test]
    fn rejects_malformed_proofs() {
        let voters = voters();
        let [a, b, c] = &voters;
        let proof = build(
            &header_at(15),
            &[prevote(10, 15, vec![a, b, c]), precommit(15, vec![a, b, c])],
        );
        assert_eq!(
            verify_proof(&proof, 4, &voting_set(&voters, &[40, 30, 30]), &PARAMETERS),
            Err(ProofError::Epoch {
                expected: 4,
                actual: 3
            })
        );
        let mut versioned = proof.clone();
        versioned[4] = 2;
        assert_eq!(verify(&versioned, &voters), Err(ProofError::Version(2)));
        assert!(matches!(
            verify(&proof[..proof.len() - 1], &voters),
            Err(ProofError::Malformed(_))
        ));
        assert!(matches!(
            proof_header(&proof[..10]),
            Err(ProofError::Malformed(_))
        ));
        let mut staged = proof.clone();
        staged[PROOF_HEADER_SIZE + 12] = 2;
        assert!(matches!(
            verify(&staged, &voters),
            Err(ProofError::Malformed(_))
        ));
    }

    #[test]
    fn voting_sets_round_trip() {
        let voters = voters();
        let set = voting_set(&voters, &[40, 30, 30]);
        assert_eq!(set.total(), 100);
        assert_eq!(VotingSet::decode(&set.encode()), Some(set.clone()));
        let encoded = set.encode();
        assert_eq!(VotingSet::decode(&encoded[..encoded.len() - 1]), None);
    }

    #[test]
    fn knows_which_heights_close_an_epoch() {
        assert_eq!(PARAMETERS.voting_set_end_height(1), 1);
        assert_eq!(PARAMETERS.voting_set_end_height(3), 20);
        let at = |epoch, height| FinalizedBlockHeader {
            round: FinalizationRound { epoch, point: 1 },
            height,
            hash: Hash256([0; 32]),
        };
        assert!(closes_epoch(&at(1, 1), 10));
        assert!(closes_epoch(&at(3, 20), 10));
        assert!(!closes_epoch(&at(3, 15), 10));
    }
}
