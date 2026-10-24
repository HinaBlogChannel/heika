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

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use heika_core::hash::Hash256;

use super::FinalizedBlockHeader;
use super::aggregator::RoundAggregator;
use super::message::{FinalizationMessage, SIGNATURE_SIZE, u32_at};

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

    /// しまう形。投票者の数 u32 と、（鍵 `[32]`、重み u64）の並び
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

/// ファイナライズしたブロック `header` の証明を、メッセージ `messages` から組む。catapult の `CreateFinalizationProof`。
///
/// 段階、高さ、ハッシュが同じメッセージを1つの組にまとめ、署名を並べる。組は（大きさ、署名するところのバイト列）の順、
/// 組の中の署名は渡された順。`header` のラウンドでないメッセージは入れない。組の大きさはいつも8の倍数なので、
/// 組のあいだに詰め物は要らない
pub fn build_proof<'a>(
    header: &FinalizedBlockHeader,
    messages: impl IntoIterator<Item = &'a FinalizationMessage>,
) -> Vec<u8> {
    // （大きさ、署名するところ）→（組の見本、署名の並び）
    type Group<'a> = (&'a FinalizationMessage, Vec<[u8; SIGNATURE_SIZE]>);
    let mut groups: BTreeMap<(usize, Vec<u8>), Group> = BTreeMap::new();
    for message in messages {
        if message.round != header.round {
            continue;
        }
        groups
            .entry((message.size(), message.signed_part()))
            .or_insert_with(|| (message, Vec::new()))
            .1
            .push(message.signature);
    }
    let mut body = Vec::new();
    for (template, signatures) in groups.values() {
        let size =
            GROUP_HEADER_SIZE + template.hashes.len() * 32 + signatures.len() * SIGNATURE_SIZE;
        body.extend_from_slice(&(size as u32).to_le_bytes());
        body.extend_from_slice(&(template.hashes.len() as u32).to_le_bytes());
        body.extend_from_slice(&(signatures.len() as u32).to_le_bytes());
        body.extend_from_slice(&u32::from(!template.is_prevote).to_le_bytes());
        body.extend_from_slice(&template.height.to_le_bytes());
        for hash in &template.hashes {
            body.extend_from_slice(&hash.0);
        }
        for signature in signatures {
            body.extend_from_slice(signature);
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

    let mut aggregator = RoundAggregator::new(epoch, Arc::new(voters.clone()), *parameters);
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
        let hashes: Vec<Hash256> = group[GROUP_HEADER_SIZE..GROUP_HEADER_SIZE + hashes_count * 32]
            .as_chunks::<32>()
            .0
            .iter()
            .map(|hash| Hash256(*hash))
            .collect();
        let signatures = &group[GROUP_HEADER_SIZE + hashes_count * 32..group_size];
        for signature in signatures.as_chunks::<SIGNATURE_SIZE>().0 {
            let message = FinalizationMessage {
                round: header.round,
                is_prevote,
                height,
                hashes: hashes.clone(),
                signature: *signature,
            };
            aggregator
                .add(message)
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
        .round()
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

#[cfg(test)]
mod tests {
    use super::super::FinalizationRound;
    use super::super::message::testing::{Voter, block_hash};
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
            let unsigned = FinalizationMessage {
                round: header.round,
                is_prevote: group.is_prevote,
                height: group.height,
                hashes: group.hashes.clone(),
                signature: [0; SIGNATURE_SIZE],
            };
            let signed = unsigned.signed_part();
            let hashes = &signed[24..];
            let size = GROUP_HEADER_SIZE + hashes.len() + group.voters.len() * SIGNATURE_SIZE;
            body.extend_from_slice(&(size as u32).to_le_bytes());
            body.extend_from_slice(&(group.hashes.len() as u32).to_le_bytes());
            body.extend_from_slice(&(group.voters.len() as u32).to_le_bytes());
            body.extend_from_slice(&u32::from(!group.is_prevote).to_le_bytes());
            body.extend_from_slice(&group.height.to_le_bytes());
            body.extend_from_slice(hashes);
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
    fn builds_proofs_that_verify() {
        let voters = voters();
        let header = header_at(15);
        let mut messages = Vec::new();
        for voter in &voters {
            for (is_prevote, height, through) in [(true, 10, 15), (false, 15, 15)] {
                messages.push(voter.message(
                    ROUND,
                    is_prevote,
                    height,
                    (height..=through).map(|at| block_hash(at, 0)).collect(),
                ));
            }
        }
        // 別のラウンドのメッセージは入らない
        let other = FinalizationRound {
            epoch: EPOCH,
            point: 1,
        };
        messages.push(voters[0].message(other, true, 10, vec![block_hash(10, 0)]));
        let proof = build_proof(&header, &messages);
        assert_eq!(verify(&proof, &voters), Ok(header));
        // 組は2つ（prevote と precommit）、それぞれ3人の署名
        assert_eq!(
            proof.len(),
            PROOF_HEADER_SIZE + 2 * GROUP_HEADER_SIZE + 7 * 32 + 6 * SIGNATURE_SIZE
        );
        // 渡す順を変えても同じ組になる
        let mut reversed = messages.clone();
        reversed.reverse();
        assert_eq!(
            verify(&build_proof(&header, &reversed), &voters),
            Ok(header)
        );
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
