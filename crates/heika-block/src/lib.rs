//! ブロック。catapult の `model/Block.h` と `model/Block.cpp` のレイアウトで読む。
//!
//! ```text
//!   0  u32 Size  u32 Reserved  [64] Signature  [32] SignerPublicKey  u32 Reserved
//! 108  u8 Version  u8 Network  u16 Type
//! 112  u64 Height  u64 Timestamp  u64 Difficulty
//! 136  VrfProof（Gamma 32、VerificationHash 16、Scalar 32）
//! 216  PreviousBlockHash  TransactionsHash  ReceiptsHash  StateHash（各 32）
//! 344  BeneficiaryAddress（24）  u32 FeeMultiplier
//! 372  通常のブロックは u32 のパディング（376 まで）。
//!      Nemesis と Importance のブロックは u32 VotingEligibleAccountsCount、
//!      u64 HarvestingEligibleAccountsCount、u64 TotalVotingBalance、[32] PreviousImportanceBlockHash（424 まで）
//!      この後ろにトランザクションが並ぶ
//! ```
//!
//! ブロックは作らずに読むだけなので、catapult が確かめない予約の部分は確かめない。
//!
//! std がなくても、alloc があれば使える（`#![no_std]`）。heika-core は `default-features = false` で使う。

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod finalization;
pub mod scoring;
pub mod statement;

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::merkle;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};
use heika_core::signature::Signature;
pub use heika_core::vrf::VrfProof;
use heika_core::vrf::{self, GenerationHash};
use heika_transaction::{DecodeError, Transaction};
use sha3::{Digest, Sha3_256};

/// 署名とハッシュの対象から外れる先頭の部分。catapult の `VerifiableEntity::Header_Size`。
/// サイズ、予約、署名、署名者の公開鍵、予約の順に並ぶ。
const UNSIGNED_HEADER_SIZE: usize = 4 + 4 + 64 + 32 + 4;
/// トランザクションのヘッダーの大きさ（catapult の `sizeof(Transaction)`）。ブロックの中のトランザクションはこれより小さくできない
const TRANSACTION_HEADER_SIZE: usize = UNSIGNED_HEADER_SIZE + 1 + 1 + 2 + 8 + 8;

/// 通常のブロックのヘッダー。末尾の4バイトは8バイト境界に合わせるためのパディング
const NORMAL_HEADER_SIZE: usize = 376;
/// Nemesis と Importance のブロックのヘッダー
const IMPORTANCE_HEADER_SIZE: usize = 424;
/// ヘッダーのうち、フッターの前まで
const FOOTER_OFFSET: usize = 372;

/// ブロックの種類。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockType {
    Nemesis,
    Normal,
    Importance,
}

impl BlockType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x8043 => Some(Self::Nemesis),
            0x8143 => Some(Self::Normal),
            0x8243 => Some(Self::Importance),
            _ => None,
        }
    }

    fn header_size(self) -> usize {
        match self {
            Self::Normal => NORMAL_HEADER_SIZE,
            Self::Nemesis | Self::Importance => IMPORTANCE_HEADER_SIZE,
        }
    }
}

/// Nemesis と Importance のブロックのフッター。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportanceFooter {
    pub voting_eligible_accounts_count: u32,
    pub harvesting_eligible_accounts_count: u64,
    /// 投票に使える残高の合計。通貨のモザイクの最小単位で数える。
    pub total_voting_balance: u64,
    pub previous_importance_block_hash: Hash256,
}

/// ブロック。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub signature: Signature,
    /// ハーベストしたアカウントの公開鍵。リモートハーベストならリモートアカウントのもの
    pub signer_public_key: PublicKey,
    pub version: u8,
    pub network: NetworkIdentifier,
    pub block_type: BlockType,
    pub height: u64,
    /// ネメシスのブロックからのミリ秒
    pub timestamp: u64,
    pub difficulty: u64,
    pub generation_hash_proof: VrfProof,
    pub previous_block_hash: Hash256,
    pub transactions_hash: Hash256,
    pub receipts_hash: Hash256,
    pub state_hash: Hash256,
    pub beneficiary_address: Address,
    pub fee_multiplier: u32,
    /// Nemesis と Importance のブロックだけにある
    pub importance_footer: Option<ImportanceFooter>,
    bytes: Vec<u8>,
    transactions: Vec<Range<usize>>,
}

impl Block {
    /// バイト列から読む。トランザクションは中身を読まずに、1件ずつの範囲だけを確かめる。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockDecodeError> {
        let type_at = bytes.get(110..112).ok_or(BlockDecodeError::TooShort)?;
        let raw_type = u16::from_le_bytes(type_at.try_into().expect("2 bytes"));
        let block_type =
            BlockType::from_u16(raw_type).ok_or(BlockDecodeError::UnknownType(raw_type))?;
        let header_size = block_type.header_size();
        if bytes.len() < header_size {
            return Err(BlockDecodeError::TooShort);
        }

        // 長さは確かめたので、ここから先の切り出しは失敗しない
        let array = |offset: usize| -> [u8; 32] {
            bytes[offset..offset + 32].try_into().expect("32 bytes")
        };
        let u32_at = |offset: usize| {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4 bytes"))
        };
        let u64_at = |offset: usize| {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes"))
        };

        let size = u32_at(0);
        if size as usize != bytes.len() {
            return Err(BlockDecodeError::SizeMismatch {
                stated: size,
                actual: bytes.len(),
            });
        }
        let importance_footer = (header_size == IMPORTANCE_HEADER_SIZE).then(|| ImportanceFooter {
            voting_eligible_accounts_count: u32_at(FOOTER_OFFSET),
            harvesting_eligible_accounts_count: u64_at(376),
            total_voting_balance: u64_at(384),
            previous_importance_block_hash: Hash256(array(392)),
        });
        Ok(Self {
            signature: Signature(bytes[8..72].try_into().expect("64 bytes")),
            signer_public_key: PublicKey(array(72)),
            version: bytes[108],
            network: NetworkIdentifier(bytes[109]),
            block_type,
            height: u64_at(112),
            timestamp: u64_at(120),
            difficulty: u64_at(128),
            generation_hash_proof: VrfProof {
                gamma: array(136),
                verification_hash: bytes[168..184].try_into().expect("16 bytes"),
                scalar: array(184),
            },
            previous_block_hash: Hash256(array(216)),
            transactions_hash: Hash256(array(248)),
            receipts_hash: Hash256(array(280)),
            state_hash: Hash256(array(312)),
            beneficiary_address: Address(bytes[344..368].try_into().expect("24 bytes")),
            fee_multiplier: u32_at(368),
            importance_footer,
            transactions: split_transactions(bytes, header_size)?,
            bytes: bytes.to_vec(),
        })
    }

    /// 署名の対象。ヘッダーのうちバージョンから後ろで、通常のブロックでは末尾のパディングを除く
    /// （catapult の `GetBlockHeaderDataBuffer`）。トランザクションは TransactionsHash を通して間接的に入る。
    fn signed_data(&self) -> &[u8] {
        let end = match self.block_type {
            BlockType::Normal => FOOTER_OFFSET,
            BlockType::Nemesis | BlockType::Importance => IMPORTANCE_HEADER_SIZE,
        };
        &self.bytes[UNSIGNED_HEADER_SIZE..end]
    }

    /// ハーベストしたアカウントの署名を確かめる。
    pub fn verify_signature(&self) -> bool {
        self.signer_public_key
            .verify(&[self.signed_data()], &self.signature)
    }

    /// ブロックのハッシュ。catapult の `model::CalculateHash(const Block&)` と同じく、
    /// 署名、署名者の公開鍵、署名の対象を続けた SHA3-256。トランザクションと違い generation hash seed は入らない。
    /// 次のブロックの PreviousBlockHash がこれになる。
    pub fn hash(&self) -> Hash256 {
        Hash256(
            Sha3_256::new()
                .chain_update(self.signature.0)
                .chain_update(self.signer_public_key.0)
                .chain_update(self.signed_data())
                .finalize()
                .into(),
        )
    }

    /// VRF の証明の gamma から、このブロックの generation hash を求める。証明は確かめない。
    pub fn generation_hash(&self) -> GenerationHash {
        vrf::proof_hash(&self.generation_hash_proof.gamma).generation_hash()
    }

    /// VRF の証明を確かめて、通ればこのブロックの generation hash を返す。catapult の `CheckGenerationHash` の前半。
    ///
    /// `vrf_public_key` は、ハーベストしたアカウントのメインアカウントにリンクされている VRF の鍵。
    /// `alpha` は1つ前のブロックの generation hash で、Nemesis のブロックなら generation hash seed、
    /// 鍵は署名者の公開鍵になる。
    pub fn verify_generation_hash_proof(
        &self,
        vrf_public_key: &PublicKey,
        alpha: &[u8; 32],
    ) -> Option<GenerationHash> {
        vrf::verify(vrf_public_key, alpha, &self.generation_hash_proof)
            .map(|hash| hash.generation_hash())
    }

    /// 中のトランザクションのバイト列。パディングは含まない。
    pub fn transactions(&self) -> impl Iterator<Item = &[u8]> {
        self.transactions
            .iter()
            .map(|range| &self.bytes[range.clone()])
    }

    /// 中のトランザクションから TransactionsHash を求める。catapult の `CalculateBlockTransactionsHash`。
    ///
    /// それぞれの [`Transaction::merkle_component_hash`] を葉にした Merkle ツリーの根。
    /// トランザクションのハッシュには generation hash seed が入るので、ブロックのネットワークのものを渡す。
    /// 葉を求めるにはトランザクションを丸ごと読むので、読めないものがあれば、そのエラーを返す。
    ///
    /// Nemesis のブロックだけは求め方が違う。nemgen はトランザクションの種類ごとの決まりを使わずに
    /// （catapult の `BlockExtensions` を `TransactionRegistry` なしで作る）、署名の範囲を種類で切らずに
    /// ヘッダーの後半から最後までを丸ごとハッシュし、連署者も混ぜない。ノードは Nemesis をファイルから読み、
    /// 同期してきたブロックにしか TransactionsHash を確かめないので、この違いはそのまま残っている。
    pub fn calculate_transactions_hash(
        &self,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<Hash256, DecodeError> {
        Ok(merkle::root(&self.merkle_leaves(generation_hash_seed)?))
    }

    /// `index` 番目（0から）のトランザクションの葉から、TransactionsHash までの Merkle の経路。
    /// 経路と葉（[`Block::merkle_leaves`]。Nemesis 以外は [`Transaction::merkle_component_hash`]）があれば、ブロック全体がなくても、
    /// そのトランザクションがこのブロックに入っていることを [`merkle::verify_path`] で確かめられる。
    /// `index` がトランザクションの数を超えていれば `None`。
    pub fn transaction_merkle_path(
        &self,
        generation_hash_seed: &GenerationHashSeed,
        index: usize,
    ) -> Result<Option<Vec<merkle::MerklePathNode>>, DecodeError> {
        Ok(merkle::path(
            &self.merkle_leaves(generation_hash_seed)?,
            index,
        ))
    }

    /// TransactionsHash の葉を、ブロックの中の順に並べたもの。
    ///
    /// ふつうは [`Transaction::merkle_component_hash`] で、REST の `meta.merkleComponentHash` と同じ。
    /// Nemesis だけは求め方が違い（[`Block::calculate_transactions_hash`]）、アグリゲートの葉が REST の値と合わない。
    pub fn merkle_leaves(
        &self,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<Vec<Hash256>, DecodeError> {
        if self.block_type == BlockType::Nemesis {
            return Ok(self
                .transactions()
                .map(|bytes| whole_transaction_hash(bytes, generation_hash_seed))
                .collect());
        }
        self.transactions()
            .map(|bytes| {
                Transaction::from_bytes(bytes)
                    .map(|transaction| transaction.merkle_component_hash(generation_hash_seed))
            })
            .collect()
    }

    /// ヘッダーの TransactionsHash が、中のトランザクションと合うか。
    /// ブロックの署名は TransactionsHash に掛かるので、署名と合わせて確かめれば、中のトランザクションもブロックの署名者が認めたものになる。
    pub fn verify_transactions_hash(
        &self,
        generation_hash_seed: &GenerationHashSeed,
    ) -> Result<bool, DecodeError> {
        Ok(self.calculate_transactions_hash(generation_hash_seed)? == self.transactions_hash)
    }

    /// ヘッダーの ReceiptsHash が、ステートメントから求めた Merkle の根と合うか。
    /// ステートメントはブロックに入っておらず、ブロックを実行して求めるもの。受け取ったり読み込んだりしたステートメントが、
    /// ヘッダーと合っているかを確かめる。
    pub fn verify_receipts_hash(&self, statement: &statement::BlockStatement) -> bool {
        statement.merkle_hash() == self.receipts_hash
    }

    /// ブロック全体のバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// トランザクションを、種類を問わずに丸ごとハッシュする。catapult の `model::CalculateHash(const Transaction&, ...)` の
/// 既定の対象（`TransactionDataBuffer`）で、署名、署名者の公開鍵、generation hash seed、ヘッダーの後半から最後まで。
/// アグリゲート以外は [`Transaction::hash`] と同じになる。
fn whole_transaction_hash(bytes: &[u8], generation_hash_seed: &GenerationHashSeed) -> Hash256 {
    Hash256(
        Sha3_256::new()
            .chain_update(&bytes[8..72])
            .chain_update(&bytes[72..UNSIGNED_HEADER_SIZE - 4])
            .chain_update(generation_hash_seed.0)
            .chain_update(&bytes[UNSIGNED_HEADER_SIZE..])
            .finalize()
            .into(),
    )
}

/// ヘッダーの後ろに並ぶトランザクションを、1件ずつの範囲に分ける。
///
/// catapult の `ContiguousEntityContainer` と同じく、最後のもの以外は後ろを8バイト境界までパディングする。
/// 1件の大きさは、トランザクションのヘッダー以上で、ブロックの中に収まっていなければならない。
/// 最後のものの後ろにパディングがあっても、ちょうど8バイト境界で終わっていれば catapult と同じく受け付ける。
fn split_transactions(
    bytes: &[u8],
    header_size: usize,
) -> Result<Vec<Range<usize>>, BlockDecodeError> {
    let mut transactions = Vec::new();
    let mut offset = header_size;
    while offset < bytes.len() {
        let size = bytes
            .get(offset..offset + 4)
            .map(|size| u32::from_le_bytes(size.try_into().expect("4 bytes")) as usize)
            .ok_or(BlockDecodeError::InvalidTransaction { offset })?;
        let end = offset
            .checked_add(size)
            .filter(|&end| size >= TRANSACTION_HEADER_SIZE && end <= bytes.len())
            .ok_or(BlockDecodeError::InvalidTransaction { offset })?;
        transactions.push(offset..end);
        let next = if end == bytes.len() {
            end
        } else {
            end + (size.next_multiple_of(8) - size)
        };
        // パディングの途中で終わっている
        if next > bytes.len() {
            return Err(BlockDecodeError::InvalidTransaction { offset: end });
        }
        offset = next;
    }
    Ok(transactions)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockDecodeError {
    /// ヘッダーの長さに足りない
    TooShort,
    /// 先頭のサイズが、実際の長さと合わない
    SizeMismatch { stated: u32, actual: usize },
    /// ブロックの種類ではない
    UnknownType(u16),
    /// `offset` から始まるトランザクションの大きさが、小さすぎるかブロックからはみ出している
    InvalidTransaction { offset: usize },
}

impl fmt::Display for BlockDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("ブロックのヘッダーの長さに足りません"),
            Self::SizeMismatch { stated, actual } => write!(
                f,
                "サイズは {stated} バイトとありますが、実際は {actual} バイトでした"
            ),
            Self::UnknownType(block_type) => {
                write!(f, "種類 0x{block_type:04X} はブロックではありません")
            }
            Self::InvalidTransaction { offset } => write!(
                f,
                "{offset} バイト目からのトランザクションの大きさが、小さすぎるかブロックからはみ出しています"
            ),
        }
    }
}

impl core::error::Error for BlockDecodeError {}

#[cfg(test)]
mod tests {
    use heika_core::key::PrivateKey;
    use heika_transaction::{Aggregate, Body, EmbeddedTransaction, KeyLink, LinkAction};

    use super::*;

    /// 中身を問わない、大きさ `size` のトランザクションの代わり
    fn transaction(size: usize, fill: u8) -> Vec<u8> {
        let mut transaction = vec![fill; size];
        transaction[..4].copy_from_slice(&(size as u32).to_le_bytes());
        transaction
    }

    /// `header_size` のヘッダーに `transactions` を並べ、`private_key` で署名したブロック。
    fn block(block_type: u16, transactions: &[Vec<u8>], private_key: &PrivateKey) -> Vec<u8> {
        let header_size = BlockType::from_u16(block_type).unwrap().header_size();
        let mut bytes = vec![0; header_size];
        for (index, transaction) in transactions.iter().enumerate() {
            bytes.extend_from_slice(transaction);
            if index + 1 < transactions.len() {
                bytes.resize(bytes.len().next_multiple_of(8), 0);
            }
        }
        let size = bytes.len() as u32;
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        bytes[72..104].copy_from_slice(&PublicKey::from_private_key(private_key).0);
        bytes[108] = 1;
        bytes[109] = NetworkIdentifier::MAINNET.0;
        bytes[110..112].copy_from_slice(&block_type.to_le_bytes());
        bytes[112..120].copy_from_slice(&720_u64.to_le_bytes());
        bytes[344] = 0x68;
        let signed_end = if header_size == NORMAL_HEADER_SIZE {
            FOOTER_OFFSET
        } else {
            header_size
        };
        let signature = private_key.sign(&[&bytes[UNSIGNED_HEADER_SIZE..signed_end]]);
        bytes[8..72].copy_from_slice(&signature.0);
        bytes
    }

    fn private_key() -> PrivateKey {
        PrivateKey::from_bytes(&[7; 32])
    }

    #[test]
    fn splits_transactions_padded_except_the_last() {
        let transactions = [
            transaction(130, 1),
            transaction(128, 2),
            transaction(133, 3),
        ];
        let block = Block::from_bytes(&block(0x8143, &transactions, &private_key())).unwrap();
        assert_eq!(block.block_type, BlockType::Normal);
        assert_eq!(block.height, 720);
        assert_eq!(block.importance_footer, None);
        assert!(
            block
                .transactions()
                .eq(transactions.iter().map(Vec::as_slice))
        );
        // 130 バイトのものの後ろだけ、6バイトのパディングが入る
        assert_eq!(block.as_bytes().len(), 376 + 136 + 128 + 133);
    }

    /// 署名した VrfKeyLink と、連署のあるアグリゲート
    fn signed_transactions(seed: &GenerationHashSeed) -> Vec<Transaction> {
        let signer = PublicKey::from_private_key(&private_key());
        let link = |byte| {
            Body::VrfKeyLink(KeyLink {
                linked_public_key: PublicKey([byte; 32]),
                link_action: LinkAction::Link,
            })
        };
        let mut single = Transaction::new(signer, NetworkIdentifier::MAINNET, 0, 0, link(1));
        single.sign(&private_key(), seed).unwrap();
        let aggregate = Aggregate::new(vec![EmbeddedTransaction::new(
            signer,
            NetworkIdentifier::MAINNET,
            link(2),
        )])
        .unwrap();
        let mut aggregate = Transaction::new(
            signer,
            NetworkIdentifier::MAINNET,
            0,
            0,
            Body::AggregateComplete(aggregate),
        );
        aggregate.sign(&private_key(), seed).unwrap();
        aggregate
            .cosign(&PrivateKey::from_bytes(&[8; 32]), seed)
            .unwrap();
        vec![single, aggregate]
    }

    #[test]
    fn compares_the_receipts_hash_with_the_statement() {
        use statement::{
            BlockStatement, Mosaic, Receipt, ReceiptBody, ReceiptSource, TransactionStatement,
        };

        let statement = BlockStatement {
            transaction_statements: vec![TransactionStatement {
                source: ReceiptSource {
                    primary_id: 0,
                    secondary_id: 0,
                },
                receipts: vec![Receipt {
                    version: 1,
                    body: ReceiptBody::Inflation(Mosaic {
                        mosaic_id: heika_transaction::MosaicId(1),
                        amount: 2,
                    }),
                }],
            }],
            ..BlockStatement::default()
        };
        let mut bytes = block(0x8143, &[], &private_key());
        bytes[280..312].copy_from_slice(&statement.merkle_hash().0);
        let block = Block::from_bytes(&bytes).unwrap();
        assert!(block.verify_receipts_hash(&statement));
        assert!(!block.verify_receipts_hash(&BlockStatement::default()));
    }

    #[test]
    fn verifies_the_generation_hash_proof_with_the_vrf_key() {
        let vrf_private_key = PrivateKey::from_bytes(&[9; 32]);
        let vrf_public_key = PublicKey::from_private_key(&vrf_private_key);
        let parent = [0x5A; 32];
        let proof = vrf::prove(&vrf_private_key, &parent).unwrap();
        let mut bytes = block(0x8143, &[], &private_key());
        bytes[136..168].copy_from_slice(&proof.gamma);
        bytes[168..184].copy_from_slice(&proof.verification_hash);
        bytes[184..216].copy_from_slice(&proof.scalar);
        let block = Block::from_bytes(&bytes).unwrap();
        assert_eq!(block.generation_hash_proof, proof);
        let expected = vrf::verify(&vrf_public_key, &parent, &proof)
            .unwrap()
            .generation_hash();
        assert_eq!(block.generation_hash(), expected);
        assert_eq!(
            block.verify_generation_hash_proof(&vrf_public_key, &parent),
            Some(expected)
        );
        // ブロックの署名者の鍵や、別の親では通らない
        assert_eq!(
            block.verify_generation_hash_proof(&block.signer_public_key, &parent),
            None
        );
        assert_eq!(
            block.verify_generation_hash_proof(&vrf_public_key, &[0xA5; 32]),
            None
        );
    }

    #[test]
    fn proves_that_each_transaction_is_in_the_block() {
        let seed = GenerationHashSeed::MAINNET;
        let transactions = signed_transactions(&seed);
        let bytes: Vec<_> = transactions.iter().map(Transaction::to_bytes).collect();
        let mut block_bytes = block(0x8143, &bytes, &private_key());
        let leaves: Vec<_> = transactions
            .iter()
            .map(|transaction| transaction.merkle_component_hash(&seed))
            .collect();
        block_bytes[248..280].copy_from_slice(&merkle::root(&leaves).0);
        let block = Block::from_bytes(&block_bytes).unwrap();
        for (index, leaf) in leaves.iter().enumerate() {
            let path = block
                .transaction_merkle_path(&seed, index)
                .unwrap()
                .unwrap();
            assert!(merkle::verify_path(leaf, &path, &block.transactions_hash));
        }
        assert_eq!(block.transaction_merkle_path(&seed, leaves.len()), Ok(None));
    }

    #[test]
    fn calculates_the_transactions_hash_from_merkle_component_hashes() {
        let seed = GenerationHashSeed::MAINNET;
        let transactions = signed_transactions(&seed);
        let bytes: Vec<_> = transactions.iter().map(Transaction::to_bytes).collect();
        let mut block_bytes = block(0x8143, &bytes, &private_key());
        let leaves: Vec<_> = transactions
            .iter()
            .map(|transaction| transaction.merkle_component_hash(&seed))
            .collect();
        // 連署のあるアグリゲートの葉は、ハッシュそのものではない
        assert_ne!(leaves[1], transactions[1].hash(&seed));
        let expected = merkle::root(&leaves);
        block_bytes[248..280].copy_from_slice(&expected.0);

        let block = Block::from_bytes(&block_bytes).unwrap();
        assert_eq!(block.calculate_transactions_hash(&seed), Ok(expected));
        assert_eq!(block.verify_transactions_hash(&seed), Ok(true));
        assert_eq!(
            block.verify_transactions_hash(&GenerationHashSeed::TESTNET),
            Ok(false)
        );

        let empty = Block::from_bytes(&self::block(0x8143, &[], &private_key())).unwrap();
        assert_eq!(empty.verify_transactions_hash(&seed), Ok(true));

        let unknown =
            Block::from_bytes(&self::block(0x8143, &[transaction(128, 0)], &private_key()))
                .unwrap();
        assert!(unknown.calculate_transactions_hash(&seed).is_err());
    }

    #[test]
    fn hashes_nemesis_transactions_whole() {
        let seed = GenerationHashSeed::MAINNET;
        let transactions = signed_transactions(&seed);
        let bytes: Vec<_> = transactions.iter().map(Transaction::to_bytes).collect();
        let leaves: Vec<_> = bytes
            .iter()
            .map(|bytes| whole_transaction_hash(bytes, &seed))
            .collect();
        // アグリゲート以外は、ふつうのハッシュと同じ
        assert_eq!(leaves[0], transactions[0].hash(&seed));
        // アグリゲートは、中のトランザクションと連署まで丸ごと入る
        assert_ne!(leaves[1], transactions[1].hash(&seed));
        assert_ne!(leaves[1], transactions[1].merkle_component_hash(&seed));

        let mut block_bytes = block(0x8043, &bytes, &private_key());
        block_bytes[248..280].copy_from_slice(&merkle::root(&leaves).0);
        let nemesis = Block::from_bytes(&block_bytes).unwrap();
        assert_eq!(nemesis.verify_transactions_hash(&seed), Ok(true));
        // 経路も、丸ごとハッシュした葉からつながる
        assert_eq!(nemesis.merkle_leaves(&seed), Ok(leaves.clone()));
        let path = nemesis.transaction_merkle_path(&seed, 1).unwrap().unwrap();
        assert!(merkle::verify_path(
            &leaves[1],
            &path,
            &nemesis.transactions_hash
        ));
    }

    #[test]
    fn verifies_the_signature_and_hashes_like_catapult() {
        let bytes = block(0x8143, &[transaction(128, 1)], &private_key());
        let block = Block::from_bytes(&bytes).unwrap();
        assert!(block.verify_signature());
        let expected: [u8; 32] = Sha3_256::new()
            .chain_update(&bytes[8..104])
            .chain_update(&bytes[108..372])
            .finalize()
            .into();
        assert_eq!(block.hash(), Hash256(expected));

        // 署名の対象はトランザクションを含まず、パディングも含まない
        let mut changed = bytes.clone();
        changed[372] = 0xFF;
        changed[400] ^= 1;
        let changed = Block::from_bytes(&changed).unwrap();
        assert!(changed.verify_signature());
        assert_eq!(changed.hash(), block.hash());

        let mut tampered = bytes;
        tampered[112] ^= 1;
        assert!(!Block::from_bytes(&tampered).unwrap().verify_signature());
    }

    #[test]
    fn reads_the_importance_footer_and_signs_it() {
        let mut bytes = block(0x8243, &[], &private_key());
        let block = Block::from_bytes(&bytes).unwrap();
        assert_eq!(block.block_type, BlockType::Importance);
        assert_eq!(block.transactions().count(), 0);
        assert!(block.verify_signature());
        assert_eq!(
            block
                .importance_footer
                .as_ref()
                .unwrap()
                .voting_eligible_accounts_count,
            0
        );
        // フッターは署名の対象に入る
        bytes[FOOTER_OFFSET] = 1;
        let block = Block::from_bytes(&bytes).unwrap();
        assert_eq!(
            block
                .importance_footer
                .as_ref()
                .unwrap()
                .voting_eligible_accounts_count,
            1
        );
        assert!(!block.verify_signature());
    }

    #[test]
    fn rejects_broken_blocks() {
        let bytes = block(
            0x8143,
            &[transaction(130, 1), transaction(128, 2)],
            &private_key(),
        );
        assert_eq!(
            Block::from_bytes(&bytes[..300]),
            Err(BlockDecodeError::TooShort)
        );
        assert_eq!(
            Block::from_bytes(&bytes[..bytes.len() - 1]),
            Err(BlockDecodeError::SizeMismatch {
                stated: bytes.len() as u32,
                actual: bytes.len() - 1
            })
        );

        let mut unknown = bytes.clone();
        unknown[110..112].copy_from_slice(&0x4154_u16.to_le_bytes());
        assert_eq!(
            Block::from_bytes(&unknown),
            Err(BlockDecodeError::UnknownType(0x4154))
        );

        // 大きさがトランザクションのヘッダーより小さい
        let mut small = bytes.clone();
        small[376..380].copy_from_slice(&127_u32.to_le_bytes());
        assert_eq!(
            Block::from_bytes(&small),
            Err(BlockDecodeError::InvalidTransaction { offset: 376 })
        );

        // 2件目がブロックからはみ出す
        let mut overflowing = bytes;
        overflowing[512..516].copy_from_slice(&129_u32.to_le_bytes());
        assert_eq!(
            Block::from_bytes(&overflowing),
            Err(BlockDecodeError::InvalidTransaction { offset: 512 })
        );
    }

    #[test]
    fn handles_padding_after_the_last_transaction_like_catapult() {
        let padded = |padding: usize| {
            let mut bytes = block(0x8143, &[transaction(130, 1)], &private_key());
            bytes.resize(bytes.len() + padding, 0);
            let size = bytes.len() as u32;
            bytes[..4].copy_from_slice(&size.to_le_bytes());
            Block::from_bytes(&bytes)
        };
        // 8バイト境界まで埋まっていれば、パディングを飛ばした先がちょうど終わりになるので受け付ける
        assert_eq!(padded(6).unwrap().transactions().count(), 1);
        // 途中で終わっていれば、飛ばした先が終わりを越えるので弾く
        assert_eq!(
            padded(3),
            Err(BlockDecodeError::InvalidTransaction { offset: 506 })
        );
        // 8バイト境界を越えて残っていれば、次のトランザクションとして読んで、小さすぎるので弾く
        assert_eq!(
            padded(10),
            Err(BlockDecodeError::InvalidTransaction { offset: 512 })
        );
    }
}
