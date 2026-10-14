//! ブロック。`/blocks/{height}` と `/blocks` が返す `BlockInfoDTO`。
//!
//! REST のブロックはヘッダーだけで、中のトランザクションは別に返す。なので、ヘッダーだけのバイト列を組み直す。
//! ブロックのハッシュと署名はヘッダーだけに掛かるので、ヘッダーだけでも求め直せる。

use heika_block::Block;
use heika_core::hash::Hash256;
use heika_core::patricia;
use heika_core::vrf::GenerationHash;
use serde::Deserialize;

use crate::{RestError, hex_array, number};

/// `BlockInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct BlockInfo {
    pub meta: BlockMeta,
    pub block: BlockHeader,
}

/// `BlockMetaDTO`。ノードがブロックを実行して求めた値。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockMeta {
    pub hash: String,
    pub generation_hash: String,
    pub total_fee: String,
    /// 状態の9本の木の根。ノードの設定で状態のハッシュを使っていなければ空
    pub state_hash_sub_cache_merkle_roots: Vec<String>,
    pub total_transactions_count: u32,
    pub transactions_count: u32,
    pub statements_count: u32,
}

/// `BlockDTO` と `ImportanceBlockDTO`。Importance のフッターの4つは、Nemesis と Importance のブロックにだけある。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    /// 中のトランザクションも含めたブロック全体の大きさ
    pub size: u32,
    pub signature: String,
    pub signer_public_key: String,
    pub version: u8,
    pub network: u8,
    #[serde(rename = "type")]
    pub block_type: u16,
    pub height: String,
    pub timestamp: String,
    pub difficulty: String,
    pub proof_gamma: String,
    pub proof_verification_hash: String,
    pub proof_scalar: String,
    pub previous_block_hash: String,
    pub transactions_hash: String,
    pub receipts_hash: String,
    pub state_hash: String,
    pub beneficiary_address: String,
    pub fee_multiplier: u32,
    pub voting_eligible_accounts_count: Option<u32>,
    pub harvesting_eligible_accounts_count: Option<String>,
    pub total_voting_balance: Option<String>,
    pub previous_importance_block_hash: Option<String>,
}

impl BlockHeader {
    /// ヘッダーだけのバイト列を組み直す。先頭のサイズは、ヘッダーだけの大きさにする（ハッシュと署名の対象には入らない）。
    pub fn to_header_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&hex_array::<64>(&self.signature, "signature")?);
        bytes.extend_from_slice(&hex_array::<32>(
            &self.signer_public_key,
            "signerPublicKey",
        )?);
        bytes.extend_from_slice(&[0; 4]);
        bytes.push(self.version);
        bytes.push(self.network);
        bytes.extend_from_slice(&self.block_type.to_le_bytes());
        for (text, field) in [
            (&self.height, "height"),
            (&self.timestamp, "timestamp"),
            (&self.difficulty, "difficulty"),
        ] {
            bytes.extend_from_slice(&number(text, field)?.to_le_bytes());
        }
        bytes.extend_from_slice(&hex_array::<32>(&self.proof_gamma, "proofGamma")?);
        bytes.extend_from_slice(&hex_array::<16>(
            &self.proof_verification_hash,
            "proofVerificationHash",
        )?);
        bytes.extend_from_slice(&hex_array::<32>(&self.proof_scalar, "proofScalar")?);
        for (text, field) in [
            (&self.previous_block_hash, "previousBlockHash"),
            (&self.transactions_hash, "transactionsHash"),
            (&self.receipts_hash, "receiptsHash"),
            (&self.state_hash, "stateHash"),
        ] {
            bytes.extend_from_slice(&hex_array::<32>(text, field)?);
        }
        bytes.extend_from_slice(&hex_array::<24>(
            &self.beneficiary_address,
            "beneficiaryAddress",
        )?);
        bytes.extend_from_slice(&self.fee_multiplier.to_le_bytes());
        match (
            self.voting_eligible_accounts_count,
            &self.harvesting_eligible_accounts_count,
            &self.total_voting_balance,
            &self.previous_importance_block_hash,
        ) {
            (Some(voting), Some(harvesting), Some(balance), Some(previous)) => {
                bytes.extend_from_slice(&voting.to_le_bytes());
                bytes.extend_from_slice(
                    &number(harvesting, "harvestingEligibleAccountsCount")?.to_le_bytes(),
                );
                bytes.extend_from_slice(&number(balance, "totalVotingBalance")?.to_le_bytes());
                bytes.extend_from_slice(&hex_array::<32>(previous, "previousImportanceBlockHash")?);
            }
            (None, None, None, None) => bytes.extend_from_slice(&[0; 4]),
            _ => {
                return Err(RestError::InvalidValue {
                    field: "previousImportanceBlockHash",
                });
            }
        }
        let size = bytes.len() as u32;
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        Ok(bytes)
    }
}

/// ヘッダーだけのブロックにする。中のトランザクションは空になる。
impl TryFrom<&BlockHeader> for Block {
    type Error = RestError;

    fn try_from(header: &BlockHeader) -> Result<Self, Self::Error> {
        Block::from_bytes(&header.to_header_bytes()?).map_err(RestError::InvalidBlock)
    }
}

impl BlockInfo {
    /// ヘッダーを組み直し、REST が一緒に返した値と、組み直したものから求めた値が合うかを確かめる。
    ///
    /// 確かめるのは、署名、ブロックのハッシュ（`meta.hash`）、VRF の証明の gamma からの generation hash
    /// （`meta.generationHash`）、9本の根からの StateHash。
    /// ブロックの中で辻褄が合っていることまでで、チェーンのつながりや、VRF の証明がハーベストした人の鍵で正しいことは、
    /// 呼び出し側で前のブロックや鍵と合わせて確かめる。
    pub fn verify(&self) -> Result<Block, RestError> {
        let block = Block::try_from(&self.block)?;
        if !block.verify_signature() {
            return Err(RestError::Mismatch { field: "signature" });
        }
        if block.hash() != Hash256(hex_array(&self.meta.hash, "meta.hash")?) {
            return Err(RestError::Mismatch { field: "meta.hash" });
        }
        let generation_hash = GenerationHash(hex_array(
            &self.meta.generation_hash,
            "meta.generationHash",
        )?);
        if block.generation_hash() != generation_hash {
            return Err(RestError::Mismatch {
                field: "meta.generationHash",
            });
        }
        if block.state_hash != self.state_hash()? {
            return Err(RestError::Mismatch { field: "stateHash" });
        }
        Ok(block)
    }

    /// 9本の根。状態のハッシュを使っていないノードなら空。
    pub fn sub_cache_merkle_roots(&self) -> Result<Vec<Hash256>, RestError> {
        self.meta
            .state_hash_sub_cache_merkle_roots
            .iter()
            .map(|root| hex_array(root, "meta.stateHashSubCacheMerkleRoots").map(Hash256))
            .collect()
    }

    /// 9本の根から求めた StateHash。根がなければ catapult と同じく全部0。
    fn state_hash(&self) -> Result<Hash256, RestError> {
        let roots = self.sub_cache_merkle_roots()?;
        if roots.is_empty() {
            return Ok(Hash256([0; 32]));
        }
        let roots: [Hash256; 9] = roots.try_into().map_err(|_| RestError::InvalidValue {
            field: "meta.stateHashSubCacheMerkleRoots",
        })?;
        Ok(patricia::state_hash(&roots))
    }
}
