//! Merkle の経路と、状態の Patricia Merkle の証明。
//!
//! - `/blocks/{height}/transactions/{hash}/merkle` と `/blocks/{height}/statements/{hash}/merkle` が返す `MerkleProofInfoDTO`
//! - `/accounts/{accountId}/merkle` などが返す `MerkleStateInfoDTO`
//!
//! 状態の証明は、問い合わせたときの最新の状態についてのもの。確かめるには、同じ高さのブロックの9本の根が要る。

use heika_core::hash::Hash256;
use heika_core::merkle::{MerklePathNode, Position};
use heika_core::patricia::TreeNode;
use serde::{Deserialize, Serialize};

use crate::{RestError, hex_array, hex_vec};

/// `MerkleProofInfoDTO`。
///
/// トランザクションの経路の葉は、REST の `meta.merkleComponentHash`（[`heika_transaction::Transaction::merkle_component_hash`]）。
/// ただし Nemesis のブロック（高さ 1）の経路は、ヘッダーの TransactionsHash にはつながらない。
/// ヘッダーは nemgen がトランザクションを丸ごとハッシュした葉で作っているのに、ノードが保存して REST が経路を作る木は、
/// ふつうの求め方の葉で作っているので、アグリゲートが入っていると2つの根が食い違う。
/// Nemesis のトランザクションを確かめるには、ブロックを丸ごと手に入れて、[`heika_block::Block::merkle_leaves`] から求める。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProofInfo {
    pub merkle_path: Vec<MerklePathItem>,
}

/// `MerklePathItemDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MerklePathItem {
    /// `left` か `right`
    pub position: String,
    pub hash: String,
}

/// 葉から根までの経路にする。[`heika_core::merkle::verify_path`] で確かめられる。
impl TryFrom<&MerkleProofInfo> for Vec<MerklePathNode> {
    type Error = RestError;

    fn try_from(info: &MerkleProofInfo) -> Result<Self, Self::Error> {
        info.merkle_path
            .iter()
            .map(|item| {
                let position = match item.position.as_str() {
                    "left" => Position::Left,
                    "right" => Position::Right,
                    _ => return Err(RestError::InvalidValue { field: "position" }),
                };
                Ok(MerklePathNode {
                    hash: Hash256(hex_array(&item.hash, "hash")?),
                    position,
                })
            })
            .collect()
    }
}

/// `MerkleStateInfoDTO`。`tree` は `raw` を読みやすくしたものなので、読まずに `raw` から組み直す。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MerkleStateInfo {
    /// ノードを根から順に並べたバイト列の16進
    pub raw: String,
}

/// 根から順に並べたノードにする。[`heika_core::patricia::prove`] で確かめられる。
impl TryFrom<&MerkleStateInfo> for Vec<TreeNode> {
    type Error = RestError;

    fn try_from(info: &MerkleStateInfo) -> Result<Self, Self::Error> {
        TreeNode::decode_all(&hex_vec(&info.raw, "raw")?).map_err(RestError::InvalidTreeNodes)
    }
}

impl MerkleStateInfo {
    /// 経路をたどり直して、`key` の状態の木での値を求める。あれば `Some(状態のハッシュ)`、ないことが示されれば `None`。
    /// `root` は、同じ時点のブロックの9本の根のうち、その状態の木の根（[`heika_core::patricia::SubCache::index`]）。
    pub fn prove(&self, key: &Hash256, root: &Hash256) -> Result<Option<Hash256>, RestError> {
        let nodes = Vec::<TreeNode>::try_from(self)?;
        heika_core::patricia::prove(key, &nodes, root).map_err(RestError::InvalidProof)
    }
}
