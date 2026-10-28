//! 状態の Patricia Merkle の木と、その証明。catapult の `tree/TreeNode.cpp`、`tree/PatriciaTree.h`、
//! `tree/PatriciaTreeSerializer.cpp`、`cache/CatapultCache.cpp`。
//!
//! ノードは状態を種類ごとに9本の木に分けて持ち、それぞれの根を並べた SHA3-256 が、ブロックのヘッダーの StateHash になる。
//! 木のキーは、種類ごとに決まったキーのバイト列の SHA3-256 で、値は状態のバイト列の SHA3-256。
//! キーを16進の1桁（ニブル）ずつたどる木で、たどった先のノードを根から順に並べたものが、
//! そのキーが木に「ある」こと（とその値）か、「ない」ことの証明になる。

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use sha3::{Digest, Sha3_256};

use crate::address::Address;
use crate::hash::Hash256;

/// キーのニブルの数。キーは SHA3-256 なので64。
const KEY_NIBBLES: usize = 64;

/// StateHash の元になる9本の木。catapult の `CacheId` のうち、木を持つものを同じ順に並べる。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SubCache {
    /// アカウント。キーはアドレス
    AccountState,
    /// ネームスペース。キーはルートのネームスペースの ID
    Namespace,
    /// モザイク。キーはモザイクの ID
    Mosaic,
    /// マルチシグ。キーはアドレス
    Multisig,
    /// ハッシュロック。キーはロックしたアグリゲートのハッシュ
    HashLockInfo,
    /// シークレットロック。キーはシークレットと受取人から求めたハッシュ
    SecretLockInfo,
    /// アカウントの制限。キーはアドレス
    AccountRestriction,
    /// モザイクの制限。キーはモザイクの ID とアドレスから求めたハッシュ
    MosaicRestriction,
    /// メタデータ。キーはメタデータの1件を指すハッシュ
    Metadata,
}

impl SubCache {
    /// StateHash に並べる順。
    pub const ALL: [Self; 9] = [
        Self::AccountState,
        Self::Namespace,
        Self::Mosaic,
        Self::Multisig,
        Self::HashLockInfo,
        Self::SecretLockInfo,
        Self::AccountRestriction,
        Self::MosaicRestriction,
        Self::Metadata,
    ];

    /// 9本の根の中での位置。
    pub fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|&cache| cache == self)
            .expect("listed in ALL")
    }
}

/// 9本の木の根から StateHash を求める。catapult の `CalculateStateHash`。根を順に続けた SHA3-256。
pub fn state_hash(roots: &[Hash256; 9]) -> Hash256 {
    let mut hasher = Sha3_256::new();
    for root in roots {
        hasher.update(root.0);
    }
    Hash256(hasher.finalize().into())
}

/// アドレスをキーにする木（アカウント、マルチシグ、アカウントの制限）の、木のキー。
pub fn address_key(address: &Address) -> Hash256 {
    key(&address.0)
}

/// ID をキーにする木（ネームスペース、モザイク）の、木のキー。ID はリトルエンディアンの8バイトにする。
pub fn id_key(id: u64) -> Hash256 {
    key(&id.to_le_bytes())
}

/// ハッシュをキーにする木（ロック2種類、モザイクの制限、メタデータ）の、木のキー。
pub fn hash_key(hash: &Hash256) -> Hash256 {
    key(&hash.0)
}

/// catapult の `SerializerHashedKeyEncoder`。キーのバイト列の SHA3-256。
fn key(bytes: &[u8]) -> Hash256 {
    Hash256(Sha3_256::digest(bytes).into())
}

/// 木のノード。経路はニブル（0 から 15）の並び。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TreeNode {
    /// 葉。経路はキーの残りすべてで、値は状態のハッシュ
    Leaf { path: Vec<u8>, value: Hash256 },
    /// 枝。経路のあとに、次のニブルごとの子のハッシュを持つ
    Branch {
        path: Vec<u8>,
        links: Box<[Option<Hash256>; 16]>,
    },
}

impl TreeNode {
    /// ノードのハッシュ。catapult の `LeafTreeNode` と `BranchTreeNode` の `hash`。
    /// 符号化した経路に、葉なら値を、枝なら16の子のハッシュ（ないところは0）を続けた SHA3-256。
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        match self {
            Self::Leaf { path, value } => {
                hasher.update(encode_path(path, true));
                hasher.update(value.0);
            }
            Self::Branch { path, links } => {
                hasher.update(encode_path(path, false));
                for link in links {
                    hasher.update(link.unwrap_or(Hash256([0; 32])).0);
                }
            }
        }
        Hash256(hasher.finalize().into())
    }

    pub fn path(&self) -> &[u8] {
        match self {
            Self::Leaf { path, .. } | Self::Branch { path, .. } => path,
        }
    }

    /// ノードを並べたバイト列から読む。catapult の `PatriciaTreeSerializer` の形で、ノードの状態の経路を問い合わせた答えもこれ。
    ///
    /// ```text
    /// 葉  u8 0xFF  u8 ニブルの数  経路（2ニブルで1バイト、奇数なら最後の下位は0）  [32] 値
    /// 枝  u8 0x00  u8 ニブルの数  経路  u16 子があるところのビット  [32] 子のハッシュをビットの順に
    /// ```
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>, TreeNodeDecodeError> {
        let mut rest = bytes;
        let mut nodes = Vec::new();
        while let Some((&marker, after)) = rest.split_first() {
            let offset = bytes.len() - rest.len();
            let mut reader = Reader::new(after);
            let node = match marker {
                0xFF => {
                    let path = reader
                        .path()
                        .ok_or(TreeNodeDecodeError::TooShort { offset })?;
                    let value = reader
                        .hash()
                        .ok_or(TreeNodeDecodeError::TooShort { offset })?;
                    Self::Leaf { path, value }
                }
                0x00 => {
                    let path = reader
                        .path()
                        .ok_or(TreeNodeDecodeError::TooShort { offset })?;
                    let mask = reader
                        .take(2)
                        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                        .ok_or(TreeNodeDecodeError::TooShort { offset })?;
                    let mut links = [None; 16];
                    for (index, link) in links.iter_mut().enumerate() {
                        if mask & (1 << index) != 0 {
                            *link = Some(
                                reader
                                    .hash()
                                    .ok_or(TreeNodeDecodeError::TooShort { offset })?,
                            );
                        }
                    }
                    Self::Branch {
                        path,
                        links: Box::new(links),
                    }
                }
                marker => return Err(TreeNodeDecodeError::UnknownMarker { offset, marker }),
            };
            if !reader.filler_is_zero {
                return Err(TreeNodeDecodeError::NonZeroFiller { offset });
            }
            nodes.push(node);
            rest = reader.rest;
        }
        Ok(nodes)
    }

    /// [`TreeNode::decode_all`] の形の1つのノードにする。経路のニブルが奇数なら、最後のバイトの下位は0
    pub fn encode(&self) -> Vec<u8> {
        let (marker, path) = match self {
            Self::Leaf { path, .. } => (0xFF, path),
            Self::Branch { path, .. } => (0x00, path),
        };
        let mut out = vec![marker, path.len() as u8];
        out.extend(
            path.chunks(2)
                .map(|pair| (pair[0] << 4) | pair.get(1).copied().unwrap_or(0)),
        );
        match self {
            Self::Leaf { value, .. } => out.extend_from_slice(&value.0),
            Self::Branch { links, .. } => {
                let mask = links
                    .iter()
                    .enumerate()
                    .filter(|(_, link)| link.is_some())
                    .fold(0u16, |mask, (index, _)| mask | (1 << index));
                out.extend_from_slice(&mask.to_le_bytes());
                for link in links.iter().flatten() {
                    out.extend_from_slice(&link.0);
                }
            }
        }
        out
    }
}

/// ハッシュに使う経路の符号化。catapult の `UpdateEncodedKey`。
/// 先頭の1バイトは、葉なら 0x20、ニブルが奇数なら 0x10 と最初のニブルを足す。残りは2ニブルずつ1バイトにする。
fn encode_path(path: &[u8], is_leaf: bool) -> Vec<u8> {
    let mut encoded = vec![if is_leaf { 0x20 } else { 0 }];
    let rest = if path.len() % 2 == 1 {
        encoded[0] |= 0x10 | path[0];
        &path[1..]
    } else {
        path
    };
    encoded.extend(rest.chunks(2).map(|pair| (pair[0] << 4) | pair[1]));
    encoded
}

/// キーを16進の1桁ずつに分ける。上位のニブルが先。
fn nibbles(key: &Hash256) -> [u8; KEY_NIBBLES] {
    core::array::from_fn(|index| {
        let byte = key.0[index / 2];
        if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0F
        }
    })
}

/// 根から順に並べたノードで、`key` が根 `root` の木にあるかを確かめる。catapult の `PatriciaTree::lookup` が
/// 返すノードの並びを、根からたどり直す。あれば `Some(値)`、ないことが示されれば `None`。
///
/// 並びは、根のハッシュから始めて、それぞれのノードのハッシュが1つ前の枝の、キーの次のニブルの子と合っていなければならない。
/// ないことは、キーがどこかのノードの経路と食い違うか、枝の次のニブルに子がないことで示される。
/// 空の木（根が全部0）には何もない。
///
/// 公式の SDK の `prove_patricia_merkle` と違い、葉で食い違って終わる「ない」の証明も受け付ける。
pub fn prove(
    key: &Hash256,
    nodes: &[TreeNode],
    root: &Hash256,
) -> Result<Option<Hash256>, PatriciaProofError> {
    if nodes.is_empty() {
        return if *root == Hash256([0; 32]) {
            Ok(None)
        } else {
            Err(PatriciaProofError::Incomplete)
        };
    }
    let key = nibbles(key);
    let mut position = 0;
    let mut expected = *root;
    for (index, node) in nodes.iter().enumerate() {
        if node.hash() != expected {
            return Err(PatriciaProofError::Unlinked { index });
        }
        let is_last = index + 1 == nodes.len();
        let conclude = |result: Option<Hash256>| {
            if is_last {
                Ok(result)
            } else {
                Err(PatriciaProofError::TrailingNodes { index: index + 1 })
            }
        };
        let path = node.path();
        let remaining = &key[position..];
        if !remaining.starts_with(path) {
            // 経路の途中でキーと食い違うので、このキーは木にない
            return conclude(None);
        }
        position += path.len();
        match node {
            TreeNode::Leaf { value, .. } => {
                return conclude((position == KEY_NIBBLES).then_some(*value));
            }
            TreeNode::Branch { links, .. } => {
                let Some(&nibble) = key.get(position) else {
                    return Err(PatriciaProofError::BranchAtKeyEnd { index });
                };
                position += 1;
                match links[nibble as usize] {
                    None => return conclude(None),
                    Some(_) if is_last => return Err(PatriciaProofError::Incomplete),
                    Some(link) => expected = link,
                }
            }
        }
    }
    unreachable!("the last node always concludes")
}

struct Reader<'a> {
    rest: &'a [u8],
    filler_is_zero: bool,
}

impl<'a> Reader<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self {
            rest,
            filler_is_zero: true,
        }
    }

    fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        if self.rest.len() < size {
            return None;
        }
        let (head, rest) = self.rest.split_at(size);
        self.rest = rest;
        Some(head)
    }

    fn hash(&mut self) -> Option<Hash256> {
        self.take(32)
            .map(|bytes| Hash256(bytes.try_into().expect("32 bytes")))
    }

    /// ニブルの数と経路を読む。catapult と同じく、奇数のときの埋め草のニブルは0でなければならない
    fn path(&mut self) -> Option<Vec<u8>> {
        let count = *self.take(1)?.first()? as usize;
        let bytes = self.take(count.div_ceil(2))?;
        let mut path: Vec<u8> = bytes
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0F])
            .collect();
        if count % 2 == 1 && path.pop() != Some(0) {
            self.filler_is_zero = false;
        }
        Some(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeNodeDecodeError {
    /// `offset` から始まるノードが途中で切れている
    TooShort { offset: usize },
    /// `offset` のノードの印が、葉（0xFF）でも枝（0x00）でもない
    UnknownMarker { offset: usize, marker: u8 },
    /// `offset` のノードの経路の、奇数のときの埋め草のニブルが0ではない
    NonZeroFiller { offset: usize },
}

impl fmt::Display for TreeNodeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { offset } => {
                write!(f, "{offset} バイト目からのノードが途中で切れています")
            }
            Self::UnknownMarker { offset, marker } => write!(
                f,
                "{offset} バイト目のノードの印 0x{marker:02X} は、葉でも枝でもありません"
            ),
            Self::NonZeroFiller { offset } => write!(
                f,
                "{offset} バイト目からのノードの経路の、埋め草のニブルが0ではありません"
            ),
        }
    }
}

impl core::error::Error for TreeNodeDecodeError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatriciaProofError {
    /// `index` 番目のノードのハッシュが、根か1つ前の枝の子と合わない
    Unlinked { index: usize },
    /// 最後の枝の、キーの次のニブルに子があるのに、その先のノードがない
    Incomplete,
    /// 答えが出たあとに、`index` 番目からノードが余っている
    TrailingNodes { index: usize },
    /// `index` 番目の枝で、キーのニブルを使い切っている
    BranchAtKeyEnd { index: usize },
}

impl fmt::Display for PatriciaProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlinked { index } => write!(
                f,
                "{index} 番目のノードのハッシュが、根か1つ前の枝の子と合いません"
            ),
            Self::Incomplete => {
                f.write_str("ノードが途中で終わっていて、あるともないとも言えません")
            }
            Self::TrailingNodes { index } => {
                write!(f, "答えが出たあとに、{index} 番目からノードが余っています")
            }
            Self::BranchAtKeyEnd { index } => {
                write!(f, "{index} 番目の枝で、キーを使い切っています")
            }
        }
    }
}

impl core::error::Error for PatriciaProofError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256([byte; 32])
    }

    fn sha3(parts: &[&[u8]]) -> Hash256 {
        let mut hasher = Sha3_256::new();
        for part in parts {
            hasher.update(part);
        }
        Hash256(hasher.finalize().into())
    }

    /// キーを、ニブルの並びで書く（足りないところは0）
    fn key(nibbles: &[u8]) -> Hash256 {
        let mut bytes = [0; 32];
        for (index, nibble) in nibbles.iter().enumerate() {
            bytes[index / 2] |= if index % 2 == 0 { nibble << 4 } else { *nibble };
        }
        Hash256(bytes)
    }

    /// 根の枝（経路 [1, 2]）の下に、次のニブル 3 と 7 の2つの葉がある木。
    /// キーは 1 2 3 0 0 … と 1 2 7 0 0 …
    fn tree() -> (TreeNode, TreeNode, TreeNode) {
        let leaf_a = TreeNode::Leaf {
            path: vec![0; 61],
            value: hash(0xAA),
        };
        let leaf_b = TreeNode::Leaf {
            path: vec![0; 61],
            value: hash(0xBB),
        };
        let mut links = [None; 16];
        links[3] = Some(leaf_a.hash());
        links[7] = Some(leaf_b.hash());
        let root = TreeNode::Branch {
            path: vec![1, 2],
            links: Box::new(links),
        };
        (root, leaf_a, leaf_b)
    }

    #[test]
    fn encodes_paths_like_catapult() {
        assert_eq!(encode_path(&[], false), [0x00]);
        assert_eq!(encode_path(&[], true), [0x20]);
        assert_eq!(encode_path(&[1, 2], true), [0x20, 0x12]);
        assert_eq!(encode_path(&[1, 2, 3], false), [0x11, 0x23]);
        assert_eq!(encode_path(&[1, 2, 3], true), [0x31, 0x23]);
    }

    #[test]
    fn hashes_nodes_like_catapult() {
        let leaf = TreeNode::Leaf {
            path: vec![1, 2, 3],
            value: hash(9),
        };
        assert_eq!(leaf.hash(), sha3(&[&[0x31, 0x23], &[9; 32]]));
        let mut links = [None; 16];
        links[2] = Some(hash(5));
        let branch = TreeNode::Branch {
            path: vec![],
            links: Box::new(links),
        };
        let mut expected = vec![0x00];
        for index in 0..16 {
            expected.extend_from_slice(if index == 2 { &[5; 32] } else { &[0; 32] });
        }
        assert_eq!(branch.hash(), sha3(&[&expected]));
    }

    #[test]
    fn encoded_nodes_read_back() {
        let (root, leaf_a, leaf_b) = tree();
        let nodes = vec![root, leaf_a, leaf_b];
        let bytes: Vec<u8> = nodes.iter().flat_map(TreeNode::encode).collect();
        assert_eq!(TreeNode::decode_all(&bytes), Ok(nodes));
    }

    #[test]
    fn reads_serialized_nodes() {
        let (root, leaf_a, _) = tree();
        // 枝：印、ニブル2つ、経路、ビット（3 と 7）、子2つ
        let mut bytes = vec![0x00, 2, 0x12];
        bytes.extend_from_slice(&0b1000_1000_u16.to_le_bytes());
        let TreeNode::Branch { links, .. } = &root else {
            unreachable!()
        };
        bytes.extend_from_slice(&links[3].unwrap().0);
        bytes.extend_from_slice(&links[7].unwrap().0);
        // 葉：ニブル61個は31バイトで、最後の下位のニブルは埋め草
        bytes.extend_from_slice(&[0xFF, 61]);
        bytes.extend_from_slice(&[0; 31]);
        bytes.extend_from_slice(&[0xAA; 32]);
        assert_eq!(TreeNode::decode_all(&bytes), Ok(vec![root, leaf_a]));

        let mut bad = bytes.clone();
        bad[2 + 1 + 2 + 64 + 2 + 30] = 0x01;
        assert_eq!(
            TreeNode::decode_all(&bad),
            Err(TreeNodeDecodeError::NonZeroFiller { offset: 69 })
        );
        assert_eq!(
            TreeNode::decode_all(&bytes[..bytes.len() - 1]),
            Err(TreeNodeDecodeError::TooShort { offset: 69 })
        );
        assert_eq!(
            TreeNode::decode_all(&[0x01]),
            Err(TreeNodeDecodeError::UnknownMarker {
                offset: 0,
                marker: 0x01
            })
        );
        assert_eq!(TreeNode::decode_all(&[]), Ok(vec![]));
    }

    #[test]
    fn proves_that_a_key_is_present() {
        let (root, leaf_a, leaf_b) = tree();
        let root_hash = root.hash();
        assert_eq!(
            prove(&key(&[1, 2, 3]), &[root.clone(), leaf_a], &root_hash),
            Ok(Some(hash(0xAA)))
        );
        assert_eq!(
            prove(&key(&[1, 2, 7]), &[root, leaf_b], &root_hash),
            Ok(Some(hash(0xBB)))
        );
    }

    #[test]
    fn proves_that_a_key_is_absent() {
        let (root, leaf_a, _) = tree();
        let root_hash = root.hash();
        // 枝の経路で食い違う
        assert_eq!(
            prove(&key(&[1, 5]), core::slice::from_ref(&root), &root_hash),
            Ok(None)
        );
        // 枝の次のニブルに子がない
        assert_eq!(
            prove(&key(&[1, 2, 4]), core::slice::from_ref(&root), &root_hash),
            Ok(None)
        );
        // 葉の経路で食い違う
        assert_eq!(
            prove(&key(&[1, 2, 3, 1]), &[root, leaf_a], &root_hash),
            Ok(None)
        );
        // 空の木
        assert_eq!(prove(&key(&[1]), &[], &Hash256([0; 32])), Ok(None));
    }

    #[test]
    fn refuses_broken_proofs() {
        let (root, leaf_a, leaf_b) = tree();
        let root_hash = root.hash();
        assert_eq!(
            prove(&key(&[1, 2, 3]), &[root.clone(), leaf_a.clone()], &hash(0)),
            Err(PatriciaProofError::Unlinked { index: 0 })
        );
        // 3 の子のところに、7 の葉を置く
        assert_eq!(
            prove(&key(&[1, 2, 3]), &[root.clone(), leaf_b], &root_hash),
            Err(PatriciaProofError::Unlinked { index: 1 })
        );
        assert_eq!(
            prove(&key(&[1, 2, 3]), core::slice::from_ref(&root), &root_hash),
            Err(PatriciaProofError::Incomplete)
        );
        assert_eq!(
            prove(&key(&[1, 5]), &[root.clone(), leaf_a.clone()], &root_hash),
            Err(PatriciaProofError::TrailingNodes { index: 1 })
        );
        assert_eq!(
            prove(&key(&[1, 2, 3]), &[], &root_hash),
            Err(PatriciaProofError::Incomplete)
        );
    }

    #[test]
    fn hashes_the_roots_in_cache_order() {
        let roots: [Hash256; 9] = core::array::from_fn(|index| hash(index as u8));
        let concatenated: Vec<u8> = roots.iter().flat_map(|root| root.0).collect();
        assert_eq!(state_hash(&roots), sha3(&[&concatenated]));
        assert_eq!(SubCache::AccountState.index(), 0);
        assert_eq!(SubCache::Metadata.index(), 8);
    }

    #[test]
    fn hashes_keys_by_their_bytes() {
        assert_eq!(id_key(0x0102), sha3(&[&0x0102_u64.to_le_bytes()]));
        assert_eq!(address_key(&Address([0x68; 24])), sha3(&[&[0x68; 24]]));
        assert_eq!(hash_key(&hash(3)), sha3(&[&[3; 32]]));
    }
}
