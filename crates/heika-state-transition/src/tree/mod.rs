//! 状態の Patricia Merkle の木。catapult の `tree/PatriciaTree.h` と同じ形で、同じ根になる。
//!
//! 全部の葉を持つ [`PatriciaTree`] と、必要なノードだけを持つ [`LazyTree`] があり、[`StateTree`] はそのどちらか。
//! ノードは根からの位置（[`Position`]: 深さと、そこまでのニブル）で呼び、保存にも位置で書く。

mod full;
mod lazy;

use heika_core::hash::Hash256;
use heika_core::patricia::TreeNode;

pub use full::PatriciaTree;
pub use lazy::LazyTree;

/// キーのニブルの数。キーは SHA3-256 なので64。
const KEY_NIBBLES: usize = 64;

/// 空の木の根。catapult では全部0。
pub const EMPTY_ROOT: Hash256 = Hash256([0; 32]);

/// ノードの位置。（深さ、そこまでのニブル。後ろは0）
pub type Position = (u8, [u8; 32]);

/// 根の位置
pub const ROOT: Position = (0, [0; 32]);

/// 状態の木の1本。全部のノードを持つか、必要なノードだけを持つか
#[derive(Debug)]
pub enum StateTree {
    Full(PatriciaTree),
    Lazy(LazyTree),
}

impl Default for StateTree {
    fn default() -> Self {
        Self::Full(PatriciaTree::default())
    }
}

impl StateTree {
    pub fn set(&mut self, key: Hash256, value: Hash256) {
        match self {
            Self::Full(tree) => tree.set(key, value),
            Self::Lazy(tree) => tree.set(key, value),
        }
    }

    pub fn remove(&mut self, key: &Hash256) {
        match self {
            Self::Full(tree) => tree.remove(key),
            Self::Lazy(tree) => tree.remove(key),
        }
    }

    pub fn root(&mut self) -> Hash256 {
        match self {
            Self::Full(tree) => tree.root(),
            Self::Lazy(tree) => tree.root(),
        }
    }

    pub fn take_node_changes(&mut self) -> Vec<(Position, Option<TreeNode>)> {
        match self {
            Self::Full(tree) => tree.take_node_changes(),
            Self::Lazy(tree) => tree.take_node_changes(),
        }
    }

    pub fn forget_node_changes(&mut self) {
        match self {
            Self::Full(tree) => tree.forget_node_changes(),
            Self::Lazy(tree) => tree.forget_node_changes(),
        }
    }

    pub fn track_node_changes(&mut self, track: bool) {
        if let Self::Full(tree) = self {
            tree.track_node_changes(track);
        }
    }

    /// 全部のノードを持つ木なら、その木。全部のノード、経路、葉の値は、全部を持つときだけ引ける
    pub fn as_full(&self) -> Option<&PatriciaTree> {
        match self {
            Self::Full(tree) => Some(tree),
            Self::Lazy(_) => None,
        }
    }

    pub fn as_full_mut(&mut self) -> Option<&mut PatriciaTree> {
        match self {
            Self::Full(tree) => Some(tree),
            Self::Lazy(_) => None,
        }
    }

    pub fn as_lazy_mut(&mut self) -> Option<&mut LazyTree> {
        match self {
            Self::Full(_) => None,
            Self::Lazy(tree) => Some(tree),
        }
    }
}

/// ノードを保存するときのキー。木の番号、深さ、そこまでのニブル（深さの半分を切り上げたバイト）
pub fn node_key(cache: u8, position: &Position) -> Vec<u8> {
    let (depth, prefix) = position;
    let mut out = vec![cache, *depth];
    out.extend_from_slice(&prefix[..usize::from(*depth).div_ceil(2)]);
    out
}

/// [`node_key`] を戻す。木の番号と位置
pub fn parse_node_key(key: &[u8]) -> Option<(u8, Position)> {
    let (&cache, rest) = key.split_first()?;
    let (&depth, bytes) = rest.split_first()?;
    if bytes.len() != usize::from(depth).div_ceil(2) || usize::from(depth) > KEY_NIBBLES {
        return None;
    }
    let mut prefix = [0; 32];
    prefix[..bytes.len()].copy_from_slice(bytes);
    Some((cache, (depth, mask(&prefix, usize::from(depth)))))
}

/// `key` へ根からたどる位置を、`node` で引きながら並べる。葉に着くか、食い違うか、子がなければ終わる
pub fn walk<E>(
    key: &Hash256,
    mut node: impl FnMut(&Position) -> Result<Option<TreeNode>, E>,
) -> Result<Vec<TreeNode>, E> {
    let mut nodes = Vec::new();
    let mut depth = 0;
    while let Some(found) = node(&(depth as u8, mask(&key.0, depth)))? {
        let next = match &found {
            TreeNode::Leaf { .. } => None,
            TreeNode::Branch { path, .. } => {
                let end = depth + path.len();
                let key_path: Vec<u8> = (depth..end).map(|index| nibble(&key.0, index)).collect();
                (key_path == *path).then_some(end + 1)
            }
        };
        nodes.push(found);
        let Some(next) = next else {
            break;
        };
        depth = next;
    }
    Ok(nodes)
}

pub(crate) fn nibble(key: &[u8; 32], index: usize) -> u8 {
    let byte = key[index / 2];
    if index.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0F
    }
}

pub(crate) fn set_nibble(key: &mut [u8; 32], index: usize, value: u8) {
    let byte = &mut key[index / 2];
    if index.is_multiple_of(2) {
        *byte = (*byte & 0x0F) | (value << 4);
    } else {
        *byte = (*byte & 0xF0) | value;
    }
}

/// `depth` 個目より後ろのニブルを0にする
pub(crate) fn mask(key: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut out = [0; 32];
    out[..depth / 2].copy_from_slice(&key[..depth / 2]);
    if depth % 2 == 1 {
        out[depth / 2] = key[depth / 2] & 0xF0;
    }
    out
}
