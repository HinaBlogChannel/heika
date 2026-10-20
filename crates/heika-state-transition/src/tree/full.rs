//! 全部の葉を持つ状態の木。葉の集まりから組む。catapult の `tree/PatriciaTree.h` と同じ形になる。
//!
//! 葉はキーの順に持ち、木のノードはその場で組む。途中のノードのハッシュは覚えておき、葉が変わったら
//! その葉から根までの道にあるものだけを忘れる。なので根を求め直すときに計算するのは、変わった葉の上だけになる。
//! ノードのハッシュの求め方は、経路を確かめる側と同じ [`TreeNode::hash`] を使う。
//!
//! ノードは、根からの位置（深さと、そこまでのニブル）で呼ぶ。[`PatriciaTree::take_node_changes`] で、変わったノードの
//! 今のノードか、なくなったことを返す。値が変わっただけなら、変わるのは根を求めるときに計算し直したノードだけなので、
//! そのとき組んだノードを取っておいて返す。葉を足したり外したりすると、その葉への道の上のノードと枝の子も
//! 現れたり消えたりするので、変える前と後の形でその位置を見る。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{BuildHasherDefault, Hasher};

use heika_core::hash::Hash256;
use heika_core::patricia::TreeNode;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{EMPTY_ROOT, KEY_NIBBLES, Position, ROOT, mask, nibble, set_nibble};

/// 葉の集まり。キーは木のキー（状態のキーの SHA3-256）、値は状態のハッシュ。
#[derive(Clone, Default, Debug)]
pub struct PatriciaTree {
    /// キーはバイト列で持つ。Hash256 には順序がないので
    leaves: BTreeMap<[u8; 32], Hash256>,
    /// （深さ、そこまでのニブル）で決まる部分木の根のハッシュ
    memo: HashMap<Position, Hash256, PositionHash>,
    /// 同じく、部分木の根の形。ハッシュと同じところで忘れる
    shapes: HashMap<Position, Shape, PositionHash>,
    /// 前にノードの変化を返してから、根を求めるときに組み直したノード
    fresh: BTreeMap<Position, TreeNode>,
    /// 前にノードの変化を返してから、足したか外した葉への、変える前の道の上のノードと枝の子の位置
    affected: BTreeSet<Position>,
    /// 前にノードの変化を返してから、足したか外した葉。木の形が変わる
    restructured: BTreeSet<[u8; 32]>,
    /// ノードの変化を覚えない。木を丸ごと組むときに、全部のノードを溜めないため
    untracked: bool,
    /// 前に根を求めてから、置いたか外した葉の数。多ければ、根を求めるときに部分木を並列に計算する
    pending: usize,
}

/// 位置のハッシュ。標準の SipHash は外から来るキーで衝突を狙われないためのもので遅い。
/// 位置は自分で作るので狙われないため、rustc の FxHash と同じ、8バイトずつ掛けて混ぜるだけのものにする。
/// 葉を置き換えるたびに、道の上の深さ 0〜64 の位置を全部忘れるので、ここが速さに効く
type PositionHash = BuildHasherDefault<PositionHasher>;

#[derive(Default)]
struct PositionHasher(u64);

impl PositionHasher {
    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(Self::SEED);
    }
}

impl Hasher for PositionHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            self.add(u64::from_le_bytes(*word));
        }
        for &byte in rest {
            self.add(u64::from(byte));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.add(u64::from(value));
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// 部分木の根のノードの形。ハッシュを求めずに、葉の並びだけからわかる
#[derive(Clone, Copy, Debug)]
enum Shape {
    Leaf([u8; 32]),
    /// 枝。`end` 個目のニブルで分かれ、`children` は子があるところのビット
    Branch {
        first: [u8; 32],
        end: usize,
        children: u16,
    },
}

impl PatriciaTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// しまったノードから戻す。葉の並びは葉のノードから、途中のハッシュは枝が持つ子のハッシュから埋めるので、
    /// ハッシュを求め直さない。ノードは1つの木の全部で、位置と合っていること
    pub fn from_nodes(nodes: impl IntoIterator<Item = (Position, TreeNode)>) -> Self {
        let mut tree = Self::new();
        for ((depth, mut prefix), node) in nodes {
            let depth = usize::from(depth);
            match node {
                TreeNode::Leaf { path, value } => {
                    for (index, nibble) in path.iter().enumerate() {
                        set_nibble(&mut prefix, depth + index, *nibble);
                    }
                    tree.leaves.insert(prefix, value);
                }
                TreeNode::Branch { path, links } => {
                    for (index, nibble) in path.iter().enumerate() {
                        set_nibble(&mut prefix, depth + index, *nibble);
                    }
                    let end = depth + path.len();
                    for (value, link) in links.iter().enumerate() {
                        if let Some(hash) = link {
                            let mut child = prefix;
                            set_nibble(&mut child, end, value as u8);
                            tree.memo
                                .insert(((end + 1) as u8, mask(&child, end + 1)), *hash);
                        }
                    }
                }
            }
        }
        tree
    }

    /// 葉を置く。同じキーがあれば値を置き換える。値が変わらなければ何もしない。
    pub fn set(&mut self, key: Hash256, value: Hash256) {
        match self.leaves.get(&key.0) {
            Some(current) if *current == value => {}
            Some(_) => {
                // 形は変わらないので、覚えた形はそのまま使える。変わるノードは、根を求めるときに組み直すものだけ
                self.pending += 1;
                self.leaves.insert(key.0, value);
                self.forget_hashes(&key.0);
            }
            None => {
                self.pending += 1;
                self.note_restructure(&key.0);
                self.leaves.insert(key.0, value);
                self.forget(&key.0);
            }
        }
    }

    /// 葉を外す。
    pub fn remove(&mut self, key: &Hash256) {
        if !self.leaves.contains_key(&key.0) {
            return;
        }
        self.pending += 1;
        self.note_restructure(&key.0);
        self.leaves.remove(&key.0);
        self.forget(&key.0);
    }

    /// 変える前の形で、`key` への道の上のノードと枝の子の位置を覚える
    fn note_restructure(&mut self, key: &[u8; 32]) {
        if !self.untracked && self.restructured.insert(*key) {
            let positions = self.walk_positions(key, true);
            self.affected.extend(positions);
        }
    }

    /// 前に呼んでから変わったノード。位置と、今のノードか、なくなったら `None`
    pub fn take_node_changes(&mut self) -> Vec<(Position, Option<TreeNode>)> {
        // 中身が変わったノードは、根を求めるときに組み直したものになる
        self.root();
        let mut changes: BTreeMap<Position, Option<TreeNode>> = std::mem::take(&mut self.fresh)
            .into_iter()
            .map(|(position, node)| (position, Some(node)))
            .collect();
        // 足したか外した葉では、ハッシュを覚えたままの部分木が、別の位置に現れたり消えたりする。
        // 変える前の道と、今の道（と枝の子）を見る
        let mut positions = std::mem::take(&mut self.affected);
        for key in std::mem::take(&mut self.restructured) {
            positions.extend(self.walk_positions(&key, true));
        }
        for position in positions {
            if changes.contains_key(&position) {
                continue;
            }
            let node = if self.is_node(&position) {
                self.subtree_node(&position.1, usize::from(position.0))
            } else {
                None
            };
            changes.insert(position, node);
        }
        changes.into_iter().collect()
    }

    /// ノードの変化を覚えるか。覚えないあいだは、根を求めても組んだノードを取っておかない。
    /// 覚え始めるときは、[`PatriciaTree::forget_node_changes`] でそれまでのものを捨ててから
    pub fn track_node_changes(&mut self, track: bool) {
        self.untracked = !track;
    }

    /// 今の木で、`position` から始まるノードがあるか
    fn is_node(&mut self, (target, prefix): &Position) -> bool {
        let target = usize::from(*target);
        let mut depth = 0;
        loop {
            let Some(shape) = self.shape(&mask(prefix, depth), depth) else {
                return false;
            };
            if depth == target {
                return true;
            }
            let Shape::Branch { first, end, .. } = shape else {
                return false;
            };
            // 位置が枝の経路の途中か、分かれるニブルそのものなら、そこから始まるノードはない
            if target <= end
                || (depth..end).any(|index| nibble(prefix, index) != nibble(&first, index))
            {
                return false;
            }
            depth = end + 1;
        }
    }

    /// 今の形で、`key` への道の上のノードの位置と、`children` なら枝の子の位置も。キーがなければ、食い違うところまで
    fn walk_positions(&mut self, key: &[u8; 32], children: bool) -> Vec<Position> {
        let mut positions = Vec::new();
        let mut depth = 0;
        loop {
            let prefix = mask(key, depth);
            let Some(shape) = self.shape(&prefix, depth) else {
                break;
            };
            positions.push((depth as u8, prefix));
            let Shape::Branch {
                first,
                end,
                children: mask_bits,
            } = shape
            else {
                break;
            };
            for value in 0..16 {
                if children && mask_bits & (1 << value) != 0 {
                    let mut child = mask(&first, end);
                    set_nibble(&mut child, end, value);
                    positions.push(((end + 1) as u8, child));
                }
            }
            if (depth..end).any(|index| nibble(key, index) != nibble(&first, index)) {
                break;
            }
            depth = end + 1;
        }
        positions
    }

    /// 木の全部のノード。根から順に
    pub fn nodes(&mut self) -> Vec<(Position, TreeNode)> {
        let mut nodes = Vec::new();
        let mut stack = vec![ROOT];
        while let Some(position) = stack.pop() {
            let Some(node) = self.subtree_node(&position.1, usize::from(position.0)) else {
                continue;
            };
            if let TreeNode::Branch { path, links } = &node {
                let end = usize::from(position.0) + path.len();
                let mut prefix = position.1;
                for (index, &value) in path.iter().enumerate() {
                    set_nibble(&mut prefix, usize::from(position.0) + index, value);
                }
                for (value, link) in links.iter().enumerate().rev() {
                    if link.is_some() {
                        let mut child = prefix;
                        set_nibble(&mut child, end, value as u8);
                        stack.push(((end + 1) as u8, child));
                    }
                }
            }
            nodes.push((position, node));
        }
        nodes
    }

    /// ノードの変化を覚えるのをやめて、捨てる。DB にあるものと同じ木を組み直したとき
    pub fn forget_node_changes(&mut self) {
        self.fresh.clear();
        self.affected.clear();
        self.restructured.clear();
    }

    pub fn get(&self, key: &Hash256) -> Option<Hash256> {
        self.leaves.get(&key.0).copied()
    }

    /// 葉のキーを順に。
    pub fn keys(&self) -> impl Iterator<Item = Hash256> + '_ {
        self.leaves.keys().map(|key| Hash256(*key))
    }

    /// 根のハッシュ。空なら [`EMPTY_ROOT`]。
    pub fn root(&mut self) -> Hash256 {
        let pending = std::mem::take(&mut self.pending);
        #[cfg(feature = "parallel")]
        if pending >= PARALLEL_LEAVES {
            self.compute_in_parallel();
        }
        #[cfg(not(feature = "parallel"))]
        let _ = pending;
        self.subtree_hash(&[0; 32], 0).unwrap_or(EMPTY_ROOT)
    }

    /// 求め直す部分木を、深さ [`PARALLEL_DEPTH`] で分けて並列に計算し、覚える。部分木どうしは重ならないので、
    /// それぞれは木を読むだけにして、求めたものは [`Overlay`] にためておき、あとでまとめて覚える
    #[cfg(feature = "parallel")]
    fn compute_in_parallel(&mut self) {
        let mut parts = Vec::new();
        let mut stack = vec![ROOT];
        while let Some((depth, prefix)) = stack.pop() {
            if self.memo.contains_key(&(depth, prefix)) {
                continue;
            }
            let Some(shape) = self.shape(&prefix, usize::from(depth)) else {
                continue;
            };
            match shape {
                Shape::Branch {
                    first,
                    end,
                    children,
                } if usize::from(depth) < PARALLEL_DEPTH => {
                    for value in 0..16 {
                        if children & (1 << value) != 0 {
                            let mut child = mask(&first, end);
                            set_nibble(&mut child, end, value);
                            stack.push(((end + 1) as u8, child));
                        }
                    }
                }
                _ => parts.push((depth, prefix)),
            }
        }
        let tree = &*self;
        let computed: Vec<_> = parts
            .par_iter()
            .map(|(depth, prefix)| {
                let mut overlay = Overlay::new(tree);
                subtree_hash(&mut overlay, prefix, usize::from(*depth));
                (overlay.memo, overlay.shapes, overlay.fresh)
            })
            .collect();
        for (memo, shapes, fresh) in computed {
            self.memo.extend(memo);
            self.shapes.extend(shapes);
            self.fresh.extend(fresh);
        }
    }

    /// `key` までの経路。根から順に並べたノードで、[`heika_core::patricia::prove`] で確かめられる。
    /// キーが木になければ、ないことを示す経路になる。空の木なら空。
    pub fn path(&mut self, key: &Hash256) -> Vec<TreeNode> {
        let nodes: Result<_, std::convert::Infallible> = super::walk(key, |(depth, prefix)| {
            Ok(self.subtree_node(prefix, usize::from(*depth)))
        });
        nodes.unwrap_or_else(|never| match never {})
    }

    /// 葉を足したか外したので、その葉から根までのノードのハッシュと形を忘れる
    fn forget(&mut self, key: &[u8; 32]) {
        self.forget_hashes(key);
        if self.shapes.is_empty() {
            return;
        }
        for depth in 0..=KEY_NIBBLES {
            self.shapes.remove(&(depth as u8, mask(key, depth)));
        }
    }

    /// 葉の値が変わったので、その葉から根までのノードのハッシュを忘れる。形はそのまま
    fn forget_hashes(&mut self, key: &[u8; 32]) {
        if self.memo.is_empty() {
            return;
        }
        for depth in 0..=KEY_NIBBLES {
            self.memo.remove(&(depth as u8, mask(key, depth)));
        }
    }

    /// `depth` 個目までのニブルが `prefix` と同じ葉からなる部分木の根の形
    fn shape(&mut self, prefix: &[u8; 32], depth: usize) -> Option<Shape> {
        shape(self, prefix, depth)
    }

    /// `depth` 個目までのニブルが `prefix` と同じ葉からなる部分木の根のノード
    fn subtree_node(&mut self, prefix: &[u8; 32], depth: usize) -> Option<TreeNode> {
        subtree_node(self, prefix, depth)
    }

    fn subtree_hash(&mut self, prefix: &[u8; 32], depth: usize) -> Option<Hash256> {
        subtree_hash(self, prefix, depth)
    }
}

/// 根を求めるときに、これだけ葉が変わっていれば部分木を並列に計算する（`parallel` 機能）。普通のブロックの
/// アカウントは数十なので並列にしない
#[cfg(feature = "parallel")]
const PARALLEL_LEAVES: usize = 512;

/// 並列に計算する部分木の深さ。キーは SHA3 で散らばるので、深さ 2 で 256 に分かれる
#[cfg(feature = "parallel")]
const PARALLEL_DEPTH: usize = 2;

/// 部分木の形とハッシュを覚えるところ。木そのものか、並列に計算するときの上書き（`Overlay`）
trait Memo {
    fn leaves(&self) -> &BTreeMap<[u8; 32], Hash256>;
    fn shape_of(&self, position: &Position) -> Option<Shape>;
    fn remember_shape(&mut self, position: Position, shape: Shape);
    fn hash_of(&self, position: &Position) -> Option<Hash256>;
    /// 組んだノードとそのハッシュを覚える
    fn remember_hash(&mut self, position: Position, hash: Hash256, node: TreeNode);
}

impl Memo for PatriciaTree {
    fn leaves(&self) -> &BTreeMap<[u8; 32], Hash256> {
        &self.leaves
    }

    fn shape_of(&self, position: &Position) -> Option<Shape> {
        self.shapes.get(position).copied()
    }

    fn remember_shape(&mut self, position: Position, shape: Shape) {
        self.shapes.insert(position, shape);
    }

    fn hash_of(&self, position: &Position) -> Option<Hash256> {
        self.memo.get(position).copied()
    }

    fn remember_hash(&mut self, position: Position, hash: Hash256, node: TreeNode) {
        self.memo.insert(position, hash);
        if !self.untracked {
            self.fresh.insert(position, node);
        }
    }
}

/// 並列に計算するとき、木を読むだけにして、求めたものをためておく上書き
#[cfg(feature = "parallel")]
struct Overlay<'a> {
    tree: &'a PatriciaTree,
    memo: HashMap<Position, Hash256, PositionHash>,
    shapes: HashMap<Position, Shape, PositionHash>,
    fresh: Vec<(Position, TreeNode)>,
}

#[cfg(feature = "parallel")]
impl<'a> Overlay<'a> {
    fn new(tree: &'a PatriciaTree) -> Self {
        Self {
            tree,
            memo: HashMap::default(),
            shapes: HashMap::default(),
            fresh: Vec::new(),
        }
    }
}

#[cfg(feature = "parallel")]
impl Memo for Overlay<'_> {
    fn leaves(&self) -> &BTreeMap<[u8; 32], Hash256> {
        &self.tree.leaves
    }

    fn shape_of(&self, position: &Position) -> Option<Shape> {
        self.shapes
            .get(position)
            .or_else(|| self.tree.shapes.get(position))
            .copied()
    }

    fn remember_shape(&mut self, position: Position, shape: Shape) {
        self.shapes.insert(position, shape);
    }

    fn hash_of(&self, position: &Position) -> Option<Hash256> {
        self.memo
            .get(position)
            .or_else(|| self.tree.memo.get(position))
            .copied()
    }

    fn remember_hash(&mut self, position: Position, hash: Hash256, node: TreeNode) {
        self.memo.insert(position, hash);
        if !self.tree.untracked {
            self.fresh.push((position, node));
        }
    }
}

/// `depth` 個目までのニブルが `prefix` と同じ葉の、最初と最後
fn bounds(
    leaves: &BTreeMap<[u8; 32], Hash256>,
    prefix: &[u8; 32],
    depth: usize,
) -> Option<([u8; 32], [u8; 32])> {
    let low = mask(prefix, depth);
    let high = fill(prefix, depth);
    let mut range = leaves.range(low..=high);
    let first = *range.next()?.0;
    let last = range.next_back().map_or(first, |(key, _)| *key);
    Some((first, last))
}

/// `depth` 個目までのニブルが `prefix` と同じ葉からなる部分木の根の形
fn shape(memo: &mut impl Memo, prefix: &[u8; 32], depth: usize) -> Option<Shape> {
    let position = (depth as u8, mask(prefix, depth));
    if let Some(shape) = memo.shape_of(&position) {
        return Some(shape);
    }
    let shape = find_shape(memo.leaves(), prefix, depth)?;
    memo.remember_shape(position, shape);
    Some(shape)
}

fn find_shape(
    leaves: &BTreeMap<[u8; 32], Hash256>,
    prefix: &[u8; 32],
    depth: usize,
) -> Option<Shape> {
    let (first, last) = bounds(leaves, prefix, depth)?;
    if first == last {
        return Some(Shape::Leaf(first));
    }
    // 並んでいるので、最初と最後が同じところまでは全部同じ
    let end = (depth..KEY_NIBBLES)
        .find(|&index| nibble(&first, index) != nibble(&last, index))
        .expect("different keys differ somewhere");
    let mut children = 0;
    for value in nibble(&first, end)..=nibble(&last, end) {
        let mut child = mask(&first, end);
        set_nibble(&mut child, end, value);
        if bounds(leaves, &child, end + 1).is_some() {
            children |= 1 << value;
        }
    }
    Some(Shape::Branch {
        first,
        end,
        children,
    })
}

/// `depth` 個目までのニブルが `prefix` と同じ葉からなる部分木の根のノード
fn subtree_node(memo: &mut impl Memo, prefix: &[u8; 32], depth: usize) -> Option<TreeNode> {
    let (first, end) = match shape(memo, prefix, depth)? {
        Shape::Leaf(key) => {
            return Some(TreeNode::Leaf {
                path: (depth..KEY_NIBBLES)
                    .map(|index| nibble(&key, index))
                    .collect(),
                value: memo.leaves()[&key],
            });
        }
        Shape::Branch { first, end, .. } => (first, end),
    };
    let mut links: Box<[Option<Hash256>; 16]> = Box::new([None; 16]);
    for (value, link) in links.iter_mut().enumerate() {
        let mut child = mask(&first, end);
        set_nibble(&mut child, end, value as u8);
        *link = subtree_hash(memo, &child, end + 1);
    }
    Some(TreeNode::Branch {
        path: (depth..end).map(|index| nibble(&first, index)).collect(),
        links,
    })
}

fn subtree_hash(memo: &mut impl Memo, prefix: &[u8; 32], depth: usize) -> Option<Hash256> {
    let position = (depth as u8, mask(prefix, depth));
    if let Some(hash) = memo.hash_of(&position) {
        return Some(hash);
    }
    let node = subtree_node(memo, prefix, depth)?;
    let hash = node.hash();
    memo.remember_hash(position, hash, node);
    Some(hash)
}

/// `depth` 個目より後ろのニブルを F にする
fn fill(key: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut out = [0xFF; 32];
    out[..depth / 2].copy_from_slice(&key[..depth / 2]);
    if depth % 2 == 1 {
        out[depth / 2] = key[depth / 2] | 0x0F;
    }
    out
}

#[cfg(test)]
mod tests {
    use heika_core::patricia::prove;

    use super::super::{node_key, parse_node_key};
    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256([byte; 32])
    }

    /// 先頭のバイトを決めたキー。残りは `fill`
    fn key(prefix: &[u8], fill: u8) -> Hash256 {
        let mut bytes = [fill; 32];
        bytes[..prefix.len()].copy_from_slice(prefix);
        Hash256(bytes)
    }

    /// 覚えたハッシュを使わずに組み直した根
    fn fresh_root(tree: &PatriciaTree) -> Hash256 {
        let mut copy = PatriciaTree::new();
        for (key, value) in &tree.leaves {
            copy.set(Hash256(*key), *value);
        }
        copy.root()
    }

    #[test]
    fn empty_tree_has_zero_root_and_empty_path() {
        let mut tree = PatriciaTree::new();
        assert_eq!(tree.root(), EMPTY_ROOT);
        assert!(tree.path(&hash(1)).is_empty());
        assert_eq!(prove(&hash(1), &[], &EMPTY_ROOT), Ok(None));
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let mut tree = PatriciaTree::new();
        tree.set(hash(1), hash(2));
        let leaf = TreeNode::Leaf {
            path: (0..KEY_NIBBLES)
                .map(|index| nibble(&hash(1).0, index))
                .collect(),
            value: hash(2),
        };
        assert_eq!(tree.root(), leaf.hash());
    }

    #[test]
    fn paths_prove_presence_and_absence() {
        let mut tree = PatriciaTree::new();
        let keys = [
            key(&[0x12, 0x34], 0),
            key(&[0x12, 0x35], 0),
            key(&[0x12, 0x35], 1),
            key(&[0x80], 0),
            key(&[0xF0], 7),
        ];
        for (index, key) in keys.iter().enumerate() {
            tree.set(*key, hash(index as u8 + 10));
        }
        let root = tree.root();
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(
                prove(key, &tree.path(key), &root),
                Ok(Some(hash(index as u8 + 10)))
            );
        }
        // ない: 枝の子がない、経路の途中で食い違う、葉で食い違う
        for missing in [key(&[0x50], 0), key(&[0x12, 0x36], 0), key(&[0x80], 1)] {
            assert_eq!(prove(&missing, &tree.path(&missing), &root), Ok(None));
        }
    }

    #[test]
    fn root_does_not_depend_on_insertion_order_and_tracks_removal() {
        let keys = [key(&[0xAB], 3), key(&[0xAC], 3), key(&[0x0A], 3)];
        let mut forward = PatriciaTree::new();
        let mut backward = PatriciaTree::new();
        for key in keys {
            forward.set(key, hash(1));
        }
        for key in keys.iter().rev() {
            backward.set(*key, hash(1));
        }
        assert_eq!(forward.root(), backward.root());

        let mut smaller = PatriciaTree::new();
        smaller.set(keys[0], hash(1));
        smaller.set(keys[2], hash(1));
        forward.remove(&keys[1]);
        assert_eq!(forward.root(), smaller.root());
    }

    #[test]
    fn nodes_round_trip_through_bytes() {
        let mut tree = PatriciaTree::new();
        for key in [
            key(&[0x12, 0x34], 0),
            key(&[0x12, 0x35], 0),
            key(&[0x80], 0),
        ] {
            tree.set(key, hash(1));
        }
        let nodes: Vec<TreeNode> = tree.nodes().into_iter().map(|(_, node)| node).collect();
        let bytes: Vec<u8> = nodes.iter().flat_map(TreeNode::encode).collect();
        assert_eq!(TreeNode::decode_all(&bytes).unwrap(), nodes);
    }

    /// ノードの変化を位置の表に当てていくと、いつも木の全部のノードと同じになる
    #[test]
    fn node_changes_track_all_nodes() {
        let mut tree = PatriciaTree::new();
        let mut stored: BTreeMap<Position, TreeNode> = BTreeMap::new();
        let mut state = 0x9E37_79B9_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407);
            state >> 33
        };
        // キーを少なめにして、足す、替える、外すが同じキーに何度も当たるようにする。
        // 先頭の8ニブルを0と1だけにして、長い経路が途中で分かれたりつながったりするようにする
        let keys: Vec<Hash256> = (0..64)
            .map(|_| {
                let mut bytes = [0; 32];
                for byte in bytes.iter_mut().take(4) {
                    let bits = next();
                    *byte = (((bits & 1) as u8) << 4) | ((bits >> 1) & 1) as u8;
                }
                for byte in bytes.iter_mut().skip(4) {
                    *byte = next() as u8;
                }
                Hash256(bytes)
            })
            .collect();
        for round in 0..200 {
            for _ in 0..(1 + next() % 5) {
                let key = keys[(next() % 64) as usize];
                if next() % 3 == 0 {
                    tree.remove(&key);
                } else {
                    tree.set(key, hash((next() % 4) as u8));
                }
            }
            tree.root();
            for (position, node) in tree.take_node_changes() {
                match node {
                    Some(node) => stored.insert(position, node),
                    None => stored.remove(&position),
                };
            }
            let all: BTreeMap<Position, TreeNode> = tree.nodes().into_iter().collect();
            assert_eq!(stored, all, "round {round}");
        }
    }

    /// たくさん変えて部分木を並列に計算しても、少しずつ変えたときと同じ根とノードになる
    #[test]
    fn parallel_roots_match_small_steps() {
        let mut state = 0x2545_F491_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407);
            state
        };
        let keys: Vec<Hash256> = (0..6000)
            .map(|_| {
                let mut bytes = [0; 32];
                for chunk in bytes.chunks_mut(8) {
                    chunk.copy_from_slice(&next().to_le_bytes());
                }
                Hash256(bytes)
            })
            .collect();
        let mut big = PatriciaTree::new();
        let mut small = PatriciaTree::new();
        // 最初の 4000 は一度に置く
        for key in &keys[..4000] {
            big.set(*key, hash(1));
        }
        for chunk in keys[..4000].chunks(100) {
            for key in chunk {
                small.set(*key, hash(1));
            }
            small.root();
        }
        assert_eq!(big.root(), small.root());
        let mut stored: BTreeMap<Position, TreeNode> = big.nodes().into_iter().collect();
        big.forget_node_changes();
        // 値を替える、外す、足すを一度に
        let mut ops: Vec<(Hash256, Option<Hash256>)> = Vec::new();
        for key in keys[..1500].iter() {
            ops.push((*key, Some(hash(2))));
        }
        for key in keys[1500..1800].iter() {
            ops.push((*key, None));
        }
        for key in keys[4000..4300].iter() {
            ops.push((*key, Some(hash(3))));
        }
        for (key, value) in &ops {
            match value {
                Some(value) => big.set(*key, *value),
                None => big.remove(key),
            }
        }
        for chunk in ops.chunks(100) {
            for (key, value) in chunk {
                match value {
                    Some(value) => small.set(*key, *value),
                    None => small.remove(key),
                }
            }
            small.root();
        }
        assert_eq!(big.root(), small.root());
        assert_eq!(big.root(), fresh_root(&big));
        for (position, node) in big.take_node_changes() {
            match node {
                Some(node) => stored.insert(position, node),
                None => stored.remove(&position),
            };
        }
        let all: BTreeMap<Position, TreeNode> = big.nodes().into_iter().collect();
        assert_eq!(stored, all);
    }

    #[test]
    fn trees_come_back_from_nodes() {
        let mut tree = PatriciaTree::new();
        for index in 0..200u8 {
            let mut bytes = [index.wrapping_mul(37); 32];
            bytes[1] = index;
            tree.set(Hash256(bytes), hash(index));
        }
        let root = tree.root();
        let nodes = tree.nodes();
        for (position, _) in &nodes {
            assert_eq!(parse_node_key(&node_key(3, position)), Some((3, *position)));
        }
        let mut back = PatriciaTree::from_nodes(nodes);
        assert_eq!(back.leaves, tree.leaves);
        assert_eq!(back.root(), root);
        // 戻したあとも、変えれば正しく求め直す
        back.set(Hash256([9; 32]), hash(1));
        tree.set(Hash256([9; 32]), hash(1));
        assert_eq!(back.root(), tree.root());
    }

    #[test]
    fn remembered_hashes_follow_changes() {
        let mut tree = PatriciaTree::new();
        // 擬似乱数のキーで、枝が深いところも浅いところもできるようにする
        let mut state = 0x1234_5678_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            state
        };
        let mut keys = Vec::new();
        for _ in 0..300 {
            let mut bytes = [0; 32];
            for chunk in bytes.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            // 半分は先頭をそろえて、長い共通の経路を作る
            if keys.len() % 2 == 0 {
                bytes[..3].copy_from_slice(&[0xAB, 0xCD, 0xE0]);
            }
            keys.push(Hash256(bytes));
        }
        for (round, chunk) in keys.chunks(50).enumerate() {
            for key in chunk {
                tree.set(*key, hash(round as u8));
            }
            // 前の組の葉を書き換えたり外したりする
            if round > 0 {
                tree.set(keys[(round - 1) * 50], hash(200));
                tree.remove(&keys[(round - 1) * 50 + 1]);
            }
            assert_eq!(tree.root(), fresh_root(&tree), "round {round}");
        }
    }
}
