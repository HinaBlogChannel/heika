//! 必要なノードだけをメモリに持つ状態の木。[`super::PatriciaTree`] と同じ根になる（catapult の
//! `tree/PatriciaTree.h` と同じ形）が、葉を全部は持たない。
//!
//! ノードは根からの位置（[`Position`]）で呼び、保存にも位置で書いてある。葉を置くか外すときは、根からその葉までの
//! 道のノードだけを読む。経路が食い違えばノードを割り、外して枝の子が1つになれば残った子と合わせる。ハッシュは、
//! 変わったノードだけを下から求め直す。枝のノードは子のハッシュを 16 個とも持っているので、兄弟の中身は要らない。
//!
//! まだ読んでいないノードが要ったら、その位置を記録して何もしない。記録があった実行は捨てて、記録された位置を
//! 読んでから当て直す。

use std::collections::{BTreeMap, BTreeSet};

use heika_core::hash::Hash256;
use heika_core::patricia::TreeNode;

use super::{EMPTY_ROOT, KEY_NIBBLES, Position, ROOT, mask, nibble, set_nibble};

/// この深さまでの位置のノードは、捨てずにいつも持つ（根に近いノードは、ほぼどの葉の道にもある）
const PINNED_DEPTH: u8 = 3;

#[derive(Default, Debug)]
pub struct LazyTree {
    /// 読んだノード。`None` は、読んだらなかった位置
    nodes: BTreeMap<Position, Option<TreeNode>>,
    /// 根を求めるときに、ハッシュを求め直すノードの位置
    stale: BTreeSet<Position>,
    /// 前にノードの変化を返してから、変わった位置
    changed: BTreeSet<Position>,
    /// 変わった位置の、変える前のもの（`None` は読んでいなかった）。実行を捨てるときに戻す
    originals: BTreeMap<Position, Option<Option<TreeNode>>>,
    /// まだ読んでいないのに要った位置
    missed: BTreeSet<Position>,
    /// 位置を最後に使った世代。捨てるときに古いものから捨てる
    used: BTreeMap<Position, u64>,
    /// 今の世代（[`LazyTree::set_generation`]）
    generation: u64,
}

/// `position` のノード `node` の、経路の終わりまでのニブルを入れたキー（後ろは0）
fn node_prefix(position: &Position, path: &[u8]) -> [u8; 32] {
    let mut prefix = position.1;
    for (index, &value) in path.iter().enumerate() {
        set_nibble(&mut prefix, usize::from(position.0) + index, value);
    }
    prefix
}

/// 経路が `end` 個目のニブルで終わる枝の、ニブル `value` の子の位置
fn child_position(prefix: &[u8; 32], end: usize, value: u8) -> Position {
    let mut child = mask(prefix, end);
    set_nibble(&mut child, end, value);
    ((end + 1) as u8, child)
}

fn nibbles(key: &[u8; 32], from: usize, to: usize) -> Vec<u8> {
    (from..to).map(|index| nibble(key, index)).collect()
}

fn no_links() -> Box<[Option<Hash256>; 16]> {
    Box::new([None; 16])
}

/// 枝の子を置き直すときに入れておく仮のハッシュ。根を求めるときに本物にする
const PENDING_LINK: Hash256 = Hash256([0xFF; 32]);

impl LazyTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// 読んだノードを入れる。`None` は、読んだらなかった。すでに持っていれば何もしない（変えたものを消さない）
    pub fn load(&mut self, position: Position, node: Option<TreeNode>) {
        self.nodes.entry(position).or_insert(node);
        self.used.insert(position, self.generation);
    }

    /// これから読むか使うノードを、世代 `generation` で使ったことにする
    pub fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    pub fn is_loaded(&self, position: &Position) -> bool {
        self.nodes.contains_key(position)
    }

    /// 根から `key` の葉までの道で、次に読むべき位置。全部読んであれば `None`。足すときに食い違うところまでと、
    /// 外すときに合わせる兄弟は含まない（それは当てる途中で記録される）
    pub fn next_on_path(&self, key: &[u8; 32]) -> Option<Position> {
        let mut position = ROOT;
        loop {
            let Some(node) = self.nodes.get(&position) else {
                return Some(position);
            };
            let Some(TreeNode::Branch { path, links }) = node else {
                return None;
            };
            let depth = usize::from(position.0);
            let end = depth + path.len();
            if (0..path.len()).any(|index| path[index] != nibble(key, depth + index)) {
                return None;
            }
            let value = nibble(key, end);
            links[usize::from(value)]?;
            position = child_position(key, end, value);
        }
    }

    /// まだ読んでいないのに要った位置
    pub fn take_missed(&mut self) -> BTreeSet<Position> {
        std::mem::take(&mut self.missed)
    }

    fn get(&mut self, position: &Position) -> Option<Option<TreeNode>> {
        match self.nodes.get(position) {
            Some(node) => {
                self.used.insert(*position, self.generation);
                Some(node.clone())
            }
            None => {
                self.missed.insert(*position);
                None
            }
        }
    }

    /// 道の上の枝に、ハッシュを求め直す印を付ける。根を求めるときに子のハッシュが書き換わるので、変える前を取っておく
    fn touch(&mut self, position: Position) {
        let before = self.nodes.get(&position).cloned();
        self.originals.entry(position).or_insert(before);
        self.stale.insert(position);
        self.changed.insert(position);
    }

    fn put(&mut self, position: Position, node: Option<TreeNode>) {
        let before = self.nodes.insert(position, node);
        self.originals.entry(position).or_insert(before);
        self.stale.insert(position);
        self.changed.insert(position);
    }

    /// 葉を置く。同じキーがあれば値を置き換える。読んでいないノードが要ったら、記録して何もしない
    pub fn set(&mut self, key: Hash256, value: Hash256) {
        let key = key.0;
        let mut position = ROOT;
        let mut above = Vec::new();
        loop {
            let Some(node) = self.get(&position) else {
                return;
            };
            let depth = usize::from(position.0);
            match node {
                None => {
                    // 空の木か、枝の空いた子
                    self.put(
                        position,
                        Some(TreeNode::Leaf {
                            path: nibbles(&key, depth, KEY_NIBBLES),
                            value,
                        }),
                    );
                    break;
                }
                Some(TreeNode::Leaf { path, value: old }) => {
                    let split =
                        (0..path.len()).find(|&index| path[index] != nibble(&key, depth + index));
                    let Some(split) = split else {
                        if old != value {
                            self.put(position, Some(TreeNode::Leaf { path, value }));
                        } else {
                            return;
                        }
                        break;
                    };
                    let leaf_key = node_prefix(&position, &path);
                    self.split(
                        position,
                        &key,
                        &path,
                        split,
                        TreeNode::Leaf {
                            path: path[split + 1..].to_vec(),
                            value: old,
                        },
                        &leaf_key,
                        value,
                    );
                    break;
                }
                Some(TreeNode::Branch { path, links }) => {
                    let split =
                        (0..path.len()).find(|&index| path[index] != nibble(&key, depth + index));
                    if let Some(split) = split {
                        let branch_key = node_prefix(&position, &path);
                        self.split(
                            position,
                            &key,
                            &path,
                            split,
                            TreeNode::Branch {
                                path: path[split + 1..].to_vec(),
                                links,
                            },
                            &branch_key,
                            value,
                        );
                        break;
                    }
                    let end = depth + path.len();
                    let child_value = nibble(&key, end);
                    let child = child_position(&key, end, child_value);
                    above.push(position);
                    if links[usize::from(child_value)].is_none() {
                        let mut links = links;
                        links[usize::from(child_value)] = Some(PENDING_LINK);
                        self.put(position, Some(TreeNode::Branch { path, links }));
                        self.put(
                            child,
                            Some(TreeNode::Leaf {
                                path: nibbles(&key, end + 1, KEY_NIBBLES),
                                value,
                            }),
                        );
                        // 空いていた子の位置に、前に外した葉の読み込みが残っていても上書きする
                        break;
                    }
                    position = child;
                }
            }
        }
        for position in above {
            self.touch(position);
        }
    }

    /// `position` のノード（経路 `path`）を `split` 個目で割り、元のノードを `moved` にして下へ動かし、`key` の
    /// 葉を足す。`moved_key` は元のノードの経路の終わりまでのキー
    #[allow(clippy::too_many_arguments)]
    fn split(
        &mut self,
        position: Position,
        key: &[u8; 32],
        path: &[u8],
        split: usize,
        moved: TreeNode,
        moved_key: &[u8; 32],
        value: Hash256,
    ) {
        let depth = usize::from(position.0);
        let end = depth + split;
        let mut links = no_links();
        let moved_value = path[split];
        let new_value = nibble(key, end);
        links[usize::from(moved_value)] = Some(PENDING_LINK);
        links[usize::from(new_value)] = Some(PENDING_LINK);
        self.put(
            position,
            Some(TreeNode::Branch {
                path: path[..split].to_vec(),
                links,
            }),
        );
        self.put(child_position(moved_key, end, moved_value), Some(moved));
        self.put(
            child_position(key, end, new_value),
            Some(TreeNode::Leaf {
                path: nibbles(key, end + 1, KEY_NIBBLES),
                value,
            }),
        );
    }

    /// 葉を外す。なければ何もしない。読んでいないノードが要ったら、記録して何もしない
    pub fn remove(&mut self, key: &Hash256) {
        let key = key.0;
        let mut position = ROOT;
        // 道の上の枝と、そこから進んだニブル
        let mut above: Vec<(Position, u8)> = Vec::new();
        loop {
            let Some(node) = self.get(&position) else {
                return;
            };
            let depth = usize::from(position.0);
            match node {
                None => return,
                Some(TreeNode::Leaf { path, .. }) => {
                    if (0..path.len()).any(|index| path[index] != nibble(&key, depth + index)) {
                        return;
                    }
                    break;
                }
                Some(TreeNode::Branch { path, links }) => {
                    if (0..path.len()).any(|index| path[index] != nibble(&key, depth + index)) {
                        return;
                    }
                    let end = depth + path.len();
                    let value = nibble(&key, end);
                    if links[usize::from(value)].is_none() {
                        return;
                    }
                    above.push((position, value));
                    position = child_position(&key, end, value);
                }
            }
        }
        let leaf = position;
        let Some((parent, value)) = above.pop() else {
            // 根が葉だった
            self.put(leaf, None);
            return;
        };
        let Some(Some(TreeNode::Branch { path, mut links })) = self.nodes.get(&parent).cloned()
        else {
            return;
        };
        links[usize::from(value)] = None;
        let remaining: Vec<usize> = (0..16).filter(|&index| links[index].is_some()).collect();
        if let [only] = remaining[..] {
            // 子が1つになった枝は、残った子と合わせる
            let end = usize::from(parent.0) + path.len();
            let parent_key = node_prefix(&parent, &path);
            let sibling = child_position(&parent_key, end, only as u8);
            let Some(sibling_node) = self.get(&sibling) else {
                return;
            };
            let Some(sibling_node) = sibling_node else {
                return;
            };
            let mut merged_path = path.clone();
            merged_path.push(only as u8);
            let merged = match sibling_node {
                TreeNode::Leaf {
                    path: sibling_path,
                    value,
                } => {
                    merged_path.extend(sibling_path);
                    TreeNode::Leaf {
                        path: merged_path,
                        value,
                    }
                }
                TreeNode::Branch {
                    path: sibling_path,
                    links,
                } => {
                    merged_path.extend(sibling_path);
                    TreeNode::Branch {
                        path: merged_path,
                        links,
                    }
                }
            };
            self.put(leaf, None);
            self.put(sibling, None);
            self.put(parent, Some(merged));
        } else {
            self.put(leaf, None);
            self.put(parent, Some(TreeNode::Branch { path, links }));
        }
        for (position, _) in above {
            self.touch(position);
        }
    }

    /// 根のハッシュ。空なら [`EMPTY_ROOT`]。根を読んでいなければ、記録して [`EMPTY_ROOT`]
    pub fn root(&mut self) -> Hash256 {
        if self.stale.contains(&ROOT) {
            self.rehash(ROOT);
        }
        self.stale.clear();
        match self.get(&ROOT) {
            Some(Some(node)) => node.hash(),
            _ => EMPTY_ROOT,
        }
    }

    /// `position` より下の、ハッシュを求め直す子の分を枝に入れ直して、このノードのハッシュを返す
    fn rehash(&mut self, position: Position) -> Option<Hash256> {
        let node = self.nodes.get(&position).cloned().flatten()?;
        let TreeNode::Branch { path, mut links } = node else {
            return Some(node.hash());
        };
        let end = usize::from(position.0) + path.len();
        let prefix = node_prefix(&position, &path);
        let mut updated = false;
        for value in 0..16u8 {
            let child = child_position(&prefix, end, value);
            if links[usize::from(value)].is_some() && self.stale.contains(&child) {
                links[usize::from(value)] = self.rehash(child);
                updated = true;
            }
        }
        let node = TreeNode::Branch { path, links };
        let hash = node.hash();
        if updated {
            self.nodes.insert(position, Some(node));
        }
        Some(hash)
    }

    /// 前に呼んでから変わったノード。位置と、今のノードか、なくなったら `None`。[`LazyTree::root`] のあとで呼ぶ
    pub fn take_node_changes(&mut self) -> Vec<(Position, Option<TreeNode>)> {
        self.root();
        self.originals.clear();
        std::mem::take(&mut self.changed)
            .into_iter()
            .map(|position| (position, self.nodes.get(&position).cloned().flatten()))
            .collect()
    }

    /// 前にノードの変化を返してから変えたノードを、変える前に戻す。保存に書かずに実行を捨てるとき
    pub fn discard_changes(&mut self) {
        for (position, before) in std::mem::take(&mut self.originals) {
            match before {
                Some(node) => {
                    self.nodes.insert(position, node);
                }
                None => {
                    self.nodes.remove(&position);
                }
            }
        }
        self.changed.clear();
        self.stale.clear();
        self.missed.clear();
    }

    /// ノードの変化を返さずに捨てる。保存にあるものと同じ木のとき
    pub fn forget_node_changes(&mut self) {
        self.changed.clear();
        self.originals.clear();
    }

    /// 読んだノードが `capacity` を超えていれば、根に近いノードと変わったノードのほかを、使った世代の古いほうから
    /// 捨てる。捨てた数
    pub fn evict(&mut self, capacity: usize) -> usize {
        if self.nodes.len() <= capacity {
            return 0;
        }
        let mut candidates: Vec<(u64, Position)> = self
            .nodes
            .keys()
            .filter(|position| position.0 > PINNED_DEPTH && !self.changed.contains(position))
            .map(|position| (self.used.get(position).copied().unwrap_or(0), *position))
            .collect();
        candidates.sort_unstable_by_key(|(generation, _)| *generation);
        let excess = self.nodes.len() - capacity;
        let mut evicted = 0;
        for (_, position) in candidates.into_iter().take(excess) {
            self.nodes.remove(&position);
            self.used.remove(&position);
            evicted += 1;
        }
        evicted
    }

    /// 読んだノードの数
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::PatriciaTree;
    use super::*;

    /// 決まった乱数
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn key(&mut self) -> [u8; 32] {
            let mut key = [0; 32];
            for chunk in key.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes());
            }
            key
        }
    }

    /// 保存の代わり。コミットしたノードを位置で持つ
    #[derive(Default)]
    struct Store(HashMap<Position, TreeNode>);

    impl Store {
        fn commit(&mut self, changes: Vec<(Position, Option<TreeNode>)>) {
            for (position, node) in changes {
                match node {
                    Some(node) => self.0.insert(position, node),
                    None => self.0.remove(&position),
                };
            }
        }

        /// `keys` の道を先に読み、足りないノードを読みながら、`apply` が記録なしで済むまで繰り返す
        fn run(&self, tree: &mut LazyTree, keys: &[[u8; 32]], apply: impl Fn(&mut LazyTree)) {
            for key in keys {
                while let Some(position) = tree.next_on_path(key) {
                    tree.load(position, self.0.get(&position).cloned());
                }
            }
            loop {
                apply(tree);
                let missed = tree.take_missed();
                if missed.is_empty() {
                    return;
                }
                tree.discard_changes();
                for position in missed {
                    tree.load(position, self.0.get(&position).cloned());
                }
            }
        }
    }

    #[test]
    fn matches_the_full_tree_through_inserts_updates_and_removals() {
        let mut rng = Rng(0x1234_5678_9ABC_DEF1);
        let mut full = PatriciaTree::new();
        let mut store = Store::default();
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for round in 0..300 {
            // 毎回新しい木で、保存から必要な分だけ読む
            let mut lazy = LazyTree::new();
            let mut operations = Vec::new();
            for _ in 0..(1 + rng.next() % 20) {
                let roll = rng.next() % 10;
                if roll < 5 || keys.is_empty() {
                    // 似たキーを作って、深いところで割れるようにする
                    let mut key = rng.key();
                    if !keys.is_empty() && roll < 2 {
                        let base = keys[(rng.next() as usize) % keys.len()];
                        let shared = (rng.next() % 31) as usize;
                        key[..shared].copy_from_slice(&base[..shared]);
                    }
                    keys.push(key);
                    operations.push((key, Some(Hash256(rng.key()))));
                } else if roll < 8 {
                    let key = keys[(rng.next() as usize) % keys.len()];
                    operations.push((key, Some(Hash256(rng.key()))));
                } else {
                    let index = (rng.next() as usize) % keys.len();
                    operations.push((keys.swap_remove(index), None));
                }
            }
            for (key, value) in &operations {
                match value {
                    Some(value) => full.set(Hash256(*key), *value),
                    None => full.remove(&Hash256(*key)),
                }
            }
            let touched: Vec<[u8; 32]> = operations.iter().map(|(key, _)| *key).collect();
            store.run(&mut lazy, &touched, |tree| {
                for (key, value) in &operations {
                    match value {
                        Some(value) => tree.set(Hash256(*key), *value),
                        None => tree.remove(&Hash256(*key)),
                    }
                }
                tree.root();
            });
            assert_eq!(lazy.root(), full.root(), "{round} 回目");
            // 捨てて当て直しても同じになる（当てる途中で足りないものがあったときと同じ）
            if round % 3 == 0 {
                lazy.discard_changes();
                for (key, value) in &operations {
                    match value {
                        Some(value) => lazy.set(Hash256(*key), *value),
                        None => lazy.remove(&Hash256(*key)),
                    }
                }
                assert!(lazy.take_missed().is_empty(), "{round} 回目");
                assert_eq!(
                    lazy.root(),
                    full.root(),
                    "{round} 回目、捨てて当て直したもの"
                );
            }
            store.commit(lazy.take_node_changes());
            // 保存にあるノードが、全部持つ木のノードと同じになる（全部比べるのは重いので、ときどき）
            if round % 20 == 19 {
                let expected: HashMap<Position, TreeNode> = full.nodes().into_iter().collect();
                assert_eq!(store.0, expected, "{round} 回目");
            }
        }
    }

    #[test]
    fn putting_leaves_back_after_eviction_needs_loading() {
        // 根に近い段より深く葉が並ぶくらいの木
        let mut rng = Rng(11);
        let mut full = PatriciaTree::new();
        let keys: Vec<[u8; 32]> = (0..20_000).map(|_| rng.key()).collect();
        let before: Vec<Hash256> = keys.iter().map(|_| Hash256(rng.key())).collect();
        for (key, value) in keys.iter().zip(&before) {
            full.set(Hash256(*key), *value);
        }
        let old_root = full.root();
        let mut store = Store(full.nodes().into_iter().collect());
        // ブロックを当てて書き、読んだノードを手放す
        let mut lazy = LazyTree::new();
        let changed = &keys[..50];
        store.run(&mut lazy, changed, |tree| {
            for key in changed {
                tree.set(Hash256(*key), Hash256([7; 32]));
            }
            tree.root();
        });
        store.commit(lazy.take_node_changes());
        lazy.evict(0);
        // 読み直さずに葉を前の値に戻すと、読んでいないノードの書き戻しが抜け、根が戻らない（巻き戻しで起きたこと）
        for (key, value) in changed.iter().zip(&before) {
            lazy.set(Hash256(*key), *value);
        }
        assert!(!lazy.take_missed().is_empty());
        assert_ne!(lazy.root(), old_root);
        // 足りないノードを読みながら戻せば、前の根になる
        let mut lazy = LazyTree::new();
        store.run(&mut lazy, changed, |tree| {
            for (key, value) in changed.iter().zip(&before) {
                tree.set(Hash256(*key), *value);
            }
            tree.root();
        });
        assert_eq!(lazy.root(), old_root);
    }

    #[test]
    fn walks_the_path_to_load() {
        let mut full = PatriciaTree::new();
        let mut rng = Rng(7);
        let keys: Vec<[u8; 32]> = (0..200).map(|_| rng.key()).collect();
        for key in &keys {
            full.set(Hash256(*key), Hash256(rng.key()));
        }
        let store: HashMap<Position, TreeNode> = full.nodes().into_iter().collect();
        let mut lazy = LazyTree::new();
        let mut reads = 0;
        while let Some(position) = lazy.next_on_path(&keys[3]) {
            lazy.load(position, store.get(&position).cloned());
            reads += 1;
        }
        // 葉までの道だけを読む
        assert!(reads <= 4, "{reads}");
        lazy.set(Hash256(keys[3]), Hash256([9; 32]));
        assert!(lazy.take_missed().is_empty());
        full.set(Hash256(keys[3]), Hash256([9; 32]));
        assert_eq!(lazy.root(), full.root());
    }
}
