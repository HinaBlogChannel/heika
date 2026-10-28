//! Merkle ツリー。catapult の `crypto/MerkleHashBuilder.cpp`。
//! ブロックのトランザクションや、アグリゲートの中のトランザクションのハッシュをまとめるのに使う。
//! 葉が根に含まれることは、葉から根までの経路で示せる。

use alloc::vec::Vec;
use sha3::{Digest, Sha3_256};

use crate::hash::Hash256;

/// 葉のハッシュから根を求める。
///
/// 2つずつ組にして SHA3-256 をとり、1つになるまで繰り返す。その段の数が奇数なら最後の1つを複製して組にする。
/// 葉がなければ根は全部0、1つならその葉がそのまま根になる。
pub fn root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256([0; 32]);
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| pair_hash(&pair[0], pair.last().expect("chunks are not empty")))
            .collect();
    }
    level[0]
}

/// catapult の `crypto/InvalidMerkleHashBuilder.cpp` の、誤った根の求め方。
///
/// 組にしたハッシュを書き戻すときに、同じ段の後ろのハッシュを1つずつずらしてしまうので、
/// 2組目からは隣どうしではないハッシュを組にする。そのため、根が守らない葉ができる。
/// 初期のアグリゲート（バージョン 1）には、この求め方で中のトランザクションのハッシュを書いたものがあり、
/// チェーンはそれも認めている。新しく使ってはいけない。
pub fn invalid_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256([0; 32]);
    }
    let mut hashes = leaves.to_vec();
    let mut remaining = hashes.len();
    while remaining > 1 {
        let mut i = 0;
        while i < remaining {
            let odd = i + 1 >= remaining;
            let right = if odd { hashes[i] } else { hashes[i + 1] };
            let mut hasher = Sha3_256::new();
            hasher.update(hashes[i].0);
            hasher.update(right.0);
            // この段の数までの範囲で、書き戻す位置より後ろを1つずつずらす
            for j in (i / 2 + 1..remaining.min(hashes.len())).rev() {
                hashes[j] = hashes[j - 1];
            }
            hashes[i / 2] = Hash256(hasher.finalize().into());
            if odd {
                // 複製した分を数に足して、この段を終える
                remaining += 1;
            }
            i += 2;
        }
        remaining /= 2;
    }
    hashes[0]
}

/// Merkle の経路の1段。兄弟のハッシュと、それが左右どちらにあるか。
/// catapult の REST が返す `merklePath` の1要素と同じ。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MerklePathNode {
    pub hash: Hash256,
    pub position: Position,
}

/// 兄弟のハッシュが、組にするときに左右どちらに来るか。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Position {
    Left,
    Right,
}

/// `index` 番目の葉から根までの経路を、葉に近い段から順に求める。catapult の REST の `buildAuditPath` と同じ。
/// 葉が1つなら経路は空。`index` が葉の数を超えていれば `None`。
///
/// 段の数が奇数のときの最後のハッシュは、複製した自分自身が兄弟になる。
pub fn path(leaves: &[Hash256], index: usize) -> Option<Vec<MerklePathNode>> {
    if index >= leaves.len() {
        return None;
    }
    let mut level = leaves.to_vec();
    let mut index = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        let (sibling, position) = if index % 2 == 1 {
            (index - 1, Position::Left)
        } else {
            ((index + 1).min(level.len() - 1), Position::Right)
        };
        path.push(MerklePathNode {
            hash: level[sibling],
            position,
        });
        level = level
            .chunks(2)
            .map(|pair| pair_hash(&pair[0], pair.last().expect("chunks are not empty")))
            .collect();
        index /= 2;
    }
    Some(path)
}

/// 葉と経路から根を求め直して、`root` と合うかを確かめる。公式の SDK の `prove_merkle`。
///
/// 経路は葉の数を含まないので、段の数が奇数のときの最後の葉は、複製されたもう1つの位置の葉としても通る。
/// 何番目の葉かまで確かめたいときは、経路の左右の並びからも位置を確かめる。
pub fn verify_path(leaf: &Hash256, path: &[MerklePathNode], root: &Hash256) -> bool {
    let computed = path
        .iter()
        .fold(*leaf, |working, node| match node.position {
            Position::Left => pair_hash(&node.hash, &working),
            Position::Right => pair_hash(&working, &node.hash),
        });
    computed == *root
}

fn pair_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(left.0);
    hasher.update(right.0);
    Hash256(hasher.finalize().into())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(byte: u8) -> Hash256 {
        Hash256([byte; 32])
    }

    fn pair(left: &Hash256, right: &Hash256) -> Hash256 {
        Hash256(Sha3_256::digest([left.0, right.0].concat()).into())
    }

    #[test]
    fn every_leaf_has_a_path_to_the_root() {
        for count in 1..=9 {
            let leaves: Vec<_> = (0..count).map(|byte| leaf(byte as u8)).collect();
            let expected = root(&leaves);
            for (index, hash) in leaves.iter().enumerate() {
                let path = path(&leaves, index).unwrap();
                assert!(verify_path(hash, &path, &expected), "{index} of {count}");
                // 別の葉や、1段でも違う経路では通らない
                assert!(
                    !verify_path(&leaf(0xFF), &path, &expected),
                    "{index} of {count}"
                );
                if let Some(first) = path.first() {
                    let mut swapped = path.clone();
                    swapped[0].position = match first.position {
                        Position::Left => Position::Right,
                        Position::Right => Position::Left,
                    };
                    if first.hash != *hash {
                        assert!(
                            !verify_path(hash, &swapped, &expected),
                            "{index} of {count}"
                        );
                    }
                }
            }
            assert_eq!(super::path(&leaves, count), None);
        }
    }

    #[test]
    fn builds_the_path_like_the_rest_audit_path() {
        // 3つの葉では、2段目で最後のハッシュが自分自身と組になる
        let leaves = [leaf(1), leaf(2), leaf(3)];
        let left = pair(&leaf(1), &leaf(2));
        assert_eq!(
            path(&leaves, 2).unwrap(),
            [
                MerklePathNode {
                    hash: leaf(3),
                    position: Position::Right
                },
                MerklePathNode {
                    hash: left,
                    position: Position::Left
                },
            ]
        );
        assert_eq!(
            path(&leaves, 1).unwrap(),
            [
                MerklePathNode {
                    hash: leaf(1),
                    position: Position::Left
                },
                MerklePathNode {
                    hash: pair(&leaf(3), &leaf(3)),
                    position: Position::Right
                },
            ]
        );
        assert_eq!(path(&[leaf(1)], 0).unwrap(), []);
        assert_eq!(path(&[], 0), None);
    }

    #[test]
    fn no_leaves_give_zero() {
        assert_eq!(root(&[]), Hash256([0; 32]));
    }

    #[test]
    fn one_leaf_is_the_root() {
        assert_eq!(root(&[leaf(1)]), leaf(1));
    }

    #[test]
    fn pairs_leaves() {
        assert_eq!(root(&[leaf(1), leaf(2)]), pair(&leaf(1), &leaf(2)));
    }

    #[test]
    fn duplicates_the_last_of_an_odd_level() {
        let left = pair(&leaf(1), &leaf(2));
        let right = pair(&leaf(3), &leaf(3));
        assert_eq!(root(&[leaf(1), leaf(2), leaf(3)]), pair(&left, &right));
        // 5つなら、2段目の3つのうち最後も複製する
        let level = [left, pair(&leaf(3), &leaf(4)), pair(&leaf(5), &leaf(5))];
        let expected = pair(&pair(&level[0], &level[1]), &pair(&level[2], &level[2]));
        let leaves: Vec<_> = (1..=5).map(leaf).collect();
        assert_eq!(root(&leaves), expected);
    }

    #[test]
    fn the_invalid_root_agrees_for_up_to_two_leaves() {
        assert_eq!(invalid_root(&[]), Hash256([0; 32]));
        assert_eq!(invalid_root(&[leaf(1)]), leaf(1));
        assert_eq!(invalid_root(&[leaf(1), leaf(2)]), root(&[leaf(1), leaf(2)]));
    }

    /// catapult の `InvalidMerkleHashBuilderTests.cpp` が示している形。8つなら、後ろの3つの葉は根に効かない
    #[test]
    fn the_invalid_root_pairs_shifted_hashes() {
        let leaves: Vec<_> = (0..8).map(leaf).collect();
        let level: Vec<_> = (0..4).map(|i| pair(&leaves[i], &leaves[i + 1])).collect();
        let expected = pair(&pair(&level[0], &level[1]), &pair(&level[1], &level[2]));
        assert_eq!(invalid_root(&leaves), expected);
        let mut changed = leaves.clone();
        changed[7] = leaf(0xFF);
        assert_eq!(invalid_root(&changed), expected);

        let leaves: Vec<_> = (0..5).map(leaf).collect();
        let level = [
            pair(&leaves[0], &leaves[1]),
            pair(&leaves[1], &leaves[2]),
            pair(&leaves[2], &leaves[2]),
        ];
        let expected = pair(&pair(&level[0], &level[1]), &pair(&level[1], &level[1]));
        assert_eq!(invalid_root(&leaves), expected);
    }
}
