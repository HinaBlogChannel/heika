//! Merkle ツリー。catapult の `crypto/MerkleHashBuilder.cpp`。
//! ブロックのトランザクションや、アグリゲートの中のトランザクションのハッシュをまとめるのに使う。

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
            .map(|pair| {
                let (left, right) = (&pair[0], pair.last().expect("chunks are not empty"));
                let mut hasher = Sha3_256::new();
                hasher.update(left.0);
                hasher.update(right.0);
                Hash256(hasher.finalize().into())
            })
            .collect();
    }
    level[0]
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
}
