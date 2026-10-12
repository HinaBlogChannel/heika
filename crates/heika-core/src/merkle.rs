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
