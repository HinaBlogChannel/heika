//! 1つのラウンドの投票の数え方。catapult の `chain::RoundContext` と `FinalizationHashTree`。
//!
//! prevote は、高さ `height` から続くブロックのハッシュの並び（枝）に投票する。枝はつなげて木にし、
//! 枝の中のどのブロックにも prevote の重みを足す。precommit は1つのブロックに投票し、そのブロックと
//! 根までの祖先に precommit の重みを足す。まだ prevote のないブロックへの precommit は、そのブロックに
//! prevote が来るまで取っておく（数えない）。
//!
//! 閾値は、重みの合計 × `threshold` / `size`（呼び出し側で計算して渡す）。
//!
//! - best prevote: prevote が閾値に届いた、いちばん高いブロック
//! - best precommit: prevote と precommit の両方が閾値に届いた、いちばん高いブロック。これがファイナライズされる
//! - estimate: best prevote とその祖先のうち、まだ precommit が閾値に届きうる、いちばん高いブロック
//! - completable: このラウンドの結果がもう変わらない。次のラウンドに進んでよい

use alloc::collections::BTreeMap;

use heika_core::hash::Hash256;

/// ブロックの（高さ、ハッシュ）
pub type Candidate = (u64, Hash256);

/// ブロックに集まった重み
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Weights {
    pub prevote: u64,
    pub precommit: u64,
}

/// 1つのラウンドの投票の数え方。catapult の `RoundContext`
#[derive(Debug)]
pub struct RoundContext {
    total_weight: u64,
    threshold: u64,
    /// 数えた precommit の重みの合計。取っておいているものは入れない
    cumulative_precommit_weight: u64,
    /// （高さ、ハッシュ）の順。いちばん高いものから探す
    candidates: BTreeMap<(u64, [u8; 32]), Weights>,
    /// 子 → 親。最初に足した枝のつながりを使う
    parents: BTreeMap<Candidate, Option<Candidate>>,
    /// 先に届いた precommit で、まだその prevote がないもの
    pending_precommits: BTreeMap<Candidate, u64>,
}

impl RoundContext {
    /// 投票者の重みの合計が `total_weight`、閾値が `threshold` のラウンド
    pub fn new(total_weight: u64, threshold: u64) -> Self {
        Self {
            total_weight,
            threshold,
            cumulative_precommit_weight: 0,
            candidates: BTreeMap::new(),
            parents: BTreeMap::new(),
            pending_precommits: BTreeMap::new(),
        }
    }

    /// prevote のあったブロックの数
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// ブロックに集まった重み。prevote のないブロックは 0
    pub fn weights(&self, candidate: Candidate) -> Weights {
        self.candidates
            .get(&(candidate.0, candidate.1.0))
            .copied()
            .unwrap_or_default()
    }

    /// prevote が閾値に届いた、いちばん高いブロック
    pub fn best_prevote(&self) -> Option<Candidate> {
        self.last_match(|_, weights| weights.prevote >= self.threshold)
    }

    /// prevote と precommit の両方が閾値に届いた、いちばん高いブロック
    pub fn best_precommit(&self) -> Option<Candidate> {
        self.last_match(|_, weights| {
            weights.prevote >= self.threshold && weights.precommit >= self.threshold
        })
    }

    /// best prevote とその祖先のうち、precommit がまだ閾値に届きうる、いちばん高いブロック
    pub fn estimate(&self) -> Option<Candidate> {
        self.estimate_below(self.best_prevote()?)
    }

    /// `child` が `parent` 自身か、その子孫か。どちらかに prevote がなければ偽
    pub fn is_descendant(&self, parent: Candidate, child: Candidate) -> bool {
        let mut current = self.parents.contains_key(&child).then_some(child);
        while let Some(node) = current {
            if node == parent {
                return true;
            }
            current = self.parents[&node];
        }
        false
    }

    /// ラウンドの結果がもう変わらないか。catapult の `isCompletable`
    pub fn is_completable(&self) -> bool {
        let Some(best_prevote) = self.best_prevote() else {
            return false;
        };
        // estimate が best prevote より前なら、もう変わらない
        if self
            .estimate_below(best_prevote)
            .is_some_and(|estimate| estimate != best_prevote)
        {
            return true;
        }
        // estimate が best prevote（か、ない）なら、best prevote の子孫のどれも precommit が閾値に届きえないときだけ
        if self.can_reach_precommit_threshold(Weights::default()) {
            return false;
        }
        !self
            .candidates
            .iter()
            .rev()
            .map(|(&(height, hash), weights)| ((height, Hash256(hash)), weights))
            .any(|(candidate, weights)| {
                candidate != best_prevote
                    && self.is_descendant(best_prevote, candidate)
                    && self.can_reach_precommit_threshold(*weights)
            })
    }

    /// 高さ `height` から続くブロック `hashes` への prevote を、重み `weight` で数える
    pub fn accept_prevote(&mut self, height: u64, hashes: &[Hash256], weight: u64) {
        let mut parent = None;
        for (index, hash) in hashes.iter().enumerate() {
            let key = (height + index as u64, *hash);
            self.parents.entry(key).or_insert(parent);
            parent = Some(key);
        }
        for (index, hash) in hashes.iter().enumerate() {
            let key = (height + index as u64, *hash);
            let weights = self.candidates.entry((key.0, key.1.0)).or_default();
            weights.prevote = weights.prevote.wrapping_add(weight);
            if let Some(pending) = self.pending_precommits.remove(&key) {
                self.add_precommit(key, pending);
            }
        }
    }

    /// ブロック（`height`、`hash`）への precommit を、重み `weight` で数える。prevote がまだなければ取っておく
    pub fn accept_precommit(&mut self, height: u64, hash: Hash256, weight: u64) {
        let key = (height, hash);
        if self.parents.contains_key(&key) {
            self.add_precommit(key, weight);
        } else {
            let pending = self.pending_precommits.entry(key).or_default();
            *pending = pending.wrapping_add(weight);
        }
    }

    /// 自分と根までの祖先に precommit の重みを足す
    fn add_precommit(&mut self, key: Candidate, weight: u64) {
        let mut current = Some(key);
        while let Some(node) = current {
            let weights = self
                .candidates
                .get_mut(&(node.0, node.1.0))
                .expect("木にあるブロックには prevote がある");
            weights.precommit = weights.precommit.wrapping_add(weight);
            current = self.parents[&node];
        }
        self.cumulative_precommit_weight = self.cumulative_precommit_weight.wrapping_add(weight);
    }

    /// まだ precommit していない重みが全部来れば、閾値に届くか。catapult と同じく u64 のまま足し引きする
    fn can_reach_precommit_threshold(&self, weights: Weights) -> bool {
        weights.precommit.wrapping_add(
            self.total_weight
                .wrapping_sub(self.cumulative_precommit_weight),
        ) >= self.threshold
    }

    fn estimate_below(&self, best_prevote: Candidate) -> Option<Candidate> {
        self.last_match(|candidate, weights| {
            self.is_descendant(candidate, best_prevote)
                && self.can_reach_precommit_threshold(*weights)
        })
    }

    /// 条件に合う、いちばん高い（同じ高さならハッシュの大きい）ブロック
    fn last_match(&self, predicate: impl Fn(Candidate, &Weights) -> bool) -> Option<Candidate> {
        self.candidates
            .iter()
            .rev()
            .map(|(&(height, hash), weights)| ((height, Hash256(hash)), weights))
            .find(|(candidate, weights)| predicate(*candidate, weights))
            .map(|(candidate, _)| candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 枝 `branch` の、`count` 個のハッシュ。どの枝でも違う
    fn branch(branch: u8, count: usize) -> Vec<Hash256> {
        (0..count)
            .map(|index| {
                let mut hash = [branch; 32];
                hash[0] = index as u8;
                Hash256(hash)
            })
            .collect()
    }

    fn unknown() -> Hash256 {
        Hash256([0xEE; 32])
    }

    fn weights(prevote: u64, precommit: u64) -> Weights {
        Weights { prevote, precommit }
    }

    #[test]
    fn starts_empty() {
        let context = RoundContext::new(1000, 670);
        assert!(context.is_empty());
        assert_eq!(context.best_prevote(), None);
        assert_eq!(context.best_precommit(), None);
        assert_eq!(context.estimate(), None);
        assert!(!context.is_completable());
    }

    /// 高さ 7 からの枝 1（重み 669）と枝 2（100）
    fn two_prevoted_branches(count: usize) -> (RoundContext, Vec<Hash256>, Vec<Hash256>) {
        let (first, second) = (branch(1, count), branch(2, count));
        let mut context = RoundContext::new(1000, 670);
        context.accept_prevote(7, &first, 669);
        context.accept_prevote(7, &second, 100);
        (context, first, second)
    }

    #[test]
    fn finds_the_best_prevote_at_or_above_the_threshold() {
        let (context, ..) = two_prevoted_branches(3);
        assert_eq!(context.best_prevote(), None);

        // { 670, *670*, 669 }
        let (mut context, hashes, _) = two_prevoted_branches(3);
        context.accept_prevote(7, &hashes[..2], 1);
        assert_eq!(context.best_prevote(), Some((8, hashes[1])));
        assert_eq!(context.best_precommit(), None);

        // { 800, *700*, 669 }
        let (mut context, hashes, _) = two_prevoted_branches(3);
        context.accept_prevote(7, &hashes[..2], 31);
        context.accept_prevote(7, &hashes[..1], 100);
        assert_eq!(context.best_prevote(), Some((8, hashes[1])));
    }

    /// 枝 1 と 2 の高さ 9 に、precommit 669 と 150
    fn two_precommitted_branches() -> (RoundContext, Vec<Hash256>) {
        let (mut context, first, second) = two_prevoted_branches(4);
        context.accept_precommit(9, first[2], 669);
        context.accept_precommit(9, second[2], 150);
        (context, first)
    }

    #[test]
    fn needs_both_prevotes_and_precommits_for_the_best_precommit() {
        let (context, _) = two_precommitted_branches();
        assert_eq!(context.best_precommit(), None);

        // precommit だけ届いた
        let (mut context, hashes) = two_precommitted_branches();
        context.accept_precommit(9, hashes[2], 100);
        assert_eq!(context.best_precommit(), None);
        assert_eq!(context.best_prevote(), None);

        // prevote だけ届いた
        let (mut context, hashes) = two_precommitted_branches();
        context.accept_prevote(7, &hashes, 100);
        assert_eq!(context.best_precommit(), None);
        assert_eq!(context.best_prevote(), Some((10, hashes[3])));

        // votes { 670, 670, *670*, 669 }, commits { 670, *670*, 669, 0 }
        let (mut context, hashes) = two_precommitted_branches();
        context.accept_prevote(7, &hashes[..3], 1);
        context.accept_precommit(8, hashes[1], 1);
        assert_eq!(context.best_precommit(), Some((8, hashes[1])));
        assert_eq!(context.best_prevote(), Some((9, hashes[2])));

        // votes { 800, 800, *700*, 669 }, commits { 790, *690*, 669, 0 }
        let (mut context, hashes) = two_precommitted_branches();
        context.accept_prevote(7, &hashes[..3], 31);
        context.accept_prevote(7, &hashes[..2], 100);
        context.accept_precommit(8, hashes[1], 21);
        context.accept_precommit(7, hashes[0], 100);
        assert_eq!(context.best_precommit(), Some((8, hashes[1])));
        assert_eq!(context.best_prevote(), Some((9, hashes[2])));
    }

    #[test]
    fn ignores_precommits_for_unknown_blocks() {
        let (mut context, hashes, _) = two_prevoted_branches(3);
        context.accept_prevote(7, &hashes[..2], 100);
        context.accept_precommit(9, unknown(), 750);
        context.accept_precommit(9, Hash256([0xDD; 32]), 150);
        assert_eq!(context.best_precommit(), None);
        assert_eq!(context.best_prevote(), Some((8, hashes[1])));
    }

    /// ```text
    ///  7 - 8 - 9 - 10       枝 1
    ///         |||
    ///          9 - 10 - 11  枝 2
    ///  7 - 8 - 9 - 10 - 11  枝 3
    /// ```
    /// どの枝にも prevote 10。返すのは枝 1 と枝 3
    fn forked() -> (RoundContext, Vec<Hash256>, Vec<Hash256>) {
        let first = branch(1, 4);
        let mut second = branch(2, 3);
        second[0] = first[2];
        let third = branch(3, 5);
        let mut context = RoundContext::new(1000, 670);
        context.accept_prevote(7, &first, 10);
        context.accept_prevote(9, &second, 10);
        context.accept_prevote(7, &third, 10);
        (context, first, third)
    }

    #[test]
    fn estimates_the_highest_block_that_can_still_be_precommitted() {
        // best prevote がない
        let (mut context, first, _) = forked();
        context.accept_precommit(9, first[2], 700);
        assert_eq!(context.estimate(), None);
        assert!(!context.is_completable());

        // best prevote も祖先も、閾値に届きえない
        let (mut context, first, third) = forked();
        context.accept_prevote(7, &first, 700);
        context.accept_precommit(9, first[2], 350);
        context.accept_precommit(9, third[2], 350);
        assert_eq!(context.estimate(), None);
        assert!(context.is_completable());

        // best prevote が閾値を超えている
        let (mut context, first, _) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(9, first[2], 700);
        assert_eq!(context.estimate(), Some((9, first[2])));
        assert!(context.is_completable());

        // best prevote はまだ届いていないが、届きうる
        let (mut context, first, _) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(9, first[2], 400);
        assert_eq!(context.estimate(), Some((9, first[2])));
        assert!(context.is_completable());

        // 届きうるのは祖先だけ
        let (mut context, first, _) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(8, first[1], 400);
        assert_eq!(context.estimate(), Some((8, first[1])));
        assert!(context.is_completable());

        // つながっていないブロックへの precommit があっても
        let (mut context, first, third) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(9, first[2], 200);
        context.accept_precommit(11, third[4], 200);
        assert_eq!(context.estimate(), Some((9, first[2])));
        assert!(context.is_completable());
    }

    #[test]
    fn leaves_pending_precommits_out_of_the_estimate_until_their_prevote() {
        let (mut context, first, _) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(9, first[2], 400);
        context.accept_precommit(10, unknown(), 500);
        assert_eq!(context.estimate(), Some((9, first[2])));
        assert!(context.is_completable());

        // 取っておいた 500 が数えられると、高さ 9 にはもう届かない
        context.accept_prevote(10, &[unknown()], 10);
        assert_eq!(context.estimate(), None);
        assert!(context.is_completable());
    }

    #[test]
    fn follows_the_tree_for_descendants() {
        //  7 - 8 - 9 - 10
        //     ||| |||
        //      8   9 - 10 - 11
        let first = branch(1, 4);
        let mut second = branch(2, 4);
        second[0] = first[1];
        second[1] = first[2];
        let mut context = RoundContext::new(1000, 670);
        context.accept_prevote(7, &first, 250);
        context.accept_prevote(8, &second, 200);
        assert!(!context.is_descendant((11, second[3]), (9, first[2])));
        assert!(context.is_descendant((9, first[2]), (9, first[2])));
        assert!(context.is_descendant((9, first[2]), (11, second[3])));
        assert!(!context.is_descendant((9, first[0]), (11, second[3])));
        assert!(!context.is_descendant((9, first[2]), (11, second[0])));
    }

    #[test]
    fn completes_only_when_no_descendant_of_the_best_prevote_can_win() {
        // 見ていない子孫が 800 を取りうる
        let (mut context, first, _) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(9, first[2], 200);
        assert!(!context.is_completable());
        assert_eq!(context.estimate(), Some((9, first[2])));

        // つながっていないブロックへの precommit で、残りが減る
        let (mut context, first, third) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(9, first[2], 200);
        context.accept_precommit(9, third[2], 200);
        assert!(context.is_completable());

        // 子孫の高さ 10 が届きうる
        let (mut context, first, _) = forked();
        context.accept_prevote(7, &first[..3], 700);
        context.accept_precommit(10, first[3], 400);
        assert!(!context.is_completable());
        assert_eq!(context.estimate(), Some((9, first[2])));

        // 取っておいた precommit は数えないが、prevote が来れば数える
        context.accept_precommit(10, unknown(), 500);
        assert!(!context.is_completable());
        context.accept_prevote(9, &[first[2], unknown()], 10);
        assert!(context.is_completable());
        assert_eq!(context.estimate(), Some((9, first[2])));
    }

    #[test]
    fn adds_weights_along_overlapping_branches() {
        let hashes = branch(1, 3);
        let mut context = RoundContext::new(1000, 670);
        context.accept_prevote(7, &hashes, 250);
        assert_eq!(context.len(), 3);
        assert_eq!(context.weights((8, hashes[1])), weights(250, 0));
        assert_eq!(context.weights((11, hashes[0])), Weights::default());
        assert_eq!(context.weights((8, unknown())), Weights::default());

        //  7 - 8 - 9 - 10
        //     ||| |||
        //      8   9 - 10 - 11
        let first = branch(1, 4);
        let mut second = branch(2, 4);
        second[0] = first[1];
        second[1] = first[2];
        for precommits_first in [false, true] {
            let mut context = RoundContext::new(1000, 670);
            let precommit = |context: &mut RoundContext| {
                context.accept_precommit(10, first[3], 100);
                context.accept_precommit(10, second[2], 150);
                context.accept_precommit(8, first[1], 50);
            };
            if precommits_first {
                precommit(&mut context);
                assert!(context.is_empty());
            }
            context.accept_prevote(7, &first, 250);
            context.accept_prevote(8, &second, 200);
            if !precommits_first {
                precommit(&mut context);
            }
            assert_eq!(context.len(), 6);
            assert_eq!(context.weights((7, first[0])), weights(250, 300));
            assert_eq!(context.weights((8, first[1])), weights(450, 300));
            assert_eq!(context.weights((9, first[2])), weights(450, 250));
            assert_eq!(context.weights((10, first[3])), weights(250, 100));
            assert_eq!(context.weights((10, second[2])), weights(200, 150));
            assert_eq!(context.weights((11, second[3])), weights(200, 0));
        }
    }

    #[test]
    fn adds_up_precommits_that_wait_for_the_same_block() {
        let first = branch(1, 3);
        let second = branch(2, 4);
        let mut context = RoundContext::new(1000, 670);
        context.accept_precommit(8, first[1], 75);
        context.accept_precommit(8, first[1], 25);
        context.accept_precommit(10, second[2], 110);
        context.accept_precommit(10, second[2], 40);
        context.accept_prevote(7, &first, 250);
        context.accept_prevote(8, &second, 200);
        assert_eq!(context.len(), 7);
        assert_eq!(context.weights((7, first[0])), weights(250, 100));
        assert_eq!(context.weights((8, first[1])), weights(250, 100));
        assert_eq!(context.weights((9, first[2])), weights(250, 0));
        assert_eq!(context.weights((8, second[0])), weights(200, 150));
        assert_eq!(context.weights((10, second[2])), weights(200, 150));
        assert_eq!(context.weights((11, second[3])), weights(200, 0));
    }
}
