//! 鍵で投票のメッセージを作る。catapult の `FinalizationMessageFactory`。
//!
//! prevote は、最後の確定のブロックから [`crate::prevote::prevote_range`] の範囲のハッシュに、precommit は
//! 段取り役の決めたブロックに署名する。鍵はエポックごとで、どう持ってどう書き残すかは [`VotingKeys`] を実装する側が
//! 決める。

use heika_block::finalization::message::{FinalizationMessage, SIGNATURE_SIZE};
use heika_block::finalization::round::Candidate;
use heika_block::finalization::{FinalizationRound, FinalizedBlockHeader};
use heika_core::hash::Hash256;

use crate::Settings;
use crate::orchestrator::MessageFactory;
use crate::prevote::prevote_range;

/// 投票の鍵
pub trait VotingKeys {
    /// 署名するところ `signed` に、エポック `epoch` の鍵で署名する（`BmTreeSignature`）。鍵がない、もう使えない
    /// エポックなら `None`。署名を返す前に、使ったことを書き残しておく（落ちて起き直しても前のエポックに戻らない）
    fn sign(&mut self, epoch: u32, signed: &[u8]) -> Option<[u8; SIGNATURE_SIZE]>;
}

/// 鍵で投票のメッセージを作る。段取り役を進めるたびに、そのときのチェーンの様子で作り直す
pub struct Signer<'a> {
    pub keys: &'a mut dyn VotingKeys,
    pub settings: Settings,
    /// 最後の確定。prevote はこのブロックから
    pub finalized: FinalizedBlockHeader,
    /// 手元のチェーンの先端の高さ
    pub chain_height: u64,
    /// 手元のチェーンの、高さ `from` から `count` 個のブロックのハッシュ。ないところより先は入れない
    pub hashes: &'a dyn Fn(u64, u64) -> Vec<Hash256>,
}

impl MessageFactory for Signer<'_> {
    fn prevote(&mut self, round: FinalizationRound) -> Option<FinalizationMessage> {
        let (from, count) = prevote_range(
            round,
            self.finalized.height,
            self.chain_height,
            &self.settings,
        );
        let mut hashes = (self.hashes)(from, count);
        if hashes.is_empty() {
            hashes = vec![self.finalized.hash];
        }
        let keys = &mut *self.keys;
        FinalizationMessage::sign(round, true, from, hashes, |signed| {
            keys.sign(round.epoch, signed)
        })
    }

    fn precommit(
        &mut self,
        round: FinalizationRound,
        target: Candidate,
    ) -> Option<FinalizationMessage> {
        let keys = &mut *self.keys;
        FinalizationMessage::sign(round, false, target.0, vec![target.1], |signed| {
            keys.sign(round.epoch, signed)
        })
    }
}

#[cfg(test)]
mod tests {
    use heika_core::voting::VotingKeyTree;

    use super::*;
    use crate::stage::tests::block_hash;

    const SETTINGS: Settings = Settings {
        step_duration: 1000,
        prevote_blocks_multiple: 4,
        max_hashes_per_point: 256,
        voting_set_grouping: 100,
    };

    /// メモリの鍵の木
    struct Tree(VotingKeyTree);

    impl VotingKeys for Tree {
        fn sign(&mut self, epoch: u32, signed: &[u8]) -> Option<[u8; SIGNATURE_SIZE]> {
            self.0.sign(epoch, &[signed])
        }
    }

    fn tree() -> Tree {
        Tree(VotingKeyTree::generate(&mut rand_core::UnwrapErr(getrandom::SysRng), 2, 4).unwrap())
    }

    fn chain_hashes(from: u64, count: u64) -> Vec<Hash256> {
        // 先端は高さ 150
        (from..from + count)
            .take_while(|height| *height <= 150)
            .map(|height| block_hash(height, 0))
            .collect()
    }

    fn signer<'a>(keys: &'a mut Tree, chain_height: u64) -> Signer<'a> {
        Signer {
            keys,
            settings: SETTINGS,
            finalized: FinalizedBlockHeader {
                round: FinalizationRound { epoch: 3, point: 1 },
                height: 140,
                hash: block_hash(140, 0),
            },
            chain_height,
            hashes: &chain_hashes,
        }
    }

    #[test]
    fn prevotes_from_the_finalized_block() {
        let mut keys = tree();
        let round = FinalizationRound { epoch: 3, point: 2 };
        let message = signer(&mut keys, 150).prevote(round).unwrap();
        assert!(message.is_prevote);
        assert_eq!(message.round, round);
        // 先端 150 の 4 前を 4 の倍数にそろえた 144 まで
        assert_eq!((message.height, message.last_height()), (140, 144));
        assert_eq!(message.hashes[0], block_hash(140, 0));
        assert!(message.verify_signature());
        assert_eq!(message.root_key(), keys.0.public_key().0);
    }

    #[test]
    fn prevotes_only_the_finalized_block_without_newer_ones() {
        let mut keys = tree();
        let round = FinalizationRound { epoch: 3, point: 2 };
        let message = signer(&mut keys, 141).prevote(round).unwrap();
        assert_eq!(message.hashes, [block_hash(140, 0)]);
    }

    #[test]
    fn precommits_the_target() {
        let mut keys = tree();
        let round = FinalizationRound { epoch: 3, point: 2 };
        let target = (143, block_hash(143, 0));
        let message = signer(&mut keys, 150).precommit(round, target).unwrap();
        assert!(!message.is_prevote);
        assert_eq!(
            (message.height, message.hashes.clone()),
            (143, vec![target.1])
        );
        assert!(message.verify_signature());
    }

    #[test]
    fn makes_nothing_without_a_key_for_the_epoch() {
        let mut keys = tree();
        let late = FinalizationRound { epoch: 5, point: 1 };
        assert!(signer(&mut keys, 150).prevote(late).is_none());
        // 先のエポックで署名したら、前のエポックには戻れない
        let round = FinalizationRound { epoch: 4, point: 1 };
        assert!(signer(&mut keys, 150).prevote(round).is_some());
        let earlier = FinalizationRound { epoch: 3, point: 9 };
        assert!(
            signer(&mut keys, 150)
                .precommit(earlier, (143, block_hash(143, 0)))
                .is_none()
        );
    }
}
