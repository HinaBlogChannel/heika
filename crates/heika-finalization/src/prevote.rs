//! prevote に入れるブロックの範囲。catapult の `FinalizationMessageFactory` の `loadPrevoteHashChain`。
//!
//! 最後にファイナライズした高さから、チェーンの先端より `prevoteBlocksMultiple` 前までを、その倍数にそろえて入れる。
//! エポックの最後の高さを超えず、`maxHashesPerPoint` を超えるなら、倍数ずつ減らす。

use heika_block::finalization::FinalizationRound;

use crate::Settings;

/// prevote に入れるブロックの、最初の高さと数。ストレージに数だけないときは、あるだけ入れる。
/// 1つも入れられなければ、最後にファイナライズしたブロックだけを入れる（catapult と同じ）
pub fn prevote_range(
    round: FinalizationRound,
    finalized_height: u64,
    chain_height: u64,
    settings: &Settings,
) -> (u64, u64) {
    let multiple = settings.prevote_blocks_multiple;
    let mut max_height = if chain_height >= multiple {
        chain_height - multiple
    } else {
        chain_height
    };
    let epoch_end = match round.epoch {
        0 | 1 => 1,
        epoch => (u64::from(epoch) - 1) * settings.voting_set_grouping,
    };
    max_height = max_height.min(epoch_end);
    let clamped = round_down(max_height, multiple);
    let mut count = if clamped > finalized_height {
        clamped - finalized_height + 1
    } else {
        1
    };
    if count > settings.max_hashes_per_point {
        count -= round_up(count - settings.max_hashes_per_point, multiple);
    }
    (finalized_height, count)
}

/// catapult の `Clamp(value, multiple, 0)`
fn round_down(value: u64, multiple: u64) -> u64 {
    if value.is_multiple_of(multiple) {
        value
    } else {
        value / multiple * multiple
    }
}

/// catapult の `Clamp(value, multiple, 1)`
fn round_up(value: u64, multiple: u64) -> u64 {
    if value.is_multiple_of(multiple) {
        value
    } else {
        (value / multiple + 1) * multiple
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETTINGS: Settings = Settings {
        step_duration: 1000,
        prevote_blocks_multiple: 4,
        max_hashes_per_point: 16,
        voting_set_grouping: 100,
    };
    /// エポック 3 は高さ 200 で終わる
    const ROUND: FinalizationRound = FinalizationRound { epoch: 3, point: 1 };

    #[test]
    fn votes_up_to_a_multiple_below_the_tip() {
        // 先端 150 の 4 前の 146 を、4 の倍数の 144 にそろえる
        assert_eq!(prevote_range(ROUND, 140, 150, &SETTINGS), (140, 5));
        // 先端 148 の 4 前は、ちょうど 144
        assert_eq!(prevote_range(ROUND, 140, 148, &SETTINGS), (140, 5));
    }

    #[test]
    fn votes_only_the_finalized_block_when_the_chain_is_not_ahead() {
        assert_eq!(prevote_range(ROUND, 140, 143, &SETTINGS), (140, 1));
        assert_eq!(prevote_range(ROUND, 140, 140, &SETTINGS), (140, 1));
        // 先端が倍数より低いときは、先端をそのまま使う
        assert_eq!(prevote_range(ROUND, 1, 3, &SETTINGS), (1, 1));
    }

    #[test]
    fn stops_at_the_end_of_the_epoch() {
        assert_eq!(prevote_range(ROUND, 196, 300, &SETTINGS), (196, 5));
    }

    #[test]
    fn trims_to_the_limit_by_multiples() {
        // 144 − 100 + 1 = 45 は 16 を 29 超える。29 を 4 の倍数の 32 にして引き、13
        assert_eq!(prevote_range(ROUND, 100, 150, &SETTINGS), (100, 13));
    }
}
