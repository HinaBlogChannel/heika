//! ハーベストの見込み。画面に「次の当たりで作れそうか」「平均でどのくらいに1回作れるか」を見せるための見積もりで、
//! 合意には使わない（浮動小数点を使う）。
//!
//! hit は `2^54 × |ln u|`（u は generation hash から求めた一様な値）なので、`2^54` で割ると平均 1 の指数分布になる。
//! 的（[`target`]）は Importance に比例するので、経過 t 秒までに Importance `I` のアカウントが当たりになる見込みは
//! `1 − exp(−I × h(t))`。`h(t)` は Importance 1 あたりの的を `2^54` で割ったもの（[`hazard_per_importance`]）。
//!
//! ここから次のことが言える。
//! - ハーベストしている Importance の合計 `A` は、直近のブロックの親からの経過 `t_k` と難易度から、最尤推定で
//!   `n ÷ Σ h(t_k)` と見積もれる（[`active_importance`]）
//! - どのアカウントも同じ `h` を使うので、1つのブロックを自分が作る見込みは、難易度や smoother によらず `自分 ÷ A`
//! - 自分の次の当たりが経過 `x` 秒と VRF でわかっていれば、ほかのだれもそれより先に当たらない見込みは
//!   `exp(−(A − 自分) × h(x))`（[`none_before`]）。ブロックが届くまでの遅れは見ない

use heika_block::scoring::{BlockStatistic, target};
use heika_core::network::NetworkParameters;

/// hit の尺度（2^54）
const HIT_SCALE: f64 = (1u64 << 54) as f64;

/// 経過 `elapsed_seconds` 秒、難易度 `difficulty` の的を、Importance 1 あたりにして 2^54 で割ったもの
pub fn hazard_per_importance(
    elapsed_seconds: u64,
    difficulty: u64,
    parameters: &NetworkParameters,
) -> f64 {
    // Importance 1 で求めると割り算で消えるので、合計の Importance で求めてから割る
    let scale = parameters.total_chain_importance.max(1);
    target(elapsed_seconds, difficulty, scale, parameters).to_f64() / scale as f64 / HIT_SCALE
}

/// 古い順に並べた直近のブロックから、ハーベストしている Importance の合計を見積もる。2つ未満なら `None`
pub fn active_importance(recent: &[BlockStatistic], parameters: &NetworkParameters) -> Option<f64> {
    let sum: f64 = recent
        .windows(2)
        .map(|pair| {
            let elapsed = pair[1].timestamp.saturating_sub(pair[0].timestamp) / 1000;
            hazard_per_importance(elapsed, pair[1].difficulty, parameters)
        })
        .sum();
    (recent.len() >= 2 && sum > 0.0).then(|| (recent.len() - 1) as f64 / sum)
}

/// 直近のブロックの、平均の間隔（秒）。2つ未満なら `None`
pub fn average_block_seconds(recent: &[BlockStatistic]) -> Option<f64> {
    let (first, last) = (recent.first()?, recent.last()?);
    (recent.len() >= 2).then(|| {
        last.timestamp.saturating_sub(first.timestamp) as f64 / 1000.0 / (recent.len() - 1) as f64
    })
}

/// 難易度 `difficulty` のブロックで、経過 `elapsed_seconds` 秒までに、Importance の合計 `others` のアカウントの
/// どれも当たりにならない見込み
pub fn none_before(
    elapsed_seconds: u64,
    difficulty: u64,
    others: f64,
    parameters: &NetworkParameters,
) -> f64 {
    (-others * hazard_per_importance(elapsed_seconds, difficulty, parameters)).exp()
}

#[cfg(test)]
mod tests {
    use heika_block::scoring::{DEFAULT_DIFFICULTY, earliest_hit_seconds};

    use super::*;

    const MAINNET: &NetworkParameters = &NetworkParameters::MAINNET;

    #[test]
    fn the_hazard_agrees_with_the_earliest_hit() {
        // hit が `2^54 × h(t) × I` を超えない一番早い t が、earliest_hit_seconds の答え
        let importance = 1_000_000_000_000u64;
        let hazard = |seconds| hazard_per_importance(seconds, DEFAULT_DIFFICULTY, MAINNET);
        for hit in [1u64 << 50, 1 << 53, 1 << 54, 3 << 54] {
            let seconds =
                earliest_hit_seconds(hit, DEFAULT_DIFFICULTY, importance, 3600, MAINNET).unwrap();
            let at = |seconds| hazard(seconds) * importance as f64 * HIT_SCALE;
            assert!(at(seconds) >= hit as f64 * 0.999, "{hit}: {seconds}");
            assert!(at(seconds - 1) <= hit as f64 * 1.001, "{hit}: {seconds}");
        }
    }

    #[test]
    fn estimates_back_the_importance_that_made_the_blocks() {
        // 間隔がどれも t 秒なら、見積もりは 1 / h(t)。その合計なら、t 秒までにだれも当たらない見込みは e^-1
        let recent: Vec<BlockStatistic> = (0..10)
            .map(|index| BlockStatistic {
                timestamp: index * 30_000,
                difficulty: DEFAULT_DIFFICULTY,
            })
            .collect();
        let active = active_importance(&recent, MAINNET).unwrap();
        assert!(
            (active * hazard_per_importance(30, DEFAULT_DIFFICULTY, MAINNET) - 1.0).abs() < 1e-9
        );
        let none = none_before(30, DEFAULT_DIFFICULTY, active, MAINNET);
        assert!((none - (-1f64).exp()).abs() < 1e-9);
        assert_eq!(average_block_seconds(&recent), Some(30.0));
        assert_eq!(active_importance(&recent[..1], MAINNET), None);
        // 早く当たるほど、だれも先に当たらない見込みは高い
        assert!(none_before(5, DEFAULT_DIFFICULTY, active, MAINNET) > none);
    }
}
