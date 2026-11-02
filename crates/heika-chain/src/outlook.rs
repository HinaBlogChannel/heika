//! ハーベストの見込み。画面に「次の当たりで作れそうか」「平均でどのくらいに1回作れるか」を見せるための見積もりで、
//! 合意には使わない（浮動小数点を使う）。
//!
//! hit は `2^54 × |ln u|`（u は generation hash から求めた一様な値）なので、`2^54` で割ると平均 1 の指数分布になる。
//! 的（[`target`]）は Importance に比例するので、経過 t 秒までに Importance `I` のアカウントが当たりになる見込みは
//! `1 − exp(−I × h(t))`。`h(t)` は Importance 1 あたりの的を `2^54` で割ったもの（[`hazard_per_importance`]）。
//!
//! ここから次のことが言える。
//! - どのアカウントも同じ `h` を使うので、1つのブロックを自分が作る見込みは、難易度や smoother によらず `自分 ÷ A`
//!   （`A` はハーベストしている Importance の合計）
//! - ブロックは、的が hit を超えた最初の整数秒に作られる（経過秒は切り捨てて数える）。なので経過 `k` 秒のブロックは、
//!   作ったアカウントの的が `k − 1` 秒から `k` 秒のあいだに hit を超え、ほかのだれも `k − 1` 秒までには超えなかった、
//!   ということ。その見込みは `exp(−A × h(k − 1)) − exp(−A × h(k))` で、直近のブロックからこれを最大にする `A` を
//!   求める（[`active_importance`]）。smoother は目標の時間を過ぎると的を指数的に広げるので、1 秒の違いが大きく効く。
//!   `k` 秒ちょうどまでだれも当たらなかったと見ると、`A` を小さく見積もってしまう（ブロックの目標が 5 秒のネットワーク
//!   で 3 割ほど、30 秒のメインネットで 5% ほど）
//! - 自分の次の当たりが経過 `x` 秒とわかっていれば、ほかのだれかが `x − 1` 秒までに当たれば先を越される。`x − 1` 秒から
//!   `x` 秒のあいだに当たれば同じ秒に並ぶので、半々とみる（[`win_chance`]）。ブロックが届くまでの遅れは見ない

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

/// 古い順に並べた直近のブロックから、ハーベストしている Importance の合計を最尤推定で見積もる。
/// 見積もれなければ（2つ未満か、どのブロックも 1 秒目に作られていて上限が決まらなければ）`None`
pub fn active_importance(recent: &[BlockStatistic], parameters: &NetworkParameters) -> Option<f64> {
    // （k − 1 秒までの h、k − 1 秒から k 秒までに増えた h）
    let intervals: Vec<(f64, f64)> = recent
        .windows(2)
        .filter_map(|pair| {
            let elapsed = pair[1].timestamp.saturating_sub(pair[0].timestamp) / 1000;
            // 0 秒では的が 0 なので、作られえない。時計のずれなどで来たものは数えない
            let before =
                hazard_per_importance(elapsed.checked_sub(1)?, pair[1].difficulty, parameters);
            let at = hazard_per_importance(elapsed, pair[1].difficulty, parameters);
            (at > before).then_some((before, at - before))
        })
        .collect();
    if intervals.is_empty() {
        return None;
    }
    // 対数尤度を A で微分したもの。A について減る一方なので、0 になるところを二分法で探す
    let score = |active: f64| -> f64 {
        intervals
            .iter()
            .map(|&(before, width)| -before + width / (active * width).exp_m1())
            .sum()
    };
    // k 秒ちょうどまでだれも当たらなかったと見た見積もりから始め、0 をはさむまで広げる
    let start = intervals.len() as f64
        / intervals
            .iter()
            .map(|(before, width)| before + width)
            .sum::<f64>();
    let (mut low, mut high) = (start, start);
    for _ in 0..64 {
        if score(low) > 0.0 {
            break;
        }
        low /= 2.0;
    }
    for _ in 0..64 {
        if score(high) < 0.0 {
            break;
        }
        high *= 2.0;
    }
    if !(score(low) > 0.0 && score(high) < 0.0) {
        return None;
    }
    // 比で割っていく。100 回で、比の差は十分に小さくなる
    for _ in 0..100 {
        let middle = (low * high).sqrt();
        if score(middle) > 0.0 {
            low = middle;
        } else {
            high = middle;
        }
    }
    Some((low * high).sqrt())
}

/// 直近のブロックの、平均の間隔（秒）。2つ未満なら `None`
pub fn average_block_seconds(recent: &[BlockStatistic]) -> Option<f64> {
    let (first, last) = (recent.first()?, recent.last()?);
    (recent.len() >= 2).then(|| {
        last.timestamp.saturating_sub(first.timestamp) as f64 / 1000.0 / (recent.len() - 1) as f64
    })
}

/// 難易度 `difficulty` のブロックを経過 `elapsed_seconds` 秒に作れる自分が、Importance の合計 `others` のほかの
/// アカウントに先を越されない見込み。同じ秒に並ぶものは半々に数える
pub fn win_chance(
    elapsed_seconds: u64,
    difficulty: u64,
    others: f64,
    parameters: &NetworkParameters,
) -> f64 {
    let none_by =
        |seconds| (-others * hazard_per_importance(seconds, difficulty, parameters)).exp();
    let before = elapsed_seconds.checked_sub(1).map_or(1.0, none_by);
    (before + none_by(elapsed_seconds)) / 2.0
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

    /// テストの中だけの、決まった並びの乱数（xorshift）。(0, 1) の一様な値を返す
    struct Uniform(u64);

    impl Uniform {
        fn next(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            ((self.0 >> 11) as f64 + 0.5) / (1u64 << 53) as f64
        }
    }

    /// Importance の合計 `active` のアカウントたちが、ブロックを `count` 個作ったときの直近のブロック。
    /// だれかの的が hit を超えた最初の整数秒に作る（ほかの規則は catapult と同じ）
    fn simulate(active: f64, count: usize, parameters: &NetworkParameters) -> Vec<BlockStatistic> {
        let mut uniform = Uniform(0x9E37_79B9_7F4A_7C15);
        let mut timestamp = 0;
        let mut recent = vec![BlockStatistic {
            timestamp,
            difficulty: DEFAULT_DIFFICULTY,
        }];
        for _ in 0..count {
            // だれも当たらない見込みが u を下回る最初の秒（どのアカウントの hit も指数分布なので、合計で見てよい）
            let needed = -uniform.next().ln();
            let seconds = (1..)
                .find(|&seconds| {
                    active * hazard_per_importance(seconds, DEFAULT_DIFFICULTY, parameters)
                        >= needed
                })
                .unwrap();
            timestamp += seconds * 1000;
            recent.push(BlockStatistic {
                timestamp,
                difficulty: DEFAULT_DIFFICULTY,
            });
        }
        recent
    }

    #[test]
    fn estimates_back_the_importance_that_made_the_blocks() {
        let mut fast = NetworkParameters::MAINNET;
        fast.block_generation_target_time = std::time::Duration::from_secs(5);
        for parameters in [MAINNET, &fast] {
            // 目標の時間ほどでブロックが作られる合計にする
            let target_time = parameters.block_generation_target_time.as_secs();
            let active = 1.0 / hazard_per_importance(target_time, DEFAULT_DIFFICULTY, parameters);
            let recent = simulate(active, 3000, parameters);
            let estimated = active_importance(&recent, parameters).unwrap();
            assert!(
                (estimated / active - 1.0).abs() < 0.05,
                "{target_time}: {estimated} / {active}"
            );
            // 整数秒ちょうどまでだれも当たらなかったと見ると、小さく見積もってしまう
            let naive = (recent.len() - 1) as f64
                / recent
                    .windows(2)
                    .map(|pair| {
                        let seconds = (pair[1].timestamp - pair[0].timestamp) / 1000;
                        hazard_per_importance(seconds, DEFAULT_DIFFICULTY, parameters)
                    })
                    .sum::<f64>();
            let bias = if target_time == 5 { 0.7 } else { 0.99 };
            assert!(naive < active * bias, "{target_time}: {naive} / {active}");
        }
        let recent = simulate(1e12, 1, MAINNET);
        assert_eq!(active_importance(&recent[..1], MAINNET), None);
    }

    #[test]
    fn counts_a_tie_as_half_and_is_surer_the_earlier() {
        let others = 1.0 / hazard_per_importance(30, DEFAULT_DIFFICULTY, MAINNET);
        // ほかにだれもいなければ必ず作れる
        assert_eq!(win_chance(30, DEFAULT_DIFFICULTY, 0.0, MAINNET), 1.0);
        // 1 秒目なら、先を越されることはなく、並ぶだけ
        let first = win_chance(1, DEFAULT_DIFFICULTY, others, MAINNET);
        assert!(first > 0.5 && first <= 1.0, "{first}");
        let chances: Vec<f64> = [1, 10, 30, 40]
            .into_iter()
            .map(|seconds| win_chance(seconds, DEFAULT_DIFFICULTY, others, MAINNET))
            .collect();
        assert!(
            chances.windows(2).all(|pair| pair[0] > pair[1]),
            "{chances:?}"
        );
        assert_eq!(average_block_seconds(&simulate(others, 0, MAINNET)), None);
    }
}
