//! ブロックの難易度と、ハーベストの当たり判定。catapult の `chain/BlockDifficultyScorer.cpp` と
//! `chain/BlockScorer.cpp`、そこで使う `utils/IntegerMath.cpp`。
//!
//! ブロックを出せるのは、ブロックの generation hash から求めた hit が、前のブロックからの経過時間、難易度、
//! ハーベストしたアカウントの Importance から求めた target より小さいときだけ。難易度は直前のブロックの
//! 難易度とタイムスタンプだけで決まるので、ヘッダーを並べれば確かめられる。Importance はその高さの状態にあるので、
//! 呼ぶ側が持ってくる。
//!
//! どれも整数だけで、catapult と同じ順番で丸める。浮動小数点は使わない。

use heika_core::network::NetworkParameters;
use heika_core::vrf::GenerationHash;

use crate::Block;

/// 難易度の既定値。直前のブロックが2つ未満のときに使う。catapult の `Difficulty_tag::Default_Value`
pub const DEFAULT_DIFFICULTY: u64 = 100_000_000_000_000;
/// 難易度の下限
pub const MIN_DIFFICULTY: u64 = DEFAULT_DIFFICULTY / 10;
/// 難易度の上限
pub const MAX_DIFFICULTY: u64 = DEFAULT_DIFFICULTY * 10;

/// 難易度を決めるのに見る、1つのブロックのタイムスタンプと難易度。catapult の `state::BlockStatistic`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BlockStatistic {
    /// ネメシスのブロックからのミリ秒
    pub timestamp: u64,
    pub difficulty: u64,
}

impl From<&Block> for BlockStatistic {
    fn from(block: &Block) -> Self {
        Self {
            timestamp: block.timestamp,
            difficulty: block.difficulty,
        }
    }
}

/// 次のブロックの難易度。catapult の `CalculateDifficulty`。
///
/// `previous` は直前のブロックを古い順に並べたもので、`maxDifficultyBlocks` 個まで（高さ1から数えて足りなければ、あるだけ）。
/// 平均の難易度を、目標の間隔と実際の間隔の比で直し、直前のブロックから 5% までしか動かさない。
pub fn difficulty(previous: &[BlockStatistic], parameters: &NetworkParameters) -> u64 {
    let previous = &previous[previous
        .len()
        .saturating_sub(parameters.max_difficulty_blocks)..];
    let (Some(first), Some(last)) = (previous.first(), previous.last()) else {
        return DEFAULT_DIFFICULTY;
    };
    if previous.len() < 2 {
        return DEFAULT_DIFFICULTY;
    }
    let count = previous.len() as u64;
    let average = previous
        .iter()
        .map(|statistic| statistic.difficulty)
        .sum::<u64>()
        / count;
    let elapsed = last.timestamp - first.timestamp;
    let target_time = parameters.block_generation_target_time.as_millis();
    // catapult は 128 ビットから 64 ビットに縮める。普通は収まる
    let scaled = u128::from(average) * target_time * u128::from(count - 1) / u128::from(elapsed);
    let mut difficulty = u64::try_from(scaled).unwrap_or(u64::MAX);
    let last = last.difficulty;
    if 19 * last > 20 * difficulty {
        difficulty = 19 * last / 20;
    } else if 21 * last < 20 * difficulty {
        difficulty = 21 * last / 20;
    }
    difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

/// generation hash から求めた hit。catapult の `CalculateHit`。
///
/// generation hash を 256 ビットの整数 v と見て、2^54 × |ln(v / 2^256)| を求める。最初の1のビットから32ビットだけを使う。
pub fn hit(generation_hash: &GenerationHash) -> u64 {
    let hash = &generation_hash.0;
    let leading_zeros = hash
        .iter()
        .position(|&byte| byte != 0)
        .map_or(256, |index| 8 * index as u32 + hash[index].leading_zeros());
    let at = |index: usize| u32::from_be_bytes(hash[index..index + 4].try_into().expect("4 bytes"));
    let (value, leading_zeros) = if leading_zeros >= 224 {
        (at(28), 224)
    } else {
        let quotient = (leading_zeros / 8) as usize;
        let remainder = leading_zeros % 8;
        // 余りが0のときの右シフト8は、u8 を int にしてからなので0になる
        let next = u32::from(hash[quotient + 4]) >> (8 - remainder);
        (
            (at(quotient) << remainder).wrapping_add(next),
            leading_zeros,
        )
    };
    if value == 0 {
        return u64::MAX;
    }
    if value == u32::MAX {
        return 0;
    }
    let log = log2_times_power_of_two(u64::from(value), 54);
    let result = u128::from(32 + leading_zeros) * (1 << 54) - u128::from(log);
    // log2(e) で割る
    (result * 10_000_000_000_000_000 / 14_426_950_408_889_634) as u64
}

/// ハーベストの的。catapult の `CalculateTarget`。hit がこれより小さければ、そのアカウントはブロックを出せる。
///
/// `elapsed_seconds` は前のブロックからの経過秒（切り捨て）、`importance` はハーベストしたアカウント
/// （リモートならメインアカウント）の、その高さの Importance。
pub fn target(
    elapsed_seconds: u64,
    difficulty: u64,
    importance: u64,
    parameters: &NetworkParameters,
) -> U256 {
    let mut target = U256::from(elapsed_seconds);
    target = target.mul_u64(importance);
    // 掛ける数は smoother << 48
    target = target.mul_u64(u64::from(smoother(elapsed_seconds, parameters)));
    target = target.shl(48);
    target = target.mul_u64(8_999_999_998);
    target = target.div_u64(parameters.total_chain_importance);
    target.div_u64(difficulty)
}

/// `block` を、前のブロック `parent` のあとに、Importance が `importance` のアカウントが出してよいか。
/// catapult の `BlockHitPredicate`。generation hash はブロックの VRF の証明から求める（証明そのものは確かめない）。
pub fn is_hit(
    parent: &Block,
    block: &Block,
    importance: u64,
    parameters: &NetworkParameters,
) -> bool {
    if block.timestamp <= parent.timestamp {
        return false;
    }
    let elapsed_seconds = (block.timestamp - parent.timestamp) / 1000;
    let target = target(elapsed_seconds, block.difficulty, importance, parameters);
    target.greater_than_u64(hit(&block.generation_hash()))
}

/// 経過時間が目標から外れたぶん、的を広げたり狭めたりする倍率。s15.16 の固定小数点。catapult の `GetMultiplier`
fn smoother(elapsed_seconds: u64, parameters: &NetworkParameters) -> u32 {
    /// log2(100) の s15.16
    const LOG2_100: i128 = 435_411;
    if parameters.block_time_smoothing_factor == 0 {
        return 1 << 16;
    }
    let factor = ((i128::from(parameters.block_time_smoothing_factor) << 16) << 16) / (1000 << 16);
    let target_time = (parameters.block_generation_target_time.as_secs() as i128) << 16;
    let elapsed = i128::from(elapsed_seconds) << 16;
    // log2(e) を掛ける。i128 の割り算は catapult と同じく0の方へ切り捨てる
    let power = factor * (elapsed - target_time) / target_time;
    let power = power * 14_426_950_408 / 10_000_000_000;
    if power < -(5 << 16) {
        0
    } else if power > LOG2_100 {
        100 << 16
    } else {
        fixed_point_power_of_two(power as i32)
    }
}

/// log2(value) × 2^n の整数部分。catapult の `Log2TimesPowerOfTwo`。`value` は0でないこと
fn log2_times_power_of_two(value: u64, n: u32) -> u64 {
    const PRECISION: u64 = 31;
    const POWER_OF_TWO: u64 = 1 << PRECISION;
    let mut y = PRECISION;
    let mut x = value;
    // x を [1, 2) に寄せる
    while x < POWER_OF_TWO {
        x <<= 1;
        y -= 1;
    }
    // 2乗するたびに、係数を1つずつ取り出す
    for _ in 0..n {
        x = (x * x) >> PRECISION;
        y <<= 1;
        if x >= 2 * POWER_OF_TWO {
            x >>= 1;
            y += 1;
        }
    }
    y
}

/// 2^value。value も答えも s15.16 の固定小数点で、-5 < value < 15 で使う。catapult の `FixedPointPowerOfTwo`
fn fixed_point_power_of_two(value: i32) -> u32 {
    // value = i + f、f は (-0.5, 0.5]
    let i = (value + 0x8000) & !0xFFFF;
    let f = i64::from(value - i);
    let shift = ((15 << 16) - i) / 65_536;
    // (-0.5, 0.5] での 2^f の最良近似の多項式
    let mut r: i64 = 0x0000_0E20;
    r = (r * f + 0x3E1C_C333) / 131_072;
    r = (r * f + 0x58BD_46A6) / 65_536;
    r = r * f + 0x7FFD_E4A3;
    (r as u32) >> shift
}

/// 256 ビットの符号なし整数。target を求めるのに要る、掛け算、割り算、シフトだけを持つ。
/// catapult の `BlockTarget`（boost の `uint256_t`）
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct U256 {
    /// 上の桁から
    limbs: [u64; 4],
}

impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self {
            limbs: [0, 0, 0, value],
        }
    }
}

impl U256 {
    /// 大きい順のバイト列
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.limbs) {
            *chunk = limb.to_be_bytes();
        }
        out
    }

    /// `value` より大きいか
    pub fn greater_than_u64(self, value: u64) -> bool {
        self > Self::from(value)
    }

    /// 掛け算。あふれた上の桁は捨てる
    fn mul_u64(self, value: u64) -> Self {
        let mut limbs = [0; 4];
        let mut carry = 0u128;
        for index in (0..4).rev() {
            let product = u128::from(self.limbs[index]) * u128::from(value) + carry;
            limbs[index] = product as u64;
            carry = product >> 64;
        }
        Self { limbs }
    }

    /// 割り算。切り捨てる
    fn div_u64(self, value: u64) -> Self {
        let mut limbs = [0; 4];
        let mut remainder = 0u128;
        for (limb, &current) in limbs.iter_mut().zip(&self.limbs) {
            let current = (remainder << 64) | u128::from(current);
            *limb = (current / u128::from(value)) as u64;
            remainder = current % u128::from(value);
        }
        Self { limbs }
    }

    /// 左シフト。64 未満だけ
    fn shl(self, bits: u32) -> Self {
        debug_assert!(0 < bits && bits < 64);
        let mut limbs = [0; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = self.limbs[index] << bits;
            if let Some(lower) = self.limbs.get(index + 1) {
                *limb |= lower >> (64 - bits);
            }
        }
        Self { limbs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET: NetworkParameters = NetworkParameters::MAINNET;

    /// 決まった間隔と難易度で並んだブロック
    fn steady(count: usize, interval: u64, difficulty: u64) -> Vec<BlockStatistic> {
        (0..count as u64)
            .map(|index| BlockStatistic {
                timestamp: 1_000_000 + index * interval,
                difficulty,
            })
            .collect()
    }

    #[test]
    fn difficulty_defaults_with_fewer_than_two_blocks() {
        assert_eq!(difficulty(&[], &MAINNET), DEFAULT_DIFFICULTY);
        assert_eq!(
            difficulty(&steady(1, 30_000, 5 * MIN_DIFFICULTY), &MAINNET),
            DEFAULT_DIFFICULTY
        );
    }

    #[test]
    fn difficulty_stays_when_blocks_keep_the_target_time() {
        let difficulty_value = 3 * DEFAULT_DIFFICULTY;
        assert_eq!(
            difficulty(&steady(60, 30_000, difficulty_value), &MAINNET),
            difficulty_value
        );
    }

    #[test]
    fn difficulty_moves_at_most_five_percent() {
        let base = 2 * DEFAULT_DIFFICULTY;
        // 速すぎれば上げ、遅すぎれば下げるが、直前のブロックの 5% まで
        assert_eq!(
            difficulty(&steady(60, 1_000, base), &MAINNET),
            base * 21 / 20
        );
        assert_eq!(
            difficulty(&steady(60, 600_000, base), &MAINNET),
            base * 19 / 20
        );
        // 少しだけずれていれば、比のとおりに動く
        let slower = difficulty(&steady(60, 31_000, base), &MAINNET);
        assert_eq!(slower, (u128::from(base) * 30_000 / 31_000) as u64);
    }

    #[test]
    fn difficulty_stays_within_the_range() {
        assert_eq!(
            difficulty(&steady(60, 600_000, MIN_DIFFICULTY), &MAINNET),
            MIN_DIFFICULTY
        );
        assert_eq!(
            difficulty(&steady(60, 1_000, MAX_DIFFICULTY), &MAINNET),
            MAX_DIFFICULTY
        );
    }

    #[test]
    fn difficulty_looks_only_at_the_last_max_difficulty_blocks() {
        let mut statistics = steady(100, 30_000, DEFAULT_DIFFICULTY);
        // 61個前より古いものは見ないので、どれだけ外れていても効かない
        statistics[0].difficulty = MAX_DIFFICULTY;
        statistics[39].timestamp = 0;
        assert_eq!(difficulty(&statistics, &MAINNET), DEFAULT_DIFFICULTY);
    }

    /// 2^54 × |ln(v / 2^256)| を浮動小数点で。最初の1から53ビットぶんしか効かない
    fn approximate_hit(hash: &[u8; 32]) -> f64 {
        let leading_zeros = hash
            .iter()
            .position(|&byte| byte != 0)
            .map_or(256, |index| 8 * index as u32 + hash[index].leading_zeros());
        let start = (leading_zeros / 8) as usize;
        let mut mantissa = 0f64;
        for (offset, &byte) in hash[start..].iter().take(8).enumerate() {
            mantissa += f64::from(byte) * 256f64.powi(-(offset as i32) - 1);
        }
        let log2 = mantissa.log2() - 8.0 * start as f64;
        -log2 * std::f64::consts::LN_2 * 2f64.powi(54)
    }

    #[test]
    fn hit_is_close_to_the_logarithm() {
        let mut hash = [0u8; 32];
        for seed in 0..200u32 {
            // 決まった並びで、先頭の0の数も散らす
            for (index, byte) in hash.iter_mut().enumerate() {
                *byte = (seed
                    .wrapping_mul(2_654_435_761)
                    .rotate_left(index as u32 * 7)
                    >> 11) as u8;
            }
            let zeros = (seed % 9) as usize;
            hash[..zeros].fill(0);
            if hash.iter().all(|&byte| byte == 0) {
                continue;
            }
            let expected = approximate_hit(&hash);
            let actual = hit(&GenerationHash(hash)) as f64;
            // catapult によれば、32ビットだけ使うことによるずれは 1ppm 未満
            assert!(
                ((actual - expected) / expected).abs() < 1e-6,
                "{seed}: {actual} と {expected}"
            );
        }
    }

    #[test]
    fn hit_handles_the_edges() {
        assert_eq!(hit(&GenerationHash([0; 32])), u64::MAX);
        assert_eq!(hit(&GenerationHash([0xFF; 32])), 0);
        // 小さいハッシュほど hit は大きい
        let mut small = [0; 32];
        small[..2].copy_from_slice(&[0x01, 0x80]);
        let mut large = [0; 32];
        large[0] = 0x80;
        assert!(hit(&GenerationHash(small)) > hit(&GenerationHash(large)));
        // 最初の1から32ビットが全部1なら、先頭にいくつ0があっても0になる
        let mut ones = [0xFF; 32];
        ones[0] = 0x01;
        assert_eq!(hit(&GenerationHash(ones)), 0);
    }

    #[test]
    fn log2_times_power_of_two_matches_the_logarithm() {
        for value in [1u64, 2, 3, 1_000, 0x8000_0000, 0xFFFF_FFFE, 123_456_789] {
            let expected = (value as f64).log2() * 2f64.powi(20);
            let actual = log2_times_power_of_two(value, 20) as f64;
            assert!(
                (actual - expected).abs() <= 1.0,
                "{value}: {actual} と {expected}"
            );
        }
    }

    #[test]
    fn fixed_point_power_of_two_matches_the_power() {
        for value in (-5 * 65_536..=435_411).step_by(4_099) {
            let expected = 2f64.powf(f64::from(value) / 65_536.0) * 65_536.0;
            let actual = f64::from(fixed_point_power_of_two(value));
            // 近似の多項式のずれと、小さい値での切り捨て
            assert!(
                (actual - expected).abs() <= expected * 1e-4 + 1.0,
                "{value}: {actual} と {expected}"
            );
        }
    }

    #[test]
    fn smoother_is_one_at_the_target_time_and_capped() {
        let one = f64::from(smoother(30, &MAINNET)) / 65_536.0;
        assert!((one - 1.0).abs() < 1e-3, "{one}");
        // 速いほど狭め、遅いほど広げる。遅すぎれば 100 倍で止まる
        assert!(smoother(20, &MAINNET) < smoother(30, &MAINNET));
        assert!(smoother(40, &MAINNET) > smoother(30, &MAINNET));
        assert_eq!(smoother(10_000, &MAINNET), 100 << 16);
        // 0秒でも 2^(-3 × log2(e)) ≈ 0.05 倍で、0にする下限（2^-5）には届かない
        let zero = f64::from(smoother(0, &MAINNET)) / 65_536.0;
        assert!(
            (zero - 2f64.powf(-3.0 * std::f64::consts::LOG2_E)).abs() < 1e-3,
            "{zero}"
        );
    }

    #[test]
    fn target_scales_with_time_and_importance() {
        let importance = MAINNET.total_chain_importance / 1000;
        let at = |seconds| {
            let bytes = target(seconds, DEFAULT_DIFFICULTY, importance, &MAINNET).to_be_bytes();
            u128::from_be_bytes(bytes[16..].try_into().unwrap())
        };
        // 目標の間隔なら、およそ 経過秒 × Importance × 2^64 × 8,999,999,998 / (合計 × 難易度)
        let expected = 30.0 * importance as f64 * 2f64.powi(64) * 8_999_999_998.0
            / (MAINNET.total_chain_importance as f64 * DEFAULT_DIFFICULTY as f64);
        let actual = at(30) as f64;
        assert!(
            ((actual - expected) / expected).abs() < 1e-3,
            "{actual} と {expected}"
        );
        assert!(at(31) > at(30));
        assert_eq!(target(30, DEFAULT_DIFFICULTY, 0, &MAINNET), U256::default());
    }

    #[test]
    fn u256_multiplies_divides_and_shifts() {
        let value = U256::from(u64::MAX).mul_u64(u64::MAX).shl(48).mul_u64(3);
        assert_eq!(
            value.div_u64(3).div_u64(u64::MAX),
            U256::from(u64::MAX).shl(48)
        );
        let bytes = U256::from(1).shl(63).mul_u64(4).to_be_bytes();
        assert_eq!(bytes[23], 2);
        assert!(U256::from(1).shl(1).greater_than_u64(1));
        assert!(!U256::from(5).greater_than_u64(5));
    }
}
