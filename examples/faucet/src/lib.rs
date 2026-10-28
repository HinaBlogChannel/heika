//! 蛇口の決まりごと。設定、PoW のパズル、予算、待ち時間。どれも時刻を引数で受け取り、ネットワークにも触らない。
//!
//! 配りすぎを防ぐのは、PoW ではなく予算と待ち時間で、PoW は人の手間を、配る量の様子に合わせて足すだけ:
//!
//! - **予算**: 一定の長さごとに配れる量。使い切っても、時間がたてば少しずつ戻る（トークンバケット）
//! - **待ち時間**: 同じアドレスと同じ接続元は、一度もらったら決まった長さのあいだもらえない
//! - **PoW**: `Never` は解かせない。`Always` はいつも `maxSeconds` ほどかかるものを、`Adaptive` は予算が半分を
//!   切ってから、減るほど長く解かせる。1 つの大きなパズルではなく小さなパズルをいくつも解かせ、かかる時間を平均に寄せる

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use heika_node::config::{API_VERSION, Metadata};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// パズルの難しさの上限（ビット）。ブラウザで解ける範囲を大きく超えないように
pub const MAX_BITS: u32 = 40;

/// 蛇口の設定ファイル。ノードの設定と同じく、Kubernetes のマニフェストの形で書く
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: Metadata,
    pub spec: FaucetConfig,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self, String> {
        let manifest: Self = serde_norway::from_str(text).map_err(|error| error.to_string())?;
        if manifest.api_version != API_VERSION {
            return Err(format!(
                "apiVersion が {} で、読める {API_VERSION} と違います",
                manifest.api_version
            ));
        }
        if manifest.kind != "Faucet" {
            return Err(format!(
                "kind が {} で、Faucet ではありません",
                manifest.kind
            ));
        }
        manifest.spec.check()?;
        Ok(manifest)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaucetConfig {
    /// ページと API を出す口（`127.0.0.1:8080` など）
    pub listen: String,
    /// 配る XYM を持つアカウントの鍵のファイル
    pub signer: PathBuf,
    /// 1 回に配る量（最小単位）
    pub amount: u64,
    pub budget: BudgetConfig,
    /// 一度もらったアドレスと接続元が、次にもらえるまでの秒数
    pub cooldown_seconds: u64,
    #[serde(default)]
    pub batch: BatchConfig,
    /// 接続元をこのヘッダーの最後の値から取る（前にリバースプロキシを置くとき。`X-Forwarded-For` など）。
    /// 書かなければ、つないできた相手の IP アドレス
    #[serde(default)]
    pub client_address_header: Option<String>,
    #[serde(default)]
    pub pow: PowConfig,
}

impl FaucetConfig {
    fn check(&self) -> Result<(), String> {
        if self.amount == 0 {
            return Err("amount は 1 以上にしてください".into());
        }
        if self.budget.amount < self.amount {
            return Err("budget.amount は amount 以上にしてください".into());
        }
        if self.budget.period_seconds == 0 || self.batch.interval_seconds == 0 {
            return Err(
                "budget.periodSeconds と batch.intervalSeconds は 1 以上にしてください".into(),
            );
        }
        if self.batch.max_transfers == 0 {
            return Err("batch.maxTransfers は 1 以上にしてください".into());
        }
        if !(1..=64).contains(&self.pow.puzzles) {
            return Err("pow.puzzles は 1 から 64 にしてください".into());
        }
        if !(self.pow.max_seconds >= 0.0 && self.pow.max_seconds.is_finite()) {
            return Err("pow.maxSeconds は 0 以上の数にしてください".into());
        }
        if self.pow.reference_hash_rate == 0 {
            return Err("pow.referenceHashRate は 1 以上にしてください".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BudgetConfig {
    /// `periodSeconds` ごとに配れる量（最小単位）
    pub amount: u64,
    pub period_seconds: u64,
}

/// 受け付けたものを、1 つのアグリゲートにまとめて出す
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchConfig {
    /// まとめて出す間隔（秒）
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    /// 1 つのアグリゲートに入れる数の上限。ネットワークの上限（ふつう 100）も超えない
    #[serde(default = "default_max_transfers")]
    pub max_transfers: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_interval(),
            max_transfers: default_max_transfers(),
        }
    }
}

fn default_interval() -> u64 {
    15
}

fn default_max_transfers() -> usize {
    100
}

/// PoW をどうするか。Kubernetes の `imagePullPolicy` のように書く
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum Policy {
    Never,
    Adaptive,
    Always,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PowConfig {
    #[serde(default = "default_policy")]
    pub policy: Policy,
    /// 基準の端末で、いちばん重いときにかかる秒数のめやす
    #[serde(default = "default_max_seconds")]
    pub max_seconds: f64,
    /// 基準の端末が 1 秒に計算できるハッシュの数。ページは解き終わると、その端末の数を出す
    #[serde(default = "default_reference_hash_rate")]
    pub reference_hash_rate: u64,
    /// 小さなパズルをいくつ解かせるか
    #[serde(default = "default_puzzles")]
    pub puzzles: u32,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            policy: default_policy(),
            max_seconds: default_max_seconds(),
            reference_hash_rate: default_reference_hash_rate(),
            puzzles: default_puzzles(),
        }
    }
}

fn default_policy() -> Policy {
    Policy::Adaptive
}

fn default_max_seconds() -> f64 {
    30.0
}

fn default_reference_hash_rate() -> u64 {
    500_000
}

fn default_puzzles() -> u32 {
    8
}

/// 解かせるパズル。`count` 個のどれも、ハッシュの頭の `bits` ビットが 0 になる数を探す
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Puzzle {
    pub bits: u32,
    pub count: u32,
}

impl Puzzle {
    /// 予算の残りの割合（0 から 1）から、解かせるパズルを決める
    pub fn for_budget(pow: &PowConfig, remaining: f64) -> Self {
        let seconds = match pow.policy {
            Policy::Never => 0.0,
            Policy::Always => pow.max_seconds,
            Policy::Adaptive => pow.max_seconds * ((0.5 - remaining) / 0.5).clamp(0.0, 1.0),
        };
        // 頭の b ビットが 0 になるまでに、平均 2^b 回ハッシュを計算する
        let per_puzzle = seconds * pow.reference_hash_rate as f64 / f64::from(pow.puzzles);
        let bits = if per_puzzle < 2.0 {
            0
        } else {
            (per_puzzle.log2().round() as u32).min(MAX_BITS)
        };
        Self {
            bits,
            count: pow.puzzles,
        }
    }

    /// 基準の端末でかかる秒数のめやす
    pub fn expected_seconds(&self, reference_hash_rate: u64) -> f64 {
        if self.bits == 0 {
            return 0.0;
        }
        f64::from(self.count) * 2f64.powi(self.bits as i32) / reference_hash_rate as f64
    }

    /// `index` 番目のパズルの答えが `counter` で合っているか。ハッシュするのは `{id}:{index}:{counter}`
    /// （10 進）の SHA-256。ページの JS も同じものを計算する
    pub fn solved(&self, id: &str, index: u32, counter: u64) -> bool {
        let hash = Sha256::digest(format!("{id}:{index}:{counter}"));
        leading_zero_bits(&hash) >= self.bits
    }
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &byte in bytes {
        bits += byte.leading_zeros();
        if byte != 0 {
            break;
        }
    }
    bits
}

/// 配れる量。`period` で `capacity` ぶん戻り、`capacity` より多くはたまらない
pub struct Budget {
    capacity: u64,
    period: Duration,
    tokens: f64,
    at: Instant,
}

impl Budget {
    /// 満タンで始める
    pub fn new(config: &BudgetConfig, now: Instant) -> Self {
        Self {
            capacity: config.amount,
            period: Duration::from_secs(config.period_seconds),
            tokens: config.amount as f64,
            at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + self.capacity as f64 * elapsed / self.period.as_secs_f64())
            .min(self.capacity as f64);
        self.at = now;
    }

    /// 残りの割合（0 から 1）
    pub fn remaining(&mut self, now: Instant) -> f64 {
        self.refill(now);
        self.tokens / self.capacity as f64
    }

    /// `amount` を使う。足りなければ、たまるまでの長さを返す
    pub fn take(&mut self, amount: u64, now: Instant) -> Result<(), Duration> {
        self.refill(now);
        let lacking = amount as f64 - self.tokens;
        if lacking > 0.0 {
            return Err(self.period.mul_f64(lacking / self.capacity as f64));
        }
        self.tokens -= amount as f64;
        Ok(())
    }

    /// 出せなかった分を戻す
    pub fn give_back(&mut self, amount: u64) {
        self.tokens = (self.tokens + amount as f64).min(self.capacity as f64);
    }
}

/// 一度もらったものが、次にもらえるまでの待ち時間。アドレスと接続元を、同じ表に入れる
pub struct Cooldown {
    length: Duration,
    last: HashMap<String, Instant>,
}

impl Cooldown {
    pub fn new(length: Duration) -> Self {
        Self {
            length,
            last: HashMap::new(),
        }
    }

    /// まだ待つなら、残りの長さ
    pub fn waiting(&self, key: &str, now: Instant) -> Option<Duration> {
        let until = *self.last.get(key)? + self.length;
        until
            .checked_duration_since(now)
            .filter(|left| !left.is_zero())
    }

    pub fn record(&mut self, key: String, now: Instant) {
        // 待ち終わったものは、表が育ちすぎないように消す
        if self.last.len() >= 4096 {
            let length = self.length;
            self.last
                .retain(|_, at| now.saturating_duration_since(*at) < length);
        }
        self.last.insert(key, now);
    }

    /// 出せなかったときに、待ちを取り消す
    pub fn forget(&mut self, key: &str) {
        self.last.remove(key);
    }
}

/// 16 進の乱数。パズルの ID にする
pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS の乱数が使える");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 待ち時間を、人が読む長さにする
pub fn human(duration: Duration) -> String {
    let seconds = duration.as_secs().max(1);
    match seconds {
        0..60 => format!("{seconds} 秒"),
        60..3600 => format!("{} 分", seconds.div_ceil(60)),
        _ => format!("{} 時間", seconds.div_ceil(3600)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "apiVersion: heika.hinablogchannel.github.io/v1alpha1
kind: Faucet
spec:
  listen: 127.0.0.1:8080
  signer: faucet.key
  amount: 100000000
  budget:
    amount: 10000000000
    periodSeconds: 3600
  cooldownSeconds: 86400
";

    fn pow(policy: Policy) -> PowConfig {
        PowConfig {
            policy,
            max_seconds: 30.0,
            reference_hash_rate: 1 << 20,
            puzzles: 8,
        }
    }

    #[test]
    fn reads_a_minimal_manifest_with_defaults() {
        let manifest = Manifest::parse(MINIMAL).unwrap();
        assert_eq!(manifest.spec.pow.policy, Policy::Adaptive);
        assert_eq!(manifest.spec.pow.puzzles, 8);
        assert_eq!(manifest.spec.batch.interval_seconds, 15);
        assert!(manifest.spec.client_address_header.is_none());
    }

    #[test]
    fn rejects_wrong_kinds_unknown_keys_and_lowercase_policies() {
        assert!(Manifest::parse(&MINIMAL.replace("kind: Faucet", "kind: Peer")).is_err());
        assert!(Manifest::parse(&format!("{MINIMAL}  typo: 1\n")).is_err());
        assert!(Manifest::parse(&format!("{MINIMAL}  pow:\n    policy: always\n")).is_err());
        assert!(Manifest::parse(&format!("{MINIMAL}  pow:\n    policy: Always\n")).is_ok());
        assert!(Manifest::parse(&MINIMAL.replace("amount: 10000000000", "amount: 1")).is_err());
    }

    #[test]
    fn never_asks_for_no_work() {
        let puzzle = Puzzle::for_budget(&pow(Policy::Never), 0.0);
        assert_eq!(puzzle.bits, 0);
        assert_eq!(puzzle.expected_seconds(1 << 20), 0.0);
        assert!(puzzle.solved("id", 0, 0));
    }

    #[test]
    fn always_asks_for_about_max_seconds() {
        // 30 秒 × 2^20 回/秒 ÷ 8 個 ≈ 2^22 回 → 22 ビットで、8 × 2^22 ÷ 2^20 = 32 秒
        let puzzle = Puzzle::for_budget(&pow(Policy::Always), 1.0);
        assert_eq!(puzzle, Puzzle { bits: 22, count: 8 });
        assert_eq!(puzzle.expected_seconds(1 << 20), 32.0);
    }

    #[test]
    fn adaptive_starts_below_half_and_grows_as_the_budget_drains() {
        let config = pow(Policy::Adaptive);
        assert_eq!(Puzzle::for_budget(&config, 1.0).bits, 0);
        assert_eq!(Puzzle::for_budget(&config, 0.5).bits, 0);
        let quarter = Puzzle::for_budget(&config, 0.25).bits;
        let empty = Puzzle::for_budget(&config, 0.0).bits;
        assert!(0 < quarter && quarter < empty);
        assert_eq!(empty, Puzzle::for_budget(&pow(Policy::Always), 1.0).bits);
    }

    #[test]
    fn bits_are_capped() {
        let mut config = pow(Policy::Always);
        config.max_seconds = 1e12;
        assert_eq!(Puzzle::for_budget(&config, 1.0).bits, MAX_BITS);
    }

    #[test]
    fn checks_answers_against_sha256_of_the_text() {
        // ページの JS で `abc` の 12 ビットを解くと 1179、10941、2412 になった
        let puzzle = Puzzle { bits: 12, count: 3 };
        for (index, counter) in [1179, 10941, 2412].into_iter().enumerate() {
            assert!(puzzle.solved("abc", index as u32, counter));
            assert!(!puzzle.solved("abc", index as u32, counter - 1));
        }
        let puzzle = Puzzle { bits: 1, count: 1 };
        let found = (0..)
            .find(|&counter| puzzle.solved("abc", 0, counter))
            .unwrap();
        assert!(Sha256::digest(format!("abc:0:{found}"))[0] < 0x80);
    }

    #[test]
    fn counts_leading_zero_bits_across_bytes() {
        assert_eq!(leading_zero_bits(&[0x80]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x10]), 11);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn budget_refills_over_the_period() {
        let start = Instant::now();
        let config = BudgetConfig {
            amount: 100,
            period_seconds: 100,
        };
        let mut budget = Budget::new(&config, start);
        assert_eq!(budget.take(60, start), Ok(()));
        assert_eq!(budget.take(60, start), Err(Duration::from_secs(20)));
        assert_eq!(budget.remaining(start), 0.4);
        let later = start + Duration::from_secs(20);
        assert_eq!(budget.take(60, later), Ok(()));
        assert_eq!(budget.remaining(later + Duration::from_secs(1000)), 1.0);
        budget.give_back(1000);
        assert_eq!(budget.remaining(later + Duration::from_secs(1000)), 1.0);
    }

    #[test]
    fn cooldown_ends_and_can_be_forgotten() {
        let start = Instant::now();
        let mut cooldown = Cooldown::new(Duration::from_secs(60));
        assert_eq!(cooldown.waiting("a", start), None);
        cooldown.record("a".into(), start);
        assert_eq!(
            cooldown.waiting("a", start + Duration::from_secs(10)),
            Some(Duration::from_secs(50))
        );
        assert_eq!(cooldown.waiting("a", start + Duration::from_secs(60)), None);
        cooldown.forget("a");
        assert_eq!(cooldown.waiting("a", start), None);
    }

    #[test]
    fn says_lengths_in_rounded_up_units() {
        assert_eq!(human(Duration::from_secs(0)), "1 秒");
        assert_eq!(human(Duration::from_secs(61)), "2 分");
        assert_eq!(human(Duration::from_secs(86400)), "24 時間");
    }
}
