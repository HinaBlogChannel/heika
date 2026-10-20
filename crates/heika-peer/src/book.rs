//! 住所録。知っているノードのアドレスと、それぞれを今使っているか、続けて失敗した回数、次に試してよい時刻、ban の
//! 期限。しまう記録（[`KnownPeer`]）にもする。アドレスはどこにも出さない。

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// つなぎに行けなかったか、通信に失敗して外したアドレスを、次に試すまで空ける時間の始めと上限。続けて
/// 失敗するたびに倍にする
const RETRY_START: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(3600);
/// 確かめられないものを返したアドレスに、つながない長さ（秒）。住所録にしまって、始め直しても覚えておく
pub const BAN_SECONDS: u64 = 7 * 24 * 60 * 60;

/// 知っているノードのアドレスと、それぞれを今使っているか、次にいつ試してよいか。アドレスはどこにも出さない
pub struct Book {
    entries: Vec<Candidate>,
}

struct Candidate {
    address: String,
    /// つないでいるか、つなぎに行っている
    in_use: bool,
    /// 確かめられないものを返したので、この時刻（UNIX 秒と、この実行での時刻）までつながない
    banned: Option<(u64, Instant)>,
    /// 続けて失敗した回数
    failures: u32,
    /// 最後につながった時刻（UNIX 秒）
    last_success: u64,
    /// 次に試してよい時刻
    ready_at: Instant,
}

impl Book {
    pub fn new(addresses: Vec<String>, now: Instant) -> Self {
        let mut candidates = Self {
            entries: Vec::new(),
        };
        for address in addresses {
            if candidates.find(&address).is_none() {
                candidates.entries.push(Candidate::new(address, now));
            }
        }
        candidates
    }

    /// しまってあった住所録から作る。続けて失敗していたものは、その回数に応じて空けてから試す。`unix`（今の
    /// UNIX 秒）でまだ ban の続いているものは試さない
    pub fn load(known: Vec<(String, KnownPeer)>, now: Instant, unix: u64) -> Self {
        let mut candidates = Self::new(Vec::new(), now);
        for (address, record) in known {
            candidates.insert(address.clone(), now);
            if let Some(candidate) = candidates.find(&address) {
                candidate.last_success = record.last_success;
                candidate.failures = record.failures;
                if record.banned_until > unix {
                    let left = Duration::from_secs(record.banned_until - unix);
                    candidate.banned = Some((record.banned_until, now + left));
                }
                if record.failures > 0 {
                    candidate.ready_at = now + backoff(record.failures);
                }
            }
        }
        candidates
    }

    /// 知らないアドレスなら足して真を返す。もう [`MAX_CANDIDATES`] 件あれば足さない
    pub fn insert(&mut self, address: String, now: Instant) -> bool {
        let new = self.find(&address).is_none() && self.entries.len() < MAX_CANDIDATES;
        if new {
            self.entries.push(Candidate::new(address, now));
        }
        new
    }

    /// しまう住所録。確からしいものから [`MAX_KNOWN`] 件と、ban しているもの（[`MAX_KNOWN`] 件まで）
    pub fn records(&self) -> Vec<(String, KnownPeer)> {
        let now = Instant::now();
        let record = |candidate: &Candidate| {
            (
                candidate.address.clone(),
                KnownPeer {
                    last_success: candidate.last_success,
                    failures: candidate.failures,
                    banned_until: candidate
                        .banned
                        .filter(|_| candidate.is_banned(now))
                        .map_or(0, |(until, _)| until),
                },
            )
        };
        let known: BTreeMap<String, KnownPeer> = self
            .entries
            .iter()
            .filter(|candidate| !candidate.is_banned(now))
            .map(record)
            .collect();
        let mut records: Vec<(String, KnownPeer)> = best(&known, MAX_KNOWN)
            .into_iter()
            .map(|address| {
                let record = known[&address];
                (address, record)
            })
            .collect();
        records.extend(
            self.entries
                .iter()
                .filter(|candidate| candidate.is_banned(now))
                .take(MAX_KNOWN)
                .map(record),
        );
        records
    }

    fn find(&mut self, address: &str) -> Option<&mut Candidate> {
        self.entries
            .iter_mut()
            .find(|candidate| candidate.address == address)
    }

    pub fn insert_in_use(&mut self, address: &str, now: Instant) {
        if self.find(address).is_none() {
            self.entries.push(Candidate::new(address.to_owned(), now));
        }
        if let Some(candidate) = self.find(address) {
            candidate.in_use = true;
        }
    }

    /// 知っているノードの数（ban しているものを除く）
    pub fn known(&self) -> usize {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|candidate| !candidate.is_banned(now))
            .count()
    }

    /// 今試してよいアドレスのうち、続けて失敗した回数が一番少ないものを使用中にして返す。なければ `None`
    pub fn take(&mut self, now: Instant) -> Option<String> {
        let candidate = self
            .entries
            .iter_mut()
            .filter(|candidate| {
                !candidate.in_use && !candidate.is_banned(now) && candidate.ready_at <= now
            })
            .min_by_key(|candidate| {
                (
                    candidate.failures,
                    std::cmp::Reverse(candidate.last_success),
                )
            })?;
        candidate.in_use = true;
        Some(candidate.address.clone())
    }

    /// つながった。`unix` はその時刻（UNIX 秒）
    pub fn connected(&mut self, address: &str, unix: u64) {
        if let Some(candidate) = self.find(address) {
            candidate.failures = 0;
            candidate.last_success = unix;
        }
    }

    /// 罰さずに外した（入れ替えなど）。失敗は数えず、すぐまた試してよい
    pub fn release(&mut self, address: &str) {
        if let Some(candidate) = self.find(address) {
            candidate.in_use = false;
        }
    }

    /// つなぎに行けなかったか、通信に失敗して外した。間を空けてから、また試す
    pub fn failed(&mut self, address: &str, now: Instant) {
        if let Some(candidate) = self.find(address) {
            candidate.in_use = false;
            candidate.failures += 1;
            candidate.ready_at = now + backoff(candidate.failures);
        }
    }

    /// 確かめられないものを返したので外した。今（`now`、UNIX 秒で `unix`）から [`BAN_SECONDS`] は試さない
    pub fn ban(&mut self, address: &str, now: Instant, unix: u64) {
        if let Some(candidate) = self.find(address) {
            candidate.in_use = false;
            candidate.banned = Some((unix + BAN_SECONDS, now + Duration::from_secs(BAN_SECONDS)));
        }
    }
}

/// `failures` 回続けて失敗したアドレスを、次に試すまで空ける時間
fn backoff(failures: u32) -> Duration {
    RETRY_START
        .saturating_mul(2u32.saturating_pow(failures.saturating_sub(1)))
        .min(RETRY_MAX)
}

impl Candidate {
    fn is_banned(&self, now: Instant) -> bool {
        self.banned.is_some_and(|(_, ends)| ends > now)
    }

    fn new(address: String, now: Instant) -> Self {
        Self {
            address,
            in_use: false,
            banned: None,
            failures: 0,
            last_success: 0,
            ready_at: now,
        }
    }
}

/// 始めるときに、住所録の確からしいもの（[`best`]）から並べてつないでみる数
pub const FIRST_TRIES: usize = 16;

/// 住所録のアドレスを、確からしい順（続けて失敗した回数が少なく、最後につながったのが新しい順）に `count` 個
pub fn best(known: &BTreeMap<String, KnownPeer>, count: usize) -> Vec<String> {
    let mut sorted: Vec<(&String, &KnownPeer)> = known.iter().collect();
    sorted.sort_by_key(|(_, record)| (record.failures, std::cmp::Reverse(record.last_success)));
    sorted
        .into_iter()
        .take(count)
        .map(|(address, _)| address.clone())
        .collect()
}

/// 住所録の1件。DB にしまう
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct KnownPeer {
    /// 最後につながった時刻（UNIX 秒）。つながったことがなければ 0
    pub last_success: u64,
    /// 続けて失敗した回数
    pub failures: u32,
    /// この時刻（UNIX 秒）まで、つながない。ban していなければ 0
    pub banned_until: u64,
}

impl KnownPeer {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = self.last_success.to_le_bytes().to_vec();
        bytes.extend_from_slice(&self.failures.to_le_bytes());
        bytes.extend_from_slice(&self.banned_until.to_le_bytes());
        bytes
    }

    /// 読めなければ `None`。ban を足す前の 12 バイトのものも読む
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 12 && bytes.len() != 20 {
            return None;
        }
        Some(Self {
            last_success: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            failures: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            banned_until: match bytes.get(12..) {
                Some(rest) if !rest.is_empty() => u64::from_le_bytes(rest.try_into().ok()?),
                _ => 0,
            },
        })
    }
}

/// しまう住所録の件数の上限。確からしいものから残す
pub const MAX_KNOWN: usize = 1000;

/// メモリに持つ住所録の件数の上限。ピアの一覧で、いくらでも足させないため
pub const MAX_CANDIDATES: usize = 2 * MAX_KNOWN;

/// ピアの一覧1つから住所録に足す数の上限
pub const MAX_LISTED: usize = 256;

/// ホストとポートから、つなぐときのアドレスを作る。IPv6 のアドレスは角括弧で包む
pub fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_wait_longer_after_each_failure_and_never_retry_a_banned_one() {
        let start = Instant::now();
        let mut candidates = Book::new(vec!["a".to_owned(), "b".to_owned()], start);
        candidates.insert_in_use("seed", start);
        assert_eq!(candidates.take(start).as_deref(), Some("a"));
        assert_eq!(candidates.take(start).as_deref(), Some("b"));
        // 使用中のものは、ほかに返さない
        assert_eq!(candidates.take(start), None);
        candidates.failed("a", start);
        candidates.ban("b", start, 1000);
        candidates.failed("seed", start);
        candidates.failed("seed", start);
        assert_eq!(candidates.take(start), None);
        // 1 回失敗した a は 1 分後に、2 回の seed は 2 分後に試してよくなる。b は二度と出てこない
        let later = start + RETRY_START;
        assert_eq!(candidates.take(later).as_deref(), Some("a"));
        assert_eq!(candidates.take(later), None);
        candidates.connected("a", 1);
        candidates.failed("a", later);
        let much_later = later + RETRY_MAX;
        assert_eq!(candidates.take(much_later).as_deref(), Some("a"));
        assert_eq!(candidates.take(much_later).as_deref(), Some("seed"));
        assert_eq!(candidates.take(much_later), None);
    }

    #[test]
    fn known_peers_round_trip_and_keep_the_most_likely_first() {
        let record = KnownPeer {
            last_success: 1_792_270_000,
            failures: 3,
            banned_until: 1_792_870_000,
        };
        assert_eq!(KnownPeer::from_bytes(&record.to_bytes()), Some(record));
        // ban を足す前の 12 バイトも読む
        assert_eq!(
            KnownPeer::from_bytes(&record.to_bytes()[..12]),
            Some(KnownPeer {
                banned_until: 0,
                ..record
            })
        );
        assert_eq!(KnownPeer::from_bytes(&[0; 11]), None);
        assert_eq!(KnownPeer::from_bytes(&[0; 13]), None);
        let start = Instant::now();
        let known = |last_success, failures| KnownPeer {
            last_success,
            failures,
            banned_until: 0,
        };
        let mut candidates = Book::load(
            vec![
                ("old".to_owned(), known(100, 0)),
                ("new".to_owned(), known(200, 0)),
                ("failing".to_owned(), known(300, 2)),
                ("never".to_owned(), known(0, 0)),
            ],
            start,
            1000,
        );
        // 失敗の少ないものから、同じなら最後につながったのが新しいものから試す。失敗していたものは空けてから
        assert_eq!(candidates.take(start).as_deref(), Some("new"));
        assert_eq!(candidates.take(start).as_deref(), Some("old"));
        assert_eq!(candidates.take(start).as_deref(), Some("never"));
        assert_eq!(candidates.take(start), None);
        assert_eq!(
            candidates.take(start + backoff(2)).as_deref(),
            Some("failing")
        );
        candidates.connected("never", 400);
        candidates.ban("old", start, 1000);
        let records = candidates.records();
        let order: Vec<&str> = records
            .iter()
            .map(|(address, _)| address.as_str())
            .collect();
        // ban したものは、期限を付けて最後にしまう
        assert_eq!(order, ["never", "new", "failing", "old"]);
        assert_eq!(records[0].1, known(400, 0));
        assert_eq!(records[3].1.banned_until, 1000 + BAN_SECONDS);
        // しまったものから作り直すと、期限まではつながず、過ぎたらつなぐ
        let take_all = |unix| {
            let mut loaded = Book::load(records.clone(), start, unix);
            std::iter::from_fn(|| loaded.take(start)).collect::<Vec<_>>()
        };
        assert!(!take_all(1000 + BAN_SECONDS - 1).contains(&"old".to_owned()));
        assert!(take_all(1000 + BAN_SECONDS).contains(&"old".to_owned()));
    }

    #[test]
    fn a_ban_ends_while_running_and_the_book_has_a_limit() {
        let start = Instant::now();
        let mut candidates = Book::new(vec!["a".to_owned()], start);
        assert_eq!(candidates.take(start).as_deref(), Some("a"));
        candidates.ban("a", start, 1000);
        let ends = start + Duration::from_secs(BAN_SECONDS);
        assert_eq!(candidates.take(ends - Duration::from_secs(1)), None);
        assert_eq!(candidates.take(ends).as_deref(), Some("a"));
        for index in 0..MAX_CANDIDATES * 2 {
            candidates.insert(format!("n{index}"), start);
        }
        assert_eq!(candidates.entries.len(), MAX_CANDIDATES);
        assert!(!candidates.insert("more".to_owned(), start));
    }

    #[test]
    fn ipv6_hosts_are_bracketed() {
        assert_eq!(endpoint("2001:db8::1", 7900), "[2001:db8::1]:7900");
        assert_eq!(endpoint("[2001:db8::1]", 7900), "[2001:db8::1]:7900");
        assert_eq!(endpoint("node.example", 7900), "node.example:7900");
        assert_eq!(endpoint("192.0.2.1", 7900), "192.0.2.1:7900");
    }

    #[test]
    fn retries_stop_growing_at_the_maximum() {
        let start = Instant::now();
        let mut candidates = Book::new(vec!["a".to_owned()], start);
        for _ in 0..40 {
            assert!(candidates.take(start + RETRY_MAX * 100).is_some());
            candidates.failed("a", start);
        }
        assert_eq!(
            candidates.take(start + RETRY_MAX - Duration::from_secs(1)),
            None
        );
        assert!(candidates.take(start + RETRY_MAX).is_some());
    }
}
