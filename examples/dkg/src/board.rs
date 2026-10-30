//! 掲示板を読んで、DKG がどこまで進んだかを決める。
//!
//! 読むのはファイナライズされたブロックだけなので、同じ掲示板を読めば、誰が読んでも同じ結論になる。
//! 参加者でなくても、セッションの ID さえ知っていれば、グループ鍵まで計算できる。
//!
//! 1 回の試みは 4 つの段階に分かれる。段階は、その試みの参加者が全員載せたブロックで閉じる。
//! 載せない人がいれば、段階が始まってから [`Session::window`] ブロック目（締め切り）で閉じる。
//!
//! 1. 約束する：締め切りまでに約束しなかった人は外す
//! 2. 配る：締め切りまでに全員に配らなかった人は外す
//! 3. 苦情を言う：苦情がなくても、「苦情なし」を載せる（全員載せたら早く閉じられるように）。
//!    締め切りまでに苦情がなければ、ここで鍵ができる。苦情を載せなかった人は、苦情なしとみなす
//!    しきい値以上の人から苦情を受けた配り手は、明かさせずに外す
//! 4. 明かす：苦情を受けて、正しい分け前を明かさなかった配り手は外す。明かせば、苦情を言った人はそれを使う
//!
//! 誰かを外したら、残った人で最初からやり直す（次の試み）。正直な参加者は外されないので、やり直すのは、
//! 不正をした人の数までで済む。残りがしきい値より少なくなったら、失敗する。
//!
//! 同じ人が同じ段階に何度載せても、最初の正しいものだけを使う。

use std::collections::{BTreeMap, BTreeSet};

use frost_core::Identifier;
use frost_core::keys::dkg::{self, round1};
use frost_core::keys::{PublicKeyPackage, SecretShare, SigningShare};
use heika_core::key::PublicKey;

use crate::wire::{Body, E, Post, SEALED, Session};

/// 試みの段階。並びの順に進む
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Commit,
    Shares,
    Complain,
    Reveal,
}

const PHASES: [Phase; 4] = [Phase::Commit, Phase::Shares, Phase::Complain, Phase::Reveal];

/// 1 回の試み
#[derive(Clone, Debug)]
pub struct Attempt {
    pub number: u16,
    /// 今の段階が始まった高さ。この次の高さから、締め切りの高さまでに載ったものが入る
    pub opened: u64,
    /// この試みの参加者（並びの位置）
    pub active: Vec<u16>,
    /// 約束と、分け前を暗号化してもらう X25519 の公開鍵
    pub commits: BTreeMap<u16, (round1::Package<E>, [u8; 32])>,
    pub shares: BTreeMap<u16, Vec<[u8; SEALED]>>,
    /// 苦情を言った人ごとの、苦情を受けた配り手
    pub complaints: BTreeMap<u16, BTreeSet<u16>>,
    /// 苦情の段階で、苦情か苦情なしを載せた人
    pub answered: BTreeSet<u16>,
    /// （配り手, 苦情を言った人）ごとの、明かされた分け前。コミットメントと合うものだけ
    pub reveals: BTreeMap<(u16, u16), SigningShare<E>>,
    /// 閉じた段階の数
    closed: usize,
}

impl Attempt {
    fn new(number: u16, opened: u64, active: Vec<u16>) -> Self {
        Self {
            number,
            opened,
            active,
            commits: BTreeMap::new(),
            shares: BTreeMap::new(),
            complaints: BTreeMap::new(),
            answered: BTreeSet::new(),
            reveals: BTreeMap::new(),
            closed: 0,
        }
    }

    /// 今の段階。全部閉じていたら `None`
    pub fn phase(&self) -> Option<Phase> {
        PHASES.get(self.closed).copied()
    }

    /// 今の段階の締め切り。この高さのブロックまでに載ったものが入る
    pub fn deadline(&self, window: u64) -> u64 {
        self.opened + window
    }

    /// 今の段階で、載せるべき人が全員載せたか
    fn complete(&self) -> bool {
        let everyone = |done: &dyn Fn(&u16) -> bool| self.active.iter().all(done);
        match self.phase() {
            Some(Phase::Commit) => everyone(&|member| self.commits.contains_key(member)),
            Some(Phase::Shares) => everyone(&|member| self.shares.contains_key(member)),
            Some(Phase::Complain) => everyone(&|member| self.answered.contains(member)),
            Some(Phase::Reveal) => self.unanswered().is_empty(),
            None => false,
        }
    }

    /// 苦情を受けて、まだ明かしていない配り手
    fn unanswered(&self) -> BTreeSet<u16> {
        self.complaints
            .iter()
            .flat_map(|(to, against)| against.iter().map(move |dealer| (*dealer, *to)))
            .filter(|pair| !self.reveals.contains_key(pair))
            .map(|(dealer, _)| dealer)
            .collect()
    }

    /// `except` 以外の参加者の約束。FROST の `part2`、`part3` に渡す形
    pub fn round1_packages(&self, except: u16) -> BTreeMap<Identifier<E>, round1::Package<E>> {
        self.commits
            .iter()
            .filter(|(member, _)| **member != except)
            .map(|(member, (package, _))| (Session::identifier(*member), package.clone()))
            .collect()
    }

    /// 配り手 `dealer` が、`recipient` 宛てに配った暗号化した分け前
    pub fn sealed(&self, dealer: u16, recipient: u16) -> Option<&[u8; SEALED]> {
        let position = self
            .active
            .iter()
            .filter(|member| **member != dealer)
            .position(|member| *member == recipient)?;
        self.shares.get(&dealer)?.get(position)
    }

    /// 配り手 `dealer` の約束
    pub fn commitment(&self, dealer: u16) -> Option<&round1::Package<E>> {
        self.commits.get(&dealer).map(|(package, _)| package)
    }
}

/// 外した理由
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// 締め切りまでに約束しなかった
    NoCommit,
    /// 締め切りまでに配らなかった
    NoShares,
    /// 苦情を受けて、正しい分け前を明かさなかった
    NoReveal,
    /// しきい値以上の人から苦情を受けた
    TooManyComplaints,
}

/// 掲示板を読んで起きたこと。表示に使う
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Started {
        height: u64,
    },
    Complained {
        attempt: u16,
        member: u16,
        against: BTreeSet<u16>,
    },
    Revealed {
        attempt: u16,
        dealer: u16,
        to: u16,
    },
    Excluded {
        attempt: u16,
        member: u16,
        reason: Reason,
    },
    Retried {
        attempt: u16,
        start: u64,
    },
    Done {
        height: u64,
        key: PublicKey,
    },
    Failed {
        height: u64,
    },
}

#[derive(Clone, Debug)]
pub enum Outcome {
    Running,
    Done(Box<PublicKeyPackage<E>>),
    Failed,
}

/// 1 つのセッションの掲示板
pub struct Board {
    id: [u8; 32],
    session: Option<Session>,
    attempts: Vec<Attempt>,
    outcome: Outcome,
    events: Vec<Event>,
}

impl Board {
    /// セッションの ID だけを知っている状態から読み始める。始めるもの（[`Session`]）は、掲示板から読む
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id,
            session: None,
            attempts: Vec::new(),
            outcome: Outcome::Running,
            events: Vec::new(),
        }
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// 今の試み
    pub fn attempt(&self) -> Option<&Attempt> {
        self.attempts.last()
    }

    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// できたグループ鍵
    pub fn group_key(&self) -> Option<PublicKey> {
        match &self.outcome {
            Outcome::Done(public) => Some(group_key(public)),
            _ => None,
        }
    }

    /// 前に呼んでから起きたこと
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// 高さ `height` のブロックに載ったものを読む。同じブロックの中では、載った順に呼ぶ
    pub fn apply(&mut self, height: u64, bytes: &[u8]) {
        self.settle(height.saturating_sub(1));
        let Some(session) = &self.session else {
            if let Some(session) = Session::decode(bytes).filter(|session| session.id() == self.id)
            {
                let everyone = (0..session.members.len() as u16).collect();
                self.attempts.push(Attempt::new(0, height, everyone));
                self.session = Some(session);
                self.events.push(Event::Started { height });
            }
            return;
        };
        if !matches!(self.outcome, Outcome::Running) {
            return;
        }
        let Some(post) = Post::decode(bytes, session, &self.id) else {
            return;
        };
        let threshold = session.threshold;
        let attempt = self.attempts.last_mut().expect("started");
        let member = post.member;
        if post.attempt != attempt.number || !attempt.active.contains(&member) {
            return;
        }
        match (attempt.phase(), post.body) {
            (
                Some(Phase::Commit),
                Body::Commit {
                    commitment,
                    proof,
                    exchange,
                },
            ) => {
                // 知識の証明で、ほかの人の約束を自分のものとして出せないようにする（rogue key）
                if !attempt.commits.contains_key(&member)
                    && dkg::verify_proof_of_knowledge(
                        Session::identifier(member),
                        &commitment,
                        &proof,
                    )
                    .is_ok()
                {
                    let package = round1::Package::new(commitment, *proof);
                    attempt.commits.insert(member, (package, exchange));
                }
            }
            (Some(Phase::Shares), Body::Shares(shares)) => {
                if shares.len() == attempt.active.len() - 1 {
                    attempt.shares.entry(member).or_insert(shares);
                }
            }
            (Some(Phase::Complain), Body::Complain(against)) => {
                let against: BTreeSet<u16> = against.into_iter().collect();
                let valid = against
                    .iter()
                    .all(|dealer| *dealer != member && attempt.active.contains(dealer));
                if valid && attempt.answered.insert(member) && !against.is_empty() {
                    attempt.complaints.insert(member, against.clone());
                    self.events.push(Event::Complained {
                        attempt: attempt.number,
                        member,
                        against,
                    });
                }
            }
            (Some(Phase::Reveal), Body::Reveal { to, share }) => {
                let complained = attempt
                    .complaints
                    .get(&to)
                    .is_some_and(|against| against.contains(&member));
                let Some(package) = attempt.commitment(member) else {
                    return;
                };
                let matches =
                    SecretShare::new(Session::identifier(to), share, package.commitment().clone())
                        .verify()
                        .is_ok();
                if complained && matches && !attempt.reveals.contains_key(&(member, to)) {
                    attempt.reveals.insert((member, to), share);
                    self.events.push(Event::Revealed {
                        attempt: attempt.number,
                        dealer: member,
                        to,
                    });
                }
            }
            _ => return,
        }
        if attempt.complete() {
            self.close(height, threshold);
        }
    }

    /// 高さ `height` までのブロックを全部読んだところで、締め切りを過ぎた段階を閉じる
    pub fn settle(&mut self, height: u64) {
        let Some(session) = &self.session else {
            return;
        };
        let (window, threshold) = (session.window, session.threshold);
        while matches!(self.outcome, Outcome::Running) {
            let deadline = self.attempts.last().expect("started").deadline(window);
            if height < deadline {
                return;
            }
            self.close(deadline, threshold);
        }
    }

    /// 今の段階を高さ `height` で閉じる。誰かを外すならやり直し、鍵ができるなら仕上げ、そうでなければ次の段階を開く
    fn close(&mut self, height: u64, threshold: u16) {
        let attempt = self.attempts.last_mut().expect("started");
        let Some(phase) = attempt.phase() else {
            return;
        };
        attempt.closed += 1;
        attempt.opened = height;
        let missing = |done: &dyn Fn(u16) -> bool| -> Vec<u16> {
            attempt
                .active
                .iter()
                .copied()
                .filter(|member| !done(*member))
                .collect()
        };
        let (faulty, reason) = match phase {
            Phase::Commit => (
                missing(&|member| attempt.commits.contains_key(&member)),
                Reason::NoCommit,
            ),
            Phase::Shares => (
                missing(&|member| attempt.shares.contains_key(&member)),
                Reason::NoShares,
            ),
            Phase::Complain => {
                // 署名に要る人数（しきい値）以上の苦情を受けた配り手は、明かさせずに外す（GJKR と同じ）。
                // 苦情を言った人の中に必ず正直な人がいるので、配り手が悪い。明かさせると、配り手の秘密が公開されてしまう
                let mut counts = BTreeMap::new();
                for dealer in attempt.complaints.values().flatten() {
                    *counts.entry(*dealer).or_insert(0usize) += 1;
                }
                let accused: Vec<u16> = counts
                    .into_iter()
                    .filter(|(_, count)| *count >= usize::from(threshold))
                    .map(|(dealer, _)| dealer)
                    .collect();
                if accused.is_empty() && !attempt.complaints.is_empty() {
                    return;
                }
                (accused, Reason::TooManyComplaints)
            }
            Phase::Reveal => (attempt.unanswered().into_iter().collect(), Reason::NoReveal),
        };
        if !faulty.is_empty() {
            self.retry(height, faulty, reason, threshold);
        } else if phase >= Phase::Complain {
            self.finish(height);
        }
    }

    /// 今の試みの約束を全部足して、グループ鍵と、参加者それぞれの検証用の公開鍵を作る
    fn finish(&mut self, height: u64) {
        let attempt = self.attempts.last().expect("started");
        let commitments = attempt
            .commits
            .iter()
            .map(|(member, (package, _))| (Session::identifier(*member), package.commitment()))
            .collect();
        match PublicKeyPackage::from_dkg_commitments(&commitments) {
            Ok(public) => {
                self.events.push(Event::Done {
                    height,
                    key: group_key(&public),
                });
                self.outcome = Outcome::Done(Box::new(public));
            }
            Err(_) => {
                self.events.push(Event::Failed { height });
                self.outcome = Outcome::Failed;
            }
        }
    }

    fn retry(&mut self, height: u64, faulty: Vec<u16>, reason: Reason, threshold: u16) {
        let attempt = self.attempts.last().expect("started");
        let number = attempt.number;
        for member in &faulty {
            self.events.push(Event::Excluded {
                attempt: number,
                member: *member,
                reason,
            });
        }
        let active: Vec<u16> = attempt
            .active
            .iter()
            .copied()
            .filter(|member| !faulty.contains(member))
            .collect();
        if active.len() < usize::from(threshold) {
            self.events.push(Event::Failed { height });
            self.outcome = Outcome::Failed;
            return;
        }
        self.attempts.push(Attempt::new(number + 1, height, active));
        self.events.push(Event::Retried {
            attempt: number + 1,
            start: height,
        });
    }
}

/// グループ鍵を、Symbol の公開鍵の形にする
pub fn group_key(public: &PublicKeyPackage<E>) -> PublicKey {
    PublicKey(
        public
            .verifying_key()
            .serialize()
            .expect("a valid key")
            .try_into()
            .expect("32 bytes"),
    )
}
