//! DKG の参加者。掲示板（[`Board`]）を読み、今の段階で自分が載せるものを作る。
//!
//! 暗号の計算は frost-core の `keys::dkg`（`part1`、`part2`、`part3`）に任せる。ここで足すのは、
//! 分け前の暗号化と、苦情を言うか、明かすかの判断だけ。
//!
//! 試すために、わざと不正をする参加者も作れる（[`Behavior`]）。

use std::collections::{BTreeMap, BTreeSet};

use frost_core::keys::dkg::{self, round1, round2};
use frost_core::keys::{KeyPackage, SecretShare, SigningShare};
use heika_core::key::{PrivateKey, PublicKey};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as ExchangeKey, StaticSecret};

use crate::board::{Board, Outcome, Phase};
use crate::wire::{self, Body, E, Post, SEALED, Session};

/// 参加者のふるまい
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behavior {
    Honest,
    /// 何も載せない
    Silent,
    /// `to` に、コミットメントと合わない分け前を配る。苦情を受けたら、`reveal` なら正しい分け前を明かす
    BadShare {
        to: u16,
        reveal: bool,
    },
    /// 正しい分け前をもらっても、`against` に苦情を言う
    FalseComplaint {
        against: u16,
    },
}

/// 1 回の試みのあいだだけ持つもの
struct Round {
    attempt: u16,
    /// 自分宛ての分け前を暗号化してもらう鍵。試みごとに作り直す
    exchange: StaticSecret,
    round1: Option<round1::SecretPackage<E>>,
    round2: Option<round2::SecretPackage<E>>,
    /// ほかの人に配った分け前（苦情を受けたら明かす）
    outgoing: BTreeMap<u16, SigningShare<E>>,
    /// 自分宛ての分け前で、コミットメントと合ったもの
    received: BTreeMap<u16, SigningShare<E>>,
    /// もう載せた段階
    posted: BTreeSet<Phase>,
}

pub struct Member {
    pub index: u16,
    key: PrivateKey,
    behavior: Behavior,
    round: Option<Round>,
    key_package: Option<KeyPackage<E>>,
}

impl Member {
    pub fn new(index: u16, key: PrivateKey, behavior: Behavior) -> Self {
        Self {
            index,
            key,
            behavior,
            round: None,
            key_package: None,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_private_key(&self.key)
    }

    pub fn behavior(&self) -> Behavior {
        self.behavior
    }

    /// できた自分の鍵の分け前
    pub fn key_package(&self) -> Option<&KeyPackage<E>> {
        self.key_package.as_ref()
    }

    /// 掲示板をファイナライズされたところまで読んだところで（[`Board::settle`] したあとで）、
    /// 今の段階で載せるものを作る。鍵ができていれば、自分の分け前を計算する
    pub fn act<R: RngCore + CryptoRng>(
        &mut self,
        board: &Board,
        rng: &mut R,
    ) -> Result<Vec<Vec<u8>>, String> {
        let (Some(session), Some(attempt)) = (board.session(), board.attempt()) else {
            return Ok(Vec::new());
        };
        if !attempt.active.contains(&self.index) {
            return Ok(Vec::new());
        }
        if self
            .round
            .as_ref()
            .is_none_or(|round| round.attempt != attempt.number)
        {
            self.round = Some(Round {
                attempt: attempt.number,
                exchange: StaticSecret::random_from_rng(&mut *rng),
                round1: None,
                round2: None,
                outgoing: BTreeMap::new(),
                received: BTreeMap::new(),
                posted: BTreeSet::new(),
            });
        }
        match board.outcome() {
            Outcome::Done(_) if self.key_package.is_none() => {
                self.finish(board)?;
                return Ok(Vec::new());
            }
            Outcome::Running => {}
            _ => return Ok(Vec::new()),
        }
        let Some(phase) = attempt.phase() else {
            return Ok(Vec::new());
        };
        let me = self.index;
        let round = self.round.as_mut().expect("set above");
        if !round.posted.insert(phase) {
            return Ok(Vec::new());
        }
        let bodies = match phase {
            Phase::Commit => {
                if self.behavior == Behavior::Silent {
                    return Ok(Vec::new());
                }
                let (secret, package) = dkg::part1(
                    Session::identifier(me),
                    attempt.active.len() as u16,
                    session.threshold,
                    &mut *rng,
                )
                .map_err(|error| error.to_string())?;
                round.round1 = Some(secret);
                vec![Body::Commit {
                    commitment: package.commitment().clone(),
                    proof: Box::new(*package.proof_of_knowledge()),
                    exchange: ExchangeKey::from(&round.exchange).to_bytes(),
                }]
            }
            Phase::Shares => {
                let Some(secret) = round.round1.take() else {
                    return Ok(Vec::new());
                };
                let (secret, packages) = dkg::part2(secret, &attempt.round1_packages(me))
                    .map_err(|error| error.to_string())?;
                round.round2 = Some(secret);
                let mut shares = Vec::new();
                for other in attempt.active.iter().copied().filter(|other| *other != me) {
                    let share = *packages[&Session::identifier(other)].signing_share();
                    round.outgoing.insert(other, share);
                    let sent = match self.behavior {
                        Behavior::BadShare { to, .. } if to == other => {
                            SigningShare::deserialize(&[1; 32]).expect("a canonical scalar")
                        }
                        _ => share,
                    };
                    let (_, theirs) = attempt.commits.get(&other).ok_or("約束がありません")?;
                    // 宛先の鍵が壊れていたら、中身のないものを送る。宛先が苦情を言えば、明かすことになる
                    let sealed = wire::seal(
                        board.id(),
                        attempt.number,
                        (me, other),
                        &round.exchange,
                        theirs,
                        &sent,
                    )
                    .unwrap_or([0; SEALED]);
                    shares.push(sealed);
                }
                vec![Body::Shares(shares)]
            }
            Phase::Complain => {
                let mut against = Vec::new();
                for dealer in attempt
                    .active
                    .iter()
                    .copied()
                    .filter(|dealer| *dealer != me)
                {
                    let (package, theirs) =
                        attempt.commits.get(&dealer).ok_or("約束がありません")?;
                    let share = attempt
                        .sealed(dealer, me)
                        .and_then(|sealed| {
                            wire::open(
                                board.id(),
                                attempt.number,
                                (dealer, me),
                                &round.exchange,
                                theirs,
                                sealed,
                            )
                        })
                        .filter(|share| {
                            SecretShare::new(
                                Session::identifier(me),
                                *share,
                                package.commitment().clone(),
                            )
                            .verify()
                            .is_ok()
                        });
                    match share {
                        Some(share) => {
                            round.received.insert(dealer, share);
                            if self.behavior == (Behavior::FalseComplaint { against: dealer }) {
                                against.push(dealer);
                            }
                        }
                        None => against.push(dealer),
                    }
                }
                // 苦情がなくても、苦情なし（空）を載せる。全員が載せれば、締め切りを待たずに進める
                vec![Body::Complain(against)]
            }
            Phase::Reveal => {
                if let Behavior::BadShare { reveal: false, .. } = self.behavior {
                    return Ok(Vec::new());
                }
                attempt
                    .complaints
                    .iter()
                    .filter(|(_, against)| against.contains(&me))
                    .filter_map(|(to, _)| {
                        Some(Body::Reveal {
                            to: *to,
                            share: *round.outgoing.get(to)?,
                        })
                    })
                    .collect()
            }
        };
        Ok(bodies
            .into_iter()
            .map(|body| {
                Post {
                    attempt: attempt.number,
                    member: me,
                    body,
                }
                .sign(board.id(), &self.key)
            })
            .collect())
    }

    /// 鍵ができた試みの約束と、自分宛ての分け前（もらったものか、明かされたもの）を足して、自分の鍵の分け前を作る
    fn finish(&mut self, board: &Board) -> Result<(), String> {
        let (Some(attempt), Outcome::Done(public)) = (board.attempt(), board.outcome()) else {
            return Ok(());
        };
        let me = self.index;
        let round = self
            .round
            .as_ref()
            .filter(|round| round.attempt == attempt.number)
            .ok_or("鍵ができた試みに加わっていません")?;
        let secret = round
            .round2
            .as_ref()
            .ok_or("鍵ができた試みで配っていません")?;
        let mut packages = BTreeMap::new();
        for dealer in attempt
            .active
            .iter()
            .copied()
            .filter(|dealer| *dealer != me)
        {
            let share = round
                .received
                .get(&dealer)
                .or_else(|| attempt.reveals.get(&(dealer, me)))
                .ok_or_else(|| format!("{dealer} からの分け前がありません"))?;
            packages.insert(Session::identifier(dealer), round2::Package::new(*share));
        }
        let (key_package, public_package) =
            dkg::part3(secret, &attempt.round1_packages(me), &packages)
                .map_err(|error| error.to_string())?;
        if public_package.verifying_key() != public.verifying_key() {
            return Err("掲示板から計算したグループ鍵と合いません".to_owned());
        }
        self.key_package = Some(key_package);
        Ok(())
    }
}
