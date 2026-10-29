//! ROAST（Ruffing ほか, 2022）で FROST の署名を作る。[examples/roast](../../roast) のまとめ役を、曲線を選べるようにしたもの。
//!
//! 見張り役は、Symbol の側では Ed25519（SHA-512）、EVM の側では secp256k1（SHA-256）の鍵を分けて持つ。
//! どちらも同じまとめ役で署名する。

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use frost_core::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_core::round2::SignatureShare;
use frost_core::{Ciphersuite, Error, Identifier, Signature, SigningPackage};
use rand_core::{CryptoRng, RngCore};

/// 1 人分の分け前の束。重みの数だけある
pub type Commitments<C> = BTreeMap<Identifier<C>, SigningCommitments<C>>;
pub type Shares<C> = BTreeMap<Identifier<C>, SignatureShare<C>>;

/// ディーラーが鍵を作り、`weights` の重みの数だけ分け前を配る。分け前を `threshold` 個集めれば署名できる。
/// ディーラーは配る前の一瞬だけ鍵の全体を持ち、1 人で署名できる。配ったら忘れる（この関数を出たら残らない）
#[allow(clippy::type_complexity)]
pub fn deal<C: Ciphersuite, R: RngCore + CryptoRng>(
    weights: &[u16],
    threshold: u16,
    rng: &mut R,
) -> Result<(Vec<Vec<SecretShare<C>>>, PublicKeyPackage<C>), Error<C>> {
    let total: u16 = weights.iter().sum();
    let (mut shares, public) = frost_core::keys::generate_with_dealer(
        total,
        threshold,
        frost_core::keys::IdentifierList::Default,
        rng,
    )?;
    let mut next = 1u16;
    let people = weights
        .iter()
        .map(|&weight| {
            (0..weight)
                .map(|_| {
                    let id = Identifier::try_from(next).expect("1 から数える");
                    next += 1;
                    shares.remove(&id).expect("配った数だけある")
                })
                .collect()
        })
        .collect();
    Ok((people, public))
}

/// 配られた分け前を確かめて、署名に使える形にする。ディーラーが変なものを配っていれば弾く
pub fn receive<C: Ciphersuite>(
    shares: Vec<SecretShare<C>>,
) -> Result<Vec<KeyPackage<C>>, Error<C>> {
    shares.into_iter().map(KeyPackage::try_from).collect()
}

/// 1 人の署名者。分け前と、出したコミットメントの対になるノンスを持つ。ノンスは 1 度使ったら捨てる
/// （同じノンスで 2 つの違うものに署名すると、分け前がばれる）
pub struct Holder<C: Ciphersuite> {
    keys: Vec<KeyPackage<C>>,
    nonces: BTreeMap<Identifier<C>, SigningNonces<C>>,
}

impl<C: Ciphersuite> Holder<C> {
    pub fn new(keys: Vec<KeyPackage<C>>) -> Self {
        Self {
            keys,
            nonces: BTreeMap::new(),
        }
    }

    /// 次の署名に使うノンスを作り、そのコミットメントを返す
    pub fn commit<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Commitments<C> {
        self.keys
            .iter()
            .map(|key| {
                let (nonce, commitment) = frost_core::round1::commit(key.signing_share(), rng);
                self.nonces.insert(*key.identifier(), nonce);
                (*key.identifier(), commitment)
            })
            .collect()
    }

    /// `package` に、持っている分け前の全部で署名する。使ったノンスは捨てる
    pub fn sign(&mut self, package: &SigningPackage<C>) -> Result<Shares<C>, Error<C>> {
        let nonces = std::mem::take(&mut self.nonces);
        self.keys
            .iter()
            .map(|key| {
                let nonce = nonces
                    .get(key.identifier())
                    .ok_or(Error::MissingCommitment)?;
                Ok((
                    *key.identifier(),
                    frost_core::round2::sign(package, nonce, key)?,
                ))
            })
            .collect()
    }
}

/// `package` の組で出した分け前が、どれも正しいか
pub fn verify_shares<C: Ciphersuite>(
    package: &SigningPackage<C>,
    public: &PublicKeyPackage<C>,
    shares: &Shares<C>,
) -> bool {
    shares.iter().all(|(id, share)| {
        public.verifying_shares().get(id).is_some_and(|verifying| {
            frost_core::verify_signature_share(
                *id,
                verifying,
                share,
                package,
                public.verifying_key(),
            )
            .is_ok()
        })
    })
}

/// 人から届いた返事
pub enum Reply<C: Ciphersuite> {
    /// 最初の返事。次の署名に使うコミットメント
    Ready(Commitments<C>),
    /// `session` の組の分け前（確かめて正しかったもの）と、次の署名に使うコミットメント
    Signed {
        session: usize,
        shares: Shares<C>,
        commitments: Commitments<C>,
    },
    /// `session` の組で、正しくない分け前を返してきた
    Invalid { session: usize },
}

/// まとめ役が決めたこと
#[derive(Debug)]
pub enum Event<C: Ciphersuite> {
    /// 組を作った。`members` に `package` を送って、分け前を頼む
    Started {
        session: usize,
        members: Vec<usize>,
        package: Arc<SigningPackage<C>>,
    },
    /// 嘘をついた人を外した
    Excluded { person: usize },
    /// 署名ができた
    Signed {
        session: usize,
        signature: Signature<C>,
    },
}

/// 署名できる人が足りなくなった
#[derive(Debug, PartialEq, Eq)]
pub struct NotEnough;

struct Person<C: Ciphersuite> {
    weight: u16,
    /// 次の組に使うコミットメント。組に入れたら空にする
    latest: Option<Commitments<C>>,
    /// 入っている組
    session: Option<usize>,
    excluded: bool,
}

struct Session<C: Ciphersuite> {
    package: Arc<SigningPackage<C>>,
    shares: Shares<C>,
    waiting: usize,
}

/// ROAST のまとめ役。返事をくれた人を待ち合わせに並べ、重みが閾値に届いたらすぐ組にする。
/// 組の誰かが黙っていても、その組を待たずに、返事をくれた人で次の組を作る。1 人が同時に入る組は 1 つだけで、
/// 嘘をついた人は二度と組に入れない。正直な人の重みが閾値以上なら、必ずどこかの組で署名ができる
pub struct Roast<C: Ciphersuite> {
    message: Vec<u8>,
    public: Arc<PublicKeyPackage<C>>,
    threshold: u16,
    people: Vec<Person<C>>,
    /// 待ち合わせにいる人
    ready: Vec<usize>,
    sessions: Vec<Session<C>>,
}

impl<C: Ciphersuite> Roast<C> {
    pub fn new(
        message: Vec<u8>,
        public: Arc<PublicKeyPackage<C>>,
        weights: &[u16],
        threshold: u16,
    ) -> Self {
        Self {
            message,
            public,
            threshold,
            people: weights
                .iter()
                .map(|&weight| Person {
                    weight,
                    latest: None,
                    session: None,
                    excluded: false,
                })
                .collect(),
            ready: Vec::new(),
            sessions: Vec::new(),
        }
    }

    /// 返事を受け取って、次にすることを返す
    pub fn receive(&mut self, person: usize, reply: Reply<C>) -> Result<Vec<Event<C>>, NotEnough> {
        if self.people[person].excluded {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        let commitments = match reply {
            Reply::Ready(commitments) => commitments,
            Reply::Invalid { session } => {
                if self.people[person].session != Some(session) {
                    return Ok(events);
                }
                self.people[person].excluded = true;
                self.people[person].session = None;
                events.push(Event::Excluded { person });
                let honest: u16 = self
                    .people
                    .iter()
                    .filter(|person| !person.excluded)
                    .map(|person| person.weight)
                    .sum();
                if honest < self.threshold {
                    return Err(NotEnough);
                }
                return Ok(events);
            }
            Reply::Signed {
                session,
                shares,
                commitments,
            } => {
                if self.people[person].session != Some(session) {
                    return Ok(events);
                }
                let entry = &mut self.sessions[session];
                entry.shares.extend(shares);
                entry.waiting -= 1;
                if entry.waiting == 0 {
                    // どの分け前も確かめてあるので、まとめれば正しい署名になる
                    if let Ok(signature) =
                        frost_core::aggregate(&entry.package, &entry.shares, &self.public)
                    {
                        events.push(Event::Signed { session, signature });
                    }
                }
                commitments
            }
        };
        let entry = &mut self.people[person];
        entry.session = None;
        entry.latest = Some(commitments);
        self.ready.push(person);
        let weight: u16 = self
            .ready
            .iter()
            .map(|&person| self.people[person].weight)
            .sum();
        if weight >= self.threshold {
            events.push(self.start());
        }
        Ok(events)
    }

    fn start(&mut self) -> Event<C> {
        let session = self.sessions.len();
        let members = std::mem::take(&mut self.ready);
        let mut commitments = Commitments::new();
        for &person in &members {
            let entry = &mut self.people[person];
            commitments.extend(entry.latest.take().expect("待ち合わせにいる人は持っている"));
            entry.session = Some(session);
        }
        let package = Arc::new(SigningPackage::new(commitments, &self.message));
        self.sessions.push(Session {
            package: package.clone(),
            shares: Shares::new(),
            waiting: members.len(),
        });
        Event::Started {
            session,
            members,
            package,
        }
    }
}

/// 見張り役の全員（このプロセスの中にいる）で、`message` に署名する。返事は届いた順に処理する。
/// `sign` は、`person` が頼まれた組に分け前を出すかどうか。`None` を返すと、その人は黙る
pub fn sign_together<C: Ciphersuite, R: RngCore + CryptoRng>(
    holders: &mut [Holder<C>],
    public: &Arc<PublicKeyPackage<C>>,
    weights: &[u16],
    threshold: u16,
    message: &[u8],
    rng: &mut R,
    mut sign: impl FnMut(usize, &mut Holder<C>, &SigningPackage<C>) -> Option<Shares<C>>,
) -> Result<Signature<C>, NotEnough> {
    let mut roast = Roast::new(message.to_vec(), public.clone(), weights, threshold);
    let mut inbox: VecDeque<(usize, Reply<C>)> = holders
        .iter_mut()
        .enumerate()
        .map(|(person, holder)| (person, Reply::Ready(holder.commit(rng))))
        .collect();
    while let Some((person, reply)) = inbox.pop_front() {
        for event in roast.receive(person, reply)? {
            match event {
                Event::Started {
                    session,
                    members,
                    package,
                } => {
                    for member in members {
                        let holder = &mut holders[member];
                        let Some(shares) = sign(member, holder, &package) else {
                            continue;
                        };
                        let reply = if verify_shares(&package, public, &shares) {
                            Reply::Signed {
                                session,
                                shares,
                                commitments: holder.commit(rng),
                            }
                        } else {
                            Reply::Invalid { session }
                        };
                        inbox.push_back((member, reply));
                    }
                }
                Event::Excluded { .. } => {}
                Event::Signed { signature, .. } => return Ok(signature),
            }
        }
    }
    Err(NotEnough)
}

#[cfg(test)]
mod tests {
    use frost_ed25519::Ed25519Sha512;
    use frost_secp256k1::Secp256K1Sha256;
    use rand_core::OsRng;

    use super::*;

    /// 1 人が黙り、1 人が嘘をついても署名できる。どちらの曲線でも
    fn signs_despite_silence_and_lies<C: Ciphersuite>() {
        let weights = [1; 5];
        let (shares, public) = deal::<C, _>(&weights, 3, &mut OsRng).unwrap();
        let public = Arc::new(public);
        let mut holders: Vec<Holder<C>> = shares
            .into_iter()
            .map(|shares| Holder::new(receive(shares).unwrap()))
            .collect();
        let signature = sign_together(
            &mut holders,
            &public,
            &weights,
            3,
            b"message",
            &mut OsRng,
            |person, holder, package| match person {
                0 => None,
                1 => {
                    let mut shares = holder.sign(package).ok()?;
                    // いちばん下のビットを変える（Ed25519 はリトルエンディアン、secp256k1 はビッグエンディアン）
                    for share in shares.values_mut() {
                        let bytes = share.serialize();
                        *share = [0, bytes.len() - 1].into_iter().find_map(|index| {
                            let mut bytes = bytes.clone();
                            bytes[index] ^= 1;
                            SignatureShare::deserialize(&bytes).ok()
                        })?;
                    }
                    Some(shares)
                }
                _ => holder.sign(package).ok(),
            },
        )
        .unwrap();
        public
            .verifying_key()
            .verify(b"message", &signature)
            .unwrap();
    }

    #[test]
    fn signs_on_ed25519() {
        signs_despite_silence_and_lies::<Ed25519Sha512>();
    }

    #[test]
    fn signs_on_secp256k1() {
        signs_despite_silence_and_lies::<Secp256K1Sha256>();
    }
}
