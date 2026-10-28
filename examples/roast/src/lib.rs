//! 閾値署名で、ふつうのアカウントのトランザクションに署名する。何人かで分けて持つ鍵で FROST の署名を作り、
//! 誰かが黙ったり嘘をついたりしても止まらないように、ROAST の決まりで署名の組を作り直す。
//!
//! Symbol のアカウントの鍵とトランザクションの署名は、ふつうの Ed25519（SHA-512）なので、FROST（Ed25519, SHA-512）で
//! できた署名を、catapult はそのまま受け付ける。チェーンから見ると、1 人のアカウントの 1 つの署名でしかない。
//!
//! - [`deal`] で、ディーラーが鍵を作り、重みの数だけ分け前を配る
//! - [`Roast`] がまとめ役。時刻もスレッドも持たず、届いた返事から次に何をするかを決めるだけ
//! - [`verify_shares`] で、届いた分け前を確かめる。重いので、まとめ役の外で並べて走らせる

use std::collections::BTreeMap;
use std::sync::Arc;

use frost::keys::{KeyPackage, PublicKeyPackage, SecretShare};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::{Identifier, Signature, SigningPackage};
use frost_ed25519 as frost;
use rand_core::{CryptoRng, RngCore};

/// 1 人分の分け前の束。重みの数だけある
pub type Commitments = BTreeMap<Identifier, SigningCommitments>;
pub type Shares = BTreeMap<Identifier, SignatureShare>;

/// ディーラーが鍵を作り、`weights` の重みの数だけ分け前を配る。分け前を `threshold` 個集めれば署名できる。
/// ディーラーは配る前の一瞬だけ鍵の全体を持ち、1 人で署名できる。配ったら忘れる（この関数を出たら残らない）
pub fn deal<R: RngCore + CryptoRng>(
    weights: &[u16],
    threshold: u16,
    rng: &mut R,
) -> Result<(Vec<Vec<SecretShare>>, PublicKeyPackage), frost::Error> {
    let total: u16 = weights.iter().sum();
    let (mut shares, public) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
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
pub fn receive(shares: Vec<SecretShare>) -> Result<Vec<KeyPackage>, frost::Error> {
    shares.into_iter().map(KeyPackage::try_from).collect()
}

/// 1 人の署名者。分け前と、出したコミットメントの対になるノンスを持つ。ノンスは 1 度使ったら捨てる
/// （同じノンスで 2 つの違うものに署名すると、分け前がばれる）
pub struct Holder {
    keys: Vec<KeyPackage>,
    nonces: BTreeMap<Identifier, frost::round1::SigningNonces>,
}

impl Holder {
    pub fn new(keys: Vec<KeyPackage>) -> Self {
        Self {
            keys,
            nonces: BTreeMap::new(),
        }
    }

    /// 次の署名に使うノンスを作り、そのコミットメントを返す
    pub fn commit<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Commitments {
        self.keys
            .iter()
            .map(|key| {
                let (nonce, commitment) = frost::round1::commit(key.signing_share(), rng);
                self.nonces.insert(*key.identifier(), nonce);
                (*key.identifier(), commitment)
            })
            .collect()
    }

    /// `package` に、持っている分け前の全部で署名する。使ったノンスは捨てる
    pub fn sign(&mut self, package: &SigningPackage) -> Result<Shares, frost::Error> {
        let nonces = std::mem::take(&mut self.nonces);
        self.keys
            .iter()
            .map(|key| {
                let nonce = nonces
                    .get(key.identifier())
                    .ok_or(frost::Error::MissingCommitment)?;
                Ok((*key.identifier(), frost::round2::sign(package, nonce, key)?))
            })
            .collect()
    }
}

/// `package` の組で出した分け前が、どれも正しいか
pub fn verify_shares(package: &SigningPackage, public: &PublicKeyPackage, shares: &Shares) -> bool {
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
pub enum Reply {
    /// 最初の返事。次の署名に使うコミットメント
    Ready(Commitments),
    /// `session` の組の分け前（確かめて正しかったもの）と、次の署名に使うコミットメント
    Signed {
        session: usize,
        shares: Shares,
        commitments: Commitments,
    },
    /// `session` の組で、正しくない分け前を返してきた
    Invalid { session: usize },
}

/// まとめ役が決めたこと
#[derive(Debug)]
pub enum Event {
    /// 組を作った。`members` に `package` を送って、分け前を頼む
    Started {
        session: usize,
        members: Vec<usize>,
        package: Arc<SigningPackage>,
    },
    /// 嘘をついた人を外した
    Excluded { person: usize },
    /// 署名ができた
    Signed {
        session: usize,
        signature: Signature,
    },
}

/// 署名できる人が足りなくなった
#[derive(Debug, PartialEq, Eq)]
pub struct NotEnough;

struct Person {
    weight: u16,
    /// 次の組に使うコミットメント。組に入れたら空にする
    latest: Option<Commitments>,
    /// 入っている組
    session: Option<usize>,
    excluded: bool,
}

struct Session {
    package: Arc<SigningPackage>,
    shares: Shares,
    waiting: usize,
}

/// ROAST のまとめ役（Ruffing ほか, 2022）。返事をくれた人を待ち合わせに並べ、重みが閾値に届いたらすぐ組にする。
/// 組の誰かが黙っていても、その組を待たずに、返事をくれた人で次の組を作る。1 人が同時に入る組は 1 つだけで、
/// 嘘をついた人は二度と組に入れない。正直な人の重みが閾値以上なら、必ずどこかの組で署名ができる
pub struct Roast {
    message: Vec<u8>,
    public: Arc<PublicKeyPackage>,
    threshold: u16,
    people: Vec<Person>,
    /// 待ち合わせにいる人
    ready: Vec<usize>,
    sessions: Vec<Session>,
}

impl Roast {
    pub fn new(
        message: Vec<u8>,
        public: Arc<PublicKeyPackage>,
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

    /// `person` が今入っている組と、その組の頼みごと。届いた分け前を確かめるのに使う
    pub fn session_of(&self, person: usize) -> Option<(usize, Arc<SigningPackage>)> {
        let session = self.people[person].session?;
        Some((session, self.sessions[session].package.clone()))
    }

    /// 返事を受け取って、次にすることを返す
    pub fn receive(&mut self, person: usize, reply: Reply) -> Result<Vec<Event>, NotEnough> {
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
                        frost::aggregate(&entry.package, &entry.shares, &self.public)
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

    fn start(&mut self) -> Event {
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use heika_core::address::Address;
    use heika_core::key::PublicKey;
    use heika_core::network::{NetworkIdentifier, NetworkParameters};
    use heika_transaction::{Body, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId};
    use rand_core::OsRng;

    use super::*;

    #[derive(Clone, Copy, PartialEq)]
    enum Behavior {
        Honest,
        /// 最初の返事のあと、黙る
        Silent,
        /// 正しくない分け前を返す
        Liar,
    }

    /// 返事を届いた順に処理して、署名ができるまで回す。返事は、届いた順にしか処理しない
    fn run(
        weights: &[u16],
        threshold: u16,
        behaviors: &[Behavior],
        message: &[u8],
    ) -> (Result<Signature, NotEnough>, PublicKeyPackage, Vec<usize>) {
        let (shares, public) = deal(weights, threshold, &mut OsRng).unwrap();
        let public = Arc::new(public);
        let mut holders: Vec<Holder> = shares
            .into_iter()
            .map(|shares| Holder::new(receive(shares).unwrap()))
            .collect();
        let mut roast = Roast::new(message.to_vec(), public.clone(), weights, threshold);
        let mut inbox: VecDeque<(usize, Reply)> = holders
            .iter_mut()
            .enumerate()
            .map(|(person, holder)| (person, Reply::Ready(holder.commit(&mut OsRng))))
            .collect();
        let mut excluded = Vec::new();
        while let Some((person, reply)) = inbox.pop_front() {
            let events = match roast.receive(person, reply) {
                Ok(events) => events,
                Err(error) => return (Err(error), Arc::unwrap_or_clone(public), excluded),
            };
            for event in events {
                match event {
                    Event::Started {
                        session,
                        members,
                        package,
                    } => {
                        for member in members {
                            let holder = &mut holders[member];
                            let mut shares = match behaviors[member] {
                                Behavior::Silent => continue,
                                _ => holder.sign(&package).unwrap(),
                            };
                            if behaviors[member] == Behavior::Liar {
                                for share in shares.values_mut() {
                                    let mut bytes = share.serialize();
                                    bytes[0] ^= 1;
                                    *share = SignatureShare::deserialize(&bytes).unwrap();
                                }
                            }
                            let reply = if verify_shares(&package, &public, &shares) {
                                Reply::Signed {
                                    session,
                                    shares,
                                    commitments: holder.commit(&mut OsRng),
                                }
                            } else {
                                Reply::Invalid { session }
                            };
                            inbox.push_back((member, reply));
                        }
                    }
                    Event::Excluded { person } => excluded.push(person),
                    Event::Signed { signature, .. } => {
                        return (Ok(signature), Arc::unwrap_or_clone(public), excluded);
                    }
                }
            }
        }
        panic!("返事がなくなっても署名ができなかった");
    }

    #[test]
    fn signs_despite_a_silent_holder_and_a_liar() {
        use Behavior::*;
        let weights = [2, 1, 2, 1, 1, 3];
        let behaviors = [Silent, Honest, Honest, Liar, Honest, Honest];
        let (signature, public, excluded) = run(&weights, 6, &behaviors, b"message");
        let signature = signature.unwrap();
        assert!(
            public
                .verifying_key()
                .verify(b"message", &signature)
                .is_ok()
        );
        assert_eq!(excluded, [3]);
    }

    #[test]
    fn gives_up_when_liars_leave_too_little_weight() {
        use Behavior::*;
        let (signature, _, _) = run(&[2, 2, 2], 5, &[Honest, Liar, Honest], b"message");
        assert_eq!(signature.unwrap_err(), NotEnough);
    }

    #[test]
    fn symbol_accepts_the_signature_as_an_ordinary_account() {
        let parameters = NetworkParameters::from_identifier(NetworkIdentifier(152)).unwrap();
        let weights = [1, 2, 1];
        let (shares, public) = deal(&weights, 3, &mut OsRng).unwrap();
        let signer = PublicKey(
            public
                .verifying_key()
                .serialize()
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let transfer = Transfer::new(
            UnresolvedAddress::from(Address::from_public_key(&signer, parameters.identifier)),
            [(UnresolvedMosaicId(parameters.currency_mosaic_id), 1)].into(),
            Vec::new(),
        )
        .unwrap();
        let mut transaction = Transaction::new(
            signer,
            parameters.identifier,
            0,
            1,
            Body::Transfer(transfer),
        );
        let message = transaction.signing_payload(&parameters.generation_hash_seed);
        // 1 人目と 2 人目（分け前 3 つ）で署名する
        let mut holders: Vec<Holder> = shares
            .into_iter()
            .take(2)
            .map(|shares| Holder::new(receive(shares).unwrap()))
            .collect();
        let commitments = holders
            .iter_mut()
            .flat_map(|holder| holder.commit(&mut OsRng))
            .collect();
        let package = SigningPackage::new(commitments, &message);
        let shares = holders
            .iter_mut()
            .flat_map(|holder| holder.sign(&package).unwrap())
            .collect();
        let signature = frost::aggregate(&package, &shares, &public).unwrap();
        transaction.signature =
            heika_core::signature::Signature(signature.serialize().unwrap().try_into().unwrap());
        assert!(transaction.verify(&parameters.generation_hash_seed));
    }
}
