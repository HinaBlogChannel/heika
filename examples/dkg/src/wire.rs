//! 掲示板に載せるもの。
//!
//! 掲示板は、Symbol の受け箱（[`inbox`]）に宛てた転送のメッセージ。メッセージの先頭に [`PREFIX`] を付ける。
//! 1 つのメッセージに収まらなければ、アグリゲートの中の転送に分けて、読む側が順につなげる（[`crate::symbol`]）。
//!
//! 載せるものは 5 種類。最初の 1 バイトで見分ける。
//!
//! - 始める（[`Session`]）：しきい値、1 段階の長さ（ブロック数）、参加者の公開鍵。誰が載せてもいい。
//!   中身のハッシュがセッションの ID なので、ID を知っている人は、中身が本物かを確かめられる
//! - 約束する（[`Body::Commit`]）：Feldman のコミットメント、定数項の知識の証明、分け前を暗号化するための X25519 の公開鍵
//! - 配る（[`Body::Shares`]）：ほかの参加者それぞれに宛てた分け前。宛先の X25519 の鍵で暗号化する
//! - 苦情を言う（[`Body::Complain`]）：届いた分け前がコミットメントと合わなかった配り手
//! - 明かす（[`Body::Reveal`]）：苦情を受けた配り手が、その人宛ての分け前を平文で出す
//!
//! 始める以外は、参加者の鍵（Symbol の鍵と同じ Ed25519）で署名する。署名にはセッションの ID を入れるので、
//! ほかのセッションには使い回せない。

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use frost_core::keys::{SigningShare, VerifiableSecretSharingCommitment};
use frost_core::{Identifier, Signature as FrostSignature};
use frost_ed25519::Ed25519Sha512;
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as ExchangeKey, StaticSecret};
use zeroize::Zeroizing;

/// 使う曲線とハッシュ。Symbol の署名と同じ Ed25519（SHA-512）
pub type E = Ed25519Sha512;

/// メッセージの先頭。1 バイト目の 0 は平文のメッセージの印で、エクスプローラーでも平文として見える
pub const PREFIX: &[u8] = b"\0dkg";

/// ハッシュと署名の頭に付ける、ほかの用途と混ざらないための文字列
const DOMAIN: &[u8] = b"heika dkg";

/// 暗号化した分け前 1 つの大きさ（32 バイトのスカラーと、16 バイトの認証タグ）
pub const SEALED: usize = 32 + 16;

const START: u8 = 0;
const COMMIT: u8 = 1;
const SHARES: u8 = 2;
const COMPLAIN: u8 = 3;
const REVEAL: u8 = 4;

/// 1 回の DKG。参加者は公開鍵の並びで決まり、FROST の識別子は並びの位置に 1 を足したもの
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// 署名に要る人数
    pub threshold: u16,
    /// 1 つの段階の長さ（ブロック数）
    pub window: u64,
    /// 同じ参加者で何度でも始められるように入れる乱数
    pub nonce: [u8; 16],
    pub members: Vec<PublicKey>,
}

impl Session {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![START];
        bytes.extend_from_slice(&self.threshold.to_le_bytes());
        bytes.extend_from_slice(&self.window.to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&(self.members.len() as u16).to_le_bytes());
        for member in &self.members {
            bytes.extend_from_slice(&member.0);
        }
        bytes
    }

    /// 読めないもの、しきい値が 2 から参加者の数までにないもの、同じ参加者が 2 回いるものは `None`
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes.strip_prefix(&[START])?);
        let threshold = reader.u16()?;
        let window = reader.u64()?;
        let nonce = reader.array()?;
        let count = reader.u16()?;
        let members = (0..count)
            .map(|_| reader.array().map(PublicKey))
            .collect::<Option<Vec<_>>>()?;
        let session = Self {
            threshold,
            window,
            nonce,
            members,
        };
        let unique = session
            .members
            .iter()
            .enumerate()
            .all(|(index, member)| !session.members[..index].contains(member));
        (reader.0.is_empty()
            && window > 0
            && 2 <= threshold
            && usize::from(threshold) <= session.members.len()
            && unique)
            .then_some(session)
    }

    /// セッションの ID。中身のハッシュ
    pub fn id(&self) -> [u8; 32] {
        hash(&[b"session", &self.encode()])
    }

    /// `member` 番目の参加者の、FROST の識別子
    pub fn identifier(member: u16) -> Identifier<E> {
        Identifier::try_from(member + 1).expect("not zero")
    }
}

/// セッションの受け箱。ID のハッシュを公開鍵の代わりにして作るので、誰も秘密鍵を持っていない
pub fn inbox(id: &[u8; 32], network: NetworkIdentifier) -> Address {
    Address::from_public_key(&PublicKey(hash(&[b"inbox", id])), network)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Commit {
        commitment: VerifiableSecretSharingCommitment<E>,
        /// 大きい（点を展開して持つ）ので、ほかの種類と大きさをそろえるために箱に入れる
        proof: Box<FrostSignature<E>>,
        /// 自分宛ての分け前を暗号化してもらう X25519 の公開鍵。やり直すたびに作り直す
        exchange: [u8; 32],
    },
    /// ほかの参加者それぞれに宛てた分け前。その回の参加者の並びから、自分を抜いた順
    Shares(Vec<[u8; SEALED]>),
    /// 届いた分け前がコミットメントと合わなかった配り手
    Complain(Vec<u16>),
    /// 苦情を言った `to` 宛ての分け前
    Reveal { to: u16, share: SigningShare<E> },
}

/// 参加者が載せるもの
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Post {
    /// 何回目のやり直しか（最初は 0）
    pub attempt: u16,
    /// 参加者の並びの位置
    pub member: u16,
    pub body: Body,
}

impl Post {
    /// 署名を付けて、載せる形にする
    pub fn sign(&self, id: &[u8; 32], key: &PrivateKey) -> Vec<u8> {
        let mut bytes = self.unsigned();
        let signature = key.sign(&[DOMAIN, id, &bytes]);
        bytes.extend_from_slice(&signature.0);
        bytes
    }

    fn unsigned(&self) -> Vec<u8> {
        let kind = match self.body {
            Body::Commit { .. } => COMMIT,
            Body::Shares(_) => SHARES,
            Body::Complain(_) => COMPLAIN,
            Body::Reveal { .. } => REVEAL,
        };
        let mut bytes = vec![kind];
        bytes.extend_from_slice(&self.attempt.to_le_bytes());
        bytes.extend_from_slice(&self.member.to_le_bytes());
        match &self.body {
            Body::Commit {
                commitment,
                proof,
                exchange,
            } => {
                for coefficient in commitment.serialize().expect("valid points") {
                    bytes.extend_from_slice(&coefficient);
                }
                bytes.extend_from_slice(&proof.serialize().expect("a valid signature"));
                bytes.extend_from_slice(exchange);
            }
            Body::Shares(shares) => {
                for share in shares {
                    bytes.extend_from_slice(share);
                }
            }
            Body::Complain(against) => {
                for member in against {
                    bytes.extend_from_slice(&member.to_le_bytes());
                }
            }
            Body::Reveal { to, share } => {
                bytes.extend_from_slice(&to.to_le_bytes());
                bytes.extend_from_slice(&share.serialize());
            }
        }
        bytes
    }

    /// `session` の参加者が署名したものだけを読む。点は、素数位数の部分群の、単位元でないものだけを受け付ける
    /// （frost-ed25519 の読み方）
    pub fn decode(bytes: &[u8], session: &Session, id: &[u8; 32]) -> Option<Self> {
        let (unsigned, signature) = bytes.split_at_checked(bytes.len().checked_sub(64)?)?;
        let mut reader = Reader(unsigned);
        let kind = reader.u8()?;
        let attempt = reader.u16()?;
        let member = reader.u16()?;
        let key = session.members.get(usize::from(member))?;
        let signature = Signature(signature.try_into().ok()?);
        if !key.verify(&[DOMAIN, id, unsigned], &signature) {
            return None;
        }
        let body = match kind {
            COMMIT => {
                let coefficients = (0..session.threshold)
                    .map(|_| reader.take(32))
                    .collect::<Option<Vec<_>>>()?;
                Body::Commit {
                    commitment: VerifiableSecretSharingCommitment::deserialize(coefficients)
                        .ok()?,
                    proof: Box::new(FrostSignature::deserialize(reader.take(64)?).ok()?),
                    exchange: reader.array()?,
                }
            }
            SHARES => {
                let mut shares = Vec::new();
                while !reader.0.is_empty() {
                    shares.push(reader.array()?);
                }
                Body::Shares(shares)
            }
            COMPLAIN => {
                let mut against = Vec::new();
                while !reader.0.is_empty() {
                    against.push(reader.u16()?);
                }
                Body::Complain(against)
            }
            REVEAL => Body::Reveal {
                to: reader.u16()?,
                share: SigningShare::deserialize(reader.take(32)?).ok()?,
            },
            _ => return None,
        };
        reader.0.is_empty().then_some(Self {
            attempt,
            member,
            body,
        })
    }
}

/// 配り手 `dealer` から `recipient` への分け前を暗号化する。`mine` は配り手のその回の X25519 の鍵、
/// `theirs` は宛先がその回の約束に載せた X25519 の公開鍵。宛先の鍵が小さい位数の点なら `None`
pub fn seal(
    id: &[u8; 32],
    attempt: u16,
    (dealer, recipient): (u16, u16),
    mine: &StaticSecret,
    theirs: &[u8; 32],
    share: &SigningShare<E>,
) -> Option<[u8; SEALED]> {
    let ours = ExchangeKey::from(mine).to_bytes();
    let cipher = cipher(
        id,
        attempt,
        (dealer, recipient),
        mine,
        theirs,
        (&ours, theirs),
    )?;
    let sealed = cipher
        .encrypt(&Nonce::default(), share.serialize().as_slice())
        .expect("a short plaintext");
    sealed.try_into().ok()
}

/// [`seal`] したものを、宛先 `recipient` が開く。`theirs` は配り手がその回の約束に載せた X25519 の公開鍵。
/// 開けないもの、スカラーとして読めないものは `None`
pub fn open(
    id: &[u8; 32],
    attempt: u16,
    (dealer, recipient): (u16, u16),
    mine: &StaticSecret,
    theirs: &[u8; 32],
    sealed: &[u8; SEALED],
) -> Option<SigningShare<E>> {
    let ours = ExchangeKey::from(mine).to_bytes();
    let cipher = cipher(
        id,
        attempt,
        (dealer, recipient),
        mine,
        theirs,
        (theirs, &ours),
    )?;
    let share = Zeroizing::new(cipher.decrypt(&Nonce::default(), sealed.as_slice()).ok()?);
    SigningShare::deserialize(&share).ok()
}

/// 配り手と宛先の組ごとの鍵。鍵は 1 回しか使わないので、ノンスは 0 のままでいい
fn cipher(
    id: &[u8; 32],
    attempt: u16,
    (dealer, recipient): (u16, u16),
    mine: &StaticSecret,
    theirs: &[u8; 32],
    (dealer_key, recipient_key): (&[u8; 32], &[u8; 32]),
) -> Option<ChaCha20Poly1305> {
    let shared = mine.diffie_hellman(&ExchangeKey::from(*theirs));
    // 相手の鍵が小さい位数の点だと、共有した秘密が 0 になり、誰でも分かってしまう
    if !shared.was_contributory() {
        return None;
    }
    let key = Zeroizing::new(hash(&[
        b"share",
        id,
        &attempt.to_le_bytes(),
        &dealer.to_le_bytes(),
        &recipient.to_le_bytes(),
        dealer_key,
        recipient_key,
        shared.as_bytes(),
    ]));
    Some(ChaCha20Poly1305::new((&*key).into()))
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(DOMAIN);
    for part in parts {
        hasher.update((part.len() as u32).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize()[..32].try_into().expect("64 bytes")
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(length)?;
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        self.array().map(u8::from_le_bytes)
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }
}

#[cfg(test)]
mod tests {
    use frost_core::keys::dkg;
    use rand_core::OsRng;

    use super::*;

    fn session(keys: &[PrivateKey]) -> Session {
        Session {
            threshold: 2,
            window: 10,
            nonce: [7; 16],
            members: keys.iter().map(PublicKey::from_private_key).collect(),
        }
    }

    fn keys(count: usize) -> Vec<PrivateKey> {
        (0..count)
            .map(|_| PrivateKey::generate().unwrap())
            .collect()
    }

    #[test]
    fn session_round_trips_and_rejects_bad_ones() {
        let keys = keys(3);
        let session = session(&keys);
        assert_eq!(Session::decode(&session.encode()), Some(session.clone()));

        let mut one = session.clone();
        one.threshold = 1;
        assert_eq!(Session::decode(&one.encode()), None);
        let mut many = session.clone();
        many.threshold = 4;
        assert_eq!(Session::decode(&many.encode()), None);
        let mut twice = session.clone();
        twice.members[2] = twice.members[0];
        assert_eq!(Session::decode(&twice.encode()), None);
        let mut longer = session.encode();
        longer.push(0);
        assert_eq!(Session::decode(&longer), None);
    }

    #[test]
    fn posts_round_trip_only_with_the_right_signature() {
        let keys = keys(3);
        let session = session(&keys);
        let id = session.id();
        let (_, package) = dkg::part1::<E, _>(Session::identifier(1), 3, 2, OsRng).unwrap();
        let posts = [
            Body::Commit {
                commitment: package.commitment().clone(),
                proof: Box::new(*package.proof_of_knowledge()),
                exchange: [9; 32],
            },
            Body::Shares(vec![[1; SEALED], [2; SEALED]]),
            Body::Complain(vec![0, 2]),
            Body::Reveal {
                to: 2,
                share: SigningShare::deserialize(&[5; 32]).unwrap(),
            },
        ]
        .map(|body| Post {
            attempt: 3,
            member: 1,
            body,
        });
        for post in posts {
            let bytes = post.sign(&id, &keys[1]);
            assert_eq!(Post::decode(&bytes, &session, &id), Some(post.clone()));
            // ほかの人の鍵、ほかのセッション
            assert_eq!(Post::decode(&post.sign(&id, &keys[0]), &session, &id), None);
            assert_eq!(Post::decode(&bytes, &session, &[0; 32]), None);
        }
    }

    #[test]
    fn rejects_points_outside_the_prime_order_subgroup() {
        let keys = keys(2);
        let session = session(&keys);
        let id = session.id();
        let (_, package) = dkg::part1::<E, _>(Session::identifier(0), 2, 2, OsRng).unwrap();
        let mut unsigned = vec![COMMIT, 0, 0, 0, 0];
        let coefficients = package.commitment().serialize().unwrap();
        // 位数 2 の点 (0, -1) を、2 つ目の係数の代わりにする
        let mut torsion = [0; 32];
        torsion[0] = 0xEC;
        torsion[1..31].fill(0xFF);
        torsion[31] = 0x7F;
        unsigned.extend_from_slice(&coefficients[0]);
        unsigned.extend_from_slice(&torsion);
        unsigned.extend_from_slice(&package.proof_of_knowledge().serialize().unwrap());
        unsigned.extend_from_slice(&[9; 32]);
        let signature = keys[0].sign(&[DOMAIN, &id, &unsigned]);
        let bytes = [unsigned, signature.0.to_vec()].concat();
        assert_eq!(Post::decode(&bytes, &session, &id), None);

        // 同じ形で、係数が正しければ読める
        let mut unsigned = bytes[..5 + 32].to_vec();
        unsigned.extend_from_slice(&coefficients[1]);
        unsigned.extend_from_slice(&bytes[5 + 64..bytes.len() - 64]);
        let signature = keys[0].sign(&[DOMAIN, &id, &unsigned]);
        let bytes = [unsigned, signature.0.to_vec()].concat();
        assert!(Post::decode(&bytes, &session, &id).is_some());
    }

    #[test]
    fn sealed_share_opens_only_for_the_recipient() {
        let id = [3; 32];
        let dealer = StaticSecret::random_from_rng(OsRng);
        let recipient = StaticSecret::random_from_rng(OsRng);
        let other = StaticSecret::random_from_rng(OsRng);
        let dealer_key = ExchangeKey::from(&dealer).to_bytes();
        let recipient_key = ExchangeKey::from(&recipient).to_bytes();
        let share = SigningShare::deserialize(&[5; 32]).unwrap();
        let sealed = seal(&id, 0, (0, 1), &dealer, &recipient_key, &share).unwrap();
        assert_eq!(
            open(&id, 0, (0, 1), &recipient, &dealer_key, &sealed),
            Some(share)
        );
        assert_eq!(open(&id, 0, (0, 1), &other, &dealer_key, &sealed), None);
        // ほかの回、ほかの組としては開けない
        assert_eq!(open(&id, 1, (0, 1), &recipient, &dealer_key, &sealed), None);
        assert_eq!(open(&id, 0, (2, 1), &recipient, &dealer_key, &sealed), None);
        // 小さい位数の鍵には暗号化しない
        assert_eq!(seal(&id, 0, (0, 1), &dealer, &[0; 32], &share), None);
    }
}
