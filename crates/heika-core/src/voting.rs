//! 投票鍵。catapult の `crypto_voting/BmPrivateKeyTree` の、2段の Bellare-Miner の鍵木と、ノードが読むそのファイル。
//!
//! 根の鍵で、エポックごとの子の鍵に署名しておく。ノードは、ファイナライズの投票にエポックの子の鍵で署名し、
//! 根の鍵による子の公開鍵への署名を添える。根の秘密鍵はファイルに残さないので、
//! 子の鍵を使い終えて消していけば、過去のエポックの投票は作り直せなくなる。
//! チェーンに紐づけるのは根の公開鍵（VotingKeyLink の linkedPublicKey）。
//!
//! ```text
//!   0  u64 StartKeyIdentifier  u64 EndKeyIdentifier      作ったときの期間（エポック）
//!  16  u64 LastKeyIdentifier  u64 LastWipeKeyIdentifier  最後に署名に使った鍵と、最後に消した鍵（まだなければ全部1）
//!  32  [32] 根の公開鍵  u64 StartIdentifier  u64 EndIdentifier
//!  80  子の鍵が、終わりのエポックから始めのエポックへ並ぶ。1つが [32] 秘密鍵 [64] 根の鍵による署名。
//!      署名の対象は、子の公開鍵とエポック（u64）。消した鍵は、秘密鍵だけが0になる
//! ```

use std::fmt;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::key::{PrivateKey, PublicKey};
use crate::signature::Signature;

/// まだない鍵の番号。catapult の `BmKeyIdentifier::Invalid_Id`。
const INVALID_KEY_IDENTIFIER: u64 = u64::MAX;
/// 先頭の、期間と、使った鍵と消した鍵の番号
const TREE_HEADER_SIZE: usize = 4 * 8;
/// 根の公開鍵と、期間
const LEVEL_HEADER_SIZE: usize = 32 + 2 * 8;
/// 子の秘密鍵と、根の鍵による署名
const ENTRY_SIZE: usize = 32 + 64;

/// エポックごとの子の鍵。消したものは秘密鍵を持たない。
struct Entry {
    private_key: Option<PrivateKey>,
    signature: Signature,
}

/// 投票鍵のファイル（`votingkeys/private_key_tree1.dat` など）。
pub struct VotingKeyTree {
    start_epoch: u32,
    end_epoch: u32,
    last_used_epoch: Option<u32>,
    last_wiped_epoch: Option<u32>,
    root_public_key: PublicKey,
    /// 始めのエポックから順に並べる（ファイルとは逆順）
    entries: Vec<Entry>,
}

impl VotingKeyTree {
    /// `start_epoch` から `end_epoch` までの鍵を作る。catapult の `BmPrivateKeyTree::Create`。
    ///
    /// 根の秘密鍵は、子の鍵に署名したら捨てる。期間がネットワークで認められるかは、呼び出し側で確かめる。
    pub fn generate<R: CryptoRng + ?Sized>(
        rng: &mut R,
        start_epoch: u32,
        end_epoch: u32,
    ) -> Result<Self, VotingKeyError> {
        if start_epoch == 0 || end_epoch < start_epoch {
            return Err(VotingKeyError::InvalidEpochs {
                start: start_epoch.into(),
                end: end_epoch.into(),
            });
        }
        let root = PrivateKey::generate_with_rng(rng);
        // catapult と同じく、終わりのエポックから作る
        let mut entries: Vec<_> = (start_epoch..=end_epoch)
            .rev()
            .map(|epoch| {
                let private_key = PrivateKey::generate_with_rng(rng);
                let signature = root.sign(&[
                    &PublicKey::from_private_key(&private_key).0,
                    &u64::from(epoch).to_le_bytes(),
                ]);
                Entry {
                    private_key: Some(private_key),
                    signature,
                }
            })
            .collect();
        entries.reverse();
        Ok(Self {
            start_epoch,
            end_epoch,
            last_used_epoch: None,
            last_wiped_epoch: None,
            root_public_key: PublicKey::from_private_key(&root),
            entries,
        })
    }

    /// ファイルから読む。catapult の `BmPrivateKeyTree::FromStream` が読むものを読み、長さと期間が合わないものは弾く。
    /// 署名は [`VotingKeyTree::verify`] で確かめる。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VotingKeyError> {
        let u64_at = |offset: usize| {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8 bytes"))
        };
        if bytes.len() < TREE_HEADER_SIZE + LEVEL_HEADER_SIZE {
            return Err(VotingKeyError::TooShort);
        }
        let (start, end) = (u64_at(0), u64_at(8));
        let (level_start, level_end) = (u64_at(64), u64_at(72));
        if (level_start, level_end) != (start, end) {
            return Err(VotingKeyError::InconsistentEpochs);
        }
        let epoch = |value: u64| u32::try_from(value).ok().filter(|&epoch| epoch != 0);
        let (Some(start_epoch), Some(end_epoch)) = (epoch(start), epoch(end)) else {
            return Err(VotingKeyError::InvalidEpochs { start, end });
        };
        if end_epoch < start_epoch {
            return Err(VotingKeyError::InvalidEpochs { start, end });
        }
        let count = (end_epoch - start_epoch) as usize + 1;
        let expected = TREE_HEADER_SIZE + LEVEL_HEADER_SIZE + count * ENTRY_SIZE;
        if bytes.len() != expected {
            return Err(VotingKeyError::SizeMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        // 使った鍵と消した鍵の番号は、まだないか、期間の中のエポック
        let marker = |value: u64| match value {
            INVALID_KEY_IDENTIFIER => Ok(None),
            value => epoch(value)
                .filter(|epoch| (start_epoch..=end_epoch).contains(epoch))
                .map(Some)
                .ok_or(VotingKeyError::InvalidKeyIdentifier(value)),
        };
        let last_used_epoch = marker(u64_at(16))?;
        let last_wiped_epoch = marker(u64_at(24))?;

        let mut entries: Vec<_> = bytes[TREE_HEADER_SIZE + LEVEL_HEADER_SIZE..]
            .chunks(ENTRY_SIZE)
            .map(|entry| {
                let private_key: &[u8; 32] = entry[..32].try_into().expect("32 bytes");
                Entry {
                    private_key: (*private_key != [0; 32])
                        .then(|| PrivateKey::from_bytes(private_key)),
                    signature: Signature(entry[32..].try_into().expect("64 bytes")),
                }
            })
            .collect();
        entries.reverse();
        Ok(Self {
            start_epoch,
            end_epoch,
            last_used_epoch,
            last_wiped_epoch,
            root_public_key: PublicKey(bytes[32..64].try_into().expect("32 bytes")),
            entries,
        })
    }

    /// ファイルに書くバイト列。子の秘密鍵が入るので、消えるようにして返す。
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let marker = |epoch: Option<u32>| epoch.map_or(INVALID_KEY_IDENTIFIER, u64::from);
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            TREE_HEADER_SIZE + LEVEL_HEADER_SIZE + self.entries.len() * ENTRY_SIZE,
        ));
        for value in [
            self.start_epoch.into(),
            self.end_epoch.into(),
            marker(self.last_used_epoch),
            marker(self.last_wiped_epoch),
        ] {
            bytes.extend_from_slice(&u64::to_le_bytes(value));
        }
        bytes.extend_from_slice(&self.root_public_key.0);
        bytes.extend_from_slice(&u64::from(self.start_epoch).to_le_bytes());
        bytes.extend_from_slice(&u64::from(self.end_epoch).to_le_bytes());
        for entry in self.entries.iter().rev() {
            match &entry.private_key {
                Some(private_key) => bytes.extend_from_slice(private_key.as_bytes()),
                None => bytes.extend_from_slice(&[0; 32]),
            }
            bytes.extend_from_slice(&entry.signature.0);
        }
        bytes
    }

    /// チェーンに紐づける公開鍵。
    pub fn public_key(&self) -> PublicKey {
        self.root_public_key
    }

    pub fn start_epoch(&self) -> u32 {
        self.start_epoch
    }

    pub fn end_epoch(&self) -> u32 {
        self.end_epoch
    }

    /// ノードが最後に投票に使ったエポック。
    pub fn last_used_epoch(&self) -> Option<u32> {
        self.last_used_epoch
    }

    /// ノードが最後に消したエポック。これより前の鍵も消えている。
    pub fn last_wiped_epoch(&self) -> Option<u32> {
        self.last_wiped_epoch
    }

    /// 子の鍵がまだ残っているエポックの数。
    pub fn remaining_keys(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.private_key.is_some())
            .count()
    }

    /// 残っている子の鍵について、根の公開鍵がそのエポックの鍵として署名していることを確かめる。
    /// 消した鍵は公開鍵がわからないので確かめられない。合わない最初のエポックを返す。
    pub fn verify(&self) -> Result<(), u32> {
        for (epoch, entry) in (self.start_epoch..=self.end_epoch).zip(&self.entries) {
            let Some(private_key) = &entry.private_key else {
                continue;
            };
            let public_key = PublicKey::from_private_key(private_key);
            if !self.root_public_key.verify(
                &[&public_key.0, &u64::from(epoch).to_le_bytes()],
                &entry.signature,
            ) {
                return Err(epoch);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for VotingKeyTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VotingKeyTree")
            .field("start_epoch", &self.start_epoch)
            .field("end_epoch", &self.end_epoch)
            .field("last_used_epoch", &self.last_used_epoch)
            .field("last_wiped_epoch", &self.last_wiped_epoch)
            .field("root_public_key", &self.root_public_key)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VotingKeyError {
    /// ヘッダーの長さに足りない
    TooShort,
    /// 期間から決まる長さと合わない
    SizeMismatch { expected: usize, actual: usize },
    /// 期間が、0 から始まるか、逆になっているか、エポックの範囲を超えている
    InvalidEpochs { start: u64, end: u64 },
    /// 先頭の期間と、根の公開鍵に続く期間が違う
    InconsistentEpochs,
    /// 使った鍵か消した鍵の番号が、期間の中にない
    InvalidKeyIdentifier(u64),
}

impl fmt::Display for VotingKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("投票鍵のファイルのヘッダーの長さに足りません"),
            Self::SizeMismatch { expected, actual } => write!(
                f,
                "期間からは {expected} バイトのはずですが、{actual} バイトでした"
            ),
            Self::InvalidEpochs { start, end } => write!(
                f,
                "期間（エポック {start} から {end} まで）が正しくありません"
            ),
            Self::InconsistentEpochs => f.write_str("先頭の期間と、公開鍵に続く期間が違います"),
            Self::InvalidKeyIdentifier(value) => {
                write!(f, "使った鍵か消した鍵の番号 {value} が期間の中にありません")
            }
        }
    }
}

impl std::error::Error for VotingKeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1バイトずつ数を増やして埋める乱数。テストで鍵を固定するのに使う。
    struct Counter(u8);

    impl rand_core::TryRng for Counter {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unimplemented!("only fill_bytes is used")
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for byte in dst {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Counter {}

    #[test]
    fn writes_the_catapult_layout() {
        let tree = VotingKeyTree::generate(&mut Counter(0), 5, 7).unwrap();
        let bytes = tree.to_bytes();
        assert_eq!(bytes.len(), 32 + 48 + 3 * 96);
        assert_eq!(bytes[..8], 5u64.to_le_bytes());
        assert_eq!(bytes[8..16], 7u64.to_le_bytes());
        assert_eq!(bytes[16..32], [0xFF; 16]);

        // 根の鍵は乱数の最初の32バイトで、ファイルには公開鍵だけが入る
        let root: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let root = PrivateKey::from_bytes(&root);
        assert_eq!(tree.public_key(), PublicKey::from_private_key(&root));
        assert_eq!(bytes[32..64], tree.public_key().0);
        assert!(!bytes.windows(32).any(|window| window == root.as_bytes()));
        assert_eq!(bytes[64..72], 5u64.to_le_bytes());
        assert_eq!(bytes[72..80], 7u64.to_le_bytes());

        // 子の鍵は終わりのエポックから作って並べる。1つめは乱数の次の32バイト
        let first: [u8; 32] = std::array::from_fn(|i| i as u8 + 33);
        assert_eq!(bytes[80..112], first);
        let signature = root.sign(&[
            &PublicKey::from_private_key(&PrivateKey::from_bytes(&first)).0,
            &7u64.to_le_bytes(),
        ]);
        assert_eq!(bytes[112..176], signature.0);
        assert_eq!(tree.verify(), Ok(()));
    }

    #[test]
    fn reads_back_what_it_writes() {
        let tree = VotingKeyTree::generate(&mut Counter(0), 1, 4).unwrap();
        let read = VotingKeyTree::from_bytes(&tree.to_bytes()).unwrap();
        assert_eq!(*read.to_bytes(), *tree.to_bytes());
        assert_eq!((read.start_epoch(), read.end_epoch()), (1, 4));
        assert_eq!(read.public_key(), tree.public_key());
        assert_eq!(read.remaining_keys(), 4);
        assert_eq!(read.verify(), Ok(()));
    }

    #[test]
    fn reads_keys_that_the_node_used_and_wiped() {
        let tree = VotingKeyTree::generate(&mut Counter(0), 1, 4).unwrap();
        let mut bytes = tree.to_bytes();
        // ノードがエポック 3 まで投票し、2 までを消したところ。ファイルは 4、3、2、1 の順に並ぶ
        bytes[16..24].copy_from_slice(&3u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&2u64.to_le_bytes());
        for index in [2, 3] {
            let offset = 80 + index * 96;
            bytes[offset..offset + 32].fill(0);
        }
        let read = VotingKeyTree::from_bytes(&bytes).unwrap();
        assert_eq!(read.last_used_epoch(), Some(3));
        assert_eq!(read.last_wiped_epoch(), Some(2));
        assert_eq!(read.remaining_keys(), 2);
        assert_eq!(read.verify(), Ok(()));
        assert_eq!(*read.to_bytes(), *bytes);
    }

    #[test]
    fn finds_a_key_that_the_root_did_not_sign() {
        let tree = VotingKeyTree::generate(&mut Counter(0), 1, 4).unwrap();
        let mut bytes = tree.to_bytes();
        // エポック 2 の署名を壊す
        bytes[80 + 2 * 96 + 32] ^= 1;
        assert_eq!(VotingKeyTree::from_bytes(&bytes).unwrap().verify(), Err(2));
    }

    #[test]
    fn rejects_broken_files() {
        let bytes = VotingKeyTree::generate(&mut Counter(0), 1, 4)
            .unwrap()
            .to_bytes();
        let with = |values: &[(usize, u64)]| {
            let mut bytes = bytes.to_vec();
            for &(offset, value) in values {
                bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
            bytes
        };
        for (name, broken, error) in [
            ("short", bytes[..40].to_vec(), VotingKeyError::TooShort),
            (
                "long",
                [bytes.as_slice(), &[0]].concat(),
                VotingKeyError::SizeMismatch {
                    expected: bytes.len(),
                    actual: bytes.len() + 1,
                },
            ),
            (
                "level",
                with(&[(64, 2)]),
                VotingKeyError::InconsistentEpochs,
            ),
            (
                "zero",
                with(&[(0, 0), (64, 0)]),
                VotingKeyError::InvalidEpochs { start: 0, end: 4 },
            ),
            (
                "used",
                with(&[(16, 5)]),
                VotingKeyError::InvalidKeyIdentifier(5),
            ),
        ] {
            assert_eq!(
                VotingKeyTree::from_bytes(&broken).unwrap_err(),
                error,
                "{name}"
            );
        }
        assert_eq!(
            VotingKeyTree::generate(&mut Counter(0), 0, 4).unwrap_err(),
            VotingKeyError::InvalidEpochs { start: 0, end: 4 }
        );
        assert_eq!(
            VotingKeyTree::generate(&mut Counter(0), 5, 4).unwrap_err(),
            VotingKeyError::InvalidEpochs { start: 5, end: 4 }
        );
    }
}
