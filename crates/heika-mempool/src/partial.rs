//! 連署を待つアグリゲートボンデッドの置き場（catapult の PT キャッシュ、`MemoryPtCache`）。IO は持たない（sans-IO）。
//!
//! 受け付けるときは、連署を外したトランザクションについて、状態に依らないことだけを確かめる（外側の署名、
//! トランザクションごとの規則、期限、手数料の上限）。連署が足りないのは、ここで待つものなので確かめない。
//! ハッシュロックが確定して有効か、連署できる人か、連署が揃ったかは状態に依るので、呼ぶ側（中核の実行役）が確かめる。
//!
//! 連署は署名者の公開鍵の順に持つ。トランザクションのハッシュと、連署を並べたもののハッシュの、それぞれの先頭
//! （[`ShortHashPair`]）で、ピアに持っているものを伝える（`Pull_Partial_Transaction_Infos`）。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use heika_chain::verify::{VerifyError, verify_transaction};
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_packet::partial::{COSIGNATURE_SIZE, CosignedInfo, PartialInfo, ShortHashPair};
use heika_packet::short_hash;
use heika_transaction::{Body, Cosignature, DetachedCosignature, Transaction};
use sha3::{Digest, Sha3_256};

/// 運用者が選ぶ上限。catapult の `config-pt.properties` と、`maxBondedTransactionLifetime`
#[derive(Clone, Debug)]
pub struct PartialConfig {
    /// 持っておくトランザクション（連署を除く）のバイト数の上限（`cacheMaxSize`）。連署はこれに数えない
    pub max_bytes: usize,
    /// `Pull_Partial_Transaction_Infos` に答えるバイト数の上限（`cacheMaxResponseSize`）
    pub max_response_bytes: usize,
    /// 期限が、今からこれより先なら受け付けない（ミリ秒、`maxBondedTransactionLifetime`）
    pub max_lifetime: u64,
}

impl Default for PartialConfig {
    /// catapult の既定値に合わせる
    fn default() -> Self {
        Self {
            max_bytes: 60 * 1024 * 1024,
            max_response_bytes: 20 * 1024 * 1024,
            max_lifetime: 48 * 60 * 60 * 1000,
        }
    }
}

/// 受け付けなかったわけ
#[derive(Debug)]
pub enum PartialRejected {
    /// トランザクションとして読めない
    Malformed(String),
    /// アグリゲートボンデッドではない
    NotBonded,
    /// 期限が過ぎている
    Expired,
    /// 期限が、今から [`PartialConfig::max_lifetime`] より先
    TooFarAhead,
    /// 外側の署名か、規則が通らない
    Invalid(VerifyError),
    /// いっぱい
    Full,
}

impl fmt::Display for PartialRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "トランザクションとして読めません: {error}"),
            Self::NotBonded => write!(f, "アグリゲートボンデッドではありません"),
            Self::Expired => write!(f, "期限が過ぎています"),
            Self::TooFarAhead => write!(f, "期限が先すぎます"),
            Self::Invalid(error) => write!(f, "確かめが通りません: {error}"),
            Self::Full => write!(f, "いっぱいです"),
        }
    }
}

/// 連署を足さなかったわけ
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CosignRejected {
    /// 連署したアグリゲートを持っていない
    UnknownParent,
    /// 署名が、アグリゲートのハッシュに対して正しくない
    InvalidSignature,
    /// 外側の署名者か、もう連署した人
    Redundant,
}

impl fmt::Display for CosignRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParent => write!(f, "連署したアグリゲートを持っていません"),
            Self::InvalidSignature => write!(f, "連署の署名が正しくありません"),
            Self::Redundant => write!(f, "もう連署しています"),
        }
    }
}

/// 受け付けた結果
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Added {
    pub hash: Hash256,
    /// 初めて受け付けた。偽なら、もう持っていたものに連署を足しただけ
    pub new: bool,
    /// 一緒に付いてきて、新しく足した連署
    pub cosignatures: Vec<Cosignature>,
}

struct Entry {
    /// 連署を外したトランザクション
    transaction: Vec<u8>,
    signer: PublicKey,
    deadline: u64,
    /// 署名者の公開鍵の順の連署（アグリゲートの中と同じ形）
    cosignatures: BTreeMap<[u8; 32], [u8; COSIGNATURE_SIZE]>,
}

impl Entry {
    /// 連署を署名者の順に並べたもののハッシュ（catapult の `CosignaturesHash`）
    fn cosignatures_hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        for bytes in self.cosignatures.values() {
            hasher.update(bytes);
        }
        Hash256(hasher.finalize().into())
    }
}

pub struct PartialPool {
    parameters: &'static NetworkParameters,
    config: PartialConfig,
    entries: HashMap<Hash256, Entry>,
    /// 期限の早い順。期限切れを掃除するのに使う
    by_deadline: BTreeSet<(u64, [u8; 32])>,
    bytes: usize,
}

impl PartialPool {
    pub fn new(parameters: &'static NetworkParameters, config: PartialConfig) -> Self {
        Self {
            parameters,
            config,
            entries: HashMap::new(),
            by_deadline: BTreeSet::new(),
            bytes: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash)
    }

    /// 署名したアグリゲートボンデッド `bytes` を、今（Nemesis からのミリ秒 `now`）、高さ `height` のブロックに入れる
    /// つもりで受け付ける。連署が付いていれば、正しいものを足す。もう持っていれば、連署を足すだけ
    pub fn add(&mut self, bytes: &[u8], now: u64, height: u64) -> Result<Added, PartialRejected> {
        let mut transaction = Transaction::from_bytes(bytes)
            .map_err(|error| PartialRejected::Malformed(error.to_string()))?;
        if !matches!(transaction.body, Body::AggregateBonded(_)) {
            return Err(PartialRejected::NotBonded);
        }
        let hash = transaction.hash(&self.parameters.generation_hash_seed);
        let cosignatures = transaction.take_cosignatures();
        let new = !self.entries.contains_key(&hash);
        if new {
            if transaction.deadline < now {
                return Err(PartialRejected::Expired);
            }
            if transaction.deadline > now.saturating_add(self.config.max_lifetime) {
                return Err(PartialRejected::TooFarAhead);
            }
            let stripped = transaction.to_bytes();
            if self.bytes + stripped.len() > self.config.max_bytes {
                return Err(PartialRejected::Full);
            }
            verify_transaction(self.parameters, height, 0, &stripped)
                .map_err(PartialRejected::Invalid)?;
            self.bytes += stripped.len();
            self.by_deadline.insert((transaction.deadline, hash.0));
            self.entries.insert(
                hash,
                Entry {
                    transaction: stripped,
                    signer: transaction.signer_public_key,
                    deadline: transaction.deadline,
                    cosignatures: BTreeMap::new(),
                },
            );
        }
        let cosignatures = cosignatures
            .into_iter()
            .filter(|cosignature| {
                let detached = DetachedCosignature {
                    cosignature: *cosignature,
                    parent_hash: hash,
                };
                self.add_cosignature(&detached).is_ok()
            })
            .collect();
        Ok(Added {
            hash,
            new,
            cosignatures,
        })
    }

    /// 切り離した連署を、持っているアグリゲートに足す
    pub fn add_cosignature(
        &mut self,
        detached: &DetachedCosignature,
    ) -> Result<(), CosignRejected> {
        let entry = self
            .entries
            .get_mut(&detached.parent_hash)
            .ok_or(CosignRejected::UnknownParent)?;
        let signer = detached.cosignature.signer_public_key;
        if signer == entry.signer || entry.cosignatures.contains_key(&signer.0) {
            return Err(CosignRejected::Redundant);
        }
        if !detached.verify() {
            return Err(CosignRejected::InvalidSignature);
        }
        entry
            .cosignatures
            .insert(signer.0, detached.cosignature.to_bytes());
        Ok(())
    }

    /// 連署を外す。連署できる人でなくなった（マルチシグが変わった）ものを外すとき
    pub fn remove_cosignature(&mut self, hash: &Hash256, signer: &PublicKey) -> bool {
        self.entries
            .get_mut(hash)
            .is_some_and(|entry| entry.cosignatures.remove(&signer.0).is_some())
    }

    /// 持っていれば、その期限（Nemesis からのミリ秒）
    pub fn deadline(&self, hash: &Hash256) -> Option<u64> {
        self.entries.get(hash).map(|entry| entry.deadline)
    }

    /// 連署を外したトランザクション
    pub fn transaction(&self, hash: &Hash256) -> Option<&[u8]> {
        self.entries
            .get(hash)
            .map(|entry| entry.transaction.as_slice())
    }

    /// 署名者の順の連署
    pub fn cosignatures(&self, hash: &Hash256) -> Vec<Cosignature> {
        self.entries.get(hash).map_or_else(Vec::new, |entry| {
            entry
                .cosignatures
                .values()
                .filter_map(|bytes| Cosignature::from_bytes(bytes).ok())
                .collect()
        })
    }

    /// 連署を署名者の順に付けたトランザクション。揃ったら、これを未承認の置き場に移す
    pub fn stitched(&self, hash: &Hash256) -> Option<Vec<u8>> {
        let mut transaction = Transaction::from_bytes(self.transaction(hash)?).ok()?;
        let Body::AggregateBonded(aggregate) = &mut transaction.body else {
            return None;
        };
        for cosignature in self.cosignatures(hash) {
            aggregate.add_cosignature(cosignature);
        }
        Some(transaction.to_bytes())
    }

    /// 外す。揃って未承認の置き場に移したもの、ブロックに入ったもの、受け付けられなくなったもの。持っていたら真
    pub fn remove(&mut self, hash: &Hash256) -> bool {
        let Some(entry) = self.entries.remove(hash) else {
            return false;
        };
        self.bytes -= entry.transaction.len();
        self.by_deadline.remove(&(entry.deadline, hash.0));
        true
    }

    /// 期限が `now` より前のものを外す。外したもののハッシュ
    pub fn prune(&mut self, now: u64) -> Vec<Hash256> {
        let expired: Vec<Hash256> = self
            .by_deadline
            .iter()
            .take_while(|(deadline, _)| *deadline < now)
            .map(|(_, hash)| Hash256(*hash))
            .collect();
        for hash in &expired {
            self.remove(hash);
        }
        expired
    }

    /// 持っているものの短いハッシュの組。ピアに頼むとき、持っているものを伝える
    pub fn short_hash_pairs(&self) -> Vec<ShortHashPair> {
        self.entries
            .iter()
            .map(|(hash, entry)| ShortHashPair {
                transaction: short_hash(hash),
                cosignatures: short_hash(&entry.cosignatures_hash()),
            })
            .collect()
    }

    /// ピアが `known`（トランザクションの短いハッシュから、連署の短いハッシュ）を持っているときに、渡すもの。
    /// 期限が `min_deadline` より前のものと、連署まで同じものは渡さない。トランザクションを知っていれば、
    /// ハッシュと連署だけを渡す。[`PartialConfig::max_response_bytes`] を超えるところで止める（catapult と同じ）
    pub fn unknown_to(
        &self,
        min_deadline: u64,
        known: &HashMap<u32, u32>,
    ) -> Vec<CosignedInfo<'_>> {
        let mut infos = Vec::new();
        let mut total = 0;
        for (deadline, hash) in self.by_deadline.range((min_deadline, [0; 32])..) {
            let hash = Hash256(*hash);
            let entry = &self.entries[&hash];
            let cosignatures_hash = short_hash(&entry.cosignatures_hash());
            let info = match known.get(&short_hash(&hash)) {
                Some(&known) if known == cosignatures_hash => continue,
                Some(_) => PartialInfo::Hash(hash),
                None => PartialInfo::Transaction(&entry.transaction),
            };
            let size = match info {
                PartialInfo::Transaction(bytes) => bytes.len(),
                PartialInfo::Hash(_) => 32,
            } + entry.cosignatures.len() * COSIGNATURE_SIZE;
            total += size;
            if total > self.config.max_response_bytes {
                break;
            }
            debug_assert!(*deadline >= min_deadline);
            infos.push(CosignedInfo {
                info,
                cosignatures: entry.cosignatures.values().collect(),
            });
        }
        infos
    }
}

/// スレッドをまたいで使う [`PartialPool`]
pub struct SharedPartialPool(Mutex<PartialPool>);

impl SharedPartialPool {
    pub fn new(pool: PartialPool) -> Self {
        Self(Mutex::new(pool))
    }

    pub fn lock(&self) -> MutexGuard<'_, PartialPool> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use heika_core::address::Address;
    use heika_core::key::PrivateKey;
    use heika_transaction::{Aggregate, EmbeddedTransaction, Transfer, UnresolvedMosaicId};

    use super::*;

    const NETWORK: &NetworkParameters = &NetworkParameters::TESTNET;
    const NOW: u64 = 1_000_000;
    const HOUR: u64 = 60 * 60 * 1000;
    /// アグリゲートのバージョン 3 が使える高さ
    const HEIGHT: u64 = 10_000_000;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte; 32])
    }

    /// `signer` が自分あてに送る転送を1つ入れた、署名したアグリゲートボンデッド。`cosigners` の連署を付ける
    fn bonded(signer: u8, deadline: u64, cosigners: &[u8]) -> (Vec<u8>, Hash256) {
        let private_key = key(signer);
        let public_key = PublicKey::from_private_key(&private_key);
        let recipient = Address::from_public_key(&public_key, NETWORK.identifier).into();
        let mosaics = BTreeMap::from([(UnresolvedMosaicId(NETWORK.currency_mosaic_id), 1)]);
        let transfer = Body::Transfer(Transfer::new(recipient, mosaics, Vec::new()).unwrap());
        let embedded = EmbeddedTransaction::new(public_key, NETWORK.identifier, transfer);
        let body = Body::AggregateBonded(Aggregate::new(vec![embedded]).unwrap());
        let mut transaction = Transaction::new(public_key, NETWORK.identifier, 0, deadline, body);
        transaction
            .sign(&private_key, &NETWORK.generation_hash_seed)
            .unwrap();
        for &cosigner in cosigners {
            transaction
                .cosign(&key(cosigner), &NETWORK.generation_hash_seed)
                .unwrap();
        }
        let hash = transaction.hash(&NETWORK.generation_hash_seed);
        (transaction.to_bytes(), hash)
    }

    fn pool() -> PartialPool {
        PartialPool::new(NETWORK, PartialConfig::default())
    }

    fn signers(pool: &PartialPool, hash: &Hash256) -> Vec<PublicKey> {
        pool.cosignatures(hash)
            .iter()
            .map(|cosignature| cosignature.signer_public_key)
            .collect()
    }

    #[test]
    fn keeps_the_transaction_without_cosignatures_and_adds_them_in_signer_order() {
        let mut pool = pool();
        let (bytes, hash) = bonded(1, NOW + HOUR, &[3, 2]);
        let added = pool.add(&bytes, NOW, HEIGHT).unwrap();
        assert_eq!(added.hash, hash);
        assert!(added.new);
        assert_eq!(added.cosignatures.len(), 2);
        let (plain, _) = bonded(1, NOW + HOUR, &[]);
        assert_eq!(pool.transaction(&hash), Some(plain.as_slice()));
        let mut expected = vec![
            PublicKey::from_private_key(&key(2)),
            PublicKey::from_private_key(&key(3)),
        ];
        expected.sort_by_key(|key| key.0);
        assert_eq!(signers(&pool, &hash), expected);

        // 同じものがまた来たら、新しい連署だけを足す
        let (more, _) = bonded(1, NOW + HOUR, &[2, 4]);
        let added = pool.add(&more, NOW, HEIGHT).unwrap();
        assert!(!added.new);
        assert_eq!(
            added
                .cosignatures
                .iter()
                .map(|c| c.signer_public_key)
                .collect::<Vec<_>>(),
            [PublicKey::from_private_key(&key(4))]
        );
        assert_eq!(pool.cosignatures(&hash).len(), 3);

        // 付けたものは、連署を署名者の順に並べた、正しいアグリゲートになる
        let stitched = Transaction::from_bytes(&pool.stitched(&hash).unwrap()).unwrap();
        assert_eq!(stitched.hash(&NETWORK.generation_hash_seed), hash);
        assert!(stitched.verify_cosignatures(&NETWORK.generation_hash_seed));
    }

    #[test]
    fn takes_detached_cosignatures_once() {
        let mut pool = pool();
        let (bytes, hash) = bonded(1, NOW + HOUR, &[]);
        pool.add(&bytes, NOW, HEIGHT).unwrap();
        let cosign = |signer: u8, parent: &Hash256| DetachedCosignature::sign(&key(signer), parent);
        assert_eq!(pool.add_cosignature(&cosign(2, &hash)), Ok(()));
        assert_eq!(
            pool.add_cosignature(&cosign(2, &hash)),
            Err(CosignRejected::Redundant)
        );
        // 外側の署名者は連署しない
        assert_eq!(
            pool.add_cosignature(&cosign(1, &hash)),
            Err(CosignRejected::Redundant)
        );
        assert_eq!(
            pool.add_cosignature(&cosign(2, &Hash256([9; 32]))),
            Err(CosignRejected::UnknownParent)
        );
        let mut forged = cosign(3, &hash);
        forged.cosignature.signature.0[0] ^= 1;
        assert_eq!(
            pool.add_cosignature(&forged),
            Err(CosignRejected::InvalidSignature)
        );
        assert!(pool.remove_cosignature(&hash, &PublicKey::from_private_key(&key(2))));
        assert!(pool.cosignatures(&hash).is_empty());
    }

    #[test]
    fn refuses_what_it_cannot_keep() {
        let mut pool = pool();
        let (expired, _) = bonded(1, NOW - 1, &[]);
        assert!(matches!(
            pool.add(&expired, NOW, HEIGHT),
            Err(PartialRejected::Expired)
        ));
        let (far, _) = bonded(1, NOW + 49 * HOUR, &[]);
        assert!(matches!(
            pool.add(&far, NOW, HEIGHT),
            Err(PartialRejected::TooFarAhead)
        ));
        let (mut forged, _) = bonded(1, NOW + HOUR, &[]);
        forged[10] ^= 1;
        assert!(matches!(
            pool.add(&forged, NOW, HEIGHT),
            Err(PartialRejected::Invalid(_))
        ));
        let mut small = PartialPool::new(
            NETWORK,
            PartialConfig {
                max_bytes: 10,
                ..PartialConfig::default()
            },
        );
        let (bytes, _) = bonded(1, NOW + HOUR, &[]);
        assert!(matches!(
            small.add(&bytes, NOW, HEIGHT),
            Err(PartialRejected::Full)
        ));
    }

    #[test]
    fn answers_peers_with_what_they_lack_and_prunes_expired() {
        let mut pool = pool();
        let (first, first_hash) = bonded(1, NOW + HOUR, &[2]);
        let (second, second_hash) = bonded(3, NOW + 2 * HOUR, &[]);
        pool.add(&first, NOW, HEIGHT).unwrap();
        pool.add(&second, NOW, HEIGHT).unwrap();

        // 何も知らないピアには、両方を連署付きで
        let infos = pool.unknown_to(0, &HashMap::new());
        assert_eq!(infos.len(), 2);
        assert!(matches!(infos[0].info, PartialInfo::Transaction(_)));
        assert_eq!(infos[0].cosignatures.len(), 1);

        // 同じものを持っているピアには何も渡さず、連署が違えばハッシュと連署だけ
        let pairs = pool.short_hash_pairs();
        let mut known: HashMap<u32, u32> = pairs
            .iter()
            .map(|pair| (pair.transaction, pair.cosignatures))
            .collect();
        assert!(pool.unknown_to(0, &known).is_empty());
        known.insert(short_hash(&first_hash), 0);
        let infos = pool.unknown_to(0, &known);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].info, PartialInfo::Hash(first_hash));

        // 期限の下限より前のものは渡さない
        assert_eq!(pool.unknown_to(NOW + HOUR + 1, &HashMap::new()).len(), 1);

        assert_eq!(pool.prune(NOW + HOUR + 1), vec![first_hash]);
        assert!(pool.contains(&second_hash));
        assert!(pool.remove(&second_hash));
        assert!(pool.is_empty());
        assert_eq!(pool.bytes, 0);
    }
}
