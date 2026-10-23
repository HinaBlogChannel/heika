//! 未承認のトランザクションの置き場（catapult の UT キャッシュ）。IO は持たない（sans-IO）。
//!
//! 受け付けるときは、状態に依らないことだけを確かめる（署名、連署、トランザクションごとの規則、期限、手数料）。
//! 残高が足りるかなど状態に依ることは確かめず、ブロックを作ってみて弾かれたものを [`Mempool::remove`] で外す。
//! 状態の写しは持たない。
//!
//! 連署を待つアグリゲートボンデッド（catapult の PT キャッシュ）は、別の置き場（[`partial`]）で待たせ、連署が
//! 揃ってからここに移す。ここに直接来たものは受け付けない。

pub mod partial;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use heika_chain::produce::{Candidate, Pending};
use heika_chain::verify::VerifyError;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_packet::short_hash;
use heika_transaction::{Body, Transaction};

/// 運用者が選ぶ上限
#[derive(Clone, Debug)]
pub struct Config {
    /// 持っておくバイト数の上限（`unconfirmedTransactionsCacheMaxSize`）
    pub max_bytes: usize,
    /// `Pull_Transactions` に答えるバイト数の上限（`unconfirmedTransactionsCacheMaxResponseSize`）
    pub max_response_bytes: usize,
    /// これより低い手数料の倍率（最大手数料を大きさで割ったもの）は受け付けない（`minFeeMultiplier`）
    pub min_fee_multiplier: u32,
    /// 1つの署名者から持っておく数の上限。catapult にはない、heika の荒らし除け
    pub max_per_signer: usize,
}

impl Default for Config {
    /// catapult の `config-node.properties` の既定値に合わせる。`max_per_signer` は heika が決めたもの
    fn default() -> Self {
        Self {
            max_bytes: 20 * 1024 * 1024,
            max_response_bytes: 5 * 1024 * 1024,
            min_fee_multiplier: 0,
            max_per_signer: 100,
        }
    }
}

/// 受け付けなかったわけ
#[derive(Debug)]
pub enum Rejected {
    /// トランザクションとして読めない
    Malformed(String),
    /// もう持っている
    Known,
    /// アグリゲートボンデッドは扱わない
    Bonded,
    /// 期限が過ぎている
    Expired,
    /// 期限が、今から `maxTransactionLifetime` より先
    TooFarAhead,
    /// 手数料の倍率が、受け付ける下限より低い
    LowFee(u32),
    /// 署名、連署、規則のどれかが通らない
    Invalid(VerifyError),
    /// 同じ署名者のものを、もう上限まで持っている
    TooManyFromSigner,
    /// いっぱいで、追い出せるほど手数料の低いものもない
    Full,
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "トランザクションとして読めません: {error}"),
            Self::Known => write!(f, "もう持っています"),
            Self::Bonded => write!(f, "アグリゲートボンデッドは扱いません"),
            Self::Expired => write!(f, "期限が過ぎています"),
            Self::TooFarAhead => write!(f, "期限が先すぎます"),
            Self::LowFee(fee_multiplier) => {
                write!(f, "手数料の倍率 {fee_multiplier} は下限より低いです")
            }
            Self::Invalid(error) => write!(f, "確かめが通りません: {error}"),
            Self::TooManyFromSigner => write!(f, "同じ署名者のものが多すぎます"),
            Self::Full => write!(f, "いっぱいです"),
        }
    }
}

impl std::error::Error for Rejected {}

struct Entry {
    candidate: Candidate,
    /// Nemesis からのミリ秒
    deadline: u64,
    signer: PublicKey,
    /// 受け付けた順
    order: u64,
}

/// 未承認のトランザクションの置き場
pub struct Mempool {
    parameters: &'static NetworkParameters,
    config: Config,
    entries: HashMap<Hash256, Entry>,
    /// 追い出す順。手数料の倍率の低いものから、同じなら新しいものから。先に来たものを、同じ手数料で押し出させない
    by_eviction: BTreeSet<(u32, std::cmp::Reverse<u64>, [u8; 32])>,
    /// 期限の早い順。期限切れを掃除するのに使う
    by_deadline: BTreeSet<(u64, [u8; 32])>,
    /// 受け付けた順。`Pull_Transactions` には古いものから答える
    by_order: BTreeMap<u64, Hash256>,
    per_signer: HashMap<PublicKey, usize>,
    bytes: usize,
    next_order: u64,
}

impl Mempool {
    pub fn new(parameters: &'static NetworkParameters, config: Config) -> Self {
        Self {
            parameters,
            config,
            entries: HashMap::new(),
            by_eviction: BTreeSet::new(),
            by_deadline: BTreeSet::new(),
            by_order: BTreeMap::new(),
            per_signer: HashMap::new(),
            bytes: 0,
            next_order: 0,
        }
    }

    /// 持っている数
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 持っているバイト数
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn contains(&self, hash: &Hash256) -> bool {
        self.entries.contains_key(hash)
    }

    /// 持っているものの短いハッシュ（[`short_hash`]）。ピアに `Pull_Transactions` で頼むとき、持っているものを伝える
    pub fn short_hashes(&self) -> Vec<u32> {
        self.entries.keys().map(short_hash).collect()
    }

    /// 受け付ける手数料の倍率の下限。ピアに頼むときも、これより低いものは要らないと伝える
    pub fn min_fee_multiplier(&self) -> u32 {
        self.config.min_fee_multiplier
    }

    /// 持っていれば、その期限（Nemesis からのミリ秒）
    pub fn deadline(&self, hash: &Hash256) -> Option<u64> {
        self.entries.get(hash).map(|entry| entry.deadline)
    }

    /// 署名したトランザクション `bytes` を、今（Nemesis からのミリ秒 `now`）、高さ `height` のブロックに入れる
    /// つもりで受け付ける。いっぱいなら、手数料の倍率がこれより低いものを追い出して空ける。受け付けたらハッシュを返す
    pub fn add(&mut self, bytes: Vec<u8>, now: u64, height: u64) -> Result<Hash256, Rejected> {
        let transaction = Transaction::from_bytes(&bytes)
            .map_err(|error| Rejected::Malformed(error.to_string()))?;
        // 署名を確かめるのは重いので、安く弾けるものを先に弾く
        let hash = transaction.hash(&self.parameters.generation_hash_seed);
        if self.entries.contains_key(&hash) {
            return Err(Rejected::Known);
        }
        if matches!(transaction.body, Body::AggregateBonded(_)) {
            return Err(Rejected::Bonded);
        }
        // catapult の `DeadlineValidator` と同じく、今からの範囲に入っていること
        if transaction.deadline < now {
            return Err(Rejected::Expired);
        }
        let lifetime =
            u64::try_from(self.parameters.max_transaction_lifetime.as_millis()).unwrap_or(u64::MAX);
        if transaction.deadline > now.saturating_add(lifetime) {
            return Err(Rejected::TooFarAhead);
        }
        let fee_multiplier =
            u32::try_from(transaction.fee / bytes.len() as u64).unwrap_or(u32::MAX);
        if fee_multiplier < self.config.min_fee_multiplier {
            return Err(Rejected::LowFee(fee_multiplier));
        }
        let signer = transaction.signer_public_key;
        if self.per_signer.get(&signer).copied().unwrap_or(0) >= self.config.max_per_signer {
            return Err(Rejected::TooManyFromSigner);
        }
        let evicted = self.to_evict(bytes.len(), fee_multiplier)?;
        let candidate =
            Candidate::new(self.parameters, height, bytes).map_err(Rejected::Invalid)?;
        for hash in evicted {
            self.remove(&hash);
        }
        self.insert(hash, candidate, transaction.deadline, signer);
        Ok(hash)
    }

    /// `size` バイトを、手数料の倍率 `fee_multiplier` のもので空けるのに追い出すもの。空けられなければ `Full`
    fn to_evict(&self, size: usize, fee_multiplier: u32) -> Result<Vec<Hash256>, Rejected> {
        let mut bytes = self.bytes;
        let mut evicted = Vec::new();
        let mut lowest = self.by_eviction.iter();
        while bytes + size > self.config.max_bytes {
            let Some(&(lower, _, hash)) = lowest.next() else {
                return Err(Rejected::Full);
            };
            if lower >= fee_multiplier {
                return Err(Rejected::Full);
            }
            let hash = Hash256(hash);
            bytes -= self.entries[&hash].candidate.bytes.len();
            evicted.push(hash);
        }
        Ok(evicted)
    }

    fn insert(&mut self, hash: Hash256, candidate: Candidate, deadline: u64, signer: PublicKey) {
        let order = self.next_order;
        self.next_order += 1;
        self.bytes += candidate.bytes.len();
        self.by_eviction
            .insert((candidate.fee_multiplier, std::cmp::Reverse(order), hash.0));
        self.by_deadline.insert((deadline, hash.0));
        self.by_order.insert(order, hash);
        *self.per_signer.entry(signer).or_default() += 1;
        self.entries.insert(
            hash,
            Entry {
                candidate,
                deadline,
                signer,
                order,
            },
        );
    }

    /// 外す。ブロックに入ったもの、作ってみて弾かれたものなど。持っていたら真
    pub fn remove(&mut self, hash: &Hash256) -> bool {
        let Some(entry) = self.entries.remove(hash) else {
            return false;
        };
        self.bytes -= entry.candidate.bytes.len();
        self.by_eviction.remove(&(
            entry.candidate.fee_multiplier,
            std::cmp::Reverse(entry.order),
            hash.0,
        ));
        self.by_deadline.remove(&(entry.deadline, hash.0));
        self.by_order.remove(&entry.order);
        if let Some(count) = self.per_signer.get_mut(&entry.signer) {
            *count -= 1;
            if *count == 0 {
                self.per_signer.remove(&entry.signer);
            }
        }
        true
    }

    /// 先端が変わった。新しい先端の枝に入ったトランザクション `included` を外し、巻き戻した枝から外れたもの
    /// `restored` を受け付け直し、期限の過ぎたものを掃除する。`now` と `height` は [`Mempool::add`] と同じ
    pub fn tip_changed(
        &mut self,
        included: &[Hash256],
        restored: Vec<Vec<u8>>,
        now: u64,
        height: u64,
    ) {
        for hash in included {
            self.remove(hash);
        }
        for bytes in restored {
            // 新しい枝にもう入っていたり、期限が過ぎていたりしたものは、受け付けないだけでよい
            let _ = self.add(bytes, now, height);
        }
        self.prune(now);
    }

    /// 期限が `now` より前のものを外す
    pub fn prune(&mut self, now: u64) {
        let expired: Vec<Hash256> = self
            .by_deadline
            .iter()
            .take_while(|&&(deadline, _)| deadline < now)
            .map(|&(_, hash)| Hash256(hash))
            .collect();
        for hash in expired {
            self.remove(&hash);
        }
    }

    /// 時刻 `timestamp` のブロックに入れられる候補。選ぶのは [`heika_chain::produce::choose`]
    pub fn candidates(&self, timestamp: u64) -> Vec<Candidate> {
        self.entries
            .values()
            .filter(|entry| entry.deadline >= timestamp)
            .map(|entry| entry.candidate.clone())
            .collect()
    }

    /// `Pull_Transactions` への答え（catapult の `unknownTransactions`）。期限が `min_deadline` 以上で、手数料の倍率が
    /// `min_fee_multiplier` 以上で、短いハッシュが `known` にないものを、受け付けた順に。合わせて
    /// `max_response_bytes` を超えるところで打ち切る
    pub fn pull(
        &self,
        min_deadline: u64,
        min_fee_multiplier: u32,
        known: &HashSet<u32>,
    ) -> Vec<&[u8]> {
        let mut total = 0;
        let mut answer = Vec::new();
        for hash in self.by_order.values() {
            let entry = &self.entries[hash];
            if entry.deadline < min_deadline
                || entry.candidate.fee_multiplier < min_fee_multiplier
                || known.contains(&short_hash(hash))
            {
                continue;
            }
            total += entry.candidate.bytes.len();
            if total > self.config.max_response_bytes {
                break;
            }
            answer.push(entry.candidate.bytes.as_slice());
        }
        answer
    }
}

/// スレッドをまたいで使う [`Mempool`]。待ち受けのスレッドが受け付け、駆動役が先端の変化を伝え、中核が候補をもらう
pub struct SharedMempool(Mutex<Mempool>);

impl SharedMempool {
    pub fn new(mempool: Mempool) -> Self {
        Self(Mutex::new(mempool))
    }

    pub fn lock(&self) -> MutexGuard<'_, Mempool> {
        // 持ち主が途中で落ちても、置き場は捨てて困るものではないので使い続ける
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Pending for SharedMempool {
    fn candidates(&self, timestamp: u64) -> Vec<Candidate> {
        self.lock().candidates(timestamp)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use heika_core::address::Address;
    use heika_core::key::PrivateKey;
    use heika_transaction::{Aggregate, Transfer, UnresolvedMosaicId};

    use super::*;

    const NETWORK: &NetworkParameters = &NetworkParameters::TESTNET;
    const NOW: u64 = 1_000_000;
    const HOUR: u64 = 60 * 60 * 1000;

    /// `key` の鍵で、自分あてに `message` を付けて送る転送。大きさを変えたいときは `message` を長くする
    fn transfer(key: u8, fee: u64, deadline: u64, message: &[u8]) -> Vec<u8> {
        let private_key = PrivateKey::from_bytes(&[key; 32]);
        let public_key = PublicKey::from_private_key(&private_key);
        let recipient = Address::from_public_key(&public_key, NETWORK.identifier).into();
        let mosaics = BTreeMap::from([(UnresolvedMosaicId(NETWORK.currency_mosaic_id), 1)]);
        let body = Body::Transfer(Transfer::new(recipient, mosaics, message.to_vec()).unwrap());
        let mut transaction = Transaction::new(public_key, NETWORK.identifier, fee, deadline, body);
        transaction
            .sign(&private_key, &NETWORK.generation_hash_seed)
            .unwrap();
        transaction.to_bytes()
    }

    fn mempool(config: Config) -> Mempool {
        Mempool::new(NETWORK, config)
    }

    #[test]
    fn accepts_once_and_forgets_on_remove() {
        let mut pool = mempool(Config::default());
        let bytes = transfer(1, 0, NOW + HOUR, b"");
        let hash = pool.add(bytes.clone(), NOW, 2).unwrap();
        assert!(pool.contains(&hash));
        assert_eq!(pool.bytes(), bytes.len());
        assert!(matches!(pool.add(bytes, NOW, 2), Err(Rejected::Known)));
        assert!(pool.remove(&hash));
        assert!(!pool.remove(&hash));
        assert!(pool.is_empty());
        assert_eq!(pool.bytes(), 0);
    }

    #[test]
    fn rejects_by_deadline_fee_and_signature() {
        let mut pool = mempool(Config {
            min_fee_multiplier: 10,
            ..Config::default()
        });
        let size = transfer(1, 0, NOW, b"").len() as u64;
        let fee = 10 * size;
        assert!(matches!(
            pool.add(transfer(1, fee, NOW - 1, b""), NOW, 2),
            Err(Rejected::Expired)
        ));
        assert!(matches!(
            pool.add(transfer(1, fee, NOW + 6 * HOUR + 1, b""), NOW, 2),
            Err(Rejected::TooFarAhead)
        ));
        assert!(matches!(
            pool.add(transfer(1, fee - 1, NOW + HOUR, b""), NOW, 2),
            Err(Rejected::LowFee(9))
        ));
        let mut tampered = transfer(1, fee, NOW + HOUR, b"");
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            pool.add(tampered, NOW, 2),
            Err(Rejected::Invalid(_))
        ));
        // 期限はちょうど今から、ちょうど寿命の端まで受け付ける
        pool.add(transfer(1, fee, NOW, b""), NOW, 2).unwrap();
        pool.add(transfer(1, fee, NOW + 6 * HOUR, b""), NOW, 2)
            .unwrap();
    }

    #[test]
    fn limits_the_count_per_signer() {
        let mut pool = mempool(Config {
            max_per_signer: 2,
            ..Config::default()
        });
        let first = pool.add(transfer(1, 0, NOW + 1, b""), NOW, 2).unwrap();
        pool.add(transfer(1, 0, NOW + 2, b""), NOW, 2).unwrap();
        assert!(matches!(
            pool.add(transfer(1, 0, NOW + 3, b""), NOW, 2),
            Err(Rejected::TooManyFromSigner)
        ));
        pool.add(transfer(2, 0, NOW + 3, b""), NOW, 2).unwrap();
        pool.remove(&first);
        pool.add(transfer(1, 0, NOW + 3, b""), NOW, 2).unwrap();
    }

    #[test]
    fn evicts_lower_fees_newest_first_when_full() {
        let size = transfer(1, 0, NOW + 1, b"").len();
        let mut pool = mempool(Config {
            max_bytes: 3 * size,
            ..Config::default()
        });
        let fee = |multiplier: u64| multiplier * size as u64;
        let old_low = pool.add(transfer(1, fee(1), NOW + 1, b""), NOW, 2).unwrap();
        let new_low = pool.add(transfer(2, fee(1), NOW + 1, b""), NOW, 2).unwrap();
        let high = pool.add(transfer(3, fee(5), NOW + 1, b""), NOW, 2).unwrap();
        // 同じ倍率では押し出せない
        assert!(matches!(
            pool.add(transfer(4, fee(1), NOW + 1, b""), NOW, 2),
            Err(Rejected::Full)
        ));
        // 高ければ、低いうちの新しいほうを押し出す
        let newer = pool.add(transfer(4, fee(2), NOW + 1, b""), NOW, 2).unwrap();
        assert!(!pool.contains(&new_low));
        assert!(pool.contains(&old_low) && pool.contains(&high) && pool.contains(&newer));
        assert_eq!(pool.bytes(), 3 * size);
        // 2つ分の大きさなら、低いものから2つ押し出す
        let big = transfer(5, fee(3) * 2, NOW + 1, &vec![0; size]);
        assert_eq!(big.len(), 2 * size);
        pool.add(big, NOW, 2).unwrap();
        assert!(!pool.contains(&old_low) && !pool.contains(&newer));
        assert!(pool.contains(&high));
    }

    #[test]
    fn rejects_bonded_aggregates() {
        // 署名を確かめる前に弾くので、署名はしない
        let mut pool = mempool(Config::default());
        let private_key = PrivateKey::from_bytes(&[1; 32]);
        let public_key = PublicKey::from_private_key(&private_key);
        let bonded = Body::AggregateBonded(Aggregate::new(Vec::new()).unwrap());
        let transaction = Transaction::new(public_key, NETWORK.identifier, 0, NOW + 1, bonded);
        assert!(matches!(
            pool.add(transaction.to_bytes(), NOW, 2),
            Err(Rejected::Bonded)
        ));
    }

    #[test]
    fn tip_change_removes_included_restores_rolled_back_and_prunes() {
        let mut pool = mempool(Config::default());
        let included = pool.add(transfer(1, 0, NOW + HOUR, b""), NOW, 2).unwrap();
        let expiring = pool.add(transfer(2, 0, NOW + 10, b""), NOW, 2).unwrap();
        let rolled_back = transfer(3, 0, NOW + HOUR, b"");
        pool.tip_changed(&[included], vec![rolled_back.clone()], NOW + 11, 3);
        assert!(!pool.contains(&included));
        assert!(!pool.contains(&expiring));
        let restored = Transaction::from_bytes(&rolled_back)
            .unwrap()
            .hash(&NETWORK.generation_hash_seed);
        assert!(pool.contains(&restored));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn candidates_skip_ones_expiring_before_the_block() {
        let mut pool = mempool(Config::default());
        pool.add(transfer(1, 0, NOW + 10, b""), NOW, 2).unwrap();
        let late = pool.add(transfer(2, 0, NOW + HOUR, b""), NOW, 2).unwrap();
        let candidates = pool.candidates(NOW + 11);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].hash(), late);
    }

    #[test]
    fn pull_answers_unknown_ones_in_order_within_the_limits() {
        let size = transfer(1, 0, NOW + 1, b"").len();
        let mut pool = mempool(Config {
            max_response_bytes: 2 * size,
            ..Config::default()
        });
        let first = transfer(1, 0, NOW + HOUR, b"");
        let second = transfer(2, 5 * size as u64, NOW + HOUR, b"");
        let early = transfer(3, 5 * size as u64, NOW + 10, b"");
        let fourth = transfer(4, 5 * size as u64, NOW + HOUR, b"");
        let fifth = transfer(5, 5 * size as u64, NOW + HOUR, b"");
        for bytes in [&first, &second, &early, &fourth, &fifth] {
            pool.add(bytes.clone(), NOW, 2).unwrap();
        }
        let none = HashSet::new();
        // 受け付けた順に、上限で打ち切る
        assert_eq!(pool.pull(0, 0, &none), [&first[..], &second[..]]);
        // 期限と手数料で絞る
        assert_eq!(pool.pull(NOW + 11, 1, &none), [&second[..], &fourth[..]]);
        // 知っているものは飛ばす
        let seed = &NETWORK.generation_hash_seed;
        let known = HashSet::from([short_hash(
            &Transaction::from_bytes(&second).unwrap().hash(seed),
        )]);
        assert_eq!(pool.pull(NOW + 11, 1, &known), [&fourth[..], &fifth[..]]);
    }
}
