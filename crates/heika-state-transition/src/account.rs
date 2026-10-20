//! アカウントの状態。catapult の `state/AccountState.h` と、葉にするバイト列の `AccountStateNonHistoricalSerializer`。

use std::collections::BTreeMap;

/// アカウントの種類。catapult の `AccountType`。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AccountType {
    #[default]
    Unlinked = 0,
    Main = 1,
    Remote = 2,
    RemoteUnlinked = 3,
}

/// importance の記録。catapult の `AccountImportanceSnapshots::ImportanceSnapshot`。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Snapshot {
    pub importance: u64,
    pub height: u64,
}

/// 活動の記録。catapult の `AccountActivityBuckets::ActivityBucket`。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Bucket {
    pub start_height: u64,
    pub total_fees_paid: u64,
    pub beneficiary_count: u32,
    pub raw_score: u64,
}

/// importance の記録の数（catapult の `Importance_History_Size`）
pub const SNAPSHOTS: usize = 3;
/// 活動の記録の数（`Activity_Bucket_History_Size`）
pub const BUCKETS: usize = 7;
/// 巻き戻しのために持っておく数（`Rollback_Buffer_Size`）。葉には書かない
const ROLLBACK_BUFFER: usize = 2;

/// 投票の鍵と、使えるエポックの範囲
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VotingKey {
    pub key: [u8; 32],
    pub start_epoch: u32,
    pub end_epoch: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountState {
    pub address: [u8; 24],
    pub address_height: u64,
    pub public_key: [u8; 32],
    /// 公開鍵が分かった高さ。まだなら 0
    pub public_key_height: u64,
    pub account_type: AccountType,
    pub linked: Option<[u8; 32]>,
    pub node: Option<[u8; 32]>,
    pub vrf: Option<[u8; 32]>,
    /// エポックの順
    pub voting: Vec<VotingKey>,
    /// 新しいものが先
    pub snapshots: [Snapshot; SNAPSHOTS],
    /// 新しいものが先
    pub buckets: [Bucket; BUCKETS],
    /// 残高が 0 のモザイクは持たない
    pub balances: BTreeMap<u64, u64>,
}

impl AccountState {
    pub fn new(address: [u8; 24], height: u64) -> Self {
        Self {
            address,
            address_height: height,
            public_key: [0; 32],
            public_key_height: 0,
            account_type: AccountType::Unlinked,
            linked: None,
            node: None,
            vrf: None,
            voting: Vec::new(),
            snapshots: [Snapshot::default(); SNAPSHOTS],
            buckets: [Bucket::default(); BUCKETS],
            balances: BTreeMap::new(),
        }
    }

    pub fn balance(&self, mosaic_id: u64) -> u64 {
        self.balances.get(&mosaic_id).copied().unwrap_or(0)
    }

    /// catapult の `AccountBalances::credit`。0 なら何もしない
    pub fn credit(&mut self, mosaic_id: u64, amount: u64) {
        if amount > 0 {
            *self.balances.entry(mosaic_id).or_default() += amount;
        }
    }

    /// catapult の `AccountBalances::debit`。0 になったモザイクは消す。足りなければ `false`
    #[must_use]
    pub fn debit(&mut self, mosaic_id: u64, amount: u64) -> bool {
        if amount == 0 {
            return true;
        }
        let Some(balance) = self.balances.get_mut(&mosaic_id) else {
            return false;
        };
        let Some(rest) = balance.checked_sub(amount) else {
            return false;
        };
        *balance = rest;
        if rest == 0 {
            self.balances.remove(&mosaic_id);
        }
        true
    }

    /// importance の記録が今あるか。catapult の `AccountImportanceSnapshots::active`。葉の形が変わる
    pub fn is_high_value_format(&self) -> bool {
        self.snapshots[0].height != 0
    }

    /// 履歴が残っているか。catapult の `HasHistoricalInformation`
    pub fn has_history(&self) -> bool {
        self.snapshots.iter().any(|snapshot| snapshot.height != 0)
            || self.buckets.iter().any(|bucket| bucket.start_height != 0)
    }

    pub fn push_snapshot(&mut self, snapshot: Snapshot) {
        self.snapshots.rotate_right(1);
        self.snapshots[0] = snapshot;
    }

    pub fn push_bucket(&mut self, bucket: Bucket) {
        self.buckets.rotate_right(1);
        self.buckets[0] = bucket;
    }

    pub fn pop_bucket(&mut self) {
        self.buckets.rotate_left(1);
        self.buckets[BUCKETS - 1] = Bucket::default();
    }

    /// いちばん新しい記録が `height` のものなら、それを変える。catapult の `AccountActivityBuckets::tryUpdate`
    pub fn try_update_bucket(&mut self, height: u64, update: impl FnOnce(&mut Bucket)) {
        if self.buckets[0].start_height == height {
            update(&mut self.buckets[0]);
        }
    }

    /// 葉にするバイト列。状態のバージョン（1）から始める。`currency` のモザイクを先に、ほかは ID の順に並べる
    pub fn to_state_bytes(&self, currency: u64) -> Vec<u8> {
        let mut out = 1u16.to_le_bytes().to_vec();
        out.extend_from_slice(&self.address);
        out.extend_from_slice(&self.address_height.to_le_bytes());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.public_key_height.to_le_bytes());
        out.push(self.account_type as u8);
        let high_value = self.is_high_value_format();
        out.push(u8::from(high_value));
        let mut mask = 0;
        for (key, bit) in [(&self.linked, 1), (&self.node, 2), (&self.vrf, 4)] {
            if key.is_some() {
                mask |= bit;
            }
        }
        out.push(mask);
        out.push(self.voting.len() as u8);
        for key in [&self.linked, &self.node, &self.vrf].into_iter().flatten() {
            out.extend_from_slice(key);
        }
        for voting in &self.voting {
            out.extend_from_slice(&voting.key);
            out.extend_from_slice(&voting.start_epoch.to_le_bytes());
            out.extend_from_slice(&voting.end_epoch.to_le_bytes());
        }
        if high_value {
            for snapshot in &self.snapshots[..SNAPSHOTS - ROLLBACK_BUFFER] {
                out.extend_from_slice(&snapshot.importance.to_le_bytes());
                out.extend_from_slice(&snapshot.height.to_le_bytes());
            }
            for bucket in &self.buckets[..BUCKETS - ROLLBACK_BUFFER] {
                out.extend_from_slice(&bucket.start_height.to_le_bytes());
                out.extend_from_slice(&bucket.total_fees_paid.to_le_bytes());
                out.extend_from_slice(&bucket.beneficiary_count.to_le_bytes());
                out.extend_from_slice(&bucket.raw_score.to_le_bytes());
            }
        }
        let mut mosaics: Vec<_> = self.balances.iter().collect();
        mosaics.sort_by_key(|(id, _)| (**id != currency, **id));
        out.extend_from_slice(&(mosaics.len() as u16).to_le_bytes());
        for (id, amount) in mosaics {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&amount.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balances_drop_empty_mosaics_and_refuse_overdrafts() {
        let mut account = AccountState::new([1; 24], 1);
        account.credit(7, 0);
        assert!(account.balances.is_empty());
        account.credit(7, 10);
        assert!(!account.debit(7, 11));
        assert!(!account.debit(8, 1));
        assert!(account.debit(7, 0));
        assert!(account.debit(7, 10));
        assert!(account.balances.is_empty());
    }

    #[test]
    fn state_bytes_put_the_currency_first() {
        let mut account = AccountState::new([1; 24], 2);
        for id in [3, 9, 5] {
            account.credit(id, id * 100);
        }
        let bytes = account.to_state_bytes(9);
        // 版 2、アドレス 24、高さ 8、公開鍵 32、高さ 8、種類 1、形 1、鍵の印 1、投票の鍵の数 1、モザイクの数 2
        let mosaics = &bytes[2 + 24 + 8 + 32 + 8 + 4..];
        assert_eq!(&mosaics[..2], &3u16.to_le_bytes());
        let ids: Vec<u64> = mosaics[2..]
            .chunks(16)
            .map(|pair| u64::from_le_bytes(pair[..8].try_into().unwrap()))
            .collect();
        assert_eq!(ids, [9, 3, 5]);
        // importance の記録がなければ、履歴は書かない
        assert!(!account.is_high_value_format());
        assert_eq!(mosaics.len(), 2 + 3 * 16);
    }
}
