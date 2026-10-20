//! 状態の表。全部をメモリに持つか、読み込んだキーだけを持つ。
//!
//! 読み込んだキーだけを持つときは、キーごとに「値がある」「本当にない（読んだらなかった）」「まだ読んでいない」を
//! 区別する。まだ読んでいないキーを引かれたら、そのキーを記録して、ないものとして答える。記録があった実行は捨てて、
//! 記録されたキーを読み込んでから当て直す。ブロックをまたいで持っておくか捨てるかは、表ではなく、状態の読み口の
//! 側で決める。

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Index;
use std::sync::Mutex;

pub struct Table<K, V> {
    rows: BTreeMap<K, V>,
    /// 全部をメモリに持っているか。持っていなければ、`rows` にも `absent` にもないキーは、まだ読んでいない
    complete: bool,
    /// 読んだらなかったキー
    absent: BTreeSet<K>,
    /// まだ読んでいないのに引かれたキー。並列に葉を求めるところからも記録するので、ロックで守る
    missed: Mutex<BTreeSet<K>>,
}

impl<K: Ord + Copy, V> Table<K, V> {
    /// 全部をメモリに持つ表
    pub fn complete() -> Self {
        Self::new(true)
    }

    /// 読み込んだキーだけを持つ表
    pub fn partial() -> Self {
        Self::new(false)
    }

    fn new(complete: bool) -> Self {
        Self {
            rows: BTreeMap::new(),
            complete,
            absent: BTreeSet::new(),
            missed: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// 値があるか、ないことを知っているか
    pub fn is_loaded(&self, key: &K) -> bool {
        self.complete || self.rows.contains_key(key) || self.absent.contains(key)
    }

    /// 読み込んだ値を入れる。`None` は、読んだらなかった（全部をメモリに持つ表では、ただ消す）
    pub fn load(&mut self, key: K, value: Option<V>) {
        match value {
            Some(value) => {
                self.absent.remove(&key);
                self.rows.insert(key, value);
            }
            None => {
                self.rows.remove(&key);
                if !self.complete {
                    self.absent.insert(key);
                }
            }
        }
    }

    fn note(&self, key: &K) {
        if !self.is_loaded(key) {
            self.missed.lock().expect("not poisoned").insert(*key);
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let value = self.rows.get(key);
        if value.is_none() {
            self.note(key);
        }
        value
    }

    /// 引いたことにせずに見る。まだ読んでいないキーでも記録しない
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.rows.get(key)
    }

    /// 読み込んだものを捨てて、まだ読んでいないことにする
    pub fn forget(&mut self, key: &K) {
        if !self.complete {
            self.rows.remove(key);
            self.absent.remove(key);
        }
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if !self.rows.contains_key(key) {
            self.note(key);
        }
        self.rows.get_mut(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// なければ `make` で作って入れる。まだ読んでいないキーなら、記録したうえで作る（その実行は捨てる）
    pub fn get_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> &mut V {
        self.note(&key);
        self.absent.remove(&key);
        self.rows.entry(key).or_insert_with(make)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.absent.remove(&key);
        self.rows.insert(key, value)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.note(key);
        if !self.complete {
            self.absent.insert(*key);
        }
        self.rows.remove(key)
    }

    /// 持っている値。全部をメモリに持っていなければ、読み込んだものだけ
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.rows.iter()
    }

    /// 持っているキー。全部をメモリに持っていなければ、読み込んだものだけ
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.rows.keys()
    }

    /// まだ読んでいないのに引かれたキーを受け取る
    pub fn take_missed(&mut self) -> BTreeSet<K> {
        std::mem::take(self.missed.get_mut().expect("not poisoned"))
    }
}

impl<K: Ord + Copy, V> Index<&K> for Table<K, V> {
    type Output = V;

    /// なければ落ちる。まだ読んでいないキーなら記録してから落ちるので、呼ぶ側で先に読み込んでおく
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("the key is in the table")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_table_never_misses() {
        let mut table: Table<u8, &str> = Table::complete();
        table.insert(1, "a");
        assert_eq!(table.get(&1), Some(&"a"));
        assert_eq!(table.get(&2), None);
        assert!(table.take_missed().is_empty());
    }

    #[test]
    fn a_partial_table_tells_absent_from_not_loaded() {
        let mut table: Table<u8, &str> = Table::partial();
        table.load(1, Some("a"));
        table.load(2, None);
        assert_eq!(table.get(&1), Some(&"a"));
        // 読んだらなかった
        assert_eq!(table.get(&2), None);
        assert!(table.take_missed().is_empty());
        // まだ読んでいない
        assert_eq!(table.get(&3), None);
        assert!(!table.contains_key(&4));
        *table.get_or_insert_with(5, || "new") = "made";
        assert_eq!(table.take_missed(), BTreeSet::from([3, 4, 5]));
        // ないと知っているキーに作るのは、記録しない
        table.get_or_insert_with(2, || "b");
        assert!(table.take_missed().is_empty());
        assert_eq!(table.get(&2), Some(&"b"));
    }
}
