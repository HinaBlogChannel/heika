//! メモリにない状態を読む口。ブロックを当てる前と、当てて足りなかったときに、キーを指定して読むので同期にする
//! （ブラウザでは、OPFS を専用の Worker から同期で使う前提）。

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use super::ExecError;

/// 今の状態の行と木のノードを読む口
pub trait StateSource {
    /// 状態の行 `key`（[`super::persist::row_key`]）。なければ `None`
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError>;
    /// 木のノード `key`（[`crate::tree::node_key`]）。なければ `None`
    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError>;
    /// キーが `prefix` で始まる状態の行を、キーの順に `visit` に渡す。全部を一度にメモリに置かない
    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError>;
}

/// 分け合っている読み口。ほかのスレッドと同じ DB を読むとき
impl<S: StateSource + ?Sized> StateSource for Arc<S> {
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        (**self).row(key)
    }

    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        (**self).node(key)
    }

    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError> {
        (**self).for_each_row(prefix, visit)
    }
}

/// [`StateSource`] を包み、読んだ行と木のノード（なかったことも）を覚えておくキャッシュ。要るものだけを読む
/// [`super::Executor`] は、ブロックをコミットするたびに読み込んだものを手放す
/// （[`super::Executor::release_loaded`]）ので、ブロックをまたいで持っておくのはここだけになる。
///
/// 覚える量は、キーと値のバイト数で決め、超えたら長く使っていないものから捨てる。コミットで変わった行と
/// ノードは [`CachedSource::record`] で、巻き戻したら [`CachedSource::clear`] で伝える。前方一致の走査
/// （[`StateSource::for_each_row`]）は覚えずに、包んだ読み口にそのまま渡す。
pub struct CachedSource<S> {
    inner: S,
    cache: Mutex<Cache>,
}

/// キャッシュの様子
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// 覚えているもののバイト数（見積もり）と数
    pub bytes: usize,
    pub entries: usize,
    /// 覚えていたものを返した数と、包んだ読み口に読みに行った数
    pub hits: u64,
    pub misses: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Kind {
    Row,
    Node,
}

type Key = (Kind, Vec<u8>);

/// 1件あたりに足すバイト数の見積もり（表の入れ物と、新しさの順の分）
const ENTRY_OVERHEAD: usize = 96;

#[derive(Default)]
struct Cache {
    /// 値（なかったら `None`）と、最後に使った順番
    entries: HashMap<Key, (Option<Vec<u8>>, u64)>,
    /// 使った順番から、キー。古いものから捨てる
    recency: BTreeMap<u64, Key>,
    next: u64,
    capacity: usize,
    stats: CacheStats,
}

fn size(key: &Key, value: &Option<Vec<u8>>) -> usize {
    key.1.len() + value.as_ref().map_or(0, Vec::len) + ENTRY_OVERHEAD
}

impl Cache {
    fn get(&mut self, key: &Key) -> Option<Option<Vec<u8>>> {
        let next = self.next;
        let Some((value, used)) = self.entries.get_mut(key) else {
            self.stats.misses += 1;
            return None;
        };
        self.recency.remove(used);
        *used = next;
        self.recency.insert(next, key.clone());
        self.next += 1;
        self.stats.hits += 1;
        Some(value.clone())
    }

    fn put(&mut self, key: Key, value: Option<Vec<u8>>) {
        if let Some((old, used)) = self.entries.remove(&key) {
            self.recency.remove(&used);
            self.stats.bytes -= size(&key, &old);
        }
        self.stats.bytes += size(&key, &value);
        self.recency.insert(self.next, key.clone());
        self.entries.insert(key, (value, self.next));
        self.next += 1;
        while self.stats.bytes > self.capacity {
            let Some((_, oldest)) = self.recency.pop_first() else {
                break;
            };
            if let Some((old, _)) = self.entries.remove(&oldest) {
                self.stats.bytes -= size(&oldest, &old);
            }
        }
        self.stats.entries = self.entries.len();
    }
}

impl<S> CachedSource<S> {
    /// `inner` を包み、最大 `capacity` バイトまで覚える
    pub fn new(inner: S, capacity: usize) -> Self {
        Self {
            inner,
            cache: Mutex::new(Cache {
                capacity,
                ..Cache::default()
            }),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// 包んだ読み口を変えるときに使う。変えた行とノードは [`CachedSource::record`] で伝えること
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// コミットで変わった行（[`super::persist::row_key`]）と木のノード（[`crate::tree::node_key`]）。`None` は消えた。
    /// 覚えているものは新しい値にし、覚えていないものも、すぐまた読まれやすいので覚える
    pub fn record(
        &self,
        rows: impl IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
        nodes: impl IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
    ) {
        let mut cache = self.cache.lock().expect("not poisoned");
        for (key, value) in rows {
            cache.put((Kind::Row, key), value);
        }
        for (key, value) in nodes {
            cache.put((Kind::Node, key), value);
        }
    }

    /// 覚えたものを全部捨てる。巻き戻したとき
    pub fn clear(&self) {
        let mut cache = self.cache.lock().expect("not poisoned");
        cache.entries.clear();
        cache.recency.clear();
        cache.stats.bytes = 0;
        cache.stats.entries = 0;
    }

    pub fn stats(&self) -> CacheStats {
        self.cache.lock().expect("not poisoned").stats
    }

    fn cached(
        &self,
        key: Key,
        read: impl FnOnce() -> Result<Option<Vec<u8>>, ExecError>,
    ) -> Result<Option<Vec<u8>>, ExecError> {
        if let Some(value) = self.cache.lock().expect("not poisoned").get(&key) {
            return Ok(value);
        }
        // 読むあいだはロックを放す（読み口が遅くても、ほかの読みを止めない）
        let value = read()?;
        self.cache
            .lock()
            .expect("not poisoned")
            .put(key, value.clone());
        Ok(value)
    }
}

impl<S: StateSource> StateSource for CachedSource<S> {
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        self.cached((Kind::Row, key.to_vec()), || self.inner.row(key))
    }

    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        self.cached((Kind::Node, key.to_vec()), || self.inner.node(key))
    }

    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError> {
        self.inner.for_each_row(prefix, visit)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// 読まれた回数を数える読み口
    #[derive(Default)]
    struct Counting {
        rows: BTreeMap<Vec<u8>, Vec<u8>>,
        reads: Cell<usize>,
    }

    impl StateSource for Counting {
        fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
            self.reads.set(self.reads.get() + 1);
            Ok(self.rows.get(key).cloned())
        }

        fn node(&self, _: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
            Ok(None)
        }

        fn for_each_row(&self, _: &[u8], _: &mut dyn FnMut(&[u8], &[u8])) -> Result<(), ExecError> {
            Ok(())
        }
    }

    #[test]
    fn remembers_values_and_absence_and_follows_commits() {
        let mut inner = Counting::default();
        inner.rows.insert(vec![1], vec![10]);
        let cached = CachedSource::new(inner, 1 << 20);
        for _ in 0..3 {
            assert_eq!(cached.row(&[1]).unwrap(), Some(vec![10]));
            assert_eq!(cached.row(&[2]).unwrap(), None);
        }
        // なかったことも覚えるので、読みに行くのは 1 回ずつ
        assert_eq!(cached.inner().reads.get(), 2);
        assert_eq!(cached.stats().hits, 4);
        // コミットで変わったものは、読み直さずに新しい値を返す
        cached.record([(vec![1], None), (vec![2], Some(vec![20]))], []);
        assert_eq!(cached.row(&[1]).unwrap(), None);
        assert_eq!(cached.row(&[2]).unwrap(), Some(vec![20]));
        assert_eq!(cached.inner().reads.get(), 2);
        cached.clear();
        assert_eq!(cached.row(&[1]).unwrap(), Some(vec![10]));
        assert_eq!(cached.inner().reads.get(), 3);
    }

    #[test]
    fn drops_the_least_recently_used_beyond_the_capacity() {
        let mut inner = Counting::default();
        for key in 0..10u8 {
            inner.rows.insert(vec![key], vec![key; 100]);
        }
        // 3 件ぶんだけ覚えられる
        let cached = CachedSource::new(inner, 3 * (1 + 100 + ENTRY_OVERHEAD));
        for key in [0, 1, 2] {
            cached.row(&[key]).unwrap();
        }
        // 0 を使い直すと、次に足したときに捨てられるのは 1
        cached.row(&[0]).unwrap();
        cached.row(&[3]).unwrap();
        let reads = cached.inner().reads.get();
        cached.row(&[0]).unwrap();
        cached.row(&[2]).unwrap();
        cached.row(&[3]).unwrap();
        assert_eq!(cached.inner().reads.get(), reads);
        cached.row(&[1]).unwrap();
        assert_eq!(cached.inner().reads.get(), reads + 1);
        assert!(cached.stats().bytes <= 3 * (1 + 100 + ENTRY_OVERHEAD));
        assert_eq!(cached.stats().entries, 3);
    }
}
