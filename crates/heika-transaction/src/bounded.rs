//! 長さを決まった幅の整数で書く配列。

use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// 長さが `MAX` までの配列。catbuffer で長さを `uint8` や `uint16` で書く配列に使い、書けない長さのものを作らせない。
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MAX: usize> TryFrom<Vec<T>> for BoundedVec<T, MAX> {
    type Error = TooLong;

    fn try_from(items: Vec<T>) -> Result<Self, TooLong> {
        if items.len() > MAX {
            return Err(TooLong {
                length: items.len(),
                max: MAX,
            });
        }
        Ok(Self(items))
    }
}

impl<T, const MAX: usize> Deref for BoundedVec<T, MAX> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}

/// 配列が、書ける長さを超えている
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLong {
    pub length: usize,
    pub max: usize,
}

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} 個までしか書けませんが、{} 個ありました",
            self.max, self.length
        )
    }
}

impl core::error::Error for TooLong {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_more_than_the_maximum() {
        let items: BoundedVec<u8, 2> = vec![1, 2].try_into().unwrap();
        assert_eq!(*items, [1, 2]);
        assert_eq!(
            BoundedVec::<u8, 2>::try_from(vec![1, 2, 3]),
            Err(TooLong { length: 3, max: 2 })
        );
    }
}
