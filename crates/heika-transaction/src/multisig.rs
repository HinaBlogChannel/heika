//! マルチシグ。catbuffer の `multisig/`。

use crate::bounded::BoundedVec;
use crate::transfer::UnresolvedAddress;
use crate::{DecodeError, Reader};

/// マルチシグの連署者と、必要な連署の数を変える。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MultisigAccountModification {
    /// 連署者を外すのに要る連署の数の増減
    pub min_removal_delta: i8,
    /// それ以外に要る連署の数の増減
    pub min_approval_delta: i8,
    pub address_additions: BoundedVec<UnresolvedAddress, { u8::MAX as usize }>,
    pub address_deletions: BoundedVec<UnresolvedAddress, { u8::MAX as usize }>,
}

impl MultisigAccountModification {
    /// アドレスの並びより前の部分。2つの増減、足す数と外す数、予約。
    const FIXED_SIZE: usize = 1 + 1 + 1 + 1 + 4;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.min_removal_delta as u8);
        out.push(self.min_approval_delta as u8);
        out.push(self.address_additions.len() as u8);
        out.push(self.address_deletions.len() as u8);
        out.extend_from_slice(&[0; 4]);
        for address in self
            .address_additions
            .iter()
            .chain(&*self.address_deletions)
        {
            out.extend_from_slice(&address.0);
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::at_least(bytes, Self::FIXED_SIZE)?;
        let min_removal_delta = reader.u8() as i8;
        let min_approval_delta = reader.u8() as i8;
        let additions_count = reader.u8() as usize;
        let deletions_count = reader.u8() as usize;
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        reader.expect_remaining((additions_count + deletions_count) * 24)?;
        let mut read = |count| {
            (0..count)
                .map(|_| UnresolvedAddress(reader.array()))
                .collect::<Vec<_>>()
                .try_into()
                .expect("u8 count")
        };
        let address_additions = read(additions_count);
        let address_deletions = read(deletions_count);
        Ok(Self {
            min_removal_delta,
            min_approval_delta,
            address_additions,
            address_deletions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use crate::testing::{decode, round_trip};

    fn modification() -> MultisigAccountModification {
        MultisigAccountModification {
            min_removal_delta: -1,
            min_approval_delta: 2,
            address_additions: vec![UnresolvedAddress([1; 24]), UnresolvedAddress([2; 24])]
                .try_into()
                .unwrap(),
            address_deletions: vec![UnresolvedAddress([3; 24])].try_into().unwrap(),
        }
    }

    #[test]
    fn writes_additions_then_deletions() {
        let body = round_trip(Body::MultisigAccountModification(modification()));
        assert_eq!(body[..8], [0xFF, 2, 2, 1, 0, 0, 0, 0]);
        assert_eq!(body[8..32], [1; 24]);
        assert_eq!(body[32..56], [2; 24]);
        assert_eq!(body[56..], [3; 24]);
    }

    #[test]
    fn rejects_reserved_bytes_and_wrong_counts() {
        let body = round_trip(Body::MultisigAccountModification(modification()));
        let mut reserved = body.clone();
        reserved[4] = 1;
        assert_eq!(decode(0x4155, &reserved), Err(DecodeError::NonZeroReserved));
        let mut counts = body;
        counts[3] = 2;
        assert_eq!(decode(0x4155, &counts), Err(DecodeError::InvalidBodySize));
    }
}
