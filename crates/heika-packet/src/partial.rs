//! 連署を待つトランザクション（アグリゲートボンデッド）を、ピアとやりとりするパケットの本体。catapult の
//! partialtransaction 拡張（`PtHandlers`、`CosignedTransactionInfoParser`）と同じ形。
//!
//! - `Push_Partial_Transactions`: トランザクションを隙間なく並べたもの（[`crate::split_size_prefixed`] で読む）
//! - `Push_Detached_Cosignatures`: 切り離した連署（[`DETACHED_COSIGNATURE_SIZE`] バイト）を並べたもの
//! - `Pull_Partial_Transaction_Infos`: 要求は、期限の下限と、知っているものの短いハッシュの組（[`ShortHashPair`]）。
//!   答えは、知らないトランザクションか、知っているもののハッシュに、連署を付けたもの（[`CosignedInfo`]）
//!
//! 連署の中身（署名者の公開鍵と署名）はここでは読まずに、バイト列のまま渡す。読むのは heika-transaction。

use heika_core::hash::Hash256;

use crate::DecodeError;

/// アグリゲートの中の連署の大きさ。バージョン（u64）、署名者の公開鍵、署名
pub const COSIGNATURE_SIZE: usize = 8 + 32 + 64;
/// 切り離した連署の大きさ。連署に、連署したアグリゲートのハッシュが続く
pub const DETACHED_COSIGNATURE_SIZE: usize = COSIGNATURE_SIZE + 32;

/// 答えの1件の頭（u64）で、トランザクションが入っていることを示すビット。下位 15 ビットは連署の数
const TRANSACTION_PRESENT: u64 = 0x8000;

/// `Push_Detached_Cosignatures` の本体を、連署1つずつに切る。空なら読まない（catapult と同じ）
pub fn split_detached_cosignatures(
    body: &[u8],
) -> Result<Vec<&[u8; DETACHED_COSIGNATURE_SIZE]>, DecodeError> {
    let (chunks, rest) = body.as_chunks::<DETACHED_COSIGNATURE_SIZE>();
    if chunks.is_empty() || !rest.is_empty() {
        return Err(DecodeError::BodySize {
            expected: chunks.len().max(1) * DETACHED_COSIGNATURE_SIZE,
            actual: body.len(),
        });
    }
    Ok(chunks.iter().collect())
}

/// 知っている連署待ちのトランザクションの短いハッシュの組。トランザクション（連署を除く）のハッシュと、連署を
/// 署名者の順に並べたもののハッシュの、それぞれ先頭4バイト（[`crate::short_hash`]）
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ShortHashPair {
    pub transaction: u32,
    pub cosignatures: u32,
}

/// `Pull_Partial_Transaction_Infos` の要求の本体。期限の下限に、短いハッシュの組が続く
pub fn pull_partial_request(min_deadline: u64, known: &[ShortHashPair]) -> Vec<u8> {
    let mut request = Vec::with_capacity(8 + 8 * known.len());
    request.extend_from_slice(&min_deadline.to_le_bytes());
    for pair in known {
        request.extend_from_slice(&pair.transaction.to_le_bytes());
        request.extend_from_slice(&pair.cosignatures.to_le_bytes());
    }
    request
}

/// [`pull_partial_request`] で書いた要求を読む。期限の下限と、知っている短いハッシュの組
pub fn read_pull_partial_request(body: &[u8]) -> Result<(u64, Vec<ShortHashPair>), DecodeError> {
    let Some((deadline, pairs)) = body.split_at_checked(8) else {
        return Err(DecodeError::Truncated {
            needed: 8,
            remaining: body.len(),
        });
    };
    let (chunks, rest) = pairs.as_chunks::<8>();
    if !rest.is_empty() {
        return Err(DecodeError::BodySize {
            expected: 8 + chunks.len() * 8,
            actual: body.len(),
        });
    }
    let known = chunks
        .iter()
        .map(|pair| ShortHashPair {
            transaction: u32::from_le_bytes(pair[..4].try_into().expect("4 bytes")),
            cosignatures: u32::from_le_bytes(pair[4..].try_into().expect("4 bytes")),
        })
        .collect();
    Ok((
        u64::from_le_bytes(deadline.try_into().expect("8 bytes")),
        known,
    ))
}

/// 答えの1件で、連署の前にあるもの
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PartialInfo<'a> {
    /// 相手が知らないトランザクション（連署を含まないもの）
    Transaction(&'a [u8]),
    /// 相手が知っているトランザクションのハッシュ。足りない連署だけを送る
    Hash(Hash256),
}

/// `Pull_Partial_Transaction_Infos` の答えの1件。連署は [`COSIGNATURE_SIZE`] バイトずつ
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CosignedInfo<'a> {
    pub info: PartialInfo<'a>,
    pub cosignatures: Vec<&'a [u8; COSIGNATURE_SIZE]>,
}

/// トランザクションの後ろを 8 バイト境界まで埋める数
fn padding(size: usize) -> usize {
    (8 - size % 8) % 8
}

/// `Pull_Partial_Transaction_Infos` の答えの本体。1件ずつ、頭（u64）、トランザクションと 8 バイト境界までの0か
/// ハッシュ、連署の順に並べる
pub fn write_partial_infos(infos: &[CosignedInfo<'_>]) -> Vec<u8> {
    let mut body = Vec::new();
    for info in infos {
        let count = info.cosignatures.len() as u64 & 0x7FFF;
        match info.info {
            PartialInfo::Transaction(transaction) => {
                body.extend_from_slice(&(TRANSACTION_PRESENT | count).to_le_bytes());
                body.extend_from_slice(transaction);
                body.resize(body.len() + padding(transaction.len()), 0);
            }
            PartialInfo::Hash(hash) => {
                body.extend_from_slice(&count.to_le_bytes());
                body.extend_from_slice(&hash.0);
            }
        }
        for cosignature in &info.cosignatures {
            body.extend_from_slice(&cosignature[..]);
        }
    }
    body
}

/// 前から読む
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], DecodeError> {
        let (head, rest) = self
            .0
            .split_at_checked(size)
            .ok_or(DecodeError::Truncated {
                needed: size,
                remaining: self.0.len(),
            })?;
        self.0 = rest;
        Ok(head)
    }

    /// 0 で埋めた `size` バイトを読み飛ばす
    fn zeros(&mut self, size: usize) -> Result<(), DecodeError> {
        if self.take(size)?.iter().any(|&byte| byte != 0) {
            return Err(DecodeError::NonZeroPadding);
        }
        Ok(())
    }
}

/// [`write_partial_infos`] の形の答えを読む。どこか1つでも読めなければ、全部を読まない（catapult と同じ）
pub fn read_partial_infos(body: &[u8]) -> Result<Vec<CosignedInfo<'_>>, DecodeError> {
    let mut reader = Reader(body);
    let mut infos = Vec::new();
    while !reader.0.is_empty() {
        let tag = reader.take(2)?;
        let tag = u16::from_le_bytes([tag[0], tag[1]]);
        reader.zeros(6)?;
        let info = if u64::from(tag) & TRANSACTION_PRESENT != 0 {
            // トランザクションの大きさは、先頭の Size
            let size = reader
                .0
                .get(..4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes")) as usize)
                .ok_or(DecodeError::Truncated {
                    needed: 4,
                    remaining: reader.0.len(),
                })?;
            if size < 4 {
                return Err(DecodeError::EntityTooSmall { size, minimum: 4 });
            }
            let transaction = reader.take(size)?;
            reader.zeros(padding(size))?;
            PartialInfo::Transaction(transaction)
        } else {
            PartialInfo::Hash(Hash256(reader.take(32)?.try_into().expect("32 bytes")))
        };
        let cosignatures = (0..tag & 0x7FFF)
            .map(|_| {
                reader
                    .take(COSIGNATURE_SIZE)
                    .map(|bytes| bytes.try_into().expect("cosignature size"))
            })
            .collect::<Result<_, _>>()?;
        infos.push(CosignedInfo { info, cosignatures });
    }
    Ok(infos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 大きさが `size` の、中身が `fill` のトランザクションらしきもの
    fn transaction(size: u32, fill: u8) -> Vec<u8> {
        let mut bytes = vec![fill; size as usize];
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn splits_detached_cosignatures() {
        let body = [
            [1u8; DETACHED_COSIGNATURE_SIZE],
            [2; DETACHED_COSIGNATURE_SIZE],
        ]
        .concat();
        let split = split_detached_cosignatures(&body).unwrap();
        assert_eq!(split.len(), 2);
        assert_eq!(split[1][0], 2);
        assert!(split_detached_cosignatures(&[]).is_err());
        assert!(split_detached_cosignatures(&body[1..]).is_err());
    }

    #[test]
    fn round_trips_a_pull_request() {
        let known = [
            ShortHashPair {
                transaction: 0x0102_0304,
                cosignatures: 0x0506_0708,
            },
            ShortHashPair {
                transaction: 9,
                cosignatures: 10,
            },
        ];
        let request = pull_partial_request(0x1122_3344_5566_7788, &known);
        assert_eq!(request.len(), 24);
        assert_eq!(&request[..8], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&request[8..12], &0x0102_0304u32.to_le_bytes());
        assert_eq!(
            read_pull_partial_request(&request),
            Ok((0x1122_3344_5566_7788, known.to_vec()))
        );
        assert_eq!(
            read_pull_partial_request(&request[..8]),
            Ok((0x1122_3344_5566_7788, Vec::new()))
        );
        assert!(read_pull_partial_request(&request[..7]).is_err());
        assert!(read_pull_partial_request(&request[..20]).is_err());
    }

    #[test]
    fn writes_and_reads_cosigned_infos_like_catapult() {
        // 大きさが 8 の倍数でないトランザクションには、0 の詰め物が付く
        let unknown = transaction(13, 0xAA);
        let cosignature = [0x55u8; COSIGNATURE_SIZE];
        let infos = [
            CosignedInfo {
                info: PartialInfo::Transaction(&unknown),
                cosignatures: vec![&cosignature],
            },
            CosignedInfo {
                info: PartialInfo::Hash(Hash256([7; 32])),
                cosignatures: vec![&cosignature, &cosignature],
            },
        ];
        let body = write_partial_infos(&infos);
        let mut expected = (0x8000u64 | 1).to_le_bytes().to_vec();
        expected.extend_from_slice(&unknown);
        expected.extend_from_slice(&[0; 3]);
        expected.extend_from_slice(&cosignature);
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&cosignature);
        expected.extend_from_slice(&cosignature);
        assert_eq!(body, expected);
        assert_eq!(read_partial_infos(&body).unwrap(), infos);
        assert_eq!(read_partial_infos(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn refuses_broken_infos() {
        let unknown = transaction(13, 0xAA);
        let body = write_partial_infos(&[CosignedInfo {
            info: PartialInfo::Transaction(&unknown),
            cosignatures: Vec::new(),
        }]);
        // 頭の詰め物、トランザクションの後ろの詰め物が0でない
        for index in [2, 8 + 13] {
            let mut broken = body.clone();
            broken[index] = 1;
            assert_eq!(
                read_partial_infos(&broken),
                Err(DecodeError::NonZeroPadding)
            );
        }
        // 途中で切れている、連署が足りない
        assert!(read_partial_infos(&body[..body.len() - 1]).is_err());
        let mut short = 3u64.to_le_bytes().to_vec();
        short.extend_from_slice(&[0; 32]);
        short.extend_from_slice(&[0; COSIGNATURE_SIZE]);
        assert!(read_partial_infos(&short).is_err());
    }
}
