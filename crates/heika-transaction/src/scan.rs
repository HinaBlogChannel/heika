//! ブロックを走査するための、トランザクションの読み方。
//!
//! 走査ではチェーンが認めたトランザクションを読むだけなので、署名やハッシュは確かめず、バイト列の形だけを頼りにする。
//! 形がわかるのは、catbuffer の `schemas/symbol` に載っている種類とバージョンの組だけなので、
//! それ以外は読んだふりをせずに [`ScanError::Unknown`] にする。
//!
//! - アグリゲート以外の23種類（どれもバージョン 1）は、中身を読む
//! - アグリゲート（バージョン 1 から 3。署名の範囲とハッシュの決まりが違うだけで、形は同じ）は、中のトランザクションを1件ずつ読む

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;

use crate::{Body, DecodeError, HEADER_SIZE};

/// アグリゲートの中のトランザクションのヘッダー。サイズ、予約、署名者の公開鍵、予約、バージョン、ネットワーク、種類。
const EMBEDDED_HEADER_SIZE: usize = 4 + 4 + 32 + 4 + 1 + 1 + 2;
/// アグリゲートの本体のうち、中のトランザクションの前まで。TransactionsHash、PayloadSize、予約。
const AGGREGATE_FIXED_SIZE: usize = 32 + 4 + 4;

/// 走査で読んだトランザクション1件。アグリゲートは、それ自体ではなく中のトランザクションを1件ずつ返す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scanned {
    pub signer_public_key: PublicKey,
    pub network: NetworkIdentifier,
    /// アグリゲートの中なら、外側の署名者
    pub aggregate_signer: Option<PublicKey>,
    pub body: Body,
}

/// 1件のトランザクションのバイト列を走査する。
pub fn scan(bytes: &[u8]) -> Result<Vec<Scanned>, ScanError> {
    if bytes.len() < HEADER_SIZE {
        return Err(DecodeError::TooShort.into());
    }
    let size = u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes"));
    if size as usize != bytes.len() {
        return Err(DecodeError::SizeMismatch {
            stated: size,
            actual: bytes.len(),
        }
        .into());
    }
    let signer_public_key = PublicKey(bytes[72..104].try_into().expect("32 bytes"));
    let version = bytes[108];
    let network = NetworkIdentifier(bytes[109]);
    let transaction_type = u16::from_le_bytes(bytes[110..112].try_into().expect("2 bytes"));
    let body = &bytes[HEADER_SIZE..];

    if !Body::is_known(transaction_type, version) {
        return Err(ScanError::Unknown {
            transaction_type,
            version,
            embedded: false,
        });
    }
    if Body::is_aggregate_type(transaction_type) {
        return scan_aggregate(body, signer_public_key);
    }
    let body = Body::decode(transaction_type, version, body)?;
    Ok(vec![Scanned {
        signer_public_key,
        network,
        aggregate_signer: None,
        body,
    }])
}

/// アグリゲートの本体から、中のトランザクションを読む。
/// 中のトランザクションは、最後のものも含めて8バイト境界までパディングされている。連署は読まない。
fn scan_aggregate(body: &[u8], aggregate_signer: PublicKey) -> Result<Vec<Scanned>, ScanError> {
    let payload_size = body
        .get(32..36)
        .map(|size| u32::from_le_bytes(size.try_into().expect("4 bytes")) as usize)
        .ok_or(DecodeError::InvalidBodySize)?;
    let mut payload = body
        .get(AGGREGATE_FIXED_SIZE..)
        .and_then(|rest| rest.get(..payload_size))
        .ok_or(DecodeError::InvalidBodySize)?;

    let mut scanned = Vec::new();
    while !payload.is_empty() {
        let size = payload
            .first_chunk()
            .map(|size| u32::from_le_bytes(*size) as usize)
            .ok_or(DecodeError::InvalidBodySize)?;
        let padded_size = size.next_multiple_of(8);
        if size < EMBEDDED_HEADER_SIZE || padded_size > payload.len() {
            return Err(DecodeError::InvalidBodySize.into());
        }
        let embedded = &payload[..size];
        let version = embedded[44];
        let transaction_type = u16::from_le_bytes(embedded[46..48].try_into().expect("2 bytes"));
        scanned.push(Scanned {
            signer_public_key: PublicKey(embedded[8..40].try_into().expect("32 bytes")),
            network: NetworkIdentifier(embedded[45]),
            aggregate_signer: Some(aggregate_signer),
            body: embedded_body(transaction_type, version, &embedded[EMBEDDED_HEADER_SIZE..])?,
        });
        payload = &payload[padded_size..];
    }
    Ok(scanned)
}

/// 中のトランザクションの本体を読む。アグリゲートは中に入れられないので、中にあれば知らないものとする。
fn embedded_body(transaction_type: u16, version: u8, body: &[u8]) -> Result<Body, ScanError> {
    if Body::is_aggregate_type(transaction_type) || !Body::is_known(transaction_type, version) {
        return Err(ScanError::Unknown {
            transaction_type,
            version,
            embedded: true,
        });
    }
    Ok(Body::decode(transaction_type, version, body)?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// catbuffer に載っていない種類とバージョンの組。heika が知らない、新しい種類かバージョンかもしれない
    Unknown {
        transaction_type: u16,
        version: u8,
        /// アグリゲートの中にあった
        embedded: bool,
    },
    /// 知っている組だが、形が合わない
    Decode(DecodeError),
}

impl From<DecodeError> for ScanError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown {
                transaction_type,
                version,
                embedded,
            } => write!(
                f,
                "{}種類 0x{transaction_type:04X} のバージョン {version} は知りません。heika が古いのかもしれません",
                if *embedded {
                    "アグリゲートの中の、"
                } else {
                    ""
                }
            ),
            Self::Decode(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use heika_core::key::PrivateKey;

    use super::*;
    use crate::{
        Aggregate, AliasAction, EmbeddedTransaction, KeyLink, LinkAction, MosaicAlias, MosaicId,
        NamespaceId, Transaction, Transfer, UnresolvedAddress,
    };

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_private_key(&PrivateKey::from_bytes(&[seed; 32]))
    }

    fn transaction(body: Body) -> Transaction {
        Transaction::new(key(1), NetworkIdentifier::MAINNET, 0, 0, body)
    }

    fn transfer() -> Body {
        Body::Transfer(
            Transfer::new(
                UnresolvedAddress([0x68; 24]),
                BTreeMap::new(),
                b"message".to_vec(),
            )
            .unwrap(),
        )
    }

    fn link() -> Body {
        Body::VrfKeyLink(KeyLink {
            linked_public_key: key(9),
            link_action: LinkAction::Link,
        })
    }

    /// 署名者 2 と 3 の、Transfer と VRF のリンクを入れたアグリゲート
    fn aggregate_bytes() -> Vec<u8> {
        let aggregate = Aggregate::new(vec![
            EmbeddedTransaction::new(key(2), NetworkIdentifier::MAINNET, transfer()),
            EmbeddedTransaction::new(key(3), NetworkIdentifier::MAINNET, link()),
        ])
        .unwrap();
        transaction(Body::AggregateComplete(aggregate)).to_bytes()
    }

    /// 本体が `body` の、種類とバージョンを指定したトランザクション
    fn raw(transaction_type: u16, version: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = transaction(transfer()).to_bytes()[..HEADER_SIZE].to_vec();
        bytes[108] = version;
        bytes[110..112].copy_from_slice(&transaction_type.to_le_bytes());
        bytes.extend_from_slice(body);
        let size = bytes.len() as u32;
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn reads_a_top_level_transfer() {
        let scanned = scan(&transaction(transfer()).to_bytes()).unwrap();
        assert_eq!(
            scanned,
            [Scanned {
                signer_public_key: key(1),
                network: NetworkIdentifier::MAINNET,
                aggregate_signer: None,
                body: transfer(),
            }]
        );
    }

    #[test]
    fn walks_aggregates_of_every_version() {
        let expected = [
            Scanned {
                signer_public_key: key(2),
                network: NetworkIdentifier::MAINNET,
                aggregate_signer: Some(key(1)),
                body: transfer(),
            },
            Scanned {
                signer_public_key: key(3),
                network: NetworkIdentifier::MAINNET,
                aggregate_signer: Some(key(1)),
                body: link(),
            },
        ];
        // 形はバージョン 1 から 3 で同じなので、バージョンだけ書き換えても同じように読める
        for (transaction_type, version) in [(0x4141, 1), (0x4141, 2), (0x4141, 3), (0x4241, 1)] {
            let mut bytes = aggregate_bytes();
            bytes[108] = version;
            bytes[110..112].copy_from_slice(&u16::to_le_bytes(transaction_type));
            assert_eq!(
                scan(&bytes).unwrap(),
                expected,
                "{transaction_type:04X} v{version}"
            );
        }
    }

    #[test]
    fn reads_every_known_type_inside_an_aggregate() {
        let alias = Body::MosaicAlias(MosaicAlias {
            namespace_id: NamespaceId(0x8000_0000_0000_0001),
            mosaic_id: MosaicId(7),
            alias_action: AliasAction::Link,
        });
        let aggregate = Aggregate::new(vec![EmbeddedTransaction::new(
            key(2),
            NetworkIdentifier::MAINNET,
            alias.clone(),
        )])
        .unwrap();
        let scanned = scan(&transaction(Body::AggregateBonded(aggregate)).to_bytes()).unwrap();
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].body, alias);
    }

    #[test]
    fn rejects_unknown_types_and_versions() {
        let unknown = |transaction_type, version, embedded| {
            Err(ScanError::Unknown {
                transaction_type,
                version,
                embedded,
            })
        };
        assert_eq!(scan(&raw(0x4999, 1, &[])), unknown(0x4999, 1, false));
        // 知っている種類でも、catbuffer にないバージョンは形がわからない
        assert_eq!(scan(&raw(0x4154, 2, &[])), unknown(0x4154, 2, false));
        assert_eq!(scan(&raw(0x414D, 0, &[])), unknown(0x414D, 0, false));
        let mut aggregate = aggregate_bytes();
        aggregate[108] = 4;
        assert_eq!(scan(&aggregate), unknown(0x4141, 4, false));

        // アグリゲートの中の2件目（VRF のリンク）の種類を書き換える。中のトランザクションは本体の 40 バイト目から並ぶ
        let first_size = u32::from_le_bytes(aggregate[168..172].try_into().unwrap()) as usize;
        let second = 168 + first_size.next_multiple_of(8);
        let mut embedded = aggregate_bytes();
        embedded[second + 46..second + 48].copy_from_slice(&0x4999_u16.to_le_bytes());
        assert_eq!(scan(&embedded), unknown(0x4999, 1, true));
        // アグリゲートは中に入れられない
        embedded[second + 44] = 3;
        embedded[second + 46..second + 48].copy_from_slice(&0x4141_u16.to_le_bytes());
        assert_eq!(scan(&embedded), unknown(0x4141, 3, true));
    }

    #[test]
    fn rejects_broken_shapes() {
        let bytes = transaction(transfer()).to_bytes();
        assert_eq!(
            scan(&bytes[..HEADER_SIZE - 1]),
            Err(ScanError::Decode(DecodeError::TooShort))
        );
        assert!(matches!(
            scan(&bytes[..bytes.len() - 1]),
            Err(ScanError::Decode(DecodeError::SizeMismatch { .. }))
        ));
        // アグリゲートの PayloadSize が本体からはみ出す
        let mut aggregate = aggregate_bytes();
        aggregate[160..164].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            scan(&aggregate),
            Err(ScanError::Decode(DecodeError::InvalidBodySize))
        );
    }
}
