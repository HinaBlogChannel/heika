//! ブロックを走査するための、トランザクションの読み方。
//!
//! 走査ではチェーンが認めたトランザクションを読むだけなので、署名やハッシュは確かめず、バイト列の形だけを頼りにする。
//! 形がわかるのは、catbuffer の `schemas/symbol` に載っている種類とバージョンの組だけなので、
//! それ以外は読んだふりをせずに [`ScanError::Unknown`] にする。
//!
//! - Transfer と、アカウント、ノード、VRF のリンク（どれもバージョン 1）は、中身を読む
//! - アグリゲート（バージョン 1 から 3。ハッシュの取り方が違うだけで、形は同じ）は、中のトランザクションを1件ずつ読む
//! - それ以外の知っている組は、種類だけを返して中身は読まない

use std::fmt;

use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;

use crate::{Body, DecodeError, HEADER_SIZE};

/// アグリゲートの中のトランザクションのヘッダー。サイズ、予約、署名者の公開鍵、予約、バージョン、ネットワーク、種類。
const EMBEDDED_HEADER_SIZE: usize = 4 + 4 + 32 + 4 + 1 + 1 + 2;
/// アグリゲートの本体のうち、中のトランザクションの前まで。TransactionsHash、PayloadSize、予約。
const AGGREGATE_FIXED_SIZE: usize = 32 + 4 + 4;

const AGGREGATE_COMPLETE: u16 = 0x4141;
const AGGREGATE_BONDED: u16 = 0x4241;
/// 中身を読む種類。Body::decode が読める、バージョン 1 のもの
const READ_TYPES: [u16; 4] = [0x414C, 0x424C, 0x4243, 0x4154];
/// バージョン 1 だけがある種類。アグリゲートの中にも入れられる。
/// catbuffer の `schemas/symbol/transaction_type.cats` と、各スキーマの `TRANSACTION_VERSION` から書き起こした
/// （symbol/symbol のコミット dbff03b4096622d1bc1fce611358e05cfa7b0296）
const VERSION_1_TYPES: [u16; 23] = [
    0x414C, // ACCOUNT_KEY_LINK
    0x424C, // NODE_KEY_LINK
    0x4143, // VOTING_KEY_LINK
    0x4243, // VRF_KEY_LINK
    0x4148, // HASH_LOCK
    0x4152, // SECRET_LOCK
    0x4252, // SECRET_PROOF
    0x4144, // ACCOUNT_METADATA
    0x4244, // MOSAIC_METADATA
    0x4344, // NAMESPACE_METADATA
    0x414D, // MOSAIC_DEFINITION
    0x424D, // MOSAIC_SUPPLY_CHANGE
    0x434D, // MOSAIC_SUPPLY_REVOCATION
    0x4155, // MULTISIG_ACCOUNT_MODIFICATION
    0x424E, // ADDRESS_ALIAS
    0x434E, // MOSAIC_ALIAS
    0x414E, // NAMESPACE_REGISTRATION
    0x4150, // ACCOUNT_ADDRESS_RESTRICTION
    0x4250, // ACCOUNT_MOSAIC_RESTRICTION
    0x4350, // ACCOUNT_OPERATION_RESTRICTION
    0x4251, // MOSAIC_ADDRESS_RESTRICTION
    0x4151, // MOSAIC_GLOBAL_RESTRICTION
    0x4154, // TRANSFER
];

/// 走査で読んだトランザクション1件。アグリゲートは、それ自体ではなく中のトランザクションを1件ずつ返す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Scanned {
    pub signer_public_key: PublicKey,
    pub network: NetworkIdentifier,
    /// アグリゲートの中なら、外側の署名者
    pub aggregate_signer: Option<PublicKey>,
    pub content: Content,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Content {
    /// 中身を読んだもの。Transfer とリンクのどれか
    Read(Body),
    /// 知っている種類だが、中身は読んでいない
    Skipped { transaction_type: u16 },
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

    if matches!(transaction_type, AGGREGATE_COMPLETE | AGGREGATE_BONDED) {
        if !(1..=3).contains(&version) {
            return Err(ScanError::Unknown {
                transaction_type,
                version,
                embedded: false,
            });
        }
        return scan_aggregate(body, signer_public_key);
    }
    let content = content(transaction_type, version, body, false)?;
    Ok(vec![Scanned {
        signer_public_key,
        network,
        aggregate_signer: None,
        content,
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
            content: content(
                transaction_type,
                version,
                &embedded[EMBEDDED_HEADER_SIZE..],
                true,
            )?,
        });
        payload = &payload[padded_size..];
    }
    Ok(scanned)
}

/// アグリゲート以外の種類の本体を、読むか飛ばす。アグリゲートは中に入れられないので、中にあれば知らないものとする。
fn content(
    transaction_type: u16,
    version: u8,
    body: &[u8],
    embedded: bool,
) -> Result<Content, ScanError> {
    if version != 1 || !VERSION_1_TYPES.contains(&transaction_type) {
        return Err(ScanError::Unknown {
            transaction_type,
            version,
            embedded,
        });
    }
    if READ_TYPES.contains(&transaction_type) {
        Ok(Content::Read(Body::decode(
            transaction_type,
            version,
            body,
        )?))
    } else {
        Ok(Content::Skipped { transaction_type })
    }
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

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use heika_core::key::PrivateKey;
    use heika_core::signature::Signature;

    use super::*;
    use crate::{
        Aggregate, EmbeddedTransaction, KeyLink, LinkAction, Transaction, Transfer,
        UnresolvedAddress,
    };

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_private_key(&PrivateKey::from_bytes(&[seed; 32]))
    }

    fn transaction(body: Body) -> Transaction {
        Transaction {
            signature: Signature([0; 64]),
            signer_public_key: key(1),
            network: NetworkIdentifier::MAINNET,
            fee: 0,
            deadline: 0,
            body,
        }
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
                content: Content::Read(transfer()),
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
                content: Content::Read(transfer()),
            },
            Scanned {
                signer_public_key: key(3),
                network: NetworkIdentifier::MAINNET,
                aggregate_signer: Some(key(1)),
                content: Content::Read(link()),
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
    fn skips_known_types_without_reading_them() {
        // MOSAIC_DEFINITION の本体の中身は読まないので、何が入っていてもよい
        let scanned = scan(&raw(0x414D, 1, &[0xFF; 3])).unwrap();
        assert_eq!(
            scanned[0].content,
            Content::Skipped {
                transaction_type: 0x414D
            }
        );
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
