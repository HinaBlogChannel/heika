//! Symbol のノードどうしがやりとりするパケットの形。catapult の `ionet/Packet.h`、`ionet/NetworkNode.h`、
//! `api/ChainPackets.h`、`handlers/ChainHandlers.cpp`、`handlers/TransactionHandlers.cpp`、
//! `extensions/finalization/src/handlers/ProofHandlers.cpp` に合わせている。どれも `#pragma pack(1)` の
//! リトルエンディアンで、パディングはない。
//!
//! バイト列の組み立てと読み取りだけで、通信はしない。どうつなぐか（TLS など）と、どうやりとりするかは使う側が決める。

use std::fmt;

use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::{GenerationHashSeed, NetworkIdentifier};

/// パケットの見出しの大きさ。見出しを含む全長 `u32` と、種類 `u32`
pub const HEADER_SIZE: usize = 8;

/// パケットの見出し。catapult の `ionet::PacketHeader`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// 見出しを含む全長
    pub size: u32,
    pub packet_type: u32,
}

impl Header {
    pub fn parse(bytes: &[u8; HEADER_SIZE]) -> Self {
        let [s0, s1, s2, s3, t0, t1, t2, t3] = *bytes;
        Self {
            size: u32::from_le_bytes([s0, s1, s2, s3]),
            packet_type: u32::from_le_bytes([t0, t1, t2, t3]),
        }
    }

    /// 本体の大きさ。全長が見出しより短ければ `None`
    pub fn body_size(&self) -> Option<usize> {
        (self.size as usize).checked_sub(HEADER_SIZE)
    }
}

/// 見出しを付けたパケット。全長が `u32` に収まらなければ、本体の大きさを `Err` で返す
pub fn encode(packet_type: u32, body: &[u8]) -> Result<Vec<u8>, usize> {
    let size = u32::try_from(HEADER_SIZE + body.len()).map_err(|_| body.len())?;
    let mut packet = Vec::with_capacity(size as usize);
    packet.extend_from_slice(&size.to_le_bytes());
    packet.extend_from_slice(&packet_type.to_le_bytes());
    packet.extend_from_slice(body);
    Ok(packet)
}

/// catapult の `ionet::PacketType` のうち使うもの。
pub mod packet_type {
    pub const CHAIN_STATISTICS: u32 = 5;
    pub const PULL_BLOCKS: u32 = 8;
    pub const PULL_TRANSACTIONS: u32 = 10;
    pub const NODE_DISCOVERY_PULL_PING: u32 = 0x111;
    pub const NODE_DISCOVERY_PULL_PEERS: u32 = 0x113;
}

/// `Pull_Blocks` の要求の本体。`height` から最大 `num_blocks` 件、合計 `num_response_bytes` バイトまで
pub fn pull_blocks_request(height: u64, num_blocks: u32, num_response_bytes: u32) -> [u8; 16] {
    let mut request = [0; 16];
    request[..8].copy_from_slice(&height.to_le_bytes());
    request[8..12].copy_from_slice(&num_blocks.to_le_bytes());
    request[12..].copy_from_slice(&num_response_bytes.to_le_bytes());
    request
}

/// `Pull_Transactions` の要求の本体。catapult の `TransactionsFilter`（Deadline、FeeMultiplier）に、短いハッシュが続く。
pub fn pull_transactions_request(
    min_deadline: u64,
    min_fee_multiplier: u32,
    known_short_hashes: &[u32],
) -> Vec<u8> {
    let mut request = Vec::with_capacity(12 + 4 * known_short_hashes.len());
    request.extend_from_slice(&min_deadline.to_le_bytes());
    request.extend_from_slice(&min_fee_multiplier.to_le_bytes());
    for short_hash in known_short_hashes {
        request.extend_from_slice(&short_hash.to_le_bytes());
    }
    request
}

/// catapult の `utils::ToShortHash`。ハッシュの先頭4バイトを u32 として読んだもの。
/// `Pull_Transactions` で、もう知っているトランザクションを伝えるのに使う。
pub fn short_hash(hash: &Hash256) -> u32 {
    u32::from_le_bytes(hash.0[..4].try_into().expect("4 bytes"))
}

/// `Chain_Statistics` の応答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainStatistics {
    pub height: u64,
    pub finalized_height: u64,
    /// catapult では `ScoreHigh` と `ScoreLow` の2つの u64 に分けて送られる
    pub score: u128,
}

impl ChainStatistics {
    const BODY_SIZE: usize = 32;

    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let body: &[u8; Self::BODY_SIZE] = body.try_into().map_err(|_| DecodeError::BodySize {
            expected: Self::BODY_SIZE,
            actual: body.len(),
        })?;
        let u64_at = |offset: usize| {
            u64::from_le_bytes(body[offset..offset + 8].try_into().expect("8 bytes"))
        };
        Ok(Self {
            height: u64_at(0),
            finalized_height: u64_at(8),
            score: (u128::from(u64_at(16)) << 64) | u128::from(u64_at(24)),
        })
    }
}

/// catapult の `NodeVersion`。1バイトずつ上位から major.minor.revision.build。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeVersion(pub u32);

impl fmt::Display for NodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, revision, build] = self.0.to_be_bytes();
        write!(f, "{major}.{minor}.{revision}.{build}")
    }
}

/// catapult の `NodeRoles`。ビットフラグ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeRoles(pub u32);

impl NodeRoles {
    pub const PEER: Self = Self(0x01);

    const NAMES: [(u32, &str); 5] = [
        (0x01, "Peer"),
        (0x02, "Api"),
        (0x04, "Voting"),
        (0x40, "IPv4"),
        (0x80, "IPv6"),
    ];

    /// `roles` のビットがすべて立っているか。
    pub fn contains(self, roles: Self) -> bool {
        self.0 & roles.0 == roles.0
    }

    /// catapult の設定ファイル（peers-p2p.json など）の書き方。`IPv4,Peer` のように `,` で区切る。
    /// catapult は知らない名前があると読み込めないので、知らないビットは落とす。
    pub fn to_config_value(self) -> String {
        Self::NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| *name)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// 立っているロールの名前。知らないビットは、まとめて `0x100` のような16進で最後に置く。
    pub fn names(self) -> Vec<String> {
        let mut names: Vec<String> = Self::NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| (*name).to_owned())
            .collect();
        let known = Self::NAMES.iter().fold(0, |bits, (bit, _)| bits | bit);
        if self.0 & !known != 0 {
            names.push(format!("{:#x}", self.0 & !known));
        }
        names
    }
}

impl fmt::Display for NodeRoles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.names();
        if names.is_empty() {
            f.write_str("None")
        } else {
            f.write_str(&names.join("|"))
        }
    }
}

/// catapult の `ionet::NetworkNode`。ノードの公開情報。
///
/// ```text
/// u32  Size  u32 Version  [32] IdentityKey  [32] NetworkGenerationHashSeed
/// u32  Roles  u16 Port  u8 NetworkIdentifier  u8 HostSize  u8 FriendlyNameSize
/// ...  host（HostSize バイト） friendly name（FriendlyNameSize バイト）
/// ```
///
/// host と friendly name はノードが自分で名乗るもので、何が入っているかわからない。表示するときは制御文字に気をつける。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkNode {
    pub version: NodeVersion,
    /// ノードの CA の公開鍵
    pub identity_key: PublicKey,
    pub network_generation_hash_seed: GenerationHashSeed,
    pub roles: NodeRoles,
    pub port: u16,
    pub network_identifier: NetworkIdentifier,
    pub host: String,
    pub friendly_name: String,
}

impl NetworkNode {
    const FIXED_SIZE: usize = 81;

    /// エンティティ1件（`Size` から最後の文字列まで）をデコードする。
    pub fn decode(entity: &[u8]) -> Result<Self, DecodeError> {
        let fixed: &[u8; Self::FIXED_SIZE] = entity
            .get(..Self::FIXED_SIZE)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(DecodeError::EntityTooSmall {
                size: entity.len(),
                minimum: Self::FIXED_SIZE,
            })?;
        let u32_at = |offset: usize| {
            u32::from_le_bytes(fixed[offset..offset + 4].try_into().expect("4 bytes"))
        };
        let declared = u32_at(0) as usize;
        if declared != entity.len() {
            return Err(DecodeError::SizeMismatch {
                declared,
                actual: entity.len(),
            });
        }
        let host_size = usize::from(fixed[79]);
        let friendly_name_size = usize::from(fixed[80]);
        let expected = Self::FIXED_SIZE + host_size + friendly_name_size;
        if declared != expected {
            return Err(DecodeError::SizeMismatch {
                declared,
                actual: expected,
            });
        }

        let (host, friendly_name) = entity[Self::FIXED_SIZE..].split_at(host_size);
        Ok(Self {
            version: NodeVersion(u32_at(4)),
            identity_key: PublicKey(fixed[8..40].try_into().expect("32 bytes")),
            network_generation_hash_seed: GenerationHashSeed(
                fixed[40..72].try_into().expect("32 bytes"),
            ),
            roles: NodeRoles(u32_at(72)),
            port: u16::from_le_bytes([fixed[76], fixed[77]]),
            network_identifier: NetworkIdentifier(fixed[78]),
            // 名前は表示に使うだけなので、壊れた UTF-8 でもリスト全体を失敗させない
            host: String::from_utf8_lossy(host).into_owned(),
            friendly_name: String::from_utf8_lossy(friendly_name).into_owned(),
        })
    }

    /// `Node_Discovery_Pull_Peers` の応答の本体（`NetworkNode` の並び）をデコードする。
    pub fn decode_list(body: &[u8]) -> Result<Vec<Self>, DecodeError> {
        split_size_prefixed(body)?
            .into_iter()
            .map(Self::decode)
            .collect()
    }
}

/// 先頭に `Size: u32`（自身を含む全長）を持つエンティティが隙間なく並んだ本体を、1件ずつに切り出す。
pub fn split_size_prefixed(mut body: &[u8]) -> Result<Vec<&[u8]>, DecodeError> {
    let mut entities = Vec::new();
    while !body.is_empty() {
        let size = body
            .get(..4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes")) as usize)
            .ok_or(DecodeError::Truncated {
                needed: 4,
                remaining: body.len(),
            })?;
        if size < 4 {
            return Err(DecodeError::EntityTooSmall { size, minimum: 4 });
        }
        let (entity, rest) = body.split_at_checked(size).ok_or(DecodeError::Truncated {
            needed: size,
            remaining: body.len(),
        })?;
        entities.push(entity);
        body = rest;
    }
    Ok(entities)
}

/// 応答を読めない理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 本体の長さが決まっているのに合わない
    BodySize { expected: usize, actual: usize },
    /// 残りのバイト数が、読もうとした長さに足りない
    Truncated { needed: usize, remaining: usize },
    /// エンティティが固定部分より短い
    EntityTooSmall { size: usize, minimum: usize },
    /// 先頭の Size と、実際の長さや中身から計算した長さが合わない
    SizeMismatch { declared: usize, actual: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodySize { expected, actual } => {
                write!(f, "本体が {expected} バイトのはずが {actual} バイトでした")
            }
            Self::Truncated { needed, remaining } => {
                write!(f, "{needed} バイト必要ですが残りは {remaining} バイトです")
            }
            Self::EntityTooSmall { size, minimum } => {
                write!(f, "{size} バイトしかありません（最低 {minimum} バイト）")
            }
            Self::SizeMismatch { declared, actual } => {
                write!(
                    f,
                    "Size は {declared} バイトですが実際は {actual} バイトです"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// catapult の `NetworkNode` の並びで書いたもの
    fn network_node(host: &[u8], friendly_name: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let size = 81 + host.len() + friendly_name.len();
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes.extend_from_slice(&0x0001_0203_u32.to_le_bytes());
        bytes.extend_from_slice(&[0x11; 32]);
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&0x43_u32.to_le_bytes());
        bytes.extend_from_slice(&7900_u16.to_le_bytes());
        bytes.push(0x68);
        bytes.push(host.len() as u8);
        bytes.push(friendly_name.len() as u8);
        bytes.extend_from_slice(host);
        bytes.extend_from_slice(friendly_name);
        bytes
    }

    #[test]
    fn decodes_a_network_node() {
        let node = NetworkNode::decode(&network_node(b"node.example", b"example")).unwrap();
        assert_eq!(node.version.to_string(), "0.1.2.3");
        assert_eq!(node.identity_key, PublicKey([0x11; 32]));
        assert_eq!(
            node.network_generation_hash_seed,
            GenerationHashSeed([0x22; 32])
        );
        assert_eq!(node.roles.to_string(), "Peer|Api|IPv4");
        assert_eq!(node.port, 7900);
        assert_eq!(node.network_identifier, NetworkIdentifier::MAINNET);
        assert_eq!(node.host, "node.example");
        assert_eq!(node.friendly_name, "example");
    }

    #[test]
    fn decodes_a_list_of_network_nodes() {
        let body = [network_node(b"a", b""), network_node(b"", b"b")].concat();
        let nodes = NetworkNode::decode_list(&body).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(
            (nodes[0].host.as_str(), nodes[1].friendly_name.as_str()),
            ("a", "b")
        );
        assert_eq!(NetworkNode::decode_list(&[]).unwrap(), []);
    }

    #[test]
    fn rejects_a_network_node_with_inconsistent_sizes() {
        let mut bytes = network_node(b"host", b"name");
        bytes.push(0);
        assert_eq!(
            NetworkNode::decode(&bytes),
            Err(DecodeError::SizeMismatch {
                declared: 89,
                actual: 90
            })
        );
        let mut bytes = network_node(b"host", b"name");
        bytes[79] = 5;
        assert!(matches!(
            NetworkNode::decode(&bytes),
            Err(DecodeError::SizeMismatch { .. })
        ));
        assert!(matches!(
            NetworkNode::decode(&bytes[..80]),
            Err(DecodeError::EntityTooSmall { .. })
        ));
    }

    #[test]
    fn decodes_chain_statistics() {
        let mut body = Vec::new();
        for value in [10_u64, 8, 1, 2] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(
            ChainStatistics::decode(&body),
            Ok(ChainStatistics {
                height: 10,
                finalized_height: 8,
                score: (1 << 64) | 2,
            })
        );
        assert!(ChainStatistics::decode(&body[..31]).is_err());
    }

    #[test]
    fn writes_a_pull_transactions_request() {
        let mut hash = [0; 32];
        hash[..4].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        let short = short_hash(&Hash256(hash));
        assert_eq!(short, 0xddcc_bbaa);
        assert_eq!(
            pull_transactions_request(0x0102_0304_0506_0708, 100, &[short]),
            [
                &[8, 7, 6, 5, 4, 3, 2, 1][..],
                &[100, 0, 0, 0],
                &[0xaa, 0xbb, 0xcc, 0xdd]
            ]
            .concat()
        );
        assert_eq!(pull_transactions_request(0, 0, &[]), [0; 12]);
    }

    #[test]
    fn writes_and_reads_headers() {
        let packet = encode(5, &[1, 2, 3]).unwrap();
        assert_eq!(packet, [11, 0, 0, 0, 5, 0, 0, 0, 1, 2, 3]);
        let header = Header::parse(packet[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(
            header,
            Header {
                size: 11,
                packet_type: 5
            }
        );
        assert_eq!(header.body_size(), Some(3));
        assert_eq!(Header::parse(&[7, 0, 0, 0, 1, 0, 0, 0]).body_size(), None);
    }

    #[test]
    fn writes_a_pull_blocks_request() {
        assert_eq!(
            pull_blocks_request(0x0102, 3, 0x0405),
            [2, 1, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 5, 4, 0, 0]
        );
    }

    #[test]
    fn names_unknown_roles() {
        assert_eq!(NodeRoles(0).to_string(), "None");
        assert_eq!(NodeRoles(0x105).to_string(), "Peer|Voting|0x100");
    }

    #[test]
    fn writes_roles_for_config_without_unknown_bits() {
        assert_eq!(NodeRoles(0x43).to_config_value(), "Peer,Api,IPv4");
        assert_eq!(NodeRoles(0x141).to_config_value(), "Peer,IPv4");
        assert!(NodeRoles(0x41).contains(NodeRoles::PEER));
        assert!(!NodeRoles(0x42).contains(NodeRoles::PEER));
    }

    #[test]
    fn splits_entities_and_rejects_truncated_ones() {
        let body = [&5_u32.to_le_bytes()[..], b"x", &4_u32.to_le_bytes()].concat();
        assert_eq!(
            split_size_prefixed(&body).unwrap(),
            [&body[..5], &body[5..]]
        );
        assert!(split_size_prefixed(&body[..7]).is_err());
        assert!(split_size_prefixed(&3_u32.to_le_bytes()).is_err());
    }
}
