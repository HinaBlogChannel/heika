//! ノードに TLS でつなぎ、公開されている情報を問い合わせる。
//!
//! パケットの形は heika-packet、TLS の接続は heika-tls にある。ここは、要求を1つ送って応答を1つ受け取る問い合わせ。

use std::fmt;
use std::time::Duration;

use heika_block::finalization::FinalizedBlockHeader;
use heika_packet::{
    ChainStatistics, DecodeError, NetworkNode, packet_type, pull_blocks_request,
    pull_transactions_request, split_size_prefixed,
};
use heika_tls::{ConnectError, Connection, Identity, RequestError};

/// ファイナライズの問い合わせのパケットの種類。catapult の
/// `extensions/finalization/src/handlers/ProofHandlers.cpp` と `FinalizationPackets.h`
mod finalization_packet_type {
    pub const FINALIZATION_STATISTICS: u32 = 0x132;
    pub const FINALIZATION_PROOF_AT_EPOCH: u32 = 0x133;
    /// 証明の要求への応答は、この種類で来る
    pub const PULL_FINALIZATION_PROOF: u32 = 0x135;
}

/// catapult の `ionet::PacketType::Block_Hashes`
const BLOCK_HASHES: u32 = 7;

/// 応答の本体として受け付ける大きさの上限。ブロックはバイト数の上限を超えても1件は返ってくるので、
/// メインネットのネメシスのブロック（4.7 MB）が収まるだけの余裕をとる。
const MAX_BODY_SIZE: usize = 32 * 1024 * 1024;

/// ノードへ問い合わせる側の接続。要求を1つ送って、応答を1つ受け取る。
#[derive(Debug)]
pub struct ClientConnection {
    connection: Connection,
}

impl ClientConnection {
    /// `address` に接続する。相手のチェーンは catapult と同じ条件で確かめる。
    pub fn connect(
        address: &str,
        identity: &Identity,
        timeout: Duration,
    ) -> Result<Self, ConnectError> {
        Connection::open(address, identity, timeout).map(|connection| Self { connection })
    }

    /// 相手が出した証明書の DER。ノード、CA の順のはず。
    pub fn peer_certificates(&self) -> Vec<Vec<u8>> {
        self.connection.peer_certificates()
    }

    /// チェーンの高さ、確定した高さ、スコア。
    pub fn chain_statistics(&mut self) -> Result<ChainStatistics, QueryError> {
        let body = self.request(packet_type::CHAIN_STATISTICS, &[])?;
        Ok(ChainStatistics::decode(&body)?)
    }

    /// ノード自身の情報。
    pub fn info(&mut self) -> Result<NetworkNode, QueryError> {
        let body = self.request(packet_type::NODE_DISCOVERY_PULL_PING, &[])?;
        Ok(NetworkNode::decode(&body)?)
    }

    /// ノードが知っているほかのノード。
    pub fn peers(&mut self) -> Result<Vec<NetworkNode>, QueryError> {
        let body = self.request(packet_type::NODE_DISCOVERY_PULL_PEERS, &[])?;
        Ok(NetworkNode::decode_list(&body)?)
    }

    /// `height` から最大 `num_blocks` 件、合計 `num_response_bytes` バイトまでのブロックを取る。
    ///
    /// ノードは設定の `maxBlocksPerSyncAttempt` と `maxChainBytesPerSyncAttempt` で切り詰め、
    /// バイト数の上限を超えても最低1件は返す。高さがチェーンより先なら空になる。
    /// ブロックの中身は確かめず、1件ずつに切り出すだけにする。
    pub fn pull_blocks(
        &mut self,
        height: u64,
        num_blocks: u32,
        num_response_bytes: u32,
    ) -> Result<Vec<Vec<u8>>, QueryError> {
        let request = pull_blocks_request(height, num_blocks, num_response_bytes);
        let body = self.request(packet_type::PULL_BLOCKS, &request)?;
        // ブロックはパディングなしで隙間なく並ぶ（catapult の `PacketPayloadBuilder::appendEntities`）
        Ok(split_size_prefixed(&body)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect())
    }

    /// `height` から最大 `num_hashes` 件のブロックのハッシュを、高さの順に取る。
    ///
    /// ノードは設定の `maxHashesPerSyncAttempt` と持っているブロックの数で切り詰める。高さがチェーンより先なら空になる。
    /// 分かれ目を探すのに使う（catapult の `CompareChains`）。
    pub fn pull_block_hashes(
        &mut self,
        height: u64,
        num_hashes: u32,
    ) -> Result<Vec<[u8; 32]>, QueryError> {
        let mut request = Vec::with_capacity(12);
        request.extend_from_slice(&height.to_le_bytes());
        request.extend_from_slice(&num_hashes.to_le_bytes());
        let body = self.request(BLOCK_HASHES, &request)?;
        if body.len() % 32 != 0 || body.len() / 32 > num_hashes as usize {
            return Err(QueryError::Decode(DecodeError::BodySize {
                expected: num_hashes as usize * 32,
                actual: body.len(),
            }));
        }
        Ok(body.as_chunks::<32>().0.to_vec())
    }

    /// ノードの未承認のトランザクションのうち、期限が `min_deadline` 以降で、最大手数料がサイズに
    /// `min_fee_multiplier` を掛けた額以上のものを取る。`known_short_hashes`（[`heika_packet::short_hash`]）にあるものは返ってこない。
    ///
    /// ノードは返すバイト数を設定の上限で切るので、未承認のトランザクションが多いと全部は返ってこない。
    /// トランザクションの中身は確かめず、1件ずつに切り出すだけにする。
    pub fn pull_transactions(
        &mut self,
        min_deadline: u64,
        min_fee_multiplier: u32,
        known_short_hashes: &[u32],
    ) -> Result<Vec<Vec<u8>>, QueryError> {
        let request =
            pull_transactions_request(min_deadline, min_fee_multiplier, known_short_hashes);
        let body = self.request(packet_type::PULL_TRANSACTIONS, &request)?;
        // ブロックと同じく、パディングなしで隙間なく並ぶ
        Ok(split_size_prefixed(&body)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect())
    }

    /// ノードが最後にファイナライズしたラウンド、高さ、ハッシュ。
    pub fn finalization_statistics(&mut self) -> Result<FinalizedBlockHeader, QueryError> {
        let body = self.request(finalization_packet_type::FINALIZATION_STATISTICS, &[])?;
        FinalizedBlockHeader::from_bytes(&body).map_err(|error| {
            QueryError::Decode(DecodeError::BodySize {
                expected: FinalizedBlockHeader::SIZE,
                actual: error.0,
            })
        })
    }

    /// エポック `epoch` のファイナライズの証明のバイト列（catapult の `FinalizationProof`）。
    /// ノードが持っていなければ `None`。中身は確かめない。
    pub fn finalization_proof_at_epoch(
        &mut self,
        epoch: u32,
    ) -> Result<Option<Vec<u8>>, QueryError> {
        // catapult は、この要求に違う種類で応答する
        self.connection.send_packet(
            finalization_packet_type::FINALIZATION_PROOF_AT_EPOCH,
            &epoch.to_le_bytes(),
        )?;
        let (response_type, body) = self.connection.receive_packet(MAX_BODY_SIZE)?;
        if response_type != finalization_packet_type::PULL_FINALIZATION_PROOF {
            return Err(QueryError::Request(RequestError::UnexpectedType(
                response_type,
            )));
        }
        // 持っていないときは、本体のない応答が返る
        Ok((!body.is_empty()).then_some(body))
    }

    fn request(&mut self, packet_type: u32, body: &[u8]) -> Result<Vec<u8>, QueryError> {
        Ok(self.connection.request(packet_type, body, MAX_BODY_SIZE)?)
    }
}

/// 問い合わせが失敗した理由。
#[derive(Debug)]
pub enum QueryError {
    Request(RequestError),
    Decode(DecodeError),
}

impl From<RequestError> for QueryError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<DecodeError> for QueryError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::Decode(error) => write!(f, "応答を読めませんでした: {error}"),
        }
    }
}

impl std::error::Error for QueryError {}
