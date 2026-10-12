//! アグリゲート。catbuffer の `aggregate/aggregate.cats` と、catapult の aggregate プラグイン。
//!
//! いくつかのトランザクションを、全部成功するか全部失敗するかのひとまとまりにする。
//! 中のトランザクション（embedded）は署名を持たず、署名者は外側の署名か連署で示す。

use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::merkle;
use heika_core::network::NetworkIdentifier;
use heika_core::signature::Signature;
use sha3::{Digest, Sha3_256};

use crate::{Body, DecodeError, Reader};

/// embedded のヘッダー。サイズ、予約、署名者の公開鍵、予約、バージョン、ネットワーク、種類。
const EMBEDDED_HEADER_SIZE: usize = 4 + 4 + 32 + 4 + 1 + 1 + 2;

/// 中のトランザクションより前の部分。中のトランザクションのハッシュ、それらの長さ、予約。
pub(crate) const FIXED_SIZE: usize = 32 + 4 + 4;

/// 連署の長さ。バージョン、署名者の公開鍵、署名。
const COSIGNATURE_SIZE: usize = 8 + 32 + 64;

/// アグリゲートの中のトランザクション。catbuffer の `EmbeddedTransaction` に、種類ごとの本体が続く。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EmbeddedTransaction {
    pub signer_public_key: PublicKey,
    pub network: NetworkIdentifier,
    pub body: Body,
}

impl EmbeddedTransaction {
    pub fn new(signer_public_key: PublicKey, network: NetworkIdentifier, body: Body) -> Self {
        Self {
            signer_public_key,
            network,
            body,
        }
    }

    /// 8バイト境界までの埋め草を含まないバイト列。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        self.body.encode(&mut body);
        let size = EMBEDDED_HEADER_SIZE + body.len();
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&(size as u32).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.signer_public_key.0);
        bytes.extend_from_slice(&[0; 4]);
        bytes.push(self.body.version());
        bytes.push(self.network.0);
        bytes.extend_from_slice(&self.body.transaction_type().to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// Merkle ツリーの葉にするハッシュ。埋め草を含まないバイト列の SHA3-256。
    /// catapult の `AggregateTransactionsHashValidator` の `HashEmbeddedTransaction`。
    pub fn hash(&self) -> Hash256 {
        Hash256(Sha3_256::digest(self.to_bytes()).into())
    }

    /// 埋め草まで含めた SHA3-256。バージョン 1 で許されていた、誤った葉の求め方
    /// （`HashEmbeddedTransactionWithPadding`）。
    fn padded_hash(&self) -> Hash256 {
        let mut bytes = self.to_bytes();
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        Hash256(Sha3_256::digest(bytes).into())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader(bytes);
        reader.u32();
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        let signer_public_key = PublicKey(reader.array());
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        let version = reader.u8();
        let network = NetworkIdentifier(reader.u8());
        let transaction_type = reader.u16();
        if Body::is_aggregate_type(transaction_type) {
            return Err(DecodeError::NestedAggregate);
        }
        let body = Body::decode(transaction_type, version, reader.0)?;
        Ok(Self {
            signer_public_key,
            network,
            body,
        })
    }
}

/// 連署。外側の署名者のほかに同意が要るアカウントが、アグリゲートのハッシュに署名したもの。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cosignature {
    pub signer_public_key: PublicKey,
    pub signature: Signature,
}

impl Cosignature {
    /// アグリゲートのハッシュに署名する。ハッシュは連署を含まないので、連署を足しても変わらない。
    pub fn sign(private_key: &PrivateKey, transaction_hash: &Hash256) -> Self {
        Self {
            signer_public_key: PublicKey::from_private_key(private_key),
            signature: private_key.sign(&[&transaction_hash.0]),
        }
    }

    pub fn verify(&self, transaction_hash: &Hash256) -> bool {
        self.signer_public_key
            .verify(&[&transaction_hash.0], &self.signature)
    }
}

/// アグリゲートの構造のバージョン。形は同じで、署名の範囲と、中のトランザクションのハッシュの決まりが違う。
///
/// 新しく作るのはいつもバージョン 3。それより前のものは、チェーンにあるものを読むためだけに扱う。
/// どの高さでどのバージョンが使えるかは、catapult の `AggregateTransactionVersionValidator` と
/// ネットワークの設定の `[fork_heights]` で決まる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AggregateVersion {
    /// メインネットで高さ 1,690,500（strictAggregateTransactionHash）より前。
    /// 中のトランザクションのハッシュに誤った求め方も許されていたので、中身から求めずに、書いてあったものを持つ
    V1 {
        transactions_hash: Hash256,
    },
    /// メインネットで高さ 4,759,100（uniqueAggregateTransactionHash）より前。
    /// 署名の範囲に、中のトランザクションの長さを含まない
    V2,
    V3,
}

impl AggregateVersion {
    pub fn number(self) -> u8 {
        match self {
            Self::V1 { .. } => 1,
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }

    /// 本体のうち、署名の範囲に入らない後ろの部分の長さ。catapult の `Footer_Size` と `Pre_V3_Footer_Size`。
    pub(crate) fn footer_size(self) -> usize {
        match self {
            Self::V3 => 4,
            _ => 4 + 4,
        }
    }
}

/// 中のトランザクションのハッシュが、どの求め方と合うか。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransactionsHashCalculation {
    /// 正しい求め方。バージョン 2 からは、これしか認められない
    Correct,
    /// バージョン 1 で許されていた誤った求め方（葉に埋め草を含める、誤った Merkle の根、またはその両方）
    Legacy,
    /// どの求め方とも合わない。バージョン 1 には、ネットワークの設定の
    /// `[corrupt_aggregate_transaction_hashes]` に載せて認めたものがある。
    /// 署名は書いてあったハッシュにしか掛かっていないので、表示している中身が署名されたものとは限らない
    Unknown,
}

/// アグリゲートの本体。中のトランザクションと連署。
///
/// 中のトランザクションのハッシュは中身から決まるので持たず、書くときに求める（バージョン 1 を除く）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Aggregate {
    version: AggregateVersion,
    transactions: Vec<EmbeddedTransaction>,
    cosignatures: Vec<Cosignature>,
}

impl Aggregate {
    /// 中のトランザクションから、連署のないアグリゲート（バージョン 3）を作る。アグリゲートは入れ子にできない。
    pub fn new(transactions: Vec<EmbeddedTransaction>) -> Result<Self, NestedAggregate> {
        if transactions
            .iter()
            .any(|transaction| Body::is_aggregate_type(transaction.body.transaction_type()))
        {
            return Err(NestedAggregate);
        }
        Ok(Self {
            version: AggregateVersion::V3,
            transactions,
            cosignatures: Vec::new(),
        })
    }

    pub fn version(&self) -> AggregateVersion {
        self.version
    }

    pub fn transactions(&self) -> &[EmbeddedTransaction] {
        &self.transactions
    }

    pub fn cosignatures(&self) -> &[Cosignature] {
        &self.cosignatures
    }

    pub fn add_cosignature(&mut self, cosignature: Cosignature) {
        self.cosignatures.push(cosignature);
    }

    /// 中のトランザクションのハッシュ。署名はこれに掛かる。
    /// ふつうは、それぞれのハッシュを葉にした Merkle ツリーの根。バージョン 1 は、書いてあったもの。
    pub fn transactions_hash(&self) -> Hash256 {
        match self.version {
            AggregateVersion::V1 { transactions_hash } => transactions_hash,
            _ => self.correct_transactions_hash(),
        }
    }

    fn correct_transactions_hash(&self) -> Hash256 {
        let leaves: Vec<_> = self
            .transactions
            .iter()
            .map(EmbeddedTransaction::hash)
            .collect();
        merkle::root(&leaves)
    }

    /// 中のトランザクションのハッシュが、どの求め方と合うか。
    /// catapult の `AggregateTransactionsHashValidator` と同じ順に確かめる。
    pub fn transactions_hash_calculation(&self) -> TransactionsHashCalculation {
        let hash = self.transactions_hash();
        if hash == self.correct_transactions_hash() {
            return TransactionsHashCalculation::Correct;
        }
        let leaves: Vec<_> = self
            .transactions
            .iter()
            .map(EmbeddedTransaction::hash)
            .collect();
        let padded: Vec<_> = self
            .transactions
            .iter()
            .map(EmbeddedTransaction::padded_hash)
            .collect();
        if [
            merkle::root(&padded),
            merkle::invalid_root(&leaves),
            merkle::invalid_root(&padded),
        ]
        .contains(&hash)
        {
            TransactionsHashCalculation::Legacy
        } else {
            TransactionsHashCalculation::Unknown
        }
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        for transaction in &self.transactions {
            payload.extend_from_slice(&transaction.to_bytes());
            payload.resize(payload.len().next_multiple_of(8), 0);
        }
        out.extend_from_slice(&self.transactions_hash().0);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&payload);
        for cosignature in &self.cosignatures {
            out.extend_from_slice(&[0; 8]);
            out.extend_from_slice(&cosignature.signer_public_key.0);
            out.extend_from_slice(&cosignature.signature.0);
        }
    }

    /// catapult の `IsSizeValid` と同じく、中のトランザクションの長さが8の倍数で、
    /// 残りが連署の長さの倍数になっているものを読む。
    /// バージョン 2 からは、中のトランザクションのハッシュが正しく求めたものと合わなければ弾く。
    /// バージョン 1 は、どのハッシュでも読む（[`Aggregate::transactions_hash_calculation`] で確かめる）。
    pub(crate) fn decode(version: u8, bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < FIXED_SIZE {
            return Err(DecodeError::InvalidBodySize);
        }
        let mut reader = Reader(bytes);
        let transactions_hash = Hash256(reader.array());
        let payload_size = reader.u32() as usize;
        if reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        if !payload_size.is_multiple_of(8)
            || payload_size > reader.0.len()
            || !(reader.0.len() - payload_size).is_multiple_of(COSIGNATURE_SIZE)
        {
            return Err(DecodeError::InvalidBodySize);
        }
        let (mut payload, cosignatures) = reader.0.split_at(payload_size);

        let mut transactions = Vec::new();
        while !payload.is_empty() {
            let size = match payload.first_chunk() {
                Some(size) => u32::from_le_bytes(*size) as usize,
                None => return Err(DecodeError::InvalidBodySize),
            };
            let padded_size = size.next_multiple_of(8);
            if size < EMBEDDED_HEADER_SIZE || padded_size > payload.len() {
                return Err(DecodeError::InvalidBodySize);
            }
            if payload[size..padded_size].iter().any(|&byte| byte != 0) {
                return Err(DecodeError::NonZeroReserved);
            }
            transactions.push(EmbeddedTransaction::decode(&payload[..size])?);
            payload = &payload[padded_size..];
        }

        let cosignatures = cosignatures
            .chunks(COSIGNATURE_SIZE)
            .map(|chunk| {
                let mut reader = Reader(chunk);
                if reader.u64() != 0 {
                    return Err(DecodeError::NonZeroReserved);
                }
                Ok(Cosignature {
                    signer_public_key: PublicKey(reader.array()),
                    signature: Signature(reader.array()),
                })
            })
            .collect::<Result<_, _>>()?;

        let version = match version {
            1 => AggregateVersion::V1 { transactions_hash },
            2 => AggregateVersion::V2,
            _ => AggregateVersion::V3,
        };
        let aggregate = Self {
            version,
            transactions,
            cosignatures,
        };
        if aggregate.transactions_hash() != transactions_hash {
            return Err(DecodeError::TransactionsHashMismatch);
        }
        Ok(aggregate)
    }
}

/// アグリゲートの中にアグリゲートを入れようとした。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedAggregate;

impl std::fmt::Display for NestedAggregate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("アグリゲートの中にアグリゲートは入れられません")
    }
}

impl std::error::Error for NestedAggregate {}

#[cfg(test)]
mod tests {
    use heika_core::network::GenerationHashSeed;

    use super::*;
    use crate::{KeyLink, LinkAction, Transaction};

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1 と 2 の秘密鍵
    const SIGNER: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    const COSIGNER: &str = "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB";

    /// 外側のトランザクションのヘッダーの長さ
    const BODY: usize = 128;

    fn signer() -> PrivateKey {
        SIGNER.parse().unwrap()
    }

    fn seed() -> GenerationHashSeed {
        GenerationHashSeed([0x5E; 32])
    }

    fn link(byte: u8) -> EmbeddedTransaction {
        EmbeddedTransaction::new(
            PublicKey::from_private_key(&signer()),
            NetworkIdentifier::TESTNET,
            Body::VrfKeyLink(KeyLink {
                linked_public_key: PublicKey([byte; 32]),
                link_action: LinkAction::Link,
            }),
        )
    }

    fn aggregate(transactions: Vec<EmbeddedTransaction>) -> Transaction {
        Transaction::new(
            PublicKey::from_private_key(&signer()),
            NetworkIdentifier::TESTNET,
            0,
            0,
            Body::AggregateComplete(Aggregate::new(transactions).unwrap()),
        )
    }

    fn body(transaction: &mut Transaction) -> &mut Aggregate {
        match &mut transaction.body {
            Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) => aggregate,
            _ => unreachable!(),
        }
    }

    #[test]
    fn writes_embedded_transactions_with_a_short_header() {
        let bytes = link(0xAA).to_bytes();
        assert_eq!(bytes.len(), 81);
        assert_eq!(bytes[..8], [81, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bytes[8..40], PublicKey::from_private_key(&signer()).0);
        assert_eq!(bytes[40..48], [0, 0, 0, 0, 1, 0x98, 0x43, 0x42]);
        assert_eq!(bytes[48..80], [0xAA; 32]);
    }

    #[test]
    fn writes_the_catbuffer_layout() {
        let transaction = aggregate(vec![link(1), link(2)]);
        let bytes = transaction.to_bytes();
        assert_eq!(bytes.len(), BODY + 40 + 2 * 88);
        assert_eq!(bytes[108..112], [3, 0x98, 0x41, 0x41]);
        let leaves = [link(1).hash(), link(2).hash()];
        assert_eq!(bytes[BODY..BODY + 32], merkle::root(&leaves).0);
        assert_eq!(bytes[BODY + 32..BODY + 40], [176, 0, 0, 0, 0, 0, 0, 0]);
        // それぞれ 81 バイトを 88 バイトまで0で埋める
        assert_eq!(bytes[BODY + 40..BODY + 121], link(1).to_bytes());
        assert_eq!(bytes[BODY + 121..BODY + 128], [0; 7]);
        assert_eq!(bytes[BODY + 128..BODY + 209], link(2).to_bytes());
    }

    #[test]
    fn round_trips_with_cosignatures() {
        let mut transaction = aggregate(vec![link(1), link(2), link(3)]);
        transaction.sign(&signer(), &seed()).unwrap();
        let hash = transaction.hash(&seed());
        let cosigner: PrivateKey = COSIGNER.parse().unwrap();
        body(&mut transaction).add_cosignature(Cosignature::sign(&cosigner, &hash));
        let bytes = transaction.to_bytes();
        assert_eq!(bytes.len(), BODY + 40 + 3 * 88 + 104);
        assert_eq!(Transaction::from_bytes(&bytes), Ok(transaction));
    }

    #[test]
    fn signs_the_header_and_the_transactions_hash_but_not_the_cosignatures() {
        let mut transaction = aggregate(vec![link(1)]);
        transaction.sign(&signer(), &seed()).unwrap();
        let bytes = transaction.to_bytes();
        let signature = signer().sign(&[&seed().0, &bytes[108..164]]);
        assert_eq!(transaction.signature, signature);

        let hash = transaction.hash(&seed());
        let cosigner: PrivateKey = COSIGNER.parse().unwrap();
        let cosignature = Cosignature::sign(&cosigner, &hash);
        assert!(cosignature.verify(&hash));
        body(&mut transaction).add_cosignature(cosignature);
        assert_eq!(transaction.hash(&seed()), hash);
        assert!(transaction.verify(&seed()));
    }

    #[test]
    fn a_changed_embedded_transaction_breaks_the_signature() {
        let mut transaction = aggregate(vec![link(1)]);
        transaction.sign(&signer(), &seed()).unwrap();
        let mut changed = aggregate(vec![link(2)]);
        changed.signature = transaction.signature;
        assert!(!changed.verify(&seed()));
    }

    /// 古いバージョンのアグリゲート。テストのために、外からは作れないものを作る
    fn old(transactions: Vec<EmbeddedTransaction>, version: AggregateVersion) -> Transaction {
        let mut transaction = aggregate(transactions);
        body(&mut transaction).version = version;
        transaction
    }

    #[test]
    fn version_2_signs_up_to_the_transactions_hash() {
        let mut transaction = old(vec![link(1)], AggregateVersion::V2);
        transaction.sign(&signer(), &seed()).unwrap();
        let bytes = transaction.to_bytes();
        assert_eq!(bytes[108], 2);
        let signature = signer().sign(&[&seed().0, &bytes[108..160]]);
        assert_eq!(transaction.signature, signature);
        assert_eq!(Transaction::from_bytes(&bytes), Ok(transaction.clone()));

        // 中のトランザクションの長さは署名されていないので、バージョン 3 と同じ署名にはならない
        let mut current = aggregate(vec![link(1)]);
        current.sign(&signer(), &seed()).unwrap();
        assert_ne!(current.signature, transaction.signature);

        let mut wrong_hash = bytes.clone();
        wrong_hash[BODY] ^= 1;
        assert_eq!(
            Transaction::from_bytes(&wrong_hash),
            Err(DecodeError::TransactionsHashMismatch)
        );
    }

    #[test]
    fn version_1_keeps_the_written_transactions_hash() {
        let transactions = vec![link(1), link(2), link(3)];
        let leaves: Vec<_> = transactions.iter().map(EmbeddedTransaction::hash).collect();
        let padded: Vec<_> = transactions
            .iter()
            .map(EmbeddedTransaction::padded_hash)
            .collect();
        for (transactions_hash, calculation) in [
            (merkle::root(&leaves), TransactionsHashCalculation::Correct),
            (merkle::root(&padded), TransactionsHashCalculation::Legacy),
            (
                merkle::invalid_root(&leaves),
                TransactionsHashCalculation::Legacy,
            ),
            (
                merkle::invalid_root(&padded),
                TransactionsHashCalculation::Legacy,
            ),
            (Hash256([0xAB; 32]), TransactionsHashCalculation::Unknown),
        ] {
            let mut transaction = old(
                transactions.clone(),
                AggregateVersion::V1 { transactions_hash },
            );
            transaction.sign(&signer(), &seed()).unwrap();
            let bytes = transaction.to_bytes();
            assert_eq!(bytes[108], 1);
            assert_eq!(bytes[BODY..BODY + 32], transactions_hash.0);
            let read = Transaction::from_bytes(&bytes).unwrap();
            assert_eq!(read, transaction);
            assert!(read.verify(&seed()));
            let Body::AggregateComplete(aggregate) = &read.body else {
                unreachable!()
            };
            assert_eq!(
                aggregate.transactions_hash_calculation(),
                calculation,
                "{transactions_hash}"
            );
        }
    }

    #[test]
    fn refuses_to_nest_aggregates() {
        let inner = EmbeddedTransaction::new(
            PublicKey([1; 32]),
            NetworkIdentifier::TESTNET,
            Body::AggregateBonded(Aggregate::new(Vec::new()).unwrap()),
        );
        assert_eq!(Aggregate::new(vec![inner]), Err(NestedAggregate));
    }

    #[test]
    fn rejects_malformed_aggregates() {
        let bytes = aggregate(vec![link(1)]).to_bytes();
        let mut nested = bytes.clone();
        nested[BODY + 40 + 46..BODY + 40 + 48].copy_from_slice(&0x4141u16.to_le_bytes());
        let mut wrong_hash = bytes.clone();
        wrong_hash[BODY] ^= 1;
        let mut padding = bytes.clone();
        *padding.last_mut().unwrap() = 1;
        let mut unaligned = bytes.clone();
        unaligned[BODY + 32] = 81;
        let mut short_embedded = bytes.clone();
        short_embedded[BODY + 40] = 40;
        let mut cosignature_version = [bytes.as_slice(), &[0; 104]].concat();
        cosignature_version[BODY + 128] = 1;
        let mut version = bytes.clone();
        version[108] = 4;
        for (name, mut bytes, error) in [
            ("nested", nested, DecodeError::NestedAggregate),
            (
                "wrong hash",
                wrong_hash,
                DecodeError::TransactionsHashMismatch,
            ),
            ("padding", padding, DecodeError::NonZeroReserved),
            ("unaligned", unaligned, DecodeError::InvalidBodySize),
            (
                "short embedded",
                short_embedded,
                DecodeError::InvalidBodySize,
            ),
            (
                "partial cosignature",
                [bytes.as_slice(), &[0; 8]].concat(),
                DecodeError::InvalidBodySize,
            ),
            (
                "cosignature version",
                cosignature_version,
                DecodeError::NonZeroReserved,
            ),
            (
                "version",
                version,
                DecodeError::UnsupportedVersion {
                    transaction_type: 0x4141,
                    version: 4,
                },
            ),
        ] {
            let size = bytes.len() as u32;
            bytes[..4].copy_from_slice(&size.to_le_bytes());
            assert_eq!(Transaction::from_bytes(&bytes), Err(error), "{name}");
        }
    }
}
