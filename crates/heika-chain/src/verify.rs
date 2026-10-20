//! ノードから取ったブロックを、状態を見ずに確かめられるところまで確かめる。
//!
//! 確かめるのは、ネットワーク、高さ、1つ前のブロックのハッシュとのつながり、ハーベストした人の署名と公開鍵が0でないこと、
//! 中のトランザクションと TransactionsHash、トランザクションごとの署名とアグリゲートの連署
//! （catapult の `BlockBatchSignatureConsumer`）、ブロックの版と種類、トランザクションの数、受け取り先のアドレス、
//! トランザクションの状態に依らない規則（[`Transaction::validate`]）、アグリゲートの版と中身のハッシュ。署名した人にハーベストの資格があるか、VRF の証明、
//! ReceiptsHash、StateHash は、状態を持って実行するまで確かめられない。
//!
//! 前後のブロックに依らないもの（[`verify_alone`]）と、1つ前のブロックとのつながり（[`verify_link`]）に分ける。
//! 前者は重い（署名とトランザクションのハッシュ）が、ブロックごとに並列に確かめられる。
//! どの Nemesis から始めるかは、ネットワークごとに決めたハッシュ（[`nemesis_hash`]）で信じる。

use std::fmt;

use heika_block::{Block, BlockType};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_transaction::{Body, Transaction, TransactionsHashCalculation};

/// `maxTransactionsPerBlock`。メインネットもテストネットも同じ
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 6_000;

/// 知っているネットワークの Nemesis のブロックのハッシュ。ここから始まるチェーンだけを受け入れる。決め打ちのない
/// ネットワーク（プライベートなネットワークなど）では `None` なので、使う側が設定から渡す
pub fn nemesis_hash(network: NetworkIdentifier) -> Option<Hash256> {
    let hex = match network {
        NetworkIdentifier::MAINNET => {
            "BEED005B82B22FC32DA6FDF4DFEB7C11BA6A8C5C504EB7B9CCF91B9B2A09E020"
        }
        NetworkIdentifier::TESTNET => {
            "135B9276FE14D6724F87764DD3F8E332813AE9A36D1A7953B12213EA9ACB6B97"
        }
        _ => return None,
    };
    hex.parse().ok()
}

/// 確かめた最後のブロック。次のブロックはこれにつながる。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tip {
    pub height: u64,
    pub hash: Hash256,
    /// 最後の importance ブロック（まだなければ Nemesis）のハッシュ。次の importance ブロックが、これを指す
    pub importance_hash: Hash256,
}

/// ブロックが確かめられなかったわけ。
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerifyError {
    Network,
    Height {
        expected: u64,
        actual: u64,
    },
    /// 高さ 1 は Nemesis、importanceGrouping の倍数は importance ブロック、ほかはふつうのブロック
    BlockType(BlockType),
    /// ブロックの版が 1 でない
    BlockVersion(u8),
    /// 受け取り先のアドレスのネットワークかチェックサムが合わない
    Beneficiary,
    /// ハーベストした人の公開鍵が0
    ZeroPublicKey,
    /// 受け取り先が、公開鍵が0のアカウントのアドレス
    ZeroAddress,
    /// トランザクションの数（アグリゲートの中も数える）が多すぎる
    TooManyTransactions(usize),
    /// 何件目（0から）のトランザクションが、状態に依らない規則で弾かれるか
    TransactionRule(usize, String),
    /// 何件目（0から）のアグリゲートの版が、この高さのものでない
    AggregateVersion(usize, u8),
    /// 何件目（0から）のアグリゲートの中身のハッシュが、どの求め方とも合わない
    AggregateTransactionsHash(usize),
    PreviousHash {
        expected: Hash256,
        actual: Hash256,
    },
    /// importance ブロックの PreviousImportanceBlockHash が、1つ前の importance ブロックを指していない
    ImportanceLink {
        expected: Hash256,
        actual: Hash256,
    },
    Signature,
    TransactionsHash,
    /// 中のトランザクションが読めない
    Transaction(String),
    /// Nemesis のブロックが、このネットワークのものと違う
    Nemesis(Hash256),
    /// 何件目（0から）のトランザクションの署名が合わない
    TransactionSignature(usize),
    /// 何件目（0から）のアグリゲートの連署が合わない
    Cosignature(usize),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network => write!(f, "ネットワークが違います"),
            Self::Height { expected, actual } => {
                write!(f, "高さ {expected} のはずが {actual} でした")
            }
            Self::BlockType(block_type) => {
                write!(f, "この高さに {block_type:?} のブロックは来ません")
            }
            Self::PreviousHash { expected, actual } => write!(
                f,
                "1つ前のブロックのハッシュが {expected} のはずが {actual} でした"
            ),
            Self::ImportanceLink { expected, actual } => write!(
                f,
                "1つ前の importance ブロックのハッシュが {expected} のはずが {actual} でした"
            ),
            Self::Signature => write!(f, "ハーベストした人の署名が合いません"),
            Self::TransactionSignature(index) => {
                write!(f, "{index} 件目のトランザクションの署名が合いません")
            }
            Self::Cosignature(index) => {
                write!(f, "{index} 件目のアグリゲートの連署が合いません")
            }
            Self::Nemesis(hash) => write!(
                f,
                "Nemesis のブロックのハッシュ {hash} が、このネットワークのものと違います"
            ),
            Self::TransactionsHash => {
                write!(f, "TransactionsHash が中のトランザクションと合いません")
            }
            Self::Transaction(error) => write!(f, "中のトランザクションが読めません: {error}"),
            Self::BlockVersion(version) => write!(f, "ブロックの版が {version} です"),
            Self::Beneficiary => write!(f, "受け取り先のアドレスが正しくありません"),
            Self::ZeroPublicKey => write!(f, "ハーベストした人の公開鍵が0です"),
            Self::ZeroAddress => write!(f, "受け取り先が、公開鍵が0のアカウントのアドレスです"),
            Self::TooManyTransactions(count) => write!(
                f,
                "トランザクションが {count} 件あり、{MAX_TRANSACTIONS_PER_BLOCK} 件を超えています"
            ),
            Self::TransactionRule(index, problem) => {
                write!(f, "{index} 件目のトランザクション: {problem}")
            }
            Self::AggregateVersion(index, version) => write!(
                f,
                "{index} 件目のアグリゲートの版 {version} は、この高さでは使えません"
            ),
            Self::AggregateTransactionsHash(index) => write!(
                f,
                "{index} 件目のアグリゲートの中身のハッシュが、どの求め方とも合いません"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// `block` が `tip` の次のブロックとして正しいかを確かめ、新しい `Tip` を返す。
/// `tip` が `None` なら、`block` は Nemesis のブロックでなければならない。
///
/// Nemesis そのものが正しいかは、ここでは確かめない。どの Nemesis から始めるかは、呼ぶ側が決めて信じる。
pub fn verify_next(
    parameters: &NetworkParameters,
    tip: Option<Tip>,
    block: &Block,
) -> Result<Tip, VerifyError> {
    verify_alone(parameters, block)?;
    verify_link(tip, block)
}

/// 前後のブロックに依らないところ。ネットワーク、高さとブロックの種類の組み合わせ、署名、TransactionsHash、
/// トランザクションごとの署名とアグリゲートの連署
pub fn verify_alone(parameters: &NetworkParameters, block: &Block) -> Result<(), VerifyError> {
    if block.network != parameters.identifier {
        return Err(VerifyError::Network);
    }
    // catapult の `BlockType`。ブロックの版は `EntityNotification` で確かめる
    let expected = if block.height == 1 {
        BlockType::Nemesis
    } else if block.height.is_multiple_of(parameters.importance_grouping) {
        BlockType::Importance
    } else {
        BlockType::Normal
    };
    if block.block_type != expected {
        return Err(VerifyError::BlockType(block.block_type));
    }
    if block.version != 1 {
        return Err(VerifyError::BlockVersion(block.version));
    }
    // catapult の `ZeroPublicKey`
    if block.signer_public_key.0 == [0; 32] {
        return Err(VerifyError::ZeroPublicKey);
    }
    // catapult の `Address` と `ZeroAddress`。ハーベストした人と違うときだけ確かめるが、同じならハーベストした人の
    // アドレスなので正しく、公開鍵が0でもない
    let beneficiary = &block.beneficiary_address;
    if beneficiary.network() != parameters.identifier || !beneficiary.has_valid_checksum() {
        return Err(VerifyError::Beneficiary);
    }
    if beneficiary.0 == Address::from_public_key(&PublicKey([0; 32]), parameters.identifier).0 {
        return Err(VerifyError::ZeroAddress);
    }
    if !block.verify_signature() {
        return Err(VerifyError::Signature);
    }
    let seed = &parameters.generation_hash_seed;
    match block.verify_transactions_hash(seed) {
        Ok(true) => {}
        Ok(false) => return Err(VerifyError::TransactionsHash),
        Err(error) => return Err(VerifyError::Transaction(error.to_string())),
    }
    let mut count = 0;
    for (index, bytes) in block.transactions().enumerate() {
        // Nemesis はハッシュで信じるので、署名のほかは確かめない（catapult も数の上限は Nemesis で見ない）
        if block.height == 1 {
            let transaction = Transaction::from_bytes(bytes)
                .map_err(|error| VerifyError::Transaction(error.to_string()))?;
            if !transaction.verify(seed) {
                return Err(VerifyError::TransactionSignature(index));
            }
            if !transaction.verify_cosignatures(seed) {
                return Err(VerifyError::Cosignature(index));
            }
            continue;
        }
        count += verify_transaction(parameters, block.height, index, bytes)?;
    }
    // catapult の `MaxTransactions`
    if block.height != 1 && count > MAX_TRANSACTIONS_PER_BLOCK {
        return Err(VerifyError::TooManyTransactions(count));
    }
    Ok(())
}

/// ブロックの `index` 件目のトランザクション（Nemesis のほか）の、前後に依らないところ。署名、連署、
/// トランザクションごとの規則、アグリゲートの版と TransactionsHash。ブロックの件数の上限に数える数（アグリゲートは
/// 中身も）を返す。ブロックを作るときに、入れる候補を選ぶのにも使う
pub fn verify_transaction(
    parameters: &NetworkParameters,
    height: u64,
    index: usize,
    bytes: &[u8],
) -> Result<usize, VerifyError> {
    let seed = &parameters.generation_hash_seed;
    let transaction = Transaction::from_bytes(bytes)
        .map_err(|error| VerifyError::Transaction(error.to_string()))?;
    if !transaction.verify(seed) {
        return Err(VerifyError::TransactionSignature(index));
    }
    if !transaction.verify_cosignatures(seed) {
        return Err(VerifyError::Cosignature(index));
    }
    if let Some(problem) = transaction.validate(parameters).first() {
        return Err(VerifyError::TransactionRule(index, problem.to_string()));
    }
    let mut count = 1;
    if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) = &transaction.body
    {
        count += aggregate.transactions().len();
        // catapult の `AggregateTransactionVersion` と `AggregateTransactionsHash`
        let version = aggregate.version().number();
        if version != parameters.aggregate_version(height) {
            return Err(VerifyError::AggregateVersion(index, version));
        }
        if aggregate.transactions_hash_calculation() == TransactionsHashCalculation::Unknown
            && !parameters
                .is_known_corrupt_aggregate(&transaction.hash(seed), &aggregate.transactions_hash())
        {
            return Err(VerifyError::AggregateTransactionsHash(index));
        }
    }
    Ok(count)
}

/// 1つ前のブロック `tip` とのつながり。高さと、1つ前のブロックのハッシュ。新しい `Tip` を返す
pub fn verify_link(tip: Option<Tip>, block: &Block) -> Result<Tip, VerifyError> {
    let expected = tip.map_or(1, |tip| tip.height + 1);
    if block.height != expected {
        return Err(VerifyError::Height {
            expected,
            actual: block.height,
        });
    }
    if let Some(tip) = tip
        && block.previous_block_hash != tip.hash
    {
        return Err(VerifyError::PreviousHash {
            expected: tip.hash,
            actual: block.previous_block_hash,
        });
    }
    // catapult の `BlockchainSyncConsumer` と `BlockchainCheckConsumer`。importance ブロックは、1つ前の importance ブロックを指す
    let hash = block.hash();
    let importance_hash = match (tip, &block.importance_footer) {
        (_, None) => tip.map_or(hash, |tip| tip.importance_hash),
        (None, Some(_)) => hash,
        (Some(tip), Some(footer)) => {
            if footer.previous_importance_block_hash != tip.importance_hash {
                return Err(VerifyError::ImportanceLink {
                    expected: tip.importance_hash,
                    actual: footer.previous_importance_block_hash,
                });
            }
            hash
        }
    };
    Ok(Tip {
        height: block.height,
        hash,
        importance_hash,
    })
}

#[cfg(test)]
mod tests {
    use heika_core::address::Address;
    use heika_core::key::{PrivateKey, PublicKey};
    use heika_transaction::{Aggregate, EmbeddedTransaction, KeyLink, LinkAction};

    use super::*;

    const NETWORK: NetworkParameters = NetworkParameters::MAINNET;

    fn private_key() -> PrivateKey {
        PrivateKey::from_bytes(&[7; 32])
    }

    fn signer() -> PublicKey {
        PublicKey::from_private_key(&private_key())
    }

    fn link(linked: u8) -> Body {
        Body::AccountKeyLink(KeyLink {
            linked_public_key: PublicKey([linked; 32]),
            link_action: LinkAction::Link,
        })
    }

    fn signed(body: Body) -> Transaction {
        let mut transaction = Transaction::new(signer(), NETWORK.identifier, 0, 0, body);
        transaction
            .sign(&private_key(), &NETWORK.generation_hash_seed)
            .unwrap();
        transaction
    }

    /// 中が `count` 件のアグリゲート（中のアグリゲートの版は今のもの）
    fn aggregate(count: usize) -> Transaction {
        let inner = (0..count)
            .map(|_| EmbeddedTransaction::new(signer(), NETWORK.identifier, link(1)))
            .collect();
        signed(Body::AggregateComplete(Aggregate::new(inner).unwrap()))
    }

    /// `edit` でヘッダーを書き換えてから、TransactionsHash を入れて署名したブロック
    fn block(
        height: u64,
        importance: bool,
        transactions: &[Transaction],
        edit: impl Fn(&mut [u8]),
    ) -> Block {
        let (block_type, header_size): (u16, usize) = if importance {
            (0x8243, 424)
        } else {
            (0x8143, 376)
        };
        let mut bytes = vec![0; header_size];
        for (index, transaction) in transactions.iter().enumerate() {
            bytes.extend_from_slice(&transaction.to_bytes());
            if index + 1 < transactions.len() {
                bytes.resize(bytes.len().next_multiple_of(8), 0);
            }
        }
        let size = bytes.len() as u32;
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        bytes[72..104].copy_from_slice(&signer().0);
        bytes[108] = 1;
        bytes[109] = NETWORK.identifier.0;
        bytes[110..112].copy_from_slice(&block_type.to_le_bytes());
        bytes[112..120].copy_from_slice(&height.to_le_bytes());
        bytes[344..368].copy_from_slice(&Address::from_public_key(&signer(), NETWORK.identifier).0);
        edit(&mut bytes);
        let hash = Block::from_bytes(&bytes)
            .unwrap()
            .calculate_transactions_hash(&NETWORK.generation_hash_seed)
            .unwrap();
        bytes[248..280].copy_from_slice(&hash.0);
        let signed_end = if header_size == 376 { 372 } else { header_size };
        let signature = private_key().sign(&[&bytes[108..signed_end]]);
        bytes[8..72].copy_from_slice(&signature.0);
        Block::from_bytes(&bytes).unwrap()
    }

    /// 高さに合った種類のブロックで確かめる
    fn check(
        height: u64,
        transactions: &[Transaction],
        edit: impl Fn(&mut [u8]),
    ) -> Result<(), VerifyError> {
        let importance = height.is_multiple_of(NETWORK.importance_grouping);
        verify_alone(&NETWORK, &block(height, importance, transactions, edit))
    }

    #[test]
    fn accepts_a_block_that_follows_the_rules() {
        let transactions = [signed(link(1)), aggregate(2)];
        assert_eq!(check(5_000_001, &transactions, |_| {}), Ok(()));
        assert_eq!(check(5_000_400, &transactions, |_| {}), Ok(()));
    }

    #[test]
    fn rejects_a_block_type_that_does_not_match_the_height() {
        let verify =
            |height, importance| verify_alone(&NETWORK, &block(height, importance, &[], |_| {}));
        assert_eq!(verify(1_440, true), Ok(()));
        assert_eq!(
            verify(1_440, false),
            Err(VerifyError::BlockType(BlockType::Normal))
        );
        assert_eq!(
            verify(1_441, true),
            Err(VerifyError::BlockType(BlockType::Importance))
        );
    }

    #[test]
    fn rejects_other_block_versions_and_broken_beneficiaries() {
        assert_eq!(
            check(2, &[], |bytes| bytes[108] = 2),
            Err(VerifyError::BlockVersion(2))
        );
        assert_eq!(
            check(2, &[], |bytes| bytes[367] ^= 1),
            Err(VerifyError::Beneficiary)
        );
    }

    #[test]
    fn rejects_the_zero_public_key_and_the_zero_address() {
        assert_eq!(
            check(2, &[], |bytes| bytes[72..104].fill(0)),
            Err(VerifyError::ZeroPublicKey)
        );
        let zero = Address::from_public_key(&PublicKey([0; 32]), NETWORK.identifier);
        assert_eq!(
            check(2, &[], |bytes| bytes[344..368].copy_from_slice(&zero.0)),
            Err(VerifyError::ZeroAddress)
        );
    }

    #[test]
    fn rejects_transactions_that_break_stateless_rules() {
        let error = check(2, &[signed(link(1)), signed(link(0))], |_| {}).unwrap_err();
        assert!(
            matches!(error, VerifyError::TransactionRule(1, _)),
            "{error}"
        );
    }

    #[test]
    fn accepts_only_the_aggregate_version_of_the_height() {
        let transactions = [aggregate(1)];
        assert_eq!(check(4_759_100, &transactions, |_| {}), Ok(()));
        assert_eq!(
            check(4_759_099, &transactions, |_| {}),
            Err(VerifyError::AggregateVersion(0, 3))
        );
    }

    #[test]
    fn counts_the_inner_transactions_against_the_block_limit() {
        // アグリゲート 60 件と、その中の 100 件ずつで 6,060 件
        let transactions: Vec<_> = (0..60).map(|_| aggregate(100)).collect();
        assert_eq!(
            check(5_000_001, &transactions, |_| {}),
            Err(VerifyError::TooManyTransactions(6_060))
        );
        assert_eq!(check(5_000_001, &transactions[..59], |_| {}), Ok(()));
    }

    #[test]
    fn nemesis_hashes_are_pinned_for_known_networks() {
        assert!(nemesis_hash(NetworkIdentifier::MAINNET).is_some());
        assert!(nemesis_hash(NetworkIdentifier::TESTNET).is_some());
        assert_ne!(
            nemesis_hash(NetworkIdentifier::MAINNET),
            nemesis_hash(NetworkIdentifier::TESTNET)
        );
        assert_eq!(nemesis_hash(NetworkIdentifier(0)), None);
    }
}
