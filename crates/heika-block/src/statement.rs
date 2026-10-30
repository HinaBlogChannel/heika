//! ブロックのステートメントとレシート。catbuffer の `receipts.cats` と `statements/`、
//! catapult の `model/TransactionStatement.cpp`、`model/ResolutionStatement.cpp`、`model/BlockStatement.cpp`、
//! `io/BlockStatementSerializer.cpp`。
//!
//! ブロックを実行して起きたこと（手数料の受け取り、ロックの払い戻し、期限切れ、ネームスペースの解決など）を、
//! ブロックごとにまとめたもの。ブロックには入っておらず、ブロックのヘッダーの ReceiptsHash が、
//! ステートメントから求めた Merkle の根になっている。
//!
//! ```text
//! BlockStatement
//!   u32 数  TransactionStatement（ReceiptSource 8、u32 数、レシートを並べたもの）
//!   u32 数  AddressResolutionStatement（UnresolvedAddress 24、u32 数、(ReceiptSource 8、Address 24) を並べたもの）
//!   u32 数  MosaicResolutionStatement（UnresolvedMosaicId 8、u32 数、(ReceiptSource 8、MosaicId 8) を並べたもの）
//!
//! Receipt
//!   u32 Size  u16 Version  u16 Type  種類ごとの本体
//! ```
//!
//! レシートはどれも8の倍数の大きさなので、並べるときにパディングは入らない。

use alloc::vec::Vec;
use core::fmt;

use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::merkle;
use heika_transaction::{MosaicId, NamespaceId, UnresolvedAddress, UnresolvedMosaicId};
use sha3::{Digest, Sha3_256};

use reader::Reader;

/// レシートのヘッダーの大きさ。サイズ、バージョン、種類。
const RECEIPT_HEADER_SIZE: usize = 4 + 2 + 2;

/// ステートメントのハッシュの先頭に置く、レシートのヘッダーのバージョン。
const STATEMENT_VERSION: u16 = 1;

/// ステートメントのハッシュに使う、トランザクションのステートメントの種類。catapult の `Receipt_Type_Transaction_Group`。
const TRANSACTION_GROUP: u16 = 0xE143;

/// レシートやステートメントの元になったもの。catapult の `model::ReceiptSource`。
///
/// `primary_id` はブロックの中のトランザクションの何件目か（1から）で、ブロックそのものなら 0。
/// `secondary_id` はアグリゲートの中のトランザクションの何件目か（1から）で、アグリゲートの中でなければ 0。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ReceiptSource {
    pub primary_id: u32,
    pub secondary_id: u32,
}

impl ReceiptSource {
    const SIZE: usize = 4 + 4;

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.primary_id.to_le_bytes());
        out.extend_from_slice(&self.secondary_id.to_le_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
        Ok(Self {
            primary_id: reader.u32()?,
            secondary_id: reader.u32()?,
        })
    }
}

/// 解決したあとのモザイクの ID と量。catbuffer の `Mosaic`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mosaic {
    pub mosaic_id: MosaicId,
    pub amount: u64,
}

impl Mosaic {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mosaic_id.0.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
    }

    fn read(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
        Ok(Self {
            mosaic_id: MosaicId(reader.u64()?),
            amount: reader.u64()?,
        })
    }
}

/// あるアカウントから別のアカウントにモザイクが動いた。catbuffer の `BalanceTransferReceipt`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BalanceTransfer {
    pub mosaic: Mosaic,
    pub sender_address: Address,
    pub recipient_address: Address,
}

/// あるアカウントのモザイクが増えたか減った。catbuffer の `BalanceChangeReceipt`。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BalanceChange {
    pub mosaic: Mosaic,
    pub target_address: Address,
}

/// レシート。catbuffer の `Receipt` を継ぐ13種類。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Receipt {
    pub version: u16,
    pub body: ReceiptBody,
}

/// 種類ごとのレシートの本体。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReceiptBody {
    /// モザイクを作った手数料。払った人から、手数料を受け取るアカウントへ
    MosaicRentalFee(BalanceTransfer),
    /// ネームスペースを借りた手数料。払った人から、手数料を受け取るアカウントへ
    NamespaceRentalFee(BalanceTransfer),
    /// ブロックをハーベストして受け取った手数料
    HarvestFee(BalanceChange),
    /// ハッシュロックが使われて、預けたモザイクが戻った
    LockHashCompleted(BalanceChange),
    /// ハッシュロックが期限切れになり、預けたモザイクがハーベストした人に渡った
    LockHashExpired(BalanceChange),
    /// シークレットロックが解かれて、モザイクが受取人に渡った
    LockSecretCompleted(BalanceChange),
    /// シークレットロックが期限切れになり、預けたモザイクが戻った
    LockSecretExpired(BalanceChange),
    /// ハッシュロックでモザイクを預けた
    LockHashCreated(BalanceChange),
    /// シークレットロックでモザイクを預けた
    LockSecretCreated(BalanceChange),
    /// モザイクの期限が切れた
    MosaicExpired(MosaicId),
    /// ネームスペースの期限が切れた
    NamespaceExpired(NamespaceId),
    /// 期限が切れたネームスペースの猶予も過ぎて、消えた
    NamespaceDeleted(NamespaceId),
    /// ブロックごとに新しく発行された通貨
    Inflation(Mosaic),
}

impl ReceiptBody {
    /// 種類。catbuffer の `ReceiptType`。
    pub fn receipt_type(&self) -> u16 {
        match self {
            Self::MosaicRentalFee(_) => 0x124D,
            Self::NamespaceRentalFee(_) => 0x134E,
            Self::HarvestFee(_) => 0x2143,
            Self::LockHashCompleted(_) => 0x2248,
            Self::LockHashExpired(_) => 0x2348,
            Self::LockSecretCompleted(_) => 0x2252,
            Self::LockSecretExpired(_) => 0x2352,
            Self::LockHashCreated(_) => 0x3148,
            Self::LockSecretCreated(_) => 0x3152,
            Self::MosaicExpired(_) => 0x414D,
            Self::NamespaceExpired(_) => 0x414E,
            Self::NamespaceDeleted(_) => 0x424E,
            Self::Inflation(_) => 0x5143,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::MosaicRentalFee(transfer) | Self::NamespaceRentalFee(transfer) => {
                transfer.mosaic.encode(out);
                out.extend_from_slice(&transfer.sender_address.0);
                out.extend_from_slice(&transfer.recipient_address.0);
            }
            Self::HarvestFee(change)
            | Self::LockHashCompleted(change)
            | Self::LockHashExpired(change)
            | Self::LockSecretCompleted(change)
            | Self::LockSecretExpired(change)
            | Self::LockHashCreated(change)
            | Self::LockSecretCreated(change) => {
                change.mosaic.encode(out);
                out.extend_from_slice(&change.target_address.0);
            }
            Self::MosaicExpired(id) => out.extend_from_slice(&id.0.to_le_bytes()),
            Self::NamespaceExpired(id) | Self::NamespaceDeleted(id) => {
                out.extend_from_slice(&id.0.to_le_bytes())
            }
            Self::Inflation(mosaic) => mosaic.encode(out),
        }
    }

    fn decode(receipt_type: u16, reader: &mut Reader) -> Result<Self, StatementDecodeError> {
        let transfer = |reader: &mut Reader| -> Result<_, StatementDecodeError> {
            Ok(BalanceTransfer {
                mosaic: Mosaic::read(reader)?,
                sender_address: Address(reader.array()?),
                recipient_address: Address(reader.array()?),
            })
        };
        let change = |reader: &mut Reader| -> Result<_, StatementDecodeError> {
            Ok(BalanceChange {
                mosaic: Mosaic::read(reader)?,
                target_address: Address(reader.array()?),
            })
        };
        Ok(match receipt_type {
            0x124D => Self::MosaicRentalFee(transfer(reader)?),
            0x134E => Self::NamespaceRentalFee(transfer(reader)?),
            0x2143 => Self::HarvestFee(change(reader)?),
            0x2248 => Self::LockHashCompleted(change(reader)?),
            0x2348 => Self::LockHashExpired(change(reader)?),
            0x2252 => Self::LockSecretCompleted(change(reader)?),
            0x2352 => Self::LockSecretExpired(change(reader)?),
            0x3148 => Self::LockHashCreated(change(reader)?),
            0x3152 => Self::LockSecretCreated(change(reader)?),
            0x414D => Self::MosaicExpired(MosaicId(reader.u64()?)),
            0x414E => Self::NamespaceExpired(NamespaceId(reader.u64()?)),
            0x424E => Self::NamespaceDeleted(NamespaceId(reader.u64()?)),
            0x5143 => Self::Inflation(Mosaic::read(reader)?),
            other => return Err(StatementDecodeError::UnknownReceiptType(other)),
        })
    }
}

impl Receipt {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        self.body.encode(&mut body);
        let mut bytes = Vec::with_capacity(RECEIPT_HEADER_SIZE + body.len());
        bytes.extend_from_slice(&((RECEIPT_HEADER_SIZE + body.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.body.receipt_type().to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }

    /// バイト列から読む。先頭のサイズが、種類から決まる大きさと合わなければ弾く。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementDecodeError> {
        let mut reader = Reader(bytes);
        let receipt = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(receipt)
    }

    fn read(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
        let size = reader.u32()? as usize;
        let rest = size
            .checked_sub(4)
            .ok_or(StatementDecodeError::InvalidReceiptSize(size))?;
        let mut body = Reader(reader.take(rest)?);
        let version = body.u16()?;
        let receipt_type = body.u16()?;
        let receipt = Self {
            version,
            body: ReceiptBody::decode(receipt_type, &mut body).map_err(|error| match error {
                StatementDecodeError::TooShort => StatementDecodeError::InvalidReceiptSize(size),
                error => error,
            })?,
        };
        if !body.0.is_empty() {
            return Err(StatementDecodeError::InvalidReceiptSize(size));
        }
        Ok(receipt)
    }
}

/// 1件のトランザクション（またはブロックそのもの）から出たレシートの並び。catapult の `model::TransactionStatement`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransactionStatement {
    pub source: ReceiptSource,
    /// catapult は種類の昇順に並べる（同じ種類なら出た順）
    pub receipts: Vec<Receipt>,
}

impl TransactionStatement {
    /// ステートメントのハッシュ。catapult の `TransactionStatement::hash`。
    /// レシートのヘッダーの形（バージョン 1、種類 0xE143）、元、それぞれのレシートのサイズを除いた部分を続けた SHA3-256。
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Sha3_256::new();
        hasher.update(STATEMENT_VERSION.to_le_bytes());
        hasher.update(TRANSACTION_GROUP.to_le_bytes());
        let mut source = Vec::with_capacity(ReceiptSource::SIZE);
        self.source.encode(&mut source);
        hasher.update(source);
        for receipt in &self.receipts {
            hasher.update(&receipt.to_bytes()[4..]);
        }
        Hash256(hasher.finalize().into())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementDecodeError> {
        let mut reader = Reader(bytes);
        let statement = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(statement)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.source.encode(out);
        out.extend_from_slice(&(self.receipts.len() as u32).to_le_bytes());
        for receipt in &self.receipts {
            out.extend_from_slice(&receipt.to_bytes());
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
        let source = ReceiptSource::read(reader)?;
        let count = reader.u32()?;
        let receipts = (0..count)
            .map(|_| Receipt::read(reader))
            .collect::<Result<_, _>>()?;
        Ok(Self { source, receipts })
    }
}

/// ネームスペースを解決した値。アドレスかモザイクの ID。
pub trait Resolved: Copy + private::Sealed {
    /// 解決する前の値
    type Unresolved: Copy + Eq + fmt::Debug;
    /// ステートメントのハッシュに使う種類。catapult の `Receipt_Type_*_Alias_Resolution`
    const RECEIPT_TYPE: u16;
}

impl Resolved for Address {
    type Unresolved = UnresolvedAddress;
    const RECEIPT_TYPE: u16 = 0xF143;
}

impl Resolved for MosaicId {
    type Unresolved = UnresolvedMosaicId;
    const RECEIPT_TYPE: u16 = 0xF243;
}

mod private {
    use super::*;

    /// 解決する前と後の値を、決まった長さのバイト列として読み書きする。
    pub trait Sealed: Sized {
        fn encode_resolved(&self, out: &mut Vec<u8>);
        fn read_resolved(reader: &mut Reader) -> Result<Self, StatementDecodeError>;
        fn encode_unresolved(unresolved: &<Self as Resolved>::Unresolved, out: &mut Vec<u8>)
        where
            Self: Resolved;
        fn read_unresolved(
            reader: &mut Reader,
        ) -> Result<<Self as Resolved>::Unresolved, StatementDecodeError>
        where
            Self: Resolved;
    }

    impl Sealed for Address {
        fn encode_resolved(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.0);
        }

        fn read_resolved(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
            Ok(Self(reader.array()?))
        }

        fn encode_unresolved(unresolved: &UnresolvedAddress, out: &mut Vec<u8>) {
            out.extend_from_slice(&unresolved.0);
        }

        fn read_unresolved(reader: &mut Reader) -> Result<UnresolvedAddress, StatementDecodeError> {
            Ok(UnresolvedAddress(reader.array()?))
        }
    }

    impl Sealed for MosaicId {
        fn encode_resolved(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.0.to_le_bytes());
        }

        fn read_resolved(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
            Ok(Self(reader.u64()?))
        }

        fn encode_unresolved(unresolved: &UnresolvedMosaicId, out: &mut Vec<u8>) {
            out.extend_from_slice(&unresolved.0.to_le_bytes());
        }

        fn read_unresolved(
            reader: &mut Reader,
        ) -> Result<UnresolvedMosaicId, StatementDecodeError> {
            Ok(UnresolvedMosaicId(reader.u64()?))
        }
    }
}

/// 解決の1件。どのトランザクションで、何に解決したか。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResolutionEntry<R> {
    pub source: ReceiptSource,
    pub resolved: R,
}

/// 1つのネームスペースを、ブロックの中でどう解決したか。catapult の `model::ResolutionStatement`。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolutionStatement<R: Resolved> {
    pub unresolved: R::Unresolved,
    /// catapult は元の昇順に並べ、続けて同じ値に解決したものは1件にまとめる
    pub entries: Vec<ResolutionEntry<R>>,
}

/// アドレスのネームスペースの解決。catbuffer の `AddressResolutionStatement`。
pub type AddressResolutionStatement = ResolutionStatement<Address>;
/// モザイクのネームスペースの解決。catbuffer の `MosaicResolutionStatement`。
pub type MosaicResolutionStatement = ResolutionStatement<MosaicId>;

impl<R: Resolved> ResolutionStatement<R> {
    /// ステートメントのハッシュ。catapult の `ResolutionStatement::hash`。
    /// レシートのヘッダーの形（バージョン 1、解決の種類）、解決する前の値、それぞれの元と解決した値を続けた SHA3-256。
    pub fn hash(&self) -> Hash256 {
        let mut data = Vec::new();
        data.extend_from_slice(&STATEMENT_VERSION.to_le_bytes());
        data.extend_from_slice(&R::RECEIPT_TYPE.to_le_bytes());
        self.encode_entries(&mut data);
        Hash256(Sha3_256::digest(&data).into())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementDecodeError> {
        let mut reader = Reader(bytes);
        let statement = Self::read(&mut reader)?;
        reader.finish()?;
        Ok(statement)
    }

    /// 数を除いた、解決する前の値と、それぞれの元と解決した値。ハッシュの対象になる
    fn encode_entries(&self, out: &mut Vec<u8>) {
        R::encode_unresolved(&self.unresolved, out);
        for entry in &self.entries {
            entry.source.encode(out);
            entry.resolved.encode_resolved(out);
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        R::encode_unresolved(&self.unresolved, out);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            entry.source.encode(out);
            entry.resolved.encode_resolved(out);
        }
    }

    fn read(reader: &mut Reader) -> Result<Self, StatementDecodeError> {
        let unresolved = R::read_unresolved(reader)?;
        let count = reader.u32()?;
        let entries = (0..count)
            .map(|_| {
                Ok(ResolutionEntry {
                    source: ReceiptSource::read(reader)?,
                    resolved: R::read_resolved(reader)?,
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            unresolved,
            entries,
        })
    }
}

/// ブロックのステートメント。catapult の `model::BlockStatement`。
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct BlockStatement {
    /// catapult は元の昇順に並べる
    pub transaction_statements: Vec<TransactionStatement>,
    /// catapult は解決する前のアドレスのバイト列の昇順に並べる
    pub address_resolution_statements: Vec<AddressResolutionStatement>,
    /// catapult は解決する前の ID の昇順に並べる
    pub mosaic_resolution_statements: Vec<MosaicResolutionStatement>,
}

impl BlockStatement {
    /// ステートメントから ReceiptsHash を求める。catapult の `model::CalculateMerkleHash(const BlockStatement&)`。
    /// トランザクション、アドレスの解決、モザイクの解決の順に、それぞれのハッシュを葉にした Merkle の根。
    /// 並びはここにあるとおりに使う。ノードから読んだものは、catapult の並べ方になっている。
    pub fn merkle_hash(&self) -> Hash256 {
        let leaves: Vec<_> = self
            .transaction_statements
            .iter()
            .map(TransactionStatement::hash)
            .chain(
                self.address_resolution_statements
                    .iter()
                    .map(ResolutionStatement::hash),
            )
            .chain(
                self.mosaic_resolution_statements
                    .iter()
                    .map(ResolutionStatement::hash),
            )
            .collect();
        merkle::root(&leaves)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.transaction_statements.len() as u32).to_le_bytes());
        for statement in &self.transaction_statements {
            statement.encode(&mut bytes);
        }
        bytes.extend_from_slice(&(self.address_resolution_statements.len() as u32).to_le_bytes());
        for statement in &self.address_resolution_statements {
            statement.encode(&mut bytes);
        }
        bytes.extend_from_slice(&(self.mosaic_resolution_statements.len() as u32).to_le_bytes());
        for statement in &self.mosaic_resolution_statements {
            statement.encode(&mut bytes);
        }
        bytes
    }

    /// バイト列から読む。catapult の `ReadBlockStatement` と違い、並べ直したりまとめたりはせず、書いてあるとおりに読む。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StatementDecodeError> {
        let mut reader = Reader(bytes);
        let transaction_statements = read_all(&mut reader, TransactionStatement::read)?;
        let address_resolution_statements = read_all(&mut reader, ResolutionStatement::read)?;
        let mosaic_resolution_statements = read_all(&mut reader, ResolutionStatement::read)?;
        reader.finish()?;
        Ok(Self {
            transaction_statements,
            address_resolution_statements,
            mosaic_resolution_statements,
        })
    }
}

fn read_all<T>(
    reader: &mut Reader,
    read: impl Fn(&mut Reader) -> Result<T, StatementDecodeError>,
) -> Result<Vec<T>, StatementDecodeError> {
    let count = reader.u32()?;
    (0..count).map(|_| read(reader)).collect()
}

mod reader {
    use super::StatementDecodeError;

    /// 前から順に読む。足りなければ [`StatementDecodeError::TooShort`]。
    pub struct Reader<'a>(pub &'a [u8]);

    impl<'a> Reader<'a> {
        pub fn take(&mut self, size: usize) -> Result<&'a [u8], StatementDecodeError> {
            if self.0.len() < size {
                return Err(StatementDecodeError::TooShort);
            }
            let (head, rest) = self.0.split_at(size);
            self.0 = rest;
            Ok(head)
        }

        pub fn array<const N: usize>(&mut self) -> Result<[u8; N], StatementDecodeError> {
            Ok(self.take(N)?.try_into().expect("N bytes"))
        }

        pub fn u16(&mut self) -> Result<u16, StatementDecodeError> {
            self.array().map(u16::from_le_bytes)
        }

        pub fn u32(&mut self) -> Result<u32, StatementDecodeError> {
            self.array().map(u32::from_le_bytes)
        }

        pub fn u64(&mut self) -> Result<u64, StatementDecodeError> {
            self.array().map(u64::from_le_bytes)
        }

        pub fn finish(self) -> Result<(), StatementDecodeError> {
            if self.0.is_empty() {
                Ok(())
            } else {
                Err(StatementDecodeError::TrailingBytes(self.0.len()))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementDecodeError {
    /// 書いてある数のぶんに足りない
    TooShort,
    /// 最後まで読んでも、余りがある
    TrailingBytes(usize),
    /// レシートの先頭のサイズが、種類から決まる大きさと合わない
    InvalidReceiptSize(usize),
    /// 知らない種類のレシート
    UnknownReceiptType(u16),
}

impl fmt::Display for StatementDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("ステートメントが途中で切れています"),
            Self::TrailingBytes(count) => {
                write!(f, "ステートメントの後ろに {count} バイト余っています")
            }
            Self::InvalidReceiptSize(size) => {
                write!(
                    f,
                    "レシートのサイズ {size} が、種類から決まる大きさと合いません"
                )
            }
            Self::UnknownReceiptType(receipt_type) => {
                write!(f, "種類 0x{receipt_type:04X} のレシートは知りません")
            }
        }
    }
}

impl core::error::Error for StatementDecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn mosaic() -> Mosaic {
        Mosaic {
            mosaic_id: MosaicId(0x6BED_913F_A202_23F8),
            amount: 1_000_000,
        }
    }

    fn harvest_fee() -> Receipt {
        Receipt {
            version: 1,
            body: ReceiptBody::HarvestFee(BalanceChange {
                mosaic: mosaic(),
                target_address: Address([0x68; 24]),
            }),
        }
    }

    fn inflation() -> Receipt {
        Receipt {
            version: 1,
            body: ReceiptBody::Inflation(mosaic()),
        }
    }

    fn source(primary_id: u32, secondary_id: u32) -> ReceiptSource {
        ReceiptSource {
            primary_id,
            secondary_id,
        }
    }

    fn sha3(parts: &[&[u8]]) -> Hash256 {
        let mut hasher = Sha3_256::new();
        for part in parts {
            hasher.update(part);
        }
        Hash256(hasher.finalize().into())
    }

    #[test]
    fn writes_the_receipt_header() {
        let bytes = harvest_fee().to_bytes();
        assert_eq!(bytes.len(), 8 + 16 + 24);
        assert_eq!(bytes[..8], [48, 0, 0, 0, 1, 0, 0x43, 0x21]);
        assert_eq!(Receipt::from_bytes(&bytes), Ok(harvest_fee()));
    }

    #[test]
    fn refuses_receipts_whose_size_does_not_fit_the_type() {
        let mut bytes = inflation().to_bytes();
        // 種類だけを、本体の大きい HarvestFee にする
        bytes[6..8].copy_from_slice(&0x2143_u16.to_le_bytes());
        assert_eq!(
            Receipt::from_bytes(&bytes),
            Err(StatementDecodeError::InvalidReceiptSize(24))
        );
        let mut bytes = harvest_fee().to_bytes();
        bytes[6..8].copy_from_slice(&0x5143_u16.to_le_bytes());
        assert_eq!(
            Receipt::from_bytes(&bytes),
            Err(StatementDecodeError::InvalidReceiptSize(48))
        );
        bytes[6..8].copy_from_slice(&0xE143_u16.to_le_bytes());
        assert_eq!(
            Receipt::from_bytes(&bytes),
            Err(StatementDecodeError::UnknownReceiptType(0xE143))
        );
        assert_eq!(
            Receipt::from_bytes(&[3, 0, 0, 0]),
            Err(StatementDecodeError::InvalidReceiptSize(3))
        );
        assert_eq!(
            Receipt::from_bytes(&inflation().to_bytes()[..20]),
            Err(StatementDecodeError::TooShort)
        );
    }

    #[test]
    fn hashes_a_transaction_statement_with_a_group_header() {
        let statement = TransactionStatement {
            source: source(0, 0),
            receipts: vec![harvest_fee(), inflation()],
        };
        // バージョン 1 と種類 0xE143 に、元と、サイズを除いたレシートを続ける
        let expected = sha3(&[
            &[1, 0, 0x43, 0xE1],
            &[0; 8],
            &harvest_fee().to_bytes()[4..],
            &inflation().to_bytes()[4..],
        ]);
        assert_eq!(statement.hash(), expected);
        assert_eq!(
            TransactionStatement::from_bytes(&statement.to_bytes()),
            Ok(statement)
        );
    }

    #[test]
    fn hashes_resolution_statements_with_their_own_type() {
        let address = AddressResolutionStatement {
            unresolved: UnresolvedAddress([0x69; 24]),
            entries: vec![ResolutionEntry {
                source: source(1, 2),
                resolved: Address([0x68; 24]),
            }],
        };
        let expected = sha3(&[
            &[1, 0, 0x43, 0xF1],
            &[0x69; 24],
            &[1, 0, 0, 0, 2, 0, 0, 0],
            &[0x68; 24],
        ]);
        assert_eq!(address.hash(), expected);

        let mosaic = MosaicResolutionStatement {
            unresolved: UnresolvedMosaicId(0xE74B_99BA_41F4_AFEE),
            entries: vec![ResolutionEntry {
                source: source(1, 0),
                resolved: MosaicId(0x6BED_913F_A202_23F8),
            }],
        };
        let expected = sha3(&[
            &[1, 0, 0x43, 0xF2],
            &0xE74B_99BA_41F4_AFEE_u64.to_le_bytes(),
            &[1, 0, 0, 0, 0, 0, 0, 0],
            &0x6BED_913F_A202_23F8_u64.to_le_bytes(),
        ]);
        assert_eq!(mosaic.hash(), expected);
    }

    #[test]
    fn merkle_hash_puts_transactions_then_addresses_then_mosaics() {
        let transaction = TransactionStatement {
            source: source(0, 0),
            receipts: vec![harvest_fee()],
        };
        let address = AddressResolutionStatement {
            unresolved: UnresolvedAddress([0x69; 24]),
            entries: Vec::new(),
        };
        let mosaic = MosaicResolutionStatement {
            unresolved: UnresolvedMosaicId(0xE74B_99BA_41F4_AFEE),
            entries: Vec::new(),
        };
        let statement = BlockStatement {
            transaction_statements: vec![transaction.clone()],
            address_resolution_statements: vec![address.clone()],
            mosaic_resolution_statements: vec![mosaic.clone()],
        };
        assert_eq!(
            statement.merkle_hash(),
            merkle::root(&[transaction.hash(), address.hash(), mosaic.hash()])
        );
        assert_eq!(
            BlockStatement::from_bytes(&statement.to_bytes()),
            Ok(statement)
        );
        // 何もなければ0
        assert_eq!(BlockStatement::default().merkle_hash(), Hash256([0; 32]));
        assert_eq!(BlockStatement::default().to_bytes(), [0; 12]);
    }

    #[test]
    fn refuses_trailing_bytes() {
        let mut bytes = BlockStatement::default().to_bytes();
        bytes.push(0);
        assert_eq!(
            BlockStatement::from_bytes(&bytes),
            Err(StatementDecodeError::TrailingBytes(1))
        );
    }
}
