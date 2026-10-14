//! レシートとステートメント。`/statements/transaction`、`/statements/resolutions/address`、
//! `/statements/resolutions/mosaic` が返す `TransactionStatementInfoDTO` と `ResolutionStatementInfoDTO`。
//!
//! REST はステートメントを1件ずつ、DB の順に返す。ブロックの ReceiptsHash を求めるには、同じ高さのものを
//! 3種類とも集めて [`block_statement`] で catapult の並びにする。

use heika_block::statement::{
    AddressResolutionStatement, BalanceChange, BalanceTransfer, BlockStatement, Mosaic,
    MosaicResolutionStatement, Receipt, ReceiptBody, ReceiptSource, ResolutionEntry,
    TransactionStatement,
};
use heika_core::address::Address;
use heika_transaction::{MosaicId, NamespaceId, UnresolvedAddress, UnresolvedMosaicId};
use serde::{Deserialize, Serialize};

use crate::{RestError, hex, hex_array, number};

/// `TransactionStatementInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TransactionStatementInfo {
    pub statement: TransactionStatementJson,
}

/// `TransactionStatementDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TransactionStatementJson {
    pub height: String,
    pub source: SourceJson,
    pub receipts: Vec<ReceiptJson>,
}

/// `SourceDTO`。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceJson {
    pub primary_id: u32,
    pub secondary_id: u32,
}

/// レシート。種類によって使う項目が違う。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptJson {
    pub version: u16,
    #[serde(rename = "type")]
    pub receipt_type: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mosaic_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
}

/// `ResolutionStatementInfoDTO`。アドレスとモザイクで同じ形。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ResolutionStatementInfo {
    pub statement: ResolutionStatementJson,
}

/// `ResolutionStatementDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionStatementJson {
    pub height: String,
    /// アドレスなら24バイトの16進、モザイクなら上位から書いた ID の16進
    pub unresolved: String,
    pub resolution_entries: Vec<ResolutionEntryJson>,
}

/// `ResolutionEntryDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ResolutionEntryJson {
    pub source: SourceJson,
    pub resolved: String,
}

impl From<SourceJson> for ReceiptSource {
    fn from(source: SourceJson) -> Self {
        Self {
            primary_id: source.primary_id,
            secondary_id: source.secondary_id,
        }
    }
}

impl From<ReceiptSource> for SourceJson {
    fn from(source: ReceiptSource) -> Self {
        Self {
            primary_id: source.primary_id,
            secondary_id: source.secondary_id,
        }
    }
}

impl TryFrom<&ReceiptJson> for Receipt {
    type Error = RestError;

    fn try_from(json: &ReceiptJson) -> Result<Self, Self::Error> {
        let address =
            |value: &Option<String>, field| hex_array(required(value, field)?, field).map(Address);
        let mosaic = || -> Result<Mosaic, RestError> {
            Ok(Mosaic {
                mosaic_id: MosaicId(id(required(&json.mosaic_id, "mosaicId")?, "mosaicId")?),
                amount: number(required(&json.amount, "amount")?, "amount")?,
            })
        };
        let transfer = || -> Result<BalanceTransfer, RestError> {
            Ok(BalanceTransfer {
                mosaic: mosaic()?,
                sender_address: address(&json.sender_address, "senderAddress")?,
                recipient_address: address(&json.recipient_address, "recipientAddress")?,
            })
        };
        let change = || -> Result<BalanceChange, RestError> {
            Ok(BalanceChange {
                mosaic: mosaic()?,
                target_address: address(&json.target_address, "targetAddress")?,
            })
        };
        let artifact = || id(required(&json.artifact_id, "artifactId")?, "artifactId");
        let body = match json.receipt_type {
            0x124D => ReceiptBody::MosaicRentalFee(transfer()?),
            0x134E => ReceiptBody::NamespaceRentalFee(transfer()?),
            0x2143 => ReceiptBody::HarvestFee(change()?),
            0x2248 => ReceiptBody::LockHashCompleted(change()?),
            0x2348 => ReceiptBody::LockHashExpired(change()?),
            0x2252 => ReceiptBody::LockSecretCompleted(change()?),
            0x2352 => ReceiptBody::LockSecretExpired(change()?),
            0x3148 => ReceiptBody::LockHashCreated(change()?),
            0x3152 => ReceiptBody::LockSecretCreated(change()?),
            0x414D => ReceiptBody::MosaicExpired(MosaicId(artifact()?)),
            0x414E => ReceiptBody::NamespaceExpired(NamespaceId(artifact()?)),
            0x424E => ReceiptBody::NamespaceDeleted(NamespaceId(artifact()?)),
            0x5143 => ReceiptBody::Inflation(mosaic()?),
            _ => return Err(RestError::InvalidValue { field: "type" }),
        };
        Ok(Self {
            version: json.version,
            body,
        })
    }
}

impl From<&Receipt> for ReceiptJson {
    fn from(receipt: &Receipt) -> Self {
        let mut json = Self {
            version: receipt.version,
            receipt_type: receipt.body.receipt_type(),
            sender_address: None,
            recipient_address: None,
            target_address: None,
            mosaic_id: None,
            amount: None,
            artifact_id: None,
        };
        let mosaic = |mosaic: &Mosaic, json: &mut Self| {
            json.mosaic_id = Some(format!("{:016X}", mosaic.mosaic_id.0));
            json.amount = Some(mosaic.amount.to_string());
        };
        match &receipt.body {
            ReceiptBody::MosaicRentalFee(transfer) | ReceiptBody::NamespaceRentalFee(transfer) => {
                mosaic(&transfer.mosaic, &mut json);
                json.sender_address = Some(transfer.sender_address.to_hex());
                json.recipient_address = Some(transfer.recipient_address.to_hex());
            }
            ReceiptBody::HarvestFee(change)
            | ReceiptBody::LockHashCompleted(change)
            | ReceiptBody::LockHashExpired(change)
            | ReceiptBody::LockSecretCompleted(change)
            | ReceiptBody::LockSecretExpired(change)
            | ReceiptBody::LockHashCreated(change)
            | ReceiptBody::LockSecretCreated(change) => {
                mosaic(&change.mosaic, &mut json);
                json.target_address = Some(change.target_address.to_hex());
            }
            ReceiptBody::MosaicExpired(id) => json.artifact_id = Some(format!("{:016X}", id.0)),
            ReceiptBody::NamespaceExpired(id) | ReceiptBody::NamespaceDeleted(id) => {
                json.artifact_id = Some(format!("{:016X}", id.0))
            }
            ReceiptBody::Inflation(inflation) => mosaic(inflation, &mut json),
        }
        json
    }
}

impl TryFrom<&TransactionStatementJson> for TransactionStatement {
    type Error = RestError;

    fn try_from(json: &TransactionStatementJson) -> Result<Self, Self::Error> {
        Ok(Self {
            source: json.source.into(),
            receipts: json
                .receipts
                .iter()
                .map(Receipt::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TransactionStatementJson {
    /// ステートメントを、REST が返す形にする。ステートメントは高さを持たないので、別に渡す。
    pub fn new(height: u64, statement: &TransactionStatement) -> Self {
        Self {
            height: height.to_string(),
            source: statement.source.into(),
            receipts: statement.receipts.iter().map(ReceiptJson::from).collect(),
        }
    }
}

impl TryFrom<&ResolutionStatementJson> for AddressResolutionStatement {
    type Error = RestError;

    fn try_from(json: &ResolutionStatementJson) -> Result<Self, Self::Error> {
        Ok(Self {
            unresolved: UnresolvedAddress(hex_array(&json.unresolved, "unresolved")?),
            entries: json
                .resolution_entries
                .iter()
                .map(|entry| {
                    Ok(ResolutionEntry {
                        source: entry.source.into(),
                        resolved: Address(hex_array(&entry.resolved, "resolved")?),
                    })
                })
                .collect::<Result<_, RestError>>()?,
        })
    }
}

impl TryFrom<&ResolutionStatementJson> for MosaicResolutionStatement {
    type Error = RestError;

    fn try_from(json: &ResolutionStatementJson) -> Result<Self, Self::Error> {
        Ok(Self {
            unresolved: UnresolvedMosaicId(id(&json.unresolved, "unresolved")?),
            entries: json
                .resolution_entries
                .iter()
                .map(|entry| {
                    Ok(ResolutionEntry {
                        source: entry.source.into(),
                        resolved: MosaicId(id(&entry.resolved, "resolved")?),
                    })
                })
                .collect::<Result<_, RestError>>()?,
        })
    }
}

impl ResolutionStatementJson {
    /// アドレスの解決のステートメントを、REST が返す形にする。
    pub fn from_address(height: u64, statement: &AddressResolutionStatement) -> Self {
        Self {
            height: height.to_string(),
            unresolved: hex(&statement.unresolved.0),
            resolution_entries: statement
                .entries
                .iter()
                .map(|entry| ResolutionEntryJson {
                    source: entry.source.into(),
                    resolved: entry.resolved.to_hex(),
                })
                .collect(),
        }
    }

    /// モザイクの解決のステートメントを、REST が返す形にする。
    pub fn from_mosaic(height: u64, statement: &MosaicResolutionStatement) -> Self {
        Self {
            height: height.to_string(),
            unresolved: format!("{:016X}", statement.unresolved.0),
            resolution_entries: statement
                .entries
                .iter()
                .map(|entry| ResolutionEntryJson {
                    source: entry.source.into(),
                    resolved: format!("{:016X}", entry.resolved.0),
                })
                .collect(),
        }
    }
}

/// 同じ高さの3種類のステートメントを、catapult の並びにまとめる。
///
/// catapult はそれぞれを `std::map` に持つので、トランザクションのステートメントは元の順、アドレスの解決は
/// 解決する前のアドレスのバイト列の順、モザイクの解決は解決する前の ID の順に並ぶ。REST は DB の順に返すので、
/// ここで並べ直す。[`BlockStatement::merkle_hash`] が、ブロックの ReceiptsHash と比べられる値になる。
pub fn block_statement(
    transactions: &[TransactionStatementInfo],
    addresses: &[ResolutionStatementInfo],
    mosaics: &[ResolutionStatementInfo],
) -> Result<BlockStatement, RestError> {
    let mut transaction_statements = transactions
        .iter()
        .map(|info| TransactionStatement::try_from(&info.statement))
        .collect::<Result<Vec<_>, _>>()?;
    transaction_statements.sort_by_key(|statement| statement.source);
    let mut address_resolution_statements = addresses
        .iter()
        .map(|info| AddressResolutionStatement::try_from(&info.statement))
        .collect::<Result<Vec<_>, _>>()?;
    address_resolution_statements.sort_by_key(|statement| statement.unresolved.0);
    let mut mosaic_resolution_statements = mosaics
        .iter()
        .map(|info| MosaicResolutionStatement::try_from(&info.statement))
        .collect::<Result<Vec<_>, _>>()?;
    mosaic_resolution_statements.sort_by_key(|statement| statement.unresolved.0);
    Ok(BlockStatement {
        transaction_statements,
        address_resolution_statements,
        mosaic_resolution_statements,
    })
}

fn required<'a, T>(value: &'a Option<T>, field: &'static str) -> Result<&'a T, RestError> {
    value.as_ref().ok_or(RestError::Missing { field })
}

/// REST は ID を上位から16進で書く
fn id(text: &str, field: &'static str) -> Result<u64, RestError> {
    hex_array(text, field).map(u64::from_be_bytes)
}
