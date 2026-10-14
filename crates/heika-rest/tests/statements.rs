//! ステートメントを REST の形の JSON にして読み、catapult の並びにまとめる。

use heika_block::statement::{
    AddressResolutionStatement, BalanceChange, BlockStatement, Mosaic, MosaicResolutionStatement,
    Receipt, ReceiptBody, ReceiptSource, ResolutionEntry, TransactionStatement,
};
use heika_core::address::Address;
use heika_rest::RestError;
use heika_rest::statement::{
    ResolutionStatementInfo, ResolutionStatementJson, TransactionStatementInfo,
    TransactionStatementJson, block_statement,
};
use heika_transaction::{MosaicId, NamespaceId, UnresolvedAddress, UnresolvedMosaicId};
use serde_json::{Value, json};

const HEIGHT: u64 = 1440;

fn source(primary_id: u32, secondary_id: u32) -> ReceiptSource {
    ReceiptSource {
        primary_id,
        secondary_id,
    }
}

fn statement() -> BlockStatement {
    let mosaic = Mosaic {
        mosaic_id: MosaicId(0x6BED_913F_A202_23F8),
        amount: 1_000_000,
    };
    BlockStatement {
        transaction_statements: vec![
            TransactionStatement {
                source: source(0, 0),
                receipts: vec![
                    Receipt {
                        version: 1,
                        body: ReceiptBody::HarvestFee(BalanceChange {
                            mosaic,
                            target_address: Address([0x68; 24]),
                        }),
                    },
                    Receipt {
                        version: 1,
                        body: ReceiptBody::NamespaceExpired(NamespaceId(0x8000_0000_0000_0001)),
                    },
                    Receipt {
                        version: 1,
                        body: ReceiptBody::Inflation(mosaic),
                    },
                ],
            },
            TransactionStatement {
                source: source(2, 1),
                receipts: vec![Receipt {
                    version: 1,
                    body: ReceiptBody::MosaicExpired(MosaicId(7)),
                }],
            },
        ],
        address_resolution_statements: vec![
            AddressResolutionStatement {
                unresolved: UnresolvedAddress([0x69; 24]),
                entries: vec![ResolutionEntry {
                    source: source(1, 0),
                    resolved: Address([0x68; 24]),
                }],
            },
            AddressResolutionStatement {
                unresolved: UnresolvedAddress([0x99; 24]),
                entries: vec![],
            },
        ],
        mosaic_resolution_statements: vec![
            MosaicResolutionStatement {
                unresolved: UnresolvedMosaicId(0x8000_0000_0000_0002),
                entries: vec![],
            },
            MosaicResolutionStatement {
                unresolved: UnresolvedMosaicId(0xE74B_99BA_41F4_AFEE),
                entries: vec![ResolutionEntry {
                    source: source(2, 1),
                    resolved: MosaicId(0x6BED_913F_A202_23F8),
                }],
            },
        ],
    }
}

/// REST の検索の1件の形。`id` と `meta` も付ける
fn info(statement: Value) -> Value {
    json!({ "id": "6962CF6A2976BBB47C1054BC", "meta": { "timestamp": "0" }, "statement": statement })
}

#[test]
fn collects_statements_in_catapult_order() {
    let statement = statement();
    // REST は DB の順に返すので、わざと逆にする
    let transactions: Vec<TransactionStatementInfo> = statement
        .transaction_statements
        .iter()
        .rev()
        .map(|s| {
            serde_json::from_value(info(
                serde_json::to_value(TransactionStatementJson::new(HEIGHT, s)).unwrap(),
            ))
            .unwrap()
        })
        .collect();
    let addresses: Vec<ResolutionStatementInfo> = statement
        .address_resolution_statements
        .iter()
        .rev()
        .map(|s| {
            serde_json::from_value(info(
                serde_json::to_value(ResolutionStatementJson::from_address(HEIGHT, s)).unwrap(),
            ))
            .unwrap()
        })
        .collect();
    let mosaics: Vec<ResolutionStatementInfo> = statement
        .mosaic_resolution_statements
        .iter()
        .rev()
        .map(|s| {
            serde_json::from_value(info(
                serde_json::to_value(ResolutionStatementJson::from_mosaic(HEIGHT, s)).unwrap(),
            ))
            .unwrap()
        })
        .collect();
    let collected = block_statement(&transactions, &addresses, &mosaics).unwrap();
    assert_eq!(collected, statement);
    assert_eq!(collected.merkle_hash(), statement.merkle_hash());
}

#[test]
fn writes_receipts_like_catapult_rest() {
    let statement = statement();
    let json = serde_json::to_value(TransactionStatementJson::new(
        HEIGHT,
        &statement.transaction_statements[0],
    ))
    .unwrap();
    assert_eq!(
        json,
        json!({
            "height": "1440",
            "source": { "primaryId": 0, "secondaryId": 0 },
            "receipts": [
                {
                    "version": 1,
                    "type": 0x2143,
                    "targetAddress": "686868686868686868686868686868686868686868686868",
                    "mosaicId": "6BED913FA20223F8",
                    "amount": "1000000",
                },
                { "version": 1, "type": 0x414E, "artifactId": "8000000000000001" },
                { "version": 1, "type": 0x5143, "mosaicId": "6BED913FA20223F8", "amount": "1000000" },
            ],
        })
    );
    let json = serde_json::to_value(ResolutionStatementJson::from_mosaic(
        HEIGHT,
        &statement.mosaic_resolution_statements[1],
    ))
    .unwrap();
    assert_eq!(
        json,
        json!({
            "height": "1440",
            "unresolved": "E74B99BA41F4AFEE",
            "resolutionEntries": [{
                "source": { "primaryId": 2, "secondaryId": 1 },
                "resolved": "6BED913FA20223F8",
            }],
        })
    );
}

#[test]
fn refuses_unknown_receipts_and_missing_fields() {
    let read = |receipt: Value| {
        let json: TransactionStatementJson = serde_json::from_value(json!({
            "height": "1",
            "source": { "primaryId": 0, "secondaryId": 0 },
            "receipts": [receipt],
        }))
        .unwrap();
        TransactionStatement::try_from(&json)
    };
    assert_eq!(
        read(json!({ "version": 1, "type": 0xE143 })),
        Err(RestError::InvalidValue { field: "type" })
    );
    assert_eq!(
        read(json!({ "version": 1, "type": 0x5143, "mosaicId": "6BED913FA20223F8" })),
        Err(RestError::Missing { field: "amount" })
    );
}
