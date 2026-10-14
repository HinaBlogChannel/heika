//! `models/receipts.json` と `models/other.json`: レシートとステートメントのバイト列と、その中身。
//!
//! ベクターのレシートはバージョンが 0 で、ステートメントの中の解決する前の値は同じものが並んでいる。
//! どちらも実際のチェーンには出てこない形だが、書いてあるとおりに読み書きできることを確かめる。

use heika_block::statement::{
    AddressResolutionStatement, BlockStatement, MosaicResolutionStatement, Receipt, ReceiptBody,
    ReceiptSource, TransactionStatement,
};
use heika_core::address::Address;
use heika_transaction::{MosaicId, NamespaceId, UnresolvedMosaicId};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Vector {
    schema_name: String,
    payload: String,
    descriptor: Value,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn address(descriptor: &Value, field: &str) -> Address {
    descriptor[field].as_str().unwrap().parse().unwrap()
}

fn number(descriptor: &Value, field: &str) -> u64 {
    descriptor[field].as_u64().unwrap()
}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn reads_and_writes_every_receipt() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/receipts.json");
    assert_eq!(vectors.len(), 13);
    for vector in vectors {
        let name = &vector.schema_name;
        let d = &vector.descriptor;
        let bytes = from_hex(&vector.payload);
        let receipt = Receipt::from_bytes(&bytes).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(receipt.to_bytes(), bytes, "{name}");
        assert_eq!(receipt.version, 0, "{name}");

        let mosaic = |mosaic: &heika_block::statement::Mosaic| {
            assert_eq!(
                mosaic.mosaic_id,
                MosaicId(number(&d["mosaic"], "mosaic_id")),
                "{name}"
            );
            assert_eq!(mosaic.amount, number(&d["mosaic"], "amount"), "{name}");
        };
        let expected_type = d["type"].as_str().unwrap();
        let actual_type = match &receipt.body {
            ReceiptBody::MosaicRentalFee(transfer) | ReceiptBody::NamespaceRentalFee(transfer) => {
                mosaic(&transfer.mosaic);
                assert_eq!(
                    transfer.sender_address,
                    address(d, "sender_address"),
                    "{name}"
                );
                assert_eq!(
                    transfer.recipient_address,
                    address(d, "recipient_address"),
                    "{name}"
                );
                match receipt.body {
                    ReceiptBody::MosaicRentalFee(_) => "mosaic_rental_fee_receipt",
                    _ => "namespace_rental_fee_receipt",
                }
            }
            ReceiptBody::HarvestFee(change)
            | ReceiptBody::LockHashCompleted(change)
            | ReceiptBody::LockHashExpired(change)
            | ReceiptBody::LockSecretCompleted(change)
            | ReceiptBody::LockSecretExpired(change)
            | ReceiptBody::LockHashCreated(change)
            | ReceiptBody::LockSecretCreated(change) => {
                mosaic(&change.mosaic);
                assert_eq!(
                    change.target_address,
                    address(d, "target_address"),
                    "{name}"
                );
                match receipt.body {
                    ReceiptBody::HarvestFee(_) => "harvest_fee_receipt",
                    ReceiptBody::LockHashCompleted(_) => "lock_hash_completed_fee_receipt",
                    ReceiptBody::LockHashExpired(_) => "lock_hash_expired_fee_receipt",
                    ReceiptBody::LockSecretCompleted(_) => "lock_secret_completed_fee_receipt",
                    ReceiptBody::LockSecretExpired(_) => "lock_secret_expired_fee_receipt",
                    ReceiptBody::LockHashCreated(_) => "lock_hash_created_fee_receipt",
                    _ => "lock_secret_created_fee_receipt",
                }
            }
            ReceiptBody::MosaicExpired(id) => {
                assert_eq!(id.0, number(d, "artifact_id"), "{name}");
                "mosaic_expired_receipt"
            }
            ReceiptBody::NamespaceExpired(id) | ReceiptBody::NamespaceDeleted(id) => {
                assert_eq!(id.0, number(d, "artifact_id"), "{name}");
                match receipt.body {
                    ReceiptBody::NamespaceExpired(_) => "namespace_expired_receipt",
                    _ => "namespace_deleted_receipt",
                }
            }
            ReceiptBody::Inflation(inflation) => {
                mosaic(inflation);
                "inflation_receipt"
            }
        };
        assert_eq!(actual_type, expected_type, "{name}");
    }
}

/// `other.json` の中身は文字列で書かれているので、読んだものは決まった値と比べる
#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn reads_and_writes_statements() {
    let vectors: Vec<Vector> = heika_vectors::fetch("models/other.json");
    let payload = |schema: &str| {
        let vector = vectors
            .iter()
            .find(|vector| vector.schema_name == schema)
            .unwrap_or_else(|| panic!("{schema} がありません"));
        from_hex(&vector.payload)
    };

    let bytes = payload("TransactionStatement");
    let transaction = TransactionStatement::from_bytes(&bytes).unwrap();
    assert_eq!(transaction.to_bytes(), bytes);
    assert_eq!(
        transaction.source,
        ReceiptSource {
            primary_id: 0x1234_5678,
            secondary_id: 0x8877_6655
        }
    );
    assert_eq!(transaction.receipts.len(), 2);
    assert!(matches!(
        transaction.receipts[0].body,
        ReceiptBody::NamespaceRentalFee(transfer) if transfer.mosaic.amount == 0x2A
    ));
    assert_eq!(
        transaction.receipts[1].body,
        ReceiptBody::MosaicExpired(MosaicId(0x8877_6655_4433_2211))
    );

    let bytes = payload("MosaicResolutionStatement");
    let mosaic = MosaicResolutionStatement::from_bytes(&bytes).unwrap();
    assert_eq!(mosaic.to_bytes(), bytes);
    assert_eq!(mosaic.unresolved, UnresolvedMosaicId(0x8877_6655_4433_2211));
    let resolved: Vec<_> = mosaic
        .entries
        .iter()
        .map(|entry| {
            (
                entry.source.primary_id,
                entry.source.secondary_id,
                entry.resolved.0,
            )
        })
        .collect();
    assert_eq!(
        resolved,
        [
            (0xD, 0x29, 0x1234_5678_90AB_CDEF),
            (0xD, 0x2B, 0x1234_5678_90AB_CDF2),
            (0xD, 0x2D, 0x1234_5678_90AB_CDF5)
        ]
    );

    let bytes = payload("AddressResolutionStatement");
    let address = AddressResolutionStatement::from_bytes(&bytes).unwrap();
    assert_eq!(address.to_bytes(), bytes);
    assert_eq!(
        address.unresolved.namespace_id(),
        Some(NamespaceId(0xF77D_7ECF_FBBB_FA52))
    );
    assert!(address.entries.is_empty());

    let bytes = payload("BlockStatement");
    let block = BlockStatement::from_bytes(&bytes).unwrap();
    assert_eq!(block.to_bytes(), bytes);
    assert_eq!(block.transaction_statements.len(), 3);
    assert_eq!(block.address_resolution_statements, vec![address; 4]);
    assert_eq!(block.mosaic_resolution_statements.len(), 5);
    assert_eq!(block.mosaic_resolution_statements[0], mosaic);
}
