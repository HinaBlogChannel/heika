//! ブロックを実行しながら、ステートメント（レシートと、ネームスペースの解決）を組み立てる。
//! catapult の `model::BlockStatementBuilder` と、observer が使う `ObserverStatementBuilder`。
//!
//! - レシートは、今の元（トランザクションの何件目か、アグリゲートの中の何件目か）ごとにまとめる。
//!   元の中では種類の昇順に並べ、同じ種類なら出た順にする（`TransactionStatement::addReceipt`）
//! - observer がネームスペースを解決したら、解決する前の値ごとに、元と解決した値を足す。
//!   続けて同じ値に解決したものは足さない（`ResolutionStatement::addResolution`）
//!
//! できたものの Merkle の根が、ブロックの ReceiptsHash になる。

use std::collections::BTreeMap;

use heika_block::statement::{
    BlockStatement, Receipt, ReceiptBody, ReceiptSource, ResolutionEntry, ResolutionStatement,
    TransactionStatement,
};
use heika_core::address::Address;
use heika_transaction::{MosaicId, UnresolvedAddress, UnresolvedMosaicId};

pub struct StatementBuilder {
    source: ReceiptSource,
    receipts: BTreeMap<ReceiptSource, Vec<Receipt>>,
    addresses: BTreeMap<[u8; 24], Vec<ResolutionEntry<Address>>>,
    mosaics: BTreeMap<u64, Vec<ResolutionEntry<MosaicId>>>,
}

impl Default for StatementBuilder {
    fn default() -> Self {
        Self {
            source: ReceiptSource {
                primary_id: 0,
                secondary_id: 0,
            },
            receipts: BTreeMap::new(),
            addresses: BTreeMap::new(),
            mosaics: BTreeMap::new(),
        }
    }
}

impl StatementBuilder {
    /// これから出るレシートと解決の元。ブロックそのものは (0, 0)
    pub fn set_source(&mut self, primary_id: u32, secondary_id: u32) {
        self.source = ReceiptSource {
            primary_id,
            secondary_id,
        };
    }

    pub fn add_receipt(&mut self, body: ReceiptBody) {
        let receipts = self.receipts.entry(self.source).or_default();
        let at = receipts
            .iter()
            .position(|receipt| receipt.body.receipt_type() > body.receipt_type())
            .unwrap_or(receipts.len());
        receipts.insert(at, Receipt { version: 1, body });
    }

    /// アドレスを解決した。ネームスペースでなければ（解決しても同じなら）何もしない
    pub fn add_address_resolution(&mut self, unresolved: &UnresolvedAddress, resolved: [u8; 24]) {
        if unresolved.0 == resolved {
            return;
        }
        add_resolution(
            self.addresses.entry(unresolved.0).or_default(),
            self.source,
            Address(resolved),
        );
    }

    /// モザイクの ID を解決した。ネームスペースでなければ何もしない
    pub fn add_mosaic_resolution(&mut self, unresolved: u64, resolved: u64) {
        if unresolved == resolved {
            return;
        }
        add_resolution(
            self.mosaics.entry(unresolved).or_default(),
            self.source,
            MosaicId(resolved),
        );
    }

    /// できたステートメント。次のブロックのために空にする
    pub fn take(&mut self) -> BlockStatement {
        let builder = std::mem::take(self);
        BlockStatement {
            transaction_statements: builder
                .receipts
                .into_iter()
                .map(|(source, receipts)| TransactionStatement { source, receipts })
                .collect(),
            address_resolution_statements: builder
                .addresses
                .into_iter()
                .map(|(unresolved, entries)| ResolutionStatement {
                    unresolved: UnresolvedAddress(unresolved),
                    entries,
                })
                .collect(),
            mosaic_resolution_statements: builder
                .mosaics
                .into_iter()
                .map(|(unresolved, entries)| ResolutionStatement {
                    unresolved: UnresolvedMosaicId(unresolved),
                    entries,
                })
                .collect(),
        }
    }
}

fn add_resolution<R: PartialEq>(
    entries: &mut Vec<ResolutionEntry<R>>,
    source: ReceiptSource,
    resolved: R,
) {
    if entries.last().is_some_and(|last| last.resolved == resolved) {
        return;
    }
    entries.push(ResolutionEntry { source, resolved });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn harvest(amount: u64) -> ReceiptBody {
        ReceiptBody::HarvestFee(heika_block::statement::BalanceChange {
            mosaic: heika_block::statement::Mosaic {
                mosaic_id: MosaicId(1),
                amount,
            },
            target_address: Address([7; 24]),
        })
    }

    #[test]
    fn receipts_are_grouped_by_source_and_sorted_by_type_keeping_order() {
        let mut builder = StatementBuilder::default();
        builder.set_source(2, 0);
        builder.add_receipt(ReceiptBody::Inflation(heika_block::statement::Mosaic {
            mosaic_id: MosaicId(1),
            amount: 5,
        }));
        builder.add_receipt(harvest(1));
        builder.add_receipt(ReceiptBody::NamespaceExpired(
            heika_transaction::NamespaceId(9),
        ));
        builder.add_receipt(harvest(2));
        builder.set_source(0, 0);
        builder.add_receipt(harvest(3));
        let statement = builder.take();
        let sources: Vec<_> = statement
            .transaction_statements
            .iter()
            .map(|statement| (statement.source.primary_id, statement.receipts.len()))
            .collect();
        assert_eq!(sources, [(0, 1), (2, 4)]);
        let types: Vec<_> = statement.transaction_statements[1]
            .receipts
            .iter()
            .map(|receipt| receipt.body)
            .collect();
        // 種類の昇順で、同じ種類は足した順
        assert_eq!(
            types,
            [
                harvest(1),
                harvest(2),
                ReceiptBody::NamespaceExpired(heika_transaction::NamespaceId(9)),
                ReceiptBody::Inflation(heika_block::statement::Mosaic {
                    mosaic_id: MosaicId(1),
                    amount: 5
                }),
            ]
        );
        // 取り出したら空になる
        assert_eq!(builder.take(), BlockStatement::default());
    }

    #[test]
    fn resolutions_collapse_repeated_values_and_skip_unchanged_ones() {
        let mut builder = StatementBuilder::default();
        let alias = 0x8000_0000_0000_0001;
        builder.set_source(1, 0);
        builder.add_mosaic_resolution(alias, 5);
        builder.add_mosaic_resolution(0x1234, 0x1234);
        builder.set_source(1, 2);
        builder.add_mosaic_resolution(alias, 5);
        builder.set_source(3, 0);
        builder.add_mosaic_resolution(alias, 6);
        let unresolved = UnresolvedAddress([0x99; 24]);
        builder.add_address_resolution(&unresolved, [1; 24]);
        builder.add_address_resolution(&UnresolvedAddress([2; 24]), [2; 24]);
        let statement = builder.take();
        assert_eq!(statement.mosaic_resolution_statements.len(), 1);
        let entries: Vec<_> = statement.mosaic_resolution_statements[0]
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
        assert_eq!(entries, [(1, 0, 5), (3, 0, 6)]);
        assert_eq!(statement.address_resolution_statements.len(), 1);
        assert_eq!(
            statement.address_resolution_statements[0].unresolved,
            unresolved
        );
    }
}
