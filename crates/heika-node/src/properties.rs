//! `/network/properties` の中身。catapult の REST は `config-network.properties` をそのまま返すが、heika は
//! 読んだ値（[`NetworkParameters`] と [`ChainConfig`]）から組み直す。
//!
//! 数と期間の書き方（桁の区切りの `'`、期間の単位）は、メインネットの設定ファイルに合わせる。値が単位で割り切れなければ、
//! 割り切れるいちばん大きい単位にする。heika が持っていない欄（`maxRollbackBlocks`、`initialCurrencyAtomicUnits`、
//! `reservedRootNamespaceNames`）は返さない。

use std::time::Duration;

use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_rest::node::{
    AccountLinkPluginJson, AccountRestrictionPluginJson, AggregatePluginJson, ChainSectionJson,
    LockHashPluginJson, LockSecretPluginJson, MetadataPluginJson, MosaicPluginJson,
    MosaicRestrictionPluginJson, MultisigPluginJson, NamespacePluginJson, NetworkPropertiesJson,
    NetworkSectionJson, PluginsJson, TransferPluginJson,
};
use heika_state_transition::config::{ChainConfig, HeightDependentAddress};

/// 期間の単位と、そのミリ秒。大きい順
const UNITS: [(&str, u64); 5] = [
    ("d", 24 * 60 * 60 * 1000),
    ("h", 60 * 60 * 1000),
    ("m", 60 * 1000),
    ("s", 1000),
    ("ms", 1),
];

/// `parameters` と `config` のネットワークの `/network/properties`
pub fn network_properties(
    parameters: &NetworkParameters,
    config: &ChainConfig,
) -> NetworkPropertiesJson {
    let block_time = parameters.block_generation_target_time;
    let blocks = |count: u64| block_time * u32::try_from(count).unwrap_or(u32::MAX);
    NetworkPropertiesJson {
        network: NetworkSectionJson {
            identifier: identifier(parameters.identifier),
            nemesis_signer_public_key: config.nemesis_signer_public_key.to_string(),
            // heika は、ピアをホストの名前で見分ける。メインネットとテストネットも同じ
            node_equality_strategy: "host".to_owned(),
            generation_hash_seed: parameters.generation_hash_seed.to_string(),
            epoch_adjustment: duration(parameters.epoch_adjustment, "s"),
        },
        chain: ChainSectionJson {
            // heika は、状態とレシートの根を確かめるネットワークしか扱わない
            enable_verifiable_state: true,
            enable_verifiable_receipts: true,
            currency_mosaic_id: id(config.currency_mosaic_id),
            harvesting_mosaic_id: id(config.harvesting_mosaic_id),
            block_generation_target_time: duration(block_time, "s"),
            block_time_smoothing_factor: parameters.block_time_smoothing_factor.to_string(),
            importance_grouping: config.importance_grouping.to_string(),
            importance_activity_percentage: config.importance_activity_percentage.to_string(),
            max_difficulty_blocks: config.max_difficulty_blocks.to_string(),
            default_dynamic_fee_multiplier: config.default_dynamic_fee_multiplier.to_string(),
            max_transaction_lifetime: duration(
                Duration::from_millis(config.max_transaction_lifetime),
                "h",
            ),
            max_block_future_time: duration(
                Duration::from_millis(config.max_block_future_time),
                "ms",
            ),
            max_mosaic_atomic_units: grouped(config.max_mosaic_atomic_units),
            total_chain_importance: grouped(config.total_chain_importance),
            min_harvester_balance: grouped(config.min_harvester_balance),
            max_harvester_balance: grouped(config.max_harvester_balance),
            min_voter_balance: grouped(config.finalization.min_voter_balance),
            voting_set_grouping: parameters.voting_set_grouping.to_string(),
            max_voting_keys_per_account: parameters.max_voting_keys_per_account.to_string(),
            min_voting_key_lifetime: parameters.min_voting_key_lifetime.to_string(),
            max_voting_key_lifetime: parameters.max_voting_key_lifetime.to_string(),
            harvest_beneficiary_percentage: config.harvest_beneficiary_percentage.to_string(),
            harvest_network_percentage: config.harvest_network_percentage.to_string(),
            harvest_network_fee_sink_address_v1: config.harvest_network_fee_sink.before.to_string(),
            harvest_network_fee_sink_address: config.harvest_network_fee_sink.after.to_string(),
            max_transactions_per_block: grouped(
                heika_chain::verify::MAX_TRANSACTIONS_PER_BLOCK as u64,
            ),
        },
        plugins: PluginsJson {
            accountlink: AccountLinkPluginJson {
                dummy: "to trigger plugin load".to_owned(),
            },
            aggregate: AggregatePluginJson {
                max_transactions_per_aggregate: parameters
                    .max_transactions_per_aggregate
                    .to_string(),
                max_cosignatures_per_aggregate: parameters
                    .max_cosignatures_per_aggregate
                    .to_string(),
                // heika が確かめるのは、メインネットとテストネットのこの決まり
                enable_strict_cosignature_check: false,
                enable_bonded_aggregate_support: true,
                max_bonded_transaction_lifetime: duration(
                    Duration::from_millis(config.max_bonded_transaction_lifetime),
                    "h",
                ),
            },
            lockhash: LockHashPluginJson {
                locked_funds_per_aggregate: grouped(config.locked_funds_per_aggregate),
                max_hash_lock_duration: duration(parameters.max_hash_lock_duration, "d"),
            },
            locksecret: LockSecretPluginJson {
                max_secret_lock_duration: duration(parameters.max_secret_lock_duration, "d"),
                min_proof_size: parameters.min_proof_size.to_string(),
                max_proof_size: parameters.max_proof_size.to_string(),
            },
            metadata: MetadataPluginJson {
                max_value_size: parameters.max_metadata_value_size.to_string(),
            },
            mosaic: {
                let (v1, current) = sinks(&config.mosaic_rental_fee_sink);
                MosaicPluginJson {
                    max_mosaics_per_account: grouped(config.max_mosaics_per_account as u64),
                    max_mosaic_duration: duration(blocks(config.max_mosaic_duration), "d"),
                    max_mosaic_divisibility: config.max_mosaic_divisibility.to_string(),
                    mosaic_rental_fee_sink_address_v1: v1,
                    mosaic_rental_fee_sink_address: current,
                    mosaic_rental_fee: config.mosaic_rental_fee.to_string(),
                }
            },
            multisig: MultisigPluginJson {
                max_multisig_depth: config.max_multisig_depth.to_string(),
                max_cosignatories_per_account: config.max_cosignatories_per_account.to_string(),
                max_cosigned_accounts_per_account: config
                    .max_cosigned_accounts_per_account
                    .to_string(),
            },
            namespace: {
                let (v1, current) = sinks(&config.namespace_rental_fee_sink);
                NamespacePluginJson {
                    max_name_size: parameters.max_namespace_name_size.to_string(),
                    max_child_namespaces: config.max_child_namespaces.to_string(),
                    max_namespace_depth: config.max_namespace_depth.to_string(),
                    min_namespace_duration: duration(parameters.min_namespace_duration, "d"),
                    max_namespace_duration: duration(parameters.max_namespace_duration, "d"),
                    namespace_grace_period_duration: duration(
                        blocks(config.namespace_grace_period),
                        "d",
                    ),
                    namespace_rental_fee_sink_address_v1: v1,
                    namespace_rental_fee_sink_address: current,
                    root_namespace_rental_fee_per_block: config
                        .root_namespace_rental_fee_per_block
                        .to_string(),
                    child_namespace_rental_fee: config.child_namespace_rental_fee.to_string(),
                }
            },
            restrictionaccount: AccountRestrictionPluginJson {
                max_account_restriction_values: config.max_account_restriction_values.to_string(),
            },
            restrictionmosaic: MosaicRestrictionPluginJson {
                max_mosaic_restriction_values: config.max_mosaic_restriction_values.to_string(),
            },
            transfer: TransferPluginJson {
                max_message_size: parameters.max_message_size.to_string(),
            },
        },
    }
}

/// catapult が名前で読むのはメインネットとテストネットだけで、ほかは数で書く
fn identifier(identifier: NetworkIdentifier) -> String {
    match identifier {
        NetworkIdentifier::MAINNET => "mainnet".to_owned(),
        NetworkIdentifier::TESTNET => "testnet".to_owned(),
        NetworkIdentifier(other) => other.to_string(),
    }
}

/// fork の前と後のアドレス
fn sinks(sink: &HeightDependentAddress) -> (String, String) {
    (sink.before.to_string(), sink.after.to_string())
}

/// 3桁ごとに `'` で区切る（`10'000'000`）
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push('\'');
        }
        out.push(digit);
    }
    out
}

/// モザイクの ID。16進で、4桁ごとに `'` で区切る（`0x6BED'913F'A202'23F8`）
fn id(value: u64) -> String {
    let hex = format!("{value:016X}");
    let groups: Vec<&str> = (0..4).map(|index| &hex[index * 4..index * 4 + 4]).collect();
    format!("0x{}", groups.join("'"))
}

/// `unit` で割り切れればその単位で、割り切れなければ割り切れるいちばん大きい単位で書く
fn duration(value: Duration, unit: &str) -> String {
    let millis = u64::try_from(value.as_millis()).unwrap_or(u64::MAX);
    let preferred = UNITS.iter().find(|(name, _)| *name == unit);
    let (name, size) = preferred
        .filter(|(_, size)| millis.is_multiple_of(*size))
        .or_else(|| UNITS.iter().find(|(_, size)| millis.is_multiple_of(*size)))
        .copied()
        .unwrap_or(("ms", 1));
    format!("{}{name}", millis / size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_grouped_by_three_digits() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(6_000), "6'000");
        assert_eq!(grouped(7_842_928_625_000_000), "7'842'928'625'000'000");
    }

    #[test]
    fn mosaic_ids_are_grouped_by_four_hex_digits() {
        assert_eq!(id(0x6BED_913F_A202_23F8), "0x6BED'913F'A202'23F8");
        assert_eq!(id(1), "0x0000'0000'0000'0001");
    }

    #[test]
    fn durations_keep_the_unit_when_it_divides() {
        assert_eq!(duration(Duration::from_secs(48 * 3600), "h"), "48h");
        assert_eq!(duration(Duration::from_millis(300), "ms"), "300ms");
        // 割り切れなければ、割り切れるいちばん大きい単位にする
        assert_eq!(duration(Duration::from_secs(90 * 60), "h"), "90m");
        assert_eq!(duration(Duration::from_millis(1500), "s"), "1500ms");
    }

    #[test]
    fn mainnet_properties_match_the_node_configuration() {
        let properties = network_properties(&NetworkParameters::MAINNET, &ChainConfig::mainnet());
        let json = serde_json::to_value(&properties).unwrap();
        assert_eq!(json["network"]["identifier"], "mainnet");
        assert_eq!(json["network"]["epochAdjustment"], "1615853185s");
        assert_eq!(json["chain"]["enableVerifiableState"], true);
        assert_eq!(json["chain"]["currencyMosaicId"], "0x6BED'913F'A202'23F8");
        assert_eq!(json["chain"]["maxTransactionLifetime"], "6h");
        assert_eq!(json["chain"]["minVoterBalance"], "3'000'000'000'000");
        assert_eq!(json["chain"]["maxTransactionsPerBlock"], "6'000");
        assert_eq!(
            json["plugins"]["aggregate"]["maxBondedTransactionLifetime"],
            "48h"
        );
        assert_eq!(json["plugins"]["mosaic"]["maxMosaicDuration"], "3650d");
        assert_eq!(
            json["plugins"]["namespace"]["namespaceGracePeriodDuration"],
            "30d"
        );
        assert_eq!(
            json["plugins"]["namespace"]["namespaceRentalFeeSinkAddressV1"]
                .as_str()
                .map(|address| address.starts_with('N')),
            Some(true)
        );
    }
}
