//! ノードの本物の設定ファイルを読めるか。設定ファイルはリポジトリに入れないので、`HEIKA_TEST_RESOURCES` に
//! ノードの `resources` フォルダー（`:` で区切って何個でも）を渡したときだけ走らせる:
//!
//! ```text
//! HEIKA_TEST_RESOURCES=/path/to/resources cargo test -p heika-state-transition --test config -- --ignored
//! ```

use std::path::Path;

use heika_core::network::{NetworkIdentifier, NetworkParameters};
use heika_state_transition::config::{ChainConfig, load_network_parameters};

#[test]
#[ignore = "HEIKA_TEST_RESOURCES にノードの resources フォルダーを渡す"]
fn reads_node_resources() {
    let folders = std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    for folder in folders.split(':') {
        let resources = Path::new(folder);
        let config =
            ChainConfig::load(resources).unwrap_or_else(|error| panic!("{folder}: {error}"));
        let network =
            load_network_parameters(resources).unwrap_or_else(|error| panic!("{folder}: {error}"));
        assert_eq!(
            config.currency_mosaic_id, network.currency_mosaic_id,
            "{folder}"
        );
        assert_eq!(
            config.importance_grouping, network.importance_grouping,
            "{folder}"
        );
        assert!(config.max_mosaics_per_account > 0, "{folder}");
        assert!(config.max_multisig_depth > 0, "{folder}");
    }
}

/// 決め打ちの設定が、ファイルから読んだものと同じか。ネットワークは `config-network.properties` の identifier で選ぶ
#[test]
#[ignore = "HEIKA_TEST_RESOURCES にノードの resources フォルダーを渡す"]
fn builtin_configs_match_node_resources() {
    let folders = std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    for folder in folders.split(':') {
        let resources = Path::new(folder);
        let loaded =
            ChainConfig::load(resources).unwrap_or_else(|error| panic!("{folder}: {error}"));
        let network =
            load_network_parameters(resources).unwrap_or_else(|error| panic!("{folder}: {error}"));
        let builtin = match network.identifier {
            NetworkIdentifier::MAINNET => ChainConfig::mainnet(),
            NetworkIdentifier::TESTNET => ChainConfig::testnet(),
            _ => continue,
        };
        assert_eq!(format!("{builtin:?}"), format!("{loaded:?}"), "{folder}");
    }
}

/// 決め打ちの設定が、heika-core の決め打ちのパラメーターと食い違わないか
#[test]
fn builtin_configs_agree_with_network_parameters() {
    for (config, parameters) in [
        (ChainConfig::mainnet(), &NetworkParameters::MAINNET),
        (ChainConfig::testnet(), &NetworkParameters::TESTNET),
    ] {
        assert_eq!(config.currency_mosaic_id, parameters.currency_mosaic_id);
        assert_eq!(config.importance_grouping, parameters.importance_grouping);
        assert_eq!(
            config.max_difficulty_blocks as usize,
            parameters.max_difficulty_blocks
        );
        assert_eq!(
            config.finalization.voting_set_grouping,
            parameters.voting_set_grouping
        );
    }
}
