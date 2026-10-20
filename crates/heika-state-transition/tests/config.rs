//! ノードの本物の設定ファイルを読めるか。設定ファイルはリポジトリに入れないので、`HEIKA_TEST_RESOURCES` に
//! ノードの `resources` フォルダー（`:` で区切って何個でも）を渡したときだけ走らせる:
//!
//! ```text
//! HEIKA_TEST_RESOURCES=/path/to/resources cargo test -p heika-state-transition --test config -- --ignored
//! ```

use std::path::Path;

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
