//! ノードの `resources` フォルダーの3つのファイルから、[`ChainConfig`] を決め打ちにした Rust のコードを作る。
//! ネットワークの設定が変わったら（ハードフォーク）、これで作り直す。
//!
//! ```text
//! cargo run -p heika-state-transition --example builtin_config -- <resources> > crates/heika-state-transition/src/config/<network>.rs
//! ```

use std::fmt::Write;
use std::path::Path;

use heika_state_transition::config::{ChainConfig, HeightDependentAddress};

fn main() {
    let resources = std::env::args()
        .nth(1)
        .expect("resources フォルダーを渡してください");
    let config = ChainConfig::load(Path::new(&resources)).expect("設定を読めません");
    print!("{}", generate(&config));
}

fn generate(c: &ChainConfig) -> String {
    let mut out = String::new();
    let sink = |sink: &HeightDependentAddress| {
        format!(
            "HeightDependentAddress {{\n            before: address(\"{}\"),\n            after: address(\"{}\"),\n            fork_height: {},\n        }}",
            encode(&sink.before.0),
            encode(&sink.after.0),
            sink.fork_height
        )
    };
    let numbers = |values: &[u64]| {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let f = &c.finalization;
    out.push_str(
        "//! `examples/builtin_config.rs` で、ノードの `resources` フォルダーの3つのファイルから作った。手で直さない\n\n",
    );
    out.push_str("use super::*;\n\n");
    out.push_str("pub(super) fn config() -> ChainConfig {\n    ChainConfig {\n");
    let mut field = |name: &str, value: String| {
        writeln!(out, "        {name}: {value},").unwrap();
    };
    field(
        "currency_mosaic_id",
        format!("0x{:016X}", c.currency_mosaic_id),
    );
    field(
        "harvesting_mosaic_id",
        format!("0x{:016X}", c.harvesting_mosaic_id),
    );
    field(
        "block_generation_target_time",
        c.block_generation_target_time.to_string(),
    );
    field("importance_grouping", c.importance_grouping.to_string());
    field(
        "importance_activity_percentage",
        c.importance_activity_percentage.to_string(),
    );
    field("max_difficulty_blocks", c.max_difficulty_blocks.to_string());
    field(
        "default_dynamic_fee_multiplier",
        c.default_dynamic_fee_multiplier.to_string(),
    );
    field(
        "total_chain_importance",
        c.total_chain_importance.to_string(),
    );
    field("min_harvester_balance", c.min_harvester_balance.to_string());
    field("max_harvester_balance", c.max_harvester_balance.to_string());
    field(
        "harvest_beneficiary_percentage",
        c.harvest_beneficiary_percentage.to_string(),
    );
    field(
        "harvest_network_percentage",
        c.harvest_network_percentage.to_string(),
    );
    field(
        "harvest_network_fee_sink",
        sink(&c.harvest_network_fee_sink),
    );
    field("mosaic_rental_fee", c.mosaic_rental_fee.to_string());
    field("mosaic_rental_fee_sink", sink(&c.mosaic_rental_fee_sink));
    field(
        "root_namespace_rental_fee_per_block",
        c.root_namespace_rental_fee_per_block.to_string(),
    );
    field(
        "child_namespace_rental_fee",
        c.child_namespace_rental_fee.to_string(),
    );
    field(
        "namespace_rental_fee_sink",
        sink(&c.namespace_rental_fee_sink),
    );
    field(
        "namespace_grace_period",
        c.namespace_grace_period.to_string(),
    );
    field("inflation", "INFLATION.to_vec()".to_owned());
    field(
        "skip_secret_lock_uniqueness_checks",
        format!("vec![{}]", numbers(&c.skip_secret_lock_uniqueness_checks)),
    );
    field(
        "skip_secret_lock_expirations",
        format!("vec![{}]", numbers(&c.skip_secret_lock_expirations)),
    );
    field(
        "force_secret_lock_expirations",
        format!("vec![{}]", numbers(&c.force_secret_lock_expirations)),
    );
    field(
        "total_voting_balance_calculation_fix",
        c.total_voting_balance_calculation_fix.to_string(),
    );
    field(
        "nemesis_signer_public_key",
        format!(
            "PublicKey(bytes(\"{}\"))",
            encode(&c.nemesis_signer_public_key.0)
        ),
    );
    field(
        "treasury_reissuance_transaction_signatures",
        format!(
            "vec![{}]",
            c.treasury_reissuance_transaction_signatures
                .iter()
                .map(|signature| format!(
                    "\n            Signature(bytes(\"{}\")),",
                    encode(&signature.0)
                ))
                .collect::<String>()
                + if c.treasury_reissuance_transaction_signatures.is_empty() {
                    ""
                } else {
                    "\n        "
                }
        ),
    );
    field(
        "treasury_reissuance_height",
        c.treasury_reissuance_height.to_string(),
    );
    field("max_block_future_time", c.max_block_future_time.to_string());
    field(
        "max_transaction_lifetime",
        c.max_transaction_lifetime.to_string(),
    );
    field(
        "max_bonded_transaction_lifetime",
        c.max_bonded_transaction_lifetime.to_string(),
    );
    field("min_proof_size", c.min_proof_size.to_string());
    field("max_proof_size", c.max_proof_size.to_string());
    field(
        "max_mosaic_atomic_units",
        c.max_mosaic_atomic_units.to_string(),
    );
    field("max_namespace_depth", c.max_namespace_depth.to_string());
    field("max_child_namespaces", c.max_child_namespaces.to_string());
    field(
        "max_namespace_duration",
        c.max_namespace_duration.to_string(),
    );
    field(
        "reserved_root_namespace_ids",
        format!(
            "vec![{}]",
            c.reserved_root_namespace_ids
                .iter()
                .map(|id| format!("0x{id:016X}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    field(
        "max_mosaics_per_account",
        c.max_mosaics_per_account.to_string(),
    );
    field("max_mosaic_duration", c.max_mosaic_duration.to_string());
    field(
        "max_mosaic_divisibility",
        c.max_mosaic_divisibility.to_string(),
    );
    field(
        "locked_funds_per_aggregate",
        c.locked_funds_per_aggregate.to_string(),
    );
    field("max_multisig_depth", c.max_multisig_depth.to_string());
    field(
        "max_cosignatories_per_account",
        c.max_cosignatories_per_account.to_string(),
    );
    field(
        "max_cosigned_accounts_per_account",
        c.max_cosigned_accounts_per_account.to_string(),
    );
    field(
        "max_account_restriction_values",
        c.max_account_restriction_values.to_string(),
    );
    field(
        "max_mosaic_restriction_values",
        c.max_mosaic_restriction_values.to_string(),
    );
    field(
        "finalization",
        format!(
            "FinalizationConfig {{\n            voting_set_grouping: {},\n            min_voter_balance: {},\n            size: {},\n            threshold: {},\n            max_hashes_per_point: {},\n            treasury_reissuance_epoch: {},\n            ineligible_voters: vec![{}],\n        }}",
            f.voting_set_grouping,
            f.min_voter_balance,
            f.size,
            f.threshold,
            f.max_hashes_per_point,
            f.treasury_reissuance_epoch,
            f.ineligible_voters
                .iter()
                .map(|address| format!("\n                bytes(\"{}\"),", encode(address)))
                .collect::<String>()
                + if f.ineligible_voters.is_empty() {
                    ""
                } else {
                    "\n            "
                }
        ),
    );
    out.push_str("    }\n}\n\n");
    out.push_str("/// （この高さから、1ブロックあたりのインフレ）\n");
    writeln!(
        out,
        "const INFLATION: [(u64, u64); {}] = [",
        c.inflation.len()
    )
    .unwrap();
    for (height, amount) in &c.inflation {
        writeln!(out, "    ({height}, {amount}),").unwrap();
    }
    out.push_str("];\n");
    out
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}
