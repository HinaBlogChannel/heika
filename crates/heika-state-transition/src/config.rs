//! ノードの設定ファイル（`config-network.properties`、`config-inflation.properties`、
//! `config-finalization.properties`）から、状態遷移に要る値（[`ChainConfig`]）と、決め打ちのないネットワークの
//! パラメーター（[`network_parameters`]）を読む。
//!
//! 読むのはテキストから。ファイルから読む口（[`ChainConfig::load`]、[`load_network_parameters`]）は、ノードの
//! `resources` フォルダーを読んで渡すだけ。
//!
//! メインネットとテストネットの [`ChainConfig`] は、ファイルなしで使えるように決め打ちでも持つ
//! （[`ChainConfig::mainnet`]、[`ChainConfig::testnet`]）。`examples/builtin_config.rs` で、ファイルから作る。

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

use heika_block::finalization::proof::ProofParameters;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::PublicKey;
use heika_core::network::{ForkHeights, GenerationHashSeed, NetworkIdentifier, NetworkParameters};
use heika_core::signature::Signature;
use heika_transaction::NamespaceId;

mod mainnet;
mod testnet;

const NETWORK_FILE: &str = "config-network.properties";
const INFLATION_FILE: &str = "config-inflation.properties";
const FINALIZATION_FILE: &str = "config-finalization.properties";

fn read(resources: &Path, name: &str) -> Result<String, ConfigError> {
    let path = resources.join(name);
    fs::read_to_string(&path)
        .map_err(|error| ConfigError(format!("{} を読めません: {error}", path.display())))
}

/// 設定が読めなかったわけ。
#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "設定: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// `[セクション]` と `キー = 値` の並び。値の `'` は桁の区切りなので外す。
struct Properties {
    values: HashMap<(String, String), String>,
    name: String,
}

impl Properties {
    /// `name` は、読めないときに出す名前
    fn parse(name: &str, text: &str) -> Self {
        let mut values = HashMap::new();
        let mut section = String::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            {
                section = name.to_owned();
            } else if let Some((key, value)) = line.split_once('=') {
                values.insert(
                    (section.clone(), key.trim().to_owned()),
                    value.trim().replace('\'', ""),
                );
            }
        }
        Self {
            values,
            name: name.to_owned(),
        }
    }

    fn get(&self, section: &str, key: &str) -> Result<&str, ConfigError> {
        self.values
            .get(&(section.to_owned(), key.to_owned()))
            .map(String::as_str)
            .ok_or_else(|| ConfigError(format!("{} に [{section}] {key} がありません", self.name)))
    }

    fn number(&self, section: &str, key: &str) -> Result<u64, ConfigError> {
        let value = self.get(section, key)?;
        let parsed = match value.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => value.parse(),
        };
        parsed.map_err(|_| ConfigError(format!("[{section}] {key} が数ではありません: {value}")))
    }

    /// `,` で区切った数の並び。空なら空の並び（テストネットの `skipSecretLockExpirations =` など）
    fn numbers(&self, section: &str, key: &str) -> Result<Vec<u64>, ConfigError> {
        let value = self.get(section, key)?;
        if value.is_empty() {
            return Ok(Vec::new());
        }
        value
            .split(',')
            .map(|value| {
                value
                    .trim()
                    .parse()
                    .map_err(|_| ConfigError(format!("[{section}] {key} が数の並びではありません")))
            })
            .collect()
    }

    fn address(&self, section: &str, key: &str) -> Result<Address, ConfigError> {
        let value = self.get(section, key)?;
        value.parse().map_err(|_| {
            ConfigError(format!(
                "[{section}] {key} がアドレスではありません: {value}"
            ))
        })
    }

    fn size(&self, section: &str, key: &str) -> Result<usize, ConfigError> {
        self.number(section, key)?
            .try_into()
            .map_err(|_| ConfigError(format!("[{section}] {key} が大きすぎます")))
    }

    /// `30s`、`1d` のような期間を、ブロックの数ではなく秒で読む
    fn seconds(&self, section: &str, key: &str) -> Result<u64, ConfigError> {
        Ok(self.milliseconds(section, key)? / 1000)
    }

    /// `300ms`、`30s` のような期間を、ミリ秒で読む
    fn milliseconds(&self, section: &str, key: &str) -> Result<u64, ConfigError> {
        let value = self.get(section, key)?;
        let split = value
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| ConfigError(format!("[{section}] {key} に単位がありません: {value}")))?;
        let (number, unit) = value.split_at(split);
        let number: u64 = number
            .parse()
            .map_err(|_| ConfigError(format!("[{section}] {key} が期間ではありません: {value}")))?;
        let unit = match unit {
            "ms" => 1,
            "s" => 1000,
            "m" => 60 * 1000,
            "h" => 60 * 60 * 1000,
            "d" => 24 * 60 * 60 * 1000,
            _ => {
                return Err(ConfigError(format!(
                    "[{section}] {key} の単位が分かりません: {value}"
                )));
            }
        };
        Ok(number * unit)
    }
}

/// ファイナライズの設定。config-network の `votingSetGrouping` と `minVoterBalance`、config-finalization から
#[derive(Clone, Debug)]
pub struct FinalizationConfig {
    pub voting_set_grouping: u64,
    pub min_voter_balance: u64,
    /// 閾値は、重みの合計 × `threshold` / `size`
    pub size: u64,
    pub threshold: u64,
    pub max_hashes_per_point: u64,
    /// `stepDuration`（ミリ秒）。投票の段取りで、prevote と precommit を待つ長さの単位
    pub step_duration: u64,
    /// `prevoteBlocksMultiple`。prevote の最後の高さを、この倍数にそろえる
    pub prevote_blocks_multiple: u64,
    /// このエポックから、`ineligible_voters` を投票者から外す
    pub treasury_reissuance_epoch: u32,
    pub ineligible_voters: Vec<[u8; 24]>,
}

impl FinalizationConfig {
    /// 証明を確かめるのに要る分
    pub fn proof_parameters(&self) -> ProofParameters {
        ProofParameters {
            voting_set_grouping: self.voting_set_grouping,
            size: self.size,
            threshold: self.threshold,
            max_hashes_per_point: self.max_hashes_per_point,
        }
    }

    /// エポック `epoch` の最後の高さ（[`ProofParameters::voting_set_end_height`]）
    pub fn voting_set_end_height(&self, epoch: u32) -> u64 {
        self.proof_parameters().voting_set_end_height(epoch)
    }
}

/// 高さによって替わるアドレス。`V1` は fork の高さより前に使う。
#[derive(Clone, Copy, Debug)]
pub struct HeightDependentAddress {
    pub before: Address,
    pub after: Address,
    pub fork_height: u64,
}

impl HeightDependentAddress {
    pub fn at(&self, height: u64) -> Address {
        if height < self.fork_height {
            self.before
        } else {
            self.after
        }
    }
}

/// 実行に要る、チェーンの設定。
#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub currency_mosaic_id: u64,
    pub harvesting_mosaic_id: u64,
    /// ブロックの間隔（秒）
    pub block_generation_target_time: u64,
    pub importance_grouping: u64,
    pub importance_activity_percentage: u64,
    pub max_difficulty_blocks: u64,
    pub default_dynamic_fee_multiplier: u32,
    pub total_chain_importance: u64,
    pub min_harvester_balance: u64,
    pub max_harvester_balance: u64,
    pub harvest_beneficiary_percentage: u64,
    pub harvest_network_percentage: u64,
    pub harvest_network_fee_sink: HeightDependentAddress,
    pub mosaic_rental_fee: u64,
    pub mosaic_rental_fee_sink: HeightDependentAddress,
    pub root_namespace_rental_fee_per_block: u64,
    pub child_namespace_rental_fee: u64,
    pub namespace_rental_fee_sink: HeightDependentAddress,
    /// ネームスペースの猶予（ブロック）
    pub namespace_grace_period: u64,
    /// （この高さから、1ブロックあたりのインフレ）を高さの順に
    pub inflation: Vec<(u64, u64)>,
    /// シークレットロックの重なりを確かめない高さ（`skipSecretLockUniquenessChecks`）
    pub skip_secret_lock_uniqueness_checks: Vec<u64>,
    /// シークレットロックの期限切れを処理しない高さ（`skipSecretLockExpirations`）
    pub skip_secret_lock_expirations: Vec<u64>,
    /// シークレットロックの期限切れを、終わりの高さでなくても処理する高さ（`forceSecretLockExpirations`）
    pub force_secret_lock_expirations: Vec<u64>,
    /// この高さから、importance ブロックの投票の残高の合計を、そのエポックに鍵のあるアカウントだけで数える
    /// （`totalVotingBalanceCalculationFix`）
    pub total_voting_balance_calculation_fix: u64,
    /// `nemesisSignerPublicKey`。Nemesis のあとは、これで署名できない（`NemesisSink`）
    pub nemesis_signer_public_key: PublicKey,
    /// 国庫の再発行の高さでだけ、Nemesis の鍵で署名してよい署名（`[treasury_reissuance_transaction_signatures]`）
    pub treasury_reissuance_transaction_signatures: Vec<Signature>,
    /// 国庫の再発行の高さ（`treasuryReissuance`）。Revokable のモザイクもここから作れる
    pub treasury_reissuance_height: u64,
    /// 受け取った枝の最後のブロックの時刻の、今からの上限（ミリ秒、`maxBlockFutureTime`）
    pub max_block_future_time: u64,
    /// トランザクションの期限の、ブロックの時刻からの上限（ミリ秒）。ボンデッドは別
    pub max_transaction_lifetime: u64,
    pub max_bonded_transaction_lifetime: u64,
    pub min_proof_size: u64,
    pub max_proof_size: u64,
    pub max_mosaic_atomic_units: u64,
    pub max_namespace_depth: usize,
    /// ルートの下に作れる子（孫も数える）の数（`maxChildNamespaces`）
    pub max_child_namespaces: usize,
    /// ネームスペースを持てる期間の、今の高さからの上限（ブロック、`maxNamespaceDuration`）
    pub max_namespace_duration: u64,
    /// Nemesis のあとは取れないルートの ID と、その直下に子を作れないもの（`reservedRootNamespaceNames`）
    pub reserved_root_namespace_ids: Vec<u64>,
    /// 1つのアカウントが持てるモザイクの種類（`maxMosaicsPerAccount`）
    pub max_mosaics_per_account: usize,
    /// モザイクを持てる期間の上限（ブロック、`maxMosaicDuration`）
    pub max_mosaic_duration: u64,
    pub max_mosaic_divisibility: u8,
    /// ハッシュロックに預ける額（`lockedFundsPerAggregate`）
    pub locked_funds_per_aggregate: u64,
    pub max_multisig_depth: usize,
    /// マルチシグの連署者の数と、1つのアカウントが連署できるマルチシグの数
    pub max_cosignatories_per_account: usize,
    pub max_cosigned_accounts_per_account: usize,
    /// アカウントの制限の値の数（`maxAccountRestrictionValues`）
    pub max_account_restriction_values: usize,
    /// モザイクの制限の値の数（`maxMosaicRestrictionValues`）
    pub max_mosaic_restriction_values: usize,
    pub finalization: FinalizationConfig,
}

impl ChainConfig {
    /// メインネットの、決め打ちの設定
    pub fn mainnet() -> Self {
        mainnet::config()
    }

    /// テストネットの、決め打ちの設定
    pub fn testnet() -> Self {
        testnet::config()
    }

    /// ノードの `resources` フォルダーの3つのファイルから読む。
    pub fn load(resources: &Path) -> Result<Self, ConfigError> {
        Self::parse(
            &read(resources, NETWORK_FILE)?,
            &read(resources, INFLATION_FILE)?,
            &read(resources, FINALIZATION_FILE)?,
        )
    }

    /// `config-network.properties`、`config-inflation.properties`、`config-finalization.properties` のテキストから読む。
    pub fn parse(network: &str, inflation: &str, finalization: &str) -> Result<Self, ConfigError> {
        let network = Properties::parse(NETWORK_FILE, network);
        let inflation = Properties::parse(INFLATION_FILE, inflation);
        let finalization = Properties::parse(FINALIZATION_FILE, finalization);
        let chain = "chain";
        let treasury = network.number("fork_heights", "treasuryReissuance")?;
        let sink = |section: &str, key: &str| -> Result<HeightDependentAddress, ConfigError> {
            Ok(HeightDependentAddress {
                before: network.address(section, &format!("{key}V1"))?,
                after: network.address(section, key)?,
                fork_height: treasury,
            })
        };
        let block_time = network.seconds(chain, "blockGenerationTargetTime")?;
        let mosaic = "plugin:catapult.plugins.mosaic";
        let namespace = "plugin:catapult.plugins.namespace";
        let aggregate = "plugin:catapult.plugins.aggregate";
        let lock_secret = "plugin:catapult.plugins.locksecret";
        let multisig = "plugin:catapult.plugins.multisig";

        let mut schedule = Vec::new();
        for ((section, key), value) in &inflation.values {
            if section != "inflation" {
                continue;
            }
            let height = key
                .strip_prefix("starting-at-height-")
                .and_then(|height| height.parse().ok())
                .ok_or_else(|| ConfigError(format!("インフレの高さが読めません: {key}")))?;
            let amount = value
                .parse()
                .map_err(|_| ConfigError(format!("インフレの量が読めません: {value}")))?;
            schedule.push((height, amount));
        }
        schedule.sort_unstable();

        Ok(Self {
            currency_mosaic_id: network.number(chain, "currencyMosaicId")?,
            harvesting_mosaic_id: network.number(chain, "harvestingMosaicId")?,
            block_generation_target_time: block_time,
            importance_grouping: network.number(chain, "importanceGrouping")?,
            importance_activity_percentage: network
                .number(chain, "importanceActivityPercentage")?,
            max_difficulty_blocks: network.number(chain, "maxDifficultyBlocks")?,
            default_dynamic_fee_multiplier: network
                .number(chain, "defaultDynamicFeeMultiplier")?
                .try_into()
                .map_err(|_| {
                    ConfigError("defaultDynamicFeeMultiplier が大きすぎます".to_owned())
                })?,
            total_chain_importance: network.number(chain, "totalChainImportance")?,
            min_harvester_balance: network.number(chain, "minHarvesterBalance")?,
            max_harvester_balance: network.number(chain, "maxHarvesterBalance")?,
            harvest_beneficiary_percentage: network
                .number(chain, "harvestBeneficiaryPercentage")?,
            harvest_network_percentage: network.number(chain, "harvestNetworkPercentage")?,
            harvest_network_fee_sink: sink(chain, "harvestNetworkFeeSinkAddress")?,
            mosaic_rental_fee: network.number(mosaic, "mosaicRentalFee")?,
            mosaic_rental_fee_sink: sink(mosaic, "mosaicRentalFeeSinkAddress")?,
            root_namespace_rental_fee_per_block: network
                .number(namespace, "rootNamespaceRentalFeePerBlock")?,
            child_namespace_rental_fee: network.number(namespace, "childNamespaceRentalFee")?,
            namespace_rental_fee_sink: sink(namespace, "namespaceRentalFeeSinkAddress")?,
            namespace_grace_period: network.seconds(namespace, "namespaceGracePeriodDuration")?
                / block_time,
            inflation: schedule,
            skip_secret_lock_uniqueness_checks: network
                .numbers("fork_heights", "skipSecretLockUniquenessChecks")?,
            skip_secret_lock_expirations: network
                .numbers("fork_heights", "skipSecretLockExpirations")?,
            force_secret_lock_expirations: network
                .numbers("fork_heights", "forceSecretLockExpirations")?,
            total_voting_balance_calculation_fix: network
                .number("fork_heights", "totalVotingBalanceCalculationFix")?,
            nemesis_signer_public_key: network
                .get("network", "nemesisSignerPublicKey")?
                .parse()
                .map_err(|_| ConfigError("nemesisSignerPublicKey が読めません".to_owned()))?,
            // catapult の `ExtractSectionKeysAsTypedVector` と同じく、値が true のキーだけ
            treasury_reissuance_transaction_signatures: network
                .values
                .iter()
                .filter(|((section, _), value)| {
                    section == "treasury_reissuance_transaction_signatures" && *value == "true"
                })
                .map(|((_, signature), _)| {
                    signature.parse().map_err(|_| {
                        ConfigError(format!("国庫の再発行の署名が読めません: {signature}"))
                    })
                })
                .collect::<Result<Vec<Signature>, _>>()
                .map(|mut signatures| {
                    // ファイルの順に依らないように並べる
                    signatures.sort_unstable_by_key(|signature| signature.0);
                    signatures
                })?,
            treasury_reissuance_height: treasury,
            max_block_future_time: network.milliseconds(chain, "maxBlockFutureTime")?,
            max_transaction_lifetime: network.seconds(chain, "maxTransactionLifetime")? * 1000,
            max_bonded_transaction_lifetime: network
                .seconds(aggregate, "maxBondedTransactionLifetime")?
                * 1000,
            min_proof_size: network.number(lock_secret, "minProofSize")?,
            max_proof_size: network.number(lock_secret, "maxProofSize")?,
            max_mosaic_atomic_units: network.number(chain, "maxMosaicAtomicUnits")?,
            max_namespace_depth: network
                .number(namespace, "maxNamespaceDepth")?
                .try_into()
                .map_err(|_| ConfigError("maxNamespaceDepth が大きすぎます".to_owned()))?,
            max_child_namespaces: network
                .number(namespace, "maxChildNamespaces")?
                .try_into()
                .map_err(|_| ConfigError("maxChildNamespaces が大きすぎます".to_owned()))?,
            max_namespace_duration: network.seconds(namespace, "maxNamespaceDuration")?
                / block_time,
            reserved_root_namespace_ids: network
                .get(namespace, "reservedRootNamespaceNames")?
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| NamespaceId::generate(None, name.as_bytes()).0)
                .collect(),
            max_mosaics_per_account: network.size(mosaic, "maxMosaicsPerAccount")?,
            max_mosaic_duration: network.seconds(mosaic, "maxMosaicDuration")? / block_time,
            max_mosaic_divisibility: network
                .number(mosaic, "maxMosaicDivisibility")?
                .try_into()
                .map_err(|_| ConfigError("maxMosaicDivisibility が大きすぎます".to_owned()))?,
            locked_funds_per_aggregate: network.number(
                "plugin:catapult.plugins.lockhash",
                "lockedFundsPerAggregate",
            )?,
            max_multisig_depth: network.size(multisig, "maxMultisigDepth")?,
            max_cosignatories_per_account: network.size(multisig, "maxCosignatoriesPerAccount")?,
            max_cosigned_accounts_per_account: network
                .size(multisig, "maxCosignedAccountsPerAccount")?,
            max_account_restriction_values: network.size(
                "plugin:catapult.plugins.restrictionaccount",
                "maxAccountRestrictionValues",
            )?,
            max_mosaic_restriction_values: network.size(
                "plugin:catapult.plugins.restrictionmosaic",
                "maxMosaicRestrictionValues",
            )?,
            finalization: FinalizationConfig {
                voting_set_grouping: network.number(chain, "votingSetGrouping")?,
                min_voter_balance: network.number(chain, "minVoterBalance")?,
                size: finalization.number("finalization", "size")?,
                threshold: finalization.number("finalization", "threshold")?,
                max_hashes_per_point: finalization.number("finalization", "maxHashesPerPoint")?,
                step_duration: finalization.milliseconds("finalization", "stepDuration")?,
                prevote_blocks_multiple: finalization
                    .number("finalization", "prevoteBlocksMultiple")?,
                treasury_reissuance_epoch: finalization
                    .number("finalization", "treasuryReissuanceEpoch")?
                    .try_into()
                    .map_err(|_| {
                        ConfigError("treasuryReissuanceEpoch が大きすぎます".to_owned())
                    })?,
                ineligible_voters: finalization
                    .values
                    .keys()
                    .filter(|(section, _)| {
                        section == "treasury_reissuance_epoch_ineligible_voter_addresses"
                    })
                    .map(|(_, address)| {
                        address
                            .parse::<Address>()
                            .map(|address| address.0)
                            .map_err(|_| {
                                ConfigError(format!(
                                    "投票者から外すアドレスが読めません: {address}"
                                ))
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(|mut addresses| {
                        addresses.sort_unstable();
                        addresses
                    })?,
            },
        })
    }

    /// `height` のブロックのインフレ。catapult の `InflationCalculator::getSpotAmount`。
    pub fn inflation_at(&self, height: u64) -> u64 {
        self.inflation
            .iter()
            .take_while(|(start, _)| *start <= height)
            .last()
            .map_or(0, |(_, amount)| *amount)
    }

    /// `height` が入る importance の区切りの高さ。catapult の `ConvertToImportanceHeight`。
    /// 再開するとき（`node::chain::load`）に読み直すかもしれない、実行した高さより前のブロックの数の見積もり。
    /// トランザクションの期限（ボンデッドを含む）の2倍のブロック数に、importance ブロックまでの数を足す。
    /// これより前のブロックは、刈り込んでも再開に困らない
    pub fn blocks_for_restart(&self) -> u64 {
        let lifetime = self
            .max_transaction_lifetime
            .max(self.max_bonded_transaction_lifetime);
        2 * lifetime / (self.block_generation_target_time * 1000) + self.importance_grouping
    }

    pub fn importance_height(&self, height: u64) -> u64 {
        let grouped =
            (height.saturating_sub(1)) / self.importance_grouping * self.importance_grouping;
        grouped.max(1)
    }
}

/// 決め打ちの設定に書く、16進のバイト列
fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), 2 * N, "決め打ちの16進の長さ");
    std::array::from_fn(|index| {
        u8::from_str_radix(&text[2 * index..2 * index + 2], 16).expect("決め打ちの16進")
    })
}

fn address(text: &str) -> Address {
    Address(bytes(text))
}

/// [`network_parameters`] を、ノードの `resources` フォルダーの `config-network.properties` から読む
pub fn load_network_parameters(resources: &Path) -> Result<NetworkParameters, ConfigError> {
    network_parameters(&read(resources, NETWORK_FILE)?)
}

/// 決め打ちのパラメーターを持たないネットワーク（プライベートなネットワークなど）の [`NetworkParameters`] を、
/// `config-network.properties` のテキストから読む。`[corrupt_aggregate_transaction_hashes]` の並びは、プロセスが
/// 終わるまで持つ（[`NetworkParameters`] が `'static` の参照で持つため）
pub fn network_parameters(network: &str) -> Result<NetworkParameters, ConfigError> {
    let network = Properties::parse(NETWORK_FILE, network);
    let chain = "chain";
    let aggregate = "plugin:catapult.plugins.aggregate";
    let lock_hash = "plugin:catapult.plugins.lockhash";
    let lock_secret = "plugin:catapult.plugins.locksecret";
    let namespace = "plugin:catapult.plugins.namespace";
    let seconds = |section: &str, key: &str| network.seconds(section, key).map(Duration::from_secs);
    let size = |section: &str, key: &str| network.size(section, key);
    let epochs = |key: &str| -> Result<u32, ConfigError> {
        network
            .number(chain, key)?
            .try_into()
            .map_err(|_| ConfigError(format!("[{chain}] {key} が大きすぎます")))
    };
    let identifier = match network.get("network", "identifier")? {
        "mainnet" => NetworkIdentifier::MAINNET,
        "testnet" => NetworkIdentifier::TESTNET,
        other => NetworkIdentifier(
            other
                .parse()
                .map_err(|_| ConfigError(format!("[network] identifier が読めません: {other}")))?,
        ),
    };
    let generation_hash_seed: GenerationHashSeed = network
        .get("network", "generationHashSeed")?
        .parse()
        .map_err(|_| ConfigError("[network] generationHashSeed が読めません".to_owned()))?;
    let mut corrupt = Vec::new();
    for ((section, aggregate_hash), transactions_hash) in &network.values {
        if section != "corrupt_aggregate_transaction_hashes" {
            continue;
        }
        let parse = |text: &str| {
            text.parse::<Hash256>().map_err(|_| {
                ConfigError(format!("壊れたアグリゲートのハッシュが読めません: {text}"))
            })
        };
        corrupt.push((parse(aggregate_hash)?, parse(transactions_hash)?));
    }
    Ok(NetworkParameters {
        identifier,
        generation_hash_seed,
        epoch_adjustment: seconds("network", "epochAdjustment")?,
        currency_mosaic_id: network.number(chain, "currencyMosaicId")?,
        block_generation_target_time: seconds(chain, "blockGenerationTargetTime")?,
        block_time_smoothing_factor: network.number(chain, "blockTimeSmoothingFactor")?,
        max_difficulty_blocks: size(chain, "maxDifficultyBlocks")?,
        total_chain_importance: network.number(chain, "totalChainImportance")?,
        importance_grouping: network.number(chain, "importanceGrouping")?,
        max_transaction_lifetime: seconds(chain, "maxTransactionLifetime")?,
        max_cosignatures_per_aggregate: size(aggregate, "maxCosignaturesPerAggregate")?,
        max_transactions_per_aggregate: size(aggregate, "maxTransactionsPerAggregate")?,
        max_message_size: size("plugin:catapult.plugins.transfer", "maxMessageSize")?,
        max_hash_lock_duration: seconds(lock_hash, "maxHashLockDuration")?,
        max_secret_lock_duration: seconds(lock_secret, "maxSecretLockDuration")?,
        min_proof_size: size(lock_secret, "minProofSize")?,
        max_proof_size: size(lock_secret, "maxProofSize")?,
        max_metadata_value_size: size("plugin:catapult.plugins.metadata", "maxValueSize")?,
        max_namespace_name_size: size(namespace, "maxNameSize")?,
        min_namespace_duration: seconds(namespace, "minNamespaceDuration")?,
        max_namespace_duration: seconds(namespace, "maxNamespaceDuration")?,
        voting_set_grouping: network.number(chain, "votingSetGrouping")?,
        min_voting_key_lifetime: epochs("minVotingKeyLifetime")?,
        max_voting_key_lifetime: epochs("maxVotingKeyLifetime")?,
        max_voting_keys_per_account: size(chain, "maxVotingKeysPerAccount")?,
        fork_heights: ForkHeights {
            strict_aggregate_transaction_hash: network
                .number("fork_heights", "strictAggregateTransactionHash")?,
            unique_aggregate_transaction_hash: network
                .number("fork_heights", "uniqueAggregateTransactionHash")?,
        },
        corrupt_aggregate_transaction_hashes: Vec::leak(corrupt),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_sections_numbers_and_lists() {
        let properties = Properties::parse(
            "test",
            "# コメント\n[chain]\nmaxDifficultyBlocks = 60\ncurrencyMosaicId = 0x6BED'913F'A202'23F8\n\
             [fork_heights]\nskipSecretLockExpirations =\nforceSecretLockExpirations = 1, 2\n",
        );
        assert_eq!(
            properties.number("chain", "maxDifficultyBlocks").unwrap(),
            60
        );
        assert_eq!(
            properties.number("chain", "currencyMosaicId").unwrap(),
            0x6BED_913F_A202_23F8
        );
        assert!(
            properties
                .numbers("fork_heights", "skipSecretLockExpirations")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            properties
                .numbers("fork_heights", "forceSecretLockExpirations")
                .unwrap(),
            [1, 2]
        );
        assert!(properties.number("chain", "missing").is_err());
    }

    #[test]
    fn reads_durations_in_milliseconds_and_seconds() {
        let properties = Properties {
            values: [
                ("300ms", "300ms"),
                ("30s", "30s"),
                ("2m", "2m"),
                ("1d", "1d"),
            ]
            .into_iter()
            .map(|(key, value)| (("chain".to_owned(), key.to_owned()), value.to_owned()))
            .collect(),
            name: "test".to_owned(),
        };
        assert_eq!(properties.milliseconds("chain", "300ms").unwrap(), 300);
        assert_eq!(properties.seconds("chain", "300ms").unwrap(), 0);
        assert_eq!(properties.milliseconds("chain", "30s").unwrap(), 30_000);
        assert_eq!(properties.seconds("chain", "2m").unwrap(), 120);
        assert_eq!(properties.seconds("chain", "1d").unwrap(), 86_400);
    }
}
