//! ノードとチェーンの様子。`/node/info`、`/node/peers`、`/chain/info`、`/node/unlockedaccount`、`/node/server`、`/node/health`、
//! `/network`、`/network/properties` が返す JSON と、heika だけの
//! `/heika/delegations`（委任の様子）と、`PUT /transactions` の本文と答え。
//!
//! catapult の REST の `NodeInfoDTO`、`ChainInfoDTO`、`UnlockedAccountDTO` に合わせている。64ビットの数は、catapult の
//! REST と同じく10進の文字列にする。heika の API はこれを返し、クライアントはこれで読む。

use serde::{Deserialize, Serialize};

/// `NodeInfoDTO`。ウォレットは、委任するノードの `nodePublicKey` をここから取る
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfoJson {
    pub version: u32,
    /// ノードを見分ける鍵（CA の公開鍵）。16進
    pub public_key: String,
    pub network_generation_hash_seed: String,
    pub roles: u32,
    pub port: u16,
    pub network_identifier: u8,
    pub host: String,
    pub friendly_name: String,
    /// 委任の鍵（NodeKeyLink を向ける鍵）。16進。`/node/peers` のピアにはない
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_public_key: Option<String>,
}

/// `NetworkTypeDTO`（`/network`）。ノードの一覧を作るクローラーは、これでどのネットワークのノードかを見分ける
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct NetworkJson {
    /// `mainnet`、`testnet` など
    pub name: String,
    pub description: String,
}

/// `NetworkConfigurationDTO`（`/network/properties`）。catapult の REST は、ノードの `config-network.properties` を
/// そのまま返す。値は、ファイルに書いてあるとおりの文字列（`6h`、`0x6BED'913F'A202'23F8`、`10'000'000` など）で、
/// `true` と `false` だけ真偽値にする。読む側は、桁の区切りの `'` を外して読む
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct NetworkPropertiesJson {
    pub network: NetworkSectionJson,
    pub chain: ChainSectionJson,
    pub plugins: PluginsJson,
}

/// `[network]`
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSectionJson {
    pub identifier: String,
    pub nemesis_signer_public_key: String,
    pub node_equality_strategy: String,
    pub generation_hash_seed: String,
    pub epoch_adjustment: String,
}

/// `[chain]`
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSectionJson {
    pub enable_verifiable_state: bool,
    pub enable_verifiable_receipts: bool,
    pub currency_mosaic_id: String,
    pub harvesting_mosaic_id: String,
    pub block_generation_target_time: String,
    pub block_time_smoothing_factor: String,
    pub importance_grouping: String,
    pub importance_activity_percentage: String,
    pub max_difficulty_blocks: String,
    pub default_dynamic_fee_multiplier: String,
    pub max_transaction_lifetime: String,
    pub max_block_future_time: String,
    pub max_mosaic_atomic_units: String,
    pub total_chain_importance: String,
    pub min_harvester_balance: String,
    pub max_harvester_balance: String,
    pub min_voter_balance: String,
    pub voting_set_grouping: String,
    pub max_voting_keys_per_account: String,
    pub min_voting_key_lifetime: String,
    pub max_voting_key_lifetime: String,
    pub harvest_beneficiary_percentage: String,
    pub harvest_network_percentage: String,
    #[serde(rename = "harvestNetworkFeeSinkAddressV1")]
    pub harvest_network_fee_sink_address_v1: String,
    pub harvest_network_fee_sink_address: String,
    pub max_transactions_per_block: String,
}

/// `[plugin:catapult.plugins.*]`
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct PluginsJson {
    pub accountlink: AccountLinkPluginJson,
    pub aggregate: AggregatePluginJson,
    pub lockhash: LockHashPluginJson,
    pub locksecret: LockSecretPluginJson,
    pub metadata: MetadataPluginJson,
    pub mosaic: MosaicPluginJson,
    pub multisig: MultisigPluginJson,
    pub namespace: NamespacePluginJson,
    pub restrictionaccount: AccountRestrictionPluginJson,
    pub restrictionmosaic: MosaicRestrictionPluginJson,
    pub transfer: TransferPluginJson,
}

/// 設定のない plugin を読み込ませるための、中身のない値
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct AccountLinkPluginJson {
    pub dummy: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatePluginJson {
    pub max_transactions_per_aggregate: String,
    pub max_cosignatures_per_aggregate: String,
    pub enable_strict_cosignature_check: bool,
    pub enable_bonded_aggregate_support: bool,
    pub max_bonded_transaction_lifetime: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockHashPluginJson {
    pub locked_funds_per_aggregate: String,
    pub max_hash_lock_duration: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockSecretPluginJson {
    pub max_secret_lock_duration: String,
    pub min_proof_size: String,
    pub max_proof_size: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataPluginJson {
    pub max_value_size: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MosaicPluginJson {
    pub max_mosaics_per_account: String,
    pub max_mosaic_duration: String,
    pub max_mosaic_divisibility: String,
    #[serde(rename = "mosaicRentalFeeSinkAddressV1")]
    pub mosaic_rental_fee_sink_address_v1: String,
    pub mosaic_rental_fee_sink_address: String,
    pub mosaic_rental_fee: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigPluginJson {
    pub max_multisig_depth: String,
    pub max_cosignatories_per_account: String,
    pub max_cosigned_accounts_per_account: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespacePluginJson {
    pub max_name_size: String,
    pub max_child_namespaces: String,
    pub max_namespace_depth: String,
    pub min_namespace_duration: String,
    pub max_namespace_duration: String,
    pub namespace_grace_period_duration: String,
    #[serde(rename = "namespaceRentalFeeSinkAddressV1")]
    pub namespace_rental_fee_sink_address_v1: String,
    pub namespace_rental_fee_sink_address: String,
    pub root_namespace_rental_fee_per_block: String,
    pub child_namespace_rental_fee: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRestrictionPluginJson {
    pub max_account_restriction_values: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MosaicRestrictionPluginJson {
    pub max_mosaic_restriction_values: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferPluginJson {
    pub max_message_size: String,
}

/// `ServerInfoDTO`（`/node/server`）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfoJson {
    pub server_info: ServerJson,
}

/// [`ServerInfoJson`] の中身。catapult の REST は、わからない値を `N/A` にする
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerJson {
    pub rest_version: String,
    pub deployment: DeploymentJson,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentJson {
    pub deployment_tool: String,
    pub deployment_tool_version: String,
    pub last_updated_date: String,
}

/// `NodeHealthDTO`（`/node/health`）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct NodeHealthJson {
    pub status: HealthStatusJson,
}

/// `up` か `down`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthStatusJson {
    pub api_node: String,
    pub db: String,
}

/// `FinalizedBlockDTO`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizedBlockJson {
    pub finalization_epoch: u32,
    pub finalization_point: u32,
    pub height: String,
    pub hash: String,
}

/// `ChainInfoDTO`
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainInfoJson {
    pub height: String,
    pub score_high: String,
    pub score_low: String,
    pub latest_finalized_block: FinalizedBlockJson,
}

impl ChainInfoJson {
    /// 高さ、スコア、確定したブロックから作る。スコアは上の64ビットと下の64ビットに分ける
    pub fn new(
        height: u64,
        score: u128,
        epoch: u32,
        point: u32,
        finalized: u64,
        hash: String,
    ) -> Self {
        Self {
            height: height.to_string(),
            score_high: ((score >> 64) as u64).to_string(),
            score_low: (score as u64).to_string(),
            latest_finalized_block: FinalizedBlockJson {
                finalization_epoch: epoch,
                finalization_point: point,
                height: finalized.to_string(),
                hash,
            },
        }
    }
}

/// `UnlockedAccountDTO`。ノードがハーベストしている、委任されたリモートの鍵（16進）
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockedAccountJson {
    pub unlocked_account: Vec<String>,
}

/// 委任の様子（heika だけ）
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DelegationStateJson {
    /// 引き受けて、ハーベストしている
    Accepted,
    /// 取り込めるが、上限を超えているので空きを待っている
    Waiting,
    /// 引き受けなかった。`reason` にわけがある
    Rejected,
}

/// `/heika/delegations` の1件。届いた委任の要求ごとに、引き受けたか、なぜ引き受けなかったか
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationJson {
    /// メインアカウントの公開鍵（16進）。わからなければ null
    pub main_public_key: Option<String>,
    /// 要求に入っていたリモートの鍵（16進）
    pub remote_public_key: String,
    /// 要求が入っていたブロックの高さ。わからなければ null
    pub height: Option<String>,
    pub state: DelegationStateJson,
    pub reason: Option<String>,
}

/// `/network/fees/transaction` が返す `TransactionFeesDTO`。直近のブロックの手数料の倍率と、ノードが受け付ける下限
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionFeesJson {
    pub average_fee_multiplier: u32,
    pub median_fee_multiplier: u32,
    pub highest_fee_multiplier: u32,
    pub lowest_fee_multiplier: u32,
    pub min_fee_multiplier: u32,
}

impl TransactionFeesJson {
    /// 直近のブロックの倍率 `multipliers`（並びは問わない）と、ノードの下限から作る。中央値は catapult の REST と同じく、
    /// 数が偶数なら真ん中の2つの平均（切り捨て）。ブロックがなければ倍率は0
    pub fn new(mut multipliers: Vec<u32>, min_fee_multiplier: u32) -> Self {
        multipliers.sort_unstable();
        let count = multipliers.len();
        let median = match count {
            0 => 0,
            _ if count % 2 == 1 => multipliers[count / 2],
            _ => {
                ((u64::from(multipliers[count / 2 - 1]) + u64::from(multipliers[count / 2])) / 2)
                    as u32
            }
        };
        let sum: u64 = multipliers.iter().map(|&value| u64::from(value)).sum();
        Self {
            average_fee_multiplier: if count == 0 {
                0
            } else {
                (sum / count as u64) as u32
            },
            median_fee_multiplier: median,
            highest_fee_multiplier: multipliers.last().copied().unwrap_or(0),
            lowest_fee_multiplier: multipliers.first().copied().unwrap_or(0),
            min_fee_multiplier,
        }
    }
}

/// `PUT /transactions` の本文。署名したトランザクション（16進）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AnnounceJson {
    pub payload: String,
}

/// `PUT /transactions` が受け付けたときの答え（catapult の REST と同じ文）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AnnounceResultJson {
    pub message: String,
}

impl AnnounceResultJson {
    pub fn pushed() -> Self {
        Self::pushed_via(9, "/transactions")
    }

    /// パケットの種類 `packet_type` で、口 `path` から流したとき（catapult の REST と同じ文）
    pub fn pushed_via(packet_type: u32, path: &str) -> Self {
        Self {
            message: format!("packet {packet_type} was pushed to the network via {path}"),
        }
    }
}

/// `PUT /transactions/cosignature` の本体（catapult の `CosignatureDTO`）。16進で、`version` は10進の文字列
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignatureJson {
    #[serde(default)]
    pub version: Option<String>,
    pub signer_public_key: String,
    pub signature: String,
    pub parent_hash: String,
}

/// 受け付けなかったときの答え（catapult の REST のエラーと同じ形）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ErrorJson {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_info_reads_the_catapult_shape() {
        let text = r#"{"height":"5887045","scoreHigh":"39","scoreLow":"10957368298990008967","latestFinalizedBlock":{"finalizationEpoch":4090,"finalizationPoint":14,"height":"5887020","hash":"AB"}}"#;
        let info: ChainInfoJson = serde_json::from_str(text).unwrap();
        let score = (39u128 << 64) | 10957368298990008967;
        assert_eq!(
            info,
            ChainInfoJson::new(5887045, score, 4090, 14, 5887020, "AB".to_owned())
        );
        assert_eq!(serde_json::to_string(&info).unwrap(), text);
    }

    #[test]
    fn summarizes_fee_multipliers() {
        let fees = TransactionFeesJson::new(vec![100, 0, 30, 10], 10);
        assert_eq!(
            serde_json::to_string(&fees).unwrap(),
            r#"{"averageFeeMultiplier":35,"medianFeeMultiplier":20,"highestFeeMultiplier":100,"lowestFeeMultiplier":0,"minFeeMultiplier":10}"#
        );
        assert_eq!(
            TransactionFeesJson::new(vec![5, 1, 3], 0).median_fee_multiplier,
            3
        );
        assert_eq!(
            TransactionFeesJson::new(Vec::new(), 7).median_fee_multiplier,
            0
        );
    }

    #[test]
    fn delegations_use_camel_case() {
        let delegation = DelegationJson {
            main_public_key: None,
            remote_public_key: "AA".to_owned(),
            height: Some("7".to_owned()),
            state: DelegationStateJson::Rejected,
            reason: Some("わけ".to_owned()),
        };
        assert_eq!(
            serde_json::to_string(&delegation).unwrap(),
            r#"{"mainPublicKey":null,"remotePublicKey":"AA","height":"7","state":"rejected","reason":"わけ"}"#
        );
        let unlocked = UnlockedAccountJson {
            unlocked_account: vec!["AA".to_owned()],
        };
        assert_eq!(
            serde_json::to_string(&unlocked).unwrap(),
            r#"{"unlockedAccount":["AA"]}"#
        );
    }
}
