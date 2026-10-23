//! ノードとチェーンの様子。`/node/info`、`/node/peers`、`/chain/info`、`/node/unlockedaccount` が返す JSON と、heika だけの
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
        Self {
            message: "packet 9 was pushed to the network via /transactions".to_owned(),
        }
    }
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
