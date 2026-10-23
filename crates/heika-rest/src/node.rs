//! ノードとチェーンの様子。`/node/info`、`/chain/info`、`/node/unlockedaccount` が返す JSON と、heika だけの
//! `/heika/delegations`（委任の様子）。
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
    /// 委任の鍵（NodeKeyLink を向ける鍵）。16進
    pub node_public_key: String,
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
