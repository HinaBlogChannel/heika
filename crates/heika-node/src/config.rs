//! ノードの設定。Kubernetes のマニフェストのように `apiVersion`、`kind`、`metadata`、`spec` を持つ YAML で書く。
//!
//! ```yaml
//! apiVersion: heika.hinablogchannel.github.io/v1alpha1
//! kind: Peer
//! metadata:
//!   name: symbol-testnet-1
//! spec:
//!   network: testnet
//!   resources: /path/to/resources
//!   dataDirectory: /path/to/data
//!   certificates:
//!     directory: /path/to/certificates
//!   listen:
//!     address: 0.0.0.0:7900
//!     publicHost: symbol-testnet-1.example
//! ```
//!
//! 知らないキーは弾く（綴りの間違いが、黙って既定値にならないように）。秘密（鍵）は書かず、置き場所だけを書く。

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// 読める設定の版。中身を変えたら上げる
pub const API_VERSION: &str = "heika.hinablogchannel.github.io/v1alpha1";

/// ノードの設定ファイル
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    pub metadata: Metadata,
    pub spec: NodeConfig,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    /// 名前。ログに出す
    #[serde(default)]
    pub name: String,
}

/// ネットワーク
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Network {
    Mainnet,
    Testnet,
    /// 決め打ちのパラメーターのないネットワーク（プライベートなネットワークなど）。`resources` の
    /// `config-network.properties` と `nemesisHash` で決める
    Custom,
}

/// ノードの設定（`spec`）
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeConfig {
    pub network: Network,
    /// `network: custom` のときの、Nemesis のブロックのハッシュ（16進）
    #[serde(default)]
    pub nemesis_hash: Option<String>,
    /// ノードの `resources` フォルダー（`config-network.properties` などのあるところ）
    pub resources: PathBuf,
    /// ブロックと状態をしまうフォルダー
    pub data_directory: PathBuf,
    /// TLS の証明書の鎖と鍵のあるフォルダー
    pub certificates: Certificates,
    /// 先端の段階でつないでおくピアの数
    #[serde(default = "default_peers")]
    pub peers: usize,
    /// 住所録が空か全滅したときに、最初につなぐノード（`ホスト:ポート`）
    #[serde(default)]
    pub seed: Option<String>,
    /// アカウントの表を全部はメモリに持たず、要るものだけを読む
    #[serde(default = "default_true")]
    pub partial_state: bool,
    #[serde(default)]
    pub prune: Prune,
    #[serde(default)]
    pub cache: Cache,
    /// ディスクの空きがこれより少なければ、書く前に止める（GB）
    #[serde(default = "default_min_free_gigabytes")]
    pub min_free_gigabytes: u64,
    /// 接続を受ける。なければ、自分からつなぐだけ
    #[serde(default)]
    pub listen: Option<Listen>,
    /// ハーベストする。なければしない
    #[serde(default)]
    pub harvest: Option<Harvest>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Certificates {
    /// `tls.crt`（ノードの証明書と CA の証明書の鎖）と `tls.key`（ノードの鍵）のあるフォルダー
    pub directory: PathBuf,
}

/// 刈り込み。なければ、全部の高さの状態を残す（アーカイブ）
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prune {
    /// 確定より何エポック下までの、状態の差分を残すか
    #[serde(default)]
    pub keep_epochs: Option<u32>,
    /// 古いブロックとステートメントも消す
    #[serde(default)]
    pub history: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cache {
    /// 要るものだけを読むときに、読んだ状態を覚えておく量（MB）
    #[serde(default = "default_state_megabytes")]
    pub state_megabytes: usize,
    /// 先端の段階で DB を開くときの、DB のキャッシュの上限（MB）
    #[serde(default = "default_database_megabytes")]
    pub database_megabytes: usize,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            state_megabytes: default_state_megabytes(),
            database_megabytes: default_database_megabytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Listen {
    /// 待ち受けるアドレス（`0.0.0.0:7900` など）
    pub address: String,
    /// 外から見たホスト名かアドレス。ping で答え、つないだピアに名乗る。なければ空にして、相手に接続元から
    /// 決めてもらう
    #[serde(default)]
    pub public_host: Option<String>,
    /// ping で答え、名乗るときの名前
    #[serde(default)]
    pub friendly_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Harvest {
    /// 1行に「署名の秘密鍵 VRF の秘密鍵」（16進、リモートならリモートの鍵）を書いたファイル。他人に読めないこと
    pub keys_file: PathBuf,
}

fn default_peers() -> usize {
    8
}

fn default_true() -> bool {
    true
}

fn default_min_free_gigabytes() -> u64 {
    10
}

fn default_state_megabytes() -> usize {
    64
}

fn default_database_megabytes() -> usize {
    256
}

/// 設定を読めなかったわけ
#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "設定: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Manifest {
    /// YAML のテキストから読む。版と種類が違えば読まない
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let manifest: Self =
            serde_norway::from_str(text).map_err(|error| ConfigError(error.to_string()))?;
        if manifest.api_version != API_VERSION {
            return Err(ConfigError(format!(
                "apiVersion が {} で、読める {API_VERSION} と違います",
                manifest.api_version
            )));
        }
        if manifest.kind != "Peer" {
            return Err(ConfigError(format!(
                "kind が {} で、Peer ではありません",
                manifest.kind
            )));
        }
        if manifest.spec.network == Network::Custom && manifest.spec.nemesis_hash.is_none() {
            return Err(ConfigError(
                "network: custom には nemesisHash が要ります".to_owned(),
            ));
        }
        Ok(manifest)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ConfigError(format!("{} を読めません: {error}", path.display())))?;
        Self::parse(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "apiVersion: heika.hinablogchannel.github.io/v1alpha1
kind: Peer
spec:
  network: testnet
  resources: /resources
  dataDirectory: /data
  certificates:
    directory: /certificates
";

    #[test]
    fn reads_a_minimal_manifest_with_defaults() {
        let manifest = Manifest::parse(MINIMAL).unwrap();
        let spec = manifest.spec;
        assert_eq!(spec.network, Network::Testnet);
        assert_eq!(spec.peers, 8);
        assert!(spec.partial_state);
        assert_eq!(spec.prune, Prune::default());
        assert_eq!(spec.cache, Cache::default());
        assert_eq!(spec.listen, None);
        assert_eq!(spec.harvest, None);
        assert_eq!(manifest.metadata.name, "");
    }

    #[test]
    fn reads_listen_harvest_and_pruning() {
        let text = format!(
            "{MINIMAL}  listen:
    address: 0.0.0.0:7900
    publicHost: node.example
  harvest:
    keysFile: /keys
  prune:
    keepEpochs: 2
    history: true
  peers: 4
"
        );
        let spec = Manifest::parse(&text).unwrap().spec;
        let listen = spec.listen.unwrap();
        assert_eq!(listen.address, "0.0.0.0:7900");
        assert_eq!(listen.public_host.as_deref(), Some("node.example"));
        assert_eq!(listen.friendly_name, None);
        assert_eq!(spec.harvest.unwrap().keys_file, PathBuf::from("/keys"));
        assert_eq!(spec.prune.keep_epochs, Some(2));
        assert!(spec.prune.history);
        assert_eq!(spec.peers, 4);
    }

    #[test]
    fn refuses_unknown_keys_versions_and_kinds() {
        // 綴りの間違い
        assert!(Manifest::parse(&format!("{MINIMAL}  peerz: 4\n")).is_err());
        assert!(Manifest::parse(&MINIMAL.replace("v1alpha1", "v1alpha2")).is_err());
        assert!(Manifest::parse(&MINIMAL.replace("kind: Peer", "kind: Node")).is_err());
        // custom には Nemesis のハッシュが要る
        let custom = MINIMAL.replace("network: testnet", "network: custom");
        assert!(Manifest::parse(&custom).is_err());
        assert!(Manifest::parse(&format!("{custom}  nemesisHash: AB\n")).is_ok());
    }
}
