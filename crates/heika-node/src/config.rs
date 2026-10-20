//! ノードの設定。Kubernetes のマニフェストのように `apiVersion`、`kind`、`metadata`、`spec` を持つ YAML で書く。
//!
//! ```yaml
//! apiVersion: heika.hinablogchannel.github.io/v1alpha1
//! kind: Peer
//! metadata:
//!   name: symbol-testnet-1
//! spec:
//!   network:
//!     type: testnet
//!     resources: /path/to/resources
//!   dataDirectory: /path/to/data
//!   certificates:
//!     directory: /path/to/certificates
//!   listen:
//!     address: 0.0.0.0:7900
//!     publicHost: symbol-testnet-1.example
//!   storage:
//!     mode: light        # archive / full / light
//!   harvesters:
//!     - signer: /path/to/signer.key
//!       vrf: /path/to/vrf.key
//! ```
//!
//! `v1alpha1` のあいだは、Kubernetes の alpha の版と同じく、中身が変わってもよい。読むときは、知らない版を弾くだけ。
//!
//! 知らないキーは弾く（綴りの間違いが、黙って既定値にならないように）。秘密（鍵）は書かず、置き場所だけを書く。

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// 読める設定の版
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

/// ネットワークの種類
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NetworkType {
    Mainnet,
    Testnet,
    /// 決め打ちのパラメーターのないネットワーク（プライベートなネットワークなど）。`resources` の
    /// `config-network.properties` と `nemesisHash` で決める
    Custom,
}

/// どのネットワークに入るか（`spec.network`）
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    #[serde(rename = "type")]
    pub network_type: NetworkType,
    /// ノードの `resources` フォルダー（`config-network.properties` などのあるところ）
    pub resources: PathBuf,
    /// `type: custom` のときだけ。Nemesis のブロックのハッシュ（16進）
    #[serde(default)]
    pub nemesis_hash: Option<String>,
}

/// ノードの設定（`spec`）
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeConfig {
    pub network: Network,
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
    /// 何を残すか、どれだけメモリに持つか
    #[serde(default)]
    pub storage: Storage,
    /// ディスクの空きがこれより少なければ、書く前に止める（GB）
    #[serde(default = "default_min_free_gigabytes")]
    pub min_free_gigabytes: u64,
    /// 接続を受ける。なければ、自分からつなぐだけ
    #[serde(default)]
    pub listen: Option<Listen>,
    /// ハーベストする鍵の組。空ならしない
    #[serde(default)]
    pub harvesters: Vec<Harvester>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Certificates {
    /// `tls.crt`（ノードの証明書と CA の証明書の鎖）と `tls.key`（ノードの鍵）のあるフォルダー
    pub directory: PathBuf,
}

/// 何を残すか。種類ごとの残し方は [`Storage::retention`]
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    /// 全部の高さの状態、木のノード、ブロック、ステートメント、確定の証明を残す。昔の高さの状態とその証明を
    /// 問い合わせられる
    Archive,
    /// 状態と木のノードの差分は確定より 2 エポック下まで。ブロック、ステートメント、確定の証明は全部残す
    #[default]
    Full,
    /// `full` から、古いブロックとステートメントも消す（再開に要る分は残す）。要るものだけを読む
    Light,
}

/// 種類ごとの残し方。エポックの数で、`None` なら全部残す
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    pub state: Option<u32>,
    pub state_proofs: Option<u32>,
    /// ブロックとステートメント（いっしょに消す）。`Some` なら、状態の差分の境から再開に要る分を残して消す
    pub blocks_and_statements: bool,
}

/// `spec.storage`
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Storage {
    #[serde(default)]
    pub mode: Mode,
    /// アカウントの表を全部はメモリに持たず、要るものだけを読む。`light` では必ず真。書かなければ真
    #[serde(default)]
    pub partial_state: Option<bool>,
    #[serde(default)]
    pub cache: Cache,
}

/// `full` と `light` で、状態と木のノードの差分を残すエポックの数。枝を取り替えるときの巻き戻しに要る分
const PRUNED_EPOCHS: u32 = 2;

impl Storage {
    pub fn retention(&self) -> Retention {
        match self.mode {
            Mode::Archive => Retention {
                state: None,
                state_proofs: None,
                blocks_and_statements: false,
            },
            Mode::Full => Retention {
                state: Some(PRUNED_EPOCHS),
                state_proofs: Some(PRUNED_EPOCHS),
                blocks_and_statements: false,
            },
            Mode::Light => Retention {
                state: Some(PRUNED_EPOCHS),
                state_proofs: Some(PRUNED_EPOCHS),
                blocks_and_statements: true,
            },
        }
    }

    pub fn partial_state(&self) -> bool {
        self.partial_state.unwrap_or(true)
    }
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

/// ハーベストする鍵の組。鍵そのものは書かず、鍵のファイルの場所を書く。ファイルは他人に読めないこと
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Harvester {
    /// ブロックに署名する鍵（メインアカウントか、リンクしたリモートの鍵）のファイル
    pub signer: PathBuf,
    /// リンクした VRF の鍵のファイル
    pub vrf: PathBuf,
}

fn default_peers() -> usize {
    8
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
        let storage = &manifest.spec.storage;
        if storage.mode == Mode::Light && storage.partial_state == Some(false) {
            return Err(ConfigError(
                "storage.mode: light では、storage.partialState を false にできません".to_owned(),
            ));
        }
        let network = &manifest.spec.network;
        match (network.network_type, &network.nemesis_hash) {
            (NetworkType::Custom, None) => {
                return Err(ConfigError(
                    "network.type: custom には network.nemesisHash が要ります".to_owned(),
                ));
            }
            (NetworkType::Mainnet | NetworkType::Testnet, Some(_)) => {
                return Err(ConfigError(
                    "network.nemesisHash は network.type: custom のときだけ書きます".to_owned(),
                ));
            }
            _ => {}
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
  network:
    type: testnet
    resources: /resources
  dataDirectory: /data
  certificates:
    directory: /certificates
";

    #[test]
    fn reads_a_minimal_manifest_with_defaults() {
        let manifest = Manifest::parse(MINIMAL).unwrap();
        let spec = manifest.spec;
        assert_eq!(spec.network.network_type, NetworkType::Testnet);
        assert_eq!(spec.network.resources, PathBuf::from("/resources"));
        assert_eq!(spec.peers, 8);
        assert_eq!(spec.storage.mode, Mode::Full);
        assert!(spec.storage.partial_state());
        assert_eq!(spec.storage.cache, Cache::default());
        assert_eq!(spec.listen, None);
        assert!(spec.harvesters.is_empty());
        assert_eq!(manifest.metadata.name, "");
    }

    #[test]
    fn reads_listen_harvest_and_pruning() {
        let text = format!(
            "{MINIMAL}  listen:
    address: 0.0.0.0:7900
    publicHost: node.example
  harvesters:
    - signer: /signer
      vrf: /vrf
    - signer: /remote
      vrf: /vrf2
  storage:
    mode: light
  peers: 4
"
        );
        let spec = Manifest::parse(&text).unwrap().spec;
        let listen = spec.listen.unwrap();
        assert_eq!(listen.address, "0.0.0.0:7900");
        assert_eq!(listen.public_host.as_deref(), Some("node.example"));
        assert_eq!(listen.friendly_name, None);
        assert_eq!(spec.harvesters.len(), 2);
        assert_eq!(spec.harvesters[1].signer, PathBuf::from("/remote"));
        assert_eq!(spec.harvesters[1].vrf, PathBuf::from("/vrf2"));
        assert_eq!(
            spec.storage.retention(),
            Retention {
                state: Some(2),
                state_proofs: Some(2),
                blocks_and_statements: true
            }
        );
        assert_eq!(spec.peers, 4);
    }

    #[test]
    fn refuses_unknown_keys_versions_and_kinds() {
        // 綴りの間違い
        assert!(Manifest::parse(&format!("{MINIMAL}  peerz: 4\n")).is_err());
        assert!(Manifest::parse(&MINIMAL.replace("v1alpha1", "v1alpha2")).is_err());
        assert!(Manifest::parse(&MINIMAL.replace("kind: Peer", "kind: Node")).is_err());
        // custom には Nemesis のハッシュが要り、ほかのネットワークには書かない
        let custom = MINIMAL.replace("type: testnet", "type: custom");
        assert!(Manifest::parse(&custom).is_err());
        let with_hash = custom.replace(
            "resources: /resources",
            "resources: /resources\n    nemesisHash: AB",
        );
        assert!(Manifest::parse(&with_hash).is_ok());
        let testnet_with_hash = with_hash.replace("type: custom", "type: testnet");
        assert!(Manifest::parse(&testnet_with_hash).is_err());
        // light は要るものだけを読む形でしか動かない
        let light = format!("{MINIMAL}  storage:\n    mode: light\n    partialState: false\n");
        assert!(Manifest::parse(&light).is_err());
        let archive = format!("{MINIMAL}  storage:\n    mode: archive\n    partialState: false\n");
        let storage = Manifest::parse(&archive).unwrap().spec.storage;
        assert_eq!(storage.retention().state, None);
        assert!(!storage.partial_state());
    }
}
