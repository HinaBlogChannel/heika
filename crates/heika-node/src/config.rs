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

use heika_packet::NodeRoles;
use heika_store_redb::Searches;
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
    /// 設定ファイルと `nemesisHash` で決める
    Custom,
}

/// どのネットワークに入るか（`spec.network`）
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    #[serde(rename = "type")]
    pub network_type: NetworkType,
    /// ノードの `resources` フォルダー（`config-network.properties` などのあるところ）。`type: custom` では要る。
    /// メインネットとテストネットでは書かなくてよく、書けば決め打ちの設定の代わりにそこから読む
    /// （ネットワークの設定が変わって、heika がまだ追いついていないときなど）
    #[serde(default)]
    pub resources: Option<PathBuf>,
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
    /// 作るブロックの受取先のアドレス。なければ、ハーベストした鍵のアドレス
    #[serde(default)]
    pub beneficiary: Option<String>,
    /// ほかの人の委任ハーベストを引き受ける。なければ引き受けない
    #[serde(default)]
    pub delegations: Option<Delegations>,
    /// REST の口で待ち受ける。空なら立てない。手元用と公開用のように、いくつでも書ける
    #[serde(default)]
    pub rest: Vec<Rest>,
    /// ファイナライズの投票。なければ何もしない
    #[serde(default)]
    pub finalization: Option<Finalization>,
}

/// ファイナライズの投票の扱い
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finalization {
    /// 投票するピア（Voting のロール）から投票のメッセージを引いて数え、自分で確定を出して、届いた証明と比べる。
    /// 投票はしない
    #[serde(default)]
    pub observe: bool,
    /// 投票の鍵のフォルダー（catapult の `votingkeys`。`private_key_tree1.dat` から順に置く）。書くと投票する
    /// （`observe` も有効になる）
    #[serde(default)]
    pub voting_keys: Option<PathBuf>,
}

impl Finalization {
    /// 投票を数えるか
    pub fn counts(&self) -> bool {
        self.observe || self.voting_keys.is_some()
    }
}

impl NodeConfig {
    /// 名乗るロール。`listen.roles` がなければ、Peer に、REST の口があれば Api を、投票するなら Voting を足す。
    /// メインネットの catapult と同じく IPv4 は立てない（catapult は、IPv4 も IPv6 もなければ IPv4 とみなす。
    /// ノードの一覧を作るクローラーには、IPv4 の立ったロールを読めないものがある）
    pub fn roles(&self) -> NodeRoles {
        self.listen
            .as_ref()
            .and_then(|listen| listen.roles)
            .unwrap_or_else(|| {
                let api = if self.rest.is_empty() { 0 } else { 0x02 };
                let voting = self
                    .finalization
                    .as_ref()
                    .filter(|finalization| finalization.voting_keys.is_some())
                    .map_or(0, |_| NodeRoles::VOTING.0);
                NodeRoles(NodeRoles::PEER.0 | api | voting)
            })
    }
}

/// REST の口
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rest {
    /// 待ち受けるアドレス（`127.0.0.1:3000` など）
    pub address: String,
    /// この口で、1 秒あたりに答える要求の数。どの道への要求も数え、超えたら 429 で答える。0 なら絞らない
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_rate_limit() -> u32 {
    60
}

/// 委任ハーベストの引き受け方
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Delegations {
    /// 引き受ける数の上限。超えたら重要度の大きい順に選ぶ
    #[serde(default = "default_max_delegations")]
    pub max: usize,
    /// 委任の鍵のファイル。委任の要求はこの鍵のアドレスに届き、この鍵で復号する。委任する人は NodeKeyLink を
    /// この鍵に向ける。なければ TLS のノードの鍵（`certificates` の `tls.key`。catapult と同じ）
    #[serde(default)]
    pub key: Option<PathBuf>,
}

impl Default for Delegations {
    fn default() -> Self {
        Self {
            max: default_max_delegations(),
            key: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Certificates {
    /// `tls.crt`（ノードの証明書と CA の証明書の鎖）と `tls.key`（ノードの鍵）のあるフォルダー
    pub directory: PathBuf,
}

/// 何を残すか。種類ごとの残し方は [`Storage::retention`]。重い（たくさん残す）順に並べる
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

impl Mode {
    /// 設定ファイルに書く名前
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Full => "full",
            Self::Light => "light",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Self::Archive, Self::Full, Self::Light]
            .into_iter()
            .find(|mode| mode.as_str() == name)
    }
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
    /// REST の検索のために作る検索表。書かなければ作らない
    #[serde(default)]
    pub search: Vec<Search>,
}

/// `storage.search` に書ける検索
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Search {
    /// `/metadata` の検索（送り主、宛先、対象から）
    Metadata,
    /// `/namespaces` の検索（持ち主、別名から）と、名前（`/namespaces/names` など）
    Namespaces,
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

    /// 作る検索表。アーカイブは状態の差分を全部残すので、昔の高さでも検索できるようにする
    pub fn searches(&self) -> Searches {
        let searches = self
            .search
            .iter()
            .fold(Searches::NONE, |searches, search| match search {
                Search::Metadata => searches.union(Searches::METADATA),
                Search::Namespaces => searches.union(Searches::NAMESPACES),
            });
        if self.mode == Mode::Archive && searches != Searches::NONE {
            searches.union(Searches::PAST)
        } else {
            searches
        }
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
    /// 名乗るロール。P2P でも REST の `/node/info` でもこれを名乗る。`0x43` や `67` のような整数か、
    /// `[Peer, Api, IPv4]` のような catapult の名前の並びで書く。なければ [`NodeConfig::roles`] の既定
    #[serde(default, deserialize_with = "deserialize_roles")]
    pub roles: Option<NodeRoles>,
}

/// `listen.roles` を、整数か名前の並びから読む
fn deserialize_roles<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NodeRoles>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Roles {
        Bits(u32),
        Names(Vec<String>),
    }
    let roles = match Roles::deserialize(deserializer)? {
        Roles::Bits(bits) => NodeRoles(bits),
        Roles::Names(names) => names.iter().try_fold(NodeRoles(0), |roles, name| {
            NodeRoles::from_name(name)
                .map(|role| NodeRoles(roles.0 | role.0))
                .ok_or_else(|| {
                    serde::de::Error::custom(format!(
                        "listen.roles の {name} を知りません（Peer、Api、Voting、IPv4、IPv6 のどれか）"
                    ))
                })
        })?,
    };
    Ok(Some(roles))
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

/// catapult の `maxUnlockedAccounts` の既定と同じ
fn default_max_delegations() -> usize {
    5
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
        if !manifest.spec.roles().contains(NodeRoles::PEER) {
            return Err(ConfigError(
                "listen.roles から Peer は外せません".to_owned(),
            ));
        }
        let network = &manifest.spec.network;
        if network.network_type == NetworkType::Custom && network.resources.is_none() {
            return Err(ConfigError(
                "network.type: custom には network.resources が要ります".to_owned(),
            ));
        }
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
        assert_eq!(spec.network.resources, Some(PathBuf::from("/resources")));
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
    fn reads_whether_to_observe_finalization() {
        assert_eq!(Manifest::parse(MINIMAL).unwrap().spec.finalization, None);
        let spec = Manifest::parse(&format!("{MINIMAL}  finalization:\n    observe: true\n"))
            .unwrap()
            .spec;
        assert_eq!(
            spec.finalization,
            Some(Finalization {
                observe: true,
                voting_keys: None
            })
        );
        let voting = format!("{MINIMAL}  finalization:\n    votingKeys: /keys\n");
        let spec = Manifest::parse(&voting).unwrap().spec;
        let finalization = spec.finalization.as_ref().unwrap();
        assert!(finalization.counts());
        assert_eq!(finalization.voting_keys, Some(PathBuf::from("/keys")));
        assert_eq!(spec.roles().0, 0x05);
        assert!(Manifest::parse(&format!("{MINIMAL}  finalization:\n    vote: true\n")).is_err());
    }

    #[test]
    fn reads_roles_as_bits_or_names_and_defaults_by_rest() {
        let listen = format!("{MINIMAL}  listen:\n    address: 0.0.0.0:7900\n");
        let roles = |extra: &str| {
            Manifest::parse(&format!("{listen}{extra}"))
                .map(|manifest| manifest.spec.roles().0)
                .map_err(|error| error.to_string())
        };
        assert_eq!(roles(""), Ok(0x01));
        assert_eq!(roles("  rest:\n    - address: 127.0.0.1:3000\n"), Ok(0x03));
        assert_eq!(roles("    roles: 0x45\n"), Ok(0x45));
        assert_eq!(roles("    roles: 67\n"), Ok(0x43));
        assert_eq!(roles("    roles: [Peer, Voting, IPv4]\n"), Ok(0x45));
        // REST の口があっても、書いたものをそのまま名乗る
        assert_eq!(
            roles("    roles: [Peer, IPv4]\n  rest:\n    - address: 127.0.0.1:3000\n"),
            Ok(0x41)
        );
        assert!(
            roles("    roles: [Peer, Harvester]\n")
                .unwrap_err()
                .contains("Harvester")
        );
        assert!(
            roles("    roles: [Api, IPv4]\n")
                .unwrap_err()
                .contains("Peer")
        );
        assert!(roles("    roles: 0x42\n").is_err());
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
        // resources は custom にだけ要る。メインネットとテストネットは決め打ちの設定を使う
        let without_resources = MINIMAL.replace("    resources: /resources\n", "");
        assert_eq!(
            Manifest::parse(&without_resources)
                .unwrap()
                .spec
                .network
                .resources,
            None
        );
        let custom_without_resources = with_hash.replace("    resources: /resources\n", "");
        assert!(Manifest::parse(&custom_without_resources).is_err());
        // light は要るものだけを読む形でしか動かない
        let light = format!("{MINIMAL}  storage:\n    mode: light\n    partialState: false\n");
        assert!(Manifest::parse(&light).is_err());
        let archive = format!("{MINIMAL}  storage:\n    mode: archive\n    partialState: false\n");
        let storage = Manifest::parse(&archive).unwrap().spec.storage;
        assert_eq!(storage.retention().state, None);
        assert!(!storage.partial_state());
        assert_eq!(storage.searches(), Searches::NONE);
        // 検索表は名前で選ぶ。知らない名前は読めない
        let search = format!("{MINIMAL}  storage:\n    search: [metadata]\n");
        let storage = Manifest::parse(&search).unwrap().spec.storage;
        assert_eq!(storage.searches(), Searches::METADATA);
        assert!(Manifest::parse(&search.replace("metadata", "accounts")).is_err());
        let both = search.replace("[metadata]", "[metadata, namespaces]");
        let storage = Manifest::parse(&both).unwrap().spec.storage;
        assert_eq!(
            storage.searches(),
            Searches::METADATA.union(Searches::NAMESPACES)
        );
        let archive = search.replace("storage:\n", "storage:\n    mode: archive\n");
        let storage = Manifest::parse(&archive).unwrap().spec.storage;
        assert_eq!(storage.searches(), Searches::METADATA.union(Searches::PAST));
    }
}
