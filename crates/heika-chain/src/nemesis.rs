//! Nemesis のブロックを作る。catapult の `catapult.tools.nemgen` と同じ `nemesis.properties` を読み、同じ順に
//! トランザクションを並べて署名し、同じバイト列のブロックと、ノードが最初に読む `seed` フォルダーの中身を作る。
//!
//! トランザクションの並びは nemgen と同じ。ルートのネームスペースごとに、ルート、サブネームスペース（浅い順）。
//! モザイクごとに、定義（ノンスは 0 から）、エイリアス、発行量の増加。アドレスごとに、配るモザイクをまとめた送金。
//! 最後に、追加のトランザクション（VRF と投票の鍵の紐づけなど、ほかのアカウントが署名したもの）。
//! ブロックは Nemesis の鍵で署名し、VRF の証明も同じ鍵で generation hash seed に対して作る。
//!
//! nemgen と違うところ:
//! - 秘密鍵は `nemesis.properties` に書かず、呼ぶ側が渡す。書いてあれば弾く
//! - ルートのネームスペースが2つ以上あるときは、ファイルに書いた順に並べる。nemgen はハッシュ表の順なので、
//!   同じ入力でも違うブロック（どちらも正しい）になりうる。サブネームスペースも、同じ深さのものはファイルの順
//! - `[cpp]` と `[output]` は読み飛ばす。書き出す場所は呼ぶ側が決める
//! - 状態のハッシュとレシートは、いつも求める（`enableVerifiableState` と `enableVerifiableReceipts` が true の
//!   ネットワーク用）
//! - catapult のノードが起動するときに確かめること（ハーベストのモザイクを配った合計が `totalChainImportance`
//!   と同じかなど）を、作る前に確かめる

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use heika_block::Block;
use heika_block::statement::BlockStatement;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{GenerationHashSeed, NetworkIdentifier, NetworkParameters};
use heika_core::vrf::{self, GenerationHash};
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;
use heika_transaction::{
    AliasAction, Body, MosaicAlias, MosaicDefinition, MosaicFlags, MosaicId, MosaicSupplyChange,
    MosaicSupplyChangeAction, NamespaceId, NamespaceRegistration, NamespaceRegistrationType,
    Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId, is_valid_namespace_name,
};

/// Nemesis のヘッダーの長さ（importance ブロックと同じく足を含む）
const HEADER_SIZE: usize = 424;
/// 署名の範囲の始まり（バージョンから）。終わりはヘッダーの終わり
const SIGNED_FROM: usize = 108;
/// catapult の `Difficulty` の既定値。Nemesis の難易度
const NEMESIS_DIFFICULTY: u64 = 100_000_000_000_000;
/// Nemesis のトランザクションの期限。nemgen はすべて 1 にし、追加のトランザクションにも 1 を求める
const NEMESIS_DEADLINE: u64 = 1;

/// 作れなかったわけ
#[derive(Debug, PartialEq, Eq)]
pub struct NemesisError(pub String);

impl fmt::Display for NemesisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nemesis: {}", self.0)
    }
}

impl std::error::Error for NemesisError {}

fn error<T>(message: impl Into<String>) -> Result<T, NemesisError> {
    Err(NemesisError(message.into()))
}

/// `nemesis.properties` の中身。
#[derive(Clone, Debug)]
pub struct NemesisProperties {
    pub network: NetworkIdentifier,
    pub generation_hash_seed: GenerationHashSeed,
    /// 取るルートのネームスペース。ファイルの順
    roots: Vec<RootSeed>,
    /// 作るモザイク。ファイルの順で、ノンスはこの並びの何番目か
    mosaics: Vec<MosaicSeed>,
    /// 配る先と、配るモザイク（`mosaics` の何番目か）と量。アドレスが初めて出てきた順
    distribution: Vec<(Address, Vec<(usize, u64)>)>,
    /// 追加のトランザクションを置くフォルダー。空なら `None`
    pub transactions_directory: Option<String>,
}

#[derive(Clone, Debug)]
struct RootSeed {
    name: String,
    /// ブロック数。0 なら期限なし
    duration: u64,
    /// サブネームスペースのフルネーム。浅い順、同じ深さはファイルの順
    children: Vec<String>,
}

#[derive(Clone, Debug)]
struct MosaicSeed {
    /// `symbol:xym` の形。`:` を `.` にしたネームスペースを、このモザイクのエイリアスにする
    name: String,
    divisibility: u8,
    duration: u64,
    supply: u64,
    flags: MosaicFlags,
}

/// `[セクション]` と `キー = 値` を、ファイルの順に持つ。使ったキーを覚え、使わなかったキーを誤りにする
struct Entries {
    items: Vec<(String, String, String)>,
    used: HashSet<usize>,
}

impl Entries {
    fn parse(text: &str) -> Result<Self, NemesisError> {
        let mut items: Vec<(String, String, String)> = Vec::new();
        let mut section = String::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_owned();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return error(format!(
                    "{} 行目が `キー = 値` の形ではありません",
                    number + 1
                ));
            };
            let key = key.trim().to_owned();
            if items.iter().any(|(s, k, _)| *s == section && *k == key) {
                return error(format!("[{section}] {key} が2つあります"));
            }
            items.push((section.clone(), key, value.trim().to_owned()));
        }
        Ok(Self {
            items,
            used: HashSet::new(),
        })
    }

    /// あれば値を返し、使ったことにする
    fn find(&mut self, section: &str, key: &str) -> Option<String> {
        let index = self
            .items
            .iter()
            .position(|(s, k, _)| s == section && k == key)?;
        self.used.insert(index);
        Some(self.items[index].2.clone())
    }

    fn get(&mut self, section: &str, key: &str) -> Result<String, NemesisError> {
        match self.find(section, key) {
            Some(value) => Ok(value),
            None => error(format!("[{section}] {key} がありません")),
        }
    }

    /// セクションのキーと値を、ファイルの順にすべて。使ったことにする
    fn section(&mut self, section: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (index, (s, key, value)) in self.items.iter().enumerate() {
            if s == section {
                self.used.insert(index);
                out.push((key.clone(), value.clone()));
            }
        }
        out
    }

    fn number(&mut self, section: &str, key: &str) -> Result<u64, NemesisError> {
        let value = self.get(section, key)?;
        parse_number(&value)
            .ok_or_else(|| NemesisError(format!("[{section}] {key} が数ではありません: {value}")))
    }

    fn boolean(&mut self, section: &str, key: &str) -> Result<bool, NemesisError> {
        let value = self.get(section, key)?;
        parse_bool(&value).ok_or_else(|| {
            NemesisError(format!(
                "[{section}] {key} が true か false ではありません: {value}"
            ))
        })
    }

    /// 使わなかったキー。catapult の nemgen も、知らないキーがあれば止まる
    fn unused(&self) -> Option<(&str, &str)> {
        (0..self.items.len())
            .find(|index| !self.used.contains(index))
            .map(|index| (self.items[index].0.as_str(), self.items[index].1.as_str()))
    }
}

/// `'` は桁の区切り
fn parse_number(value: &str) -> Option<u64> {
    value.replace('\'', "").parse().ok()
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

impl NemesisProperties {
    /// `nemesis.properties` のテキストから読む。
    pub fn parse(text: &str) -> Result<Self, NemesisError> {
        let mut entries = Entries::parse(text)?;
        if entries.find("nemesis", "nemesisSignerPrivateKey").is_some() {
            return error(
                "[nemesis] nemesisSignerPrivateKey は書かないでください。秘密鍵は標準入力で渡します",
            );
        }
        let network = entries.get("nemesis", "networkIdentifier")?;
        let network = match network.as_str() {
            "mainnet" => NetworkIdentifier::MAINNET,
            "testnet" => NetworkIdentifier::TESTNET,
            other => NetworkIdentifier(other.parse().map_err(|_| {
                NemesisError(format!("[nemesis] networkIdentifier が読めません: {other}"))
            })?),
        };
        let generation_hash_seed = entries
            .get("nemesis", "nemesisGenerationHashSeed")?
            .parse()
            .map_err(|_| {
                NemesisError("[nemesis] nemesisGenerationHashSeed が読めません".to_owned())
            })?;
        // 書き出す場所は呼ぶ側が決めるので、読み飛ばす
        entries.section("cpp");
        entries.section("output");

        let roots = parse_namespaces(&mut entries)?;
        let names: HashSet<String> = roots
            .iter()
            .flat_map(|root| std::iter::once(root.name.clone()).chain(root.children.clone()))
            .collect();
        let (mosaics, distribution) = parse_mosaics(&mut entries, &names, network)?;

        let transactions_directory = entries.get("transactions", "transactionsDirectory")?;
        if let Some((section, key)) = entries.unused() {
            return error(format!("知らない設定です: [{section}] {key}"));
        }
        Ok(Self {
            network,
            generation_hash_seed,
            roots,
            mosaics,
            distribution,
            transactions_directory: (!transactions_directory.is_empty())
                .then_some(transactions_directory),
        })
    }
}

fn parse_namespaces(entries: &mut Entries) -> Result<Vec<RootSeed>, NemesisError> {
    let mut roots: Vec<RootSeed> = Vec::new();
    for (name, enabled) in entries.section("namespaces") {
        let enabled = parse_bool(&enabled).ok_or_else(|| {
            NemesisError(format!(
                "[namespaces] {name} が true か false ではありません"
            ))
        })?;
        if !name
            .split('.')
            .all(|part| is_valid_namespace_name(part.as_bytes()))
        {
            return error(format!("ネームスペースの名前が正しくありません: {name}"));
        }
        match name.rsplit_once('.') {
            None => {
                // nemgen は、使わないルートの期間も読む
                let duration = entries.number(&format!("namespace>{name}"), "duration")?;
                if !enabled {
                    continue;
                }
                if roots.iter().any(|root| root.name == name) {
                    return error(format!("ルートのネームスペース {name} が2つあります"));
                }
                roots.push(RootSeed {
                    name,
                    duration,
                    children: Vec::new(),
                });
            }
            Some((parent, _)) => {
                if !enabled {
                    continue;
                }
                let root_name = name.split('.').next().expect("split has a first part");
                let Some(root) = roots.iter_mut().find(|root| root.name == root_name) else {
                    return error(format!("{name} のルートのネームスペースがありません"));
                };
                if parent != root.name && !root.children.iter().any(|child| child == parent) {
                    return error(format!("{name} の親のネームスペースがありません"));
                }
                if root.children.contains(&name) {
                    return error(format!("ネームスペース {name} が2つあります"));
                }
                root.children.push(name);
            }
        }
    }
    // nemgen は、サブネームスペースを浅い順に取る（同じ深さはファイルの順のまま）
    for root in &mut roots {
        root.children.sort_by_key(|name| name.matches('.').count());
    }
    Ok(roots)
}

type Distribution = Vec<(Address, Vec<(usize, u64)>)>;

fn parse_mosaics(
    entries: &mut Entries,
    namespaces: &HashSet<String>,
    network: NetworkIdentifier,
) -> Result<(Vec<MosaicSeed>, Distribution), NemesisError> {
    let mut mosaics: Vec<MosaicSeed> = Vec::new();
    let mut distribution: Distribution = Vec::new();
    for (name, enabled) in entries.section("mosaics") {
        let enabled = parse_bool(&enabled).ok_or_else(|| {
            NemesisError(format!("[mosaics] {name} が true か false ではありません"))
        })?;
        // nemgen は、使わないモザイクの性質と配る先も読む
        let section = format!("mosaic>{name}");
        let divisibility = entries.number(&section, "divisibility")?;
        let duration = entries.number(&section, "duration")?;
        let supply = entries.number(&section, "supply")?;
        let mut flags = MosaicFlags::default();
        for (key, flag) in [
            ("isTransferable", MosaicFlags::TRANSFERABLE),
            ("isSupplyMutable", MosaicFlags::SUPPLY_MUTABLE),
            ("isRestrictable", MosaicFlags::RESTRICTABLE),
        ] {
            if entries.boolean(&section, key)? {
                flags = flags | flag;
            }
        }
        let seeds = entries.section(&format!("distribution>{name}"));
        if !enabled {
            continue;
        }
        let divisibility = u8::try_from(divisibility)
            .map_err(|_| NemesisError(format!("[{section}] divisibility が大きすぎます")))?;
        if mosaics.iter().any(|mosaic| mosaic.name == name) {
            return error(format!("モザイク {name} が2つあります"));
        }
        if !namespaces.contains(&name.replace(':', ".")) {
            return error(format!(
                "モザイク {name} のエイリアスにするネームスペースがありません"
            ));
        }
        let index = mosaics.len();
        mosaics.push(MosaicSeed {
            name: name.clone(),
            divisibility,
            duration,
            supply,
            flags,
        });
        for (address, amount) in seeds {
            let parsed: Address = address
                .parse()
                .ok()
                .filter(|parsed: &Address| parsed.network() == network)
                .ok_or_else(|| {
                    NemesisError(format!(
                        "[distribution>{name}] にこのネットワークのアドレスでないものがあります"
                    ))
                })?;
            let amount = parse_number(&amount).ok_or_else(|| {
                NemesisError(format!("[distribution>{name}] に数でない量があります"))
            })?;
            match distribution.iter_mut().find(|(seen, _)| *seen == parsed) {
                Some((_, seeds)) => seeds.push((index, amount)),
                None => distribution.push((parsed, vec![(index, amount)])),
            }
        }
    }
    Ok((mosaics, distribution))
}

/// 作った Nemesis。ブロックと、catapult が一緒にしまうもの
#[derive(Debug)]
pub struct Nemesis {
    pub block: Block,
    pub generation_hash: GenerationHash,
    /// 実行したときのステートメント。ブロックの ReceiptsHash は、これの Merkle の根
    pub statement: BlockStatement,
    /// 9本の状態の木の根。ブロックの StateHash は、これをつないだもののハッシュ
    pub sub_cache_roots: [Hash256; 9],
}

/// `properties` のとおりに、`config` のネットワークの Nemesis を `signer` の鍵で作る。`additional` は追加の
/// トランザクション（署名したもの）を、入れる順に。`config` と `parameters` は、そのネットワークの
/// `config-network.properties` などから読んだもの。
pub fn generate(
    properties: &NemesisProperties,
    config: ChainConfig,
    parameters: &NetworkParameters,
    signer: &PrivateKey,
    additional: &[Vec<u8>],
) -> Result<Nemesis, NemesisError> {
    let seed = &properties.generation_hash_seed;
    let network = properties.network;
    let signer_public_key = PublicKey::from_private_key(signer);
    if network != parameters.identifier {
        return error("networkIdentifier が config-network の identifier と違います");
    }
    if *seed != parameters.generation_hash_seed {
        return error(
            "nemesisGenerationHashSeed が config-network の generationHashSeed と違います",
        );
    }
    if signer_public_key != config.nemesis_signer_public_key {
        return error("秘密鍵が config-network の nemesisSignerPublicKey と合いません");
    }
    let owner = Address::from_public_key(&signer_public_key, network);
    let mosaic_ids: Vec<MosaicId> = (0..properties.mosaics.len())
        .map(|nonce| MosaicId::generate(&owner, nonce as u32))
        .collect();
    check_funding(properties, &config, &mosaic_ids)?;

    let mut transactions = Vec::new();
    let mut add = |body: Body| -> Result<(), NemesisError> {
        let mut transaction =
            Transaction::new(signer_public_key, network, 0, NEMESIS_DEADLINE, body);
        transaction
            .sign(signer, seed)
            .map_err(|error| NemesisError(error.to_string()))?;
        transactions.push(transaction.to_bytes());
        Ok(())
    };
    for root in &properties.roots {
        add(registration(
            &root.name,
            // 0 は期限なし（catapult の `Eternal_Artifact_Duration`）
            NamespaceRegistrationType::Root {
                duration: root.duration,
            },
        )?)?;
        for child in &root.children {
            let (parent, name) = child.rsplit_once('.').expect("child has a parent");
            let parent_id = namespace_id(parent)?;
            add(registration(
                name,
                NamespaceRegistrationType::Child { parent_id },
            )?)?;
        }
    }
    let mut aliases = Vec::new();
    for (nonce, mosaic) in properties.mosaics.iter().enumerate() {
        add(Body::MosaicDefinition(MosaicDefinition {
            id: mosaic_ids[nonce],
            duration: mosaic.duration,
            nonce: nonce as u32,
            flags: mosaic.flags,
            divisibility: mosaic.divisibility,
        }))?;
        let alias = namespace_id(&mosaic.name.replace(':', "."))?;
        add(Body::MosaicAlias(MosaicAlias {
            namespace_id: alias,
            mosaic_id: mosaic_ids[nonce],
            alias_action: AliasAction::Link,
        }))?;
        // 送金と発行量は、エイリアスのネームスペースで指す
        let unresolved = UnresolvedMosaicId(alias.0);
        add(Body::MosaicSupplyChange(MosaicSupplyChange {
            mosaic_id: unresolved,
            delta: mosaic.supply,
            action: MosaicSupplyChangeAction::Increase,
        }))?;
        aliases.push(unresolved);
    }
    for (address, seeds) in &properties.distribution {
        let mosaics: BTreeMap<UnresolvedMosaicId, u64> = seeds
            .iter()
            .map(|&(index, amount)| (aliases[index], amount))
            .collect();
        if mosaics.len() != seeds.len() {
            return error(format!("{address} に同じモザイクを2回配っています"));
        }
        let transfer = Transfer::new(UnresolvedAddress(address.0), mosaics, Vec::new())
            .map_err(|error| NemesisError(error.to_string()))?;
        add(Body::Transfer(transfer))?;
    }
    for (index, bytes) in additional.iter().enumerate() {
        check_additional(bytes, &signer_public_key, seed).map_err(|NemesisError(why)| {
            NemesisError(format!("追加の {} 件目: {why}", index + 1))
        })?;
        transactions.push(bytes.clone());
    }

    let proof = vrf::prove(signer, &seed.0)
        .ok_or_else(|| NemesisError("VRF の証明が作れません".to_owned()))?;
    let mut bytes = assemble(network, &signer_public_key, &owner, &proof, &transactions)?;
    let unsigned = decode(&bytes)?;
    let transactions_hash = unsigned
        .calculate_transactions_hash(seed)
        .map_err(|error| NemesisError(error.to_string()))?;
    bytes[248..280].copy_from_slice(&transactions_hash.0);

    let mut executor = Executor::new(config, network, *seed);
    let produced = executor
        .apply_produced(&decode(&bytes)?)
        .map_err(|error| NemesisError(format!("実行できません: {error}")))?;
    bytes[280..312].copy_from_slice(&produced.receipts_hash.0);
    bytes[312..344].copy_from_slice(&produced.state_hash.0);
    let (voting, harvesting, balance) = produced
        .footer
        .ok_or_else(|| NemesisError("足が求まりません".to_owned()))?;
    bytes[372..376].copy_from_slice(&voting.to_le_bytes());
    bytes[376..384].copy_from_slice(&harvesting.to_le_bytes());
    bytes[384..392].copy_from_slice(&balance.to_le_bytes());
    let signature = signer.sign(&[&bytes[SIGNED_FROM..HEADER_SIZE]]);
    bytes[8..72].copy_from_slice(&signature.0);
    let block = decode(&bytes)?;
    if !block.verify_signature() {
        return error("作ったブロックの署名が確かめられません");
    }
    Ok(Nemesis {
        generation_hash: vrf::proof_hash(&proof.gamma).generation_hash(),
        block,
        statement: produced.statement,
        sub_cache_roots: executor.roots(),
    })
}

fn namespace_id(full_name: &str) -> Result<NamespaceId, NemesisError> {
    NamespaceId::from_full_name(full_name).map_err(|error| NemesisError(error.to_string()))
}

fn registration(
    name: &str,
    registration_type: NamespaceRegistrationType,
) -> Result<Body, NemesisError> {
    let parent = match registration_type {
        NamespaceRegistrationType::Root { .. } => None,
        NamespaceRegistrationType::Child { parent_id } => Some(parent_id),
    };
    Ok(Body::NamespaceRegistration(NamespaceRegistration {
        registration_type,
        id: NamespaceId::generate(parent, name.as_bytes()),
        name: name
            .as_bytes()
            .to_vec()
            .try_into()
            .map_err(|_| NemesisError(format!("ネームスペースの名前が長すぎます: {name}")))?,
    }))
}

/// catapult のノードが Nemesis を読むときに確かめる、配った量の合計（`NemesisBlockLoader`）。
/// 追加のトランザクションでは送金できないので、配る先の並びだけで決まる
fn check_funding(
    properties: &NemesisProperties,
    config: &ChainConfig,
    mosaic_ids: &[MosaicId],
) -> Result<(), NemesisError> {
    let mut funded = vec![0u64; mosaic_ids.len()];
    for (_, seeds) in &properties.distribution {
        for &(index, amount) in seeds {
            funded[index] = funded[index]
                .checked_add(amount)
                .ok_or_else(|| NemesisError("配る量の合計が大きすぎます".to_owned()))?;
        }
    }
    let total_of = |id: u64, what: &str| -> Result<u64, NemesisError> {
        mosaic_ids
            .iter()
            .position(|mosaic| mosaic.0 == id)
            .map(|index| funded[index])
            .ok_or_else(|| {
                NemesisError(format!(
                    "config-network の {what}（{id:016X}）を、Nemesis で作っていません"
                ))
            })
    };
    total_of(config.currency_mosaic_id, "currencyMosaicId")?;
    let harvesting = total_of(config.harvesting_mosaic_id, "harvestingMosaicId")?;
    if harvesting != config.total_chain_importance {
        return error(format!(
            "ハーベストのモザイクを配った合計 {harvesting} が、totalChainImportance {} と違います",
            config.total_chain_importance
        ));
    }
    for (mosaic, total) in properties.mosaics.iter().zip(&funded) {
        if *total > config.max_mosaic_atomic_units {
            return error(format!(
                "{} を配った合計が maxMosaicAtomicUnits を超えます",
                mosaic.name
            ));
        }
    }
    Ok(())
}

/// nemgen が追加のトランザクションに求めること。期限は 1、手数料は 0、送金とボンデッドは入れられない、
/// Nemesis の鍵では署名しない。加えて、署名がこのネットワークのものかを確かめる（nemgen は確かめない）
fn check_additional(
    bytes: &[u8],
    nemesis: &PublicKey,
    seed: &GenerationHashSeed,
) -> Result<(), NemesisError> {
    let transaction = Transaction::from_bytes(bytes)
        .map_err(|error| NemesisError(format!("読めません: {error}")))?;
    if transaction.deadline != NEMESIS_DEADLINE {
        return error("期限が 1 ではありません");
    }
    if transaction.fee != 0 {
        return error("手数料が 0 ではありません");
    }
    let mut signers = vec![transaction.signer_public_key];
    match &transaction.body {
        Body::Transfer(_) => return error("送金は入れられません"),
        Body::AggregateBonded(_) => return error("ボンデッドのアグリゲートは入れられません"),
        Body::AggregateComplete(aggregate) => {
            for embedded in aggregate.transactions() {
                if matches!(embedded.body, Body::Transfer(_)) {
                    return error("アグリゲートの中の送金は入れられません");
                }
                signers.push(embedded.signer_public_key);
            }
            if !transaction.verify_cosignatures(seed) {
                return error("連署が確かめられません");
            }
        }
        _ => {}
    }
    if signers.contains(nemesis) {
        return error("Nemesis の鍵で署名したものは入れられません");
    }
    if !transaction.verify(seed) {
        return error("署名が確かめられません（generation hash seed が違うかもしれません）");
    }
    Ok(())
}

/// 署名と、実行して求めるもの（StateHash、ReceiptsHash、足）と、TransactionsHash のほかを書いたバイト列
fn assemble(
    network: NetworkIdentifier,
    signer: &PublicKey,
    owner: &Address,
    proof: &vrf::VrfProof,
    transactions: &[Vec<u8>],
) -> Result<Vec<u8>, NemesisError> {
    let mut bytes = vec![0u8; HEADER_SIZE];
    bytes[72..104].copy_from_slice(&signer.0);
    bytes[108] = 1;
    bytes[109] = network.0;
    bytes[110..112].copy_from_slice(&0x8043u16.to_le_bytes());
    bytes[112..120].copy_from_slice(&1u64.to_le_bytes());
    bytes[128..136].copy_from_slice(&NEMESIS_DIFFICULTY.to_le_bytes());
    bytes[136..168].copy_from_slice(&proof.gamma);
    bytes[168..184].copy_from_slice(&proof.verification_hash);
    bytes[184..216].copy_from_slice(&proof.scalar);
    // 受取先は署名した鍵のアドレス（catapult の `CreateBlock`）
    bytes[344..368].copy_from_slice(&owner.0);
    // トランザクションは 8 バイトの境目にそろえ、最後のものの後ろは埋めない
    for (index, transaction) in transactions.iter().enumerate() {
        bytes.extend_from_slice(transaction);
        if index + 1 < transactions.len() {
            bytes.resize(bytes.len().next_multiple_of(8), 0);
        }
    }
    let size = u32::try_from(bytes.len()).map_err(|_| NemesisError("大きすぎます".into()))?;
    bytes[0..4].copy_from_slice(&size.to_le_bytes());
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Block, NemesisError> {
    Block::from_bytes(bytes)
        .map_err(|error| NemesisError(format!("組んだブロックが読めません: {error}")))
}

/// `seed` フォルダーの中の、Nemesis のブロックを含むファイル
pub const SEED_BLOCK_FILE: &str = "00000/00001.dat";

/// `seed` の [`SEED_BLOCK_FILE`] の中身から、Nemesis のブロックを読む。ブロックのあとに続くハッシュなどは読まない
pub fn read_seed_block(element: &[u8]) -> Result<Block, NemesisError> {
    let size = element
        .get(..4)
        .map(|size| u32::from_le_bytes(size.try_into().expect("4 bytes")) as usize)
        .filter(|&size| size <= element.len())
        .ok_or_else(|| NemesisError(format!("{SEED_BLOCK_FILE} が短すぎます")))?;
    let block = Block::from_bytes(&element[..size]).map_err(|error| {
        NemesisError(format!("{SEED_BLOCK_FILE} のブロックが読めません: {error}"))
    })?;
    if block.height != 1 || block.block_type != heika_block::BlockType::Nemesis {
        return error(format!(
            "{SEED_BLOCK_FILE} のブロックが Nemesis ではありません"
        ));
    }
    Ok(block)
}

/// Nemesis を確定した、エポック 1 の証明。投票はなく、Nemesis のハッシュだけで決まる（大きさ、版、エポック 1、
/// ポイント 1、高さ 1、ハッシュ）。catapult の nemgen が seed に書くものと同じ
pub fn nemesis_proof(hash: &Hash256) -> Vec<u8> {
    let mut proof = Vec::with_capacity(56);
    proof.extend_from_slice(&56u32.to_le_bytes());
    proof.extend_from_slice(&1u32.to_le_bytes());
    proof.extend_from_slice(&1u32.to_le_bytes());
    proof.extend_from_slice(&1u32.to_le_bytes());
    proof.extend_from_slice(&1u64.to_le_bytes());
    proof.extend_from_slice(&hash.0);
    proof
}

impl Nemesis {
    /// catapult のノードの `seed` フォルダーに置くファイル（パスと中身）。`seedDirectory` に置けば、catapult の
    /// ノードはここから始める。ブロック、ステートメント、高さ 1 のハッシュ、Nemesis を確定した証明
    pub fn seed_files(&self, seed: &GenerationHashSeed) -> Vec<(&'static str, Vec<u8>)> {
        let hash = self.block.hash();
        let mut element = self.block.as_bytes().to_vec();
        element.extend_from_slice(&hash.0);
        element.extend_from_slice(&self.generation_hash.0);
        let transactions: Vec<Transaction> = self
            .block
            .transactions()
            .map(|bytes| Transaction::from_bytes(bytes).expect("built from these bytes"))
            .collect();
        element.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
        for transaction in &transactions {
            element.extend_from_slice(&transaction.hash(seed).0);
            element.extend_from_slice(&transaction.merkle_component_hash(seed).0);
        }
        element.extend_from_slice(&(self.sub_cache_roots.len() as u32).to_le_bytes());
        for root in &self.sub_cache_roots {
            element.extend_from_slice(&root.0);
        }

        // 高さ 0 の分は 0 で埋め、高さ 1 に Nemesis のハッシュ
        let mut hashes = vec![0u8; 32];
        hashes.extend_from_slice(&hash.0);

        // 確定した最後のラウンド（エポック 1、ポイント 1、高さ 1、ハッシュ）は、証明の版のあと
        let proof = nemesis_proof(&hash);
        let round = proof[8..].to_vec();

        vec![
            ("index.dat", 1u64.to_le_bytes().to_vec()),
            ("00000/hashes.dat", hashes),
            (SEED_BLOCK_FILE, element),
            ("00000/00001.stmt", self.statement.to_bytes()),
            ("proof.index.dat", round),
            ("00000/proof.heights.dat", vec![0; 16]),
            ("00000/00001.proof", proof),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heika_block::BlockType;
    use heika_transaction::{KeyLink, LinkAction};

    const SEED: GenerationHashSeed = GenerationHashSeed([7; 32]);
    /// ハーベストできる下限（テストネットは 10,000 XYM）を超える量
    const STAKE: u64 = 20_000_000_000;

    fn key(byte: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[byte; 32])
    }

    fn address(byte: u8) -> Address {
        Address::from_public_key(
            &PublicKey::from_private_key(&key(byte)),
            NetworkIdentifier::TESTNET,
        )
    }

    fn properties_text(extra: &str) -> String {
        format!(
            "[nemesis]\n\nnetworkIdentifier = testnet\nnemesisGenerationHashSeed = {}\n\n\
             [cpp]\n\ncppFileHeader =\n\n[output]\n\ncppFile =\nbinDirectory = seed\n\n\
             [namespaces]\n\nsymbol = true\nsymbol.xym = true\n\n[namespace>symbol]\n\nduration = 0\n\n\
             [mosaics]\n\nsymbol:xym = true\n\n[mosaic>symbol:xym]\n\ndivisibility = 6\nduration = 0\n\
             supply = 40'000'000'000\nisTransferable = true\nisSupplyMutable = false\nisRestrictable = false\n\n\
             [distribution>symbol:xym]\n\n{} = 20'000'000'000\n{} = 20'000'000'000\n{extra}\n\
             [transactions]\n\ntransactionsDirectory =\n",
            hex(&SEED.0),
            address(2),
            address(3),
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02X}")).collect()
    }

    /// Nemesis の鍵（1）で作るテストネットの設定。配る量の合計を totalChainImportance にする
    fn network() -> (ChainConfig, NetworkParameters) {
        let signer = PublicKey::from_private_key(&key(1));
        let currency = MosaicId::generate(
            &Address::from_public_key(&signer, NetworkIdentifier::TESTNET),
            0,
        );
        let mut config = ChainConfig::testnet();
        config.nemesis_signer_public_key = signer;
        config.currency_mosaic_id = currency.0;
        config.harvesting_mosaic_id = currency.0;
        config.total_chain_importance = 2 * STAKE;
        let mut parameters = NetworkParameters::TESTNET;
        parameters.generation_hash_seed = SEED;
        (config, parameters)
    }

    fn build(text: &str, additional: &[Vec<u8>]) -> Result<Nemesis, NemesisError> {
        let properties = NemesisProperties::parse(text)?;
        let (config, parameters) = network();
        generate(&properties, config, &parameters, &key(1), additional)
    }

    /// `signer` の鍵で署名した、VRF の鍵の紐づけ
    fn vrf_link(signer: u8, fee: u64) -> Vec<u8> {
        let mut transaction = Transaction::new(
            PublicKey::from_private_key(&key(signer)),
            NetworkIdentifier::TESTNET,
            fee,
            NEMESIS_DEADLINE,
            Body::VrfKeyLink(KeyLink {
                linked_public_key: PublicKey::from_private_key(&key(9)),
                link_action: LinkAction::Link,
            }),
        );
        transaction.sign(&key(signer), &SEED).unwrap();
        transaction.to_bytes()
    }

    #[test]
    fn builds_a_nemesis_that_replays_to_the_same_hashes() {
        let link = vrf_link(2, 0);
        let nemesis = build(&properties_text(""), std::slice::from_ref(&link)).unwrap();
        let block = &nemesis.block;
        assert_eq!(block.block_type, BlockType::Nemesis);
        assert!(block.verify_signature());
        assert_eq!(block.verify_transactions_hash(&SEED), Ok(true));
        assert_eq!(
            block.verify_generation_hash_proof(&block.signer_public_key, &SEED.0),
            Some(nemesis.generation_hash)
        );
        assert_eq!(block.beneficiary_address, address(1));
        assert_eq!(block.difficulty, NEMESIS_DIFFICULTY);
        let footer = block.importance_footer.as_ref().unwrap();
        assert_eq!(footer.harvesting_eligible_accounts_count, 2);
        assert_eq!(footer.voting_eligible_accounts_count, 0);
        assert!(block.verify_receipts_hash(&nemesis.statement));

        // 受け取った側として実行し直しても、同じ状態になる
        let (config, _) = network();
        let mut executor = Executor::new(config, NetworkIdentifier::TESTNET, SEED);
        executor.apply(block).unwrap();
        assert_eq!(executor.state_hash(), block.state_hash);
        assert_eq!(executor.roots(), nemesis.sub_cache_roots);

        // 署名は決定的なので、同じ入力からは同じブロックになる
        let again = build(&properties_text(""), &[link]).unwrap();
        assert_eq!(again.block.as_bytes(), block.as_bytes());
    }

    #[test]
    fn orders_transactions_like_nemgen() {
        let nemesis = build(&properties_text(""), &[vrf_link(3, 0)]).unwrap();
        let types: Vec<u16> = nemesis
            .block
            .transactions()
            .map(|bytes| {
                Transaction::from_bytes(bytes)
                    .unwrap()
                    .body
                    .transaction_type()
            })
            .collect();
        // ルート、サブ、モザイクの定義、エイリアス、発行量、送金 2 件、追加
        assert_eq!(
            types,
            [
                0x414E, 0x414E, 0x414D, 0x434E, 0x424D, 0x4154, 0x4154, 0x4243
            ]
        );
    }

    #[test]
    fn writes_the_seed_layout() {
        let nemesis = build(&properties_text(""), &[]).unwrap();
        let files = nemesis.seed_files(&SEED);
        let file = |name: &str| &files.iter().find(|(path, _)| *path == name).unwrap().1;
        let hash = nemesis.block.hash();
        assert_eq!(file("index.dat"), &1u64.to_le_bytes());
        assert_eq!(&file("00000/hashes.dat")[32..], &hash.0);
        let element = file(SEED_BLOCK_FILE);
        let size = nemesis.block.as_bytes().len();
        assert_eq!(&element[..size], nemesis.block.as_bytes());
        assert_eq!(&element[size..size + 32], &hash.0);
        // ブロック、2つのハッシュ、件数とトランザクションごとに2つのハッシュ、根の数と9本の根
        assert_eq!(element.len(), size + 64 + 4 + 7 * 64 + 4 + 9 * 32);
        assert_eq!(
            BlockStatement::from_bytes(file("00000/00001.stmt")).unwrap(),
            nemesis.statement
        );
        assert_eq!(&file("00000/00001.proof")[24..], &hash.0);
        assert_eq!(file("proof.index.dat"), &file("00000/00001.proof")[8..]);
        // ノードが手元で作るエポック 1 の証明も、seed のものと同じで、エポック 1 を閉じる
        assert_eq!(file("00000/00001.proof"), &nemesis_proof(&hash));
        let header = heika_block::finalization::proof::proof_header(&nemesis_proof(&hash)).unwrap();
        assert_eq!(
            (header.round.epoch, header.height, header.hash),
            (1, 1, hash)
        );
        assert!(heika_block::finalization::proof::closes_epoch(&header, 60));
        // 書いたものから、同じブロックが読める
        assert_eq!(read_seed_block(element).unwrap(), nemesis.block);
        assert!(read_seed_block(&element[..100]).is_err());
    }

    #[test]
    fn rejects_what_nemgen_or_the_node_would() {
        let fails = |text: &str, additional: &[Vec<u8>]| build(text, additional).unwrap_err().0;
        let text = properties_text("");
        // 秘密鍵は properties に書かない
        let with_key = text.replace(
            "[cpp]",
            &format!(
                "nemesisSignerPrivateKey = {}\n\n[cpp]",
                hex(key(1).as_bytes())
            ),
        );
        assert!(fails(&with_key, &[]).contains("nemesisSignerPrivateKey"));
        // 知らないキー
        assert!(fails(&format!("{text}typo = 1\n"), &[]).contains("知らない設定"));
        // ハーベストのモザイクを配った合計が totalChainImportance と違う
        let more = properties_text(&format!("{} = 1\n", address(4)));
        assert!(fails(&more, &[]).contains("totalChainImportance"));
        // 親のないサブネームスペース
        let orphan = text.replace("symbol.xym = true", "symbol.xym = true\nother.child = true");
        assert!(fails(&orphan, &[]).contains("ルート"));
        // 追加のトランザクションの手数料は 0、Nemesis の鍵では署名しない
        assert!(fails(&text, &[vrf_link(2, 1)]).contains("手数料"));
        assert!(fails(&text, &[vrf_link(1, 0)]).contains("Nemesis の鍵"));
    }

    #[test]
    fn skips_disabled_entries_but_keeps_reading_them() {
        // 使わないモザイクも性質を書く。使わないものはノンスを数えない（nemgen の作るブロックと同じ）
        let text = properties_text("").replace(
            "[mosaics]\n\nsymbol:xym = true\n",
            "[mosaics]\n\nsymbol:old = false\nsymbol:xym = true\n\n[mosaic>symbol:old]\n\n\
             divisibility = 0\nduration = 0\nsupply = 1\nisTransferable = true\n\
             isSupplyMutable = false\nisRestrictable = false\n",
        );
        let nemesis = build(&text, &[]).unwrap();
        assert_eq!(nemesis.block.transactions().count(), 7);
        // 使わないモザイクの性質がなければ弾く
        let missing = properties_text("").replace(
            "[mosaics]\n\nsymbol:xym = true\n",
            "[mosaics]\n\nsymbol:old = false\nsymbol:xym = true\n",
        );
        assert!(
            build(&missing, &[])
                .unwrap_err()
                .0
                .contains("mosaic>symbol:old")
        );
    }
}
