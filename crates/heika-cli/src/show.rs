//! トランザクションの中身を、署名する前に人が確かめられる形にする。
//!
//! いったん項目の並び（[`Description`]）にしてから文字にする。文字にする以外の出し方を足すときも、並びは同じものを使う。
//! チェーンを見ないとわからないこと（ネームスペースが指す先、通貨以外のモザイクの可分性）は推し量らず、書いてあるとおりに出す。

use std::fmt::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::{NetworkIdentifier, NetworkParameters, NetworkTimestamp};
use heika_core::signature::Signature;
use heika_transaction::{
    AccountRestriction, AccountRestrictionFlags, AggregateVersion, AliasAction, Body, Failure,
    LinkAction, Location, LockHashAlgorithm, Metadata, MosaicFlags, MosaicId,
    MosaicRestrictionType, MosaicSupplyChangeAction, NamespaceId, NamespaceRegistrationType,
    Transaction, TransactionsHashCalculation, UnresolvedAddress, UnresolvedMosaic,
    UnresolvedMosaicId,
};
use heika_wallet::harvest_request;

use crate::json;

/// 通貨のモザイクに付いているネームスペース `symbol.xym`
const CURRENCY_NAMESPACE: NamespaceId = NamespaceId(0xE74B_99BA_41F4_AFEE);
/// 通貨のモザイクの可分性
const CURRENCY_DIVISIBILITY: u32 = 6;

/// 表示する1項目。同じ名前の項目が並ぶこともある（モザイクや連署など）。
#[derive(Debug, PartialEq, Eq)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
}

/// トランザクション1件の表示。アグリゲートなら、中のトランザクションも1件ずつ持つ。
#[derive(Debug, PartialEq, Eq)]
pub struct Description {
    pub title: String,
    pub fields: Vec<Field>,
    pub embedded: Vec<Description>,
}

impl Description {
    fn new(title: String) -> Self {
        Self {
            title,
            fields: Vec::new(),
            embedded: Vec::new(),
        }
    }

    fn push(&mut self, label: &'static str, value: impl Into<String>) {
        self.fields.push(Field {
            label,
            value: value.into(),
        });
    }

    /// 字下げして文字にする。中のトランザクションは、さらに字下げする。
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out, 0);
        out
    }

    /// JSON にする。項目の名前と値は、表示と同じ文字列のまま入れる
    pub fn to_json(&self) -> json::Value {
        json::Value::Object(vec![
            ("title", self.title.as_str().into()),
            (
                "fields",
                json::Value::Array(
                    self.fields
                        .iter()
                        .map(|field| {
                            json::Value::Object(vec![
                                ("label", field.label.into()),
                                ("value", field.value.as_str().into()),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "embedded",
                json::Value::Array(self.embedded.iter().map(Description::to_json).collect()),
            ),
        ])
    }

    fn render_into(&self, out: &mut String, depth: usize) {
        let indent = "  ".repeat(depth);
        writeln!(out, "{indent}{}", self.title).unwrap();
        for field in &self.fields {
            writeln!(out, "{indent}  {}: {}", field.label, field.value).unwrap();
        }
        for embedded in &self.embedded {
            embedded.render_into(out, depth + 1);
        }
    }
}

/// トランザクションを表示の並びにする。`now` は期限までの残りを出すのに使う。
pub fn describe(transaction: &Transaction, now: SystemTime) -> Description {
    let context = Context::new(transaction.network);
    let body = &transaction.body;
    let mut description = Description::new(title(body));
    description.push("ネットワーク", context.network_name());
    description.push("署名者", context.signer(&transaction.signer_public_key));
    description.push("手数料", context.currency(transaction.fee));
    description.push("期限", context.deadline(transaction.deadline, now));
    match context.network {
        Some(network) => {
            let seed = network.generation_hash_seed;
            if transaction.signature == Signature([0; 64]) {
                description.push("署名", "まだない");
            } else {
                description.push(
                    "署名",
                    if transaction.verify(&seed) {
                        "あり（正しい）"
                    } else {
                        "あり（正しくない）"
                    },
                );
                description.push("ハッシュ", transaction.hash(&seed).to_string());
            }
        }
        None => description.push("署名", "ネットワークがわからないので確かめられない"),
    }
    describe_body(
        body,
        &transaction.signer_public_key,
        &context,
        &mut description,
    );

    if let Body::AggregateComplete(aggregate) | Body::AggregateBonded(aggregate) = body {
        let hash = context
            .network
            .map(|network| transaction.hash(&network.generation_hash_seed));
        match aggregate.version() {
            AggregateVersion::V3 => {}
            version => description.push(
                "形式",
                format!(
                    "バージョン {} は古く、チェーンにあるものを読むためだけのもの（今は送れない）",
                    version.number()
                ),
            ),
        }
        if let AggregateVersion::V1 { .. } = aggregate.version() {
            description.push(
                "中のトランザクションのハッシュ",
                match aggregate.transactions_hash_calculation() {
                    TransactionsHashCalculation::Correct => "正しい求め方",
                    TransactionsHashCalculation::Legacy => {
                        "バージョン 1 で許されていた誤った求め方"
                    }
                    TransactionsHashCalculation::Unknown
                        if context.network.zip(hash).is_some_and(|(network, hash)| {
                            network.is_known_corrupt_aggregate(
                                &hash,
                                &aggregate.transactions_hash(),
                            )
                        }) =>
                    {
                        "どの求め方とも合わないが、ネットワークの設定で1件ずつ認められたもの（下の中身が署名されたものとは限らない）"
                    }
                    TransactionsHashCalculation::Unknown => {
                        "どの求め方とも合わない（下の中身が署名されたものとは限らない）"
                    }
                },
            );
        }
        for cosignature in aggregate.cosignatures() {
            let verified = match hash {
                Some(hash) if cosignature.verify(&hash) => "正しい",
                Some(_) => "正しくない",
                None => "確かめられない",
            };
            description.push(
                "連署",
                format!(
                    "{}（{verified}）",
                    context.signer(&cosignature.signer_public_key)
                ),
            );
        }
        let count = aggregate.transactions().len();
        for (index, embedded) in aggregate.transactions().iter().enumerate() {
            let mut inner = Description::new(format!(
                "中のトランザクション {}/{count}: {}",
                index + 1,
                title(&embedded.body)
            ));
            if embedded.network != transaction.network {
                inner.push(
                    "ネットワーク",
                    format!(
                        "{}（外側と違う）",
                        Context::new(embedded.network).network_name()
                    ),
                );
            }
            inner.push("署名者", context.signer(&embedded.signer_public_key));
            describe_body(
                &embedded.body,
                &embedded.signer_public_key,
                &context,
                &mut inner,
            );
            description.embedded.push(inner);
        }
    }
    // ネットワークがわかれば、ノードが状態を見ずに弾くところを、見つかった場所に添える
    if let Some(network) = context.network {
        for problem in transaction.validate(network) {
            let target = match problem.location {
                Location::Transaction => &mut description,
                Location::Embedded(index) => &mut description.embedded[index],
            };
            target.push("ノードで弾かれる", describe_failure(&problem.failure));
        }
    }
    description
}

/// 弾かれる理由。REST のステータスと見比べられるように、catapult の結果の名前を添える。
pub fn describe_failure(failure: &Failure) -> String {
    match failure.result() {
        Some((name, _)) => format!("{failure}（{name}）"),
        None => failure.to_string(),
    }
}

fn describe_body(
    body: &Body,
    signer: &PublicKey,
    context: &Context,
    description: &mut Description,
) {
    match body {
        Body::AccountKeyLink(link) | Body::NodeKeyLink(link) | Body::VrfKeyLink(link) => {
            description.push("操作", link_action(link.link_action));
            description.push("公開鍵", link.linked_public_key.to_string());
        }
        Body::VotingKeyLink(link) => {
            description.push("操作", link_action(link.link_action));
            description.push("公開鍵", link.linked_public_key.to_string());
            description.push(
                "エポック",
                format!("{} から {} まで", link.start_epoch, link.end_epoch),
            );
        }
        Body::HashLock(lock) => {
            description.push("モザイク", context.mosaic(&lock.mosaic));
            description.push("期間", context.blocks(lock.duration));
            description.push("ロックするアグリゲートのハッシュ", lock.hash.to_string());
        }
        Body::SecretLock(lock) => {
            description.push("受取人", context.address(&lock.recipient_address));
            description.push("モザイク", context.mosaic(&lock.mosaic));
            description.push("期間", context.blocks(lock.duration));
            description.push("シークレット", lock.secret.to_string());
            description.push("ハッシュの種類", hash_algorithm(lock.hash_algorithm));
        }
        Body::SecretProof(proof) => {
            description.push("受取人", context.address(&proof.recipient_address));
            description.push("シークレット", proof.secret.to_string());
            description.push("ハッシュの種類", hash_algorithm(proof.hash_algorithm));
            description.push("プルーフ", hex(&proof.proof));
        }
        Body::AccountMetadata(metadata) => describe_metadata(metadata, context, description),
        Body::MosaicMetadata(metadata) => {
            description.push(
                "対象のモザイク",
                context.mosaic_id(metadata.target_mosaic_id),
            );
            describe_metadata(&metadata.metadata, context, description);
        }
        Body::NamespaceMetadata(metadata) => {
            description.push(
                "対象のネームスペース",
                namespace_id(metadata.target_namespace_id),
            );
            describe_metadata(&metadata.metadata, context, description);
        }
        Body::MosaicDefinition(definition) => {
            let generated = context
                .identifier
                .map(|identifier| Address::from_public_key(signer, identifier))
                .map(|owner| MosaicId::generate(&owner, definition.nonce));
            let mismatch = match generated {
                Some(generated) if generated != definition.id => {
                    "（署名者とノンスから求めた ID と合わない）"
                }
                _ => "",
            };
            description.push("ID", format!("{}{mismatch}", mosaic_id(definition.id)));
            description.push("ノンス", definition.nonce.to_string());
            description.push(
                "期間",
                if definition.duration == 0 {
                    "期限なし".to_owned()
                } else {
                    context.blocks(definition.duration)
                },
            );
            description.push("性質", mosaic_flags(definition.flags));
            description.push(
                "可分性",
                format!("小数点以下 {} 桁", definition.divisibility),
            );
        }
        Body::MosaicSupplyChange(change) => {
            description.push("モザイク", context.mosaic_id(change.mosaic_id));
            description.push(
                "操作",
                match change.action {
                    MosaicSupplyChangeAction::Increase => "増やす",
                    MosaicSupplyChangeAction::Decrease => "減らす",
                },
            );
            description.push("量", format!("{}（最小単位）", change.delta));
        }
        Body::MosaicSupplyRevocation(revocation) => {
            description.push("回収する相手", context.address(&revocation.source_address));
            description.push("モザイク", context.mosaic(&revocation.mosaic));
        }
        Body::MultisigAccountModification(modification) => {
            description.push(
                "連署者を外すのに要る連署の数",
                signed_delta(modification.min_removal_delta.into()),
            );
            description.push(
                "それ以外に要る連署の数",
                signed_delta(modification.min_approval_delta.into()),
            );
            for address in modification.address_additions.iter() {
                description.push("足す連署者", context.address(address));
            }
            for address in modification.address_deletions.iter() {
                description.push("外す連署者", context.address(address));
            }
        }
        Body::AddressAlias(alias) => {
            description.push("操作", alias_action(alias.alias_action));
            description.push("ネームスペース", namespace_id(alias.namespace_id));
            description.push(
                "アドレス",
                context.address(&UnresolvedAddress(alias.address.0)),
            );
        }
        Body::MosaicAlias(alias) => {
            description.push("操作", alias_action(alias.alias_action));
            description.push("ネームスペース", namespace_id(alias.namespace_id));
            description.push(
                "モザイク",
                context.mosaic_id(UnresolvedMosaicId(alias.mosaic_id.0)),
            );
        }
        Body::NamespaceRegistration(registration) => {
            let parent_id = match registration.registration_type {
                NamespaceRegistrationType::Root { duration } => {
                    description.push("種類", "ルート");
                    description.push("期間", context.blocks(duration));
                    None
                }
                NamespaceRegistrationType::Child { parent_id } => {
                    description.push("種類", "サブネームスペース");
                    description.push("親", namespace_id(parent_id));
                    Some(parent_id)
                }
            };
            description.push("名前", text(&registration.name));
            let mismatch =
                if NamespaceId::generate(parent_id, &registration.name) != registration.id {
                    "（名前と親から求めた ID と合わない）"
                } else {
                    ""
                };
            description.push("ID", format!("{}{mismatch}", namespace_id(registration.id)));
        }
        Body::AccountAddressRestriction(restriction) => {
            describe_restriction(restriction, |address| context.address(address), description)
        }
        Body::AccountMosaicRestriction(restriction) => {
            describe_restriction(restriction, |id| context.mosaic_id(*id), description)
        }
        Body::AccountOperationRestriction(restriction) => describe_restriction(
            restriction,
            |transaction_type| type_name(transaction_type.0).to_owned(),
            description,
        ),
        Body::MosaicAddressRestriction(restriction) => {
            description.push("モザイク", context.mosaic_id(restriction.mosaic_id));
            description.push("キー", format!("0x{:016X}", restriction.restriction_key));
            description.push("アドレス", context.address(&restriction.target_address));
            description.push(
                "値",
                format!(
                    "{} から {} に",
                    restriction.previous_restriction_value, restriction.new_restriction_value
                ),
            );
        }
        Body::MosaicGlobalRestriction(restriction) => {
            description.push("モザイク", context.mosaic_id(restriction.mosaic_id));
            if restriction.reference_mosaic_id.0 != 0 {
                description.push(
                    "条件を借りるモザイク",
                    context.mosaic_id(restriction.reference_mosaic_id),
                );
            }
            description.push("キー", format!("0x{:016X}", restriction.restriction_key));
            description.push(
                "条件",
                format!(
                    "{} {} から {} {} に",
                    restriction_type(restriction.previous_restriction_type),
                    restriction.previous_restriction_value,
                    restriction_type(restriction.new_restriction_type),
                    restriction.new_restriction_value
                ),
            );
        }
        Body::Transfer(transfer) => {
            description.push("受取人", context.address(transfer.recipient_address()));
            if transfer.mosaics().is_empty() {
                description.push("モザイク", "なし");
            }
            for (&mosaic_id, &amount) in transfer.mosaics() {
                description.push(
                    "モザイク",
                    context.mosaic(&UnresolvedMosaic { mosaic_id, amount }),
                );
            }
            description.push("メッセージ", message(transfer.message()));
        }
        // 中のトランザクションと連署は、呼び出し元で並べる
        Body::AggregateComplete(_) | Body::AggregateBonded(_) => {}
    }
}

fn describe_metadata(metadata: &Metadata, context: &Context, description: &mut Description) {
    description.push("持ち主", context.address(&metadata.target_address));
    description.push("キー", format!("0x{:016X}", metadata.scoped_metadata_key));
    description.push("長さの増減", signed_delta(metadata.value_size_delta.into()));
    description.push("値（前の値との XOR）", text(&metadata.value));
}

fn describe_restriction<T>(
    restriction: &AccountRestriction<T>,
    value: impl Fn(&T) -> String,
    description: &mut Description,
) {
    let flags = restriction.restriction_flags;
    description.push(
        "向き",
        if flags.contains(AccountRestrictionFlags::OUTGOING) {
            "送る側"
        } else {
            "受け取る側"
        },
    );
    description.push(
        "方針",
        if flags.contains(AccountRestrictionFlags::BLOCK) {
            "並べたものを拒む"
        } else {
            "並べたものだけを許す"
        },
    );
    for added in restriction.restriction_additions.iter() {
        description.push("足す", value(added));
    }
    for deleted in restriction.restriction_deletions.iter() {
        description.push("外す", value(deleted));
    }
}

/// トランザクションのネットワーク。メインネットとテストネットのときだけ、ハッシュや期限の日時が出せる。
struct Context {
    identifier: Option<NetworkIdentifier>,
    raw: NetworkIdentifier,
    network: Option<&'static NetworkParameters>,
}

impl Context {
    fn new(identifier: NetworkIdentifier) -> Self {
        let network = NetworkParameters::from_identifier(identifier);
        Self {
            identifier: network.map(|_| identifier),
            raw: identifier,
            network,
        }
    }

    fn network_name(&self) -> String {
        match self.identifier {
            Some(NetworkIdentifier::MAINNET) => "メインネット".to_owned(),
            Some(NetworkIdentifier::TESTNET) => "テストネット".to_owned(),
            _ => format!("不明（0x{:02X}）", self.raw.0),
        }
    }

    /// 公開鍵と、このネットワークでのアドレス
    fn signer(&self, public_key: &PublicKey) -> String {
        format!(
            "{}（公開鍵 {public_key}）",
            Address::from_public_key(public_key, self.raw)
        )
    }

    /// アドレスかネームスペース。アドレスなら、このネットワークのものか、チェックサムが合うかも確かめる
    fn address(&self, address: &UnresolvedAddress) -> String {
        let Some(address) = address.address() else {
            let id = address.namespace_id().expect("not an address");
            return format!("ネームスペース {}", namespace_id(id));
        };
        let warning = if address.network() != self.raw {
            "（別のネットワークのアドレス）"
        } else if !address.has_valid_checksum() {
            "（チェックサムが合わない）"
        } else {
            ""
        };
        format!("{address}{warning}")
    }

    fn currency_mosaic_id(&self) -> Option<UnresolvedMosaicId> {
        Some(UnresolvedMosaicId(self.network?.currency_mosaic_id))
    }

    /// ブロック数と、ブロックの目標間隔から見積もった時間。知らないネットワークなら、ブロック数だけ
    fn blocks(&self, count: u64) -> String {
        let Some(network) = self.network else {
            return format!("{count} ブロック");
        };
        let duration = network
            .block_generation_target_time
            .saturating_mul(count.min(u32::MAX.into()) as u32);
        format!("{count} ブロック（約 {}）", approximate(duration))
    }

    fn is_currency(&self, id: UnresolvedMosaicId) -> bool {
        id.0 == CURRENCY_NAMESPACE.0 || Some(id) == self.currency_mosaic_id()
    }

    /// まだ解決していないモザイクの ID。最上位ビットが立っていればネームスペース
    fn mosaic_id(&self, id: UnresolvedMosaicId) -> String {
        let name = match id.mosaic_id() {
            Some(mosaic) => mosaic_id(mosaic),
            None => format!(
                "ネームスペース {}",
                namespace_id(id.namespace_id().expect("not a mosaic"))
            ),
        };
        if self.is_currency(id) && id.mosaic_id().is_some() {
            format!("{name}（XYM）")
        } else {
            name
        }
    }

    /// モザイクと量。通貨なら XYM に直し、それ以外は可分性がわからないので最小単位のまま出す
    fn mosaic(&self, mosaic: &UnresolvedMosaic) -> String {
        if self.is_currency(mosaic.mosaic_id) {
            format!(
                "{}（{}）",
                xym(mosaic.amount),
                self.mosaic_id(mosaic.mosaic_id)
            )
        } else {
            format!(
                "{}（最小単位）: {}",
                mosaic.amount,
                self.mosaic_id(mosaic.mosaic_id)
            )
        }
    }

    fn currency(&self, amount: u64) -> String {
        format!("{}（{amount}）", xym(amount))
    }

    /// 期限。ネットワークのエポックからのミリ秒を UTC の日時に直し、今からの残りを添える
    fn deadline(&self, milliseconds: u64, now: SystemTime) -> String {
        let Some(network) = self.network else {
            return format!("エポックから {milliseconds} ミリ秒");
        };
        let Some(deadline) = network.time_of(NetworkTimestamp(milliseconds)) else {
            return format!("エポックから {milliseconds} ミリ秒");
        };
        let remaining = match deadline.duration_since(now) {
            Ok(remaining) => format!("あと {}", approximate(remaining)),
            Err(_) => "期限切れ".to_owned(),
        };
        format!("{}（{remaining}）", utc(deadline))
    }
}

/// 通貨の量。最小単位の量を、可分性の桁で区切る
fn xym(amount: u64) -> String {
    let unit = 10_u64.pow(CURRENCY_DIVISIBILITY);
    format!(
        "{}.{:0width$} XYM",
        amount / unit,
        amount % unit,
        width = CURRENCY_DIVISIBILITY as usize
    )
}

fn mosaic_id(id: MosaicId) -> String {
    format!("0x{:016X}", id.0)
}

fn namespace_id(id: NamespaceId) -> String {
    if id == CURRENCY_NAMESPACE {
        format!("0x{:016X}（symbol.xym）", id.0)
    } else {
        format!("0x{:016X}", id.0)
    }
}

/// いちばん大きい単位で、だいたいの時間を出す
pub(crate) fn approximate(duration: Duration) -> String {
    let minutes = duration.as_secs() / 60;
    match minutes {
        0 => format!("{} 秒", duration.as_secs()),
        1..60 => format!("{minutes} 分"),
        60..1440 => format!("{} 時間 {} 分", minutes / 60, minutes % 60),
        _ => format!("{} 日", minutes / 1440),
    }
}

/// UTC の日時。Howard Hinnant の `civil_from_days` で、1970-01-01 からの日数を年月日にする
fn utc(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = (seconds / 86_400) as i64;
    let second_of_day = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        second_of_day / 3600,
        second_of_day / 60 % 60,
        second_of_day % 60
    )
}

fn signed_delta(delta: i32) -> String {
    format!("{delta:+}")
}

fn link_action(action: LinkAction) -> &'static str {
    match action {
        LinkAction::Link => "紐づける",
        LinkAction::Unlink => "外す",
    }
}

fn alias_action(action: AliasAction) -> &'static str {
    match action {
        AliasAction::Link => "紐づける",
        AliasAction::Unlink => "外す",
    }
}

fn hash_algorithm(algorithm: LockHashAlgorithm) -> &'static str {
    match algorithm {
        LockHashAlgorithm::Sha3_256 => "SHA3-256",
        LockHashAlgorithm::Hash160 => "RIPEMD-160(SHA-256)",
        LockHashAlgorithm::Hash256 => "SHA-256(SHA-256)",
    }
}

fn restriction_type(restriction_type: MosaicRestrictionType) -> &'static str {
    match restriction_type {
        MosaicRestrictionType::None => "なし",
        MosaicRestrictionType::Eq => "=",
        MosaicRestrictionType::Ne => "≠",
        MosaicRestrictionType::Lt => "<",
        MosaicRestrictionType::Le => "≤",
        MosaicRestrictionType::Gt => ">",
        MosaicRestrictionType::Ge => "≥",
    }
}

fn mosaic_flags(flags: MosaicFlags) -> String {
    let names: Vec<_> = [
        (MosaicFlags::SUPPLY_MUTABLE, "発行量を変えられる"),
        (MosaicFlags::TRANSFERABLE, "ほかの人どうしで送れる"),
        (MosaicFlags::RESTRICTABLE, "制限をかけられる"),
        (MosaicFlags::REVOKABLE, "作った人が回収できる"),
    ]
    .into_iter()
    .filter(|(flag, _)| flags.contains(*flag))
    .map(|(_, name)| name)
    .collect();
    if names.is_empty() {
        "なし".to_owned()
    } else {
        names.join("、")
    }
}

/// Transfer のメッセージ。先頭の1バイトで種類を見分ける
fn message(message: &[u8]) -> String {
    if message.is_empty() {
        return "なし".to_owned();
    }
    if harvest_request::is_harvest_request(message) {
        return "委任ハーベストの要求（リモートと VRF の秘密鍵を、ノードの鍵で暗号化したもの）"
            .to_owned();
    }
    match message[0] {
        0x00 => format!("平文 {}", text(&message[1..])),
        0x01 => format!("暗号化されたメッセージ（16進: {}）", hex(&message[1..])),
        // 種類の印を付けずに、文字列をそのまま入れるウォレットもある
        _ => match std::str::from_utf8(message) {
            Ok(_) => format!("種類の印のない文字列 {}", text(message)),
            Err(_) => format!("16進: {}", hex(message)),
        },
    }
}

/// UTF-8 として読めれば引用符で囲んだ文字列、読めなければ16進。
/// 端末の表示を書き換えられないように、制御文字と、表示の向きを変える文字はエスケープする
fn text(bytes: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return format!("16進: {}", hex(bytes));
    };
    let mut out = String::from("\"");
    for character in text.chars() {
        if character.is_control()
            || matches!(character, '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        {
            write!(out, "\\u{{{:04X}}}", character as u32).unwrap();
        } else if character == '"' || character == '\\' {
            out.push('\\');
            out.push(character);
        } else {
            out.push(character);
        }
    }
    out.push('"');
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// 本体の種類の名前と、catbuffer の番号とバージョン
fn title(body: &Body) -> String {
    format!(
        "{}（0x{:04X}、バージョン {}）",
        type_name(body.transaction_type()),
        body.transaction_type(),
        body.version()
    )
}

/// catbuffer の `TransactionType` の名前
fn type_name(transaction_type: u16) -> &'static str {
    match transaction_type {
        0x414C => "AccountKeyLink",
        0x424C => "NodeKeyLink",
        0x4141 => "AggregateComplete",
        0x4241 => "AggregateBonded",
        0x4143 => "VotingKeyLink",
        0x4243 => "VrfKeyLink",
        0x4148 => "HashLock",
        0x4152 => "SecretLock",
        0x4252 => "SecretProof",
        0x4144 => "AccountMetadata",
        0x4244 => "MosaicMetadata",
        0x4344 => "NamespaceMetadata",
        0x414D => "MosaicDefinition",
        0x424D => "MosaicSupplyChange",
        0x434D => "MosaicSupplyRevocation",
        0x4155 => "MultisigAccountModification",
        0x424E => "AddressAlias",
        0x434E => "MosaicAlias",
        0x414E => "NamespaceRegistration",
        0x4150 => "AccountAddressRestriction",
        0x4250 => "AccountMosaicRestriction",
        0x4350 => "AccountOperationRestriction",
        0x4251 => "MosaicAddressRestriction",
        0x4151 => "MosaicGlobalRestriction",
        0x4154 => "Transfer",
        _ => "不明な種類",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use heika_core::key::PrivateKey;
    use heika_core::network::GenerationHashSeed;
    use heika_transaction::{
        Aggregate, EmbeddedTransaction, MosaicDefinition, NamespaceRegistration, Transfer,
    };

    use super::*;

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1
    const PRIVATE: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";

    fn private_key() -> PrivateKey {
        PRIVATE.parse().unwrap()
    }

    fn signer() -> PublicKey {
        PublicKey::from_private_key(&private_key())
    }

    /// メインネットのエポックから1時間後が期限の、メインネットのトランザクション
    fn transaction(body: Body) -> Transaction {
        Transaction::new(
            signer(),
            NetworkIdentifier::MAINNET,
            17_600,
            3_600_000,
            body,
        )
    }

    fn epoch() -> SystemTime {
        NetworkParameters::MAINNET.epoch()
    }

    fn value<'a>(description: &'a Description, label: &str) -> Vec<&'a str> {
        description
            .fields
            .iter()
            .filter(|field| field.label == label)
            .map(|field| field.value.as_str())
            .collect()
    }

    fn transfer(recipient: UnresolvedAddress, mosaics: &[(u64, u64)], message: &[u8]) -> Body {
        let mosaics: BTreeMap<_, _> = mosaics
            .iter()
            .map(|&(id, amount)| (UnresolvedMosaicId(id), amount))
            .collect();
        Body::Transfer(Transfer::new(recipient, mosaics, message.to_vec()).unwrap())
    }

    fn own_address() -> UnresolvedAddress {
        Address::from_public_key(&signer(), NetworkIdentifier::MAINNET).into()
    }

    #[test]
    fn describes_the_header() {
        let mut transaction = transaction(transfer(own_address(), &[], b""));
        let description = describe(&transaction, epoch());
        assert_eq!(description.title, "Transfer（0x4154、バージョン 1）");
        assert_eq!(value(&description, "ネットワーク"), ["メインネット"]);
        assert_eq!(value(&description, "手数料"), ["0.017600 XYM（17600）"]);
        assert_eq!(
            value(&description, "期限"),
            ["2021-03-16 01:06:25 UTC（あと 1 時間 0 分）"]
        );
        assert_eq!(value(&description, "署名"), ["まだない"]);
        assert!(value(&description, "ハッシュ").is_empty());

        transaction
            .sign(&private_key(), &GenerationHashSeed::MAINNET)
            .unwrap();
        let later = epoch() + Duration::from_secs(7200);
        let description = describe(&transaction, later);
        assert_eq!(value(&description, "署名"), ["あり（正しい）"]);
        assert_eq!(value(&description, "ハッシュ").len(), 1);
        assert!(value(&description, "期限")[0].ends_with("（期限切れ）"));
    }

    #[test]
    fn describes_currency_and_other_mosaics() {
        let body = transfer(
            own_address(),
            &[
                (0x6BED_913F_A202_23F8, 1_500_000),
                (0x0102, 3),
                (CURRENCY_NAMESPACE.0, 1),
            ],
            b"",
        );
        let description = describe(&transaction(body), epoch());
        assert_eq!(
            value(&description, "モザイク"),
            [
                "3（最小単位）: 0x0000000000000102",
                "1.500000 XYM（0x6BED913FA20223F8（XYM））",
                "0.000001 XYM（ネームスペース 0xE74B99BA41F4AFEE（symbol.xym））",
            ]
        );
    }

    #[test]
    fn warns_about_addresses_of_another_network_or_a_bad_checksum() {
        let testnet = Address::from_public_key(&signer(), NetworkIdentifier::TESTNET);
        let mut broken = Address::from_public_key(&signer(), NetworkIdentifier::MAINNET);
        broken.0[23] ^= 1;
        let mut namespace = [0; 24];
        namespace[0] = 0x69;
        namespace[1..9].copy_from_slice(&0x8000_0000_0000_0001_u64.to_le_bytes());
        let context = Context::new(NetworkIdentifier::MAINNET);
        assert!(
            context
                .address(&testnet.into())
                .ends_with("（別のネットワークのアドレス）")
        );
        assert!(
            context
                .address(&broken.into())
                .ends_with("（チェックサムが合わない）")
        );
        assert_eq!(
            context.address(&UnresolvedAddress(namespace)),
            "ネームスペース 0x8000000000000001"
        );
    }

    #[test]
    fn escapes_text_that_could_rewrite_the_terminal() {
        assert_eq!(text(b"hi \"there\""), "\"hi \\\"there\\\"\"");
        assert_eq!(
            text("a\u{1B}[2Jb\u{202E}c".as_bytes()),
            "\"a\\u{001B}[2Jb\\u{202E}c\""
        );
        assert_eq!(text(&[0xFF, 0x00]), "16進: FF00");
        assert_eq!(message(b"\0hello"), "平文 \"hello\"");
        assert_eq!(message(b"hello"), "種類の印のない文字列 \"hello\"");
        assert_eq!(message(&[1, 0xAB]), "暗号化されたメッセージ（16進: AB）");
        assert_eq!(message(b""), "なし");
    }

    #[test]
    fn checks_ids_derived_from_the_signer_and_the_name() {
        let owner = Address::from_public_key(&signer(), NetworkIdentifier::MAINNET);
        let definition = |id| {
            Body::MosaicDefinition(MosaicDefinition {
                id,
                duration: 0,
                nonce: 7,
                flags: MosaicFlags::TRANSFERABLE,
                divisibility: 0,
            })
        };
        let good = describe(
            &transaction(definition(MosaicId::generate(&owner, 7))),
            epoch(),
        );
        assert!(!value(&good, "ID")[0].contains("合わない"));
        let bad = describe(&transaction(definition(MosaicId(1))), epoch());
        assert!(value(&bad, "ID")[0].ends_with("（署名者とノンスから求めた ID と合わない）"));

        let registration = |id| {
            Body::NamespaceRegistration(NamespaceRegistration {
                registration_type: NamespaceRegistrationType::Root { duration: 2880 },
                id,
                name: b"heika".to_vec().try_into().unwrap(),
            })
        };
        let good = describe(
            &transaction(registration(NamespaceId::generate(None, b"heika"))),
            epoch(),
        );
        assert!(!value(&good, "ID")[0].contains("合わない"));
        assert_eq!(value(&good, "期間"), ["2880 ブロック（約 1 日）"]);
        let bad = describe(&transaction(registration(NamespaceId(1 << 63))), epoch());
        assert!(value(&bad, "ID")[0].ends_with("（名前と親から求めた ID と合わない）"));
    }

    #[test]
    fn warns_about_old_aggregates() {
        let aggregate = Aggregate::new(vec![EmbeddedTransaction::new(
            signer(),
            NetworkIdentifier::MAINNET,
            transfer(own_address(), &[], b""),
        )])
        .unwrap();
        let current_transaction = transaction(Body::AggregateComplete(aggregate));
        let current = describe(&current_transaction, epoch());
        assert!(value(&current, "形式").is_empty());
        assert!(value(&current, "中のトランザクションのハッシュ").is_empty());

        // バージョン 1 にして、中のトランザクションのハッシュを壊す
        let mut bytes = current_transaction.to_bytes();
        bytes[108] = 1;
        bytes[128] ^= 1;
        let old = describe(&Transaction::from_bytes(&bytes).unwrap(), epoch());
        assert_eq!(old.title, "AggregateComplete（0x4141、バージョン 1）");
        assert!(value(&old, "形式")[0].contains("今は送れない"));
        assert_eq!(
            value(&old, "中のトランザクションのハッシュ"),
            ["どの求め方とも合わない（下の中身が署名されたものとは限らない）"]
        );
    }

    #[test]
    fn lists_embedded_transactions_under_the_aggregate() {
        let other = PublicKey::from_private_key(&PrivateKey::from_bytes(&[7; 32]));
        let aggregate = Aggregate::new(vec![
            EmbeddedTransaction::new(
                other,
                NetworkIdentifier::MAINNET,
                transfer(own_address(), &[], b"\0a"),
            ),
            EmbeddedTransaction::new(
                signer(),
                NetworkIdentifier::TESTNET,
                transfer(own_address(), &[], b""),
            ),
        ])
        .unwrap();
        let description = describe(&transaction(Body::AggregateComplete(aggregate)), epoch());
        assert_eq!(description.embedded.len(), 2);
        assert_eq!(
            description.embedded[0].title,
            "中のトランザクション 1/2: Transfer（0x4154、バージョン 1）"
        );
        assert!(value(&description.embedded[0], "ネットワーク").is_empty());
        assert_eq!(
            value(&description.embedded[1], "ネットワーク"),
            ["テストネット（外側と違う）"]
        );
        let rendered = description.render();
        assert!(rendered.contains("\n  中のトランザクション 1/2"));
        assert!(rendered.contains("\n    メッセージ: 平文 \"a\"\n"));
    }

    #[test]
    fn writes_the_same_fields_as_json() {
        let description = describe(&transaction(transfer(own_address(), &[], b"\0hi")), epoch());
        let json: serde_json::Value =
            serde_json::from_str(&description.to_json().render()).unwrap();
        assert_eq!(json["title"], description.title);
        let fields = json["fields"].as_array().unwrap();
        assert_eq!(fields.len(), description.fields.len());
        for (field, expected) in fields.iter().zip(&description.fields) {
            assert_eq!(field["label"], expected.label);
            assert_eq!(field["value"], expected.value);
        }
        assert_eq!(json["embedded"], serde_json::json!([]));
    }

    #[test]
    fn writes_utc_dates_and_rough_durations() {
        assert_eq!(utc(UNIX_EPOCH), "1970-01-01 00:00:00 UTC");
        // うるう日
        assert_eq!(
            utc(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "2000-02-29 00:00:00 UTC"
        );
        assert_eq!(approximate(Duration::from_secs(59)), "59 秒");
        assert_eq!(approximate(Duration::from_secs(90 * 60)), "1 時間 30 分");
        assert_eq!(approximate(Duration::from_secs(3 * 86_400)), "3 日");
        assert_eq!(xym(0), "0.000000 XYM");
    }
}
