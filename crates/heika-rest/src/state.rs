//! 状態。`/accounts/{id}`、`/mosaics/{id}`、`/namespaces`、`/metadata` が返す JSON から、
//! catapult が状態の木の葉にする状態のバイト列を組み直す。ノードが REST の口で返すために、
//! 状態のバイト列から JSON にする逆向きもある。
//!
//! 葉の値は、状態のバージョン（u16）に続けて、履歴を除いた状態を書いたものの SHA3-256
//! （catapult の `CacheSerializerAdapter` と、それぞれの `*NonHistoricalSerializer` や `*Serializer`）。
//! `/accounts/{id}/merkle` などが返す経路の葉と比べれば、REST の状態の JSON が木にあるものと同じだと確かめられる。
//!
//! 状態は最新のものしか取れないので、経路の根と比べる9本の根も、同じ時点のブロックのものを使う。

use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::patricia;
use heika_transaction::{MetadataKey, MetadataType};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{RestError, hex, hex_array, hex_vec, number};

/// どの状態も、バージョンは 1
const STATE_VERSION: u16 = 1;

/// 大口のアカウントが持つ、活動の記録の数。catapult の `Activity_Bucket_History_Size - Rollback_Buffer_Size`
const ACTIVITY_BUCKETS: usize = 5;

/// `AccountInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AccountInfo {
    pub account: AccountJson,
}

/// `AccountDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountJson {
    pub version: u16,
    pub address: String,
    pub address_height: String,
    pub public_key: String,
    pub public_key_height: String,
    pub account_type: u8,
    pub supplemental_public_keys: SupplementalPublicKeysJson,
    /// importance の履歴の先頭。大口のアカウントでなければ "0"
    pub importance: String,
    pub importance_height: String,
    /// 大口のアカウントだけが持つ、活動の記録
    pub activity_buckets: Vec<ActivityBucketJson>,
    pub mosaics: Vec<BalanceJson>,
}

/// `SupplementalPublicKeysDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct SupplementalPublicKeysJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked: Option<PublicKeyJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<PublicKeyJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf: Option<PublicKeyJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voting: Option<VotingPublicKeysJson>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJson {
    pub public_key: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VotingPublicKeysJson {
    pub public_keys: Vec<VotingPublicKeyJson>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VotingPublicKeyJson {
    pub public_key: String,
    pub start_epoch: u32,
    pub end_epoch: u32,
}

/// `ActivityBucketDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityBucketJson {
    pub start_height: String,
    pub total_fees_paid: String,
    pub beneficiary_count: u32,
    pub raw_score: String,
}

/// 残高。`Mosaic`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BalanceJson {
    pub id: String,
    pub amount: String,
}

impl AccountJson {
    /// 状態のバイト列。catapult の `AccountStateNonHistoricalSerializer`。
    pub fn to_state_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut out = header(self.version)?;
        out.extend_from_slice(&hex_array::<24>(&self.address, "address")?);
        out.extend_from_slice(&number(&self.address_height, "addressHeight")?.to_le_bytes());
        out.extend_from_slice(&hex_array::<32>(&self.public_key, "publicKey")?);
        out.extend_from_slice(&number(&self.public_key_height, "publicKeyHeight")?.to_le_bytes());
        out.push(self.account_type);
        // 大口のアカウント（High_Value）だけが、importance と活動の記録を持つ
        let high_value = !self.activity_buckets.is_empty();
        out.push(u8::from(high_value));

        let keys = &self.supplemental_public_keys;
        let voting = keys
            .voting
            .as_ref()
            .map_or(&[][..], |voting| &voting.public_keys[..]);
        let mut mask = 0;
        for (key, bit) in [(&keys.linked, 0x01), (&keys.node, 0x02), (&keys.vrf, 0x04)] {
            if key.is_some() {
                mask |= bit;
            }
        }
        out.push(mask);
        out.push(
            u8::try_from(voting.len()).map_err(|_| RestError::InvalidValue {
                field: "supplementalPublicKeys.voting",
            })?,
        );
        for (key, field) in [
            (&keys.linked, "supplementalPublicKeys.linked"),
            (&keys.node, "supplementalPublicKeys.node"),
            (&keys.vrf, "supplementalPublicKeys.vrf"),
        ] {
            if let Some(key) = key {
                out.extend_from_slice(&hex_array::<32>(&key.public_key, field)?);
            }
        }
        for key in voting {
            out.extend_from_slice(&hex_array::<32>(
                &key.public_key,
                "supplementalPublicKeys.voting",
            )?);
            out.extend_from_slice(&key.start_epoch.to_le_bytes());
            out.extend_from_slice(&key.end_epoch.to_le_bytes());
        }

        if high_value {
            if self.activity_buckets.len() != ACTIVITY_BUCKETS {
                return Err(RestError::InvalidValue {
                    field: "activityBuckets",
                });
            }
            out.extend_from_slice(&number(&self.importance, "importance")?.to_le_bytes());
            out.extend_from_slice(
                &number(&self.importance_height, "importanceHeight")?.to_le_bytes(),
            );
            for bucket in &self.activity_buckets {
                out.extend_from_slice(
                    &number(&bucket.start_height, "activityBuckets.startHeight")?.to_le_bytes(),
                );
                out.extend_from_slice(
                    &number(&bucket.total_fees_paid, "activityBuckets.totalFeesPaid")?
                        .to_le_bytes(),
                );
                out.extend_from_slice(&bucket.beneficiary_count.to_le_bytes());
                out.extend_from_slice(
                    &number(&bucket.raw_score, "activityBuckets.rawScore")?.to_le_bytes(),
                );
            }
        }

        out.extend_from_slice(
            &u16::try_from(self.mosaics.len())
                .map_err(|_| RestError::InvalidValue { field: "mosaics" })?
                .to_le_bytes(),
        );
        for mosaic in &self.mosaics {
            out.extend_from_slice(&id(&mosaic.id, "mosaics.id")?.to_le_bytes());
            out.extend_from_slice(&number(&mosaic.amount, "mosaics.amount")?.to_le_bytes());
        }
        Ok(out)
    }

    /// 状態のバイト列から、REST が返す形にする。[`AccountJson::to_state_bytes`] の逆。ノードが REST の口で返すときに使う
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, RestError> {
        let mut reader = StateReader::new(bytes)?;
        let address = hex(reader.take(24)?);
        let address_height = reader.u64()?.to_string();
        let public_key = hex(reader.take(32)?);
        let public_key_height = reader.u64()?.to_string();
        let account_type = reader.u8()?;
        let high_value = reader.u8()? != 0;
        let mask = reader.u8()?;
        let voting_count = reader.u8()?;
        // linked、node、vrf の順に、ビットが立っているものだけが並ぶ
        let key = |bit: u8, reader: &mut StateReader| -> Result<Option<PublicKeyJson>, RestError> {
            if mask & bit == 0 {
                return Ok(None);
            }
            Ok(Some(PublicKeyJson {
                public_key: hex(reader.take(32)?),
            }))
        };
        let linked = key(0x01, &mut reader)?;
        let node = key(0x02, &mut reader)?;
        let vrf = key(0x04, &mut reader)?;
        let voting: Vec<VotingPublicKeyJson> = (0..voting_count)
            .map(|_| {
                Ok(VotingPublicKeyJson {
                    public_key: hex(reader.take(32)?),
                    start_epoch: reader.u32()?,
                    end_epoch: reader.u32()?,
                })
            })
            .collect::<Result<_, RestError>>()?;
        let (importance, importance_height, activity_buckets) = if high_value {
            let importance = reader.u64()?.to_string();
            let importance_height = reader.u64()?.to_string();
            let buckets = (0..ACTIVITY_BUCKETS)
                .map(|_| {
                    Ok(ActivityBucketJson {
                        start_height: reader.u64()?.to_string(),
                        total_fees_paid: reader.u64()?.to_string(),
                        beneficiary_count: reader.u32()?,
                        raw_score: reader.u64()?.to_string(),
                    })
                })
                .collect::<Result<_, RestError>>()?;
            (importance, importance_height, buckets)
        } else {
            ("0".to_owned(), "0".to_owned(), Vec::new())
        };
        let mosaics = (0..reader.u16()?)
            .map(|_| {
                Ok(BalanceJson {
                    id: format!("{:016X}", reader.u64()?),
                    amount: reader.u64()?.to_string(),
                })
            })
            .collect::<Result<_, RestError>>()?;
        reader.finish()?;
        Ok(Self {
            version: STATE_VERSION,
            address,
            address_height,
            public_key,
            public_key_height,
            account_type,
            supplemental_public_keys: SupplementalPublicKeysJson {
                linked,
                node,
                vrf,
                voting: (!voting.is_empty()).then_some(VotingPublicKeysJson {
                    public_keys: voting,
                }),
            },
            importance,
            importance_height,
            activity_buckets,
            mosaics,
        })
    }

    /// 状態の木の葉の値。
    pub fn state_hash(&self) -> Result<Hash256, RestError> {
        Ok(sha3(&self.to_state_bytes()?))
    }

    /// 状態の木のキー。アドレスの SHA3-256。
    pub fn tree_key(&self) -> Result<Hash256, RestError> {
        Ok(patricia::address_key(&Address(hex_array(
            &self.address,
            "address",
        )?)))
    }
}

/// `MosaicInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MosaicInfo {
    pub mosaic: MosaicStateJson,
}

/// `MosaicDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MosaicStateJson {
    pub version: u16,
    pub id: String,
    pub supply: String,
    pub start_height: String,
    pub owner_address: String,
    pub revision: u32,
    pub flags: u8,
    pub divisibility: u8,
    pub duration: String,
}

impl MosaicStateJson {
    /// 状態のバイト列。catapult の `MosaicEntrySerializer`。
    pub fn to_state_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut out = header(self.version)?;
        out.extend_from_slice(&id(&self.id, "id")?.to_le_bytes());
        out.extend_from_slice(&number(&self.supply, "supply")?.to_le_bytes());
        out.extend_from_slice(&number(&self.start_height, "startHeight")?.to_le_bytes());
        out.extend_from_slice(&hex_array::<24>(&self.owner_address, "ownerAddress")?);
        out.extend_from_slice(&self.revision.to_le_bytes());
        out.push(self.flags);
        out.push(self.divisibility);
        out.extend_from_slice(&number(&self.duration, "duration")?.to_le_bytes());
        Ok(out)
    }

    /// 状態のバイト列から、REST が返す形にする。[`MosaicStateJson::to_state_bytes`] の逆
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, RestError> {
        let mut reader = StateReader::new(bytes)?;
        let mosaic = Self {
            version: STATE_VERSION,
            id: format!("{:016X}", reader.u64()?),
            supply: reader.u64()?.to_string(),
            start_height: reader.u64()?.to_string(),
            owner_address: hex(reader.take(24)?),
            revision: reader.u32()?,
            flags: reader.u8()?,
            divisibility: reader.u8()?,
            duration: reader.u64()?.to_string(),
        };
        reader.finish()?;
        Ok(mosaic)
    }

    pub fn state_hash(&self) -> Result<Hash256, RestError> {
        Ok(sha3(&self.to_state_bytes()?))
    }

    /// 状態の木のキー。モザイクの ID の SHA3-256。
    pub fn tree_key(&self) -> Result<Hash256, RestError> {
        Ok(patricia::id_key(id(&self.id, "id")?))
    }
}

/// `MultisigAccountInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MultisigInfo {
    pub multisig: MultisigJson,
}

/// `MultisigDTO`。マルチシグのアカウントと、その連署者（`cosignatoryAddresses`）、連署者として入っている
/// マルチシグ（`multisigAddresses`）。連署者にしかなっていないアカウントにもある
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigJson {
    pub version: u16,
    pub account_address: String,
    pub min_approval: u32,
    pub min_removal: u32,
    pub cosignatory_addresses: Vec<String>,
    pub multisig_addresses: Vec<String>,
}

/// `MultisigAccountGraphInfoDTO`。マルチシグの木の1段。0 が引いたアカウントで、負は上（入っているマルチシグ）、
/// 正は下（連署者）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultisigGraphLevel {
    pub level: i32,
    pub multisig_entries: Vec<MultisigInfo>,
}

impl MultisigJson {
    /// 状態のバイト列。catapult の `MultisigEntrySerializer`。
    pub fn to_state_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut out = header(self.version)?;
        out.extend_from_slice(&self.min_approval.to_le_bytes());
        out.extend_from_slice(&self.min_removal.to_le_bytes());
        out.extend_from_slice(&hex_array::<24>(&self.account_address, "accountAddress")?);
        for (addresses, name) in [
            (&self.cosignatory_addresses, "cosignatoryAddresses"),
            (&self.multisig_addresses, "multisigAddresses"),
        ] {
            out.extend_from_slice(&(addresses.len() as u64).to_le_bytes());
            for address in addresses {
                out.extend_from_slice(&hex_array::<24>(address, name)?);
            }
        }
        Ok(out)
    }

    /// 状態のバイト列から、REST が返す形にする。[`MultisigJson::to_state_bytes`] の逆
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, RestError> {
        let mut reader = StateReader::new(bytes)?;
        let min_approval = reader.u32()?;
        let min_removal = reader.u32()?;
        let account_address = hex(reader.take(24)?);
        let mut addresses = || -> Result<Vec<String>, RestError> {
            let count = reader.u64()?;
            (0..count).map(|_| Ok(hex(reader.take(24)?))).collect()
        };
        let cosignatory_addresses = addresses()?;
        let multisig_addresses = addresses()?;
        reader.finish()?;
        Ok(Self {
            version: STATE_VERSION,
            account_address,
            min_approval,
            min_removal,
            cosignatory_addresses,
            multisig_addresses,
        })
    }

    pub fn state_hash(&self) -> Result<Hash256, RestError> {
        Ok(sha3(&self.to_state_bytes()?))
    }

    /// 状態の木のキー。アドレスの SHA3-256。
    pub fn tree_key(&self) -> Result<Hash256, RestError> {
        Ok(patricia::address_key(&Address(hex_array(
            &self.account_address,
            "accountAddress",
        )?)))
    }
}

/// `MetadataInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataInfo {
    /// 検索のページ送り（`offset`）に渡す位置。catapult の REST では MongoDB の ID、heika では
    /// [`MetadataEntryJson::position`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub metadata_entry: MetadataEntryJson,
}

/// `MetadataEntryDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataEntryJson {
    pub version: u16,
    /// 1件を指すハッシュ。[`MetadataKey::unique_key`]
    pub composite_hash: String,
    pub source_address: String,
    pub target_address: String,
    pub scoped_metadata_key: String,
    pub target_id: String,
    pub metadata_type: u8,
    pub value_size: u16,
    pub value: String,
}

impl MetadataEntryJson {
    /// 1件を指すキー。
    pub fn key(&self) -> Result<MetadataKey, RestError> {
        Ok(MetadataKey {
            source_address: Address(hex_array(&self.source_address, "sourceAddress")?),
            target_address: Address(hex_array(&self.target_address, "targetAddress")?),
            scoped_metadata_key: id(&self.scoped_metadata_key, "scopedMetadataKey")?,
            target_id: id(&self.target_id, "targetId")?,
            metadata_type: metadata_type(self.metadata_type)?,
        })
    }

    /// heika の REST の検索で、この件の位置（`id`）。送り主、種類、宛先、対象の ID、キーを16進でつないだもの。
    /// 検索の `offset` に渡すと、この件の次から返す
    pub fn position(&self) -> String {
        format!(
            "{}{:02X}{}{}{}",
            self.source_address,
            self.metadata_type,
            self.target_address,
            self.target_id,
            self.scoped_metadata_key
        )
    }

    /// 状態のバイト列から、REST が返す形にする。[`MetadataEntryJson::to_state_bytes`] の逆
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, RestError> {
        let mut reader = StateReader::new(bytes)?;
        let key = MetadataKey {
            source_address: Address(reader.array()?),
            target_address: Address(reader.array()?),
            scoped_metadata_key: reader.u64()?,
            target_id: reader.u64()?,
            metadata_type: metadata_type(reader.u8()?)?,
        };
        let value_size = reader.u16()?;
        let value = reader.take(usize::from(value_size))?;
        reader.finish()?;
        Ok(Self {
            version: STATE_VERSION,
            composite_hash: key.unique_key().to_string(),
            source_address: hex(&key.source_address.0),
            target_address: hex(&key.target_address.0),
            scoped_metadata_key: format!("{:016X}", key.scoped_metadata_key),
            target_id: format!("{:016X}", key.target_id),
            metadata_type: key.metadata_type as u8,
            value_size,
            value: hex(value),
        })
    }

    /// 状態のバイト列。catapult の `MetadataEntrySerializer`。
    pub fn to_state_bytes(&self) -> Result<Vec<u8>, RestError> {
        let key = self.key()?;
        let value = hex_vec(&self.value, "value")?;
        if value.len() != usize::from(self.value_size) {
            return Err(RestError::Mismatch { field: "valueSize" });
        }
        let mut out = header(self.version)?;
        out.extend_from_slice(&key.source_address.0);
        out.extend_from_slice(&key.target_address.0);
        out.extend_from_slice(&key.scoped_metadata_key.to_le_bytes());
        out.extend_from_slice(&key.target_id.to_le_bytes());
        out.push(self.metadata_type);
        out.extend_from_slice(&self.value_size.to_le_bytes());
        out.extend_from_slice(&value);
        Ok(out)
    }

    pub fn state_hash(&self) -> Result<Hash256, RestError> {
        Ok(sha3(&self.to_state_bytes()?))
    }

    /// 状態の木のキー。REST の `compositeHash` が中身から求めた1件のハッシュと合うかを確かめてから、その SHA3-256 にする。
    pub fn tree_key(&self) -> Result<Hash256, RestError> {
        let unique_key = self.key()?.unique_key();
        if unique_key != Hash256(hex_array(&self.composite_hash, "compositeHash")?) {
            return Err(RestError::Mismatch {
                field: "compositeHash",
            });
        }
        Ok(patricia::hash_key(&unique_key))
    }
}

/// `NamespaceInfoDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct NamespaceInfo {
    /// 検索のページ送り（`offset`）に渡す位置。catapult の REST では MongoDB の ID、heika では検索表のキー
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub meta: NamespaceMetaJson,
    pub namespace: NamespaceJson,
}

/// `NamespaceNameDTO`。`POST /namespaces/names` が返す1件。名前は自分の部分だけ（`xym` など）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceNameJson {
    pub id: String,
    pub name: String,
    /// 子のときだけ
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

/// `AccountNamesDTO`。`POST /namespaces/account/names` の1件。名前はルートからつないだもの（`symbol.xym` など）
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AccountNamesJson {
    pub address: String,
    pub names: Vec<String>,
}

/// `MosaicNamesDTO`。`POST /namespaces/mosaic/names` の1件
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MosaicNamesJson {
    pub mosaic_id: String,
    pub names: Vec<String>,
}

/// `NamespaceMetaDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct NamespaceMetaJson {
    /// 期限の高さ（`endHeight`。catapult は猶予の期間を足した高さを持つ）が今の高さより後なら `true`。
    /// `false` のものは状態には残るが、状態の木からは外れている
    pub active: bool,
}

/// `NamespaceDTO`。ルートも子も、1つずつ別に返る。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceJson {
    pub version: u16,
    pub registration_type: u8,
    /// 経路の長さ（1から3）
    pub depth: u8,
    pub level0: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level2: Option<String>,
    pub alias: AliasJson,
    /// 親の ID。ルートは `0000000000000000`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub owner_address: String,
    pub start_height: String,
    pub end_height: String,
}

/// `AliasDTO`。`type` が 0 なら別名なし、1 ならモザイク、2 ならアドレス。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AliasJson {
    #[serde(rename = "type")]
    pub alias_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mosaic_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl NamespaceJson {
    /// ルートからの ID の並び。
    pub fn path(&self) -> Result<Vec<u64>, RestError> {
        let levels = [
            Some(&self.level0),
            self.level1.as_ref(),
            self.level2.as_ref(),
        ];
        let depth = usize::from(self.depth);
        if !(1..=3).contains(&depth) {
            return Err(RestError::InvalidValue { field: "depth" });
        }
        levels[..depth]
            .iter()
            .map(|level| id(level.ok_or(RestError::Missing { field: "level" })?, "level"))
            .collect()
    }
}

impl AliasJson {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), RestError> {
        out.push(self.alias_type);
        match self.alias_type {
            0 => {}
            1 => out.extend_from_slice(
                &id(
                    self.mosaic_id.as_ref().ok_or(RestError::Missing {
                        field: "alias.mosaicId",
                    })?,
                    "alias.mosaicId",
                )?
                .to_le_bytes(),
            ),
            2 => out.extend_from_slice(&hex_array::<24>(
                self.address.as_ref().ok_or(RestError::Missing {
                    field: "alias.address",
                })?,
                "alias.address",
            )?),
            _ => {
                return Err(RestError::InvalidValue {
                    field: "alias.type",
                });
            }
        }
        Ok(())
    }

    fn decode(reader: &mut StateReader) -> Result<Self, RestError> {
        let alias_type = reader.u8()?;
        let (mosaic_id, address) = match alias_type {
            0 => (None, None),
            1 => (Some(format!("{:016X}", reader.u64()?)), None),
            2 => (None, Some(hex(reader.take(24)?))),
            _ => {
                return Err(RestError::InvalidValue {
                    field: "alias.type",
                });
            }
        };
        Ok(Self {
            alias_type,
            mosaic_id,
            address,
        })
    }
}

/// ルートのネームスペースの状態。REST はルートと子を1つずつ別に返すので、同じルートのもの
/// （`/namespaces?level0=<ルートの ID>` で取れる）を集めて組み直す。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RootNamespaceState {
    root_id: u64,
    root: NamespaceJson,
    /// 経路の辞書順に並べた子
    children: Vec<(Vec<u64>, NamespaceJson)>,
}

impl RootNamespaceState {
    /// `root_id` のルートと、その子を集める。期限（猶予を含む）が過ぎたもの（`meta.active` が `false`）は、状態の木に
    /// ないので除く。
    pub fn collect(root_id: u64, entries: &[NamespaceInfo]) -> Result<Self, RestError> {
        let mut root = None;
        let mut children = Vec::new();
        for entry in entries.iter().filter(|entry| entry.meta.active) {
            let path = entry.namespace.path()?;
            if path[0] != root_id {
                continue;
            }
            if path.len() == 1 {
                if root.replace(entry.namespace.clone()).is_some() {
                    return Err(RestError::InvalidValue { field: "level0" });
                }
            } else {
                children.push((path, entry.namespace.clone()));
            }
        }
        // catapult の `RootNamespace::sortedChildPaths` と同じく、経路の ID を辞書順に並べる
        children.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self {
            root_id,
            root: root.ok_or(RestError::Missing { field: "level0" })?,
            children,
        })
    }

    /// 状態のバイト列から組む。[`RootNamespaceState::to_state_bytes`] の逆で、ルートと子を
    /// REST が返す形（[`NamespaceJson`]）にする
    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, RestError> {
        let mut reader = StateReader::new(bytes)?;
        let root_id = reader.u64()?;
        let owner_address = hex(reader.take(24)?);
        let start_height = reader.u64()?.to_string();
        let end_height = reader.u64()?.to_string();
        // 子も、持ち主と期間はルートのもの
        let entry = |path: &[u64], alias| {
            let level = |depth: usize| path.get(depth).map(|id| format!("{id:016X}"));
            let parent = if path.len() > 1 {
                path[path.len() - 2]
            } else {
                0
            };
            NamespaceJson {
                version: STATE_VERSION,
                registration_type: u8::from(path.len() > 1),
                depth: path.len() as u8,
                level0: format!("{:016X}", path[0]),
                level1: level(1),
                level2: level(2),
                alias,
                parent_id: Some(format!("{parent:016X}")),
                owner_address: owner_address.clone(),
                start_height: start_height.clone(),
                end_height: end_height.clone(),
            }
        };
        let root = entry(&[root_id], AliasJson::decode(&mut reader)?);
        let mut children = Vec::new();
        for _ in 0..reader.u64()? {
            let depth = reader.u8()?;
            if !(1..=2).contains(&depth) {
                return Err(RestError::InvalidValue { field: "state" });
            }
            let mut path = vec![root_id];
            for _ in 0..depth {
                path.push(reader.u64()?);
            }
            let child = entry(&path, AliasJson::decode(&mut reader)?);
            children.push((path, child));
        }
        reader.finish()?;
        Ok(Self {
            root_id,
            root,
            children,
        })
    }

    /// ルートか子の `id` を、`/namespaces/{id}` の形にする。なければ `None`。
    /// `height` は今のチェーンの高さで、catapult の REST と同じく、終わりの高さがそれより後なら `active`
    pub fn info(&self, id: u64, height: u64) -> Result<Option<NamespaceInfo>, RestError> {
        let namespace = if id == self.root_id {
            &self.root
        } else {
            match self
                .children
                .iter()
                .find(|(path, _)| path.last() == Some(&id))
            {
                Some((_, child)) => child,
                None => return Ok(None),
            }
        };
        Ok(Some(NamespaceInfo {
            id: None,
            meta: NamespaceMetaJson {
                active: number(&self.root.end_height, "endHeight")? > height,
            },
            namespace: namespace.clone(),
        }))
    }

    /// 状態のバイト列。catapult の `RootNamespaceHistoryNonHistoricalSerializer`。
    /// 今のルートだけを、子の経路（ルートの ID を除く）と別名とともに書く。
    pub fn to_state_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut out = header(self.root.version)?;
        out.extend_from_slice(&self.root_id.to_le_bytes());
        out.extend_from_slice(&hex_array::<24>(&self.root.owner_address, "ownerAddress")?);
        out.extend_from_slice(&number(&self.root.start_height, "startHeight")?.to_le_bytes());
        out.extend_from_slice(&number(&self.root.end_height, "endHeight")?.to_le_bytes());
        self.root.alias.encode(&mut out)?;
        out.extend_from_slice(&(self.children.len() as u64).to_le_bytes());
        for (path, child) in &self.children {
            out.push((path.len() - 1) as u8);
            for id in &path[1..] {
                out.extend_from_slice(&id.to_le_bytes());
            }
            child.alias.encode(&mut out)?;
        }
        Ok(out)
    }

    pub fn state_hash(&self) -> Result<Hash256, RestError> {
        Ok(sha3(&self.to_state_bytes()?))
    }

    /// 状態の木のキー。ルートの ID の SHA3-256。
    pub fn tree_key(&self) -> Hash256 {
        patricia::id_key(self.root_id)
    }
}

fn metadata_type(value: u8) -> Result<MetadataType, RestError> {
    match value {
        0 => Ok(MetadataType::Account),
        1 => Ok(MetadataType::Mosaic),
        2 => Ok(MetadataType::Namespace),
        _ => Err(RestError::InvalidValue {
            field: "metadataType",
        }),
    }
}

/// 状態のバージョンを書く。知らないバージョンは弾く。
fn header(version: u16) -> Result<Vec<u8>, RestError> {
    if version != STATE_VERSION {
        return Err(RestError::InvalidValue { field: "version" });
    }
    Ok(version.to_le_bytes().to_vec())
}

/// 状態のバイト列を前から読む。足りなかったり余ったりしたら、`state` が読めないことにする
struct StateReader<'a>(&'a [u8]);

impl<'a> StateReader<'a> {
    /// バージョンを読んで確かめる
    fn new(bytes: &'a [u8]) -> Result<Self, RestError> {
        let mut reader = Self(bytes);
        if reader.u16()? != STATE_VERSION {
            return Err(RestError::InvalidValue { field: "version" });
        }
        Ok(reader)
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8], RestError> {
        let (head, rest) = self
            .0
            .split_at_checked(size)
            .ok_or(RestError::InvalidValue { field: "state" })?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RestError> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, RestError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RestError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, RestError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, RestError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn finish(self) -> Result<(), RestError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(RestError::InvalidValue { field: "state" })
        }
    }
}

fn sha3(bytes: &[u8]) -> Hash256 {
    Hash256(Sha3_256::digest(bytes).into())
}

/// REST は ID を上位から16進で書く
pub(crate) fn id(text: &str, field: &'static str) -> Result<u64, RestError> {
    hex_array(text, field).map(u64::from_be_bytes)
}
