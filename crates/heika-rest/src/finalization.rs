//! ファイナライズの証明。`/finalization/proof/epoch/{epoch}` と `/finalization/proof/height/{height}` が返す
//! `FinalizationProofDTO`。
//!
//! catapult の REST は、ノードから受け取ったバイナリの証明を、並びを変えずに項目に分けて返す。なので、項目を同じ順に
//! 並べ直せば、ノードが返すものと同じバイト列に戻る。ここでは並べ直すだけで、投票の署名と重みは確かめない。
//! 確かめるのは、そのエポックの投票者を知っている側（heika-block の `verify_proof`）。

use serde::{Deserialize, Serialize};

use crate::{RestError, hex, hex_array, number};

/// `FinalizationProofDTO`。
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationProof {
    pub version: u32,
    pub finalization_epoch: u32,
    pub finalization_point: u32,
    pub height: String,
    pub hash: String,
    pub message_groups: Vec<MessageGroup>,
}

/// `MessageGroup`。同じ段階、高さ、ハッシュに投じた票の署名をまとめたもの
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageGroup {
    pub stage: u32,
    pub height: String,
    pub hashes: Vec<String>,
    pub signatures: Vec<BmTreeSignature>,
}

/// `BmTreeSignature`。2段の鍵の木の署名
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BmTreeSignature {
    pub root: ParentPublicKeySignaturePair,
    pub bottom: ParentPublicKeySignaturePair,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentPublicKeySignaturePair {
    pub parent_public_key: String,
    pub signature: String,
}

impl FinalizationProof {
    /// ノードが返すものと同じバイナリの証明に戻す
    pub fn to_bytes(&self) -> Result<Vec<u8>, RestError> {
        let mut body = Vec::new();
        for group in &self.message_groups {
            let start = body.len();
            body.extend_from_slice(&[0; 4]);
            body.extend_from_slice(&(group.hashes.len() as u32).to_le_bytes());
            body.extend_from_slice(&(group.signatures.len() as u32).to_le_bytes());
            body.extend_from_slice(&group.stage.to_le_bytes());
            body.extend_from_slice(&number(&group.height, "messageGroups.height")?.to_le_bytes());
            for hash in &group.hashes {
                body.extend_from_slice(&hex_array::<32>(hash, "messageGroups.hashes")?);
            }
            for signature in &group.signatures {
                for pair in [&signature.root, &signature.bottom] {
                    body.extend_from_slice(&hex_array::<32>(
                        &pair.parent_public_key,
                        "messageGroups.signatures.parentPublicKey",
                    )?);
                    body.extend_from_slice(&hex_array::<64>(
                        &pair.signature,
                        "messageGroups.signatures.signature",
                    )?);
                }
            }
            let size = (body.len() - start) as u32;
            body[start..start + 4].copy_from_slice(&size.to_le_bytes());
        }
        let size = 8 + 4 + 4 + 8 + 32 + body.len();
        let mut proof = Vec::with_capacity(size);
        proof.extend_from_slice(&(size as u32).to_le_bytes());
        proof.extend_from_slice(&self.version.to_le_bytes());
        proof.extend_from_slice(&self.finalization_epoch.to_le_bytes());
        proof.extend_from_slice(&self.finalization_point.to_le_bytes());
        proof.extend_from_slice(&number(&self.height, "height")?.to_le_bytes());
        proof.extend_from_slice(&hex_array::<32>(&self.hash, "hash")?);
        proof.extend_from_slice(&body);
        Ok(proof)
    }

    /// ノードが持つバイナリの証明を、REST の形にする（[`to_bytes`](Self::to_bytes) の逆）。
    /// 長さが合わなければ `None`。署名と重みは確かめない
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader(bytes);
        let size = reader.u32()? as usize;
        if size != bytes.len() {
            return None;
        }
        let version = reader.u32()?;
        let finalization_epoch = reader.u32()?;
        let finalization_point = reader.u32()?;
        let height = reader.u64()?.to_string();
        let hash = hex(reader.take(32)?);
        let mut message_groups = Vec::new();
        while !reader.0.is_empty() {
            let size = reader.u32()? as usize;
            let mut group = Reader(reader.take(size.checked_sub(4)?)?);
            let hashes = group.u32()?;
            let signatures = group.u32()?;
            let stage = group.u32()?;
            let height = group.u64()?.to_string();
            let hashes = (0..hashes)
                .map(|_| group.take(32).map(hex))
                .collect::<Option<_>>()?;
            let mut pair = || {
                Some(ParentPublicKeySignaturePair {
                    parent_public_key: hex(group.take(32)?),
                    signature: hex(group.take(64)?),
                })
            };
            let signatures = (0..signatures)
                .map(|_| {
                    Some(BmTreeSignature {
                        root: pair()?,
                        bottom: pair()?,
                    })
                })
                .collect::<Option<_>>()?;
            if !group.0.is_empty() {
                return None;
            }
            message_groups.push(MessageGroup {
                stage,
                height,
                hashes,
                signatures,
            });
        }
        Some(Self {
            version,
            finalization_epoch,
            finalization_point,
            height,
            hash,
            message_groups,
        })
    }
}

/// 頭から順に読む
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(size)?;
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use heika_block::finalization::proof::proof_header;
    use serde_json::json;

    use super::*;

    #[test]
    fn rebuilds_the_binary_proof() {
        let hex = |byte: u8, len: usize| format!("{byte:02X}").repeat(len);
        let pair = || json!({ "parentPublicKey": hex(0x11, 32), "signature": hex(0x22, 64) });
        let proof: FinalizationProof = serde_json::from_value(json!({
            "version": 1,
            "finalizationEpoch": 7,
            "finalizationPoint": 3,
            "height": "8640",
            "hash": hex(0xAB, 32),
            "messageGroups": [{
                "stage": 1,
                "height": "8640",
                "hashes": [hex(0xAB, 32)],
                "signatures": [{ "root": pair(), "bottom": pair() }],
            }],
        }))
        .unwrap();
        let bytes = proof.to_bytes().unwrap();
        // 見出し 56、組の見出し 24、ハッシュ 32、署名 192
        assert_eq!(bytes.len(), 56 + 24 + 32 + 192);
        let header = proof_header(&bytes).unwrap();
        assert_eq!((header.round.epoch, header.round.point), (7, 3));
        assert_eq!(header.height, 8640);
        assert_eq!(header.hash.0, [0xAB; 32]);
        let group = &bytes[56..];
        assert_eq!(
            u32::from_le_bytes(group[..4].try_into().unwrap()),
            24 + 32 + 192
        );
        assert_eq!(&group[8..12], &1u32.to_le_bytes());
        assert_eq!(&group[56..88], &[0x11; 32]);
        assert_eq!(&group[88..152], &[0x22; 64]);
        // バイナリから戻すと、同じ JSON になる
        assert_eq!(FinalizationProof::from_bytes(&bytes), Some(proof));
        assert_eq!(
            FinalizationProof::from_bytes(&bytes[..bytes.len() - 1]),
            None
        );
    }
}
