//! ノードの harvesters.dat。catapult の harvesting 拡張の `UnlockedAccountsStorage` に合わせている。
//!
//! 暗号化したままの委任の要求の中身（124 バイト）を、ヘッダーなしで並べただけのファイル。
//! ノードは起動するときに全部をノードの鍵で復号して取り込み、1件でも復号できなければ起動しない。
//! 大きさが 124 バイトの倍数でなければ、壊れているものとして扱う。
//! 取り込んだあとで、リンクが合わないものやハーベストできないものを外し、ファイルを書き直す。

use std::fmt;

use heika_core::key::{PrivateKey, PublicKey};
use heika_wallet::harvest_request;

use crate::delegation::ENCRYPTED_PAYLOAD_SIZE;

/// harvesters.dat の1件。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// 暗号化したままの要求の中身。先頭の32バイトが、catapult での要求の識別子になる
    pub encrypted_payload: [u8; ENCRYPTED_PAYLOAD_SIZE],
    /// 中に入っていたリモートアカウントの公開鍵
    pub remote: PublicKey,
    /// 中に入っていた VRF の公開鍵
    pub vrf: PublicKey,
}

/// harvesters.dat の中身を読み、1件ずつノードの鍵で復号する。ノードが起動するときに弾くものは弾く。
pub fn read(bytes: &[u8], node_private_key: &PrivateKey) -> Result<Vec<Entry>, ReadError> {
    if !bytes.len().is_multiple_of(ENCRYPTED_PAYLOAD_SIZE) {
        return Err(ReadError::IncompleteEntry { size: bytes.len() });
    }
    bytes
        .chunks(ENCRYPTED_PAYLOAD_SIZE)
        .enumerate()
        .map(|(index, encrypted_payload)| {
            // 復号は要求のメッセージと同じなので、目印を付けて読む。復号した秘密鍵は公開鍵を出したらすぐに捨てる
            let message = [&harvest_request::MARKER[..], encrypted_payload].concat();
            let keys = harvest_request::decode(node_private_key, &message)
                .map_err(|_| ReadError::Undecryptable { index })?;
            Ok(Entry {
                encrypted_payload: encrypted_payload
                    .try_into()
                    .expect("chunks of the payload size"),
                remote: PublicKey::from_private_key(&keys.signing),
                vrf: PublicKey::from_private_key(&keys.vrf),
            })
        })
        .collect()
}

/// harvesters.dat が読めない理由。どちらも、ノードが起動しなくなるもの。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// 大きさが1件の大きさの倍数ではない
    IncompleteEntry { size: usize },
    /// `index` 件目（0から数える）が、ノードの鍵で復号できない
    Undecryptable { index: usize },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteEntry { size } => write!(
                f,
                "大きさ {size} バイトが、1件の {ENCRYPTED_PAYLOAD_SIZE} バイトの倍数ではありません。ノードも壊れているとして起動しません"
            ),
            Self::Undecryptable { index } => write!(
                f,
                "{} 件目が、ノードの鍵で復号できません。ノードも起動しません。ほかのノードの鍵で暗号化したものかもしれません",
                index + 1
            ),
        }
    }
}

impl std::error::Error for ReadError {}

#[cfg(test)]
mod tests {
    use heika_wallet::harvest_request::HarvesterKeys;

    use super::*;
    use crate::testing::Replay;

    fn private_key(seed: u8) -> PrivateKey {
        PrivateKey::from_bytes(&[seed; 32])
    }

    /// ノード `node` あての、リモート `remote`、VRF `vrf` の要求の、暗号化した中身
    fn payload(node: &PrivateKey, remote: u8, vrf: u8) -> Vec<u8> {
        let keys = HarvesterKeys {
            signing: private_key(remote),
            vrf: private_key(vrf),
        };
        let randomness = [remote; 32 + 12];
        let message = harvest_request::encode(
            &mut Replay(&randomness),
            &PublicKey::from_private_key(node),
            &keys,
        )
        .unwrap();
        message[harvest_request::MARKER.len()..].to_vec()
    }

    #[test]
    fn reads_and_decrypts_every_entry() {
        let node = private_key(100);
        let bytes = [payload(&node, 1, 2), payload(&node, 3, 4)].concat();
        let entries = read(&bytes, &node).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].encrypted_payload[..], bytes[..124]);
        assert_eq!(
            entries[0].remote,
            PublicKey::from_private_key(&private_key(1))
        );
        assert_eq!(entries[0].vrf, PublicKey::from_private_key(&private_key(2)));
        assert_eq!(
            entries[1].remote,
            PublicKey::from_private_key(&private_key(3))
        );
        // 空のファイルは、委任が1件もないだけ
        assert_eq!(read(&[], &node).unwrap(), []);
    }

    #[test]
    fn rejects_what_the_node_would_refuse_to_load() {
        let node = private_key(100);
        let other = private_key(101);
        let bytes = [payload(&node, 1, 2), payload(&other, 3, 4)].concat();
        assert_eq!(
            read(&bytes, &node),
            Err(ReadError::Undecryptable { index: 1 })
        );
        assert_eq!(
            read(&bytes[..125], &node),
            Err(ReadError::IncompleteEntry { size: 125 })
        );
        // 1バイトでも書き換わっていれば、認証タグが合わずに復号できない
        let mut tampered = payload(&node, 1, 2);
        tampered[100] ^= 1;
        assert_eq!(
            read(&tampered, &node),
            Err(ReadError::Undecryptable { index: 0 })
        );
    }
}
