//! Transfer。catbuffer の `transfer/transfer.cats`。

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use heika_core::address::Address;
use heika_core::network::NetworkIdentifier;

use crate::mosaic::MosaicId;
use crate::namespace::NamespaceId;
use crate::{DecodeError, Reader};

/// まだ解決していないアドレス。アドレスそのものか、アドレスに紐づけたネームスペースのどちらか。
/// 先頭の1バイトの最下位ビットが1ならネームスペースで、どちらも24バイトで書く。
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct UnresolvedAddress(pub [u8; 24]);

impl From<Address> for UnresolvedAddress {
    fn from(address: Address) -> Self {
        Self(address.0)
    }
}

impl UnresolvedAddress {
    /// ネームスペースを指すアドレスにする。公式の SDK の `Address.from_namespace_id` と同じく、
    /// ネットワークの識別子の最下位ビットを立てた1バイト、ID の8バイト、残りの0を並べる。
    /// catapult が読むのは、先頭の最下位ビットと ID だけ。
    pub fn from_namespace_id(namespace_id: NamespaceId, network: NetworkIdentifier) -> Self {
        let mut bytes = [0; 24];
        bytes[0] = network.0 | 1;
        bytes[1..9].copy_from_slice(&namespace_id.0.to_le_bytes());
        Self(bytes)
    }

    /// ネームスペースを指していれば、その ID。catapult の `addAddressResolver` と同じく、先頭の最下位ビットで見分ける。
    pub fn namespace_id(&self) -> Option<NamespaceId> {
        (self.0[0] & 1 == 1).then(|| {
            NamespaceId(u64::from_le_bytes(
                self.0[1..9].try_into().expect("8 bytes"),
            ))
        })
    }

    /// ネームスペースを指していなければ、そのアドレス。
    pub fn address(&self) -> Option<Address> {
        (self.0[0] & 1 == 0).then_some(Address(self.0))
    }
}

/// まだ解決していないモザイクの ID。モザイクの ID か、モザイクに紐づけたネームスペースの ID のどちらか。
/// 最上位ビットが1ならネームスペース。
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct UnresolvedMosaicId(pub u64);

impl From<MosaicId> for UnresolvedMosaicId {
    fn from(id: MosaicId) -> Self {
        Self(id.0)
    }
}

impl From<NamespaceId> for UnresolvedMosaicId {
    fn from(id: NamespaceId) -> Self {
        Self(id.0)
    }
}

impl UnresolvedMosaicId {
    /// ネームスペースを指していれば、その ID。catapult の `addMosaicResolver` と同じく、最上位ビットで見分ける。
    pub fn namespace_id(self) -> Option<NamespaceId> {
        (self.0 >> 63 == 1).then_some(NamespaceId(self.0))
    }

    /// ネームスペースを指していなければ、そのモザイクの ID。
    pub fn mosaic_id(self) -> Option<MosaicId> {
        (self.0 >> 63 == 0).then_some(MosaicId(self.0))
    }
}

/// モザイクとメッセージを送る本体。
///
/// catapult はモザイクが ID の昇順に重複なく並んでいるものだけを受け付けるので、
/// ID から量への対応として持ち、書くときに昇順に並べる。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transfer {
    recipient_address: UnresolvedAddress,
    mosaics: BTreeMap<UnresolvedMosaicId, u64>,
    message: Vec<u8>,
}

impl Transfer {
    /// 受取人、送るモザイクの ID と量、メッセージから作る。
    /// モザイクの数とメッセージの長さが、書ける範囲に収まらなければ弾く。
    ///
    /// メッセージの長さの上限はネットワークの設定（`maxMessageSize`）で決まるので、ここでは確かめない。
    pub fn new(
        recipient_address: UnresolvedAddress,
        mosaics: BTreeMap<UnresolvedMosaicId, u64>,
        message: Vec<u8>,
    ) -> Result<Self, TransferError> {
        if mosaics.len() > u8::MAX as usize {
            return Err(TransferError::TooManyMosaics(mosaics.len()));
        }
        if message.len() > u16::MAX as usize {
            return Err(TransferError::MessageTooLong(message.len()));
        }
        Ok(Self {
            recipient_address,
            mosaics,
            message,
        })
    }

    pub fn recipient_address(&self) -> &UnresolvedAddress {
        &self.recipient_address
    }

    pub fn mosaics(&self) -> &BTreeMap<UnresolvedMosaicId, u64> {
        &self.mosaics
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// モザイクの並びより前の部分。受取人、メッセージの長さ、モザイクの数、予約。
    const FIXED_SIZE: usize = 24 + 2 + 1 + 1 + 4;

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.recipient_address.0);
        out.extend_from_slice(&(self.message.len() as u16).to_le_bytes());
        out.push(self.mosaics.len() as u8);
        out.extend_from_slice(&[0; 1 + 4]);
        for (id, amount) in &self.mosaics {
            out.extend_from_slice(&id.0.to_le_bytes());
            out.extend_from_slice(&amount.to_le_bytes());
        }
        out.extend_from_slice(&self.message);
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < Self::FIXED_SIZE {
            return Err(DecodeError::InvalidBodySize);
        }
        let mut reader = Reader(bytes);
        let recipient_address = UnresolvedAddress(reader.array());
        let message_size = reader.u16() as usize;
        let mosaics_count = reader.u8() as usize;
        if reader.u8() != 0 || reader.u32() != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        if reader.0.len() != mosaics_count * 16 + message_size {
            return Err(DecodeError::InvalidBodySize);
        }
        let mut mosaics = BTreeMap::new();
        for _ in 0..mosaics_count {
            let id = UnresolvedMosaicId(reader.u64());
            let amount = reader.u64();
            // 前のものより大きい ID だけを受け付ける
            if mosaics
                .last_key_value()
                .is_some_and(|(last, _)| *last >= id)
            {
                return Err(DecodeError::UnsortedMosaics);
            }
            mosaics.insert(id, amount);
        }
        Ok(Self {
            recipient_address,
            mosaics,
            message: reader.0.to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// モザイクの数が255を超える
    TooManyMosaics(usize),
    /// メッセージが65535バイトを超える
    MessageTooLong(usize),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyMosaics(count) => {
                write!(f, "モザイクは255種類までですが、{count} 種類ありました")
            }
            Self::MessageTooLong(length) => {
                write!(
                    f,
                    "メッセージは65535バイトまでですが、{length} バイトありました"
                )
            }
        }
    }
}

impl core::error::Error for TransferError {}

#[cfg(test)]
mod tests {
    use heika_core::key::PublicKey;
    use heika_core::network::NetworkIdentifier;

    use super::*;
    use crate::{Body, Transaction};

    const BODY: usize = 128;

    fn transfer(mosaics: &[(u64, u64)], message: &[u8]) -> Transfer {
        Transfer::new(
            UnresolvedAddress([0x98; 24]),
            mosaics
                .iter()
                .map(|&(id, amount)| (UnresolvedMosaicId(id), amount))
                .collect(),
            message.to_vec(),
        )
        .unwrap()
    }

    fn to_bytes(transfer: Transfer) -> Vec<u8> {
        Transaction::new(
            PublicKey([0x11; 32]),
            NetworkIdentifier::TESTNET,
            0,
            0,
            Body::Transfer(transfer),
        )
        .to_bytes()
    }

    #[test]
    fn points_an_address_at_a_namespace() {
        let id = NamespaceId(0xE74B_99BA_41F4_AFEE);
        let alias = UnresolvedAddress::from_namespace_id(id, NetworkIdentifier::MAINNET);
        assert_eq!(alias.0[0], 0x69);
        assert_eq!(alias.0[1..9], id.0.to_le_bytes());
        assert_eq!(alias.0[9..], [0; 15]);
        assert_eq!(alias.namespace_id(), Some(id));
        assert_eq!(alias.address(), None);

        let address = UnresolvedAddress::from(Address([0x68; 24]));
        assert_eq!(address.namespace_id(), None);
        assert_eq!(address.address(), Some(Address([0x68; 24])));
    }

    #[test]
    fn tells_mosaics_from_namespaces_by_the_high_bit() {
        let namespace = UnresolvedMosaicId::from(NamespaceId(0xE74B_99BA_41F4_AFEE));
        assert_eq!(
            namespace.namespace_id(),
            Some(NamespaceId(0xE74B_99BA_41F4_AFEE))
        );
        assert_eq!(namespace.mosaic_id(), None);
        let mosaic = UnresolvedMosaicId::from(MosaicId(0x6BED_913F_A202_23F8));
        assert_eq!(mosaic.namespace_id(), None);
        assert_eq!(mosaic.mosaic_id(), Some(MosaicId(0x6BED_913F_A202_23F8)));
    }

    #[test]
    fn writes_the_catbuffer_layout() {
        let bytes = to_bytes(transfer(&[(0x0102, 3)], b"hi"));
        assert_eq!(bytes.len(), BODY + 32 + 16 + 2);
        assert_eq!(bytes[110..112], [0x54, 0x41]);
        assert_eq!(bytes[BODY..BODY + 24], [0x98; 24]);
        assert_eq!(bytes[BODY + 24..BODY + 32], [2, 0, 1, 0, 0, 0, 0, 0]);
        assert_eq!(bytes[BODY + 32..BODY + 40], [2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bytes[BODY + 40..BODY + 48], [3, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bytes[BODY + 48..], *b"hi");
    }

    #[test]
    fn writes_mosaics_in_ascending_order_of_id() {
        let bytes = to_bytes(transfer(&[(9, 1), (2, 1), (5, 1)], b""));
        let ids: Vec<u8> = (0..3).map(|index| bytes[BODY + 32 + index * 16]).collect();
        assert_eq!(ids, [2, 5, 9]);
    }

    #[test]
    fn round_trips() {
        for transfer in [
            transfer(&[], b""),
            transfer(&[(1, 2), (u64::MAX, 3)], b""),
            transfer(&[], &[0xFE; 300]),
        ] {
            let bytes = to_bytes(transfer.clone());
            let transaction = Transaction::from_bytes(&bytes).unwrap();
            assert_eq!(transaction.body, Body::Transfer(transfer));
        }
    }

    #[test]
    fn rejects_unsorted_or_duplicate_mosaics() {
        let bytes = to_bytes(transfer(&[(1, 0), (2, 0)], b""));
        for second in [1u8, 0] {
            let mut bytes = bytes.clone();
            bytes[BODY + 48] = second;
            assert_eq!(
                Transaction::from_bytes(&bytes),
                Err(DecodeError::UnsortedMosaics),
                "second id {second}"
            );
        }
    }

    #[test]
    fn rejects_non_zero_reserved_bytes() {
        for offset in [BODY + 27, BODY + 28] {
            let mut bytes = to_bytes(transfer(&[], b""));
            bytes[offset] = 1;
            assert_eq!(
                Transaction::from_bytes(&bytes),
                Err(DecodeError::NonZeroReserved),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn rejects_a_body_of_the_wrong_size() {
        let bytes = to_bytes(transfer(&[(1, 0)], b"hi"));
        for (index, mut bytes) in [
            bytes[..BODY + 31].to_vec(),
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), &[0]].concat(),
        ]
        .into_iter()
        .enumerate()
        {
            let size = bytes.len() as u32;
            bytes[..4].copy_from_slice(&size.to_le_bytes());
            assert_eq!(
                Transaction::from_bytes(&bytes),
                Err(DecodeError::InvalidBodySize),
                "case {index}"
            );
        }
    }

    #[test]
    fn refuses_what_cannot_be_written() {
        let mosaics = (0..256).map(|id| (UnresolvedMosaicId(id), 1)).collect();
        assert_eq!(
            Transfer::new(UnresolvedAddress([0; 24]), mosaics, Vec::new()),
            Err(TransferError::TooManyMosaics(256))
        );
        assert_eq!(
            Transfer::new(UnresolvedAddress([0; 24]), BTreeMap::new(), vec![0; 65536]),
            Err(TransferError::MessageTooLong(65536))
        );
    }
}
