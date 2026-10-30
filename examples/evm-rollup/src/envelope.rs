//! EVM のトランザクションを、Symbol の転送のメッセージに包む。
//!
//! - Symbol のトランザクション 1 つに、EVM のトランザクションを 1 つ入れる
//! - メッセージの先頭に [`PREFIX`] を付け、その後ろに EIP-2718 の形のバイト列を入れる
//! - 1 つのメッセージに収まらなければ、アグリゲートの中の転送に分ける。読む側は、同じ Symbol のトランザクションの中で、
//!   受け箱に宛てた [`PREFIX`] 付きのメッセージを順につなげる
//!
//! アグリゲートは全部入るか全部入らないかなので、途中の欠片だけが載ることはない。

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;

/// メッセージの先頭。1 バイト目の 0 は平文のメッセージの印で、エクスプローラーでも平文として見える
pub const PREFIX: &[u8] = b"\0evm";

/// 受け箱のアドレス。チェーン ID のハッシュを公開鍵の代わりにして作るので、誰も秘密鍵を持っていない
pub fn inbox(chain_id: u64, network: NetworkIdentifier) -> Address {
    let seed = alloy_primitives::keccak256(format!("heika evm-rollup {chain_id}"));
    Address::from_public_key(&PublicKey(seed.0), network)
}

/// `transaction` を、メッセージ 1 つに `max_message` バイトまでのメッセージに分ける。`max_parts` 個を超えるなら `None`
pub fn wrap(transaction: &[u8], max_message: usize, max_parts: usize) -> Option<Vec<Vec<u8>>> {
    let room = max_message
        .checked_sub(PREFIX.len())
        .filter(|room| *room > 0)?;
    let parts: Vec<Vec<u8>> = transaction
        .chunks(room)
        .map(|chunk| [PREFIX, chunk].concat())
        .collect();
    (!parts.is_empty() && parts.len() <= max_parts).then_some(parts)
}

/// 同じ Symbol のトランザクションの中のメッセージを、順につなげる。[`PREFIX`] のないものは飛ばす
pub fn unwrap<'a>(messages: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    messages
        .into_iter()
        .filter_map(|message| message.strip_prefix(PREFIX))
        .flatten()
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_unwraps() {
        let transaction: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let parts = wrap(&transaction, 1024, 100).unwrap();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.len() <= 1024));
        assert_eq!(unwrap(parts.iter().map(Vec::as_slice)), transaction);
    }

    #[test]
    fn small_transaction_is_one_message() {
        let parts = wrap(&[1, 2, 3], 1024, 100).unwrap();
        assert_eq!(parts, vec![b"\0evm\x01\x02\x03".to_vec()]);
    }

    #[test]
    fn refuses_too_many_parts() {
        assert!(wrap(&[0; 1021], 1024, 1).is_none());
        assert!(wrap(&[0; 1020], 1024, 1).is_some());
        assert!(wrap(&[], 1024, 100).is_none());
    }

    #[test]
    fn skips_other_messages() {
        let other: &[u8] = b"\0hello";
        assert_eq!(unwrap([other, b"\0evm\x05", b"\0evm\x06"]), vec![5, 6]);
    }
}
