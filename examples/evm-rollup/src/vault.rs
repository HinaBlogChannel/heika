//! 橋の預かり口座。[examples/evm-bridge](../../evm-bridge) の Symbol の側と同じ作り。
//!
//! 預かり口座は、見張り役で分けて持つ鍵（グループ鍵）だけを連署者にした 1-of-1 のマルチシグにする。
//! 預かり口座の鍵は作ったあとに捨てるので、預かった XYM を動かせるのはグループ鍵だけになる。
//!
//! 手数料は、アグリゲートに署名するグループ鍵のアカウントが払う。そのぶんの XYM（手数料の予算）は、
//! 預かり口座を作るときに、アグリゲートの中の送金で渡しておく。

use crate::rollup::Withdrawal;
use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, MultisigAccountModification, Transaction, Transfer,
    UnresolvedAddress, UnresolvedMosaicId,
};

/// 入金のメッセージ（先頭の 1 バイトが 0 の平文）から、`0x` で始まる EVM のアドレスを読む
pub fn evm_recipient(message: &[u8]) -> Option<[u8; 20]> {
    let text = std::str::from_utf8(message.strip_prefix(&[0]).unwrap_or(message)).ok()?;
    let hex = text.trim().strip_prefix("0x")?;
    if hex.len() != 40 {
        return None;
    }
    let mut address = [0; 20];
    for (index, byte) in address.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(address)
}

/// 払い出しの送金のメッセージ。引き出しの番号を入れて、同じ引き出しで 2 回払わないようにする
pub fn withdrawal_message(id: u64) -> Vec<u8> {
    [&[0][..], format!("withdraw:{id}").as_bytes()].concat()
}

/// [`withdrawal_message`] から番号を読む
pub fn withdrawal_id(message: &[u8]) -> Option<u64> {
    std::str::from_utf8(message.strip_prefix(&[0])?)
        .ok()?
        .strip_prefix("withdraw:")?
        .parse()
        .ok()
}

/// 通貨（XYM）だけの送金
fn transfer(
    parameters: &NetworkParameters,
    recipient: Address,
    amount: u64,
    message: Vec<u8>,
) -> Body {
    Body::Transfer(
        Transfer::new(
            UnresolvedAddress::from(recipient),
            [(UnresolvedMosaicId(parameters.currency_mosaic_id), amount)].into(),
            message,
        )
        .expect("one mosaic and a short message"),
    )
}

/// アグリゲートを作り、手数料を `cosignatures` 個の連署のぶんまで見込んで決める
fn aggregate(
    parameters: &NetworkParameters,
    signer: PublicKey,
    deadline: u64,
    fee_multiplier: u32,
    cosignatures: usize,
    transactions: Vec<(PublicKey, Body)>,
) -> Transaction {
    let transactions = transactions
        .into_iter()
        .map(|(signer, body)| EmbeddedTransaction::new(signer, parameters.identifier, body))
        .collect();
    let mut transaction = Transaction::new(
        signer,
        parameters.identifier,
        0,
        deadline,
        Body::AggregateComplete(Aggregate::new(transactions).expect("not nested")),
    );
    transaction.fee = transaction.fee_for(fee_multiplier, cosignatures);
    transaction
}

/// 預かり口座を作る。預かり口座の鍵で署名し、グループ鍵が連署する（連署者に加わるには、加わる側の同意が要る）。
///
/// - 預かり口座から、グループ鍵のアカウントに手数料の予算 `budget` を送る
/// - 預かり口座を、グループ鍵だけを連署者にした 1-of-1 のマルチシグにする
pub fn setup(
    parameters: &NetworkParameters,
    deadline: u64,
    fee_multiplier: u32,
    vault: PublicKey,
    group: PublicKey,
    budget: u64,
) -> Transaction {
    let group_address = Address::from_public_key(&group, parameters.identifier);
    let multisig = Body::MultisigAccountModification(MultisigAccountModification {
        min_removal_delta: 1,
        min_approval_delta: 1,
        address_additions: vec![UnresolvedAddress::from(group_address)]
            .try_into()
            .expect("one address"),
        address_deletions: Vec::new().try_into().expect("no address"),
    });
    aggregate(
        parameters,
        vault,
        deadline,
        fee_multiplier,
        1,
        vec![
            (
                vault,
                transfer(parameters, group_address, budget, Vec::new()),
            ),
            (vault, multisig),
        ],
    )
}

/// 預かり口座から、引き出しの宛先に送る。グループ鍵が署名する
pub fn withdraw(
    parameters: &NetworkParameters,
    deadline: u64,
    fee_multiplier: u32,
    vault: PublicKey,
    group: PublicKey,
    withdrawal: &Withdrawal,
) -> Transaction {
    aggregate(
        parameters,
        group,
        deadline,
        fee_multiplier,
        0,
        vec![(
            vault,
            transfer(
                parameters,
                withdrawal.recipient,
                withdrawal.amount,
                withdrawal_message(withdrawal.id),
            ),
        )],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_evm_recipients() {
        let address = [0xab; 20];
        let text = format!("\0 0x{} ", "ab".repeat(20));
        assert_eq!(evm_recipient(text.as_bytes()), Some(address));
        assert_eq!(evm_recipient(b"\0hello"), None);
        assert_eq!(evm_recipient(b"\x000x1234"), None);
    }

    #[test]
    fn withdrawal_ids_round_trip() {
        assert_eq!(withdrawal_id(&withdrawal_message(42)), Some(42));
        assert_eq!(withdrawal_id(b"\0burn:42"), None);
        assert_eq!(withdrawal_id(b"withdraw:42"), None);
    }
}
