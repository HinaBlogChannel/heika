//! 原子的な交換の、Symbol 側。「この連署をチェーンに出すと、相手にこの秘密がばれる」仕掛けを、アダプター署名で作る。
//!
//! - [`adaptor`]: Ed25519 のアダプター署名。署名する鍵とは別の点 `T = tG` を仕込み、`t` を知る人だけが完成でき、
//!   完成した署名がチェーンに出ると、仕込んだ人が `t` を取り出せる
//! - [`setup`]、[`payout`]: 交換に使うアグリゲート。使い捨ての 2-of-2 のアカウントに、ちょうどの額を入れてから
//!   マルチシグにするものと、そこから全額を1人に送るもの（受け取りと返金に使う）
//!
//! 相手のチェーン（Monero など）は扱わない。そちらで要るのは、2 人が半分ずつ持つ秘密 `a`、`b` だけなので、
//! ここではスカラーとして作り、`a + b` がそろうことを確かめるところまでにする。

pub mod adaptor;

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkIdentifier;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, MultisigAccountModification, Transaction, Transfer,
    UnresolvedAddress, UnresolvedMosaicId,
};

/// 2-of-2 のアカウントに `amount` を入れて、`alice` と `bob` の 2-of-2 にするアグリゲート。外側の署名者は
/// Alice で、手数料も払う。連署は、2-of-2 になるアカウント自身（`joint`）と、連署者に加わる Bob の2つが要る
pub fn setup(
    network: NetworkIdentifier,
    alice: &PublicKey,
    bob: &PublicKey,
    joint: &PublicKey,
    currency: u64,
    amount: u64,
    deadline: u64,
) -> Transaction {
    let address = |key: &PublicKey| UnresolvedAddress::from(Address::from_public_key(key, network));
    let fund = Transfer::new(
        address(joint),
        [(UnresolvedMosaicId(currency), amount)].into(),
        Vec::new(),
    )
    .expect("one mosaic and no message");
    let modification = MultisigAccountModification {
        min_removal_delta: 2,
        min_approval_delta: 2,
        address_additions: vec![address(alice), address(bob)]
            .try_into()
            .expect("two addresses"),
        address_deletions: Vec::new().try_into().expect("no addresses"),
    };
    let aggregate = Aggregate::new(vec![
        EmbeddedTransaction::new(*alice, network, Body::Transfer(fund)),
        EmbeddedTransaction::new(
            *joint,
            network,
            Body::MultisigAccountModification(modification),
        ),
    ])
    .expect("no nested aggregates");
    Transaction::new(
        *alice,
        network,
        0,
        deadline,
        Body::AggregateComplete(aggregate),
    )
}

/// 2-of-2 のアカウント `joint` から、`to` に `amount` を送るアグリゲート。外側の署名者は受け取る人
/// （`to`）で、手数料も払う。外側の署名は 2-of-2 の連署者の1人ぶんに数えられるので、要る連署はもう1人ぶん
pub fn payout(
    network: NetworkIdentifier,
    to: &PublicKey,
    joint: &PublicKey,
    currency: u64,
    amount: u64,
    deadline: u64,
) -> Transaction {
    let transfer = Transfer::new(
        UnresolvedAddress::from(Address::from_public_key(to, network)),
        [(UnresolvedMosaicId(currency), amount)].into(),
        Vec::new(),
    )
    .expect("one mosaic and no message");
    let aggregate = Aggregate::new(vec![EmbeddedTransaction::new(
        *joint,
        network,
        Body::Transfer(transfer),
    )])
    .expect("no nested aggregates");
    Transaction::new(
        *to,
        network,
        0,
        deadline,
        Body::AggregateComplete(aggregate),
    )
}
