//! 即時還元。委任してくれた人の鍵で作ったブロックの先頭に、そのブロックで受取先に入る額の一部を、その人に
//! 返す転送を入れる。
//!
//! - 報酬はブロックのトランザクションを当てたあとに入るので、還元は受取先の手持ちから先に払い、同じブロックの
//!   最後に入る受取先の分で埋まる。受取先には、1 ブロック分の還元より多い残高が要る
//! - 期限をブロックの時刻にする。ほかの人のブロックには入らず、ブロックが巻き戻れば、還元も入れ直されずに消える
//! - 受取先の手持ちが足りなければ、ノードはそのブロックを還元なしで作る

use std::collections::BTreeMap;

use heika_chain::produce::{Assemble, Slot};
use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_transaction::{Body, Transaction, Transfer, UnresolvedAddress, UnresolvedMosaicId};

pub struct Rebate {
    /// 受取先の鍵
    key: PrivateKey,
    beneficiary: Address,
    parameters: &'static NetworkParameters,
    /// 受取先の分のうち、返す千分率
    permille: u64,
}

impl Rebate {
    /// 受取先の鍵 `key` で、受取先の分の `permille`‰ を返す
    pub fn new(key: PrivateKey, parameters: &'static NetworkParameters, permille: u64) -> Self {
        let beneficiary =
            Address::from_public_key(&PublicKey::from_private_key(&key), parameters.identifier);
        Self {
            key,
            beneficiary,
            parameters,
            permille: permille.min(1000),
        }
    }

    /// 還元を払う受取先。ノードの `beneficiary` をこれにする
    pub fn beneficiary(&self) -> Address {
        self.beneficiary
    }

    /// `slot` のブロックで、`chosen` の前に入れる還元（署名したもの）。受取先がほかのアドレスのブロックや、
    /// 受取先の分がないブロック、受取先が自分でハーベストしたブロックには入れない
    pub fn rebate(&self, slot: &Slot, chosen: &[Vec<u8>]) -> Option<Vec<u8>> {
        if slot.beneficiary != self.beneficiary || slot.harvester == self.beneficiary {
            return None;
        }
        // 額を変えても大きさは変わらないので、0 で組んだもので手数料と受取先の分を求める
        let transfer = |amount| {
            let mosaics = BTreeMap::from([(
                UnresolvedMosaicId(self.parameters.currency_mosaic_id),
                amount,
            )]);
            let body = Transfer::new(UnresolvedAddress::from(slot.harvester), mosaics, Vec::new())
                .expect("one mosaic and no message");
            Transaction::new(
                PublicKey::from_private_key(&self.key),
                self.parameters.identifier,
                0,
                slot.timestamp,
                Body::Transfer(body),
            )
        };
        let fee = transfer(0).fee_for(slot.fee_multiplier, 0);
        let all: Vec<Vec<u8>> = std::iter::once(transfer(0).to_bytes())
            .chain(chosen.iter().cloned())
            .collect();
        let amount = slot.beneficiary_amount(&all) * self.permille / 1000;
        if amount == 0 {
            return None;
        }
        let mut transaction = transfer(amount);
        transaction.fee = fee;
        transaction
            .sign(&self.key, &self.parameters.generation_hash_seed)
            .expect("the signer is the key's public key");
        Some(transaction.to_bytes())
    }
}

impl Assemble for Rebate {
    fn assemble(&self, slot: &Slot, chosen: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        match self.rebate(slot, &chosen) {
            Some(rebate) => std::iter::once(rebate).chain(chosen).collect(),
            None => chosen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(rebate: &Rebate) -> Slot {
        let delegator = PrivateKey::from_bytes(&[2; 32]);
        Slot {
            height: 100,
            timestamp: 123_456_789,
            signer: PublicKey::from_private_key(&PrivateKey::from_bytes(&[3; 32])),
            harvester: Address::from_public_key(
                &PublicKey::from_private_key(&delegator),
                rebate.parameters.identifier,
            ),
            beneficiary: rebate.beneficiary(),
            fee_multiplier: 100,
            inflation: 73_210_170,
            beneficiary_percentage: 25,
        }
    }

    #[test]
    fn pays_a_share_of_this_block_to_the_harvester_until_the_block_time() {
        let rebate = Rebate::new(
            PrivateKey::from_bytes(&[1; 32]),
            &NetworkParameters::TESTNET,
            500,
        );
        let slot = slot(&rebate);
        let chosen = vec![vec![0; 200]];
        let transactions = rebate.assemble(&slot, chosen.clone());
        assert_eq!(transactions.len(), 2);
        assert_eq!(transactions[1], chosen[0]);
        let paid = Transaction::from_bytes(&transactions[0]).unwrap();
        assert!(paid.verify(&NetworkParameters::TESTNET.generation_hash_seed));
        assert_eq!(paid.deadline, slot.timestamp);
        assert_eq!(paid.fee, transactions[0].len() as u64 * 100);
        let Body::Transfer(transfer) = &paid.body else {
            panic!("not a transfer");
        };
        assert_eq!(transfer.recipient_address().address(), Some(slot.harvester));
        // 還元と選んだものの手数料にインフレを足した 25% の半分
        let total = (transactions[0].len() as u64 + 200) * 100 + 73_210_170;
        let amount = transfer.mosaics().values().copied().sum::<u64>();
        assert_eq!(amount, total * 25 / 100 * 500 / 1000);
    }

    #[test]
    fn leaves_blocks_without_a_share_alone() {
        let rebate = Rebate::new(
            PrivateKey::from_bytes(&[1; 32]),
            &NetworkParameters::TESTNET,
            500,
        );
        let chosen = vec![vec![0; 200]];
        let others = Slot {
            beneficiary: Address([9; 24]),
            ..slot(&rebate)
        };
        assert_eq!(rebate.assemble(&others, chosen.clone()), chosen);
        let own = Slot {
            harvester: rebate.beneficiary(),
            ..slot(&rebate)
        };
        assert_eq!(rebate.assemble(&own, chosen.clone()), chosen);
        let none = Slot {
            beneficiary_percentage: 0,
            inflation: 0,
            ..slot(&rebate)
        };
        assert_eq!(rebate.assemble(&none, chosen.clone()), chosen);
    }
}
