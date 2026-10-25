//! 預けない交換。注文は署名済みのアグリゲートで出し、ハーベスターが自分のブロックの中で約定させる。
//!
//! - 注文: メイカーは注文ごとにランダムな鍵 P を作り、「メイカー → P に出すもの」「P → メイカーに欲しいもの」
//!   「メイカー → P に手数料の XYM」の3つを入れた AggregateComplete に署名する。それを P の秘密鍵と一緒に、
//!   誰も鍵を持たない掲示板のアドレス（[`board`]）あての送金のメッセージに入れて出す
//! - 約定: ハーベスターは、自分のブロックで「ノード → P に欲しいもの」「注文（P の連署を付ける）」「P → ノードに
//!   出されたものと手数料」を続けて並べる。ほかの人はそのあいだに入れないので、P に置いたものを抜かれない
//! - P の鍵は公開なので、誰でも P をマルチシグにしたり制限をかけたりして、その注文を取り消せる。盗むことはできない。
//!   注文ごとに P を変えるので、取り消すには注文の数だけ手数料がかかる

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use heika_chain::produce::{Assemble, Slot};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkParameters;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, Transaction, Transfer, UnresolvedAddress,
    UnresolvedMosaicId,
};
use sha3::{Digest, Sha3_256};

/// 注文のメッセージの頭。メッセージの種類の 0（平文）、1（暗号文）、0xFE（委任の要求）と重ならないようにする
pub const MAGIC: [u8; 4] = [0xD3, b'I', b'D', b'X'];
/// 注文のメッセージの版
pub const VERSION: u8 = 1;
/// 掲示板の公開鍵の元。この文字列の SHA3-256 を公開鍵とみなすので、対になる秘密鍵は誰も知らない
const BOARD_SEED: &[u8] = b"heika intent-dex board v1";
/// 1つの注文を約定させようとする高さの数の上限。返したブロックが弾かれても、フックには知らされないので数で打ち切る。
/// 同じ高さで何度呼ばれても、1回と数える
const MAX_TRIES: u32 = 3;

/// 注文を出す掲示板のアドレス。鍵を持つ人がいないので、誰も受け取りの制限をかけられない
pub fn board(parameters: &NetworkParameters) -> Address {
    let public_key = PublicKey(Sha3_256::digest(BOARD_SEED).into());
    Address::from_public_key(&public_key, parameters.identifier)
}

/// モザイクとその量（最小単位）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Amount {
    pub mosaic: UnresolvedMosaicId,
    pub amount: u64,
}

/// 注文の中身
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    pub maker: Address,
    /// メイカーが出すもの
    pub give: Amount,
    /// メイカーが欲しいもの
    pub get: Amount,
    /// 約定させた人に払う XYM
    pub tip: u64,
}

/// 注文。P の秘密鍵と、メイカーが署名したアグリゲート（連署はまだない）
pub struct Order {
    pub key: PrivateKey,
    pub transaction: Transaction,
}

impl Order {
    /// `maker` が `key`（P）を相手に、`give` を出して `get` を受け取る注文を作る。最大手数料は、P の連署を足した
    /// 大きさに `fee_multiplier` を掛けたもの
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parameters: &NetworkParameters,
        maker: &PrivateKey,
        key: PrivateKey,
        give: Amount,
        get: Amount,
        tip: u64,
        fee_multiplier: u32,
        deadline: u64,
    ) -> Self {
        let network = parameters.identifier;
        let maker_public = PublicKey::from_private_key(maker);
        let maker_address = Address::from_public_key(&maker_public, network);
        let p_public = PublicKey::from_private_key(&key);
        let p_address = Address::from_public_key(&p_public, network);
        let transfer = |signer, to, amount: Amount| {
            EmbeddedTransaction::new(
                signer,
                network,
                Body::Transfer(single(to, amount).expect("one mosaic and no message")),
            )
        };
        let currency = Amount {
            mosaic: UnresolvedMosaicId(parameters.currency_mosaic_id),
            amount: tip,
        };
        let aggregate = Aggregate::new(vec![
            transfer(maker_public, p_address, give),
            transfer(p_public, maker_address, get),
            transfer(maker_public, p_address, currency),
        ])
        .expect("transfers are not aggregates");
        let mut transaction = Transaction::new(
            maker_public,
            network,
            0,
            deadline,
            Body::AggregateComplete(aggregate),
        );
        transaction.fee = transaction.fee_for(fee_multiplier, 1);
        transaction
            .sign(maker, &parameters.generation_hash_seed)
            .expect("the signer is the maker's public key");
        Self { key, transaction }
    }

    /// 掲示板あての送金に入れるメッセージ
    pub fn to_message(&self) -> Vec<u8> {
        let mut message = Vec::from(MAGIC);
        message.push(VERSION);
        message.extend_from_slice(self.key.as_bytes());
        message.extend_from_slice(&self.transaction.to_bytes());
        message
    }

    /// 掲示板の送金のメッセージから読む。誰でも書けるので、形が違うもの、署名が正しくないもの、P の鍵と中身が
    /// 合わないものは `None`
    pub fn from_message(parameters: &NetworkParameters, message: &[u8]) -> Option<Self> {
        let rest = message.strip_prefix(&MAGIC)?.strip_prefix(&[VERSION])?;
        let (key, transaction) = rest.split_first_chunk::<32>()?;
        let order = Self {
            key: PrivateKey::from_bytes(key),
            transaction: Transaction::from_bytes(transaction).ok()?,
        };
        if order.transaction.network != parameters.identifier
            || !order.transaction.verify(&parameters.generation_hash_seed)
        {
            return None;
        }
        order.terms(parameters)?;
        Some(order)
    }

    /// 注文の中身。決まった形（連署のない AggregateComplete に、メイカーと P のあいだの送金が3つ）でなければ `None`
    pub fn terms(&self, parameters: &NetworkParameters) -> Option<Terms> {
        let Body::AggregateComplete(aggregate) = &self.transaction.body else {
            return None;
        };
        let [give, get, tip] = aggregate.transactions() else {
            return None;
        };
        if !aggregate.cosignatures().is_empty() {
            return None;
        }
        let network = parameters.identifier;
        let maker = self.transaction.signer_public_key;
        let maker_address = Address::from_public_key(&maker, network);
        let p = PublicKey::from_private_key(&self.key);
        let p_address = Address::from_public_key(&p, network);
        let read = |embedded: &EmbeddedTransaction, signer: PublicKey, to: Address| {
            let Body::Transfer(transfer) = &embedded.body else {
                return None;
            };
            let [(mosaic, amount)] = transfer.mosaics().iter().collect::<Vec<_>>()[..] else {
                return None;
            };
            (embedded.signer_public_key == signer
                && transfer.recipient_address().address() == Some(to)
                && transfer.message().is_empty()
                && *amount > 0)
                .then_some(Amount {
                    mosaic: *mosaic,
                    amount: *amount,
                })
        };
        let give = read(give, maker, p_address)?;
        let get = read(get, p, maker_address)?;
        let tip = read(tip, maker, p_address)?;
        (give.mosaic != get.mosaic
            && tip.mosaic == UnresolvedMosaicId(parameters.currency_mosaic_id))
        .then_some(Terms {
            maker: maker_address,
            give,
            get,
            tip: tip.amount,
        })
    }

    /// 注文のハッシュ。連署はハッシュに入らないので、約定したものもこのハッシュで引ける
    pub fn hash(&self, parameters: &NetworkParameters) -> Hash256 {
        self.transaction.hash(&parameters.generation_hash_seed)
    }

    /// P のアドレス
    pub fn p_address(&self, parameters: &NetworkParameters) -> Address {
        Address::from_public_key(
            &PublicKey::from_private_key(&self.key),
            parameters.identifier,
        )
    }
}

/// モザイク1つだけの送金
fn single(to: Address, amount: Amount) -> Result<Transfer, heika_transaction::TransferError> {
    Transfer::new(
        UnresolvedAddress::from(to),
        BTreeMap::from([(amount.mosaic, amount.amount)]),
        Vec::new(),
    )
}

/// ノードの在庫で注文の相手になる。`sells` を出して `buys` を受け取る
pub struct Desk {
    /// 在庫を持つ鍵。ハーベストの鍵とは分け、残高に上限をかけておく
    key: PrivateKey,
    parameters: &'static NetworkParameters,
    pub buys: UnresolvedMosaicId,
    pub sells: UnresolvedMosaicId,
    /// `sells` を `price.1` 出すごとに、`buys` を少なくとも `price.0` 受け取る（最小単位どうし）
    pub price: (u64, u64),
    /// 1回に出す `sells` の上限
    pub max_lot: u64,
}

impl Desk {
    pub fn new(
        key: PrivateKey,
        parameters: &'static NetworkParameters,
        buys: UnresolvedMosaicId,
        sells: UnresolvedMosaicId,
        price: (u64, u64),
        max_lot: u64,
    ) -> Self {
        Self {
            key,
            parameters,
            buys,
            sells,
            price,
            max_lot,
        }
    }

    /// 在庫のアドレス
    pub fn address(&self) -> Address {
        Address::from_public_key(
            &PublicKey::from_private_key(&self.key),
            self.parameters.identifier,
        )
    }

    /// `slot` のブロックで `order` を約定させる3つ（貸す、注文、回収する）。値段や量が合わないもの、期限が
    /// 過ぎたもの、ブロックの手数料の倍率に最大手数料が届かないもの、手数料の XYM で回収の手数料を払えない
    /// ものは `None`
    pub fn fill(&self, slot: &Slot, order: &Order) -> Option<Vec<Vec<u8>>> {
        let parameters = self.parameters;
        let seed = &parameters.generation_hash_seed;
        let terms = order.terms(parameters)?;
        let (wanted, per) = self.price;
        if terms.give.mosaic != self.buys
            || terms.get.mosaic != self.sells
            || terms.get.amount > self.max_lot
            || u128::from(terms.give.amount) * u128::from(per)
                < u128::from(terms.get.amount) * u128::from(wanted)
            || order.transaction.deadline < slot.timestamp
        {
            return None;
        }
        let mut cosigned = order.transaction.clone();
        cosigned.cosign(&order.key, seed).ok()?;
        if cosigned.fee < cosigned.fee_for(slot.fee_multiplier, 0) {
            return None;
        }

        let network = parameters.identifier;
        let p_address = order.p_address(parameters);
        let signed = |key: &PrivateKey, to: Address, mosaics: BTreeMap<UnresolvedMosaicId, u64>| {
            let body = Transfer::new(UnresolvedAddress::from(to), mosaics, Vec::new())
                .expect("at most two mosaics and no message");
            let mut transaction = Transaction::new(
                PublicKey::from_private_key(key),
                network,
                0,
                slot.timestamp,
                Body::Transfer(body),
            );
            transaction.fee = transaction.fee_for(slot.fee_multiplier, 0);
            transaction
                .sign(key, seed)
                .expect("the signer is the key's public key");
            transaction
        };
        let lend = signed(
            &self.key,
            p_address,
            BTreeMap::from([(terms.get.mosaic, terms.get.amount)]),
        );
        // 額を変えても大きさは変わらないので、手数料を見込まない額で組んで手数料を求める
        let currency = UnresolvedMosaicId(parameters.currency_mosaic_id);
        let sweep = |tip: u64| {
            let mut mosaics = BTreeMap::from([(terms.give.mosaic, terms.give.amount)]);
            *mosaics.entry(currency).or_default() += tip;
            signed(&order.key, self.address(), mosaics)
        };
        let fee = sweep(terms.tip).fee;
        let left = terms.tip.checked_sub(fee).filter(|left| *left > 0)?;
        Some(vec![
            lend.to_bytes(),
            cosigned.to_bytes(),
            sweep(left).to_bytes(),
        ])
    }
}

/// 約定させられそうな注文の一覧と、試した高さの数と最後に試した高さ
#[derive(Default)]
struct Book {
    orders: Vec<Arc<Order>>,
    tries: HashMap<Hash256, (u32, u64)>,
}

/// 掲示板の注文を、自分のブロックで1つずつ約定させる。1つのブロックに1つだけにして、弾かれたときに
/// ほかの注文まで巻き込まないようにする
pub struct Solver {
    pub desk: Desk,
    book: Mutex<Book>,
}

impl Solver {
    pub fn new(desk: Desk) -> Self {
        Self {
            desk,
            book: Mutex::new(Book::default()),
        }
    }

    /// 約定させられそうな注文を入れ替える。試した回数は、残った注文の分だけ持ち越す
    pub fn replace(&self, orders: Vec<Arc<Order>>) {
        let parameters = self.desk.parameters;
        let mut book = self
            .book
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hashes: Vec<Hash256> = orders.iter().map(|order| order.hash(parameters)).collect();
        book.tries.retain(|hash, _| hashes.contains(hash));
        book.orders = orders;
    }

    /// `slot` のブロックで約定させる注文と、その3つ
    pub fn pick(&self, slot: &Slot) -> Option<(Arc<Order>, Vec<Vec<u8>>)> {
        let parameters = self.desk.parameters;
        let mut book = self
            .book
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Book { orders, tries } = &mut *book;
        orders.iter().find_map(|order| {
            let (count, last) = tries.entry(order.hash(parameters)).or_default();
            let again = *last == slot.height;
            if !again && *count >= MAX_TRIES {
                return None;
            }
            let filled = self.desk.fill(slot, order)?;
            if !again {
                (*count, *last) = (*count + 1, slot.height);
            }
            Some((Arc::clone(order), filled))
        })
    }
}

impl Assemble for Solver {
    fn assemble(&self, slot: &Slot, chosen: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        match self.pick(slot) {
            Some((_, filled)) => filled.into_iter().chain(chosen).collect(),
            None => chosen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMETERS: &NetworkParameters = &NetworkParameters::TESTNET;
    const TOKEN: UnresolvedMosaicId = UnresolvedMosaicId(0x1234_5678_9ABC_DEF0);

    fn xym() -> UnresolvedMosaicId {
        UnresolvedMosaicId(PARAMETERS.currency_mosaic_id)
    }

    fn maker() -> PrivateKey {
        PrivateKey::from_bytes(&[1; 32])
    }

    /// TOKEN を 50 出して XYM を 1000 受け取り、約定させた人に 0.1 XYM 払う注文
    fn order() -> Order {
        Order::new(
            PARAMETERS,
            &maker(),
            PrivateKey::from_bytes(&[2; 32]),
            Amount {
                mosaic: TOKEN,
                amount: 50,
            },
            Amount {
                mosaic: xym(),
                amount: 1000,
            },
            100_000,
            100,
            1_000_000,
        )
    }

    /// XYM を出して TOKEN を受け取る。XYM 20 につき TOKEN 1 以上
    fn desk() -> Desk {
        Desk::new(
            PrivateKey::from_bytes(&[3; 32]),
            PARAMETERS,
            TOKEN,
            xym(),
            (1, 20),
            10_000,
        )
    }

    fn slot() -> Slot {
        Slot {
            height: 100,
            timestamp: 999_000,
            signer: PublicKey::from_private_key(&PrivateKey::from_bytes(&[4; 32])),
            harvester: Address([5; 24]),
            beneficiary: Address([5; 24]),
            fee_multiplier: 10,
            inflation: 0,
            beneficiary_percentage: 0,
        }
    }

    fn transfer(bytes: &[u8]) -> (Transaction, Transfer) {
        let transaction = Transaction::from_bytes(bytes).unwrap();
        let Body::Transfer(transfer) = transaction.body.clone() else {
            panic!("not a transfer");
        };
        (transaction, transfer)
    }

    #[test]
    fn reads_back_an_order_from_its_message() {
        let order = order();
        let message = order.to_message();
        assert!(message.starts_with(&MAGIC));
        assert!(message.len() <= 1023, "{} bytes", message.len());
        let read = Order::from_message(PARAMETERS, &message).unwrap();
        assert_eq!(read.transaction, order.transaction);
        let terms = read.terms(PARAMETERS).unwrap();
        assert_eq!(
            terms.maker,
            Address::from_public_key(
                &PublicKey::from_private_key(&maker()),
                PARAMETERS.identifier
            )
        );
        assert_eq!((terms.give.mosaic, terms.give.amount), (TOKEN, 50));
        assert_eq!((terms.get.mosaic, terms.get.amount), (xym(), 1000));
        assert_eq!(terms.tip, 100_000);
    }

    #[test]
    fn ignores_messages_that_are_not_orders() {
        let message = order().to_message();
        assert!(Order::from_message(PARAMETERS, b"hello").is_none());
        assert!(Order::from_message(PARAMETERS, &message[..message.len() - 1]).is_none());
        // P の鍵が中身と合わない
        let mut other_key = message.clone();
        other_key[5] ^= 1;
        assert!(Order::from_message(PARAMETERS, &other_key).is_none());
        // 署名が合わない
        let mut tampered = message.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(Order::from_message(PARAMETERS, &tampered).is_none());
        // ほかのネットワーク
        assert!(Order::from_message(&NetworkParameters::MAINNET, &message).is_none());
    }

    #[test]
    fn fills_an_order_with_a_loan_the_order_and_a_sweep() {
        let order = order();
        let desk = desk();
        let slot = slot();
        let filled = desk.fill(&slot, &order).unwrap();
        assert_eq!(filled.len(), 3);
        let seed = &PARAMETERS.generation_hash_seed;
        let p = order.p_address(PARAMETERS);

        let (lend, body) = transfer(&filled[0]);
        assert!(lend.verify(seed));
        assert_eq!(lend.deadline, slot.timestamp);
        assert_eq!(lend.fee, filled[0].len() as u64 * 10);
        assert_eq!(body.recipient_address().address(), Some(p));
        assert_eq!(body.mosaics(), &BTreeMap::from([(xym(), 1000)]));

        let cosigned = Transaction::from_bytes(&filled[1]).unwrap();
        assert!(cosigned.verify(seed));
        assert!(cosigned.verify_cosignatures(seed));
        assert_eq!(cosigned.hash(seed), order.hash(PARAMETERS));

        let (sweep, body) = transfer(&filled[2]);
        assert!(sweep.verify(seed));
        assert_eq!(
            sweep.signer_public_key,
            PublicKey::from_private_key(&order.key)
        );
        assert_eq!(body.recipient_address().address(), Some(desk.address()));
        let fee = filled[2].len() as u64 * 10;
        assert_eq!(sweep.fee, fee);
        assert_eq!(
            body.mosaics(),
            &BTreeMap::from([(TOKEN, 50), (xym(), 100_000 - fee)])
        );
    }

    #[test]
    fn leaves_orders_it_does_not_want() {
        let order = order();
        let slot = slot();
        // 安すぎる: XYM 1000 に TOKEN 50 では、XYM 10 につき TOKEN 1 を求めると足りない
        let strict = Desk {
            price: (1, 10),
            ..desk()
        };
        assert!(strict.fill(&slot, &order).is_none());
        // 量が多すぎる
        let small = Desk {
            max_lot: 999,
            ..desk()
        };
        assert!(small.fill(&slot, &order).is_none());
        // 逆向き
        let reversed = Desk {
            buys: xym(),
            sells: TOKEN,
            ..desk()
        };
        assert!(reversed.fill(&slot, &order).is_none());
        // 期限が過ぎた
        let late = Slot {
            timestamp: 1_000_001,
            ..slot
        };
        assert!(desk().fill(&late, &order).is_none());
        // 最大手数料が、ブロックの倍率に届かない
        let expensive = Slot {
            fee_multiplier: 101,
            ..self::slot()
        };
        assert!(desk().fill(&expensive, &order).is_none());
    }

    #[test]
    fn tries_each_order_at_a_few_heights_and_one_per_block() {
        let solver = Solver::new(desk());
        let order = Arc::new(order());
        solver.replace(vec![Arc::clone(&order)]);
        let chosen = vec![vec![0; 10]];
        for height in 100..100 + u64::from(MAX_TRIES) {
            let slot = Slot { height, ..slot() };
            // 同じ高さで呼び直されても、1回と数える
            for _ in 0..2 {
                let assembled = solver.assemble(&slot, chosen.clone());
                assert_eq!(assembled.len(), 4);
                assert_eq!(assembled[3], chosen[0]);
            }
        }
        let slot = Slot {
            height: 200,
            ..slot()
        };
        assert_eq!(solver.assemble(&slot, chosen.clone()), chosen);
        // 一覧を入れ替えても、残った注文の回数は持ち越す
        solver.replace(vec![Arc::clone(&order)]);
        assert_eq!(solver.assemble(&slot, chosen.clone()), chosen);
    }

    #[test]
    fn the_board_has_a_fixed_address() {
        assert_eq!(board(PARAMETERS), board(PARAMETERS));
        assert_ne!(board(PARAMETERS), board(&NetworkParameters::MAINNET));
    }
}
