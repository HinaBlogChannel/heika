//! Symbol の側。預かり口座を作り、入金を拾い、見張り役の鍵で引き出し、連署者を入れ替える。
//!
//! 預かり口座は、見張り役で分けて持つ鍵（グループ鍵）だけを連署者にした 1-of-1 のマルチシグにする。
//! 預かり口座の鍵は作ったあとに捨てるので、預かった XYM を動かせるのはグループ鍵だけになる。
//! 見張り役が入れ替わるときは、新しいグループ鍵に連署者を差し替える。預かった XYM は動かさなくていい。
//!
//! 手数料は、アグリゲートに署名するグループ鍵のアカウントが払う。そのぶんの XYM（手数料の予算）は、
//! 預かり口座を作るときと連署者を入れ替えるときに、アグリゲートの中の送金で渡しておく。

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use heika_core::address::Address;
use heika_core::key::PublicKey;
use heika_core::network::NetworkParameters;
use heika_node::config::Manifest;
use heika_node::driver;
use heika_rest::node::{ChainInfoJson, TransactionFeesJson};
use heika_rest::send::{ANNOUNCE_PATH, TransactionStatus, announce_body};
use heika_rest::state::AccountInfo;
use heika_rest::transaction::TransactionInfo;
use heika_transaction::{
    Aggregate, Body, EmbeddedTransaction, MultisigAccountModification, Transaction, Transfer,
    UnresolvedAddress, UnresolvedMosaicId,
};
use serde::Deserialize;

/// トランザクションの期限。Symbol の上限は 6 時間だが、署名にかかる時間を見込んでも 1 時間で足りる
pub const LIFETIME: Duration = Duration::from_secs(60 * 60);

/// 送金の種類（`TRANSFER`）
const TRANSFER_TYPE: u16 = 0x4154;

/// 検索の 1 ページの件数
const PAGE_SIZE: usize = 100;

static AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
});

/// 預かり口座への入金
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    /// 入金のトランザクションのハッシュ。EVM の側で、同じ入金で 2 回発行しないために使う
    pub hash: [u8; 32],
    pub height: u64,
    /// XYM の最小単位
    pub amount: u64,
    /// 発行先の EVM のアドレス（メッセージに書いてあったもの）
    pub to: [u8; 20],
}

/// メッセージ（先頭の 1 バイトが 0 の平文）から、`0x` で始まる EVM のアドレスを読む
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

/// 引き出しの送金のメッセージ。EVM の Burn の番号を入れて、同じ Burn で 2 回払わないようにする
pub fn burn_message(id: u64) -> Vec<u8> {
    [&[0][..], format!("burn:{id}").as_bytes()].concat()
}

fn burn_id(message: &[u8]) -> Option<u64> {
    std::str::from_utf8(message.strip_prefix(&[0])?)
        .ok()?
        .strip_prefix("burn:")?
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

fn multisig(additions: Vec<Address>, deletions: Vec<Address>, delta: i8) -> Body {
    let addresses = |addresses: Vec<Address>| {
        addresses
            .into_iter()
            .map(UnresolvedAddress::from)
            .collect::<Vec<_>>()
            .try_into()
            .expect("one address")
    };
    Body::MultisigAccountModification(MultisigAccountModification {
        min_removal_delta: delta,
        min_approval_delta: delta,
        address_additions: addresses(additions),
        address_deletions: addresses(deletions),
    })
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
            (vault, multisig(vec![group_address], Vec::new(), 1)),
        ],
    )
}

/// 引き出し。EVM の Burn 1 つぶん
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Withdrawal {
    /// Burn の番号
    pub id: u64,
    pub recipient: Address,
    /// XYM の最小単位
    pub amount: u64,
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
                burn_message(withdrawal.id),
            ),
        )],
    )
}

/// 連署者を、今のグループ鍵 `old` から新しいグループ鍵 `new` に差し替える。`old` が署名し、`new` が連署する。
/// 残っている手数料の予算 `budget` も、`new` のアカウントに移す
pub fn rotate(
    parameters: &NetworkParameters,
    deadline: u64,
    fee_multiplier: u32,
    vault: PublicKey,
    old: PublicKey,
    new: PublicKey,
    budget: u64,
) -> Transaction {
    let old_address = Address::from_public_key(&old, parameters.identifier);
    let new_address = Address::from_public_key(&new, parameters.identifier);
    aggregate(
        parameters,
        old,
        deadline,
        fee_multiplier,
        1,
        vec![
            (old, transfer(parameters, new_address, budget, Vec::new())),
            (vault, multisig(vec![new_address], vec![old_address], 0)),
        ],
    )
}

/// ノードの REST
pub struct Chain {
    pub parameters: &'static NetworkParameters,
    /// `http://127.0.0.1:3000` など
    rest: String,
}

#[derive(Deserialize)]
struct Page {
    data: Vec<TransactionInfo>,
}

impl Chain {
    /// `heika experimental peer start` と同じ設定から、ネットワークと REST（最初の `rest` の口）を決める
    pub fn load(config: &Path) -> Result<Self, String> {
        let manifest = Manifest::load(config).map_err(|error| error.to_string())?;
        let parameters =
            driver::network_parameters(&manifest.spec).map_err(|error| error.to_string())?;
        let listen = &manifest
            .spec
            .rest
            .first()
            .ok_or("ノードの設定に rest がありません")?
            .address;
        Ok(Self {
            parameters,
            rest: format!("http://{}", listen.replace("0.0.0.0", "127.0.0.1")),
        })
    }

    pub fn address(&self, key: &PublicKey) -> Address {
        Address::from_public_key(key, self.parameters.identifier)
    }

    /// 今から [`LIFETIME`] 後の期限
    pub fn deadline(&self) -> Result<u64, String> {
        self.parameters
            .timestamp_at(SystemTime::now() + LIFETIME)
            .map(|timestamp| timestamp.0)
            .ok_or_else(|| "時計がネットワークのエポックより前になっています".to_owned())
    }

    /// 直近のブロックの中央値。ノードの下限より低ければ下限
    pub fn fee_multiplier(&self) -> Result<u32, String> {
        let fees: TransactionFeesJson = self.json("/network/fees/transaction")?;
        Ok(fees.median_fee_multiplier.max(fees.min_fee_multiplier))
    }

    /// `address` の XYM。まだ誰も知らないアカウントなら 0
    pub fn balance(&self, address: &Address) -> Result<u64, String> {
        let Some(body) = self.get(&format!("/accounts/{address}"))? else {
            return Ok(0);
        };
        let info: AccountInfo = serde_json::from_slice(&body).map_err(|error| error.to_string())?;
        Ok(info
            .account
            .mosaics
            .iter()
            .filter(|mosaic| {
                u64::from_str_radix(&mosaic.id, 16).ok() == Some(self.parameters.currency_mosaic_id)
            })
            .filter_map(|mosaic| mosaic.amount.parse::<u64>().ok())
            .sum())
    }

    /// ファイナライズされた高さ
    pub fn finalized_height(&self) -> Result<u64, String> {
        let info: ChainInfoJson = self.json("/chain/info")?;
        info.latest_finalized_block
            .height
            .parse()
            .map_err(|_| "ファイナライズされた高さが読めません".to_owned())
    }

    /// 高さ `from` から `to` までの、`vault` への入金。メッセージに EVM のアドレスがないものは飛ばす
    pub fn deposits(&self, vault: &Address, from: u64, to: u64) -> Result<Vec<Deposit>, String> {
        let mut deposits = Vec::new();
        for info in self.search(&format!(
            "recipientAddress={vault}&type={TRANSFER_TYPE}&fromHeight={from}&toHeight={to}"
        ))? {
            let body = &info.transaction.body;
            let (Some(hash), Some(height), Some(message)) =
                (&info.meta.hash, &info.meta.height, &body.message)
            else {
                continue;
            };
            let Some(to) = hex(message).and_then(|message| evm_recipient(&message)) else {
                continue;
            };
            let amount = body
                .mosaics
                .iter()
                .flatten()
                .filter(|mosaic| {
                    u64::from_str_radix(&mosaic.id, 16).ok()
                        == Some(self.parameters.currency_mosaic_id)
                })
                .filter_map(|mosaic| mosaic.amount.parse::<u64>().ok())
                .sum();
            let (Some(hash), Ok(height)) = (
                hex(hash).and_then(|hash| hash.try_into().ok()),
                height.parse(),
            ) else {
                continue;
            };
            if amount > 0 {
                deposits.push(Deposit {
                    hash,
                    height,
                    amount,
                    to,
                });
            }
        }
        Ok(deposits)
    }

    /// 預かり口座から、もう払った Burn の番号
    pub fn paid_burns(&self, vault: &PublicKey) -> Result<BTreeSet<u64>, String> {
        Ok(self
            .search(&format!(
                "signerPublicKey={vault}&embedded=true&type={TRANSFER_TYPE}"
            ))?
            .iter()
            .filter_map(|info| info.transaction.body.message.as_deref())
            .filter_map(|message| burn_id(&hex(message)?))
            .collect())
    }

    /// 承認されたトランザクションを、古いものから全部
    fn search(&self, query: &str) -> Result<Vec<TransactionInfo>, String> {
        let mut found = Vec::new();
        for number in 1.. {
            let page: Page = self.json(&format!(
                "/transactions/confirmed?{query}&order=asc&pageSize={PAGE_SIZE}&pageNumber={number}"
            ))?;
            let last = page.data.len() < PAGE_SIZE;
            found.extend(page.data);
            if last {
                break;
            }
        }
        Ok(found)
    }

    pub fn announce(&self, transaction: &Transaction) -> Result<(), String> {
        let response = AGENT
            .put(&format!("{}{ANNOUNCE_PATH}", self.rest))
            .header("Content-Type", "application/json")
            .send(announce_body(transaction))
            .map_err(|error| format!("REST に送れませんでした: {error}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "REST が受け付けませんでした: {}",
                response.status()
            ));
        }
        Ok(())
    }

    /// 承認されるか弾かれるまで、`timeout` だけ待つ。承認された高さを返す
    pub fn confirm(&self, transaction: &Transaction, timeout: Duration) -> Result<u64, String> {
        let path = TransactionStatus::path(transaction, &self.parameters.generation_hash_seed);
        let started = Instant::now();
        while started.elapsed() < timeout {
            if let Some(body) = self.get(&path)? {
                let status = TransactionStatus::from_slice(&body)?;
                match (status.group.as_str(), status.height) {
                    ("confirmed", Some(height)) => {
                        return height
                            .parse()
                            .map_err(|_| format!("承認された高さが読めません: {height}"));
                    }
                    ("failed", _) => {
                        return Err(format!("弾かれました: {}", status.code.unwrap_or_default()));
                    }
                    _ => {}
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!(
            "{} 秒待っても承認されませんでした",
            timeout.as_secs()
        ))
    }

    fn json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let body = self.get(path)?.ok_or_else(|| format!("{path}: 404"))?;
        serde_json::from_slice(&body).map_err(|error| format!("{path}: {error}"))
    }

    fn get(&self, path: &str) -> Result<Option<Vec<u8>>, String> {
        let mut response = AGENT
            .get(&format!("{}{path}", self.rest))
            .call()
            .map_err(|error| format!("{path}: {error}"))?;
        match response.status().as_u16() {
            200 => response
                .body_mut()
                .read_to_vec()
                .map(Some)
                .map_err(|error| format!("{path}: {error}")),
            404 => Ok(None),
            status => Err(format!("{path}: {status}")),
        }
    }
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use frost_ed25519::Ed25519Sha512;
    use heika_core::key::PrivateKey;
    use heika_core::network::NetworkIdentifier;
    use heika_core::signature::Signature;
    use heika_transaction::Cosignature;
    use rand_core::OsRng;

    use super::*;
    use crate::roast::{Holder, deal, receive, sign_together};

    #[test]
    fn reads_evm_recipient_from_plain_message() {
        let expected = [0xAB; 20];
        let text = format!("0x{}", "ab".repeat(20));
        assert_eq!(
            evm_recipient(&[&[0][..], text.as_bytes()].concat()),
            Some(expected)
        );
        assert_eq!(
            evm_recipient(text.to_uppercase().replace("0X", "0x").as_bytes()),
            Some(expected)
        );
        assert_eq!(evm_recipient(b"\0hello"), None);
        assert_eq!(
            evm_recipient(format!("\00x{}", "ab".repeat(19)).as_bytes()),
            None
        );
    }

    #[test]
    fn burn_message_round_trips() {
        assert_eq!(burn_id(&burn_message(42)), Some(42));
        assert_eq!(burn_id(b"\0burn:x"), None);
    }

    /// 見張り役（3 人のうち 2 人）で、アグリゲートの署名と連署を作る
    fn group_sign(
        holders: &mut [Holder<Ed25519Sha512>],
        public: &Arc<frost_core::keys::PublicKeyPackage<Ed25519Sha512>>,
        message: &[u8],
    ) -> Signature {
        let signature = sign_together(
            holders,
            public,
            &[1; 3],
            2,
            message,
            &mut OsRng,
            |_, holder, package| holder.sign(package).ok(),
        )
        .unwrap();
        Signature(signature.serialize().unwrap().try_into().unwrap())
    }

    fn group() -> (
        Vec<Holder<Ed25519Sha512>>,
        Arc<frost_core::keys::PublicKeyPackage<Ed25519Sha512>>,
        PublicKey,
    ) {
        let (shares, public) = deal::<Ed25519Sha512, _>(&[1; 3], 2, &mut OsRng).unwrap();
        let key = PublicKey(
            public
                .verifying_key()
                .serialize()
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let holders = shares
            .into_iter()
            .map(|shares| Holder::new(receive(shares).unwrap()))
            .collect();
        (holders, Arc::new(public), key)
    }

    #[test]
    fn group_signs_setup_withdraw_and_rotate() {
        let parameters = NetworkParameters::from_identifier(NetworkIdentifier(152)).unwrap();
        let seed = &parameters.generation_hash_seed;
        let vault_key = PrivateKey::generate().unwrap();
        let vault = PublicKey::from_private_key(&vault_key);
        let (mut holders, public, key) = group();

        // 預かり口座を作る：預かり口座の鍵で署名し、グループ鍵が連署する
        let mut transaction = setup(parameters, 1, 100, vault, key, 1_000_000);
        transaction.sign(&vault_key, seed).unwrap();
        let hash = transaction.hash(seed);
        let cosignature = Cosignature {
            signer_public_key: key,
            signature: group_sign(&mut holders, &public, &hash.0),
        };
        let Body::AggregateComplete(aggregate) = &mut transaction.body else {
            unreachable!()
        };
        aggregate.add_cosignature(cosignature);
        assert!(transaction.verify(seed));
        assert!(transaction.verify_cosignatures(seed));
        assert_eq!(transaction.hash(seed), hash);

        // 引き出す：グループ鍵だけで署名する
        let mut transaction = withdraw(
            parameters,
            1,
            100,
            vault,
            key,
            &Withdrawal {
                id: 7,
                recipient: Address([0x98; 24]),
                amount: 5,
            },
        );
        transaction.signature =
            group_sign(&mut holders, &public, &transaction.signing_payload(seed));
        assert!(transaction.verify(seed));

        // 入れ替える：今のグループ鍵が署名し、新しいグループ鍵が連署する
        let (mut new_holders, new_public, new_key) = group();
        let mut transaction = rotate(parameters, 1, 100, vault, key, new_key, 500_000);
        transaction.signature =
            group_sign(&mut holders, &public, &transaction.signing_payload(seed));
        let hash = transaction.hash(seed);
        let cosignature = Cosignature {
            signer_public_key: new_key,
            signature: group_sign(&mut new_holders, &new_public, &hash.0),
        };
        let Body::AggregateComplete(aggregate) = &mut transaction.body else {
            unreachable!()
        };
        aggregate.add_cosignature(cosignature);
        assert!(transaction.verify(seed));
        assert!(transaction.verify_cosignatures(seed));
    }
}
