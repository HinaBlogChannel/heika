//! 署名したトランザクションを REST に送り、ブロックに入ったことを確かめる。
//!
//! 送るのは `PUT /transactions` に [`announce_body`] を載せるだけで、REST は受け取ったことしか返さない。
//! 入ったことは、こちらで控えたトランザクションから求めた葉が、ブロックの TransactionsHash に経路でつながることで確かめる
//! （[`verify_inclusion_parts`]）。ブロックの署名と StateHash も確かめるので、残高と同じく、信じたままなのは
//! そのブロックが正しいチェーンのものかどうかだけ。
//!
//! 入っていないことは、1つの REST からは確かめられない。REST が隠しているのか、本当にないのかを区別できないので、
//! [`find_inclusion`] が `None` を返しても、それは「この REST には見えていない」でしかない。
//! 期限を過ぎたトランザクションは、もう二度とブロックに入らないので、入らないことが確定するのは期限を過ぎてから。
//! [`TransactionStatus`] は早く知るための目安で、確かめたものではない。

use std::future::IntoFuture;

use heika_block::Block;
use heika_core::merkle::{MerklePathNode, verify_path};
use heika_core::network::GenerationHashSeed;
use heika_transaction::Transaction;
use serde::Deserialize;

use crate::RestError;
use crate::balance::{BalanceError, Mismatch, VerifyError, optional, required};
use crate::block::BlockInfo;
use crate::merkle::MerkleProofInfo;

/// 送るパス。`PUT` で [`announce_body`] を送る
pub const ANNOUNCE_PATH: &str = "/transactions";

/// `PUT /transactions` の本文（`{"payload":"16進"}`）
pub fn announce_body(transaction: &Transaction) -> String {
    let payload: String = transaction
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    format!(r#"{{"payload":"{payload}"}}"#)
}

/// `/transactionStatus/{hash}` が返す `TransactionStatusDTO`。REST が言っているだけで、確かめたものではない
#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionStatus {
    /// `unconfirmed`、`confirmed`、`failed` のどれか
    pub group: String,
    /// `Success` か、失敗したわけ（`Failure_Core_Insufficient_Balance` など）
    pub code: Option<String>,
    pub hash: String,
    pub deadline: Option<String>,
    pub height: Option<String>,
}

/// 入ったことを確かめたトランザクション
#[derive(Clone, Debug)]
pub struct VerifiedInclusion {
    /// 入っていたブロック。署名と StateHash は確かめてある
    pub block: Block,
}

/// 承認されたトランザクションを聞くパス。`/transactions/confirmed/{hash}`
fn confirmed_path(transaction: &Transaction, seed: &GenerationHashSeed) -> String {
    format!("/transactions/confirmed/{}", transaction.hash(seed))
}

fn merkle_path(height: u64, transaction: &Transaction, seed: &GenerationHashSeed) -> String {
    format!(
        "/blocks/{height}/transactions/{}/merkle",
        transaction.hash(seed)
    )
}

/// 取ってきたブロックと経路で、`transaction` がそのブロックに入ったことを確かめる。通信はしない。
///
/// 葉は REST の答えではなく、`transaction` から求める。なので、REST が別のトランザクションの経路を返しても通らない。
pub fn verify_inclusion_parts(
    transaction: &Transaction,
    seed: &GenerationHashSeed,
    block: &BlockInfo,
    proof: &MerkleProofInfo,
) -> Result<VerifiedInclusion, VerifyError> {
    let verified = block.verify().map_err(|error| invalid("ブロック", error))?;
    if verified.network != transaction.network {
        return Err(VerifyError::WrongNetwork);
    }
    // Nemesis の TransactionsHash は、ふつうの葉で作られていない（merkle の説明を見る）
    if verified.height <= 1 {
        return Err(invalid(
            "トランザクション",
            RestError::InvalidValue { field: "height" },
        ));
    }
    let path = Vec::<MerklePathNode>::try_from(proof)
        .map_err(|error| invalid("トランザクション", error))?;
    let leaf = transaction.merkle_component_hash(seed);
    if !verify_path(&leaf, &path, &verified.transactions_hash) {
        return Err(invalid(
            "トランザクション",
            RestError::Mismatch {
                field: "merklePath",
            },
        ));
    }
    Ok(VerifiedInclusion { block: verified })
}

/// `transaction` が入ったブロックを REST に聞いて、入ったことを確かめる。
///
/// REST が「まだ承認されていない」と答えれば `Ok(None)`。これは確かめたものではない（このモジュールの説明を見る）。
/// `fetch` は [`crate::balance::verify_balance`] と同じもの。ブロックも経路も REST の DB から取るので、
/// 残高のように DB とノードが食い違うことはなく、取り直さない。
pub async fn find_inclusion<F, R, E>(
    transaction: &Transaction,
    seed: &GenerationHashSeed,
    mut fetch: F,
) -> Result<Option<VerifiedInclusion>, BalanceError<E>>
where
    F: FnMut(String) -> R,
    R: IntoFuture<Output = Result<Option<Vec<u8>>, E>>,
{
    #[derive(Deserialize)]
    struct Confirmed {
        meta: Meta,
    }
    #[derive(Deserialize)]
    struct Meta {
        height: String,
    }
    let path = confirmed_path(transaction, seed);
    let Some(confirmed) = optional::<Confirmed, _, _, _>(&mut fetch, path).await? else {
        return Ok(None);
    };
    let height = crate::number(&confirmed.meta.height, "meta.height")
        .map_err(|error| BalanceError::Verify(invalid("トランザクション", error)))?;
    let block: BlockInfo = required(&mut fetch, format!("/blocks/{height}")).await?;
    let proof: MerkleProofInfo =
        required(&mut fetch, merkle_path(height, transaction, seed)).await?;
    verify_inclusion_parts(transaction, seed, &block, &proof)
        .map(Some)
        .map_err(BalanceError::Verify)
}

fn invalid(what: &str, error: RestError) -> VerifyError {
    VerifyError::Invalid {
        what: what.to_owned(),
        error: Mismatch::Rest(error),
    }
}
