//! アカウントの残高を、最新のブロックの StateHash まで確かめる。
//!
//! 1つの REST から、次のものを取って突き合わせる。
//! 1. `/chain/info` の高さの `/blocks/{height}`。[`BlockInfo::verify`] で、署名と、9本の根からの StateHash を確かめる
//! 2. `/accounts/{address}` と `/accounts/{address}/merkle`。アカウントの状態を組み直したハッシュが、状態の経路をたどった葉と合い、
//!    1 の根につながることを確かめる。経路が「ない」ことを示せば、まだチェーンに載っていないアカウントとする
//! 3. 持っているモザイクごとに `/mosaics/{id}` と `/mosaics/{id}/merkle`。可分性を、同じように 1 の根で確かめる
//!
//! 信じたままなのは、そのブロックが正しいチェーンのものかどうか。ブロックの中の辻褄までは確かめる。
//!
//! 確かめるところ（[`verify_balance_parts`]）は、取ってきたものを受け取るだけの同期の計算で、通信も待ちもしない。
//! 取る順番と取り直し（[`verify_balance`]）は、取ってくる関数と間をおく関数を受け取る非同期の関数にして、
//! どう取るか（同期の HTTP、スレッド、ブラウザの `fetch`）と、どう待つか（スレッドを眠らせる、タイマー）は呼び出し側に任せる。

use std::fmt;
use std::future::IntoFuture;

use heika_block::Block;
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::patricia::{self, SubCache};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::RestError;
use crate::block::BlockInfo;
use crate::merkle::MerkleStateInfo;
use crate::state::{AccountInfo, AccountJson, MosaicInfo, id};

/// 根が合わなかったときに、最初から取り直す回数の上限
const ATTEMPTS: usize = 5;

/// 確かめた残高
#[derive(Clone, Debug)]
pub struct VerifiedBalance {
    pub address: Address,
    /// 突き合わせたブロック。署名と StateHash は確かめてある
    pub block: Block,
    /// チェーンに載っていなければ `None`。載っていないことも、状態の経路で確かめてある
    pub account: Option<VerifiedAccount>,
}

/// 確かめたアカウントの状態
#[derive(Clone, Debug)]
pub struct VerifiedAccount {
    /// REST が返したアカウントの状態。組み直したハッシュが状態の木の葉と合ったもの
    pub state: AccountJson,
    /// 持っているモザイク。REST が返した順
    pub mosaics: Vec<VerifiedMosaic>,
}

/// 持っているモザイクの量
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VerifiedMosaic {
    pub id: u64,
    /// 可分性を考えない、整数の量
    pub amount: u64,
    /// 可分性。モザイクの定義が状態の木にもうなければ `None`。ないことは確かめてある
    pub divisibility: Option<u8>,
}

impl VerifiedMosaic {
    /// 可分性の桁で区切った量（`1234.567890` など）。定義がもうなく、可分性がわからなければ `None`
    pub fn decimal(&self) -> Option<String> {
        let divisibility = usize::from(self.divisibility?);
        if divisibility == 0 {
            return Some(self.amount.to_string());
        }
        let digits = format!("{:0>width$}", self.amount, width = divisibility + 1);
        let (whole, fraction) = digits.split_at(digits.len() - divisibility);
        Some(format!("{whole}.{fraction}"))
    }
}

/// 1つのモザイクの定義について取ってきたもの
#[derive(Clone, Debug)]
pub struct MosaicParts {
    pub id: u64,
    /// `/mosaics/{id}`。404 なら `None`
    pub info: Option<MosaicInfo>,
    /// `/mosaics/{id}/merkle`
    pub proof: MerkleStateInfo,
}

/// 取ってきたものを確かめたら、合わなかった
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VerifyError {
    /// アドレスのネットワークが、ブロックのネットワークと違う
    WrongNetwork,
    /// ノードが状態のハッシュを使っていないので、状態を確かめられない
    NoStateHash,
    /// アカウントが持っているモザイクの定義が、渡されていない
    MissingMosaic(u64),
    /// `what`（「アカウント」など）を確かめたら合わなかった。取るあいだにブロックが進んでも起きる
    Invalid { what: String, error: Mismatch },
}

/// 合わなかったところ
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Mismatch {
    /// 組み直せないか、求め直した値が合わない
    Rest(RestError),
    /// REST の状態のハッシュが、状態の経路の葉と違う
    StateHash,
    /// REST は状態を返したのに、状態の経路はないことを示している
    UnexpectedAbsence,
    /// REST は状態を返さなかったのに、状態の経路はあることを示している
    UnexpectedPresence,
    /// 問い合わせたものと違うものが返ってきた
    WrongEntity,
}

/// 残高を確かめられなかった。`E` は取ってくる関数のエラー
#[derive(Debug)]
pub enum BalanceError<E> {
    /// 取ってこられなかった
    Fetch(E),
    /// 要るものが REST になかった
    NotFound { path: String },
    /// JSON として読めなかった
    Json { path: String, error: String },
    /// 確かめたら合わなかった。取り直しても合わなかったときは、最後のもの
    Verify(VerifyError),
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rest(error) => error.fmt(f),
            Self::StateHash => f.write_str("状態のハッシュが、状態の経路の葉と合いません"),
            Self::UnexpectedAbsence => {
                f.write_str("REST は状態を返しましたが、状態の経路はないことを示しています")
            }
            Self::UnexpectedPresence => {
                f.write_str("REST は状態を返しませんでしたが、状態の経路はあることを示しています")
            }
            Self::WrongEntity => f.write_str("問い合わせたものと違うものが返ってきました"),
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongNetwork => {
                f.write_str("アドレスのネットワークが、REST のネットワークと違います")
            }
            Self::NoStateHash => f.write_str(
                "この REST のノードは状態のハッシュを使っていないので、状態を確かめられません",
            ),
            Self::MissingMosaic(id) => write!(f, "モザイク {id:016X} の定義がありません"),
            Self::Invalid { what, error } => write!(f, "{what}を確かめられません: {error}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl<E: fmt::Display> fmt::Display for BalanceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(error) => error.fmt(f),
            Self::NotFound { path } => write!(f, "REST に {path} がありません"),
            Self::Json { path, error } => write!(f, "{path} を読めません: {error}"),
            Self::Verify(error) => error.fmt(f),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for BalanceError<E> {}

/// アカウントについて取るパス。`/accounts/{address}` と `/accounts/{address}/merkle`
pub fn account_paths(address: &Address) -> [String; 2] {
    let path = format!("/accounts/{address}");
    let merkle = format!("{path}/merkle");
    [path, merkle]
}

/// モザイクの定義について取るパス。`/mosaics/{id}` と `/mosaics/{id}/merkle`
pub fn mosaic_paths(id: u64) -> [String; 2] {
    let path = format!("/mosaics/{id:016X}");
    let merkle = format!("{path}/merkle");
    [path, merkle]
}

/// アカウントが持っているモザイクの ID。これらの定義を取って、[`verify_balance_parts`] に渡す
pub fn mosaic_ids(account: &AccountInfo) -> Result<Vec<u64>, RestError> {
    account
        .account
        .mosaics
        .iter()
        .map(|balance| id(&balance.id, "mosaics.id"))
        .collect()
}

/// 取ってきたものを突き合わせて、残高を確かめる。通信はしない。
///
/// `account` は `/accounts/{address}`（404 なら `None`）、`account_proof` はその経路、
/// `mosaics` はアカウントが持っているモザイク（[`mosaic_ids`]）の定義と経路。
/// どれも `block` と同じ時点のものでないと、根が合わずに [`VerifyError::Invalid`] になる。
pub fn verify_balance_parts(
    address: &Address,
    block: &BlockInfo,
    account: Option<&AccountInfo>,
    account_proof: &MerkleStateInfo,
    mosaics: &[MosaicParts],
) -> Result<VerifiedBalance, VerifyError> {
    let verified_block = block.verify().map_err(|error| invalid("ブロック", error))?;
    if verified_block.network != address.network() {
        return Err(VerifyError::WrongNetwork);
    }
    let roots = block
        .sub_cache_merkle_roots()
        .map_err(|error| invalid("ブロック", error))?;
    if roots.is_empty() {
        return Err(VerifyError::NoStateHash);
    }

    let key = patricia::address_key(address);
    let leaf = prove(
        "アカウント",
        account_proof,
        &key,
        &roots[SubCache::AccountState.index()],
    )?;
    let account = match (account, leaf) {
        (None, None) => None,
        (None, Some(_)) => return Err(mismatch("アカウント", Mismatch::UnexpectedPresence)),
        (Some(_), None) => return Err(mismatch("アカウント", Mismatch::UnexpectedAbsence)),
        (Some(info), Some(leaf)) => {
            let state = &info.account;
            let rest = |error| invalid("アカウント", error);
            if state.tree_key().map_err(rest)? != key {
                return Err(mismatch("アカウント", Mismatch::WrongEntity));
            }
            if state.state_hash().map_err(rest)? != leaf {
                return Err(mismatch("アカウント", Mismatch::StateHash));
            }
            let mut verified = Vec::with_capacity(state.mosaics.len());
            for (mosaic_id, balance) in mosaic_ids(info)
                .map_err(rest)?
                .into_iter()
                .zip(&state.mosaics)
            {
                let parts = mosaics
                    .iter()
                    .find(|parts| parts.id == mosaic_id)
                    .ok_or(VerifyError::MissingMosaic(mosaic_id))?;
                verified.push(VerifiedMosaic {
                    id: mosaic_id,
                    amount: crate::number(&balance.amount, "mosaics.amount").map_err(rest)?,
                    divisibility: verify_divisibility(parts, &roots)?,
                });
            }
            Some(VerifiedAccount {
                state: state.clone(),
                mosaics: verified,
            })
        }
    };
    Ok(VerifiedBalance {
        address: *address,
        block: verified_block,
        account,
    })
}

/// モザイクの定義を状態の木で確かめて、可分性を返す
fn verify_divisibility(parts: &MosaicParts, roots: &[Hash256]) -> Result<Option<u8>, VerifyError> {
    let what = format!("モザイク {:016X} ", parts.id);
    let key = patricia::id_key(parts.id);
    let leaf = prove(&what, &parts.proof, &key, &roots[SubCache::Mosaic.index()])?;
    match (&parts.info, leaf) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(mismatch(&what, Mismatch::UnexpectedPresence)),
        (Some(_), None) => Err(mismatch(&what, Mismatch::UnexpectedAbsence)),
        (Some(info), Some(leaf)) => {
            let state = &info.mosaic;
            if state.tree_key().map_err(|error| invalid(&what, error))? != key {
                return Err(mismatch(&what, Mismatch::WrongEntity));
            }
            if state.state_hash().map_err(|error| invalid(&what, error))? != leaf {
                return Err(mismatch(&what, Mismatch::StateHash));
            }
            Ok(Some(state.divisibility))
        }
    }
}

/// `address` の残高を、REST の最新のブロックの StateHash まで確かめる。
///
/// `fetch` は REST のパス（`/chain/info` など）を受け取り、本文のバイト列を返す future（[`IntoFuture`]）を返す。
/// 404 なら `Ok(None)`、それ以外の失敗は `Err` にする。中身が同期なら [`std::future::ready`] で返せばよい。
/// タイムアウトや、問い合わせの数を絞られたときの待ちは `fetch` の側でする。
///
/// 根が合わなければ、`pause` が返す future を待ってから、最初から取り直す。
/// REST は高さとブロックを DB から返すが、状態の経路はノードにその場で問い合わせるので、
/// ノードが新しいブロックを取り込んでから DB に書かれるまでのあいだは、経路だけが新しくなって根が合わない。
/// 待たずに取り直すと DB が追いつく前に取り直し終えてしまうので、数秒おくとよい。
pub async fn verify_balance<F, R, P, S, E>(
    address: &Address,
    mut fetch: F,
    mut pause: P,
) -> Result<VerifiedBalance, BalanceError<E>>
where
    F: FnMut(String) -> R,
    R: IntoFuture<Output = Result<Option<Vec<u8>>, E>>,
    P: FnMut() -> S,
    S: IntoFuture<Output = ()>,
{
    let mut attempt = 0;
    loop {
        attempt += 1;
        match attempt_once(address, &mut fetch).await {
            Err(BalanceError::Verify(VerifyError::Invalid { .. })) if attempt < ATTEMPTS => {
                pause().await;
            }
            result => return result,
        }
    }
}

async fn attempt_once<F, R, E>(
    address: &Address,
    fetch: &mut F,
) -> Result<VerifiedBalance, BalanceError<E>>
where
    F: FnMut(String) -> R,
    R: IntoFuture<Output = Result<Option<Vec<u8>>, E>>,
{
    #[derive(Deserialize)]
    struct ChainInfo {
        height: String,
    }
    let chain: ChainInfo = required(fetch, "/chain/info".to_owned()).await?;
    let block: BlockInfo = required(fetch, format!("/blocks/{}", chain.height)).await?;
    // 違うネットワークなら、アカウントを問い合わせる前にやめる
    if block.block.network != address.network().0 {
        return Err(BalanceError::Verify(VerifyError::WrongNetwork));
    }
    let [account_path, account_merkle] = account_paths(address);
    let account: Option<AccountInfo> = optional(fetch, account_path).await?;
    let account_proof: MerkleStateInfo = required(fetch, account_merkle).await?;

    let ids = match &account {
        Some(info) => {
            mosaic_ids(info).map_err(|error| BalanceError::Verify(invalid("アカウント", error)))?
        }
        None => Vec::new(),
    };
    let mut mosaics = Vec::with_capacity(ids.len());
    for id in ids {
        let [path, merkle] = mosaic_paths(id);
        mosaics.push(MosaicParts {
            id,
            info: optional(fetch, path).await?,
            proof: required(fetch, merkle).await?,
        });
    }
    verify_balance_parts(address, &block, account.as_ref(), &account_proof, &mosaics)
        .map_err(BalanceError::Verify)
}

fn prove(
    what: &str,
    proof: &MerkleStateInfo,
    key: &Hash256,
    root: &Hash256,
) -> Result<Option<Hash256>, VerifyError> {
    proof.prove(key, root).map_err(|error| invalid(what, error))
}

fn invalid(what: &str, error: RestError) -> VerifyError {
    mismatch(what, Mismatch::Rest(error))
}

fn mismatch(what: &str, error: Mismatch) -> VerifyError {
    VerifyError::Invalid {
        what: what.to_owned(),
        error,
    }
}

async fn optional<T, F, R, E>(fetch: &mut F, path: String) -> Result<Option<T>, BalanceError<E>>
where
    T: DeserializeOwned,
    F: FnMut(String) -> R,
    R: IntoFuture<Output = Result<Option<Vec<u8>>, E>>,
{
    let Some(body) = fetch(path.clone()).await.map_err(BalanceError::Fetch)? else {
        return Ok(None);
    };
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| BalanceError::Json {
            path,
            error: error.to_string(),
        })
}

async fn required<T, F, R, E>(fetch: &mut F, path: String) -> Result<T, BalanceError<E>>
where
    T: DeserializeOwned,
    F: FnMut(String) -> R,
    R: IntoFuture<Output = Result<Option<Vec<u8>>, E>>,
{
    match optional(fetch, path.clone()).await? {
        Some(value) => Ok(value),
        None => Err(BalanceError::NotFound { path }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mosaic(amount: u64, divisibility: Option<u8>) -> VerifiedMosaic {
        VerifiedMosaic {
            id: 1,
            amount,
            divisibility,
        }
    }

    #[test]
    fn splits_amounts_by_divisibility() {
        let decimal = |amount, divisibility| mosaic(amount, divisibility).decimal();
        assert_eq!(decimal(1_234_567_890, Some(6)).unwrap(), "1234.567890");
        assert_eq!(decimal(5, Some(6)).unwrap(), "0.000005");
        assert_eq!(decimal(0, Some(2)).unwrap(), "0.00");
        assert_eq!(decimal(42, Some(0)).unwrap(), "42");
        // 0. と、255 桁
        assert_eq!(decimal(u64::MAX, Some(255)).unwrap().len(), 2 + 255);
        assert_eq!(decimal(7, None), None);
    }
}
