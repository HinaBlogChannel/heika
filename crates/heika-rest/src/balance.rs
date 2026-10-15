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
//! 状態は取ったときの最新のものしかないので、取るあいだにブロックが進むと根が合わなくなる。
//! そのときは、最初から何回か取り直す。

use std::fmt;

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

/// ブロックが進んで根が合わなくなったときに、最初から取り直す回数の上限
const ATTEMPTS: usize = 3;

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

/// 残高を確かめられなかった。`E` は取ってくる関数のエラー
#[derive(Debug)]
pub enum BalanceError<E> {
    /// 取ってこられなかった
    Fetch(E),
    /// 要るものが REST になかった
    NotFound { path: String },
    /// JSON として読めなかった
    Json { path: String, error: String },
    /// アドレスのネットワークが、ブロックのネットワークと違う
    WrongNetwork,
    /// ノードが状態のハッシュを使っていないので、状態を確かめられない
    NoStateHash,
    /// 確かめたら合わなかった。取り直しても合わなかったときの、最後のもの
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

impl<E: fmt::Display> fmt::Display for BalanceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(error) => error.fmt(f),
            Self::NotFound { path } => write!(f, "REST に {path} がありません"),
            Self::Json { path, error } => write!(f, "{path} を読めません: {error}"),
            Self::WrongNetwork => {
                f.write_str("アドレスのネットワークが、REST のネットワークと違います")
            }
            Self::NoStateHash => f.write_str(
                "この REST のノードは状態のハッシュを使っていないので、状態を確かめられません",
            ),
            Self::Invalid { what, error } => write!(f, "{what}を確かめられません: {error}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for BalanceError<E> {}

/// `address` の残高を、REST の最新のブロックの StateHash まで確かめる。
///
/// `fetch` は REST のパス（`/chain/info` など）を受け取り、本文のバイト列を返す。
/// 404 なら `Ok(None)` を返す。それ以外の失敗は `Err` にする。
pub fn verify_balance<E>(
    address: &Address,
    mut fetch: impl FnMut(&str) -> Result<Option<Vec<u8>>, E>,
) -> Result<VerifiedBalance, BalanceError<E>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match attempt_once(address, &mut fetch) {
            Err(BalanceError::Invalid { .. }) if attempt < ATTEMPTS => continue,
            result => return result,
        }
    }
}

fn attempt_once<E>(
    address: &Address,
    fetch: &mut impl FnMut(&str) -> Result<Option<Vec<u8>>, E>,
) -> Result<VerifiedBalance, BalanceError<E>> {
    #[derive(Deserialize)]
    struct ChainInfo {
        height: String,
    }
    let chain: ChainInfo = required(fetch, "/chain/info")?;
    let block_info: BlockInfo = required(fetch, &format!("/blocks/{}", chain.height))?;
    let block = block_info
        .verify()
        .map_err(|error| invalid("ブロック", error))?;
    if block.network != address.network() {
        return Err(BalanceError::WrongNetwork);
    }
    let roots = block_info
        .sub_cache_merkle_roots()
        .map_err(|error| invalid("ブロック", error))?;
    if roots.is_empty() {
        return Err(BalanceError::NoStateHash);
    }

    let account_path = format!("/accounts/{address}");
    let account: Option<AccountInfo> = optional(fetch, &account_path)?;
    let proof: MerkleStateInfo = required(fetch, &format!("{account_path}/merkle"))?;
    let leaf = prove(
        "アカウント",
        &proof,
        &patricia::address_key(address),
        &roots[SubCache::AccountState.index()],
    )?;
    let account = match (account, leaf) {
        (None, None) => None,
        (None, Some(_)) => return Err(mismatch("アカウント", Mismatch::UnexpectedPresence)),
        (Some(_), None) => return Err(mismatch("アカウント", Mismatch::UnexpectedAbsence)),
        (Some(info), Some(leaf)) => {
            let state = info.account;
            if state
                .tree_key()
                .map_err(|error| invalid("アカウント", error))?
                != patricia::address_key(address)
            {
                return Err(mismatch("アカウント", Mismatch::WrongEntity));
            }
            if state
                .state_hash()
                .map_err(|error| invalid("アカウント", error))?
                != leaf
            {
                return Err(mismatch("アカウント", Mismatch::StateHash));
            }
            let mut mosaics = Vec::with_capacity(state.mosaics.len());
            for balance in &state.mosaics {
                let mosaic_id =
                    id(&balance.id, "mosaics.id").map_err(|error| invalid("アカウント", error))?;
                let amount = crate::number(&balance.amount, "mosaics.amount")
                    .map_err(|error| invalid("アカウント", error))?;
                let divisibility = verify_divisibility(fetch, mosaic_id, &roots)?;
                mosaics.push(VerifiedMosaic {
                    id: mosaic_id,
                    amount,
                    divisibility,
                });
            }
            Some(VerifiedAccount { state, mosaics })
        }
    };
    Ok(VerifiedBalance {
        address: *address,
        block,
        account,
    })
}

/// モザイクの定義を状態の木で確かめて、可分性を返す
fn verify_divisibility<E>(
    fetch: &mut impl FnMut(&str) -> Result<Option<Vec<u8>>, E>,
    mosaic_id: u64,
    roots: &[Hash256],
) -> Result<Option<u8>, BalanceError<E>> {
    let what = format!("モザイク {mosaic_id:016X} ");
    let path = format!("/mosaics/{mosaic_id:016X}");
    let mosaic: Option<MosaicInfo> = optional(fetch, &path)?;
    let proof: MerkleStateInfo = required(fetch, &format!("{path}/merkle"))?;
    let key = patricia::id_key(mosaic_id);
    let leaf = prove(&what, &proof, &key, &roots[SubCache::Mosaic.index()])?;
    match (mosaic, leaf) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(mismatch(&what, Mismatch::UnexpectedPresence)),
        (Some(_), None) => Err(mismatch(&what, Mismatch::UnexpectedAbsence)),
        (Some(info), Some(leaf)) => {
            let state = info.mosaic;
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

fn prove<E>(
    what: &str,
    proof: &MerkleStateInfo,
    key: &Hash256,
    root: &Hash256,
) -> Result<Option<Hash256>, BalanceError<E>> {
    proof.prove(key, root).map_err(|error| invalid(what, error))
}

fn invalid<E>(what: &str, error: RestError) -> BalanceError<E> {
    mismatch(what, Mismatch::Rest(error))
}

fn mismatch<E>(what: &str, error: Mismatch) -> BalanceError<E> {
    BalanceError::Invalid {
        what: what.to_owned(),
        error,
    }
}

fn optional<T: DeserializeOwned, E>(
    fetch: &mut impl FnMut(&str) -> Result<Option<Vec<u8>>, E>,
    path: &str,
) -> Result<Option<T>, BalanceError<E>> {
    let Some(body) = fetch(path).map_err(BalanceError::Fetch)? else {
        return Ok(None);
    };
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| BalanceError::Json {
            path: path.to_owned(),
            error: error.to_string(),
        })
}

fn required<T: DeserializeOwned, E>(
    fetch: &mut impl FnMut(&str) -> Result<Option<Vec<u8>>, E>,
    path: &str,
) -> Result<T, BalanceError<E>> {
    optional(fetch, path)?.ok_or_else(|| BalanceError::NotFound {
        path: path.to_owned(),
    })
}
