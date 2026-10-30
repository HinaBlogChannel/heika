//! できた鍵で署名する。署名に要る人数ぶんの参加者が、このプロセスの中で FROST の 2 回のやりとりをする。
//!
//! 黙る人がいても署名を続けるには ROAST が要る（[examples/roast](../../roast)）。この例では、DKG を見せるのが
//! 目的なので、署名する人は全員が応じるものとする。

use std::collections::BTreeMap;

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{SigningPackage, aggregate, round1, round2};
use heika_core::signature::Signature;
use rand_core::{CryptoRng, RngCore};

use crate::wire::E;

/// `signers` の分け前で `message` に署名する。FROST の署名は、ふつうの Ed25519 の署名になる
pub fn sign<R: RngCore + CryptoRng>(
    signers: &[&KeyPackage<E>],
    public: &PublicKeyPackage<E>,
    message: &[u8],
    rng: &mut R,
) -> Result<Signature, String> {
    let (nonces, commitments): (BTreeMap<_, _>, BTreeMap<_, _>) = signers
        .iter()
        .map(|signer| {
            let (nonces, commitments) = round1::commit(signer.signing_share(), &mut *rng);
            (
                (*signer.identifier(), nonces),
                (*signer.identifier(), commitments),
            )
        })
        .unzip();
    let package = SigningPackage::new(commitments, message);
    let shares = signers
        .iter()
        .map(|signer| {
            let identifier = signer.identifier();
            round2::sign(&package, &nonces[identifier], signer).map(|share| (*identifier, share))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
        .map_err(|error| error.to_string())?;
    let signature = aggregate(&package, &shares, public).map_err(|error| error.to_string())?;
    let bytes = signature.serialize().map_err(|error| error.to_string())?;
    Ok(Signature(
        bytes.try_into().map_err(|_| "64 バイトではありません")?,
    ))
}
