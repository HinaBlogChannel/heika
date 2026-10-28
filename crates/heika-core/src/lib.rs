//! Symbol の合意形成に関わる計算。ノードも同じ計算をしていて、間違えると合意から外れるもの。
//!
//! std がなくても、alloc があれば使える（`#![no_std]`）。OS の時刻とネットワーク時刻の行き来
//! （[`network::NetworkParameters::timestamp_at`] など）は、feature の `std`（既定）で入る。

#![cfg_attr(not(test), no_std)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod address;
mod base32;
mod ed25519;
pub mod hash;
#[cfg(feature = "hazmat")]
pub mod hazmat;
mod hex;
pub mod key;
pub mod merkle;
pub mod network;
pub mod patricia;
pub mod signature;
pub mod voting;
pub mod vrf;

pub use hex::ParseHexError;
