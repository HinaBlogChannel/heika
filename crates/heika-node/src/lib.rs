//! Symbol のノードを組み立てて動かす。チェーンの中核（heika-chain）とピアの意思決定（heika-peer）に、スレッド、
//! ソケット、保存（heika-store-redb）をつなぐ。

pub mod config;
pub mod keys;
