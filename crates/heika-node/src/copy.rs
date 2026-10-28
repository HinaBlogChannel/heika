//! 止めたノードの DB を、設定の残し方（`storage.mode`）で刈り込んで、新しいファイルに写す。
//!
//! アーカイブをライトにするとき、その場で刈り込むと、消すものが多くて書き直しも多く、ファイルも縮まない。
//! 残すものだけを写せば、写しは小さく、すぐにできる。`Archive` なら全部写すので、詰め直しになる。

use std::path::Path;

use heika_block::finalization::proof::proof_header;
use heika_chain::chain::Keep;
use heika_store_redb::{CopyBounds, Db};

use crate::config::Manifest;
use crate::driver::{NodeError, chain_config, keep, network_parameters};

/// `manifest` のノードの DB を、刈り込んで `directory` に写す。ノードを止めてから使う
pub fn copy_pruned(manifest: &Manifest, directory: &Path) -> Result<(), NodeError> {
    let spec = &manifest.spec;
    let config = chain_config(spec)?;
    let parameters = network_parameters(spec)?;
    let keep = keep(spec)?;
    let db = Db::open_read_only(&spec.data_directory).map_err(|error| {
        format!(
            "{} の DB を開けません（ノードを止めてください）: {error}",
            spec.data_directory.display()
        )
    })?;
    let finalized = match db.proofs_tip()? {
        0 => 1,
        epoch => proof_header(&db.proof(epoch)?.ok_or("しまった証明がありません")?)?.height,
    };
    let floor = db
        .checkpoint_at_or_below(finalized)?
        .map_or(0, |(height, _)| height);
    let prune = Keep::plan(keep, &config, parameters, finalized, floor);
    println!(
        "確定した高さ {finalized} をもとに、{} の残し方で写します",
        spec.storage.mode.name()
    );
    if let Some((state, trie)) = prune.history {
        println!(
            "状態の差分は高さ {} から、木のノードの差分は高さ {} から残します",
            state + 1,
            trie + 1
        );
    }
    if let Some((through, epoch)) = prune.blocks {
        println!(
            "ブロックとステートメントは高さ {} から、証明はエポック {epoch} から残します",
            through + 1
        );
    }
    if std::fs::read_dir(directory).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(format!("{} は空ではありません", directory.display()).into());
    }
    let target = Db::open(directory)?;
    let bounds = prune.history.map(|(state, trie)| CopyBounds {
        state,
        trie,
        statements: prune.blocks.map(|(through, _)| through),
        blocks: prune.blocks,
    });
    db.copy_to(&target, bounds, |table, rows| {
        println!("{table}: {rows} 行");
        true
    })?;
    println!("差分の索引を作ります");
    target.build_history(|table, height| {
        println!("{table} の索引: 高さ {height} まで");
        true
    })?;
    target.prune_checkpoints(prune.checkpoints_below)?;
    println!("{} に写しました", directory.display());
    Ok(())
}
