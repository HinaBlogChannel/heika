//! ファイナライズの投票の段取り。catapult の `extensions/finalization` の、`FinalizationOrchestrator`、
//! `FinalizationStageAdvancer`、`FinalizationMessageFactory` と、`FinalizationOrchestratorService` の
//! エポックの進め方と確定（finalizer）。
//!
//! ラウンド（エポック、ポイント）ごとに、prevote を出し、precommit を出し、ラウンドの結果がもう変わらなくなったら
//! 次のポイントに進む。いつ出すかは [`stage`]、出す順と出したかどうかは [`orchestrator`]、エポックの切り替えと、
//! 集まったメッセージからの確定と証明は [`epoch`]。
//!
//! 投票の鍵がなくても同じ段取りで進める。メッセージを作れないだけで、ラウンドは進み、集まったメッセージから確定と
//! 証明を出せる（catapult も、鍵で署名できないときは作れなかったとログに出すだけで進む）。
//!
//! メッセージを集めて数えるのは `heika_block::finalization::aggregator`。ここはストレージにも時計にも触らず、
//! 時刻（ネットワークの時刻、ミリ秒）とチェーンの様子を引数でもらう。

pub mod epoch;
pub mod orchestrator;
pub mod prevote;
pub mod stage;

/// 段取りの設定。catapult の config-finalization.properties と、config-network.properties の `votingSetGrouping`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// `stepDuration`（ミリ秒）。prevote はこの1倍、precommit は2倍待てば、結果が決まっていなくても出す
    pub step_duration: u64,
    /// `prevoteBlocksMultiple`。prevote の最後の高さを、この倍数にそろえる
    pub prevote_blocks_multiple: u64,
    /// `maxHashesPerPoint`
    pub max_hashes_per_point: u64,
    /// `votingSetGrouping`
    pub voting_set_grouping: u64,
}

impl Settings {
    /// メインネットの値（stepDuration 5m、prevoteBlocksMultiple 4、maxHashesPerPoint 256、votingSetGrouping 1440）
    pub const MAINNET: Self = Self {
        step_duration: 5 * 60 * 1000,
        prevote_blocks_multiple: 4,
        max_hashes_per_point: 256,
        voting_set_grouping: 1440,
    };
}
