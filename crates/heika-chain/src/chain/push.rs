//! 接続してきたピアが押し付けたブロックを使う。時刻がまだなら、来るまで持っておく。

use super::*;

impl<S: ChainStore + StateSource> Chain<'_, S> {
    /// 押し付けられたブロック。先端の次で先端につながり、同期の途中でないときだけ使い、使ったらピアに流す。先端と同じ親の上の別の
    /// ブロックなら、[`Self::on_rival`] に回す。時刻がまだ来ていなければ
    /// （テストネットもメインネットも、ネットワークの時刻は UTC より数秒進んでいる）、来るまで1つだけ持っておく。
    /// ほかのもの（もう持っている高さ、枝の先、先の高さ）は、統計を聞いて追うのに任せる。弾いたら、押し付けた
    /// 鍵 `from` を待ち受けでしばらく受けない
    pub(super) async fn on_pushed(
        &mut self,
        block: Block,
        bytes: Vec<u8>,
        from: Option<PublicKey>,
    ) -> Result<(), ChainError> {
        let height = block.height;
        if height == self.tip.height
            && block.previous_block_hash == self.parent.previous_block_hash
            && block.hash() != self.tip.hash
        {
            return self.on_rival(block, bytes, from).await;
        }
        if height <= self.tip.height {
            let now = self.env.now();
            let late = self
                .accepted_at
                .iter()
                .find(|(accepted, _)| *accepted == height)
                .and_then(|(_, at)| now.duration_since(*at).ok());
            self.pushes.known += 1;
            if let Some(late) = late {
                self.pushes.late_total += late;
                self.pushes.late_count += 1;
            }
            return Ok(());
        }
        if height > self.tip.height + 1 {
            self.pushes.ahead += 1;
            return Ok(());
        }
        if block.previous_block_hash != self.tip.hash {
            self.pushes.unlinked += 1;
            return Ok(());
        }
        // 時刻がまだなら、同期の途中でも持っておく（受け入れるのは、時刻が来て同期を終えてから）
        if let Some(due) = self.not_yet(&block) {
            // 同じ高さのものをもう持っていれば、先に届いた方を残す
            if self.held.is_some() {
                self.pushes.future += 1;
            } else {
                self.pushes.held += 1;
                self.held = Some((block, bytes, from));
                self.actions.push(Action::WakeAt(due));
            }
            return Ok(());
        }
        if !matches!(self.sync, Sync::Idle) {
            self.pushes.syncing += 1;
            return Ok(());
        }
        match self.accept(&block, bytes, true).await {
            Ok(()) => {
                self.pushes.used += 1;
                self.broadcast(block.as_bytes().to_vec());
            }
            Err(error) => {
                self.pushes.rejected += 1;
                self.reject_push(height, from, &error);
            }
        }
        Ok(())
    }

    /// 押し付けられた、先端と同じ親の上の別のブロック。catapult と同じく（`BlockchainSyncConsumer` の、押し付けで
    /// 巻き戻してよいのは先端の 1 つだけ）、スコアが先端より真に高ければ先端と差し替える。巻き戻しは重いので、
    /// 先に難易度とスコアをヘッダーだけで比べ、勝てないものは巻き戻さない。確定より下、同期の途中、時刻のまだ
    /// 来ていないものは試さない（勝つものなら、統計を聞いて追うときに取り直す）
    async fn on_rival(
        &mut self,
        block: Block,
        bytes: Vec<u8>,
        from: Option<PublicKey>,
    ) -> Result<(), ChainError> {
        let height = block.height;
        let common = height - 1;
        let grandparent = self.statistics.iter().rev().nth(1).copied();
        let Some(grandparent) = grandparent.filter(|_| {
            common >= self.finalized.height
                && matches!(self.sync, Sync::Idle)
                && self.not_yet(&block).is_none()
        }) else {
            self.pushes.rival_skipped += 1;
            return Ok(());
        };
        match rival_verdict(
            &grandparent,
            &BlockStatistic::from(&self.parent),
            &BlockStatistic::from(&block),
        ) {
            Verdict::WrongDifficulty => {
                self.pushes.rival_rejected += 1;
                let error = invalid(format!(
                    "難易度が {} で、同じ親の上の先端の {} と違います",
                    block.difficulty, self.parent.difficulty
                ));
                self.reject_push(height, from, &error);
                return Ok(());
            }
            Verdict::Worse => {
                self.pushes.rival_worse += 1;
                return Ok(());
            }
            Verdict::Better => {}
        }
        let old = self.tip;
        let relayed = bytes.clone();
        match self.replace(common, vec![(block, bytes)], true).await? {
            Replaced::Done => {
                self.pushes.replaced += 1;
                self.broadcast(relayed);
                self.progress(format!(
                    "押し付けられた高さ {height} のブロックのほうがスコアが高いので、先端を差し替えました: {} → {}（{}）",
                    old.hash,
                    self.tip.hash,
                    sender(from)
                ));
            }
            Replaced::Failed { message, penalty } => {
                self.pushes.rival_rejected += 1;
                let error = if penalty == Penalty::None {
                    ChainError::from(message)
                } else {
                    invalid(message)
                };
                self.reject_push(height, from, &error);
            }
        }
        Ok(())
    }

    /// 自分の時計（UTC）で、`block` の時刻がまだ来ていない（`maxBlockFutureTime` を引いても先にある）なら、
    /// 受け入れてよくなる時刻
    pub(super) fn not_yet(&self, block: &Block) -> Option<SystemTime> {
        let due = self.due_at(block.timestamp);
        (due > self.env.now()).then_some(due)
    }

    /// 持っている未来のブロックが、まだ先端の次につながり、時刻が来ていれば受け入れる。つながらなくなって
    /// いれば捨てる。時刻がまだなら、もう一度起こしてもらう
    pub(super) async fn accept_held(&mut self) -> Result<(), ChainError> {
        let Some((block, _, _)) = &self.held else {
            return Ok(());
        };
        if block.height != self.tip.height + 1 || block.previous_block_hash != self.tip.hash {
            self.held = None;
            return Ok(());
        }
        if let Some(due) = self.not_yet(block) {
            self.actions.push(Action::WakeAt(due));
            return Ok(());
        }
        // 同期の途中なら、次の Tick で試す
        if !matches!(self.sync, Sync::Idle) {
            return Ok(());
        }
        let (block, bytes, from) = self.held.take().expect("checked above");
        match self.accept(&block, bytes, true).await {
            Ok(()) => {
                self.pushes.used_late += 1;
                self.broadcast(block.as_bytes().to_vec());
            }
            Err(error) => {
                self.pushes.rejected_late += 1;
                self.reject_push(block.height, from, &error);
            }
        }
        Ok(())
    }

    /// 押し付けられた高さ `height` を弾いたことを知らせる。ブロックが規則に合わなければ、押し付けた鍵 `from` の
    /// 接続を切る（締め出さない）。先端につながるブロックしか試さないので、同じ規則のノードのものなら通る。
    /// REST で届いたもの（`from` が `None`）は、知らせるだけ
    pub(super) fn reject_push(&mut self, height: u64, from: Option<PublicKey>, error: &ChainError) {
        if !is_invalid(error) {
            self.notify(Notice::Progress {
                message: format!(
                    "押し付けられた高さ {height} を受け入れられませんでした（こちらの都合）: {error}"
                ),
                warning: true,
            });
            return;
        }
        let Some(from) = from else {
            self.notify(Notice::Progress {
                message: format!("REST で届いた高さ {height} を弾きました: {error}"),
                warning: true,
            });
            return;
        };
        self.notify(Notice::Progress {
            message: format!(
                "押し付けられた高さ {height} を弾き、鍵 {from} の接続を切ります: {error}"
            ),
            warning: true,
        });
        self.actions.push(Action::RejectPush(from));
    }

    /// 押し付けの数を、前に知らせてから 1 分たっていれば知らせて 0 に戻す
    pub(super) fn report_pushes(&mut self) {
        let now = self.env.now();
        let due = now
            .duration_since(self.pushes.since.unwrap_or(now))
            .is_ok_and(|elapsed| elapsed >= PUSH_REPORT);
        if self.pushes.since.is_none() {
            self.pushes.since = Some(now);
        }
        if !due {
            return;
        }
        let counts = std::mem::take(&mut self.pushes);
        self.pushes.since = Some(now);
        if counts.total() > 0 {
            self.progress(counts.to_string());
        }
    }
}

/// 押し付けた相手を、知らせに書く形にする
fn sender(from: Option<PublicKey>) -> String {
    match from {
        Some(key) => format!("鍵 {key}"),
        None => "REST".to_owned(),
    }
}

/// 先端と同じ親の上の別のブロックを、ヘッダーだけで先端と比べた結果
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// スコアが先端より真に高い。当ててみる
    Better,
    /// スコアが先端より高くない
    Worse,
    /// 難易度は親までのブロックで決まるので、同じ親の上なら先端と同じはず。違えば規則に合わない
    WrongDifficulty,
}

/// 親 `grandparent` の上の先端 `tip` と、同じ親の上の `rival` を比べる。難易度が同じなら、スコアの差は親からの
/// 経過秒だけなので、時刻の早い方が勝つ（同じなら先端のまま）
fn rival_verdict(
    grandparent: &BlockStatistic,
    tip: &BlockStatistic,
    rival: &BlockStatistic,
) -> Verdict {
    if rival.difficulty != tip.difficulty {
        Verdict::WrongDifficulty
    } else if block_score(grandparent, rival) > block_score(grandparent, tip) {
        Verdict::Better
    } else {
        Verdict::Worse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statistic(seconds: u64, difficulty: u64) -> BlockStatistic {
        BlockStatistic {
            timestamp: seconds * 1000,
            difficulty,
        }
    }

    #[test]
    fn rival_wins_only_when_it_came_strictly_earlier() {
        let grandparent = statistic(100, 90_000);
        let tip = statistic(130, 100_000);
        let verdict = |rival| rival_verdict(&grandparent, &tip, &rival);
        assert_eq!(verdict(statistic(125, 100_000)), Verdict::Better);
        // 同じ時刻なら、行ったり来たりしないように先端のまま
        assert_eq!(verdict(statistic(130, 100_000)), Verdict::Worse);
        assert_eq!(verdict(statistic(135, 100_000)), Verdict::Worse);
        // 親より前の時刻はスコアが 0
        assert_eq!(verdict(statistic(100, 100_000)), Verdict::Worse);
        assert_eq!(verdict(statistic(125, 100_001)), Verdict::WrongDifficulty);
    }
}
