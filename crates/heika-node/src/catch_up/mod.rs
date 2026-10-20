//! 追いつく段階。確定の高さまで、ピアからまとめて取って確かめ、実行して、まとめて書く。取る、実行する、書くを
//! 別々のスレッドに分けて重ねる。止める合図を受けたら、まだコミットしていない分を捨てて、最後のコミットのまま終わる。

mod fetch;
mod proofs;

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use heika_block::Block;
use heika_block::finalization::proof::{closes_epoch, proof_header};
use heika_block::scoring::{self, BlockStatistic, difficulty};
use heika_chain::chain::Keep;
use heika_chain::store::EXECUTOR_META;
use heika_chain::verify::Tip;
use heika_core::hash::Hash256;
use heika_core::network::NetworkParameters;
use heika_core::vrf::GenerationHash;
use heika_peer_protocol::ClientConnection;
use heika_state_transition::config::ChainConfig;
use heika_state_transition::executor::Executor;
use heika_store_redb::{Db, DbError};
use heika_tls::Identity;

use fetch::Fetched;
pub(crate) use fetch::connect_any;
pub use fetch::{Discovered, Peer};

use crate::driver::NodeError;

/// 内訳を区切って出す間隔（ブロック）。チェーンの前と後ろで重いところが違うので
const PROFILE_EVERY: u64 = 500_000;

/// コミットの何回に1回、ディスクに書き出し終わるのを待つか。落ちたときは、最後に待ったところから続ける
const DURABLE_EVERY: u64 = 2;

/// 実行で、状態をコミットする間隔（ブロック）の既定
pub const DEFAULT_SAVE_EVERY: u64 = 50_000;

/// 追いつく段階に渡すもの
pub struct Context<'a> {
    pub parameters: &'static NetworkParameters,
    pub identity: &'a Identity,
    /// このネットワークの Nemesis のブロックのハッシュ
    pub nemesis: Hash256,
    /// 止める合図。真になったら、まだコミットしていない分を捨てて終わる
    pub stopping: &'a (dyn Fn() -> bool + Sync),
    /// 終わったあと、抜けている確定の証明を取るのにつなぐ
    pub connect: &'a (dyn Fn() -> Result<ClientConnection, NodeError> + Sync),
}

/// 実行するブロックをどこから取るか
pub enum Source {
    /// DB にしまったブロック（状態を消して実行し直すときなど）
    Stored,
    /// ピアから取る。`discovered` からブロックを分け合って取り、`proof_peers` から確定の証明を取る。
    /// `finalized` はピアの言う確定の高さで、そこまで実行する
    Peers {
        discovered: Discovered,
        proof_peers: Vec<ClientConnection>,
        finalized: u64,
    },
}

/// `db` の実行した高さから、`source` のブロックを、確定の高さ（`to` があればそこまで）まで実行して書く。`keep` なら
/// 刈り込んで実行する。実行する目標の高さから残す分を引いた境まで差分を消し、そこより下の高さでは差分を書かない。
/// 実行した高さを返す
pub fn execute(
    db: &mut Db,
    config: ChainConfig,
    context: &Context<'_>,
    source: Source,
    keep: Option<Keep>,
    save_every: u64,
    to: Option<u64>,
) -> Result<u64, NodeError> {
    let finalization = config.finalization.clone();
    let config_blocks_for_restart = config.blocks_for_restart();
    let seed = context.parameters.generation_hash_seed;
    let lifetime = config
        .max_transaction_lifetime
        .max(config.max_bonded_transaction_lifetime);
    let mut executor = match db.meta(EXECUTOR_META)? {
        Some(meta) => Executor::restore(
            config,
            context.parameters.identifier,
            seed,
            db.state_rows()?,
            &meta,
        )?,
        None => Executor::new(config, context.parameters.identifier, seed),
    };
    let start = executor.height();
    // スコアを持たない前の DB なら、しまったブロックから一度だけ求める
    if executor.score().is_none() {
        let started = Instant::now();
        let mut total = scoring::NEMESIS_CHAIN_SCORE;
        let mut last = None;
        for height in 1..=start {
            let bytes = db
                .block(height)?
                .ok_or("実行した高さのブロックがありません")?;
            let current = BlockStatistic::from(&Block::from_bytes(&bytes)?);
            if let Some(parent) = &last {
                total += u128::from(scoring::block_score(parent, &current));
            }
            last = Some(current);
        }
        if let Some(last) = last {
            executor.set_score(total, last);
            eprintln!(
                "高さ {start} までのスコアを、しまったブロックから求めました（{:.0} 秒）",
                started.elapsed().as_secs_f64()
            );
        }
    }
    // 同じトランザクションの二度入れを弾くハッシュはしまっていないので、期限が残っているかもしれない
    // 直前のブロックから覚え直す
    let mut recent = Vec::new();
    for height in (1..=start).rev() {
        let block = Block::from_bytes(
            &db.block(height)?
                .ok_or("実行した高さのブロックがありません")?,
        )?;
        let done = recent
            .first()
            .is_some_and(|last: &Block| block.timestamp + lifetime < last.timestamp);
        if done {
            break;
        }
        recent.push(block);
    }
    for block in recent.iter().rev() {
        executor.remember_transactions(block)?;
    }
    let fetching = matches!(source, Source::Peers { .. });
    let (peer, proof_job, last) = match source {
        Source::Stored => (None, None, db.blocks_tip()?),
        Source::Peers {
            discovered,
            mut proof_peers,
            finalized,
        } => {
            println!(
                "{} か所のピアからブロックを、{} か所から証明を取ります",
                discovered.peers.len(),
                proof_peers.len()
            );
            let current = proof_peers
                .first_mut()
                .and_then(|peer| peer.finalization_statistics().ok())
                .map(|statistics| statistics.round.epoch);
            (
                Some(discovered),
                current.map(|current| (proof_peers, current)),
                finalized,
            )
        }
    };
    let target = to.map_or(last, |to| to.min(last));
    println!("高さ {} から {target} まで実行します", start + 1);
    // 取る証明は、指す高さ（エポック E なら (E − 1) × votingSetGrouping）が target までのもの
    let first_epoch = first_proof_epoch(db, context.parameters)?;
    let last_epoch = u32::try_from(target / finalization.voting_set_grouping + 1)?;
    let proof_job = proof_job.map(|(peers, current): (Vec<ClientConnection>, u32)| {
        (
            peers,
            first_epoch..current.min(last_epoch + 1).max(first_epoch),
        )
    });
    // 最初のブロックの1つ前。つながりと、難易度、ブロックを出した人を確かめるのに使う
    let mut parent = match db.block(start)? {
        Some(bytes) if start > 0 => Some(Block::from_bytes(&bytes)?),
        _ => None,
    };
    let start_tip = parent
        .as_ref()
        .map(|block| tip_of(db, context.parameters, block))
        .transpose()?;
    // generation hash は、どの高さでもブロックの VRF の証明から求まる。Nemesis の証明は generation hash seed のもの
    let mut parent_generation_hash = parent
        .as_ref()
        .map_or(GenerationHash([0; 32]), Block::generation_hash);
    // 難易度は直前の60ブロックから決まる
    let window = context.parameters.max_difficulty_blocks;
    let mut statistics = VecDeque::with_capacity(window);
    for height in start.saturating_sub(window as u64 - 1).max(1)..=start {
        let bytes = db
            .block(height)?
            .ok_or("実行した高さのブロックがありません")?;
        statistics.push_back(BlockStatistic::from(&Block::from_bytes(&bytes)?));
    }
    let mut progress = Progress::new(start);
    // 木を戻す。しまった木のノードがあればそこから戻し、根がこの高さのブロックの StateHash と合うかを確かめる。
    // 合わなければ、行から組み直す。木のノードをまだ残していなければ、今の木を全部書いてから残し始める
    let mut batch = db.batch()?;
    batch.start_history(start)?;
    let trie_started = db.trie_started()?;
    if trie_started && start > 0 {
        let started = Instant::now();
        executor.restore_trees(db.trie_nodes()?)?;
        let expected =
            Block::from_bytes(&db.block(start)?.ok_or("戻した高さのブロックがありません")?)?
                .state_hash;
        if executor.state_hash() == expected {
            eprintln!(
                "しまった木のノードから木を戻しました（{:.0} 秒）",
                started.elapsed().as_secs_f64()
            );
        } else {
            eprintln!("しまった木のノードの根が StateHash と合わないので、行から組み直します");
            executor.rebuild_trees();
        }
    }
    executor.roots();
    if trie_started {
        executor.forget_node_changes();
    } else {
        batch.start_trie(start)?;
        let nodes = executor
            .all_nodes()
            .ok_or("全部のノードを持たない木から、ノードを全部は書けません")?;
        batch.set_trie_at(start, nodes.iter().map(|(key, node)| (key, Some(node))))?;
    }
    batch.commit()?;
    if let Some(keep) = keep {
        prune_for_execution(db, context, keep, target)?;
    }
    // ブロック、ステートメント、証明も刈り込むなら、終わったあとに消す境。ノードから取って追いつくときは、
    // この境より下のステートメントは書かず、ブロックも再開に要る分より前は書いた端から消す。証明は終わってから
    // しまったブロックと突き合わせるので、証明が指す高さ（エポックの区切り）のブロックだけは終わるまで残す
    let grouping = finalization.voting_set_grouping;
    let history_through = keep.filter(|keep| keep.history).map(|keep| {
        target
            .saturating_sub(keep.state * grouping)
            .saturating_sub(config_blocks_for_restart)
    });
    let drop_while_fetching = history_through.filter(|_| fetching);

    // 差分の索引は、終わってからまとめて作る
    db.defer_history();
    // 読む（取る）スレッド、実行するスレッド（ここ）、書くスレッドに分ける。実行はブロックの順にしかできないので、
    // その前後の読むことと書くことを重ねる
    // 目標まで実行できずに終わるときは、証明を取り終えるのを待たない（取るのに何分もかかる）
    let abandoned = AtomicBool::new(false);
    let stop_proofs = || (context.stopping)() || abandoned.load(Ordering::Relaxed);
    let (failure, interrupted, peer, prefetched, committed) = std::thread::scope(
        |scope| -> Result<_, NodeError> {
            let (block_sender, blocks) = mpsc::sync_channel::<Fetched>(256);
            let (write_sender, writes) = mpsc::sync_channel::<Write>(256);
            let db = &db;
            let fetching = peer.is_some();
            let reader = scope.spawn(move || match peer {
                None => read_stored(db, start, target, &block_sender),
                Some(found) => {
                    fetch::fetch(found, context, start_tip, target, &block_sender);
                }
            });
            let proof_fetcher = proof_job.map(|(peers, epochs)| {
                scope.spawn(move || proofs::fetch(peers, epochs, &stop_proofs))
            });
            let writer = scope.spawn(move || -> Result<([Duration; 2], u64), DbError> {
                // 書くのと、コミットにかかった時間。全体と、区間（PROFILE_EVERY ごと）
                let mut spent = [Duration::ZERO; 2];
                let mut segment = [Duration::ZERO; 2];
                let mut segment_start = start + 1;
                // 最後にコミットした高さ
                let mut committed = start;
                let mut batch = db.batch()?;
                batch.defer_history_after(start)?;
                for write in writes {
                    // 止める合図を見たら、残りは書かずに読み捨てる。コンテナの猶予（10〜30 秒）のうちに
                    // 終わるように、まだコミットしていない分は捨て、最後のコミットのまま終わる
                    if (context.stopping)() {
                        continue;
                    }
                    let started = Instant::now();
                    let commit = matches!(write, Write::Commit { .. });
                    match write {
                        Write::Height {
                            height,
                            block,
                            state,
                            nodes,
                            voters,
                            statement,
                        } => {
                            if let Some(block) = block {
                                batch.put_block(height, &block)?;
                            }
                            batch.set_state_at(height, state)?;
                            batch.set_trie_at(height, nodes)?;
                            if let Some(statement) = statement {
                                batch.put_statement(height, &statement)?;
                            }
                            if let Some((epoch, voters)) = voters {
                                batch.put_voters(epoch, &voters)?;
                            }
                        }
                        Write::Commit {
                            height,
                            meta,
                            durable,
                            drop_blocks_through,
                        } => {
                            if let Some(through) = drop_blocks_through {
                                batch.remove_blocks_through(through, |height| {
                                    height == 1 || height.is_multiple_of(grouping)
                                })?;
                            }
                            batch.put_meta(EXECUTOR_META, &meta)?;
                            batch.put_checkpoint(height, &meta)?;
                            if durable {
                                batch.commit()?;
                            } else {
                                batch.commit_lazily()?;
                            }
                            batch = db.batch()?;
                            committed = height;
                            segment[1] += started.elapsed();
                            spent[1] += started.elapsed();
                            // 区間の切れ目を越えたコミットで、その区間の内訳を出す
                            if height / PROFILE_EVERY
                                > segment_start.saturating_sub(1) / PROFILE_EVERY
                            {
                                report_writer(&format!("高さ {segment_start}〜{height}"), segment);
                                segment = [Duration::ZERO; 2];
                                segment_start = height + 1;
                            }
                            continue;
                        }
                    }
                    segment[usize::from(commit)] += started.elapsed();
                    spent[usize::from(commit)] += started.elapsed();
                }
                // コミットしていない高さは捨てる。待たずにコミットしたものは、空のコミットで書き出し終わるのを待つ
                drop(batch);
                db.batch()?.commit()?;
                if segment != [Duration::ZERO; 2] {
                    report_writer(&format!("高さ {segment_start}〜"), segment);
                }
                Ok((spent, committed))
            });
            let mut uncommitted = false;
            let mut failure = None;
            // 取れなくなったか、確かめられないブロックが来た。そこまでに実行したものはしまう
            let mut interrupted = None;
            let mut phases = Phases::default();
            // 区間（PROFILE_EVERY ごと）の内訳。全体の内訳は、区間のものを足していく
            let mut total = Phases::default();
            let mut segment_start = start + 1;
            while executor.height() < target && !(context.stopping)() {
                let height = executor.height() + 1;
                let mut lap = Instant::now();
                let (block, bytes) = match blocks.recv() {
                    Ok(Ok(fetched)) => fetched,
                    Ok(Err(error)) => {
                        interrupted = Some(error);
                        break;
                    }
                    // 止める合図で、読むスレッドが先に終わった
                    Err(_) if (context.stopping)() => break,
                    Err(_) => {
                        interrupted = Some("ブロックを読むスレッドが止まりました".to_owned());
                        break;
                    }
                };
                phases.add(Phase::WaitBlocks, &mut lap);
                // 実行する前に、1つ前のブロックのあとの状態で、難易度とブロックを出した人を確かめる。Nemesis は信じる
                let generation_hash = match &parent {
                    None => block.generation_hash(),
                    Some(parent) => {
                        let expected = difficulty(statistics.make_contiguous(), context.parameters);
                        if block.difficulty != expected {
                            failure = Some(format!(
                                "高さ {height}: 難易度が {} で、直前のブロックから求めた {expected} と合いません",
                                block.difficulty
                            ));
                            break;
                        }
                        match executor.check_harvester(
                            parent,
                            &parent_generation_hash,
                            &block,
                            context.parameters,
                        ) {
                            Ok(generation_hash) => generation_hash,
                            Err(error) => {
                                failure = Some(format!("高さ {height}: {error}"));
                                break;
                            }
                        }
                    }
                };
                phases.add(Phase::Harvester, &mut lap);
                if let Err(error) = executor.apply(&block) {
                    failure = Some(format!("高さ {height}: {error}"));
                    break;
                }
                phases.add(Phase::Apply, &mut lap);
                let state_hash = executor.state_hash();
                phases.add(Phase::Roots, &mut lap);
                if state_hash != block.state_hash {
                    // 最後にコミットしたところまで戻る
                    let roots = executor.roots();
                    let roots: Vec<String> = roots.iter().map(ToString::to_string).collect();
                    failure = Some(format!(
                        "高さ {height}: StateHash が合いません。9本の根: {}",
                        roots.join(" ")
                    ));
                    break;
                }
                let statement = executor.take_statement();
                let receipts_hash = statement.merkle_hash();
                phases.add(Phase::Statement, &mut lap);
                if receipts_hash != block.receipts_hash {
                    failure = Some(format!(
                        "高さ {height}: ReceiptsHash が合いません。ステートメント: {statement:?}"
                    ));
                    break;
                }
                let changes = executor.take_changes();
                let puts = changes
                    .puts
                    .into_iter()
                    .map(|(key, value)| (key, Some(value)));
                let deletes = changes.deletes.into_iter().map(|key| (key, None));
                let state = puts.chain(deletes).collect();
                phases.add(Phase::Rows, &mut lap);
                let nodes = executor.take_node_changes();
                phases.add(Phase::Nodes, &mut lap);
                // エポック E の投票者は、E - 1 の最後の高さ（高さ 1 か、区切りの倍数）の状態で決まる
                let next_epoch = if height == 1 {
                    Some(2)
                } else if height % grouping == 0 {
                    u32::try_from(height / grouping + 2).ok()
                } else {
                    None
                };
                let write = Write::Height {
                    height,
                    block: bytes,
                    state,
                    nodes,
                    voters: next_epoch.map(|epoch| (epoch, executor.voting_set(epoch).encode())),
                    statement: (drop_while_fetching.is_none_or(|through| height > through))
                        .then(|| statement.to_bytes()),
                };
                uncommitted = true;
                phases.add(Phase::Voters, &mut lap);
                let mut sent = write_sender.send(write);
                if sent.is_ok() && height % save_every == 0 {
                    sent = write_sender.send(Write::Commit {
                        height,
                        meta: executor.encode_meta(),
                        durable: height % (save_every * DURABLE_EVERY) == 0,
                        drop_blocks_through: drop_while_fetching.map(|through| {
                            through.min(height.saturating_sub(config_blocks_for_restart))
                        }),
                    });
                    uncommitted = false;
                }
                if sent.is_err() {
                    // 書くスレッドが止まった。理由はそちらが返す
                    break;
                }
                phases.add(Phase::WaitWriter, &mut lap);
                statistics.push_back(BlockStatistic::from(&block));
                if statistics.len() > window {
                    statistics.pop_front();
                }
                parent = Some(block);
                parent_generation_hash = generation_hash;
                progress.tick(height, target);
                if height % PROFILE_EVERY == 0 {
                    phases.report(&format!("高さ {segment_start}〜{height}"));
                    total.add_all(&phases);
                    phases = Phases::default();
                    segment_start = height + 1;
                }
            }
            if executor.height() < target {
                abandoned.store(true, Ordering::Relaxed);
            }
            if failure.is_none() && uncommitted && !(context.stopping)() {
                // 取れなくなって止まったときも、そこまでに実行したものはしまう。止める合図のときは、しまわずに
                // 捨てる（次に始めたときに、最後のコミットから実行し直す）
                let _ = write_sender.send(Write::Commit {
                    height: executor.height(),
                    meta: executor.encode_meta(),
                    durable: true,
                    drop_blocks_through: None,
                });
            }
            drop(write_sender);
            drop(blocks);
            let (written, committed) = writer.join().expect("writer does not panic")?;
            reader.join().expect("reader does not panic");
            if executor.height() >= segment_start {
                let label = format!("高さ {segment_start}〜{}", executor.height());
                phases.report(&label);
            }
            total.add_all(&phases);
            total.report("全体");
            report_writer("全体", written);
            let prefetched = proof_fetcher
                .map(|fetcher| fetcher.join().expect("proof fetcher does not panic"))
                .unwrap_or_default();
            Ok((failure, interrupted, fetching, prefetched, committed))
        },
    )?;
    if let Some(failure) = failure {
        return Err(failure.into());
    }
    if let Some(error) = interrupted {
        // 実行したところまではしまってある。索引は、続きを実行し終えるか index で作る
        return Err(format!("高さ {} で止まりました: {error}", executor.height()).into());
    }
    if (context.stopping)() {
        // 索引と詰め直しは長くかかるので、止めるときはしない
        println!(
            "高さ {committed} までをしまって止めました（実行した高さ {} までの残りは捨て、次に始めたときに実行し直します）。差分の索引は、続きを実行し終えるか index で作ります",
            executor.height()
        );
        return Ok(committed);
    }
    build_history(db, context)?;
    if peer {
        sync_proofs(
            context,
            db,
            &mut (context.connect)()?,
            executor.height(),
            prefetched,
        )?;
    }
    // 証明は手元のブロックと突き合わせて確かめるので、ブロックを消すのは確かめ終えてから
    if let Some(through) = history_through {
        let started = Instant::now();
        let epoch = u32::try_from(context.parameters.finalization_epoch(through))?;
        let rows = db.prune_history(through, epoch)?;
        println!(
            "ブロックとステートメントを高さ {through} 以下で、証明をエポック {epoch} より前で、合わせて {rows} 行消しました（{:.0} 秒）",
            started.elapsed().as_secs_f64()
        );
    }
    println!(
        "高さ {} まで実行しました。StateHash {}、スコア {}",
        executor.height(),
        executor.state_hash(),
        executor.score().unwrap_or_default()
    );
    Ok(executor.height())
}

/// 実行するスレッドの、1ブロックの中の段階
#[derive(Clone, Copy)]
enum Phase {
    /// 読むスレッドからブロックが来るのを待つ
    WaitBlocks,
    /// 難易度と、ブロックを出した人（VRF の証明と当たり）を確かめる
    Harvester,
    /// ブロックを当てる
    Apply,
    /// 9本の根と StateHash
    Roots,
    /// ステートメントの Merkle の根
    Statement,
    /// 書く状態の行を作る
    Rows,
    /// 書く木のノードを作る
    Nodes,
    /// 投票者とステートメントのバイト列を作る
    Voters,
    /// 書くスレッドが受け取るのを待つ
    WaitWriter,
}

/// 実行するスレッドが、段階ごとにかけた時間
#[derive(Default)]
struct Phases([Duration; 9]);

impl Phases {
    /// `lap` からの時間を `phase` に足し、`lap` を今にする
    fn add(&mut self, phase: Phase, lap: &mut Instant) {
        let now = Instant::now();
        self.0[phase as usize] += now - *lap;
        *lap = now;
    }

    /// 内訳を出す。`written` は書くスレッドの、書くのとコミットにかけた時間
    fn add_all(&mut self, other: &Self) {
        for (total, spent) in self.0.iter_mut().zip(other.0) {
            *total += spent;
        }
    }

    /// 内訳を出す。`label` はどの高さの分か
    fn report(&self, label: &str) {
        let seconds = |duration: Duration| duration.as_secs_f64();
        let [
            wait_blocks,
            harvester,
            apply,
            roots,
            statement,
            rows,
            nodes,
            voters,
            wait_writer,
        ] = self.0.map(seconds);
        eprintln!(
            "{label}: 実行するスレッドの内訳（秒）: ブロックを待つ {wait_blocks:.1}、難易度とブロックを出した人 {harvester:.1}、当てる {apply:.1}、\
             根 {roots:.1}、ステートメント {statement:.1}、書く行 {rows:.1}、書く木のノード {nodes:.1}、\
             投票者など {voters:.1}、書くのを待つ {wait_writer:.1}"
        );
    }
}

/// 書くスレッドの、書くのとコミットにかけた時間を出す
fn report_writer(label: &str, written: [Duration; 2]) {
    eprintln!(
        "{label}: 書くスレッドの内訳（秒）: 書く {:.1}、コミット {:.1}",
        written[0].as_secs_f64(),
        written[1].as_secs_f64(),
    );
}

/// しまったブロックを順に読んで送る
fn read_stored(db: &Db, start: u64, target: u64, sender: &mpsc::SyncSender<Fetched>) {
    for height in start + 1..=target {
        let block = match db.block(height) {
            Ok(Some(bytes)) => Block::from_bytes(&bytes)
                .map(|block| (block, None))
                .map_err(|error| error.to_string()),
            Ok(None) => Err("途中のブロックがありません".to_owned()),
            Err(error) => Err(error.to_string()),
        };
        let stop = block.is_err();
        if sender.send(block).is_err() || stop {
            break;
        }
    }
}

/// 実行するスレッドから書くスレッドへ送るもの
enum Write {
    /// その高さで変わった状態の行と木のノード
    Height {
        height: u64,
        /// ノードから取ったブロックなら、そのバイト列。しまう
        block: Option<Vec<u8>>,
        state: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        nodes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
        /// この高さがエポックの最後なら、次のエポックとその投票者
        voters: Option<(u32, Vec<u8>)>,
        /// このブロックを実行して出たステートメント。刈り込んで消す高さなら書かない（`None`）
        statement: Option<Vec<u8>>,
    },
    /// `height` までをコミットする。木に入らない実行の状態を添え、チェックポイントにもする。
    /// `durable` でなければ、ディスクに書き出し終わるのを待たない
    Commit {
        height: u64,
        meta: Vec<u8>,
        durable: bool,
        /// この高さ以下のブロックを、ファイナライズの証明が指す高さのほかは消す（刈り込んで追いつくとき）
        drop_blocks_through: Option<u64>,
    },
}

/// 刈り込んで実行する前に、`target` から残す分を引いた境まで差分を消して境を上げ、これから書く高さのうち
/// 境以下のものでは差分を書かないようにする。追いつく段階を繰り返すと、そのたびに境が上がる
fn prune_for_execution(
    db: &mut Db,
    context: &Context<'_>,
    keep: Keep,
    target: u64,
) -> Result<(), NodeError> {
    let grouping = context.parameters.voting_set_grouping;
    let state = target.saturating_sub(keep.state * grouping);
    let trie = target.saturating_sub(keep.trie * grouping);
    let started = Instant::now();
    let pruned_state = db.prune_state_history(state, |_| !(context.stopping)())?;
    let pruned_trie = db.prune_trie_history(trie, |_| !(context.stopping)())?;
    if !pruned_state.done || !pruned_trie.done {
        return Err("刈り込みを途中で止めました。もう一度動かすと続きを消します".into());
    }
    db.quiet_history_through(state, trie);
    println!(
        "刈り込んで実行します。差分は、状態が高さ {state}、木のノードが高さ {trie} より上だけを残します（消した差分 {} 行、{:.0} 秒）",
        pruned_state.rows + pruned_trie.rows,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// 終わったエポックのファイナライズの証明を、しまってあるブロックの高さ `blocks_tip` までの分だけ取る。
/// 先に取ってある `prefetched` があればそれを使い、ないエポックだけを `node` に順に頼む。
/// 証明が指す高さとハッシュが、しまったブロックと合うものだけをしまう。今のエポックの証明はまだ変わるので取らない
fn sync_proofs(
    context: &Context<'_>,
    db: &Db,
    node: &mut ClientConnection,
    blocks_tip: u64,
    mut prefetched: BTreeMap<u32, Vec<u8>>,
) -> Result<(), NodeError> {
    let current = node.finalization_statistics()?.round.epoch;
    let first = first_proof_epoch(db, context.parameters)?;
    let mut batch = db.batch()?;
    let mut last = None;
    let mut asked = 0;
    for epoch in first..current {
        if (context.stopping)() {
            break;
        }
        let proof = match prefetched.remove(&epoch) {
            Some(proof) => proof,
            None => {
                asked += 1;
                node.finalization_proof_at_epoch(epoch)?
                    .ok_or_else(|| format!("ノードがエポック {epoch} の証明を返しません"))?
            }
        };
        if (epoch - first + 1).is_multiple_of(500) {
            eprintln!(
                "ファイナライズの証明をエポック {epoch} まで確かめました（{} 件のうち、順に取ったもの {asked} 件）",
                epoch - first + 1
            );
        }
        let header = proof_header(&proof).map_err(|error| format!("エポック {epoch}: {error}"))?;
        if header.round.epoch != epoch {
            return Err(format!(
                "エポック {epoch}: 証明のエポックが {} です",
                header.round.epoch
            )
            .into());
        }
        if header.height > blocks_tip {
            break;
        }
        let bytes = db.block(header.height)?.ok_or_else(|| {
            format!(
                "エポック {epoch}: 高さ {} のブロックがありません",
                header.height
            )
        })?;
        let hash = Block::from_bytes(&bytes)?.hash();
        if hash != header.hash {
            return Err(format!(
                "エポック {epoch}: 証明が指す高さ {} のハッシュ {} が、しまったブロックの {hash} と違います",
                header.height, header.hash
            )
            .into());
        }
        batch.put_proof(epoch, &proof)?;
        last = Some((epoch, header.height));
        if epoch % 100 == 0 {
            batch.commit()?;
            batch = db.batch()?;
        }
    }
    batch.commit()?;
    match last {
        None => println!("足すファイナライズの証明はありませんでした"),
        Some((epoch, height)) => println!(
            "ファイナライズの証明をエポック {first} から {epoch}（高さ {height}）までしまいました（順に取ったもの {asked} 件）"
        ),
    }
    Ok(())
}

/// 10秒ごとに、どこまで進んだかを出す
struct Progress {
    started: Instant,
    start_height: u64,
    last: Instant,
}

impl Progress {
    fn new(start_height: u64) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            start_height,
            last: now,
        }
    }

    fn tick(&mut self, height: u64, target: u64) {
        if self.last.elapsed() < Duration::from_secs(10) && height != target {
            return;
        }
        self.last = Instant::now();
        let seconds = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = (height - self.start_height) as f64 / seconds;
        eprintln!("高さ {height} / {target}（{rate:.0} ブロック/秒）");
    }
}

/// しまったブロック `block` の `Tip`。最後の importance ブロック（なければ Nemesis）も、しまったものから読む
fn tip_of(db: &Db, parameters: &NetworkParameters, block: &Block) -> Result<Tip, NodeError> {
    let grouping = parameters.importance_grouping;
    let importance_height = (block.height / grouping * grouping).max(1);
    let importance_hash = if importance_height == block.height {
        block.hash()
    } else {
        let bytes = db
            .block(importance_height)?
            .ok_or("最後の importance ブロックがありません")?;
        Block::from_bytes(&bytes)?.hash()
    };
    Ok(Tip {
        height: block.height,
        hash: block.hash(),
        importance_hash,
    })
}

/// 証明を取り始めるエポック。しまった最後の証明がエポックの途中のポイントのもの（先端の段階でしまった）なら、
/// そのエポックから取り直す
fn first_proof_epoch(db: &Db, parameters: &NetworkParameters) -> Result<u32, NodeError> {
    let tip = db.proofs_tip()?;
    let closed = match db.proof(tip)? {
        Some(proof) => closes_epoch(&proof_header(&proof)?, parameters.voting_set_grouping),
        None => true,
    };
    Ok(if closed { tip + 1 } else { tip })
}

fn build_history(db: &Db, context: &Context<'_>) -> Result<(), NodeError> {
    let started = Instant::now();
    let mut last = Instant::now();
    let built = db.build_history(|name, height| {
        if last.elapsed() >= Duration::from_secs(10) {
            last = Instant::now();
            eprintln!("差分の索引（{name}）: 高さ {height} まで");
        }
        !(context.stopping)()
    })?;
    if !built {
        return Err("差分の索引を途中で止めました。続きは index で作ります".into());
    }
    eprintln!(
        "差分の索引を作りました（{:.0} 秒）",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
