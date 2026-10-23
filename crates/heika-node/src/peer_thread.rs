//! つないだピア1つごとのスレッド。頼まれたことをして、返事を受信箱に返すだけ。取ったブロックは、返す前に状態を
//! 見ない確かめ（[`verify_alone`]）を並列に済ませる。命令の口が閉じたら終わる。

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};

use heika_block::Block;
use heika_block::finalization::FinalizationRound;
use heika_chain::event::{ChainEvent, PULL_BYTES, PeerCommand, PeerId};
use heika_chain::verify::verify_alone;
use heika_core::network::NetworkParameters;
use heika_packet::packet_type;
use heika_packet::partial::ShortHashPair;
use heika_peer::{Ask, PeerEvent};
use heika_peer_protocol::{ClientConnection, PulledPartial};

use crate::partials::Incoming;
use rayon::prelude::*;

/// ピアのスレッドへの命令。中核からのものと、ピアの意思決定からのもの
#[derive(Debug)]
pub enum Request {
    Chain(PeerCommand),
    Peer(Ask),
    /// 受け付けたトランザクションを押し付ける。返事はなく、失敗したときだけ `ChainEvent::Failed` を返す
    Transactions(Arc<Vec<u8>>),
    /// `packet_type` の本体 `body` を押し付ける（連署を待つものと、連署）。返事はない
    Push {
        packet_type: u32,
        body: Arc<Vec<u8>>,
    },
    /// 連署を待つものを頼む。[`NodeEvent::PulledPartial`] で返す
    PullPartial {
        min_deadline: u64,
        known: Vec<ShortHashPair>,
    },
    /// 未承認のトランザクションを頼む。期限が `min_deadline` 以降で、手数料の倍率が `min_fee_multiplier` 以上のもののうち、
    /// `known`（短いハッシュ）にないもの。[`NodeEvent::Pulled`] で返す
    PullTransactions {
        min_deadline: u64,
        min_fee_multiplier: u32,
        known: Vec<u32>,
    },
    /// ラウンド `min` から `max` までの投票のメッセージのうち、`known`（短いハッシュ）にないものを頼む。
    /// [`NodeEvent::PulledVotes`] で返す
    PullVotes {
        min: FinalizationRound,
        max: FinalizationRound,
        known: Vec<u32>,
    },
}

/// 駆動役の受信箱に入れる出来事。どちらの状態機械あてか
pub enum NodeEvent {
    Chain(ChainEvent),
    Peer(PeerEvent),
    /// 新しく受け付けたトランザクション（1件以上を隙間なく並べたもの。`Push_Transactions` の本体）。つないでいるピアの
    /// みなに押し付ける。`except` は、それを渡してきたピア（送り返さない）。受け付けるのは初めて見たときだけなので、
    /// ピアのあいだを回り続けることはない
    Relay {
        transactions: Arc<Vec<u8>>,
        except: Option<PeerId>,
    },
    /// 連署を待つものが入ってきた。`from` は、それをくれたピア（送り返さない）
    Partial {
        incoming: Incoming,
        from: Option<PeerId>,
    },
    /// ピアに頼んだ、連署を待つもの
    PulledPartial {
        peer: PeerId,
        pulled: Vec<PulledPartial>,
    },
    /// ピアに頼んだ未承認のトランザクション（1件ずつのバイト列）
    Pulled {
        peer: PeerId,
        transactions: Vec<Vec<u8>>,
    },
    /// ピアに頼んだか、押し付けられた投票のメッセージ（1つずつのバイト列）。`from` は頼んだピア
    Votes {
        messages: Vec<Vec<u8>>,
        from: Option<PeerId>,
    },
    /// 投票するピアみなに配る投票のメッセージ。`except` は、それをくれたピア（送り返さない）
    VotesToRelay {
        messages: Vec<Vec<u8>>,
        except: Option<PeerId>,
    },
}

/// ピア `peer` のスレッドを立て、命令の口を返す。`announce`（自分の `NetworkNode`）があれば、始めにピアに押し付けて
/// 名乗る。catapult はそれを受けると、こちらに ping を聞き返して確かめ、知っているノードに足す
pub fn spawn(
    peer: PeerId,
    mut connection: ClientConnection,
    parameters: &'static NetworkParameters,
    events: Sender<NodeEvent>,
    announce: Option<Arc<Vec<u8>>>,
) -> Sender<Request> {
    let (requests, receiver): (Sender<Request>, Receiver<Request>) = mpsc::channel();
    std::thread::spawn(move || {
        if let Some(node) = announce
            && let Err(error) = connection.push(packet_type::NODE_DISCOVERY_PUSH_PING, &node)
        {
            let _ = events.send(failed(peer, error, false));
            return;
        }
        for request in receiver {
            let event = match request {
                Request::Chain(command) => match answer(&mut connection, parameters, peer, command)
                {
                    Some(event) => event,
                    None => continue,
                },
                Request::Peer(Ask::Info) => match connection.info() {
                    Ok(node) => NodeEvent::Peer(PeerEvent::Info { id: peer, node }),
                    Err(error) => failed(peer, error, false),
                },
                Request::Peer(Ask::Peers) => match connection.peers() {
                    Ok(nodes) => NodeEvent::Peer(PeerEvent::Nodes { id: peer, nodes }),
                    Err(error) => failed(peer, error, false),
                },
                Request::PullTransactions {
                    min_deadline,
                    min_fee_multiplier,
                    known,
                } => match connection.pull_transactions(min_deadline, min_fee_multiplier, &known) {
                    Ok(transactions) => NodeEvent::Pulled { peer, transactions },
                    Err(error) => failed(peer, error, false),
                },
                Request::PullVotes { min, max, known } => {
                    match connection.pull_finalization_messages(min, max, &known) {
                        Ok(messages) => NodeEvent::Votes {
                            messages,
                            from: Some(peer),
                        },
                        Err(error) => failed(peer, error, false),
                    }
                }
                Request::Push { packet_type, body } => match connection.push(packet_type, &body) {
                    Ok(()) => continue,
                    Err(error) => failed(peer, error, false),
                },
                Request::PullPartial {
                    min_deadline,
                    known,
                } => match connection.pull_partial_infos(min_deadline, &known) {
                    Ok(pulled) => NodeEvent::PulledPartial { peer, pulled },
                    Err(error) => failed(peer, error, false),
                },
                Request::Transactions(bytes) => {
                    match connection.push(packet_type::PUSH_TRANSACTIONS, &bytes) {
                        Ok(()) => continue,
                        Err(error) => failed(peer, error, false),
                    }
                }
            };
            let stop = matches!(event, NodeEvent::Chain(ChainEvent::Failed { .. }));
            if events.send(event).is_err() || stop {
                return;
            }
        }
    });
    requests
}

/// 中核の命令に答える。答えのない押し付けがうまくいったら `None`
fn answer(
    connection: &mut ClientConnection,
    parameters: &NetworkParameters,
    peer: PeerId,
    command: PeerCommand,
) -> Option<NodeEvent> {
    let event = match command {
        PeerCommand::Statistics => match connection.chain_statistics() {
            Ok(statistics) => ChainEvent::Statistics { peer, statistics },
            Err(error) => return Some(failed(peer, error, false)),
        },
        PeerCommand::PullBlocks { from, count } => {
            match pull(connection, parameters, from, count) {
                Ok(blocks) => ChainEvent::Blocks {
                    peer,
                    from,
                    count,
                    blocks,
                },
                Err((error, malformed)) => return Some(failed(peer, error, malformed)),
            }
        }
        PeerCommand::PullHashes { from, count } => {
            match connection.pull_block_hashes(from, count) {
                Ok(hashes) => ChainEvent::Hashes {
                    peer,
                    from,
                    count,
                    hashes,
                },
                Err(error) => return Some(failed(peer, error, false)),
            }
        }
        PeerCommand::Finalized => match connection.finalization_statistics() {
            Ok(header) => ChainEvent::Finalized { peer, header },
            Err(error) => return Some(failed(peer, error, false)),
        },
        PeerCommand::PullProof { epoch } => match connection.finalization_proof_at_epoch(epoch) {
            Ok(proof) => ChainEvent::Proof { peer, epoch, proof },
            Err(error) => return Some(failed(peer, error, false)),
        },
        PeerCommand::Push(block) => match connection.push(packet_type::PUSH_BLOCK, &block) {
            Ok(()) => return None,
            Err(error) => return Some(failed(peer, error, false)),
        },
    };
    Some(NodeEvent::Chain(event))
}

/// 取れなかったわけと、確かめに落ちた（壊れている）か
type PullError = (String, bool);

fn failed(peer: PeerId, error: impl std::fmt::Display, malformed: bool) -> NodeEvent {
    NodeEvent::Chain(ChainEvent::Failed {
        peer,
        error: error.to_string(),
        malformed,
    })
}

/// `from` から最大 `count` 件を取り、高さと状態を見ない確かめをして返す。通信の失敗なら偽、確かめに落ちた
/// （壊れている）なら真を付けて返す
fn pull(
    connection: &mut ClientConnection,
    parameters: &NetworkParameters,
    from: u64,
    count: u32,
) -> Result<Vec<(Block, Vec<u8>)>, PullError> {
    let pulled = connection
        .pull_blocks(from, count, PULL_BYTES)
        .map_err(|error| (error.to_string(), false))?;
    if pulled.len() > count as usize {
        return Err((
            format!("{count} 件を頼んで {} 件が来ました", pulled.len()),
            true,
        ));
    }
    pulled
        .into_par_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let block = Block::from_bytes(&bytes).map_err(|error| (error.to_string(), true))?;
            let expected = from + index as u64;
            if block.height != expected {
                return Err((
                    format!("高さ {expected} を頼んで {} が来ました", block.height),
                    true,
                ));
            }
            verify_alone(parameters, &block)
                .map_err(|error| (format!("高さ {}: {error}", block.height), true))?;
            Ok((block, bytes))
        })
        .collect()
}
