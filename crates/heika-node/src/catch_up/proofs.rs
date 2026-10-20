//! ファイナライズの証明を、いくつかのピアから並列に取る。
//!
//! 証明はエポックごとに1回ずつ頼むので、1つのピアに順に頼むと、往復を待つ時間がそのまま積み上がる。
//! 実行のあいだにピアごとのスレッドでエポックを分け合って取り、メモリに置いておく。しまったブロックと
//! 突き合わせてしまうのは、ブロックが揃ってから呼ぶ側がする。取れなかったエポックは、呼ぶ側が順に取り直す。

use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use heika_peer_protocol::ClientConnection;

use heika_block::finalization::proof::proof_header;

/// 何件取るごとに進み具合を出すか
const PROGRESS_EVERY: usize = 500;

/// `epochs` の証明を、`peers` のそれぞれのスレッドで分け合って取る。エポックが証明の中身と合うものだけを返す。
/// 取れないか合わないピアは、そのエポックを残して外す。`stopping` が真になったら、そこで終わる
pub fn fetch(
    peers: Vec<ClientConnection>,
    epochs: Range<u32>,
    stopping: &(dyn Fn() -> bool + Sync),
) -> BTreeMap<u32, Vec<u8>> {
    let total = epochs.len();
    let pending = Mutex::new(epochs.collect::<VecDeque<_>>());
    let fetched = Mutex::new(BTreeMap::new());
    let done = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for mut peer in peers {
            let (pending, fetched, done) = (&pending, &fetched, &done);
            scope.spawn(move || {
                while !stopping() {
                    let Some(epoch) = pending.lock().expect("not poisoned").pop_front() else {
                        break;
                    };
                    let proof = match peer.finalization_proof_at_epoch(epoch) {
                        Ok(Some(proof))
                            if proof_header(&proof)
                                .is_ok_and(|header| header.round.epoch == epoch) =>
                        {
                            proof
                        }
                        _ => {
                            // ほかのピアに任せる
                            pending.lock().expect("not poisoned").push_back(epoch);
                            break;
                        }
                    };
                    fetched.lock().expect("not poisoned").insert(epoch, proof);
                    let count = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if count.is_multiple_of(PROGRESS_EVERY) {
                        eprintln!("ファイナライズの証明を {count} / {total} 件取りました");
                    }
                }
            });
        }
    });
    fetched.into_inner().expect("not poisoned")
}
