//! メモリの中の掲示板で、DKG を通しで動かす。ブロックはすぐにファイナライズされるものとする。

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::{NetworkIdentifier, NetworkParameters};
use rand_core::OsRng;

use crate::board::{Board, Event, Outcome, Reason};
use crate::member::{Behavior, Member};
use crate::sign::sign;
use crate::symbol;
use crate::wire::Session;

struct Run {
    board: Board,
    members: Vec<Member>,
    events: Vec<Event>,
    /// 掲示板に載ったもの（高さと中身）
    log: Vec<(u64, Vec<u8>)>,
}

/// `behaviors` の参加者で、しきい値 `threshold` の DKG を最後まで動かす
fn run(behaviors: &[Behavior], threshold: u16) -> Run {
    run_with(behaviors, threshold, 3)
}

/// 1 段階を `window` ブロックにして動かす
fn run_with(behaviors: &[Behavior], threshold: u16, window: u64) -> Run {
    let mut members: Vec<Member> = behaviors
        .iter()
        .enumerate()
        .map(|(index, behavior)| {
            Member::new(index as u16, PrivateKey::generate().unwrap(), *behavior)
        })
        .collect();
    let session = Session {
        threshold,
        window,
        nonce: [1; 16],
        members: members.iter().map(Member::public_key).collect(),
    };
    let mut board = Board::new(session.id());
    let mut events = Vec::new();
    let mut log = vec![(1, session.encode())];
    board.apply(1, &session.encode());
    for height in 2..1000 {
        // 高さ height - 1 までファイナライズされたのを見て、次のブロックに載せる
        board.settle(height - 1);
        events.extend(board.take_events());
        let mut posts = Vec::new();
        for member in &mut members {
            posts.extend(member.act(&board, &mut OsRng).unwrap());
        }
        let finished = !matches!(board.outcome(), Outcome::Running);
        for post in posts {
            board.apply(height, &post);
            log.push((height, post));
        }
        if finished {
            break;
        }
    }
    events.extend(board.take_events());
    Run {
        board,
        members,
        events,
        log,
    }
}

impl Run {
    fn key(&self) -> PublicKey {
        self.board.group_key().expect("done")
    }

    /// 鍵ができた高さ
    fn done_at(&self) -> u64 {
        self.events
            .iter()
            .find_map(|event| match event {
                Event::Done { height, .. } => Some(*height),
                _ => None,
            })
            .expect("done")
    }

    fn excluded(&self) -> Vec<(u16, Reason)> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Excluded { member, reason, .. } => Some((*member, *reason)),
                _ => None,
            })
            .collect()
    }

    /// `signers` 番目の参加者で署名し、Symbol と同じ検証で確かめる
    fn signs_with(&self, signers: &[usize]) -> bool {
        let Outcome::Done(public) = self.board.outcome() else {
            return false;
        };
        let packages: Vec<_> = signers
            .iter()
            .map(|index| self.members[*index].key_package().expect("has a share"))
            .collect();
        let message = b"heika dkg test";
        let signature = sign(&packages, public, message, &mut OsRng).unwrap();
        self.key().verify(&[message], &signature)
    }
}

const HONEST: Behavior = Behavior::Honest;

#[test]
fn honest_members_make_one_key() {
    let run = run(&[HONEST; 5], 3);
    assert!(run.excluded().is_empty());
    let key = run.key();
    for member in &run.members {
        let package = member.key_package().unwrap();
        assert_eq!(package.verifying_key().serialize().unwrap(), key.0.to_vec());
    }
    assert!(run.signs_with(&[0, 1, 2]));
    assert!(run.signs_with(&[2, 3, 4]));
}

#[test]
fn phases_close_as_soon_as_everyone_posts() {
    // 約束、配る、苦情なしが、それぞれ次のブロックに載る
    let run = run_with(&[HONEST; 5], 3, 100);
    assert_eq!(run.done_at(), 4);
    // 黙る人がいると、約束の段階は締め切りまで閉じない。やり直しは全員が載せるので早い
    let run = run_with(&[HONEST, HONEST, Behavior::Silent], 2, 100);
    assert_eq!(run.excluded(), vec![(2, Reason::NoCommit)]);
    assert_eq!(run.done_at(), 101 + 3);
}

#[test]
fn outsider_computes_the_same_key_from_the_board() {
    let run = run(&[HONEST; 4], 2);
    let mut outsider = Board::new(*run.board.id());
    for (height, bytes) in &run.log {
        outsider.apply(*height, bytes);
    }
    outsider.settle(u64::MAX);
    assert_eq!(outsider.group_key(), Some(run.key()));
}

#[test]
fn silent_member_is_left_out_and_others_retry() {
    let run = run(&[HONEST, HONEST, Behavior::Silent, HONEST, HONEST], 3);
    assert_eq!(run.excluded(), vec![(2, Reason::NoCommit)]);
    assert_eq!(run.board.attempt().unwrap().number, 1);
    assert!(run.members[2].key_package().is_none());
    assert!(run.signs_with(&[0, 1, 4]));
}

#[test]
fn bad_share_revealed_on_complaint_keeps_the_dealer() {
    let run = run(
        &[
            HONEST,
            HONEST,
            HONEST,
            Behavior::BadShare {
                to: 1,
                reveal: true,
            },
            HONEST,
        ],
        3,
    );
    assert!(run.excluded().is_empty());
    assert!(run.events.iter().any(|event| matches!(
        event,
        Event::Revealed {
            dealer: 3,
            to: 1,
            ..
        }
    )));
    assert_eq!(run.board.attempt().unwrap().number, 0);
    // 苦情を言った人は、明かされた分け前で鍵を作れている
    assert!(run.signs_with(&[1, 3, 4]));
}

#[test]
fn bad_share_not_revealed_excludes_the_dealer() {
    let run = run(
        &[
            HONEST,
            Behavior::BadShare {
                to: 0,
                reveal: false,
            },
            HONEST,
            HONEST,
            HONEST,
        ],
        3,
    );
    assert_eq!(run.excluded(), vec![(1, Reason::NoReveal)]);
    assert!(run.members[1].key_package().is_none());
    assert!(run.signs_with(&[0, 2, 3]));
}

#[test]
fn false_complaint_costs_only_a_reveal() {
    let run = run(
        &[
            HONEST,
            HONEST,
            Behavior::FalseComplaint { against: 0 },
            HONEST,
        ],
        3,
    );
    assert!(run.excluded().is_empty());
    assert!(run.signs_with(&[0, 2, 3]));
}

#[test]
fn dealer_with_threshold_complaints_is_left_out_without_revealing() {
    let run = run(
        &[
            HONEST,
            Behavior::FalseComplaint { against: 0 },
            Behavior::FalseComplaint { against: 0 },
            HONEST,
        ],
        2,
    );
    assert_eq!(run.excluded(), vec![(0, Reason::TooManyComplaints)]);
    assert!(
        !run.events
            .iter()
            .any(|event| matches!(event, Event::Revealed { .. }))
    );
    assert!(run.signs_with(&[1, 3]));
}

#[test]
fn fails_when_too_few_remain() {
    let run = run(&[HONEST, Behavior::Silent, Behavior::Silent], 2);
    assert!(matches!(run.board.outcome(), Outcome::Failed));
    assert!(
        run.members
            .iter()
            .all(|member| member.key_package().is_none())
    );
}

#[test]
fn groups_sign_vault_setup_rotate_and_spend() {
    let parameters = NetworkParameters::from_identifier(NetworkIdentifier(152)).unwrap();
    let seed = &parameters.generation_hash_seed;
    let relay_key = PrivateKey::generate().unwrap();
    let relay = PublicKey::from_private_key(&relay_key);
    let vault = run(&[HONEST; 3], 2);
    let committee = run(&[HONEST; 3], 2);
    let next = run(&[HONEST; 3], 2);
    let group_sign = |run: &Run, message: &[u8]| {
        let Outcome::Done(public) = run.board.outcome() else {
            unreachable!()
        };
        let packages: Vec<_> = run.members[..2]
            .iter()
            .map(|member| member.key_package().unwrap())
            .collect();
        sign(&packages, public, message, &mut OsRng).unwrap()
    };
    let terms = (1, 100);
    // 中継役は、どのアグリゲートでも、中のどれかのトランザクションの署名者になっている（catapult の規則）
    let relay_signs_inside = |transaction: &heika_transaction::Transaction| {
        let heika_transaction::Body::AggregateComplete(aggregate) = &transaction.body else {
            return false;
        };
        aggregate
            .transactions()
            .iter()
            .any(|inner| inner.signer_public_key == relay)
    };

    let mut transaction = symbol::setup(
        parameters,
        terms,
        relay,
        vault.key(),
        committee.key(),
        1_000_000,
    );
    assert!(relay_signs_inside(&transaction));
    transaction.sign(&relay_key, seed).unwrap();
    let hash = transaction.hash(seed);
    for group in [&vault, &committee] {
        symbol::cosign(&mut transaction, group.key(), group_sign(group, &hash.0));
    }
    assert!(transaction.verify(seed));
    assert!(transaction.verify_cosignatures(seed));
    assert_eq!(transaction.hash(seed), hash);

    let mut transaction = symbol::rotate(
        parameters,
        terms,
        relay,
        vault.key(),
        committee.key(),
        next.key(),
    );
    assert!(relay_signs_inside(&transaction));
    transaction.sign(&relay_key, seed).unwrap();
    let hash = transaction.hash(seed);
    for group in [&committee, &next] {
        symbol::cosign(&mut transaction, group.key(), group_sign(group, &hash.0));
    }
    assert!(transaction.verify_cosignatures(seed));

    let mut transaction = symbol::spend(
        parameters,
        terms,
        relay,
        vault.key(),
        Address::from_public_key(&relay, parameters.identifier),
        1,
    );
    assert!(relay_signs_inside(&transaction));
    transaction.sign(&relay_key, seed).unwrap();
    let hash = transaction.hash(seed);
    symbol::cosign(&mut transaction, next.key(), group_sign(&next, &hash.0));
    assert!(transaction.verify_cosignatures(seed));

    // 預かり口座の鍵そのものの署名も、Symbol の署名として正しい（マルチシグにしたあとは、チェーンが弾く）
    let mut transaction = symbol::direct(parameters, terms, vault.key(), Address([0x98; 24]), 1);
    transaction.signature = group_sign(&vault, &transaction.signing_payload(seed));
    assert!(transaction.verify(seed));
}
