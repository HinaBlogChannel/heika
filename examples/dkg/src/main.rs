//! Symbol を掲示板にして、ディーラーなしで鍵を作り、預かり口座を動かす。参加者はみなこのプロセスの中にいる。
//!
//! ```sh
//! dkg run <ノードの設定> [1 段階のブロック数] < 中継役の秘密鍵
//! dkg observe <ノードの設定> <セッションの ID>
//! ```
//!
//! `run` は、DKG を 3 回して、預かり口座の連署者を入れ替えるところまでやる。
//!
//! 1. 預かり口座の鍵（①）と、委員会の鍵（②）を、それぞれ 5 人で作る（署名に要るのは 3 人）。2 つは同時に進める
//!    - ①では、1 人が壊れた分け前を配り、苦情を受けて正しいものを明かす（誰も外れない）
//!    - ②では、1 人が壊れた分け前を配り、苦情を受けても明かさない（外れて、残った 4 人でやり直す）
//! 2. 預かり口座を、②だけを連署者にした 1-of-1 のマルチシグにする。①と②が連署する
//! 3. ①の鍵で預かり口座から送ってみる（弾かれる）
//! 4. 新しい委員会の鍵（③）を作る。1 人は黙っている（外れて、残った 4 人でやり直す）
//! 5. 連署者を②から③に差し替える。②と③が連署する
//! 6. ②で預かり口座から送ってみる（弾かれる）。③で送る（通る）
//!
//! 掲示板に載せるのも、トランザクションに署名して手数料を払うのも、中継役。中継役の鍵は標準入力から読む。
//!
//! `observe` は、セッションの ID だけを手がかりに掲示板を読み、DKG の進み具合とグループ鍵を出す。
//! 参加者でなくても、同じ鍵になることを確かめられる。

use std::io::{self, BufRead};
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use dkg::board::{Board, Event, Outcome, Reason};
use dkg::member::{Behavior, Member};
use dkg::sign::sign;
use dkg::symbol::{self, Chain};
use dkg::wire::{self, Session};
use heika_core::address::Address;
use heika_core::hash::Hash256;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::signature::Signature;
use heika_transaction::Transaction;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// 1 つの DKG の参加者の数
const MEMBERS: usize = 5;
/// 署名に要る人数
const THRESHOLD: u16 = 3;
/// 1 段階のブロック数の既定。ファイナライズの遅れより長くないと、参加者が締め切りに間に合わない
const WINDOW: u64 = 20;
/// 預かり口座に入れる量（XYM の最小単位）
const DEPOSIT: u64 = 2_000_000;
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const POLL: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["run", config] => run(Path::new(config), WINDOW),
        ["run", config, window] => match window.parse() {
            Ok(window) if window > 0 => run(Path::new(config), window),
            _ => Err(format!("ブロック数が読めません: {window}")),
        },
        ["observe", config, id] => observe(Path::new(config), id),
        _ => {
            eprintln!("使い方: dkg run <ノードの設定> [1 段階のブロック数] < 中継役の秘密鍵");
            eprintln!("        dkg observe <ノードの設定> <セッションの ID>");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

/// 1 つの DKG。参加者と、参加者が見ている掲示板
struct Dkg {
    name: &'static str,
    session: Session,
    board: Board,
    members: Vec<Member>,
    inbox: Address,
    /// 次に読む高さ
    next: u64,
}

impl Dkg {
    fn new(chain: &Chain, name: &'static str, behaviors: [Behavior; MEMBERS], window: u64) -> Self {
        let members: Vec<Member> = behaviors
            .into_iter()
            .enumerate()
            .map(|(index, behavior)| {
                Member::new(
                    index as u16,
                    PrivateKey::generate().expect("OS の乱数"),
                    behavior,
                )
            })
            .collect();
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let session = Session {
            threshold: THRESHOLD,
            window,
            nonce,
            members: members.iter().map(Member::public_key).collect(),
        };
        let id = session.id();
        Self {
            name,
            session,
            board: Board::new(id),
            members,
            inbox: wire::inbox(&id, chain.parameters.identifier),
            next: 1,
        }
    }

    /// 掲示板の高さ `finalized` までを読み、参加者に動いてもらう。載せるものを返す
    fn step(&mut self, chain: &Chain, finalized: u64) -> Result<Vec<Vec<u8>>, String> {
        if finalized >= self.next {
            for (height, bytes) in chain.posted(&self.inbox, self.next, finalized)? {
                self.board.apply(height, &bytes);
            }
            self.next = finalized + 1;
        }
        self.board.settle(finalized);
        for event in self.board.take_events() {
            println!("[{}] {}", self.name, describe(chain, &event));
        }
        let mut posts = Vec::new();
        for member in &mut self.members {
            posts.extend(member.act(&self.board, &mut OsRng)?);
        }
        Ok(posts)
    }

    /// 鍵ができて、最後の試みの参加者がみな自分の分け前を持っているか
    fn finished(&self) -> Result<bool, String> {
        match self.board.outcome() {
            Outcome::Running => Ok(false),
            Outcome::Failed => Err(format!("[{}] 鍵を作れませんでした", self.name)),
            Outcome::Done(_) => {
                let attempt = self.board.attempt().expect("started");
                Ok(attempt
                    .active
                    .iter()
                    .all(|index| self.members[usize::from(*index)].key_package().is_some()))
            }
        }
    }

    fn key(&self) -> PublicKey {
        self.board.group_key().expect("done")
    }

    /// 分け前を持っている最初の [`THRESHOLD`] 人で署名する
    fn sign(&self, message: &[u8]) -> Result<Signature, String> {
        let Outcome::Done(public) = self.board.outcome() else {
            return Err("鍵がまだありません".to_owned());
        };
        let signers: Vec<_> = self
            .members
            .iter()
            .filter_map(Member::key_package)
            .take(usize::from(THRESHOLD))
            .collect();
        sign(&signers, public, message, &mut OsRng)
    }
}

/// `dkgs` を同時に進め、全部の鍵ができるまで待つ
fn run_dkgs(chain: &Chain, relay: &PrivateKey, dkgs: &mut [Dkg]) -> Result<(), String> {
    let finalized = chain.finalized_height()?;
    for dkg in dkgs.iter_mut() {
        chain.post(relay, &dkg.inbox, &dkg.session.encode())?;
        dkg.next = finalized + 1;
        println!(
            "[{}] セッション {} を始めます（参加者 {MEMBERS} 人、署名に要るのは {THRESHOLD} 人、1 段階は {} ブロック）",
            dkg.name,
            Hash256(*dkg.board.id()),
            dkg.session.window,
        );
    }
    loop {
        let finalized = chain.finalized_height()?;
        let mut finished = true;
        for dkg in dkgs.iter_mut() {
            for post in dkg.step(chain, finalized)? {
                chain.post(relay, &dkg.inbox, &post)?;
            }
            finished &= dkg.finished()?;
        }
        if finished {
            return Ok(());
        }
        thread::sleep(POLL);
    }
}

fn describe(chain: &Chain, event: &Event) -> String {
    let who = |member: &u16| format!("参加者 {}", member + 1);
    match event {
        Event::Started { height } => format!("高さ {height} で始まりました"),
        Event::Complained {
            attempt,
            member,
            against,
        } => format!(
            "試み {attempt}: {} が、{} からの分け前に苦情を言いました",
            who(member),
            against.iter().map(who).collect::<Vec<_>>().join("、")
        ),
        Event::Revealed {
            attempt,
            dealer,
            to,
        } => format!(
            "試み {attempt}: {} が、{} 宛ての分け前を明かしました（コミットメントと合っています）",
            who(dealer),
            who(to)
        ),
        Event::Excluded {
            attempt,
            member,
            reason,
        } => {
            let reason = match reason {
                Reason::NoCommit => "締め切りまでに約束しませんでした",
                Reason::NoShares => "締め切りまでに配りませんでした",
                Reason::NoReveal => "苦情を受けて、正しい分け前を明かしませんでした",
                Reason::TooManyComplaints => "しきい値以上の人から苦情を受けました",
            };
            format!("試み {attempt}: {} を外します（{reason}）", who(member))
        }
        Event::Retried { attempt, start } => {
            format!("高さ {start} の次から、残った人でやり直します（試み {attempt}）")
        }
        Event::Done { height, key } => {
            format!("高さ {height} で鍵ができました: {}", chain.address(key))
        }
        Event::Failed { height } => format!("高さ {height} で、人数が足りなくなりました"),
    }
}

/// 中継役が署名したアグリゲートに、`groups` が連署して出し、承認を待つ
fn submit(
    chain: &Chain,
    relay: &PrivateKey,
    mut transaction: Transaction,
    groups: &[&Dkg],
) -> Result<u64, String> {
    let seed = &chain.parameters.generation_hash_seed;
    transaction
        .sign(relay, seed)
        .map_err(|error| error.to_string())?;
    let hash = transaction.hash(seed);
    for group in groups {
        symbol::cosign(&mut transaction, group.key(), group.sign(&hash.0)?);
    }
    chain.announce(&transaction)?;
    chain.confirm(&transaction, CONFIRM_TIMEOUT)
}

/// 弾かれるはずのものを出す。通ってしまったら `Err`
fn expect_rejected(result: Result<u64, String>) -> Result<String, String> {
    match result {
        Ok(height) => Err(format!("高さ {height} で通ってしまいました")),
        Err(reason) => Ok(reason),
    }
}

fn run(config: &Path, window: u64) -> Result<(), String> {
    let chain = Chain::load(config)?;
    let parameters = chain.parameters;
    let mut line = Zeroizing::new(String::new());
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|error| error.to_string())?;
    let relay_key: PrivateKey = line
        .trim()
        .parse()
        .map_err(|_| "標準入力の秘密鍵が読めません".to_owned())?;
    let relay = PublicKey::from_private_key(&relay_key);
    let relay_address = chain.address(&relay);

    use Behavior::{BadShare, Honest, Silent};
    let mut first = [
        Dkg::new(
            &chain,
            "① 預かり口座",
            [
                Honest,
                Honest,
                Honest,
                BadShare {
                    to: 1,
                    reveal: true,
                },
                Honest,
            ],
            window,
        ),
        Dkg::new(
            &chain,
            "② 委員会",
            [
                Honest,
                BadShare {
                    to: 0,
                    reveal: false,
                },
                Honest,
                Honest,
                Honest,
            ],
            window,
        ),
    ];
    run_dkgs(&chain, &relay_key, &mut first)?;
    let [vault, committee] = first;
    let vault_key = vault.key();
    let vault_address = chain.address(&vault_key);

    let height = submit(
        &chain,
        &relay_key,
        symbol::setup(
            parameters,
            chain.terms()?,
            relay,
            vault_key,
            committee.key(),
            DEPOSIT,
        ),
        &[&vault, &committee],
    )?;
    println!(
        "高さ {height} で、預かり口座 {vault_address} を、②だけを連署者にしたマルチシグにしました（{} XYM を入れました）",
        xym(DEPOSIT)
    );

    let mut transaction = symbol::direct(parameters, chain.terms()?, vault_key, relay_address, 1);
    let seed = &parameters.generation_hash_seed;
    transaction.signature = vault.sign(&transaction.signing_payload(seed))?;
    let reason = expect_rejected(
        chain
            .announce(&transaction)
            .and_then(|()| chain.confirm(&transaction, CONFIRM_TIMEOUT)),
    )?;
    println!("①の鍵で預かり口座から送ろうとすると、{reason}");

    let mut second = [Dkg::new(
        &chain,
        "③ 新しい委員会",
        [Honest, Honest, Honest, Honest, Silent],
        window,
    )];
    run_dkgs(&chain, &relay_key, &mut second)?;
    let [next] = second;

    let height = submit(
        &chain,
        &relay_key,
        symbol::rotate(
            parameters,
            chain.terms()?,
            relay,
            vault_key,
            committee.key(),
            next.key(),
        ),
        &[&committee, &next],
    )?;
    println!(
        "高さ {height} で、預かり口座の連署者を②から③に差し替えました（預かった XYM は動かしていません）"
    );

    let spend = |terms| {
        symbol::spend(
            parameters,
            terms,
            relay,
            vault_key,
            relay_address,
            DEPOSIT / 2,
        )
    };
    let reason = expect_rejected(submit(
        &chain,
        &relay_key,
        spend(chain.terms()?),
        &[&committee],
    ))?;
    println!("②で預かり口座から送ろうとすると、{reason}");
    let height = submit(&chain, &relay_key, spend(chain.terms()?), &[&next])?;
    println!(
        "高さ {height} で、③が預かり口座から {} XYM を送りました",
        xym(DEPOSIT / 2)
    );
    Ok(())
}

fn observe(config: &Path, id: &str) -> Result<(), String> {
    let chain = Chain::load(config)?;
    let id: Hash256 = id
        .parse()
        .map_err(|_| format!("セッションの ID が読めません: {id}"))?;
    let mut board = Board::new(id.0);
    let inbox = wire::inbox(&id.0, chain.parameters.identifier);
    let mut next = 1;
    loop {
        let finalized = chain.finalized_height()?;
        if finalized >= next {
            for (height, bytes) in chain.posted(&inbox, next, finalized)? {
                board.apply(height, &bytes);
            }
            next = finalized + 1;
        }
        board.settle(finalized);
        for event in board.take_events() {
            println!("{}", describe(&chain, &event));
        }
        if !matches!(board.outcome(), Outcome::Running) {
            return Ok(());
        }
        thread::sleep(POLL);
    }
}

fn xym(amount: u64) -> String {
    format!("{}.{:06}", amount / 1_000_000, amount % 1_000_000)
}
