//! ブロックと状態を redb にしまう DB。
//!
//! redb の型はこのクレートの外に出さない。
//! 書くものはまとめて1つのトランザクションでコミットするので、ブロックと、あとで足す状態や差分の高さがずれることはない。
//!
//! 表:
//! - `blocks`: 高さ → ブロックのバイト列
//! - `state`: 木の番号 + 状態のキー → 状態（`execute::persist`）
//! - `meta`: 名前 → 値。`executor` に、木に入らない実行の状態
//! - `changesets`: （高さ、状態のキー）→ その高さのブロックで変わる前の状態。`ABSENT`（0 の 1 バイト）ならなかった
//! - `history`: （状態のキー、高さ）→ なし。キーが変わった高さの索引
//! - `proofs`: エポック → ファイナライズの証明のバイト列（catapult の `FinalizationProof`）
//! - `voters`: エポック → 投票者（`heika_block::finalization::proof::VotingSet::encode`）。実行のついでに、前のエポックの最後の高さで書く
//! - `trie`、`trie_changesets`、`trie_history`: 同じ3つを、状態の木のノードで。キーは木の番号とノードの位置
//! - `checkpoints`: 高さ → その高さでコミットした、木に入らない実行の状態（`meta` の `executor` と同じもの）。巻き戻しに使う
//! - `statements`: 高さ → ブロックのステートメント
//! - `orphans`: （高さ、ハッシュ）→ 枝の取り替えで外れた元の枝のブロック
//! - `peers`: アドレス → 知っているノードの記録
//! - `search`: 検索表（[`search`]）。REST の検索のために、今の状態の行を別の切り口で並べ直したキー → なし
//! - `search_past`: 検索表から消えたキー → なし。昔の高さで検索するときの候補（[`Searches::PAST`]）
//! - `namespace_names`: ネームスペースの ID → 親の ID（ルートは 0）と名前。ブロックの登録から拾う（[`Searches::NAMESPACES`]）
//! - `transaction_hashes`: トランザクション（アグリゲートの中のものは除く）のハッシュ → （高さ、ブロックの中の番号）
//!   （[`Searches::TRANSACTIONS`]）
//! - `address_transactions`: （関わったアドレス、高さ、ブロックの中の番号）→ なし。アドレスからトランザクションを引く
//!   （[`Searches::TRANSACTIONS`]）
//!
//! `meta` の `format` に、この形の版（[`FORMAT`]）を書く。違う版の DB は開かない。
//!
//! 昔の高さの値は Reth と同じやり方で引く。求める高さより後で最初に変わった高さを `history` から探し、
//! その高さの `changesets` にある変わる前の値を使う。後で変わっていなければ今の値を使う。
//!
//! たくさん実行するあいだは、`history` を書かずに後でまとめて作れる（[`Db::defer_history`]、[`Db::build_history`]）。
//! `history` は高さの順に書くと、キーがばらばらなので B 木のあちこちを書き換えることになり、重いため。
//! まだ作っていない高さがあるあいだは、昔の値は引けない。

mod chain_store;
pub mod search;

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use heika_core::hash::Hash256;
use heika_state_transition::executor::ExecError;
use heika_state_transition::executor::source::StateSource;

pub use search::{MetadataFields, Searches, TransactionNetwork};

use heika_block::statement::BlockStatement;
use search::IndexedTransaction;

use redb::{
    AccessGuard, Database, Durability, Key, ReadOnlyDatabase, ReadOnlyTable, ReadTransaction,
    ReadableDatabase, ReadableTable, ReadableTableMetadata, StorageError, TableDefinition,
    TableHandle, Value, WriteTransaction,
};

const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
const STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const PROOFS: TableDefinition<u32, &[u8]> = TableDefinition::new("proofs");
const VOTERS: TableDefinition<u32, &[u8]> = TableDefinition::new("voters");
/// 高さ → そのブロックを実行して出たステートメント（heika-block の `BlockStatement` のバイト列）
const STATEMENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("statements");
/// 高さ → その高さでコミットした、木に入らない実行の状態。高さごとの差分がないので、巻き戻すときはここから実行し直す
const CHECKPOINTS: TableDefinition<u64, &[u8]> = TableDefinition::new("checkpoints");
/// （高さ, ハッシュ）→ 先端の段階で枝を取り替えて、自分の枝から外れたブロックのバイト列
const ORPHANS: TableDefinition<(u64, &[u8]), &[u8]> = TableDefinition::new("orphans");
/// ノードのアドレス → 住所録の記録（最後につながった時刻と、続けて失敗した回数）。チェーンのものではないので、
/// [`Db::copy_to`] では写さない
const PEERS: TableDefinition<&str, &[u8]> = TableDefinition::new("peers");
/// 検索表（[`search`]）
const SEARCH: TableDefinition<&[u8], ()> = TableDefinition::new("search");
/// 検索表から消えたキー（[`search`]）
const SEARCH_PAST: TableDefinition<&[u8], ()> = TableDefinition::new("search_past");
/// ネームスペースの ID → 親の ID（u64、ルートは 0）と名前。ID は親と名前から決まるので、足すだけで消さない
const NAMES: TableDefinition<u64, &[u8]> = TableDefinition::new("namespace_names");
/// 名前の表を、しまってあるブロックから作る残り（次に読む高さと、そこまで読む高さ）をしまう `meta` の名前
const NAMES_BACKFILL: &str = "namespace_names_backfill";
/// 作る検索（[`Searches`] のビット）をしまう `meta` の名前
const SEARCH_META: &str = "search";
/// トランザクションのハッシュ → （高さ、ブロックの中の番号）。枝を取り替えたら、外れたブロックの分を消す。
/// ブロックを刈り込んでも消さないので、引いた先のブロックがないこともある
const TRANSACTION_HASHES: TableDefinition<&[u8], (u64, u32)> =
    TableDefinition::new("transaction_hashes");
/// （関わったアドレス、高さ、ブロックの中の番号）→ なし（[`search::address_key`]）。関わったアドレスは
/// [`search::involved_addresses`] と、ステートメントから解決した先（[`search::resolved_addresses`]）。
/// 枝を取り替えたら、外れたブロックの分を消す。ブロックを刈り込んでも消さない
const ADDRESS_TRANSACTIONS: TableDefinition<&[u8], ()> =
    TableDefinition::new("address_transactions");
/// ハッシュとアドレスの表を、しまってあるブロックから作る残りをしまう `meta` の名前（[`NAMES_BACKFILL`] と同じ形）
const TRANSACTIONS_BACKFILL: &str = "transaction_hashes_backfill";
/// トランザクションの索引を作るのに要るネットワークの値（[`TransactionNetwork`]）をしまう `meta` の名前
const NETWORK_META: &str = "transaction_network";

/// 今の値、差分、索引の3つの表と、差分を残し始めた高さをしまう `meta` の名前
#[derive(Clone, Copy)]
struct Versioned {
    current: TableDefinition<'static, &'static [u8], &'static [u8]>,
    changesets: TableDefinition<'static, (u64, &'static [u8]), &'static [u8]>,
    history: TableDefinition<'static, (&'static [u8], u64), ()>,
    /// これより前の高さの値は引けない
    from: &'static str,
    /// `meta` にあれば、`history` はこの高さまでしかできていない。なければ全部できている
    indexed: &'static str,
}

/// 状態の行
const STATE_TABLES: Versioned = Versioned {
    current: STATE,
    changesets: TableDefinition::new("changesets"),
    history: TableDefinition::new("history"),
    from: "history_from",
    indexed: "history_indexed",
};

/// 状態の木のノード
const TRIE_TABLES: Versioned = Versioned {
    current: TableDefinition::new("trie"),
    changesets: TableDefinition::new("trie_changesets"),
    history: TableDefinition::new("trie_history"),
    from: "trie_from",
    indexed: "trie_indexed",
};

/// `changesets` で、変わる前にはなかったことを表す値。ある値は先頭に [`PRESENT`] を付ける
const ABSENT: &[u8] = &[0];
const PRESENT: u8 = 1;

/// `meta` にあれば、ステートメントはこの高さからしか残っていない（刈り込んだ）
const STATEMENTS_FROM: &str = "statements_from";
/// この高さより前のブロックは消してある（[`Db::prune_history`]）
const BLOCKS_FROM: &str = "blocks_from";
/// 1つのトランザクションで消す行の数の上限。古い DB をまとめて刈り込むときに、トランザクションが大きくなりすぎないように
const HISTORY_CHUNK: usize = 100_000;

/// 刈り込みで消したもの
#[derive(Debug, PartialEq, Eq)]
pub struct Pruned {
    /// 消した差分の行の数（索引の行も同じ数だけ消える）
    pub rows: u64,
    /// 境まで消し終えたか。偽なら途中で止めた
    pub done: bool,
}

/// 刈り込みながら写すときの境（[`Db::copy_to`]）。それぞれ、この高さより上の差分だけを写す
#[derive(Clone, Copy, Debug)]
pub struct CopyBounds {
    pub state: u64,
    pub trie: u64,
    /// ステートメントも、この高さより上だけを写す。`None` なら全部
    pub statements: Option<u64>,
    /// ブロックをこの高さより上だけ、ファイナライズの証明をこのエポックから写す（[`Db::prune_history`] と同じ境）。
    /// `None` なら全部
    pub blocks: Option<(u64, u32)>,
}

/// 状態の行（キー、値）
pub type StateRow = (Vec<u8>, Vec<u8>);

/// 変わった状態（キー、変わる前の値）
pub type Change = (Vec<u8>, Option<Vec<u8>>);

/// 表の大きさ（名前、行の数、キーと値のバイト数、B 木の枝などのバイト数、断片のバイト数）
pub type TableSize = (String, u64, u64, u64, u64);

/// 書けるように開いた DB の、既定のキャッシュの上限。小さいと、たくさん書くあいだにキャッシュから追い出す書き込みで
/// 待つ。一つずつ書くだけなら小さくてよい（[`Db::open_with_cache`]）
pub const DEFAULT_CACHE_SIZE: usize = 16 << 30;

/// DB のファイルの名前
pub const FILE_NAME: &str = "heika.redb";

/// DB の形の版。表や値の形を変えたら上げる
pub const FORMAT: u32 = 1;

/// `meta` の、形の版の名前
const FORMAT_META: &str = "format";

/// DB のエラー。
#[derive(Debug)]
pub enum DbError {
    /// redb が返したもの
    Storage(redb::Error),
    /// 読むだけに開いた DB に書こうとした
    ReadOnly,
    /// ディスクの空きが決めた量より少ないので、書く前に止めた
    LowSpace { free: u64, min_free: u64 },
    /// 差分を残し始めるより前の高さの状態を引こうとした
    NoHistory { height: u64, from: u64 },
    /// 巻き戻す先の高さ以下に、チェックポイントがない
    NoCheckpoint { height: u64 },
    /// 形の版が [`FORMAT`] でない（`None` は印がない）
    Format(Option<u32>),
    /// `history` をまだ作っていない高さがあるので、昔の値は引けない
    NotIndexed { through: u64 },
    /// トランザクションの索引を作るのに、ネットワークの値がない（[`Db::set_transaction_network`]）
    NoNetwork,
    /// しまってあるネットワークの値が、渡されたものと違う（別のネットワークの DB）
    OtherNetwork,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "DB: {error}"),
            Self::ReadOnly => write!(f, "DB: 読むだけに開いた DB には書けません"),
            Self::LowSpace { free, min_free } => write!(
                f,
                "DB: ディスクの空きが {} GB で、{} GB より少ないので書く前に止めました",
                free / GB,
                min_free / GB
            ),
            Self::NoHistory { height, from } => write!(
                f,
                "DB: 差分は高さ {from} からなので、高さ {height} の状態は引けません"
            ),
            Self::NotIndexed { through } => write!(
                f,
                "DB: 差分の索引は高さ {through} までしかできていないので、昔の値は引けません。index で作ってください"
            ),
            Self::NoCheckpoint { height } => write!(
                f,
                "DB: 高さ {height} 以下にチェックポイントがないので、巻き戻せません"
            ),
            Self::Format(Some(version)) => write!(
                f,
                "DB: 形の版が {version} で、この版で読める {FORMAT} と違います"
            ),
            Self::Format(None) => write!(f, "DB: 形の版の印がありません"),
            Self::NoNetwork => write!(
                f,
                "DB: トランザクションの索引を作るのに要る、ネットワークの値がありません"
            ),
            Self::OtherNetwork => write!(
                f,
                "DB: しまってあるネットワークの値（generation hash seed など）が、このネットワークのものと違います"
            ),
        }
    }
}

impl std::error::Error for DbError {}

const GB: u64 = 1_000_000_000;

fn check_format(format: Option<&[u8]>) -> Result<(), DbError> {
    let version = format
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes);
    match version {
        Some(FORMAT) => Ok(()),
        version => Err(DbError::Format(version)),
    }
}

fn db_error(error: impl Into<redb::Error>) -> DbError {
    DbError::Storage(error.into())
}

enum Handle {
    Write(Database),
    Read(ReadOnlyDatabase),
}

/// 開いた DB。書く側は1つのプロセスだけで、書いているあいだはほかのプロセスから読むだけにも開けない。
pub struct Db {
    handle: Handle,
    directory: std::path::PathBuf,
    /// 書く前に確かめるディスクの空き。0 なら確かめない
    min_free: u64,
    /// [`Batch`] で `history` を書かない
    defer_history: bool,
    /// [`Batch`] で、状態と木のノードのそれぞれ、この高さ以下では差分も索引も書かない（刈り込んで実行する）
    quiet_through: [Option<u64>; 2],
    /// 作る検索。`meta` の `search` と同じ
    search: Searches,
    /// トランザクションの索引を作るのに要るネットワークの値。`meta` の `transaction_network` と同じ
    network: Option<TransactionNetwork>,
}

impl Db {
    /// `directory` の DB を、書けるように開く。なければ作る。キャッシュは [`DEFAULT_CACHE_SIZE`] まで
    pub fn open(directory: &Path) -> Result<Self, DbError> {
        Self::open_with_cache(directory, DEFAULT_CACHE_SIZE)
    }

    /// [`Db::open`] を、キャッシュの上限 `cache_size` バイトで
    pub fn open_with_cache(directory: &Path, cache_size: usize) -> Result<Self, DbError> {
        std::fs::create_dir_all(directory).map_err(db_error)?;
        let database = Database::builder()
            .set_cache_size(cache_size)
            .create(directory.join(FILE_NAME))
            .map_err(db_error)?;
        // 表がないと読むときに困るので、最初に作っておく
        let transaction = database.begin_write().map_err(db_error)?;
        transaction.open_table(BLOCKS).map_err(db_error)?;
        transaction.open_table(STATE).map_err(db_error)?;
        transaction.open_table(META).map_err(db_error)?;
        transaction.open_table(PROOFS).map_err(db_error)?;
        transaction.open_table(VOTERS).map_err(db_error)?;
        transaction.open_table(CHECKPOINTS).map_err(db_error)?;
        transaction.open_table(ORPHANS).map_err(db_error)?;
        transaction.open_table(PEERS).map_err(db_error)?;
        transaction.open_table(SEARCH).map_err(db_error)?;
        transaction.open_table(SEARCH_PAST).map_err(db_error)?;
        transaction.open_table(NAMES).map_err(db_error)?;
        transaction
            .open_table(TRANSACTION_HASHES)
            .map_err(db_error)?;
        transaction
            .open_table(ADDRESS_TRANSACTIONS)
            .map_err(db_error)?;
        for tables in [STATE_TABLES, TRIE_TABLES] {
            transaction.open_table(tables.current).map_err(db_error)?;
            transaction
                .open_table(tables.changesets)
                .map_err(db_error)?;
            transaction.open_table(tables.history).map_err(db_error)?;
        }
        // 空の DB なら版の印を書き、そうでなければ確かめる
        {
            let mut meta = transaction.open_table(META).map_err(db_error)?;
            let format = meta
                .get(FORMAT_META)
                .map_err(db_error)?
                .map(|value| value.value().to_vec());
            let empty = transaction
                .open_table(BLOCKS)
                .map_err(db_error)?
                .is_empty()
                .map_err(db_error)?
                && meta.is_empty().map_err(db_error)?;
            match format {
                None if empty => {
                    meta.insert(FORMAT_META, &FORMAT.to_le_bytes()[..])
                        .map_err(db_error)?;
                }
                format => check_format(format.as_deref())?,
            }
        }
        let (search, network) = {
            let meta = transaction.open_table(META).map_err(db_error)?;
            (read_searches(&meta)?, read_network(&meta)?)
        };
        transaction.commit().map_err(db_error)?;
        Ok(Self {
            handle: Handle::Write(database),
            directory: directory.to_path_buf(),
            min_free: 0,
            defer_history: false,
            quiet_through: [None; 2],
            search,
            network,
        })
    }

    /// 読むだけに開く。
    pub fn open_read_only(directory: &Path) -> Result<Self, DbError> {
        let database = ReadOnlyDatabase::open(directory.join(FILE_NAME)).map_err(db_error)?;
        let (format, search, network) = {
            let transaction = database.begin_read().map_err(db_error)?;
            let meta = transaction.open_table(META).map_err(db_error)?;
            let format = meta
                .get(FORMAT_META)
                .map_err(db_error)?
                .map(|value| value.value().to_vec());
            (format, read_searches(&meta)?, read_network(&meta)?)
        };
        check_format(format.as_deref())?;
        Ok(Self {
            handle: Handle::Read(database),
            directory: directory.to_path_buf(),
            min_free: 0,
            defer_history: false,
            quiet_through: [None; 2],
            search,
            network,
        })
    }

    /// トランザクションの索引（[`Searches::TRANSACTIONS`]）を作るのに要る、ネットワークの値を覚える。まだなければ
    /// `meta` に書き、違うものがしまってあれば [`DbError::OtherNetwork`]
    pub fn set_transaction_network(&mut self, network: TransactionNetwork) -> Result<(), DbError> {
        match self.network {
            Some(stored) if stored == network => return Ok(()),
            Some(_) => return Err(DbError::OtherNetwork),
            None => {}
        }
        let mut batch = self.batch()?;
        batch.put_meta(NETWORK_META, &network.encode())?;
        batch.commit()?;
        self.network = Some(network);
        Ok(())
    }

    /// 作っている検索
    pub fn searches(&self) -> Searches {
        self.search
    }

    /// 作る検索を `searches` にする。足した検索は今の状態の行から作り、外した検索の行は消す。
    /// [`Searches::PAST`] なら、検索表から消えたキーも、状態の差分の前の値から作る。
    /// 1つのトランザクションでコミットする。外して小さくなった DB を詰めるなら [`Db::copy_to`]
    pub fn set_search(&mut self, searches: Searches) -> Result<(), DbError> {
        if searches == self.search {
            return Ok(());
        }
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        if searches.contains(Searches::TRANSACTIONS) && self.network.is_none() {
            return Err(DbError::NoNetwork);
        }
        self.check_space()?;
        let (old, new) = (self.search, searches);
        let transaction = database.begin_write().map_err(db_error)?;
        {
            let mut current = transaction.open_table(SEARCH).map_err(db_error)?;
            let mut past = transaction.open_table(SEARCH_PAST).map_err(db_error)?;
            // 外した検索の行と、昔の高さをやめたなら消えたキーを全部消す
            let removed = Searches::from_bits(old.kinds().bits() & !new.kinds().bits());
            for prefix in removed.prefixes() {
                for table in [&mut current, &mut past] {
                    table
                        .extract_from_if(&[prefix][..]..&[prefix + 1][..], |_, _| true)
                        .map_err(db_error)?
                        .for_each(drop);
                }
            }
            if !new.contains(Searches::PAST) {
                past.extract_if(|_, _| true)
                    .map_err(db_error)?
                    .for_each(drop);
            }
            let state = transaction.open_table(STATE).map_err(db_error)?;
            let added = Searches::from_bits(new.kinds().bits() & !old.kinds().bits());
            for cache in search::caches(added) {
                for row in state
                    .range(&[cache][..]..&[cache + 1][..])
                    .map_err(db_error)?
                {
                    let (key, value) = row.map_err(db_error)?;
                    for search_key in search::keys_of(added, key.value(), Some(value.value())) {
                        current
                            .insert(search_key.as_slice(), ())
                            .map_err(db_error)?;
                    }
                }
            }
            // 消えたキーは、状態の差分の前の値から。昔の高さを今始めたなら全部の検索の、もう始めていたなら足した検索の分
            if new.contains(Searches::PAST) {
                let backfill = if old.contains(Searches::PAST) {
                    added
                } else {
                    new.kinds()
                };
                let history = transaction
                    .open_table(STATE_TABLES.history)
                    .map_err(db_error)?;
                let changesets = transaction
                    .open_table(STATE_TABLES.changesets)
                    .map_err(db_error)?;
                for cache in search::caches(backfill) {
                    let range = history
                        .range((&[cache][..], 0)..(&[cache + 1][..], 0))
                        .map_err(db_error)?;
                    for row in range {
                        let (entry, _) = row.map_err(db_error)?;
                        let (key, height) = entry.value();
                        let Some(before) = changesets.get((height, key)).map_err(db_error)? else {
                            continue;
                        };
                        let [PRESENT, value @ ..] = before.value() else {
                            continue;
                        };
                        for search_key in search::keys_of(backfill, key, Some(value)) {
                            if current
                                .get(search_key.as_slice())
                                .map_err(db_error)?
                                .is_none()
                            {
                                past.insert(search_key.as_slice(), ()).map_err(db_error)?;
                            }
                        }
                    }
                }
            }
            let mut meta = transaction.open_table(META).map_err(db_error)?;
            // 名前とハッシュの表は、足したらしまってあるブロックから作り（[`Db::backfill_names`]、
            // [`Db::backfill_transactions`]）、外したら消す
            let blocks = transaction.open_table(BLOCKS).map_err(db_error)?;
            let range = (
                blocks
                    .first()
                    .map_err(db_error)?
                    .map(|(height, _)| height.value()),
                blocks
                    .last()
                    .map_err(db_error)?
                    .map(|(height, _)| height.value()),
            );
            for (search, pending_key) in [
                (Searches::NAMESPACES, NAMES_BACKFILL),
                (Searches::TRANSACTIONS, TRANSACTIONS_BACKFILL),
            ] {
                if added.contains(search)
                    && let (Some(first), Some(last)) = range
                {
                    let pending = [first.to_le_bytes(), last.to_le_bytes()].concat();
                    meta.insert(pending_key, pending.as_slice())
                        .map_err(db_error)?;
                }
                if removed.contains(search) {
                    meta.remove(pending_key).map_err(db_error)?;
                }
            }
            if removed.contains(Searches::NAMESPACES) {
                transaction
                    .open_table(NAMES)
                    .map_err(db_error)?
                    .extract_if(|_, _| true)
                    .map_err(db_error)?
                    .for_each(drop);
            }
            if removed.contains(Searches::TRANSACTIONS) {
                transaction
                    .open_table(TRANSACTION_HASHES)
                    .map_err(db_error)?
                    .extract_if(|_, _| true)
                    .map_err(db_error)?
                    .for_each(drop);
                transaction
                    .open_table(ADDRESS_TRANSACTIONS)
                    .map_err(db_error)?
                    .extract_if(|_, _| true)
                    .map_err(db_error)?
                    .for_each(drop);
            }
            meta.insert(SEARCH_META, &[new.bits()][..])
                .map_err(db_error)?;
        }
        transaction.commit().map_err(db_error)?;
        self.search = new;
        Ok(())
    }

    /// 名前の表を、しまってあるブロックから作る（[`Searches::NAMESPACES`] を足したとき）。まとまりごとにコミットし、
    /// 止めても次は続きから。`stopping` が真になるか、全部読んだら返る。全部読んだら `true`。
    /// `progress` には、読んだ高さと、そこまで読む高さを渡す
    pub fn backfill_names(
        &self,
        stopping: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<bool, DbError> {
        self.backfill(
            NAMES_BACKFILL,
            stopping,
            progress,
            &|transaction, blocks| {
                let mut names = transaction.open_table(NAMES).map_err(db_error)?;
                for (_, block) in blocks {
                    for (id, parent, name) in search::names_in_block(block) {
                        let value = [&parent.to_le_bytes()[..], &name].concat();
                        names.insert(id, value.as_slice()).map_err(db_error)?;
                    }
                }
                Ok(())
            },
        )
    }

    /// トランザクションのハッシュとアドレスの表を、しまってあるブロックとステートメントから作る
    /// （[`Searches::TRANSACTIONS`] を足したとき）。作り方は [`Db::backfill_names`] と同じ
    pub fn backfill_transactions(
        &self,
        stopping: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<bool, DbError> {
        use rayon::prelude::*;
        if self.meta(TRANSACTIONS_BACKFILL)?.is_none() {
            return Ok(true);
        }
        let network = self.network.ok_or(DbError::NoNetwork)?;
        self.backfill(
            TRANSACTIONS_BACKFILL,
            stopping,
            progress,
            &|transaction, blocks| {
                let statements: Vec<Option<Vec<u8>>> = {
                    let table = transaction.open_table(STATEMENTS).map_err(db_error)?;
                    blocks
                        .iter()
                        .map(|(height, _)| {
                            Ok(table
                                .get(*height)
                                .map_err(db_error)?
                                .map(|value| value.value().to_vec()))
                        })
                        .collect::<Result<_, DbError>>()?
                };
                // 読んで求めるのが重いので、ブロックごとに並列に
                let indexed: Vec<(u64, Vec<IndexedTransaction>)> = blocks
                    .par_iter()
                    .zip(statements.par_iter())
                    .map(|((height, block), statement)| {
                        (
                            *height,
                            indexed_with_resolutions(block, statement.as_deref(), &network),
                        )
                    })
                    .collect();
                let mut hashes = transaction
                    .open_table(TRANSACTION_HASHES)
                    .map_err(db_error)?;
                let mut addresses = transaction
                    .open_table(ADDRESS_TRANSACTIONS)
                    .map_err(db_error)?;
                for (height, transactions) in indexed {
                    for entry in transactions {
                        hashes
                            .insert(entry.hash.0.as_slice(), (height, entry.index))
                            .map_err(db_error)?;
                        for address in &entry.addresses {
                            let key = search::address_key(address, height, entry.index);
                            addresses.insert(key.as_slice(), ()).map_err(db_error)?;
                        }
                    }
                }
                Ok(())
            },
        )
    }

    /// しまってあるブロックを、`meta` の `pending_key` にある残りの分だけ、まとまりごとに `add` に渡してコミットする
    fn backfill(
        &self,
        pending_key: &str,
        stopping: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(u64, u64),
        add: &BackfillAdd<'_>,
    ) -> Result<bool, DbError> {
        /// 1回のコミットで読むブロックの数
        const CHUNK: u64 = 100_000;
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        loop {
            let Some(pending) = self.meta(pending_key)? else {
                return Ok(true);
            };
            if stopping() {
                return Ok(false);
            }
            let (next, through) = (u64_from(&pending[..8]), u64_from(&pending[8..]));
            let last = through.min(next.saturating_add(CHUNK - 1));
            self.check_space()?;
            let transaction = database.begin_write().map_err(db_error)?;
            {
                let blocks: Vec<(u64, Vec<u8>)> = {
                    let table = transaction.open_table(BLOCKS).map_err(db_error)?;
                    table
                        .range(next..=last)
                        .map_err(db_error)?
                        .map(|row| {
                            let (height, block) = row.map_err(db_error)?;
                            Ok((height.value(), block.value().to_vec()))
                        })
                        .collect::<Result<_, DbError>>()?
                };
                add(&transaction, &blocks)?;
                let mut meta = transaction.open_table(META).map_err(db_error)?;
                if last >= through {
                    meta.remove(pending_key).map_err(db_error)?;
                } else {
                    let pending = [(last + 1).to_le_bytes(), through.to_le_bytes()].concat();
                    meta.insert(pending_key, pending.as_slice())
                        .map_err(db_error)?;
                }
            }
            transaction.commit().map_err(db_error)?;
            progress(last, through);
        }
    }

    /// `address` が関わったトランザクション（アグリゲートの中のものは除く）の（高さ、ブロックの中の番号）を、高さが
    /// `heights` の中のものだけ、古い順に（`reverse` なら新しい順に）`visit` に渡す。`after` があれば、その順で
    /// それより後のものから。`visit` が `false` を返したら止める。表を作っていなければ何も渡さない
    pub fn for_each_address_transaction(
        &self,
        address: &[u8; 24],
        heights: std::ops::RangeInclusive<u64>,
        after: Option<(u64, u32)>,
        reverse: bool,
        visit: &mut dyn FnMut(u64, u32) -> bool,
    ) -> Result<(), DbError> {
        let transaction = self.begin_read()?;
        let Some(table) = open_if_exists(&transaction, ADDRESS_TRANSACTIONS)? else {
            return Ok(());
        };
        let mut low = search::address_key(address, *heights.start(), 0);
        let mut high = search::address_key(address, *heights.end(), u32::MAX);
        if let Some((height, index)) = after {
            let at = search::address_key(address, height, index);
            if reverse {
                high = at;
            } else {
                low = at;
            }
        }
        if low > high {
            return Ok(());
        }
        let range = table
            .range(low.as_slice()..=high.as_slice())
            .map_err(db_error)?;
        let mut visit_key = |key: &[u8]| {
            let height = u64::from_be_bytes(key[24..32].try_into().expect("8 バイト"));
            let index = u32::from_be_bytes(key[32..36].try_into().expect("4 バイト"));
            // `after` そのものは渡さない
            if after == Some((height, index)) {
                return true;
            }
            visit(height, index)
        };
        if reverse {
            for row in range.rev() {
                if !visit_key(row.map_err(db_error)?.0.value()) {
                    break;
                }
            }
        } else {
            for row in range {
                if !visit_key(row.map_err(db_error)?.0.value()) {
                    break;
                }
            }
        }
        Ok(())
    }

    /// トランザクション（アグリゲートの中のものは除く）が入った高さと、ブロックの中の番号。表になければ `None`。
    /// 枝を取り替えたり刈り込んだりしたあとは、そのブロックにもうないこともあるので、引いた側で確かめる
    pub fn transaction_location(&self, hash: &Hash256) -> Result<Option<(u64, u32)>, DbError> {
        let transaction = self.begin_read()?;
        let Some(table) = open_if_exists(&transaction, TRANSACTION_HASHES)? else {
            return Ok(None);
        };
        Ok(table
            .get(hash.0.as_slice())
            .map_err(db_error)?
            .map(|value| value.value()))
    }

    /// ネームスペースの名前と親の ID（ルートは 0）。登録を見ていなければ `None`
    pub fn namespace_name(&self, id: u64) -> Result<Option<(u64, Vec<u8>)>, DbError> {
        let transaction = self.begin_read()?;
        let Some(names) = open_if_exists(&transaction, NAMES)? else {
            return Ok(None);
        };
        Ok(names.get(id).map_err(db_error)?.and_then(|value| {
            let value = value.value();
            (value.len() >= 8).then(|| (u64_from(&value[..8]), value[8..].to_vec()))
        }))
    }

    /// 検索表のキーが `prefix` で始まるものを、キーの順に（`reverse` なら逆に）`visit` に渡す。
    /// `after` があれば、その順でそれより後のものから。`visit` が `false` を返したら止める
    pub fn for_each_search_key(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        reverse: bool,
        visit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), DbError> {
        let transaction = self.begin_read()?;
        let Some(table) = open_if_exists(&transaction, SEARCH)? else {
            return Ok(());
        };
        for key in search_range(&table, prefix, after, reverse)? {
            if !visit(&key?) {
                break;
            }
        }
        Ok(())
    }

    /// [`Db::for_each_search_key`] を、検索表から消えたキー（[`Searches::PAST`]）も混ぜて、キーの順に。
    /// 昔の高さで検索するときの候補で、その高さにあったかは呼ぶ側が状態の行で確かめる
    pub fn for_each_search_key_with_past(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        reverse: bool,
        visit: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), DbError> {
        let transaction = self.begin_read()?;
        let (Some(current), Some(past)) = (
            open_if_exists(&transaction, SEARCH)?,
            open_if_exists(&transaction, SEARCH_PAST)?,
        ) else {
            return Ok(());
        };
        let mut left = search_range(&current, prefix, after, reverse)?.peekable();
        let mut right = search_range(&past, prefix, after, reverse)?.peekable();
        loop {
            // 2つの表の先頭のうち、順で先のほう。同じキーなら1回だけ
            let take_left = match (left.peek(), right.peek()) {
                (None, None) => return Ok(()),
                (Some(Err(_)), _) | (Some(Ok(_)), None) => true,
                (None, Some(_)) | (_, Some(Err(_))) => false,
                (Some(Ok(l)), Some(Ok(r))) if l == r => {
                    right.next();
                    true
                }
                (Some(Ok(l)), Some(Ok(r))) => (l < r) != reverse,
            };
            let key = if take_left { left.next() } else { right.next() }.expect("peeked")?;
            if !visit(&key) {
                return Ok(());
            }
        }
    }

    /// 書く前と詰める前に、ディスクの空きが `bytes` 以上あるかを確かめる。
    /// 足りなければ書かずに [`DbError::LowSpace`] を返すので、DB は最後にコミットしたところのまま残る。
    pub fn set_min_free(&mut self, bytes: u64) {
        self.min_free = bytes;
    }

    /// これから作る [`Batch`] では `history` を書かず、後で [`Db::build_history`] でまとめて作る。
    /// 書く前に [`Batch::defer_history_after`] で、どこまでできているかを残すこと
    pub fn defer_history(&mut self) {
        self.defer_history = true;
    }

    /// これから作る [`Batch`] では、状態は `state` 以下、木のノードは `trie` 以下の高さで、差分も索引も書かず、
    /// 今の値だけを書く。先に [`Db::prune_state_history`] と [`Db::prune_trie_history`] で、境をそこまで
    /// 上げておくこと（境より上の高さだけを書かないと、引いた昔の値が黙って違ってしまう）
    pub fn quiet_history_through(&mut self, state: u64, trie: u64) {
        self.quiet_through = [Some(state), Some(trie)];
    }

    /// 後回しにした `history` を、差分から作る。差分を高さの順に読み、まとまりごとにキーの順に並べてから足し、
    /// まとまりごとにコミットする。作り終えたら、どこまでできているかの印を消す。`progress` には、
    /// 状態か木のノードかと、どの高さまでできたかを渡し、偽が返ったらそのコミットで止める（印から続けられる）。
    /// 作り終えたら真
    pub fn build_history(
        &self,
        mut progress: impl FnMut(&str, u64) -> bool,
    ) -> Result<bool, DbError> {
        /// 1回のコミットで足す数の目安。高さの切れ目まで足すので、少し超える
        const CHUNK: usize = 4_000_000;
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        for (name, tables) in [("状態", STATE_TABLES), ("木のノード", TRIE_TABLES)] {
            loop {
                self.check_space()?;
                let transaction = database.begin_write().map_err(db_error)?;
                let Some(indexed) = read_u64(&transaction, tables.indexed)? else {
                    break;
                };
                let mut rows: Vec<(Vec<u8>, u64)> = Vec::new();
                let mut through = indexed;
                let mut done = true;
                {
                    let changesets = transaction
                        .open_table(tables.changesets)
                        .map_err(db_error)?;
                    for row in changesets
                        .range((indexed + 1, &[][..])..)
                        .map_err(db_error)?
                    {
                        let (key, _) = row.map_err(db_error)?;
                        let (height, key) = key.value();
                        if height != through && rows.len() >= CHUNK {
                            done = false;
                            break;
                        }
                        through = height;
                        rows.push((key.to_vec(), height));
                    }
                }
                rows.sort_unstable();
                {
                    let mut history = transaction.open_table(tables.history).map_err(db_error)?;
                    for (key, height) in &rows {
                        history
                            .insert((key.as_slice(), *height), ())
                            .map_err(db_error)?;
                    }
                    let mut meta = transaction.open_table(META).map_err(db_error)?;
                    if done {
                        meta.remove(tables.indexed).map_err(db_error)?;
                    } else {
                        meta.insert(tables.indexed, through.to_le_bytes().as_slice())
                            .map_err(db_error)?;
                    }
                }
                transaction.commit().map_err(db_error)?;
                let go_on = progress(name, through);
                if done {
                    break;
                }
                if !go_on {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn check_space(&self) -> Result<(), DbError> {
        if self.min_free == 0 {
            return Ok(());
        }
        let free = free_space(&self.directory).map_err(db_error)?;
        if free < self.min_free {
            return Err(DbError::LowSpace {
                free,
                min_free: self.min_free,
            });
        }
        Ok(())
    }

    /// 書けるように開いたか
    pub fn is_writable(&self) -> bool {
        matches!(self.handle, Handle::Write(_))
    }

    fn begin_read(&self) -> Result<ReadTransaction, DbError> {
        match &self.handle {
            Handle::Write(database) => database.begin_read(),
            Handle::Read(database) => database.begin_read(),
        }
        .map_err(db_error)
    }

    /// 表ごとの大きさ。表を全部たどるので重い
    pub fn table_sizes(&self) -> Result<Vec<TableSize>, DbError> {
        let transaction = self.begin_read()?;
        let mut sizes = Vec::new();
        for handle in transaction.list_tables().map_err(db_error)? {
            let name = handle.name().to_owned();
            let table = transaction.open_untyped_table(handle).map_err(db_error)?;
            let stats = table.stats().map_err(db_error)?;
            sizes.push((
                name,
                table.len().map_err(db_error)?,
                stats.stored_bytes(),
                stats.metadata_bytes(),
                stats.fragmented_bytes(),
            ));
        }
        Ok(sizes)
    }

    /// しまった最後のブロックの高さ。まだなければ 0。
    pub fn blocks_tip(&self) -> Result<u64, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(BLOCKS).map_err(db_error)?;
        Ok(table
            .last()
            .map_err(db_error)?
            .map_or(0, |(height, _)| height.value()))
    }

    /// `height` のブロック。なければ `None`。
    pub fn block(&self, height: u64) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(BLOCKS).map_err(db_error)?;
        Ok(table
            .get(height)
            .map_err(db_error)?
            .map(|bytes| bytes.value().to_vec()))
    }

    /// しまった最後のファイナライズの証明のエポック。まだなければ 0。
    pub fn proofs_tip(&self) -> Result<u32, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(PROOFS).map_err(db_error)?;
        Ok(table
            .last()
            .map_err(db_error)?
            .map_or(0, |(epoch, _)| epoch.value()))
    }

    /// 残っている一番低いブロックの高さ（[`Db::prune_history`] で消していなければ 0）
    pub fn blocks_from(&self) -> Result<u64, DbError> {
        Ok(self.meta(BLOCKS_FROM)?.map_or(0, |value| u64_from(&value)))
    }

    /// エポック `epoch` のファイナライズの証明。なければ `None`。
    pub fn proof(&self, epoch: u32) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(PROOFS).map_err(db_error)?;
        Ok(table
            .get(epoch)
            .map_err(db_error)?
            .map(|bytes| bytes.value().to_vec()))
    }

    /// 高さ `height` のブロックを実行して出たステートメントのバイト列。なければ `None`。
    pub fn statement(&self, height: u64) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        // 表を足す前に作った DB を読むだけに開いたときは、表がない
        let table = match transaction.open_table(STATEMENTS) {
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            table => table.map_err(db_error)?,
        };
        Ok(table
            .get(height)
            .map_err(db_error)?
            .map(|bytes| bytes.value().to_vec()))
    }

    /// 住所録。アドレスと記録のバイト列
    pub fn known_peers(&self) -> Result<Vec<(String, Vec<u8>)>, DbError> {
        let transaction = self.begin_read()?;
        let table = match transaction.open_table(PEERS) {
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            table => table.map_err(db_error)?,
        };
        table
            .iter()
            .map_err(db_error)?
            .map(|entry| {
                entry
                    .map(|(address, record)| (address.value().to_owned(), record.value().to_vec()))
                    .map_err(db_error)
            })
            .collect()
    }

    /// 自分の枝から外れたブロックのバイト列を、高さとハッシュの順に
    pub fn orphans(&self) -> Result<Vec<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        // 表を足す前に作った DB を読むだけに開いたときは、表がない
        let table = match transaction.open_table(ORPHANS) {
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            table => table.map_err(db_error)?,
        };
        table
            .iter()
            .map_err(db_error)?
            .map(|entry| {
                entry
                    .map(|(_, bytes)| bytes.value().to_vec())
                    .map_err(db_error)
            })
            .collect()
    }

    /// エポック `epoch` の投票者のバイト列。なければ `None`。
    pub fn voters(&self, epoch: u32) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        // 表を足す前に作った DB を読むだけに開いたときは、表がない
        let table = match transaction.open_table(VOTERS) {
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            table => table.map_err(db_error)?,
        };
        Ok(table
            .get(epoch)
            .map_err(db_error)?
            .map(|bytes| bytes.value().to_vec()))
    }

    /// 状態の行を全部。起動したときに読む
    pub fn state_rows(&self) -> Result<Vec<StateRow>, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(STATE).map_err(db_error)?;
        let mut rows = Vec::new();
        for row in table.iter().map_err(db_error)? {
            let (key, value) = row.map_err(db_error)?;
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
    }

    /// 今の状態の行 `key`（[`heika_state_transition::executor::persist::row_key`]）。なければ `None`
    pub fn state_row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.current(STATE, key)
    }

    /// 今の木のノード `key`（[`heika_state_transition::tree::node_key`]）。なければ `None`
    pub fn trie_node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.current(TRIE_TABLES.current, key)
    }

    fn current(
        &self,
        table: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(table).map_err(db_error)?;
        Ok(table
            .get(key)
            .map_err(db_error)?
            .map(|value| value.value().to_vec()))
    }

    /// キーが `prefix` で始まる今の状態の行を、キーの順に `visit` に渡す。全部を一度にメモリに置かない
    pub fn for_each_state_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(STATE).map_err(db_error)?;
        for row in table.range(prefix..).map_err(db_error)? {
            let (key, value) = row.map_err(db_error)?;
            if !key.value().starts_with(prefix) {
                break;
            }
            visit(key.value(), value.value());
        }
        Ok(())
    }

    /// キーが `prefix` で始まる今の木のノードを、キーの順に `visit` に渡す
    pub fn for_each_trie_node(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), DbError> {
        let transaction = self.begin_read()?;
        let table = transaction
            .open_table(TRIE_TABLES.current)
            .map_err(db_error)?;
        for row in table.range(prefix..).map_err(db_error)? {
            let (key, value) = row.map_err(db_error)?;
            if !key.value().starts_with(prefix) {
                break;
            }
            visit(key.value(), value.value());
        }
        Ok(())
    }

    /// `meta` の値。なければ `None`。
    pub fn meta(&self, name: &str) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction.open_table(META).map_err(db_error)?;
        Ok(table
            .get(name)
            .map_err(db_error)?
            .map(|value| value.value().to_vec()))
    }

    /// `height` のブロックを実行したあとの、`key` の状態。なければ `None`。
    pub fn state_at(&self, key: &[u8], height: u64) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        let past = Past::open(&transaction, STATE_TABLES, height)?;
        past.get(key)
    }

    /// `height` のブロックを実行したあとの状態と木のノードを、1つの読み取りで引くもの。
    /// その高さの履歴がなければ [`DbError::NoHistory`]。実行した高さより上かは確かめない（今の値が返る）
    /// 今の状態を引く先。1つの読み取りを開いたままにするので、何度引いても、開いた時点の同じ高さの値になる
    pub fn now(&self) -> Result<Now, DbError> {
        let transaction = self.begin_read()?;
        Ok(Now {
            state: transaction.open_table(STATE).map_err(db_error)?,
        })
    }

    pub fn at(&self, height: u64) -> Result<At, DbError> {
        let transaction = self.begin_read()?;
        Ok(At {
            state: Past::open(&transaction, STATE_TABLES, height)?,
            trie: Past::open(&transaction, TRIE_TABLES, height)?,
        })
    }

    /// `height` のブロックを実行したあとの、キーが `prefix` で始まる状態の行。キーの順
    pub fn state_rows_with_prefix_at(
        &self,
        prefix: &[u8],
        height: u64,
    ) -> Result<Vec<StateRow>, DbError> {
        let high = search::prefix_end(prefix);
        let mut rows = self.state_rows_in(&[height], height, prefix, high.as_deref())?;
        Ok(rows.pop().unwrap_or_default())
    }

    /// `height` のブロックを実行したあとの、`key`（[`heika_state_transition::tree::node_key`]）の木のノード。なければ `None`。
    pub fn trie_node_at(&self, key: &[u8], height: u64) -> Result<Option<Vec<u8>>, DbError> {
        let transaction = self.begin_read()?;
        let past = Past::open(&transaction, TRIE_TABLES, height)?;
        past.get(key)
    }

    /// 調べもの用: 木のノード `key` が変わった高さと、変わる前の値
    #[doc(hidden)]
    pub fn trie_changes_of(&self, key: &[u8]) -> Result<Vec<Change>, DbError> {
        let transaction = self.begin_read()?;
        let history = transaction
            .open_table(TRIE_TABLES.history)
            .map_err(db_error)?;
        let changesets = transaction
            .open_table(TRIE_TABLES.changesets)
            .map_err(db_error)?;
        let mut out = Vec::new();
        for entry in history
            .range((key, 0)..=(key, u64::MAX))
            .map_err(db_error)?
        {
            let height = entry.map_err(db_error)?.0.value().1;
            let before = changesets
                .get((height, key))
                .map_err(db_error)?
                .map(|value| value.value().to_vec());
            out.push((height.to_le_bytes().to_vec(), before));
        }
        Ok(out)
    }

    /// 今の状態の木のノードを全部。キー（[`heika_state_transition::tree::node_key`]）とノードのバイト列
    pub fn trie_nodes(&self) -> Result<Vec<StateRow>, DbError> {
        let transaction = self.begin_read()?;
        let table = transaction
            .open_table(TRIE_TABLES.current)
            .map_err(db_error)?;
        let mut rows = Vec::new();
        for row in table.iter().map_err(db_error)? {
            let (key, value) = row.map_err(db_error)?;
            rows.push((key.value().to_vec(), value.value().to_vec()));
        }
        Ok(rows)
    }

    /// 木のノードを残し始めているか
    pub fn trie_started(&self) -> Result<bool, DbError> {
        Ok(self.meta(TRIE_TABLES.from)?.is_some())
    }

    /// `height` のブロックを実行したあとの、状態の行を全部。
    pub fn state_rows_at(&self, height: u64) -> Result<Vec<StateRow>, DbError> {
        let transaction = self.begin_read()?;
        let past = Past::open(&transaction, STATE_TABLES, height)?;
        // 今あるキーと、いつか変わったキー。消えたキーも、昔はあったかもしれない
        let mut keys = std::collections::BTreeSet::new();
        for row in past.state.iter().map_err(db_error)? {
            keys.insert(row.map_err(db_error)?.0.value().to_vec());
        }
        let mut last: Option<Vec<u8>> = None;
        for row in past.history.iter().map_err(db_error)? {
            let (entry, _) = row.map_err(db_error)?;
            let key = entry.value().0;
            if last.as_deref() != Some(key) {
                keys.insert(key.to_vec());
                last = Some(key.to_vec());
            }
        }
        let mut rows = Vec::new();
        for key in keys {
            if let Some(value) = past.get(&key)? {
                rows.push((key, value));
            }
        }
        Ok(rows)
    }

    /// `heights` のそれぞれのブロックを実行したあとの、状態の行を全部。[`Db::state_rows_at`] を高さごとに呼ぶと
    /// 履歴の表を毎回なめるので、今の状態の表と履歴の表をキーの順に1回だけなめ、キーごとに全部の高さの値を決める。
    /// 変わる前の値を引くのを待つ時間が長いので、キーを木の番号と最初のバイトで範囲に分け、範囲ごとに並列になめる
    pub fn state_rows_at_heights(&self, heights: &[u64]) -> Result<Vec<Vec<StateRow>>, DbError> {
        use rayon::prelude::*;

        let Some(&lowest) = heights.iter().min() else {
            return Ok(Vec::new());
        };
        // 履歴があって、索引がそろっていることを先に確かめる
        Past::open(&self.begin_read()?, STATE_TABLES, lowest)?;
        // 木の番号ごとに、最初のバイトで 16 に分ける。最後の範囲は上を区切らない
        let mut bounds: Vec<Vec<u8>> = (0..heika_core::patricia::SubCache::ALL.len() as u8)
            .flat_map(|cache| (0..16u8).map(move |high| vec![cache, high << 4]))
            .collect();
        bounds[0] = Vec::new();
        let ranges: Vec<(Vec<u8>, Option<Vec<u8>>)> = bounds
            .iter()
            .enumerate()
            .map(|(index, low)| (low.clone(), bounds.get(index + 1).cloned()))
            .collect();
        let parts: Vec<Vec<Vec<StateRow>>> = ranges
            .par_iter()
            .map(|(low, high)| self.state_rows_in(heights, lowest, low, high.as_deref()))
            .collect::<Result<_, _>>()?;
        let mut rows = vec![Vec::new(); heights.len()];
        for part in parts {
            for (out, mut part) in rows.iter_mut().zip(part) {
                out.append(&mut part);
            }
        }
        Ok(rows)
    }

    /// [`Db::state_rows_at_heights`] の、キーが `low` 以上 `high` 未満の分
    fn state_rows_in(
        &self,
        heights: &[u64],
        lowest: u64,
        low: &[u8],
        high: Option<&[u8]>,
    ) -> Result<Vec<Vec<StateRow>>, DbError> {
        let mut rows = vec![Vec::new(); heights.len()];
        let transaction = self.begin_read()?;
        let past = Past::open(&transaction, STATE_TABLES, lowest)?;
        let (mut current, mut history) = match high {
            Some(high) => (
                past.state.range(low..high).map_err(db_error)?,
                past.history.range((low, 0)..(high, 0)).map_err(db_error)?,
            ),
            None => (
                past.state.range(low..).map_err(db_error)?,
                past.history.range((low, 0)..).map_err(db_error)?,
            ),
        };
        let mut current = std::iter::from_fn(move || current.next()).peekable();
        let mut history = std::iter::from_fn(move || history.next()).peekable();
        loop {
            // 次のキーは、2つの表の先頭の小さいほう
            let next_current = match current.peek() {
                None => None,
                Some(Ok((key, _))) => Some(key.value().to_vec()),
                Some(Err(_)) => {
                    current.next().expect("peeked").map_err(db_error)?;
                    unreachable!("peeked an error")
                }
            };
            let next_history = match history.peek() {
                None => None,
                Some(Ok((entry, _))) => Some(entry.value().0.to_vec()),
                Some(Err(_)) => {
                    history.next().expect("peeked").map_err(db_error)?;
                    unreachable!("peeked an error")
                }
            };
            let key = match (next_current, next_history) {
                (None, None) => break,
                (Some(key), None) | (None, Some(key)) => key,
                (Some(left), Some(right)) => left.min(right),
            };
            let value = match current.peek() {
                Some(Ok((stored, _))) if stored.value() == key.as_slice() => {
                    let (_, value) = current.next().expect("peeked").map_err(db_error)?;
                    Some(value.value().to_vec())
                }
                _ => None,
            };
            // そのキーが変わった高さ。表の順に、低いほうから並ぶ
            let mut changed = Vec::new();
            while let Some(Ok((entry, _))) = history.peek() {
                let (stored, height) = entry.value();
                if stored != key.as_slice() {
                    break;
                }
                changed.push(height);
                history.next();
            }
            for (out, &height) in rows.iter_mut().zip(heights) {
                let later = changed[changed.partition_point(|&at| at <= height)..].first();
                let at_height = match later {
                    None => value.clone(),
                    Some(&changed) => {
                        let before = past
                            .changesets
                            .get((changed, key.as_slice()))
                            .map_err(db_error)?
                            .expect("history points to a changeset");
                        match before.value() {
                            [PRESENT, value @ ..] => Some(value.to_vec()),
                            _ => None,
                        }
                    }
                };
                if let Some(at_height) = at_height {
                    out.push((key.clone(), at_height));
                }
            }
        }
        Ok(rows)
    }

    /// `height` のブロックで変わった状態のキーと、変わる前の値。
    pub fn changeset(&self, height: u64) -> Result<Vec<Change>, DbError> {
        let transaction = self.begin_read()?;
        let changesets = transaction
            .open_table(STATE_TABLES.changesets)
            .map_err(db_error)?;
        let mut rows = Vec::new();
        let range = changesets
            .range((height, &[][..])..(height + 1, &[][..]))
            .map_err(db_error)?;
        for row in range {
            let (key, before) = row.map_err(db_error)?;
            let before = match before.value() {
                [PRESENT, value @ ..] => Some(value.to_vec()),
                _ => None,
            };
            rows.push((key.value().1.to_vec(), before));
        }
        Ok(rows)
    }

    /// `height` 以下で一番新しいチェックポイントの高さと、木に入らない実行の状態
    pub fn checkpoint_at_or_below(&self, height: u64) -> Result<Option<(u64, Vec<u8>)>, DbError> {
        let transaction = self.begin_read()?;
        let checkpoints = transaction.open_table(CHECKPOINTS).map_err(db_error)?;
        checkpoints
            .range(..=height)
            .map_err(db_error)?
            .next_back()
            .transpose()
            .map_err(db_error)
            .map(|found| found.map(|(key, value)| (key.value(), value.value().to_vec())))
    }

    /// `below` より下のチェックポイントを、その中で一番新しい1つを残して消す。ファイナライズより下には巻き戻らない
    /// ので、そこより十分下のものは要らない。消した数を返す
    pub fn prune_checkpoints(&self, below: u64) -> Result<usize, DbError> {
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        let transaction = database.begin_write().map_err(db_error)?;
        let removed = {
            let mut checkpoints = transaction.open_table(CHECKPOINTS).map_err(db_error)?;
            let heights: Vec<u64> = checkpoints
                .range(..below)
                .map_err(db_error)?
                .map(|row| row.map(|(key, _)| key.value()))
                .collect::<Result<_, _>>()
                .map_err(db_error)?;
            let removed = heights.len().saturating_sub(1);
            for height in heights.into_iter().rev().skip(1) {
                checkpoints.remove(height).map_err(db_error)?;
            }
            removed
        };
        transaction.commit().map_err(db_error)?;
        Ok(removed)
    }

    /// 状態の差分と索引を、`through` 以下の高さの分だけ消す（刈り込み）
    pub fn prune_state_history(
        &self,
        through: u64,
        progress: impl FnMut(u64) -> bool,
    ) -> Result<Pruned, DbError> {
        self.prune(STATE_TABLES, through, progress)
    }

    /// [`Db::prune_state_history`] と同じことを、木のノードで
    pub fn prune_trie_history(
        &self,
        through: u64,
        progress: impl FnMut(u64) -> bool,
    ) -> Result<Pruned, DbError> {
        self.prune(TRIE_TABLES, through, progress)
    }

    /// 高さ `c` の差分は `c` で変わる前の値なので、`through` 以上の高さの値を引くのに要るのは `through` より上の
    /// 差分だけ。そこで、先に `from` を `through` に上げてコミットし（ここで、それより前は引かなくなる）、
    /// それから `through` 以下の差分と、同じ組の索引を、まとまりごとに消してコミットする。
    /// `progress` には消し終えた高さを渡し、偽が返ったらそのコミットで止める。もう一度呼べば、`from` までの残りを消す。
    /// 差分を残していなければ何もしない。`from` は下げない。
    ///
    /// 巻き戻しは `from` より下のチェックポイントには戻れないので、`through` を決めるのは呼ぶ側
    fn prune(
        &self,
        tables: Versioned,
        through: u64,
        progress: impl FnMut(u64) -> bool,
    ) -> Result<Pruned, DbError> {
        /// 1回のコミットで消す行の数の目安
        const CHUNK: usize = 2_000_000;
        self.prune_in_chunks(tables, through, CHUNK, progress)
    }

    fn prune_in_chunks(
        &self,
        tables: Versioned,
        through: u64,
        chunk: usize,
        mut progress: impl FnMut(u64) -> bool,
    ) -> Result<Pruned, DbError> {
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        let transaction = database.begin_write().map_err(db_error)?;
        let Some(from) = read_u64(&transaction, tables.from)? else {
            return Ok(Pruned {
                rows: 0,
                done: true,
            });
        };
        // 前に止めたときの残りも消す
        let through = through.max(from);
        if through > from {
            let mut meta = transaction.open_table(META).map_err(db_error)?;
            meta.insert(tables.from, through.to_le_bytes().as_slice())
                .map_err(db_error)?;
        }
        transaction.commit().map_err(db_error)?;

        let mut rows = 0;
        loop {
            let transaction = database.begin_write().map_err(db_error)?;
            let keys = {
                let changesets = transaction
                    .open_table(tables.changesets)
                    .map_err(db_error)?;
                changesets
                    .range(..(through + 1, &[][..]))
                    .map_err(db_error)?
                    .take(chunk)
                    .map(|row| row.map(|(key, _)| (key.value().0, key.value().1.to_vec())))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(db_error)?
            };
            {
                let mut changesets = transaction
                    .open_table(tables.changesets)
                    .map_err(db_error)?;
                let mut history = transaction.open_table(tables.history).map_err(db_error)?;
                for (height, key) in &keys {
                    changesets
                        .remove((*height, key.as_slice()))
                        .map_err(db_error)?;
                    history
                        .remove((key.as_slice(), *height))
                        .map_err(db_error)?;
                }
            }
            transaction.commit().map_err(db_error)?;
            rows += keys.len() as u64;
            let done = keys.len() < chunk;
            let reached = keys.last().map_or(through, |(height, _)| *height);
            let go_on = progress(if done { through } else { reached });
            if done {
                return Ok(Pruned { rows, done: true });
            }
            if !go_on {
                return Ok(Pruned { rows, done: false });
            }
        }
    }

    /// `through` 以下の高さのステートメントを消し、`meta` に、どこから残っているかを書く
    pub fn prune_statements(&self, through: u64) -> Result<u64, DbError> {
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        let transaction = database.begin_write().map_err(db_error)?;
        let mut rows = 0;
        {
            let mut statements = transaction.open_table(STATEMENTS).map_err(db_error)?;
            while statements
                .first()
                .map_err(db_error)?
                .is_some_and(|(height, _)| height.value() <= through)
            {
                statements.pop_first().map_err(db_error)?;
                rows += 1;
            }
            let mut meta = transaction.open_table(META).map_err(db_error)?;
            let from = meta
                .get(STATEMENTS_FROM)
                .map_err(db_error)?
                .map_or(0, |value| u64_from(value.value()));
            if through + 1 > from {
                meta.insert(STATEMENTS_FROM, (through + 1).to_le_bytes().as_slice())
                    .map_err(db_error)?;
            }
        }
        transaction.commit().map_err(db_error)?;
        Ok(rows)
    }

    /// 高さ `through` 以下のブロックとステートメント、エポック `before_epoch` より前のファイナライズの証明を消す。
    /// 状態と巻き戻しに要るもの（差分、チェックポイント、投票者）は消さない。消した行の数
    pub fn prune_history(&self, through: u64, before_epoch: u32) -> Result<u64, DbError> {
        self.prune_history_while(through, before_epoch, || true)
            .map(|pruned| pruned.rows)
    }

    /// [`Db::prune_history`] を、まとまりごとのコミットのあとで `keep_going` が偽を返したら止める。もう一度呼べば続きを消す
    pub fn prune_history_while(
        &self,
        through: u64,
        before_epoch: u32,
        mut keep_going: impl FnMut() -> bool,
    ) -> Result<Pruned, DbError> {
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        let mut rows = 0;
        loop {
            let transaction = database.begin_write().map_err(db_error)?;
            let (pruned, done) =
                prune_history_in(&transaction, through, before_epoch, HISTORY_CHUNK)?;
            transaction.commit().map_err(db_error)?;
            rows += pruned;
            if done || !keep_going() {
                return Ok(Pruned { rows, done });
            }
        }
    }

    /// 状態の差分、木のノードの差分、ステートメントが、それぞれどの高さから残っているか。
    /// 差分を残していなければ `None`、ステートメントは消していなければ 0
    pub fn kept_from(&self) -> Result<(Option<u64>, Option<u64>, u64), DbError> {
        let read = |name| -> Result<Option<u64>, DbError> {
            Ok(self.meta(name)?.map(|value| u64_from(&value)))
        };
        Ok((
            read(STATE_TABLES.from)?,
            read(TRIE_TABLES.from)?,
            read(STATEMENTS_FROM)?.unwrap_or(0),
        ))
    }

    /// `height` より上のブロックで変わった状態のキーと、`height` のときの値（なかったなら `None`）。キーの順。
    /// 巻き戻す前に読み、メモリの実行の状態を `height` に戻すのに使う（[`Db::rollback`] で差分は消える）
    pub fn changes_above(&self, height: u64) -> Result<Vec<Change>, DbError> {
        let transaction = self.begin_read()?;
        let changesets = transaction
            .open_table(STATE_TABLES.changesets)
            .map_err(db_error)?;
        // 差分は高さの順に並ぶので、キーごとに最初に出てきたもの（一番低い高さで変わる前の値）が height のときの値
        let mut rows: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for row in changesets
            .range((height + 1, &[][..])..)
            .map_err(db_error)?
        {
            let (key, before) = row.map_err(db_error)?;
            rows.entry(key.value().1.to_vec())
                .or_insert_with(|| match before.value() {
                    [PRESENT, value @ ..] => Some(value.to_vec()),
                    _ => None,
                });
        }
        Ok(rows.into_iter().collect())
    }

    /// 書き換えで空いたページを詰めて、ファイルを小さくする。redb は書き換えのたびに新しいページに書くので、
    /// たくさん書いたあとはファイルが中身の倍以上になる。
    pub fn compact(&mut self) -> Result<(), DbError> {
        self.check_space()?;
        let Handle::Write(database) = &mut self.handle else {
            return Err(DbError::ReadOnly);
        };
        database.compact().map_err(db_error)?;
        Ok(())
    }

    /// この DB の表を、新しく作った空の DB `target` に、キーの順に写す。新しいファイルには空いたページがないので、
    /// その場の [`Db::compact`] の代わりになる。`bounds` があれば刈り込みながら写す。差分は境より上だけを写し、
    /// 索引は写さずに、写した差分から後で [`Db::build_history`] で作る。`progress` には、写している表と、
    /// その表で写し終えた行の数を渡し、偽が返ったらそのコミットで止める（続けられないので、写し先を消して
    /// やり直す）。写し終えたら真
    pub fn copy_to(
        &self,
        target: &Db,
        bounds: Option<CopyBounds>,
        mut progress: impl FnMut(&str, u64) -> bool,
    ) -> Result<bool, DbError> {
        let Handle::Write(database) = &target.handle else {
            return Err(DbError::ReadOnly);
        };
        let source = self.begin_read()?;
        let copier = Copier {
            source: &source,
            target,
            database,
        };
        let progress = &mut progress;
        let whole = [
            copier.table(STATE, progress)?,
            copier.table(TRIE_TABLES.current, progress)?,
            copier.table(META, progress)?,
            copier.table(VOTERS, progress)?,
            copier.table(CHECKPOINTS, progress)?,
            copier.table(ORPHANS, progress)?,
            copier.table(PEERS, progress)?,
            copier.table(SEARCH, progress)?,
            copier.table(SEARCH_PAST, progress)?,
            copier.table(NAMES, progress)?,
            copier.table(TRANSACTION_HASHES, progress)?,
            copier.table(ADDRESS_TRANSACTIONS, progress)?,
        ];
        if whole.contains(&false) {
            return Ok(false);
        }
        match bounds.and_then(|bounds| bounds.blocks) {
            Some((through, epoch)) => {
                let blocks = source.open_table(BLOCKS).map_err(db_error)?;
                let proofs = source.open_table(PROOFS).map_err(db_error)?;
                if !copier.rows(
                    BLOCKS,
                    blocks.range(through + 1..).map_err(db_error)?,
                    progress,
                )? || !copier.rows(PROOFS, proofs.range(epoch..).map_err(db_error)?, progress)?
                {
                    return Ok(false);
                }
            }
            None => {
                if !copier.table(BLOCKS, progress)? || !copier.table(PROOFS, progress)? {
                    return Ok(false);
                }
            }
        }
        let read_from = |name| -> Result<Option<u64>, DbError> {
            Ok(source
                .open_table(META)
                .map_err(db_error)?
                .get(name)
                .map_err(db_error)?
                .map(|value| u64_from(value.value())))
        };
        let Some(bounds) = bounds else {
            let rest = [
                copier.table(STATEMENTS, progress)?,
                copier.table(STATE_TABLES.changesets, progress)?,
                copier.table(STATE_TABLES.history, progress)?,
                copier.table(TRIE_TABLES.changesets, progress)?,
                copier.table(TRIE_TABLES.history, progress)?,
            ];
            return Ok(!rest.contains(&false));
        };
        // 境の高さを、引ける高さとして `meta` に書く。索引は、境までできていることにして、後で続きを作る
        let mut meta: Vec<(&str, u64)> = Vec::new();
        for (tables, through) in [(STATE_TABLES, bounds.state), (TRIE_TABLES, bounds.trie)] {
            // 差分を残していなければ、写すものはない
            let Some(from) = read_from(tables.from)? else {
                continue;
            };
            let through = through.max(from);
            let changesets = source.open_table(tables.changesets).map_err(db_error)?;
            let rows = changesets
                .range((through + 1, &[][..])..)
                .map_err(db_error)?;
            if !copier.rows(tables.changesets, rows, progress)? {
                return Ok(false);
            }
            meta.extend([(tables.from, through), (tables.indexed, through)]);
        }
        if let Some((through, _)) = bounds.blocks {
            let from = read_from(BLOCKS_FROM)?.unwrap_or(0).max(through + 1);
            meta.push((BLOCKS_FROM, from));
        }
        match bounds.statements {
            Some(through) => {
                let from = read_from(STATEMENTS_FROM)?.unwrap_or(0).max(through + 1);
                if let Some(statements) = open_if_exists(&source, STATEMENTS)? {
                    let rows = statements.range(from..).map_err(db_error)?;
                    if !copier.rows(STATEMENTS, rows, progress)? {
                        return Ok(false);
                    }
                }
                meta.push((STATEMENTS_FROM, from));
            }
            None => {
                if !copier.table(STATEMENTS, progress)? {
                    return Ok(false);
                }
            }
        }
        let transaction = database.begin_write().map_err(db_error)?;
        {
            let mut table = transaction.open_table(META).map_err(db_error)?;
            for (name, height) in meta {
                table
                    .insert(name, height.to_le_bytes().as_slice())
                    .map_err(db_error)?;
            }
        }
        transaction.commit().map_err(db_error)?;
        Ok(true)
    }

    /// 実行した状態を、`height` 以下で最後のチェックポイントまで巻き戻す。そこから `height` までは実行し直すこと。
    ///
    /// 状態と木のノードは、上の高さから順に `changesets` の変わる前の値に戻し、その差分と索引を消す。
    /// ステートメントとチェックポイントはその高さより上を、投票者は `voters_from` 以上のエポックを消す。
    /// `meta` の `meta_name` は、そのチェックポイントにする。`drop_blocks` なら、`height` より上のブロックも消す。
    /// `orphans`（高さ、ハッシュ、バイト列）は、孤立ブロックの表に足す。
    /// 全部を1つのトランザクションでコミットする。戻した高さを返す
    pub fn rollback(
        &self,
        height: u64,
        voters_from: u32,
        meta_name: &str,
        drop_blocks: bool,
        orphans: &[(u64, [u8; 32], &[u8])],
    ) -> Result<u64, DbError> {
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        self.check_space()?;
        let transaction = database.begin_write().map_err(db_error)?;
        let (checkpoint, executor) = {
            let checkpoints = transaction.open_table(CHECKPOINTS).map_err(db_error)?;
            let found = checkpoints
                .range(..=height)
                .map_err(db_error)?
                .next_back()
                .transpose()
                .map_err(db_error)?
                .map(|(key, value)| (key.value(), value.value().to_vec()));
            found.ok_or(DbError::NoCheckpoint { height })?
        };
        {
            let meta = transaction.open_table(META).map_err(db_error)?;
            for tables in [STATE_TABLES, TRIE_TABLES] {
                let from = meta
                    .get(tables.from)
                    .map_err(db_error)?
                    .map(|value| u64_from(value.value()));
                if from.is_none_or(|from| checkpoint < from) {
                    return Err(DbError::NoHistory {
                        height: checkpoint,
                        from: from.unwrap_or(u64::MAX),
                    });
                }
            }
        }
        for tables in [STATE_TABLES, TRIE_TABLES] {
            let search = if tables.current.name() == STATE.name() {
                self.search
            } else {
                Searches::NONE
            };
            undo_above(&transaction, tables, checkpoint, search)?;
            // 索引を後回しにしていたなら、できているのはチェックポイントまで
            if let Some(indexed) = read_u64(&transaction, tables.indexed)?
                && indexed > checkpoint
            {
                let mut meta = transaction.open_table(META).map_err(db_error)?;
                meta.insert(tables.indexed, checkpoint.to_le_bytes().as_slice())
                    .map_err(db_error)?;
            }
        }
        drop_above(&transaction, STATEMENTS, checkpoint)?;
        drop_above(&transaction, CHECKPOINTS, checkpoint)?;
        if drop_blocks {
            drop_above(&transaction, BLOCKS, height)?;
        }
        {
            let mut table = transaction.open_table(ORPHANS).map_err(db_error)?;
            for (height, hash, block) in orphans {
                table
                    .insert((*height, hash.as_slice()), *block)
                    .map_err(db_error)?;
            }
        }
        {
            let mut voters = transaction.open_table(VOTERS).map_err(db_error)?;
            while voters
                .last()
                .map_err(db_error)?
                .is_some_and(|(epoch, _)| epoch.value() >= voters_from)
            {
                voters.pop_last().map_err(db_error)?;
            }
            let mut meta = transaction.open_table(META).map_err(db_error)?;
            meta.insert(meta_name, executor.as_slice())
                .map_err(db_error)?;
        }
        transaction.commit().map_err(db_error)?;
        Ok(checkpoint)
    }

    /// まとめて書く。[`Batch::commit`] するまで、ほかからは見えない。
    pub fn batch(&self) -> Result<Batch, DbError> {
        let Handle::Write(database) = &self.handle else {
            return Err(DbError::ReadOnly);
        };
        self.check_space()?;
        Ok(Batch {
            transaction: database.begin_write().map_err(db_error)?,
            defer_history: self.defer_history,
            quiet_through: self.quiet_through,
            search: self.search,
            network: self.network,
        })
    }
}

/// `meta` の `name` にある高さ
fn read_u64(transaction: &WriteTransaction, name: &str) -> Result<Option<u64>, DbError> {
    let meta = transaction.open_table(META).map_err(db_error)?;
    let value = meta.get(name).map_err(db_error)?;
    Ok(value.map(|value| u64_from(value.value())))
}

/// 検索表のキーを順に読むもの
type SearchKeys<'a> = Box<dyn Iterator<Item = Result<Vec<u8>, DbError>> + 'a>;

/// 検索表 `table` のキーが `prefix` で始まるものを、順に（`reverse` なら逆に）。`after` があれば、その順でそれより後から
fn search_range<'a>(
    table: &'a ReadOnlyTable<&'static [u8], ()>,
    prefix: &[u8],
    after: Option<&[u8]>,
    reverse: bool,
) -> Result<SearchKeys<'a>, DbError> {
    use std::ops::Bound;

    let end = search::prefix_end(prefix);
    let mut low = Bound::Included(prefix);
    let mut high = match &end {
        Some(end) => Bound::Excluded(end.as_slice()),
        None => Bound::Unbounded,
    };
    if let Some(after) = after {
        let past_end = end.as_deref().is_some_and(|end| after >= end);
        if reverse {
            if after <= prefix {
                return Ok(Box::new(std::iter::empty()));
            }
            if !past_end {
                high = Bound::Excluded(after);
            }
        } else {
            if past_end {
                return Ok(Box::new(std::iter::empty()));
            }
            if after >= prefix {
                low = Bound::Excluded(after);
            }
        }
    }
    let range = table.range::<&[u8]>((low, high)).map_err(db_error)?;
    let keys = |row: Result<(AccessGuard<&[u8]>, AccessGuard<()>), StorageError>| {
        row.map(|(key, _)| key.value().to_vec()).map_err(db_error)
    };
    Ok(if reverse {
        Box::new(range.rev().map(keys))
    } else {
        Box::new(range.map(keys))
    })
}

/// `meta` に覚えた、作る検索
fn read_network(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Option<TransactionNetwork>, DbError> {
    Ok(meta
        .get(NETWORK_META)
        .map_err(db_error)?
        .and_then(|value| TransactionNetwork::decode(value.value())))
}

fn read_searches(
    meta: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Searches, DbError> {
    Ok(meta
        .get(SEARCH_META)
        .map_err(db_error)?
        .and_then(|value| value.value().first().copied())
        .map(Searches::from_bits)
        .unwrap_or_default())
}

/// 状態の行 `key` が `before` から `after` に変わったので、検索表を直す。[`Searches::PAST`] なら、消えたキーを残す
fn update_search(
    table: &mut redb::Table<&[u8], ()>,
    past: &mut redb::Table<&[u8], ()>,
    search: Searches,
    key: &[u8],
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<(), DbError> {
    if search.kinds() == Searches::NONE {
        return Ok(());
    }
    let (removed, added) = (
        search::keys_of(search, key, before),
        search::keys_of(search, key, after),
    );
    if removed == added {
        return Ok(());
    }
    for search_key in &removed {
        table.remove(search_key.as_slice()).map_err(db_error)?;
        if search.contains(Searches::PAST) && !added.contains(search_key) {
            past.insert(search_key.as_slice(), ()).map_err(db_error)?;
        }
    }
    for search_key in &added {
        table.insert(search_key.as_slice(), ()).map_err(db_error)?;
    }
    Ok(())
}

/// `tables` を、上の高さから1つずつ、変わる前の値に戻す。`height` より上の差分と索引は消える
fn undo_above(
    transaction: &WriteTransaction,
    tables: Versioned,
    height: u64,
    search: Searches,
) -> Result<(), DbError> {
    let mut current = transaction.open_table(tables.current).map_err(db_error)?;
    let mut search_table = transaction.open_table(SEARCH).map_err(db_error)?;
    let mut past_table = transaction.open_table(SEARCH_PAST).map_err(db_error)?;
    let mut changesets = transaction
        .open_table(tables.changesets)
        .map_err(db_error)?;
    let mut history = transaction.open_table(tables.history).map_err(db_error)?;
    loop {
        let last = changesets
            .last()
            .map_err(db_error)?
            .map(|(key, _)| key.value().0);
        let Some(changed) = last.filter(|&changed| changed > height) else {
            return Ok(());
        };
        let mut rows = Vec::new();
        for row in changesets
            .range((changed, &[][..])..(changed + 1, &[][..]))
            .map_err(db_error)?
        {
            let (key, before) = row.map_err(db_error)?;
            rows.push((key.value().1.to_vec(), before.value().to_vec()));
        }
        for (key, before) in rows {
            let restored = match before.as_slice() {
                [PRESENT, value @ ..] => Some(value),
                _ => None,
            };
            let undone = match restored {
                Some(value) => current.insert(key.as_slice(), value),
                None => current.remove(key.as_slice()),
            }
            .map_err(db_error)?
            .map(|value| value.value().to_vec());
            update_search(
                &mut search_table,
                &mut past_table,
                search,
                &key,
                undone.as_deref(),
                restored,
            )?;
            history
                .remove((key.as_slice(), changed))
                .map_err(db_error)?;
            changesets
                .remove((changed, key.as_slice()))
                .map_err(db_error)?;
        }
    }
}

/// 高さの表の、`height` より上を消す
fn drop_above(
    transaction: &WriteTransaction,
    table: TableDefinition<u64, &[u8]>,
    height: u64,
) -> Result<(), DbError> {
    let mut table = transaction.open_table(table).map_err(db_error)?;
    while table
        .last()
        .map_err(db_error)?
        .is_some_and(|(key, _)| key.value() > height)
    {
        table.pop_last().map_err(db_error)?;
    }
    Ok(())
}
/// 表がなければ `None`。表を足す前に作った DB を読むだけに開いたとき
fn open_if_exists<K: Key + 'static, V: Value + 'static>(
    transaction: &ReadTransaction,
    definition: TableDefinition<K, V>,
) -> Result<Option<ReadOnlyTable<K, V>>, DbError> {
    match transaction.open_table(definition) {
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        table => table.map(Some).map_err(db_error),
    }
}

/// [`Db::copy_to`] で、読むトランザクションから、新しい DB に写す
struct Copier<'a> {
    source: &'a ReadTransaction,
    target: &'a Db,
    database: &'a Database,
}

impl Copier<'_> {
    /// 表をまるごと写す
    fn table<K: Key + 'static, V: Value + 'static>(
        &self,
        definition: TableDefinition<K, V>,
        progress: &mut impl FnMut(&str, u64) -> bool,
    ) -> Result<bool, DbError> {
        let Some(table) = open_if_exists(self.source, definition)? else {
            return Ok(true);
        };
        self.rows(definition, table.iter().map_err(db_error)?, progress)
    }

    /// キーの順に並んだ `rows` を、まとまりごとに書いてコミットする。最後に、待たずにコミットしたものを書き出し終える
    fn rows<'r, K: Key + 'static, V: Value + 'static>(
        &self,
        definition: TableDefinition<K, V>,
        mut rows: impl Iterator<Item = Result<(AccessGuard<'r, K>, AccessGuard<'r, V>), StorageError>>,
        progress: &mut impl FnMut(&str, u64) -> bool,
    ) -> Result<bool, DbError> {
        /// 1回のコミットで写す行の数の目安
        const CHUNK: u64 = 4_000_000;
        let name = definition.name();
        let mut copied = 0;
        loop {
            self.target.check_space()?;
            let mut transaction = self.database.begin_write().map_err(db_error)?;
            transaction
                .set_durability(Durability::None)
                .map_err(db_error)?;
            let mut count = 0;
            {
                let mut table = transaction.open_table(definition).map_err(db_error)?;
                while count < CHUNK {
                    let Some(row) = rows.next() else {
                        break;
                    };
                    let (key, value) = row.map_err(db_error)?;
                    table.insert(key.value(), value.value()).map_err(db_error)?;
                    count += 1;
                }
            }
            transaction.commit().map_err(db_error)?;
            copied += count;
            let go_on = progress(name, copied);
            if count < CHUNK || !go_on {
                // 空のコミットで、待たずにコミットしたものを書き出し終える
                self.database
                    .begin_write()
                    .map_err(db_error)?
                    .commit()
                    .map_err(db_error)?;
                return Ok(count < CHUNK);
            }
        }
    }
}

/// 昔の高さの状態と木のノードを引くもの（[`Db::at`]）。開いたときの読み取りのまま、あとから書いたものは見えない
pub struct At {
    state: Past,
    trie: Past,
}

impl At {
    /// 状態の行。なければ `None`
    pub fn state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.state.get(key)
    }

    /// 木のノード。なければ `None`
    pub fn trie_node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        self.trie.get(key)
    }
}

/// 今の状態を、1つの読み取りで引く先（[`Db::now`]）
pub struct Now {
    state: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
}

impl Now {
    /// 状態の行。なければ `None`
    pub fn state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        Ok(self
            .state
            .get(key)
            .map_err(db_error)?
            .map(|value| value.value().to_vec()))
    }
}

/// ブロックの索引に入れるものに、ステートメント（あれば）からエイリアスを解決した先のアドレスも足したもの
fn indexed_with_resolutions(
    block: &[u8],
    statement: Option<&[u8]>,
    network: &TransactionNetwork,
) -> Vec<IndexedTransaction> {
    let mut indexed = search::indexed_transactions(block, network);
    if let Some(statement) = statement.and_then(|bytes| BlockStatement::from_bytes(bytes).ok()) {
        for entry in &mut indexed {
            let resolved = search::resolved_addresses(&statement, entry.index, &entry.addresses);
            entry.addresses.extend(resolved);
        }
    }
    indexed
}

/// しまってあるブロックから表を作るところ（[`Db::backfill`]）。まとまりの（高さ、ブロック）を受け取って書く
type BackfillAdd<'a> =
    dyn Fn(&WriteTransaction, &[(u64, Vec<u8>)]) -> Result<(), DbError> + Sync + 'a;

/// 昔の高さの状態を引くための、開いた表
struct Past {
    height: u64,
    state: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
    changesets: redb::ReadOnlyTable<(u64, &'static [u8]), &'static [u8]>,
    history: redb::ReadOnlyTable<(&'static [u8], u64), ()>,
}

impl Past {
    fn open(
        transaction: &ReadTransaction,
        tables: Versioned,
        height: u64,
    ) -> Result<Self, DbError> {
        let meta = transaction.open_table(META).map_err(db_error)?;
        let from = meta
            .get(tables.from)
            .map_err(db_error)?
            .map(|value| u64_from(value.value()));
        if from.is_none_or(|from| height < from) {
            return Err(DbError::NoHistory {
                height,
                from: from.unwrap_or(u64::MAX),
            });
        }
        if let Some(through) = meta.get(tables.indexed).map_err(db_error)? {
            return Err(DbError::NotIndexed {
                through: u64_from(through.value()),
            });
        }
        Ok(Self {
            height,
            state: transaction.open_table(tables.current).map_err(db_error)?,
            changesets: transaction
                .open_table(tables.changesets)
                .map_err(db_error)?,
            history: transaction.open_table(tables.history).map_err(db_error)?,
        })
    }

    /// 求める高さより後で最初に変わった高さの、変わる前の値。後で変わっていなければ今の値
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, DbError> {
        let later = self
            .history
            .range((key, self.height + 1)..=(key, u64::MAX))
            .map_err(db_error)?
            .next()
            .transpose()
            .map_err(db_error)?
            .map(|(entry, _)| entry.value().1);
        if let Some(changed) = later {
            let before = self
                .changesets
                .get((changed, key))
                .map_err(db_error)?
                .expect("history points to a changeset");
            return Ok(match before.value() {
                [PRESENT, value @ ..] => Some(value.to_vec()),
                _ => None,
            });
        }
        Ok(self
            .state
            .get(key)
            .map_err(db_error)?
            .map(|value| value.value().to_vec()))
    }
}

/// まとめて書くもの。
pub struct Batch {
    transaction: WriteTransaction,
    /// `history` を書かない（[`Db::defer_history`]）
    defer_history: bool,
    /// 状態と木のノードのそれぞれ、この高さ以下では差分も索引も書かない（[`Db::quiet_history_through`]）
    quiet_through: [Option<u64>; 2],
    /// 作る検索（[`Db::set_search`]）
    search: Searches,
    /// トランザクションの索引を作る（[`Db::set_transaction_network`]）
    network: Option<TransactionNetwork>,
}

impl Batch {
    /// ブロックを足す。高さの順を守るのは呼ぶ側。
    /// [`Searches::NAMESPACES`] なら、ネームスペースの登録から名前の表も足す。[`Searches::TRANSACTIONS`] なら、
    /// トランザクションのハッシュとアドレスの表も足し、その高さにあったブロック（枝を取り替えたとき）の分を消す。
    /// エイリアスを解決した先のアドレスは、ステートメントを足すとき（[`Batch::put_statement`]）に足す
    pub fn put_block(&mut self, height: u64, block: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(BLOCKS).map_err(db_error)?;
        let replaced = table
            .insert(height, block)
            .map_err(db_error)?
            .map(|old| old.value().to_vec());
        drop(table);
        if self.search.contains(Searches::TRANSACTIONS) {
            let network = self.network.ok_or(DbError::NoNetwork)?;
            if let Some(old) = replaced {
                // 外れるブロックのステートメントは、まだ書き換えていない
                let statement = self
                    .transaction
                    .open_table(STATEMENTS)
                    .map_err(db_error)?
                    .get(height)
                    .map_err(db_error)?
                    .map(|value| value.value().to_vec());
                self.remove_indexed(
                    height,
                    &indexed_with_resolutions(&old, statement.as_deref(), &network),
                )?;
            }
            let indexed = search::indexed_transactions(block, &network);
            let mut hashes = self
                .transaction
                .open_table(TRANSACTION_HASHES)
                .map_err(db_error)?;
            let mut addresses = self
                .transaction
                .open_table(ADDRESS_TRANSACTIONS)
                .map_err(db_error)?;
            for entry in &indexed {
                hashes
                    .insert(entry.hash.0.as_slice(), (height, entry.index))
                    .map_err(db_error)?;
                for address in &entry.addresses {
                    let key = search::address_key(address, height, entry.index);
                    addresses.insert(key.as_slice(), ()).map_err(db_error)?;
                }
            }
        }
        if self.search.contains(Searches::NAMESPACES) {
            let mut names = self.transaction.open_table(NAMES).map_err(db_error)?;
            for (id, parent, name) in search::names_in_block(block) {
                let value = [&parent.to_le_bytes()[..], &name].concat();
                names.insert(id, value.as_slice()).map_err(db_error)?;
            }
        }
        Ok(())
    }

    /// 外れるブロックの、ハッシュとアドレスの表の行を消す。ハッシュは、ほかの高さに入り直していれば残す
    fn remove_indexed(
        &mut self,
        height: u64,
        indexed: &[IndexedTransaction],
    ) -> Result<(), DbError> {
        let mut hashes = self
            .transaction
            .open_table(TRANSACTION_HASHES)
            .map_err(db_error)?;
        let mut addresses = self
            .transaction
            .open_table(ADDRESS_TRANSACTIONS)
            .map_err(db_error)?;
        for entry in indexed {
            let here = hashes
                .get(entry.hash.0.as_slice())
                .map_err(db_error)?
                .is_some_and(|value| value.value().0 == height);
            if here {
                hashes.remove(entry.hash.0.as_slice()).map_err(db_error)?;
            }
            for address in &entry.addresses {
                let key = search::address_key(address, height, entry.index);
                addresses.remove(key.as_slice()).map_err(db_error)?;
            }
        }
        Ok(())
    }

    /// ファイナライズの証明を足す。
    pub fn put_proof(&mut self, epoch: u32, proof: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(PROOFS).map_err(db_error)?;
        table.insert(epoch, proof).map_err(db_error)?;
        Ok(())
    }

    /// 自分の枝に入れたブロックが孤立ブロックの表にあれば消す（枝が行ったり来たりしたとき）
    pub fn remove_orphan(&mut self, height: u64, hash: &[u8; 32]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(ORPHANS).map_err(db_error)?;
        table.remove((height, hash.as_slice())).map_err(db_error)?;
        Ok(())
    }

    /// ステートメントを足す。[`Searches::TRANSACTIONS`] なら、その高さのブロック（先に [`Batch::put_block`] で
    /// 足したもの）のトランザクションに、エイリアスを解決した先のアドレスも足す
    pub fn put_statement(&mut self, height: u64, statement: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(STATEMENTS).map_err(db_error)?;
        table.insert(height, statement).map_err(db_error)?;
        drop(table);
        if self.search.contains(Searches::TRANSACTIONS) {
            let network = self.network.ok_or(DbError::NoNetwork)?;
            // エイリアスを解決しなかったブロックなら、足すものはない（ほとんどのブロック）
            let statement = match BlockStatement::from_bytes(statement) {
                Ok(statement) if !statement.address_resolution_statements.is_empty() => statement,
                _ => return Ok(()),
            };
            let block = self
                .transaction
                .open_table(BLOCKS)
                .map_err(db_error)?
                .get(height)
                .map_err(db_error)?
                .map(|value| value.value().to_vec());
            let Some(block) = block else {
                return Ok(());
            };
            let mut addresses = self
                .transaction
                .open_table(ADDRESS_TRANSACTIONS)
                .map_err(db_error)?;
            for entry in search::indexed_transactions(&block, &network) {
                for address in search::resolved_addresses(&statement, entry.index, &entry.addresses)
                {
                    let key = search::address_key(&address, height, entry.index);
                    addresses.insert(key.as_slice(), ()).map_err(db_error)?;
                }
            }
        }
        Ok(())
    }

    /// `through` 以下のブロックを、`keep` が真の高さのほかは消す。追いつく段階で、もう再開に要らないブロックを
    /// 書いた端から消すのに使う（ファイルが広がらないよう、空いたページを次の書き込みで使い回す）。
    /// 残っている一番低い高さ（[`Db::blocks_from`]）は変えない
    pub fn remove_blocks_through(
        &mut self,
        through: u64,
        keep: impl Fn(u64) -> bool,
    ) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(BLOCKS).map_err(db_error)?;
        table
            .retain_in(..=through, |height, _| keep(height))
            .map_err(db_error)?;
        Ok(())
    }

    /// `height` でコミットする、木に入らない実行の状態
    pub fn put_checkpoint(&mut self, height: u64, executor: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(CHECKPOINTS).map_err(db_error)?;
        table.insert(height, executor).map_err(db_error)?;
        Ok(())
    }

    pub fn put_voters(&mut self, epoch: u32, voters: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(VOTERS).map_err(db_error)?;
        table.insert(epoch, voters).map_err(db_error)?;
        Ok(())
    }

    pub fn put_state(&mut self, key: &[u8], value: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(STATE).map_err(db_error)?;
        let before = table
            .insert(key, value)
            .map_err(db_error)?
            .map(|before| before.value().to_vec());
        let mut search = self.transaction.open_table(SEARCH).map_err(db_error)?;
        let mut past = self.transaction.open_table(SEARCH_PAST).map_err(db_error)?;
        update_search(
            &mut search,
            &mut past,
            self.search,
            key,
            before.as_deref(),
            Some(value),
        )
    }

    pub fn delete_state(&mut self, key: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(STATE).map_err(db_error)?;
        let before = table
            .remove(key)
            .map_err(db_error)?
            .map(|before| before.value().to_vec());
        let mut search = self.transaction.open_table(SEARCH).map_err(db_error)?;
        let mut past = self.transaction.open_table(SEARCH_PAST).map_err(db_error)?;
        update_search(
            &mut search,
            &mut past,
            self.search,
            key,
            before.as_deref(),
            None,
        )
    }

    /// `height` のブロックで、状態の行をキーごとに値にする（`None` なら消す）。
    /// 前と違えば、変わる前の値を `changesets` に、高さを `history` に残す。
    /// 同じキーは高さの順に書くこと。
    pub fn set_state_at<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        height: u64,
        writes: impl IntoIterator<Item = (K, Option<V>)>,
    ) -> Result<(), DbError> {
        let quiet = self.quiet_through[0].is_some_and(|through| height <= through);
        self.set_at(STATE_TABLES, height, quiet, self.search, writes)
    }

    /// [`Batch::set_state_at`] と同じことを、木のノードで。
    pub fn set_trie_at<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        height: u64,
        writes: impl IntoIterator<Item = (K, Option<V>)>,
    ) -> Result<(), DbError> {
        let quiet = self.quiet_through[1].is_some_and(|through| height <= through);
        self.set_at(TRIE_TABLES, height, quiet, Searches::NONE, writes)
    }

    /// `quiet` なら、今の値だけを書く。検索表は `search` の分を直す
    fn set_at<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        tables: Versioned,
        height: u64,
        quiet: bool,
        search: Searches,
        writes: impl IntoIterator<Item = (K, Option<V>)>,
    ) -> Result<(), DbError> {
        // 表を開くのは1回にする。開くたびに表の根を読み直すので
        let mut current = self
            .transaction
            .open_table(tables.current)
            .map_err(db_error)?;
        let mut changesets = self
            .transaction
            .open_table(tables.changesets)
            .map_err(db_error)?;
        let mut history = self
            .transaction
            .open_table(tables.history)
            .map_err(db_error)?;
        let mut search_table = self.transaction.open_table(SEARCH).map_err(db_error)?;
        let mut past_table = self.transaction.open_table(SEARCH_PAST).map_err(db_error)?;
        for (key, value) in writes {
            let key = key.as_ref();
            let value = value.as_ref().map(AsRef::as_ref);
            let before = match value {
                Some(value) => current.insert(key, value),
                None => current.remove(key),
            }
            .map_err(db_error)?
            .map(|before| before.value().to_vec());
            update_search(
                &mut search_table,
                &mut past_table,
                search,
                key,
                before.as_deref(),
                value,
            )?;
            if quiet || before.as_deref() == value {
                continue;
            }
            let before = match before {
                Some(mut bytes) => {
                    bytes.insert(0, PRESENT);
                    bytes
                }
                None => ABSENT.to_vec(),
            };
            changesets
                .insert((height, key), before.as_slice())
                .map_err(db_error)?;
            if !self.defer_history {
                history.insert((key, height), ()).map_err(db_error)?;
            }
        }
        Ok(())
    }

    /// `history` を後回しにするとき、今は `height` までできていることを残す。もっと前までしかできていなければ、そのまま
    pub fn defer_history_after(&mut self, height: u64) -> Result<(), DbError> {
        let mut meta = self.transaction.open_table(META).map_err(db_error)?;
        for tables in [STATE_TABLES, TRIE_TABLES] {
            if meta.get(tables.indexed).map_err(db_error)?.is_none() {
                meta.insert(tables.indexed, height.to_le_bytes().as_slice())
                    .map_err(db_error)?;
            }
        }
        Ok(())
    }

    /// 状態の差分を残し始める高さを、まだ決めていなければ決める。
    pub fn start_history(&mut self, height: u64) -> Result<(), DbError> {
        self.start(STATE_TABLES, height)
    }

    /// 木のノードの差分を残し始める高さを、まだ決めていなければ決める。
    pub fn start_trie(&mut self, height: u64) -> Result<(), DbError> {
        self.start(TRIE_TABLES, height)
    }

    fn start(&mut self, tables: Versioned, height: u64) -> Result<(), DbError> {
        let mut meta = self.transaction.open_table(META).map_err(db_error)?;
        if meta.get(tables.from).map_err(db_error)?.is_none() {
            meta.insert(tables.from, height.to_le_bytes().as_slice())
                .map_err(db_error)?;
        }
        Ok(())
    }

    pub fn put_meta(&mut self, name: &str, value: &[u8]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(META).map_err(db_error)?;
        table.insert(name, value).map_err(db_error)?;
        Ok(())
    }

    /// 住所録を `peers` で置き換える
    pub fn replace_known_peers(&mut self, peers: &[(String, Vec<u8>)]) -> Result<(), DbError> {
        let mut table = self.transaction.open_table(PEERS).map_err(db_error)?;
        table.retain(|_, _| false).map_err(db_error)?;
        for (address, record) in peers {
            table
                .insert(address.as_str(), record.as_slice())
                .map_err(db_error)?;
        }
        Ok(())
    }

    /// まとめてディスクに残す。
    pub fn commit(self) -> Result<(), DbError> {
        self.transaction.commit().map_err(db_error)
    }

    /// まとめて書くが、ディスクに書き出し終わるのを待たない。落ちると、前に [`Batch::commit`] したところまで戻る。
    pub fn commit_lazily(mut self) -> Result<(), DbError> {
        self.transaction
            .set_durability(Durability::None)
            .map_err(db_error)?;
        self.transaction.commit().map_err(db_error)
    }
}

/// `transaction` の中で、高さ `through` 以下のブロックとステートメントと、エポック `before_epoch` より前の証明を、
/// 合わせて `limit` 行まで消す。（消した行の数、全部消し終えたか）
fn prune_history_in(
    transaction: &WriteTransaction,
    through: u64,
    before_epoch: u32,
    limit: usize,
) -> Result<(u64, bool), DbError> {
    let mut rows = 0;
    for (table, from) in [(BLOCKS, BLOCKS_FROM), (STATEMENTS, STATEMENTS_FROM)] {
        let mut table = transaction.open_table(table).map_err(db_error)?;
        while table
            .first()
            .map_err(db_error)?
            .is_some_and(|(height, _)| height.value() <= through)
        {
            if rows == limit {
                return Ok((rows as u64, false));
            }
            table.pop_first().map_err(db_error)?;
            rows += 1;
        }
        let mut meta = transaction.open_table(META).map_err(db_error)?;
        let kept = meta
            .get(from)
            .map_err(db_error)?
            .map_or(0, |value| u64_from(value.value()));
        if through + 1 > kept {
            meta.insert(from, (through + 1).to_le_bytes().as_slice())
                .map_err(db_error)?;
        }
    }
    let mut proofs = transaction.open_table(PROOFS).map_err(db_error)?;
    while proofs
        .first()
        .map_err(db_error)?
        .is_some_and(|(epoch, _)| epoch.value() < before_epoch)
    {
        if rows == limit {
            return Ok((rows as u64, false));
        }
        proofs.pop_first().map_err(db_error)?;
        rows += 1;
    }
    Ok((rows as u64, true))
}

fn u64_from(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("u64 in meta"))
}

/// `path` のあるファイルシステムで、ふつうのユーザーが使える空き
#[cfg(unix)]
fn free_space(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path は NUL で終わり、stat は statvfs が埋める
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: 成功したので埋まっている
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::useless_conversion)] // 32ビットの環境では u32
    Ok(u64::from(stat.f_bavail) * u64::from(stat.f_frsize))
}

#[cfg(not(unix))]
fn free_space(_path: &Path) -> std::io::Result<u64> {
    Ok(u64::MAX)
}

impl StateSource for Db {
    fn row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        self.state_row(key).map_err(read_error)
    }

    fn node(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ExecError> {
        self.trie_node(key).map_err(read_error)
    }

    fn for_each_row(
        &self,
        prefix: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]),
    ) -> Result<(), ExecError> {
        self.for_each_state_row(prefix, visit).map_err(read_error)
    }
}

fn read_error(error: DbError) -> ExecError {
    ExecError::Source(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// テストごとの一時フォルダー。drop で消す
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "heika-store-redb-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn refuses_a_database_of_another_format() {
        let dir = TempDir::new();
        drop(Db::open(&dir.0).unwrap());
        assert!(Db::open(&dir.0).is_ok());
        assert!(Db::open_read_only(&dir.0).is_ok());
        for (written, expected) in [(&2u32.to_le_bytes()[..], Some(2)), (&b""[..], None)] {
            let db = Db::open(&dir.0).unwrap();
            let mut batch = db.batch().unwrap();
            batch.put_meta(FORMAT_META, written).unwrap();
            batch.commit().unwrap();
            drop(db);
            assert!(matches!(Db::open(&dir.0), Err(DbError::Format(found)) if found == expected));
            assert!(matches!(
                Db::open_read_only(&dir.0),
                Err(DbError::Format(found)) if found == expected
            ));
            // 元に戻す（開けないので、redb で直に書く）
            let database = Database::create(dir.0.join(FILE_NAME)).unwrap();
            let transaction = database.begin_write().unwrap();
            transaction
                .open_table(META)
                .unwrap()
                .insert(FORMAT_META, &FORMAT.to_le_bytes()[..])
                .unwrap();
            transaction.commit().unwrap();
        }
    }

    #[test]
    fn blocks_are_visible_only_after_commit_and_survive_reopen() {
        let dir = TempDir::new();
        {
            let db = Db::open(&dir.0).unwrap();
            assert_eq!(db.blocks_tip().unwrap(), 0);
            let mut batch = db.batch().unwrap();
            batch.put_block(1, b"one").unwrap();
            batch.put_block(2, b"two").unwrap();
            drop(batch);
            assert_eq!(db.blocks_tip().unwrap(), 0, "コミットしなければ残らない");

            let mut batch = db.batch().unwrap();
            batch.put_block(1, b"one").unwrap();
            batch.put_block(2, b"two").unwrap();
            batch.commit().unwrap();
        }
        let db = Db::open_read_only(&dir.0).unwrap();
        assert_eq!(db.blocks_tip().unwrap(), 2);
        assert_eq!(db.block(2).unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(db.block(3).unwrap(), None);
        assert!(db.batch().is_err());
    }

    #[test]
    fn reads_state_and_trie_of_one_height_together() {
        let dir = TempDir::new();
        let db = Db::open(&dir.0).unwrap();
        assert!(matches!(db.at(1), Err(DbError::NoHistory { .. })));
        let mut batch = db.batch().unwrap();
        batch.start_history(1).unwrap();
        batch.start_trie(1).unwrap();
        batch
            .set_state_at(
                1,
                [(&b"\x01a"[..], Some(&b"a1"[..])), (b"\x02z", Some(b"z1"))],
            )
            .unwrap();
        batch.set_trie_at(1, [(b"n", Some(b"n1"))]).unwrap();
        batch
            .set_state_at(2, [(&b"\x01a"[..], None), (b"\x01b", Some(&b"b2"[..]))])
            .unwrap();
        batch.set_trie_at(2, [(b"n", Some(b"n2"))]).unwrap();
        batch.commit().unwrap();

        let at = db.at(1).unwrap();
        assert_eq!(at.state(b"\x01a").unwrap().as_deref(), Some(&b"a1"[..]));
        assert_eq!(at.state(b"\x01b").unwrap(), None);
        assert_eq!(at.trie_node(b"n").unwrap().as_deref(), Some(&b"n1"[..]));
        assert_eq!(
            db.at(2).unwrap().trie_node(b"n").unwrap().as_deref(),
            Some(&b"n2"[..])
        );
        assert!(matches!(db.at(0), Err(DbError::NoHistory { .. })));

        // 前方一致は、消えた行も昔の高さなら返し、ほかの前方の行は返さない
        let rows = |height| db.state_rows_with_prefix_at(b"\x01", height).unwrap();
        assert_eq!(rows(1), vec![(b"\x01a".to_vec(), b"a1".to_vec())]);
        assert_eq!(rows(2), vec![(b"\x01b".to_vec(), b"b2".to_vec())]);
        assert_eq!(
            db.state_rows_with_prefix_at(b"\x02", 2).unwrap(),
            vec![(b"\x02z".to_vec(), b"z1".to_vec())]
        );
    }

    /// メタデータの状態の行のキー（木の番号と compositeHash）と値。値の中身だけ違うものを `value` で作る
    fn metadata_row(source: u8, value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut row = vec![source; 24];
        row.extend_from_slice(&[0x69; 24]);
        row.extend_from_slice(&7u64.to_le_bytes());
        row.extend_from_slice(&0u64.to_le_bytes());
        row.push(0);
        row.extend_from_slice(&(value.len() as u16).to_le_bytes());
        row.extend_from_slice(value);
        let mut key = vec![heika_core::patricia::SubCache::Metadata.index() as u8];
        key.extend_from_slice(
            &MetadataFields::from_row(&row)
                .unwrap()
                .composite_hash()
                .unwrap(),
        );
        (key, row)
    }

    fn search_keys(db: &Db, prefix: &[u8]) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        db.for_each_search_key(prefix, None, false, &mut |key| {
            keys.push(key.to_vec());
            true
        })
        .unwrap();
        keys
    }

    #[test]
    fn search_follows_the_state_and_its_rollback() {
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        let (a, a1) = metadata_row(0x01, b"a1");
        let (_, a2) = metadata_row(0x01, b"a2");
        let (b, b1) = metadata_row(0x02, b"b1");
        let mut batch = db.batch().unwrap();
        batch.start_history(1).unwrap();
        batch.start_trie(1).unwrap();
        batch.set_state_at(1, [(&a, Some(&a1))]).unwrap();
        batch.put_checkpoint(1, b"one").unwrap();
        batch.commit().unwrap();

        // 足したときに、今の状態の行から作る
        assert!(search_keys(&db, &[]).is_empty());
        db.set_search(Searches::METADATA).unwrap();
        let by_source = |source: u8| {
            let mut prefix = vec![search::METADATA_BY_SOURCE];
            prefix.extend_from_slice(&[source; 24]);
            search_keys(&db, &prefix)
        };
        assert_eq!(by_source(0x01).len(), 1);
        // アカウントのメタデータなので、送り主と宛先からの2本だけ
        assert_eq!(search_keys(&db, &[]).len(), 2);
        assert_eq!(
            MetadataFields::from_search_key(&by_source(0x01)[0])
                .unwrap()
                .source,
            [0x01; 24]
        );

        // 値が変わっても検索表は変わらず、行ができたら足し、消えたら消す
        let mut batch = db.batch().unwrap();
        batch
            .set_state_at(2, [(&a, Some(&a2)), (&b, Some(&b1))])
            .unwrap();
        batch.set_state_at(3, [(&a, None::<&Vec<u8>>)]).unwrap();
        batch.commit().unwrap();
        assert!(by_source(0x01).is_empty());
        assert_eq!(by_source(0x02).len(), 1);

        // 巻き戻したら、差分から元に戻る
        db.rollback(1, u32::MAX, "executor", false, &[]).unwrap();
        assert_eq!(by_source(0x01).len(), 1);
        assert!(by_source(0x02).is_empty());

        // 逆の順でも引ける
        let mut reversed = Vec::new();
        db.for_each_search_key(&[], None, true, &mut |key| {
            reversed.push(key.to_vec());
            true
        })
        .unwrap();
        let mut forward = search_keys(&db, &[]);
        forward.reverse();
        assert_eq!(reversed, forward);

        // 写しにも入り、外したら消える。開き直しても覚えている
        let copy = TempDir::new();
        let target = Db::open(&copy.0).unwrap();
        assert!(db.copy_to(&target, None, |_, _| true).unwrap());
        drop(target);
        let target = Db::open_read_only(&copy.0).unwrap();
        assert_eq!(target.searches(), Searches::METADATA);
        assert_eq!(search_keys(&target, &[]).len(), 2);
        db.set_search(Searches::NONE).unwrap();
        assert!(search_keys(&db, &[]).is_empty());
        drop(db);
        assert_eq!(Db::open(&dir.0).unwrap().searches(), Searches::NONE);
    }

    fn search_keys_with_past(db: &Db, reverse: bool) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        db.for_each_search_key_with_past(
            &[search::METADATA_BY_SOURCE],
            None,
            reverse,
            &mut |key| {
                keys.push(key.to_vec());
                true
            },
        )
        .unwrap();
        keys
    }

    #[test]
    fn past_search_keeps_removed_keys() {
        let rows: Vec<_> = (1..=3).map(|source| metadata_row(source, b"v")).collect();
        let write = |db: &Db| {
            let mut batch = db.batch().unwrap();
            batch.start_history(1).unwrap();
            batch.start_trie(1).unwrap();
            batch
                .set_state_at(
                    1,
                    [
                        (&rows[0].0, Some(&rows[0].1)),
                        (&rows[2].0, Some(&rows[2].1)),
                    ],
                )
                .unwrap();
            batch.put_checkpoint(1, b"one").unwrap();
            batch
                .set_state_at(2, [(&rows[1].0, Some(&rows[1].1))])
                .unwrap();
            batch
                .set_state_at(3, [(&rows[0].0, None::<&Vec<u8>>)])
                .unwrap();
            batch.commit().unwrap();
        };
        let source_of = |key: &[u8]| MetadataFields::from_search_key(key).unwrap().source[0];
        let sources =
            |keys: Vec<Vec<u8>>| keys.iter().map(|key| source_of(key)).collect::<Vec<_>>();

        // 書きながら残す
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        db.set_search(Searches::METADATA.union(Searches::PAST))
            .unwrap();
        write(&db);
        assert_eq!(
            sources(search_keys(&db, &[search::METADATA_BY_SOURCE])),
            vec![2, 3]
        );
        assert_eq!(sources(search_keys_with_past(&db, false)), vec![1, 2, 3]);
        assert_eq!(sources(search_keys_with_past(&db, true)), vec![3, 2, 1]);
        // 巻き戻しで消えた2も候補に残るが、それは引くときに状態の行で落とす
        db.rollback(1, u32::MAX, "executor", false, &[]).unwrap();
        assert_eq!(
            sources(search_keys(&db, &[search::METADATA_BY_SOURCE])),
            vec![1, 3]
        );
        assert_eq!(sources(search_keys_with_past(&db, false)), vec![1, 2, 3]);
        // 検索表のキーから、その状態の行が引ける
        let row = search::row_key_of(&search_keys(&db, &[search::METADATA_BY_SOURCE])[0]).unwrap();
        let fields = MetadataFields::from_row(&db.state_row(&row).unwrap().unwrap()).unwrap();
        assert_eq!(fields.source, [1; 24]);
        // 位置の後から読む。今の表と消えたキーの表を混ぜても、順でそれより後だけ
        let keys = search_keys_with_past(&db, false);
        let after = |after: &[u8], reverse: bool| {
            let mut out = Vec::new();
            db.for_each_search_key_with_past(
                &[search::METADATA_BY_SOURCE],
                Some(after),
                reverse,
                &mut |key| {
                    out.push(source_of(key));
                    true
                },
            )
            .unwrap();
            out
        };
        assert_eq!(after(&keys[0], false), vec![2, 3]);
        assert_eq!(after(&keys[2], true), vec![2, 1]);
        assert_eq!(after(&keys[2], false), Vec::<u8>::new());
        // 頭より前や後の位置なら、全部か何もなし
        assert_eq!(after(&[0], false), vec![1, 2, 3]);
        assert_eq!(after(&[0], true), Vec::<u8>::new());
        assert_eq!(after(&[0xFF], true), vec![3, 2, 1]);
        let mut current = Vec::new();
        db.for_each_search_key(
            &[search::METADATA_BY_SOURCE],
            Some(&keys[0]),
            false,
            &mut |key| {
                current.push(source_of(key));
                true
            },
        )
        .unwrap();
        assert_eq!(current, vec![3]);

        // やめたら消える
        db.set_search(Searches::METADATA).unwrap();
        assert_eq!(sources(search_keys_with_past(&db, false)), vec![1, 3]);

        // あとから始めたら、状態の差分の前の値から作る
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        write(&db);
        db.set_search(Searches::METADATA.union(Searches::PAST))
            .unwrap();
        assert_eq!(
            sources(search_keys(&db, &[search::METADATA_BY_SOURCE])),
            vec![2, 3]
        );
        assert_eq!(sources(search_keys_with_past(&db, false)), vec![1, 2, 3]);
    }

    /// ネームスペースの登録を1件入れた、通常のブロックのバイト列。署名は確かめないので0のまま
    fn block_registering(parent: Option<u64>, name: &[u8], right_id: bool) -> Vec<u8> {
        use heika_transaction::{NamespaceId, NamespaceRegistration, NamespaceRegistrationType};
        let parent = parent.map(NamespaceId);
        let mut id = NamespaceId::generate(parent, name);
        if !right_id {
            id.0 ^= 1;
        }
        let registration = NamespaceRegistration {
            registration_type: match parent {
                None => NamespaceRegistrationType::Root { duration: 100 },
                Some(parent_id) => NamespaceRegistrationType::Child { parent_id },
            },
            id,
            name: name.to_vec().try_into().unwrap(),
        };
        let transaction = heika_transaction::Transaction::new(
            heika_core::key::PublicKey([0x11; 32]),
            heika_core::network::NetworkIdentifier::MAINNET,
            0,
            0,
            heika_transaction::Body::NamespaceRegistration(registration),
        )
        .to_bytes();
        let mut block = vec![0; 376];
        block[110..112].copy_from_slice(&0x8143u16.to_le_bytes());
        block.extend_from_slice(&transaction);
        block.resize(block.len().next_multiple_of(8), 0);
        let size = block.len() as u32;
        block[..4].copy_from_slice(&size.to_le_bytes());
        block
    }

    #[test]
    fn names_come_from_namespace_registrations() {
        use heika_transaction::NamespaceId;
        let root = NamespaceId::generate(None, b"hina").0;
        let child = NamespaceId::generate(Some(NamespaceId(root)), b"xym").0;
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        // 有効にする前のブロック
        let mut batch = db.batch().unwrap();
        batch
            .put_block(1, &block_registering(None, b"hina", true))
            .unwrap();
        batch.commit().unwrap();
        assert_eq!(db.namespace_name(root).unwrap(), None);

        // 有効にしたら、しまってあるブロックから作る
        db.set_search(Searches::NAMESPACES).unwrap();
        assert_eq!(db.namespace_name(root).unwrap(), None);
        let mut seen = Vec::new();
        assert!(
            db.backfill_names(&|| false, &mut |at, through| seen.push((at, through)))
                .unwrap()
        );
        assert_eq!(seen, vec![(1, 1)]);
        assert_eq!(
            db.namespace_name(root).unwrap(),
            Some((0, b"hina".to_vec()))
        );
        // 終わったら、もう読まない
        assert!(db.backfill_names(&|| false, &mut |_, _| panic!()).unwrap());

        // 有効なあいだは、足すブロックから。ID が名前と合わないものは入れない
        let mut batch = db.batch().unwrap();
        batch
            .put_block(2, &block_registering(Some(root), b"xym", true))
            .unwrap();
        batch
            .put_block(3, &block_registering(None, b"fake", false))
            .unwrap();
        batch.commit().unwrap();
        assert_eq!(
            db.namespace_name(child).unwrap(),
            Some((root, b"xym".to_vec()))
        );
        let fake = NamespaceId::generate(None, b"fake").0;
        assert_eq!(db.namespace_name(fake).unwrap(), None);
        assert_eq!(db.namespace_name(fake ^ 1).unwrap(), None);

        // 止める合図なら、続きを残して返る
        db.set_search(Searches::NONE).unwrap();
        assert_eq!(db.namespace_name(root).unwrap(), None);
        db.set_search(Searches::NAMESPACES).unwrap();
        assert!(!db.backfill_names(&|| true, &mut |_, _| {}).unwrap());
        assert!(db.backfill_names(&|| false, &mut |_, _| {}).unwrap());
        assert_eq!(
            db.namespace_name(child).unwrap(),
            Some((root, b"xym".to_vec()))
        );
    }

    /// 署名者 [0x11; 32] から `recipient` への送金を1件入れた、通常のブロックのバイト列
    fn block_sending(recipient: [u8; 24], message: &[u8]) -> Vec<u8> {
        let transfer = heika_transaction::Transfer::new(
            heika_transaction::UnresolvedAddress(recipient),
            Default::default(),
            message.to_vec(),
        )
        .unwrap();
        let transaction = heika_transaction::Transaction::new(
            heika_core::key::PublicKey([0x11; 32]),
            heika_core::network::NetworkIdentifier::MAINNET,
            0,
            0,
            heika_transaction::Body::Transfer(transfer),
        )
        .to_bytes();
        let mut block = vec![0; 376];
        block[110..112].copy_from_slice(&0x8143u16.to_le_bytes());
        block.extend_from_slice(&transaction);
        block.resize(block.len().next_multiple_of(8), 0);
        let size = block.len() as u32;
        block[..4].copy_from_slice(&size.to_le_bytes());
        block
    }

    #[test]
    fn transaction_indexes_come_from_blocks_and_statements() {
        use heika_block::statement::{AddressResolutionStatement, ReceiptSource, ResolutionEntry};
        let network = search::tests::test_network();
        // ブロックの中の1つ目のトランザクションのハッシュ。ブロックのヘッダーは 376 バイト
        let hash_of = |block: &[u8]| {
            let size = u32::from_le_bytes(block[376..380].try_into().unwrap()) as usize;
            heika_transaction::Transaction::from_bytes(&block[376..376 + size])
                .unwrap()
                .hash(&network.generation_hash_seed)
        };
        let signer = heika_core::address::Address::from_public_key(
            &heika_core::key::PublicKey([0x11; 32]),
            heika_core::network::NetworkIdentifier::MAINNET,
        )
        .0;
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        let listed = |db: &Db, address: &[u8; 24]| {
            let mut out = Vec::new();
            db.for_each_address_transaction(address, 0..=u64::MAX, None, false, &mut |h, i| {
                out.push((h, i));
                true
            })
            .unwrap();
            out
        };
        // ネットワークの値がなければ作れない。しまったら、違うものは受け付けない
        assert!(matches!(
            db.set_search(Searches::TRANSACTIONS),
            Err(DbError::NoNetwork)
        ));
        db.set_transaction_network(network).unwrap();
        db.set_transaction_network(network).unwrap();
        let other = TransactionNetwork {
            mosaic_rental_fee_sink: [0xA3; 24],
            ..network
        };
        assert!(matches!(
            db.set_transaction_network(other),
            Err(DbError::OtherNetwork)
        ));
        drop(db);
        let mut db = Db::open(&dir.0).unwrap();
        assert!(matches!(
            db.set_transaction_network(other),
            Err(DbError::OtherNetwork)
        ));

        // 有効にする前のブロックは、しまってあるブロックとステートメントから作る。2 番目のブロックは、
        // エイリアス [0x99; 24] に送り、ステートメントで [0x66; 24] に解決した
        let alias = [0x99; 24];
        let statement = BlockStatement {
            transaction_statements: Vec::new(),
            address_resolution_statements: vec![AddressResolutionStatement {
                unresolved: heika_transaction::UnresolvedAddress(alias),
                entries: vec![ResolutionEntry {
                    source: ReceiptSource {
                        primary_id: 1,
                        secondary_id: 0,
                    },
                    resolved: heika_core::address::Address([0x66; 24]),
                }],
            }],
            mosaic_resolution_statements: Vec::new(),
        }
        .to_bytes();
        let mut batch = db.batch().unwrap();
        batch
            .put_block(1, &block_sending([0x55; 24], b"a"))
            .unwrap();
        batch.put_block(2, &block_sending(alias, b"b")).unwrap();
        batch.put_statement(2, &statement).unwrap();
        batch.commit().unwrap();
        let a = hash_of(&block_sending([0x55; 24], b"a"));
        db.set_search(Searches::TRANSACTIONS).unwrap();
        assert_eq!(db.transaction_location(&a).unwrap(), None);
        assert!(db.backfill_transactions(&|| false, &mut |_, _| {}).unwrap());
        assert_eq!(db.transaction_location(&a).unwrap(), Some((1, 0)));
        assert_eq!(listed(&db, &signer), vec![(1, 0), (2, 0)]);
        assert_eq!(listed(&db, &[0x55; 24]), vec![(1, 0)]);
        assert_eq!(listed(&db, &alias), vec![(2, 0)]);
        assert_eq!(listed(&db, &[0x66; 24]), vec![(2, 0)]);
        assert!(
            db.backfill_transactions(&|| false, &mut |_, _| panic!())
                .unwrap()
        );

        // 有効なあいだは、足すブロックとステートメントから
        let mut batch = db.batch().unwrap();
        batch.put_block(3, &block_sending(alias, b"c")).unwrap();
        batch.put_statement(3, &statement).unwrap();
        batch.commit().unwrap();
        assert_eq!(listed(&db, &[0x66; 24]), vec![(2, 0), (3, 0)]);
        // 新しい順、高さの範囲、続き
        let mut seen = Vec::new();
        db.for_each_address_transaction(&signer, 2..=3, None, true, &mut |h, i| {
            seen.push((h, i));
            true
        })
        .unwrap();
        assert_eq!(seen, vec![(3, 0), (2, 0)]);
        let mut seen = Vec::new();
        db.for_each_address_transaction(&signer, 0..=u64::MAX, Some((1, 0)), false, &mut |h, i| {
            seen.push((h, i));
            false
        })
        .unwrap();
        assert_eq!(seen, vec![(2, 0)]);

        // 枝を取り替えたら、外れたブロックの分（解決した先も）は消える
        let (c, d) = (
            hash_of(&block_sending(alias, b"c")),
            hash_of(&block_sending([0x55; 24], b"d")),
        );
        let mut batch = db.batch().unwrap();
        batch
            .put_block(3, &block_sending([0x55; 24], b"d"))
            .unwrap();
        batch.put_statement(3, &[]).unwrap_or(());
        batch.commit().unwrap();
        assert_eq!(db.transaction_location(&c).unwrap(), None);
        assert_eq!(db.transaction_location(&d).unwrap(), Some((3, 0)));
        assert_eq!(listed(&db, &[0x66; 24]), vec![(2, 0)]);
        assert_eq!(listed(&db, &alias), vec![(2, 0)]);
        assert_eq!(listed(&db, &[0x55; 24]), vec![(1, 0), (3, 0)]);

        // 外したら消し、また足したら作り直す。止める合図なら、続きを残して返る
        db.set_search(Searches::NONE).unwrap();
        assert_eq!(db.transaction_location(&a).unwrap(), None);
        assert!(listed(&db, &signer).is_empty());
        db.set_search(Searches::TRANSACTIONS).unwrap();
        assert!(!db.backfill_transactions(&|| true, &mut |_, _| {}).unwrap());
        assert!(db.backfill_transactions(&|| false, &mut |_, _| {}).unwrap());
        assert_eq!(db.transaction_location(&a).unwrap(), Some((1, 0)));
        assert_eq!(listed(&db, &signer), vec![(1, 0), (2, 0), (3, 0)]);
        assert_eq!(listed(&db, &[0x66; 24]), vec![(2, 0)]);
    }

    #[test]
    fn past_states_come_from_changesets() {
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        let mut batch = db.batch().unwrap();
        batch.start_history(0).unwrap();
        batch.set_state_at(1, [(b"a", Some(b"a1"))]).unwrap();
        batch.set_state_at(2, [(b"a", Some(b"a1"))]).unwrap(); // 変わらない
        batch
            .set_state_at(3, [(b"a", Some(b"a3")), (b"b", Some(b"b3"))])
            .unwrap();
        batch.commit().unwrap();
        let mut batch = db.batch().unwrap();
        batch.start_history(5).unwrap(); // 決めてあれば替わらない
        batch.set_state_at(5, [(b"a", None::<&[u8]>)]).unwrap();
        batch.commit().unwrap();

        let at = |key: &[u8], height| db.state_at(key, height).unwrap();
        assert_eq!(at(b"a", 0), None);
        assert_eq!(at(b"a", 1).as_deref(), Some(&b"a1"[..]));
        assert_eq!(at(b"a", 2).as_deref(), Some(&b"a1"[..]));
        assert_eq!(at(b"a", 4).as_deref(), Some(&b"a3"[..]));
        assert_eq!(at(b"a", 5), None);
        assert_eq!(at(b"b", 2), None);
        assert_eq!(at(b"b", 9).as_deref(), Some(&b"b3"[..]));
        assert_eq!(
            db.state_rows_at(4).unwrap(),
            vec![
                (b"a".to_vec(), b"a3".to_vec()),
                (b"b".to_vec(), b"b3".to_vec())
            ]
        );
        assert_eq!(
            db.state_rows_at(5).unwrap(),
            vec![(b"b".to_vec(), b"b3".to_vec())]
        );
        assert_eq!(db.changeset(2).unwrap(), vec![]);
        assert_eq!(
            db.changeset(3).unwrap(),
            vec![(b"a".to_vec(), Some(b"a1".to_vec())), (b"b".to_vec(), None)]
        );

        db.set_min_free(u64::MAX);
        assert!(matches!(db.batch(), Err(DbError::LowSpace { .. })));
    }

    #[test]
    fn rollback_returns_to_the_last_checkpoint() {
        let dir = TempDir::new();
        let db = Db::open(&dir.0).unwrap();
        let mut batch = db.batch().unwrap();
        batch.start_history(0).unwrap();
        batch.start_trie(0).unwrap();
        for height in 1..=6u64 {
            batch.put_block(height, b"block").unwrap();
        }
        batch.set_state_at(1, [(b"a", Some(b"a1"))]).unwrap();
        batch.set_trie_at(1, [(b"n", Some(b"n1"))]).unwrap();
        batch.put_statement(1, b"s1").unwrap();
        batch.put_voters(2, b"v2").unwrap();
        batch.set_state_at(2, [(b"a", Some(b"a2"))]).unwrap();
        batch.put_checkpoint(2, b"c2").unwrap();
        batch.put_meta("executor", b"c2").unwrap();
        batch.commit().unwrap();
        let mut batch = db.batch().unwrap();
        batch
            .set_state_at(3, [(b"a", Some(b"a3")), (b"b", Some(b"b3"))])
            .unwrap();
        batch.set_trie_at(3, [(b"n", None::<&[u8]>)]).unwrap();
        batch.put_statement(3, b"s3").unwrap();
        batch.put_voters(3, b"v3").unwrap();
        batch.set_state_at(4, [(b"a", Some(b"a4"))]).unwrap();
        batch.put_checkpoint(4, b"c4").unwrap();
        batch.put_meta("executor", b"c4").unwrap();
        batch.commit().unwrap();

        assert!(matches!(
            db.rollback(1, 3, "executor", false, &[]),
            Err(DbError::NoCheckpoint { height: 1 })
        ));
        // 2 より上で変わったのは a（2 では a2）と b（2 ではない）
        assert_eq!(
            db.changes_above(2).unwrap(),
            vec![(b"a".to_vec(), Some(b"a2".to_vec())), (b"b".to_vec(), None)]
        );
        assert_eq!(
            db.changes_above(1).unwrap(),
            vec![(b"a".to_vec(), Some(b"a1".to_vec())), (b"b".to_vec(), None)]
        );
        assert_eq!(db.changes_above(4).unwrap(), vec![]);
        // 4 より下のチェックポイント（2）は1つだけなので残す
        assert_eq!(db.prune_checkpoints(4).unwrap(), 0);
        assert_eq!(
            db.checkpoint_at_or_below(3)
                .unwrap()
                .map(|(height, _)| height),
            Some(2)
        );
        // 3 へ戻すときは、2 のチェックポイントまで戻る
        assert_eq!(db.rollback(3, 3, "executor", true, &[]).unwrap(), 2);
        assert_eq!(
            db.state_rows().unwrap(),
            vec![(b"a".to_vec(), b"a2".to_vec())]
        );
        assert_eq!(
            db.trie_nodes().unwrap(),
            vec![(b"n".to_vec(), b"n1".to_vec())]
        );
        assert_eq!(db.changeset(3).unwrap(), vec![]);
        assert_eq!(db.state_at(b"a", 1).unwrap().as_deref(), Some(&b"a1"[..]));
        assert_eq!(db.statement(1).unwrap().as_deref(), Some(&b"s1"[..]));
        assert_eq!(db.statement(3).unwrap(), None);
        assert_eq!(db.voters(2).unwrap().as_deref(), Some(&b"v2"[..]));
        assert_eq!(db.voters(3).unwrap(), None);
        assert_eq!(db.meta("executor").unwrap().as_deref(), Some(&b"c2"[..]));
        assert_eq!(db.blocks_tip().unwrap(), 3);
        // 差分は消えたので、もう一度書ける
        let mut batch = db.batch().unwrap();
        batch.set_state_at(3, [(b"a", Some(b"x3"))]).unwrap();
        batch.commit().unwrap();
        assert_eq!(db.state_at(b"a", 2).unwrap().as_deref(), Some(&b"a2"[..]));
        assert_eq!(db.state_at(b"a", 3).unwrap().as_deref(), Some(&b"x3"[..]));
    }

    #[test]
    fn pruning_keeps_the_newest_checkpoint_below() {
        let dir = TempDir::new();
        let db = Db::open(&dir.0).unwrap();
        let mut batch = db.batch().unwrap();
        for height in [2u64, 4, 6, 8] {
            batch.put_checkpoint(height, b"c").unwrap();
        }
        batch.commit().unwrap();
        // 7 より下は 2、4、6。6 を残して 2 と 4 を消す
        assert_eq!(db.prune_checkpoints(7).unwrap(), 2);
        let heights: Vec<u64> = (1..=8)
            .filter_map(|height| db.checkpoint_at_or_below(height).unwrap())
            .map(|(height, _)| height)
            .collect();
        assert_eq!(heights, [6, 6, 8]);
        assert_eq!(db.prune_checkpoints(7).unwrap(), 0);
    }

    #[test]
    fn deferred_history_is_built_later() {
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        let mut batch = db.batch().unwrap();
        batch.start_history(0).unwrap();
        batch.start_trie(0).unwrap();
        batch.set_state_at(1, [(b"a", Some(b"a1"))]).unwrap();
        batch.commit().unwrap();
        db.defer_history();
        let mut batch = db.batch().unwrap();
        batch.defer_history_after(1).unwrap();
        batch.set_state_at(2, [(b"a", Some(b"a2"))]).unwrap();
        batch
            .set_state_at(3, [(b"a", Some(b"a3")), (b"b", Some(b"b3"))])
            .unwrap();
        batch.commit().unwrap();
        let mut batch = db.batch().unwrap();
        batch.defer_history_after(3).unwrap(); // もっと前までしかできていないので、そのまま
        batch.set_state_at(4, [(b"b", None::<&[u8]>)]).unwrap();
        batch.put_checkpoint(4, b"c4").unwrap();
        batch.commit().unwrap();
        assert!(matches!(
            db.state_at(b"a", 2),
            Err(DbError::NotIndexed { through: 1 })
        ));
        let mut seen = Vec::new();
        let built = db
            .build_history(|name, height| {
                seen.push((name.to_owned(), height));
                true
            })
            .unwrap();
        assert!(built);
        assert_eq!(seen, [("状態".to_owned(), 4), ("木のノード".to_owned(), 1)]);
        let at = |key: &[u8], height| db.state_at(key, height).unwrap();
        assert_eq!(at(b"a", 1).as_deref(), Some(&b"a1"[..]));
        assert_eq!(at(b"a", 2).as_deref(), Some(&b"a2"[..]));
        assert_eq!(at(b"b", 2), None);
        assert_eq!(at(b"b", 3).as_deref(), Some(&b"b3"[..]));
        assert_eq!(at(b"b", 4), None);

        // 後回しにしたあとで巻き戻すと、できているのはチェックポイントまで
        let mut batch = db.batch().unwrap();
        batch.defer_history_after(4).unwrap();
        batch.set_state_at(5, [(b"a", Some(b"a5"))]).unwrap();
        batch.put_meta("executor", b"c5").unwrap();
        batch.commit().unwrap();
        let mut batch = db.batch().unwrap();
        batch.set_state_at(6, [(b"a", Some(b"a6"))]).unwrap();
        batch.commit().unwrap();
        db.rollback(5, 0, "executor", false, &[]).unwrap();
        assert!(matches!(
            db.state_at(b"a", 4),
            Err(DbError::NotIndexed { through: 4 })
        ));
        db.build_history(|_, _| true).unwrap();
        assert_eq!(at(b"a", 4).as_deref(), Some(&b"a3"[..]));
        assert_eq!(
            db.state_rows().unwrap(),
            vec![(b"a".to_vec(), b"a3".to_vec())]
        );
    }

    #[test]
    fn past_states_need_history() {
        let dir = TempDir::new();
        let db = Db::open(&dir.0).unwrap();
        assert!(matches!(
            db.state_at(b"a", 1),
            Err(DbError::NoHistory { .. })
        ));
    }

    /// 高さ 1〜5 で a を書き換え、3 で b を足し、木のノード n を 1 と 4 で書き換えた DB。チェックポイントは 2 と 4
    fn pruning_fixture(dir: &Path) -> Db {
        let db = Db::open(dir).unwrap();
        let mut batch = db.batch().unwrap();
        batch.start_history(0).unwrap();
        batch.start_trie(0).unwrap();
        for height in 1..=5u64 {
            let value = format!("a{height}");
            batch
                .set_state_at(height, [(b"a", Some(value.as_bytes()))])
                .unwrap();
            batch.put_statement(height, value.as_bytes()).unwrap();
        }
        batch.set_state_at(3, [(b"b", Some(b"b3"))]).unwrap();
        batch.set_trie_at(1, [(b"n", Some(b"n1"))]).unwrap();
        batch.set_trie_at(4, [(b"n", Some(b"n4"))]).unwrap();
        batch.put_checkpoint(2, b"c2").unwrap();
        batch.put_checkpoint(4, b"c4").unwrap();
        batch.put_meta("executor", b"c4").unwrap();
        batch.commit().unwrap();
        db
    }

    /// 二つの DB で、引けるものが同じか。引けない高さでは、どちらも同じように引けない
    fn assert_same(left: &Db, right: &Db) {
        assert_eq!(left.kept_from().unwrap(), right.kept_from().unwrap());
        assert_eq!(left.state_rows().unwrap(), right.state_rows().unwrap());
        assert_eq!(left.trie_nodes().unwrap(), right.trie_nodes().unwrap());
        assert_eq!(
            left.meta("executor").unwrap(),
            right.meta("executor").unwrap()
        );
        for height in 0..=6 {
            let state = |db: &Db, key: &[u8]| format!("{:?}", db.state_at(key, height));
            assert_eq!(state(left, b"a"), state(right, b"a"), "a {height}");
            assert_eq!(state(left, b"b"), state(right, b"b"), "b {height}");
            let node = |db: &Db| format!("{:?}", db.trie_node_at(b"n", height));
            assert_eq!(node(left), node(right), "n {height}");
            assert_eq!(
                left.changeset(height).unwrap(),
                right.changeset(height).unwrap()
            );
            assert_eq!(
                left.statement(height).unwrap(),
                right.statement(height).unwrap()
            );
            assert_eq!(
                left.checkpoint_at_or_below(height).unwrap(),
                right.checkpoint_at_or_below(height).unwrap()
            );
        }
    }

    #[test]
    fn copying_without_bounds_keeps_everything() {
        let (dir, copy) = (TempDir::new(), TempDir::new());
        let db = pruning_fixture(&dir.0);
        let target = Db::open(&copy.0).unwrap();
        assert!(db.copy_to(&target, None, |_, _| true).unwrap());
        assert_same(&db, &target);
        assert_eq!(
            target.state_at(b"a", 1).unwrap().as_deref(),
            Some(&b"a1"[..])
        );
    }

    #[test]
    fn copying_with_bounds_matches_pruning_in_place() {
        let (dir, copy) = (TempDir::new(), TempDir::new());
        let db = pruning_fixture(&dir.0);
        let target = Db::open(&copy.0).unwrap();
        let bounds = CopyBounds {
            state: 2,
            trie: 1,
            statements: Some(2),
            blocks: None,
        };
        let mut tables = Vec::new();
        assert!(
            db.copy_to(&target, Some(bounds), |name, _| {
                tables.push(name.to_owned());
                true
            })
            .unwrap()
        );
        assert!(tables.contains(&"changesets".to_owned()));
        assert!(!tables.contains(&"history".to_owned()));
        // 索引は、写した差分から作る
        assert!(matches!(
            target.state_at(b"a", 3),
            Err(DbError::NotIndexed { .. })
        ));
        assert!(target.build_history(|_, _| true).unwrap());

        db.prune_state_history(2, |_| true).unwrap();
        db.prune_trie_history(1, |_| true).unwrap();
        db.prune_statements(2).unwrap();
        assert_same(&db, &target);
        assert_eq!(target.kept_from().unwrap(), (Some(2), Some(1), 3));
        assert_eq!(
            target.state_at(b"a", 3).unwrap().as_deref(),
            Some(&b"a3"[..])
        );
        // 境の高さのチェックポイントには戻れる
        assert_eq!(target.rollback(3, 0, "executor", false, &[]).unwrap(), 2);
        assert_eq!(
            target.state_rows().unwrap(),
            vec![(b"a".to_vec(), b"a2".to_vec())]
        );
    }

    #[test]
    fn copying_with_block_bounds_matches_pruning_history_in_place() {
        let (dir, copy) = (TempDir::new(), TempDir::new());
        let db = pruning_fixture(&dir.0);
        let mut batch = db.batch().unwrap();
        for height in 1..=5u64 {
            batch.put_block(height, &[height as u8]).unwrap();
        }
        for epoch in 1..=3u32 {
            batch.put_proof(epoch, &[epoch as u8]).unwrap();
        }
        batch
            .replace_known_peers(&[("peer".to_owned(), b"p".to_vec())])
            .unwrap();
        batch.commit().unwrap();
        let target = Db::open(&copy.0).unwrap();
        let bounds = CopyBounds {
            state: 2,
            trie: 1,
            statements: Some(3),
            blocks: Some((3, 2)),
        };
        assert!(db.copy_to(&target, Some(bounds), |_, _| true).unwrap());
        assert!(target.build_history(|_, _| true).unwrap());

        db.prune_state_history(2, |_| true).unwrap();
        db.prune_trie_history(1, |_| true).unwrap();
        db.prune_history(3, 2).unwrap();
        assert_same(&db, &target);
        assert_eq!(target.blocks_from().unwrap(), 4);
        for height in 1..=5 {
            assert_eq!(db.block(height).unwrap(), target.block(height).unwrap());
        }
        for epoch in 1..=3 {
            assert_eq!(db.proof(epoch).unwrap(), target.proof(epoch).unwrap());
        }
        assert_eq!(target.known_peers().unwrap().len(), 1);
    }

    #[test]
    fn pruning_drops_history_through_the_bound() {
        let dir = TempDir::new();
        let db = pruning_fixture(&dir.0);
        let pruned = db.prune_state_history(2, |_| true).unwrap();
        // 1 と 2 の a の差分
        assert_eq!(
            pruned,
            Pruned {
                rows: 2,
                done: true
            }
        );
        assert!(matches!(
            db.state_at(b"a", 1),
            Err(DbError::NoHistory { height: 1, from: 2 })
        ));
        let at = |key: &[u8], height| db.state_at(key, height).unwrap();
        assert_eq!(at(b"a", 2).as_deref(), Some(&b"a2"[..]));
        assert_eq!(at(b"a", 3).as_deref(), Some(&b"a3"[..]));
        assert_eq!(at(b"b", 2), None);
        assert_eq!(at(b"b", 5).as_deref(), Some(&b"b3"[..]));
        assert_eq!(
            db.state_rows_at(2).unwrap(),
            vec![(b"a".to_vec(), b"a2".to_vec())]
        );
        assert_eq!(db.changeset(2).unwrap(), vec![]);
        // 木のノードは別の境なので、まだ引ける
        assert_eq!(
            db.trie_node_at(b"n", 1).unwrap().as_deref(),
            Some(&b"n1"[..])
        );
        // 境は下げないし、もう一度呼んでも消すものはない
        assert_eq!(
            db.prune_state_history(1, |_| true).unwrap(),
            Pruned {
                rows: 0,
                done: true
            }
        );
        assert_eq!(db.kept_from().unwrap(), (Some(2), Some(0), 0));

        // 境の高さのチェックポイントには戻れる
        assert_eq!(db.rollback(3, 0, "executor", false, &[]).unwrap(), 2);
        assert_eq!(
            db.state_rows().unwrap(),
            vec![(b"a".to_vec(), b"a2".to_vec())]
        );
    }

    #[test]
    fn pruning_above_a_checkpoint_blocks_rollback_to_it() {
        let dir = TempDir::new();
        let db = pruning_fixture(&dir.0);
        db.prune_state_history(3, |_| true).unwrap();
        assert!(matches!(
            db.rollback(3, 0, "executor", false, &[]),
            Err(DbError::NoHistory { height: 2, from: 3 })
        ));
    }

    #[test]
    fn stopped_pruning_resumes_from_the_raised_bound() {
        let dir = TempDir::new();
        let db = pruning_fixture(&dir.0);
        // 1行ずつコミットし、最初のコミットで止める
        let mut seen = Vec::new();
        let pruned = db
            .prune_in_chunks(STATE_TABLES, 3, 1, |height| {
                seen.push(height);
                false
            })
            .unwrap();
        assert_eq!(
            pruned,
            Pruned {
                rows: 1,
                done: false
            }
        );
        assert_eq!(seen, [1]);
        // 境はもう上がっているので、低い境で呼んでも残りを消す
        assert!(matches!(
            db.state_at(b"a", 2),
            Err(DbError::NoHistory { from: 3, .. })
        ));
        let pruned = db.prune_in_chunks(STATE_TABLES, 0, 1, |_| true).unwrap();
        // a の 2 と 3、b の 3
        assert_eq!(
            pruned,
            Pruned {
                rows: 3,
                done: true
            }
        );
        assert_eq!(db.state_at(b"a", 3).unwrap().as_deref(), Some(&b"a3"[..]));
        assert_eq!(db.state_at(b"a", 4).unwrap().as_deref(), Some(&b"a4"[..]));
    }

    #[test]
    fn reads_current_rows_one_by_one_in_one_read_and_by_prefix() {
        let dir = TempDir::new();
        let db = pruning_fixture(&dir.0);
        assert_eq!(db.state_row(b"a").unwrap().as_deref(), Some(&b"a5"[..]));
        assert_eq!(db.state_row(b"c").unwrap(), None);
        let now = db.now().unwrap();
        assert_eq!(now.state(b"a").unwrap().as_deref(), Some(&b"a5"[..]));
        assert_eq!(now.state(b"c").unwrap(), None);
        assert_eq!(db.trie_node(b"n").unwrap().as_deref(), Some(&b"n4"[..]));
        let mut seen = Vec::new();
        db.for_each_state_row(b"", &mut |key, value| {
            seen.push((key.to_vec(), value.to_vec()))
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                (b"a".to_vec(), b"a5".to_vec()),
                (b"b".to_vec(), b"b3".to_vec())
            ]
        );
        let mut only_b = Vec::new();
        db.for_each_state_row(b"b", &mut |key, _| only_b.push(key.to_vec()))
            .unwrap();
        assert_eq!(only_b, [b"b".to_vec()]);
    }

    #[test]
    fn pruning_history_keeps_state_and_records_where_blocks_start() {
        let dir = TempDir::new();
        let db = pruning_fixture(&dir.0);
        let mut batch = db.batch().unwrap();
        for height in 1..=5u64 {
            batch.put_block(height, &[height as u8]).unwrap();
        }
        for epoch in 1..=3u32 {
            batch.put_proof(epoch, &[epoch as u8]).unwrap();
        }
        batch.commit().unwrap();
        assert_eq!(db.blocks_from().unwrap(), 0);
        // ブロック 1〜3、ステートメント 1〜3、証明 1
        assert_eq!(db.prune_history(3, 2).unwrap(), 7);
        assert_eq!(db.block(3).unwrap(), None);
        assert_eq!(db.block(4).unwrap().as_deref(), Some(&[4][..]));
        assert_eq!(db.statement(3).unwrap(), None);
        assert_eq!(db.proof(1).unwrap(), None);
        assert_eq!(db.proof(2).unwrap().as_deref(), Some(&[2][..]));
        assert_eq!(db.blocks_from().unwrap(), 4);
        assert_eq!(db.kept_from().unwrap(), (Some(0), Some(0), 4));
        // 状態とその差分には触らない
        assert_eq!(db.state_at(b"a", 1).unwrap().as_deref(), Some(&b"a1"[..]));
        // 低い境で呼んでも、残っている境は下げない
        assert_eq!(db.prune_history(1, 1).unwrap(), 0);
        assert_eq!(db.blocks_from().unwrap(), 4);
    }

    #[test]
    fn pruning_statements_records_where_they_start() {
        let dir = TempDir::new();
        let db = pruning_fixture(&dir.0);
        assert_eq!(db.prune_statements(2).unwrap(), 2);
        assert_eq!(db.statement(2).unwrap(), None);
        assert_eq!(db.statement(3).unwrap().as_deref(), Some(&b"a3"[..]));
        assert_eq!(db.kept_from().unwrap(), (Some(0), Some(0), 3));
        // 低い境で呼んでも、残っている境は下げない
        assert_eq!(db.prune_statements(1).unwrap(), 0);
        assert_eq!(db.kept_from().unwrap().2, 3);
    }

    #[test]
    fn quiet_heights_write_only_the_current_values() {
        let dir = TempDir::new();
        let mut db = Db::open(&dir.0).unwrap();
        let mut batch = db.batch().unwrap();
        batch.start_history(0).unwrap();
        batch.start_trie(0).unwrap();
        batch.commit().unwrap();
        // ジェネシスから刈り込んで実行するときと同じ順: 境を上げてから、境以下では差分を書かない
        db.prune_state_history(3, |_| true).unwrap();
        db.prune_trie_history(4, |_| true).unwrap();
        db.quiet_history_through(3, 4);
        let mut batch = db.batch().unwrap();
        for height in 1..=5u64 {
            let value = format!("a{height}");
            batch
                .set_state_at(height, [(b"a", Some(value.as_bytes()))])
                .unwrap();
            batch
                .set_trie_at(height, [(b"n", Some(value.as_bytes()))])
                .unwrap();
        }
        batch.commit().unwrap();
        assert_eq!(db.changeset(3).unwrap(), vec![]);
        assert_eq!(
            db.changeset(4).unwrap(),
            vec![(b"a".to_vec(), Some(b"a3".to_vec()))]
        );
        let at = |key: &[u8], height| db.state_at(key, height).unwrap();
        assert_eq!(at(b"a", 3).as_deref(), Some(&b"a3"[..]));
        assert_eq!(at(b"a", 4).as_deref(), Some(&b"a4"[..]));
        assert_eq!(at(b"a", 5).as_deref(), Some(&b"a5"[..]));
        assert!(matches!(
            db.state_at(b"a", 2),
            Err(DbError::NoHistory { from: 3, .. })
        ));
        assert_eq!(
            db.trie_node_at(b"n", 4).unwrap().as_deref(),
            Some(&b"a4"[..])
        );
        assert_eq!(db.kept_from().unwrap(), (Some(3), Some(4), 0));
    }

    #[test]
    fn pruning_without_history_does_nothing() {
        let dir = TempDir::new();
        let db = Db::open(&dir.0).unwrap();
        assert_eq!(
            db.prune_trie_history(5, |_| true).unwrap(),
            Pruned {
                rows: 0,
                done: true
            }
        );
        assert_eq!(db.kept_from().unwrap(), (None, None, 0));
    }
}
