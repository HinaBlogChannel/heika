//! 追いつく段階の速さを測る。ブロックを DB に入れてから、しまったブロックから実行して、かかった時間を出す。
//! ピアからは取らないので、実行と書き込みの速さだけになる。
//!
//! ブロックと設定と、DB を作るフォルダーを渡したときだけ走らせる（大きくなるので、ルートのディスクでないところ）。
//! フォルダーにまだブロックがなければ、まずファイルから入れる。`HEIKA_TEST_IMPORT_ONLY` なら入れるだけで終わる
//! （同じ DB を写して、ほかのバイナリでも測れるように）。
//!
//! ```text
//! HEIKA_TEST_BLOCKS=mainnet-1-950000.blocks HEIKA_TEST_RESOURCES=/path/to/resources HEIKA_TEST_DATA=/path/to/dir \
//!     cargo test --release -p heika-node --test execute_speed -- --ignored --nocapture
//! ```

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;

use heika_block::Block;
use heika_core::network::NetworkParameters;
use heika_node::catch_up::{self, Context, Source};
use heika_state_transition::config::ChainConfig;
use heika_store_redb::Db;

#[test]
#[ignore = "HEIKA_TEST_BLOCKS、HEIKA_TEST_RESOURCES、HEIKA_TEST_DATA を渡す"]
fn executes_stored_blocks() {
    let path = std::env::var("HEIKA_TEST_BLOCKS").expect("HEIKA_TEST_BLOCKS がありません");
    let resources =
        std::env::var("HEIKA_TEST_RESOURCES").expect("HEIKA_TEST_RESOURCES がありません");
    let data = std::env::var("HEIKA_TEST_DATA").expect("HEIKA_TEST_DATA がありません");
    let to: u64 = std::env::var("HEIKA_TEST_TO").map_or(950_000, |to| to.parse().unwrap());
    let parameters = &NetworkParameters::MAINNET;
    let mut db = Db::open(Path::new(&data)).expect("DB を開けません");
    if db.blocks_tip().unwrap() < to {
        let started = Instant::now();
        let mut file = BufReader::new(File::open(&path).expect("HEIKA_TEST_BLOCKS を開けません"));
        let mut batch = db.batch().unwrap();
        for height in 1..=to {
            let mut size = [0; 4];
            file.read_exact(&mut size).expect("ブロックが足りません");
            let mut bytes = vec![0; u32::from_le_bytes(size) as usize];
            bytes[..4].copy_from_slice(&size);
            file.read_exact(&mut bytes[4..]).unwrap();
            assert_eq!(Block::from_bytes(&bytes).unwrap().height, height);
            batch.put_block(height, &bytes).unwrap();
            if height.is_multiple_of(100_000) {
                batch.commit().unwrap();
                batch = db.batch().unwrap();
            }
        }
        batch.commit().unwrap();
        eprintln!(
            "高さ {to} までのブロックを入れました（{:.0} 秒）",
            started.elapsed().as_secs_f64()
        );
    }
    if std::env::var("HEIKA_TEST_IMPORT_ONLY").is_ok() {
        return;
    }
    let config = ChainConfig::load(Path::new(&resources)).expect("設定を読めません");
    let connect = || Err("ピアは使いません".into());
    let context = Context {
        parameters,
        nemesis: heika_chain::verify::nemesis_hash(parameters.identifier).unwrap(),
        stopping: &|| false,
        connect: &connect,
    };
    let started = Instant::now();
    let executed = catch_up::execute(
        &mut db,
        config,
        &context,
        Source::Stored,
        None,
        catch_up::DEFAULT_SAVE_EVERY,
        Some(to),
    )
    .expect("実行できません");
    assert_eq!(executed, to);
    eprintln!(
        "高さ {to} まで実行しました（{:.0} 秒）",
        started.elapsed().as_secs_f64()
    );
}
