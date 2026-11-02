//! DB を持つ Web Worker。Web Locks でオリジンに1つだけにしてから、OPFS の上の redb を開く。
//!
//! 画面には次のものを配列で送る。
//! - `["waiting"]`: ほかのタブの Worker が DB を持っている。そのタブが閉じるまで待つ
//! - `["opened", 開いた回数, 開くのにかかったミリ秒, ブロックの高さ, ファイルのバイト数]`
//! - `["bench", 書いたブロックの数, 書くミリ秒, 読むミリ秒, ブロックの高さ, ファイルのバイト数]`
//! - `["error", 理由]`
//!
//! 画面から `"bench"` が届いたら、ブロックの代わりのバイト列を書いて読み、かかった時間を返す。

use std::rc::Rc;

use heika_store_redb::Db;
use js_sys::Array;
use node_web::{OpfsFile, hold_lock};
use wasm_bindgen::prelude::*;
use web_sys::{DedicatedWorkerGlobalScope, MessageEvent};

/// DB を持つ Worker を1つにするロックの名前
const LOCK: &str = "heika-node-web/db";
/// OPFS の中のファイルの名前
const FILE: &str = "heika.redb";
/// redb のキャッシュの上限
const CACHE_SIZE: usize = 64 << 20;
/// 開いた回数を数える meta のキー。開き直して増えていれば、OPFS に残っている
const OPENED: &str = "node-web/opened";
/// 1回の計測で書くブロックの数と大きさ。メインネットのブロックはほとんどが数百バイトから数 KiB
const BENCH_BLOCKS: u64 = 1000;
const BLOCK_SIZE: usize = 4096;

fn main() {
    let scope: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(error) = run(scope.clone()).await {
            post(&scope, &["error".into(), error.into()]);
        }
    });
}

fn post(scope: &DedicatedWorkerGlobalScope, parts: &[JsValue]) {
    let _ = scope.post_message(&parts.iter().collect::<Array>());
}

fn now(scope: &DedicatedWorkerGlobalScope) -> f64 {
    scope
        .performance()
        .map_or(0.0, |performance| performance.now())
}

async fn run(scope: DedicatedWorkerGlobalScope) -> Result<(), String> {
    let js = |error: JsValue| format!("{error:?}");
    hold_lock(LOCK, || post(&scope, &["waiting".into()]))
        .await
        .map_err(js)?;
    let file = OpfsFile::open(FILE).await.map_err(js)?;

    let started = now(&scope);
    let db = Db::open_with_backend(file.clone(), CACHE_SIZE).map_err(|error| error.to_string())?;
    let open_ms = now(&scope) - started;
    let opened = count_opening(&db).map_err(|error| error.to_string())?;
    post(
        &scope,
        &[
            "opened".into(),
            (opened as f64).into(),
            open_ms.into(),
            (db.blocks_tip().map_err(|error| error.to_string())? as f64).into(),
            (file.size().map_err(|error| error.to_string())? as f64).into(),
        ],
    );

    let db = Rc::new(db);
    let poster = scope.clone();
    let onmessage = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        if event.data().as_string().as_deref() != Some("bench") {
            return;
        }
        let message = match bench(&poster, &db, &file) {
            Ok(parts) => parts,
            Err(error) => vec!["error".into(), error.into()],
        };
        post(&poster, &message);
    });
    scope.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));
    // Worker が終わるまで DB を持ち続けるので、放さない
    onmessage.forget();
    Ok(())
}

/// meta の数を1つ増やして書き、増やしたあとの数を返す
fn count_opening(db: &Db) -> Result<u64, heika_store_redb::DbError> {
    let opened = db
        .meta(OPENED)?
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u64::from_le_bytes)
        + 1;
    let mut batch = db.batch()?;
    batch.put_meta(OPENED, &opened.to_le_bytes())?;
    batch.commit()?;
    Ok(opened)
}

/// 今の先端の上に [`BENCH_BLOCKS`] 個を1回のコミットで書き、全部を読み戻す
fn bench(
    scope: &DedicatedWorkerGlobalScope,
    db: &Db,
    file: &OpfsFile,
) -> Result<Vec<JsValue>, String> {
    let error = |error: heika_store_redb::DbError| error.to_string();
    let tip = db.blocks_tip().map_err(error)?;
    let heights = tip + 1..=tip + BENCH_BLOCKS;
    let block = |height: u64| vec![height as u8; BLOCK_SIZE];

    let started = now(scope);
    let mut batch = db.batch().map_err(error)?;
    for height in heights.clone() {
        batch.put_block(height, &block(height)).map_err(error)?;
    }
    batch.commit().map_err(error)?;
    let write_ms = now(scope) - started;

    let started = now(scope);
    for height in heights {
        if db.block(height).map_err(error)? != Some(block(height)) {
            return Err(format!("高さ {height} のブロックが、書いたものと違います"));
        }
    }
    let read_ms = now(scope) - started;

    Ok(vec![
        "bench".into(),
        (BENCH_BLOCKS as f64).into(),
        write_ms.into(),
        read_ms.into(),
        (db.blocks_tip().map_err(error)? as f64).into(),
        (file.size().map_err(|error| error.to_string())? as f64).into(),
    ])
}
