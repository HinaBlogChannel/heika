//! ビルドごとに変わる印を `NODE_WEB_BUILD` に入れる。画面は Worker をこの印つきで読み、ブラウザのキャッシュに残った
//! 前の版の Worker と組み合わさらないようにする（trunk は Worker のファイル名にハッシュを付けない）

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let build = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    println!("cargo:rustc-env=NODE_WEB_BUILD={build}");
    println!("cargo:rerun-if-changed=src");
}
