//! 公開ノードの一覧を埋め込む。`KUSA_NODES` に `discover` で作った JSON のパスがあればそれを、なければ空の一覧を使う。
//! 一覧はリポジトリに入れず、ビルドするたびに渡す。

use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=KUSA_NODES");
    println!("cargo:rerun-if-env-changed=KUSA_TARGET");
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("nodes.json");
    let nodes = match std::env::var("KUSA_NODES") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("KUSA_NODES の {path} が読めません: {error}"))
        }
        _ => "{}".to_owned(),
    };
    std::fs::write(out, nodes).expect("nodes.json を書けません");
}
