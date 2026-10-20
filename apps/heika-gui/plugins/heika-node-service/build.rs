// 画面から呼ぶコマンドはない。アプリの本体（Rust）から、Android のサービスを始めて、通知を変えて、止めるだけ
fn main() {
    tauri_plugin::Builder::new(&[])
        .android_path("android")
        .build();
}
