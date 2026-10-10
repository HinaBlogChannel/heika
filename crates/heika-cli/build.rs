fn main() {
    // 標準入力から秘密鍵を読むとき、Unix 以外では std のバッファを通すので、鍵がメモリに残る
    if std::env::var_os("CARGO_CFG_UNIX").is_none() {
        println!(
            "cargo::warning=Unix 以外では、標準入力から読んだ秘密鍵が std のバッファに残ります"
        );
    }
}
