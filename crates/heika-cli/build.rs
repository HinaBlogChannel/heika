fn main() {
    // Unix 以外では、標準入力から読む秘密鍵は std のバッファを通るのでメモリに残り、
    // 書き出す秘密鍵のファイルは自分だけが読めるようにできない
    if std::env::var_os("CARGO_CFG_UNIX").is_none() {
        println!(
            "cargo::warning=Unix 以外では、標準入力から読んだ秘密鍵が std のバッファに残り、書き出す秘密鍵のファイルも権限が絞られません"
        );
    }
}
