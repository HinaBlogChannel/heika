//! 動かしたまま入れ替えられる、メモリだけで渡すハーベストの鍵。ディスクに鍵を置かずにハーベストするためのもの。
//!
//! 設定ファイルの `harvesters` の鍵に足して使う。入れ替えは、先端の段階で次の `Tick`（5 秒ごと）に効く。
//!
//! 別のプロセスから渡すときは、[`read_input`] で標準入力などの行を読む。
//!
//! ```text
//! harvesters <署名の鍵の16進> <VRF の鍵の16進> <署名の鍵の16進> <VRF の鍵の16進> …
//! ```
//!
//! 1行で全部を入れ替え、組がなければ（`harvesters` だけなら）メモリの鍵ではハーベストしない。

use std::io::{BufRead, Read};
use std::sync::{Arc, Mutex};

use heika_core::key::PrivateKey;
use zeroize::Zeroizing;

/// ハーベストする鍵の組（署名の鍵、VRF の鍵）。リモートでハーベストするなら、署名の鍵はリモートの鍵
pub type KeyPair = (PrivateKey, PrivateKey);

/// 1行の長さの上限。鍵の組で 129 バイトなので、30 組まで入る
const MAX_LINE: u64 = 4096;

/// メモリだけで渡すハーベストの鍵と、入れ替えた回数
#[derive(Default)]
pub struct MemoryHarvesters(Mutex<(u64, Arc<Vec<KeyPair>>)>);

impl MemoryHarvesters {
    pub fn new() -> Self {
        Self::default()
    }

    /// 鍵を入れ替える。空にすると、メモリの鍵ではハーベストしない
    pub fn replace(&self, keys: Vec<KeyPair>) {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = (slot.0 + 1, Arc::new(keys));
    }

    /// 入れ替えた回数と、今の鍵
    pub(crate) fn current(&self) -> (u64, Arc<Vec<KeyPair>>) {
        let slot = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (slot.0, Arc::clone(&slot.1))
    }
}

/// `input` を読めなくなる（EOF）まで行で読み、`harvesters` の行で鍵を入れ替える。読めない行は、中身を出さずに
/// 警告して読み飛ばす
pub fn read_input(mut input: impl BufRead, harvesters: &MemoryHarvesters) {
    loop {
        // 鍵が入るので、引っ越さないように先に確保し、上限より長い行は読まない
        let mut line = Zeroizing::new(Vec::with_capacity(MAX_LINE as usize));
        match Read::take(&mut input, MAX_LINE).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.last() != Some(&b'\n') {
            eprintln!("警告: 長すぎる行を読み飛ばしました");
            // 行の残りを捨てる
            loop {
                line.clear();
                match Read::take(&mut input, MAX_LINE).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => return,
                    Ok(_) if line.last() == Some(&b'\n') => break,
                    Ok(_) => {}
                }
            }
            continue;
        }
        match parse_line(&line) {
            Ok(keys) => {
                println!("メモリで渡された {} 組の鍵に入れ替えます", keys.len());
                harvesters.replace(keys);
            }
            Err(error) => eprintln!("警告: {error}"),
        }
    }
}

/// `harvesters` の行を読む。読めなければ、中身を出さないわけを返す
fn parse_line(line: &[u8]) -> Result<Vec<KeyPair>, &'static str> {
    let line = std::str::from_utf8(line).map_err(|_| "UTF-8 でない行を読み飛ばしました")?;
    let mut words = line.split_ascii_whitespace();
    if words.next() != Some("harvesters") {
        return Err("知らない行を読み飛ばしました");
    }
    let keys = words
        .map(|word| word.parse::<PrivateKey>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "harvesters の行に、秘密鍵の16進として読めないものがあります")?;
    if keys.len() % 2 != 0 {
        return Err("harvesters の行の鍵が、署名の鍵と VRF の鍵の組になっていません");
    }
    let mut keys = keys.into_iter();
    let mut pairs = Vec::new();
    while let (Some(signing), Some(vrf)) = (keys.next(), keys.next()) {
        pairs.push((signing, vrf));
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(byte: u8) -> String {
        format!("{byte:02X}").repeat(32)
    }

    fn bytes(keys: &[KeyPair]) -> Vec<(u8, u8)> {
        keys.iter()
            .map(|(signing, vrf)| (signing.as_bytes()[0], vrf.as_bytes()[0]))
            .collect()
    }

    #[test]
    fn replaces_keys_line_by_line() {
        let input = format!(
            "harvesters {} {} {} {}\nunknown\nharvesters {}\n{}\nharvesters\n",
            hex(1),
            hex(2),
            hex(3),
            hex(4),
            hex(5),
            "x".repeat(5000),
        );
        let harvesters = MemoryHarvesters::new();
        assert_eq!(harvesters.current().0, 0);

        let mut lines = input.split_inclusive('\n');
        read_input(lines.next().unwrap().as_bytes(), &harvesters);
        let (version, keys) = harvesters.current();
        assert_eq!((version, bytes(&keys)), (1, vec![(1, 2), (3, 4)]));

        // 知らない行、組にならない行、長すぎる行は読み飛ばし、そのあとの行は読む
        read_input(lines.collect::<String>().as_bytes(), &harvesters);
        let (version, keys) = harvesters.current();
        assert_eq!((version, keys.len()), (2, 0));
    }

    #[test]
    fn rejects_lines_without_keys() {
        assert!(parse_line(b"harvesters zz\n").is_err());
        assert!(parse_line(&[0xFF, b'\n']).is_err());
        assert!(parse_line(b"harvesters\n").unwrap().is_empty());
    }
}
