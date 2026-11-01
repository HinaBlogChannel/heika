//! heika どうしだけで使うパケット。catapult は使わない。
//!
//! 種類の上位のビットが立った範囲（[`RANGE_START`] から）を heika のものにする。catapult の種類は
//! `0x100` 台の P2P と、それより上の API の範囲で、ここまでは届かない。
//!
//! TLS のハンドシェイクで互いに heika だとわかった接続でだけ送る（heika-tls の ALPN）。なので catapult が
//! この範囲のパケットを受け取ることはない。heika どうしでは、知らない種類が来ても切らずに読み捨てる。
//! 新しい heika が足したパケットを古い heika が受けても、つながったままにするため。

use crate::DecodeError;

/// heika のパケットの種類の始まり。これより上は heika のもの
pub const RANGE_START: u32 = 0x8000_0000;

/// できること（capability）を相手に伝える。つないだ側が、ハンドシェイクのすぐあとに1回送る。
/// 受けた側は、受け取ったら自分のものを1回返す。応答を待たずに次の要求を送ってよい
pub const PUSH_CAPABILITIES: u32 = RANGE_START;

/// 名前つきの拡張を入れる封筒。本体は、名前の長さ `u8`、名前（capability の名前と同じ決まり）、中身の順。
///
/// 拡張ごとに種類の番号を振る代わりに、名前で区切る。名前は capability と同じものを使い、相手がその
/// capability を名乗っているときだけ送る。heika のほかの実装が足すものは、SSH の拡張と同じく `名前@ドメイン`
/// にして、名前がぶつからないようにする。要求と応答は同じ名前で、1つの接続では1つずつ順に行き来する。
/// 知らない名前の要求には答えない
pub const ENVELOPE: u32 = RANGE_START + 1;

/// capability と封筒の名前: このノードのソースの ZIP を返す（AGPL-3.0 の 13 条のため）。要求の中身は空で、
/// 応答の中身が ZIP。ソースを埋め込んでいないビルドなら名乗らない
pub const SOURCE_ZIP: &str = "source/zip";

/// capability: ネメシスから自分の今の高さまで、ブロックを抜けなく持っていて、頼まれれば返す。
/// 同期中でも名乗ってよい（今の高さより上は、まだ持っていないだけ）。古いブロックを刈り込むなら名乗らない
pub const BLOCKS_ALL: &str = "blocks/all";

/// 1つのパケットに入れる capability の数の上限
pub const MAX_CAPABILITIES: usize = 64;

/// `packet_type` が heika の範囲か
pub fn is_extension(packet_type: u32) -> bool {
    packet_type >= RANGE_START
}

/// capability の名前として使えるか。1〜255 バイトの、空白と制御文字を除く ASCII
pub fn is_capability_name(name: &str) -> bool {
    (1..=255).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_graphic())
}

/// [`PUSH_CAPABILITIES`] の本体。数 `u16` のあと、名前ごとに長さ `u8` と ASCII のバイト列を並べる。
///
/// 名前が [`is_capability_name`] を満たさないか、数が [`MAX_CAPABILITIES`] を超えるなら、使う側の間違いなので panic する
pub fn capabilities_body(names: &[&str]) -> Vec<u8> {
    assert!(names.len() <= MAX_CAPABILITIES, "capability が多すぎます");
    let mut body = Vec::new();
    body.extend_from_slice(&(names.len() as u16).to_le_bytes());
    for name in names {
        assert!(
            is_capability_name(name),
            "capability の名前 {name:?} は使えません"
        );
        body.push(name.len() as u8);
        body.extend_from_slice(name.as_bytes());
    }
    body
}

/// [`PUSH_CAPABILITIES`] の本体を読む。名前に使えない文字が入っていれば、そのまま失敗にする
pub fn read_capabilities(body: &[u8]) -> Result<Vec<String>, DecodeError> {
    let truncated = |needed: usize, remaining: usize| DecodeError::Truncated { needed, remaining };
    let (count, mut rest) = body
        .split_first_chunk::<2>()
        .ok_or(truncated(2, body.len()))?;
    let count = u16::from_le_bytes(*count) as usize;
    if count > MAX_CAPABILITIES {
        return Err(DecodeError::InvalidValue("capability が多すぎます"));
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let (&length, after) = rest.split_first().ok_or(truncated(1, 0))?;
        let length = length as usize;
        if after.len() < length {
            return Err(truncated(length, after.len()));
        }
        let (name, after) = after.split_at(length);
        let name = std::str::from_utf8(name)
            .ok()
            .filter(|name| is_capability_name(name))
            .ok_or(DecodeError::InvalidValue(
                "capability の名前に使えない文字があります",
            ))?;
        names.push(name.to_owned());
        rest = after;
    }
    if !rest.is_empty() {
        return Err(DecodeError::SizeMismatch {
            declared: body.len() - rest.len(),
            actual: body.len(),
        });
    }
    Ok(names)
}

/// 名前 `name` で中身が `content` の、[`ENVELOPE`] の本体。名前が使えないなら、使う側の間違いなので panic する
pub fn envelope_body(name: &str, content: &[u8]) -> Vec<u8> {
    assert!(is_capability_name(name), "封筒の名前 {name:?} は使えません");
    let mut body = Vec::with_capacity(1 + name.len() + content.len());
    body.push(name.len() as u8);
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(content);
    body
}

/// [`ENVELOPE`] の本体を、名前と中身に分ける
pub fn read_envelope(body: &[u8]) -> Result<(&str, &[u8]), DecodeError> {
    let (&length, rest) = body.split_first().ok_or(DecodeError::Truncated {
        needed: 1,
        remaining: 0,
    })?;
    let length = length as usize;
    if rest.len() < length {
        return Err(DecodeError::Truncated {
            needed: length,
            remaining: rest.len(),
        });
    }
    let (name, content) = rest.split_at(length);
    let name = std::str::from_utf8(name)
        .ok()
        .filter(|name| is_capability_name(name))
        .ok_or(DecodeError::InvalidValue(
            "封筒の名前に使えない文字があります",
        ))?;
    Ok((name, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_capabilities() {
        assert_eq!(capabilities_body(&[]), [0, 0]);
        assert_eq!(read_capabilities(&[0, 0]).unwrap(), Vec::<String>::new());
        let body = capabilities_body(&["source-zip", "block-compression/zstd"]);
        assert_eq!(&body[..3], [2, 0, 10]);
        assert_eq!(
            read_capabilities(&body).unwrap(),
            ["source-zip", "block-compression/zstd"]
        );
    }

    #[test]
    fn rejects_malformed_capabilities() {
        assert!(read_capabilities(&[]).is_err());
        assert!(read_capabilities(&[1, 0]).is_err());
        assert!(read_capabilities(&[1, 0, 3, b'a', b'b']).is_err());
        assert!(read_capabilities(&[1, 0, 2, b'a', b' ']).is_err());
        assert!(read_capabilities(&[1, 0, 0]).is_err());
        assert!(read_capabilities(&[0, 0, 0]).is_err());
        assert!(read_capabilities(&[65, 0]).is_err());
    }

    #[test]
    fn round_trips_envelopes() {
        let body = envelope_body(SOURCE_ZIP, b"PK");
        assert_eq!(body, [&[10][..], b"source/zip", b"PK"].concat());
        assert_eq!(read_envelope(&body).unwrap(), (SOURCE_ZIP, &b"PK"[..]));
        assert_eq!(read_envelope(&[1, b'a']).unwrap(), ("a", &[][..]));
        assert!(read_envelope(&[]).is_err());
        assert!(read_envelope(&[0]).is_err());
        assert!(read_envelope(&[3, b'a']).is_err());
        assert!(read_envelope(&[1, b' ']).is_err());
    }

    #[test]
    fn reserves_the_upper_range() {
        assert!(!is_extension(0x135));
        assert!(is_extension(PUSH_CAPABILITIES));
        assert!(is_extension(u32::MAX));
    }
}
