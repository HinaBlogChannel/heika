//! age 形式のファイルの暗号化と復号のうち、パスフレーズ（scrypt）で鍵を包むもの。
//! 仕様は <https://age-encryption.org/v1> と C2SP の age.md。
//!
//! キーストアをこの形式で書くと、heika がなくても `age -d` で開ける。公開鍵あての暗号化や ASCII armor は使わないので持たない。
//!
//! ```text
//! age-encryption.org/v1
//! -> scrypt <ソルト（16バイト）の Base64> <計算量の log2>
//! <ファイル鍵を包んだもの（32バイト）の Base64>
//! --- <ヘッダーの HMAC-SHA256 の Base64>
//! <ノンス 16バイト><本文を 64KiB ごとに ChaCha20-Poly1305 で暗号化したもの>
//! ```

use std::fmt;

use base64ct::{Base64Unpadded, Encoding};
use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::cipher::hmac_sha256;

const VERSION_LINE: &[u8] = b"age-encryption.org/v1\n";
/// scrypt のソルトの前に付けるラベル
const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const SCRYPT_SALT_SIZE: usize = 16;
/// ヘッダーの本文の1行の Base64 の文字数。これより短い行で本文が終わる
const LINE_LENGTH: usize = 64;
const FILE_KEY_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
/// 本文を暗号化するまとまりの、平文の長さ
const CHUNK_SIZE: usize = 64 * 1024;

/// 書くときの scrypt の計算量（2^18）。age の既定と同じで、今の PC で1秒ほどかかる
pub const DEFAULT_WORK_FACTOR: u8 = 18;
/// 読むときに受け付ける計算量の上限。age の参照実装と同じく、これより重いものは開かずに弾く
pub const MAX_WORK_FACTOR: u8 = 22;

/// パスフレーズで暗号化する。
pub fn encrypt<R: CryptoRng + ?Sized>(
    rng: &mut R,
    passphrase: &[u8],
    work_factor: u8,
    plaintext: &[u8],
) -> Vec<u8> {
    let mut file_key = Zeroizing::new([0; FILE_KEY_SIZE]);
    rng.fill_bytes(&mut *file_key);
    let mut salt = [0; SCRYPT_SALT_SIZE];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);

    let wrap_key = scrypt_key(passphrase, &salt, work_factor);
    let mut wrapped = [0; FILE_KEY_SIZE + TAG_SIZE];
    wrapped[..FILE_KEY_SIZE].copy_from_slice(&*file_key);
    let tag = ChaCha20Poly1305::new((&*wrap_key).into())
        .encrypt_inout_detached(&[0; 12].into(), &[], (&mut wrapped[..FILE_KEY_SIZE]).into())
        .expect("the file key fits in ChaCha20-Poly1305");
    wrapped[FILE_KEY_SIZE..].copy_from_slice(&tag);

    let mut out = VERSION_LINE.to_vec();
    out.extend_from_slice(
        format!(
            "-> scrypt {} {work_factor}\n{}\n---",
            Base64Unpadded::encode_string(&salt),
            Base64Unpadded::encode_string(&wrapped)
        )
        .as_bytes(),
    );
    let mac = header_mac(&file_key, &out);
    out.extend_from_slice(format!(" {}\n", Base64Unpadded::encode_string(&*mac)).as_bytes());
    out.extend_from_slice(&nonce);

    let key = payload_key(&file_key, &nonce);
    let cipher = ChaCha20Poly1305::new((&*key).into());
    // 空の平文も、空の最後のまとまりを1つ書く
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(CHUNK_SIZE).collect()
    };
    let mut buffer = Zeroizing::new(Vec::with_capacity(CHUNK_SIZE));
    for (index, chunk) in chunks.iter().enumerate() {
        buffer.clear();
        buffer.extend_from_slice(chunk);
        let tag = cipher
            .encrypt_inout_detached(
                &chunk_nonce(index as u64, index + 1 == chunks.len()).into(),
                &[],
                buffer.as_mut_slice().into(),
            )
            .expect("a chunk fits in ChaCha20-Poly1305");
        out.extend_from_slice(&buffer);
        out.extend_from_slice(&tag);
    }
    out
}

/// パスフレーズで復号する。scrypt で包んだ鍵が1つだけのファイルを読む。
pub fn decrypt(passphrase: &[u8], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, AgeError> {
    let header = Header::parse(encrypted)?;
    let file_key = unwrap_scrypt(&header, passphrase)?;
    decrypt_payload(&header, &file_key)
}

/// ファイル鍵がもうわかっているときに、ヘッダーの HMAC と本文を確かめて復号する。
/// 包んだ鍵は見ないので、ヘッダーの形と本文の照合を、公式のテストベクターで確かめるのに使う。
#[doc(hidden)]
pub fn decrypt_with_file_key(
    file_key: &[u8; FILE_KEY_SIZE],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AgeError> {
    let header = Header::parse(encrypted)?;
    decrypt_payload(&header, file_key)
}

/// 鍵を包んだもの1つ。`-> <種類> <引数>...` の行と、Base64 の本文。
struct Stanza<'a> {
    arguments: Vec<&'a [u8]>,
    body: Vec<u8>,
}

struct Header<'a> {
    stanzas: Vec<Stanza<'a>>,
    /// HMAC の対象。先頭から `---` まで
    mac_input: &'a [u8],
    mac: [u8; 32],
    /// ヘッダーのあと（ノンスから）
    payload: &'a [u8],
}

impl<'a> Header<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, AgeError> {
        let mut rest = bytes.strip_prefix(VERSION_LINE).ok_or(AgeError::Header)?;
        let mut stanzas = Vec::new();
        loop {
            let (line, after) = split_line(rest)?;
            if let Some(mac) = line.strip_prefix(b"---") {
                let mac_input = &bytes[..bytes.len() - rest.len() + 3];
                let mac = mac.strip_prefix(b" ").ok_or(AgeError::Header)?;
                let mac = decode_exact::<32>(mac)?;
                return Ok(Self {
                    stanzas,
                    mac_input,
                    mac,
                    payload: after,
                });
            }
            let arguments = line.strip_prefix(b"-> ").ok_or(AgeError::Header)?;
            let arguments: Vec<&[u8]> = arguments.split(|&byte| byte == b' ').collect();
            // どの引数も、空白と制御文字を含まない1文字以上の ASCII
            if arguments.iter().any(|argument| {
                argument.is_empty() || !argument.iter().all(|byte| (33..=126).contains(byte))
            }) {
                return Err(AgeError::Header);
            }
            rest = after;
            // 本文は 64 文字の行が続き、64 文字より短い行（空でもよい）で終わる
            let mut body = Vec::new();
            loop {
                let (line, after) = split_line(rest)?;
                rest = after;
                if line.len() > LINE_LENGTH {
                    return Err(AgeError::Header);
                }
                body.extend_from_slice(line);
                if line.len() < LINE_LENGTH {
                    break;
                }
            }
            stanzas.push(Stanza {
                arguments,
                body: decode(&body)?,
            });
        }
    }
}

/// 改行（LF）で1行を切り出す。CR は許さない。
fn split_line(bytes: &[u8]) -> Result<(&[u8], &[u8]), AgeError> {
    let end = bytes
        .iter()
        .position(|&byte| byte == b'\n')
        .ok_or(AgeError::Header)?;
    let line = &bytes[..end];
    if line.contains(&b'\r') {
        return Err(AgeError::Header);
    }
    Ok((line, &bytes[end + 1..]))
}

/// パディングのない、正規の Base64 だけを読む。書き戻して同じにならないものは弾く。
fn decode(text: &[u8]) -> Result<Vec<u8>, AgeError> {
    let text = std::str::from_utf8(text).map_err(|_| AgeError::Header)?;
    let bytes = Base64Unpadded::decode_vec(text).map_err(|_| AgeError::Header)?;
    if Base64Unpadded::encode_string(&bytes) != text {
        return Err(AgeError::Header);
    }
    Ok(bytes)
}

fn decode_exact<const N: usize>(text: &[u8]) -> Result<[u8; N], AgeError> {
    decode(text)?.try_into().map_err(|_| AgeError::Header)
}

/// scrypt で包んだ鍵を開く。scrypt はほかの包み方と一緒には使えず、1つだけでなければならない。
fn unwrap_scrypt(
    header: &Header,
    passphrase: &[u8],
) -> Result<Zeroizing<[u8; FILE_KEY_SIZE]>, AgeError> {
    let is_scrypt = |stanza: &&Stanza| stanza.arguments[0] == b"scrypt";
    let Some(stanza) = header.stanzas.iter().find(is_scrypt) else {
        return Err(AgeError::NoMatch);
    };
    if header.stanzas.len() != 1 {
        return Err(AgeError::Header);
    }
    let [_, salt, work_factor] = stanza.arguments[..] else {
        return Err(AgeError::Header);
    };
    let salt = decode_exact::<SCRYPT_SALT_SIZE>(salt)?;
    let work_factor = parse_work_factor(work_factor)?;
    if stanza.body.len() != FILE_KEY_SIZE + TAG_SIZE {
        return Err(AgeError::Header);
    }

    let wrap_key = scrypt_key(passphrase, &salt, work_factor);
    let mut file_key = Zeroizing::new([0; FILE_KEY_SIZE]);
    file_key.copy_from_slice(&stanza.body[..FILE_KEY_SIZE]);
    ChaCha20Poly1305::new((&*wrap_key).into())
        .decrypt_inout_detached(
            &[0; 12].into(),
            &[],
            (&mut file_key[..]).into(),
            stanza.body[FILE_KEY_SIZE..]
                .try_into()
                .expect("checked the body size"),
        )
        .map_err(|_| AgeError::NoMatch)?;
    Ok(file_key)
}

/// 計算量は、先頭に 0 のない10進の 1 から [`MAX_WORK_FACTOR`] まで。
fn parse_work_factor(text: &[u8]) -> Result<u8, AgeError> {
    if text.first() == Some(&b'0') || !text.iter().all(u8::is_ascii_digit) {
        return Err(AgeError::Header);
    }
    std::str::from_utf8(text)
        .ok()
        .and_then(|text| text.parse::<u8>().ok())
        .filter(|work_factor| (1..=MAX_WORK_FACTOR).contains(work_factor))
        .ok_or(AgeError::Header)
}

fn scrypt_key(
    passphrase: &[u8],
    salt: &[u8; SCRYPT_SALT_SIZE],
    work_factor: u8,
) -> Zeroizing<[u8; 32]> {
    let mut labeled_salt = [0; SCRYPT_LABEL.len() + SCRYPT_SALT_SIZE];
    labeled_salt[..SCRYPT_LABEL.len()].copy_from_slice(SCRYPT_LABEL);
    labeled_salt[SCRYPT_LABEL.len()..].copy_from_slice(salt);
    let params = scrypt::Params::new(work_factor, 8, 1).expect("the work factor is checked");
    let mut key = Zeroizing::new([0; 32]);
    scrypt::scrypt(passphrase, &labeled_salt, &params, &mut *key)
        .expect("32 bytes is a valid length");
    key
}

fn decrypt_payload(
    header: &Header,
    file_key: &[u8; FILE_KEY_SIZE],
) -> Result<Zeroizing<Vec<u8>>, AgeError> {
    if *header_mac(file_key, header.mac_input) != header.mac {
        return Err(AgeError::Hmac);
    }
    let (nonce, mut payload) = header
        .payload
        .split_first_chunk::<NONCE_SIZE>()
        .ok_or(AgeError::Header)?;
    let key = payload_key(file_key, nonce);
    let cipher = ChaCha20Poly1305::new((&*key).into());

    let mut plaintext = Zeroizing::new(Vec::with_capacity(payload.len()));
    let mut index = 0u64;
    loop {
        let size = payload.len().min(CHUNK_SIZE + TAG_SIZE);
        let last = size == payload.len();
        let (chunk, rest) = payload.split_at(size);
        let (ciphertext, tag) = chunk
            .split_last_chunk::<TAG_SIZE>()
            .ok_or(AgeError::Payload)?;
        // 空のまとまりは、平文が空のときの最初で最後のものだけ
        if ciphertext.is_empty() && index != 0 {
            return Err(AgeError::Payload);
        }
        let start = plaintext.len();
        plaintext.extend_from_slice(ciphertext);
        cipher
            .decrypt_inout_detached(
                &chunk_nonce(index, last).into(),
                &[],
                (&mut plaintext[start..]).into(),
                tag.into(),
            )
            .map_err(|_| AgeError::Payload)?;
        if last {
            return Ok(plaintext);
        }
        payload = rest;
        index += 1;
    }
}

/// ヘッダーの HMAC。鍵はファイル鍵から HKDF-SHA256 で導出する（salt は空、info は "header"）。
fn header_mac(file_key: &[u8; FILE_KEY_SIZE], header: &[u8]) -> Zeroizing<[u8; 32]> {
    let key = hkdf_sha256(&[], file_key, b"header");
    hmac_sha256(&*key, &[header])
}

/// 本文の鍵。ファイル鍵から HKDF-SHA256 で導出する（salt はノンス、info は "payload"）。
fn payload_key(file_key: &[u8; FILE_KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> Zeroizing<[u8; 32]> {
    hkdf_sha256(nonce, file_key, b"payload")
}

/// RFC 5869 の HKDF-SHA256 で、32バイトだけ取り出す。
fn hkdf_sha256(salt: &[u8], input_key: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let pseudo_random_key = hmac_sha256(salt, &[input_key]);
    hmac_sha256(&*pseudo_random_key, &[info, &[1]])
}

/// STREAM のノンス。11バイトの通し番号（ビッグエンディアン）と、最後のまとまりなら 1 の1バイト。
fn chunk_nonce(index: u64, last: bool) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// 復号できなかった理由。公式のテストベクターの `expect` と同じ分け方にする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeError {
    /// ヘッダーの形が正しくない。ノンスがないものも含む
    Header,
    /// パスフレーズで包んだ鍵がないか、パスフレーズが違う
    NoMatch,
    /// ヘッダーが書き換えられている
    Hmac,
    /// 本文が書き換えられているか、途中で切れている
    Payload,
}

impl fmt::Display for AgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Header => "age のファイルのヘッダーが正しくありません",
            Self::NoMatch => "パスフレーズが違います",
            Self::Hmac => "age のファイルのヘッダーが書き換えられています",
            Self::Payload => "age のファイルの中身が壊れているか、途中で切れています",
        })
    }
}

impl std::error::Error for AgeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Replay;

    /// ファイル鍵、ソルト、ノンスの順に使う48バイト。1 から 48 まで
    const RANDOM: [u8; 48] = {
        let mut bytes = [0; 48];
        let mut i = 0;
        while i < 48 {
            bytes[i] = i as u8 + 1;
            i += 1;
        }
        bytes
    };

    /// テストを速くするための、軽い計算量
    const LIGHT: u8 = 4;

    #[test]
    fn round_trips_short_and_long_plaintexts() {
        for size in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            3 * CHUNK_SIZE,
        ] {
            let plaintext: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let encrypted = encrypt(&mut Replay(&RANDOM), b"passphrase", LIGHT, &plaintext);
            let chunks = size.div_ceil(CHUNK_SIZE).max(1);
            let header_size = encrypted.len() - NONCE_SIZE - size - chunks * TAG_SIZE;
            assert!(encrypted[..header_size].ends_with(b"\n"), "{size}");
            assert_eq!(
                *decrypt(b"passphrase", &encrypted).unwrap(),
                plaintext,
                "{size}"
            );
        }
    }

    #[test]
    fn writes_the_age_header() {
        let encrypted = encrypt(&mut Replay(&RANDOM), b"passphrase", LIGHT, b"hello");
        let text = String::from_utf8_lossy(&encrypted);
        let lines: Vec<&str> = text.lines().take(4).collect();
        assert_eq!(lines[0], "age-encryption.org/v1");
        // ソルトは乱数の17バイト目から（最初の16バイトはファイル鍵）
        let salt: Vec<u8> = (17..=32).collect();
        assert_eq!(
            lines[1],
            format!("-> scrypt {} 4", Base64Unpadded::encode_string(&salt))
        );
        assert_eq!(lines[2].len(), 43);
        assert!(lines[3].starts_with("--- ") && lines[3].len() == 4 + 43);
    }

    #[test]
    fn rejects_a_wrong_passphrase_and_tampering() {
        let encrypted = encrypt(&mut Replay(&RANDOM), b"passphrase", LIGHT, b"hello");
        assert_eq!(decrypt(b"wrong", &encrypted), Err(AgeError::NoMatch));
        let mut payload = encrypted.clone();
        *payload.last_mut().unwrap() ^= 1;
        assert_eq!(decrypt(b"passphrase", &payload), Err(AgeError::Payload));
        let mut truncated = encrypted.clone();
        truncated.truncate(encrypted.len() - 1);
        assert_eq!(decrypt(b"passphrase", &truncated), Err(AgeError::Payload));
    }

    #[test]
    fn reads_work_factors_strictly() {
        assert_eq!(parse_work_factor(b"18"), Ok(18));
        assert_eq!(parse_work_factor(b"22"), Ok(22));
        for text in [
            &b"23"[..],
            b"0",
            b"018",
            b"+18",
            b"-1",
            b"0x12",
            b"",
            b"300",
        ] {
            assert_eq!(parse_work_factor(text), Err(AgeError::Header), "{text:?}");
        }
    }

    #[test]
    fn hkdf_matches_rfc_5869() {
        // RFC 5869 の付録 A.3（salt と info が空）の、先頭32バイト
        let ikm = [0x0B; 22];
        let expected = "8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D";
        let key = hkdf_sha256(&[], &ikm, &[]);
        let hex: String = key.iter().map(|byte| format!("{byte:02X}")).collect();
        assert_eq!(hex, expected);
    }
}
