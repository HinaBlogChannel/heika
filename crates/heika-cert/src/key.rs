//! Ed25519 の鍵の DER と PEM。OpenSSL が書き出すのと同じ RFC 8410 の形だけを扱う。
//!
//! 秘密鍵は PKCS#8 の v1（公開鍵を含まない48バイト）、公開鍵は SubjectPublicKeyInfo（44バイト）。
//! どちらも決まった前置きに32バイトの鍵が続くだけなので、ASN.1 は解釈せずに前置きと長さを比べる。
//!
//! Base64 との変換は定数時間で行う。PEM は末尾に改行を付けずに書き、読むときは前後の空白を無視する。

use std::fmt;

use base64ct::{Base64, Encoding};
use heika_core::key::{PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING (32バイト) } }`
const PRIVATE_KEY_PREFIX: [u8; 16] = [
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (32バイト) }`
const PUBLIC_KEY_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub const PRIVATE_KEY_DER_LENGTH: usize = PRIVATE_KEY_PREFIX.len() + 32;
pub const PUBLIC_KEY_DER_LENGTH: usize = PUBLIC_KEY_PREFIX.len() + 32;

const PRIVATE_KEY_LABEL: &str = "PRIVATE KEY";
const PUBLIC_KEY_LABEL: &str = "PUBLIC KEY";

/// Base64 にした長さ。どちらの鍵も PEM の1行（64文字）に収まる
const PRIVATE_KEY_BASE64_LENGTH: usize = PRIVATE_KEY_DER_LENGTH.div_ceil(3) * 4;
const PUBLIC_KEY_BASE64_LENGTH: usize = PUBLIC_KEY_DER_LENGTH.div_ceil(3) * 4;

pub fn private_key_to_der(key: &PrivateKey) -> Zeroizing<[u8; PRIVATE_KEY_DER_LENGTH]> {
    let mut der = Zeroizing::new([0; PRIVATE_KEY_DER_LENGTH]);
    der[..PRIVATE_KEY_PREFIX.len()].copy_from_slice(&PRIVATE_KEY_PREFIX);
    der[PRIVATE_KEY_PREFIX.len()..].copy_from_slice(key.as_bytes());
    der
}

pub fn private_key_from_der(der: &[u8]) -> Result<PrivateKey, ParseKeyError> {
    match der.split_first_chunk::<{ PRIVATE_KEY_PREFIX.len() }>() {
        Some((prefix, key)) if *prefix == PRIVATE_KEY_PREFIX => key
            .try_into()
            .map(PrivateKey::from_bytes)
            .map_err(|_| ParseKeyError::UnsupportedFormat),
        _ => Err(ParseKeyError::UnsupportedFormat),
    }
}

pub fn private_key_to_pem(key: &PrivateKey) -> Zeroizing<String> {
    let der = private_key_to_der(key);
    let mut base64 = Zeroizing::new([0; PRIVATE_KEY_BASE64_LENGTH]);
    let base64 = Base64::encode(&*der, &mut *base64).expect("the buffer fits the Base64");
    // String を伸ばすと古い領域が残るので、固定長のバッファで組み立ててから String にする
    let mut buffer = Zeroizing::new([0; pem_length(PRIVATE_KEY_LABEL, PRIVATE_KEY_BASE64_LENGTH)]);
    Zeroizing::new(write_pem(PRIVATE_KEY_LABEL, base64, &mut *buffer).to_owned())
}

pub fn private_key_from_pem(pem: &str) -> Result<PrivateKey, ParseKeyError> {
    let mut base64 = Zeroizing::new([0; PRIVATE_KEY_BASE64_LENGTH]);
    let mut der = Zeroizing::new([0; PRIVATE_KEY_DER_LENGTH]);
    private_key_from_der(read_pem(pem, PRIVATE_KEY_LABEL, &mut *base64, &mut *der)?)
}

pub fn public_key_to_der(key: &PublicKey) -> [u8; PUBLIC_KEY_DER_LENGTH] {
    let mut der = [0; PUBLIC_KEY_DER_LENGTH];
    der[..PUBLIC_KEY_PREFIX.len()].copy_from_slice(&PUBLIC_KEY_PREFIX);
    der[PUBLIC_KEY_PREFIX.len()..].copy_from_slice(&key.0);
    der
}

pub fn public_key_from_der(der: &[u8]) -> Result<PublicKey, ParseKeyError> {
    match der.split_first_chunk::<{ PUBLIC_KEY_PREFIX.len() }>() {
        Some((prefix, key)) if *prefix == PUBLIC_KEY_PREFIX => key
            .try_into()
            .map(PublicKey)
            .map_err(|_| ParseKeyError::UnsupportedFormat),
        _ => Err(ParseKeyError::UnsupportedFormat),
    }
}

pub fn public_key_to_pem(key: &PublicKey) -> String {
    let mut base64 = [0; PUBLIC_KEY_BASE64_LENGTH];
    let base64 =
        Base64::encode(&public_key_to_der(key), &mut base64).expect("the buffer fits the Base64");
    let mut buffer = [0; pem_length(PUBLIC_KEY_LABEL, PUBLIC_KEY_BASE64_LENGTH)];
    write_pem(PUBLIC_KEY_LABEL, base64, &mut buffer).to_owned()
}

pub fn public_key_from_pem(pem: &str) -> Result<PublicKey, ParseKeyError> {
    let mut base64 = [0; PUBLIC_KEY_BASE64_LENGTH];
    let mut der = [0; PUBLIC_KEY_DER_LENGTH];
    public_key_from_der(read_pem(pem, PUBLIC_KEY_LABEL, &mut base64, &mut der)?)
}

const fn pem_length(label: &str, base64_length: usize) -> usize {
    let boundary = "-----BEGIN -----".len() + label.len();
    boundary + 1 + base64_length + 1 + boundary - "BEGIN".len() + "END".len()
}

/// 本体が1行に収まる PEM を `buffer` に書く。
fn write_pem<'b>(label: &str, base64: &str, buffer: &'b mut [u8]) -> &'b str {
    let mut length = 0;
    for part in [
        "-----BEGIN ",
        label,
        "-----\n",
        base64,
        "\n-----END ",
        label,
        "-----",
    ] {
        buffer[length..length + part.len()].copy_from_slice(part.as_bytes());
        length += part.len();
    }
    str::from_utf8(&buffer[..length]).expect("PEM is ASCII")
}

/// PEM の枠を外し、本体を Base64 として `der` に読む。
///
/// 本体の改行は詰めてから読むので、何文字で折り返されていてもよい。
/// 詰めた本体が `base64` に、読んだ結果が `der` に収まらなければ、扱う形ではないものとする。
fn read_pem<'d>(
    pem: &str,
    label: &'static str,
    base64: &mut [u8],
    der: &'d mut [u8],
) -> Result<&'d [u8], ParseKeyError> {
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.strip_prefix(label))
        .and_then(|rest| rest.strip_prefix("-----"))
        .and_then(|rest| rest.strip_suffix("-----"))
        .and_then(|rest| rest.strip_suffix(label))
        .and_then(|rest| rest.strip_suffix("-----END "))
        .ok_or(ParseKeyError::NotPem { label })?;
    let mut length = 0;
    for &byte in body.trim().as_bytes() {
        if byte == b'\n' || byte == b'\r' {
            continue;
        }
        let slot = base64
            .get_mut(length)
            .ok_or(ParseKeyError::UnsupportedFormat)?;
        *slot = byte;
        length += 1;
    }
    Base64::decode(&base64[..length], der).map_err(|error| match error {
        base64ct::Error::InvalidLength => ParseKeyError::UnsupportedFormat,
        base64ct::Error::InvalidEncoding => ParseKeyError::InvalidBase64,
    })
}

/// 鍵が読めなかった理由。秘密鍵の一部を漏らさないように、どこの何が悪かったかは含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseKeyError {
    /// `-----BEGIN <label>-----` と `-----END <label>-----` で挟まれていない
    NotPem { label: &'static str },
    /// 本体が Base64 として読めない
    InvalidBase64,
    /// RFC 8410 の Ed25519 の鍵の形ではない
    UnsupportedFormat,
}

impl fmt::Display for ParseKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPem { label } => write!(
                f,
                "-----BEGIN {label}----- と -----END {label}----- で挟まれた PEM ではありません"
            ),
            Self::InvalidBase64 => f.write_str("PEM の本体が Base64 として読めません"),
            Self::UnsupportedFormat => f.write_str(
                "Ed25519 の鍵の形ではありません（OpenSSL が書き出す RFC 8410 の形だけを受け付けます）",
            ),
        }
    }
}

impl std::error::Error for ParseKeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8410 の 10.3 節と 10.1 節にある鍵。10.3 節の後半の例から、2つが組だとわかる
    const PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";
    const PRIVATE_HEX: &str = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";
    const PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----";
    const PUBLIC_HEX: &str = "19BF44096984CDFE8541BAC167DC3B96C85086AA30B6B6CB0C5C38AD703166E1";

    #[test]
    fn reads_the_rfc_8410_private_key() {
        let key = private_key_from_pem(PRIVATE_PEM).unwrap();
        assert_eq!(*key.to_hex(), PRIVATE_HEX);
        assert_eq!(PublicKey::from_private_key(&key).to_string(), PUBLIC_HEX);
    }

    #[test]
    fn writes_the_rfc_8410_private_key() {
        let key: PrivateKey = PRIVATE_HEX.parse().unwrap();
        assert_eq!(*private_key_to_pem(&key), PRIVATE_PEM);
    }

    #[test]
    fn reads_and_writes_the_rfc_8410_public_key() {
        let key = public_key_from_pem(PUBLIC_PEM).unwrap();
        assert_eq!(key.to_string(), PUBLIC_HEX);
        assert_eq!(public_key_to_pem(&key), PUBLIC_PEM);
    }

    #[test]
    fn round_trips_through_der() {
        let private_key: PrivateKey = PRIVATE_HEX.parse().unwrap();
        let der = private_key_to_der(&private_key);
        assert_eq!(*private_key_from_der(&*der).unwrap().to_hex(), PRIVATE_HEX);
        let public_key: PublicKey = PUBLIC_HEX.parse().unwrap();
        let der = public_key_to_der(&public_key);
        assert_eq!(public_key_from_der(&der).unwrap(), public_key);
    }

    #[test]
    fn ignores_surrounding_whitespace_and_crlf() {
        let pem = format!("\n  {}\r\n", PRIVATE_PEM.replace('\n', "\r\n"));
        assert_eq!(*private_key_from_pem(&pem).unwrap().to_hex(), PRIVATE_HEX);
    }

    #[test]
    fn reads_a_body_wrapped_at_any_width() {
        let (head, tail) = PUBLIC_PEM.split_at(PUBLIC_PEM.find("\n").unwrap() + 30);
        let pem = format!("{head}\n{tail}");
        assert_eq!(public_key_from_pem(&pem).unwrap().to_string(), PUBLIC_HEX);
    }

    #[test]
    fn rejects_the_wrong_label() {
        assert_eq!(
            private_key_from_pem(PUBLIC_PEM).unwrap_err(),
            ParseKeyError::NotPem {
                label: "PRIVATE KEY"
            }
        );
        assert_eq!(
            public_key_from_pem(PRIVATE_PEM).unwrap_err(),
            ParseKeyError::NotPem {
                label: "PUBLIC KEY"
            }
        );
    }

    #[test]
    fn rejects_a_private_key_with_the_public_key() {
        // RFC 8410 の 10.3 節の後半。PKCS#8 の v2 で、属性と公開鍵が付いている
        let pem = "-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----";
        assert_eq!(
            private_key_from_pem(pem).unwrap_err(),
            ParseKeyError::UnsupportedFormat
        );
    }

    #[test]
    fn rejects_a_key_of_another_algorithm() {
        let mut der = *private_key_to_der(&PRIVATE_HEX.parse().unwrap());
        // OID の最後を 1.3.101.110（X25519）にする
        der[11] = 0x6E;
        assert_eq!(
            private_key_from_der(&der).unwrap_err(),
            ParseKeyError::UnsupportedFormat
        );
    }

    #[test]
    fn rejects_a_short_der() {
        let der = private_key_to_der(&PRIVATE_HEX.parse().unwrap());
        assert_eq!(
            private_key_from_der(&der[..47]).unwrap_err(),
            ParseKeyError::UnsupportedFormat
        );
    }

    #[test]
    fn rejects_invalid_base64_without_revealing_it() {
        let pem = PRIVATE_PEM.replace("MC4C", "MC4!");
        let error = private_key_from_pem(&pem).unwrap_err();
        assert_eq!(error, ParseKeyError::InvalidBase64);
        assert!(!error.to_string().contains('!'));
    }
}
