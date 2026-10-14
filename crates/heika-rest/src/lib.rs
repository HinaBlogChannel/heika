//! Symbol の REST（catapult-rest）が返す JSON を読み、heika の型に変えて確かめる。
//!
//! HTTP は持たない。どのクライアントで取ってきたかは問わず、受け取った JSON を serde で読み、
//! `TryFrom` で heika の型にする。REST の答えはそのまま信じず、組み直したバイト列から
//! ハッシュや署名を求め直して、REST が一緒に返した値と合うかを確かめられる。
//!
//! 型と項目の名前は、symbol/symbol の `openapi/spec` に合わせる。

use std::fmt;

pub mod block;
pub mod merkle;
pub mod state;
pub mod statement;
pub mod transaction;

/// REST の JSON を heika の型にできなかった。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestError {
    /// 16進の文字列として読めないか、長さが違う
    InvalidHex { field: &'static str },
    /// 10進の数として読めないか、範囲を超えている
    InvalidNumber { field: &'static str },
    /// 決まった値のどれでもない
    InvalidValue { field: &'static str },
    /// 要る項目がない
    Missing { field: &'static str },
    /// 組み直したバイト列を、ブロックとして読めない
    InvalidBlock(heika_block::BlockDecodeError),
    /// 組み直したバイト列を、トランザクションとして読めない
    InvalidTransaction(heika_transaction::DecodeError),
    /// 状態の経路が根からつながらない
    InvalidProof(heika_core::patricia::PatriciaProofError),
    /// 状態の木のノードを読めない
    InvalidTreeNodes(heika_core::patricia::TreeNodeDecodeError),
    /// 組み直したものから求めた値が、REST が一緒に返した値と合わない
    Mismatch { field: &'static str },
}

impl fmt::Display for RestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex { field } => write!(f, "{field} を16進として読めません"),
            Self::InvalidNumber { field } => write!(f, "{field} を数として読めません"),
            Self::InvalidValue { field } => write!(f, "{field} の値を知りません"),
            Self::Missing { field } => write!(f, "{field} がありません"),
            Self::InvalidBlock(error) => write!(f, "ブロックとして読めません: {error}"),
            Self::InvalidTransaction(error) => {
                write!(f, "トランザクションとして読めません: {error}")
            }
            Self::InvalidProof(error) => write!(f, "状態の経路を確かめられません: {error}"),
            Self::InvalidTreeNodes(error) => write!(f, "状態の木のノードを読めません: {error}"),
            Self::Mismatch { field } => write!(
                f,
                "組み直したものから求めた値が、REST の {field} と合いません"
            ),
        }
    }
}

impl std::error::Error for RestError {}

/// バイト列を、REST と同じ大文字の16進にする。
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// 決まった長さの16進の文字列を読む。REST は大文字で返すが、小文字も受け付ける。
fn hex_array<const N: usize>(text: &str, field: &'static str) -> Result<[u8; N], RestError> {
    hex_vec(text, field)?
        .try_into()
        .map_err(|_| RestError::InvalidHex { field })
}

fn hex_vec(text: &str, field: &'static str) -> Result<Vec<u8>, RestError> {
    let error = || RestError::InvalidHex { field };
    if !text.len().is_multiple_of(2) {
        return Err(error());
    }
    let digit = |byte: u8| (byte as char).to_digit(16).map(|value| value as u8);
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect::<Option<_>>()
        .ok_or_else(error)
}

/// REST が u64 を10進の文字列で返すものを読む。
fn number(text: &str, field: &'static str) -> Result<u64, RestError> {
    // 符号や空白は受け付けない
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RestError::InvalidNumber { field });
    }
    text.parse().map_err(|_| RestError::InvalidNumber { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hex_in_either_case() {
        assert_eq!(hex_array::<2>("0aFf", "x"), Ok([0x0A, 0xFF]));
        assert_eq!(
            hex_array::<2>("0aF", "x"),
            Err(RestError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_array::<2>("0aFf00", "x"),
            Err(RestError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_array::<1>("0g", "x"),
            Err(RestError::InvalidHex { field: "x" })
        );
    }

    #[test]
    fn reads_u64_from_decimal_strings() {
        assert_eq!(number("18446744073709551615", "x"), Ok(u64::MAX));
        for text in ["", "-1", "+1", " 1", "18446744073709551616", "0x10"] {
            assert_eq!(
                number(text, "x"),
                Err(RestError::InvalidNumber { field: "x" }),
                "{text:?}"
            );
        }
    }
}
