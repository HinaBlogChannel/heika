//! 16進の文字列との変換。catapult の `utils/HexParser.cpp` に合わせて、
//! 読むときは大文字も小文字も受け付け、書くときは大文字にする。

use std::fmt;

pub fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

pub fn decode<const N: usize>(text: &str) -> Result<[u8; N], ParseHexError> {
    if let Some((index, character)) = text
        .chars()
        .enumerate()
        .find(|(_, character)| !character.is_ascii_hexdigit())
    {
        return Err(ParseHexError::InvalidCharacter { index, character });
    }
    // ここから先は ASCII だけなので、バイト数と文字数は同じ
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return Err(ParseHexError::InvalidLength {
            expected: N * 2,
            actual: digits.len(),
        });
    }
    let mut bytes = [0; N];
    for (byte, [high, low]) in bytes.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = nibble(*high) << 4 | nibble(*low);
    }
    Ok(bytes)
}

fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'A'..=b'F' => digit - b'A' + 10,
        b'a'..=b'f' => digit - b'a' + 10,
        _ => unreachable!("checked by is_ascii_hexdigit"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseHexError {
    /// 文字数が、バイト数の2倍になっていない
    InvalidLength { expected: usize, actual: usize },
    /// 16進の数字ではない文字が含まれている
    InvalidCharacter { index: usize, character: char },
}

impl fmt::Display for ParseHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "16進で {expected} 文字のはずが {actual} 文字でした")
            }
            Self::InvalidCharacter { index, character } => {
                write!(
                    f,
                    "{index} 文字目の {character:?} は16進の数字ではありません"
                )
            }
        }
    }
}

impl std::error::Error for ParseHexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_in_upper_case() {
        assert_eq!(encode(&[0x00, 0xAB, 0x0F]), "00AB0F");
    }

    #[test]
    fn decodes_both_cases() {
        assert_eq!(decode::<2>("aBcD"), Ok([0xAB, 0xCD]));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            decode::<2>("ABC"),
            Err(ParseHexError::InvalidLength {
                expected: 4,
                actual: 3
            })
        );
    }

    #[test]
    fn rejects_non_hex_characters() {
        assert_eq!(
            decode::<2>("ABCG"),
            Err(ParseHexError::InvalidCharacter {
                index: 3,
                character: 'G'
            })
        );
    }

    #[test]
    fn reports_multibyte_characters_without_panicking() {
        // 「あ」は3バイトなので全体で4バイトになるが、位置は文字で数える
        assert_eq!(
            decode::<2>("Aあ"),
            Err(ParseHexError::InvalidCharacter {
                index: 1,
                character: 'あ'
            })
        );
    }
}
