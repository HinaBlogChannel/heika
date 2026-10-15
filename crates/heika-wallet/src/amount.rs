//! 人が書いた量（`1.5` など）を、いちばん小さい単位の数にする。

use std::fmt;

/// 量を読めなかった
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AmountError {
    /// 数字と小数点だけの形でない
    Malformed,
    /// 小数点の下が、可分性の桁より多い
    TooManyDecimals { divisibility: u8 },
    /// u64 に収まらない
    TooLarge,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("1.5 のように、数字と小数点で書いてください"),
            Self::TooManyDecimals { divisibility } => {
                write!(f, "小数点の下は {divisibility} 桁までです")
            }
            Self::TooLarge => f.write_str("量が大きすぎます"),
        }
    }
}

impl std::error::Error for AmountError {}

/// 可分性が `divisibility` のモザイクの量 `text` を、いちばん小さい単位の数にする。
/// 符号、指数、桁の区切り、前後の空白は受け付けない
pub fn parse(text: &str, divisibility: u8) -> Result<u64, AmountError> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(fraction) || text.ends_with('.') {
        return Err(AmountError::Malformed);
    }
    let width = usize::from(divisibility);
    if fraction.len() > width {
        return Err(AmountError::TooManyDecimals { divisibility });
    }
    format!("{whole}{fraction:0<width$}")
        .parse()
        .map_err(|_| AmountError::TooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_amounts_in_the_smallest_unit() {
        assert_eq!(parse("1.5", 6), Ok(1_500_000));
        assert_eq!(parse("0.000001", 6), Ok(1));
        assert_eq!(parse("12", 6), Ok(12_000_000));
        assert_eq!(parse("0", 6), Ok(0));
        assert_eq!(parse("7", 0), Ok(7));
        for wrong in ["", ".5", "1.", "1.2.3", "-1", "1,000", " 1", "1e3"] {
            assert_eq!(parse(wrong, 6), Err(AmountError::Malformed), "{wrong}");
        }
        assert_eq!(
            parse("0.0000001", 6),
            Err(AmountError::TooManyDecimals { divisibility: 6 })
        );
        assert_eq!(
            parse("1.5", 0),
            Err(AmountError::TooManyDecimals { divisibility: 0 })
        );
        assert_eq!(
            parse("18446744073709.551616", 6),
            Err(AmountError::TooLarge)
        );
    }
}
