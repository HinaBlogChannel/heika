//! アドレスの模様。`NAKAMOTO`、`N.SUNBORU.*`、`N.*SUNBORU` のように書く。
//!
//! - 1 文字目は `N`（メインネット）か `T`（テストネット）で、どちらのネットワークで探すかもこれで決まる
//! - `.` はどの文字でもよい。末尾の `.*` は書いても書かなくても同じ（頭が合えばよい）
//! - 途中に `.*` を 1 つ置くと、そのあとの部分は、頭より後ろのどこにあってもよい。`N.*SUNBORU` は SUNBORU を含むアドレス
//! - 文字は Base32 の `A`〜`Z` と `2`〜`7`。小文字は大文字として読む

use core::fmt;

use heika_core::address::Address;
use heika_core::network::NetworkIdentifier;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// どの文字でもよい位置
const ANY: u8 = 0xFF;

/// GPU にそのまま渡すので、`repr(C)` にする。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pattern {
    /// 頭、続いて途中の `.*` のあとの部分の、文字ごとの 5 ビットの値。どれでもよければ [`ANY`]
    values: [u8; Address::ENCODED_SIZE],
    /// 頭の長さ。`values` のここまでは、アドレスの先頭から決まった位置で比べる
    head: u8,
    /// 途中の `.*` のあとの部分の長さ。なければ 0
    body: u8,
    /// アドレスの先頭のバイト
    pub network: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternError {
    /// 1 文字目が `N` でも `T` でもない
    UnknownNetwork,
    /// 長すぎる（アドレスは 39 文字）
    TooLong,
    /// Base32 にない文字か、`.*` の形でない `*`、2 つめの途中の `.*`
    InvalidCharacter { position: usize, character: char },
    /// 途中の `.*` のあとの部分を、どこに置いても合うアドレスがない
    NoRoom,
    /// その位置には来ない文字。2 文字目は `A`〜`D` のどれかで、39 文字目は `A`、`I`、`Q`、`Y` のどれか
    Unreachable { position: usize, character: char },
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNetwork => {
                write!(
                    f,
                    "1 文字目は N（メインネット）か T（テストネット）にしてください"
                )
            }
            Self::TooLong => write!(f, "アドレスは {} 文字までです", Address::ENCODED_SIZE),
            Self::InvalidCharacter {
                position,
                character,
            } => write!(
                f,
                "{} 文字目の {character:?} は使えません（A〜Z、2〜7、. だけ）",
                position + 1
            ),
            Self::NoRoom => write!(f, ".* のあとの部分が入る場所がありません"),
            Self::Unreachable {
                position,
                character,
            } => write!(
                f,
                "{} 文字目が {character:?} のアドレスはありません",
                position + 1
            ),
        }
    }
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let text = text.strip_suffix(".*").unwrap_or(text);
        let network = match text.as_bytes().first() {
            Some(b'N' | b'n') => NetworkIdentifier::MAINNET,
            Some(b'T' | b't') => NetworkIdentifier::TESTNET,
            _ => return Err(PatternError::UnknownNetwork),
        };
        let (head_text, body_text) = text.split_once(".*").unwrap_or((text, ""));
        if head_text.chars().count() + body_text.chars().count() > Address::ENCODED_SIZE {
            return Err(PatternError::TooLong);
        }
        let mut values = [ANY; Address::ENCODED_SIZE];
        let head = head_text.chars().count();
        for (position, character) in head_text.chars().enumerate() {
            values[position] = read(character, position)?;
            if values[position] != ANY && !reachable(network.0, position, values[position]) {
                return Err(PatternError::Unreachable {
                    position,
                    character: character.to_ascii_uppercase(),
                });
            }
        }
        for (index, character) in body_text.chars().enumerate() {
            // 文字の位置は、エラーで示すときのために、書いた文字列（間の `.*` も数える）で数える
            values[head + index] = read(character, head + 2 + index)?;
        }
        let pattern = Self {
            values,
            head: head as u8,
            body: body_text.chars().count() as u8,
            network: network.0,
        };
        if pattern.probability() == 0.0 {
            return Err(PatternError::NoRoom);
        }
        Ok(pattern)
    }

    pub fn network(&self) -> NetworkIdentifier {
        NetworkIdentifier(self.network)
    }

    /// アドレスの 24 バイトが模様に合うか。Base32 の文字列にはせず、5 ビットずつ取り出して比べる。
    pub fn matches(&self, address: &[u8; Address::SIZE]) -> bool {
        let (head, body) = (self.head as usize, self.body as usize);
        if !self.matches_at(address, 0, &self.values[..head]) {
            return false;
        }
        if body == 0 {
            return true;
        }
        let body_values = &self.values[head..head + body];
        (head..=Address::ENCODED_SIZE - body)
            .any(|offset| self.matches_at(address, offset, body_values))
    }

    /// `offset` 文字目から `values` が並んでいるか
    fn matches_at(&self, address: &[u8; Address::SIZE], offset: usize, values: &[u8]) -> bool {
        values
            .iter()
            .enumerate()
            .all(|(index, &value)| value == ANY || digit(address, offset + index) == value)
    }

    /// 1 回で合う見込み。ざっと何回試せば 1 つ見つかるかの目安に使う。
    /// 途中の `.*` のあとの部分は、置ける場所ごとの見込みを足す（重なりを数えすぎるが、目安には十分）
    pub fn probability(&self) -> f64 {
        let (head, body) = (self.head as usize, self.body as usize);
        let head_probability = self.probability_at(0, &self.values[..head]);
        if body == 0 {
            return head_probability;
        }
        let body_values = &self.values[head..head + body];
        let body_probability: f64 = (head..=Address::ENCODED_SIZE - body)
            .map(|offset| self.probability_at(offset, body_values))
            .sum();
        head_probability * body_probability.min(1.0)
    }

    /// `offset` 文字目から `values` が並ぶ見込み。来ない文字があれば 0
    fn probability_at(&self, offset: usize, values: &[u8]) -> f64 {
        let mut probability = 1.0;
        for (index, &value) in values.iter().enumerate() {
            let position = offset + index;
            if value == ANY {
                continue;
            }
            if !reachable(self.network, position, value) {
                return 0.0;
            }
            probability /= (1u64 << free_bits(position)) as f64;
        }
        probability
    }
}

/// 模様の 1 文字を、5 ビットの値か [`ANY`] にする
fn read(character: char, position: usize) -> Result<u8, PatternError> {
    if character == '.' {
        return Ok(ANY);
    }
    let upper = character.to_ascii_uppercase();
    ALPHABET
        .iter()
        .position(|&letter| letter as char == upper)
        .map(|value| value as u8)
        .ok_or(PatternError::InvalidCharacter {
            position,
            character,
        })
}

/// `position` 文字目の 5 ビット。24 バイトの後ろに 0 を足して読む（catapult と同じ）。
fn digit(address: &[u8; Address::SIZE], position: usize) -> u8 {
    let bit = position * 5;
    let byte = |index: usize| address.get(index).copied().unwrap_or(0) as u16;
    let window = byte(bit / 8) << 8 | byte(bit / 8 + 1);
    (window >> (11 - bit % 8)) as u8 & 0x1F
}

/// `position` 文字目のうち、ネットワークのバイトにも、末尾の詰め物にもかからない、自由なビットの数
fn free_bits(position: usize) -> u32 {
    let begin = (position * 5).max(8);
    let end = (position * 5 + 5).min(Address::SIZE * 8);
    end.saturating_sub(begin) as u32
}

/// `position` 文字目が `value` になるアドレスがあるか。
/// 先頭のバイトはネットワークで決まり、24 バイトの後ろの詰め物は 0 なので、そこにかかる位置は来る値が限られる。
fn reachable(network: u8, position: usize, value: u8) -> bool {
    let mut fixed = [0; Address::SIZE];
    fixed[0] = network;
    let mut mask = [0; Address::SIZE];
    mask[0] = 0xFF;
    // 決まっているビットだけを比べる。詰め物の位置は digit が 0 を読むので、mask の外でも 0 と比べればよい
    let known = digit(&mask, position) | !digit_mask(position);
    (value & known & 0x1F) == (digit(&fixed, position) & known & 0x1F)
}

/// `position` 文字目のうち、24 バイトの中にあるビットを 1 にしたもの
fn digit_mask(position: usize) -> u8 {
    digit(&[0xFF; Address::SIZE], position)
}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use heika_core::key::{PrivateKey, PublicKey};

    use super::*;

    #[test]
    fn reads_network_wildcards_and_trailing_star() {
        let pattern = Pattern::parse("n.sunboru.*").unwrap();
        assert_eq!(pattern.network(), NetworkIdentifier::MAINNET);
        assert_eq!(pattern, Pattern::parse("N.SUNBORU").unwrap());
        assert_eq!(
            Pattern::parse("TA").unwrap().network(),
            NetworkIdentifier::TESTNET
        );
    }

    #[test]
    fn rejects_what_no_address_can_have() {
        assert_eq!(Pattern::parse(".A"), Err(PatternError::UnknownNetwork));
        assert_eq!(
            Pattern::parse("NSUNBORU"),
            Err(PatternError::Unreachable {
                position: 1,
                character: 'S'
            })
        );
        assert_eq!(
            Pattern::parse("NA1"),
            Err(PatternError::InvalidCharacter {
                position: 2,
                character: '1'
            })
        );
        assert_eq!(
            Pattern::parse("NA*B"),
            Err(PatternError::InvalidCharacter {
                position: 2,
                character: '*'
            })
        );
        assert_eq!(
            Pattern::parse("N.*A.*B"),
            Err(PatternError::InvalidCharacter {
                position: 5,
                character: '*'
            })
        );
        // 39 文字目にしか置けず、そこには来ない文字
        assert_eq!(
            Pattern::parse(&("N".to_string() + &".".repeat(37) + ".*B")),
            Err(PatternError::NoRoom)
        );
        assert_eq!(
            Pattern::parse(&("NA".to_string() + &"A".repeat(38))),
            Err(PatternError::TooLong)
        );
        // 39 文字目は 2 ビットしかなく、残りの 3 ビットは詰め物の 0
        let last =
            |c: char| Pattern::parse(&(".".repeat(38) + &c.to_string()).replacen('.', "N", 1));
        assert!(last('Q').is_ok());
        assert_eq!(
            last('B'),
            Err(PatternError::Unreachable {
                position: 38,
                character: 'B'
            })
        );
    }

    #[test]
    fn matches_the_same_as_the_base32_address() {
        for seed in 0..64u8 {
            let key = PrivateKey::from_bytes(&[seed; 32]);
            let address = Address::from_public_key(
                &PublicKey::from_private_key(&key),
                NetworkIdentifier::MAINNET,
            );
            let text = address.to_string();
            for length in 1..=text.len() {
                assert!(
                    Pattern::parse(&text[..length]).unwrap().matches(&address.0),
                    "{text} {length}"
                );
            }
            // 途中の `.*` のあとの部分は、どこにあっても合う
            for begin in 2..text.len() - 3 {
                let contains = "N.*".to_string() + &text[begin..begin + 4];
                assert!(
                    Pattern::parse(&contains).unwrap().matches(&address.0),
                    "{text} {contains}"
                );
            }
            // 1 文字だけ変えると合わない
            let mut other = text.clone().into_bytes();
            other[5] = if other[5] == b'A' { b'B' } else { b'A' };
            assert!(
                !Pattern::parse(core::str::from_utf8(&other).unwrap())
                    .unwrap()
                    .matches(&address.0)
            );
        }
    }

    #[test]
    fn second_character_carries_two_free_bits() {
        assert_eq!(free_bits(0), 0);
        assert_eq!(free_bits(1), 2);
        assert_eq!(free_bits(2), 5);
        assert_eq!(free_bits(38), 2);
        assert_eq!(
            Pattern::parse("NAKAMOTO").unwrap().probability(),
            1.0 / (4.0 * 32f64.powi(6))
        );
        // 2 文字目からなら 1/4 × 1/32、3 文字目から 37 文字目までの 35 か所は 1/32²。38 文字目からは、39 文字目に B が来ない
        let expected = 1.0 / 128.0 + 35.0 / 1024.0;
        assert!((Pattern::parse("N.*BB").unwrap().probability() - expected).abs() < 1e-12);
    }
}
