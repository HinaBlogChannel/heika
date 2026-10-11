//! BIP 39 のニーモニック。
//!
//! 単語と番号の変換は、どの単語かが処理時間から漏れないように、毎回2048語すべてを見る。

use std::fmt;
use std::str::FromStr;

use rand_core::CryptoRng;
use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// 英語の単語リスト。アルファベット順に並んでいて、番号が単語の11ビットの値になる。
pub static ENGLISH: [&str; 2048] = split_lines(include_str!("bip39/english.txt"));

/// 改行で終わる行を2048個に分ける。数が合わなければコンパイルで止まる。
const fn split_lines(text: &str) -> [&str; 2048] {
    let mut words = [""; 2048];
    let mut rest = text;
    let mut index = 0;
    while index < words.len() {
        let mut length = 0;
        while rest.as_bytes()[length] != b'\n' {
            length += 1;
        }
        let (word, tail) = rest.split_at(length);
        words[index] = word;
        rest = tail.split_at(1).1;
        index += 1;
    }
    assert!(rest.is_empty(), "the word list has more than 2048 lines");
    words
}

/// 単語リストでいちばん長い単語の文字数。
const MAX_WORD_LENGTH: usize = 8;
const MAX_WORD_COUNT: usize = 24;
const MAX_ENTROPY_LENGTH: usize = 32;
/// 単語のあいだに半角スペースを入れた文の最大のバイト数。
const MAX_PHRASE_LENGTH: usize = MAX_WORD_COUNT * (MAX_WORD_LENGTH + 1) - 1;
const MAX_PASSPHRASE_LENGTH: usize = 256;
/// PBKDF2 のソルトはパスフレーズの前にこれを付けたもの。
const SALT_PREFIX: &[u8] = b"mnemonic";

/// BIP 39 のニーモニック。もとになるエントロピー（16〜32バイト）を持ち、使い終わるとメモリを0で上書きする。
/// 中身が表示されないように、`Display` は持たない。
pub struct Mnemonic {
    entropy: Zeroizing<[u8; MAX_ENTROPY_LENGTH]>,
    length: usize,
}

impl Mnemonic {
    /// 渡された暗号用の乱数で作る。
    pub fn generate_with_rng<R: CryptoRng + ?Sized>(rng: &mut R, word_count: WordCount) -> Self {
        let mut entropy = Zeroizing::new([0; MAX_ENTROPY_LENGTH]);
        let length = word_count.entropy_length();
        rng.fill_bytes(&mut entropy[..length]);
        Self::from_entropy(&entropy[..length]).expect("the word count fixes the length")
    }

    /// OS の乱数で作る。
    #[cfg(feature = "getrandom")]
    pub fn generate(word_count: WordCount) -> Result<Self, getrandom::Error> {
        let mut entropy = Zeroizing::new([0; MAX_ENTROPY_LENGTH]);
        let length = word_count.entropy_length();
        getrandom::fill(&mut entropy[..length])?;
        Ok(Self::from_entropy(&entropy[..length]).expect("the word count fixes the length"))
    }

    /// エントロピーから作る。長さは16、20、24、28、32バイトのどれか。
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, InvalidEntropyLength> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(InvalidEntropyLength);
        }
        let mut bytes = Zeroizing::new([0; MAX_ENTROPY_LENGTH]);
        bytes[..entropy.len()].copy_from_slice(entropy);
        Ok(Self {
            entropy: bytes,
            length: entropy.len(),
        })
    }

    /// もとになるエントロピー。
    pub fn entropy(&self) -> &[u8] {
        &self.entropy[..self.length]
    }

    /// 単語の数。12、15、18、21、24のどれか。
    pub fn word_count(&self) -> usize {
        self.length * 3 / 4
    }

    /// 単語を半角スペースでつないだ文。表示するつもりで呼ぶときだけ使う。
    pub fn to_phrase(&self) -> Zeroizing<String> {
        let mut buffer = Zeroizing::new([0; MAX_PHRASE_LENGTH]);
        let length = self.write_phrase(&mut buffer);
        Zeroizing::new(
            str::from_utf8(&buffer[..length])
                .expect("the word list is ASCII")
                .to_owned(),
        )
    }

    /// BIP 39 のシードにする。PBKDF2-HMAC-SHA512 を2048回まわす。
    ///
    /// パスフレーズは BIP 39 では NFKD で正規化してから使うが、正規化は実装していないので、
    /// 正規化しても変わらない ASCII だけを受け付ける。
    pub fn to_seed(&self, passphrase: &str) -> Result<Seed, InvalidPassphrase> {
        if !passphrase.is_ascii() {
            return Err(InvalidPassphrase::NonAscii);
        }
        if passphrase.len() > MAX_PASSPHRASE_LENGTH {
            return Err(InvalidPassphrase::TooLong);
        }
        let mut password = Zeroizing::new([0; MAX_PHRASE_LENGTH]);
        let password_length = self.write_phrase(&mut password);
        let mut salt = Zeroizing::new([0; SALT_PREFIX.len() + MAX_PASSPHRASE_LENGTH]);
        let salt_length = SALT_PREFIX.len() + passphrase.len();
        salt[..SALT_PREFIX.len()].copy_from_slice(SALT_PREFIX);
        salt[SALT_PREFIX.len()..salt_length].copy_from_slice(passphrase.as_bytes());
        let mut seed = Zeroizing::new([0; 64]);
        pbkdf2::pbkdf2_hmac::<Sha512>(
            &password[..password_length],
            &salt[..salt_length],
            2048,
            &mut *seed,
        );
        Ok(Seed(seed))
    }

    /// 単語を半角スペースでつないで書き、書いたバイト数を返す。
    fn write_phrase(&self, buffer: &mut [u8; MAX_PHRASE_LENGTH]) -> usize {
        let mut cursor = 0;
        for (position, &index) in self
            .word_indices()
            .iter()
            .take(self.word_count())
            .enumerate()
        {
            if position > 0 {
                buffer[cursor] = b' ';
                cursor += 1;
            }
            let word = Zeroizing::new(word_at(index).to_le_bytes());
            let length = word_length(&word);
            buffer[cursor..cursor + length].copy_from_slice(&word[..length]);
            cursor += length;
        }
        cursor
    }

    /// エントロピーにチェックサムを続けたビット列を、11ビットずつ単語の番号にする。
    fn word_indices(&self) -> Zeroizing<[u16; MAX_WORD_COUNT]> {
        let mut bits = Zeroizing::new([0; MAX_ENTROPY_LENGTH + 3]);
        bits[..self.length].copy_from_slice(self.entropy());
        bits[self.length] = checksum(self.entropy());
        let mut indices = Zeroizing::new([0; MAX_WORD_COUNT]);
        for (position, index) in indices.iter_mut().take(self.word_count()).enumerate() {
            let offset = position * 11;
            let start = offset / 8;
            let window = u32::from_be_bytes([0, bits[start], bits[start + 1], bits[start + 2]]);
            *index = (window >> (24 - 11 - offset % 8)) as u16 & 0x7FF;
        }
        indices
    }
}

/// ニーモニックの単語の数。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCount {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl WordCount {
    /// 単語の数。
    pub fn get(self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words15 => 15,
            Self::Words18 => 18,
            Self::Words21 => 21,
            Self::Words24 => 24,
        }
    }

    /// もとになるエントロピーのバイト数。
    fn entropy_length(self) -> usize {
        self.get() * 4 / 3
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mnemonic(..)")
    }
}

impl FromStr for Mnemonic {
    type Err = ParseMnemonicError;

    /// 小文字の英単語を空白で区切った文を読む。
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let word_count = text.split_whitespace().count();
        if !matches!(word_count, 12 | 15 | 18 | 21 | 24) {
            return Err(ParseMnemonicError::InvalidWordCount);
        }
        let mut bits = Zeroizing::new([0; MAX_ENTROPY_LENGTH + 3]);
        for (position, word) in text.split_whitespace().enumerate() {
            let index = index_of(word).ok_or(ParseMnemonicError::UnknownWord)?;
            let offset = position * 11;
            let start = offset / 8;
            let window = Zeroizing::new((u32::from(index) << (24 - 11 - offset % 8)).to_be_bytes());
            bits[start] |= window[1];
            bits[start + 1] |= window[2];
            bits[start + 2] |= window[3];
        }
        let length = word_count * 4 / 3;
        let mnemonic =
            Self::from_entropy(&bits[..length]).expect("the word count fixes the length");
        // チェックサムは単語の数の 1/3 ビット
        let shift = 8 - word_count / 3;
        if bits[length] >> shift != checksum(mnemonic.entropy()) >> shift {
            return Err(ParseMnemonicError::InvalidChecksum);
        }
        Ok(mnemonic)
    }
}

/// エントロピーの SHA-256 の先頭バイト。上位のビットがチェックサムになる。
fn checksum(entropy: &[u8]) -> u8 {
    let hash = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(entropy)));
    hash[0]
}

/// 単語を `MAX_WORD_LENGTH` バイトになるまで0で埋め、リトルエンディアンの整数にする。
/// 長すぎる単語はリストにないので `None`。
fn pack(word: &str) -> Option<u64> {
    let bytes = word.as_bytes();
    if bytes.len() > MAX_WORD_LENGTH {
        return None;
    }
    let mut padded = Zeroizing::new([0; MAX_WORD_LENGTH]);
    padded[..bytes.len()].copy_from_slice(bytes);
    Some(u64::from_le_bytes(*padded))
}

/// 0で埋めた単語の文字数。
fn word_length(padded: &[u8; MAX_WORD_LENGTH]) -> usize {
    padded.iter().map(|&byte| usize::from(byte != 0)).sum()
}

fn index_of(word: &str) -> Option<u16> {
    let target = Zeroizing::new(pack(word)?);
    let mut found = Choice::from(0);
    let mut index = Zeroizing::new(0u16);
    for (candidate, entry) in (0..).zip(&ENGLISH) {
        let matched = pack(entry).expect("the word list fits").ct_eq(&target);
        index.conditional_assign(&candidate, matched);
        found |= matched;
    }
    bool::from(found).then_some(*index)
}

fn word_at(index: u16) -> u64 {
    let mut word = 0u64;
    for (candidate, entry) in (0u16..).zip(&ENGLISH) {
        let packed = pack(entry).expect("the word list fits");
        word.conditional_assign(&packed, candidate.ct_eq(&index));
    }
    word
}

/// エントロピーの長さが BIP 39 で使えるものではない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidEntropyLength;

impl fmt::Display for InvalidEntropyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("エントロピーは16、20、24、28、32バイトのどれかのはずです")
    }
}

impl std::error::Error for InvalidEntropyLength {}

/// ニーモニックが読めなかった理由。ニーモニックの一部を漏らさないように、何番目の何が悪かったかは含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseMnemonicError {
    /// 単語の数が12、15、18、21、24のどれでもない
    InvalidWordCount,
    /// 単語リストにない単語が含まれている
    UnknownWord,
    /// 最後の単語に入っているチェックサムが合わない
    InvalidChecksum,
}

impl fmt::Display for ParseMnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWordCount => f.write_str("ニーモニックは12、15、18、21、24語のどれかのはずです"),
            Self::UnknownWord => f.write_str("ニーモニックに単語リストにない単語が含まれています"),
            Self::InvalidChecksum => f.write_str("ニーモニックのチェックサムが合いません。単語の書き間違いか順番の入れ違いがありそうです"),
        }
    }
}

impl std::error::Error for ParseMnemonicError {}

/// BIP 39 のシード（64バイト）。SLIP-10 などで鍵を導出するもとになる。使い終わるとメモリを0で上書きする。
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// パスフレーズが使えない理由。パスフレーズの一部を漏らさないように、どこの何が悪かったかは含めない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidPassphrase {
    /// ASCII 以外の文字が含まれている
    NonAscii,
    /// 256バイトより長い
    TooLong,
}

impl fmt::Display for InvalidPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonAscii => f.write_str("パスフレーズには ASCII の文字だけが使えます"),
            Self::TooLong => f.write_str("パスフレーズは256バイトまでです"),
        }
    }
}

impl std::error::Error for InvalidPassphrase {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Replay;

    #[test]
    fn english_is_sorted_without_duplicates() {
        assert!(ENGLISH.is_sorted_by(|a, b| a < b));
    }

    #[test]
    fn english_words_are_lower_case_ascii() {
        for word in &ENGLISH {
            assert!(
                !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase()),
                "{word:?}"
            );
        }
    }

    #[test]
    fn english_words_fit_in_max_word_length() {
        assert_eq!(
            ENGLISH.iter().map(|word| word.len()).max(),
            Some(MAX_WORD_LENGTH)
        );
    }

    #[test]
    fn english_starts_and_ends_with_the_known_words() {
        assert_eq!(ENGLISH[0], "abandon");
        assert_eq!(ENGLISH[3], "about");
        assert_eq!(ENGLISH[2047], "zoo");
    }
    /// trezor/python-mnemonic の vectors.json から、英語の組をいくつか
    const VECTORS: [(u8, usize, &str); 6] = [
        (
            0x00,
            16,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            0x7F,
            16,
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            0x80,
            16,
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            0xFF,
            16,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            0x00,
            24,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        ),
        (
            0xFF,
            32,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
    ];

    #[test]
    fn converts_entropy_to_phrase() {
        for (byte, length, phrase) in VECTORS {
            let mnemonic = Mnemonic::from_entropy(&vec![byte; length]).unwrap();
            assert_eq!(*mnemonic.to_phrase(), phrase);
            assert_eq!(mnemonic.word_count(), length * 3 / 4);
        }
    }

    #[test]
    fn parses_phrase_to_entropy() {
        for (byte, length, phrase) in VECTORS {
            let mnemonic: Mnemonic = phrase.parse().unwrap();
            assert_eq!(mnemonic.entropy(), vec![byte; length]);
        }
    }

    #[test]
    fn ignores_extra_whitespace() {
        let phrase = format!("  {}\n", VECTORS[0].2.replace(' ', " \t "));
        let mnemonic: Mnemonic = phrase.parse().unwrap();
        assert_eq!(*mnemonic.to_phrase(), VECTORS[0].2);
    }

    #[test]
    fn rejects_entropy_of_invalid_length() {
        assert_eq!(
            Mnemonic::from_entropy(&[0; 15]).unwrap_err(),
            InvalidEntropyLength
        );
    }

    #[test]
    fn rejects_invalid_word_count() {
        let phrase = VECTORS[0].2.rsplit_once(' ').unwrap().0;
        assert_eq!(
            phrase.parse::<Mnemonic>().unwrap_err(),
            ParseMnemonicError::InvalidWordCount
        );
    }

    #[test]
    fn rejects_unknown_words_without_revealing_them() {
        for typo in ["abandonn", "abandonment", "Abandon", "あ"] {
            let phrase = VECTORS[0].2.replacen("abandon", typo, 1);
            let error = phrase.parse::<Mnemonic>().unwrap_err();
            assert_eq!(error, ParseMnemonicError::UnknownWord);
            assert!(!error.to_string().contains(typo));
        }
    }

    #[test]
    fn rejects_invalid_checksum() {
        let phrase = "abandon ".repeat(12);
        assert_eq!(
            phrase.parse::<Mnemonic>().unwrap_err(),
            ParseMnemonicError::InvalidChecksum
        );
    }

    #[test]
    fn debug_hides_the_mnemonic() {
        let mnemonic: Mnemonic = VECTORS[0].2.parse().unwrap();
        assert_eq!(format!("{mnemonic:?}"), "Mnemonic(..)");
    }

    #[test]
    fn derives_the_seed_with_a_passphrase() {
        // trezor/python-mnemonic の vectors.json の最初の組
        let mnemonic: Mnemonic = VECTORS[0].2.parse().unwrap();
        let seed = mnemonic.to_seed("TREZOR").unwrap();
        assert_eq!(
            seed.as_bytes()[..],
            hex(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
        );
    }

    #[test]
    fn accepts_a_passphrase_up_to_256_bytes() {
        let mnemonic: Mnemonic = VECTORS[0].2.parse().unwrap();
        assert!(mnemonic.to_seed(&"a".repeat(256)).is_ok());
        assert_eq!(
            mnemonic.to_seed(&"a".repeat(257)).unwrap_err(),
            InvalidPassphrase::TooLong
        );
    }

    #[test]
    fn rejects_a_non_ascii_passphrase() {
        let mnemonic: Mnemonic = VECTORS[0].2.parse().unwrap();
        assert_eq!(
            mnemonic.to_seed("ﾊﾟｽ").unwrap_err(),
            InvalidPassphrase::NonAscii
        );
    }

    #[test]
    fn seed_debug_hides_the_seed() {
        let mnemonic: Mnemonic = VECTORS[0].2.parse().unwrap();
        assert_eq!(format!("{:?}", mnemonic.to_seed("").unwrap()), "Seed(..)");
    }

    #[test]
    fn generates_from_the_given_rng() {
        for (byte, length, phrase) in VECTORS {
            let bytes = vec![byte; 32];
            let word_count = match length {
                16 => WordCount::Words12,
                24 => WordCount::Words18,
                32 => WordCount::Words24,
                _ => unreachable!(),
            };
            let mnemonic = Mnemonic::generate_with_rng(&mut Replay(&bytes), word_count);
            assert_eq!(*mnemonic.to_phrase(), phrase);
        }
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn generates_different_mnemonics_from_the_os() {
        let first = Mnemonic::generate(WordCount::Words24).unwrap();
        let second = Mnemonic::generate(WordCount::Words24).unwrap();
        assert_eq!(first.word_count(), 24);
        assert_ne!(first.entropy(), second.entropy());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
