//! BIP 39 のニーモニック。

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn english_starts_and_ends_with_the_known_words() {
        assert_eq!(ENGLISH[0], "abandon");
        assert_eq!(ENGLISH[3], "about");
        assert_eq!(ENGLISH[2047], "zoo");
    }
}
