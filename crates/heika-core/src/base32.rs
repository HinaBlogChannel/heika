//! Base32（RFC 4648、パディングなし）。catapult の `utils/Base32.cpp` に合わせて、
//! 5バイト単位のデータと8文字単位の文字列だけを扱い、大文字だけを受け付ける。

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode(bytes: &[u8]) -> String {
    assert!(
        bytes.len().is_multiple_of(5),
        "Base32 encodes 5-byte blocks"
    );
    let mut text = String::with_capacity(bytes.len() / 5 * 8);
    for block in bytes.as_chunks::<5>().0 {
        let bits = block
            .iter()
            .fold(0u64, |bits, &byte| bits << 8 | u64::from(byte));
        for shift in (0..8).rev() {
            text.push(ALPHABET[(bits >> (shift * 5)) as usize & 0x1F] as char);
        }
    }
    text
}

/// 読めない文字があれば、その位置（文字数で数える）と文字を返す。
pub fn decode(text: &str) -> Result<Vec<u8>, (usize, char)> {
    let values = text
        .chars()
        .enumerate()
        .map(|(index, character)| match character {
            'A'..='Z' => Ok(character as u8 - b'A'),
            '2'..='7' => Ok(character as u8 - b'2' + 26),
            _ => Err((index, character)),
        })
        .collect::<Result<Vec<u8>, _>>()?;
    assert!(
        values.len().is_multiple_of(8),
        "Base32 decodes 8-character blocks"
    );
    let mut bytes = Vec::with_capacity(values.len() / 8 * 5);
    for block in values.as_chunks::<8>().0 {
        let bits = block
            .iter()
            .fold(0u64, |bits, &value| bits << 5 | u64::from(value));
        bytes.extend_from_slice(&bits.to_be_bytes()[3..]);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 の 10 節にあるテストベクターのうち、5バイト単位でパディングが付かないもの
    #[test]
    fn matches_rfc_4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"fooba"), "MZXW6YTB");
        assert_eq!(decode("MZXW6YTB"), Ok(b"fooba".to_vec()));
    }

    #[test]
    fn round_trips_every_byte_value() {
        let bytes: Vec<u8> = (0..=255).chain(0..4).collect();
        assert_eq!(decode(&encode(&bytes)), Ok(bytes));
    }

    #[test]
    fn rejects_lower_case_and_digits_outside_the_alphabet() {
        assert_eq!(decode("MZXW6YTb"), Err((7, 'b')));
        assert_eq!(decode("MZXW1YTB"), Err((4, '1')));
    }
}
