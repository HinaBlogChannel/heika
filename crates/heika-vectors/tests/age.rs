//! `testdata/age`: C2SP の CCTV にある age のテストベクター。
//!
//! パスフレーズのものはパスフレーズで開く。ヘッダーと本文の形を確かめるものは鍵を X25519 で包んであるので、
//! ヘッダーに書いてあるファイル鍵を直接使う。どちらも、成功か、どの段階で失敗するかまで照合する。
//! ネットワークは使わない。

use std::fs;
use std::path::Path;

use heika_wallet::age::{self, AgeError};
use sha2::{Digest, Sha256};

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn decrypts_like_the_age_test_vectors() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/age");
    let mut count = 0;
    for entry in fs::read_dir(&directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if name == "README.md" {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let split = bytes.windows(2).position(|pair| pair == b"\n\n").unwrap();
        let header = std::str::from_utf8(&bytes[..split]).unwrap();
        let mut data = bytes[split + 2..].to_vec();
        let field = |key: &str| {
            header
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{key}: ")))
        };
        if field("compressed") == Some("zlib") {
            data = miniz_oxide::inflate::decompress_to_vec_zlib(&data).unwrap();
        }
        assert_eq!(field("armored"), None, "{name}");

        let result = match field("passphrase") {
            Some(passphrase) => age::decrypt(passphrase.as_bytes(), &data),
            None => {
                let file_key = from_hex(field("file key").unwrap()).try_into().unwrap();
                age::decrypt_with_file_key(&file_key, &data)
            }
        };
        let expected = match field("expect").unwrap() {
            "success" => Ok(()),
            "no match" => Err(AgeError::NoMatch),
            "HMAC failure" => Err(AgeError::Hmac),
            "header failure" => Err(AgeError::Header),
            "payload failure" => Err(AgeError::Payload),
            other => panic!("{name}: expect {other}"),
        };
        match result {
            Ok(plaintext) => {
                assert_eq!(expected, Ok(()), "{name}");
                let hash: String = Sha256::digest(&*plaintext)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(Some(hash.as_str()), field("payload"), "{name}");
            }
            Err(error) => assert_eq!(expected, Err(error), "{name}"),
        }
        count += 1;
    }
    assert!(count > 0);
    eprintln!("{count} age vectors checked");
}
