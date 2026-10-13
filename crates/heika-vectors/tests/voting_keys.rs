//! `crypto/7.test-voting-keys-generation.json`: 決まった秘密鍵の並びから、投票の鍵のファイルを作る。
//!
//! 公式の SDK のテストと同じく、子の秘密鍵は乱数の代わりに決まった手順で作る。
//! heika は根の秘密鍵も同じ乱数から作るので、根の鍵を先頭に置いて渡す。

use heika_core::voting::VotingKeyTree;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[serde(rename = "rootPrivateKey")]
    root_private_key: String,
    #[serde(rename = "startEpoch")]
    start_epoch: u32,
    #[serde(rename = "endEpoch")]
    end_epoch: u32,
    #[serde(rename = "expectedFileHex")]
    expected: String,
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// 公式の SDK の `FibPrivateKeyGenerator`。1, 2 から始めたフィボナッチ数の下位1バイトで鍵を作る。
/// `fill` なら全体をその値から1ずつ増やして埋め、そうでなければ最後のバイトだけに置く。
fn fibonacci_keys(count: usize, fill: bool) -> Vec<[u8; 32]> {
    let (mut previous, mut current) = (1_u64, 2_u64);
    (0..count)
        .map(|_| {
            (previous, current) = (current, previous + current);
            let seed = (current % 256) as u8;
            if fill {
                std::array::from_fn(|index| seed.wrapping_add(index as u8))
            } else {
                let mut key = [0; 32];
                key[31] = seed;
                key
            }
        })
        .collect()
}

/// 決まったバイト列を返すだけの乱数。
struct Replay(Vec<u8>);

impl rand_core::TryRng for Replay {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unimplemented!("only fill_bytes is used")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unimplemented!("only fill_bytes is used")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Replay {}

#[test]
#[ignore = "fetches the official vectors from GitHub"]
fn generates_voting_key_files() {
    let vectors: Vec<Vector> = heika_vectors::fetch("crypto/7.test-voting-keys-generation.json");
    assert_eq!(vectors.len(), 3);
    for vector in &vectors {
        let count = (vector.end_epoch - vector.start_epoch + 1) as usize;
        let children = match vector.name.as_str() {
            "test_vector_1" => fibonacci_keys(count, false),
            "test_vector_2" => fibonacci_keys(count, true),
            // 公式の SDK のテストに書かれている3つの鍵
            "test_vector_3" => [
                "12F98B7CB64A6D840931A2B624FB1EACAFA2C25C3EF0018CD67E8D470A248B2F",
                "B5593870940F28DAEE262B26367B69143AD85E43048D23E624F4ED8008C0427F",
                "6CFC879ABCCA78F5A4C9739852C7C643AEC3990E93BF4C6F685EB58224B16A59",
            ]
            .iter()
            .map(|key| from_hex(key).try_into().unwrap())
            .collect(),
            other => panic!("{other}"),
        };
        assert_eq!(children.len(), count, "{}", vector.name);
        let mut bytes = from_hex(&vector.root_private_key);
        bytes.extend(children.iter().flatten());
        let mut rng = Replay(bytes);
        let tree = VotingKeyTree::generate(&mut rng, vector.start_epoch, vector.end_epoch).unwrap();
        assert!(rng.0.is_empty(), "{}", vector.name);
        assert_eq!(
            *tree.to_bytes(),
            from_hex(&vector.expected),
            "{}",
            vector.name
        );
    }
}
