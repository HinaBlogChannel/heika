//! Transfer のメッセージ。公式の SDK の `MessageEncoder` と同じ並び。
//!
//! メッセージの中身はチェーンから見ればただのバイト列で、先頭の1バイトで種類を見分けるのは
//! ウォレットどうしの決まり。平文は 0x00、暗号化したものは 0x01 で始める。
//! 委任ハーベストの要求は別の目印で始まり、[`crate::harvest_request`] で扱う。
//!
//! 暗号化は、送る人の秘密鍵と受け取る人の公開鍵から導出した共有鍵の AES-256-GCM なので、
//! 送った人も受け取った人も、自分の秘密鍵と相手の公開鍵で復号できる。

use std::fmt;

use heika_core::key::{PrivateKey, PublicKey};
use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::cipher::{self, DecryptError, InvalidPublicKey, SharedKey};

/// 平文のメッセージの先頭の印
pub const PLAIN: u8 = 0x00;
/// 暗号化したメッセージの先頭の印
pub const ENCRYPTED: u8 = 0x01;

/// 平文のメッセージにする。
pub fn plain(text: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(1 + text.len());
    message.push(PLAIN);
    message.extend_from_slice(text);
    message
}

/// 相手の公開鍵あてに暗号化したメッセージにする。印に続けて、認証タグ、初期化ベクトル、暗号文を並べる。
/// 乱数は初期化ベクトルにだけ使う。
pub fn encrypt<R: CryptoRng + ?Sized>(
    rng: &mut R,
    private_key: &PrivateKey,
    other_public_key: &PublicKey,
    text: &[u8],
) -> Result<Vec<u8>, InvalidPublicKey> {
    let key = SharedKey::derive(private_key, other_public_key)?;
    let mut iv = [0; cipher::IV_SIZE];
    rng.fill_bytes(&mut iv);
    let mut message = vec![ENCRYPTED];
    message.extend_from_slice(&cipher::encrypt(&key, &iv, text));
    Ok(message)
}

/// 暗号化したメッセージを、自分の秘密鍵と相手の公開鍵で復号する。
/// 送った人なら受け取った人の公開鍵を、受け取った人なら送った人の公開鍵を渡す。
pub fn decrypt(
    private_key: &PrivateKey,
    other_public_key: &PublicKey,
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptMessageError> {
    let Some((&ENCRYPTED, encrypted)) = message.split_first() else {
        return Err(DecryptMessageError::NotEncrypted);
    };
    let key = SharedKey::derive(private_key, other_public_key)
        .map_err(|_| DecryptMessageError::Decrypt(DecryptError::InvalidPublicKey))?;
    cipher::decrypt(&key, encrypted).map_err(DecryptMessageError::Decrypt)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptMessageError {
    /// 暗号化したメッセージの印で始まっていない
    NotEncrypted,
    Decrypt(DecryptError),
}

impl fmt::Display for DecryptMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEncrypted => f.write_str("暗号化したメッセージではありません"),
            Self::Decrypt(DecryptError::InvalidPublicKey) => {
                f.write_str("相手の公開鍵が、鍵の共有に使える曲線上の点ではありません")
            }
            Self::Decrypt(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DecryptMessageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Replay;

    // RFC 8032 の 7.1 節にある Ed25519 のテスト 1 と 2 の秘密鍵
    const ALICE: &str = "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60";
    const BOB: &str = "4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB";

    fn key(text: &str) -> (PrivateKey, PublicKey) {
        let private_key: PrivateKey = text.parse().unwrap();
        let public_key = PublicKey::from_private_key(&private_key);
        (private_key, public_key)
    }

    #[test]
    fn puts_the_plain_marker_first() {
        assert_eq!(plain(b"heika"), b"\0heika");
        assert_eq!(plain(b""), [PLAIN]);
    }

    #[test]
    fn encrypts_in_the_sdk_layout() {
        let (alice, _) = key(ALICE);
        let (_, bob) = key(BOB);
        let iv = [7; cipher::IV_SIZE];
        let message = encrypt(&mut Replay(&iv), &alice, &bob, b"heika").unwrap();
        let shared = SharedKey::derive(&alice, &bob).unwrap();
        let mut expected = vec![ENCRYPTED];
        expected.extend_from_slice(&cipher::encrypt(&shared, &iv, b"heika"));
        assert_eq!(message, expected);
        assert_eq!(message.len(), 1 + cipher::TAG_SIZE + cipher::IV_SIZE + 5);
    }

    #[test]
    fn both_sides_decrypt() {
        let (alice, alice_public) = key(ALICE);
        let (bob, bob_public) = key(BOB);
        let message = encrypt(&mut Replay(&[7; 12]), &alice, &bob_public, b"heika").unwrap();
        assert_eq!(*decrypt(&alice, &bob_public, &message).unwrap(), b"heika");
        assert_eq!(*decrypt(&bob, &alice_public, &message).unwrap(), b"heika");
    }

    #[test]
    fn refuses_other_keys_changed_bytes_and_other_kinds() {
        let (alice, _) = key(ALICE);
        let (bob, bob_public) = key(BOB);
        let message = encrypt(&mut Replay(&[7; 12]), &alice, &bob_public, b"heika").unwrap();
        // 相手の公開鍵を間違えると、共有鍵が変わる
        assert_eq!(
            decrypt(&bob, &bob_public, &message),
            Err(DecryptMessageError::Decrypt(DecryptError::Failed))
        );
        let (alice, _) = key(ALICE);
        let mut changed = message.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(
            decrypt(&alice, &bob_public, &changed),
            Err(DecryptMessageError::Decrypt(DecryptError::Failed))
        );
        assert_eq!(
            decrypt(&alice, &bob_public, &plain(b"heika")),
            Err(DecryptMessageError::NotEncrypted)
        );
        assert_eq!(
            decrypt(&alice, &bob_public, &[]),
            Err(DecryptMessageError::NotEncrypted)
        );
        assert_eq!(
            decrypt(&alice, &bob_public, &[ENCRYPTED, 0]),
            Err(DecryptMessageError::Decrypt(DecryptError::TooShort))
        );
    }
}
