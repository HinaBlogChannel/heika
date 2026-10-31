//! 使い方を誤ると資産を失う、上級者向けの道具。

use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

use clap::Subcommand;
use heika_core::hazmat::curve25519_dalek::edwards::EdwardsPoint;
use heika_core::hazmat::curve25519_dalek::scalar::Scalar;
use heika_core::hazmat::curve25519_dalek::traits::IsIdentity;
use heika_core::hazmat::{self, ExpandedKey};
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::signature::Signature;
use zeroize::Zeroizing;

use crate::{Failure, read_secret, write_secret};

#[derive(Subcommand)]
pub enum ExpertCommand {
    /// 公開鍵を、曲線の点として扱う
    #[command(subcommand)]
    PublicKey(PublicKeyCommand),
    /// 秘密鍵（シード）の代わりに、スカラーをじかに扱う
    ///
    /// スカラーは、32バイトのリトルエンディアンの16進で、素数位数 ℓ で割った余りとして扱う。
    /// スカラーは秘密鍵と同じ重みを持つ。漏れれば、そのアカウントのものはすべて動かせる。
    #[command(subcommand)]
    Scalar(ScalarCommand),
}

#[derive(Subcommand)]
pub enum ScalarCommand {
    /// 標準入力から読んだ秘密鍵（シード）を SHA-512 で広げ、クランプしたスカラーを ℓ で割った余りにして、ファイルに書く
    ///
    /// 署名に使う s = r + h·a の a。RFC 8032 の後半（ノンスを決めるのに使う）は書かない。
    Expand {
        /// スカラー（16進）を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// 標準入力から読んだスカラーの公開鍵（a·B）を出す
    PublicKey,
    /// 標準入力から読んだスカラーとノンスで、メッセージに署名し、署名（R と s、64バイト）を16進で出す
    ///
    /// 標準入力の1行目がスカラー a、2行目がノンス r。2行目を省くと OS の乱数で r を決める。
    /// R = r·B、h = H(R ‖ A ‖ M)、s = r + h·a。A は a·B で、--public-key で別の公開鍵のバイト列に差し替えられる。
    ///
    /// 同じスカラーで、違うメッセージに同じノンスを使うと、2つの署名からスカラーが求まる。ノンスを自分で決めるなら、
    /// メッセージと署名に仕込むものすべてから決めるか、乱数で作る。
    ///
    /// 出した署名は、catapult と同じ検証を通るとは限らない。--public-key で部分群の外の点を渡したときなどは通らない。
    Sign {
        /// メッセージ（16進）。複数渡すと、順につないだものに署名する
        #[arg(required = true, value_name = "MESSAGE")]
        messages: Vec<HexBytes>,
        /// h = H(R ‖ A ‖ M) の A に、a·B の代わりに使う公開鍵（16進）
        #[arg(long, value_name = "PUBLIC_KEY")]
        public_key: Option<PublicKey>,
    },
}

/// R = r·B、h = H(R ‖ A ‖ M)、s = r + h·a
fn sign(scalar: &Scalar, nonce: &Scalar, public_key: &[u8; 32], message: &[&[u8]]) -> [u8; 64] {
    let encoded_r = EdwardsPoint::mul_base(nonce).compress().to_bytes();
    let s = nonce + hazmat::challenge(&encoded_r, public_key, message) * scalar;
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&encoded_r);
    signature[32..].copy_from_slice(s.as_bytes());
    signature
}

/// 秘密でない、長さの決まっていない16進
#[derive(Clone)]
pub struct HexBytes(Vec<u8>);

impl FromStr for HexBytes {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if !text.len().is_multiple_of(2) {
            return Err("16進の桁の数が奇数です".into());
        }
        (0..text.len())
            .step_by(2)
            .map(|i| {
                text.get(i..i + 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                    .ok_or_else(|| format!("16進として読めません: {text}"))
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

/// 標準入力から読む、32バイトの秘密の16進のスカラー。
///
/// 16進は秘密鍵と同じく定数時間で読むために、[`PrivateKey`] として読んでから、ℓ で割った余りにする。
struct SecretScalar(Zeroizing<Scalar>);

impl FromStr for SecretScalar {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = PrivateKey::from_str(text.trim())
            .map_err(|_| "32バイトの16進（64文字）として読めません".to_string())?;
        Ok(Self(Zeroizing::new(Scalar::from_bytes_mod_order(
            *bytes.as_bytes(),
        ))))
    }
}

/// `scalar sign` の標準入力。1行目がスカラー、2行目があればノンス
struct SignSecrets {
    scalar: SecretScalar,
    nonce: Option<SecretScalar>,
}

impl FromStr for SignSecrets {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let scalar = lines.next().ok_or("スカラーがありません")?.parse()?;
        let nonce = lines.next().map(str::parse).transpose()?;
        if lines.next().is_some() {
            return Err("スカラーとノンスの2行より多く渡されました".into());
        }
        Ok(Self { scalar, nonce })
    }
}

#[derive(Subcommand)]
pub enum PublicKeyCommand {
    /// 小さい位数の点（位数が 8 の約数の点）8 個を、1 行に 1 個、16進と位数をタブで区切って出す
    ///
    /// 位数の小さい順で、同じ位数の中では16進の小さい順。単位元 0100…00 も含む。
    /// 番号の振り方には決まったものがないので、add には16進のまま渡す。
    ListTorsion,
    /// 公開鍵（曲線の点）を足して、正規形の16進で出す
    ///
    /// 正規形で曲線上にある点なら、素数位数の部分群の外の点も受け付ける。
    ///
    /// 公開鍵に、list-torsion の単位元以外の点を足すと、今の catapult の検証では誰も署名できない鍵になる。
    /// そのアドレスに送ったものは、二度と動かせない。ただし、これは今の検証の決まりの下での話で、
    /// 位数 8 を掛けてから比べる検証（ZIP-215 など）に変わると、元の鍵の持ち主が署名できるようになる。
    /// 小さい位数の点そのものなら、誰でも署名できるようになる。
    /// 単位元 0100…00 の鍵は、今でも誰でも署名できる。
    ///
    /// 公開鍵どうしの和の秘密鍵は、それぞれの秘密鍵（クランプしたスカラー）の和で、Symbol の秘密鍵としては
    /// 取り出せない。他人の公開鍵との和を、共同の鍵として使ってはいけない（rogue key）。
    Add {
        /// 足す公開鍵（16進）。2 個以上
        #[arg(required = true, num_args = 2.., value_name = "PUBLIC_KEY")]
        public_keys: Vec<PublicKey>,
    },
    /// 公開鍵（曲線の点）の逆元を、正規形の16進で出す。add と合わせると引き算になる
    Neg {
        /// 公開鍵（16進）
        public_key: PublicKey,
    },
    /// 公開鍵（曲線の点）が、素数位数の部分群に入っているかを調べる
    ///
    /// 入っていれば「主部分群」、外なら混ざった小さい位数の成分の位数を出す。単位元と、小さい位数の点そのものは
    /// そう書く。部分群に入っていて単位元でないときだけ、終了コード 0 で終わる。外か単位元なら 1、正規形の曲線上の点
    /// として読めなければ 2 で終わる。
    Inspect {
        /// 公開鍵（16進）
        public_key: PublicKey,
    },
}

fn decode(public_key: &PublicKey) -> Result<hazmat::curve25519_dalek::EdwardsPoint, String> {
    hazmat::decode_any_point(&public_key.0)
        .ok_or_else(|| format!("{public_key} は、正規形の曲線上の点として読めません"))
}

pub fn run(command: ExpertCommand) -> Result<(), Failure> {
    match command {
        ExpertCommand::PublicKey(PublicKeyCommand::ListTorsion) => {
            for (point, order) in hazmat::small_order_points() {
                outln!("{}\t{order}", PublicKey(point));
            }
        }
        ExpertCommand::PublicKey(PublicKeyCommand::Add { public_keys }) => {
            // 単位元から始めて足していき、読めない点があればそれを示す
            let mut sum = hazmat::small_order_points()[0].0;
            for public_key in &public_keys {
                sum = hazmat::add_points(&sum, &public_key.0).ok_or_else(|| {
                    format!("{public_key} は、正規形の曲線上の点として読めません")
                })?;
            }
            outln!("{}", PublicKey(sum));
        }
        ExpertCommand::PublicKey(PublicKeyCommand::Neg { public_key }) => {
            let point = decode(&public_key)?;
            outln!("{}", PublicKey((-point).compress().to_bytes()));
        }
        ExpertCommand::PublicKey(PublicKeyCommand::Inspect { public_key }) => {
            let Some(point) = hazmat::decode_any_point(&public_key.0) else {
                outln!("正規形の曲線上の点として読めません");
                return Err(Failure::Code(2));
            };
            // 2^j 倍して主部分群に入る最小の 2^j が、小さい位数の成分の位数
            let order = [1u8, 2, 4, 8]
                .into_iter()
                .find(|&order| {
                    (point * hazmat::curve25519_dalek::Scalar::from(order)).is_torsion_free()
                })
                .expect("the curve's cofactor is 8");
            if point.is_identity() {
                outln!("単位元。誰でも署名できる");
            } else if order == 1 {
                outln!("主部分群");
                return Ok(());
            } else if point.is_small_order() {
                outln!("小さい位数の点そのもの（位数 {order}）。今の検証では誰も署名できない");
            } else {
                outln!(
                    "主部分群の外（小さい位数の成分の位数 {order}）。今の検証では誰も署名できない"
                );
            }
            return Err(Failure::Code(1));
        }
        ExpertCommand::Scalar(ScalarCommand::Expand { out }) => {
            let private_key: PrivateKey = read_secret("秘密鍵", "alice.key")?;
            let expanded = ExpandedKey::new(&private_key);
            let scalar = PrivateKey::from_bytes(&expanded.scalar().to_bytes());
            write_secret(&out, &scalar.to_hex())?;
            outln!("公開鍵: {}", PublicKey::from_private_key(&private_key));
        }
        ExpertCommand::Scalar(ScalarCommand::PublicKey) => {
            let SecretScalar(scalar) = read_secret("スカラー", "alice.scalar")?;
            outln!(
                "{}",
                PublicKey(EdwardsPoint::mul_base(&scalar).compress().to_bytes())
            );
        }
        ExpertCommand::Scalar(ScalarCommand::Sign {
            messages,
            public_key,
        }) => {
            let SignSecrets { scalar, nonce } = read_secret("スカラーとノンス", "alice.scalar")?;
            let SecretScalar(scalar) = scalar;
            let nonce = match nonce {
                Some(SecretScalar(nonce)) => nonce,
                None => {
                    let mut wide = Zeroizing::new([0; 64]);
                    getrandom::fill(&mut *wide)
                        .map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
                    Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide))
                }
            };
            let public_key = public_key
                .map(|public_key| public_key.0)
                .unwrap_or_else(|| EdwardsPoint::mul_base(&scalar).compress().to_bytes());
            let message: Vec<&[u8]> = messages.iter().map(|message| &message.0[..]).collect();
            let signature = sign(&scalar, &nonce, &public_key, &message);
            outln!("{}", Signature(signature));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_like_rfc_8032_with_its_nonce() {
        let key = PrivateKey::from_bytes(&[7; 32]);
        let expanded = ExpandedKey::new(&key);
        let public_key = PublicKey::from_private_key(&key);
        let message: [&[u8]; 2] = [b"mess", b"age"];
        let nonce = Scalar::from_bytes_mod_order_wide(&hazmat::sha512([
            &expanded.prefix()[..],
            b"mess",
            b"age",
        ]));
        let signature = sign(expanded.scalar(), &nonce, &public_key.0, &message);
        assert_eq!(signature, key.sign(&message).0);
        // ほかのノンスでも、catapult と同じ検証を通る
        let other = sign(
            expanded.scalar(),
            &Scalar::from(5u8),
            &public_key.0,
            &message,
        );
        assert_ne!(other, signature);
        assert!(public_key.verify(&message, &Signature(other)));
    }

    #[test]
    fn reads_one_or_two_lines_of_secrets() {
        let a = "07".repeat(32);
        let secrets: SignSecrets = a.parse().unwrap();
        assert!(secrets.nonce.is_none());
        let secrets: SignSecrets = format!("{a}\n{a}\n").parse().unwrap();
        assert!(secrets.nonce.is_some());
        assert!(format!("{a}\n{a}\n{a}").parse::<SignSecrets>().is_err());
        assert!("".parse::<SignSecrets>().is_err());
    }

    #[test]
    fn reads_hex_messages() {
        assert_eq!("6D65".parse::<HexBytes>().unwrap().0, b"me");
        assert!("6D6".parse::<HexBytes>().is_err());
        assert!("zz".parse::<HexBytes>().is_err());
    }
}
