//! 使い方を誤ると資産を失う、上級者向けの道具。

use std::io::{self, Write};

use clap::Subcommand;
use heika_core::hazmat::{self, curve25519_dalek::traits::IsIdentity};
use heika_core::key::PublicKey;

use crate::Failure;

#[derive(Subcommand)]
pub enum ExpertCommand {
    /// 公開鍵を、曲線の点として扱う
    #[command(subcommand)]
    PublicKey(PublicKeyCommand),
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
    }
    Ok(())
}
