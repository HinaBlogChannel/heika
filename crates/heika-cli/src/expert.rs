//! 使い方を誤ると資産を失う、上級者向けの道具。

use std::io::{self, Write};

use clap::Subcommand;
use heika_core::hazmat;
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
    }
    Ok(())
}
