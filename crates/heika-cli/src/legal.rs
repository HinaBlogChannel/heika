//! heika と依存のライセンスと、バイナリに埋め込んだソース。

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Subcommand;
use heika_wallet::bip39;

use crate::Failure;
use crate::tx::write_new;

/// heika のライセンス
const LICENSE: &str = include_str!("../../../LICENSE");
/// 依存のクレートのライセンス。about.toml の手順で作り直す
const THIRD_PARTY_LICENSES: &str = include_str!("../THIRD-PARTY-LICENSES");
/// ビルドしたときの作業ツリーを、build.rs が git archive でまとめたもの。まとめられなかったときは空。
///
/// 実行しなくても取り出せるように、決まった名前のセクションに置く。
/// PE のセクションの名前は8バイトまでなので、Windows では短くする
#[used]
#[cfg_attr(
    not(any(target_vendor = "apple", windows)),
    unsafe(link_section = ".heika_source")
)]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__TEXT,__heika_source")
)]
#[cfg_attr(windows, unsafe(link_section = ".hksrc"))]
pub(crate) static SOURCE: [u8; SOURCE_LEN] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/source.zip"));
const SOURCE_LEN: usize = include_bytes!(concat!(env!("OUT_DIR"), "/source.zip")).len();
/// SOURCE をどのコミットから作ったか
const SOURCE_DESCRIPTION: &str = env!("HEIKA_SOURCE_DESCRIPTION");

#[derive(Subcommand)]
pub enum LegalCommand {
    /// heika のライセンス（AGPL-3.0-only）の全文を出す
    License,
    /// バイナリに入っている、ほかのソフトウェアのライセンスを出す
    ThirdParty,
    /// このバイナリのソースを ZIP に書く
    ///
    /// ビルドしたときの作業ツリーを、git archive でまとめて埋め込んだもの。
    /// コミットしていない変更も入り、追跡していないファイルは入らない。
    /// heika の git のリポジトリの外でビルドしたバイナリには入っていない。
    Source {
        /// ZIP を書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
}

pub fn run(command: LegalCommand) -> Result<(), Failure> {
    match command {
        LegalCommand::License => outln!("{}", LICENSE.trim_end()),
        LegalCommand::ThirdParty => {
            outln!("{}", THIRD_PARTY_LICENSES.trim_end());
            outln!();
            outln!("{}", "=".repeat(80));
            outln!("NOTICE-BIP39");
            outln!();
            outln!("{}", bip39::ENGLISH_NOTICE.trim_end());
        }
        LegalCommand::Source { out } => {
            if SOURCE.is_empty() {
                return Err(
                    "このバイナリにはソースが入っていません。heika の git のリポジトリの外でビルドしたものです"
                        .to_owned()
                        .into(),
                );
            }
            write_new(&out, &SOURCE)?;
            outln!("{} に書きました（{SOURCE_DESCRIPTION}）", out.display());
        }
    }
    Ok(())
}
