//! `heika key voting`: ファイナライズの投票に使う、投票鍵のファイルを作って調べる。

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Subcommand;
use heika_core::key::PublicKey;
use heika_core::voting::VotingKeyTree;
use zeroize::Zeroizing;

use crate::{Failure, Network, create_secret_file, show};

#[derive(Subcommand)]
pub enum VotingCommand {
    /// 投票鍵のファイルを作り、チェーンに紐づける公開鍵を出す
    ///
    /// 根の鍵でエポックごとの鍵に署名したら、根の秘密鍵は捨てる。
    /// 作ったファイルはノードの votingkeys フォルダーに、private_key_tree1.dat から順に番号を振って置く。
    Generate {
        #[arg(long, value_enum)]
        network: Network,
        /// 最初のエポック。今のエポックより後にする
        #[arg(long, value_name = "EPOCH")]
        start_epoch: u32,
        /// 最後のエポック。期間（最後 - 最初 + 1）は、メインネットなら 112 から 360、テストネットなら 28 から 720
        #[arg(long, value_name = "EPOCH")]
        end_epoch: u32,
        /// 書くファイル。すでにあるファイルは上書きしない
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    /// 投票鍵のファイルを読み、公開鍵と期間、ノードが使って消した鍵を出し、残っている鍵の署名を確かめる
    Show {
        /// 投票鍵のファイル（private_key_tree1.dat など）
        file: PathBuf,
    },
}

pub fn run(command: VotingCommand) -> Result<(), Failure> {
    match command {
        VotingCommand::Generate {
            network,
            start_epoch,
            end_epoch,
            out,
        } => {
            let parameters = network.parameters();
            if start_epoch == 0 || end_epoch < start_epoch {
                return Err(format!(
                    "期間（エポック {start_epoch} から {end_epoch} まで）が正しくありません。最初のエポックは 1 以上で、最後のエポック以下にしてください"
                )
                .into());
            }
            let count = end_epoch - start_epoch + 1;
            let lifetime = parameters.min_voting_key_lifetime..=parameters.max_voting_key_lifetime;
            if !lifetime.contains(&count) {
                return Err(format!(
                    "期間は {count} エポックですが、このネットワークでは {} から {} エポックにしてください",
                    lifetime.start(),
                    lifetime.end()
                )
                .into());
            }
            let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
            let tree = VotingKeyTree::generate(&mut rng, start_epoch, end_epoch)
                .map_err(|error| error.to_string())?;
            write_tree(&out, &tree.to_bytes())?;
            outln!("公開鍵: {}", tree.public_key());
            let epoch_length =
                parameters.block_generation_target_time * parameters.voting_set_grouping as u32;
            outln!(
                "期間: エポック {start_epoch} から {end_epoch} まで（{count} エポック、約 {}）",
                show::approximate(epoch_length * count)
            );
            outln!(
                "heika harvesting で紐づけるときは、--link-voting {} を付けてください",
                VotingLink::of(&tree)
            );
        }
        VotingCommand::Show { file } => {
            let bytes = Zeroizing::new(
                fs::read(&file)
                    .map_err(|error| format!("{} を読めませんでした: {error}", file.display()))?,
            );
            let tree = VotingKeyTree::from_bytes(&bytes)
                .map_err(|error| format!("{}: {error}", file.display()))?;
            let epoch = |epoch: Option<u32>| {
                epoch.map_or("まだない".to_owned(), |epoch| epoch.to_string())
            };
            outln!("公開鍵: {}", tree.public_key());
            outln!(
                "期間: エポック {} から {} まで（{} エポック）",
                tree.start_epoch(),
                tree.end_epoch(),
                tree.end_epoch() - tree.start_epoch() + 1
            );
            outln!(
                "最後に投票に使ったエポック: {}",
                epoch(tree.last_used_epoch())
            );
            outln!("最後に消したエポック: {}", epoch(tree.last_wiped_epoch()));
            outln!("残っている鍵: {}", tree.remaining_keys());
            tree.verify().map_err(|epoch| {
                format!(
                    "{}: エポック {epoch} の鍵に、公開鍵の署名が合いません",
                    file.display()
                )
            })?;
            outln!("署名: 残っている鍵は、どれも公開鍵の署名と合う");
            outln!(
                "heika harvesting で使うときの書き方: {}",
                VotingLink::of(&tree)
            );
        }
    }
    Ok(())
}

/// 子の秘密鍵が入るので、秘密鍵と同じく自分だけが読み書きできるファイルにする。
fn write_tree(path: &Path, bytes: &[u8]) -> Result<(), String> {
    create_secret_file(path)?
        .write_all(bytes)
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}

/// チェーンに紐づける投票鍵。`<公開鍵>:<最初のエポック>-<最後のエポック>` と書く。
/// 外すときは、紐づけたときの期間まで同じでなければならない。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VotingLink {
    pub public_key: PublicKey,
    pub start_epoch: u32,
    pub end_epoch: u32,
}

impl VotingLink {
    fn of(tree: &VotingKeyTree) -> Self {
        Self {
            public_key: tree.public_key(),
            start_epoch: tree.start_epoch(),
            end_epoch: tree.end_epoch(),
        }
    }
}

impl fmt::Display for VotingLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}-{}",
            self.public_key, self.start_epoch, self.end_epoch
        )
    }
}

impl FromStr for VotingLink {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || "<公開鍵>:<最初のエポック>-<最後のエポック> と書いてください".to_owned();
        let (public_key, epochs) = text.split_once(':').ok_or_else(invalid)?;
        let (start, end) = epochs.split_once('-').ok_or_else(invalid)?;
        let link = Self {
            public_key: public_key
                .parse()
                .map_err(|error| format!("公開鍵: {error}"))?,
            start_epoch: start.parse().map_err(|_| invalid())?,
            end_epoch: end.parse().map_err(|_| invalid())?,
        };
        if link.start_epoch == 0 || link.end_epoch < link.start_epoch {
            return Err("最初のエポックは 1 以上で、最後のエポック以下にしてください".to_owned());
        }
        Ok(link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_voting_links() {
        let link = VotingLink {
            public_key: PublicKey([0xAB; 32]),
            start_epoch: 100,
            end_epoch: 459,
        };
        let text = link.to_string();
        assert_eq!(text, format!("{}:100-459", "AB".repeat(32)));
        assert_eq!(text.parse(), Ok(link));
        for broken in [
            "AB",
            &format!("{}:100", "AB".repeat(32)),
            &format!("{}:0-10", "AB".repeat(32)),
            &format!("{}:10-9", "AB".repeat(32)),
            &format!("{}:a-9", "AB".repeat(32)),
        ] {
            assert!(broken.parse::<VotingLink>().is_err(), "{broken}");
        }
    }
}
