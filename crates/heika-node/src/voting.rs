//! 投票の鍵のファイルと、投票状況のファイル。catapult と同じ置き方と形。
//!
//! - 鍵: `finalization.votingKeys` のフォルダーの `private_key_tree1.dat`、`private_key_tree2.dat`、…（catapult の
//!   `votingkeys`）。1から順に読み、今の木の期間を過ぎたら、その木の鍵を全部消して次の番号の木に移る
//! - 投票状況: データのフォルダーの `voting_status.dat`。どのラウンドまで進み、そのラウンドで何を出したか
//!
//! どちらも、署名を外に出す前に、書いてディスクに届くのを待つ。落ちて起き直しても、使ったエポックより前の鍵で
//! 署名せず、出した段階をもう一度出さない（catapult は出したあとで投票状況を書くが、ここでは先に書く）。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use heika_core::voting::VotingKeyTree;
use heika_finalization::orchestrator::VotingStatus;
use heika_finalization::signer::VotingKeys;

use crate::driver::NodeError;
use crate::keys::others_can_read;

/// 投票の鍵のファイルの並び。catapult の `AggregateBmPrivateKeyTree`
pub struct KeyFiles {
    directory: PathBuf,
    /// 今の木と、その番号
    current: Option<(u32, VotingKeyTree)>,
}

impl KeyFiles {
    /// `directory` の `private_key_tree1.dat` から読む。なければ署名できないまま進む
    pub fn open(directory: &Path) -> Result<Self, NodeError> {
        let mut files = Self {
            directory: directory.to_owned(),
            current: None,
        };
        files.current = files.load(1)?;
        if files.current.is_none() {
            eprintln!(
                "警告: {} に投票の鍵がないので、投票しません",
                files.path(1).display()
            );
        }
        Ok(files)
    }

    /// 根の公開鍵と期間（ログに出す）
    pub fn describe(&self) -> Option<String> {
        self.current.as_ref().map(|(sequence, tree)| {
            format!(
                "投票の鍵 {}: エポック {} から {} まで（{} エポック分が残っています）",
                self.path(*sequence).display(),
                tree.start_epoch(),
                tree.end_epoch(),
                tree.remaining_keys()
            )
        })
    }

    fn path(&self, sequence: u32) -> PathBuf {
        self.directory
            .join(format!("private_key_tree{sequence}.dat"))
    }

    fn load(&self, sequence: u32) -> Result<Option<(u32, VotingKeyTree)>, NodeError> {
        let path = self.path(sequence);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("{} を読めません: {error}", path.display()).into()),
        };
        if others_can_read(&path).unwrap_or(false) {
            eprintln!(
                "警告: {} は持ち主のほかも読めます。投票の鍵なので、chmod 600 にしてください",
                path.display()
            );
        }
        let tree = VotingKeyTree::from_bytes(&bytes)
            .map_err(|error| format!("{} を読めません: {error}", path.display()))?;
        if let Err(epoch) = tree.verify() {
            return Err(format!(
                "{} のエポック {epoch} の鍵が、根の鍵の署名と合いません",
                path.display()
            )
            .into());
        }
        Ok(Some((sequence, tree)))
    }

    fn save(&self, sequence: u32, tree: &VotingKeyTree) -> Result<(), NodeError> {
        write_durably(&self.path(sequence), &tree.to_bytes())
    }

    /// エポック `epoch` の鍵がある木に移る。過ぎた木は鍵を全部消して書き戻す。書き戻せなければ、どの木も持たない
    /// （署名しない）
    fn advance(&mut self, epoch: u32) -> Result<(), NodeError> {
        while let Some((sequence, mut tree)) = self.current.take() {
            if tree.end_epoch() >= epoch {
                self.current = Some((sequence, tree));
                break;
            }
            let end = tree.end_epoch();
            tree.wipe_through(end);
            self.save(sequence, &tree)?;
            let next = self.load(sequence + 1)?;
            if let Some((_, tree)) = &next
                && tree.start_epoch() <= end
            {
                return Err(format!(
                    "{} の期間（エポック {} から）が、前の木の終わり（エポック {end}）と重なっています",
                    self.path(sequence + 1).display(),
                    tree.start_epoch()
                )
                .into());
            }
            self.current = next;
        }
        Ok(())
    }

    fn try_sign(&mut self, epoch: u32, signed: &[u8]) -> Result<Option<[u8; 192]>, NodeError> {
        self.advance(epoch)?;
        let Some((sequence, tree)) = self.current.as_mut() else {
            return Ok(None);
        };
        let Some(signature) = tree.sign(epoch, &[signed]) else {
            return Ok(None);
        };
        // catapult と同じく、前のエポックまでの鍵を消す
        if epoch > tree.start_epoch() {
            tree.wipe_through(epoch - 1);
        }
        let sequence = *sequence;
        let tree = &self.current.as_ref().expect("signed with it").1;
        self.save(sequence, tree)?;
        Ok(Some(signature))
    }
}

impl VotingKeys for KeyFiles {
    fn sign(&mut self, epoch: u32, signed: &[u8]) -> Option<[u8; 192]> {
        match self.try_sign(epoch, signed) {
            Ok(signature) => signature,
            Err(error) => {
                // 書き残せなかった署名は出さない
                eprintln!("投票の鍵で署名できません: {error}");
                None
            }
        }
    }
}

/// 投票状況を読む。なければ `None`
pub fn read_status(data_directory: &Path) -> Result<Option<VotingStatus>, NodeError> {
    let path = data_directory.join("voting_status.dat");
    match std::fs::read(&path) {
        Ok(bytes) => VotingStatus::from_bytes(&bytes)
            .map(Some)
            .ok_or_else(|| format!("{} の形が違います", path.display()).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{} を読めません: {error}", path.display()).into()),
    }
}

/// 投票状況を書く
pub fn write_status(data_directory: &Path, status: &VotingStatus) -> Result<(), NodeError> {
    write_durably(
        &data_directory.join("voting_status.dat"),
        &status.to_bytes(),
    )
}

/// 持ち主だけが読める別のファイルに書いてディスクに届くのを待ち、置き換えて、フォルダーもディスクに届くのを待つ
fn write_durably(path: &Path, bytes: &[u8]) -> Result<(), NodeError> {
    let fail = |error: std::io::Error| format!("{} を書けません: {error}", path.display());
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".new");
    let temporary = PathBuf::from(temporary);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(fail)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(fail)?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(fail)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(fail)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use heika_block::finalization::FinalizationRound;

    use super::*;

    fn tree(start: u32, end: u32) -> VotingKeyTree {
        VotingKeyTree::generate(&mut rand_core::UnwrapErr(getrandom::SysRng), start, end).unwrap()
    }

    fn directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("heika-voting-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn signs_and_remembers_used_and_wiped_epochs_on_disk() {
        let dir = directory("sign");
        std::fs::write(dir.join("private_key_tree1.dat"), tree(2, 4).to_bytes()).unwrap();
        let mut files = KeyFiles::open(&dir).unwrap();
        assert!(files.sign(1, b"x").is_none());
        assert!(files.sign(3, b"x").is_some());
        assert!(files.sign(3, b"y").is_some());

        // ファイルにも、使ったエポックと消した鍵が残る
        let reread =
            VotingKeyTree::from_bytes(&std::fs::read(dir.join("private_key_tree1.dat")).unwrap())
                .unwrap();
        assert_eq!(reread.last_used_epoch(), Some(3));
        assert_eq!(reread.last_wiped_epoch(), Some(2));
        let mut reopened = KeyFiles::open(&dir).unwrap();
        assert!(reopened.sign(2, b"x").is_none());
        assert!(reopened.sign(3, b"x").is_some());
        #[cfg(unix)]
        assert!(!others_can_read(&dir.join("private_key_tree1.dat")).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn moves_to_the_next_tree_and_wipes_the_old_one() {
        let dir = directory("next");
        std::fs::write(dir.join("private_key_tree1.dat"), tree(2, 3).to_bytes()).unwrap();
        std::fs::write(dir.join("private_key_tree2.dat"), tree(4, 6).to_bytes()).unwrap();
        let mut files = KeyFiles::open(&dir).unwrap();
        assert!(files.sign(5, b"x").is_some());
        let old =
            VotingKeyTree::from_bytes(&std::fs::read(dir.join("private_key_tree1.dat")).unwrap())
                .unwrap();
        assert_eq!(old.remaining_keys(), 0);
        // 木がなくなれば署名しない
        assert!(files.sign(7, b"x").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_overlapping_trees() {
        let dir = directory("overlap");
        std::fs::write(dir.join("private_key_tree1.dat"), tree(2, 4).to_bytes()).unwrap();
        std::fs::write(dir.join("private_key_tree2.dat"), tree(4, 6).to_bytes()).unwrap();
        let mut files = KeyFiles::open(&dir).unwrap();
        assert!(files.sign(5, b"x").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_back_the_voting_status() {
        let dir = directory("status");
        assert_eq!(read_status(&dir).unwrap(), None);
        let status = VotingStatus {
            round: FinalizationRound { epoch: 4, point: 2 },
            sent_prevote: true,
            sent_precommit: false,
        };
        write_status(&dir, &status).unwrap();
        assert_eq!(read_status(&dir).unwrap(), Some(status));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
