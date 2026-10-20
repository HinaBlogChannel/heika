//! 鍵のリンク（accountlink、keylink、votingkeylink のプラグイン）を当てる。

use heika_transaction::{KeyLink, VotingKeyLink};

use super::*;

impl Executor {
    pub(super) fn apply_account_key_link(
        &mut self,
        height: u64,
        signer: [u8; 24],
        signer_key: &PublicKey,
        link: &KeyLink,
    ) -> Result<(), ExecError> {
        let remote_key = link.linked_public_key;
        match link.link_action {
            LinkAction::Link => {
                let remote = self.add_public_key(&remote_key, height);
                let main = self.account_mut(&signer)?;
                main.linked = Some(remote_key.0);
                main.account_type = AccountType::Main;
                let remote = self.account_mut(&remote)?;
                remote.linked = Some(signer_key.0);
                remote.account_type = AccountType::Remote;
            }
            LinkAction::Unlink => {
                let remote = self.address_of(&remote_key);
                let main = self.account_mut(&signer)?;
                main.linked = None;
                main.account_type = AccountType::Unlinked;
                let remote = self.account_mut(&remote)?;
                remote.linked = None;
                remote.account_type = AccountType::RemoteUnlinked;
            }
        }
        Ok(())
    }

    pub(super) fn apply_vrf_or_node_key_link(
        &mut self,
        signer: [u8; 24],
        body: &Body,
        link: &KeyLink,
    ) -> Result<(), ExecError> {
        let value = match link.link_action {
            LinkAction::Link => Some(link.linked_public_key.0),
            LinkAction::Unlink => None,
        };
        let account = self.account_mut(&signer)?;
        if matches!(body, Body::VrfKeyLink(_)) {
            account.vrf = value;
        } else {
            account.node = value;
        }
        Ok(())
    }

    pub(super) fn apply_voting_key_link(
        &mut self,
        signer: [u8; 24],
        link: &VotingKeyLink,
    ) -> Result<(), ExecError> {
        let key = VotingKey {
            key: link.linked_public_key.0,
            start_epoch: link.start_epoch,
            end_epoch: link.end_epoch,
        };
        let voting = &mut self.account_mut(&signer)?.voting;
        match link.link_action {
            LinkAction::Link => {
                let at = voting.partition_point(|other| other.start_epoch < key.start_epoch);
                voting.insert(at, key);
            }
            LinkAction::Unlink => {
                let at = voting
                    .iter()
                    .position(|other| *other == key)
                    .ok_or_else(|| invalid("外す投票の鍵がありません"))?;
                voting.remove(at);
            }
        }
        Ok(())
    }
}
