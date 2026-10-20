//! 送金（catapult の transfer プラグイン）を当てる。

use heika_transaction::Transfer;

use super::*;

impl Executor {
    pub(super) fn apply_transfer(
        &mut self,
        height: u64,
        signer: [u8; 24],
        is_nemesis_signer: bool,
        transfer: &Transfer,
    ) -> Result<(), ExecError> {
        let recipient = self.resolve_address(transfer.recipient_address())?;
        self.add_address(recipient, height);
        for (&id, &amount) in transfer.mosaics() {
            let id = self.resolve_mosaic(id.0)?;
            if is_nemesis_signer {
                let funding = match self.implicit_funding {
                    Some(funding) => funding,
                    None => {
                        let funding = self.accounts[&signer].balance(id) == 0;
                        self.implicit_funding = Some(funding);
                        funding
                    }
                };
                if funding {
                    self.credit(&signer, id, amount)?;
                }
            }
            self.transfer(&signer, &recipient, id, amount)?;
        }
        Ok(())
    }
}
