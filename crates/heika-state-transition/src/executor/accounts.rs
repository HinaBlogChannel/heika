//! アカウントを作る、引く、残高を動かす。

use super::*;

impl Executor {
    pub(super) fn address_of(&self, public_key: &PublicKey) -> [u8; 24] {
        Address::from_public_key(public_key, self.network).0
    }

    /// catapult の `AccountStateCacheDelta::addAccount(address)`
    pub(super) fn add_address(&mut self, address: [u8; 24], height: u64) {
        self.accounts
            .get_or_insert_with(address, || AccountState::new(address, height));
        self.touched.insert(address);
    }

    /// catapult の `AccountStateCacheDelta::addAccount(publicKey)`
    pub(super) fn add_public_key(&mut self, public_key: &PublicKey, height: u64) -> [u8; 24] {
        let address = self.address_of(public_key);
        self.add_address(address, height);
        let account = self.accounts.get_mut(&address).expect("just added");
        if account.public_key_height == 0 {
            account.public_key = public_key.0;
            account.public_key_height = height;
        }
        address
    }

    pub(super) fn account_mut(
        &mut self,
        address: &[u8; 24],
    ) -> Result<&mut AccountState, ExecError> {
        self.touched.insert(*address);
        self.accounts
            .get_mut(address)
            .ok_or_else(|| invalid(format!("アカウント {} がありません", Address(*address))))
    }

    /// Remote のアカウントなら、そのメインのアカウント。catapult の `ProcessForwardedAccountState`
    pub(super) fn forwarded(&mut self, address: &[u8; 24]) -> Result<[u8; 24], ExecError> {
        let account = self.account_mut(address)?;
        if account.account_type != AccountType::Remote {
            return Ok(*address);
        }
        let main_key = account
            .linked
            .ok_or_else(|| invalid("Remote のアカウントにリンクがありません"))?;
        let main = self.address_of(&PublicKey(main_key));
        self.account_mut(&main)?;
        Ok(main)
    }

    pub(super) fn credit(
        &mut self,
        address: &[u8; 24],
        mosaic_id: u64,
        amount: u64,
    ) -> Result<(), ExecError> {
        self.account_mut(address)?.credit(mosaic_id, amount);
        Ok(())
    }

    pub(super) fn debit(
        &mut self,
        address: &[u8; 24],
        mosaic_id: u64,
        amount: u64,
    ) -> Result<(), ExecError> {
        if !self.account_mut(address)?.debit(mosaic_id, amount) {
            return Err(invalid(format!(
                "{} のモザイク {mosaic_id:016X} が {amount} に足りません",
                Address(*address)
            )));
        }
        Ok(())
    }

    pub(super) fn transfer(
        &mut self,
        from: &[u8; 24],
        to: &[u8; 24],
        mosaic_id: u64,
        amount: u64,
    ) -> Result<(), ExecError> {
        self.debit(from, mosaic_id, amount)?;
        self.credit(to, mosaic_id, amount)
    }
}
