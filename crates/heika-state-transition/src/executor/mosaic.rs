//! モザイクの定義、供給量の変更、取り上げ（mosaic プラグイン）を当てる。

use heika_transaction::{MosaicDefinition, MosaicSupplyChange, MosaicSupplyRevocation};

use super::*;

impl Executor {
    pub(super) fn apply_mosaic_definition(
        &mut self,
        height: u64,
        signer: [u8; 24],
        is_nemesis_signer: bool,
        definition: &MosaicDefinition,
    ) -> Result<(), ExecError> {
        let id = definition.id.0;
        // MosaicId: ID は持ち主と nonce から決まる
        if MosaicId::generate(&Address(signer), definition.nonce) != definition.id {
            return Err(invalid(format!(
                "モザイク {id:016X} は {} の nonce {} のものではありません",
                Address(signer),
                definition.nonce
            )));
        }
        // MosaicFlags: Revokable は国庫の再発行の高さから
        let flags = definition.flags.bits();
        let all = if height < self.config.treasury_reissuance_height {
            MOSAIC_FLAGS_ALL & !MosaicFlags::REVOKABLE.bits()
        } else {
            MOSAIC_FLAGS_ALL
        };
        if flags > all {
            return Err(invalid(format!("モザイク {id:016X} のフラグ {flags:#X}")));
        }
        // MosaicAvailability: 作り直せるのは、生きていて持ち主が同じで、何か変わり、発行量が 0 のとき
        if let Some(current) = self.mosaics.get(&id) {
            if !current.is_active(height) || current.owner != signer {
                return Err(invalid(format!(
                    "モザイク {id:016X} は作り直せません（生きていないか、持ち主が違う）"
                )));
            }
            let changes = flags != 0
                || definition.divisibility != 0
                || (current.duration != 0 && definition.duration != 0);
            if !changes || current.supply != 0 {
                return Err(invalid(format!(
                    "モザイク {id:016X} は作り直せません（変わらないか、発行量が残っている）"
                )));
            }
        }
        let sink = self.config.mosaic_rental_fee_sink.at(height).0;
        self.add_address(sink, height);
        if !is_nemesis_signer {
            let fee = self.config.mosaic_rental_fee * u64::from(self.dynamic_fee_multiplier);
            self.transfer(&signer, &sink, self.config.currency_mosaic_id, fee)?;
            let receipt = transfer_receipt(signer, sink, self.config.currency_mosaic_id, fee);
            self.statement
                .add_receipt(ReceiptBody::MosaicRentalFee(receipt));
        }
        let entry = match self.mosaics.remove(&id) {
            Some(current) => MosaicEntry {
                supply: 0,
                start_height: current.start_height,
                owner: signer,
                revision: current.revision + 1,
                flags: current.flags ^ definition.flags.bits(),
                divisibility: current.divisibility ^ definition.divisibility,
                duration: current.duration + definition.duration,
            },
            None => MosaicEntry {
                supply: 0,
                start_height: height,
                owner: signer,
                revision: 1,
                flags: definition.flags.bits(),
                divisibility: definition.divisibility,
                duration: definition.duration,
            },
        };
        self.mosaics.insert(id, entry);
        self.schedule_mosaic_receipt(id);
        self.touch(SubCache::Mosaic, &id.to_le_bytes());
        Ok(())
    }

    pub(super) fn apply_mosaic_supply_change(
        &mut self,
        height: u64,
        signer: [u8; 24],
        change: &MosaicSupplyChange,
    ) -> Result<(), ExecError> {
        let id = self.resolve_mosaic(change.mosaic_id.0)?;
        // RequiredMosaic と MosaicSupplyChangeAllowed
        let entry = self.check_mosaic_owner(height, id, &signer)?;
        let owned = self
            .accounts
            .get(&signer)
            .map_or(0, |account| account.balance(id));
        let mutable = entry.flags & MosaicFlags::SUPPLY_MUTABLE.bits() != 0;
        if !mutable && owned != entry.supply {
            return Err(invalid(format!(
                "モザイク {id:016X} の発行量は、持ち主が全部持っていないと変えられません"
            )));
        }
        let allowed = match change.action {
            MosaicSupplyChangeAction::Increase => entry
                .supply
                .checked_add(change.delta)
                .is_some_and(|supply| supply <= self.config.max_mosaic_atomic_units),
            MosaicSupplyChangeAction::Decrease => owned >= change.delta,
        };
        if !allowed {
            return Err(invalid(format!(
                "モザイク {id:016X} の発行量を {} 変えられません",
                change.delta
            )));
        }
        self.touch(SubCache::Mosaic, &id.to_le_bytes());
        let entry = self
            .mosaics
            .get_mut(&id)
            .ok_or_else(|| invalid(format!("モザイク {id:016X} がありません")))?;
        let owner = entry.owner;
        match change.action {
            MosaicSupplyChangeAction::Increase => {
                entry.supply += change.delta;
                self.credit(&owner, id, change.delta)?;
            }
            MosaicSupplyChangeAction::Decrease => {
                entry.supply -= change.delta;
                self.debit(&owner, id, change.delta)?;
            }
        }
        Ok(())
    }

    pub(super) fn apply_mosaic_supply_revocation(
        &mut self,
        height: u64,
        signer: [u8; 24],
        revocation: &MosaicSupplyRevocation,
    ) -> Result<(), ExecError> {
        // 発行量は変えず、持っているアカウントから持ち主へ移す
        let source = self.resolve_address(&revocation.source_address)?;
        let id = self.resolve_mosaic(revocation.mosaic.mosaic_id.0)?;
        // RequiredMosaic: 持ち主が、Revokable のモザイクだけ（Nemesis の署名者はフラグを問わない）
        let entry = self.check_mosaic_owner(height, id, &signer)?;
        if signer != self.nemesis && entry.flags & MosaicFlags::REVOKABLE.bits() == 0 {
            return Err(invalid(format!("モザイク {id:016X} は取り上げられません")));
        }
        self.transfer(&source, &signer, id, revocation.mosaic.amount)?;
        Ok(())
    }

    /// モザイクの期限切れのレシートを出す高さを覚える。期限のないものは何もしない
    pub(super) fn schedule_mosaic_receipt(&mut self, id: u64) {
        let Some(entry) = self.mosaics.get(&id).filter(|entry| entry.duration != 0) else {
            return;
        };
        self.artifact_expiries
            .entry(entry.start_height + entry.duration)
            .or_default()
            .insert(Artifact::Mosaic(id));
    }
}
