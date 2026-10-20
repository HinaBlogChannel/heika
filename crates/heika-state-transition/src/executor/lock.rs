//! ハッシュロックとシークレットロック（lockhash、locksecret プラグイン）を当てる。

use heika_transaction::{HashLock, SecretLock, SecretProof};

use super::*;

impl Executor {
    pub(super) fn apply_hash_lock(
        &mut self,
        height: u64,
        signer: [u8; 24],
        lock: &HashLock,
    ) -> Result<(), ExecError> {
        let mosaic_id = self.resolve_mosaic(lock.mosaic.mosaic_id.0)?;
        self.debit(&signer, mosaic_id, lock.mosaic.amount)?;
        self.statement
            .add_receipt(ReceiptBody::LockHashCreated(change(
                signer,
                mosaic_id,
                lock.mosaic.amount,
            )));
        self.hash_locks
            .get_or_insert_with(lock.hash.0, Vec::new)
            .push(HashLockInfo {
                owner: signer,
                mosaic_id,
                amount: lock.mosaic.amount,
                end_height: height + lock.duration,
                status: LockStatus::Unused,
            });
        self.touch(SubCache::HashLockInfo, &lock.hash.0);
        self.expire_at(height + lock.duration, SubCache::HashLockInfo, &lock.hash.0);
        Ok(())
    }

    pub(super) fn apply_secret_lock(
        &mut self,
        height: u64,
        signer: [u8; 24],
        lock: &SecretLock,
    ) -> Result<(), ExecError> {
        let recipient = self.resolve_address(&lock.recipient_address)?;
        self.add_address(recipient, height);
        let mosaic_id = self.resolve_mosaic(lock.mosaic.mosaic_id.0)?;
        self.debit(&signer, mosaic_id, lock.mosaic.amount)?;
        self.statement
            .add_receipt(ReceiptBody::LockSecretCreated(change(
                signer,
                mosaic_id,
                lock.mosaic.amount,
            )));
        let key = secret_lock_key(&lock.secret, &Address(recipient));
        self.secret_locks
            .entry(key.0)
            .or_default()
            .push(SecretLockInfo {
                owner: signer,
                mosaic_id,
                amount: lock.mosaic.amount,
                end_height: height + lock.duration,
                status: LockStatus::Unused,
                hash_algorithm: hash_algorithm_byte(lock.hash_algorithm),
                secret: lock.secret.0,
                recipient,
            });
        self.touch(SubCache::SecretLockInfo, &key.0);
        self.stale_secret_locks.remove(&key.0);
        self.expire_at(height + lock.duration, SubCache::SecretLockInfo, &key.0);
        Ok(())
    }

    pub(super) fn apply_secret_proof(
        &mut self,
        height: u64,
        proof: &SecretProof,
    ) -> Result<(), ExecError> {
        // ProofSecret: 証明の長さと、そのハッシュがシークレットになること
        let size = proof.proof.len() as u64;
        if size < self.config.min_proof_size || size > self.config.max_proof_size {
            return Err(invalid(format!("証明の長さ {size} が範囲の外です")));
        }
        if proof.hash_algorithm.secret(&proof.proof) != proof.secret {
            return Err(invalid(format!(
                "証明がシークレット {} に合いません",
                proof.secret
            )));
        }
        let recipient = self.resolve_address(&proof.recipient_address)?;
        let key = secret_lock_key(&proof.secret, &Address(recipient));
        // Proof: ロックが生きていて（使っていない、切れていない）、ハッシュの種類が同じこと
        let algorithm = hash_algorithm_byte(proof.hash_algorithm);
        let usable = self
            .secret_locks
            .get(&key.0)
            .and_then(|history| history.last())
            .is_some_and(|lock| {
                lock.status == LockStatus::Unused
                    && height < lock.end_height
                    && lock.hash_algorithm == algorithm
            });
        if !usable {
            return Err(invalid(format!(
                "シークレットロック {key} は生きていないか、ハッシュの種類が違います"
            )));
        }
        self.touch(SubCache::SecretLockInfo, &key.0);
        self.stale_secret_locks.remove(&key.0);
        let lock = self
            .secret_locks
            .get_mut(&key.0)
            .and_then(|history| history.last_mut())
            .ok_or_else(|| invalid(format!("シークレットロック {key} がありません")))?;
        lock.status = LockStatus::Used;
        let (to, mosaic_id, amount) = (lock.recipient, lock.mosaic_id, lock.amount);
        self.credit(&to, mosaic_id, amount)?;
        self.statement
            .add_receipt(ReceiptBody::LockSecretCompleted(change(
                to, mosaic_id, amount,
            )));
        Ok(())
    }
}
