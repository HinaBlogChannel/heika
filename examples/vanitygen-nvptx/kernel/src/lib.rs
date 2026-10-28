//! GPU の上で、アドレスが模様に合う秘密鍵を探すカーネル。
//!
//! 鍵を作ってアドレスにするところは heika-core をそのまま使う。

// 手元では std のまま（cdylib を作るのに要る）、GPU では std なし
#![cfg_attr(target_arch = "nvptx64", no_std)]
#![cfg_attr(target_arch = "nvptx64", feature(abi_ptx, stdarch_nvptx))]

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::network::NetworkIdentifier;

pub mod pattern;

pub use pattern::Pattern;

/// `counter` 番目の候補の秘密鍵。`seed` の先頭 8 バイトに `counter` を XOR する。
/// Symbol は秘密鍵を SHA-512 にかけてから使うので、隣どうしの候補でも鍵としては関係がない。
pub fn candidate(seed: &[u8; 32], counter: u64) -> PrivateKey {
    let mut bytes = *seed;
    for (byte, count) in bytes.iter_mut().zip(counter.to_le_bytes()) {
        *byte ^= count;
    }
    let key = PrivateKey::from_bytes(&bytes);
    zeroize(&mut bytes);
    key
}

/// `counter` 番目の候補のアドレス。
pub fn address_of(seed: &[u8; 32], counter: u64, network: NetworkIdentifier) -> Address {
    Address::from_public_key(
        &PublicKey::from_private_key(&candidate(seed, counter)),
        network,
    )
}

fn zeroize(bytes: &mut [u8; 32]) {
    for byte in bytes.iter_mut() {
        // 最適化で消されないように、volatile で書く
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

#[cfg(target_arch = "nvptx64")]
mod gpu {
    use core::arch::nvptx;
    use core::sync::atomic::{AtomicU64, Ordering};

    use heika_core::network::NetworkIdentifier;

    use crate::{Pattern, address_of};

    /// スレッドごとに `start` から数えて `per_thread` 個の候補を試し、最初に合った番号 + 1 を `found` に書く。
    /// 秘密鍵そのものは書き出さない。番号から鍵を作るのは、手元の側でする。
    ///
    /// # Safety
    /// ポインターはどれもデバイスのメモリを指していること。`found` は 8 バイトに揃っていること。
    #[unsafe(no_mangle)]
    pub unsafe extern "ptx-kernel" fn search(
        seed: *const [u8; 32],
        pattern: *const Pattern,
        start: u64,
        per_thread: u32,
        found: *mut u64,
    ) {
        let thread = unsafe {
            nvptx::_block_idx_x() as u64 * nvptx::_block_dim_x() as u64
                + nvptx::_thread_idx_x() as u64
        };
        let seed = unsafe { &*seed };
        let pattern = unsafe { &*pattern };
        let found = unsafe { AtomicU64::from_ptr(found) };
        let network = NetworkIdentifier(pattern.network);
        let first = start + thread * per_thread as u64;
        for counter in first..first + per_thread as u64 {
            if found.load(Ordering::Relaxed) != 0 {
                return;
            }
            if pattern.matches(&address_of(seed, counter, network).0) {
                let _ =
                    found.compare_exchange(0, counter + 1, Ordering::Relaxed, Ordering::Relaxed);
                return;
            }
        }
    }

    /// heika-core は `alloc` を使うので、つなぐのに要る。鍵からアドレスを作る道筋では割り当てないので、
    /// 割り当てようとしたら失敗させる（GPU の上では止まる）
    struct NoAlloc;

    unsafe impl core::alloc::GlobalAlloc for NoAlloc {
        unsafe fn alloc(&self, _: core::alloc::Layout) -> *mut u8 {
            core::ptr::null_mut()
        }

        unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: NoAlloc = NoAlloc;

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        unsafe { nvptx::trap() }
    }
}
