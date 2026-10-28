//! アドレスが模様に合う Symbol の秘密鍵を、GPU（か CPU）で探す。
//!
//! 使い方: vanitygen-nvptx [--cpu] 模様 秘密鍵を書くファイル
//!
//! 候補は「OS の乱数の種（32 バイト）に通し番号を XOR したもの」。GPU には種を渡し、当たった番号だけを返してもらう。
//! 秘密鍵は、手元で番号から作り直し、アドレスが模様に合うことを確かめてからファイルに書く。

use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use heika_core::address::Address;
use heika_core::key::{PrivateKey, PublicKey};
use vanitygen_kernel::{Pattern, address_of, candidate};

/// CPU のスレッドが 1 度に取る候補の数
const CPU_BATCH: u64 = 1 << 10;
/// 進み具合を出す間隔
const REPORT_EVERY: Duration = Duration::from_secs(5);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let cpu = match arguments.iter().position(|argument| argument == "--cpu") {
        Some(index) => {
            arguments.remove(index);
            true
        }
        None => false,
    };
    let [pattern, out] = <[String; 2]>::try_from(arguments)
        .map_err(|_| "使い方: vanitygen-nvptx [--cpu] 模様 秘密鍵を書くファイル".to_owned())?;
    let pattern = Pattern::parse(&pattern).map_err(|error| error.to_string())?;
    let out = PathBuf::from(out);
    // 何時間も探してから書けないとわかるのを避けるため、先に作っておく
    let mut file = create_secret_file(&out)?;
    let result = search_and_write(&pattern, cpu, &mut file, &out);
    if result.is_err() {
        // 見つけられなかったときは、作った空のファイルを残さない
        let _ = std::fs::remove_file(&out);
    }
    result
}

fn search_and_write(
    pattern: &Pattern,
    cpu: bool,
    file: &mut File,
    out: &Path,
) -> Result<(), String> {
    let seed =
        PrivateKey::generate().map_err(|error| format!("OS の乱数を取れませんでした: {error}"))?;
    println!(
        "ざっと {:.0} 回に 1 回当たります",
        1.0 / pattern.probability()
    );

    let search = Search {
        next: AtomicU64::new(0),
        tried: AtomicU64::new(0),
        found: AtomicU64::new(0),
    };
    let started = Instant::now();
    let (seed_bytes, pattern_ref, search_ref) = (seed.as_bytes(), pattern, &search);
    let counter = thread::scope(|scope| {
        let mut workers = Vec::new();
        if cpu {
            let count = thread::available_parallelism().map_or(1, |count| count.get());
            println!("CPU の {count} スレッドで探します");
            for _ in 0..count {
                workers.push(scope.spawn(move || cpu_worker(seed_bytes, pattern_ref, search_ref)));
            }
        } else {
            for ordinal in 0..gpu::device_count()? {
                workers.push(
                    scope.spawn(move || gpu::worker(ordinal, seed_bytes, pattern_ref, search_ref)),
                );
            }
        }
        let mut last = (started, 0);
        loop {
            thread::sleep(Duration::from_millis(100));
            if let Some(counter) = search.found() {
                return Ok(counter);
            }
            if workers.iter().all(|worker| worker.is_finished()) {
                let errors: Vec<String> = workers
                    .into_iter()
                    .filter_map(|worker| worker.join().ok()?.err())
                    .collect();
                return Err(format!("どこでも探せなくなりました: {}", errors.join("、")));
            }
            if last.0.elapsed() >= REPORT_EVERY {
                let tried = search.tried.load(Ordering::Relaxed);
                let rate = (tried - last.1) as f64 / last.0.elapsed().as_secs_f64();
                println!("{tried} 回（毎秒 {rate:.0} 回）");
                last = (Instant::now(), tried);
            }
        }
    })?;

    // GPU の答えをうのみにせず、手元で作り直して確かめる
    let private_key = candidate(seed.as_bytes(), counter);
    let public_key = PublicKey::from_private_key(&private_key);
    let address = Address::from_public_key(&public_key, pattern.network());
    if !pattern.matches(&address.0) {
        return Err(format!(
            "{counter} 番が当たったと返ってきましたが、手元で作り直すと模様に合いません"
        ));
    }
    write_secret(file, out, &private_key)?;
    println!("{:.1} 秒で見つかりました", started.elapsed().as_secs_f64());
    println!("アドレス: {address}");
    println!("公開鍵: {public_key}");
    println!("秘密鍵を {} に書きました", out.display());
    Ok(())
}

/// スレッドどうしで分け合う、探索の状態
struct Search {
    /// 次に配る通し番号
    next: AtomicU64,
    /// 試し終えた数
    tried: AtomicU64,
    /// 当たった番号 + 1。0 ならまだ
    found: AtomicU64,
}

impl Search {
    fn take(&self, count: u64) -> u64 {
        self.next.fetch_add(count, Ordering::Relaxed)
    }

    fn report(&self, counter: u64) {
        let _ = self
            .found
            .compare_exchange(0, counter + 1, Ordering::Relaxed, Ordering::Relaxed);
    }

    fn found(&self) -> Option<u64> {
        self.found.load(Ordering::Relaxed).checked_sub(1)
    }
}

fn cpu_worker(seed: &[u8; 32], pattern: &Pattern, search: &Search) -> Result<(), String> {
    let network = pattern.network();
    while search.found().is_none() {
        let start = search.take(CPU_BATCH);
        for counter in start..start + CPU_BATCH {
            if pattern.matches(&address_of(seed, counter, network).0) {
                search.report(counter);
                return Ok(());
            }
        }
        search.tried.fetch_add(CPU_BATCH, Ordering::Relaxed);
    }
    Ok(())
}

#[cfg(feature = "gpu")]
mod gpu {
    use std::sync::atomic::Ordering;

    use cudarc::driver::sys::CUdevice_attribute;
    use cudarc::driver::{CudaContext, DriverError, LaunchConfig, PushKernelArg};
    use cudarc::nvrtc::Ptx;
    use vanitygen_kernel::Pattern;

    use crate::Search;

    /// `cargo +nightly build --release -p vanitygen-kernel --target nvptx64-nvidia-cuda` で作ったもの
    const PTX: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/nvptx64-nvidia-cuda/release/vanitygen_kernel.ptx"
    ));
    /// 1 ブロックのスレッドの数
    const THREADS: u32 = 256;
    /// SM 1 つあたりのブロックの数
    const BLOCKS_PER_SM: u32 = 8;
    /// 1 スレッドが 1 回の起動で試す数
    const PER_THREAD: u32 = 16;

    pub fn device_count() -> Result<usize, String> {
        // libcuda がないと、cudarc は最初の呼び出しで panic するので、先に確かめる
        if !unsafe { cudarc::driver::sys::is_culib_present() } {
            return Err(
                "libcuda が見つからないので、GPU を使えません（--cpu なら CPU で探します）"
                    .to_owned(),
            );
        }
        let count = CudaContext::device_count()
            .map_err(|error| format!("GPU を使えません（--cpu なら CPU で探します）: {error}"))?;
        if count == 0 {
            return Err("GPU がありません（--cpu なら CPU で探します）".to_owned());
        }
        Ok(count as usize)
    }

    pub fn worker(
        ordinal: usize,
        seed: &[u8; 32],
        pattern: &Pattern,
        search: &Search,
    ) -> Result<(), String> {
        run(ordinal, seed, pattern, search).map_err(|error| format!("GPU {ordinal}: {error}"))
    }

    fn run(
        ordinal: usize,
        seed: &[u8; 32],
        pattern: &Pattern,
        search: &Search,
    ) -> Result<(), DriverError> {
        let context = CudaContext::new(ordinal)?;
        let stream = context.default_stream();
        let function = context
            .load_module(Ptx::from_src(PTX))?
            .load_function("search")?;
        let sms =
            context.attribute(CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT)? as u32;
        println!("GPU {ordinal}: {}（SM {sms} 個）", context.name()?);

        let mut seed_on_device = stream.clone_htod(seed)?;
        // Pattern は repr(C) で u8 だけからなるので、そのままのバイト列で渡せる
        let pattern_bytes: [u8; size_of::<Pattern>()] = unsafe { core::mem::transmute(*pattern) };
        let pattern_on_device = stream.clone_htod(&pattern_bytes)?;
        let mut found = stream.alloc_zeros::<u64>(1)?;
        let config = LaunchConfig {
            grid_dim: (sms * BLOCKS_PER_SM, 1, 1),
            block_dim: (THREADS, 1, 1),
            shared_mem_bytes: 0,
        };
        let batch = (sms * BLOCKS_PER_SM * THREADS) as u64 * PER_THREAD as u64;
        let result = loop {
            if search.found().is_some() {
                break Ok(());
            }
            let start = search.take(batch);
            let mut launch = stream.launch_builder(&function);
            launch
                .arg(&seed_on_device)
                .arg(&pattern_on_device)
                .arg(&start)
                .arg(&PER_THREAD)
                .arg(&mut found);
            if let Err(error) = unsafe { launch.launch(config) } {
                break Err(error);
            }
            // 読み出しが終わるのを待つので、ここで起動したカーネルも終わっている
            match stream.clone_dtoh(&found) {
                Ok(value) if value[0] != 0 => {
                    search.report(value[0] - 1);
                    break Ok(());
                }
                Ok(_) => {
                    search.tried.fetch_add(batch, Ordering::Relaxed);
                }
                Err(error) => break Err(error),
            }
        };
        // 種を GPU のメモリに残さない
        stream.memset_zeros(&mut seed_on_device)?;
        stream.synchronize()?;
        result
    }
}

#[cfg(not(feature = "gpu"))]
mod gpu {
    use vanitygen_kernel::Pattern;

    use crate::Search;

    pub fn device_count() -> Result<usize, String> {
        Err("GPU なしでビルドしました。--cpu を付けてください".to_owned())
    }

    pub fn worker(_: usize, _: &[u8; 32], _: &Pattern, _: &Search) -> Result<(), String> {
        unreachable!()
    }
}

/// 秘密を書くファイルを新しく作る。すでにあれば上書きしない。
/// ほかのユーザーから読めないように、Unix では自分だけが読み書きできるファイルにする。
fn create_secret_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|error| format!("{} を作れませんでした: {error}", path.display()))
}

fn write_secret(file: &mut File, path: &Path, private_key: &PrivateKey) -> Result<(), String> {
    // 改行を足すと String が領域を取り直して、0で上書きされない古い領域が残るので、分けて書く
    file.write_all(private_key.to_hex().as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| format!("{} に書けませんでした: {error}", path.display()))
}
