//! ブラウザの中で heika の DB を持つための部品。
//!
//! - [`OpfsFile`]: OPFS（Origin Private File System）のファイルを、redb の [`StorageBackend`] にする。
//!   同期ハンドルは Dedicated Worker の中でしか作れないので、DB は Worker が持つ
//! - [`hold_lock`]: Web Locks で、DB を持つ Worker をオリジンで1つにする。タブが閉じると放され、
//!   待っていたほかのタブの Worker が引き継ぐ
//! - [`rest`]: 公開されている REST からブロックを取って組み直す

pub mod delegation;
pub mod rest;

use std::cell::Cell;
use std::io;
use std::rc::Rc;

use heika_store_redb::StorageBackend;
use js_sys::{Function, Promise, Reflect};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    Blob, FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetFileOptions,
    FileSystemReadWriteOptions, FileSystemSyncAccessHandle, WorkerGlobalScope,
};

// JS のものは、それを作ったスレッドでしか触れない。スレッドを使う wasm（atomics）でビルドすると、
// 下の Send と Sync の約束が守れなくなるので、ビルドさせない
#[cfg(target_feature = "atomics")]
compile_error!("OpfsFile はスレッドのない wasm でだけ使えます");

/// OPFS のファイル1つ。redb の [`StorageBackend`] として、[`heika_store_redb::Db::open_with_backend`] に渡す
#[derive(Debug, Clone)]
pub struct OpfsFile(FileSystemSyncAccessHandle);

// SAFETY: スレッドのない wasm（上の compile_error! で確かめる）では、ほかのスレッドから触られることがない
unsafe impl Send for OpfsFile {}
// SAFETY: 同じ理由
unsafe impl Sync for OpfsFile {}

impl OpfsFile {
    /// OPFS の一番上の `name` を開く。なければ空で作る。Dedicated Worker の中で呼ぶ。
    ///
    /// 同期ハンドルはファイルを1人占めするので、ほかで開いたままだと失敗する。先に [`hold_lock`] で順番を待つ
    pub async fn open(name: &str) -> Result<Self, JsValue> {
        let scope: WorkerGlobalScope = js_sys::global().dyn_into()?;
        let root: FileSystemDirectoryHandle =
            JsFuture::from(scope.navigator().storage().get_directory())
                .await?
                .dyn_into()?;
        let options = FileSystemGetFileOptions::new();
        options.set_create(true);
        let file: FileSystemFileHandle =
            JsFuture::from(root.get_file_handle_with_options(name, &options))
                .await?
                .dyn_into()?;
        let handle = JsFuture::from(file.create_sync_access_handle())
            .await?
            .dyn_into()?;
        Ok(Self(handle))
    }

    /// 今の大きさ（バイト）
    pub fn size(&self) -> io::Result<u64> {
        StorageBackend::len(self)
    }

    /// 閉じる。閉じたあとは読み書きできない。ほかで同じファイルを開く前に呼ぶ
    pub fn close(&self) {
        self.0.close();
    }

    /// `blob`（画面で選んだファイルなど）を、OPFS の `name` に丸ごと写す。前の中身は捨てる。
    /// `progress` には、写したバイト数と全体のバイト数を渡す
    pub async fn import(
        blob: &Blob,
        name: &str,
        mut progress: impl FnMut(f64, f64),
    ) -> Result<Self, JsValue> {
        /// 1回に読む大きさ。大きいほど速いが、wasm のメモリに一度に置く
        const CHUNK: f64 = 16.0 * 1024.0 * 1024.0;
        let file = Self::open(name).await?;
        file.0.truncate_with_f64(0.0)?;
        let total = blob.size();
        let mut offset = 0.0;
        while offset < total {
            let end = (offset + CHUNK).min(total);
            let buffer =
                JsFuture::from(blob.slice_with_f64_and_f64(offset, end)?.array_buffer()).await?;
            let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
            file.0
                .write_with_u8_array_and_options(&bytes, &at(offset as u64))?;
            offset = end;
            progress(offset, total);
        }
        file.0.flush()?;
        Ok(file)
    }
}

async fn root() -> Result<FileSystemDirectoryHandle, JsValue> {
    let scope: WorkerGlobalScope = js_sys::global().dyn_into()?;
    JsFuture::from(scope.navigator().storage().get_directory())
        .await?
        .dyn_into()
}

/// OPFS の一番上の `name` を消す。なければ何もしない
pub async fn remove(name: &str) -> Result<(), JsValue> {
    match JsFuture::from(root().await?.remove_entry(name)).await {
        Ok(_) => Ok(()),
        Err(error)
            if Reflect::get(&error, &"name".into())?.as_string().as_deref()
                == Some("NotFoundError") =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// OPFS の一番上の `from` の名前を `to` に変える。`to` は先に消しておく。どちらも閉じてから呼ぶ
pub async fn rename(from: &str, to: &str) -> Result<(), JsValue> {
    let file = JsFuture::from(root().await?.get_file_handle(from)).await?;
    // web-sys にはまだ move がないので、JS のオブジェクトとして呼ぶ
    let rename: Function = Reflect::get(&file, &"move".into())?
        .dyn_into()
        .map_err(|_| JsValue::from("このブラウザは OPFS のファイルの名前を変えられません"))?;
    JsFuture::from(rename.call1(&file, &to.into())?.dyn_into::<Promise>()?).await?;
    Ok(())
}

fn js_error(error: JsValue) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

fn at(offset: u64) -> FileSystemReadWriteOptions {
    let options = FileSystemReadWriteOptions::new();
    options.set_at(offset as f64);
    options
}

impl StorageBackend for OpfsFile {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.get_size().map_err(js_error)? as u64)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let read = self
            .0
            .read_with_u8_array_and_options(out, &at(offset))
            .map_err(js_error)?;
        // 終わりを越えて読もうとすると短くなる。redb はぴったり読めることを前提にしている
        if read as usize != out.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.truncate_with_f64(len as f64).map_err(js_error)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.0.flush().map_err(js_error)
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let written = self
            .0
            .write_with_u8_array_and_options(data, &at(offset))
            .map_err(js_error)?;
        if written as usize != data.len() {
            return Err(io::Error::other("OPFS に書ききれませんでした"));
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        self.0.close();
        Ok(())
    }
}

/// Web Locks のロック `name` を取るまで待ち、この Worker が終わるまで持ち続ける。
///
/// すぐに取れなかったら、待ち始める前に `on_wait` を1回呼ぶ。ロックはタブを閉じたり
/// Worker を止めたりすると放され、次に待っていたものに渡る
pub async fn hold_lock(name: &str, on_wait: impl FnOnce()) -> Result<(), JsValue> {
    let scope: WorkerGlobalScope = js_sys::global().dyn_into()?;
    // web-sys の LockManager はまだ unstable の印つきなので、JS のオブジェクトとして呼ぶ
    let locks = Reflect::get(&scope.navigator(), &"locks".into())?;
    if locks.is_undefined() {
        return Err("このブラウザは Web Locks に対応していません".into());
    }
    if !request_lock(&locks, name, true).await? {
        on_wait();
        request_lock(&locks, name, false).await?;
    }
    Ok(())
}

/// `locks.request` を呼び、取れたら決して終わらない Promise を返して持ち続ける。
/// `if_available` なら待たずに、取れなかったとき `false` を返す
async fn request_lock(locks: &JsValue, name: &str, if_available: bool) -> Result<bool, JsValue> {
    let request: Function = Reflect::get(locks, &"request".into())?.dyn_into()?;
    let options = js_sys::Object::new();
    Reflect::set(&options, &"ifAvailable".into(), &if_available.into())?;

    // ロックの API が呼ぶ関数。取れたかどうかを `answer` で知らせる
    let answer = Rc::new(Cell::new(None::<Function>));
    let answered = {
        let answer = answer.clone();
        Promise::new(&mut move |resolve, _| answer.set(Some(resolve)))
    };
    let callback = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |lock: JsValue| {
        let got = !lock.is_null();
        if let Some(resolve) = answer.take() {
            let _ = resolve.call1(&JsValue::NULL, &got.into());
        }
        if got {
            Promise::new(&mut |_, _| {})
        } else {
            Promise::resolve(&JsValue::UNDEFINED)
        }
    });
    let held: Promise = request
        .call3(locks, &name.into(), &options, callback.as_ref())?
        .dyn_into()?;
    // 持っているあいだ、ロックの API から呼ばれうるものなので放さない
    callback.forget();
    // request が失敗したら held が先に reject される
    let got = JsFuture::from(Promise::race(&js_sys::Array::of2(&answered, &held))).await?;
    Ok(got.as_bool() == Some(true))
}
