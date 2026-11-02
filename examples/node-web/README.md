# node-web

ブラウザの中に、heika のノードの DB を置く例です。ブラウザのノードに向けた最初の一歩で、今はまだ同期しません。DB を開いて、残るか、ほかのタブと取り合わないか、書き読みがどれくらい速いかを確かめます。

- DB は、ネイティブの heika と同じ redb（`heika-store-redb`）です。ファイルの代わりに OPFS（Origin Private File System、ブラウザの中のこのサイトだけのファイル）に置きます
- OPFS の同期ハンドルは Dedicated Worker の中でしか作れないので、DB は Worker が持ちます。画面とはメッセージでやり取りします
- DB を持つ Worker は、Web Locks でこのサイトに1つだけにします。2つ目のタブは、1つ目が閉じるまで待ってから引き継ぎます
- COOP や COEP のヘッダーは要りません。GitHub Pages のような、ヘッダーを変えられないところにも置けます

## 動かす

```sh
trunk serve --release
```

表示されたアドレスを開きます。OPFS と Web Locks は安全なコンテキストでしか使えないので、`localhost` か HTTPS で開いてください。

- 「開いた回数」は、開くたびに DB に書いて数えます。再読み込みして増えていれば、DB はブラウザに残っています
- 「測る」を押すと、4 KiB のバイト列をブロックの代わりに 1,000 個、1 回のコミットで書き、全部読み戻して時間を出します
- 別のタブで開くと「ほかのタブがこの DB を使っています」になり、最初のタブを閉じると引き継ぎます

データを消すときは、ブラウザでこのサイトのデータを消します。

## ライブラリとして使う

### 渡されるもの

`heika_store_redb::Db::open_with_backend` は、ファイルのパスの代わりに redb の `StorageBackend` を受け取って DB を開きます。`StorageBackend` は `heika_store_redb` から使えるので、redb の版を合わせる必要はありません。

`StorageBackend` が求める5つは、OPFS の `FileSystemSyncAccessHandle` とそのまま対応します。

| `StorageBackend` | `FileSystemSyncAccessHandle` |
|---|---|
| `len()` | `getSize()` |
| `read(offset, out)` | `read(buffer, { at })` |
| `write(offset, data)` | `write(buffer, { at })` |
| `set_len(len)` | `truncate(len)` |
| `sync_data()` | `flush()` |

この対応を書いたのが `src/lib.rs` の `OpfsFile` です。

### 最小の形

Dedicated Worker の中で書きます。

```rust
use heika_store_redb::Db;
use node_web::{OpfsFile, hold_lock};

// ほかのタブの Worker が持っていたら、閉じるまで待つ
hold_lock("my-app/db", || { /* 待っていることを画面に知らせる */ }).await?;
let file = OpfsFile::open("heika.redb").await?;
let db = Db::open_with_backend(file, 64 << 20)?;

let mut batch = db.batch()?;
batch.put_block(1, &block_bytes)?;
batch.commit()?;
```

開いたあとは、ネイティブと同じ `Db` です。

### 守ること

- `OpfsFile` は、スレッドを使わない wasm でだけ使えます。JS のものを `Send` と `Sync` にしているので、`atomics` を有効にしてビルドすると止まるようにしてあります
- 同期ハンドルはファイルを1人占めします。開く前に `hold_lock` で順番を待ってください。待たずに開くと、ほかのタブが持っているあいだは失敗します
- ロックは Worker が終わるまで持ち続けます。タブを閉じるか Worker を止めると放されます
- ブラウザには空き容量を調べる手段がないので、`Db::set_min_free` は 0 のままにします。0 でないと、書くときに失敗します
- ブラウザがサイトのデータを消すことがあります。消えても困らないように、DB は作り直せるものとして扱ってください。秘密鍵はここに置きません

### ほかの使い道

- `OpfsFile` は redb の `StorageBackend` なので、heika の DB に限らず、redb をブラウザで使いたいときにそのまま使えます
- `hold_lock` は、OPFS のほかにも「このサイトで1つだけ動かしたいもの」に使えます

## この先

ここから、公開されている REST からブロックを取り、検証して状態を進める、見るだけのノードにしていく予定です。
