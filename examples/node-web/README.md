# node-web

ブラウザの中で、Symbol のチェーンを確かめながら同期する例です。公開されている REST からブロックを取り、Nemesis から順に、署名、難易度、VRF、状態のハッシュまで確かめて実行し、DB をブラウザの中に書きます。

- REST の答えは信じません。組み直したブロックを、ネイティブの heika と同じ規則で確かめるので、どの REST から取っても、間違ったものは弾かれます。catapult の REST でも heika の REST でも使えます
- 取る区切りごとに REST を順に替えるので、1か所に負荷が寄りません
- 同期するのは、確定した高さまでです。確定した先は巻き戻ることがあるので、まだ取りません
- DB は、ネイティブの heika と同じ redb（`heika-store-redb`）です。ファイルの代わりに OPFS（Origin Private File System、ブラウザの中のこのサイトだけのファイル）に置くので、閉じても続きから始めます
- DB を持つのは Dedicated Worker で、Web Locks でこのサイトに1つだけにします。2つ目のタブは、1つ目が閉じるまで待ってから引き継ぎます
- COOP や COEP のヘッダーは要りません。GitHub Pages のような、ヘッダーを変えられないところにも置けます

今はメインネットとテストネットだけに対応しています。DB はライトのノードと同じく刈り込み、状態と木の差分は確定から 2 エポック分、ブロックとステートメントは再開に要る分だけを残します。アカウントなどの大きい状態の表も全部はメモリに持たず、ブロックごとに要る分だけを読みます。

## 動かす

```sh
trunk serve --release
```

表示されたアドレスを開き、REST のオリジン（`https://<ホスト>:3001` など）を 1 行に 1 つ入れて「同期する」を押します。OPFS と Web Locks は安全なコンテキストでしか使えないので、`localhost` か HTTPS で開いてください。

### 手元のノードの DB から始める

Nemesis から全部を確かめると、メインネットでは半日ほどかかります。heika のノードを持っていれば、その DB から始められます。

```sh
# 止めたノードの DB を、ライトの残し方で写す（設定の storage.mode を Light にしたもの。メインネットで 2 GB ほど）
heika experimental peer copy --config light.yaml --to ./light
```

画面の「手元のノードの DB から始める」で `light/heika.redb` を選ぶと、OPFS に写して、その先端から同期を続けます。

- 読み込んだところまでの履歴は確かめずに信じます。自分のノードの DB を使ってください
- 読み込んだ DB の状態が先端のブロックの StateHash と合うかは、開くときに確かめます。続きのブロックが先端につながらなければ（違うチェーンの DB なら）、同期で弾かれます
- OPFS のファイルの名前を変える `move` を使うので、対応していないブラウザでは読み込めません

データを消すときは、ブラウザでこのサイトのデータを消します。

## ライブラリとして使う

### 渡されるもの

- `heika_rest::block::BlockInfo::assemble`: `/blocks` の1件と、その高さを含む `/transactions/confirmed?embedded=true` の答えから、ブロック全体のバイト列（P2P の `Pull_Blocks` と同じ形）を組み直します。並べるだけで、中身は確かめません
- `heika_store_redb::replay::Replay`: 組み直したブロックを、Nemesis から順に確かめて実行します。heika-node の追いつく段階と同じ確かめを、スレッドなしでします。残し方（`heika_chain::chain::Keep`）を渡すと、刈り込みながら進みます。`partial` なら、アカウントなどの大きい表を全部はメモリに持たず、ブロックごとに要る分だけを DB の書きかけから読みます
- `heika_store_redb::Db::open_with_backend`: ファイルのパスの代わりに、redb の `StorageBackend` の上に DB を開きます。`StorageBackend` が求める5つは、OPFS の `FileSystemSyncAccessHandle` とそのまま対応します

| `StorageBackend` | `FileSystemSyncAccessHandle` |
|---|---|
| `len()` | `getSize()` |
| `read(offset, out)` | `read(buffer, { at })` |
| `write(offset, data)` | `write(buffer, { at })` |
| `set_len(len)` | `truncate(len)` |
| `sync_data()` | `flush()` |

この例の `src/lib.rs` に、OPFS の `OpfsFile`、Web Locks の `hold_lock`、REST から取る `rest` があります。

### 最小の形

Dedicated Worker の中で書きます。

```rust
use heika_chain::chain::Keep;
use heika_store_redb::Db;
use heika_store_redb::replay::Replay;
use node_web::rest::{self, Network};
use node_web::{OpfsFile, hold_lock};

hold_lock("my-app/db", || { /* 待っていることを画面に知らせる */ }).await?;
let network = Network::from_node_info(&rest::get_json(origin, "/node/info").await?)?;
let db = Db::open_with_backend(OpfsFile::open("heika.redb").await?, 64 << 20)?;

let light = Keep { state: 2, trie: 2, history: true };
let mut replay = Replay::open(&db, network.config.clone(), network.parameters, network.nemesis, Some(light), true)?;
let target = rest::finalized_height(origin).await?;
replay.set_target(target)?;
while replay.height() < target {
    let from = replay.height() + 1;
    for bytes in rest::fetch_blocks(origin, from, target).await? {
        replay.push(bytes)?;
    }
    replay.commit()?;
}
```

### 守ること

- `Replay::push` で弾かれたら、その `Replay` は途中まで当たった状態なので捨て、`Replay::open` で最後のコミットから開き直します。続けて弾かれるなら、別の REST から取り直します
- `Replay` は巻き戻せません。確定した高さより先は取らないでください。`set_target` に渡すのも確定した高さまでにします（そこから残す分より下の差分は、書かずに捨てます）
- 刈り込むときは、コミットのたびに古いものを 1 回 2 秒まで消します。消しきれなかった分は、次のコミットで続けます。redb はファイルを縮めないので、消した分は次に書くときに使い回されます
- `commit` するまで DB には残りません。間隔が長いと止めたときに失う分が増え、短いと書く回数が増えます。この例は 5 秒ごとです
- `OpfsFile` は、スレッドを使わない wasm でだけ使えます。JS のものを `Send` と `Sync` にしているので、`atomics` を有効にしてビルドすると止まるようにしてあります
- 同期ハンドルはファイルを1人占めします。開く前に `hold_lock` で順番を待ってください
- ブラウザには空き容量を調べる手段がないので、`Db::set_min_free` は 0 のままにします
- ブラウザがサイトのデータを消すことがあります。DB は作り直せるものとして扱い、秘密鍵は置きません

### ほかの使い道

- `assemble` と `Replay` は、ネイティブでも動きます。REST しか開いていないところから、確かめながら DB を作れます（`crates/heika-vectors/tests/rest_replay.rs`）
- `OpfsFile` は redb の `StorageBackend` なので、heika の DB に限らず、redb をブラウザで使いたいときにそのまま使えます
- `hold_lock` は、OPFS のほかにも「このサイトで1つだけ動かしたいもの」に使えます

## この先

- 状態を全部はメモリに持たない
- 確定した先の先端を追い、ハーベストする
