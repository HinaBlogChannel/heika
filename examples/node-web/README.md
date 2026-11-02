# node-web

ブラウザの中で、Symbol のチェーンを確かめながら同期する例です。公開されている REST からブロックを取り、Nemesis から順に、署名、難易度、VRF、状態のハッシュまで確かめて実行し、DB をブラウザの中に書きます。

- REST の答えは信じません。組み直したブロックを、ネイティブの heika と同じ規則で確かめるので、どの REST から取っても、間違ったものは弾かれます。catapult の REST でも heika の REST でも使えます
- 取る区切りごとに REST を順に替えるので、1か所に負荷が寄りません
- 確定した高さまでは、まとめて取って確かめながら進めます。追いついたら、その確定の証明を、実行して求めた投票者で確かめてしまい、そこから先はネイティブの heika と同じ中核（`heika_chain::chain::Chain`）で先端を追います。確定した先は巻き戻ることがあるので、枝の取り替えもする中核に任せます。確定が先に進みすぎたら、まとめて進める段階に戻ります
- 先端を追うあいだ、ハーベストもできます。ブラウザのノードの公開鍵に委任してもらい、当たりの時刻が来たらブロックを作って、heika のノードの REST（`PUT /blocks`）に出します
- DB は、ネイティブの heika と同じ redb（`heika-store-redb`）です。ファイルの代わりに OPFS（Origin Private File System、ブラウザの中のこのサイトだけのファイル）に置くので、閉じても続きから始めます
- DB を持つのは Dedicated Worker で、Web Locks でこのサイトに1つだけにします。2つ目のタブは、1つ目が閉じるまで待ってから引き継ぎます
- COOP や COEP のヘッダーは要りません。GitHub Pages のような、ヘッダーを変えられないところにも置けます

メインネットとテストネットは、設定を持っています。ほかのネットワーク（プライベートなネットワークなど）は、その設定ファイルと Nemesis のハッシュを入れれば同期できます。DB はライトのノードと同じく刈り込み、状態と木の差分は確定から 2 エポック分、ブロックとステートメントは再開に要る分だけを残します。アカウントなどの大きい状態の表も全部はメモリに持たず、ブロックごとに要る分だけを読みます。

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

### 自分のネットワークを同期する

メインネットとテストネットのほかは、画面の「自分のネットワーク」に次のものを入れてから同期します。

- ノードの `resources` フォルダーの `config-network.properties`、`config-inflation.properties`、`config-finalization.properties`（3つまとめて選べます）
- Nemesis のブロックのハッシュ（16 進）

REST の generation hash seed が入れた設定と合えば、その設定で確かめます。ルールは REST からもらいません。何で確かめるかを REST に決めさせると、REST を信じないことにならないからです。入れたものは秘密ではないので、このサイトの localStorage に覚えておきます。DB のファイルはネットワークごとに分け、名前は `private-` に generation hash seed の頭 8 桁を付けたものです。

heika のノードしかないネットワークでは、heika の REST を入れます。確定までの同期に使う証明は `/finalization/proof/epoch/{epoch}` から取ります。

### ハーベストする

ブラウザのノードは、初めて開いたときに自分の鍵を作り、画面の「ハーベストする」に公開鍵を出します。この公開鍵を委任先にして委任してもらうと、届いた委任でハーベストします。heika の CLI なら次のとおりです。

```sh
heika harvesting --delegate <ノードの公開鍵> …
```

「ハーベストする」に印を付け、作ったブロックを出す heika のノードの REST を入れてから同期します。確定した先の先端を追い始めると、委任の要求を探して、使えるものを確かめます。そのあと当たりの時刻を求めて、画面に出します。時刻が来たらブロックを作って自分の先端に足し、出す先の REST に `PUT /blocks` で出します。

- ノードの秘密鍵は、X25519 の鍵にして Web Crypto に読み出せない鍵（non-extractable な `CryptoKey`）として渡し、IndexedDB にしまいます。元の秘密鍵はその場で捨てます。ページの JS からも鍵の中身は読めず、ブラウザに X25519 を頼むだけです
- 委任の要求は、ノードのアドレスあての送金を REST（`/transactions/confirmed`）で探します。heika の REST なら、そのノードが検索の表（`storage.search` の `Transactions`）を作っていないと探せません。REST は信じません。開いたリモートと VRF の鍵は、自分で確かめた状態で、メインアカウントのリモート、VRF、ノードの紐づけと合うときだけ使います。REST が要求を隠せば委任を受け損ねますが、偽の委任を受けることはありません
- 開いたリモートと VRF の鍵は、メモリにだけ置きます。1 分ごとに要求を探し直し、紐づけを確かめ直します。紐づけを外した委任は、そこで使わなくなります
- サイトのデータを消すとノードの鍵も消えるので、委任をやり直すことになります
- 鍵を直接入れてもハーベストできます（委任と合わせて使えます）。直接入れた鍵も、メモリにだけ置きます
- catapult の REST には、ブロックを受け取る口がありません。出す先は heika のノードにします。取る REST は、今までどおりどれでもかまいません
- 当たりの見込みをメーターで見せます。次の当たりまでの残りの秒数と、その当たりで作れる見込み（ほかのだれにも先を越されない見込み。同じ秒に並べば半々に数えます）、1 ブロックあたりの見込みと、平均でどのくらいに 1 回作れるかです。hit は指数分布で、的は Importance に比例するので、ハーベストしている Importance の合計を直近のブロックの間隔と難易度から最尤推定で見積もれます。ブロックは的が hit を超えた最初の整数秒に作られるので、経過 k 秒のブロックは「k − 1 秒から k 秒のあいだに超えた」として数えます。そこから、1 ブロックあたりの見込みは「自分 ÷ 合計」になります（`heika_chain::outlook`）。見積もりは直近の 60 ブロックほどからなので、少しぶれます
- 当たりが 1 分より近づくと、未承認のトランザクションを REST（`/transactions/unconfirmed`）から 5 秒ごとに取り、未承認の置き場（`heika_mempool::Mempool`）に入れます。置き場は、受け付けるときに署名と規則を確かめます。残高などの状態に依ることは、ブロックを作るときに確かめ、通らないものは外します。なので、REST が偽のトランザクションを返しても、作るブロックには入りません。当たりが遠いうちは取りに行かないので、REST への負荷はわずかです
- 連署を待つアグリゲートボンデッドは、まだ入れません
- 当たりの時刻は、ブラウザの時計で測ります。時計がずれていると、ほかのノードに受け入れられません
- 出したブロックを足すかは、受け取ったノードのチェーンが決めます。ほかのブロックに負ければ、こちらの先端も枝の取り替えで戻ります

データを消すときは、ブラウザでこのサイトのデータを消します。

## ライブラリとして使う

### 渡されるもの

- `heika_rest::block::BlockInfo::assemble`: `/blocks` の1件と、その高さを含む `/transactions/confirmed?embedded=true` の答えから、ブロック全体のバイト列（P2P の `Pull_Blocks` と同じ形）を組み直します。並べるだけで、中身は確かめません
- `heika_store_redb::replay::Replay`: 組み直したブロックを、Nemesis から順に確かめて実行します。heika-node の追いつく段階と同じ確かめを、スレッドなしでします。残し方（`heika_chain::chain::Keep`）を渡すと、刈り込みながら進みます。`partial` なら、アカウントなどの大きい表を全部はメモリに持たず、ブロックごとに要る分だけを DB の書きかけから読みます
- `heika_chain::chain::Chain::set_harvesters` と `Chain::harvest_plan`: 先端を追う中核に鍵を渡すと、当たりの時刻を求めてブロックを作り、ピアへの押し付け（`PeerCommand::Push`）として返します。この例は、それを `PUT /blocks` に出します。`harvest_plan` で次の当たりを読めます
- `heika_wallet::harvest_request::decode_x25519`: 委任の要求を、ノードの秘密鍵の代わりに X25519 の結果で開きます。catapult は共有した点を Edwards の形（y と x の符号）で使いますが、X25519 の結果には x の符号がありません。両方を試し、AES-GCM の認証タグで合うほうを選びます。ノードの鍵を X25519 の鍵にするのは `heika_wallet::cipher::x25519_private_key`、要求の使い捨ての鍵を X25519 の公開鍵にするのは `harvest_request::x25519_ephemeral_key` です
- `heika_chain::chain::Chain::harvest_outlook`: ハーベストの見込みです。ハーベストしている Importance の合計の見積もり、1 ブロックあたりの見込み、次の当たりで作れる見込みを返します。画面に見せるための見積もりで、合意には使いません
- `heika_mempool::Mempool` と `SharedMempool`: 未承認の置き場です。`Chain::set_pending` に渡すと、ブロックを作るときに候補をもらい、入ったもの、戻ったもの、弾かれたものを `Action::Included`、`Action::Restored`、`Action::Dropped` で知らせてきます
- `heika_harvesting::unlocked::check` と `choose`: 開いた委任が今の状態で使えるか（catapult と同じ3つの紐づけ）を確かめ、重要度の大きい順に選びます
- `heika_store_redb::Db::open_with_backend`: ファイルのパスの代わりに、redb の `StorageBackend` の上に DB を開きます。`StorageBackend` が求める5つは、OPFS の `FileSystemSyncAccessHandle` とそのまま対応します

| `StorageBackend` | `FileSystemSyncAccessHandle` |
|---|---|
| `len()` | `getSize()` |
| `read(offset, out)` | `read(buffer, { at })` |
| `write(offset, data)` | `write(buffer, { at })` |
| `set_len(len)` | `truncate(len)` |
| `sync_data()` | `flush()` |

この例の `src/lib.rs` に、OPFS の `OpfsFile`、Web Locks の `hold_lock`、REST から取る `rest`、委任を受ける `delegation` があります。

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
- ブラウザがサイトのデータを消すことがあります。DB は作り直せるものとして扱い、秘密鍵は置きません。ハーベストの鍵も、メモリにだけ持ちます。ノードの鍵は、読み出せない `CryptoKey` にしてしまいます
- 中核は、作ったブロックを、つないでいるピアの数だけ押し付けます。REST の1つを1つのピアにしているので、同じブロック（同じ `Arc`）は1回だけ出します

### ほかの使い道

- `assemble` と `Replay` は、ネイティブでも動きます。REST しか開いていないところから、確かめながら DB を作れます（`crates/heika-vectors/tests/rest_replay.rs`）
- `OpfsFile` は redb の `StorageBackend` なので、heika の DB に限らず、redb をブラウザで使いたいときにそのまま使えます
- `hold_lock` は、OPFS のほかにも「このサイトで1つだけ動かしたいもの」に使えます

## この先

- 連署のそろったアグリゲートボンデッドも入れる
