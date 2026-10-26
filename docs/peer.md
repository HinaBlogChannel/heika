# 試験的なノード

`heika experimental peer start` は、heika をピアとしてネットワークに入れる。試験的なので、コマンドの形も設定の中身も、断りなく変わる。

## できること

- メインネット、テストネット、決め打ちの値のないネットワーク（プライベートなネットワークなど）に、ピアとして入る
- 確定したところまでは、いくつかのピアからまとめて取って実行する（追いつく段階）。そのあとは、届いたブロックを1つずつ確かめて先端を追い、枝を取り替える（先端の段階）。押し付けられたブロックは、先端の次につながるものに加えて、先端と同じ親の上でスコアの高いもの（時刻の早いもの）なら先端と差し替える。catapult と同じく、押し付けで巻き戻すのは先端の1つだけで、深い枝は統計を聞いて取りに行く。押し付けられて受け入れたブロックは、作ったブロックと同じく、つないでいるピアに流す（catapult と同じ）。確定から遅れれば、また追いつく段階に戻る
- ブロックの署名、難易度、VRF の証明とハーベストの当たり、トランザクションの中身、StateHash と ReceiptsHash、ファイナライズの証明（投票の署名と重み）まで、自分で確かめる
- 残し方をアーカイブ、フル、ライトから選ぶ
- 接続を受けて、ほかのノードの問い合わせに答える。名乗るロールは設定で決められ、P2P と REST で同じものを名乗る
- ファイナライズの投票を見る、または投票する（`finalization` を書いたとき）。投票するピアから投票のメッセージを引いて catapult と同じ規則で数え、自分で出した確定を、届いた証明と比べる。投票の鍵があれば、catapult と同じ時に prevote と precommit を出して配る
- REST の口を立てる（`rest` を書いたとき）
- ハーベストする（キーストアのアカウントを `--harvest` で渡すか、鍵のファイルを設定に書いたとき）
- ほかの人の委任ハーベストを引き受ける（`delegations` を書いたとき）
- 押し付けられた未承認のトランザクションを受け付けて、作るブロックに入れ、`Pull_Transactions` に答える。受け付けるときに確かめるのは、署名、連署、トランザクションごとの規則、期限、手数料までで、残高など状態に依ることは、ブロックを作ってみて弾かれたら外す。catapult と同じく、つないでいるピアに順に `Pull_Transactions` で頼み、持っていないものを集める（5 秒ごとに1つのピア）ので、待ち受けていないノードにも集まる。初めて受け付けたもの（REST の `PUT /transactions`、押し付けられたもの、頼んで集めたもの）は、つないでいるピアのみなに押し付ける（集めたものは、そのピアには送り返さない）。受け付けるのは初めて見たときだけなので、ピアのあいだを回り続けることはない
- 連署を待つアグリゲートボンデッドは、別の置き場で待たせる（catapult の partialtransaction 拡張と同じやりとり）。受け付けるときは、ハッシュロックが確定して使えることと、連署できる人かを、今の状態で確かめる。連署が揃ったら、連署を付けて未承認のトランザクションにする。連署を待つものと連署は、Api のロールのピアにだけ押し付け、そこから順に頼んで集める。catapult は partialtransaction 拡張を Api のノードにだけ入れ、入れていないノードはこのやりとりを知らない要求として接続を切るためである。ブロックに入ったものと、期限が過ぎたものは外す
- SIGINT か SIGTERM で、今のブロックを書き終えてから止まり、次に始めると続きから進む

## コマンドの例

```sh
heika experimental peer start --config peer.yaml
```

```sh
heika harvesting --network mainnet --link-derived main --out link.bin
heika tx sign --network mainnet --wallet-account main --out link.signed.bin link.bin
heika tx announce --network mainnet --connect <ホスト>:<ポート> --client-cert node.full.crt.pem link.signed.bin < node.key.pem
heika experimental peer start --config peer.yaml --harvest main
```

`--harvest <ラベル>` を付けると、起動するときにキーストアのパスフレーズを聞き、そのアカウントのリモートと VRF の鍵を導出して、ノードのメモリにだけ渡す。鍵はディスクに書かないので、止めて起動し直すたびにパスフレーズを聞く。先に `heika harvesting --link-derived` で、同じ鍵をチェーンに紐づけておく。`--keystore`、`--passphrase-file`、`--expert` は `heika wallet` と同じ。

前で動き、様子を標準出力と標準エラーに出す。止めるときは Ctrl+C か `kill <pid>`（SIGTERM）にする。DB は書きかけで落ちても壊れないが、SIGKILL で止めると、次に開くときに直すのに時間がかかる。

## 設定

Kubernetes のマニフェストのように、`apiVersion`、`kind`、`metadata`、`spec` を持つ YAML で書く。知らないキーは、綴りの間違いが黙って既定値にならないように弾く。`v1alpha1` のあいだは、中身が変わっても版は上げない。

```yaml
apiVersion: heika.hinablogchannel.github.io/v1alpha1
kind: Peer
metadata:
  name: my-peer
spec:
  network:
    type: mainnet          # mainnet / testnet / custom
  dataDirectory: /path/to/data
  certificates:
    directory: /path/to/certificates
  seed: <ホスト>:7900
  storage:
    mode: light            # archive / full / light
```

- `network.type`: `mainnet` と `testnet` は、ネットワークの設定（`config-network.properties` などにあたる値）を heika が持っているので、ほかに何も要らない。`network.resources` にノードの `resources` フォルダーを書けば、代わりにそこから読む（ネットワークの設定が変わって、heika がまだ追いついていないときなど）。`custom` には、`network.resources` と、`network.nemesisHash`（Nemesis のブロックのハッシュ）か `network.nemesisSeed`（Nemesis の seed フォルダー）が要る。`nemesisSeed` を書くと、DB が空ならピアから取らずにそこの Nemesis から始め、住所録のノードにつながらなくても先端の段階に進む。新しいネットワークの最初のノードに使う（[nemesis.md](nemesis.md)）。ただし、同じチェーンのピアが1つもいないあいだはハーベストしないので、ブロックができ始めるのは2台目がつながってから
- `dataDirectory`: ブロックと状態をしまうフォルダー
- `certificates.directory`: `tls.crt`（ノードの証明書と CA の証明書の鎖）と `tls.key`（ノードの鍵）のあるフォルダー。`heika cert ca` と `heika cert node` で作れる。同じ IP から違う証明書で次々につなぐとほかのノードに嫌われるので、いつも同じ証明書を使う
- `seed`: 住所録が空か、どこにもつながらないときに、最初につなぐノード（`ホスト:ポート`）。そのノードからほかのノードの一覧をもらい、住所録に足していく
- `peers`: 先端の段階でつないでおくピアの数。既定は 8
- `minFreeGigabytes`: ディスクの空きがこれより少なければ、書く前に止める。既定は 10
- `storage`: 何を残すか（下の「残し方」）
- `listen`: 接続を受ける。`address`（`0.0.0.0:7900` など）、`publicHost`（ほかのノードに名乗るホスト名。なければ相手が接続元から決める）、`friendlyName`、`roles`（名乗るロール。`0x03` や `3` のような整数か、`[Peer, Api]` のような名前の並び。P2P でも REST の `/node/info` でも同じものを名乗る。なければ Peer に、`rest` があれば Api を、投票するなら Voting を足す。メインネットの catapult と同じく IPv4 は立てない（catapult は、IPv4 も IPv6 もなければ IPv4 とみなす）。Peer は外せない）。なければ、自分からつなぐだけ
- `harvesters`: 鍵のファイルでハーベストするときの、鍵の組の並び。キーストアのアカウントでハーベストするなら、ここには書かずに `--harvest` を使う。`signer`（ブロックに署名する鍵。メインアカウントか、リンクしたリモートの鍵）と `vrf`（リンクした VRF の鍵）に、鍵のファイルの場所を書く。鍵は PEM、DER、16進のどれでも読む。持ち主のほかも読めるファイルなら警告を出す
- `beneficiary`: 作るブロックの受取先のアドレス（報酬のうち受取先の分を受け取る）。なければ、ハーベストした鍵のアドレス。委任を引き受けるなら、運営者のアドレスを書く
- `delegations`: ほかの人の委任ハーベストを引き受ける。書かなければ引き受けない。`max`（引き受ける数の上限。既定は 5 で、超えたら重要度の大きい順）と `key`（委任の鍵のファイル。なければ TLS のノードの鍵 `tls.key`）を書ける。下の「委任を引き受ける」を見る
- `rest`: REST の口で待ち受けるアドレスの並び（`- address: 127.0.0.1:3000` の形）。書かなければ立てない。下の「REST」を見る。口ごとに `rateLimit` で 1 秒あたりに答える要求の数を絞る（既定 60、0 なら絞らない）。どの道への要求も数え、超えたら 429
- `finalization.observe`: `true` にすると、ファイナライズの投票を見る。投票はしない。つないでいるピアのうち投票するもの（Voting のロール）から投票のメッセージを引いて catapult と同じ規則で数え、自分で確定を出して証明を組み、ピアから届いた証明と同じラウンドになったところで比べてログに出す。組んだ証明は、ピアから届いた証明と同じに確かめて、中核の確定にも使う（catapult も自分で組んだ証明をしまう）。そのため、catapult のいない heika だけのネットワークでもエポックが進む。つないでいるピアに投票するものがなければ、何も数えない
- `finalization.votingKeys`: 投票の鍵のフォルダー（catapult の `votingkeys` と同じ。`private_key_tree1.dat` から順に番号を振って置く。`heika key voting generate` で作れる）。書くと投票する（`observe` も有効になる）。ロールを書いていなければ Voting も名乗る。prevote と precommit を catapult と同じ時に出し、投票するピアに配る。ピアから届いた投票も、新しく足せたものはほかの投票するピアに配り、引かれれば返す。前のエポックの鍵は使ったら消し、どのラウンドで何を出したかをデータのフォルダーの `voting_status.dat` に書く。どちらも、ディスクに届いてから投票を配るので、落ちて起き直しても、同じ段階をもう一度出さず、消した鍵にも戻らない。投票するには、アカウントに最低残高（メインネットは 3M XYM）と、投票の鍵のリンク（VotingKeyLink）が要る

## 残し方

`storage.mode` で選ぶ。既定は `full`。

| | 状態と状態の証明 | ブロックとステートメント | ファイナライズの証明 |
|---|---|---|---|
| `archive` | 全部の高さ | 全部 | 全部 |
| `full` | 確定より 2 エポック下まで | 全部 | 全部 |
| `light` | 確定より 2 エポック下まで | 再開に要る分だけ | 最近の分だけ |

- `archive`: 昔のどの高さの状態も、その高さの StateHash への証明つきで引ける
- `full`: 昔からのブロックを全部持つので、新しく入ってくるノードに渡せる
- `light`: いちばん軽い。アカウントの表も全部はメモリに持たず、要るものだけを読む

一度動かしたデータより重い残し方（たくさん残す方）では起動しない。消したものは戻らないので、たとえば `light` で動かしたデータを `archive` にはできない。軽くする方は、刈り込めばよいのでできる。重くしたいときは、`dataDirectory` を空にして最初から追いつき直す。

軽くするとき、その場で刈り込むと、消すものが多くて時間がかかり、DB のファイルも縮まない。止めたノードから、残すものだけを写した新しい DB を作れる。

```sh
heika experimental peer copy --config light.yaml --to <新しいフォルダー>
```

`--config` の `dataDirectory` の DB を、その設定の `storage.mode` の残し方で刈り込んで、`--to` のフォルダーに写す。たとえばアーカイブのデータを指し、`storage.mode` だけを `light` にした設定を渡すと、ライトの写しができる。`archive` なら全部写すので、詰め直しになる。ノードを止めてから使い（動いていれば DB を開けずに止まる）、`--to` に DB がもうあれば写さない。できた写しを `dataDirectory` に置き換えて起動する。

`storage.partialState` は、アカウントの表を全部はメモリに持たずに要るものだけを読むかで、`light` ではいつも真、ほかは書かなければ真。`storage.cache.stateMegabytes`（既定 64）と `storage.cache.databaseMegabytes`（既定 256）で、読んだ状態と DB のキャッシュの量を決める。

`storage.search` に名前を並べると、REST の検索のための検索表を DB に作る（たとえば `search: [metadata]`）。書かなければ作らないので、ライトの軽さはそのまま。今の状態の行を別の切り口で並べ直しただけのもので、ブロックと同じ書き込みで直し、巻き戻しでは状態の差分から戻す。途中で足せば、起動したときに今の状態の行から作る（メインネットのメタデータ 12 万件なら数秒）。外せば、その行を消す（詰め直すなら `peer copy`）。`storage.mode: archive` なら、検索表から消えたキーも残し、`?height=` 付きで昔の高さでも検索できる（候補を両方の表から取り、その高さの状態の行で確かめる）。アーカイブで途中から足せば、状態の差分の前の値から作る。ほかの残し方では、今の状態だけを検索できる。

| 名前 | 答える検索 |
|---|---|
| `metadata` | `/metadata` を、送り主、宛先、対象（モザイクかネームスペース）から引く |
| `namespaces` | `/namespaces` を、持ち主と別名（アドレスかモザイク）から引く。ネームスペースの名前の表も作り、`/namespaces/names`、`/namespaces/account/names`、`/namespaces/mosaic/names` に答える |
| `transactions` | トランザクションのハッシュから入った高さとブロックの中の番号を引く表と、関わったアドレスから引く表を作る。`/transactions/confirmed/{hash}` と `/transactionStatus/{hash}` に直近のブロックより前のものも答え、`/transactions/confirmed?address=` の検索に答える。ブロックから作るので、途中で足せば、起動したときにしまってあるブロックを全部読む（止めても続きから）。ブロックを刈り込む残し方では、刈り込んだブロックの分は答えない |

ネームスペースの名前は状態の木になく、登録のトランザクションにしかないので、名前の表はブロックから拾う。ID は親と名前から決まるので、ID と合う登録だけを入れ、足すだけで消さない（どのブロックから拾っても正しい）。`namespaces` を足したら、起動したときに、しまってあるブロックから拾う（止めても、次の起動で続きから）。ライトは古いブロックを持たないので、名前を知っているのは、しまってあるブロックとその後に登録されたものだけで、知らない名前は返さない。

## 委任を引き受ける

`delegations` を書くと、catapult のノードと同じ形で、ほかの人の委任ハーベストを引き受ける。

- 委任する人は、リモートの鍵（AccountKeyLink）、VRF の鍵（VrfKeyLink）、ノードの委任の鍵（NodeKeyLink）をメインアカウントにリンクし、委任の鍵のアドレスあてに委任の要求（リモートと VRF の秘密鍵を、委任の鍵あてに暗号化したメッセージ）を送る。委任の鍵とそのアドレスは、起動したときに出す
- ノードは、catapult と同じく、先端に足したブロックを高さの順に読み、要求を拾う。委任する人を確定まで待たせないため。枝を取り替えたら、分かれ目から読み直す。初めて動かしたときは、そのときの先端より後に届いた要求から読む
- 引き受けるのは、リモートの鍵のアカウントがメインアカウントにリンクしていて、メインアカウントの3つのリンクが要求とこのノードの委任の鍵に合うときだけ。ブロックを足すたびに確かめ直し、リンクを外したり、ほかのノードに付け替えたりしたものは外す。リンクと要求の入ったブロックが巻き戻れば、リンクもなくなるので、ここで外れる
- 上限を超えたら、重要度の大きい順に選ぶ。超えた分も取り込めるものとして残し、空きができたら使う
- 引き受けている要求は、暗号化したまま `dataDirectory` の `harvesters.dat`（catapult と同じ形）に、どこまで読んだかは `harvesters.height` にしまう。届いた要求ごとの様子（下の `/heika/delegations` が返すもの）は `delegations.yaml` にしまい、起動し直しても残る
- 委任の鍵は、既定では TLS のノードの鍵を使う。`key` で別の鍵にできるが、そのときは委任する人に、その鍵に NodeKeyLink を向けてもらう

## REST

`rest` を書くと、ノードと同じプロセスで REST の口を立てる。catapult の REST のうち、ウォレットが委任に使う口、トランザクションを送る口、heika のウォレットが残高と送金を確かめるのに使う口に同じ形で答え、heika だけの口も足す。`heika account show --rest` をこのノードに向ければ、残高を状態の木の根まで確かめられる。どこのページからでも読めるように、CORS は開けてある。

| 口 | 返すもの |
|---|---|
| `/node/info` | ノードの身元。`nodePublicKey` は委任の鍵（委任する人が NodeKeyLink を向ける鍵） |
| `/node/peers` | 知っているピア（ピアの名簿の問い合わせに答えるものと同じ）。GUI のノードは、ここから最初のつなぎ先を選ぶ |
| `/chain/info` | 高さ、スコア、確定したブロック |
| `/network`、`/node/server`、`/node/health` | ネットワークの名前（`mainnet` など）、REST の版（heika の版。配った道具は `heika`）、動いているか（同じプロセスなので、答えられれば `up`）。ノードの一覧を作るクローラーが、最初に叩く |
| `/node/unlockedaccount` | 引き受けて、ハーベストしている委任のリモートの鍵 |
| `/heika/sourcecode.zip` | このノードのソース（`heika legal source` と同じ、バイナリに入れた ZIP）。手を入れてビルドしたなら、そのソースが返る。AGPL-3.0 の 13 条のため。ソースの入っていないバイナリなら 404 |
| `/heika/delegations` | 届いた委任の要求ごとに、引き受けたか（`accepted`）、上限を超えて待っているか（`waiting`）、引き受けなかったか（`rejected`。`reason` にわけ） |
| `/accounts/{accountId}` | アカウントの今の状態。ID はアドレス（Base32 か16進）か公開鍵 |
| `/mosaics/{mosaicId}` | モザイクの定義の今の状態 |
| `POST /accounts`、`POST /mosaics` | まとめて引く。本文は catapult の REST と同じく `{"addresses": [...]}` か `{"publicKeys": [...]}`（両方は 409）、`{"mosaicIds": [...]}`。配列の代わりに1つの文字列でもよい。あるものだけを頼んだ順に、同じものは1回だけ返す。全部を同じ高さで読む。1回に 1000 件まで（catapult には上限がない） |
| `/account/{address}/multisig` | マルチシグの今の状態。連署者（`cosignatoryAddresses`）と、連署者として入っているマルチシグ（`multisigAddresses`）。連署者にしかなっていないアカウントにもある。ID はアドレス（Base32 か16進）で、公開鍵では引けない（catapult と同じ） |
| `/account/{address}/multisig/graph` | そのアカウントから上と下にたどったマルチシグの木。catapult の REST と同じく、段（`level`。0 が引いたアカウント、負は上、正は下）ごとに、前の段の全員の上か下のアドレスを集めて引いたもの。上の段から順に並ぶ。全部を同じ高さで読む |
| `/lock/hash/{hash}`、`/lock/secret/{compositeHash}` | ハッシュロックとシークレットロック。ID はロックしたアグリゲートのハッシュと、シークレットと受取人から求めたハッシュ。catapult の REST と同じく、使ったもの（`status` が 1）や期限を過ぎたものも、状態に残っていれば返す（状態の木に入るのは、まだ使っておらず期限前のものだけ） |
| `/restrictions/account/{address}`、`/restrictions/mosaic/{compositeHash}` | アカウントの制限と、モザイクの制限（`entryType` が 0 ならアドレスごとの値、1 ならモザイク全体の決まり） |
| `POST /lock/hash`、`POST /lock/secret`、`POST /restrictions/account`、`POST /restrictions/mosaic` | まとめて引く。本文は catapult の REST と同じく `{"hashes": [...]}`、`{"compositeHashes": [...]}`、`{"addresses": [...]}`。答え方と上限は `POST /accounts` と同じ。アドレスやモザイクから探す検索（`/lock/hash?address=` など）は、まだない |
| `/namespaces/{namespaceId}` | ネームスペースの今の状態。ルートでも子でも引ける。期限の高さ（`endHeight`。catapult と同じく、猶予の 30 日を足した高さ）を過ぎたものも、状態に残っていれば返し、`active` が `false`（状態の木からは外れている）。catapult の `meta.index`（持ち主の履歴の番号）は返さない |
| `/metadata/{compositeHash}` | メタデータの今の状態。ID は1件を指すハッシュ（`compositeHash`） |
| `/metadata` | メタデータの検索。`storage.search` に `metadata` があるときだけで、なければ 501。catapult の REST と同じく `sourceAddress`、`targetAddress`、`scopedMetadataKey`、`targetId`、`metadataType` で絞り、`pageSize`（10 から 100）と `pageNumber` でページを送る。並びは登録の順ではなく項目の順（`order=desc` で逆）。1件ごとの `id` は MongoDB の ID ではなく、その件の位置（送り主、種類、宛先、対象の ID、キーをつないだ16進）。前のページの最後の `id` を `offset` に渡すと、その次から返す。飛ばす分をなめないので、`pageNumber` で送るより深いページが速い。`?height=` はアーカイブだけで、ほかは 501 |
| `/namespaces` | ネームスペースの検索。`storage.search` に `namespaces` があるときだけで、なければ 501。catapult の REST と同じく `ownerAddress`、`level0`、`registrationType`、`aliasType` で絞る。ページ送り、`id` と `offset`、アーカイブでの `?height=` はメタデータの検索と同じ（`id` は検索表のキーの16進で、同じ絞り込みの検索の `offset` にだけ渡せる） |
| `POST /namespaces/names` | `{"namespaceIds": [...]}` の ID と、その親の名前（自分の部分）。名前を知らないものは返さない。1回に 100 件まで |
| `POST /namespaces/account/names`、`POST /namespaces/mosaic/names` | `{"addresses": [...]}` か `{"mosaicIds": [...]}` を別名にしている、今有効なネームスペースの名前（`symbol.xym` のようにルートからつないだもの）。1回に 100 件まで |
| `/accounts/{accountId}/merkle`、`/account/{address}/multisig/merkle`、`/lock/hash/{hash}/merkle`、`/lock/secret/{compositeHash}/merkle`、`/restrictions/account/{address}/merkle`、`/restrictions/mosaic/{compositeHash}/merkle`、`/mosaics/{mosaicId}/merkle`、`/namespaces/{namespaceId}/merkle`、`/metadata/{compositeHash}/merkle` | 状態の木の、根からその葉への道（`raw`）。ないことを示す道も返す。ネームスペースの木の葉はルートごとなので、子の ID ではないことを示す道になる（catapult と同じ） |
| `/blocks/{height}` | ブロックのヘッダーと、その高さの9本の根。根はその高さの木から求め直すので、差分を刈り込んだ高さ（フルの残し方での古いブロック）は 404 |
| `/network/fees/transaction` | 直近 300 ブロックの手数料の倍率（平均、中央値、最高、最低）と、ノードが受け付ける下限 |
| `/network/properties` | ネットワークの設定（catapult の `config-network.properties`）。catapult の REST と同じ書き方（`6h`、`0x6BED'913F'A202'23F8` など）で返す。heika が持っていない `maxRollbackBlocks`、`initialCurrencyAtomicUnits`、`reservedRootNamespaceNames` はない |
| `/transactionStatus/{hash}` | 送ったトランザクションの行方。メモリプールにあれば `unconfirmed`、直近のブロック（`storage.search` に `transactions` があれば、しまってある全部のブロック）に入っていれば `confirmed` と高さ |
| `/transactions/confirmed` | 承認されたトランザクションの検索。catapult の REST と同じく、`address`（関わったアドレス。catapult の `meta.addresses` と同じく、署名者、宛先などのトランザクションの種類ごとに決まった相手、アグリゲートの中の署名者と相手、エイリアスを解決した先。連署者は入らない）、`signerPublicKey`、`recipientAddress`（送金、シークレットロック、シークレットの証明の宛先）、`type`（何回でも書ける）、`transferMosaicId` と `fromTransferAmount`、`toTransferAmount`（送金のモザイクと額。額はモザイクとは別に、どれかが範囲に入ればよい。catapult と同じ）、`height`、`fromHeight`、`toHeight` で絞る。`address`、`signerPublicKey`、`recipientAddress` で絞るには `storage.search` の `transactions` が要り、なければ 501。それらがなければ、しまってあるブロックを順に読むので、索引がなくても答える（めったにない種類だけで絞ると、全部のブロックを読むので時間がかかる。mainnet で 20 秒ほど）。`embedded=true` なら、catapult と同じく、アグリゲートの中のトランザクションも 1 件ずつ、外側のすぐ後に返す（中のものの `meta` は、入った高さ、`aggregateHash`、`aggregateId`（外側の `id`）、アグリゲートの中の番号の `index`）。中のものは署名者、宛先、種類、送金のモザイクと額では合うが、catapult と同じく `address` では合わない（catapult の中のトランザクションの文書には `meta.addresses` がない）。答えの `meta` には、catapult と同じく、入ったブロックの `timestamp` と `feeMultiplier` を足す（中のものにも）。アグリゲートは中のトランザクションも付けて返す（catapult の検索は付けない）。並びは高さとブロックの中の順（`order=desc` で逆）。catapult は MongoDB の ID の順で、同じブロックの中では並びがばらつくので、そこだけ catapult と違うことがある。ページ送りはメタデータの検索と同じで、1件ごとの `id` は高さ（12 桁）、ブロックの中の番号（8 桁）、アグリゲートの中の番号（4 桁。外側は 0、中のものは 1 から）をつないだ 24 桁の16進 |
| `/transactions/confirmed/{hash}` | 直近のブロック（同じく、`transactions` があれば全部）に入ったトランザクションと、入った高さ。アグリゲートの中のものには、catapult と同じく、入った高さ、`aggregateHash`、`aggregateId`、`index`、ブロックの時刻と倍率の `meta` を付ける |
| `/blocks/{height}/transactions/{hash}/merkle` | そのブロックの TransactionsHash への Merkle の経路 |
| `PUT /transactions/partial`、`PUT /transactions/cosignature` | 連署を待つアグリゲートボンデッドと、その連署（catapult の `CosignatureDTO`）を受け付ける。受け付けたら 202。ハッシュロックや連署できる人かは、そのあとノードで確かめる。連署を待っているものは、行方（`/transactionStatus`）で `partial` になる |
| `/transactions/partial/{hash}`、`/transactions/partial` | 連署を待っているもの（集まった連署付き、高さは "0"）と、その一覧。一覧は `address`（外側の署名者、中のトランザクションの署名者、連署者、送金の宛先のどれか）と `signerPublicKey`（外側の署名者）で絞り、`pageSize`（10 から 100）と `pageNumber` でページを送る |
| `PUT /transactions` | 署名したトランザクション（`{"payload":"16進"}`）を受け付けて、つないでいるピアに流す。catapult の REST と同じく、受け付けたら 202。heika は先にメモリプールで確かめるので、受け付けなかったら 409 で `message` にわけを返す |
| `PUT /blocks` | 外で組んで署名したブロックを受け取る。本文は、`Content-Type: application/json` なら `{"payload":"16進"}`、`application/octet-stream` ならブロックのバイト列そのまま（ほかは 415）。ブロックは P2P の `Push_Block` と同じく 32 MiB まで（JSON は16進なのでおよそ 64 MiB まで。超えたら 413）。heika だけの口。P2P の `Push_Block` と同じく、形と署名を確かめて 202 を返し（読めなければ 409）、先端の次につながるか、先端と同じ親の上でスコアが高ければ足して、つないでいるピアに流す。足したかはノードのログか `/chain/info` で見る。規則に合わなくても、P2P と違って締め出す相手はいない |

- トランザクションの行方は、トランザクションの期限（`maxTransactionLifetime`、メインネットで 6 時間）の分の直近のブロックだけから答える。送ったばかりのものは、その間に入るか二度と入らないかなので、送金のあとの確かめには足りる。索引はメモリにだけ持ち、起動したら直近のブロックを読んで作り直す（ライトの残し方でもブロックはその分ある）。それより古いトランザクションは 404
- 状態の口（`/accounts`、`/mosaics`、`/namespaces`、`/metadata` と、それぞれの `/merkle`、`POST /accounts`、`POST /mosaics`、`/account/{address}/multisig` と `/graph`、ロックと制限の口）は、`?height=N` を付けると、高さ N のブロックを実行したあとの状態を返す（heika だけ）。`/merkle` の道はブロック N の9本の根につながるので、`/blocks/{N}` の StateHash まで確かめられる。ネームスペースの `active` も、その高さで決める
  - 答えには、引いた高さを `X-Heika-Height` で添える。catapult はこのクエリを知らずに今の状態を返すので、このヘッダーがなければ、その高さの答えではない
  - まだ実行していない高さと、読めない形の高さは 409。その高さの差分を持っていなければ 410（`Gone`）。アーカイブの残し方なら全部の高さ、ライトとフルなら残している差分の分だけ答えられる
- 話すのは HTTP だけ。HTTPS で外に出すなら、手前に Nginx や Caddy を置き、そこで TLS を終わらせる。systemd と Caddy で外に出す手順は [deploy.md](deploy.md)

## GUI

ウォレットの GUI では、iOS のほかで、「ノード」のタブから同じノードを動かせる。設定ファイルは見せずに GUI が書き、ネットワークと最初につなぐノードは、設定の REST から決める。鍵と証明書は、初めて起動したときに作って使い続ける。待ち受けるのは、その PC の中（`127.0.0.1:7900`）だけ。

- REST も、その PC の中（`127.0.0.1:7910`）だけで立てる。設定の「自分のノードで確かめる」を選ぶと、ノードが先端を追っているあいだは、残高、送金、ハーベストの設定をそのノードで確かめる。止まっているときや追いついていないときは、設定の REST に聞く。どちらに聞いたかは、残高の「信じていること」に出る

- デスクトップでは、ノードはウォレットとは別のプロセスで動く。ノードが動いているあいだは、窓を閉じても通知領域に隠れるだけで、通知領域のメニューの「終了」でノードを止めて終わる
- Android では、ノードはアプリの中で動き、そのあいだは通知を出して、裏に回っても画面を消しても動き続ける
- ノードが動いているあいだは、「このノードでブロックを作る」で、今のアカウントから導出した鍵でハーベストする。リンクがまだか、ほかの鍵なら、リンクのアグリゲートを確かめてもらってから送り、ブロックに入ったのが見えたら、鍵をノードのメモリにだけ渡す。鍵は、キーストアを閉じてもノードを止めるまで渡したままにする
