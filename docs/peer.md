# 試験的なノード

`heika experimental peer start` は、heika をピアとしてネットワークに入れる。試験的なので、コマンドの形も設定の中身も、断りなく変わる。

## できること

- メインネット、テストネット、決め打ちの値のないネットワーク（プライベートなネットワークなど）に、ピアとして入る
- 確定したところまでは、いくつかのピアからまとめて取って実行する（追いつく段階）。そのあとは、届いたブロックを1つずつ確かめて先端を追い、枝を取り替える（先端の段階）。確定から遅れれば、また追いつく段階に戻る
- ブロックの署名、難易度、VRF の証明とハーベストの当たり、トランザクションの中身、StateHash と ReceiptsHash、ファイナライズの証明（投票の署名と重み）まで、自分で確かめる
- 残し方をアーカイブ、フル、ライトから選ぶ
- 接続を受けて、ほかのノードの問い合わせに答える
- ハーベストする（鍵のファイルを渡したとき）
- SIGINT か SIGTERM で、今のブロックを書き終えてから止まり、次に始めると続きから進む

## コマンドの例

```sh
heika experimental peer start --config peer.yaml
```

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

- `network.type`: `mainnet` と `testnet` は、ネットワークの設定（`config-network.properties` などにあたる値）を heika が持っているので、ほかに何も要らない。`network.resources` にノードの `resources` フォルダーを書けば、代わりにそこから読む（ネットワークの設定が変わって、heika がまだ追いついていないときなど）。`custom` には、`network.resources` と `network.nemesisHash`（Nemesis のブロックのハッシュ）が要る
- `dataDirectory`: ブロックと状態をしまうフォルダー
- `certificates.directory`: `tls.crt`（ノードの証明書と CA の証明書の鎖）と `tls.key`（ノードの鍵）のあるフォルダー。`heika cert ca` と `heika cert node` で作れる。同じ IP から違う証明書で次々につなぐとほかのノードに嫌われるので、いつも同じ証明書を使う
- `seed`: 住所録が空か、どこにもつながらないときに、最初につなぐノード（`ホスト:ポート`）。そのノードからほかのノードの一覧をもらい、住所録に足していく
- `peers`: 先端の段階でつないでおくピアの数。既定は 8
- `minFreeGigabytes`: ディスクの空きがこれより少なければ、書く前に止める。既定は 10
- `storage`: 何を残すか（下の「残し方」）
- `listen`: 接続を受ける。`address`（`0.0.0.0:7900` など）、`publicHost`（ほかのノードに名乗るホスト名。なければ相手が接続元から決める）、`friendlyName`。なければ、自分からつなぐだけ
- `harvesters`: ハーベストする鍵の組の並び。`signer`（ブロックに署名する鍵。メインアカウントか、リンクしたリモートの鍵）と `vrf`（リンクした VRF の鍵）に、鍵のファイルの場所を書く。鍵は PEM、DER、16進のどれでも読む。持ち主のほかも読めるファイルなら警告を出す

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

`storage.partialState` は、アカウントの表を全部はメモリに持たずに要るものだけを読むかで、`light` ではいつも真、ほかは書かなければ真。`storage.cache.stateMegabytes`（既定 64）と `storage.cache.databaseMegabytes`（既定 256）で、読んだ状態と DB のキャッシュの量を決める。

## GUI

ウォレットの GUI では、iOS のほかで、「ノード」のタブから同じノードを動かせる。設定ファイルは見せずに GUI が書き、ネットワークと最初につなぐノードは、設定の REST から決める。鍵と証明書は、初めて起動したときに作って使い続ける。待ち受けるのは、その PC の中（`127.0.0.1:7900`）だけ。

- デスクトップでは、ノードはウォレットとは別のプロセスで動く。ノードが動いているあいだは、窓を閉じても通知領域に隠れるだけで、通知領域のメニューの「終了」でノードを止めて終わる
- Android では、ノードはアプリの中で動き、そのあいだは通知を出して、裏に回っても画面を消しても動き続ける
