# Nemesis のブロック

`heika experimental nemgen` は、新しいネットワークの最初のブロック（Nemesis）を作り、ノードが最初に読む `seed` フォルダーを書く。入力は catapult の `catapult.tools.nemgen` と同じ `nemesis.properties` で、同じ入力からは同じバイト列のブロックができる。試験的なので、コマンドの形は断りなく変わる。

## コマンドの例

```sh
heika experimental nemgen --resources resources --nemesis nemesis.properties --out seed < nemesis.key
```

- `--resources`: そのネットワークの `config-network.properties` などのあるフォルダー。`nemesisSignerPublicKey`、`generationHashSeed`、`identifier`、`currencyMosaicId`、`harvestingMosaicId`、`totalChainImportance` が、`nemesis.properties` と標準入力の鍵に合っていること
- `--nemesis`: `nemesis.properties`。`transactionsDirectory` は、今いるフォルダーから数える
- `--out`: `seed` を書くフォルダー。もうあれば書かない

Nemesis の秘密鍵は、標準入力からだけ読む。`nemesis.properties` に `nemesisSignerPrivateKey` を書いてあれば弾く（catapult の nemgen は properties から読み、ログにも出す）。

書くファイルは catapult の nemgen と同じ。

| ファイル | 中身 |
| --- | --- |
| `index.dat` | 高さ（1） |
| `00000/00001.dat` | ブロック、ハッシュ、generation hash、トランザクションごとのハッシュ、9本の状態の木の根 |
| `00000/00001.stmt` | 実行したときのステートメント |
| `00000/hashes.dat` | 高さごとのブロックのハッシュ |
| `proof.index.dat`、`00000/00001.proof`、`00000/proof.heights.dat` | Nemesis を確定した、投票のない証明 |

heika のノードは、設定の `network.nemesisSeed` にこのフォルダーを書けば、ここから始める（[peer.md](peer.md)）。catapult のノードは、`config-user.properties` の `seedDirectory` に書けば、ここから始める。

## 作るもの

トランザクションの並びは catapult の nemgen と同じ。

1. ルートのネームスペースごとに、ルートとサブネームスペース（浅い順）
2. モザイクごとに、定義（ノンスは 0 から、使うものだけを数える）、エイリアス、発行量の増加
3. 配る先のアドレスごとに、配るモザイクをまとめた送金（モザイクはエイリアスのネームスペースで指す）
4. `transactionsDirectory` のファイルを、名前の順に（1ファイルに1件。VRF と投票の鍵の紐づけなど）

どれも期限は 1、手数料は 0。ブロックは Nemesis の鍵で署名し、VRF の証明も同じ鍵で generation hash seed に対して作る。ブロックを実行して、StateHash、ReceiptsHash、足（投票できるアカウントの数、ハーベストできるアカウントの数、投票の残高の合計）を入れる。

## catapult の nemgen と違うところ

- ルートのネームスペースが2つ以上あるときは、ファイルに書いた順に並べる。nemgen はハッシュ表の順に並べるので、同じ入力から違うブロック（どちらも正しい）ができうる。同じ深さのサブネームスペースも、ファイルの順に並べる
- `[cpp]` と `[output]` は読み飛ばす
- 状態のハッシュとレシートは、いつも求める。`enableVerifiableState` と `enableVerifiableReceipts` が true のネットワーク用
- catapult のノードが起動するときに確かめること（ハーベストのモザイクを配った合計が `totalChainImportance` と同じか、`maxMosaicAtomicUnits` を超えないか）を、作る前に確かめる
- 追加のトランザクションは、署名がこのネットワークのものか（generation hash seed が合うか）も確かめる

ルートのネームスペースが1つのとき（`symbol` と `symbol.xym` だけなど）は、catapult の nemgen と同じファイルができることを、テストネットの設定から作ったネットワークで確かめてある。そのネットワークで、heika のノード2台がこの seed から始めてブロックを作り、catapult のノードも同じ seed から始めて、heika の作ったチェーンを取り込んだ。
