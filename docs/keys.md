# 鍵とキーストア

## できること

- ニーモニックと秘密鍵の生成と、公開鍵とアドレスの導出（ニーモニックからは公式ウォレットと同じパスで導出する）
- 鍵の PEM と16進の相互変換（秘密鍵は PKCS#8 の v1 と、公開鍵だけが付いた v2 を読める）
- 端末から秘密鍵を入れるときに、画面に出さない（Unix と Windows）
- ニーモニックと秘密鍵を、パスフレーズで暗号化したキーストアにしまう（age 形式なので、heika がなくても `age -d` で開ける）。署名と連署にそのまま使える
- キーストアのパスフレーズの変更と、アカウントのラベルの変更、削除
- アカウントの残高を、REST の最新のブロックの StateHash まで確かめて出す（まだチェーンに載っていないことも確かめる）

秘密鍵とニーモニックは標準入力からのみ読む。キーストアのパスフレーズだけは、標準入力とは別に端末から聞く。扱いの方針は [secrets.md](secrets.md) にある。

## 鍵

```sh
heika key mnemonic --out alice.mnemonic
heika key derive < alice.mnemonic
heika key generate --out alice.key
heika key public-key < alice.key
heika key address <公開鍵>

heika key from-pem --out main.key < ca.key.pem
heika key from-pem --public < ca.pubkey.pem
heika key to-pem --out node.key.pem < node.key
heika key to-pem --public <公開鍵>
```

## 公開鍵を点として足す（上級者向け）

使い方を誤ると資産を失う。`heika expert` の下に置いてある。

```sh
heika expert public-key list-torsion
heika expert public-key add <公開鍵> <公開鍵>...
heika expert public-key neg <公開鍵>
heika expert public-key inspect <公開鍵>
```

`list-torsion` は、小さい位数の点（位数が 8 の約数の点）8 個を、16進と位数で出す。番号の振り方には決まったものがないので、点は16進のまま扱う。`add` は、公開鍵を曲線の点として足す。素数位数の部分群の外の点も受け付ける。`neg` は逆元を出すので、`add` と合わせると引き算になる。`inspect` は、点が素数位数の部分群に入っているかを調べ、外なら混ざった小さい位数の成分の位数を出す。部分群に入っていて単位元でないときだけ、終了コード 0 で終わる。

- 公開鍵に単位元以外の小さい位数の点を足すと、今の catapult の検証では部分群の外の公開鍵が弾かれるので、誰も署名できない。そのアドレスに送ったものは二度と動かせない
- ただし、これは今の検証の決まりの下での話である。位数 8 を掛けてから比べる検証（ZIP-215 など）に変わると、元の鍵の持ち主が署名できるようになり、小さい位数の点そのものの鍵は誰でも署名できるようになる
- 単位元 `0100…00` の鍵は、今でも誰でも署名できる
- 公開鍵どうしの和は、Symbol の秘密鍵としては取り出せない。他人の公開鍵との和を、共同の鍵として使ってはいけない（rogue key）

## キーストア

```sh
heika wallet init
heika wallet add --mnemonic --label main --network mainnet
heika wallet import --mnemonic --label old --network mainnet < alice.mnemonic
heika wallet derive --from main --label sub --network mainnet --account 1
heika wallet list
heika wallet export --label main --out main.key
heika wallet rename --label sub --new-label savings
heika wallet remove --label savings
heika wallet change-passphrase
heika tx sign --network mainnet harvesting.bin --out harvesting.signed --wallet-account main
```

`heika wallet` は、ニーモニックや秘密鍵を、パスフレーズで暗号化した1つのファイル（キーストア）にしまう。`heika wallet add` はニーモニックか秘密鍵をその場で作ってキーストアに入れるので、作った秘密が平文のファイルになることがない。すでにあるものは `heika wallet import` で標準入力から取り込む。置き場所は、Linux では `~/.local/share/heika/keystore.age`、macOS では `~/Library/Application Support/heika/keystore.age`、Windows では `%LOCALAPPDATA%\heika\keystore.age` で、`--keystore` で変えられる。ファイルは age 形式で、heika がなくても `age -d` で開け、中身は人が読めるテキストである（形式は [keystore.md](docs/keystore.md)）。ニーモニックからは、公式ウォレットと同じパスでアカウントを増やせる。`heika tx sign` と `heika tx cosign` に `--wallet-account <ラベル>` を付けると、標準入力の代わりにキーストアの鍵で署名する。パスフレーズは端末から聞き、スクリプトから動かすときは `--passphrase-file` で渡せる。`--expert` を付けると、続けて BIP39 のパスフレーズも聞く。空なら公式ウォレットと同じ鍵、何か入れると同じ番号のまま別の鍵（隠しウォレット）になる。BIP39 のパスフレーズはどこにも保存しないので、隠しウォレットがあることはキーストアからはわからない。その代わり、忘れると取り戻せず、公式ウォレットでも開けない。キーストアはバックアップの代わりにならないので、ニーモニックは紙にも控えておく。

`heika wallet rename` はアカウントのラベルを、`heika wallet change-passphrase` はキーストアのパスフレーズを変える。パスフレーズを変えると、前のパスフレーズで開ける `.bak` を消すかを聞く。`heika wallet remove` はアカウントを消すが、ニーモニックや秘密鍵の最後のアカウントは、`--with-secret` を付けたときだけ秘密ごと消す。どちらの場合も、消す前の中身は `.bak` に残るので、残したくなければそれも消す。

## 残高

```sh
heika account show <アドレス> --rest https://<ホスト>:3001
heika account show <アドレス> --rest https://<ホスト>:3001 --json
```

`heika account show` は、REST の答えをそのまま出さずに、確かめてから出す。最新のブロックの署名と、9本の根から求めた StateHash を確かめ、アカウントの状態と、持っているモザイクの定義（可分性）が、状態の経路でその根につながることを確かめる。まだチェーンに載っていないアカウントは、載っていないことを状態の経路で確かめる。取るあいだにブロックが進んで根が合わなくなったら、最初から取り直す。信じたままなのは、そのブロックが正しいチェーンのものかどうかで、そこは REST を信じる。出力にも、確かめたことと信じたままのことを書く。モザイクは ID で出し、通貨だけ XYM と出す。REST には HTTPS でつなぎ、ルート証明書は OS のものを使う。

## 送金

```sh
heika tx transfer --network mainnet --signer <自分の公開鍵> --to <宛先のアドレス> --amount 1.5 --message "ありがとう" --out transfer.bin
heika tx sign --network mainnet transfer.bin --out transfer.signed.bin --wallet-account main
heika tx announce --network mainnet --rest https://<ホスト>:3001 transfer.signed.bin
heika tx status --network mainnet --rest https://<ホスト>:3001 transfer.signed.bin
```

`heika tx transfer` は、XYM を送る署名していない送金を組む。量は XYM の単位で、小数点の下は6桁まで書ける。メッセージは暗号化しない平文なので、チェーンの上で誰でも読める。手数料はバイト数に `--fee-multiplier`（既定は 100）を掛けたもので、期限は `--deadline-hours`（既定は 2 時間）で決める。宛先のネットワークが違ったり、ノードで弾かれる形だったりすれば書かない。`heika tx announce --rest` は、署名したものを REST に渡す。REST は受け取ったことしか返さないので、ブロックに入ったかは `heika tx status` で確かめる。`heika tx status` は、REST から入ったブロックを聞き、そのブロックの署名と StateHash、このトランザクションからブロックの TransactionsHash への経路を確かめる。経路の葉は REST の答えではなく、手元のトランザクションから求める。見つからなくても、入っていないことは1つの REST からは確かめられないので、期限までの時間を出す。期限を過ぎたトランザクションは、もう入ることはない。REST の transactionStatus も参考に出すが、確かめたものではない。
