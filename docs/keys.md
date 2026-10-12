# 鍵とキーストア

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

## キーストア

```sh
heika wallet init
heika wallet add --mnemonic --label main --network mainnet
heika wallet import --mnemonic --label old --network mainnet < alice.mnemonic
heika wallet derive --from main --label sub --network mainnet --account 1
heika wallet list
heika wallet export --label main --out main.key
heika tx sign --network mainnet harvesting.bin --out harvesting.signed --wallet-account main
```

`heika wallet` は、ニーモニックや秘密鍵を、パスフレーズで暗号化した1つのファイル（キーストア）にしまう。`heika wallet add` はニーモニックか秘密鍵をその場で作ってキーストアに入れるので、作った秘密が平文のファイルになることがない。すでにあるものは `heika wallet import` で標準入力から取り込む。置き場所は、Linux では `~/.local/share/heika/keystore.age`、macOS では `~/Library/Application Support/heika/keystore.age`、Windows では `%LOCALAPPDATA%\heika\keystore.age` で、`--keystore` で変えられる。ファイルは age 形式で、heika がなくても `age -d` で開け、中身は人が読めるテキストである（形式は [keystore.md](docs/keystore.md)）。ニーモニックからは、公式ウォレットと同じパスでアカウントを増やせる。`heika tx sign` と `heika tx cosign` に `--wallet-account <ラベル>` を付けると、標準入力の代わりにキーストアの鍵で署名する。パスフレーズは端末から聞き、スクリプトから動かすときは `--passphrase-file` で渡せる。`--expert` を付けると、続けて BIP39 のパスフレーズも聞く。空なら公式ウォレットと同じ鍵、何か入れると同じ番号のまま別の鍵（隠しウォレット）になる。BIP39 のパスフレーズはどこにも保存しないので、隠しウォレットがあることはキーストアからはわからない。その代わり、忘れると取り戻せず、公式ウォレットでも開けない。キーストアはバックアップの代わりにならないので、ニーモニックは紙にも控えておく。
