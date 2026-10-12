# heika

Symbol（XYM。NEM の後継のブロックチェーン）のノード運営のための、鍵と証明書の Rust のツールキット。

## 機能

### 鍵

- ✅DONE: ニーモニックと秘密鍵の生成と、公開鍵とアドレスの導出（ニーモニックからは公式ウォレットと同じパスで導出する）
- ✅DONE: 鍵の PEM と16進の相互変換（秘密鍵は PKCS#8 の v1 と、公開鍵だけが付いた v2 を読める）
- ✅DONE: 端末から秘密鍵を入れるときに、画面に出さない（Unix と Windows）
- ✅DONE: ニーモニックと秘密鍵を、パスフレーズで暗号化したキーストアにしまう（age 形式なので、heika がなくても `age -d` で開ける）。署名と連署にそのまま使える

### 証明書

- ✅DONE: CA とノードの証明書の発行（v3 は shoestring と同じ拡張で、v1 も選べる。DN は RFC 4514 の形（CN=node,O=example）でも OpenSSL の形（/O=example/CN=node）でも書ける）
- ✅DONE: 証明書の確認。ファイルのほかに、ノードが実際に出しているものも確かめられる（有効期間、catapult がつなぐときの条件、CA の公開鍵のアドレス。ノードには、こちらの証明書が受け付けられるかも）
- ✅DONE: shoestring や symbol-bootstrap の証明書のフォルダーでの、ノードの証明書の更新（元のファイルは日時つきのフォルダーにコピーして残す）
- ✅DONE: 証明書の期限が近いことを、終了コードで知らせる（定期実行の仕組みから、そのまま呼べる。ファイル、証明書のフォルダー、ノードが実際に出しているものを確かめられる）

### ハーベストとトランザクション

- ✅DONE: ハーベストのためのリンクと委任（古いリンクの解除、新しいリンク、委任の要求を1つのアグリゲートにまとめる。委任ではリモートと VRF の鍵を毎回作り直す）
- ✅DONE: 投票鍵のファイルの作成と確認、チェーンへの紐づけ（catapult の votingkey と同じファイルを書き、公式の Python SDK と照合している）
- ✅DONE: トランザクションの中身の表示（25種類すべてと、チェーンにある古いバージョンのアグリゲート）
- ✅DONE: トランザクションへの署名と連署と、ノードへの送信（ノードの証明書で名乗って、ノードと TLS でつなぐ）
- ✅DONE: ノードあての委任の一覧（ブロックから委任の要求を拾い、メインアカウントのリンクと比べて、今も有効かを出す。harvesters.dat と突き合わせて、入っていない有効な委任を足した harvesters.dat を書ける）

### ノード

- ✅DONE: 近くて速いノードを探す（ノードと TLS でつなぎ、接続にかかる時間、高さ、ブロックの読み出しの速さを測る。REST のないノードも調べられる）
- ✅DONE: 見つけた速いノードを、catapult の peers-p2p.json の形式で書く
- ✅DONE: 測った結果を JSON で出す

### ライブラリのみ

- ✅DONE: catapult と同じ判定の署名の検証
- ✅DONE: catbuffer にある25種類すべてのトランザクションの読み書きとハッシュ、委任ハーベストの要求のメッセージの読み書き

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名、Merkle ツリー、メインネットとテストネットで決まっている値
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER、X.509 の証明書。shoestring と symbol-bootstrap の証明書のフォルダー（feature の `shoestring-compat` と `bootstrap-compat`）
- `heika-tls`: catapult と同じ設定（TLS 1.3、X25519）での TLS の接続と、相手の証明書の確認
- `heika-p2p`: ノードへの問い合わせ。ノードの情報、高さ、ほかのノードの一覧、ブロック
- `heika-transaction`: トランザクションの読み書き、署名、ハッシュ。catbuffer にある25種類すべて
- `heika-block`: ブロックの読み込み、署名の確認、ハッシュ。中のトランザクションの切り分けと、TransactionsHash の確認
- `heika-wallet`: ウォレットのための計算。BIP 39、SLIP-10、委任ハーベストの要求に使う公開鍵あての暗号化
- `heika-harvesting`: ノードへの委任ハーベスト。ブロックから委任の要求を拾い、メインアカウントのリンクと比べて今も有効かを確かめる
- `heika-cli`: コマンドラインツール `heika`
- `heika-vectors`: Symbol の公式テストベクター、公式の Python SDK で作ったベクター、メインネットのブロックとの照合

## インストール

Releases に、次のバイナリを置いている。

- Linux の x86_64 と aarch64（musl で静的にリンクしたもの）
- macOS の Apple Silicon
- Windows の x86_64

ダウンロードしたものは、`SHA256SUMS` と、GitHub Actions で作ったことを示す来歴の証明で確かめられる。

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify heika-<バージョン>-<ターゲット>.tar.gz --repo <リポジトリ>
```

macOS のバイナリは Apple の公証を受けていない。ブラウザーでダウンロードすると Gatekeeper に止められるので、`curl` で取るか、`xattr -d com.apple.quarantine heika` で印を外す。

Windows でも、標準入力から読んだ秘密鍵を std のバッファに残さず、コンソールから打った文字は画面に出さない。ただし、書き出す秘密鍵のファイルは、Unix のように自分だけが読めるようにはできず、置いたフォルダーの権限を引き継ぐ。自分のユーザーのフォルダーの中に置く。

ソースからなら、Rust 1.99 以上で次のようにする。

```sh
cargo install --git <リポジトリの URL> heika-cli
cargo install --path crates/heika-cli  # 手元に clone したなら
```

## 使い方

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
heika key voting generate --network mainnet --start-epoch <エポック> --end-epoch <エポック> --out private_key_tree1.dat
heika key voting show private_key_tree1.dat

heika wallet init
heika wallet add --mnemonic --label main --network mainnet
heika wallet import --mnemonic --label old --network mainnet < alice.mnemonic
heika wallet derive --from main --label sub --network mainnet --account 1
heika wallet list
heika wallet export --label main --out main.key
heika tx sign --network mainnet harvesting.bin --out harvesting.signed --wallet-account main

heika cert ca --subject "CN=CA example" --out ca.crt.pem < ca.key.pem
heika cert node --ca-cert ca.crt.pem --public-key <公開鍵> --subject "CN=node example" --out node.crt.pem < ca.key.pem
heika cert renew --shoestring-certs-dir <フォルダー> < ca.key.pem
heika cert show node.full.crt.pem
heika cert show --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem
heika cert check --warn-days 30 --shoestring-certs-dir <フォルダー>
heika cert check --warn-days 30 --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem

heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --delegate <ノードの公開鍵> --out harvesting.bin
heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --link-remote <公開鍵> --link-vrf <公開鍵> --out harvesting.bin
heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --link-voting <公開鍵>:<最初のエポック>-<最後のエポック> --out voting.bin
heika tx show harvesting.bin
heika tx show --json harvesting.bin
heika tx sign --network mainnet --out harvesting.signed.bin harvesting.bin < main.key
heika tx cosign --network mainnet --out harvesting.cosigned.bin harvesting.signed.bin < cosigner.key
heika tx announce --network mainnet --connect <ホスト>:<ポート> --client-cert node.full.crt.pem harvesting.signed.bin < node.key.pem

heika node find --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem
heika node delegations --connect <自分のノード>:<ポート> --client-cert node.full.crt.pem --from-height <高さ> < node.key.pem
heika node find --connect <ホスト>:<ポート> --client-cert node.full.crt.pem --crawl --limit 300 --peers-json peers-p2p.json < node.key.pem
heika node find --connect <ホスト>:<ポート> --client-cert node.full.crt.pem --json < node.key.pem > nodes.json

heika legal third-party
heika legal source --out heika-source.zip
```

秘密鍵とニーモニックは標準入力からのみ読む。キーストアのパスフレーズだけは、標準入力とは別に端末から聞く。扱いの方針は [docs/secrets.md](docs/secrets.md) にある。

`heika wallet` は、ニーモニックや秘密鍵を、パスフレーズで暗号化した1つのファイル（キーストア）にしまう。`heika wallet add` はニーモニックか秘密鍵をその場で作ってキーストアに入れるので、作った秘密が平文のファイルになることがない。すでにあるものは `heika wallet import` で標準入力から取り込む。置き場所は、Linux では `~/.local/share/heika/keystore.age`、macOS では `~/Library/Application Support/heika/keystore.age`、Windows では `%LOCALAPPDATA%\heika\keystore.age` で、`--keystore` で変えられる。ファイルは age 形式で、heika がなくても `age -d` で開け、中身は人が読めるテキストである（形式は [docs/keystore.md](docs/keystore.md)）。ニーモニックからは、公式ウォレットと同じパスでアカウントを増やせる。`heika tx sign` と `heika tx cosign` に `--wallet-account <ラベル>` を付けると、標準入力の代わりにキーストアの鍵で署名する。パスフレーズは端末から聞き、スクリプトから動かすときは `--passphrase-file` で渡せる。`--expert` を付けると、続けて BIP39 のパスフレーズも聞く。空なら公式ウォレットと同じ鍵、何か入れると同じ番号のまま別の鍵（隠しウォレット）になる。BIP39 のパスフレーズはどこにも保存しないので、隠しウォレットがあることはキーストアからはわからない。その代わり、忘れると取り戻せず、公式ウォレットでも開けない。キーストアはバックアップの代わりにならないので、ニーモニックは紙にも控えておく。

`heika key voting generate` は、ファイナライズの投票に使う投票鍵のファイルを、catapult の votingkey と同じ形で書く。根の鍵でエポックごとの鍵に署名したら、根の秘密鍵は捨てる。期間はネットワークの設定の範囲（メインネットは 112 から 360 エポック）で確かめる。作ったファイルは、ノードの votingkeys フォルダーに private_key_tree1.dat から順に番号を振って置く。`heika key voting show` は、ノードが使っているファイルも読み、公開鍵と期間、ノードが使って消したエポック、残っている鍵の数を出し、残っている鍵が公開鍵の署名と合うかを確かめる。

DN は RFC 4514 の形（`CN=node,O=example`）でも、OpenSSL の `-subj` の形（`/O=example/CN=node`）でも書ける。2 つは区切りが違い、書く順番も逆になる。証明書を表示するときは RFC 4514 の形で出す。

`heika cert check` は、証明書のファイル、証明書のフォルダー（CA とノードの証明書）、`--connect` のノードが実際に出している証明書について、期限までの日数を1行ずつ出す。終了コードは `openssl x509 -checkend` に合わせていて、期限まで `--warn-days` 日（既定は 30 日）を切ったもの、切れたもの、まだ有効でないものがあれば 1、確かめられないものがあれば 2、どれもなければ 0 になる。heika のほかのコマンドはエラーを 1 で返すので、ここだけ違う。定期実行は cron、systemd の timer、Kubernetes の CronJob など、使っている仕組みから呼ぶ。`--connect` は、ファイルを更新したのにノードを再起動していない、という状態も見つけられる。

`heika harvesting` は、リンクの解除、紐づけ、委任の要求を1つのアグリゲートにまとめる。`--delegate` を付けると、リモートアカウントと VRF の鍵をその場で作り、委任先のノードにだけ渡す。前の委任先のノードは古い鍵を知っているので、使い回すとそのノードがハーベストを続けられてしまうためである。自分のノードでハーベストするなら、`heika key generate` で作った鍵の公開鍵を `--link-remote` と `--link-vrf` に渡す。古いリンクは `--unlink-remote`、`--unlink-vrf`、`--unlink-node` で外す。外すべき公開鍵は、前回の `heika harvesting` が表示する。投票鍵は、`heika key voting generate` が出す `<公開鍵>:<最初のエポック>-<最後のエポック>` を `--link-voting` に渡して紐づけ、同じ書き方で `--unlink-voting` に渡して外す。組むのに秘密鍵は要らず、メインアカウントの秘密鍵は `heika tx sign` で読む。署名する前に、`heika tx show` で中身を確かめられる。`heika tx show` は秘密鍵を使わず、バイト列そのものでも16進のテキストでも読む。署名者とアドレス、手数料と期限（UTC の日時）、中のトランザクションの1件ずつを出し、署名があれば正しいかも確かめる。メッセージの文字列は、端末の表示を書き換えられないように制御文字をエスケープする。通貨以外のモザイクの量は、可分性がわからないので最小単位のまま出す。チェーンにある古いアグリゲート（バージョン 1 と 2）も読み、バージョン 1 なら中のトランザクションのハッシュがどの求め方で書かれているかも出す。古いアグリゲートは、署名も送信もしない。`--json` を付けると、表示と同じ項目を JSON で出す。`heika tx sign` も、署名したあとに同じ中身を出す。マルチシグのアカウントなどで連署が要るときは、署名したものに `heika tx cosign` で1人ずつ連署を足す。連署するのは外側の署名を含むハッシュなので、先に署名しておく。`heika tx announce` は、ネットワーク、署名と連署、期限を確かめてから送る。ノードは受け取ったことを返さないので、ブロックに入ったかは、表示するハッシュで確かめる。

`heika node find` は、最初につないだノードからほかのノードの一覧をもらい、1つずつ順につないで測る。`--crawl` を付けると、測ったノードからも一覧をもらってたどるので、ネットワーク全体を調べられる。名乗る証明書は、ノードを持っていなくても `heika cert ca` と `heika cert node` で作れる。同じ IP から違う証明書で次々につなぐとノードに嫌われるので、いつも同じ証明書を使う。`--json` を付けると、表の代わりに、測った結果と測れなかったノードを JSON で標準出力に出す。途中の経過は標準エラーに出すので、標準出力をそのままファイルに書ける。時間はミリ秒、遅れはブロックで、公開鍵はノードが名乗ったものと、TLS で確かめた CA のものの両方を出す。

`--peers-json` を付けると、測ったノードのうち、Peer のロールがあって遅れが 5 ブロック以下のノードを、読み出しの速い順に `--peers-count` 台（既定は 10 台）選び、catapult の `peers-p2p.json` の形式で書く。公開鍵は、ノードが名乗ったものではなく、TLS で確かめた CA の公開鍵を書く。自分のノードの証明書で名乗っていれば、自分のノードは除く。すでにあるファイルは上書きしないので、ノードの `resources/peers-p2p.json` には、中身を確かめてから置き換える。

`heika node delegations` は、自分のノードにノード自身の証明書で名乗ってつなぎ、`--from-height` から `--to-height`（省略するとノードの今の高さ）までのブロックを読んで、ノードあての委任の要求を拾う。標準入力から読む `node.key.pem` は、名乗るのにも、要求を復号するのにも使う。要求ごとに、走査した範囲で最後に見たメインアカウントのリンク（リモート、VRF、ノード）と比べ、有効（3つとも合う）、無効（合わないものがある）、不明（走査した範囲でリンクを見ていない）に分けて出す。`--from-height` は、ノードが委任を受け付け始めたころにすると、不明が減る。ネームスペースあての要求は、ネームスペースを解決できないので数えるだけにする。ブロックが前後でつながっていることと、中のトランザクションがヘッダーの TransactionsHash と合うことを確かめ、合わなければ止める。知らない種類のトランザクションがあれば、結果が正しくないかもしれないので止める。`--harvesters-dat` にノードの harvesters.dat を渡すと、見つけた要求が入っているかを突き合わせ、有効なのに入っていないものの数を出す。ファイルは読むだけで、書き換えない。ノードの鍵で復号できないものが入っていれば、ノードも起動しないので、走査する前に止める。さらに `--write-harvesters-dat` を付けると、今の harvesters.dat の項目をすべて残したまま、入っていない有効な委任と有効かわからない委任を足して、新しいファイルに書く。importance が 0 の時期にノードが外し、そのあと戻らなくなった委任を戻せる。無効なものや合わないものは、ノードが起動したあとで外す。書く前と書いたあとに、どの項目もノードの鍵で復号できることを確かめる。ノードのファイルは書き換えないので、ノードを止め、元のファイルを残したうえで置き換える。

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --include-ignored  # 公式ベクターと SDK のベクターとの照合。公式ベクターはネットワークから取る。メインネットのブロックは docs/testing.md の手順で
cargo test -p heika-cert --all-features             # heika-cert だけを、feature つきのモジュールも含めて
```

方針は [docs/testing.md](docs/testing.md) にある。

## ライセンス

AGPL-3.0-only。BIP 39 の単語リストは MIT（[crates/heika-wallet/src/bip39/NOTICE](crates/heika-wallet/src/bip39/NOTICE)）。バイナリに入る依存のクレートのライセンスは [crates/heika-cli/THIRD-PARTY-LICENSES](crates/heika-cli/THIRD-PARTY-LICENSES) にまとめてあり、Release のアーカイブにも入れている。バイナリそのものにも、heika と依存のライセンスと、ビルドしたときのソースを入れてあり、`heika legal` で取り出せる。ベクターを作るスクリプト（`crates/heika-vectors/scripts/`）は MIT。

バイナリに入れたソースは、実行しなくても取り出せる。動かせないアーキテクチャのバイナリや、実行したくないバイナリからでも取り出せるように、決まった名前のセクションに置いている。

```sh
objcopy -O binary --only-section=.heika_source heika heika-source.zip      # Linux
segedit heika -extract __TEXT __heika_source heika-source.zip              # macOS
llvm-objcopy --dump-section .hksrc=heika-source.zip heika.exe              # Windows
```
