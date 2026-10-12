# heika

Symbol（XYM。NEM の後継のブロックチェーン）のノード運営のための、鍵と証明書の Rust のツールキット。

## 機能

### 鍵

- ニーモニックと秘密鍵の生成と、公開鍵とアドレスの導出（ニーモニックからは公式ウォレットと同じパスで導出する）
- 鍵の PEM と16進の相互変換（秘密鍵は PKCS#8 の v1 と、公開鍵だけが付いた v2 を読める）
- 端末から秘密鍵を入れるときに、画面に出さない（Unix と Windows）
- ニーモニックと秘密鍵を、パスフレーズで暗号化したキーストアにしまう（age 形式なので、heika がなくても `age -d` で開ける）。署名と連署にそのまま使える

### 証明書

- CA とノードの証明書の発行（v3 は shoestring と同じ拡張で、v1 も選べる。DN は RFC 4514 の形（CN=node,O=example）でも OpenSSL の形（/O=example/CN=node）でも書ける）
- 証明書の確認。ファイルのほかに、ノードが実際に出しているものも確かめられる（有効期間、catapult がつなぐときの条件、CA の公開鍵のアドレス。ノードには、こちらの証明書が受け付けられるかも）
- shoestring や symbol-bootstrap の証明書のフォルダーでの、ノードの証明書の更新（元のファイルは日時つきのフォルダーにコピーして残す）
- 証明書の期限が近いことを、終了コードで知らせる（定期実行の仕組みから、そのまま呼べる。ファイル、証明書のフォルダー、ノードが実際に出しているものを確かめられる）

### ハーベストとトランザクション

- ハーベストのためのリンクと委任（古いリンクの解除、新しいリンク、委任の要求を1つのアグリゲートにまとめる。委任ではリモートと VRF の鍵を毎回作り直す）
- 投票鍵のファイルの作成と確認、チェーンへの紐づけ（catapult の votingkey と同じファイルを書き、公式の Python SDK と照合している）
- トランザクションの中身の表示（25種類すべてと、チェーンにある古いバージョンのアグリゲート）
- トランザクションへの署名と連署と、ノードへの送信（ノードの証明書で名乗って、ノードと TLS でつなぐ）
- ノードあての委任の一覧（ブロックから委任の要求を拾い、メインアカウントのリンクと比べて、今も有効かを出す。harvesters.dat と突き合わせて、入っていない有効な委任を足した harvesters.dat を書ける）

### ノード

- 近くて速いノードを探す（ノードと TLS でつなぎ、接続にかかる時間、高さ、ブロックの読み出しの速さを測る。REST のないノードも調べられる）
- 見つけた速いノードを、catapult の peers-p2p.json の形式で書く
- 測った結果を JSON で出す

### ライブラリのみ

- catapult と同じ判定の署名の検証
- catbuffer にある25種類すべてのトランザクションの読み書きとハッシュ、委任ハーベストの要求のメッセージの読み書き

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

ノードの証明書を更新して、期限を確かめる。

```sh
heika cert renew --shoestring-certs-dir <フォルダー> < ca.key.pem
heika cert check --warn-days 30 --shoestring-certs-dir <フォルダー>
```

鍵をキーストアに作り、ノードへの委任ハーベストを組んで、署名して送る。

```sh
heika wallet add --mnemonic --label main --network mainnet
heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --delegate <ノードの公開鍵> --out harvesting.bin
heika tx show harvesting.bin
heika tx sign --network mainnet harvesting.bin --out harvesting.signed.bin --wallet-account main
heika tx announce --network mainnet --connect <ホスト>:<ポート> --client-cert node.full.crt.pem harvesting.signed.bin < node.key.pem
```

秘密鍵とニーモニックは標準入力からのみ読む。キーストアのパスフレーズだけは、標準入力とは別に端末から聞く。扱いの方針は [docs/secrets.md](docs/secrets.md) にある。

ほかのコマンドと詳しい説明は、次にある。

- [docs/keys.md](docs/keys.md): 鍵の生成と変換、キーストア（`heika key`、`heika wallet`）
- [docs/cert.md](docs/cert.md): 証明書の発行、更新、確認（`heika cert`）
- [docs/harvesting.md](docs/harvesting.md): 投票鍵、ハーベストのリンクと委任、トランザクションの表示、署名、送信（`heika key voting`、`heika harvesting`、`heika tx`）
- [docs/node.md](docs/node.md): 速いノードを探す、ノードあての委任の一覧（`heika node`）
- `heika legal`: heika と依存のライセンス、ビルドしたときのソース（下の「ライセンス」）

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --include-ignored  # 公式ベクターと SDK のベクターとの照合。公式ベクターはネットワークから取る。メインネットのブロックは docs/testing.md の手順で
cargo test -p heika-cert --all-features             # heika-cert だけを、feature つきのモジュールも含めて
```

方針は [docs/testing.md](docs/testing.md) にある。

## ライセンス

AGPL-3.0-only。BIP 39 の単語リストは MIT（[crates/heika-wallet/src/bip39/NOTICE](crates/heika-wallet/src/bip39/NOTICE)）。バイナリに入る依存のクレートのライセンスは [crates/heika-cli/THIRD-PARTY-LICENSES](crates/heika-cli/THIRD-PARTY-LICENSES) にまとめてあり、Release のアーカイブにも入れている。バイナリそのものにも、heika と依存のライセンスと、ビルドしたときのソースを入れてあり、`heika legal` で取り出せる。ベクターを作るスクリプト（`crates/heika-vectors/scripts/`）は MIT。

```sh
heika legal third-party
heika legal source --out heika-source.zip
```

バイナリに入れたソースは、実行しなくても取り出せる。動かせないアーキテクチャのバイナリや、実行したくないバイナリからでも取り出せるように、決まった名前のセクションに置いている。

```sh
objcopy -O binary --only-section=.heika_source heika heika-source.zip      # Linux
segedit heika -extract __TEXT __heika_source heika-source.zip              # macOS
llvm-objcopy --dump-section .hksrc=heika-source.zip heika.exe              # Windows
```
