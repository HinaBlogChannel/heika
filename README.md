# heika

Symbol（XYM。NEM の後継のブロックチェーン）のノード運営のための、鍵と証明書の Rust のツールキット。

## なぜ heika か

ノードの運用で鍵を扱う作業は、証明書の更新、ハーベストの委任、投票鍵の作り直しと、どれも数か月から1年に一度しか来ない。そのたびに手順を調べ直すことになり、秘密鍵をあちこちに貼る機会も増える。heika は、こうした作業をコマンドにまとめ、秘密の扱いを道具の側で守る。

**バイナリ1つで動く。** Linux 向けは静的にリンクしてあり、Node.js も Python も Docker も要らない。ノードのサーバーにも、ネットワークから切り離したマシンにも、そのまま置ける。

**秘密を残さない。** 秘密鍵とニーモニックは標準入力からだけ読み、引数やシェルの履歴に残さない。使い終えたらメモリから 0 で消し、しまうときは age 形式で暗号化する。age なら、heika がなくても開ける。

**組む、確かめる、署名する、送るを分ける。** トランザクションを組むのに秘密鍵は要らない。署名する前に `heika tx show` で中身を読める形で確かめられ、署名はネットワークにつながずにできる。

**ノードと同じ計算をする。** 署名の検証は catapult と同じ判定にし、公式のテストベクター、公式の Python SDK、メインネットのブロックと照合している。

**今の構成のまま使える。** shoestring や symbol-bootstrap を置き換えるのではなく、その証明書のフォルダーをそのまま読み書きする。

## 機能

- ノードの証明書の発行と更新。shoestring や symbol-bootstrap の証明書のフォルダーをそのまま扱える
- 証明書の期限が近いことを、終了コードで知らせる。ファイルのほかに、ノードが実際に出している証明書も確かめられる
- ハーベストのリンクと委任、投票鍵の紐づけをトランザクションに組み、署名してノードへ送る
- ノードあての委任の一覧と、harvesters.dat に入っていない有効な委任の書き足し
- ニーモニックと秘密鍵を、パスフレーズで暗号化したキーストアにしまう。age 形式なので、heika がなくても `age -d` で開ける
- 秘密鍵とニーモニックは標準入力からだけ読み、画面に出さない。使い終えた秘密はメモリから 0 で消す（消しきれないものは [docs/secrets.md](docs/secrets.md) に）

ほかにも、近くて速いノードを探す、トランザクションの中身を読める形で出す、鍵の PEM と16進を相互に変換する、などいろいろ。すべての機能は、[使い方](#使い方)にある各文書の「できること」にまとめてある。

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名（catapult と同じ判定の検証）、Merkle ツリー、メインネットとテストネットで決まっている値
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER、X.509 の証明書。shoestring と symbol-bootstrap の証明書のフォルダー（feature の `shoestring-compat` と `bootstrap-compat`）
- `heika-tls`: catapult と同じ設定（TLS 1.3、X25519）での TLS の接続と、相手の証明書の確認
- `heika-p2p`: ノードへの問い合わせ。ノードの情報、高さ、ほかのノードの一覧、ブロック
- `heika-transaction`: トランザクションの読み書き、署名、ハッシュ。catbuffer にある25種類すべて
- `heika-block`: ブロックの読み込み、署名の確認、ハッシュ。中のトランザクションの切り分けと、TransactionsHash の確認
- `heika-wallet`: ウォレットのための計算。BIP 39、SLIP-10、キーストア、委任ハーベストの要求のメッセージの読み書きと、それに使う公開鍵あての暗号化
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
