# heika

Symbol（XYM。NEM の後継のブロックチェーン）のノード運営のための、鍵と証明書の Rust のツールキット。

## 機能

### 鍵

- ✅DONE: ニーモニックと秘密鍵の生成と、公開鍵とアドレスの導出（ニーモニックからは公式ウォレットと同じパスで導出する）
- ✅DONE: 鍵の PEM と16進の相互変換（秘密鍵は PKCS#8 の v1 と、公開鍵だけが付いた v2 を読める）
- 📝TODO: 端末から秘密鍵を入れるときに、画面に出さない

### 証明書

- ✅DONE: CA とノードの証明書の発行（v3 は shoestring と同じ拡張で、v1 も選べる。DN は RFC 4514 の形（CN=node,O=example）でも OpenSSL の形（/O=example/CN=node）でも書ける）
- ✅DONE: 証明書の確認。ファイルのほかに、ノードが実際に出しているものも確かめられる（有効期間、catapult がつなぐときの条件、CA の公開鍵のアドレス。ノードには、こちらの証明書が受け付けられるかも）
- ✅DONE: shoestring や symbol-bootstrap の証明書のフォルダーでの、ノードの証明書の更新（元のファイルは日時つきのフォルダーにコピーして残す）
- 📝TODO: 鍵を交換したときの、証明書のフォルダーへの配置
- 📝TODO: 期限の近い証明書に、cron などで気づけるようにする

### ハーベストとトランザクション

- ✅DONE: ハーベストのためのリンクと委任（古いリンクの解除、新しいリンク、委任の要求を1つのアグリゲートにまとめる。委任ではリモートと VRF の鍵を毎回作り直す）
- ✅DONE: トランザクションへの署名と連署と、ノードへの送信（ノードの証明書で名乗って、ノードと TLS でつなぐ）

### ノード

- ✅DONE: 近くて速いノードを探す（ノードと TLS でつなぎ、接続にかかる時間、高さ、ブロックの読み出しの速さを測る。REST のないノードも調べられる）
- ✅DONE: 見つけた速いノードを、catapult の peers-p2p.json の形式で書く
- 📝TODO: 測った結果を JSON や CSV で出す

### ライブラリのみ

- ✅DONE: catapult と同じ判定の署名の検証
- ✅DONE: リンク（アカウント、ノード、VRF）と Transfer とアグリゲートのトランザクションの読み書きとハッシュ、委任ハーベストの要求のメッセージの読み書き

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名、Merkle ツリー
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER、X.509 の証明書。shoestring と symbol-bootstrap の証明書のフォルダー（feature の `shoestring-compat` と `bootstrap-compat`）
- `heika-tls`: catapult と同じ設定（TLS 1.3、X25519）での TLS の接続と、相手の証明書の確認
- `heika-p2p`: ノードへの問い合わせ。ノードの情報、高さ、ほかのノードの一覧、ブロック
- `heika-transaction`: トランザクションの読み書き、署名、ハッシュ。リンク、Transfer、アグリゲート
- `heika-wallet`: ウォレットのための計算。BIP 39、SLIP-10、委任ハーベストの要求に使う公開鍵あての暗号化
- `heika-cli`: コマンドラインツール `heika`
- `heika-vectors`: Symbol の公式テストベクターと、公式の Python SDK で作ったベクターとの照合

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

Windows のバイナリはおまけ程度である。Unix 以外では、標準入力から読んだ秘密鍵が std のバッファに残り、書き出す秘密鍵のファイルも自分だけが読めるようにはならない。

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

heika cert ca --subject "CN=CA example" --out ca.crt.pem < ca.key.pem
heika cert node --ca-cert ca.crt.pem --public-key <公開鍵> --subject "CN=node example" --out node.crt.pem < ca.key.pem
heika cert renew --shoestring-certs-dir <フォルダー> < ca.key.pem
heika cert show node.full.crt.pem
heika cert show --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem

heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --delegate <ノードの公開鍵> --out harvesting.bin
heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --link-remote <公開鍵> --link-vrf <公開鍵> --out harvesting.bin
heika tx sign --network mainnet --out harvesting.signed.bin harvesting.bin < main.key
heika tx cosign --network mainnet --out harvesting.cosigned.bin harvesting.signed.bin < cosigner.key
heika tx announce --network mainnet --connect <ホスト>:<ポート> --client-cert node.full.crt.pem harvesting.signed.bin < node.key.pem

heika node find --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem
heika node find --connect <ホスト>:<ポート> --client-cert node.full.crt.pem --crawl --limit 300 --peers-json peers-p2p.json < node.key.pem

heika legal third-party
heika legal source --out heika-source.zip
```

秘密鍵とニーモニックは標準入力からのみ読む。扱いの方針は [docs/secrets.md](docs/secrets.md) にある。

DN は RFC 4514 の形（`CN=node,O=example`）でも、OpenSSL の `-subj` の形（`/O=example/CN=node`）でも書ける。2 つは区切りが違い、書く順番も逆になる。証明書を表示するときは RFC 4514 の形で出す。

`heika harvesting` は、リンクの解除、紐づけ、委任の要求を1つのアグリゲートにまとめる。`--delegate` を付けると、リモートアカウントと VRF の鍵をその場で作り、委任先のノードにだけ渡す。前の委任先のノードは古い鍵を知っているので、使い回すとそのノードがハーベストを続けられてしまうためである。自分のノードでハーベストするなら、`heika key generate` で作った鍵の公開鍵を `--link-remote` と `--link-vrf` に渡す。古いリンクは `--unlink-remote`、`--unlink-vrf`、`--unlink-node` で外す。外すべき公開鍵は、前回の `heika harvesting` が表示する。組むのに秘密鍵は要らず、メインアカウントの秘密鍵は `heika tx sign` で読む。マルチシグのアカウントなどで連署が要るときは、署名したものに `heika tx cosign` で1人ずつ連署を足す。連署するのは外側の署名を含むハッシュなので、先に署名しておく。`heika tx announce` は、ネットワーク、署名と連署、期限を確かめてから送る。ノードは受け取ったことを返さないので、ブロックに入ったかは、表示するハッシュで確かめる。

`heika node find` は、最初につないだノードからほかのノードの一覧をもらい、1つずつ順につないで測る。`--crawl` を付けると、測ったノードからも一覧をもらってたどるので、ネットワーク全体を調べられる。名乗る証明書は、ノードを持っていなくても `heika cert ca` と `heika cert node` で作れる。同じ IP から違う証明書で次々につなぐとノードに嫌われるので、いつも同じ証明書を使う。

`--peers-json` を付けると、測ったノードのうち、Peer のロールがあって遅れが 5 ブロック以下のノードを、読み出しの速い順に `--peers-count` 台（既定は 10 台）選び、catapult の `peers-p2p.json` の形式で書く。公開鍵は、ノードが名乗ったものではなく、TLS で確かめた CA の公開鍵を書く。自分のノードの証明書で名乗っていれば、自分のノードは除く。すでにあるファイルは上書きしないので、ノードの `resources/peers-p2p.json` には、中身を確かめてから置き換える。

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --include-ignored  # 公式ベクターと SDK のベクターとの照合。公式ベクターはネットワークから取る
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
