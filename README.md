# heika

Symbol のノード運営のための、鍵と証明書の Rust のツールキット。

## 機能

- ✅DONE: ニーモニックの生成と、公式ウォレットと同じパスでの鍵とアドレスの導出
- ✅DONE: 秘密鍵の生成と、公開鍵とアドレスの導出
- ✅DONE: 鍵の PEM と16進の相互変換
- ✅DONE: catapult と同じ判定の署名の検証（ライブラリのみ）
- ✅DONE: CA とノードの証明書の発行（DN と有効期間を指定できる。v3 は shoestring と同じ拡張、v1 も選べる）
- ✅DONE: DN は RFC 4514 の形（CN=node,O=example）でも OpenSSL の形（/O=example/CN=node）でも書ける
- ✅DONE: 証明書の確認（有効期間、catapult がつなぐときの条件、CA の公開鍵のアドレス）
- ✅DONE: ノードが実際に出している証明書の確認（TLS でつなぎ、こちらの証明書が受け付けられるかも確かめる）
- ✅DONE: shoestring や symbol-bootstrap の証明書のフォルダーでのノードの証明書の更新（元のファイルは日時つきのフォルダーにコピーして残す）
- ✅DONE: リンク（アカウント、ノード、VRF）と Transfer とアグリゲートのトランザクションの読み書き、署名、連署、ハッシュ（ライブラリのみ）
- ✅DONE: 委任ハーベストの要求のメッセージの読み書き（ライブラリのみ）
- 🚧WIP: 鍵を交換したときの、証明書のフォルダーへの配置
- ✅DONE: ハーベストのためのリンクと委任（古いリンクの解除、新しいリンク、委任の要求を1つのアグリゲートにまとめる。委任ではリモートと VRF の鍵を毎回作り直す）と、トランザクションへの署名
- ✅DONE: 署名したトランザクションの送信（ノードの証明書で名乗って、ノードと TLS でつなぐ）

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名、Merkle ツリー
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER、X.509 の証明書。shoestring と symbol-bootstrap の証明書のフォルダー（feature の `shoestring-compat` と `bootstrap-compat`）
- `heika-tls`: catapult と同じ設定（TLS 1.3、X25519）での TLS の接続と、相手の証明書の確認
- `heika-transaction`: トランザクションの読み書き、署名、ハッシュ。リンク、Transfer、アグリゲート
- `heika-wallet`: ウォレットのための計算。BIP 39、SLIP-10、委任ハーベストの要求に使う公開鍵あての暗号化
- `heika-cli`: コマンドラインツール `heika`
- `heika-vectors`: Symbol の公式テストベクターと、公式の Python SDK で作ったベクターとの照合

## 使い方

```sh
cargo install --path crates/heika-cli

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
heika tx announce --network mainnet --connect <ホスト>:<ポート> --client-cert node.full.crt.pem harvesting.signed.bin < node.key.pem
```

秘密鍵とニーモニックは標準入力からのみ読む。扱いの方針は [docs/secrets.md](docs/secrets.md) にある。

DN は RFC 4514 の形（`CN=node,O=example`）でも、OpenSSL の `-subj` の形（`/O=example/CN=node`）でも書ける。2 つは区切りが違い、書く順番も逆になる。証明書を表示するときは RFC 4514 の形で出す。

`heika harvesting` は、リンクの解除、紐づけ、委任の要求を1つのアグリゲートにまとめる。`--delegate` を付けると、リモートアカウントと VRF の鍵をその場で作り、委任先のノードにだけ渡す。前の委任先のノードは古い鍵を知っているので、使い回すとそのノードがハーベストを続けられてしまうためである。自分のノードでハーベストするなら、`heika key generate` で作った鍵の公開鍵を `--link-remote` と `--link-vrf` に渡す。古いリンクは `--unlink-remote`、`--unlink-vrf`、`--unlink-node` で外す。外すべき公開鍵は、前回の `heika harvesting` が表示する。組むのに秘密鍵は要らず、メインアカウントの秘密鍵は `heika tx sign` で読む。`heika tx announce` は、ネットワーク、署名、期限を確かめてから送る。ノードは受け取ったことを返さないので、ブロックに入ったかは、表示するハッシュで確かめる。

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --include-ignored  # 公式ベクターと SDK のベクターとの照合。公式ベクターはネットワークから取る
cargo test -p heika-cert --all-features             # heika-cert だけを、feature つきのモジュールも含めて
```

方針は [docs/testing.md](docs/testing.md) にある。

## ライセンス

AGPL-3.0-only。BIP 39 の単語リストは MIT（[crates/heika-wallet/src/bip39/NOTICE](crates/heika-wallet/src/bip39/NOTICE)）。ベクターを作るスクリプト（`crates/heika-vectors/scripts/`）は MIT。
