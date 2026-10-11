# heika

Symbol のノード運営のための、鍵と証明書の Rust のツールキット。

## 機能

- ✅DONE: ニーモニックの生成と、公式ウォレットと同じパスでの鍵とアドレスの導出
- ✅DONE: 秘密鍵の生成と、公開鍵とアドレスの導出
- ✅DONE: 鍵の PEM と16進の相互変換
- ✅DONE: catapult と同じ判定の署名の検証（ライブラリのみ）
- ✅DONE: CA とノードの証明書の発行（DN と有効期間を指定できる。今は v1 のみ）
- ✅DONE: 証明書の確認（有効期間、catapult がつなぐときの条件、CA の公開鍵のアドレス）
- 🚧WIP: v3 の証明書（shoestring と同じ拡張）
- 🚧WIP: shoestring や symbol-bootstrap のフォルダーへの証明書の配置
- 🚧WIP: OpenSSL の形（/CN=node）の DN
- 🚧WIP: VRF キーなどを紐づけるリンクのトランザクション

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER、X.509 の証明書
- `heika-wallet`: ウォレットのための計算。BIP 39、SLIP-10
- `heika-cli`: コマンドラインツール `heika`
- `heika-vectors`: Symbol の公式テストベクターとの照合。ベクターはテスト時に取得する

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
heika cert show node.full.crt.pem
```

秘密鍵とニーモニックは標準入力からのみ読む。扱いの方針は [docs/secrets.md](docs/secrets.md) にある。

DN は RFC 4514 の形（`CN=node,O=example`）で書く。OpenSSL の `-subj`（`/O=example/CN=node`）とは区切りが違い、順番も逆になる。

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --ignored  # 公式ベクターとの照合。ネットワークを使う
```

方針は [docs/testing.md](docs/testing.md) にある。

## ライセンス

AGPL-3.0-only。BIP 39 の単語リストは MIT（[crates/heika-wallet/src/bip39/NOTICE](crates/heika-wallet/src/bip39/NOTICE)）。
