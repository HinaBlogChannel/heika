# heika

Symbol のノード運営のための、鍵と証明書の Rust のツールキット。

## 機能

- ✅DONE: ニーモニックの生成と、公式ウォレットと同じパスでの鍵とアドレスの導出
- ✅DONE: 秘密鍵の生成と、公開鍵とアドレスの導出
- ✅DONE: 鍵の PEM と16進の相互変換
- ✅DONE: catapult と同じ判定の署名の検証（ライブラリのみ）
- 🚧WIP: ノードの証明書の作成と更新（有効期間を指定できる）
- 🚧WIP: 証明書の確認（期限、メインアカウントのアドレス）
- 🚧WIP: VRF キーなどを紐づけるリンクのトランザクション

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER
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
```

秘密鍵とニーモニックは標準入力からのみ読む。扱いの方針は [docs/secrets.md](docs/secrets.md) にある。

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --ignored  # 公式ベクターとの照合。ネットワークを使う
```

方針は [docs/testing.md](docs/testing.md) にある。

## ライセンス

AGPL-3.0-only。BIP 39 の単語リストは MIT（[crates/heika-wallet/src/bip39/NOTICE](crates/heika-wallet/src/bip39/NOTICE)）。
