# heika

Symbol のピアプロトコルを話すための Rust のツールキット。ノードの 7900 番ポートに直接つなぐことを目指す。

現在は鍵とアドレスまわりのみ実装している。

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵
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
