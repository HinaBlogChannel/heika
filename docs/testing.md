# テスト

## 単体テスト

`cargo test` で実行する。ネットワークは使わない。

- 期待値には、仕様や参照実装が公開しているテストベクターを使う。
  - Ed25519: RFC 8032 の 7.1 節
  - BIP 39: trezor/python-mnemonic の `vectors.json`
  - SLIP-10: SLIP-0010 の ed25519 のテストベクター 1
- Symbol の公式テストベクターは単体テストに書き写さない。公式ベクターとの照合は `heika-vectors` にまとめる。
- 秘密を扱うものは、値の正しさに加えて、`Debug` やエラーに中身が出ないことも確かめる。

## 公式ベクターとの照合

`cargo test -p heika-vectors -- --ignored` で実行する。

- github.com/symbol/symbol の `tests/vectors/symbol/` から、コミットを固定した URL でテストのたびに取得する。リポジトリには含めない。
- 固定するコミットは `crates/heika-vectors/src/lib.rs` の `COMMIT` にある。
- ネットワークを使うので、`heika-vectors` はワークスペースの `default-members` から外し、テストには `#[ignore]` を付けている。

| ベクター | 照合する内容 |
| --- | --- |
| `crypto/1.test-keys.json` | 秘密鍵から公開鍵 |
| `crypto/1.test-address.json` | 公開鍵からメインネットとテストネットのアドレス |
| `crypto/6.test-hd-derivation.json` | ニーモニックからシード、シードから子の鍵、ネットワークごとのパス |

## 入力の検証

- ライブラリは Symbol の SDK と同じ範囲の入力を受け付ける。
- 利用者が打ち間違えうる値は、CLI の引数の解析で厳しく弾く。たとえば `--account` は hardened のビットが立たない範囲に限る。

## コミットの前に

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test
```
