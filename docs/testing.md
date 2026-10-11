# テスト

## 単体テスト

`cargo test` で実行する。ネットワークは使わない。

- 期待値には、仕様や参照実装が公開しているテストベクターを使う。
  - Ed25519: RFC 8032 の 7.1 節
  - BIP 39: trezor/python-mnemonic の `vectors.json`
  - SLIP-10: SLIP-0010 の ed25519 のテストベクター 1
  - PEM と DER: RFC 8410 の 10.1 節と 10.3 節の例
- 証明書は、OpenSSL 3.5 で作った v3 の証明書と P-256 の証明書（`crates/heika-cert/testdata/`）を読めることも確かめる。作るのに使った鍵は置かない。
- TLS の接続は、テストの中に立てた rustls のサーバーで確かめる。こちらの証明書を受け付けるサーバーと弾くサーバーの両方を使う。
- heika-cert の `certs_dir` は feature を有効にしたときだけコンパイルされる。ワークスペースの `cargo test` では heika-cli が有効にするので走る。heika-cert だけを試すときは `--all-features` を付ける。
- Symbol の公式テストベクターは単体テストに書き写さない。公式ベクターとの照合は `heika-vectors` にまとめる。
- 秘密を扱うものは、値の正しさに加えて、`Debug` やエラーに中身が出ないことも確かめる。
- 署名の検証は、catapult が弾くものと通すものの境界をテストに入れる。正しい署名が通ることだけでは、判定が catapult と同じかどうかはわからないためである。

## 公式ベクターとの照合

`cargo test -p heika-vectors -- --include-ignored` で実行する。下の SDK で作ったベクターとの照合も一緒に走る。

- github.com/symbol/symbol の `tests/vectors/symbol/` から、コミットを固定した URL でテストのたびに取得する。リポジトリには含めない。
- 固定するコミットは `crates/heika-vectors/src/lib.rs` の `COMMIT` にある。
- ネットワークを使うので、`heika-vectors` はワークスペースの `default-members` から外し、テストには `#[ignore]` を付けている。

| ベクター | 照合する内容 |
| --- | --- |
| `crypto/1.test-keys.json` | 秘密鍵から公開鍵 |
| `crypto/1.test-address.json` | 公開鍵からメインネットとテストネットのアドレス |
| `crypto/2.test-sign.json` | 秘密鍵でデータに署名した結果と、その署名の検証 |
| `crypto/3.test-derive-hkdf.json` | 秘密鍵と相手の公開鍵から、委任ハーベストの要求の暗号化に使う共有鍵 |
| `crypto/4.test-cipher.json` | 共有鍵での AES-GCM の暗号化と復号 |
| `crypto/6.test-hd-derivation.json` | ニーモニックからシード、シードから子の鍵、ネットワークごとのパス |
| `models/transactions.json` | トランザクションのバイト列と中身の読み書き（リンク、Transfer、中身がそれらだけのバージョン 3 のアグリゲート）。ここの署名はレイアウトを試すための値で、検証は通らない |

## SDK で作ったベクター

公式ベクターにはトランザクションの正しい署名とハッシュがないので、公式の Python SDK で署名したものを `crates/heika-vectors/testdata/sdk-transactions.json` に置いて照合する。

- `crates/heika-vectors/scripts/generate-sdk-vectors.py` が作る。SDK のバージョンはスクリプトの先頭のインラインメタデータで固定していて、`uv run` で動く。
- 鍵は、誰でも知っているテスト用のニーモニック（test を11個並べて最後が junk）から SDK のパスで導出する。このアカウントには何も送らない。
- 鍵以外の値は `SHA-256("<ラベル>/<番号>")` から切り出すので、作り直せば同じものが出る。スクリプトを変えたら作り直して差分を確かめる。
- 委任ハーベストの要求では、SDK が `secrets.token_bytes` で作る使い捨ての鍵と初期化ベクトルを、`SHA-512("harvest-request/randomness/<番号>")` から切り出したものに差し替える。照合では同じバイト列を乱数として渡す。
- 照合では、ニーモニックから heika-wallet で鍵を導出し、heika-transaction で組んで署名した結果が、署名、ハッシュ、バイト列のすべてで SDK と一致することを確かめる。アグリゲートは、中のトランザクションを0から5件入れ、外側と違うアカウントが中のトランザクションの署名者なら、そのアカウントで連署する。
- 委任ハーベストの要求は、メッセージのバイト列が SDK と一致することと、ノードの鍵で復号すると元の鍵に戻ることを確かめる。
- ネットワークを使わないので `#[ignore]` は付けていない。
- スクリプトは AGPL から外して MIT にしている。

```sh
uv run crates/heika-vectors/scripts/generate-sdk-vectors.py > crates/heika-vectors/testdata/sdk-transactions.json
```

## 入力の検証

- ライブラリは Symbol の SDK と同じ範囲の入力を受け付ける。
- 利用者が打ち間違えうる値は、CLI の引数の解析で厳しく弾く。たとえば `--account` は hardened のビットが立たない範囲に限る。

## コミットの前に

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test
```

## GitHub Actions

- `.github/workflows/ci.yaml`: `master` への push と PR で、整形、clippy（警告はエラーにする）、`cargo test`、`heika-cert` の `--all-features`、公式ベクターと SDK のベクターとの照合を回す。最後に SDK のベクターを作り直し、コミットしたものと差分がないことを確かめる。依存のライセンスの一覧（`crates/heika-cli/THIRD-PARTY-LICENSES`）も cargo-about で作り直し、同じように確かめる。依存を変えたら、`crates/heika-cli` で `cargo about generate --locked about.hbs -o THIRD-PARTY-LICENSES` をしてコミットする。
- `.github/workflows/release.yaml`: `v*` のタグで、4つのターゲットのバイナリを `ci.yaml` と並べて作り、`ci.yaml` が通ったら `SHA256SUMS` と来歴の証明を付けて Release に載せる。タグは `Cargo.toml` のバージョンと同じでなければならず、`v0.2.0-rc.1` のようにハイフンのあるタグはプレリリースにする。手で回すとビルドまでして Release は作らないので、ビルドが通るかだけを試せる。
- Rust のツールチェインは、ワークフローの `RUST_TOOLCHAIN` で固定する。Action はコミットのハッシュで固定する。
