# heika

Symbol（XYM。NEM の後継のブロックチェーン）の、鍵と証明書の Rust のツールキット。試験的に、ノードそのものも動く。

## なぜ heika か

ノードの運用で鍵を扱う作業は、証明書の更新、ハーベストの委任、投票鍵の作り直しと、どれも数か月から1年に一度しか来ない。そのたびに手順を調べ直すことになり、秘密鍵をあちこちに貼る機会も増える。heika は、こうした作業をコマンドにまとめ、秘密の扱いを道具の側で守る。

**バイナリ1つで動く。** Linux 向けは静的にリンクしてあり、Node.js も Python も Docker も要らない。ノードのサーバーにも、ネットワークから切り離したマシンにも、そのまま置ける。

**秘密を残さない。** 秘密鍵とニーモニックは標準入力からだけ読み、引数やシェルの履歴に残さない。使い終えたらメモリから 0 で消し、しまうときは age 形式で暗号化する。age なら、heika がなくても開ける。依存ライブラリの中で消しきれないものも含めて、[docs/secrets.md](docs/secrets.md) にまとめてある。

**組む、確かめる、署名する、送るを分ける。** トランザクションを組むのに秘密鍵は要らない。署名する前に `heika tx show` で中身を読める形で確かめられ、ノードで弾かれるところがあればその理由も出る。署名はネットワークにつながずにできる。

**ノードと同じ計算をする。** 署名の検証は catapult と同じ判定にし、公式のテストベクター、公式の Python SDK、メインネットのブロックと照合している。

**今の構成のまま使える。** shoestring や symbol-bootstrap を置き換えるのではなく、その証明書のフォルダーをそのまま読み書きする。

**ノードも動く（試験的）。** `heika experimental peer start` か、GUI のボタン1つで、ピアとしてネットワークに入る。ブロックの署名、VRF の証明、StateHash、ファイナライズの証明まで自分で確かめながら追いつき、先端を追う。残し方はアーカイブ、フル、ライトから選べ、ライトなら Android でも裏で動き続ける。ハーベストもでき、鍵はキーストアから導出してノードのメモリにだけ渡すので、鍵のファイルをディスクに置かない。

## 機能

- ノードの証明書の発行と更新。shoestring や symbol-bootstrap の証明書のフォルダーをそのまま扱える
- 証明書の期限が近いことを、終了コードで知らせる。ファイルのほかに、ノードが実際に出している証明書も確かめられる
- ハーベストのリンクと委任、投票鍵の紐づけをトランザクションに組み、署名してノードへ送る
- ノードあての委任の一覧と、harvesters.dat に入っていない有効な委任の書き足し
- ニーモニックと秘密鍵を、パスフレーズで暗号化したキーストアにしまう。age 形式なので、heika がなくても `age -d` で開ける
- 試験的なノード。メインネットとテストネットに、ピアとして入って追いつき、先端を追う。残し方（アーカイブ、フル、ライト）を選べる。キーストアから導出した鍵で、CLI でも GUI でもハーベストできる

ほかにも、近くて速いノードを探す、アカウントの残高を StateHash まで確かめて出す、XYM を送って、ブロックに入ったことを TransactionsHash への経路で確かめる、トランザクションの中身を読める形で出す、鍵の PEM と16進を相互に変換する、などいろいろ。すべての機能は、[使い方](#使い方)にある各文書の「できること」にまとめてある。

## 構成

- `heika-core`: ノードと同じ計算をするもの。アドレス、鍵、署名（catapult と同じ判定の検証）、VRF の証明、Merkle ツリーとその経路、状態の Patricia Merkle の証明と StateHash、ネットワーク時刻、メインネットとテストネットで決まっている値
- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。PEM、DER、X.509 の証明書。shoestring と symbol-bootstrap の証明書のフォルダー（feature の `shoestring-compat` と `bootstrap-compat`）
- `heika-packet`: ノードどうしがやりとりするパケットの形。見出し、要求と応答の本体の組み立てと読み取りだけで、通信はしない
- `heika-tls`: catapult と同じ設定（TLS 1.3、X25519）での TLS の接続と、相手の証明書の確認。パケットを送り、受け取る
- `heika-peer-protocol`: ノードへの問い合わせ。ノードの情報、高さ、ほかのノードの一覧、ブロック、未承認のトランザクション
- `heika-transaction`: トランザクションの読み書き、署名、ハッシュ。catbuffer にある25種類すべて。署名するバイト列の取り出しと、別の場所で作った署名の付け方、切り離した連署、ネームスペースのフルネームからの ID、アドレスとモザイクの別名、手数料、メタデータの値の差分、メタデータと制限のキー、状態の中の1件を指すハッシュ。ノードが状態を見ずに弾くところ（メッセージの長さ、ID と名前の対応、単独では送れない種類など）の、送る前の確認
- `heika-block`: ブロックの読み込み、署名の確認、ハッシュ。中のトランザクションの切り分けと、TransactionsHash と VRF の証明の確認、トランザクションがブロックに入っていることの Merkle の経路。直前のブロックから決まる難易度と、ハーベストの当たり判定（hit と target）。レシートとステートメントの読み書きと、ReceiptsHash の確認。ファイナライズされたブロックの読み書き
- `heika-wallet`: ウォレットのための計算。BIP 39、SLIP-10、キーストア、暗号化したメッセージ（昔の公式ウォレットの形も読む）と委任ハーベストの要求の読み書きと、それに使う公開鍵あての暗号化
- `heika-rest`: REST が返す JSON を heika の型に変えて確かめる。HTTP は持たない。ノードとチェーンの情報、委任の様子の JSON の型も持ち、heika-api はこの型で答える。ブロックのヘッダーを組み直して署名、ハッシュ、generation hash、StateHash を求め直す。トランザクションを25種類すべて組み直して署名、ハッシュ、Merkle の葉を求め直す（中のトランザクションのないアグリゲートと、平たく並んだ中のトランザクションも）。レシートとステートメントを集めて ReceiptsHash を求め直す。アカウント、モザイク、ネームスペース、メタデータの状態を組み直し、状態の経路で確かめる。アカウントの残高とモザイクの可分性を、最新のブロックの StateHash まで確かめる（確かめるところは通信しない同期の計算で、取る順番と取り直しは、取ってくる関数を受け取る非同期の関数。どう取ってどう待つかは使う側が決める）。送るトランザクションの本文と、それがブロックに入ったことを、手元のトランザクションから求めた葉で TransactionsHash まで確かめる。heika の型から REST の形の JSON も書く。Merkle の経路と状態の証明
- `heika-state-transition`: 状態遷移。catapult と同じ規則でブロックを当て、9本の状態の木と StateHash を求める。メインネットとテストネットの設定を持つ。IO は持たない
- `heika-store-redb`: ブロック、状態、差分、ファイナライズの証明を redb にしまう。昔の高さの状態の問い合わせと、刈り込み
- `heika-chain`: チェーンを追う中核。ブロックと証明を確かめて先端を進め、枝を取り替え、ハーベストする。IO は持たない（sans-IO）
- `heika-mempool`: 未承認のトランザクションの置き場。状態に依らない確かめで受け付け、ブロックを作るときの候補と、ほかのノードへの答えを出す。IO は持たない
- `heika-peer`: ピアについての意思決定。住所録、つなぐ相手、外したピアの罰。IO は持たない（sans-IO）
- `heika-node`: ノードを組み立てて動かす。設定、ピアのスレッド、待ち受け、まとめて追いつく段階と先端を追う段階、委任ハーベストの引き受け
- `heika-api`: ノードの REST。catapult の REST のうち、ウォレットが委任に使う口（`/node/info`、`/chain/info`、`/node/unlockedaccount`）と、委任の様子を返す heika だけの口。ノードの駆動役が書いた様子を返すだけで、チェーンには触らない
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

ウォレットの GUI（`heika-gui-v…`）も、同じ Release に置いている。どれも上と同じように確かめられる。iOS のほかでは、試験的なノードも「ノード」のタブから動かせる。

- Linux の x86_64: `.deb`、`.rpm`、`.AppImage`
- macOS の Apple Silicon: `.dmg`。公証を受けていないので、上の `xattr` で印を外してから開く
- Windows の x86_64: `.msi` と `-setup.exe`。署名していないので、SmartScreen に止められたら「詳細情報」から実行する
- Android の aarch64: `.apk`。署名の証明書の SHA-256 は `79b38fb9557cf0249f75aadf806805f3e5b4f6b196a69b6f986c075cdb64c5ad` で、`apksigner verify --print-certs` で確かめられる。どの版もこの鍵で署名するので、上書きして更新できる
- iOS: `-unsigned.ipa`。署名していないので、自分で署名し直して入れる

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

- [docs/keys.md](docs/keys.md): 鍵の生成と変換、キーストア、確かめた残高（`heika key`、`heika wallet`、`heika account`）
- [docs/cert.md](docs/cert.md): 証明書の発行、更新、確認（`heika cert`）
- [docs/harvesting.md](docs/harvesting.md): 投票鍵、ハーベストのリンクと委任、トランザクションの表示、署名、送信（`heika key voting`、`heika harvesting`、`heika tx`）
- [docs/node.md](docs/node.md): 速いノードを探す、ノードあての委任の一覧（`heika node`）
- [docs/peer.md](docs/peer.md): 試験的なノード（`heika experimental peer start`）
- [docs/deploy.md](docs/deploy.md): systemd と Caddy で、ノードを P2P と REST で外に出す
- `heika legal`: heika と依存のライセンス、ビルドしたときのソース（下の「ライセンス」）

## テスト

```sh
cargo test
cargo test -p heika-vectors -- --include-ignored  # 公式ベクターと SDK のベクターとの照合。公式ベクターはネットワークから取る。メインネットのブロックは docs/testing.md の手順で
cargo test -p heika-cert --all-features             # heika-cert だけを、feature つきのモジュールも含めて
```

方針は [docs/testing.md](docs/testing.md) にある。

## ライセンス

AGPL-3.0-only。BIP 39 の単語リストは MIT（[crates/heika-wallet/src/bip39/NOTICE](crates/heika-wallet/src/bip39/NOTICE)）。バイナリに入る依存のクレートのライセンスは [crates/heika-cli/THIRD-PARTY-LICENSES](crates/heika-cli/THIRD-PARTY-LICENSES) にまとめてあり、Release のアーカイブにも入れている。バイナリそのものにも、heika と依存のライセンスと、ビルドしたときのソースを入れてあり、`heika legal` で取り出せる。 GUI の依存のライセンスは [apps/heika-gui/THIRD-PARTY-LICENSES](apps/heika-gui/THIRD-PARTY-LICENSES) にあり、アプリの設定の「ライセンスを見る」でも読める。ベクターを作るスクリプト（`crates/heika-vectors/scripts/`）は MIT。

```sh
heika legal third-party
heika legal source --out heika-source.zip
```

ノードの REST を立てると、同じ ZIP を `GET /heika/sourcecode.zip` でも返す（[docs/peer.md](docs/peer.md)）。

バイナリに入れたソースは、実行しなくても取り出せる。動かせないアーキテクチャのバイナリや、実行したくないバイナリからでも取り出せるように、決まった名前のセクションに置いている。

```sh
objcopy -O binary --only-section=.heika_source heika heika-source.zip      # Linux
segedit heika -extract __TEXT __heika_source heika-source.zip              # macOS
llvm-objcopy --dump-section .hksrc=heika-source.zip heika.exe              # Windows
```
