# heika

**Symbol のノードを、アプリの部品にする。**

heika は、Symbol（XYM。NEM の後継のブロックチェーン）のノードを、Rust の部品に分けて作り直したものだ。ブロックの確かめ、状態遷移、チェーンを追う中核、ピアとのやりとり、ハーベスト、ファイナライズの投票まで、どれも crate として取り出して、自分のアプリに組み込める。部品を組み上げたノードも動き、catapult と並んでメインネットに入って先端を追い、ハーベストし、投票する。

## なぜ部品にするのか

ふつう、Symbol のアプリはノードの REST に問い合わせて、返ってきた答えを信じる。heika の部品を使えば、アプリがチェーンを自分で確かめられる。

**REST を信じない。** REST の答えからブロックやトランザクションや状態を組み直し、署名、ハッシュ、StateHash まで求め直す。どの REST から取っても、間違った答えは弾かれる。

**どこでもノードになる。** チェーンを追う中核、未承認のトランザクションの置き場、ファイナライズの段取り、ピアの選び方は IO を持たない（sans-IO）。だからデスクトップでも、Android の裏でも、ブラウザの中（wasm）でもノードになる。

**ブロックの中身を自分で決める。** ハーベストするノードを自分のコードで組めるので、自分のブロックに何をどう並べるかに手を入れられる。Symbol の規則は変えないので、catapult もそのブロックを受け入れる。

**catapult と同じ計算をする。** 署名の検証は catapult と同じ判定にし、公式のテストベクター、公式の Python SDK、メインネットのブロックと照合している。

## 部品で組んだもの

### アプリ

- **`heika`**: コマンドラインツール。ノードの証明書の発行と更新、ハーベストのリンクと委任、投票鍵、トランザクションの組み立て、確かめ、署名、送信。それに、ノードそのもの（`heika peer start`）。下の[コマンドラインツール](#コマンドラインツール)と[使い方](#使い方)
- **heika GUI**（[apps/heika-gui](apps/heika-gui)）: ウォレットとノード。iOS のほかでは、「ノード」のタブのボタン1つでノードが動き、Android でも裏で動き続ける
- **ノード**: ブロックの署名、VRF の証明、StateHash、ファイナライズの証明まで自分で確かめながら追いつき、先端を追う。残し方はアーカイブ、フル、ライトから選べる。ハーベストし、ほかの人の委任を引き受け、ファイナライズに投票し、catapult の REST の一部と同じ形で答える口も立てる。[docs/peer.md](docs/peer.md)

### ブラウザで動く例

heika の crate を wasm にして、ブラウザだけで動かす。どれも静的なページで、サーバーは要らない。

- [node-web](https://hinablogchannel.github.io/heika/examples/node-web/): ブラウザの中のノード。公開ノードの REST からブロックを取り、Nemesis から署名、難易度、VRF、状態のハッシュまで確かめながら同期し、先端を追う。REST の答えは信じない。DB はネイティブの heika と同じ redb をブラウザの中（OPFS）に置く。委任を受けてハーベストし、作ったブロックを heika のノードに出すこともできる
- [web-vanitygen](https://hinablogchannel.github.io/heika/examples/web-vanitygen/): 決まった文字で始まるアドレスを探す。鍵はブラウザの中で作り、外に出さない
- [すんぼる草不可避](https://hinablogchannel.github.io/heika/examples/sunboru-kusa/): 送金で、畑に草が生える。何が生えるかは送金のハッシュだけで決まる

### ブロックの中身に手を入れる例

- [instant-rebate](examples/instant-rebate): 即時還元。委任してくれた人のブロックの中で、受取先の分の一部をその人に返す。還元が入っているかは、ブロックを見れば1つずつ確かめられる
- [intent-dex](examples/intent-dex): 預けない交換。署名済みの注文を、ハーベスターが自分のブロックの中で約定させる

### Symbol を掲示板にする例

Symbol のハードフォークは要らない。ファイナライズされたブロックの並びを、後から間に差し込めない掲示板として使う。

- [evm-rollup](examples/evm-rollup): Symbol の上の EVM。EVM のトランザクションを Symbol のメッセージに載せ、Symbol のブロックの順に実行する。XYM を EVM に持ち込み、持ち帰る橋もある
- [dkg](examples/dkg): ディーラーなしで、FROST の鍵を参加者で分けて作る。やりとりは全部 Symbol のメッセージに載せる
- [roast](examples/roast): 400 人で分けて持つ鍵で、ふつうのアカウントの送金に署名する
- [evm-bridge](examples/evm-bridge): XYM を EVM のチェーンに持っていく橋。見張り役みんなで分けて持つ鍵の署名1つで認める
- [adaptor-swap](examples/adaptor-swap): ほかのチェーンとの、誰にも預けない交換の Symbol 側。アダプター署名で、連署を出すと相手に秘密がばれるようにする

### そのほかの例

- [faucet](examples/faucet): 自分で立てたネット向けの蛇口。ページ1枚から XYM を配る
- [vanitygen-nvptx](examples/vanitygen-nvptx): heika-core をそのまま NVIDIA の GPU の上で動かして、アドレスを探す

## 部品の一覧

各 crate の API の文書は、リリースした版のものを [Pages](https://hinablogchannel.github.io/heika/crates/) に置いている。

ノードと同じ計算。std がなくても（alloc があれば）使える。

- `heika-core`: アドレス、鍵、署名、VRF の証明、Merkle ツリーとその経路、状態の Patricia Merkle の証明と StateHash、ネットワーク時刻
- `heika-transaction`: トランザクションの読み書き、署名、ハッシュ。catbuffer にある25種類すべてと、送る前の確認
- `heika-block`: ブロックの読み込み、署名の確認、ハッシュ。ハーベストの当たり判定、レシートとステートメント、ファイナライズの投票と証明

ファイルと通信。

- `heika-cert`: ノードの TLS で使う鍵と証明書のファイル。shoestring と symbol-bootstrap の証明書のフォルダーも読み書きする
- `heika-packet`: ノードどうしがやりとりするパケットの形
- `heika-tls`: catapult と同じ設定（TLS 1.3、X25519）での TLS の接続
- `heika-peer-protocol`: ノードへの問い合わせ
- `heika-rest`: REST が返す JSON を heika の型に組み直して確かめる。HTTP は持たない
- `heika-wallet`: BIP 39、SLIP-10、キーストア、暗号化したメッセージ、委任ハーベストの要求

ノードの中身。IO を持たない。

- `heika-state-transition`: catapult と同じ規則でブロックを当て、状態の木と StateHash を求める
- `heika-chain`: チェーンを追う中核。ブロックと証明を確かめて先端を進め、枝を取り替え、ハーベストする
- `heika-mempool`: 未承認のトランザクションの置き場
- `heika-finalization`: ファイナライズの投票の段取り
- `heika-peer`: ピアについての意思決定。住所録、つなぐ相手、外したピアの罰

ノードの組み立て。

- `heika-store-redb`: ブロック、状態、差分、ファイナライズの証明を redb にしまう
- `heika-harvesting`: ノードへの委任ハーベスト。委任の要求を拾い、今も有効かを確かめる
- `heika-node`: ノードを組み立てて動かす
- `heika-api`: ノードの REST

道具。

- `heika-cli`: コマンドラインツール `heika`
- `heika-vectors`: 公式のテストベクター、公式の Python SDK で作ったベクター、メインネットのブロックとの照合

## コマンドラインツール

`heika` は、数か月から1年に一度しか来ないノードの鍵の作業（証明書の更新、ハーベストの委任、投票鍵の作り直し）をコマンドにまとめ、秘密の扱いを道具の側で守る。

**バイナリ1つで動く。** Linux 向けは静的にリンクしてあり、Node.js も Python も Docker も要らない。ノードのサーバーにも、ネットワークから切り離したマシンにも、そのまま置ける。

**秘密を残さない。** 秘密鍵とニーモニックは標準入力からだけ読み、引数やシェルの履歴に残さない。使い終えたらメモリから 0 で消し、しまうときは age 形式で暗号化する。age なら、heika がなくても開ける。依存ライブラリの中で消しきれないものも含めて、[docs/secrets.md](docs/secrets.md) にまとめてある。

**組む、確かめる、署名する、送るを分ける。** トランザクションを組むのに秘密鍵は要らない。署名する前に `heika tx show` で中身を読める形で確かめられ、ノードで弾かれるところがあればその理由も出る。署名はネットワークにつながずにできる。

**今の構成のまま使える。** shoestring や symbol-bootstrap を置き換えるのではなく、その証明書のフォルダーをそのまま読み書きする。

ほかにも、近くて速いノードを探す、アカウントの残高を StateHash まで確かめて出す、XYM を送ってブロックに入ったことを TransactionsHash への経路で確かめる、などいろいろ。すべての機能は、[使い方](#使い方)にある各文書の「できること」にまとめてある。

## インストール

Releases に、次のバイナリを置いている。

- Linux の x86_64 と aarch64（musl で静的にリンクしたもの）
- macOS の Apple Silicon と Intel
- Windows の x86_64

ダウンロードしたものは、`SHA256SUMS` と、GitHub Actions で作ったことを示す来歴の証明で確かめられる。

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify heika-<バージョン>-<ターゲット>.tar.gz --repo <リポジトリ>
```

macOS のバイナリは Apple の公証を受けていない。ブラウザーでダウンロードすると Gatekeeper に止められるので、`curl` で取るか、`xattr -d com.apple.quarantine heika` で印を外す。

Windows でも、標準入力から読んだ秘密鍵を std のバッファに残さず、コンソールから打った文字は画面に出さない。ただし、書き出す秘密鍵のファイルは、Unix のように自分だけが読めるようにはできず、置いたフォルダーの権限を引き継ぐ。自分のユーザーのフォルダーの中に置く。

ウォレットの GUI（`heika-gui-v…`）も、同じ Release に置いている。どれも上と同じように確かめられる。iOS のほかでは、ノードも「ノード」のタブから動かせる。

- Linux の x86_64: `.deb`、`.rpm`、`.AppImage`
- macOS: `.dmg`。`-macos-universal` は Apple Silicon と Intel のどちらでも動く。迷ったらこれを使う。`-macos-aarch64`（Apple Silicon）と `-macos-x86_64`（Intel）は、そのチップの分だけが入った小さいもの。公証を受けていないので、上の `xattr` で印を外してから開く
- Windows の x86_64: `.msi` と `-setup.exe`。署名していないので、SmartScreen に止められたら「詳細情報」から実行する
- Android の aarch64: `.apk`。署名の証明書の SHA-256 は `79b38fb9557cf0249f75aadf806805f3e5b4f6b196a69b6f986c075cdb64c5ad` で、`apksigner verify --print-certs` で確かめられる。どの版もこの鍵で署名するので、上書きして更新できる
- iOS: `-unsigned.ipa`。署名していないので、自分で署名し直して入れる

コンテナイメージは `ghcr.io/hinablogchannel/heika` に、版のタグ（`v…`）と `latest` で置いている（linux/amd64 と linux/arm64）。中身は Releases の Linux のバイナリと同じもので、ほかには CA 証明書だけが入っている。非 root（UID 65532）で動き、データの置き場は `/data`。作り方と動かし方は [containers/heika/Dockerfile](containers/heika/Dockerfile) の頭に書いた。イメージも同じように確かめられる。

```sh
docker run --rm ghcr.io/hinablogchannel/heika:<バージョン> --version
gh attestation verify oci://ghcr.io/hinablogchannel/heika:<バージョン> --repo <リポジトリ>
```

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

- [docs/keys.md](docs/keys.md): 鍵の生成と変換、キーストア、確かめた残高、上級者向けの公開鍵の足し算（`heika key`、`heika wallet`、`heika account`、`heika expert`）
- [docs/cert.md](docs/cert.md): 証明書の発行、更新、確認（`heika cert`）
- [docs/harvesting.md](docs/harvesting.md): 投票鍵、ハーベストのリンクと委任、トランザクションの表示、署名、送信（`heika key voting`、`heika harvesting`、`heika tx`）
- [docs/node.md](docs/node.md): 速いノードを探す、ノードあての委任の一覧、投票するノードが集めている投票のメッセージ（`heika node`）
- [docs/peer.md](docs/peer.md): ノードと、その DB を刈り込んだ写し（`heika peer start`、`heika peer copy`）
- [docs/nemesis.md](docs/nemesis.md): 新しいネットワークの Nemesis のブロックと seed フォルダーを作る（`heika nemgen`）
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

ノードの REST を立てると、同じ ZIP を `GET /heika/sourcecode.zip` でも返す。REST を立てなくても、ほかの heika には P2P で渡し、`heika node source` でもらえる（[docs/peer.md](docs/peer.md)）。

バイナリに入れたソースは、実行しなくても取り出せる。動かせないアーキテクチャのバイナリや、実行したくないバイナリからでも取り出せるように、決まった名前のセクションに置いている。

```sh
objcopy -O binary --only-section=.heika_source heika heika-source.zip      # Linux
segedit heika -extract __TEXT __heika_source heika-source.zip              # macOS
llvm-objcopy --dump-section .hksrc=heika-source.zip heika.exe              # Windows
```
