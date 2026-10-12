heika {{VERSION}}

Symbol（XYM）のノード運営のための、鍵と証明書のコマンドラインツールです。
ダブルクリックでは動きません。ターミナル（Windows では PowerShell）から使います。

https://github.com/{{REPOSITORY}}


■ 入っているもの

  heika（Windows では heika.exe）  本体
  README.txt                       このファイル
  docs/                            コマンドごとの詳しい説明
  LICENSE                          heika のライセンス（AGPL-3.0）
  THIRD-PARTY-LICENSES             本体に入っている、ほかのソフトウェアのライセンス
  NOTICE-BIP39                     BIP 39 の単語リストのライセンス（MIT）


■ ダウンロードしたものを確かめる

Release のページにある SHA256SUMS と、ダウンロードしたファイルのハッシュが同じかを確かめます。

  Linux と macOS:
    sha256sum --check --ignore-missing SHA256SUMS

  Windows（PowerShell）:
    Get-FileHash {{ARCHIVE}}
    出てきた Hash を、SHA256SUMS の {{ARCHIVE}} の行と見比べます。

GitHub CLI があれば、GitHub Actions で作ったものかどうかも確かめられます。

    gh attestation verify {{ARCHIVE}} --repo {{REPOSITORY}}


■ 動かす

  Windows:
    エクスプローラーでこのフォルダーを開き、アドレスバーに powershell と入れて Enter を押します。
    .\heika.exe --help

  macOS:
    ブラウザーでダウンロードすると、Apple の公証を受けていないため Gatekeeper に止められます。
    ターミナルでこのフォルダーに移り、印を外してから動かします。
    xattr -d com.apple.quarantine heika
    ./heika --help

  Linux:
    ./heika --help

どのフォルダーからでも heika と打って使いたいときは、PATH の通ったフォルダーに置きます。
コマンドごとの使い方は、heika cert --help のように --help を付けると出ます。


■ たとえば

ノードの証明書を更新して、期限を確かめる（shoestring のとき）。

  heika cert renew --shoestring-certs-dir <フォルダー> < ca.key.pem
  heika cert check --warn-days 30 --shoestring-certs-dir <フォルダー>

ニーモニックを作って、パスフレーズで暗号化したキーストアにしまう。

  heika wallet add --mnemonic --label main --network mainnet
  heika wallet list


■ 気をつけること

- 秘密鍵、ニーモニック、キーストアのパスフレーズは、誰にも見せません。チャット、メール、Web のフォームにも貼りません。heika の作者を名乗る人に聞かれても教えません。
- 秘密鍵とニーモニックは、標準入力（< ファイル名）からだけ読みます。コマンドの引数には書きません。
- ニーモニックは紙にも控えます。キーストアのファイルは、なくしたりパスフレーズを忘れたりすると開けなくなるので、バックアップの代わりにはなりません。
- Windows では、書き出した秘密鍵のファイルは、置いたフォルダーの権限を引き継ぎます。自分のユーザーのフォルダーの中に置きます。


■ 詳しい説明

docs/ の中のファイルは、メモ帳などで読めるテキストです。

  docs/keys.md        鍵の生成と変換、キーストア
  docs/cert.md        証明書の発行、更新、確認
  docs/harvesting.md  投票鍵、ハーベストのリンクと委任、トランザクションの署名と送信
  docs/node.md        速いノードを探す、ノードあての委任の一覧
  docs/secrets.md     秘密の扱いの方針
  docs/keystore.md    キーストアのファイルの形式


■ ライセンス

heika は AGPL-3.0-only です。本体には、heika とほかのソフトウェアのライセンスと、ビルドしたときのソースが入っていて、次で取り出せます。

  heika legal third-party
  heika legal source --out heika-source.zip
