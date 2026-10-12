# 証明書

## できること

- CA とノードの証明書の発行（v3 は shoestring と同じ拡張で、v1 も選べる。DN は RFC 4514 の形（CN=node,O=example）でも OpenSSL の形（/O=example/CN=node）でも書ける）
- 証明書の確認。ファイルのほかに、ノードが実際に出しているものも確かめられる（有効期間、catapult がつなぐときの条件、CA の公開鍵のアドレス。ノードには、こちらの証明書が受け付けられるかも）
- shoestring や symbol-bootstrap の証明書のフォルダーでの、ノードの証明書の更新（元のファイルは日時つきのフォルダーにコピーして残す）
- 証明書の期限が近いことを、終了コードで知らせる（定期実行の仕組みから、そのまま呼べる。ファイル、証明書のフォルダー、ノードが実際に出しているものを確かめられる）

## コマンドの例

```sh
heika cert ca --subject "CN=CA example" --out ca.crt.pem < ca.key.pem
heika cert node --ca-cert ca.crt.pem --public-key <公開鍵> --subject "CN=node example" --out node.crt.pem < ca.key.pem
heika cert renew --shoestring-certs-dir <フォルダー> < ca.key.pem
heika cert show node.full.crt.pem
heika cert show --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem
heika cert check --warn-days 30 --shoestring-certs-dir <フォルダー>
heika cert check --warn-days 30 --connect <ホスト>:<ポート> --client-cert node.full.crt.pem < node.key.pem
```

## DN

DN は RFC 4514 の形（`CN=node,O=example`）でも、OpenSSL の `-subj` の形（`/O=example/CN=node`）でも書ける。2 つは区切りが違い、書く順番も逆になる。証明書を表示するときは RFC 4514 の形で出す。

## 期限の確認

`heika cert check` は、証明書のファイル、証明書のフォルダー（CA とノードの証明書）、`--connect` のノードが実際に出している証明書について、期限までの日数を1行ずつ出す。終了コードは `openssl x509 -checkend` に合わせていて、期限まで `--warn-days` 日（既定は 30 日）を切ったもの、切れたもの、まだ有効でないものがあれば 1、確かめられないものがあれば 2、どれもなければ 0 になる。heika のほかのコマンドはエラーを 1 で返すので、ここだけ違う。定期実行は cron、systemd の timer、Kubernetes の CronJob など、使っている仕組みから呼ぶ。`--connect` は、ファイルを更新したのにノードを再起動していない、という状態も見つけられる。
