# ノードを外に出す

heika のノードを、外から P2P と REST でつながる形で動かす手順。`deploy/` の systemd のユニットと Caddyfile を使う。

| ポート | 受け持つもの | 中身 |
|---|---|---|
| 7900 | heika | P2P（TLS）。間に何も挟まずに heika が直接受ける（相手の IP が見えるように） |
| 3000 | Caddy | REST（HTTP） |
| 3001 | Caddy | REST（HTTPS）。証明書は Let's Encrypt |
| 80 | Caddy | Let's Encrypt の確かめ（HTTP-01）にだけ使う |
| 3002 | heika | REST の本体。`127.0.0.1` だけで待ち受け、Caddy が中継する |

## 1. 名前

ノードが名乗る名前と、証明書の名前を決める。自分のドメインがなければ、IP をハイフンで書いた sslip.io の名前
（`heika-1.203-0-113-7.sslip.io` など）が、そのまま IP に引ける。IP が変わると名前も変わるので、URL を人に配るなら
自分のドメインを取って、向け先だけ変えられるようにする。

## 2. ノード

```yaml
apiVersion: heika.hinablogchannel.github.io/v1alpha1
kind: Peer
metadata:
  name: heika-1
spec:
  network:
    type: mainnet
  dataDirectory: /srv/heika/data
  certificates:
    directory: /home/heika/heika-mainnet/certs
  seed: xym122.allnodes.me:7900
  listen:
    address: 0.0.0.0:7900
    publicHost: heika-1.203-0-113-7.sslip.io
    friendlyName: heika-1
  storage:
    mode: light
  beneficiary: N...              # ハーベストの報酬を受け取るアドレス
  delegations:
    max: 5
  rest:
    - address: 127.0.0.1:3002
```

- 鍵と証明書は、このノードのために新しく作る（`heika cert ca` と `heika cert node`）。ほかで使った鍵は使い回さない
- 受取人のアドレスも、新しく作ったものにする（`heika key generate` と `heika key address`）
- 項目の意味は [peer.md](peer.md)

`deploy/heika.service` を `/etc/systemd/system/heika.service` に置き、`User`、`WorkingDirectory`、`ExecStart` のパスを
直してから:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now heika
journalctl -u heika -f
```

止めるのは `sudo systemctl stop heika`。SIGTERM で今のブロックを書き終えるまで待つ（ユニットの
`TimeoutStopSec=infinity`）。バイナリを入れ替えるときは、動いているファイルに上書きせずに置き換えてから起動し直す:

```sh
install -m 755 heika /home/heika/heika-mainnet/bin/heika
sudo systemctl restart heika
```

起動し直すあいだの数秒に来た REST の要求は、Caddy が最大 15 秒待ってつなぎ直すので、エラーにならない。

## 3. Caddy

```sh
sudo apt install caddy
sudo install -m 644 deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl edit caddy        # [Service] に Environment=HEIKA_HOST=<1 の名前> を書く
sudo systemctl restart caddy
journalctl -u caddy -f           # certificate obtained successfully が出れば証明書が取れた
```

443 番を開けていなければ、Caddy はまず TLS-ALPN-01 を試して失敗し、続けて HTTP-01（80 番）で取る。

## 4. ポートを開ける

ノードの機械の防火壁で、7900、80、3000、3001 の TCP を受け付ける。3002 は開けない（Caddy だけがつなぐ）。

```
# nftables の例（input の既定が drop のとき）
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state established,related accept
        iifname "lo" accept
        tcp dport { 22, 80, 3000, 3001, 7900 } accept
    }
}
```

ufw なら `sudo ufw allow 80,3000,3001,7900/tcp`。クラウドの VPS なら、そのサービスのファイアウォール（セキュリティグループ
など）でも同じポートを開ける。

Caddy は HTTP/3（UDP）も使えると知らせる（`alt-svc`）。UDP の 3001 も開ければ HTTP/3 で話し、開けなければブラウザーは
TCP に戻るだけなので、どちらでもよい。

外から届くかは、外から確かめる。Let's Encrypt の証明書が取れれば 80 に、heika のログに外のピアからの接続が出れば 7900 に
届いている。3000 と 3001 は、別の回線（モバイル回線のスマホなど）から `https://<名前>:3001/chain/info` を開く。
同じ回線の中から公開側の IP につなぐと、ルーターが折り返さずに届かないことがあり、確かめにならない。
