# ハーベストとトランザクション

## できること

- ハーベストのためのリンクと委任（古いリンクの解除、新しいリンク、委任の要求を1つのアグリゲートにまとめる。委任ではリモートと VRF の鍵を毎回作り直す）
- キーストアから導出したリモートと VRF の鍵のリンク（`--link-derived`）。同じ鍵を `heika experimental peer start --harvest` で導出して、鍵のファイルなしでハーベストする（[peer.md](peer.md)）
- 投票鍵のファイルの作成と確認、チェーンへの紐づけ（catapult の votingkey と同じファイルを書き、公式の Python SDK と照合している）
- トランザクションの中身の表示（25種類すべてと、チェーンにある古いバージョンのアグリゲート）
- トランザクションへの署名と連署と、ノードへの送信（ノードの証明書で名乗って、ノードと TLS でつなぐ）

## コマンドの例

```sh
heika key voting generate --network mainnet --start-epoch <エポック> --end-epoch <エポック> --out private_key_tree1.dat
heika key voting show private_key_tree1.dat

heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --delegate <ノードの公開鍵> --out harvesting.bin
heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --link-remote <公開鍵> --link-vrf <公開鍵> --out harvesting.bin
heika harvesting --network mainnet --link-derived main --out harvesting.bin
heika harvesting --network mainnet --signer <メインアカウントの公開鍵> --link-voting <公開鍵>:<最初のエポック>-<最後のエポック> --out voting.bin
heika tx show harvesting.bin
heika tx show --json harvesting.bin
heika tx sign --network mainnet --out harvesting.signed.bin harvesting.bin < main.key
heika tx cosign --network mainnet --out harvesting.cosigned.bin harvesting.signed.bin < cosigner.key
heika tx announce --network mainnet --connect <ホスト>:<ポート> --client-cert node.full.crt.pem harvesting.signed.bin < node.key.pem
```

## 投票鍵

`heika key voting generate` は、ファイナライズの投票に使う投票鍵のファイルを、catapult の votingkey と同じ形で書く。根の鍵でエポックごとの鍵に署名したら、根の秘密鍵は捨てる。期間はネットワークの設定の範囲（メインネットは 112 から 360 エポック）で確かめる。作ったファイルは、ノードの votingkeys フォルダーに private_key_tree1.dat から順に番号を振って置く。`heika key voting show` は、ノードが使っているファイルも読み、公開鍵と期間、ノードが使って消したエポック、残っている鍵の数を出し、残っている鍵が公開鍵の署名と合うかを確かめる。

## ハーベストのリンクと委任

`heika harvesting` は、リンクの解除、紐づけ、委任の要求を1つのアグリゲートにまとめる。`--delegate` を付けると、リモートアカウントと VRF の鍵をその場で作り、委任先のノードにだけ渡す。前の委任先のノードは古い鍵を知っているので、使い回すとそのノードがハーベストを続けられてしまうためである。自分のノードでハーベストするなら、`--link-derived <ラベル>` で、キーストアのそのアカウントから導出したリモートと VRF の公開鍵を紐づける。鍵はキーストアの `Harvest-Secret` から決まった形で導出するので、ファイルに書いて持っておく必要がない（[keystore.md](keystore.md)）。`--signer` を省くと、そのアカウントの公開鍵にする。heika のほかのノードで使う鍵なら、`heika key generate` で作った鍵の公開鍵を `--link-remote` と `--link-vrf` に渡す。古いリンクは `--unlink-remote`、`--unlink-vrf`、`--unlink-node` で外す。外すべき公開鍵は、前回の `heika harvesting` が表示する。投票鍵は、`heika key voting generate` が出す `<公開鍵>:<最初のエポック>-<最後のエポック>` を `--link-voting` に渡して紐づけ、同じ書き方で `--unlink-voting` に渡して外す。組むのに秘密鍵は要らず、メインアカウントの秘密鍵は `heika tx sign` で読む。

## トランザクション

署名する前に、`heika tx show` で中身を確かめられる。`heika tx show` は秘密鍵を使わず、バイト列そのものでも16進のテキストでも読む。署名者とアドレス、手数料と期限（UTC の日時）、中のトランザクションの1件ずつを出し、署名があれば正しいかも確かめる。メッセージの文字列は、端末の表示を書き換えられないように制御文字をエスケープする。通貨以外のモザイクの量は、可分性がわからないので最小単位のまま出す。チェーンにある古いアグリゲート（バージョン 1 と 2）も読み、バージョン 1 なら中のトランザクションのハッシュがどの求め方で書かれているかも出す。古いアグリゲートは、署名も送信もしない。`--json` を付けると、表示と同じ項目を JSON で出す。`heika tx sign` も、署名したあとに同じ中身を出す。マルチシグのアカウントなどで連署が要るときは、署名したものに `heika tx cosign` で1人ずつ連署を足す。連署するのは外側の署名を含むハッシュなので、先に署名しておく。`heika tx announce` は、ネットワーク、署名と連署、期限を確かめてから送る。ノードは受け取ったことを返さないので、ブロックに入ったかは、表示するハッシュで確かめる。
