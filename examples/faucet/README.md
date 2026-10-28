# 蛇口

プライベートネットで、試すための XYM を配る例です。ページは 1 枚だけです。アドレスを入れて「もらう」を押すと、ブラウザが小さなパズルを解き、しばらくして XYM が届きます。ページとその API は、同じ 1 つのプログラムが出します。

公開のテストネットには公式の蛇口があるので、これは heika で立てた自分のネット向けです。

## 動かす

```sh
cargo build --release
./target/release/faucet peer.yaml faucet.yaml
```

- `peer.yaml` は `heika experimental peer start` と同じ設定です。ここからネットワークと REST（最初の `rest` の口）を決めます
- `faucet.yaml` は蛇口の設定です（下）。書いた `listen` の口でページを開きます

```yaml
apiVersion: heika.hinablogchannel.github.io/v1alpha1
kind: Faucet
metadata:
  name: privnet-faucet
spec:
  listen: 127.0.0.1:8080
  signer: /path/to/faucet.key   # 配る XYM を持つアカウントの鍵（PEM、DER、16進）
  amount: 100000000             # 1 回に配る量（最小単位。これで 100 XYM）
  budget:
    amount: 10000000000         # periodSeconds ごとに配れる量
    periodSeconds: 3600
  cooldownSeconds: 86400        # 一度もらったアドレスと接続元が、次にもらえるまで
  # clientAddressHeader: X-Forwarded-For   # 前にリバースプロキシを置くとき
  batch:
    intervalSeconds: 15         # 受け付けたものを、この間隔でまとめて送る
    maxTransfers: 100
  pow:
    policy: Adaptive            # Never / Adaptive / Always
    maxSeconds: 30
    referenceHashRate: 500000
    puzzles: 8
```

`batch` と `pow` は書かなければ、上の値になります。知らないキーと、`adaptive` のような小文字の値は弾きます。

送るたびと、承認されるたびに、1 行ずつ出します。

```
3 件をまとめて送りました（96111A15…）
高さ 11 で承認されました（96111A15…）
```

## 配りすぎを防ぐしくみ

困ることは 2 つあります。アドレスを作り直しながら何度ももらわれて空にされることと、サーバーに押し寄せられることです。CAPTCHA や外のサービスでのログインは使いません。ほかの会社に頼ることになるうえ、誰がもらったかの記録も残るからです。

- **予算**: `periodSeconds` ごとに配れる量です。使い切っても、時間がたてば少しずつ戻ります。空にされても、止まるのはしばらくのあいだだけです
- **待ち時間**: 同じアドレスと同じ接続元は、`cooldownSeconds` のあいだもらえません
- **まとめて送る**: 受け付けたものを `intervalSeconds` ごとに 1 つのアグリゲートにまとめます。どれだけ押し寄せても、ノードに届くのは 1 ブロックに 1 件ほどです。手数料も、別々に送るより安く済みます
- **PoW**: 人の手間を、予算の様子に合わせて足します。決めるのはサーバーの設定で、ページはいつも同じ手順で動きます

送れなかったときと、期限（1 時間）までに承認されなかったときは、その分の予算と待ち時間を戻します。

### PoW

`policy` は Kubernetes の `imagePullPolicy` と同じ書き方です。

- `Never`: 解かせません
- `Always`: いつも、`maxSeconds` ほどかかるものを解かせます
- `Adaptive`: 予算が半分より多いあいだは解かせません。半分を切ったら、減るほど長くします。空に近いときは `maxSeconds` です

パズルは `{ID}:{番号}:{数}` の SHA-256 の頭の何ビットかが 0 になる数を探すもので、それを `puzzles` 個解かせます。1 つの大きなパズルだと、運しだいで、めやすの何倍も待たされることがあります。小さなものをいくつも解かせると、かかる時間がめやすの近くに寄ります（足し合わせるほど、ばらつきが平均に比べて小さくなります）。

何ビットにするかは、サーバーが `referenceHashRate`（基準の端末が 1 秒に計算できる数）から決めます。ページは解き終わると、その端末が 1 秒に計算した数を、開発者ツールのコンソールに出します。配る相手が使いそうな端末で測って、書き換えてください。既定の 500000 は、まだ測っていないおおよその値です（手元の bun では 1 秒に約 150 万回でした）。

SHA-256 は、ページの JS に自分で書いています。ブラウザの Web Crypto は https か localhost でしか使えないので、LAN の中の http でページを開いても動くようにするためです。

PoW は、手間を足すだけです。速い計算機を持つ人には効きにくいので、配りすぎを防ぐのは、あくまで予算と待ち時間です。

## API

ページが使うものです。自分でページを作るなら、これを呼んでください。

- `GET /api/info`: `{"amount":…,"cooldownSeconds":…}`
- `GET /api/challenge?address=…`: もらえるかを確かめて、`{"id":…,"bits":…,"count":…,"expectedSeconds":…}` を返します。`count` 個のどれも、`{id}:{番号}:{数}`（番号は 0 から、数は 10 進）の SHA-256 の頭の `bits` ビットが 0 になる数を探します。`bits` が 0 なら、どの数でも合います
- `POST /api/claim`: `{"challenge":"<id>","solutions":[…]}` を送ると、`{"id":…}` を返します。1 つのパズルで出せるのは 1 回だけで、間違えたら `challenge` からやり直します
- `GET /api/claims/{id}`: `{"state":"Queued"}`、`{"state":"Announced","hash":…}`、`{"state":"Confirmed","hash":…,"height":…}`、`{"state":"Failed","reason":…}` のどれかを返します

断るときは、400 か 429 で `{"message":…}` を返します。

## heika の使い方

[`src/main.rs`](src/main.rs) の `App::send` が、まとめて送るところです。

- `heika_transaction::Transfer::new` で 1 人分ずつ作り、`EmbeddedTransaction::new` で蛇口のアカウントが出すものにして、`Aggregate::new` で 1 つにまとめます
- 手数料は `Transaction::fee_for` に、REST の `/network/fees/transaction`（`heika_rest::node::TransactionFeesJson`）の中央値とノードの下限の大きいほうを渡して決めます
- `Transaction::sign` で署名し、`heika_rest::send::announce_body` を `PUT /transactions` に送ります
- 承認は `heika_rest::send::TransactionStatus` で見ます。これは REST が言っているだけで、確かめたものではありません。届いたことまで確かめるなら、`heika_rest::send::find_inclusion` を使います
- ネットワークの決まり（generation hash seed、通貨のモザイク ID、アグリゲートに入れられる数）は、`heika_node::driver::network_parameters` でノードの設定から取ります

[`src/lib.rs`](src/lib.rs) の予算、待ち時間、パズルは、時刻を引数で受け取るだけなので、ネットワークなしで試せます。

## 気をつけること

- 送り先のどれか 1 つでも弾かれる（受け取りの制限をかけているなど）と、同じアグリゲートの全員の分が届きません。その分は、期限が過ぎたあとで戻します
- heika のノードは、残高が足りないなど、状態によって外したトランザクションを `failed` にしません。蛇口のアカウントが空になると、期限（1 時間）が過ぎるまで `Announced` のままになります
- 待ち時間と受け付けたものは、メモリにだけ置きます。止めると忘れます
- 接続元は IP アドレスで見ます。リバースプロキシの後ろに置くなら、`clientAddressHeader` を書いてください。書かないと、全員がプロキシの IP アドレスに見え、1 人もらったら全員が待つことになります。逆に、プロキシなしで書くと、ヘッダーを偽って待ち時間をすり抜けられます

## プライベートネットで確かめたこと

2026-10-28 に、heika のノード 3 台のプライベートネットで、次のことを確かめました。設定は `pow.policy: Always`、`maxSeconds: 2`、予算 300 XYM で、`X-Forwarded-For` で接続元の違う人を真似ました。

- 3 人分が 1 つのアグリゲートで送られ、同じブロックで承認されて、3 人とも 100 XYM を受け取った
- 同じ接続元の別のアドレスも、別の接続元の同じアドレスも、待ち時間で断られた
- 答えを 1 つ書き換えると断られ、そのパズルは使えなくなった
- 予算を使い切ると、戻るまでの長さを添えて断られた
- 読めないアドレスは断られた
- 18 ビット × 8 個（めやす 2.1 秒）は、bun で 0.8 秒から 1.2 秒で解けた

ブラウザでは、まだ試していません。
