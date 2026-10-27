# 原子的な交換の Symbol 側

XYM とほかのチェーンのお金を、誰にも預けずに交換するときの、Symbol 側の仕掛けを作る例です。仕掛けの中心は**アダプター署名**で、「この連署をチェーンに出すと、相手に秘密がばれる」ようにします。相手のチェーンには何の仕組みも要らず、2 人が秘密の半分ずつを持つ鍵にお金を置くだけで済みます。Monero のように、スクリプトも時間ロックもないチェーンとも交換できる形です。

ここで作るのは Symbol 側だけです。相手のチェーンの代わりに、2 人が秘密の半分 `a`、`b` をスカラーとして作り、`a + b` がそろうことを確かめるところまでにします。試作なので、メインネットでは使わないでください。

## 動かす

プライベートネットに heika のノードを1台入れ、その設定に `rest` を書いて、REST に向けます。下の例の `$NET` は、プライベートネットの鍵と設定を置いたフォルダーです。

```sh
cargo build --release
B=./target/release/adaptor-swap
$B $NET/heika3/peer.yaml $NET/keys/faucet.key $NET/keys/main1.key 1000000000 redeem
$B $NET/heika3/peer.yaml $NET/keys/faucet.key $NET/keys/main1.key 1000000000 refund
$B $NET/heika3/peer.yaml $NET/keys/faucet.key $NET/keys/main1.key 1000000000 both
```

- 1 つめの引数は `heika experimental peer start` と同じ設定です。ここからネットワークと REST（最初の `rest` の口）を決めます
- 2 つめが Alice（XYM を出す人）、3 つめが Bob（XYM を受け取る人）の鍵のファイルです。PEM、DER、16進のどれでも読みます。Alice には額と手数料、Bob には手数料ぶんの XYM が要ります
- 量は XYM の最小単位で書きます（1000000000 は 1,000 XYM）
- `redeem`: Bob が受け取ります。Bob が出した連署から、Alice が `b` を取り出します（約 30 秒）
- `refund`: Bob は受け取らず、返金の窓が開くのを待って、Alice が取り返します。Alice が出した連署から、Bob が `a` を取り出します（約 4 分）
- `both`: `redeem` のあと、返金の窓が開くのを待って返金も出し、通らないことを確かめます（約 5 分）

`redeem` の出力です。

```
1. 相手のチェーンの代わりに、2 人が秘密の半分 a、b を作り、公開する点 A、B を交換する
    A = 2904F921…、B = 6E586628…、A + B = 335F36DC…（相手のチェーンでお金を置く先。a + b がそろうと動かせる）
2. Alice が返金のアグリゲートを作って外側に署名し、Bob が A を仕込んだ連署を返す
    Alice は、a を足せば Bob の連署になることを確かめた（まだ出せない。窓が開くのは受け取りの窓が閉じたあと）
3. Alice が、使い捨てのアカウントにちょうど 1000000000 を入れて、Alice と Bob の 2-of-2 にする
    → 2-of-2 にするアグリゲートが高さ 36 で承認されました
4. （相手のチェーンで、Bob が A + B にお金を置いたことにする）
5. Bob が受け取りのアグリゲートを作って外側に署名し、Alice が B を仕込んだ連署を返す
    Bob は、b を足せば Alice の連署になることを確かめた
6. Bob が b で Alice の連署を完成させて、受け取りを出す
    → 受け取りが高さ 37 で承認されました
7. Alice が、チェーンに出た自分の連署から b を取り出す
    取り出した b の点 = 6E586628…。a + b の点 = 335F36DC…（A + B と同じ）
    Alice は a + b をそろえたので、相手のチェーンのお金を動かせる
```

## しくみ

### アダプター署名

Ed25519 の署名は `(R, s)` で、`s = r + e·x` です（`r` はノンス、`x` は秘密鍵、`e` はハッシュ）。アダプター署名では、署名する鍵とは別の点 `T = tG` を選んで、`t` だけ足りない署名 `ŝ` を作って渡します。

- 受け取った人は、`t` を足せば正しい署名になることを確かめられます
- `t` を知っている人だけが、`s = ŝ + t` で正しい署名にできます。Symbol から見れば、ふつうの Ed25519 の署名です
- 完成した署名がチェーンに出ると、`ŝ` を持っている人は `t = s − ŝ` を取り出せます

ハッシュには `R` ではなく `R + T` を使い、完成した署名の `R` の欄にも `R + T` が入ります。RFC 8032 の決まり（ノンスをメッセージから決める）どおりの署名ではありませんが、検証の式は満たすので、catapult の厳しめの検証もそのまま通ります。ノンスは、鍵を広げた後半と、`T` と、メッセージから決めます。同じメッセージに違う `T` を仕込んでも、同じノンスを使い回しません。

### 交換の流れ

1. 2 人が秘密の半分 `a`、`b` を作り、点 `A`、`B` を交換します。受け取った点は、素数位数の部分群に入っているかを確かめます。小さい位数の成分が混ざった点を仕込むと、完成した署名が catapult の検証で弾かれます
2. **返金を先に用意します。** Alice が「2-of-2 から Alice へ全額」のアグリゲートを作って外側に署名し、Bob が `A` を仕込んだ連署を返します。Alice は、XYM を入れる前にこれを確かめます
3. Alice が、使い捨てのアカウントにちょうどの額を入れて、Alice と Bob の 2-of-2 にします。1 つのアグリゲートで、入金とマルチシグにする変更をします
4. 相手のチェーンで、Bob が `A + B` にお金を置きます（ここでは置いたことにします）
5. Bob が「2-of-2 から Bob へ全額」のアグリゲートを作って外側に署名し、Alice が `B` を仕込んだ連署を返します
6. Bob が `b` で完成させて出すと、Alice は `b` を取り出し、`a + b` で相手のチェーンのお金を動かせます。Bob が受け取らなければ、Alice は返金の窓が開いてから `a` で完成させて出し、Bob は `a` を取り出して自分のお金を取り戻せます

どちらの経路でも、XYM を動かすことと、相手に秘密の半分を渡すことが、同じ 1 つの署名で結ばれています。

### Symbol 側で気をつけること

- **署名の順番:** 連署は、外側の署名まで含めたアグリゲートのハッシュに対する署名です。なので、外側の署名者（手数料を払う人）が先に署名し、もう一人がそのハッシュにアダプター連署を作ります。外側の署名ができた時点で、手数料、期限、受取人、額がすべて決まり、あとから変えられません
- **期限の窓:** Symbol のトランザクションは、期限の前の `maxTransactionLifetime`（テストネットとメインネットは 6 時間）のあいだしか入りません。返金の期限を、受け取りの期限 + 30 秒 + `maxTransactionLifetime` にしているので、返金の窓は受け取りの窓が閉じてから開きます。2 つが同時に使える時間はありません
- **どちらか一方だけ:** 受け取りと返金は別の署名なので、署名だけでは排他になりません。2-of-2 のアカウントにちょうどの額だけを入れておき、先に入ったほうが残高を使い切ることで、もう一方を通らなくします。誰かがこのアカウントに送り足すと、両方が通る隙ができます
- **2-of-2 のアカウントの鍵:** マルチシグにしたあとは、その鍵では何も署名できません。交換ごとに作り捨てます

### 作っていないもの

- 相手のチェーン（Monero の場合は、受け取りの確かめに要る見るための鍵の共有、`A + B` への入金と取り出し）
- 2 人のあいだの通信路。ここでは 1 つのプログラムが 2 人を演じます
- 片方が途中で消えたときの罰の経路と、匿名性を崩さないための作法（額をそろえる、待ち時間をばらつかせる、相手を変える）
- 日本では、暗号資産どうしの交換も課税の対象になります

## 使っている heika の API

### アダプター署名（[`src/adaptor.rs`](src/adaptor.rs)）

heika-core の feature `hazmat` を有効にして、heika の署名と検証が使っている部品をそのまま使います。

```toml
heika-core = { path = "../../crates/heika-core", features = ["hazmat"] }
```

- `hazmat::ExpandedKey::new(&private_key)`: 秘密鍵を広げたもの。`scalar()` が署名の `x`、`prefix()` がノンスを決めるのに使う後半、`public_point()` が公開鍵の点
- `hazmat::challenge(&encoded_r, &public_key, &[message])`: 検証と同じハッシュ `e = H(R ‖ A ‖ M)`
- `hazmat::decode_point(&bytes)`: catapult が公開鍵に求めるのと同じく、正規形で素数位数の部分群に入っている点だけを受け付ける
- `hazmat::sha512(parts)`、`hazmat::curve25519_dalek`: 同じ版のハッシュと曲線

できた署名は、`PublicKey::verify`（catapult と同じ検証）で確かめます。`hazmat` の部品は、使い方を誤ると秘密鍵が漏れます（同じノンスを違うメッセージに使う、など）。

### アグリゲートと連署（[`src/lib.rs`](src/lib.rs)、[`src/main.rs`](src/main.rs)）

```rust
// 外側に署名してから、そのハッシュに連署する
let mut redeem = payout(network, &bob_public, &joint_public, currency, amount, deadline);
redeem.fee = redeem.fee_for(FEE_MULTIPLIER, 1); // あとから付く連署 1 つぶんも払う
redeem.sign(&bob, &seed)?;
let hash = redeem.hash(&seed);

// Alice は、B を仕込んだアダプター署名を作って渡す
let pre = adaptor::pre_sign(&alice, &hash.0, &big_b).unwrap();

// Bob は b で完成させ、切り離した連署として付ける。付けるときに署名を確かめる
let detached = DetachedCosignature {
    cosignature: Cosignature { signer_public_key: alice_public, signature: adaptor::complete(&pre, &b) },
    parent_hash: hash,
};
redeem.attach_cosignature(&detached, &seed)?;
```

- `Transaction::fee_for(倍率, 連署の数)`: 連署は 1 つ 104 バイト増えるので、あとから付く数も渡す
- `Transaction::cosign`: ふつうの連署。外側に署名したあとでないと付けられない
- `Transaction::attach_cosignature`: 切り離した連署を付ける。署名と、連署したアグリゲートがこれかを確かめる
- `MultisigAccountModification`: 2-of-2 にする変更。連署者に加わる人と、2-of-2 になるアカウント自身の連署が要る

### REST

- `heika_rest::send::{ANNOUNCE_PATH, announce_body}`: `PUT /transactions` で送る
- `heika_rest::send::TransactionStatus`: `/transactionStatus/{hash}` の答え。heika のノードは、ブロックを作ってみて状態に依ることで弾いたものを、`failed`（コード `Failure_Heika_Rejected_When_Harvesting`）と答えます
- `heika_rest::transaction::TransactionInfo`: `/transactions/confirmed/{hash}` の答え。`Transaction::try_from(&info.transaction)` で、連署ごとトランザクションに組み直せます。`TransactionInfo::verify` は、決め打ちのネットワーク（メインネットとテストネット）の generation hash seed で確かめるので、プライベートネットでは `Transaction::verify` と `verify_cosignatures` に、そのネットワークの seed を渡して確かめます

## プライベートネットで確かめたこと

catapult 2 台と heika 1 台のプライベートネットで、2026-10-27 に確かめました。

- `redeem`: 完成させたアダプター連署の入った受け取りが承認され、catapult の 2 台も同じブロックを持っていました（catapult の検証も通った）。Alice は `b` を取り出し、`a + b` の点が `A + B` と一致しました
- `refund`: 返金の窓が開いてから出した返金が承認され、Bob は `a` を取り出しました
- `both`: 受け取りのあとに出した返金は、2-of-2 のアカウントの残高が足りずに弾かれました
- 単体テスト（`cargo test`）: 完成させた署名が heika の検証を通ること、取り出した秘密の点が一致すること、違うメッセージや違う点では確かめが通らないこと、小さい位数の成分を混ぜた点を弾くこと
