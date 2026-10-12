# age のテストベクター

C2SP の CCTV（https://github.com/C2SP/CCTV）の `age/testdata` から、heika が読む形のものだけを写した。
コミット 50a8ecf2a220f4c8bdc4f085789b8e85c26829e7 のもの。

- パスフレーズ（scrypt）のもの（ASCII armor のものを除く）
- ヘッダー、HMAC、本文（STREAM）の形を確かめるもの。鍵は X25519 で包んであるので、ヘッダーに書いてあるファイル鍵を直接使って照合する

公開鍵あての暗号化（X25519、ハイブリッド）と ASCII armor のものは、heika が持たないので写していない。

ライセンスは、元の README にあるとおり、Zero-Clause BSD、CC0 1.0、Unlicense から選べる。帰属表示はいらない。

```
Copyright (c) 2022 The age Authors

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.
```
