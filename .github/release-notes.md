`heika-v…` はコマンドラインツール、`heika-gui-v…` はウォレットの GUI。確かめ方と、署名していないものの入れ方は README の「インストール」にある。

- どのファイルも `SHA256SUMS` と、`gh attestation verify <ファイル> --repo <このリポジトリ>` で確かめられる
- CLI のコンテナイメージ（linux/amd64、linux/arm64）は `ghcr.io/hinablogchannel/heika:<この版>` にある。`gh attestation verify oci://ghcr.io/hinablogchannel/heika:<この版> --repo <このリポジトリ>` で確かめられる
- APK の署名の証明書の SHA-256 は `79b38fb9557cf0249f75aadf806805f3e5b4f6b196a69b6f986c075cdb64c5ad`（`apksigner verify --print-certs` で見られる）
- macOS の dmg は公証を受けておらず、Windows のインストーラーは署名していない
- iOS の IPA は署名していない。自分で署名し直さないと入らない
