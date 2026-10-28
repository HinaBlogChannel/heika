# heika のコンテナイメージ。ビルドし直さず、CI のリリースビルド（静的リンクの musl）をそのまま入れる。
# コンテキストは、heika-amd64 と heika-arm64 だけを置いたフォルダーにする（リポジトリは送らない）:
#
#   docker buildx build -f containers/heika/Dockerfile --platform linux/amd64,linux/arm64 <フォルダー>
#
# ノードは、設定を /etc/heika/peer.yaml に、データを /data に置いて動かす:
#
#   docker run -v ./peer.yaml:/etc/heika/peer.yaml:ro -v heika-data:/data -p 7900:7900 <イメージ> \
#     experimental peer start --config /etc/heika/peer.yaml
#
# 止めるときは SIGTERM で、今のブロックを書き終えてから止まる。待たずに SIGKILL すると、次に開くときに
# DB の長い修復が走るので、猶予は長めにする（docker stop -t、Kubernetes の terminationGracePeriodSeconds）

# HTTPS の REST につなぐ CLI のコマンドのための CA 証明書の束と、空のデータの置き場。
# ビルドするマシンの上で作るので、ほかのアーキテクチャーのエミュレーションは要らない
FROM --platform=$BUILDPLATFORM debian:trixie-slim@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31 AS base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && mkdir /data

FROM scratch
ARG TARGETARCH
LABEL org.opencontainers.image.source=https://github.com/hinablogchannel/heika \
      org.opencontainers.image.licenses=AGPL-3.0-only \
      org.opencontainers.image.description="Symbol のノード運営のための、鍵と証明書のコマンドラインツール"
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# 名前付きのボリュームは、最初にここの持ち主を写すので、そのまま書ける
COPY --from=base --chown=65532:65532 /data /data
COPY --chmod=0755 heika-${TARGETARCH} /heika
USER 65532:65532
EXPOSE 7900 3000
ENTRYPOINT ["/heika"]
