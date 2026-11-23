# sbomops のコンテナイメージ (Go 版 + syft + trivy)。docker / podman のどちらでも動く。
# ホストの / を /host に読み取り専用でマウントして、ホストを調べる (container/README.md)。
#   docker build -t sbomops .

ARG GO_VERSION=1.27
ARG DEBIAN_VERSION=trixie

# ---- Go 版のビルド (ビルドするマシンのアーキテクチャで動かし、対象向けにクロスコンパイル)
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS TARGETARCH
WORKDIR /src/go
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/sbomops ./cmd/sbomops-go

# ---- syft / trivy (sha256 を検証して取得)
FROM debian:${DEBIAN_VERSION}-slim AS tools
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates >/dev/null \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/install-tools.sh /usr/local/bin/install-tools.sh
RUN install-tools.sh /out

# ---- 稼働中コンテナのイメージを調べるための docker CLI (静的バイナリ。podman のソケットにも使える)
FROM docker:29-cli AS dockercli

# ---- 実行用
FROM debian:${DEBIAN_VERSION}-slim
# dpkg-query は基本に含まれる。rpm は RHEL 系ホストのパッケージ DB を読むため、tini は PID 1 用
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates tzdata rpm tini >/dev/null \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/sbomops /usr/local/bin/sbomops
COPY --from=tools /out/syft /out/trivy /opt/sbomops/bin/
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY container/config.yaml /etc/sbomops/config.yaml
COPY container/entrypoint.sh /usr/local/bin/entrypoint.sh
ENV SBOMOPS_HOST_ROOT=/host \
    SBOMOPS_RUN_AT=03:00
VOLUME /var/lib/sbomops
LABEL org.opencontainers.image.title="sbomops" \
      org.opencontainers.image.description="syft + trivy による SBOM 日次運用 (ホストの / を /host にマウントして使う)" \
      org.opencontainers.image.source="https://github.com/tndkn1/sbom-ops" \
      org.opencontainers.image.licenses=""
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["daemon"]
