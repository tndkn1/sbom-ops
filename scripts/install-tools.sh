#!/usr/bin/env bash
# syft と trivy を GitHub Releases から取得し、sha256 を検証して DEST に置く。
#   usage: scripts/install-tools.sh [DEST]        (既定: /opt/sbomops/bin)
#   バージョンは環境変数 SYFT_VERSION / TRIVY_VERSION で上書きできる。
# 必要なもの: curl, tar, sha256sum (Ubuntu / RHEL どちらも標準で入っている)
set -euo pipefail

SYFT_VERSION="${SYFT_VERSION:-1.57.2}"
TRIVY_VERSION="${TRIVY_VERSION:-0.76.2}"
DEST="${1:-/opt/sbomops/bin}"

case "$(uname -m)" in
  x86_64)        syft_arch=linux_amd64; trivy_arch=Linux-64bit ;;
  aarch64|arm64) syft_arch=linux_arm64; trivy_arch=Linux-ARM64 ;;
  *) echo "未対応のアーキテクチャ: $(uname -m)" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# fetch <URL のベース> <アーカイブ名> <checksums ファイル名> <取り出すバイナリ名>
fetch() {
  local base=$1 tarball=$2 sums=$3 bin=$4
  echo "-- $tarball"
  curl -fsSL --retry 3 -o "$work/$tarball" "$base/$tarball"
  curl -fsSL --retry 3 -o "$work/$sums" "$base/$sums"
  (cd "$work" && grep -E "  ${tarball}\$" "$sums" | sha256sum -c -) \
    || { echo "!! sha256 が一致しない: $tarball" >&2; exit 1; }
  tar -xzf "$work/$tarball" -C "$work" "$bin"
  install -m 0755 "$work/$bin" "$DEST/$bin"
}

mkdir -p "$DEST"
fetch "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
  "syft_${SYFT_VERSION}_${syft_arch}.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" syft
fetch "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
  "trivy_${TRIVY_VERSION}_${trivy_arch}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" trivy

"$DEST/syft" version | grep -E '^Version'
"$DEST/trivy" --version | head -1
echo "インストール先: $DEST"
