#!/usr/bin/env bash
# sbomops をこのホストに入れる (root で実行)。再実行すると本体と syft/trivy を更新し、設定は残す。
#   sudo ./install.sh            本体・ツール・設定の雛形・systemd ユニットを配置
#   sudo ./install.sh --enable   上に加えてタイマーを有効化
#   sudo ./install.sh --no-tools syft / trivy を入れ直さない
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "root で実行してください (sudo ./install.sh)" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/sbomops
ETC=/etc/sbomops
DATA=/var/lib/sbomops
enable=0 tools=1
for a in "$@"; do
  case $a in
    --enable) enable=1 ;;
    --no-tools) tools=0 ;;
    *) echo "不明な引数: $a" >&2; exit 2 ;;
  esac
done

# Python 3.9 以上 (RHEL 8 は python39 を入れて SBOMOPS_PYTHON=python3.9 を使う)
PY=${SBOMOPS_PYTHON:-python3}
if ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
  for c in python3.12 python3.11 python3.9; do
    if command -v "$c" >/dev/null; then PY=$c; break; fi
  done
  "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
    || { echo "Python 3.9 以上が必要です (RHEL 8: dnf install python39 python39-pyyaml)" >&2; exit 1; }
fi
"$PY" -c 'import yaml' 2>/dev/null \
  || echo "注意: PyYAML がないため設定は JSON で書く必要があります (apt install python3-yaml / dnf install python3-pyyaml)"

echo "-- 本体を $PREFIX に配置"
install -d -m 0755 "$PREFIX" "$PREFIX/bin"
rm -rf "$PREFIX/sbomops.new"
cp -a "$SRC/sbomops" "$PREFIX/sbomops.new"
find "$PREFIX/sbomops.new" -name __pycache__ -prune -exec rm -rf {} +
rm -rf "$PREFIX/sbomops" && mv "$PREFIX/sbomops.new" "$PREFIX/sbomops"
install -m 0755 "$SRC/bin/sbomops" "$PREFIX/bin/sbomops"
install -m 0644 "$SRC/README.md" "$PREFIX/README.md"
if [[ $PY != python3 ]]; then
  sed -i "s|\${SBOMOPS_PYTHON:-python3}|\${SBOMOPS_PYTHON:-$PY}|" "$PREFIX/bin/sbomops"
fi
ln -sf "$PREFIX/bin/sbomops" /usr/local/bin/sbomops

if (( tools )); then
  echo "-- syft / trivy"
  "$SRC/scripts/install-tools.sh" "$PREFIX/bin"
fi

echo "-- 設定 ($ETC)"
install -d -m 0750 "$ETC"
[[ -e $ETC/config.yaml ]] || install -m 0640 "$SRC/config/sbomops.example.yaml" "$ETC/config.yaml"
if [[ ! -e $ETC/secrets.env ]]; then
  umask 077
  printf '# Slack Incoming Webhook の URL\nSLACK_WEBHOOK_URL=\n' > "$ETC/secrets.env"
fi
chmod 0600 "$ETC/secrets.env"
if [[ ! -e $ETC/accepted.tsv ]]; then
  cat > "$ETC/accepted.tsv" <<'EOF'
# 期限付きの受容リスト。期限を過ぎると通常の通知対象に戻る。
# 書式 (空白区切り): vuln_id  unit(glob)  package(glob)  期限(YYYY-MM-DD か -)  理由
# 例:
# CVE-2026-12345  os  openssl  2027-01-31  ベンダー修正待ち。外部公開なし
EOF
fi
install -d -m 0700 "$DATA"

echo "-- systemd"
install -m 0644 "$SRC/systemd/sbomops.service" "$SRC/systemd/sbomops.timer" /etc/systemd/system/
systemctl daemon-reload
if (( enable )); then
  systemctl enable --now sbomops.timer
  systemctl list-timers sbomops.timer --no-pager
else
  echo "タイマーは未有効化: 設定を確認後 systemctl enable --now sbomops.timer"
fi

cat <<EOF

完了。次の手順:
  1. $ETC/config.yaml の targets と notify を確認
  2. $ETC/secrets.env に SLACK_WEBHOOK_URL を設定
  3. sudo sbomops test-notify             (Slack に届くか)
  4. sudo sbomops run --dry-run            (初回スキャン。通知内容を表示するだけ)
  5. sudo systemctl enable --now sbomops.timer
EOF
