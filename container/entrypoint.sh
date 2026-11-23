#!/bin/sh
# コンテナの入口。
#   daemon (既定)  毎日 SBOMOPS_RUN_AT (HH:MM、TZ の時刻) に sbomops run を実行し続ける。
#                  SBOMOPS_RUN_ON_START=1 なら起動直後にも 1 回実行する
#   それ以外       sbomops にそのまま渡す (例: run --dry-run / status / findings / test-notify)
set -eu

run_once() {
  sbomops run && return 0
  echo "sbomops run の終了コード: $?" >&2
}

if [ "${1:-daemon}" != daemon ]; then
  exec sbomops "$@"
fi

at=${SBOMOPS_RUN_AT:-03:00}
date -d "today $at" >/dev/null 2>&1 || { echo "SBOMOPS_RUN_AT の書式が不正: $at (例: 03:00)" >&2; exit 2; }
# 設定とホストのマウントを先に確かめる (間違っていれば翌日まで気づかないため)
sbomops targets >/dev/null || exit 2
if [ "${SBOMOPS_RUN_ON_START:-0}" = 1 ]; then
  run_once
fi
while :; do
  now=$(date +%s)
  next=$(date -d "today $at" +%s)
  [ "$next" -gt "$now" ] || next=$(date -d "tomorrow $at" +%s)
  echo "次回の run: $(date -d "@$next" '+%F %T %Z')"
  sleep $((next - now))
  run_once
done
