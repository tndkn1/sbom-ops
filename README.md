# sbomops

syft と trivy を使ってホストの SBOM を作り、毎日脆弱性 DB と照合して Slack に通知するツール。
Ubuntu / Debian と RHEL 系 (RHEL 8/9、Rocky、Alma) のどちらでも動く。

- **分割スキャン**: ホスト全体を一度にスキャンせず、「OS パッケージ」「/usr/local」「各ホーム」などの単位に分ける。
  単位ごとに周期 (`every`) を変えられる。OS パッケージは数十秒で終わるので毎日、重いディレクトリは週 1 などにする。
  日々の照合は全単位の最新 SBOM に対して毎日行うので、新しい CVE はすぐに拾える
- **低負荷**: syft / trivy は `nice 19` + `ionice idle` で動かし、RSS が上限を超えたら kill して次へ進む
  (cgroup v1 の環境でも効く)。1 回の実行時間の上限 (`scan_budget`) を超えた分は翌日に回す
- **通知の調整**: 重大度の下限、修正版の有無、KEV / EPSS による例外、ベンダーが「修正しない」としたものの除外
- **パッチ適用で止まる**: 次の照合で検出が消えれば「解消」として報告し、以後は通知しない。
  `repeat: until_fixed` なら未適用のあいだ `remind_every` ごとに催促し、`once` なら初回だけ
- **ノイズの除去**: 起動していない古いカーネル、ディストリのパッケージが所有するファイル上の言語パッケージ /
  Go バイナリ (OS パッケージ側の照合で追えるため)、パッケージキャッシュ。期限付きの受容リスト
- **AI による評価 (任意)**: 通知対象を Claude Code / Codex に渡し、このホストでの優先度 (P1〜P4) と対処を通知に付ける
- **OS の更新を検知**: os-release が変わったら全単位の SBOM を作り直す。SBOM が古くなったら警告する

Python 版 (このディレクトリ) と、同じ設定・状態 DB・通知を持つ **Go 版** ([go/](go/README.md)、単一バイナリ) がある。
両者の振る舞いは [spec/](spec/README.md) の共通テストデータで同期させている。

**コンテナで動かすのがいちばん簡単** (Go 版 + syft + trivy 入りのイメージを CI が毎回作る。詳しくは [container/](container/README.md)):

```sh
docker run -d --name sbomops --restart unless-stopped \
  -v /:/host:ro -v sbomops-data:/var/lib/sbomops \
  -e TZ=Asia/Tokyo -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \
  ghcr.io/tndkn1/sbom-ops:latest
```

## 必要なもの

- Python 3.9 以上 (標準ライブラリのみ。設定を YAML で書くなら PyYAML)
  - Ubuntu: `apt install python3-yaml`
  - RHEL 9 系: `dnf install python3-pyyaml`
  - RHEL 8 系: `dnf install python39 python39-pyyaml` (install.sh が python3.9 を自動で選ぶ)
- systemd、curl、tar (install.sh が syft / trivy をバージョン固定・sha256 検証つきで入れる)
- ホスト全体を見るには root

## インストール

```sh
git clone git@github.com:tndkn1/sbom-ops.git && cd sbom-ops
sudo ./install.sh
sudoedit /etc/sbomops/config.yaml     # targets と notify を確認
sudoedit /etc/sbomops/secrets.env     # SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
sudo sbomops test-notify              # Slack に届くか
sudo sbomops run --dry-run            # 初回スキャン。通知は送らず内容を表示 (通知済みにもしない)
sudo systemctl enable --now sbomops.timer   # 毎日 04:30
```

更新は `git pull && sudo ./install.sh` (設定は残る)。配置先:

| パス | 内容 |
|---|---|
| `/opt/sbomops/` | 本体と syft / trivy |
| `/etc/sbomops/config.yaml` | 設定 ([例](config/sbomops.example.yaml)) |
| `/etc/sbomops/secrets.env` | Slack の Webhook URL (0600) |
| `/etc/sbomops/accepted.tsv` | 期限付きの受容リスト |
| `/var/lib/sbomops/` | SBOM、照合結果、状態 DB (`state.db`)、ログ |

ログ:

- 実行ログ: journald (`journalctl -u sbomops.service`) と `/var/lib/sbomops/logs/run-<日付>.log`。
  `retention.logs_days` (既定は `results_days` と同じ 14 日) より古いものは run の最後に消す
- syft のログ: `/var/lib/sbomops/logs/syft/<単位>.log` (スキャンごとに上書き)
- 実行履歴: `state.db` の `runs` テーブル (`sbomops status` で直近 5 回)

## 使い方

```sh
sbomops run [--only ID,...] [--force] [--no-scan] [--dry-run] [--no-notify] [--no-assess]
sbomops status                # 単位ごとの最終スキャン・所要時間・ピーク RSS・件数、直近の実行
sbomops targets [-v]          # 設定から展開した単位と、次回スキャンするか (-v は syft の引数も)
sbomops findings [--all] [--unit 'proj:*'] [--json]
sbomops assess [--limit N]    # 通知対象を AI で評価して表示
sbomops test-notify [--dry-run]
```

`sbomops -v ...` で詳細ログ。設定ファイルは `-c`、`$SBOMOPS_CONFIG`、`/etc/sbomops/config.yaml` の順に探す。

## 日次の流れ

1. 周期が来た単位だけ syft で SBOM (CycloneDX) を作り直す。期限切れの長いものから順に、`scan_budget` まで
2. trivy の DB を更新し、KEV / EPSS を取得する (取得に失敗したら前回のキャッシュ)
3. 全単位の最新 SBOM を `trivy sbom` で照合する
4. 状態 DB と突き合わせ、新規 / 継続 / 解消を決める。分類 (有効・ノイズ・受容) と通知条件を評価する
5. (任意) 通知対象を AI で評価する
6. Slack に 1 通にまとめて送る。送れたものだけ「通知済み」にする (失敗したら次回また送る)
   通知の末尾には、対象ごとの syft / trivy の開始・終了時刻と所要時間 (`report_timings`) と、
   調査対象外にしたもの (無効・`skip` に一致・パスがない・時間切れ・SBOM なし など、`report_skipped`) を載せる。
   周期内で syft を動かさなかった対象は「周期内 (前回 月/日)」と出る

検出の同一性は「単位 + 脆弱性 ID + パッケージ名 + 場所」で判定する。パッケージを更新してもまだ脆弱な版なら
同じ検出のまま (版だけ更新)、脆弱でない版になれば解消になる。

## 分割の単位の調整

`targets` に並べた 1 項目が設定上の単位で、`path` を複数書くか `path_glob` を使うと 1 ディレクトリ = 1 単位に展開される。

```yaml
targets:
  - {id: os, type: os-packages, every: 1d}
  - {id: projects, type: dir, path_glob: "/home/*/work/*", every: 7d, max_runtime: 30m, mem_max: 2G}
  - {id: containers, type: running-images, every: 7d}   # イメージ ID が変われば周期前でも作り直す
```

- 1 単位の syft が重い (時間切れ・メモリ超過) なら、`path_glob` で細かく分けるか `exclude` を足す
- `sbomops status` の `sec` と `RSS` 列で単位ごとの負荷が分かる
- `scan_budget` を超えた単位は翌日に回る。毎日あふれるなら `every` を延ばす
- 単位を設定から外す (またはコンテナを止める) と、その単位の検出は解消扱いになる

## 通知ポリシーの例

緊急のものだけを、直るまで毎日:

```yaml
notify:
  policy:
    min_severity: CRITICAL
    only_fixable: true
    always_notify: {kev: true, epss_gte: 0.3}
    repeat: until_fixed
    remind_every: 1d
```

新規の HIGH 以上を 1 回だけ、未対応の催促は週 1:

```yaml
notify:
  policy: {min_severity: HIGH, repeat: until_fixed, remind_every: 7d}
```

受容リスト (`/etc/sbomops/accepted.tsv`) の書式は `vuln_id unit package 期限 理由` (空白区切り、glob 可)。
期限を過ぎると通常の通知対象に戻り、警告にも出る。

## AI による評価

```yaml
assess:
  enabled: true
  engine: claude        # claude | codex | command
  run_as: alice         # root の systemd から呼ぶとき、CLI にログイン済みのユーザー
  max_per_run: 20
  cache: 30d
```

- claude は `claude -p --output-format json --tools ""` (ツールなし)、codex は `codex exec --sandbox read-only` で呼ぶ
- 評価は検出ごとにキャッシュし、`cache` の期間は再評価しない
- 外部の API に送られるのは CVE ID、パッケージ名・版・修正版、重大度、KEV/EPSS、場所と単位名
  (`redact` でホスト名と `/home/<user>` を伏せる)。送りたくない環境では無効のままにする
- `engine: command` なら、stdin でプロンプトを受け JSON 配列を stdout に返す任意のコマンドを使える

## 開発

```sh
scripts/install-tools.sh .tools            # 開発用に syft / trivy をリポジトリ内へ
python3 -m unittest discover -s tests -t .  # 偽の syft / trivy で日次の流れも試験する
bin/sbomops -c config/local-dev.yaml run --dry-run   # data_dir を書き換えた設定で一般ユーザーでも動く
```

通知先を足すときは `sbomops/notify/base.py` の `Notifier` を継承して `render` / `send` を実装し、
`sbomops/notify/__init__.py` の `REGISTRY` に登録する (設定は `notify.<名前>.enabled`)。

振る舞いを変えるときは Python 版・Go 版・`spec/` を一緒に直す (手順は [spec/README.md](spec/README.md))。

```sh
python3 spec/gen.py                        # Python 版から spec の期待値を作り直す
(cd go && go test ./...)                   # Go 版が spec を満たすか
```
