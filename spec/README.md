# spec/ — Python 版と Go 版の共通仕様

sbomops には Python 版 (`sbomops/`) と Go 版 (`go/`) の 2 つの実装がある。
このディレクトリのデータを**両方のテストが読む**ことで、振る舞いを同期させる。

| ファイル | 内容 | Python のテスト | Go のテスト |
|---|---|---|---|
| `defaults.json` | 設定の既定値・target の既定値・重大度の順 | `config.DEFAULTS` と一致 | `go/internal/sbomops/defaults.json` (写し) と一致し、実行時に埋め込んで使う |
| `schema.sql` | 状態 DB のスキーマ (両方で同じ DB を読み書きできる) | `store.SCHEMA` と一致 | `go/internal/sbomops/schema.sql` (写し) と一致 |
| `cases/util.json` | 期間・サイズの解析、表示、glob、除外パス | | |
| `cases/policy.json` | 通知条件・再通知・並び順・ノイズ/受容の分類 | | |
| `cases/config.json` | 設定の検証 (YAML 1.1 の真偽値を含む) | | |
| `cases/normalize/*.json` | trivy の結果 → 検出レコード (`want` は生成) | | |
| `cases/slack/*.json` | 通知内容 → Slack のペイロード (`want` は生成) | | |
| `scenarios/*.json` | 偽の syft / trivy (`fake/`) で日次の流れを通す | | |

テストは `tests/test_spec.py` (Python) と `go/internal/sbomops/spec_test.go` (Go)。

## 仕様を変えるときの手順

1. **Python 版を直す** (仕様の基準は Python 版)
2. 入力を変えた・増やしたなら `spec/cases/` / `spec/scenarios/` を編集する。
   新しい振る舞いには、それを確かめるケースを足す
3. `python3 spec/gen.py` で `want` (Slack のペイロード・正規化の結果) を作り直し、`git diff spec/` で差分を確認する
4. 既定値やスキーマを変えたら `defaults.json` / `schema.sql` も直し、Go 側へ写す:
   `cp spec/defaults.json spec/schema.sql go/internal/sbomops/`
5. **Go 版を直す**。`cd go && go test ./...` が通るまで
6. 両方のテストを流す: `python3 -m unittest discover -s tests -t .` と `cd go && go test ./...`

CI では次を確かめるので、片方だけ直すと落ちる。

- `spec` ジョブ: `spec/gen.py` を流して `spec/` に差分が出ないこと (Python 版を直して期待値を更新し忘れていない)
- `test` ジョブ: Python 版が spec を満たすこと / `go` ジョブ: Go 版が spec を満たすこと
- `compare` ジョブ: 本物の syft / trivy で両方を動かし、Slack のペイロード (時刻を除く) と状態 DB が一致すること

## Go 版で Python と挙動を合わせている点

- 文字数は Python と同じくコードポイントで数える (Slack の 3000 文字の分割、各種の切り詰め)
- `fnmatch` は `*` が `/` にも一致する Python の `fnmatch.fnmatch` を移植したもの (`path.Match` ではない)
- `glob` は Python の `glob.glob` と同じく、パターンの要素が `.` で始まらない限り隠しファイルを返さない
- YAML は引用符なしの `yes` / `no` / `on` / `off` を真偽値として読む (PyYAML = YAML 1.1 と同じ)。
  真偽値の設定は Python の真偽判定で読む (`enabled: "no"` は真)
- 時刻は `2026-01-01T00:00:00+00:00` の形 (`datetime.isoformat()`) で状態 DB に書く
