# 日次の流れのシナリオ

偽の syft / trivy (`spec/fake/`) を使って `run` を繰り返し、通知の中身を確かめる。
Python 版は `tests/test_spec.py`、Go 版は `go/internal/sbomops/spec_test.go` が同じファイルを実行する。

- `base_config` (`_base.json`) に各シナリオの `config` を重ねる。`policy` は `notify.policy` に重ねる
- 文字列中の `{dir}` は一時ディレクトリ、`{dirname}` はその単位名用の形 (`safe_name(dir.strip("/"))`)、`{fake}` は偽ツールのディレクトリ、`{today+N}` / `{today-N}` は日付に置き換える
- steps:
  - `{"set_version": "1.0"}` 偽 syft が SBOM に書く example パッケージの版 (1.0 なら脆弱、1.1 なら解消)
  - `{"write_accepted": "..."}` 受容リスト (`notify.suppress_file`) を書く
  - `{"mkdir": ["g/one", ...]}` 一時ディレクトリの下にディレクトリを作る
  - `{"age_notifications": N}` 通知済みの検出を N 日前に通知したことにする
  - `{"run": {"force": bool, "no_scan": bool}, "expect": {...}}`
    - `rc` 終了コード / `sent` 通知を送ったか
    - `items` 通知した [vuln_id, new|remind] (順序どおり) / `resolved` 解消として報告した vuln_id
    - `skipped` 調査対象外 [名前, 理由] のうち含まれるべきもの / `skipped_exact` 調査対象外の全体
    - `warnings_contain` 警告に含まれるべき文字列
    - `timings` 対象ごとの {unit, syft: ok|failed|null, syft_skip_prefix, trivy: ok|failed|null}。`[]` は載せないこと
