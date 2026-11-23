# sbomops

Python 版 (`sbomops/`) と Go 版 (`go/`) の 2 実装がある。**仕様 (振る舞い・設定・通知の形・状態 DB) は両方で同じに保つ。**

- 振る舞いを変える変更は、両方の実装と `spec/` (共通テストデータ) を同じコミットで直す。手順は `spec/README.md`
- 基準は Python 版。Python 版を直したら `python3 spec/gen.py` で期待値を作り直し、Go 版を合わせる
- 既定値・スキーマを変えたら `cp spec/defaults.json spec/schema.sql go/internal/sbomops/`
- テスト: `python3 -m unittest discover -s tests -t .` と `cd go && go test ./...` (両方通すこと)
- 通知の文言・記号・並びも仕様の一部 (Slack のペイロードはバイト単位で比較している)
