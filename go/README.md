# sbomops-go

[sbomops](../README.md) (Python 版) の Go 実装。単一の静的バイナリで、Python が要らない。

- 設定ファイル (`/etc/sbomops/config.yaml`)・状態 DB (`/var/lib/sbomops/state.db`)・Slack の通知内容は Python 版と同じ。
  同じ `data_dir` を使えば、途中から Python 版 ↔ Go 版を入れ替えても検出の履歴 (通知済み・解消) が引き継がれる
- サブコマンド・オプション・終了コードも同じ (`run` / `status` / `targets` / `findings` / `assess` / `test-notify`)
- 振る舞いは `../spec/` の共通データで Python 版と同じであることを確かめている (同期の手順は [spec/README.md](../spec/README.md))

## ビルド

Go 1.27 以上。CGO は不要 (SQLite は modernc.org/sqlite)。

```sh
cd go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sbomops-go ./cmd/sbomops-go
go test ./...      # spec/ の共通データでの試験 (偽の syft / trivy に python3 を使う)
```

## インストール

syft / trivy・設定・systemd タイマーは Python 版の `install.sh` と共通。

```sh
sudo ../install.sh --go          # Python 版の代わりに Go 版を入れる (ビルド済みの go/sbomops-go を使う)
```

`--go` を付けると、`/opt/sbomops/bin/sbomops` を Go 版のバイナリにする (systemd のユニットはそのまま使える)。
Python 版に戻すときは `--go` なしで `install.sh` を実行し直す。

**両方のタイマーを同時に動かさないこと。** 同じ `data_dir` なら後から起動した方がロックで止まる (終了コード 3) が、
別の `data_dir` にすると Slack に二重に通知される。

## Python 版との違い

- `nice` は子プロセスの前に `nice -n` コマンドを挟んで掛ける (Go では fork 後に `nice()` を呼べないため)
- `findings --json` の `resolved_at` / `last_notified` は、未設定のとき `null` ではなく `""` になる
- `noise.distro_vendor_regex` は Go の正規表現 (RE2) で解釈する (後方参照・先読みは使えない)
