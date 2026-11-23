# コンテナで動かす

`ghcr.io/tndkn1/sbom-ops` は Go 版 sbomops・syft・trivy・docker CLI を入れたイメージ (linux/amd64・arm64)。
CI が試験に通ったものを push する。

| タグ | 内容 |
|---|---|
| `latest` | main の最新 |
| `sha-<短いコミット ID>` | そのコミット |
| `1.2.3` / `1.2` | `v1.2.3` タグを付けたとき |

ホストの `/` を **`/host` に読み取り専用でマウント**して、ホストを調べる。記録・通知するパスはホスト上のパス
(`/usr/local/...`) のままで、ネイティブにインストールした場合と同じ結果になる (CI で比べている)。
ホスト名は `/host/etc/hostname` から取る。

## docker

```sh
docker run -d --name sbomops --restart unless-stopped \
  -v /:/host:ro \
  -v sbomops-data:/var/lib/sbomops \
  -e TZ=Asia/Tokyo -e SBOMOPS_RUN_AT=03:00 \
  -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \
  ghcr.io/tndkn1/sbom-ops:latest
```

毎日 `SBOMOPS_RUN_AT` (TZ の時刻) に `sbomops run` を実行する。`docker compose` なら [compose.yaml](compose.yaml)。

その場で動かす・状態を見る (引数はそのまま sbomops に渡る):

```sh
docker run --rm -v /:/host:ro -v sbomops-data:/var/lib/sbomops ghcr.io/tndkn1/sbom-ops run --dry-run
docker exec sbomops sbomops status
docker exec sbomops sbomops findings
docker exec -e SLACK_WEBHOOK_URL=... sbomops sbomops test-notify
```

## podman

```sh
sudo podman run -d --name sbomops --restart unless-stopped \
  --security-opt label=disable \
  -v /:/host:ro -v sbomops-data:/var/lib/sbomops \
  -e TZ=Asia/Tokyo -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \
  ghcr.io/tndkn1/sbom-ops:latest
```

- **root で動かす (`sudo podman`)**。rootless だと root しか読めないファイル (`/root` など) を調べられない
- SELinux が有効なホスト (RHEL 系) では `--security-opt label=disable` がないと `/host` を読めない
- 再起動後も動かすには `podman generate systemd --new --name sbomops` か Quadlet でユニットにする

## 設定

既定の設定 ([config.yaml](config.yaml)) は OS パッケージを毎日、`/usr/local` と `/opt` を週 1 で調べ、
CRITICAL だけを通知する。変えるときは自分の設定をマウントする (書き方は [config/sbomops.example.yaml](../config/sbomops.example.yaml)。
**パスはホスト上のパスで書き、`/host` は付けない**):

```sh
-v ./config.yaml:/etc/sbomops/config.yaml:ro
-v ./accepted.tsv:/etc/sbomops/accepted.tsv:ro      # 受容リスト
```

| 環境変数 | 既定 | 内容 |
|---|---|---|
| `SLACK_WEBHOOK_URL` | | Slack の Incoming Webhook (`secrets_file` の代わり) |
| `TZ` | UTC | 実行時刻と通知の時刻 |
| `SBOMOPS_RUN_AT` | `03:00` | 毎日の実行時刻 |
| `SBOMOPS_RUN_ON_START` | `0` | `1` なら起動直後にも 1 回実行する |
| `SBOMOPS_HOST_ROOT` | `/host` | ホストの / をマウントした場所 |

状態 DB・SBOM・trivy DB は `/var/lib/sbomops` (ボリューム) に残る。ネイティブ版の `/var/lib/sbomops` を
マウントすれば、検出の履歴を引き継いだままコンテナに移れる (その場合はネイティブ版のタイマーを止める)。

## 稼働中のコンテナのイメージも調べる

`running-images` の対象は、コンテナランタイムのソケットをマウントしたときだけ調べられる
(ないと通知の「調査対象外」に出る)。**ソケットを渡すとホストの root 権限相当を渡すことになる**ので、必要なときだけにする。

```sh
-v /var/run/docker.sock:/var/run/docker.sock              # docker
-v /run/podman/podman.sock:/var/run/docker.sock           # podman (sudo systemctl enable --now podman.socket)
```

## ネイティブ版との違い

- AI による評価 (`assess`) の claude / codex CLI は入っていない (`engine: command` で別のコマンドを使うことはできる)
- 再起動待ちの判定は `/host/run/reboot-required` とカーネルの版で行う (`needs-restarting` は使わない)
- `distro_owned` の判定は、イメージ内の dpkg-query / rpm でホストのパッケージ DB を読む
  (`--admindir /host/var/lib/dpkg` / `--root /host`)

## 自分でビルドする

```sh
docker build -t sbomops .          # リポジトリの直下で
podman build -t sbomops .
```
