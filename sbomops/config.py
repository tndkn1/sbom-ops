"""設定の読み込み (YAML または JSON)。既定値に利用者の設定を重ねる。"""
from __future__ import annotations

import copy
import json
import os
import socket

from .util import parse_duration, parse_size

SEARCH_PATHS = ["/etc/sbomops/config.yaml", "/etc/sbomops/config.yml", "/etc/sbomops/config.json"]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# syft で dir:/ 系をスキャンするときに常に外すもの (仮想FS・コンテナ層・キャッシュ)
SYSTEM_EXCLUDES = [
    "/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/lost+found",
    "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/snapd",
    "/snap", "/var/cache", "/var/log", "/media", "/mnt",
]

DEFAULTS = {
    "host_label": None,                 # 通知に出すホスト名 (既定: hostname)
    "data_dir": "/var/lib/sbomops",
    "secrets_file": "/etc/sbomops/secrets.env",
    "tools": {"syft": None, "trivy": None},   # 未指定なら /opt/sbomops/bin → PATH の順に探す
    "resources": {
        "nice": 19,
        "ionice_class": "idle",          # idle | best-effort | none
        "mem_max": "4G",                 # 1プロセスあたりの RSS 上限 (超えたら kill)
        "syft_parallelism": 2,
        "wrap": [],                      # 例: ["systemd-run", "--scope", "-q", "-p", "MemoryMax=4G"]
    },
    "run": {
        "scan_budget": "3h",             # 1回の run でスキャンに使う時間の上限。超えた対象は次回へ
        "stale_factor": 2,               # SBOM が every × この倍数より古いと警告
        "rescan_on_os_change": True,     # os-release が変わったら全対象を作り直す
    },
    "targets": [],
    "trivy": {
        "db_repository": [],             # ミラーを使う場合に指定
        "extra_args": [],
        "db_max_age": "3d",              # DB がこれより古いと警告
    },
    "enrich": {
        "kev": True,
        "kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "epss": True,
        "epss_url": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "refresh": "1d",
    },
    "noise": {
        "old_kernels": True,             # 起動中でないカーネルのパッケージ
        "distro_owned": True,            # ディストリのパッケージが所有するファイル上の言語パッケージ
        "distro_vendor_regex": r"(?i)ubuntu|debian|red hat|rocky|almalinux|centos|fedora|oracle|suse|amazon",
        "package_cache": True,           # /var/cache/{apt,dnf,yum} などの中のもの
        "paths": [],                     # 追加でノイズ扱いにするパス (glob)
    },
    "notify": {
        "policy": {
            "min_severity": "HIGH",
            "only_fixable": True,
            "always_notify": {"kev": True, "epss_gte": 0.5},
            "vendor_status_ignore": ["will_not_fix", "end_of_life"],
            "repeat": "until_fixed",     # until_fixed | once
            "remind_every": "1d",
            "report_resolved": True,
            "quiet_when_empty": True,
            "notify_reboot_required": True,
            "notify_warnings": True,     # スキャン失敗・SBOM の鮮度・DB の古さ
            "max_items": 30,             # 1通に載せる行数 (超過分は件数だけ)
            "group_by_package": True,    # 同じパッケージ・場所の CVE を 1 行にまとめる
            "report_timings": True,      # 対象ごとの syft / trivy の開始・終了時刻と所要時間を載せる
            "report_skipped": True,      # 調査対象外にしたもの (無効・skip・パスなし・時間切れなど) を載せる
        },
        "suppress_file": "/etc/sbomops/accepted.tsv",
        "slack": {
            "enabled": False,
            "webhook_env": "SLACK_WEBHOOK_URL",
            "mention": "<!here>",
            "mention_on": ["kev", "critical"],
            "timeout": 20,
        },
    },
    "assess": {
        "enabled": False,
        "engine": "claude",              # claude | codex | command
        "command": None,                 # engine=command のとき: プロンプトを stdin で受け、JSON を stdout に返すコマンド
        "model": None,
        "run_as": None,                  # root 実行時、このユーザーとして CLI を呼ぶ (認証情報がそのユーザーにあるため)
        "max_per_run": 20,
        "cache": "30d",
        "timeout": "15m",
        "include_host_context": False,
        "redact": {"hostname": True, "home_paths": True},
        "language": "ja",
    },
    "retention": {"results_days": 14, "logs_days": None, "sbom_keep": 3},   # logs_days 未指定 = results_days
}

TARGET_DEFAULTS = {
    "every": "1d",
    "enabled": True,
    "exclude": [],
    "syft_args": [],
    "max_runtime": "2h",
    "mem_max": None,       # 未指定なら resources.mem_max
}

TARGET_TYPES = ("os-packages", "dir", "image", "running-images")


class ConfigError(Exception):
    pass


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_file(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if path.endswith(".json"):
        return json.loads(text) or {}
    try:
        import yaml  # type: ignore
    except ImportError:
        try:
            return json.loads(text) or {}
        except json.JSONDecodeError:
            raise ConfigError(
                f"{path} は YAML ですが PyYAML がありません。"
                " apt install python3-yaml / dnf install python3-pyyaml で入れるか、JSON で書いてください") from None
    return yaml.safe_load(text) or {}


def find_config(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    if os.environ.get("SBOMOPS_CONFIG"):
        return os.environ["SBOMOPS_CONFIG"]
    for p in SEARCH_PATHS:
        if os.path.isfile(p):
            return p
    return None


def load(path: str | None) -> dict:
    user = _load_file(path) if path else {}
    if not isinstance(user, dict):
        raise ConfigError(f"{path}: トップレベルはマップである必要があります")
    cfg = _merge(DEFAULTS, user)
    cfg["_path"] = path
    validate(cfg)
    return cfg


def validate(cfg: dict) -> None:
    errs = []
    cfg["host_label"] = cfg.get("host_label") or socket.gethostname()
    pol = cfg["notify"]["policy"]
    if str(pol["min_severity"]).upper() not in SEVERITIES:
        errs.append(f"notify.policy.min_severity は {SEVERITIES} のいずれか")
    pol["min_severity"] = str(pol["min_severity"]).upper()
    if pol["repeat"] not in ("until_fixed", "once"):
        errs.append("notify.policy.repeat は until_fixed / once")
    if cfg["assess"]["engine"] not in ("claude", "codex", "command"):
        errs.append("assess.engine は claude / codex / command")
    if cfg["assess"]["engine"] == "command" and cfg["assess"]["enabled"] and not cfg["assess"]["command"]:
        errs.append("assess.engine=command のときは assess.command が必要")
    try:
        for v in (cfg["run"]["scan_budget"], cfg["notify"]["policy"]["remind_every"],
                  cfg["assess"]["cache"], cfg["assess"]["timeout"], cfg["enrich"]["refresh"],
                  cfg["trivy"]["db_max_age"]):
            parse_duration(v)
        parse_size(cfg["resources"]["mem_max"])
    except ValueError as e:
        errs.append(str(e))

    ids = set()
    targets = []
    for i, t in enumerate(cfg.get("targets") or []):
        if not isinstance(t, dict):
            errs.append(f"targets[{i}] はマップで書いてください")
            continue
        t = _merge(TARGET_DEFAULTS, t)
        tid = t.get("id")
        if not tid:
            errs.append(f"targets[{i}]: id が必要")
            continue
        if tid in ids:
            errs.append(f"targets: id {tid!r} が重複")
        ids.add(tid)
        if t.get("type") not in TARGET_TYPES:
            errs.append(f"targets[{tid}]: type は {TARGET_TYPES} のいずれか")
        if t["type"] in ("dir",) and not (t.get("path") or t.get("path_glob")):
            errs.append(f"targets[{tid}]: dir には path か path_glob が必要")
        if t["type"] == "image" and not t.get("ref"):
            errs.append(f"targets[{tid}]: image には ref が必要")
        try:
            parse_duration(t["every"])
            parse_duration(t["max_runtime"])
            parse_size(t["mem_max"])
        except ValueError as e:
            errs.append(f"targets[{tid}]: {e}")
        targets.append(t)
    cfg["targets"] = targets
    if errs:
        raise ConfigError("設定エラー:\n  - " + "\n  - ".join(errs))
