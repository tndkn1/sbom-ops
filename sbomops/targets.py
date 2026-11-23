"""スキャン対象の展開 (path_glob / running-images を具体的な単位に分ける) と実行周期の判定"""
from __future__ import annotations

import fnmatch
import glob
import os
from dataclasses import dataclass, field

from . import host
from .util import parse_duration, parse_size, safe_name, log


@dataclass
class Unit:
    """1回の syft 実行に対応する単位"""
    id: str                 # 状態DB・ファイル名に使う一意な名前
    group: str              # 設定上の target id
    type: str               # os-packages | dir | image
    source: str             # syft に渡すソース (dir:/usr/local, docker:nginx:1 など)
    root: str               # location を絶対パスに直すための基点 (dir 以外は "")
    every: int
    max_runtime: int
    mem_max: int
    syft_args: list = field(default_factory=list)
    digest: str = ""        # イメージの場合の ID (変わったら作り直す)


def _excludes(root: str, patterns: list[str]) -> list[str]:
    """絶対パスの除外を syft の書式 (./rel/**) にする。root の外のものは捨てる"""
    out = []
    root = root.rstrip("/") or "/"
    for p in patterns:
        if p.startswith("./") or p.startswith("**"):
            out.append(p)
            continue
        if not p.startswith("/"):
            out.append("./" + p)
            continue
        if root == "/":
            rel = p.lstrip("/")
        elif p == root or p.startswith(root + "/"):
            rel = p[len(root) + 1:]
        else:
            continue
        if not rel:
            continue
        out.append(f"./{rel}" if any(c in rel for c in "*?[") else f"./{rel}/**")
    return out


def expand(cfg: dict, with_images: bool = True,
           skipped: list | None = None) -> tuple[list[Unit], set[str]]:
    """(単位の一覧, 展開に失敗した target id) を返す。失敗した target の既存の単位は解消扱いにしない。
    skipped を渡すと、調査対象から外したものを (名前, 理由) で追加する"""
    skipped = [] if skipped is None else skipped
    from .config import SYSTEM_EXCLUDES
    res = cfg["resources"]
    units: list[Unit] = []
    failed: set[str] = set()
    for t in cfg["targets"]:
        if not t.get("enabled", True):
            skipped.append((t["id"], "無効 (enabled: false)"))
            continue
        every = parse_duration(t["every"])
        maxrt = parse_duration(t["max_runtime"])
        mem = parse_size(t["mem_max"] or res["mem_max"])
        args = list(t.get("syft_args") or [])
        tp = t["type"]
        if tp == "os-packages":
            # パッケージ DB と os-release だけを一時ディレクトリに写してから読む (scan.py)。
            # dir:/ を歩くとデータ領域の大きいホストで遅くなるため
            root = t.get("path") or "/"
            a = ["--override-default-catalogers", "os",
                 "--select-catalogers", "-rpm-archive-cataloger,-deb-archive-cataloger"]
            units.append(Unit(t["id"], t["id"], tp, f"dir:{root}", root, every, maxrt, mem, a + args))
        elif tp == "dir":
            paths = []
            if t.get("path"):
                paths += [t["path"]] if isinstance(t["path"], str) else list(t["path"])
            for g in ([t["path_glob"]] if isinstance(t.get("path_glob"), str) else t.get("path_glob") or []):
                paths += sorted(p.rstrip("/") for p in glob.glob(g) if os.path.isdir(p))
            skip = t.get("skip") or []
            for p in paths:
                if any(fnmatch.fnmatch(p, s) for s in skip):
                    skipped.append((f"{t['id']}: {p}", "skip に一致"))
            paths = [p for p in paths if not any(fnmatch.fnmatch(p, s) for s in skip)]
            multi = bool(t.get("path_glob")) or len(paths) > 1
            for p in paths:
                if not os.path.isdir(p):
                    log.info("-- %s: %s がない (スキップ)", t["id"], p)
                    skipped.append((f"{t['id']}: {p}", "パスがない"))
                    continue
                uid = f"{t['id']}:{safe_name(p.strip('/'))}" if multi else t["id"]
                # sbomops 自身のデータ (SBOM ファイル) を syft の sbom-cataloger が読まないように外す
                ex = list(t["exclude"]) + ["./**/.git/**", cfg["data_dir"]]
                if p.rstrip("/") in ("", "/"):
                    ex += SYSTEM_EXCLUDES
                units.append(Unit(uid, t["id"], tp, f"dir:{p}", p, every, maxrt, mem,
                                  _flag_ex(_excludes(p, ex)) + args))
        elif tp == "image":
            ref = t["ref"]
            schemes = ("docker", "podman", "containerd", "registry", "oci-archive", "docker-archive", "oci-dir")
            src = ref if ref.split(":", 1)[0] in schemes else f"registry:{ref}"
            units.append(Unit(t["id"], t["id"], "image", src, "", every, maxrt, mem, args))
        elif tp == "running-images" and with_images:
            rt = t.get("runtime") or host.container_runtime()
            if not rt:
                log.warning("-- %s: docker / podman が使えない (スキップ)", t["id"])
                skipped.append((t["id"], "docker / podman が使えない"))
                failed.add(t["id"])
                continue
            try:
                imgs = host.running_images(rt)
            except Exception as e:  # noqa: BLE001
                log.warning("-- %s: %s", t["id"], e)
                skipped.append((t["id"], f"稼働中イメージを取得できない: {str(e)[:100]}"))
                failed.add(t["id"])
                continue
            for img, iid in imgs:
                units.append(Unit(f"{t['id']}:{safe_name(img)}", t["id"], "image", f"{rt}:{img}", "",
                                  every, maxrt, mem, args, digest=iid))
        elif tp == "running-images":
            failed.add(t["id"])
    return units, failed


def _flag_ex(ex: list[str]) -> list[str]:
    out = []
    for e in dict.fromkeys(ex):
        out += ["--exclude", e]
    return out


def due(units: list[Unit], state: dict[str, dict], now_ts: float, force: bool = False) -> list[Unit]:
    """作り直しが必要な単位を、期限切れの長いものから並べて返す"""
    scored = []
    for u in units:
        st = state.get(u.id) or {}
        last = st.get("last_scan_ts") or 0
        if force or not last or not st.get("sbom_path") or not os.path.exists(st["sbom_path"]):
            scored.append((float("inf"), u))
            continue
        if u.digest and st.get("digest") != u.digest:
            scored.append((float("inf"), u))
            continue
        # 毎日同じ時刻に動かすので、周期の 1 時間手前を過ぎていれば対象にする
        over = now_ts - last - (u.every - 3600)
        if over >= 0:
            scored.append((over, u))
    scored.sort(key=lambda x: -x[0])
    return [u for _, u in scored]
