"""スキャン対象の展開 (path_glob / running-images を具体的な単位に分ける) と実行周期の判定"""
from __future__ import annotations

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


def expand(cfg: dict, with_images: bool = True) -> tuple[list[Unit], set[str]]:
    """(単位の一覧, 展開に失敗した target id) を返す。失敗した target の既存の単位は解消扱いにしない"""
    from .config import SYSTEM_EXCLUDES
    res = cfg["resources"]
    units: list[Unit] = []
    failed: set[str] = set()
    for t in cfg["targets"]:
        if not t.get("enabled", True):
            continue
        every = parse_duration(t["every"])
        maxrt = parse_duration(t["max_runtime"])
        mem = parse_size(t["mem_max"] or res["mem_max"])
        args = list(t.get("syft_args") or [])
        tp = t["type"]
        if tp == "os-packages":
            root = t.get("path") or "/"
            ex = _excludes(root, SYSTEM_EXCLUDES + ["/home", "/root", "/opt", "/srv", "/usr/local",
                                                    "/usr/share", "/usr/src", "/usr/include", "/boot"]
                           + list(t["exclude"]))
            # OS のパッケージ DB を読む cataloger だけを使う (apt/dnf/apk/pacman などに共通の os タグ)
            a = ["--override-default-catalogers", "os", "--select-catalogers", "-rpm-archive-cataloger"]
            units.append(Unit(t["id"], t["id"], tp, f"dir:{root}", root, every, maxrt, mem,
                              a + _flag_ex(ex) + args))
        elif tp == "dir":
            paths = []
            if t.get("path"):
                paths += [t["path"]] if isinstance(t["path"], str) else list(t["path"])
            for g in ([t["path_glob"]] if isinstance(t.get("path_glob"), str) else t.get("path_glob") or []):
                paths += sorted(p.rstrip("/") for p in glob.glob(g) if os.path.isdir(p))
            multi = bool(t.get("path_glob")) or len(paths) > 1
            for p in paths:
                if not os.path.isdir(p):
                    log.info("-- %s: %s がない (スキップ)", t["id"], p)
                    continue
                uid = f"{t['id']}:{safe_name(p.strip('/'))}" if multi else t["id"]
                ex = list(t["exclude"]) + ["./**/.git/**"]
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
                failed.add(t["id"])
                continue
            try:
                imgs = host.running_images(rt)
            except Exception as e:  # noqa: BLE001
                log.warning("-- %s: %s", t["id"], e)
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
