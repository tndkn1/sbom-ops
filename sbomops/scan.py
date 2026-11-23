"""syft で SBOM (CycloneDX JSON) を作る"""
from __future__ import annotations

import glob
import json
import os
import shutil
import tempfile
import time

from . import host, runner
from .targets import Unit
from .util import fmt_duration, log, safe_name


def find_tool(cfg: dict, name: str) -> str:
    p = cfg["tools"].get(name)
    if p:
        return p
    for c in (f"/opt/sbomops/bin/{name}", os.path.join(os.path.dirname(__file__), "..", ".tools", name)):
        if os.access(c, os.X_OK):
            return os.path.abspath(c)
    w = shutil.which(name)
    if not w:
        raise FileNotFoundError(f"{name} が見つかりません (scripts/install-tools.sh で入れるか tools.{name} を設定)")
    return w


# OS のパッケージ DB と、ディストリ判定に使うファイル (syft の os タグの cataloger が読むもの)
OS_DB_PATHS = [
    "etc/os-release", "usr/lib/os-release", "etc/system-release", "etc/redhat-release",
    "etc/debian_version", "etc/alpine-release", "etc/lsb-release",
    "var/lib/dpkg/status", "var/lib/dpkg/status.d",
    "var/lib/rpm", "usr/lib/sysimage/rpm", "usr/share/rpm",
    "lib/apk/db/installed", "var/lib/pacman/local", "var/db/pkg",
]


def snapshot_os_db(root: str, dest: str) -> int:
    """root のパッケージ DB を dest に写す。写したパスの数を返す"""
    n = 0
    for rel in OS_DB_PATHS:
        src = os.path.join(root, rel)
        dst = os.path.join(dest, rel)
        if os.path.islink(src):
            src = os.path.realpath(src)
        if os.path.isdir(src):
            shutil.copytree(src, dst, symlinks=False, ignore_dangling_symlinks=True,
                            ignore=shutil.ignore_patterns("__db.*", "*.lock", ".dbenv.lock"))
            n += 1
        elif os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            n += 1
    return n


def scan_unit(cfg: dict, u: Unit, data_dir: str) -> tuple[str, runner.Result]:
    """SBOM を作り、保存先のパスと実行結果を返す。失敗時は RuntimeError"""
    syft = find_tool(cfg, "syft")
    d = os.path.join(data_dir, "sbom", safe_name(u.id))
    os.makedirs(d, mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    out = os.path.join(d, f"{stamp}.cdx.json")
    tmp = out + ".part"
    logp = os.path.join(data_dir, "logs", "syft", f"{safe_name(u.id)}.log")
    os.makedirs(os.path.dirname(logp), exist_ok=True)
    with open(logp, "w") as f:
        f.write(f"# {time.strftime('%F %T')} {u.source}\n")
    env = {
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        # ファイル単位のハッシュ等は不要で、メモリを最も使うため無効化
        "SYFT_FILE_METADATA_SELECTION": "none",
        "SYFT_PARALLELISM": str(cfg["resources"].get("syft_parallelism", 2)),
    }
    if u.type == "image":
        name = u.source.split(":", 1)[1]
    else:
        name = u.root.rstrip("/") or host.hostname()
    cmd = [syft, "scan", "-q", u.source, *u.syft_args, "--source-name", name,
           "-o", f"cyclonedx-json={tmp}"]
    log.info("scan %s (%s)", u.id, u.source)
    if u.type == "dir" and host.ROOT != "/":
        cmd[cmd.index(u.source)] = f"dir:{host.hpath(u.root)}"   # 記録はホスト上のパスのまま、読むのは host_root の下
    snap = None
    if u.type == "os-packages":
        snap = tempfile.mkdtemp(prefix="osdb-", dir=data_dir)
        if not snapshot_os_db(host.hpath(u.root), snap):
            shutil.rmtree(snap, ignore_errors=True)
            raise RuntimeError(f"{u.root} にパッケージ DB が見つからない")
        cmd[cmd.index(u.source)] = f"dir:{snap}"
    try:
        r = runner.run(cmd, cfg["resources"], mem_max=u.mem_max, timeout=u.max_runtime, env=env,
                       log_path=logp)
    finally:
        if snap:
            shutil.rmtree(snap, ignore_errors=True)
    if r.rc != 0 or r.killed or not os.path.exists(tmp):
        if os.path.exists(tmp):
            os.unlink(tmp)
        why = r.killed or f"rc={r.rc}"
        raise RuntimeError(f"syft 失敗 ({why}): {(r.stderr_tail.strip().splitlines() or [''])[-1]}")
    with open(tmp, encoding="utf-8") as f:
        n = len(json.load(f).get("components") or [])
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    log.info("  -> %d components, %s, peak RSS %dMiB", n, fmt_duration(r.elapsed), r.peak_rss >> 20)
    _prune(d, int(cfg["retention"].get("sbom_keep", 3)))
    return out, r


def _prune(d: str, keep: int) -> None:
    files = sorted(glob.glob(os.path.join(d, "*.cdx.json")))
    for f in files[:-max(keep, 1)]:
        os.unlink(f)
