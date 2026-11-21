"""ホストの情報をディストリに依存せずに得る (os-release、dpkg / rpm、カーネル、コンテナランタイム)"""
from __future__ import annotations

import glob
import os
import platform
import re
import shutil
import subprocess

from .util import log


def os_release(root: str = "/") -> dict:
    out = {}
    for p in ("etc/os-release", "usr/lib/os-release"):
        path = os.path.join(root, p)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.rstrip("\n").split("=", 1)
                        out[k] = v.strip().strip('"')
            break
    return out


def os_fingerprint() -> str:
    r = os_release()
    return f"{r.get('ID', '?')}-{r.get('VERSION_ID', '?')}"


def package_manager() -> str | None:
    """パッケージ DB の種類。dpkg と rpm が両方ある場合 (Ubuntu に rpm コマンドだけ入っている等) は dpkg を優先"""
    if os.path.isfile("/var/lib/dpkg/status") and shutil.which("dpkg-query"):
        return "dpkg"
    if shutil.which("rpm") and (os.path.isdir("/var/lib/rpm") or os.path.isdir("/usr/lib/sysimage/rpm")):
        return "rpm"
    return None


def running_kernel() -> str:
    return platform.release()


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def file_owners(paths: list[str]) -> dict[str, str | None]:
    """ファイル → 所有パッケージ名 (なければ None)。まとめて問い合わせる。"""
    pm = package_manager()
    res: dict[str, str | None] = {p: None for p in paths}
    if not pm or not paths:
        return res
    uniq = sorted(set(paths))
    for i in range(0, len(uniq), 200):
        chunk = uniq[i:i + 200]
        if pm == "dpkg":
            # 出力: "pkg1, pkg2: /path"。所有者がないものは stderr に出る
            r = _run(["dpkg-query", "-S", *chunk])
            for line in r.stdout.splitlines():
                if ": " not in line or line.startswith("diversion"):
                    continue
                pkgs, path = line.split(": ", 1)
                if path in res:
                    res[path] = pkgs.split(",")[0].strip().split(":")[0]
        else:
            # rpm -qf は引数の順に1行ずつ返す (所有者なしは "... is not owned by any package")
            r = _run(["rpm", "-qf", "--qf", "%{NAME}\n", *chunk])
            lines = r.stdout.splitlines()
            if len(lines) == len(chunk):
                for path, line in zip(chunk, lines):
                    if "not owned" not in line and "No such file" not in line:
                        res[path] = line.strip()
            else:  # 1つのファイルに複数パッケージが対応するなどで行数がずれたら1件ずつ
                for path in chunk:
                    r1 = _run(["rpm", "-qf", "--qf", "%{NAME}\n", path])
                    if r1.returncode == 0:
                        res[path] = r1.stdout.splitlines()[0].strip()
    return res


def package_vendors(pkgs: list[str]) -> dict[str, str]:
    """パッケージ → 提供元の文字列 (dpkg は Maintainer、rpm は Vendor)"""
    pm = package_manager()
    res: dict[str, str] = {}
    uniq = sorted({p for p in pkgs if p})
    if not pm or not uniq:
        return res
    for i in range(0, len(uniq), 200):
        chunk = uniq[i:i + 200]
        if pm == "dpkg":
            r = _run(["dpkg-query", "-W", "-f", "${Package}\t${Maintainer}\n", *chunk])
        else:
            r = _run(["rpm", "-q", "--qf", "%{NAME}\t%{VENDOR}\n", *chunk])
        for line in r.stdout.splitlines():
            if "\t" in line:
                name, vendor = line.split("\t", 1)
                res.setdefault(name.split(":")[0], vendor)
    return res


def installed_kernels() -> list[str]:
    """インストール済みカーネルのリリース文字列 (uname -r と同じ形)"""
    rel = set()
    for p in glob.glob("/lib/modules/*/") + glob.glob("/usr/lib/modules/*/"):
        name = os.path.basename(p.rstrip("/"))
        if os.path.exists(os.path.join(p, "modules.dep")) or glob.glob(f"/boot/vmlinuz-{name}"):
            rel.add(name)
    return sorted(rel, key=_ver_key)


def _ver_key(s: str):
    return [int(x) if x.isdigit() else x for x in re.split(r"[.\-_+~]", s)]


def reboot_required() -> str | None:
    """再起動が必要なら理由を返す"""
    if os.path.exists("/var/run/reboot-required"):
        pk = ""
        try:
            with open("/var/run/reboot-required.pkgs") as f:
                pk = ", ".join(sorted({x.strip() for x in f if x.strip()})[:5])
        except OSError:
            pass
        return "reboot-required" + (f" ({pk})" if pk else "")
    if shutil.which("needs-restarting"):
        try:
            r = _run(["needs-restarting", "-r"], timeout=60)
            if r.returncode == 1:
                return "needs-restarting -r: 再起動が必要"
            if r.returncode == 0:
                return None
        except (OSError, subprocess.SubprocessError):
            pass
    ks = installed_kernels()
    cur = running_kernel()
    if ks and cur in ks and ks[-1] != cur:
        return f"新しいカーネル {ks[-1]} がインストール済み (起動中: {cur})"
    return None


def container_runtime() -> str | None:
    for rt in ("docker", "podman"):
        if shutil.which(rt):
            try:
                if _run([rt, "info", "--format", "{{.ID}}"], timeout=30).returncode == 0:
                    return rt
            except (OSError, subprocess.SubprocessError):
                continue
    return None


def running_images(runtime: str) -> list[tuple[str, str]]:
    """(イメージ名, イメージ ID) の一覧"""
    r = _run([runtime, "ps", "--format", "{{.Image}}"], timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"{runtime} ps 失敗: {r.stderr.strip()}")
    out = []
    for img in sorted(set(x.strip() for x in r.stdout.splitlines() if x.strip())):
        i = _run([runtime, "image", "inspect", "--format", "{{.Id}}", img], timeout=60)
        out.append((img, i.stdout.strip() if i.returncode == 0 else ""))
    return out


def running_executables() -> set[str]:
    """稼働中プロセスの実行ファイルのパス (読める範囲で)"""
    exes = set()
    for p in glob.glob("/proc/[0-9]*/exe"):
        try:
            exes.add(os.readlink(p).removesuffix(" (deleted)"))
        except OSError:
            continue
    return exes


def home_dirs() -> dict[str, str]:
    """ユーザー名 → ホーム (UID 1000 以上と root)"""
    import pwd
    return {p.pw_name: p.pw_dir for p in pwd.getpwall()
            if (p.pw_uid >= 1000 or p.pw_uid == 0) and p.pw_dir not in ("/", "/nonexistent")}


def log_summary() -> None:
    r = os_release()
    log.info("host: %s %s, kernel %s, pkg=%s", r.get("ID"), r.get("VERSION_ID"),
             running_kernel(), package_manager())
