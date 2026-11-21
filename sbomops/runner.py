"""外部コマンドを低優先度で実行し、RSS とタイムアウトを監視する。

cgroup v1 の環境 (RHEL 8 の既定など) では systemd の MemoryMax が効かないため、
プロセスグループ全体の RSS を /proc から合計し、上限を超えたらグループごと kill する。
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass

from .util import log

PAGE = os.sysconf("SC_PAGE_SIZE")


@dataclass
class Result:
    rc: int
    elapsed: float
    peak_rss: int          # バイト
    killed: str | None     # "mem" | "timeout" | None
    stderr_tail: str


def _group_rss(pgid: int) -> int:
    total = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as f:
                st = f.read().rsplit(b")", 1)[1].split()
            # st[0]=state st[2]=pgrp ... st[21]=rss(pages)  (comm の後ろから数える)
            if int(st[2]) == pgid:
                total += int(st[21]) * PAGE
        except (OSError, IndexError, ValueError):
            continue
    return total


def _prefix(res: dict) -> list[str]:
    pre = list(res.get("wrap") or [])
    cls = res.get("ionice_class", "idle")
    if cls and cls != "none" and shutil.which("ionice"):
        pre += ["ionice", "-c", {"idle": "3", "best-effort": "2", "realtime": "1"}.get(cls, "3")]
        if cls == "best-effort":
            pre += ["-n", "7"]
    return pre


def run(cmd: list[str], res: dict, *, mem_max: int = 0, timeout: int = 0,
        env: dict | None = None, stdout=None, stdin_data: bytes | None = None,
        log_path: str | None = None) -> Result:
    """cmd を実行する。res は config の resources。"""
    full = _prefix(res) + cmd
    e = dict(os.environ)
    e.update(env or {})
    if mem_max:
        # Go 製ツール (syft/trivy) は GOMEMLIMIT で上限の手前から GC を効かせる
        e.setdefault("GOMEMLIMIT", f"{mem_max * 3 // 4 // (1 << 20)}MiB")
    nice = int(res.get("nice", 19) or 0)

    def pre():
        os.setsid()
        if nice:
            os.nice(nice)

    log.debug("exec: %s", " ".join(full))
    errf = open(log_path, "ab") if log_path else subprocess.PIPE
    start = time.monotonic()
    p = subprocess.Popen(full, env=e, stdout=stdout or subprocess.DEVNULL, stderr=errf,
                         stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                         preexec_fn=pre)
    if stdin_data is not None:
        try:
            p.stdin.write(stdin_data)
            p.stdin.close()
        except BrokenPipeError:
            pass
    peak, killed = 0, None
    # stderr は PIPE のとき詰まらないように別スレッドで読む
    err_chunks: list[bytes] = []
    if errf is subprocess.PIPE:
        import threading

        def drain():
            for chunk in iter(lambda: p.stderr.read(65536), b""):
                err_chunks.append(chunk)
                if len(err_chunks) > 64:
                    del err_chunks[0]
        th = threading.Thread(target=drain, daemon=True)
        th.start()
    try:
        while p.poll() is None:
            rss = _group_rss(p.pid)
            peak = max(peak, rss)
            if mem_max and rss > mem_max:
                killed = "mem"
            elif timeout and time.monotonic() - start > timeout:
                killed = "timeout"
            if killed:
                log.warning("%s: %s のため停止 (RSS %dMiB)", os.path.basename(cmd[0]),
                            "メモリ上限超過" if killed == "mem" else "時間切れ", rss >> 20)
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                p.wait()
                break
            try:
                p.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    except BaseException:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        raise
    finally:
        if log_path:
            errf.close()
    if errf is subprocess.PIPE:
        th.join(timeout=5)
        p.stderr.close()
        tail = b"".join(err_chunks)[-4000:].decode(errors="replace")
    else:
        tail = _tail(log_path)
    return Result(p.returncode, time.monotonic() - start, peak, killed, tail)


def _tail(path: str, n: int = 4000) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - n))
            return f.read().decode(errors="replace")
    except OSError:
        return ""
