"""小さな共通関数 (期間・サイズの解析、原子的な書き込み、ログ)"""
from __future__ import annotations

import datetime as dt
import logging
import os
import re
import tempfile

log = logging.getLogger("sbomops")

_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$")
_DUR_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}


def parse_duration(v) -> int:
    """'90m' '6h' '1d' '2w' や数値 (秒) を秒数にする。0 / None / 'off' は 0。"""
    if v in (None, "", 0, "0", "off", False):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    m = _DUR.match(str(v))
    if not m:
        raise ValueError(f"期間の書式が不正: {v!r} (例: 30m, 6h, 1d, 2w)")
    return int(float(m.group(1)) * _DUR_UNIT[m.group(2)])


_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*$", re.I)


def parse_size(v) -> int:
    """'4G' '512M' や数値 (バイト) をバイト数にする。0 / None は 0 (無制限)。"""
    if v in (None, "", 0, "0", "off", False):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    m = _SIZE.match(str(v))
    if not m:
        raise ValueError(f"サイズの書式が不正: {v!r} (例: 512M, 4G)")
    return int(float(m.group(1)) * 1024 ** "_KMGT".index(m.group(2).upper() or "_"))


def fmt_duration(sec: float) -> str:
    sec = int(sec)
    if sec >= 86400 and sec % 86400 == 0:
        return f"{sec // 86400}d"
    if sec < 120:
        return f"{sec}s"
    if sec < 7200:
        return f"{sec // 60}m"
    if sec < 2 * 86400:
        return f"{sec / 3600:.1f}h"
    return f"{sec / 86400:.1f}d"


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t: dt.datetime | None) -> str | None:
    return t.isoformat() if t else None


def parse_iso(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    # Python 3.9 の fromisoformat は "Z" と 7 桁以上の小数秒 (trivy はナノ秒) を読めない
    s = re.sub(r"(\.\d{6})\d+", r"\1", s.strip().replace("Z", "+00:00"))
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def atomic_write(path: str, data: bytes | str, mode: int = 0o640) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def safe_name(s: str) -> str:
    """ファイル名に使える形にする"""
    return re.sub(r"[^A-Za-z0-9._@+-]+", "_", s).strip("_") or "_"


def setup_logging(verbose: bool = False, logfile: str | None = None) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S")
    root = logging.getLogger("sbomops")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()
    h = logging.StreamHandler()
    h.setFormatter(fmt)
    root.addHandler(h)
    if logfile:
        os.makedirs(os.path.dirname(logfile), exist_ok=True)
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)


def load_env_file(path: str) -> None:
    """KEY=VALUE 形式のファイルを読み、未設定の環境変数だけを埋める (systemd の EnvironmentFile 互換)"""
    if not path or not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip().removeprefix("export ").strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            os.environ.setdefault(k, v)
