"""検出の分類 (ノイズ / 受容 / 有効) と、通知するかどうかの判定"""
from __future__ import annotations

import datetime as dt
import fnmatch
import os
import re
from dataclasses import dataclass

from . import host
from .config import SEVERITIES
from .match import OS_PURL
from .util import log, parse_duration, parse_iso

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}   # CRITICAL=0 が最も高い
KERNEL_PKG = re.compile(r"^(linux-(image|modules|headers|tools|cloud-tools|buildinfo|objects)(-[a-z0-9.]+)*"
                        r"|kernel(-[a-z]+)*)$")
KVER = re.compile(r"(\d+\.\d+\.\d+-\d+)")
CACHE_DIRS = ("/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/", "/var/cache/zypp/")


# ------------------------------------------------------------------ 受容リスト
@dataclass
class Accept:
    vuln: str
    unit: str
    pkg: str
    until: dt.date | None
    reason: str


def load_accepts(path: str) -> list[Accept]:
    """書式 (空白区切り): vuln_id  unit(glob)  package(glob)  期限(YYYY-MM-DD か -)  理由..."""
    out: list[Accept] = []
    if not path or not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 4)
            if len(parts) < 4:
                log.warning("%s:%d: 列が足りない (無視): %s", path, n, line)
                continue
            until = None if parts[3] == "-" else dt.date.fromisoformat(parts[3])
            out.append(Accept(parts[0], parts[1], parts[2], until, parts[4] if len(parts) > 4 else ""))
    return out


class Classifier:
    def __init__(self, cfg: dict, today: dt.date):
        self.cfg = cfg
        self.noise = cfg["noise"]
        self.today = today
        self.kernel = host.running_kernel()
        self.accepts = load_accepts(cfg["notify"].get("suppress_file"))
        self.vendor_re = re.compile(self.noise.get("distro_vendor_regex") or "$^")
        self._owner: dict[str, str | None] = {}
        self._vendor: dict[str, str] = {}
        self.expired_accepts: list[str] = []

    def prepare(self, recs: list[dict], unit_type: str) -> None:
        """ファイル所有者の問い合わせをまとめて行う (ホスト上の対象のみ)"""
        if not self.noise.get("distro_owned") or unit_type == "image":
            return
        paths = [r["location"] for r in recs
                 if r["location"].startswith("/") and r["location"] not in self._owner
                 and not r["purl"].startswith(OS_PURL)]
        if paths:
            self._owner.update(host.file_owners(paths))
            pk = [p for p in self._owner.values() if p and p not in self._vendor]
            self._vendor.update(host.package_vendors(pk))

    def classify(self, r: dict, unit_type: str) -> str:
        """active | noise:<理由> | suppressed:<理由>"""
        n = self.noise
        loc = r["location"] or ""
        is_os_pkg = r["purl"].startswith(OS_PURL)
        if unit_type != "image":
            if n.get("old_kernels") and is_os_pkg and KERNEL_PKG.match(r["pkg"]):
                m = KVER.search(r["pkg"]) or KVER.search(r["version"])
                if m and not self.kernel.startswith(m.group(1)):
                    return "noise:old-kernel"
            if n.get("package_cache") and loc.startswith(CACHE_DIRS):
                return "noise:package-cache"
            if n.get("distro_owned") and not is_os_pkg and loc:
                owner = self._owner.get(loc)
                if owner and self.vendor_re.search(self._vendor.get(owner, "")):
                    return f"noise:distro-owned({owner})"
        for pat in n.get("paths") or []:
            if loc and fnmatch.fnmatch(loc, pat):
                return "noise:path"
        for a in self.accepts:
            if (a.vuln == r["vuln_id"] or fnmatch.fnmatch(r["vuln_id"], a.vuln)) \
                    and fnmatch.fnmatch(r["unit"], a.unit) and fnmatch.fnmatch(r["pkg"], a.pkg):
                if a.until and a.until < self.today:
                    self.expired_accepts.append(r["key"])
                    continue      # 期限切れは通常の検出に戻す
                return "suppressed:accepted"
        return "active"


def eligible(r, pol: dict) -> bool:
    """通知条件 (重大度・修正版の有無・KEV/EPSS) を満たすか"""
    if r["vstatus"] in (pol.get("vendor_status_ignore") or []):
        return False
    always = pol.get("always_notify") or {}
    if always.get("kev") and r["kev"]:
        return True
    eg = always.get("epss_gte")
    if eg is not None and r["epss"] is not None and r["epss"] >= float(eg):
        return True
    if pol.get("only_fixable") and not r["fixed"]:
        return False
    return SEV_RANK.get(r["severity"], 99) <= SEV_RANK[pol["min_severity"]]


def should_notify(r, pol: dict, now: dt.datetime) -> str | None:
    """通知するなら 'new' / 'remind' を返す"""
    if r["state"] != "open" or not r["eligible"] or not str(r["class"]).startswith("active"):
        return None
    last = parse_iso(r["last_notified"])
    if last is None:
        return "new"
    if pol["repeat"] == "once":
        return None
    gap = parse_duration(pol.get("remind_every")) or 86400
    # 毎日同じ時刻に動かすので 1 時間の余裕を持たせる
    if (now - last).total_seconds() >= gap - 3600:
        return "remind"
    return None


def sort_key(r, assess: dict | None = None):
    a = (assess or {}).get(r["key"])
    pr = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}.get(a["priority"] if a else "", 4)
    return (pr, -int(r["kev"] or 0), SEV_RANK.get(r["severity"], 99), -(r["epss"] or 0), r["vuln_id"])
