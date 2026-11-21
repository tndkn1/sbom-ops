"""KEV (CISA) と EPSS (FIRST) を取得してキャッシュする。取得に失敗したら前回のキャッシュを使う。"""
from __future__ import annotations

import csv
import gzip
import json
import os
import time
import urllib.request

from .util import atomic_write, log, parse_duration

UA = "sbomops/1.0"


def _fetch(url: str, path: str, max_age: int) -> str | None:
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age:
        return path
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r:
            atomic_write(path, r.read(), 0o644)
        return path
    except Exception as e:  # noqa: BLE001
        if os.path.exists(path):
            log.warning("取得失敗のため前回のキャッシュを使う: %s (%s)", url, e)
            return path
        log.warning("取得失敗: %s (%s)", url, e)
        return None


class Enricher:
    def __init__(self, cfg: dict, data_dir: str):
        e = cfg["enrich"]
        d = os.path.join(data_dir, "feeds")
        age = parse_duration(e["refresh"]) or 86400
        self.kev: set[str] = set()
        self.epss: dict[str, float] = {}
        self.warnings: list[str] = []
        if e.get("kev"):
            p = _fetch(e["kev_url"], os.path.join(d, "kev.json"), age)
            if p:
                with open(p, encoding="utf-8") as f:
                    self.kev = {v["cveID"] for v in json.load(f).get("vulnerabilities", [])}
            else:
                self.warnings.append("KEV リストを取得できない")
        if e.get("epss"):
            p = _fetch(e["epss_url"], os.path.join(d, "epss.csv.gz"), age)
            if p:
                with gzip.open(p, "rt", encoding="utf-8") as f:
                    rows = (line for line in f if not line.startswith("#"))
                    for row in csv.DictReader(rows):
                        try:
                            self.epss[row["cve"]] = float(row["epss"])
                        except (KeyError, ValueError):
                            continue
            else:
                self.warnings.append("EPSS を取得できない")
        log.info("enrich: KEV %d 件, EPSS %d 件", len(self.kev), len(self.epss))

    def apply(self, rec: dict) -> None:
        ids = [rec["vuln_id"]] + rec.pop("_aliases", [])
        rec["kev"] = int(any(i in self.kev for i in ids))
        scores = [self.epss[i] for i in ids if i in self.epss]
        rec["epss"] = max(scores) if scores else None

