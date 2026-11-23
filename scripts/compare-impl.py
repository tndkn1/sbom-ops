#!/usr/bin/env python3
"""Python 版と Go 版の結果を比べる (CI の compare ジョブ用)。

    compare-impl.py PY_PAYLOAD.json GO_PAYLOAD.json PY_STATE.db GO_STATE.db

Slack のペイロードは調査時間の時刻・秒数だけを伏せて完全一致、状態 DB は findings の全列と
units の主な列が一致することを確かめる。
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys

TIME = re.compile(r"\d\d:\d\d:\d\d〜\d\d:\d\d:\d\d \(\d+(\.\d)?[smhd]\)")
COLS = ("key,unit,vuln_id,pkg,pkg_type,version,fixed,vstatus,severity,title,url,location,purl,kev,epss,"
        "class,eligible,state,first_seen,last_seen,resolved_at,last_notified")


def payload(path: str):
    with open(path, encoding="utf-8") as f:
        return json.loads(TIME.sub("T", f.read()))


def table(path: str, sql: str) -> list:
    db = sqlite3.connect(path)
    try:
        return db.execute(sql).fetchall()
    finally:
        db.close()


def main() -> int:
    pa, pb, da, db = sys.argv[1:5]
    ok = True
    a, b = payload(pa), payload(pb)
    if a != b:
        ok = False
        print(f"ペイロードが違う: {a['text']!r} / {b['text']!r}")
        for i, (x, y) in enumerate(zip(a["blocks"], b["blocks"])):
            if x != y:
                print(f"  block {i}\n    py: {json.dumps(x, ensure_ascii=False)[:500]}\n"
                      f"    go: {json.dumps(y, ensure_ascii=False)[:500]}")
                break
    for name, sql in (("findings", f"SELECT {COLS} FROM findings ORDER BY key"),
                      ("units", "SELECT id, grp, type, source, root, every, last_scan_status, last_match_status "
                                "FROM units ORDER BY id"),
                      ("meta", "SELECT k, v FROM meta ORDER BY k")):
        x, y = table(da, sql), table(db, sql)
        if x != y:
            ok = False
            diff = [(r, s) for r, s in zip(x, y) if r != s][:3]
            print(f"{name} が違う ({len(x)} 行 / {len(y)} 行): {diff}")
    print(f"{a['text']}\n{'一致' if ok else '不一致'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
