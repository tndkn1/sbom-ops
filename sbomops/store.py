"""状態 DB (sqlite3)。検出の初出・最終確認・通知日時・解消日時と、対象ごとのスキャン状態を持つ。"""
from __future__ import annotations

import json
import os
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
  key TEXT PRIMARY KEY,          -- unit|vuln_id|pkg_name|location
  unit TEXT NOT NULL,
  vuln_id TEXT NOT NULL,
  pkg TEXT NOT NULL,
  pkg_type TEXT,
  version TEXT,
  fixed TEXT,
  vstatus TEXT,                  -- trivy の Status (fixed / affected / will_not_fix ...)
  severity TEXT,
  title TEXT,
  url TEXT,
  location TEXT,
  purl TEXT,
  kev INTEGER DEFAULT 0,
  epss REAL,
  class TEXT,                    -- active | noise:<理由> | suppressed:<理由>
  eligible INTEGER DEFAULT 0,    -- 通知条件を満たすか (最新の評価)
  state TEXT NOT NULL,           -- open | resolved
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  resolved_at TEXT,
  last_notified TEXT
);
CREATE INDEX IF NOT EXISTS findings_unit ON findings(unit, state);
CREATE TABLE IF NOT EXISTS units (
  id TEXT PRIMARY KEY,
  grp TEXT,
  type TEXT,
  source TEXT,
  root TEXT,
  every INTEGER,
  sbom_path TEXT,
  digest TEXT,
  last_scan_ts REAL,
  last_scan_status TEXT,
  last_scan_error TEXT,
  last_scan_sec REAL,
  last_scan_rss INTEGER,
  last_match_ts REAL,
  last_match_status TEXT,
  seen_in_config INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS assessments (
  key TEXT PRIMARY KEY,
  ts TEXT,
  engine TEXT,
  priority TEXT,
  exploitable TEXT,
  rationale TEXT,
  action TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started TEXT,
  finished TEXT,
  result TEXT,
  summary TEXT
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""

FINDING_COLS = ["key", "unit", "vuln_id", "pkg", "pkg_type", "version", "fixed", "vstatus",
                "severity", "title", "url", "location", "purl", "kev", "epss"]


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        os.chmod(path, 0o600)

    def close(self):
        self.db.commit()
        self.db.close()

    # ---- meta
    def get_meta(self, k: str, default=None):
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return json.loads(r["v"]) if r else default

    def set_meta(self, k: str, v) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", (k, json.dumps(v)))
        self.db.commit()

    # ---- units
    def units(self) -> dict[str, dict]:
        return {r["id"]: dict(r) for r in self.db.execute("SELECT * FROM units")}

    def upsert_unit(self, uid: str, **kw) -> None:
        cur = self.db.execute("SELECT 1 FROM units WHERE id=?", (uid,)).fetchone()
        if not cur:
            self.db.execute("INSERT INTO units(id) VALUES (?)", (uid,))
        if kw:
            sets = ", ".join(f"{k}=?" for k in kw)
            self.db.execute(f"UPDATE units SET {sets} WHERE id=?", (*kw.values(), uid))
        self.db.commit()

    def mark_config_units(self, ids: set[str]) -> None:
        self.db.execute("UPDATE units SET seen_in_config=0")
        for i in ids:
            self.db.execute("UPDATE units SET seen_in_config=1 WHERE id=?", (i,))
        self.db.commit()

    # ---- findings
    def open_findings(self, unit: str) -> dict[str, sqlite3.Row]:
        return {r["key"]: r for r in self.db.execute(
            "SELECT * FROM findings WHERE unit=? AND state='open'", (unit,))}

    def get(self, key: str):
        return self.db.execute("SELECT * FROM findings WHERE key=?", (key,)).fetchone()

    def sync_unit(self, unit: str, records: list[dict], today: str) -> tuple[list[str], list[str]]:
        """unit の今回の検出で状態を更新する。(新規 key, 解消 key) を返す。
        一度解消したものが再び出た場合は新規として扱う (first_seen を付け直す)。"""
        before = self.open_findings(unit)
        new, seen = [], set()
        for r in records:
            seen.add(r["key"])
            old = self.get(r["key"])
            vals = [r.get(c) for c in FINDING_COLS]
            if old is None:
                self.db.execute(
                    f"INSERT INTO findings({','.join(FINDING_COLS)}, state, first_seen, last_seen)"
                    f" VALUES ({','.join('?' * len(FINDING_COLS))}, 'open', ?, ?)", (*vals, today, today))
                new.append(r["key"])
            else:
                reopened = old["state"] != "open"
                sets = ", ".join(f"{c}=?" for c in FINDING_COLS[1:])
                self.db.execute(
                    f"UPDATE findings SET {sets}, state='open', last_seen=?, resolved_at=NULL"
                    + (", first_seen=?, last_notified=NULL" if reopened else "") + " WHERE key=?",
                    (*vals[1:], today, *([today] if reopened else []), r["key"]))
                if reopened:
                    new.append(r["key"])
        resolved = [k for k in before if k not in seen]
        for k in resolved:
            self.db.execute("UPDATE findings SET state='resolved', resolved_at=? WHERE key=?", (today, k))
        self.db.commit()
        return new, resolved

    def resolve_unit(self, unit: str, today: str) -> list[str]:
        keys = list(self.open_findings(unit))
        self.db.execute("UPDATE findings SET state='resolved', resolved_at=? WHERE unit=? AND state='open'",
                        (today, unit))
        self.db.commit()
        return keys

    def set_class(self, key: str, cls: str, eligible: bool) -> None:
        self.db.execute("UPDATE findings SET class=?, eligible=? WHERE key=?", (cls, int(eligible), key))

    def mark_notified(self, keys: list[str], ts: str) -> None:
        self.db.executemany("UPDATE findings SET last_notified=? WHERE key=?", [(ts, k) for k in keys])
        self.db.commit()

    def query(self, sql: str, args=()) -> list[sqlite3.Row]:
        return self.db.execute(sql, args).fetchall()

    def commit(self):
        self.db.commit()

    # ---- assessments
    def assessment(self, key: str):
        return self.db.execute("SELECT * FROM assessments WHERE key=?", (key,)).fetchone()

    def save_assessment(self, key: str, ts: str, engine: str, a: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO assessments VALUES (?,?,?,?,?,?,?)",
                        (key, ts, engine, a.get("priority"), str(a.get("exploitable_here", "")),
                         a.get("rationale"), a.get("action")))
        self.db.commit()

    # ---- runs
    def start_run(self, ts: str) -> int:
        cur = self.db.execute("INSERT INTO runs(started, result) VALUES (?, 'running')", (ts,))
        self.db.commit()
        return cur.lastrowid

    def finish_run(self, rid: int, ts: str, result: str, summary: dict) -> None:
        self.db.execute("UPDATE runs SET finished=?, result=?, summary=? WHERE id=?",
                        (ts, result, json.dumps(summary, ensure_ascii=False), rid))
        self.db.commit()
