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
