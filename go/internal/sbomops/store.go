package sbomops

// 状態 DB (sqlite3)。Python 版と同じスキーマ (spec/schema.sql) なので、同じ data_dir を使い回せる。

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

var findingCols = []string{"key", "unit", "vuln_id", "pkg", "pkg_type", "version", "fixed", "vstatus",
	"severity", "title", "url", "location", "purl", "kev", "epss"}

// Finding は findings の 1 行 (Python 版の dict / sqlite3.Row と同じキー)。
type Finding struct {
	Key          string   `json:"key"`
	Unit         string   `json:"unit"`
	VulnID       string   `json:"vuln_id"`
	Pkg          string   `json:"pkg"`
	PkgType      string   `json:"pkg_type"`
	Version      string   `json:"version"`
	Fixed        string   `json:"fixed"`
	VStatus      string   `json:"vstatus"`
	Severity     string   `json:"severity"`
	Title        string   `json:"title"`
	URL          string   `json:"url"`
	Location     string   `json:"location"`
	PURL         string   `json:"purl"`
	KEV          int      `json:"kev"`
	EPSS         *float64 `json:"epss"`
	Class        string   `json:"class"`
	Eligible     int      `json:"eligible"`
	State        string   `json:"state"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	ResolvedAt   string   `json:"resolved_at"`
	LastNotified string   `json:"last_notified"`
	Aliases      []string `json:"-"` // 照合直後だけ使う (VendorIDs のうち CVE)
}

func (f *Finding) colValues() []any {
	var epss any
	if f.EPSS != nil {
		epss = *f.EPSS
	}
	return []any{f.Key, f.Unit, f.VulnID, f.Pkg, f.PkgType, f.Version, f.Fixed, f.VStatus, f.Severity,
		f.Title, f.URL, f.Location, f.PURL, f.KEV, epss}
}

// UnitState は units の 1 行。
type UnitState struct {
	ID              string
	Grp             string
	Type            string
	Source          string
	Root            string
	Every           int64
	SbomPath        string
	Digest          string
	LastScanTS      float64
	LastScanStatus  string
	LastScanError   string
	LastScanSec     float64
	LastScanRSS     int64
	LastMatchTS     float64
	LastMatchStatus string
}

// Assessment は assessments の 1 行。
type Assessment struct {
	Key         string `json:"key"`
	TS          string `json:"ts"`
	Engine      string `json:"engine"`
	Priority    string `json:"priority"`
	Exploitable string `json:"exploitable"`
	Rationale   string `json:"rationale"`
	Action      string `json:"action"`
}

type Store struct {
	DB *sql.DB
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	os.Chmod(path, 0o600)
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

// ---- meta (値は JSON)

func (s *Store) GetMeta(k string, out any) bool {
	var v string
	if err := s.DB.QueryRow("SELECT v FROM meta WHERE k=?", k).Scan(&v); err != nil {
		return false
	}
	return json.Unmarshal([]byte(v), out) == nil
}

func (s *Store) GetMetaString(k string) string {
	var v *string
	if !s.GetMeta(k, &v) || v == nil {
		return ""
	}
	return *v
}

func (s *Store) SetMeta(k string, v any) error {
	b, _ := json.Marshal(v)
	_, err := s.DB.Exec("INSERT OR REPLACE INTO meta(k, v) VALUES (?, ?)", k, string(b))
	return err
}

// ---- units

func (s *Store) Units() (map[string]*UnitState, error) {
	rows, err := s.DB.Query(`SELECT id, grp, type, source, root, every, sbom_path, digest, last_scan_ts,
		last_scan_status, last_scan_error, last_scan_sec, last_scan_rss, last_match_ts, last_match_status FROM units`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*UnitState{}
	for rows.Next() {
		var id string
		var grp, tp, src, root, sbom, dig, lss, lse, lms sql.NullString
		var every, rss sql.NullInt64
		var lst, lsec, lmt sql.NullFloat64
		if err := rows.Scan(&id, &grp, &tp, &src, &root, &every, &sbom, &dig, &lst, &lss, &lse, &lsec, &rss,
			&lmt, &lms); err != nil {
			return nil, err
		}
		out[id] = &UnitState{ID: id, Grp: grp.String, Type: tp.String, Source: src.String, Root: root.String,
			Every: every.Int64, SbomPath: sbom.String, Digest: dig.String, LastScanTS: lst.Float64,
			LastScanStatus: lss.String, LastScanError: lse.String, LastScanSec: lsec.Float64,
			LastScanRSS: rss.Int64, LastMatchTS: lmt.Float64, LastMatchStatus: lms.String}
	}
	return out, rows.Err()
}

// UpsertUnit は units の行を作り (なければ)、kv の列を更新する。値 nil は NULL。
func (s *Store) UpsertUnit(id string, kv map[string]any) error {
	if _, err := s.DB.Exec("INSERT OR IGNORE INTO units(id) VALUES (?)", id); err != nil {
		return err
	}
	if len(kv) == 0 {
		return nil
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sets := make([]string, len(keys))
	args := make([]any, 0, len(keys)+1)
	for i, k := range keys {
		sets[i] = k + "=?"
		args = append(args, kv[k])
	}
	args = append(args, id)
	_, err := s.DB.Exec("UPDATE units SET "+strings.Join(sets, ", ")+" WHERE id=?", args...)
	return err
}

func (s *Store) DeleteUnit(id string) error {
	_, err := s.DB.Exec("DELETE FROM units WHERE id=?", id)
	return err
}

// ---- findings

const findingSelect = `SELECT key, unit, vuln_id, pkg, pkg_type, version, fixed, vstatus, severity, title, url,
	location, purl, kev, epss, class, eligible, state, first_seen, last_seen, resolved_at, last_notified FROM findings`

func scanFindings(rows *sql.Rows) ([]*Finding, error) {
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		var f Finding
		var pt, ver, fix, vs, sev, title, url, loc, purl, cls, ra, ln sql.NullString
		var kev, elig sql.NullInt64
		var epss sql.NullFloat64
		if err := rows.Scan(&f.Key, &f.Unit, &f.VulnID, &f.Pkg, &pt, &ver, &fix, &vs, &sev, &title, &url, &loc,
			&purl, &kev, &epss, &cls, &elig, &f.State, &f.FirstSeen, &f.LastSeen, &ra, &ln); err != nil {
			return nil, err
		}
		f.PkgType, f.Version, f.Fixed, f.VStatus, f.Severity = pt.String, ver.String, fix.String, vs.String, sev.String
		f.Title, f.URL, f.Location, f.PURL, f.Class = title.String, url.String, loc.String, purl.String, cls.String
		f.ResolvedAt, f.LastNotified = ra.String, ln.String
		f.KEV, f.Eligible = int(kev.Int64), int(elig.Int64)
		if epss.Valid {
			v := epss.Float64
			f.EPSS = &v
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

// Query は findings を条件付きで読む (where は "state='open' AND ..." の形)。
func (s *Store) QueryFindings(where string, args ...any) ([]*Finding, error) {
	q := findingSelect
	if where != "" {
		q += " WHERE " + where
	}
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanFindings(rows)
}

func (s *Store) Get(key string) (*Finding, error) {
	l, err := s.QueryFindings("key=?", key)
	if err != nil || len(l) == 0 {
		return nil, err
	}
	return l[0], nil
}

func (s *Store) openKeys(unit string) ([]string, error) {
	rows, err := s.DB.Query("SELECT key FROM findings WHERE unit=? AND state='open'", unit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// SyncUnit は unit の今回の検出で状態を更新し、(新規 key, 解消 key) を返す。
// 一度解消したものが再び出た場合は新規として扱う (first_seen を付け直す)。
func (s *Store) SyncUnit(unit string, recs []*Finding, day string) (newKeys, resolved []string, err error) {
	before, err := s.openKeys(unit)
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	seen := map[string]bool{}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(findingCols)), ",")
	sets := make([]string, 0, len(findingCols)-1)
	for _, c := range findingCols[1:] {
		sets = append(sets, c+"=?")
	}
	for _, r := range recs {
		seen[r.Key] = true
		var state string
		e := tx.QueryRow("SELECT state FROM findings WHERE key=?", r.Key).Scan(&state)
		vals := r.colValues()
		switch {
		case e == sql.ErrNoRows:
			_, err = tx.Exec("INSERT INTO findings("+strings.Join(findingCols, ",")+", state, first_seen, last_seen)"+
				" VALUES ("+ph+", 'open', ?, ?)", append(vals, day, day)...)
			newKeys = append(newKeys, r.Key)
		case e != nil:
			return nil, nil, e
		default:
			reopened := state != "open"
			q := "UPDATE findings SET " + strings.Join(sets, ", ") + ", state='open', last_seen=?, resolved_at=NULL"
			args := append(append([]any{}, vals[1:]...), day)
			if reopened {
				q += ", first_seen=?, last_notified=NULL"
				args = append(args, day)
				newKeys = append(newKeys, r.Key)
			}
			_, err = tx.Exec(q+" WHERE key=?", append(args, r.Key)...)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	for _, k := range before {
		if !seen[k] {
			resolved = append(resolved, k)
			if _, err := tx.Exec("UPDATE findings SET state='resolved', resolved_at=? WHERE key=?", day, k); err != nil {
				return nil, nil, err
			}
		}
	}
	return newKeys, resolved, tx.Commit()
}

func (s *Store) ResolveUnit(unit, day string) ([]string, error) {
	keys, err := s.openKeys(unit)
	if err != nil {
		return nil, err
	}
	_, err = s.DB.Exec("UPDATE findings SET state='resolved', resolved_at=? WHERE unit=? AND state='open'", day, unit)
	return keys, err
}

func (s *Store) SetClass(key, cls string, eligible bool) error {
	e := 0
	if eligible {
		e = 1
	}
	_, err := s.DB.Exec("UPDATE findings SET class=?, eligible=? WHERE key=?", cls, e, key)
	return err
}

func (s *Store) MarkNotified(keys []string, ts string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, k := range keys {
		if _, err := tx.Exec("UPDATE findings SET last_notified=? WHERE key=?", ts, k); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- assessments

func (s *Store) Assessment(key string) (*Assessment, error) {
	var a Assessment
	var ts, eng, pr, ex, ra, ac sql.NullString
	err := s.DB.QueryRow("SELECT key, ts, engine, priority, exploitable, rationale, action FROM assessments WHERE key=?",
		key).Scan(&a.Key, &ts, &eng, &pr, &ex, &ra, &ac)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.TS, a.Engine, a.Priority, a.Exploitable, a.Rationale, a.Action = ts.String, eng.String, pr.String, ex.String, ra.String, ac.String
	return &a, nil
}

func (s *Store) SaveAssessment(key, ts, engine string, x map[string]any) error {
	ex := ""
	if v, ok := x["exploitable_here"]; ok && v != nil {
		ex = pyStr(v)
	}
	_, err := s.DB.Exec("INSERT OR REPLACE INTO assessments VALUES (?,?,?,?,?,?,?)",
		key, ts, engine, anyOrNil(x["priority"]), ex, anyOrNil(x["rationale"]), anyOrNil(x["action"]))
	return err
}

func anyOrNil(v any) any {
	if v == nil {
		return nil
	}
	return pyStr(v)
}

// pyStr は Python の str() に近い文字列化 (bool は True / False)。
func pyStr(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	}
	return str(v)
}

// ---- runs

func (s *Store) StartRun(ts string) (int64, error) {
	r, err := s.DB.Exec("INSERT INTO runs(started, result) VALUES (?, 'running')", ts)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) FinishRun(id int64, ts, result string, summary any) error {
	b, _ := json.Marshal(summary)
	_, err := s.DB.Exec("UPDATE runs SET finished=?, result=?, summary=? WHERE id=?", ts, result, string(b), id)
	return err
}

type RunRow struct {
	Started, Finished, Result, Summary string
}

func (s *Store) RecentRuns(n int) ([]RunRow, error) {
	rows, err := s.DB.Query("SELECT started, finished, result, summary FROM runs ORDER BY id DESC LIMIT ?", n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunRow
	for rows.Next() {
		var st, fi, re, su sql.NullString
		if err := rows.Scan(&st, &fi, &re, &su); err != nil {
			return nil, err
		}
		out = append(out, RunRow{st.String, fi.String, re.String, su.String})
	}
	return out, rows.Err()
}
