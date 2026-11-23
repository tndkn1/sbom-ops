package sbomops

// 日次の流れ: 期限の来た対象の SBOM 作成 → trivy DB 更新 → 全 SBOM の照合 → 分類 → 通知

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ErrLocked は別の sbomops (Python 版を含む) が同じ data_dir で実行中。
var ErrLocked = errors.New("別の sbomops が実行中")

func lockDataDir(dataDir string) (*os.File, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dataDir, ".lock"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrLocked
	}
	return f, nil
}

func OpenDataStore(cfg *Config) (*Store, error) {
	return OpenStore(filepath.Join(cfg.DataDir, "state.db"))
}

func newStep(t0, t1 float64, ok bool) *Step { return &Step{Start: t0, End: t1, Sec: t1 - t0, OK: ok} }

type timingMap struct {
	order []string
	m     map[string]*Timing
}

func newTimingMap() *timingMap { return &timingMap{m: map[string]*Timing{}} }

func (tm *timingMap) get(uid string) *Timing {
	if t, ok := tm.m[uid]; ok {
		return t
	}
	t := &Timing{Unit: uid}
	tm.m[uid] = t
	tm.order = append(tm.order, uid)
	return t
}

func sp(s string) *string { return &s }

func errText(err error, n int) string { return truncRunes(err.Error(), n) }

func scanPhase(cfg *Config, st *Store, units []Unit, only map[string]bool, force bool, warnings *[]string,
	tm *timingMap, skipped *[]Skip) error {
	data := cfg.DataDir
	state, err := st.Units()
	if err != nil {
		return err
	}
	if len(only) > 0 {
		var sel []Unit
		for _, u := range units {
			if only[u.ID] || only[u.Group] {
				sel = append(sel, u)
			} else {
				tm.get(u.ID).SyftSkip = sp("--only の対象外")
			}
		}
		units = sel
	}
	todo := Due(units, state, nowEpoch(), force)
	inTodo := map[string]bool{}
	for _, u := range todo {
		inTodo[u.ID] = true
	}
	for _, u := range units {
		if !inTodo[u.ID] {
			s := "周期内"
			if us := state[u.ID]; us != nil && us.LastScanTS != 0 {
				s += " (前回 " + time.Unix(int64(us.LastScanTS), 0).Format("01/02") + ")"
			}
			tm.get(u.ID).SyftSkip = sp(s)
		}
	}
	budget := MustDuration(cfg.Run.ScanBudget)
	start := time.Now()
	logInfo("scan: %d / %d 単位が対象", len(todo), len(units))
	var deferred []string
	for _, u := range todo {
		if budget > 0 && time.Since(start).Seconds() > float64(budget) {
			deferred = append(deferred, u.ID)
			tm.get(u.ID).SyftSkip = sp("時間切れで次回")
			*skipped = append(*skipped, Skip{u.ID, "scan_budget 超過で次回に回した"})
			continue
		}
		t0 := nowEpoch()
		path, r, err := ScanUnit(cfg, u, data)
		if err == nil {
			tm.get(u.ID).Syft = newStep(t0, nowEpoch(), true)
			err = st.UpsertUnit(u.ID, map[string]any{"sbom_path": path, "digest": u.Digest, "last_scan_ts": nowEpoch(),
				"last_scan_status": "ok", "last_scan_error": nil, "last_scan_sec": r.Elapsed, "last_scan_rss": r.PeakRSS})
			if err != nil {
				return err
			}
			continue
		}
		logError("scan %s 失敗: %v", u.ID, err)
		tm.get(u.ID).Syft = newStep(t0, nowEpoch(), false)
		if e := st.UpsertUnit(u.ID, map[string]any{"last_scan_status": "failed",
			"last_scan_error": errText(err, 500)}); e != nil {
			return e
		}
		*warnings = append(*warnings, fmt.Sprintf("スキャン失敗: %s: %s", u.ID, errText(err, 200)))
	}
	if len(deferred) > 0 {
		logWarn("scan_budget を超えたため次回に回す: %s", strings.Join(deferred, ", "))
		head := deferred
		if len(head) > 5 {
			head = head[:5]
		}
		*warnings = append(*warnings, fmt.Sprintf("時間切れで次回に回したスキャン %d 件: %s", len(deferred),
			strings.Join(head, ", ")))
	}
	return nil
}

// matchPhase は全単位を照合して状態 DB を更新し、(今回解消した key, 照合できた unit) を返す。
func matchPhase(cfg *Config, st *Store, units []Unit, failedGroups map[string]bool, warnings *[]string,
	day string, tm *timingMap, skipped *[]Skip) ([]string, map[string]bool, error) {
	data := cfg.DataDir
	if err := UpdateTrivyDB(cfg, data); err != nil {
		if dbs, _ := filepath.Glob(filepath.Join(data, "trivy-cache", "db", "*.db")); len(dbs) == 0 {
			return nil, nil, err
		}
		*warnings = append(*warnings, "trivy DB を更新できず、前回の DB で照合: "+errText(err, 200))
	}
	upd := TrivyDBUpdatedAt(cfg, data)
	if upd != "" {
		if t, ok := ParseISO(upd); ok {
			lim := MustDuration(cfg.Trivy.DBMaxAge)
			if lim == 0 {
				lim = 3 * 86400
			}
			if Now().Sub(t).Seconds() > float64(lim) {
				*warnings = append(*warnings, fmt.Sprintf("trivy DB が古い (%s)", upd))
			}
		}
		st.SetMeta("trivy_db_updated_at", upd)
	} else {
		st.SetMeta("trivy_db_updated_at", nil)
	}

	enr := NewEnricher(cfg, data)
	*warnings = append(*warnings, enr.Warnings...)
	cls, err := NewClassifier(cfg, day)
	if err != nil {
		return nil, nil, err
	}
	pol := cfg.Notify.Policy
	state, err := st.Units()
	if err != nil {
		return nil, nil, err
	}
	ids := map[string]bool{}
	for _, u := range units {
		ids[u.ID] = true
	}
	var resolvedAll []string
	matched := map[string]bool{}
	for _, u := range units {
		s := state[u.ID]
		if s == nil || s.SbomPath == "" || !exists(s.SbomPath) {
			*skipped = append(*skipped, Skip{u.ID, "SBOM がないため照合せず"})
			continue
		}
		t0 := nowEpoch()
		out, err := MatchUnit(cfg, u.ID, s.SbomPath, data, day)
		var recs []*Finding
		if err == nil {
			tm.get(u.ID).Trivy = newStep(t0, nowEpoch(), true)
			recs, err = Normalize(u.ID, u.Root, out, s.SbomPath)
		} else {
			tm.get(u.ID).Trivy = newStep(t0, nowEpoch(), false)
		}
		if err != nil {
			logError("match %s 失敗: %v", u.ID, err)
			st.UpsertUnit(u.ID, map[string]any{"last_match_status": "failed"})
			*warnings = append(*warnings, fmt.Sprintf("照合失敗: %s: %s", u.ID, errText(err, 200)))
			continue
		}
		for _, r := range recs {
			enr.Apply(r)
		}
		cls.Prepare(recs, u.Type)
		newKeys, resolved, err := st.SyncUnit(u.ID, recs, day)
		if err != nil {
			return nil, nil, err
		}
		resolvedAll = append(resolvedAll, resolved...)
		for _, r := range recs {
			c := cls.Classify(r, u.Type)
			row, err := st.Get(r.Key)
			if err != nil {
				return nil, nil, err
			}
			if err := st.SetClass(r.Key, c, c == "active" && row != nil && Eligible(row, pol)); err != nil {
				return nil, nil, err
			}
		}
		if err := st.UpsertUnit(u.ID, map[string]any{"grp": u.Group, "type": u.Type, "source": u.Source,
			"root": u.Root, "every": u.Every, "last_match_ts": nowEpoch(), "last_match_status": "ok"}); err != nil {
			return nil, nil, err
		}
		matched[u.ID] = true
		logInfo("match %s: %d 件 (新規 %d, 解消 %d)", u.ID, len(recs), len(newKeys), len(resolved))
	}

	// 設定から消えた単位 (コンテナ停止・ディレクトリ削除など) の検出は解消扱いにする
	uids := make([]string, 0, len(state))
	for uid := range state {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		grp := state[uid].Grp
		if grp == "" {
			grp, _, _ = strings.Cut(uid, ":")
		}
		if ids[uid] || failedGroups[grp] {
			continue
		}
		gone, err := st.ResolveUnit(uid, day)
		if err != nil {
			return nil, nil, err
		}
		if len(gone) > 0 {
			logInfo("対象から外れた %s の %d 件を解消扱いにする", uid, len(gone))
			resolvedAll = append(resolvedAll, gone...)
		}
		st.DeleteUnit(uid)
	}
	if len(cls.ExpiredAccepts) > 0 {
		*warnings = append(*warnings, fmt.Sprintf("受容期限が切れた検出 %d 件 (通常の通知対象に戻した)",
			len(uniqSorted(cls.ExpiredAccepts))))
	}
	return resolvedAll, matched, nil
}

func staleWarnings(cfg *Config, st *Store, units []Unit) []string {
	var out []string
	fac := cfg.Run.StaleFactor
	state, _ := st.Units()
	t := nowEpoch()
	for _, u := range units {
		if s := state[u.ID]; s != nil && s.LastScanTS != 0 && t-s.LastScanTS > float64(u.Every)*fac {
			out = append(out, fmt.Sprintf("SBOM が古い: %s (%s 前)", u.ID, FmtDuration(t-s.LastScanTS)))
		}
	}
	return out
}

func buildReport(cfg *Config, st *Store, resolvedKeys, warnings []string, day string) (*Report, error) {
	pol := cfg.Notify.Policy
	t := Now()
	rows, err := st.QueryFindings("state='open' AND eligible=1 AND class='active'")
	if err != nil {
		return nil, err
	}
	var items []Item
	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Severity]++
		if k := ShouldNotify(r, pol, t); k != "" {
			items = append(items, Item{r, k})
		}
	}
	var resolved []*Finding
	if pol.ReportResolved && len(resolvedKeys) > 0 {
		for _, k := range uniqSorted(resolvedKeys) {
			r, err := st.Get(k)
			if err != nil {
				return nil, err
			}
			if r != nil && r.LastNotified != "" {
				resolved = append(resolved, r)
			}
		}
	}
	rp := &Report{Host: cfg.HostLabel, Date: day, Items: items, Resolved: resolved, OpenCounts: counts,
		Assess: map[string]*Assessment{}}
	if pol.NotifyWarnings {
		rp.Warnings = warnings
	}
	if pol.NotifyRebootRequired {
		rp.Reboot = RebootRequired()
	}
	return rp, nil
}

// attachRunInfo は対象ごとの所要時間と調査対象外にしたものを通知に載せる (設定で切れる)。
func attachRunInfo(cfg *Config, rp *Report, units []Unit, tm *timingMap, skipped []Skip) {
	pol := cfg.Notify.Policy
	if pol.ReportTimings {
		inUnits := map[string]bool{}
		var order []string
		for _, u := range units {
			inUnits[u.ID] = true
			order = append(order, u.ID)
		}
		for _, k := range tm.order {
			if !inUnits[k] {
				order = append(order, k)
			}
		}
		for _, k := range order {
			if t, ok := tm.m[k]; ok {
				rp.Timings = append(rp.Timings, t)
			}
		}
	}
	if pol.ReportSkipped {
		seen := map[Skip]bool{}
		for _, s := range skipped {
			if !seen[s] {
				seen[s] = true
				rp.Skipped = append(rp.Skipped, s)
			}
		}
	}
}

func sendReport(cfg *Config, st *Store, rp *Report, dryRun bool) int {
	pol := cfg.Notify.Policy
	sort.SliceStable(rp.Items, func(i, j int) bool { return sortLess(rp.Items[i].Row, rp.Items[j].Row, rp.Assess) })
	sort.SliceStable(rp.Resolved, func(i, j int) bool { return sortLess(rp.Resolved[i], rp.Resolved[j], nil) })
	if rp.Empty() && bool(pol.QuietWhenEmpty) && !dryRun {
		logInfo("通知対象なし (quiet_when_empty のため送信しない)")
		return 0
	}
	ns := buildNotifiers(cfg)
	if len(ns) == 0 {
		logWarn("有効な通知先がない (notify.slack.enabled)")
		if dryRun {
			ns = []Notifier{&SlackNotifier{Cfg: cfg.Notify.Slack, Policy: pol}}
		}
	}
	errs := 0
	for _, n := range ns {
		if err := n.Send(rp, dryRun); err != nil {
			errs++
			logError("通知 %s 失敗: %v", n.Name(), err)
			continue
		}
		suffix := ""
		if dryRun {
			suffix = " (dry-run)"
		}
		logInfo("通知 %s: %d 件%s", n.Name(), len(rp.Items), suffix)
	}
	if !dryRun && len(ns) > 0 && errs < len(ns) {
		keys := make([]string, len(rp.Items))
		for i, it := range rp.Items {
			keys[i] = it.Row.Key
		}
		if err := st.MarkNotified(keys, ISO(Now())); err != nil {
			logError("通知済みにできない: %v", err)
		}
	}
	return errs
}

// RunRetention は古い照合結果 (results/<日付>/) と実行ログ (logs/run-<日付>.log) を消す。
func RunRetention(cfg *Config, day time.Time) {
	ret := cfg.Retention
	rdays := ret.ResultsDays
	ldays := rdays
	if ret.LogsDays != nil && *ret.LogsDays != 0 {
		ldays = *ret.LogsDays
	}
	limit := day.AddDate(0, 0, -rdays).Format("2006-01-02")
	ds, _ := filepath.Glob(filepath.Join(cfg.DataDir, "results", "????-??-??"))
	for _, d := range ds {
		if filepath.Base(d) < limit {
			os.RemoveAll(d)
		}
	}
	limit = day.AddDate(0, 0, -ldays).Format("2006-01-02")
	n := 0
	fs, _ := filepath.Glob(filepath.Join(cfg.DataDir, "logs", "run-????-??-??.log"))
	for _, f := range fs {
		if filepath.Base(f)[4:14] < limit {
			if err := os.Remove(f); err != nil {
				logWarn("ログを消せない: %s (%v)", f, err)
			} else {
				n++
			}
		}
	}
	if n > 0 {
		logInfo("retention: %d 日より古い実行ログ %d 件を削除", ldays, n)
	}
}

// RunOptions は run サブコマンドの指定。
type RunOptions struct {
	Only     map[string]bool
	Force    bool
	NoScan   bool
	NoNotify bool
	DryRun   bool
	Assess   *bool // nil なら設定 (assess.enabled) に従う
}

type runSummary struct {
	Units    int            `json:"units"`
	Matched  int            `json:"matched"`
	Notify   int            `json:"notify"`
	Resolved int            `json:"resolved"`
	Warnings int            `json:"warnings"`
	Open     map[string]int `json:"open"`
}

// Run は日次の本体。終了コード (0: 正常, 1: 通知失敗, 2: 失敗, 3: 実行中) を返す。
func Run(cfg *Config, o RunOptions) (int, error) {
	data := cfg.DataDir
	lk, err := lockDataDir(data)
	if err != nil {
		return 3, err
	}
	defer lk.Close()
	st, err := OpenDataStore(cfg)
	if err != nil {
		return 2, err
	}
	defer st.Close()
	day := today()
	rid, _ := st.StartRun(ISO(Now()))
	var warnings []string
	tm := newTimingMap()
	var skipped []Skip
	var units []Unit

	fail := func(e error) (int, error) {
		logError("run 失敗: %v", e)
		st.FinishRun(rid, ISO(Now()), "failed", map[string]string{"error": e.Error()})
		if !o.NoNotify {
			rp := &Report{Host: cfg.HostLabel, Date: day, Failed: truncRunes(e.Error(), 300), Warnings: warnings}
			attachRunInfo(cfg, rp, nil, tm, skipped)
			sendReport(cfg, st, rp, o.DryRun)
		}
		return 2, nil
	}

	LogHostSummary()
	fp := OSFingerprint()
	prev := st.GetMetaString("os_fingerprint")
	force := o.Force
	if prev != "" && prev != fp && cfg.Run.RescanOnOSChange {
		logWarn("OS が変わった (%s → %s)。全対象を作り直す", prev, fp)
		warnings = append(warnings, fmt.Sprintf("OS の変更を検知 (%s → %s)。全対象の SBOM を作り直した", prev, fp))
		force = true
	}
	units, failedGroups := ExpandTargets(cfg, true, &skipped)
	if len(units) == 0 {
		return fail(errors.New("スキャン対象がない (targets を設定してください)"))
	}
	if !o.NoScan {
		if err := scanPhase(cfg, st, units, o.Only, force, &warnings, tm, &skipped); err != nil {
			return fail(err)
		}
	} else {
		for _, u := range units {
			tm.get(u.ID).SyftSkip = sp("--no-scan")
		}
	}
	st.SetMeta("os_fingerprint", fp)
	resolved, matched, err := matchPhase(cfg, st, units, failedGroups, &warnings, day, tm, &skipped)
	if err != nil {
		return fail(err)
	}
	warnings = append(warnings, staleWarnings(cfg, st, units)...)
	rp, err := buildReport(cfg, st, resolved, warnings, day)
	if err != nil {
		return fail(err)
	}
	attachRunInfo(cfg, rp, units, tm, skipped)
	doAssess := bool(cfg.Assess.Enabled)
	if o.Assess != nil {
		doAssess = *o.Assess
	}
	if doAssess {
		rows := make([]*Finding, len(rp.Items))
		for i, it := range rp.Items {
			rows[i] = it.Row
		}
		if a, err := RunAssess(cfg, st, rows, -1); err != nil {
			logError("assess 失敗: %v", err)
			rp.Warnings = append(rp.Warnings, "AI 評価に失敗: "+errText(err, 200))
		} else {
			rp.Assess = a
		}
	}
	summary := runSummary{Units: len(units), Matched: len(matched), Notify: len(rp.Items),
		Resolved: len(rp.Resolved), Warnings: len(rp.Warnings), Open: rp.OpenCounts}
	errs := 0
	if !o.NoNotify {
		errs = sendReport(cfg, st, rp, o.DryRun)
	}
	RunRetention(cfg, time.Now())
	result := "ok"
	if errs > 0 {
		result = "notify_failed"
	} else if len(rp.Warnings) > 0 {
		result = "warn"
	}
	st.FinishRun(rid, ISO(Now()), result, summary)
	logInfo("完了 result=%s %+v", result, summary)
	if errs > 0 {
		return 1, nil
	}
	return 0, nil
}
