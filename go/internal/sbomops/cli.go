package sbomops

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const usage = `sbomops-go run          期限の来た対象の SBOM を作り、全 SBOM を照合して通知する (日次の本体)
sbomops-go status       対象ごとのスキャン状況と未解消の件数
sbomops-go targets      設定から展開したスキャン単位と、次回スキャンの要否
sbomops-go findings     検出の一覧 (既定: 通知条件を満たす未解消のもの)
sbomops-go assess       通知対象を AI (claude / codex) で評価して表示
sbomops-go test-notify  テスト通知を送る (--dry-run でペイロードを表示するだけ)
`

type globalOpts struct {
	config  string
	dataDir string
	verbose bool
}

// Main は Python 版 sbomops と同じサブコマンド・オプション・終了コードを持つ。
func Main(argv []string, stdout, stderr io.Writer) int {
	g := globalOpts{}
	fs := flag.NewFlagSet("sbomops-go", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&g.config, "c", "", "設定ファイル (既定: $SBOMOPS_CONFIG, /etc/sbomops/config.yaml)")
	fs.StringVar(&g.config, "config", "", "設定ファイル")
	fs.StringVar(&g.dataDir, "data-dir", "", "data_dir を上書き")
	fs.BoolVar(&g.verbose, "v", false, "詳細ログ")
	fs.BoolVar(&g.verbose, "verbose", false, "詳細ログ")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: sbomops-go [-c CONFIG] [--data-dir DIR] [-v] <command> [options]\n\n%s", usage)
	}
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	cmd, args := rest[0], rest[1:]

	cfg, err := LoadConfig(FindConfig(g.config))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if g.dataDir != "" {
		cfg.DataDir = g.dataDir
	}
	LoadEnvFile(cfg.SecretsFile)
	logfile := ""
	if cmd == "run" {
		logfile = filepath.Join(cfg.DataDir, "logs", "run-"+today()+".log")
	}
	if err := SetupLogging(g.verbose, logfile); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	syscall.Umask(0o077)

	var rc int
	switch cmd {
	case "run":
		rc, err = cmdRun(cfg, args, stderr)
	case "status":
		rc, err = cmdStatus(cfg, stdout)
	case "targets":
		rc, err = cmdTargets(cfg, g.verbose, stdout)
	case "findings":
		rc, err = cmdFindings(cfg, args, stdout, stderr)
	case "assess":
		rc, err = cmdAssess(cfg, args, stdout, stderr)
	case "test-notify":
		rc, err = cmdTestNotify(cfg, args, stderr)
	default:
		fmt.Fprintf(stderr, "不明なコマンド: %s\n\n", cmd)
		fs.Usage()
		return 2
	}
	if errors.Is(err, ErrLocked) {
		logError("%v", err)
		return 3
	}
	if err != nil {
		logError("%v", err)
		if rc == 0 {
			rc = 1
		}
	}
	return rc
}

func cmdRun(cfg *Config, args []string, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	only := fs.String("only", "", "この単位 / target id だけスキャンする (カンマ区切り)")
	force := fs.Bool("force", false, "周期に関係なくスキャンする")
	noScan := fs.Bool("no-scan", false, "スキャンせず、既存の SBOM の照合と通知だけ")
	noNotify := fs.Bool("no-notify", false, "通知しない (状態は更新する)")
	noAssess := fs.Bool("no-assess", false, "AI 評価をしない")
	dry := fs.Bool("dry-run", false, "通知を送らずペイロードを表示する (通知済みにしない)")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	o := RunOptions{Force: *force, NoScan: *noScan, NoNotify: *noNotify, DryRun: *dry}
	if *only != "" {
		o.Only = map[string]bool{}
		for _, x := range strings.Split(*only, ",") {
			o.Only[x] = true
		}
	}
	if *noAssess {
		f := false
		o.Assess = &f
	}
	return Run(cfg, o)
}

func cmdStatus(cfg *Config, w io.Writer) (int, error) {
	st, err := OpenDataStore(cfg)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	units, err := st.Units()
	if err != nil {
		return 1, err
	}
	type cnt struct{ active, notify, noise, suppressed, crit int }
	counts := map[string]*cnt{}
	rows, err := st.DB.Query("SELECT unit, class, eligible, severity, COUNT(*) n FROM findings " +
		"WHERE state='open' GROUP BY unit, class, eligible, severity")
	if err != nil {
		return 1, err
	}
	for rows.Next() {
		var unit string
		var cls, sev *string
		var elig *int
		var n int
		if err := rows.Scan(&unit, &cls, &elig, &sev, &n); err != nil {
			rows.Close()
			return 1, err
		}
		c := counts[unit]
		if c == nil {
			c = &cnt{}
			counts[unit] = c
		}
		k := "active"
		if cls != nil && *cls != "" {
			k, _, _ = strings.Cut(*cls, ":")
		}
		switch k {
		case "active":
			c.active += n
		case "noise":
			c.noise += n
		case "suppressed":
			c.suppressed += n
		}
		if elig != nil && *elig != 0 {
			c.notify += n
			if sev != nil && *sev == "CRITICAL" {
				c.crit += n
			}
		}
	}
	rows.Close()
	fmt.Fprintf(w, "%-38s %8s %-7s %6s %6s  %6s %4s %6s %6s %5s\n", "unit", "scan", "status", "sec", "RSS",
		"notify", "crit", "active", "noise", "supp")
	ids := make([]string, 0, len(units))
	for id := range units {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t := nowEpoch()
	for _, id := range ids {
		u := units[id]
		age := "-"
		if u.LastScanTS != 0 {
			age = FmtDuration(t - u.LastScanTS)
		}
		status := u.LastScanStatus
		if status == "" {
			status = "-"
		}
		c := counts[id]
		if c == nil {
			c = &cnt{}
		}
		fmt.Fprintf(w, "%-38s %8s %-7s %6d %5dM  %6d %4d %6d %6d %5d\n", truncRunes(id, 38), age, status,
			int64(u.LastScanSec), u.LastScanRSS>>20, c.notify, c.crit, c.active, c.noise, c.suppressed)
	}
	runs, _ := st.RecentRuns(5)
	fmt.Fprintln(w, "\n直近の run:")
	for _, r := range runs {
		fmt.Fprintf(w, "  %s  %-13s %s\n", r.Started, r.Result, r.Summary)
	}
	db := st.GetMetaString("trivy_db_updated_at")
	osfp := st.GetMetaString("os_fingerprint")
	fmt.Fprintf(w, "\ntrivy DB: %s  OS: %s\n", noneIfEmpty(db), noneIfEmpty(osfp))
	return 0, nil
}

func noneIfEmpty(s string) string {
	if s == "" {
		return "None"
	}
	return s
}

func cmdTargets(cfg *Config, verbose bool, w io.Writer) (int, error) {
	units, failed := ExpandTargets(cfg, true, nil)
	st, err := OpenDataStore(cfg)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	state, err := st.Units()
	if err != nil {
		return 1, err
	}
	due := map[string]bool{}
	for _, u := range Due(units, state, nowEpoch(), false) {
		due[u.ID] = true
	}
	for _, u := range units {
		mark := " "
		if due[u.ID] {
			mark = "*"
		}
		fmt.Fprintf(w, "%s %-40s %-12s every=%-5s %s\n", mark, u.ID, u.Type, FmtDuration(float64(u.Every)), u.Source)
		if verbose {
			fmt.Fprintf(w, "      syft args: %s\n", strings.Join(u.SyftArgs, " "))
		}
	}
	if len(failed) > 0 {
		var l []string
		for k := range failed {
			l = append(l, k)
		}
		sort.Strings(l)
		fmt.Fprintf(w, "展開に失敗: %s\n", strings.Join(l, ", "))
	}
	fmt.Fprintln(w, "(* = 次回の run でスキャンする)")
	return 0, nil
}

func cmdFindings(cfg *Config, args []string, w, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(stderr)
	all := fs.Bool("all", false, "ノイズ・受容・通知条件外も含める")
	unit := fs.String("unit", "", "unit で絞り込む (* 可)")
	limit := fs.Int("limit", 0, "表示件数")
	asJSON := fs.Bool("json", false, "JSON で出す")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	st, err := OpenDataStore(cfg)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	where := []string{"state='open'"}
	if !*all {
		where = append(where, "eligible=1 AND class='active'")
	}
	var qargs []any
	if *unit != "" {
		where = append(where, "unit LIKE ?")
		qargs = append(qargs, strings.ReplaceAll(*unit, "*", "%"))
	}
	rows, err := st.QueryFindings(strings.Join(where, " AND "), qargs...)
	if err != nil {
		return 1, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return sortLess(rows[i], rows[j], nil) })
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		if rows == nil {
			rows = []*Finding{}
		}
		return 0, enc.Encode(rows)
	}
	for i, r := range rows {
		if *limit > 0 && i >= *limit {
			break
		}
		tg := ""
		if r.KEV != 0 {
			tg += "KEV "
		}
		if r.EPSS != nil && *r.EPSS != 0 {
			tg += "EPSS=" + pyFixed2(*r.EPSS) + " "
		}
		fixed := r.Fixed
		if fixed == "" {
			fixed = "-"
		}
		cls := ""
		if *all {
			cls = r.Class
		}
		fmt.Fprintf(w, "%-8s %-20s %-30s %-20s → %-20s %s%s %s\n", r.Severity, r.VulnID, truncRunes(r.Pkg, 30),
			truncRunes(r.Version, 20), truncRunes(fixed, 20), tg, r.Unit, cls)
	}
	fmt.Fprintf(w, "計 %d 件\n", len(rows))
	return 0, nil
}

func cmdAssess(cfg *Config, args []string, w, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	fs.SetOutput(stderr)
	limit := fs.Int("limit", -1, "評価する件数 (既定: assess.max_per_run)")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	st, err := OpenDataStore(cfg)
	if err != nil {
		return 1, err
	}
	defer st.Close()
	rows, err := st.QueryFindings("state='open' AND eligible=1 AND class='active'")
	if err != nil {
		return 1, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return sortLess(rows[i], rows[j], nil) })
	res, err := RunAssess(cfg, st, rows, *limit)
	if err != nil {
		return 1, err
	}
	for _, r := range rows {
		if x := res[r.Key]; x != nil {
			fmt.Fprintf(w, "%s %s %s %s (%s)\n   悪用: %s  %s\n   対処: %s\n", x.Priority, r.VulnID, r.Pkg, r.Version,
				r.Unit, x.Exploitable, x.Rationale, x.Action)
		}
	}
	return 0, nil
}

func cmdTestNotify(cfg *Config, args []string, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("test-notify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dry := fs.Bool("dry-run", false, "ペイロードを表示するだけ")
	if err := fs.Parse(args); err != nil {
		return 2, nil
	}
	ep := 0.02
	d := time.Now().Format("2006-01-02")
	sample := &Finding{Key: "test", Unit: "os", VulnID: "CVE-0000-0000", Pkg: "example", PkgType: "ubuntu",
		Version: "1.0", Fixed: "1.1", VStatus: "fixed", Severity: "HIGH", Title: "sbomops のテスト通知",
		EPSS: &ep, FirstSeen: d}
	rp := &Report{Host: cfg.HostLabel, Date: d, Items: []Item{{sample, "new"}}, Warnings: []string{"これはテスト通知です"}}
	ns := buildNotifiers(cfg)
	if len(ns) == 0 {
		if !*dry {
			fmt.Fprintln(stderr, "有効な通知先がありません (notify.slack.enabled: true を設定)")
			return 1, nil
		}
		ns = []Notifier{&SlackNotifier{Cfg: cfg.Notify.Slack, Policy: cfg.Notify.Policy}}
	}
	for _, n := range ns {
		if err := n.Send(rp, *dry); err != nil {
			return 1, err
		}
		msg := "送信しました"
		if *dry {
			msg = "表示のみ"
		}
		fmt.Fprintf(stderr, "%s: %s\n", n.Name(), msg)
	}
	return 0, nil
}
