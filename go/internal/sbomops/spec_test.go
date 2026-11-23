package sbomops

// ../../../spec/ の共通テストデータを Go 版で実行する (Python 版は tests/test_spec.py が同じデータを使う)。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

var specDir = func() string {
	p, _ := filepath.Abs(filepath.Join("..", "..", "..", "spec"))
	return p
}()

func loadSpec(t *testing.T, rel string, out any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
}

func mergeAny(base, over map[string]any) map[string]any {
	if over == nil {
		return deepCopy(base).(map[string]any)
	}
	return merge(base, over)
}

func toJSONMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func fromMap(t *testing.T, m any, out any) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
}

func defaultPolicy(t *testing.T, over map[string]any) Policy {
	var p Policy
	base := defaults.Config["notify"].(map[string]any)["policy"].(map[string]any)
	fromMap(t, mergeAny(base, over), &p)
	return p
}

// ---------------------------------------------------------------- 既定値・スキーマ

func TestSpecDefaultsAndSchema(t *testing.T) {
	for _, pair := range [][2]string{{"defaults.json", "defaults.json"}, {"schema.sql", "schema.sql"}} {
		want, err := os.ReadFile(filepath.Join(specDir, pair[0]))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if string(want) != string(got) {
			t.Errorf("go/internal/sbomops/%s が spec/%s と違う (cp spec/%s go/internal/sbomops/ で更新)", pair[1], pair[0], pair[0])
		}
	}
}

// ---------------------------------------------------------------- util

func TestSpecUtil(t *testing.T) {
	var c map[string][][]any
	loadSpec(t, "cases/util.json", &c)
	for _, x := range c["parse_duration"] {
		got, err := ParseDuration(x[0])
		if x[1] == "error" {
			if err == nil {
				t.Errorf("ParseDuration(%v): エラーにならない", x[0])
			}
		} else if err != nil || float64(got) != x[1].(float64) {
			t.Errorf("ParseDuration(%v) = %v, %v; want %v", x[0], got, err, x[1])
		}
	}
	for _, x := range c["parse_size"] {
		got, err := ParseSize(x[0])
		if x[1] == "error" {
			if err == nil {
				t.Errorf("ParseSize(%v): エラーにならない", x[0])
			}
		} else if err != nil || float64(got) != x[1].(float64) {
			t.Errorf("ParseSize(%v) = %v, %v; want %v", x[0], got, err, x[1])
		}
	}
	for _, x := range c["fmt_duration"] {
		if got := FmtDuration(x[0].(float64)); got != x[1] {
			t.Errorf("FmtDuration(%v) = %q; want %q", x[0], got, x[1])
		}
	}
	for _, x := range c["safe_name"] {
		if got := SafeName(x[0].(string)); got != x[1] {
			t.Errorf("SafeName(%q) = %q; want %q", x[0], got, x[1])
		}
	}
	for _, x := range c["parse_iso"] {
		tm, ok := ParseISO(x[0].(string))
		if !ok || abs(epoch(tm)-x[1].(float64)) > 1e-5 {
			t.Errorf("ParseISO(%q) = %v; want %v", x[0], epoch(tm), x[1])
		}
	}
	for _, x := range c["fnmatch"] {
		if got := fnmatch(x[0].(string), x[1].(string)); got != x[2].(bool) {
			t.Errorf("fnmatch(%q, %q) = %v", x[0], x[1], got)
		}
	}
	for _, x := range c["excludes"] {
		var pats, want []string
		fromMap(t, x[1], &pats)
		fromMap(t, x[2], &want)
		if got := excludes(x[0].(string), pats); !reflect.DeepEqual(got, want) {
			t.Errorf("excludes(%q, %v) = %v; want %v", x[0], pats, got, want)
		}
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// ---------------------------------------------------------------- policy

type policySpec struct {
	BaseRow  map[string]any `json:"base_row"`
	Eligible []struct {
		Row    map[string]any `json:"row"`
		Policy map[string]any `json:"policy"`
		Want   bool           `json:"want"`
	} `json:"eligible"`
	ShouldNotify struct {
		Now   string `json:"now"`
		Cases []struct {
			Row    map[string]any `json:"row"`
			Policy map[string]any `json:"policy"`
			Want   *string        `json:"want"`
		} `json:"cases"`
	} `json:"should_notify"`
	Sort struct {
		Rows           []map[string]any  `json:"rows"`
		Want           []string          `json:"want"`
		Assess         map[string]string `json:"assess"`
		WantWithAssess []string          `json:"want_with_assess"`
	} `json:"sort"`
	Classify struct {
		RunningKernel string         `json:"running_kernel"`
		Noise         map[string]any `json:"noise"`
		Today         string         `json:"today"`
		Accepts       string         `json:"accepts"`
		Cases         []struct {
			Row     map[string]any `json:"row"`
			Type    string         `json:"type"`
			Want    string         `json:"want"`
			Expired bool           `json:"expired"`
		} `json:"cases"`
	} `json:"classify"`
}

func (p *policySpec) row(t *testing.T, over map[string]any) *Finding {
	var f Finding
	fromMap(t, mergeAny(p.BaseRow, over), &f)
	return &f
}

func TestSpecPolicy(t *testing.T) {
	var p policySpec
	loadSpec(t, "cases/policy.json", &p)
	for i, x := range p.Eligible {
		if got := Eligible(p.row(t, x.Row), defaultPolicy(t, x.Policy)); got != x.Want {
			t.Errorf("eligible[%d] %v %v = %v", i, x.Row, x.Policy, got)
		}
	}
	now, _ := ParseISO(p.ShouldNotify.Now)
	for i, x := range p.ShouldNotify.Cases {
		want := ""
		if x.Want != nil {
			want = *x.Want
		}
		if got := ShouldNotify(p.row(t, x.Row), defaultPolicy(t, x.Policy), now); got != want {
			t.Errorf("should_notify[%d] %v %v = %q; want %q", i, x.Row, x.Policy, got, want)
		}
	}
	sortIDs := func(asm map[string]*Assessment) []string {
		var rows []*Finding
		for _, r := range p.Sort.Rows {
			rows = append(rows, p.row(t, r))
		}
		sort.SliceStable(rows, func(i, j int) bool { return sortLess(rows[i], rows[j], asm) })
		var ids []string
		for _, r := range rows {
			ids = append(ids, r.VulnID)
		}
		return ids
	}
	if got := sortIDs(nil); !reflect.DeepEqual(got, p.Sort.Want) {
		t.Errorf("sort = %v; want %v", got, p.Sort.Want)
	}
	asm := map[string]*Assessment{}
	for k, v := range p.Sort.Assess {
		asm[k] = &Assessment{Key: k, Priority: v}
	}
	if got := sortIDs(asm); !reflect.DeepEqual(got, p.Sort.WantWithAssess) {
		t.Errorf("sort (assess) = %v; want %v", got, p.Sort.WantWithAssess)
	}

	c := p.Classify
	d := t.TempDir()
	acc := filepath.Join(d, "accepted.tsv")
	os.WriteFile(acc, []byte(c.Accepts), 0o644)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	fromMap(t, mergeAny(toJSONMap(t, cfg.Noise), c.Noise), &cfg.Noise)
	cfg.Notify.SuppressFile = acc
	old := runningKernel
	runningKernel = func() string { return c.RunningKernel }
	defer func() { runningKernel = old }()
	cls, err := NewClassifier(cfg, c.Today)
	if err != nil {
		t.Fatal(err)
	}
	for i, x := range c.Cases {
		cls.ExpiredAccepts = nil
		if got := cls.Classify(p.row(t, x.Row), x.Type); got != x.Want {
			t.Errorf("classify[%d] %v (%s) = %q; want %q", i, x.Row, x.Type, got, x.Want)
		}
		if (len(cls.ExpiredAccepts) > 0) != x.Expired {
			t.Errorf("classify[%d]: expired = %v", i, cls.ExpiredAccepts)
		}
	}
}

// ---------------------------------------------------------------- config

func lookupPath(v any, path string) (any, bool) {
	for _, k := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			var ok bool
			if v, ok = x[k]; !ok {
				return nil, false
			}
		case []any:
			var i int
			fmt.Sscan(k, &i)
			if i >= len(x) {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, true
}

func TestSpecConfig(t *testing.T) {
	var c struct {
		Cases []struct {
			Config        map[string]any `json:"config"`
			YAML          *string        `json:"yaml"`
			OK            bool           `json:"ok"`
			Want          map[string]any `json:"want"`
			ErrorsContain []string       `json:"errors_contain"`
		} `json:"cases"`
	}
	loadSpec(t, "cases/config.json", &c)
	for i, x := range c.Cases {
		p := filepath.Join(t.TempDir(), "c.json")
		b, _ := json.Marshal(x.Config)
		if x.YAML != nil {
			p, b = filepath.Join(t.TempDir(), "c.yaml"), []byte(*x.YAML)
		}
		os.WriteFile(p, b, 0o644)
		cfg, err := LoadConfig(p)
		if x.OK {
			if err != nil {
				t.Errorf("config[%d] %v: %v", i, x.Config, err)
				continue
			}
			m := toJSONMap(t, cfg)
			for path, want := range x.Want {
				got, ok := lookupPath(m, path)
				if !ok || !reflect.DeepEqual(got, want) {
					t.Errorf("config[%d] %s = %v; want %v", i, path, got, want)
				}
			}
			continue
		}
		if err == nil {
			t.Errorf("config[%d] %v: エラーにならない", i, x.Config)
			continue
		}
		for _, s := range x.ErrorsContain {
			if !strings.Contains(err.Error(), s) {
				t.Errorf("config[%d]: %q がない: %v", i, s, err)
			}
		}
	}
}

// ---------------------------------------------------------------- normalize

func TestSpecNormalize(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(specDir, "cases", "normalize", "*.json"))
	for _, f := range files {
		var c struct {
			Unit  string           `json:"unit"`
			Root  string           `json:"root"`
			SBOM  any              `json:"sbom"`
			Trivy any              `json:"trivy"`
			Want  []map[string]any `json:"want"`
		}
		loadSpec(t, strings.TrimPrefix(f, specDir+"/"), &c)
		d := t.TempDir()
		sp, tp := filepath.Join(d, "s.json"), filepath.Join(d, "t.json")
		b, _ := json.Marshal(c.SBOM)
		os.WriteFile(sp, b, 0o644)
		b, _ = json.Marshal(c.Trivy)
		os.WriteFile(tp, b, 0o644)
		recs, err := Normalize(c.Unit, c.Root, tp, sp)
		if err != nil {
			t.Fatal(err)
		}
		var got []map[string]any
		for _, r := range recs {
			aliases := []any{}
			for _, a := range r.Aliases {
				aliases = append(aliases, a)
			}
			got = append(got, map[string]any{"key": r.Key, "unit": r.Unit, "vuln_id": r.VulnID, "pkg": r.Pkg,
				"pkg_type": r.PkgType, "version": r.Version, "fixed": r.Fixed, "vstatus": r.VStatus,
				"severity": r.Severity, "title": r.Title, "url": r.URL, "location": r.Location, "purl": r.PURL,
				"_aliases": aliases})
		}
		sort.Slice(got, func(i, j int) bool { return got[i]["key"].(string) < got[j]["key"].(string) })
		if !reflect.DeepEqual(toAny(t, got), toAny(t, c.Want)) {
			gb, _ := json.MarshalIndent(got, "", " ")
			t.Errorf("%s: 結果が違う:\n%s", filepath.Base(f), gb)
		}
	}
}

func toAny(t *testing.T, v any) any {
	b, _ := json.Marshal(v)
	var out any
	json.Unmarshal(b, &out)
	return out
}

// ---------------------------------------------------------------- slack

type slackCase struct {
	Slack   map[string]any `json:"slack"`
	Policy  map[string]any `json:"policy"`
	BaseRow map[string]any `json:"base_row"`
	Report  struct {
		Host  string `json:"host"`
		Date  string `json:"date"`
		Items []struct {
			Row  map[string]any `json:"row"`
			Kind string         `json:"kind"`
		} `json:"items"`
		RepeatItems *struct {
			Count int            `json:"count"`
			Kind  string         `json:"kind"`
			Row   map[string]any `json:"row"`
		} `json:"repeat_items"`
		Resolved   []map[string]any       `json:"resolved"`
		Warnings   []string               `json:"warnings"`
		Reboot     string                 `json:"reboot"`
		OpenCounts map[string]int         `json:"open_counts"`
		Assess     map[string]*Assessment `json:"assess"`
		Failed     string                 `json:"failed"`
		Timings    []*Timing              `json:"timings"`
		Skipped    [][2]string            `json:"skipped"`
	} `json:"report"`
	Want any `json:"want"`
}

func substAny(v any, i int) any {
	switch x := v.(type) {
	case string:
		return strings.NewReplacer("{i}", fmt.Sprint(i), "{i%7}", fmt.Sprint(i%7)).Replace(x)
	case map[string]any:
		m := map[string]any{}
		for k, vv := range x {
			m[k] = substAny(vv, i)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for j, vv := range x {
			l[j] = substAny(vv, i)
		}
		return l
	}
	return v
}

func (c *slackCase) report(t *testing.T) *Report {
	r := c.Report
	row := func(over map[string]any) *Finding {
		var f Finding
		fromMap(t, mergeAny(c.BaseRow, over), &f)
		return &f
	}
	rp := &Report{Host: r.Host, Date: r.Date, Warnings: r.Warnings, Reboot: r.Reboot, OpenCounts: r.OpenCounts,
		Assess: r.Assess, Failed: r.Failed, Timings: r.Timings}
	for _, x := range r.Items {
		rp.Items = append(rp.Items, Item{row(x.Row), x.Kind})
	}
	if r.RepeatItems != nil {
		for i := 0; i < r.RepeatItems.Count; i++ {
			rp.Items = append(rp.Items, Item{row(substAny(r.RepeatItems.Row, i).(map[string]any)), r.RepeatItems.Kind})
		}
	}
	for _, x := range r.Resolved {
		rp.Resolved = append(rp.Resolved, row(x))
	}
	for _, s := range r.Skipped {
		rp.Skipped = append(rp.Skipped, Skip{s[0], s[1]})
	}
	return rp
}

func TestSpecSlack(t *testing.T) {
	old := time.Local
	time.Local = time.UTC
	defer func() { time.Local = old }()
	files, _ := filepath.Glob(filepath.Join(specDir, "cases", "slack", "*.json"))
	if len(files) == 0 {
		t.Fatal("spec/cases/slack がない")
	}
	for _, f := range files {
		var c slackCase
		loadSpec(t, strings.TrimPrefix(f, specDir+"/"), &c)
		var sc SlackCfg
		fromMap(t, mergeAny(defaults.Config["notify"].(map[string]any)["slack"].(map[string]any), c.Slack), &sc)
		n := &SlackNotifier{Cfg: sc, Policy: defaultPolicy(t, c.Policy)}
		got := toAny(t, n.Render(c.report(t)))
		if !reflect.DeepEqual(got, c.Want) {
			diffPayload(t, filepath.Base(f), got, c.Want)
		}
	}
}

func diffPayload(t *testing.T, name string, got, want any) {
	gb, _ := json.MarshalIndent(got, "", " ")
	wb, _ := json.MarshalIndent(want, "", " ")
	gl, wl := strings.Split(string(gb), "\n"), strings.Split(string(wb), "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g != w {
			t.Errorf("%s: %d 行目が違う\n got: %s\nwant: %s", name, i+1, g, w)
			return
		}
	}
}

// ---------------------------------------------------------------- シナリオ

type scenario struct {
	Config map[string]any   `json:"config"`
	Policy map[string]any   `json:"policy"`
	Steps  []map[string]any `json:"steps"`
}

func substMap(v any, m [][2]string) any {
	switch x := v.(type) {
	case string:
		for _, kv := range m {
			x = strings.ReplaceAll(x, kv[0], kv[1])
		}
		return x
	case map[string]any:
		out := map[string]any{}
		for k, vv := range x {
			out[k] = substMap(vv, m)
		}
		return out
	case []any:
		l := make([]any, len(x))
		for i, vv := range x {
			l[i] = substMap(vv, m)
		}
		return l
	}
	return v
}

type capture struct{ sent *[]*Report }

func (c capture) Name() string { return "slack" }
func (c capture) Send(rp *Report, _ bool) error {
	*c.sent = append(*c.sent, rp)
	return nil
}

func TestSpecScenarios(t *testing.T) {
	var base map[string]any
	loadSpec(t, "scenarios/_base.json", &base)
	files, _ := filepath.Glob(filepath.Join(specDir, "scenarios", "*.json"))
	n := 0
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), "_") {
			continue
		}
		n++
		var sc scenario
		loadSpec(t, strings.TrimPrefix(f, specDir+"/"), &sc)
		t.Run(filepath.Base(f), func(t *testing.T) { runScenario(t, base, sc) })
	}
	if n == 0 {
		t.Fatal("spec/scenarios にシナリオがない")
	}
}

func runScenario(t *testing.T, base map[string]any, sc scenario) {
	d := t.TempDir()
	state := filepath.Join(d, "fake-state")
	os.MkdirAll(state, 0o755)
	os.MkdirAll(filepath.Join(d, "app"), 0o755)
	t.Setenv("FAKE_STATE", state)
	m := [][2]string{{"{dirname}", SafeName(strings.Trim(d, "/"))}, {"{dir}", d}, {"{fake}", filepath.Join(specDir, "fake")}}
	now := time.Now()
	for n := 30; n >= 0; n-- {
		m = append(m, [2]string{fmt.Sprintf("{today+%d}", n), now.AddDate(0, 0, n).Format("2006-01-02")},
			[2]string{fmt.Sprintf("{today-%d}", n), now.AddDate(0, 0, -n).Format("2006-01-02")})
	}
	user := mergeAny(base, sc.Config)
	notify := user["notify"].(map[string]any)
	user["notify"] = mergeAny(notify, map[string]any{"policy": orEmpty(sc.Policy)})
	user = substMap(user, m).(map[string]any)
	cp := filepath.Join(d, "cfg.json")
	b, _ := json.Marshal(user)
	os.WriteFile(cp, b, 0o644)
	cfg, err := LoadConfig(cp)
	if err != nil {
		t.Fatal(err)
	}
	var sent []*Report
	oldB := buildNotifiers
	buildNotifiers = func(*Config) []Notifier { return []Notifier{capture{&sent}} }
	defer func() { buildNotifiers = oldB }()

	for i, raw := range sc.Steps {
		step := substMap(raw, m).(map[string]any)
		ctx := fmt.Sprintf("step %d: %v", i, step)
		switch {
		case step["set_version"] != nil:
			os.WriteFile(filepath.Join(state, "version"), []byte(step["set_version"].(string)), 0o644)
		case step["write_accepted"] != nil:
			os.WriteFile(cfg.Notify.SuppressFile, []byte(step["write_accepted"].(string)), 0o644)
		case step["mkdir"] != nil:
			for _, x := range step["mkdir"].([]any) {
				os.MkdirAll(filepath.Join(d, x.(string)), 0o755)
			}
		case step["age_notifications"] != nil:
			st, err := OpenDataStore(cfg)
			if err != nil {
				t.Fatal(err)
			}
			days := int(step["age_notifications"].(float64))
			ts := ISO(Now().AddDate(0, 0, -days))
			if _, err := st.DB.Exec("UPDATE findings SET last_notified=? WHERE last_notified IS NOT NULL", ts); err != nil {
				t.Fatal(err)
			}
			st.Close()
		case step["run"] != nil:
			r := step["run"].(map[string]any)
			before := len(sent)
			rc, err := Run(cfg, RunOptions{Force: r["force"] == true, NoScan: r["no_scan"] == true})
			if err != nil {
				t.Fatalf("%s: %v", ctx, err)
			}
			checkExpect(t, ctx, step["expect"].(map[string]any), rc, sent[before:])
		default:
			t.Fatalf("不明な step: %v", step)
		}
	}
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func checkExpect(t *testing.T, ctx string, e map[string]any, rc int, sent []*Report) {
	t.Helper()
	if v, ok := e["rc"]; ok && float64(rc) != v.(float64) {
		t.Errorf("%s: rc = %d", ctx, rc)
	}
	if v, ok := e["sent"]; ok && (len(sent) > 0) != v.(bool) {
		t.Errorf("%s: sent = %d", ctx, len(sent))
	}
	if len(sent) == 0 {
		return
	}
	rp := sent[len(sent)-1]
	if v, ok := e["items"]; ok {
		got := []any{}
		for _, it := range rp.Items {
			got = append(got, []any{it.Row.VulnID, it.Kind})
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("%s: items = %v", ctx, got)
		}
	}
	if v, ok := e["resolved"]; ok {
		got := []any{}
		for _, r := range rp.Resolved {
			got = append(got, r.VulnID)
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("%s: resolved = %v", ctx, got)
		}
	}
	if v, ok := e["skipped"]; ok {
		for _, s := range v.([]any) {
			p := s.([]any)
			want := Skip{p[0].(string), p[1].(string)}
			found := false
			for _, x := range rp.Skipped {
				found = found || x == want
			}
			if !found {
				t.Errorf("%s: skipped に %v がない: %v", ctx, want, rp.Skipped)
			}
		}
	}
	if v, ok := e["skipped_exact"]; ok && len(rp.Skipped) != len(v.([]any)) {
		t.Errorf("%s: skipped = %v", ctx, rp.Skipped)
	}
	if v, ok := e["warnings_contain"]; ok {
		for _, s := range v.([]any) {
			found := false
			for _, w := range rp.Warnings {
				found = found || strings.Contains(w, s.(string))
			}
			if !found {
				t.Errorf("%s: 警告に %q がない: %v", ctx, s, rp.Warnings)
			}
		}
	}
	if v, ok := e["timings"]; ok {
		want := v.([]any)
		if len(rp.Timings) != len(want) {
			t.Errorf("%s: timings の数 %d", ctx, len(rp.Timings))
			return
		}
		stat := func(s *Step) any {
			if s == nil {
				return nil
			}
			if s.OK {
				return "ok"
			}
			return "failed"
		}
		for i, w := range want {
			wm := w.(map[string]any)
			g := rp.Timings[i]
			if g.Unit != wm["unit"] || stat(g.Syft) != wm["syft"] || stat(g.Trivy) != wm["trivy"] {
				t.Errorf("%s: timings[%d] = %s syft=%v trivy=%v; want %v", ctx, i, g.Unit, stat(g.Syft), stat(g.Trivy), wm)
			}
			if p, ok := wm["syft_skip_prefix"]; ok {
				if g.SyftSkip == nil || !strings.HasPrefix(*g.SyftSkip, p.(string)) {
					t.Errorf("%s: timings[%d].syft_skip = %v", ctx, i, g.SyftSkip)
				}
			}
		}
	}
}
