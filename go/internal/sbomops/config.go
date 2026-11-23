package sbomops

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaults.json / schema.sql は ../../../spec/ の写し (spec_test.go が一致を確かめる)。
//
//go:embed defaults.json
var defaultsJSON []byte

type specDefaults struct {
	Config         map[string]any `json:"config"`
	Target         map[string]any `json:"target"`
	Severities     []string       `json:"severities"`
	SystemExcludes []string       `json:"system_excludes"`
	SearchPaths    []string       `json:"search_paths"`
}

var defaults = func() specDefaults {
	var d specDefaults
	if err := json.Unmarshal(defaultsJSON, &d); err != nil {
		panic(err)
	}
	return d
}()

var (
	Severities     = defaults.Severities
	SystemExcludes = defaults.SystemExcludes
	SearchPaths    = defaults.SearchPaths
	targetTypes    = []string{"os-packages", "dir", "image", "running-images"}
)

// ---------------------------------------------------------------- 型

type Config struct {
	HostLabel   string    `json:"host_label"`
	DataDir     string    `json:"data_dir"`
	SecretsFile string    `json:"secrets_file"`
	Tools       Tools     `json:"tools"`
	Resources   Resources `json:"resources"`
	Run         RunCfg    `json:"run"`
	Targets     []Target  `json:"targets"`
	Trivy       TrivyCfg  `json:"trivy"`
	Enrich      EnrichCfg `json:"enrich"`
	Noise       NoiseCfg  `json:"noise"`
	Notify      NotifyCfg `json:"notify"`
	Assess      AssessCfg `json:"assess"`
	Retention   Retention `json:"retention"`
	Path        string    `json:"-"`
}

type Tools struct {
	Syft  string `json:"syft"`
	Trivy string `json:"trivy"`
}

type Resources struct {
	Nice            int      `json:"nice"`
	IoniceClass     string   `json:"ionice_class"`
	MemMax          any      `json:"mem_max"`
	SyftParallelism int      `json:"syft_parallelism"`
	Wrap            []string `json:"wrap"`
}

type RunCfg struct {
	ScanBudget       any     `json:"scan_budget"`
	StaleFactor      float64 `json:"stale_factor"`
	RescanOnOSChange PyBool  `json:"rescan_on_os_change"`
}

type Target struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Path       any      `json:"path"`
	PathGlob   any      `json:"path_glob"`
	Skip       []string `json:"skip"`
	Ref        string   `json:"ref"`
	Runtime    string   `json:"runtime"`
	Every      any      `json:"every"`
	Enabled    PyBool   `json:"enabled"`
	Exclude    []string `json:"exclude"`
	SyftArgs   []string `json:"syft_args"`
	MaxRuntime any      `json:"max_runtime"`
	MemMax     any      `json:"mem_max"`
}

type TrivyCfg struct {
	DBRepository []string `json:"db_repository"`
	ExtraArgs    []string `json:"extra_args"`
	DBMaxAge     any      `json:"db_max_age"`
}

type EnrichCfg struct {
	KEV     PyBool `json:"kev"`
	KEVURL  string `json:"kev_url"`
	EPSS    PyBool `json:"epss"`
	EPSSURL string `json:"epss_url"`
	Refresh any    `json:"refresh"`
}

type NoiseCfg struct {
	OldKernels        PyBool   `json:"old_kernels"`
	DistroOwned       PyBool   `json:"distro_owned"`
	DistroVendorRegex string   `json:"distro_vendor_regex"`
	PackageCache      PyBool   `json:"package_cache"`
	Paths             []string `json:"paths"`
}

type NotifyCfg struct {
	Policy       Policy   `json:"policy"`
	SuppressFile string   `json:"suppress_file"`
	Slack        SlackCfg `json:"slack"`
}

type Policy struct {
	MinSeverity          string       `json:"min_severity"`
	OnlyFixable          PyBool       `json:"only_fixable"`
	AlwaysNotify         AlwaysNotify `json:"always_notify"`
	VendorStatusIgnore   []string     `json:"vendor_status_ignore"`
	Repeat               string       `json:"repeat"`
	RemindEvery          any          `json:"remind_every"`
	ReportResolved       PyBool       `json:"report_resolved"`
	QuietWhenEmpty       PyBool       `json:"quiet_when_empty"`
	NotifyRebootRequired PyBool       `json:"notify_reboot_required"`
	NotifyWarnings       PyBool       `json:"notify_warnings"`
	MaxItems             int          `json:"max_items"`
	GroupByPackage       PyBool       `json:"group_by_package"`
	ReportTimings        PyBool       `json:"report_timings"`
	ReportSkipped        PyBool       `json:"report_skipped"`
}

type AlwaysNotify struct {
	KEV     PyBool   `json:"kev"`
	EPSSGte *float64 `json:"epss_gte"`
}

type SlackCfg struct {
	Enabled    PyBool   `json:"enabled"`
	WebhookEnv string   `json:"webhook_env"`
	Mention    string   `json:"mention"`
	MentionOn  []string `json:"mention_on"`
	Timeout    int      `json:"timeout"`
}

type AssessCfg struct {
	Enabled            PyBool          `json:"enabled"`
	Engine             string          `json:"engine"`
	Command            any             `json:"command"`
	Model              string          `json:"model"`
	RunAs              string          `json:"run_as"`
	MaxPerRun          int             `json:"max_per_run"`
	Cache              any             `json:"cache"`
	Timeout            any             `json:"timeout"`
	IncludeHostContext PyBool          `json:"include_host_context"`
	Redact             map[string]bool `json:"redact"`
	Language           string          `json:"language"`
}

type Retention struct {
	ResultsDays int  `json:"results_days"`
	LogsDays    *int `json:"logs_days"`
	SbomKeep    int  `json:"sbom_keep"`
}

// PyBool は Python の真偽判定 (空文字・0・null・空リストは偽、それ以外は真) で読む bool。
// Python 版は enabled: "no" のような値も truthy として受け付けるため、Go 版も同じに読む。
type PyBool bool

func (b *PyBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*b = PyBool(truthy(v))
	return nil
}

// ConfigError は設定の誤り。
type ConfigError struct{ Msg string }

func (e *ConfigError) Error() string { return e.Msg }

// ---------------------------------------------------------------- 読み込み

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			m[k] = deepCopy(vv)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, vv := range x {
			l[i] = deepCopy(vv)
		}
		return l
	}
	return v
}

// merge は Python 版 _merge と同じく、マップは再帰的に重ね、それ以外は置き換える。
func merge(base, over map[string]any) map[string]any {
	out := deepCopy(base).(map[string]any)
	for k, v := range over {
		vm, ok1 := v.(map[string]any)
		bm, ok2 := out[k].(map[string]any)
		if ok1 && ok2 {
			out[k] = merge(bm, vm)
		} else {
			out[k] = deepCopy(v)
		}
	}
	return out
}

// normalizeYAML は yaml.v3 の結果を JSON と同じ型 (map[string]any, []any, float64...) にそろえる。
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = normalizeYAML(vv)
		}
		return x
	case map[any]any:
		m := map[string]any{}
		for k, vv := range x {
			m[fmt.Sprint(k)] = normalizeYAML(vv)
		}
		return m
	case []any:
		for i, vv := range x {
			x[i] = normalizeYAML(vv)
		}
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	}
	return v
}

func loadFile(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if strings.HasSuffix(path, ".json") {
		if err := json.Unmarshal(b, &v); err != nil {
			return nil, &ConfigError{fmt.Sprintf("%s: %v", path, err)}
		}
	} else {
		var n yaml.Node
		if err := yaml.Unmarshal(b, &n); err != nil {
			return nil, &ConfigError{fmt.Sprintf("%s: %v", path, err)}
		}
		if err := fixYAML11(&n); err != nil {
			return nil, &ConfigError{fmt.Sprintf("%s: %v", path, err)}
		}
		if err := n.Decode(&v); err != nil {
			return nil, &ConfigError{fmt.Sprintf("%s: %v", path, err)}
		}
	}
	if v == nil {
		return map[string]any{}, nil
	}
	return normalizeYAML(v), nil
}

// yaml11Bool は PyYAML (YAML 1.1) が真偽値として読む裸の単語。yaml.v3 (YAML 1.2) は文字列として読むため、
// Python 版と同じ設定を同じ意味に読むよう、引用符なしのものだけ真偽値に直す。
var yaml11Bool = map[string]bool{
	"yes": true, "Yes": true, "YES": true, "on": true, "On": true, "ON": true,
	"no": false, "No": false, "NO": false, "off": false, "Off": false, "OFF": false,
}

func fixYAML11(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Style == 0 && n.Tag == "!!str" {
		if b, ok := yaml11Bool[n.Value]; ok {
			n.Tag = "!!bool"
			n.Value = fmt.Sprint(b)
		}
	}
	for i, c := range n.Content {
		// マップのキーはそのまま (on: などをキーに使う設定はない)
		if n.Kind == yaml.MappingNode && i%2 == 0 {
			continue
		}
		if err := fixYAML11(c); err != nil {
			return err
		}
	}
	return nil
}

// FindConfig は -c、$SBOMOPS_CONFIG、/etc/sbomops/config.{yaml,yml,json} の順に探す。
func FindConfig(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("SBOMOPS_CONFIG"); p != "" {
		return p
	}
	for _, p := range SearchPaths {
		if isFile(p) {
			return p
		}
	}
	return ""
}

// LoadConfig は既定値に利用者の設定を重ねて検証する。path が空なら既定値だけ。
func LoadConfig(path string) (*Config, error) {
	user := map[string]any{}
	if path != "" {
		v, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, &ConfigError{path + ": トップレベルはマップである必要があります"}
		}
		user = m
	}
	merged := merge(defaults.Config, user)
	cfg, err := validate(merged)
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	return cfg, nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func getMap(m map[string]any, k string) map[string]any {
	if x, ok := m[k].(map[string]any); ok {
		return x
	}
	return map[string]any{}
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func pyList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = "'" + s + "'"
	}
	return strings.Join(q, ", ")
}

// validate は Python 版 config.validate と同じ検査をし、型付きの設定にする。
func validate(m map[string]any) (*Config, error) {
	var errs []string
	host, _ := os.Hostname()
	if !truthy(m["host_label"]) {
		m["host_label"] = host
	}
	notify := getMap(m, "notify")
	pol := getMap(notify, "policy")
	sev := strings.ToUpper(str(pol["min_severity"]))
	if !contains(Severities, sev) {
		errs = append(errs, fmt.Sprintf("notify.policy.min_severity は [%s] のいずれか", pyList(Severities)))
	}
	pol["min_severity"] = sev
	if r := str(pol["repeat"]); r != "until_fixed" && r != "once" {
		errs = append(errs, "notify.policy.repeat は until_fixed / once")
	}
	as := getMap(m, "assess")
	eng := str(as["engine"])
	if eng != "claude" && eng != "codex" && eng != "command" {
		errs = append(errs, "assess.engine は claude / codex / command")
	}
	if eng == "command" && truthy(as["enabled"]) && !truthy(as["command"]) {
		errs = append(errs, "assess.engine=command のときは assess.command が必要")
	}
	durErr := func() error {
		for _, v := range []any{getMap(m, "run")["scan_budget"], pol["remind_every"], as["cache"], as["timeout"],
			getMap(m, "enrich")["refresh"], getMap(m, "trivy")["db_max_age"]} {
			if _, err := ParseDuration(v); err != nil {
				return err
			}
		}
		_, err := ParseSize(getMap(m, "resources")["mem_max"])
		return err
	}()
	if durErr != nil {
		errs = append(errs, durErr.Error())
	}

	ids := map[string]bool{}
	var targets []any
	tl, _ := m["targets"].([]any)
	for i, raw := range tl {
		t0, ok := raw.(map[string]any)
		if !ok {
			errs = append(errs, fmt.Sprintf("targets[%d] はマップで書いてください", i))
			continue
		}
		t := merge(defaults.Target, t0)
		tid := str(t["id"])
		if !truthy(t["id"]) {
			errs = append(errs, fmt.Sprintf("targets[%d]: id が必要", i))
			continue
		}
		if ids[tid] {
			errs = append(errs, fmt.Sprintf("targets: id '%s' が重複", tid))
		}
		ids[tid] = true
		tp := str(t["type"])
		if !contains(targetTypes, tp) {
			errs = append(errs, fmt.Sprintf("targets[%s]: type は (%s) のいずれか", tid, pyList(targetTypes)))
		}
		if tp == "dir" && !(truthy(t["path"]) || truthy(t["path_glob"])) {
			errs = append(errs, fmt.Sprintf("targets[%s]: dir には path か path_glob が必要", tid))
		}
		if tp == "image" && !truthy(t["ref"]) {
			errs = append(errs, fmt.Sprintf("targets[%s]: image には ref が必要", tid))
		}
		if err := func() error {
			if _, err := ParseDuration(t["every"]); err != nil {
				return err
			}
			if _, err := ParseDuration(t["max_runtime"]); err != nil {
				return err
			}
			_, err := ParseSize(t["mem_max"])
			return err
		}(); err != nil {
			errs = append(errs, fmt.Sprintf("targets[%s]: %v", tid, err))
		}
		targets = append(targets, t)
	}
	if targets == nil {
		targets = []any{}
	}
	m["targets"] = targets
	if len(errs) > 0 {
		return nil, &ConfigError{"設定エラー:\n  - " + strings.Join(errs, "\n  - ")}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, &ConfigError{err.Error()}
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, &ConfigError{"設定エラー: " + err.Error()}
	}
	return &cfg, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// strList は 文字列 / 文字列のリスト / nil を []string にする (path, path_glob, command)。
func strList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, str(e))
		}
		return out
	case []string:
		return x
	}
	return []string{str(v)}
}
