package sbomops

// 検出の分類 (ノイズ / 受容 / 有効) と、通知するかどうかの判定

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	sevRank = func() map[string]int {
		m := map[string]int{}
		for i, s := range Severities {
			m[s] = i
		}
		return m
	}()
	kernelPkg = regexp.MustCompile(`^(linux-(image|modules|headers|tools|cloud-tools|buildinfo|objects)(-[a-z0-9.]+)*` +
		`|kernel(-[a-z]+)*)$`)
	kver      = regexp.MustCompile(`(\d+\.\d+\.\d+-\d+)`)
	cacheDirs = []string{"/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/", "/var/cache/zypp/"}
)

func rank(sev string) int {
	if r, ok := sevRank[sev]; ok {
		return r
	}
	return 99
}

// ---------------------------------------------------------------- 受容リスト

type Accept struct {
	Vuln, Unit, Pkg string
	Until           string // YYYY-MM-DD か ""
	Reason          string
}

// LoadAccepts は 書式 (空白区切り): vuln_id  unit(glob)  package(glob)  期限(YYYY-MM-DD か -)  理由... を読む。
func LoadAccepts(path string) ([]Accept, error) {
	var out []Accept
	if path == "" || !isFile(path) {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := splitN(line, 5)
		if len(parts) < 4 {
			logWarn("%s:%d: 列が足りない (無視): %s", path, n, line)
			continue
		}
		until := ""
		if parts[3] != "-" {
			if _, err := time.Parse("2006-01-02", parts[3]); err != nil {
				return nil, fmt.Errorf("%s:%d: 期限の書式が不正: %s", path, n, parts[3])
			}
			until = parts[3]
		}
		reason := ""
		if len(parts) > 4 {
			reason = parts[4]
		}
		out = append(out, Accept{parts[0], parts[1], parts[2], until, reason})
	}
	return out, sc.Err()
}

// splitN は Python の str.split(None, n-1) と同じ (空白で最大 n 個に分ける)。
func splitN(s string, n int) []string {
	var out []string
	s = strings.TrimSpace(s)
	for len(out) < n-1 && s != "" {
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			break
		}
		out = append(out, s[:i])
		s = strings.TrimLeft(s[i:], " \t")
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

type Classifier struct {
	noise          NoiseCfg
	today          string
	kernel         string
	accepts        []Accept
	vendorRe       *regexp.Regexp
	owner          map[string]string
	ownerAsked     map[string]bool
	vendor         map[string]string
	ExpiredAccepts []string
}

func NewClassifier(cfg *Config, day string) (*Classifier, error) {
	acc, err := LoadAccepts(cfg.Notify.SuppressFile)
	if err != nil {
		return nil, err
	}
	pat := cfg.Noise.DistroVendorRegex
	if pat == "" {
		pat = `$^`
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("noise.distro_vendor_regex: %v", err)
	}
	return &Classifier{noise: cfg.Noise, today: day, kernel: runningKernel(), accepts: acc, vendorRe: re,
		owner: map[string]string{}, ownerAsked: map[string]bool{}, vendor: map[string]string{}}, nil
}

// Prepare はファイル所有者の問い合わせをまとめて行う (ホスト上の対象のみ)。
func (c *Classifier) Prepare(recs []*Finding, unitType string) {
	if !c.noise.DistroOwned || unitType == "image" {
		return
	}
	var paths []string
	for _, r := range recs {
		if strings.HasPrefix(r.Location, "/") && !c.ownerAsked[r.Location] && !isOSPURL(r.PURL) {
			paths = append(paths, r.Location)
		}
	}
	if len(paths) == 0 {
		return
	}
	got := FileOwners(paths)
	for _, p := range paths {
		c.ownerAsked[p] = true
		if o, ok := got[p]; ok {
			c.owner[p] = o
		}
	}
	var pk []string
	for _, o := range c.owner {
		if _, ok := c.vendor[o]; !ok && o != "" {
			pk = append(pk, o)
		}
	}
	for k, v := range PackageVendors(pk) {
		c.vendor[k] = v
	}
}

// Classify は active | noise:<理由> | suppressed:<理由> を返す。
func (c *Classifier) Classify(r *Finding, unitType string) string {
	n := c.noise
	loc := r.Location
	isOS := isOSPURL(r.PURL)
	if unitType != "image" {
		if bool(n.OldKernels) && isOS && kernelPkg.MatchString(r.Pkg) {
			m := kver.FindStringSubmatch(r.Pkg)
			if m == nil {
				m = kver.FindStringSubmatch(r.Version)
			}
			if m != nil && !strings.HasPrefix(c.kernel, m[1]) {
				return "noise:old-kernel"
			}
		}
		if n.PackageCache {
			for _, d := range cacheDirs {
				if strings.HasPrefix(loc, d) {
					return "noise:package-cache"
				}
			}
		}
		if bool(n.DistroOwned) && !isOS && loc != "" {
			if owner := c.owner[loc]; owner != "" && c.vendorRe.MatchString(c.vendor[owner]) {
				return "noise:distro-owned(" + owner + ")"
			}
		}
	}
	for _, pat := range n.Paths {
		if loc != "" && fnmatch(loc, pat) {
			return "noise:path"
		}
	}
	for _, a := range c.accepts {
		if (a.Vuln == r.VulnID || fnmatch(r.VulnID, a.Vuln)) && fnmatch(r.Unit, a.Unit) && fnmatch(r.Pkg, a.Pkg) {
			if a.Until != "" && a.Until < c.today {
				c.ExpiredAccepts = append(c.ExpiredAccepts, r.Key)
				continue // 期限切れは通常の検出に戻す
			}
			return "suppressed:accepted"
		}
	}
	return "active"
}

// Eligible は通知条件 (重大度・修正版の有無・KEV/EPSS) を満たすか。
func Eligible(r *Finding, pol Policy) bool {
	if contains(pol.VendorStatusIgnore, r.VStatus) {
		return false
	}
	if pol.AlwaysNotify.KEV && r.KEV != 0 {
		return true
	}
	if eg := pol.AlwaysNotify.EPSSGte; eg != nil && r.EPSS != nil && *r.EPSS >= *eg {
		return true
	}
	if pol.OnlyFixable && r.Fixed == "" {
		return false
	}
	return rank(r.Severity) <= rank(pol.MinSeverity)
}

// ShouldNotify は通知するなら "new" / "remind"、しないなら "" を返す。
func ShouldNotify(r *Finding, pol Policy, now time.Time) string {
	if r.State != "open" || r.Eligible == 0 || !strings.HasPrefix(r.Class, "active") {
		return ""
	}
	last, ok := ParseISO(r.LastNotified)
	if !ok {
		return "new"
	}
	if pol.Repeat == "once" {
		return ""
	}
	gap := MustDuration(pol.RemindEvery)
	if gap == 0 {
		gap = 86400
	}
	// 毎日同じ時刻に動かすので 1 時間の余裕を持たせる
	if now.Sub(last).Seconds() >= float64(gap-3600) {
		return "remind"
	}
	return ""
}

// sortKey の比較 (Python 版 sort_key のタプルと同じ順)。
func sortLess(a, b *Finding, assess map[string]*Assessment) bool {
	pr := func(r *Finding) int {
		if x := assess[r.Key]; x != nil {
			switch x.Priority {
			case "P1":
				return 0
			case "P2":
				return 1
			case "P3":
				return 2
			case "P4":
				return 3
			}
		}
		return 4
	}
	ep := func(r *Finding) float64 {
		if r.EPSS == nil {
			return 0
		}
		return *r.EPSS
	}
	if x, y := pr(a), pr(b); x != y {
		return x < y
	}
	if a.KEV != b.KEV {
		return a.KEV > b.KEV
	}
	if x, y := rank(a.Severity), rank(b.Severity); x != y {
		return x < y
	}
	if x, y := ep(a), ep(b); x != y && !(math.IsNaN(x) || math.IsNaN(y)) {
		return x > y
	}
	return a.VulnID < b.VulnID
}
