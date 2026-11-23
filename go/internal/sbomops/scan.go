package sbomops

// syft で SBOM (CycloneDX JSON) を作る / trivy で照合して 1 検出 1 レコードに正規化する

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FindTool は tools.<name> → /opt/sbomops/bin → 実行ファイルの近くの .tools → PATH の順に探す。
func FindTool(cfg *Config, name string) (string, error) {
	p := cfg.Tools.Syft
	if name == "trivy" {
		p = cfg.Tools.Trivy
	}
	if p != "" {
		return p, nil
	}
	cands := []string{"/opt/sbomops/bin/" + name}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		cands = append(cands, filepath.Join(d, ".tools", name), filepath.Join(d, "..", ".tools", name),
			filepath.Join(d, "..", "..", ".tools", name))
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return filepath.Abs(c)
		}
	}
	w, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s が見つかりません (scripts/install-tools.sh で入れるか tools.%s を設定)", name, name)
	}
	return w, nil
}

// OS のパッケージ DB と、ディストリ判定に使うファイル (syft の os タグの cataloger が読むもの)
var osDBPaths = []string{
	"etc/os-release", "usr/lib/os-release", "etc/system-release", "etc/redhat-release",
	"etc/debian_version", "etc/alpine-release", "etc/lsb-release",
	"var/lib/dpkg/status", "var/lib/dpkg/status.d",
	"var/lib/rpm", "usr/lib/sysimage/rpm", "usr/share/rpm",
	"lib/apk/db/installed", "var/lib/pacman/local", "var/db/pkg",
}

func ignoredDBFile(name string) bool {
	return fnmatch(name, "__db.*") || fnmatch(name, "*.lock") || name == ".dbenv.lock"
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chtimes(dst, st.ModTime(), st.ModTime())
}

// copyTree はシンボリックリンクをたどってコピーする (壊れたリンクは飛ばす)。
func copyTree(src, dst string) error {
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, e := range ents {
		if ignoredDBFile(e.Name()) {
			continue
		}
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		st, err := os.Stat(s)
		if err != nil {
			continue // 壊れたリンク
		}
		if st.IsDir() {
			if err := copyTree(s, d); err != nil {
				return err
			}
		} else if st.Mode().IsRegular() {
			if err := copyFile(s, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// SnapshotOSDB は root のパッケージ DB を dest に写し、写したパスの数を返す。
func SnapshotOSDB(root, dest string) (int, error) {
	n := 0
	for _, rel := range osDBPaths {
		src := filepath.Join(root, rel)
		dst := filepath.Join(dest, rel)
		if r, err := filepath.EvalSymlinks(src); err == nil {
			src = r
		}
		switch {
		case isDir(src):
			if err := copyTree(src, dst); err != nil {
				return n, err
			}
			n++
		case isFile(src):
			if err := copyFile(src, dst); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// ScanUnit は SBOM を作り、保存先のパスと実行結果を返す。
func ScanUnit(cfg *Config, u Unit, dataDir string) (string, Result, error) {
	syft, err := FindTool(cfg, "syft")
	if err != nil {
		return "", Result{}, err
	}
	d := filepath.Join(dataDir, "sbom", SafeName(u.ID))
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", Result{}, err
	}
	out := filepath.Join(d, time.Now().Format("20060102T150405")+".cdx.json")
	tmp := out + ".part"
	logp := filepath.Join(dataDir, "logs", "syft", SafeName(u.ID)+".log")
	os.MkdirAll(filepath.Dir(logp), 0o755)
	os.WriteFile(logp, []byte(fmt.Sprintf("# %s %s\n", time.Now().Format("2006-01-02 15:04:05"), u.Source)), 0o644)
	env := map[string]string{
		"SYFT_CHECK_FOR_APP_UPDATE": "false",
		// ファイル単位のハッシュ等は不要で、メモリを最も使うため無効化
		"SYFT_FILE_METADATA_SELECTION": "none",
		"SYFT_PARALLELISM":             fmt.Sprint(cfg.Resources.SyftParallelism),
	}
	var name string
	if u.Type == "image" {
		_, name, _ = strings.Cut(u.Source, ":")
	} else {
		name = strings.TrimRight(u.Root, "/")
		if name == "" {
			name = HostName()
		}
	}
	source := u.Source
	if u.Type == "dir" && hostRoot != "/" {
		source = "dir:" + hpath(u.Root) // 記録はホスト上のパスのまま、読むのは host_root の下
	}
	logInfo("scan %s (%s)", u.ID, u.Source)
	snap := ""
	if u.Type == "os-packages" {
		snap, err = os.MkdirTemp(dataDir, "osdb-")
		if err != nil {
			return "", Result{}, err
		}
		defer os.RemoveAll(snap)
		n, err := SnapshotOSDB(hpath(u.Root), snap)
		if err != nil {
			return "", Result{}, err
		}
		if n == 0 {
			return "", Result{}, fmt.Errorf("%s にパッケージ DB が見つからない", u.Root)
		}
		source = "dir:" + snap
	}
	cmd := append([]string{syft, "scan", "-q", source}, u.SyftArgs...)
	cmd = append(cmd, "--source-name", name, "-o", "cyclonedx-json="+tmp)
	r, err := RunCmd(cmd, cfg.Resources, RunOpts{MemMax: u.MemMax, Timeout: u.MaxRuntime, Env: env, LogPath: logp})
	if err != nil {
		return "", r, err
	}
	if r.RC != 0 || r.Killed != "" || !exists(tmp) {
		os.Remove(tmp)
		why := r.Killed
		if why == "" {
			why = fmt.Sprintf("rc=%d", r.RC)
		}
		lines := splitLines(strings.TrimSpace(r.StderrTail))
		last := ""
		if len(lines) > 0 {
			last = lines[len(lines)-1]
		}
		return "", r, fmt.Errorf("syft 失敗 (%s): %s", why, last)
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return "", r, err
	}
	var bom struct {
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(b, &bom); err != nil {
		return "", r, fmt.Errorf("SBOM を読めない: %v", err)
	}
	os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, out); err != nil {
		return "", r, err
	}
	logInfo("  -> %d components, %s, peak RSS %dMiB", len(bom.Components), FmtDuration(r.Elapsed), r.PeakRSS>>20)
	pruneSBOM(d, cfg.Retention.SbomKeep)
	return out, r, nil
}

func pruneSBOM(d string, keep int) {
	files, _ := filepath.Glob(filepath.Join(d, "*.cdx.json"))
	sort.Strings(files)
	if keep < 1 {
		keep = 1
	}
	for i := 0; i < len(files)-keep; i++ {
		os.Remove(files[i])
	}
}

// ---------------------------------------------------------------- trivy

var osPURL = []string{"pkg:deb/", "pkg:rpm/", "pkg:apk/", "pkg:alpm/", "pkg:ebuild/"}

func isOSPURL(p string) bool {
	for _, x := range osPURL {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

func trivyBaseArgs(cfg *Config, cache string) []string {
	a := []string{"--cache-dir", cache, "--quiet", "--disable-telemetry", "--skip-version-check"}
	for _, repo := range cfg.Trivy.DBRepository {
		a = append(a, "--db-repository", repo)
	}
	return a
}

func UpdateTrivyDB(cfg *Config, dataDir string) error {
	trivy, err := FindTool(cfg, "trivy")
	if err != nil {
		return err
	}
	cache := filepath.Join(dataDir, "trivy-cache")
	cmd := append(append([]string{trivy, "sbom"}, trivyBaseArgs(cfg, cache)...), "--download-db-only")
	logInfo("trivy DB を更新")
	r, err := RunCmd(cmd, cfg.Resources, RunOpts{MemMax: MustSize(cfg.Resources.MemMax), Timeout: 1800})
	if err != nil {
		return err
	}
	if r.RC != 0 {
		return fmt.Errorf("trivy DB の更新に失敗: %s", tailRunes(strings.TrimSpace(r.StderrTail), 500))
	}
	return nil
}

func TrivyDBUpdatedAt(cfg *Config, dataDir string) string {
	trivy, err := FindTool(cfg, "trivy")
	if err != nil {
		return ""
	}
	r, err := runOut([]string{trivy, "version", "--cache-dir", filepath.Join(dataDir, "trivy-cache"), "--format", "json"},
		60*time.Second, "")
	if err != nil {
		return ""
	}
	var v struct {
		VulnerabilityDB *struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if json.Unmarshal([]byte(r.stdout), &v) != nil || v.VulnerabilityDB == nil {
		return ""
	}
	return v.VulnerabilityDB.UpdatedAt
}

// MatchUnit は trivy sbom を実行し、結果 JSON のパスを返す。
func MatchUnit(cfg *Config, unitID, sbomPath, dataDir, day string) (string, error) {
	trivy, err := FindTool(cfg, "trivy")
	if err != nil {
		return "", err
	}
	cache := filepath.Join(dataDir, "trivy-cache")
	outd := filepath.Join(dataDir, "results", day)
	if err := os.MkdirAll(outd, 0o700); err != nil {
		return "", err
	}
	out := filepath.Join(outd, SafeName(unitID)+".trivy.json")
	cmd := append(append([]string{trivy, "sbom"}, trivyBaseArgs(cfg, cache)...),
		"--skip-db-update", "--scanners", "vuln", "--format", "json", "-o", out)
	cmd = append(append(cmd, cfg.Trivy.ExtraArgs...), sbomPath)
	r, err := RunCmd(cmd, cfg.Resources, RunOpts{MemMax: MustSize(cfg.Resources.MemMax), Timeout: 3600})
	if err != nil {
		return "", err
	}
	if r.RC != 0 || r.Killed != "" {
		why := r.Killed
		if why == "" {
			why = fmt.Sprintf("rc=%d", r.RC)
		}
		return "", fmt.Errorf("trivy 失敗 (%s): %s", why, tailRunes(strings.TrimSpace(r.StderrTail), 300))
	}
	return out, nil
}

// purlBase は package-id など syft 固有の修飾子を除いた purl。
func purlBase(purl string) string {
	head, q, ok := strings.Cut(purl, "?")
	if !ok {
		return purl
	}
	var keep []string
	for _, x := range strings.Split(q, "&") {
		if !strings.HasPrefix(x, "package-id=") {
			keep = append(keep, x)
		}
	}
	if len(keep) == 0 {
		return head
	}
	return head + "?" + strings.Join(keep, "&")
}

type cdxBOM struct {
	Components []struct {
		BOMRef     string `json:"bom-ref"`
		PURL       string `json:"purl"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	} `json:"components"`
}

// sbomLocations は CycloneDX から (bom-ref → 場所, purl → 全ての場所) を作る。
//
// 同じ purl のコンポーネントが複数の場所にある場合 (同じ Go モジュールを含む複数のバイナリなど)、
// trivy は 1 件にまとめて返し、どの bom-ref を使うかも一定しないため、purl から全ての場所を引けるようにする。
func sbomLocations(sbomPath string) (map[string]string, map[string][]string, error) {
	b, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, nil, err
	}
	var bom cdxBOM
	if err := json.Unmarshal(b, &bom); err != nil {
		return nil, nil, err
	}
	byRef := map[string]string{}
	byPurl := map[string]map[string]bool{}
	for _, c := range bom.Components {
		var locs []string
		for _, p := range c.Properties {
			if strings.HasPrefix(p.Name, "syft:location:") && strings.HasSuffix(p.Name, ":path") {
				locs = append(locs, p.Value)
			}
		}
		if len(locs) == 0 {
			continue
		}
		if c.BOMRef != "" {
			byRef[c.BOMRef] = locs[0]
		}
		if c.PURL != "" {
			k := purlBase(c.PURL)
			if byPurl[k] == nil {
				byPurl[k] = map[string]bool{}
			}
			byPurl[k][locs[0]] = true
		}
	}
	out := map[string][]string{}
	for k, set := range byPurl {
		var l []string
		for x := range set {
			l = append(l, x)
		}
		sort.Strings(l)
		out[k] = l
	}
	return byRef, out, nil
}

type trivyReport struct {
	Results []struct {
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Status           string   `json:"Status"`
			Severity         *string  `json:"Severity"`
			Title            string   `json:"Title"`
			PrimaryURL       string   `json:"PrimaryURL"`
			VendorIDs        []string `json:"VendorIDs"`
			PkgIdentifier    struct {
				PURL   string `json:"PURL"`
				BOMRef string `json:"BOMRef"`
			} `json:"PkgIdentifier"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

var archRe = regexp.MustCompile(`[?&]arch=([^&]+)`)

// Normalize は trivy の結果を 1 検出 1 レコードにする (順序は trivy の出力順、重複 key は最初のもの)。
func Normalize(unitID, unitRoot, trivyJSON, sbomPath string) ([]*Finding, error) {
	b, err := os.ReadFile(trivyJSON)
	if err != nil {
		return nil, err
	}
	var data trivyReport
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	byRef, byPurl, err := sbomLocations(sbomPath)
	if err != nil {
		return nil, err
	}
	root := strings.TrimRight(unitRoot, "/")
	absloc := func(loc string) string {
		// syft はスキャン起点からの相対パスを返す (先頭の / は付いたり付かなかったりする)
		loc = "/" + strings.TrimLeft(loc, "/")
		if root == "" || strings.HasPrefix(loc, root+"/") {
			return loc
		}
		return root + loc
	}
	var out []*Finding
	seen := map[string]bool{}
	for _, res := range data.Results {
		for _, v := range res.Vulnerabilities {
			purl := v.PkgIdentifier.PURL
			type place struct{ loc, ident string }
			var places []place
			if isOSPURL(purl) {
				// OS パッケージの場所は常にパッケージ DB なので、代わりにアーキテクチャで区別する
				arch := ""
				if m := archRe.FindStringSubmatch(purl); m != nil {
					arch = m[1]
				}
				places = []place{{"", arch}}
			} else {
				locs := byPurl[purlBase(purl)]
				if len(locs) == 0 {
					locs = []string{byRef[v.PkgIdentifier.BOMRef]}
				}
				for _, x := range locs {
					if x == "" {
						places = append(places, place{"", ""})
					} else {
						places = append(places, place{absloc(x), absloc(x)})
					}
				}
			}
			for _, p := range places {
				key := strings.Join([]string{unitID, v.VulnerabilityID, v.PkgName, p.ident}, "|")
				if seen[key] {
					continue
				}
				seen[key] = true
				sev := "UNKNOWN"
				if v.Severity != nil {
					sev = *v.Severity
				}
				var aliases []string
				for _, x := range v.VendorIDs {
					if strings.HasPrefix(x, "CVE-") {
						aliases = append(aliases, x)
					}
				}
				out = append(out, &Finding{Key: key, Unit: unitID, VulnID: v.VulnerabilityID, Pkg: v.PkgName,
					PkgType: res.Type, Version: v.InstalledVersion, Fixed: v.FixedVersion, VStatus: v.Status,
					Severity: sev, Title: truncRunes(v.Title, 200), URL: v.PrimaryURL, Location: p.loc,
					PURL: purl, Aliases: aliases})
			}
		}
	}
	return out, nil
}
