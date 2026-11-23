package sbomops

// ホストの情報をディストリに依存せずに得る (os-release、dpkg / rpm、カーネル、コンテナランタイム)

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// hostRoot は調べるホストのルート。コンテナからホストの / を /host にマウントして調べるときは "/host"
// (設定 host_root / 環境変数 SBOMOPS_HOST_ROOT。LoadConfig が設定する)。
// 記録するパス (unit の root・検出の場所) はホスト上のパスのままにし、読むときだけこれを前に付ける。
var hostRoot = "/"

func setHostRoot(root string) {
	root = strings.TrimRight(root, "/")
	if root == "" {
		root = "/"
	}
	hostRoot = root
}

// hpath はホスト上のパス p を、このプロセスから読めるパスにする。
func hpath(p string) string {
	if hostRoot == "/" {
		return p
	}
	return hostRoot + "/" + strings.TrimLeft(p, "/")
}

// unhpath は hpath の逆 (glob の結果などをホスト上のパスに戻す)。
func unhpath(p string) string {
	if hostRoot == "/" || !(p == hostRoot || strings.HasPrefix(p, hostRoot+"/")) {
		return p
	}
	if r := p[len(hostRoot):]; r != "" {
		return r
	}
	return "/"
}

// HostName は調べるホストの名前 (host_root が / 以外なら <host_root>/etc/hostname)。
func HostName() string {
	if hostRoot != "/" {
		if b, err := os.ReadFile(hpath("/etc/hostname")); err == nil {
			if n := strings.TrimSpace(string(b)); n != "" {
				return n
			}
		}
	}
	h, _ := os.Hostname()
	return h
}

func dpkgCmd() []string {
	if hostRoot == "/" {
		return []string{"dpkg-query"}
	}
	return []string{"dpkg-query", "--admindir", hpath("/var/lib/dpkg")}
}

func rpmCmd() []string {
	if hostRoot == "/" {
		return []string{"rpm"}
	}
	return []string{"rpm", "--root", hostRoot}
}

func OSRelease(root string) map[string]string {
	out := map[string]string{}
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		path := filepath.Join(root, p)
		if !isFile(path) {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), "="); ok {
				out[k] = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
		f.Close()
		break
	}
	return out
}

func getOr(m map[string]string, k, def string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

func OSFingerprint() string {
	r := OSRelease(hpath("/"))
	return getOr(r, "ID", "?") + "-" + getOr(r, "VERSION_ID", "?")
}

func which(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// PackageManager はパッケージ DB の種類。dpkg と rpm が両方ある場合は dpkg を優先。
func PackageManager() string {
	if isFile(hpath("/var/lib/dpkg/status")) && which("dpkg-query") {
		return "dpkg"
	}
	if which("rpm") && (isDir(hpath("/var/lib/rpm")) || isDir(hpath("/usr/lib/sysimage/rpm"))) {
		return "rpm"
	}
	return ""
}

func charsToString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

// runningKernel は uname -r と同じ (テストで差し替えられるよう変数にしている)。
var runningKernel = func() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return charsToString(u.Release[:])
}

type procOut struct {
	rc     int
	stdout string
	stderr string
}

func runOut(cmd []string, timeout time.Duration, stdin string) (procOut, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	var so, se strings.Builder
	c.Stdout, c.Stderr = &so, &se
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	err := c.Run()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			return procOut{rc: -1, stderr: err.Error()}, err
		}
	}
	if ctx.Err() != nil {
		return procOut{rc: -1, stdout: so.String(), stderr: se.String()}, ctx.Err()
	}
	return procOut{rc: rc, stdout: so.String(), stderr: se.String()}, nil
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// FileOwners はファイル → 所有パッケージ名 (なければ含めない)。まとめて問い合わせる。
func FileOwners(paths []string) map[string]string {
	pm := PackageManager()
	res := map[string]string{}
	if pm == "" || len(paths) == 0 {
		return res
	}
	uniq := uniqSorted(paths)
	want := map[string]bool{}
	for _, p := range uniq {
		want[p] = true
	}
	for i := 0; i < len(uniq); i += 200 {
		chunk := uniq[i:min(i+200, len(uniq))]
		if pm == "dpkg" {
			// 出力: "pkg1, pkg2: /path"。所有者がないものは stderr に出る
			r, _ := runOut(append(append(dpkgCmd(), "-S"), chunk...), 120*time.Second, "")
			for _, line := range splitLines(r.stdout) {
				if !strings.Contains(line, ": ") || strings.HasPrefix(line, "diversion") {
					continue
				}
				pkgs, path, _ := strings.Cut(line, ": ")
				if want[path] {
					p := strings.TrimSpace(strings.Split(pkgs, ",")[0])
					res[path] = strings.Split(p, ":")[0]
				}
			}
		} else {
			r, _ := runOut(append(append(rpmCmd(), "-qf", "--qf", "%{NAME}\n"), chunk...), 120*time.Second, "")
			lines := splitLines(r.stdout)
			if len(lines) == len(chunk) {
				for j, path := range chunk {
					if !strings.Contains(lines[j], "not owned") && !strings.Contains(lines[j], "No such file") {
						res[path] = strings.TrimSpace(lines[j])
					}
				}
			} else {
				for _, path := range chunk {
					r1, _ := runOut(append(rpmCmd(), "-qf", "--qf", "%{NAME}\n", path), 120*time.Second, "")
					if r1.rc == 0 {
						if l := splitLines(r1.stdout); len(l) > 0 {
							res[path] = strings.TrimSpace(l[0])
						}
					}
				}
			}
		}
	}
	return res
}

// PackageVendors はパッケージ → 提供元の文字列 (dpkg は Maintainer、rpm は Vendor)。
func PackageVendors(pkgs []string) map[string]string {
	pm := PackageManager()
	res := map[string]string{}
	var nz []string
	for _, p := range pkgs {
		if p != "" {
			nz = append(nz, p)
		}
	}
	uniq := uniqSorted(nz)
	if pm == "" || len(uniq) == 0 {
		return res
	}
	for i := 0; i < len(uniq); i += 200 {
		chunk := uniq[i:min(i+200, len(uniq))]
		var r procOut
		if pm == "dpkg" {
			r, _ = runOut(append(append(dpkgCmd(), "-W", "-f", "${Package}\t${Maintainer}\n"), chunk...), 120*time.Second, "")
		} else {
			r, _ = runOut(append(append(rpmCmd(), "-q", "--qf", "%{NAME}\t%{VENDOR}\n"), chunk...), 120*time.Second, "")
		}
		for _, line := range splitLines(r.stdout) {
			if name, vendor, ok := strings.Cut(line, "\t"); ok {
				name = strings.Split(name, ":")[0]
				if _, set := res[name]; !set {
					res[name] = vendor
				}
			}
		}
	}
	return res
}

func uniqSorted(l []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range l {
		if !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

var verSplit = regexp.MustCompile(`[.\-_+~]`)

func verLess(a, b string) bool {
	pa, pb := verSplit.Split(a, -1), verSplit.Split(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				return na < nb
			}
		case ea == nil:
			return true
		case eb == nil:
			return false
		default:
			if pa[i] != pb[i] {
				return pa[i] < pb[i]
			}
		}
	}
	return len(pa) < len(pb)
}

// InstalledKernels はインストール済みカーネルのリリース文字列 (uname -r と同じ形)。
func InstalledKernels() []string {
	rel := map[string]bool{}
	ds, _ := filepath.Glob(hpath("/lib/modules/*/"))
	ds2, _ := filepath.Glob(hpath("/usr/lib/modules/*/"))
	for _, p := range append(ds, ds2...) {
		if !isDir(p) {
			continue
		}
		name := filepath.Base(strings.TrimRight(p, "/"))
		vm, _ := filepath.Glob(hpath("/boot/vmlinuz-" + name))
		if exists(filepath.Join(p, "modules.dep")) || len(vm) > 0 {
			rel[name] = true
		}
	}
	var out []string
	for k := range rel {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return verLess(out[i], out[j]) })
	return out
}

// RebootRequired は再起動が必要なら理由を返す。
func RebootRequired() string {
	// /var/run は /run へのリンクなので、host_root の下では /run を見る
	if exists(hpath("/run/reboot-required")) || exists(hpath("/var/run/reboot-required")) {
		pk := ""
		pkgs := hpath("/run/reboot-required.pkgs")
		if !exists(pkgs) {
			pkgs = hpath("/var/run/reboot-required.pkgs")
		}
		if b, err := os.ReadFile(pkgs); err == nil {
			var l []string
			for _, x := range strings.Split(string(b), "\n") {
				if x = strings.TrimSpace(x); x != "" {
					l = append(l, x)
				}
			}
			l = uniqSorted(l)
			if len(l) > 5 {
				l = l[:5]
			}
			pk = strings.Join(l, ", ")
		}
		if pk != "" {
			return "reboot-required (" + pk + ")"
		}
		return "reboot-required"
	}
	if hostRoot == "/" && which("needs-restarting") {
		r, err := runOut([]string{"needs-restarting", "-r"}, 60*time.Second, "")
		if err == nil {
			if r.rc == 1 {
				return "needs-restarting -r: 再起動が必要"
			}
			if r.rc == 0 {
				return ""
			}
		}
	}
	ks := InstalledKernels()
	cur := runningKernel()
	if len(ks) > 0 && contains(ks, cur) && ks[len(ks)-1] != cur {
		return fmt.Sprintf("新しいカーネル %s がインストール済み (起動中: %s)", ks[len(ks)-1], cur)
	}
	return ""
}

func ContainerRuntime() string {
	for _, rt := range []string{"docker", "podman"} {
		if which(rt) {
			if r, err := runOut([]string{rt, "info", "--format", "{{.ID}}"}, 30*time.Second, ""); err == nil && r.rc == 0 {
				return rt
			}
		}
	}
	return ""
}

// RunningImages は (イメージ名, イメージ ID) の一覧。
func RunningImages(runtime string) ([][2]string, error) {
	r, err := runOut([]string{runtime, "ps", "--format", "{{.Image}}"}, 60*time.Second, "")
	if err != nil || r.rc != 0 {
		return nil, fmt.Errorf("%s ps 失敗: %s", runtime, strings.TrimSpace(r.stderr))
	}
	var imgs []string
	for _, x := range splitLines(r.stdout) {
		if x = strings.TrimSpace(x); x != "" {
			imgs = append(imgs, x)
		}
	}
	var out [][2]string
	for _, img := range uniqSorted(imgs) {
		i, err := runOut([]string{runtime, "image", "inspect", "--format", "{{.Id}}", img}, 60*time.Second, "")
		id := ""
		if err == nil && i.rc == 0 {
			id = strings.TrimSpace(i.stdout)
		}
		out = append(out, [2]string{img, id})
	}
	return out, nil
}

// RunningExecutables は稼働中プロセスの実行ファイルのパス (読める範囲で)。
func RunningExecutables() map[string]bool {
	exes := map[string]bool{}
	ps, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, p := range ps {
		if t, err := os.Readlink(p); err == nil {
			exes[strings.TrimSuffix(t, " (deleted)")] = true
		}
	}
	return exes
}

func LogHostSummary() {
	r := OSRelease(hpath("/"))
	pm := PackageManager()
	if pm == "" {
		pm = "None"
	}
	logInfo("host: %s %s, kernel %s, pkg=%s", getOr(r, "ID", "None"), getOr(r, "VERSION_ID", "None"), runningKernel(), pm)
}
