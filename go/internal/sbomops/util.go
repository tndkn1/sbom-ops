// Package sbomops は Python 版 sbomops (リポジトリ直下の sbomops/) の Go 実装。
// 振る舞いの仕様は ../../spec/ にあり、Python 版と同じテストデータで検証する。
package sbomops

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- ログ

var (
	logger  = log.New(os.Stderr, "", 0)
	verbose bool
)

// SetupLogging は Python 版と同じ書式 ("2026-01-01T03:00:00 INFO ...") でログを出す。
func SetupLogging(v bool, logfile string) error {
	verbose = v
	var w io.Writer = os.Stderr
	if logfile != "" {
		if err := os.MkdirAll(filepath.Dir(logfile), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		w = io.MultiWriter(os.Stderr, f)
	}
	logger = log.New(w, "", 0)
	return nil
}

func logf(level, format string, a ...any) {
	if level == "DEBUG" && !verbose {
		return
	}
	logger.Printf("%s %s %s", time.Now().Format("2006-01-02T15:04:05"), level, fmt.Sprintf(format, a...))
}

func logDebug(format string, a ...any) { logf("DEBUG", format, a...) }
func logInfo(format string, a ...any)  { logf("INFO", format, a...) }
func logWarn(format string, a ...any)  { logf("WARNING", format, a...) }
func logError(format string, a ...any) { logf("ERROR", format, a...) }

// ---------------------------------------------------------------- 期間・サイズ

var (
	durRe    = regexp.MustCompile(`^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$`)
	durUnit  = map[string]float64{"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
	sizeRe   = regexp.MustCompile(`(?i)^\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*$`)
	sizeUnit = map[string]float64{"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
)

func isOff(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == "" || x == "0" || x == "off"
	case float64:
		return x == 0
	case int:
		return x == 0
	case int64:
		return x == 0
	}
	return false
}

func asNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

// ParseDuration は '90m' '6h' '1d' '2w' や数値 (秒) を秒数にする。0 / nil / 'off' は 0。
func ParseDuration(v any) (int64, error) {
	if isOff(v) {
		return 0, nil
	}
	if n, ok := asNumber(v); ok {
		return int64(n), nil
	}
	s := fmt.Sprint(v)
	m := durRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("期間の書式が不正: %s (例: 30m, 6h, 1d, 2w)", pyRepr(v))
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	return int64(f * durUnit[m[2]]), nil
}

// MustDuration は検証済みの値に使う (不正なら 0)。
func MustDuration(v any) int64 {
	d, _ := ParseDuration(v)
	return d
}

// ParseSize は '4G' '512M' や数値 (バイト) をバイト数にする。0 / nil は 0 (無制限)。
func ParseSize(v any) (int64, error) {
	if isOff(v) {
		return 0, nil
	}
	if n, ok := asNumber(v); ok {
		return int64(n), nil
	}
	s := fmt.Sprint(v)
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("サイズの書式が不正: %s (例: 512M, 4G)", pyRepr(v))
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	return int64(f * sizeUnit[strings.ToUpper(m[2])]), nil
}

func MustSize(v any) int64 {
	n, _ := ParseSize(v)
	return n
}

// FmtDuration は秒数を短く表す (Python 版 fmt_duration と同じ)。
func FmtDuration(sec float64) string {
	s := int64(sec)
	switch {
	case s >= 86400 && s%86400 == 0:
		return fmt.Sprintf("%dd", s/86400)
	case s < 120:
		return fmt.Sprintf("%ds", s)
	case s < 7200:
		return fmt.Sprintf("%dm", s/60)
	case s < 2*86400:
		return pyFixed1(float64(s)/3600) + "h"
	}
	return pyFixed1(float64(s)/86400) + "d"
}

// pyFixed1 は Python の f"{x:.1f}" と同じ丸め (2 進表現の値を最近接偶数丸め) をする。
func pyFixed1(x float64) string { return strconv.FormatFloat(x, 'f', 1, 64) }

// pyRepr は Python の repr() に近い表記 (エラーメッセージを揃えるため)。
func pyRepr(v any) string {
	switch x := v.(type) {
	case string:
		return "'" + x + "'"
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	}
	return fmt.Sprint(v)
}

// ---------------------------------------------------------------- 時刻

const isoLayout = "2006-01-02T15:04:05-07:00"

// Now は秒未満を切り捨てた UTC の現在時刻。
func Now() time.Time { return time.Now().UTC().Truncate(time.Second) }

// ISO は Python の datetime.isoformat() と同じ形 (UTC は +00:00)。
func ISO(t time.Time) string { return t.Format(isoLayout) }

// ParseISO は "Z"・ナノ秒・タイムゾーンなし (UTC とみなす) を受け付ける。
func ParseISO(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return t.Truncate(time.Microsecond), true
		}
	}
	return time.Time{}, false
}

func today() string { return time.Now().Format("2006-01-02") }

func epoch(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func nowEpoch() float64 { return epoch(time.Now()) }

// ---------------------------------------------------------------- ファイル

// AtomicWrite は一時ファイルに書いてから置き換える。
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

var safeRe = regexp.MustCompile(`[^A-Za-z0-9._@+-]+`)

// SafeName はファイル名に使える形にする。
func SafeName(s string) string {
	r := strings.Trim(safeRe.ReplaceAllString(s, "_"), "_")
	if r == "" {
		return "_"
	}
	return r
}

// LoadEnvFile は KEY=VALUE 形式のファイルを読み、未設定の環境変数だけを埋める (systemd の EnvironmentFile 互換)。
func LoadEnvFile(path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		k = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), "export "))
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == v[len(v)-1] && (v[0] == '\'' || v[0] == '"') {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// ---------------------------------------------------------------- 文字列

// truncRunes は Python の s[:n] と同じく文字 (コードポイント) 単位で切る。
func truncRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// tailRunes は Python の s[-n:] と同じ。
func tailRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func runeLen(s string) int { return len([]rune(s)) }

// fnmatch は Python の fnmatch.fnmatch (POSIX) と同じ。* は / にも一致する。
func fnmatch(name, pat string) bool {
	re, err := regexp.Compile(fnmatchTranslate(pat))
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

func fnmatchTranslate(pat string) string {
	var b strings.Builder
	b.WriteString(`(?s)^`)
	rs := []rune(pat)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(rs) && rs[j] == '!' {
				j++
			}
			if j < len(rs) && rs[j] == ']' {
				j++
			}
			for j < len(rs) && rs[j] != ']' {
				j++
			}
			if j >= len(rs) {
				b.WriteString(`\[`)
				continue
			}
			stuff := string(rs[i+1 : j])
			i = j
			if strings.HasPrefix(stuff, "!") {
				stuff = "^" + stuff[1:]
			} else if strings.HasPrefix(stuff, "^") {
				stuff = `\` + stuff
			}
			stuff = strings.ReplaceAll(stuff, `\`, `\\`)
			if strings.HasPrefix(stuff, `\\^`) {
				stuff = `\^` + stuff[3:]
			}
			b.WriteString("[" + stuff + "]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString(`$`)
	return b.String()
}

// pyGlob は Python の glob.glob と同じく、パターンの要素が . で始まらない限り隠しファイルを返さない。
func pyGlob(pattern string) []string {
	ms, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	pp := strings.Split(pattern, "/")
	var out []string
	for _, m := range ms {
		mp := strings.Split(m, "/")
		ok := len(mp) == len(pp)
		for i := 0; ok && i < len(pp); i++ {
			if strings.ContainsAny(pp[i], "*?[") && !strings.HasPrefix(pp[i], ".") && strings.HasPrefix(mp[i], ".") {
				ok = false
			}
		}
		if ok {
			out = append(out, m)
		}
	}
	return out
}

func roundTo(x float64, n int) float64 {
	p := math.Pow(10, float64(n))
	return math.Round(x*p) / p
}
