package sbomops

// Claude Code / Codex (または任意のコマンド) に検出を評価させる。
//
// 検出をまとめて 1 回のプロンプトにし、各検出の優先度・このホストで悪用されうるか・対処を JSON で返させる。
// CLI にはツールを使わせない (claude は --tools "", codex は read-only サンドボックス)。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const assessPrompt = `あなたはサーバ運用のセキュリティ担当です。以下は {os} のホストで SBOM (syft) と trivy が検出した脆弱性です。
各項目について、このホストでの対応優先度を評価してください。

判断の観点:
- KEV (既知の悪用あり) / EPSS (30日以内の悪用確率) / 重大度
- 脆弱なコンポーネントが実際に使われていそうか (場所、稼働プロセスとの関係、パッケージの種類)
- 修正版の有無と、更新の容易さ (OS パッケージの更新で済むか、アプリの再ビルドが要るか)

優先度の基準: P1=今日中に対応 / P2=今週中 / P3=定期メンテで対応 / P4=影響は小さい・監視のみ

出力は JSON 配列だけにしてください (前後に説明文を付けない)。各要素:
{"id": "<項目の id>", "priority": "P1|P2|P3|P4", "exploitable_here": "yes|no|unknown",
  "rationale": "<{lang}で 120 文字以内の根拠>", "action": "<{lang}で 80 文字以内の対処>"}

検出:
{items}
`

var (
	homeRe     = regexp.MustCompile(`/home/[^/\s]+`)
	homeUnitRe = regexp.MustCompile(`\bhome_[^_/\s]+_`)
	jsonArrRe  = regexp.MustCompile(`(?s)\[.*\]`)
)

func redact(s string, cfg *Config) string {
	rd := cfg.Assess.Redact
	if s == "" {
		return s
	}
	if rd["hostname"] {
		if hn, _ := os.Hostname(); hn != "" {
			s = strings.ReplaceAll(s, hn, "HOST")
		}
	}
	if rd["home_paths"] {
		s = homeRe.ReplaceAllString(s, "/home/USER")
		s = homeUnitRe.ReplaceAllString(s, "home_USER_") // unit id (パスから作った名前)
	}
	return s
}

func assessCommand(cfg *Config) []string {
	a := cfg.Assess
	switch a.Engine {
	case "claude":
		cmd := []string{"claude", "-p", "--output-format", "json", "--tools", "", "--no-session-persistence",
			"--strict-mcp-config"}
		if a.Model != "" {
			cmd = append(cmd, "--model", a.Model)
		}
		return cmd
	case "codex":
		cmd := []string{"codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", "--ephemeral",
			"--color", "never"}
		if a.Model != "" {
			cmd = append(cmd, "-m", a.Model)
		}
		return append(cmd, "-o", "{out}", "-")
	}
	if s, ok := a.Command.(string); ok {
		return []string{"/bin/sh", "-c", s}
	}
	return strList(a.Command)
}

func runAs(cmd []string, username string) ([]string, []string, error) {
	if username != "" && os.Geteuid() == 0 {
		u, err := user.Lookup(username)
		if err != nil {
			return nil, nil, err
		}
		env := []string{"HOME=" + u.HomeDir, "USER=" + username, "LOGNAME=" + username,
			"PATH=" + u.HomeDir + "/.local/bin:/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
		full := append([]string{"runuser", "-u", username, "--", "env", "-i"}, env...)
		return append(full, cmd...), env, nil
	}
	return cmd, os.Environ(), nil
}

func extractJSON(text string) ([]map[string]any, error) {
	// claude --output-format json は {"result": "..."} で包まれている
	var d any
	if json.Unmarshal([]byte(text), &d) == nil {
		switch x := d.(type) {
		case map[string]any:
			if r, ok := x["result"]; ok {
				text = str(r)
			}
		case []any:
			return toMaps(x), nil
		}
	}
	m := jsonArrRe.FindString(text)
	if m == "" {
		return nil, errors.New("JSON 配列が見つからない")
	}
	var arr []any
	if err := json.Unmarshal([]byte(m), &arr); err != nil {
		return nil, err
	}
	return toMaps(arr), nil
}

func toMaps(l []any) []map[string]any {
	var out []map[string]any
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// RunAssess は rows を評価し、key -> 評価 (キャッシュ済みも含む) を返す。limit < 0 なら max_per_run。
func RunAssess(cfg *Config, st *Store, rows []*Finding, limit int) (map[string]*Assessment, error) {
	a := cfg.Assess
	cache := MustDuration(a.Cache)
	t := Now()
	result := map[string]*Assessment{}
	var todo []*Finding
	for _, r := range rows {
		old, err := st.Assessment(r.Key)
		if err != nil {
			return nil, err
		}
		if old != nil && cache > 0 {
			if ts, ok := ParseISO(old.TS); ok && t.Sub(ts).Seconds() < float64(cache) {
				result[r.Key] = old
				continue
			}
		}
		todo = append(todo, r)
	}
	if limit < 0 {
		limit = a.MaxPerRun
	}
	if len(todo) > limit {
		todo = todo[:limit]
	}
	if len(todo) == 0 {
		return result, nil
	}
	var exes map[string]bool
	if a.IncludeHostContext {
		exes = RunningExecutables()
	}
	type item map[string]any
	var items []item
	for i, r := range todo {
		var fixed any
		if r.Fixed != "" {
			fixed = r.Fixed
		}
		var epss any
		if r.EPSS != nil {
			epss = *r.EPSS
		}
		it := item{"id": strconv.Itoa(i), "vuln": r.VulnID, "package": r.Pkg, "type": r.PkgType,
			"version": r.Version, "fixed": fixed, "severity": r.Severity, "kev": r.KEV != 0, "epss": epss,
			"title": r.Title, "location": redact(r.Location, cfg), "target": redact(r.Unit, cfg)}
		if a.IncludeHostContext && r.Location != "" {
			it["running_executable"] = exes[r.Location]
		}
		items = append(items, it)
	}
	osName := getOr(OSRelease("/"), "PRETTY_NAME", "Linux")
	lang := "English"
	if a.Language == "ja" {
		lang = "日本語"
	}
	var ib strings.Builder
	enc := json.NewEncoder(&ib)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	enc.Encode(items)
	prompt := strings.NewReplacer("{os}", osName, "{lang}", lang, "{items}", strings.TrimSpace(ib.String())).Replace(assessPrompt)

	td, err := os.MkdirTemp("", "sbomops-assess-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(td)
	out := filepath.Join(td, "out.txt")
	var cmd []string
	for _, c := range assessCommand(cfg) {
		cmd = append(cmd, strings.ReplaceAll(c, "{out}", out))
	}
	cmd, env, err := runAs(cmd, a.RunAs)
	if err != nil {
		return nil, err
	}
	if a.RunAs != "" && os.Geteuid() == 0 {
		if u, err := user.Lookup(a.RunAs); err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			os.Chown(td, uid, -1)
		}
	}
	logInfo("assess: %s で %d 件を評価", a.Engine, len(todo))
	to := MustDuration(a.Timeout)
	if to == 0 {
		to = 900
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(to)*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Env, c.Dir = env, td
	c.Stdin = strings.NewReader(prompt)
	var so, se strings.Builder
	c.Stdout, c.Stderr = &so, &se
	runErr := c.Run()
	text := so.String()
	if b, err := os.ReadFile(out); err == nil {
		text = string(b)
	}
	if runErr != nil {
		msg := se.String()
		if msg == "" {
			msg = so.String()
		}
		rc := -1
		if ee, ok := runErr.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		}
		return nil, fmt.Errorf("%s 失敗 (rc=%d): %s", a.Engine, rc, tailRunes(msg, 300))
	}
	ans, err := extractJSON(text)
	if err != nil {
		return nil, err
	}
	ts := ISO(t)
	for _, x := range ans {
		idx, err := strconv.Atoi(str(x["id"]))
		if err != nil || idx < 0 || idx >= len(todo) {
			continue
		}
		if p := str(x["priority"]); p != "P1" && p != "P2" && p != "P3" && p != "P4" {
			continue
		}
		r := todo[idx]
		if err := st.SaveAssessment(r.Key, ts, a.Engine, x); err != nil {
			return nil, err
		}
		if as, err := st.Assessment(r.Key); err == nil && as != nil {
			result[r.Key] = as
		}
	}
	n := 0
	for _, r := range todo {
		if result[r.Key] != nil {
			n++
		}
	}
	logInfo("assess: %d 件の評価を保存", n)
	return result, nil
}
