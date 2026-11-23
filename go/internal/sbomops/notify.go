package sbomops

// 通知 (Slack Incoming Webhook / Block Kit)。新しい通知先は Notifier を実装して buildNotifiers に足す。

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Item は通知する検出と種類 ("new" | "remind")。
type Item struct {
	Row  *Finding
	Kind string
}

// Step は syft / trivy 1 回分の時刻 (epoch 秒)。
type Step struct {
	Start float64 `json:"start"`
	End   float64 `json:"end"`
	Sec   float64 `json:"sec"`
	OK    bool    `json:"ok"`
}

// Timing は対象ごとの所要時間。SyftSkip は syft を動かさなかった理由。
type Timing struct {
	Unit     string  `json:"unit"`
	Syft     *Step   `json:"syft"`
	Trivy    *Step   `json:"trivy"`
	SyftSkip *string `json:"syft_skip"`
}

type Report struct {
	Host       string
	Date       string
	Items      []Item
	Resolved   []*Finding
	Warnings   []string
	Reboot     string
	OpenCounts map[string]int
	Assess     map[string]*Assessment
	Failed     string
	Timings    []*Timing
	Skipped    []Skip
}

func (r *Report) Empty() bool {
	return len(r.Items) == 0 && len(r.Resolved) == 0 && len(r.Warnings) == 0 && r.Reboot == "" && r.Failed == ""
}

type Notifier interface {
	Name() string
	Send(rp *Report, dryRun bool) error
}

// buildNotifiers は notify.<名前>.enabled が true の通知先を作る (テストで差し替える)。
var buildNotifiers = func(cfg *Config) []Notifier {
	var out []Notifier
	if cfg.Notify.Slack.Enabled {
		out = append(out, &SlackNotifier{Cfg: cfg.Notify.Slack, Policy: cfg.Notify.Policy})
	}
	return out
}

// ---------------------------------------------------------------- Slack

var (
	sevIcon = map[string]string{"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:",
		"MEDIUM": ":large_yellow_circle:", "LOW": ":white_circle:", "UNKNOWN": ":white_circle:"}
	sevOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
	vkeySep  = regexp.MustCompile(`[.\-+~:_]`)
)

const (
	maxText   = 2900 // section の text は 3000 文字まで
	maxBlocks = 48   // 1 メッセージ 50 ブロックまで
)

type TextObj struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type Block struct {
	Type     string    `json:"type"`
	Text     *TextObj  `json:"text,omitempty"`
	Elements []TextObj `json:"elements,omitempty"`
}

type SlackPayload struct {
	Text   string  `json:"text"`
	Blocks []Block `json:"blocks"`
}

type SlackNotifier struct {
	Cfg    SlackCfg
	Policy Policy
}

func (n *SlackNotifier) Name() string { return "slack" }

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// vkeyLess は版の比較 (Python 版 _vkey: 数字の要素は数値、それ以外は文字列で、数字 < 文字列)。
func vkeyLess(a, b string) bool {
	pa, pb := vkeySep.Split(a, -1), vkeySep.Split(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		da, db := isDigits(pa[i]), isDigits(pb[i])
		switch {
		case da && db:
			if c := cmpDigits(pa[i], pb[i]); c != 0 {
				return c < 0
			}
		case da != db:
			return da
		case pa[i] != pb[i]:
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func pyFixed2(x float64) string { return strconv.FormatFloat(x, 'f', 2, 64) }

func tags(r *Finding, kind string) []string {
	var t []string
	if r.KEV != 0 {
		t = append(t, ":rotating_light:KEV")
	}
	if r.EPSS != nil && *r.EPSS >= 0.01 {
		t = append(t, "EPSS "+pyFixed2(*r.EPSS))
	}
	if kind == "remind" {
		t = append(t, "未対応 "+r.FirstSeen+"〜")
	} else {
		t = append(t, ":new:")
	}
	return t
}

func vid(r *Finding) string {
	if r.URL != "" {
		return "<" + r.URL + "|" + esc(r.VulnID) + ">"
	}
	return esc(r.VulnID)
}

func where(r *Finding) string {
	s := "\n      _" + esc(r.Unit) + "_"
	if r.Location != "" {
		s += " `" + esc(r.Location) + "`"
	}
	return s
}

func aiLine(a *Assessment) string {
	if a == nil {
		return ""
	}
	p := a.Priority
	if p == "" {
		p = "?"
	}
	s := "\n      :robot_face: *" + esc(p) + "* " + esc(truncRunes(a.Rationale, 160))
	if a.Action != "" {
		s += " — " + esc(truncRunes(a.Action, 120))
	}
	return s
}

func oneLine(r *Finding, kind string, a *Assessment) string {
	s := sevIcon[r.Severity] + " *" + vid(r) + "* `" + esc(r.Pkg) + "` " + esc(r.Version)
	if r.Fixed != "" {
		s += " → " + esc(r.Fixed)
	} else {
		s += " (修正版なし)"
	}
	return s + "  " + strings.Join(tags(r, kind), " ") + where(r) + aiLine(a)
}

// groupLine は同じ unit・パッケージ・場所の検出を 1 行にまとめる (先頭が最も優先度の高いもの)。
func groupLine(group []Item, assess map[string]*Assessment) string {
	r, kind := group[0].Row, group[0].Kind
	if len(group) == 1 {
		return oneLine(r, kind, assess[r.Key])
	}
	var ids []string
	for i, x := range group {
		if i == 4 {
			break
		}
		ids = append(ids, vid(x.Row))
	}
	idstr := strings.Join(ids, ", ")
	if len(group) > 4 {
		idstr += fmt.Sprintf(" ほか%d件", len(group)-4)
	}
	var fixes []string
	for _, x := range group {
		if x.Row.Fixed != "" {
			for _, f := range strings.Split(x.Row.Fixed, ",") {
				fixes = append(fixes, strings.TrimSpace(f))
			}
		}
	}
	top := group[0].Row.Severity
	for _, x := range group[1:] {
		if ordOf(x.Row.Severity) < ordOf(top) {
			top = x.Row.Severity
		}
	}
	s := sevIcon[top] + " `" + esc(r.Pkg) + "` " + esc(r.Version)
	// 全件を直すのに必要な版の目安として、最も大きい修正版を出す
	if len(fixes) > 0 {
		best := fixes[0]
		for _, f := range fixes[1:] {
			if vkeyLess(best, f) {
				best = f
			}
		}
		s += " → " + esc(best) + " 以上"
	} else {
		s += " (修正版なし)"
	}
	s += fmt.Sprintf("  *%d件* (%s)", len(group), idstr)
	var t []string
	kev, anyNew := false, false
	ep := 0.0
	first := ""
	for _, x := range group {
		if x.Row.KEV != 0 {
			kev = true
		}
		if x.Row.EPSS != nil && *x.Row.EPSS > ep {
			ep = *x.Row.EPSS
		}
		if x.Kind == "new" {
			anyNew = true
		}
		if first == "" || x.Row.FirstSeen < first {
			first = x.Row.FirstSeen
		}
	}
	if kev {
		t = append(t, ":rotating_light:KEV")
	}
	if ep >= 0.01 {
		t = append(t, "EPSS "+pyFixed2(ep))
	}
	if anyNew {
		t = append(t, ":new:")
	} else {
		t = append(t, "未対応 "+first+"〜")
	}
	var best *Assessment
	for _, x := range group {
		if a, ok := assess[x.Row.Key]; ok {
			best = a
			break
		}
	}
	return s + "  " + strings.Join(t, " ") + where(r) + aiLine(best)
}

func ordOf(sev string) int {
	if o, ok := sevOrder[sev]; ok {
		return o
	}
	return 9
}

func hms(ts float64) string {
	sec := int64(ts)
	return time.Unix(sec, 0).Format("15:04:05")
}

func stepText(name string, t *Step, skip string) string {
	if t == nil {
		if skip == "" {
			skip = "なし"
		}
		return name + " " + esc(skip)
	}
	mark := ""
	if !t.OK {
		mark = ":x: "
	}
	return fmt.Sprintf("%s%s %s〜%s (%s)", mark, name, hms(t.Start), hms(t.End), FmtDuration(t.Sec))
}

func timingLine(t *Timing) string {
	skip := ""
	if t.SyftSkip != nil {
		skip = *t.SyftSkip
	}
	return "`" + esc(t.Unit) + "`  " + stepText("syft", t.Syft, skip) + " / " + stepText("trivy", t.Trivy, "未実行")
}

func chunks(lines []string) []string {
	var out []string
	cur := ""
	curLen := 0
	for _, ln := range lines {
		l := runeLen(ln)
		if curLen+l+1 > maxText && cur != "" {
			out = append(out, cur)
			cur, curLen = "", 0
		}
		cur += ln + "\n"
		curLen += l + 1
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func section(text string) Block {
	return Block{Type: "section", Text: &TextObj{"mrkdwn", text}}
}

// Render は Python 版 SlackNotifier.render と同じペイロードを作る (spec/cases/slack で検証)。
func (n *SlackNotifier) Render(rp *Report) SlackPayload {
	sc, pol := n.Cfg, n.Policy
	nnew := 0
	for _, it := range rp.Items {
		if it.Kind == "new" {
			nnew++
		}
	}
	rem := len(rp.Items) - nnew
	title := fmt.Sprintf("SBOM %s %s", rp.Host, rp.Date)
	var summary string
	switch {
	case rp.Failed != "":
		summary = ":x: ジョブ失敗: " + rp.Failed
	case len(rp.Items) > 0:
		summary = fmt.Sprintf("通知 %d 件 (新規 %d / 継続 %d)", len(rp.Items), nnew, rem)
	default:
		summary = "通知対象なし"
	}
	if len(rp.Resolved) > 0 {
		summary += fmt.Sprintf(" / 解消 %d 件", len(rp.Resolved))
	}
	blocks := []Block{{Type: "header", Text: &TextObj{"plain_text", truncRunes(title, 150)}}}
	mention := ""
	on := map[string]bool{}
	for _, x := range sc.MentionOn {
		on[x] = true
	}
	if sc.Mention != "" {
		hit := rp.Failed != ""
		for _, it := range rp.Items {
			if hit {
				break
			}
			hit = (on["kev"] && it.Row.KEV != 0) || (on["critical"] && it.Row.Severity == "CRITICAL") ||
				(on["new"] && it.Kind == "new") || on["any"]
		}
		if hit {
			mention = sc.Mention + " "
		}
	}
	var ctx []string
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		if c := rp.OpenCounts[s]; c != 0 {
			ctx = append(ctx, fmt.Sprintf("%s %d", s, c))
		}
	}
	blocks = append(blocks, section(mention+summary))
	if len(ctx) > 0 {
		blocks = append(blocks, Block{Type: "context", Elements: []TextObj{
			{"mrkdwn", "未解消 (通知条件内): " + strings.Join(ctx, " / ")}}})
	}

	maxn := pol.MaxItems
	var glist [][]Item
	if pol.GroupByPackage {
		idx := map[[4]string]int{}
		for _, it := range rp.Items { // rp.Items は優先度順に並んでいる
			k := [4]string{it.Row.Unit, it.Row.Pkg, it.Row.Version, it.Row.Location}
			if i, ok := idx[k]; ok {
				glist[i] = append(glist[i], it)
			} else {
				idx[k] = len(glist)
				glist = append(glist, []Item{it})
			}
		}
	} else {
		for _, it := range rp.Items {
			glist = append(glist, []Item{it})
		}
	}
	var lines []string
	for i, g := range glist {
		if i >= maxn {
			break
		}
		lines = append(lines, groupLine(g, rp.Assess))
	}
	if len(glist) > maxn {
		rest := 0
		for _, g := range glist[max(maxn, 0):] {
			rest += len(g)
		}
		lines = append(lines, fmt.Sprintf("…ほか %d 件 (`sbomops findings` で一覧)", rest))
	}
	for _, c := range chunks(lines) {
		blocks = append(blocks, section(c))
	}

	if len(rp.Resolved) > 0 {
		rl := []string{"*解消 (パッチ適用済み・削除済み)*"}
		for i, r := range rp.Resolved {
			if i == 15 {
				break
			}
			rl = append(rl, fmt.Sprintf(":white_check_mark: %s `%s` _%s_", esc(r.VulnID), esc(r.Pkg), esc(r.Unit)))
		}
		if len(rp.Resolved) > 15 {
			rl = append(rl, fmt.Sprintf("…ほか %d 件", len(rp.Resolved)-15))
		}
		blocks = append(blocks, Block{Type: "divider"})
		for _, c := range chunks(rl) {
			blocks = append(blocks, section(c))
		}
	}
	if len(rp.Skipped) > 0 {
		sl := []string{"*調査対象外*"}
		for i, s := range rp.Skipped {
			if i == 20 {
				break
			}
			sl = append(sl, fmt.Sprintf(":no_entry_sign: `%s` %s", esc(s.Name), esc(s.Reason)))
		}
		if len(rp.Skipped) > 20 {
			sl = append(sl, fmt.Sprintf("…ほか %d 件", len(rp.Skipped)-20))
		}
		blocks = append(blocks, Block{Type: "divider"})
		for _, c := range chunks(sl) {
			blocks = append(blocks, section(c))
		}
	}
	var extra []string
	if rp.Reboot != "" {
		extra = append(extra, ":arrows_counterclockwise: 再起動待ち: "+esc(rp.Reboot))
	}
	for _, w := range rp.Warnings {
		extra = append(extra, ":warning: "+esc(w))
	}
	if len(extra) > 0 {
		blocks = append(blocks, Block{Type: "divider"})
		for _, c := range chunks(extra) {
			blocks = append(blocks, section(c))
		}
	}
	if len(rp.Timings) > 0 {
		tl := []string{"*調査時間* (開始〜終了)"}
		for _, t := range rp.Timings {
			tl = append(tl, timingLine(t))
		}
		blocks = append(blocks, Block{Type: "divider"})
		for _, c := range chunks(tl) {
			blocks = append(blocks, section(c))
		}
	}
	if len(blocks) > maxBlocks {
		blocks = append(blocks[:maxBlocks-1], Block{Type: "context", Elements: []TextObj{
			{"mrkdwn", "(長すぎるため省略)"}}})
	}
	return SlackPayload{Text: title + ": " + summary, Blocks: blocks}
}

func (n *SlackNotifier) Send(rp *Report, dryRun bool) error {
	payload := n.Render(rp)
	if dryRun {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return err
		}
		os.Stdout.Write(buf.Bytes())
		return nil
	}
	envName := n.Cfg.WebhookEnv
	if envName == "" {
		envName = "SLACK_WEBHOOK_URL"
	}
	url := os.Getenv(envName)
	if url == "" {
		return fmt.Errorf("Slack の Webhook URL がない (環境変数 %s)", n.Cfg.WebhookEnv)
	}
	body, _ := json.Marshal(payload)
	timeout := n.Cfg.Timeout
	if timeout == 0 {
		timeout = 20
	}
	c := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if t := strings.TrimSpace(string(b)); resp.StatusCode != 200 || (t != "ok" && t != "") {
		return fmt.Errorf("Slack 応答: %d %s", resp.StatusCode, truncRunes(string(b), 200))
	}
	return nil
}
