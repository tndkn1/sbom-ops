package sbomops

// スキャン対象の展開 (path_glob / running-images を具体的な単位に分ける) と実行周期の判定

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// Unit は 1 回の syft 実行に対応する単位。
type Unit struct {
	ID         string // 状態 DB・ファイル名に使う一意な名前
	Group      string // 設定上の target id
	Type       string // os-packages | dir | image
	Source     string // syft に渡すソース (dir:/usr/local, docker:nginx:1 など)
	Root       string // location を絶対パスに直すための基点 (dir 以外は "")
	Every      int64
	MaxRuntime int64
	MemMax     int64
	SyftArgs   []string
	Digest     string // イメージの場合の ID (変わったら作り直す)
}

// Skip は調査対象から外したもの。
type Skip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// excludes は絶対パスの除外を syft の書式 (./rel/**) にする。root の外のものは捨てる。
func excludes(root string, patterns []string) []string {
	out := []string{}
	root = strings.TrimRight(root, "/")
	if root == "" {
		root = "/"
	}
	for _, p := range patterns {
		if strings.HasPrefix(p, "./") || strings.HasPrefix(p, "**") {
			out = append(out, p)
			continue
		}
		if !strings.HasPrefix(p, "/") {
			out = append(out, "./"+p)
			continue
		}
		var rel string
		switch {
		case root == "/":
			rel = strings.TrimLeft(p, "/")
		case p == root || strings.HasPrefix(p, root+"/"):
			if len(p) > len(root)+1 {
				rel = p[len(root)+1:]
			}
		default:
			continue
		}
		if rel == "" {
			continue
		}
		if strings.ContainsAny(rel, "*?[") {
			out = append(out, "./"+rel)
		} else {
			out = append(out, "./"+rel+"/**")
		}
	}
	return out
}

func flagEx(ex []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range ex {
		if !seen[e] {
			seen[e] = true
			out = append(out, "--exclude", e)
		}
	}
	return out
}

// ExpandTargets は (単位の一覧, 展開に失敗した target id) を返す。失敗した target の既存の単位は解消扱いにしない。
// skipped が nil でなければ、調査対象から外したものを追加する。
func ExpandTargets(cfg *Config, withImages bool, skipped *[]Skip) ([]Unit, map[string]bool) {
	skip := func(name, why string) {
		if skipped != nil {
			*skipped = append(*skipped, Skip{name, why})
		}
	}
	res := cfg.Resources
	var units []Unit
	failed := map[string]bool{}
	for _, t := range cfg.Targets {
		if !t.Enabled {
			skip(t.ID, "無効 (enabled: false)")
			continue
		}
		every := MustDuration(t.Every)
		maxrt := MustDuration(t.MaxRuntime)
		mem := MustSize(t.MemMax)
		if isOff(t.MemMax) {
			mem = MustSize(res.MemMax)
		}
		args := append([]string{}, t.SyftArgs...)
		switch t.Type {
		case "os-packages":
			// パッケージ DB と os-release だけを一時ディレクトリに写してから読む (scan.go)
			root := str(t.Path)
			if root == "" {
				root = "/"
			}
			a := []string{"--override-default-catalogers", "os",
				"--select-catalogers", "-rpm-archive-cataloger,-deb-archive-cataloger"}
			units = append(units, Unit{t.ID, t.ID, t.Type, "dir:" + root, root, every, maxrt, mem, append(a, args...), ""})
		case "dir":
			var paths []string
			paths = append(paths, strList(t.Path)...)
			for _, g := range strList(t.PathGlob) {
				var ms []string
				for _, p := range pyGlob(g) {
					if isDir(p) {
						ms = append(ms, strings.TrimRight(p, "/"))
					}
				}
				sort.Strings(ms)
				paths = append(paths, ms...)
			}
			var kept []string
			for _, p := range paths {
				hit := false
				for _, s := range t.Skip {
					if fnmatch(p, s) {
						hit = true
						break
					}
				}
				if hit {
					skip(fmt.Sprintf("%s: %s", t.ID, p), "skip に一致")
				} else {
					kept = append(kept, p)
				}
			}
			multi := truthy(t.PathGlob) || len(kept) > 1
			for _, p := range kept {
				if !isDir(p) {
					logInfo("-- %s: %s がない (スキップ)", t.ID, p)
					skip(fmt.Sprintf("%s: %s", t.ID, p), "パスがない")
					continue
				}
				uid := t.ID
				if multi {
					uid = t.ID + ":" + SafeName(strings.Trim(p, "/"))
				}
				// sbomops 自身のデータ (SBOM ファイル) を syft の sbom-cataloger が読まないように外す
				ex := append(append([]string{}, t.Exclude...), "./**/.git/**", cfg.DataDir)
				if strings.TrimRight(p, "/") == "" {
					ex = append(ex, SystemExcludes...)
				}
				units = append(units, Unit{uid, t.ID, t.Type, "dir:" + p, p, every, maxrt, mem,
					append(flagEx(excludes(p, ex)), args...), ""})
			}
		case "image":
			ref := t.Ref
			src := "registry:" + ref
			scheme, _, _ := strings.Cut(ref, ":")
			if contains([]string{"docker", "podman", "containerd", "registry", "oci-archive", "docker-archive", "oci-dir"}, scheme) {
				src = ref
			}
			units = append(units, Unit{t.ID, t.ID, "image", src, "", every, maxrt, mem, args, ""})
		case "running-images":
			if !withImages {
				failed[t.ID] = true
				continue
			}
			rt := t.Runtime
			if rt == "" {
				rt = ContainerRuntime()
			}
			if rt == "" {
				logWarn("-- %s: docker / podman が使えない (スキップ)", t.ID)
				skip(t.ID, "docker / podman が使えない")
				failed[t.ID] = true
				continue
			}
			imgs, err := RunningImages(rt)
			if err != nil {
				logWarn("-- %s: %v", t.ID, err)
				skip(t.ID, "稼働中イメージを取得できない: "+truncRunes(err.Error(), 100))
				failed[t.ID] = true
				continue
			}
			for _, im := range imgs {
				units = append(units, Unit{t.ID + ":" + SafeName(im[0]), t.ID, "image", rt + ":" + im[0], "",
					every, maxrt, mem, args, im[1]})
			}
		}
	}
	return units, failed
}

// Due は作り直しが必要な単位を、期限切れの長いものから並べて返す。
func Due(units []Unit, state map[string]*UnitState, nowTS float64, force bool) []Unit {
	type sc struct {
		over float64
		u    Unit
	}
	var scored []sc
	for _, u := range units {
		st := state[u.ID]
		if st == nil {
			st = &UnitState{}
		}
		last := st.LastScanTS
		if force || last == 0 || st.SbomPath == "" || !exists(st.SbomPath) {
			scored = append(scored, sc{math.Inf(1), u})
			continue
		}
		if u.Digest != "" && st.Digest != u.Digest {
			scored = append(scored, sc{math.Inf(1), u})
			continue
		}
		// 毎日同じ時刻に動かすので、周期の 1 時間手前を過ぎていれば対象にする
		over := nowTS - last - float64(u.Every-3600)
		if over >= 0 {
			scored = append(scored, sc{over, u})
		}
	}
	sort.SliceStable(scored, func(i, j int) bool { return scored[i].over > scored[j].over })
	out := make([]Unit, len(scored))
	for i, s := range scored {
		out[i] = s.u
	}
	return out
}
