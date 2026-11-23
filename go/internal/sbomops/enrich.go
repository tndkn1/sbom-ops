package sbomops

// KEV (CISA) と EPSS (FIRST) を取得してキャッシュする。取得に失敗したら前回のキャッシュを使う。

import (
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const userAgent = "sbomops/1.0"

func fetchCached(url, path string, maxAge int64) string {
	if st, err := os.Stat(path); err == nil && time.Since(st.ModTime()).Seconds() < float64(maxAge) {
		return path
	}
	err := func() error {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		c := &http.Client{Timeout: 60 * time.Second}
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return AtomicWrite(path, b, 0o644)
	}()
	if err == nil {
		return path
	}
	if exists(path) {
		logWarn("取得失敗のため前回のキャッシュを使う: %s (%v)", url, err)
		return path
	}
	logWarn("取得失敗: %s (%v)", url, err)
	return ""
}

type Enricher struct {
	KEV      map[string]bool
	EPSS     map[string]float64
	Warnings []string
}

func NewEnricher(cfg *Config, dataDir string) *Enricher {
	e := cfg.Enrich
	d := filepath.Join(dataDir, "feeds")
	age := MustDuration(e.Refresh)
	if age == 0 {
		age = 86400
	}
	en := &Enricher{KEV: map[string]bool{}, EPSS: map[string]float64{}}
	if e.KEV {
		if p := fetchCached(e.KEVURL, filepath.Join(d, "kev.json"), age); p != "" {
			var v struct {
				Vulnerabilities []struct {
					CveID string `json:"cveID"`
				} `json:"vulnerabilities"`
			}
			if b, err := os.ReadFile(p); err == nil && json.Unmarshal(b, &v) == nil {
				for _, x := range v.Vulnerabilities {
					en.KEV[x.CveID] = true
				}
			}
		} else {
			en.Warnings = append(en.Warnings, "KEV リストを取得できない")
		}
	}
	if e.EPSS {
		if p := fetchCached(e.EPSSURL, filepath.Join(d, "epss.csv.gz"), age); p != "" {
			en.loadEPSS(p)
		} else {
			en.Warnings = append(en.Warnings, "EPSS を取得できない")
		}
	}
	logInfo("enrich: KEV %d 件, EPSS %d 件", len(en.KEV), len(en.EPSS))
	return en
}

func (en *Enricher) loadEPSS(p string) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return
	}
	b, err := io.ReadAll(gz)
	if err != nil {
		return
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	r := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil || len(recs) == 0 {
		return
	}
	ci, ei := -1, -1
	for i, h := range recs[0] {
		switch h {
		case "cve":
			ci = i
		case "epss":
			ei = i
		}
	}
	if ci < 0 || ei < 0 {
		return
	}
	for _, row := range recs[1:] {
		if len(row) <= ci || len(row) <= ei {
			continue
		}
		if v, err := strconv.ParseFloat(row[ei], 64); err == nil {
			en.EPSS[row[ci]] = v
		}
	}
}

// Apply は KEV / EPSS を検出に付ける (VendorIDs の CVE 別名も見る)。
func (en *Enricher) Apply(rec *Finding) {
	ids := append([]string{rec.VulnID}, rec.Aliases...)
	rec.Aliases = nil
	rec.KEV = 0
	var best *float64
	for _, i := range ids {
		if en.KEV[i] {
			rec.KEV = 1
		}
		if v, ok := en.EPSS[i]; ok && (best == nil || v > *best) {
			x := v
			best = &x
		}
	}
	rec.EPSS = best
}
