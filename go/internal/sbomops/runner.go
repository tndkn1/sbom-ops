package sbomops

// 外部コマンドを低優先度で実行し、RSS とタイムアウトを監視する。
//
// cgroup v1 の環境 (RHEL 8 の既定など) では systemd の MemoryMax が効かないため、
// プロセスグループ全体の RSS を /proc から合計し、上限を超えたらグループごと kill する。

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var pageSize = int64(os.Getpagesize())

// Result は外部コマンドの実行結果。
type Result struct {
	RC         int
	Elapsed    float64 // 秒
	PeakRSS    int64   // バイト
	Killed     string  // "mem" | "timeout" | ""
	StderrTail string
}

func groupRSS(pgid int) int64 {
	var total int64
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range ents {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile("/proc/" + name + "/stat")
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		// st[0]=state st[2]=pgrp ... st[21]=rss(pages)  (comm の後ろから数える)
		st := strings.Fields(string(b[i+1:]))
		if len(st) < 22 {
			continue
		}
		pg, err1 := strconv.Atoi(st[2])
		rss, err2 := strconv.ParseInt(st[21], 10, 64)
		if err1 == nil && err2 == nil && pg == pgid {
			total += rss * pageSize
		}
	}
	return total
}

func cmdPrefix(res Resources) []string {
	pre := append([]string{}, res.Wrap...)
	cls := res.IoniceClass
	if cls != "" && cls != "none" {
		if _, err := exec.LookPath("ionice"); err == nil {
			c := map[string]string{"idle": "3", "best-effort": "2", "realtime": "1"}[cls]
			if c == "" {
				c = "3"
			}
			pre = append(pre, "ionice", "-c", c)
			if cls == "best-effort" {
				pre = append(pre, "-n", "7")
			}
		}
	}
	// Python 版は子プロセスで os.nice() する。Go では fork 後に呼べないため nice コマンドを挟む
	if res.Nice != 0 {
		if _, err := exec.LookPath("nice"); err == nil {
			pre = append(pre, "nice", "-n", strconv.Itoa(res.Nice))
		}
	}
	return pre
}

// tailBuffer は末尾 n バイトだけを残す。
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	n   int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.n {
		t.buf = append([]byte{}, t.buf[len(t.buf)-t.n:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// RunOpts は RunCmd の追加指定。
type RunOpts struct {
	MemMax  int64
	Timeout int64 // 秒
	Env     map[string]string
	Stdout  io.Writer
	Stdin   []byte
	LogPath string // stderr を追記するファイル
}

// RunCmd は cmd を実行する。res は設定の resources。
func RunCmd(cmd []string, res Resources, o RunOpts) (Result, error) {
	full := append(cmdPrefix(res), cmd...)
	env := os.Environ()
	envMap := map[string]bool{}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		envMap[k] = true
	}
	for k, v := range o.Env {
		env = append(env, k+"="+v)
		envMap[k] = true
	}
	if o.MemMax > 0 && !envMap["GOMEMLIMIT"] {
		// Go 製ツール (syft/trivy) は GOMEMLIMIT で上限の手前から GC を効かせる
		env = append(env, fmt.Sprintf("GOMEMLIMIT=%dMiB", o.MemMax*3/4/(1<<20)))
	}
	logDebug("exec: %s", strings.Join(full, " "))
	c := exec.Command(full[0], full[1:]...)
	c.Env = env
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if o.Stdout != nil {
		c.Stdout = o.Stdout
	}
	if o.Stdin != nil {
		c.Stdin = bytes.NewReader(o.Stdin)
	}
	tail := &tailBuffer{n: 4000}
	var logf *os.File
	if o.LogPath != "" {
		f, err := os.OpenFile(o.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return Result{}, err
		}
		logf = f
		defer f.Close()
		c.Stderr = io.MultiWriter(f, tail)
	} else {
		c.Stderr = tail
	}
	start := time.Now()
	if err := c.Start(); err != nil {
		return Result{RC: 127, StderrTail: err.Error()}, nil
	}
	pid := c.Process.Pid
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	var peak int64
	killed := ""
	var werr error
loop:
	for {
		select {
		case werr = <-done:
			break loop
		case <-time.After(time.Second):
		}
		rss := groupRSS(pid)
		if rss > peak {
			peak = rss
		}
		if o.MemMax > 0 && rss > o.MemMax {
			killed = "mem"
		} else if o.Timeout > 0 && time.Since(start).Seconds() > float64(o.Timeout) {
			killed = "timeout"
		}
		if killed != "" {
			why := "時間切れ"
			if killed == "mem" {
				why = "メモリ上限超過"
			}
			logWarn("%s: %s のため停止 (RSS %dMiB)", filepath.Base(cmd[0]), why, rss>>20)
			syscall.Kill(-pid, syscall.SIGKILL)
			werr = <-done
			break
		}
	}
	_ = logf
	rc := 0
	if werr != nil {
		if ee, ok := werr.(*exec.ExitError); ok {
			rc = ee.ExitCode()
			if rc < 0 {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					rc = -int(ws.Signal())
				}
			}
		} else {
			rc = 1
		}
	}
	return Result{RC: rc, Elapsed: time.Since(start).Seconds(), PeakRSS: peak, Killed: killed,
		StderrTail: tail.String()}, nil
}
