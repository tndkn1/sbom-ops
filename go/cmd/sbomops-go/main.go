// sbomops-go は sbomops (Python 版) の Go 実装。設定・状態 DB・通知の形は Python 版と同じ。
package main

import (
	"os"

	"github.com/tndkn1/sbom-ops/go/internal/sbomops"
)

func main() {
	os.Exit(sbomops.Main(os.Args[1:], os.Stdout, os.Stderr))
}
