"""テスト用の偽 syft / trivy (実体は spec/fake/ にあり、Go 版のテストと共有する)。

偽 syft は $FAKE_STATE/version の中身 (1.0 など) を example パッケージの版として SBOM を書く。
偽 trivy は example の版が 1.0 なら CVE-2099-0001 (HIGH, 修正版 1.1) と CVE-2099-0002 (LOW) を返し、
1.1 以上なら何も返さない。これで「パッチ適用 → 解消」を再現する。
"""
from __future__ import annotations

import os
import stat
import sys

FAKE_DIR = os.path.join(os.path.dirname(__file__), "..", "spec", "fake")


def make(dirpath: str) -> tuple[str, str]:
    """spec/fake の偽ツールを、今の Python を使うように書き換えて dirpath に置く"""
    os.makedirs(dirpath, exist_ok=True)
    paths = []
    for name in ("syft", "trivy"):
        with open(os.path.join(FAKE_DIR, name)) as f:
            body = f.read().split("\n", 1)[1]
        p = os.path.join(dirpath, name)
        with open(p, "w") as f:
            f.write(f"#!{sys.executable}\n{body}")
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
        paths.append(p)
    return paths[0], paths[1]
