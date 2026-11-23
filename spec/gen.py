#!/usr/bin/env python3
"""spec の期待値 (want) を Python 版から作り直す。

仕様を変えたら Python 版を直してこれを実行し、差分 (git diff spec/) を確認してからコミットする。
Go 版のテストは同じ期待値と比べるので、Go 側も直すまで CI が落ちる。
    python3 spec/gen.py
"""
from __future__ import annotations

import glob
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
os.environ["TZ"] = "UTC"

from sbomops import match  # noqa: E402
from tests.spec_support import report_from_json, render_slack  # noqa: E402


def dump(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def normalize_cases():
    for p in sorted(glob.glob(os.path.join(HERE, "cases", "normalize", "*.json"))):
        with open(p, encoding="utf-8") as f:
            c = json.load(f)
        with tempfile.TemporaryDirectory() as d:
            sp, tp = os.path.join(d, "s.json"), os.path.join(d, "t.json")
            dump(sp, c["sbom"])
            dump(tp, c["trivy"])
            recs = match.normalize(c["unit"], c["root"], tp, sp)
        c["want"] = sorted(recs, key=lambda r: r["key"])
        dump(p, c)


def slack_cases():
    for p in sorted(glob.glob(os.path.join(HERE, "cases", "slack", "*.json"))):
        with open(p, encoding="utf-8") as f:
            c = json.load(f)
        c["want"] = render_slack(c)
        dump(p, c)


if __name__ == "__main__":
    normalize_cases()
    slack_cases()
    print("spec の期待値を更新しました。git diff spec/ で確認してください")
