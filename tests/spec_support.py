"""spec/ の共通テストデータを Python 版で読むための補助 (Go 版は go/internal/sbomops/spec_test.go)"""
from __future__ import annotations

import copy
import json
import os
import time

SPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "spec")


def load(rel: str):
    with open(os.path.join(SPEC, rel), encoding="utf-8") as f:
        return json.load(f)


def merge(base: dict, over: dict | None) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _subst(obj, i: int):
    if isinstance(obj, str):
        return obj.replace("{i}", str(i)).replace("{i%7}", str(i % 7))
    if isinstance(obj, dict):
        return {k: _subst(v, i) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, i) for v in obj]
    return obj


def report_from_json(c: dict):
    """slack ケースの report を Report にする。items の row は base_row に重ねる。
    repeat_items: {"count": n, "row": {...}, "kind": "new"} は {i} を 0..n-1 に置き換えて n 件足す"""
    from sbomops.notify.base import Report
    r = c["report"]
    base = c.get("base_row") or {}
    items = [(merge(base, x["row"]), x["kind"]) for x in r.get("items") or []]
    rep = r.get("repeat_items")
    if rep:
        items += [(merge(base, _subst(rep["row"], i)), rep["kind"]) for i in range(rep["count"])]
    return Report(
        host=r["host"], date=r["date"], items=items,
        resolved=[merge(base, x) for x in r.get("resolved") or []],
        warnings=list(r.get("warnings") or []), reboot=r.get("reboot"),
        open_counts=dict(r.get("open_counts") or {}), assess=dict(r.get("assess") or {}),
        failed=r.get("failed"), timings=list(r.get("timings") or []),
        skipped=[tuple(x) for x in r.get("skipped") or []])


def render_slack(c: dict) -> dict:
    from sbomops import config
    from sbomops.notify.slack import SlackNotifier
    os.environ["TZ"] = "UTC"
    time.tzset()
    sc = merge(config.DEFAULTS["notify"]["slack"], c.get("slack"))
    pol = merge(config.DEFAULTS["notify"]["policy"], c.get("policy"))
    return SlackNotifier(sc, pol).render(report_from_json(c))
