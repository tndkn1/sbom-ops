"""sbomops コマンド"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time

from . import config, pipeline, policy, targets
from .util import fmt_duration, load_env_file, log, setup_logging

USAGE = """\
sbomops run          期限の来た対象の SBOM を作り、全 SBOM を照合して通知する (日次の本体)
sbomops status       対象ごとのスキャン状況と未解消の件数
sbomops targets      設定から展開したスキャン単位と、次回スキャンの要否
sbomops findings     検出の一覧 (既定: 通知条件を満たす未解消のもの)
sbomops assess       通知対象を AI (claude / codex) で評価して表示
sbomops test-notify  テスト通知を送る (--dry-run でペイロードを表示するだけ)
"""


def _cfg(a) -> dict:
    path = config.find_config(a.config)
    cfg = config.load(path)
    if a.data_dir:
        cfg["data_dir"] = a.data_dir
    load_env_file(cfg.get("secrets_file"))
    return cfg


def cmd_run(a, cfg) -> int:
    only = set(a.only.split(",")) if a.only else None
    return pipeline.run(cfg, only=only, force=a.force, no_scan=a.no_scan, no_notify=a.no_notify,
                        dry_run=a.dry_run, do_assess=False if a.no_assess else None)


def cmd_status(a, cfg) -> int:
    st = pipeline.open_store(cfg)
    units = st.units()
    t = time.time()
    counts = {}
    for r in st.query("SELECT unit, class, eligible, severity, COUNT(*) n FROM findings "
                      "WHERE state='open' GROUP BY unit, class, eligible, severity"):
        c = counts.setdefault(r["unit"], {"active": 0, "notify": 0, "noise": 0, "suppressed": 0, "crit": 0})
        k = (r["class"] or "active").split(":")[0]
        c[k] = c.get(k, 0) + r["n"]
        if r["eligible"]:
            c["notify"] += r["n"]
            if r["severity"] == "CRITICAL":
                c["crit"] += r["n"]
    print(f"{'unit':38} {'scan':>8} {'status':7} {'sec':>6} {'RSS':>6}  {'notify':>6} {'crit':>4} "
          f"{'active':>6} {'noise':>6} {'supp':>5}")
    for uid in sorted(units):
        u = units[uid]
        age = fmt_duration(t - u["last_scan_ts"]) if u["last_scan_ts"] else "-"
        c = counts.get(uid, {})
        print(f"{uid[:38]:38} {age:>8} {u['last_scan_status'] or '-':7} "
              f"{int(u['last_scan_sec'] or 0):>6} {(u['last_scan_rss'] or 0) >> 20:>5}M  "
              f"{c.get('notify', 0):>6} {c.get('crit', 0):>4} {c.get('active', 0):>6} "
              f"{c.get('noise', 0):>6} {c.get('suppressed', 0):>5}")
    runs = st.query("SELECT * FROM runs ORDER BY id DESC LIMIT 5")
    print("\n直近の run:")
    for r in runs:
        print(f"  {r['started']}  {r['result']:13} {r['summary'] or ''}")
    print(f"\ntrivy DB: {st.get_meta('trivy_db_updated_at')}  OS: {st.get_meta('os_fingerprint')}")
    st.close()
    return 0


def cmd_targets(a, cfg) -> int:
    units, failed = targets.expand(cfg)
    st = pipeline.open_store(cfg)
    due = {u.id for u in targets.due(units, st.units(), time.time())}
    for u in units:
        print(f"{'*' if u.id in due else ' '} {u.id:40} {u.type:12} every={fmt_duration(u.every):5} {u.source}")
        if a.verbose:
            print(f"      syft args: {' '.join(u.syft_args)}")
    if failed:
        print(f"展開に失敗: {', '.join(sorted(failed))}")
    print("(* = 次回の run でスキャンする)")
    st.close()
    return 0


def cmd_findings(a, cfg) -> int:
    st = pipeline.open_store(cfg)
    where = ["state='open'"]
    if not a.all:
        where.append("eligible=1 AND class='active'")
    args = []
    if a.unit:
        where.append("unit LIKE ?")
        args.append(a.unit.replace("*", "%"))
    rows = st.query(f"SELECT * FROM findings WHERE {' AND '.join(where)}", args)
    rows.sort(key=lambda r: policy.sort_key(r))
    if a.json:
        print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=1))
    else:
        for r in rows[: a.limit or None]:
            tags = ("KEV " if r["kev"] else "") + (f"EPSS={r['epss']:.2f} " if r["epss"] else "")
            print(f"{r['severity']:8} {r['vuln_id']:20} {r['pkg'][:30]:30} {r['version'][:20]:20} "
                  f"→ {(r['fixed'] or '-')[:20]:20} {tags}{r['unit']} {r['class'] if a.all else ''}")
        print(f"計 {len(rows)} 件")
    st.close()
    return 0


def cmd_assess(a, cfg) -> int:
    from . import assess
    st = pipeline.open_store(cfg)
    rows = st.query("SELECT * FROM findings WHERE state='open' AND eligible=1 AND class='active'")
    rows.sort(key=lambda r: policy.sort_key(r))
    res = assess.assess(cfg, st, rows, limit=a.limit)
    for r in rows:
        x = res.get(r["key"])
        if x:
            print(f"{x['priority']} {r['vuln_id']:20} {r['pkg'][:28]:28} {r['unit']}\n"
                  f"   悪用: {x['exploitable']}  {x['rationale']}\n   対処: {x['action']}")
    st.close()
    return 0


def cmd_test_notify(a, cfg) -> int:
    from . import notify
    sample = {"key": "test", "unit": "os", "vuln_id": "CVE-0000-0000", "pkg": "example",
              "pkg_type": "ubuntu", "version": "1.0", "fixed": "1.1", "vstatus": "fixed",
              "severity": "HIGH", "title": "sbomops のテスト通知", "url": "", "location": "",
              "purl": "", "kev": 0, "epss": 0.02, "first_seen": dt.date.today().isoformat()}
    rp = notify.Report(host=cfg["host_label"], date=dt.date.today().isoformat(),
                       items=[(sample, "new")], warnings=["これはテスト通知です"])
    ns = notify.build(cfg)
    if not ns:
        if not a.dry_run:
            print("有効な通知先がありません (notify.slack.enabled: true を設定)", file=sys.stderr)
            return 1
        from .notify.slack import SlackNotifier
        ns = [SlackNotifier(cfg["notify"]["slack"], cfg["notify"]["policy"])]
    for n in ns:
        n.send(rp, dry_run=a.dry_run)
        print(f"{n.name}: {'表示のみ' if a.dry_run else '送信しました'}", file=sys.stderr)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sbomops", description="syft + trivy による SBOM 日次運用",
                                epilog=USAGE, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-c", "--config", help="設定ファイル (既定: $SBOMOPS_CONFIG, /etc/sbomops/config.yaml)")
    p.add_argument("--data-dir", help="data_dir を上書き")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="日次の本体")
    r.add_argument("--only", help="この単位 / target id だけスキャンする (カンマ区切り)")
    r.add_argument("--force", action="store_true", help="周期に関係なくスキャンする")
    r.add_argument("--no-scan", action="store_true", help="スキャンせず、既存の SBOM の照合と通知だけ")
    r.add_argument("--no-notify", action="store_true", help="通知しない (状態は更新する)")
    r.add_argument("--no-assess", action="store_true", help="AI 評価をしない")
    r.add_argument("--dry-run", action="store_true", help="通知を送らずペイロードを表示する (通知済みにしない)")
    sub.add_parser("status")
    sub.add_parser("targets")
    f = sub.add_parser("findings")
    f.add_argument("--all", action="store_true", help="ノイズ・受容・通知条件外も含める")
    f.add_argument("--unit", help="unit で絞り込む (* 可)")
    f.add_argument("--limit", type=int, default=0)
    f.add_argument("--json", action="store_true")
    s = sub.add_parser("assess")
    s.add_argument("--limit", type=int, default=None)
    t = sub.add_parser("test-notify")
    t.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)

    try:
        cfg = _cfg(a)
    except config.ConfigError as e:
        print(e, file=sys.stderr)
        return 2
    logfile = None
    if a.cmd == "run":
        logfile = os.path.join(cfg["data_dir"], "logs", f"run-{dt.date.today().isoformat()}.log")
    setup_logging(a.verbose, logfile)
    os.umask(0o077)
    fn = {"run": cmd_run, "status": cmd_status, "targets": cmd_targets, "findings": cmd_findings,
          "assess": cmd_assess, "test-notify": cmd_test_notify}[a.cmd]
    try:
        return fn(a, cfg)
    except pipeline.Locked as e:
        log.error("%s", e)
        return 3
    except KeyboardInterrupt:
        return 130

