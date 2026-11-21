"""日次の流れ: 期限の来た対象の SBOM 作成 → trivy DB 更新 → 全 SBOM の照合 → 分類 → 通知"""
from __future__ import annotations

import datetime as dt
import fcntl
import glob
import os
import shutil
import time

from . import host, match, notify, policy, scan, targets
from .enrich import Enricher
from .store import Store
from .util import fmt_duration, iso, log, now, parse_duration, parse_iso


class Locked(Exception):
    pass


def lock(data_dir: str):
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    f = open(os.path.join(data_dir, ".lock"), "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Locked("別の sbomops が実行中") from None
    return f


def open_store(cfg: dict) -> Store:
    return Store(os.path.join(cfg["data_dir"], "state.db"))


def scan_phase(cfg: dict, st: Store, units, only: set[str] | None, force: bool, warnings: list) -> None:
    data = cfg["data_dir"]
    state = st.units()
    if only:
        units = [u for u in units if u.id in only or u.group in only]
    todo = targets.due(units, state, time.time(), force=force)
    budget = parse_duration(cfg["run"]["scan_budget"])
    start = time.monotonic()
    log.info("scan: %d / %d 単位が対象", len(todo), len(units))
    deferred = []
    for u in todo:
        if budget and time.monotonic() - start > budget:
            deferred.append(u.id)
            continue
        try:
            path, r = scan.scan_unit(cfg, u, data)
            st.upsert_unit(u.id, sbom_path=path, digest=u.digest, last_scan_ts=time.time(),
                           last_scan_status="ok", last_scan_error=None, last_scan_sec=r.elapsed,
                           last_scan_rss=r.peak_rss)
        except Exception as e:  # noqa: BLE001
            log.error("scan %s 失敗: %s", u.id, e)
            st.upsert_unit(u.id, last_scan_status="failed", last_scan_error=str(e)[:500])
            warnings.append(f"スキャン失敗: {u.id}: {str(e)[:200]}")
    if deferred:
        log.warning("scan_budget を超えたため次回に回す: %s", ", ".join(deferred))
        warnings.append(f"時間切れで次回に回したスキャン {len(deferred)} 件: {', '.join(deferred[:5])}")


def match_phase(cfg: dict, st: Store, units, failed_groups: set[str], warnings: list,
                today: str) -> tuple[list[str], set[str]]:
    """全単位を照合して状態 DB を更新する。(今回解消した key, 照合できた unit) を返す"""
    data = cfg["data_dir"]
    try:
        match.update_db(cfg, data)
    except Exception as e:  # noqa: BLE001
        if not glob.glob(os.path.join(data, "trivy-cache", "db", "*.db")):
            raise
        warnings.append(f"trivy DB を更新できず、前回の DB で照合: {str(e)[:200]}")
    upd = match.db_updated_at(cfg, data)
    if upd:
        age = (now() - parse_iso(upd)).total_seconds()
        if age > (parse_duration(cfg["trivy"]["db_max_age"]) or 3 * 86400):
            warnings.append(f"trivy DB が古い ({upd})")
    st.set_meta("trivy_db_updated_at", upd)

    enr = Enricher(cfg, data)
    warnings.extend(enr.warnings)
    cls = policy.Classifier(cfg, dt.date.fromisoformat(today))
    pol = cfg["notify"]["policy"]
    state = st.units()
    ids = {u.id for u in units}
    resolved_all: list[str] = []
    matched: set[str] = set()
    for u in units:
        s = state.get(u.id) or {}
        sbom = s.get("sbom_path")
        if not sbom or not os.path.exists(sbom):
            continue
        try:
            out = match.match_unit(cfg, u.id, sbom, data, today)
            recs = match.normalize(u.id, u.root, out, sbom)
        except Exception as e:  # noqa: BLE001
            log.error("match %s 失敗: %s", u.id, e)
            st.upsert_unit(u.id, last_match_status="failed")
            warnings.append(f"照合失敗: {u.id}: {str(e)[:200]}")
            continue
        for r in recs:
            enr.apply(r)
        cls.prepare(recs, u.type)
        new, resolved = st.sync_unit(u.id, recs, today)
        resolved_all += resolved
        for r in recs:
            c = cls.classify(r, u.type)
            row = st.get(r["key"])
            st.set_class(r["key"], c, c == "active" and policy.eligible(row, pol))
        st.commit()
        st.upsert_unit(u.id, grp=u.group, type=u.type, source=u.source, root=u.root, every=u.every,
                       last_match_ts=time.time(), last_match_status="ok")
        matched.add(u.id)
        log.info("match %s: %d 件 (新規 %d, 解消 %d)", u.id, len(recs), len(new), len(resolved))

    # 設定から消えた単位 (コンテナ停止・ディレクトリ削除など) の検出は解消扱いにする
    for uid, s in state.items():
        if uid not in ids and (s.get("grp") or uid.split(":")[0]) not in failed_groups:
            gone = st.resolve_unit(uid, today)
            if gone:
                log.info("対象から外れた %s の %d 件を解消扱いにする", uid, len(gone))
                resolved_all += gone
            st.db.execute("DELETE FROM units WHERE id=?", (uid,))
    st.commit()
    if cls.expired_accepts:
        warnings.append(f"受容期限が切れた検出 {len(set(cls.expired_accepts))} 件 (通常の通知対象に戻した)")
    return resolved_all, matched


def stale_warnings(cfg: dict, st: Store, units) -> list[str]:
    out = []
    fac = float(cfg["run"].get("stale_factor", 2))
    state = st.units()
    t = time.time()
    for u in units:
        s = state.get(u.id) or {}
        last = s.get("last_scan_ts")
        if last and t - last > u.every * fac:
            out.append(f"SBOM が古い: {u.id} ({fmt_duration(t - last)} 前)")
    return out


def build_report(cfg: dict, st: Store, resolved_keys: list[str], warnings: list[str], today: str) -> notify.Report:
    pol = cfg["notify"]["policy"]
    t = now()
    rows = st.query("SELECT * FROM findings WHERE state='open' AND eligible=1 AND class='active'")
    items = []
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        k = policy.should_notify(r, pol, t)
        if k:
            items.append((r, k))
    resolved = []
    if pol.get("report_resolved") and resolved_keys:
        for k in set(resolved_keys):
            r = st.get(k)
            if r and r["last_notified"]:
                resolved.append(r)
    rp = notify.Report(host=cfg["host_label"], date=today, items=items, resolved=resolved,
                       warnings=warnings if pol.get("notify_warnings", True) else [],
                       open_counts=counts)
    if pol.get("notify_reboot_required", True):
        rp.reboot = host.reboot_required()
    return rp


def send(cfg: dict, st: Store, rp: notify.Report, dry_run: bool) -> int:
    pol = cfg["notify"]["policy"]
    rp.items.sort(key=lambda x: policy.sort_key(x[0], rp.assess))
    rp.resolved.sort(key=lambda r: policy.sort_key(r))
    if rp.empty() and pol.get("quiet_when_empty", True) and not dry_run:
        log.info("通知対象なし (quiet_when_empty のため送信しない)")
        return 0
    ns = notify.build(cfg)
    if not ns:
        log.warning("有効な通知先がない (notify.slack.enabled)")
        if dry_run:
            from .notify.slack import SlackNotifier
            ns = [SlackNotifier(cfg["notify"]["slack"], pol)]
    errors = 0
    for n in ns:
        try:
            n.send(rp, dry_run=dry_run)
            log.info("通知 %s: %d 件%s", n.name, len(rp.items), " (dry-run)" if dry_run else "")
        except Exception as e:  # noqa: BLE001
            errors += 1
            log.error("通知 %s 失敗: %s", n.name, e)
    if not dry_run and ns and errors < len(ns):
        st.mark_notified([r["key"] for r, _ in rp.items], iso(now()))
    return errors


def retention(cfg: dict, today: dt.date | None = None) -> None:
    """古い照合結果 (results/<日付>/) と実行ログ (logs/run-<日付>.log) を消す"""
    ret = cfg["retention"]
    today = today or dt.date.today()
    rdays = int(ret.get("results_days", 14))
    ldays = int(ret.get("logs_days") or rdays)   # 未指定なら results_days と同じ
    limit = (today - dt.timedelta(days=rdays)).isoformat()
    for d in glob.glob(os.path.join(cfg["data_dir"], "results", "????-??-??")):
        if os.path.basename(d) < limit:
            shutil.rmtree(d, ignore_errors=True)
    limit = (today - dt.timedelta(days=ldays)).isoformat()
    n = 0
    for f in glob.glob(os.path.join(cfg["data_dir"], "logs", "run-????-??-??.log")):
        if os.path.basename(f)[4:14] < limit:
            try:
                os.unlink(f)
                n += 1
            except OSError as e:
                log.warning("ログを消せない: %s (%s)", f, e)
    if n:
        log.info("retention: %d 日より古い実行ログ %d 件を削除", ldays, n)


def run(cfg: dict, *, only=None, force=False, no_scan=False, no_notify=False, dry_run=False,
        do_assess=None) -> int:
    data = cfg["data_dir"]
    lk = lock(data)
    st = open_store(cfg)
    today = dt.date.today().isoformat()
    rid = st.start_run(iso(now()))
    warnings: list[str] = []
    summary = {}
    try:
        host.log_summary()
        fp = host.os_fingerprint()
        prev = st.get_meta("os_fingerprint")
        if prev and prev != fp and cfg["run"].get("rescan_on_os_change", True):
            log.warning("OS が変わった (%s → %s)。全対象を作り直す", prev, fp)
            warnings.append(f"OS の変更を検知 ({prev} → {fp})。全対象の SBOM を作り直した")
            force = True
        units, failed_groups = targets.expand(cfg)
        if not units:
            raise RuntimeError("スキャン対象がない (targets を設定してください)")
        if not no_scan:
            scan_phase(cfg, st, units, only, force, warnings)
        st.set_meta("os_fingerprint", fp)
        resolved, matched = match_phase(cfg, st, units, failed_groups, warnings, today)
        warnings += stale_warnings(cfg, st, units)
        rp = build_report(cfg, st, resolved, warnings, today)
        if cfg["assess"]["enabled"] if do_assess is None else do_assess:
            from . import assess
            try:
                rp.assess = assess.assess(cfg, st, [r for r, _ in rp.items])
            except Exception as e:  # noqa: BLE001
                log.error("assess 失敗: %s", e)
                rp.warnings.append(f"AI 評価に失敗: {str(e)[:200]}")
        summary = {"units": len(units), "matched": len(matched), "notify": len(rp.items),
                   "resolved": len(rp.resolved), "warnings": len(rp.warnings), "open": rp.open_counts}
        errs = 0 if no_notify else send(cfg, st, rp, dry_run)
        retention(cfg)
        result = "ok" if not errs and not rp.warnings else ("notify_failed" if errs else "warn")
        st.finish_run(rid, iso(now()), result, summary)
        log.info("完了 result=%s %s", result, summary)
        return 1 if errs else 0
    except Exception as e:
        log.exception("run 失敗")
        st.finish_run(rid, iso(now()), "failed", {"error": str(e)})
        if not no_notify:
            rp = notify.Report(host=cfg["host_label"], date=today, failed=str(e)[:300], warnings=warnings)
            try:
                send(cfg, st, rp, dry_run)
            except Exception:  # noqa: BLE001
                log.exception("失敗通知も送れなかった")
        return 2
    finally:
        st.close()
        lk.close()
