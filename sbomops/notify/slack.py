"""Slack Incoming Webhook への通知 (Block Kit)"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .base import Notifier, Report

SEV_ICON = {"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:", "MEDIUM": ":large_yellow_circle:",
            "LOW": ":white_circle:", "UNKNOWN": ":white_circle:"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
MAX_TEXT = 2900      # section の text は 3000 文字まで
MAX_BLOCKS = 48      # 1 メッセージ 50 ブロックまで


def _vkey(v: str):
    return [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.\-+~:_]", v)]


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _tags(r, kind: str) -> list[str]:
    tags = []
    if r["kev"]:
        tags.append(":rotating_light:KEV")
    if r["epss"] is not None and r["epss"] >= 0.01:
        tags.append(f"EPSS {r['epss']:.2f}")
    tags.append(f"未対応 {r['first_seen']}〜" if kind == "remind" else ":new:")
    return tags


def _vid(r) -> str:
    return f"<{r['url']}|{_esc(r['vuln_id'])}>" if r["url"] else _esc(r["vuln_id"])


def _where(r) -> str:
    return f"\n      _{_esc(r['unit'])}_" + (f" `{_esc(r['location'])}`" if r["location"] else "")


def _ai(a) -> str:
    if not a:
        return ""
    s = f"\n      :robot_face: *{_esc(a['priority'] or '?')}* {_esc((a['rationale'] or '')[:160])}"
    if a["action"]:
        s += f" — {_esc(a['action'][:120])}"
    return s


def _line(r, kind: str, a) -> str:
    s = f"{SEV_ICON.get(r['severity'], '')} *{_vid(r)}* `{_esc(r['pkg'])}` {_esc(r['version'])}"
    s += f" → {_esc(r['fixed'])}" if r["fixed"] else " (修正版なし)"
    return s + "  " + " ".join(_tags(r, kind)) + _where(r) + _ai(a)


def _group_line(group: list, assess: dict) -> str:
    """同じ unit・パッケージ・場所の検出を 1 行にまとめる (先頭が最も優先度の高いもの)"""
    r, kind = group[0]
    if len(group) == 1:
        return _line(r, kind, assess.get(r["key"]))
    ids = ", ".join(_vid(x) for x, _ in group[:4]) + (f" ほか{len(group) - 4}件" if len(group) > 4 else "")
    fixes = [f.strip() for x, _ in group if x["fixed"] for f in x["fixed"].split(",")]
    top = min((x["severity"] for x, _ in group), key=lambda v: SEV_ORDER.get(v, 9))
    s = f"{SEV_ICON.get(top, '')} `{_esc(r['pkg'])}` {_esc(r['version'])}"
    # 全件を直すのに必要な版の目安として、最も大きい修正版を出す
    s += f" → {_esc(max(fixes, key=_vkey))} 以上" if fixes else " (修正版なし)"
    s += f"  *{len(group)}件* ({ids})"
    tags = []
    if any(x["kev"] for x, _ in group):
        tags.append(":rotating_light:KEV")
    ep = max((x["epss"] or 0) for x, _ in group)
    if ep >= 0.01:
        tags.append(f"EPSS {ep:.2f}")
    tags.append(":new:" if any(k == "new" for _, k in group) else f"未対応 {min(x['first_seen'] for x, _ in group)}〜")
    best = next((assess[x["key"]] for x, _ in group if x["key"] in assess), None)
    return s + "  " + " ".join(tags) + _where(r) + _ai(best)


def _chunks(lines: list[str]) -> list[str]:
    out, cur = [], ""
    for ln in lines:
        if len(cur) + len(ln) + 1 > MAX_TEXT and cur:
            out.append(cur)
            cur = ""
        cur += ln + "\n"
    if cur:
        out.append(cur)
    return out


class SlackNotifier(Notifier):
    name = "slack"

    def render(self, rp: Report) -> dict:
        sc = self.cfg
        pol = self.policy
        new = sum(1 for _, k in rp.items if k == "new")
        rem = len(rp.items) - new
        title = f"SBOM {rp.host} {rp.date}"
        if rp.failed:
            summary = f":x: ジョブ失敗: {rp.failed}"
        elif rp.items:
            summary = f"通知 {len(rp.items)} 件 (新規 {new} / 継続 {rem})"
        else:
            summary = "通知対象なし"
        if rp.resolved:
            summary += f" / 解消 {len(rp.resolved)} 件"
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": title[:150]}}]
        mention = ""
        on = set(sc.get("mention_on") or [])
        if sc.get("mention") and (rp.failed or any(
                ("kev" in on and r["kev"]) or ("critical" in on and r["severity"] == "CRITICAL")
                or ("new" in on and k == "new") or ("any" in on) for r, k in rp.items)):
            mention = sc["mention"] + " "
        oc = rp.open_counts
        ctx = " / ".join(f"{s} {oc[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if oc.get(s))
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": mention + summary}})
        if ctx:
            blocks.append({"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"未解消 (通知条件内): {ctx}"}]})

        maxn = int(pol.get("max_items", 30))
        if pol.get("group_by_package", True):
            groups: dict = {}
            for r, k in rp.items:   # rp.items は優先度順に並んでいる
                groups.setdefault((r["unit"], r["pkg"], r["version"], r["location"]), []).append((r, k))
            glist = list(groups.values())
        else:
            glist = [[x] for x in rp.items]
        lines = [_group_line(g, rp.assess) for g in glist[:maxn]]
        if len(glist) > maxn:
            rest = sum(len(g) for g in glist[maxn:])
            lines.append(f"…ほか {rest} 件 (`sbomops findings` で一覧)")
        for c in _chunks(lines):
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": c}})

        if rp.resolved:
            rl = [f":white_check_mark: {_esc(r['vuln_id'])} `{_esc(r['pkg'])}` _{_esc(r['unit'])}_"
                  for r in rp.resolved[:15]]
            if len(rp.resolved) > 15:
                rl.append(f"…ほか {len(rp.resolved) - 15} 件")
            blocks.append({"type": "divider"})
            for c in _chunks(["*解消 (パッチ適用済み・削除済み)*"] + rl):
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": c}})
        extra = []
        if rp.reboot:
            extra.append(f":arrows_counterclockwise: 再起動待ち: {_esc(rp.reboot)}")
        extra += [f":warning: {_esc(w)}" for w in rp.warnings]
        if extra:
            blocks.append({"type": "divider"})
            for c in _chunks(extra):
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": c}})
        if len(blocks) > MAX_BLOCKS:
            blocks = blocks[:MAX_BLOCKS - 1] + [{"type": "context", "elements": [
                {"type": "mrkdwn", "text": "(長すぎるため省略)"}]}]
        return {"text": f"{title}: {summary}", "blocks": blocks}

    def send(self, rp: Report, dry_run: bool = False) -> None:
        payload = self.render(rp)
        if dry_run:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return
        url = os.environ.get(self.cfg.get("webhook_env") or "SLACK_WEBHOOK_URL")
        if not url:
            raise RuntimeError(f"Slack の Webhook URL がない (環境変数 {self.cfg.get('webhook_env')})")
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=int(self.cfg.get("timeout", 20))) as r:
            body = r.read().decode(errors="replace")
            if r.status != 200 or body.strip() not in ("ok", ""):
                raise RuntimeError(f"Slack 応答: {r.status} {body[:200]}")
