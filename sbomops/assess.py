"""Claude Code / Codex (または任意のコマンド) に検出を評価させる。

検出をまとめて 1 回のプロンプトにし、各検出の優先度・このホストで悪用されうるか・対処を JSON で返させる。
CLI にはツールを使わせない (claude は --tools "", codex は read-only サンドボックス)。
"""
from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import tempfile

from . import host
from .util import iso, log, now, parse_duration, parse_iso

PROMPT = """あなたはサーバ運用のセキュリティ担当です。以下は {os} のホストで SBOM (syft) と trivy が検出した脆弱性です。
各項目について、このホストでの対応優先度を評価してください。

判断の観点:
- KEV (既知の悪用あり) / EPSS (30日以内の悪用確率) / 重大度
- 脆弱なコンポーネントが実際に使われていそうか (場所、稼働プロセスとの関係、パッケージの種類)
- 修正版の有無と、更新の容易さ (OS パッケージの更新で済むか、アプリの再ビルドが要るか)

優先度の基準: P1=今日中に対応 / P2=今週中 / P3=定期メンテで対応 / P4=影響は小さい・監視のみ

出力は JSON 配列だけにしてください (前後に説明文を付けない)。各要素:
{{"id": "<項目の id>", "priority": "P1|P2|P3|P4", "exploitable_here": "yes|no|unknown",
  "rationale": "<{lang}で 120 文字以内の根拠>", "action": "<{lang}で 80 文字以内の対処>"}}

検出:
{items}
"""


def _redact(s: str, cfg: dict) -> str:
    rd = cfg["assess"].get("redact") or {}
    if not s:
        return s
    if rd.get("hostname"):
        hn = host.hostname()
        if hn:
            s = s.replace(hn, "HOST")
    if rd.get("home_paths"):
        s = re.sub(r"/home/[^/\s]+", "/home/USER", s)
        s = re.sub(r"\bhome_[^_/\s]+_", "home_USER_", s)   # unit id (パスから作った名前)
    return s


def _command(cfg: dict) -> list[str]:
    a = cfg["assess"]
    if a["engine"] == "claude":
        cmd = ["claude", "-p", "--output-format", "json", "--tools", "", "--no-session-persistence",
               "--strict-mcp-config"]
        if a.get("model"):
            cmd += ["--model", a["model"]]
        return cmd
    if a["engine"] == "codex":
        cmd = ["codex", "exec", "--sandbox", "read-only", "--skip-git-repo-check", "--ephemeral",
               "--color", "never"]
        if a.get("model"):
            cmd += ["-m", a["model"]]
        return cmd + ["-o", "{out}", "-"]
    c = a["command"]
    return c if isinstance(c, list) else ["/bin/sh", "-c", c]


def _run_as(cmd: list[str], user: str | None) -> tuple[list[str], dict]:
    env = dict(os.environ)
    if user and os.geteuid() == 0:
        pw = pwd.getpwnam(user)
        env = {"HOME": pw.pw_dir, "USER": user, "LOGNAME": user,
               "PATH": f"{pw.pw_dir}/.local/bin:/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
        return ["runuser", "-u", user, "--", "env", "-i", *[f"{k}={v}" for k, v in env.items()], *cmd], env
    return cmd, env


def _extract_json(text: str):
    # claude --output-format json は {"result": "..."} で包まれている
    try:
        d = json.loads(text)
        if isinstance(d, dict) and "result" in d:
            text = d["result"]
        elif isinstance(d, list):
            return d
    except ValueError:
        pass
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        raise ValueError("JSON 配列が見つからない")
    return json.loads(m.group(0))


def assess(cfg: dict, store, rows: list, limit: int | None = None) -> dict:
    """rows (findings の行) を評価し、key -> assessment 行 の辞書を返す (キャッシュ済みも含む)"""
    a = cfg["assess"]
    cache = parse_duration(a["cache"])
    t = now()
    result, todo = {}, []
    for r in rows:
        old = store.assessment(r["key"])
        if old and cache and (t - parse_iso(old["ts"])).total_seconds() < cache:
            result[r["key"]] = old
        else:
            todo.append(r)
    todo = todo[: (limit if limit is not None else int(a["max_per_run"]))]
    if not todo:
        return result
    exes = host.running_executables() if a.get("include_host_context") else set()
    items = []
    for i, r in enumerate(todo):
        it = {"id": str(i), "vuln": r["vuln_id"], "package": r["pkg"], "type": r["pkg_type"],
              "version": r["version"], "fixed": r["fixed"] or None, "severity": r["severity"],
              "kev": bool(r["kev"]), "epss": r["epss"], "title": r["title"],
              "location": _redact(r["location"], cfg), "target": _redact(r["unit"], cfg)}
        if a.get("include_host_context") and r["location"]:
            it["running_executable"] = r["location"] in exes
        items.append(it)
    osr = host.os_release()
    prompt = PROMPT.format(os=osr.get("PRETTY_NAME", "Linux"), lang="日本語" if a.get("language") == "ja" else "English",
                           items=json.dumps(items, ensure_ascii=False, indent=1))
    with tempfile.TemporaryDirectory(prefix="sbomops-assess-") as td:
        out = os.path.join(td, "out.txt")
        cmd = [c.replace("{out}", out) for c in _command(cfg)]
        cmd, env = _run_as(cmd, a.get("run_as"))
        if a.get("run_as") and os.geteuid() == 0:
            os.chown(td, pwd.getpwnam(a["run_as"]).pw_uid, -1)
        log.info("assess: %s で %d 件を評価", a["engine"], len(todo))
        p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, env=env, cwd=td,
                           timeout=parse_duration(a["timeout"]) or 900)
        text = open(out, encoding="utf-8").read() if os.path.exists(out) else p.stdout
    if p.returncode != 0:
        raise RuntimeError(f"{a['engine']} 失敗 (rc={p.returncode}): {(p.stderr or p.stdout)[-300:]}")
    ans = _extract_json(text)
    ts = iso(t)
    for x in ans:
        try:
            r = todo[int(x["id"])]
        except (KeyError, ValueError, IndexError, TypeError):
            continue
        if str(x.get("priority")) not in ("P1", "P2", "P3", "P4"):
            continue
        store.save_assessment(r["key"], ts, a["engine"], x)
        result[r["key"]] = store.assessment(r["key"])
    log.info("assess: %d 件の評価を保存", sum(1 for r in todo if r["key"] in result))
    return result
