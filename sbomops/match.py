"""trivy で SBOM を脆弱性 DB と照合し、1検出1レコードに正規化する"""
from __future__ import annotations

import json
import os
import subprocess

from . import runner
from .scan import find_tool
from .util import log, parse_size, safe_name


def _base_args(cfg: dict, cache_dir: str) -> list[str]:
    a = ["--cache-dir", cache_dir, "--quiet", "--disable-telemetry", "--skip-version-check"]
    for repo in cfg["trivy"].get("db_repository") or []:
        a += ["--db-repository", repo]
    return a


def update_db(cfg: dict, data_dir: str) -> None:
    trivy = find_tool(cfg, "trivy")
    cache = os.path.join(data_dir, "trivy-cache")
    cmd = [trivy, "sbom", *_base_args(cfg, cache), "--download-db-only"]
    log.info("trivy DB を更新")
    r = runner.run(cmd, cfg["resources"], mem_max=parse_size(cfg["resources"]["mem_max"]), timeout=1800)
    if r.rc != 0:
        raise RuntimeError(f"trivy DB の更新に失敗: {r.stderr_tail.strip()[-500:]}")


def db_updated_at(cfg: dict, data_dir: str) -> str | None:
    trivy = find_tool(cfg, "trivy")
    cache = os.path.join(data_dir, "trivy-cache")
    try:
        r = subprocess.run([trivy, "version", "--cache-dir", cache, "--format", "json"],
                           capture_output=True, text=True, timeout=60)
        return (json.loads(r.stdout).get("VulnerabilityDB") or {}).get("UpdatedAt")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def match_unit(cfg: dict, unit_id: str, sbom_path: str, data_dir: str, day: str) -> str:
    """trivy sbom を実行し、結果 JSON のパスを返す"""
    trivy = find_tool(cfg, "trivy")
    cache = os.path.join(data_dir, "trivy-cache")
    outd = os.path.join(data_dir, "results", day)
    os.makedirs(outd, mode=0o700, exist_ok=True)
    out = os.path.join(outd, f"{safe_name(unit_id)}.trivy.json")
    cmd = [trivy, "sbom", *_base_args(cfg, cache), "--skip-db-update", "--scanners", "vuln",
           "--format", "json",
           "-o", out, *cfg["trivy"].get("extra_args", []), sbom_path]
    r = runner.run(cmd, cfg["resources"], mem_max=parse_size(cfg["resources"]["mem_max"]), timeout=3600)
    if r.rc != 0 or r.killed:
        raise RuntimeError(f"trivy 失敗 ({r.killed or 'rc=%d' % r.rc}): {r.stderr_tail.strip()[-300:]}")
    return out


def _locations(sbom_path: str) -> dict[str, str]:
    """CycloneDX の bom-ref → syft が記録したファイルの場所"""
    with open(sbom_path, encoding="utf-8") as f:
        bom = json.load(f)
    out = {}
    for c in bom.get("components") or []:
        locs = [p["value"] for p in c.get("properties") or []
                if p.get("name", "").startswith("syft:location:") and p["name"].endswith(":path")]
        if locs and c.get("bom-ref"):
            out[c["bom-ref"]] = locs[0]
    return out


def normalize(unit_id: str, unit_root: str, trivy_json: str, sbom_path: str) -> list[dict]:
    with open(trivy_json, encoding="utf-8") as f:
        data = json.load(f)
    locs = _locations(sbom_path)
    root = (unit_root or "").rstrip("/")
    recs: dict[str, dict] = {}
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            pid = v.get("PkgIdentifier") or {}
            loc = locs.get(pid.get("BOMRef", ""), "")
            if loc and root and not loc.startswith(root + "/"):
                loc = root + ("" if loc.startswith("/") else "/") + loc
            pkg = v.get("PkgName", "")
            key = "|".join([unit_id, v["VulnerabilityID"], pkg, loc])
            sev = v.get("Severity", "UNKNOWN")
            rec = {
                "key": key, "unit": unit_id, "vuln_id": v["VulnerabilityID"], "pkg": pkg,
                "pkg_type": res.get("Type", ""), "version": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion") or "", "vstatus": v.get("Status", ""),
                "severity": sev, "title": (v.get("Title") or "")[:200],
                "url": v.get("PrimaryURL") or "", "location": loc, "purl": pid.get("PURL", ""),
                "_aliases": [x for x in v.get("VendorIDs") or [] if x.startswith("CVE-")],
            }
            # 同じ key が複数回出る (同じバイナリ内に同じモジュールが複数) 場合は 1 件にまとめる
            recs.setdefault(key, rec)
    return list(recs.values())
