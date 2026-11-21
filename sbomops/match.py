"""trivy で SBOM を脆弱性 DB と照合し、1検出1レコードに正規化する"""
from __future__ import annotations

import json
import os
import re
import subprocess

from . import runner
from .scan import find_tool
from .util import log, parse_size, safe_name


OS_PURL = ("pkg:deb/", "pkg:rpm/", "pkg:apk/", "pkg:alpm/", "pkg:ebuild/")


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


def _purl_base(purl: str) -> str:
    """package-id など syft 固有の修飾子を除いた purl"""
    if "?" not in purl:
        return purl
    head, q = purl.split("?", 1)
    keep = [x for x in q.split("&") if not x.startswith("package-id=")]
    return head + ("?" + "&".join(keep) if keep else "")


def _locations(sbom_path: str) -> tuple[dict[str, str], dict[str, list[str]]]:
    """CycloneDX から (bom-ref → 場所, purl → 全ての場所) を作る。

    同じ purl のコンポーネントが複数の場所にある場合 (同じ Go モジュールを含む複数のバイナリなど)、
    trivy は 1 件にまとめて返し、どの bom-ref を使うかも一定しないため、purl から全ての場所を引けるようにする。
    """
    with open(sbom_path, encoding="utf-8") as f:
        bom = json.load(f)
    by_ref: dict[str, str] = {}
    by_purl: dict[str, set] = {}
    for c in bom.get("components") or []:
        locs = [p["value"] for p in c.get("properties") or []
                if p.get("name", "").startswith("syft:location:") and p["name"].endswith(":path")]
        if not locs:
            continue
        if c.get("bom-ref"):
            by_ref[c["bom-ref"]] = locs[0]
        if c.get("purl"):
            by_purl.setdefault(_purl_base(c["purl"]), set()).add(locs[0])
    return by_ref, {k: sorted(v) for k, v in by_purl.items()}


def normalize(unit_id: str, unit_root: str, trivy_json: str, sbom_path: str) -> list[dict]:
    with open(trivy_json, encoding="utf-8") as f:
        data = json.load(f)
    by_ref, by_purl = _locations(sbom_path)
    root = (unit_root or "").rstrip("/")

    def absloc(loc: str) -> str:
        # syft はスキャン起点からの相対パスを返す (先頭の / は付いたり付かなかったりする)
        loc = "/" + loc.lstrip("/")
        return loc if not root or loc.startswith(root + "/") else root + loc

    recs: dict[str, dict] = {}
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            pid = v.get("PkgIdentifier") or {}
            pkg = v.get("PkgName", "")
            purl = pid.get("PURL", "")
            if purl.startswith(OS_PURL):
                # OS パッケージの場所は常にパッケージ DB なので、代わりにアーキテクチャで区別する
                m = re.search(r"[?&]arch=([^&]+)", purl)
                places = [("", m.group(1) if m else "")]
            else:
                locs = by_purl.get(_purl_base(purl)) or [by_ref.get(pid.get("BOMRef", ""), "")]
                places = [(absloc(x), absloc(x)) if x else ("", "") for x in locs]
            for loc, ident in places:
                key = "|".join([unit_id, v["VulnerabilityID"], pkg, ident])
                # 同じ key が重複する場合は 1 件にまとめる
                recs.setdefault(key, {
                    "key": key, "unit": unit_id, "vuln_id": v["VulnerabilityID"], "pkg": pkg,
                    "pkg_type": res.get("Type", ""), "version": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion") or "", "vstatus": v.get("Status", ""),
                    "severity": v.get("Severity", "UNKNOWN"), "title": (v.get("Title") or "")[:200],
                    "url": v.get("PrimaryURL") or "", "location": loc, "purl": purl,
                    "_aliases": [x for x in v.get("VendorIDs") or [] if x.startswith("CVE-")],
                })
    return list(recs.values())
