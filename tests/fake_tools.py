"""テスト用の偽 syft / trivy を作る。

偽 syft は $FAKE_STATE/version の中身 (1.0 など) を example パッケージの版として SBOM を書く。
偽 trivy は example の版が 1.0 なら CVE-2099-0001 (HIGH, 修正版 1.1) と CVE-2099-0002 (LOW) を返し、
1.1 以上なら何も返さない。これで「パッチ適用 → 解消」を再現する。
"""
from __future__ import annotations

import os
import stat
import sys
import textwrap

SYFT = r'''#!PY
import json, os, sys
args = sys.argv[1:]
out = [a.split("=", 1)[1] for a in args if a.startswith("cyclonedx-json=")][0]
ver = open(os.path.join(os.environ["FAKE_STATE"], "version")).read().strip()
src = args[args.index("scan") + 2] if "scan" in args else ""
bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
    {"bom-ref": "pkg:pypi/example@%s?package-id=1" % ver, "type": "library", "name": "example",
     "version": ver, "purl": "pkg:pypi/example@" + ver,
     "properties": [{"name": "syft:location:0:path", "value": "/lib/example-%s.dist-info/METADATA" % ver}]}]}
json.dump(bom, open(out, "w"))
'''

TRIVY = r'''#!PY
import json, sys
args = sys.argv[1:]
if "--download-db-only" in args:
    sys.exit(0)
if args and args[0] == "version":
    print(json.dumps({"VulnerabilityDB": {"UpdatedAt": "2099-01-01T00:00:00Z"}})); sys.exit(0)
out = args[args.index("-o") + 1]
bom = json.load(open(args[-1]))
c = bom["components"][0]
vulns = []
if c["version"] == "1.0":
    for vid, sev, fix in (("CVE-2099-0001", "HIGH", "1.1"), ("CVE-2099-0002", "LOW", "")):
        vulns.append({"VulnerabilityID": vid, "PkgName": "example", "InstalledVersion": c["version"],
                      "FixedVersion": fix, "Status": "fixed" if fix else "affected", "Severity": sev,
                      "Title": "test", "PrimaryURL": "",
                      "PkgIdentifier": {"PURL": c["purl"], "BOMRef": c["bom-ref"]}})
json.dump({"Results": [{"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg",
                        "Vulnerabilities": vulns}]}, open(out, "w"))
'''


def make(dirpath: str) -> tuple[str, str]:
    os.makedirs(dirpath, exist_ok=True)
    paths = []
    for name, body in (("syft", SYFT), ("trivy", TRIVY)):
        p = os.path.join(dirpath, name)
        with open(p, "w") as f:
            f.write(textwrap.dedent(body).replace("#!PY", "#!" + sys.executable, 1))
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
        paths.append(p)
    return paths[0], paths[1]
