from __future__ import annotations

import datetime as dt
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbomops import config, policy, targets  # noqa: E402
from sbomops.notify.base import Report  # noqa: E402
from sbomops.notify.slack import SlackNotifier  # noqa: E402
from sbomops.store import Store  # noqa: E402
from sbomops.util import parse_duration, parse_size  # noqa: E402


def row(**kw):
    r = {"key": "u|CVE-1|p|", "unit": "u", "vuln_id": "CVE-1", "pkg": "p", "pkg_type": "python-pkg",
         "version": "1.0", "fixed": "1.1", "vstatus": "fixed", "severity": "HIGH", "title": "",
         "url": "", "location": "", "purl": "pkg:pypi/p@1.0", "kev": 0, "epss": None,
         "class": "active", "eligible": 1, "state": "open", "first_seen": "2026-01-01",
         "last_notified": None}
    r.update(kw)
    return r


class UtilTest(unittest.TestCase):
    def test_duration(self):
        self.assertEqual(parse_duration("90m"), 5400)
        self.assertEqual(parse_duration("1d"), 86400)
        self.assertEqual(parse_duration(None), 0)
        with self.assertRaises(ValueError):
            parse_duration("1 day")

    def test_parse_iso(self):
        from sbomops.util import parse_iso
        t = parse_iso("2026-11-21T13:02:47.203212637Z")
        self.assertEqual((t.microsecond, t.utcoffset().total_seconds()), (203212, 0))

    def test_size(self):
        self.assertEqual(parse_size("4G"), 4 << 30)
        self.assertEqual(parse_size("512MiB"), 512 << 20)


class ConfigTest(unittest.TestCase):
    def test_validation(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write('{"targets": [{"id": "a", "type": "dir"}, {"id": "a", "type": "nope"}],'
                    ' "notify": {"policy": {"repeat": "always"}}}')
        try:
            with self.assertRaises(config.ConfigError) as e:
                config.load(f.name)
            msg = str(e.exception)
            self.assertIn("path", msg)
            self.assertIn("重複", msg)
            self.assertIn("repeat", msg)
        finally:
            os.unlink(f.name)


class TargetsTest(unittest.TestCase):
    def test_excludes(self):
        self.assertEqual(targets._excludes("/", ["/proc", "/var/lib/docker"]),
                         ["./proc/**", "./var/lib/docker/**"])
        self.assertEqual(targets._excludes("/opt", ["/opt/big", "/usr", "./x/**", "*.iso"]),
                         ["./big/**", "./x/**", "./*.iso"])

    def test_due(self):
        u = targets.Unit("a", "a", "dir", "dir:/x", "/x", 86400, 0, 0)
        with tempfile.NamedTemporaryFile() as f:
            now = time.time()
            fresh = {"a": {"last_scan_ts": now - 3600, "sbom_path": f.name}}
            old = {"a": {"last_scan_ts": now - 86400 + 1800, "sbom_path": f.name}}
            self.assertEqual(targets.due([u], fresh, now), [])
            self.assertEqual(targets.due([u], old, now), [u])      # 1 時間の余裕
            self.assertEqual(targets.due([u], fresh, now, force=True), [u])
            self.assertEqual(targets.due([u], {}, now), [u])


class PolicyTest(unittest.TestCase):
    pol = dict(config.DEFAULTS["notify"]["policy"])

    def test_eligible(self):
        self.assertTrue(policy.eligible(row(), self.pol))
        self.assertFalse(policy.eligible(row(severity="MEDIUM"), self.pol))
        self.assertFalse(policy.eligible(row(fixed=""), self.pol))
        self.assertTrue(policy.eligible(row(severity="LOW", fixed="", kev=1), self.pol))
        self.assertTrue(policy.eligible(row(severity="LOW", epss=0.9), self.pol))
        self.assertFalse(policy.eligible(row(vstatus="will_not_fix", kev=1), self.pol))

    def test_should_notify(self):
        now = dt.datetime(2026, 1, 10, 4, 30, tzinfo=dt.timezone.utc)
        y = (now - dt.timedelta(days=1, minutes=5)).isoformat()
        h = (now - dt.timedelta(hours=2)).isoformat()
        self.assertEqual(policy.should_notify(row(), self.pol, now), "new")
        self.assertEqual(policy.should_notify(row(last_notified=y), self.pol, now), "remind")
        self.assertIsNone(policy.should_notify(row(last_notified=h), self.pol, now))
        once = dict(self.pol, repeat="once")
        self.assertIsNone(policy.should_notify(row(last_notified=y), once, now))
        weekly = dict(self.pol, remind_every="7d")
        self.assertIsNone(policy.should_notify(row(last_notified=y), weekly, now))
        self.assertIsNone(policy.should_notify(row(state="resolved"), self.pol, now))
        self.assertIsNone(policy.should_notify(row(**{"class": "noise:old-kernel"}), self.pol, now))

    def test_old_kernel(self):
        cfg = config.load(None)
        with mock.patch("sbomops.host.running_kernel", return_value="7.0.0-44-generic"):
            c = policy.Classifier(cfg, dt.date.today())
        old = row(pkg="linux-image-7.0.0-38-generic", purl="pkg:deb/ubuntu/linux-image-7.0.0-38-generic@7.0.0-38.38")
        cur = row(pkg="linux-image-7.0.0-44-generic", purl="pkg:deb/ubuntu/linux-image-7.0.0-44-generic@7.0.0-44.44")
        rpm_old = row(pkg="kernel-core", version="5.14.0-427.el9", purl="pkg:rpm/rocky/kernel-core@5.14.0-427.el9")
        self.assertEqual(c.classify(old, "os-packages"), "noise:old-kernel")
        self.assertEqual(c.classify(cur, "os-packages"), "active")
        self.assertEqual(c.classify(rpm_old, "os-packages"), "noise:old-kernel")
        self.assertEqual(c.classify(old, "image"), "active")


class StoreTest(unittest.TestCase):
    def test_sync(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "s.db"))
            a = {k: v for k, v in row().items() if k in ("key", "unit", "vuln_id", "pkg", "version", "severity")}
            new, res = st.sync_unit("u", [a], "2026-01-01")
            self.assertEqual((new, res), (["u|CVE-1|p|"], []))
            new, res = st.sync_unit("u", [a], "2026-01-02")
            self.assertEqual((new, res), ([], []))
            st.mark_notified(["u|CVE-1|p|"], "2026-01-02T00:00:00+00:00")
            new, res = st.sync_unit("u", [], "2026-01-03")
            self.assertEqual(res, ["u|CVE-1|p|"])
            # 再発したら新規扱い (通知済みも消える)
            new, _ = st.sync_unit("u", [a], "2026-01-05")
            self.assertEqual(new, ["u|CVE-1|p|"])
            r = st.get("u|CVE-1|p|")
            self.assertEqual((r["first_seen"], r["last_notified"]), ("2026-01-05", None))
            st.close()


class NormalizeTest(unittest.TestCase):
    def test_same_purl_in_multiple_binaries(self):
        """trivy が 1 件にまとめた同一 purl を、SBOM 上の全ての場所に展開する"""
        import json
        from sbomops import match
        comp = lambda pid, path: {"bom-ref": f"pkg:golang/x@v1?package-id={pid}", "name": "x",
                                  "purl": f"pkg:golang/x@v1?package-id={pid}",
                                  "properties": [{"name": "syft:location:0:path", "value": path}]}
        bom = {"components": [comp("a", "bin/one"), comp("b", "/bin/two"),
                              {"bom-ref": "deb1", "purl": "pkg:deb/ubuntu/libc6@2.39?arch=amd64",
                               "properties": [{"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"}]}]}
        tr = {"Results": [{"Type": "gobinary", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "x", "InstalledVersion": "v1", "Severity": "HIGH",
             "PkgIdentifier": {"PURL": "pkg:golang/x@v1", "BOMRef": "pkg:golang/x@v1?package-id=b"}}]},
            {"Type": "ubuntu", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2", "PkgName": "libc6", "InstalledVersion": "2.39", "Severity": "LOW",
             "PkgIdentifier": {"PURL": "pkg:deb/ubuntu/libc6@2.39?arch=amd64", "BOMRef": "deb1"}}]}]}
        with tempfile.TemporaryDirectory() as d:
            sp, tp = os.path.join(d, "s.json"), os.path.join(d, "t.json")
            json.dump(bom, open(sp, "w"))
            json.dump(tr, open(tp, "w"))
            recs = match.normalize("u", "/usr", tp, sp)
        self.assertEqual(sorted(r["location"] for r in recs if r["vuln_id"] == "CVE-1"),
                         ["/usr/bin/one", "/usr/bin/two"])
        deb = [r for r in recs if r["vuln_id"] == "CVE-2"][0]
        self.assertEqual((deb["key"], deb["location"]), ("u|CVE-2|libc6|amd64", ""))


class SlackTest(unittest.TestCase):
    def test_render_limits(self):
        items = [(row(key=f"k{i}", vuln_id=f"CVE-{i}", pkg=f"p{i % 40}", location=f"/x/{i % 40}" * 20,
                      kev=int(i == 3)), "new") for i in range(400)]
        rp = Report(host="h", date="2026-01-01", items=items, warnings=["w"] * 30, open_counts={"HIGH": 400})
        n = SlackNotifier({"mention": "<!here>", "mention_on": ["kev"]}, dict(config.DEFAULTS["notify"]["policy"]))
        p = n.render(rp)
        self.assertLessEqual(len(p["blocks"]), 50)
        for b in p["blocks"]:
            if b["type"] == "section":
                self.assertLessEqual(len(b["text"]["text"]), 3000)
        self.assertTrue(p["blocks"][1]["text"]["text"].startswith("<!here>"))


if __name__ == "__main__":
    unittest.main()
