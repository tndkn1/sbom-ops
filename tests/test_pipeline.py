"""偽の syft / trivy で日次の流れを通し、通知・再通知・解消の振る舞いを確かめる"""
from __future__ import annotations

import datetime as dt
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbomops import config, pipeline  # noqa: E402
from sbomops.store import Store  # noqa: E402
from sbomops.util import iso  # noqa: E402
from tests import fake_tools  # noqa: E402


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.state = os.path.join(d, "fake")
        os.makedirs(self.state)
        os.environ["FAKE_STATE"] = self.state
        syft, trivy = fake_tools.make(os.path.join(d, "bin"))
        os.makedirs(os.path.join(d, "app"))
        self.user = {
            "data_dir": os.path.join(d, "data"),
            "secrets_file": "",
            "tools": {"syft": syft, "trivy": trivy},
            "resources": {"nice": 0, "ionice_class": "none"},
            "enrich": {"kev": False, "epss": False},
            "noise": {"distro_owned": False},
            "notify": {"suppress_file": os.path.join(d, "accepted.tsv"),
                       "policy": {"notify_reboot_required": False}},
            "targets": [{"id": "app", "type": "dir", "path": os.path.join(d, "app"), "every": "1d"}],
        }
        self.sent = []
        patcher = mock.patch("sbomops.notify.slack.SlackNotifier.send",
                             lambda _self, rp, dry_run=False: self.sent.append(rp))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def cfg(self, **policy):
        u = dict(self.user)
        u["notify"] = dict(u["notify"], slack={"enabled": True},
                           policy=dict(u["notify"]["policy"], **policy))
        path = os.path.join(self.tmp.name, "cfg.json")
        import json
        with open(path, "w") as f:
            json.dump(u, f)
        return config.load(path)

    def set_version(self, v):
        with open(os.path.join(self.state, "version"), "w") as f:
            f.write(v)

    def age_notifications(self, days: int):
        """前回の通知を days 日前に送ったことにする"""
        st = Store(os.path.join(self.user["data_dir"], "state.db"))
        t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
        st.db.execute("UPDATE findings SET last_notified=? WHERE last_notified IS NOT NULL", (iso(t),))
        st.close()

    def test_until_fixed_then_resolved(self):
        cfg = self.cfg(repeat="until_fixed", remind_every="1d")
        self.set_version("1.0")
        self.assertEqual(pipeline.run(cfg), 0)
        rp = self.sent[-1]
        # HIGH で修正版ありの 1 件だけ (LOW は min_severity 未満)
        self.assertEqual([(r["vuln_id"], k) for r, k in rp.items], [("CVE-2099-0001", "new")])

        # 同じ日にもう一度実行しても再通知しない
        self.assertEqual(pipeline.run(cfg, force=True), 0)
        self.assertEqual(len(self.sent), 1)

        # 1 日経つと、未適用なので再通知する
        self.age_notifications(1)
        pipeline.run(cfg, force=True)
        self.assertEqual([k for _, k in self.sent[-1].items], ["remind"])

        # パッチ適用 (1.1) → 解消として報告し、以後は通知しない
        self.set_version("1.1")
        self.age_notifications(1)
        pipeline.run(cfg, force=True)
        rp = self.sent[-1]
        self.assertEqual(rp.items, [])
        self.assertEqual([r["vuln_id"] for r in rp.resolved], ["CVE-2099-0001"])
        n = len(self.sent)
        self.age_notifications(1)
        pipeline.run(cfg, force=True)
        self.assertEqual(len(self.sent), n)   # quiet_when_empty

    def test_once(self):
        cfg = self.cfg(repeat="once")
        self.set_version("1.0")
        pipeline.run(cfg)
        self.age_notifications(3)
        pipeline.run(cfg, force=True)
        self.assertEqual(len(self.sent), 1)

    def test_min_severity_and_fixable(self):
        cfg = self.cfg(min_severity="LOW", only_fixable=False)
        self.set_version("1.0")
        pipeline.run(cfg)
        self.assertEqual(sorted(r["vuln_id"] for r, _ in self.sent[-1].items),
                         ["CVE-2099-0001", "CVE-2099-0002"])

    def test_accepted_until(self):
        future = (dt.date.today() + dt.timedelta(days=10)).isoformat()
        with open(self.user["notify"]["suppress_file"], "w") as f:
            f.write(f"CVE-2099-0001 app example {future} 検証中\n")
        cfg = self.cfg()
        self.set_version("1.0")
        pipeline.run(cfg)
        self.assertEqual(self.sent, [])
        # 期限切れになると通常の通知に戻る
        past = (dt.date.today() - dt.timedelta(days=1)).isoformat()
        with open(self.user["notify"]["suppress_file"], "w") as f:
            f.write(f"CVE-2099-0001 app example {past} 検証中\n")
        pipeline.run(cfg, force=True)
        self.assertEqual([r["vuln_id"] for r, _ in self.sent[-1].items], ["CVE-2099-0001"])

    def test_due_skips_fresh_sbom(self):
        cfg = self.cfg()
        self.set_version("1.0")
        pipeline.run(cfg)
        self.set_version("1.1")
        # every=1d なので、同じ日の 2 回目は SBOM を作り直さない (= まだ 1.0 のまま)
        self.age_notifications(1)
        pipeline.run(cfg)
        self.assertEqual([k for _, k in self.sent[-1].items], ["remind"])


if __name__ == "__main__":
    unittest.main()
