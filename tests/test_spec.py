"""spec/ の共通テストデータを Python 版で実行する (Go 版も同じデータでテストする)"""
from __future__ import annotations

import datetime as dt
import glob
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sbomops import config, match, pipeline, policy, store, targets  # noqa: E402
from sbomops.store import Store  # noqa: E402
from sbomops.util import fmt_duration, iso, parse_duration, parse_iso, parse_size, safe_name  # noqa: E402
from tests import fake_tools  # noqa: E402
from tests.spec_support import SPEC, load, merge, render_slack  # noqa: E402


class DefaultsTest(unittest.TestCase):
    def test_defaults_match_spec(self):
        d = load("defaults.json")
        self.assertEqual(d["config"], config.DEFAULTS)
        self.assertEqual(d["target"], config.TARGET_DEFAULTS)
        self.assertEqual(d["severities"], config.SEVERITIES)
        self.assertEqual(d["system_excludes"], config.SYSTEM_EXCLUDES)
        self.assertEqual(d["search_paths"], config.SEARCH_PATHS)

    def test_schema_matches_spec(self):
        with open(os.path.join(SPEC, "schema.sql"), encoding="utf-8") as f:
            self.assertEqual(f.read(), store.SCHEMA.lstrip("\n"))


class UtilSpecTest(unittest.TestCase):
    c = load("cases/util.json")

    def _table(self, name, fn):
        for arg, want in self.c[name]:
            with self.subTest(name=name, arg=arg):
                if want == "error":
                    with self.assertRaises(ValueError):
                        fn(arg)
                else:
                    self.assertEqual(fn(arg), want)

    def test_tables(self):
        self._table("parse_duration", parse_duration)
        self._table("parse_size", parse_size)
        self._table("fmt_duration", fmt_duration)
        self._table("safe_name", safe_name)
        for s, want in self.c["parse_iso"]:
            self.assertAlmostEqual(parse_iso(s).timestamp(), want, places=5)

    def test_fnmatch_and_excludes(self):
        import fnmatch
        for name, pat, want in self.c["fnmatch"]:
            self.assertEqual(fnmatch.fnmatch(name, pat), want, (name, pat))
        for root, pats, want in self.c["excludes"]:
            self.assertEqual(targets._excludes(root, pats), want)


class PolicySpecTest(unittest.TestCase):
    c = load("cases/policy.json")
    pol = config.DEFAULTS["notify"]["policy"]

    def row(self, over):
        return merge(self.c["base_row"], over)

    def test_eligible(self):
        for x in self.c["eligible"]:
            with self.subTest(x=x):
                self.assertEqual(policy.eligible(self.row(x["row"]), merge(self.pol, x.get("policy"))), x["want"])

    def test_should_notify(self):
        s = self.c["should_notify"]
        now = parse_iso(s["now"])
        for x in s["cases"]:
            with self.subTest(x=x):
                self.assertEqual(policy.should_notify(self.row(x["row"]), merge(self.pol, x.get("policy")), now),
                                 x["want"])

    def test_sort(self):
        s = self.c["sort"]
        rows = [self.row(r) for r in s["rows"]]
        self.assertEqual([r["vuln_id"] for r in sorted(rows, key=policy.sort_key)], s["want"])
        asm = {k: {"priority": v} for k, v in s["assess"].items()}
        self.assertEqual([r["vuln_id"] for r in sorted(rows, key=lambda r: policy.sort_key(r, asm))],
                         s["want_with_assess"])

    def test_classify(self):
        s = self.c["classify"]
        with tempfile.TemporaryDirectory() as d:
            acc = os.path.join(d, "accepted.tsv")
            with open(acc, "w", encoding="utf-8") as f:
                f.write(s["accepts"])
            cfg = config.load(None)
            cfg["noise"] = merge(cfg["noise"], s["noise"])
            cfg["notify"]["suppress_file"] = acc
            with mock.patch("sbomops.host.running_kernel", return_value=s["running_kernel"]):
                cls = policy.Classifier(cfg, dt.date.fromisoformat(s["today"]))
        for x in s["cases"]:
            with self.subTest(x=x):
                r = self.row(x["row"])
                cls.expired_accepts = []
                self.assertEqual(cls.classify(r, x["type"]), x["want"])
                self.assertEqual(bool(cls.expired_accepts), bool(x.get("expired")))


class ConfigSpecTest(unittest.TestCase):
    def test_cases(self):
        for x in load("cases/config.json")["cases"]:
            suffix = ".yaml" if "yaml" in x else ".json"
            with self.subTest(x=x.get("yaml", x.get("config"))), \
                    tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as f:
                if "yaml" in x:
                    f.write(x["yaml"])
                else:
                    json.dump(x["config"], f)
            try:
                if x.get("ok"):
                    cfg = config.load(f.name)
                    for path, want in (x.get("want") or {}).items():
                        v = cfg
                        for k in path.split("."):
                            v = v[int(k)] if isinstance(v, list) else v[k]
                        self.assertEqual(v, want, path)
                else:
                    with self.assertRaises(config.ConfigError) as e:
                        config.load(f.name)
                    for s in x["errors_contain"]:
                        self.assertIn(s, str(e.exception))
            finally:
                os.unlink(f.name)


class NormalizeSpecTest(unittest.TestCase):
    def test_cases(self):
        for p in sorted(glob.glob(os.path.join(SPEC, "cases", "normalize", "*.json"))):
            with open(p, encoding="utf-8") as f:
                c = json.load(f)
            with tempfile.TemporaryDirectory() as d:
                sp, tp = os.path.join(d, "s.json"), os.path.join(d, "t.json")
                for path, obj in ((sp, c["sbom"]), (tp, c["trivy"])):
                    with open(path, "w") as f:
                        json.dump(obj, f)
                recs = match.normalize(c["unit"], c["root"], tp, sp)
            self.assertEqual(sorted(recs, key=lambda r: r["key"]), c["want"], p)


class SlackSpecTest(unittest.TestCase):
    def test_golden(self):
        for p in sorted(glob.glob(os.path.join(SPEC, "cases", "slack", "*.json"))):
            with self.subTest(case=os.path.basename(p)):
                with open(p, encoding="utf-8") as f:
                    c = json.load(f)
                self.assertEqual(render_slack(c), c["want"])


def _subst(obj, m: dict):
    if isinstance(obj, str):
        for k, v in m.items():
            obj = obj.replace(k, v)
        return obj
    if isinstance(obj, dict):
        return {k: _subst(v, m) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, m) for v in obj]
    return obj


class ScenarioSpecTest(unittest.TestCase):
    def test_scenarios(self):
        base = load("scenarios/_base.json")
        files = sorted(glob.glob(os.path.join(SPEC, "scenarios", "[!_]*.json")))
        self.assertTrue(files, "spec/scenarios にシナリオがない")
        for p in files:
            with self.subTest(scenario=os.path.basename(p)):
                with open(p, encoding="utf-8") as f:
                    self._run(base, json.load(f))

    def _run(self, base: dict, sc: dict):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "fake")
            fake_tools.make(fake)
            state = os.path.join(d, "fake-state")
            os.makedirs(state)
            os.makedirs(os.path.join(d, "app"))
            today = dt.date.today()
            m = {"{dirname}": safe_name(d.strip("/")), "{dir}": d, "{fake}": fake}
            for n in range(0, 31):
                m[f"{{today+{n}}}"] = (today + dt.timedelta(days=n)).isoformat()
                m[f"{{today-{n}}}"] = (today - dt.timedelta(days=n)).isoformat()
            for rel, body in (sc.get("files") or {}).items():
                os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
                with open(os.path.join(d, rel), "w", encoding="utf-8") as f:
                    f.write(body)
            for rel in sc.get("dirs") or []:
                os.makedirs(os.path.join(d, rel), exist_ok=True)
            user = merge(base, sc.get("config"))
            user["notify"] = merge(user["notify"], {"policy": sc.get("policy") or {}})
            user = _subst(user, m)
            cpath = os.path.join(d, "cfg.json")
            with open(cpath, "w") as f:
                json.dump(user, f)
            cfg = config.load(cpath)
            sent = []
            with mock.patch.dict(os.environ, {"FAKE_STATE": state}), \
                    mock.patch("sbomops.notify.slack.SlackNotifier.send",
                               lambda _s, rp, dry_run=False: sent.append(rp)):
                for i, step in enumerate(sc["steps"]):
                    step = _subst(step, m)
                    ctx = f"step {i}: {step}"
                    if "set_version" in step:
                        with open(os.path.join(state, "version"), "w") as f:
                            f.write(step["set_version"])
                    elif "write_accepted" in step:
                        with open(user["notify"]["suppress_file"], "w", encoding="utf-8") as f:
                            f.write(step["write_accepted"])
                    elif "mkdir" in step:
                        for x in step["mkdir"]:
                            os.makedirs(os.path.join(d, x))
                    elif "age_notifications" in step:
                        st = Store(os.path.join(cfg["data_dir"], "state.db"))
                        t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=step["age_notifications"])
                        st.db.execute("UPDATE findings SET last_notified=? WHERE last_notified IS NOT NULL",
                                      (iso(t),))
                        st.close()
                    elif "run" in step:
                        r = step["run"]
                        before = len(sent)
                        rc = pipeline.run(cfg, force=r.get("force", False), no_scan=r.get("no_scan", False))
                        self._check(step["expect"], rc, sent[before:], ctx)
                        for k, want in (step["expect"].get("meta") or {}).items():
                            st = Store(os.path.join(cfg["data_dir"], "state.db"))
                            got = st.get_meta(k)
                            st.close()
                            if want.startswith("!"):
                                self.assertNotEqual(got, want[1:], ctx)
                                self.assertTrue(got, ctx)
                            else:
                                self.assertEqual(got, want, ctx)
                    else:
                        self.fail(f"不明な step: {step}")

    def _check(self, e: dict, rc: int, sent: list, ctx: str):
        if "rc" in e:
            self.assertEqual(rc, e["rc"], ctx)
        if "sent" in e:
            self.assertEqual(bool(sent), e["sent"], ctx)
        if not sent:
            return
        rp = sent[-1]
        if "items" in e:
            self.assertEqual([[r["vuln_id"], k] for r, k in rp.items], e["items"], ctx)
        if "host" in e:
            self.assertEqual(rp.host, e["host"], ctx)
        if "locations" in e:
            self.assertEqual([r["location"] for r, _ in rp.items], e["locations"], ctx)
        if "resolved" in e:
            self.assertEqual([r["vuln_id"] for r in rp.resolved], e["resolved"], ctx)
        for s in e.get("skipped") or []:
            self.assertIn(tuple(s), rp.skipped, ctx)
        if "skipped_exact" in e:
            self.assertEqual([list(x) for x in rp.skipped], e["skipped_exact"], ctx)
        for s in e.get("warnings_contain") or []:
            self.assertTrue(any(s in w for w in rp.warnings), f"{ctx}: {s!r} not in {rp.warnings}")
        if "timings" in e:
            got = []
            for t in rp.timings:
                st = lambda x: None if x is None else ("ok" if x["ok"] else "failed")  # noqa: E731
                got.append({"unit": t["unit"], "syft": st(t["syft"]), "trivy": st(t["trivy"]),
                            "syft_skip": t.get("syft_skip")})
            self.assertEqual(len(got), len(e["timings"]), f"{ctx}: {got}")
            for g, w in zip(got, e["timings"]):
                self.assertEqual((g["unit"], g["syft"], g["trivy"]), (w["unit"], w["syft"], w["trivy"]), ctx)
                if "syft_skip_prefix" in w:
                    self.assertTrue((g["syft_skip"] or "").startswith(w["syft_skip_prefix"]), f"{ctx}: {g}")


if __name__ == "__main__":
    unittest.main()
