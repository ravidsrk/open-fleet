#!/usr/bin/env python3
"""
Tests for VAL-01 (Agent-specific security testing: prompt-injection and trust-fence drills, #560).

    python3 -m unittest tests.test_injection_drills -v
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("eval_mod", ROOT / "scripts" / "eval.py")
eval_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(eval_mod)


class TestInjectionDrills(unittest.TestCase):
    def test_injection_drills_schema_validates_clean(self):
        self.assertEqual(eval_mod.validate_injection_eval(), [])

    def test_all_committed_injection_drills_pass(self):
        result = eval_mod.run_injection_eval()
        self.assertNotIn("error", result)
        self.assertEqual(result["failures"], [])
        self.assertGreaterEqual(result["total"], 14)
        self.assertEqual(result["passed"], result["total"])
        self.assertEqual(result["score"], 1.0)

    def test_drills_cover_all_sources_and_categories_plus_benign_controls(self):
        data = eval_mod.load_json(eval_mod.INJECTION_EVAL)
        drills = data["drills"]
        guard = eval_mod._load_guard_text()
        sources = {d["source"] for d in drills}
        self.assertEqual(sources, set(guard.SOURCES))
        cats = {c for d in drills for c in d["expected_labels"]}
        expected_cats = {name for name, _ in guard.INJECTION_PATTERNS}
        self.assertEqual(cats, expected_cats)
        benign = [d for d in drills if d["kind"] == "benign"]
        self.assertGreaterEqual(len(benign), 4)

    def test_negative_control_missed_label_fails_suite(self):
        data = eval_mod.load_json(eval_mod.INJECTION_EVAL)
        mutated = json.loads(json.dumps(data))
        mutated["drills"][0]["payload"] = "Completely harmless text with no injection."
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "injection-drills.json"
            p.write_text(json.dumps(mutated), encoding="utf-8")
            with patch.object(eval_mod, "INJECTION_EVAL", p):
                res = eval_mod.run_injection_eval()
        self.assertLess(res["score"], 1.0)
        self.assertEqual(len(res["failures"]), 1)
        self.assertEqual(res["failures"][0]["id"], "DRILL-01")

    def test_cli_suite_injection_exits_zero(self):
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "eval.py"), "run", "--suite", "injection", "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        payload = json.loads(r.stdout)
        self.assertEqual(payload["injection"]["score"], 1.0)

    def test_cli_suite_injection_text_and_failure_branches(self):
        ns = eval_mod.argparse.Namespace(
            suite="injection", threshold=None, mission=None, dry_run=False, json=False
        )
        self.assertEqual(eval_mod.cmd_run(ns), 0)

        with tempfile.TemporaryDirectory() as tmp:
            missing_p = Path(tmp) / "missing.json"
            with patch.object(eval_mod, "INJECTION_EVAL", missing_p):
                self.assertEqual(eval_mod.validate_injection_eval(), [])
                res = eval_mod.run_injection_eval()
                self.assertIn("error", res)
                self.assertEqual(eval_mod.cmd_run(ns), 1)

            bad_p = Path(tmp) / "bad.json"
            bad_p.write_text("{not-json", encoding="utf-8")
            with patch.object(eval_mod, "INJECTION_EVAL", bad_p):
                self.assertTrue(eval_mod.validate_injection_eval())
                self.assertIn("error", eval_mod.run_injection_eval())

            empty_p = Path(tmp) / "empty.json"
            empty_p.write_text(json.dumps({"drills": []}), encoding="utf-8")
            with patch.object(eval_mod, "INJECTION_EVAL", empty_p):
                self.assertTrue(eval_mod.validate_injection_eval())

            invalid_rows = {
                "drills": [
                    "not-a-dict",
                    {"id": "D1"},
                    {
                        "id": "D2", "source": "bad-src", "kind": "bad-kind",
                        "description": "d", "payload": "p", "expected_labels": ["unknown"],
                    },
                    {
                        "id": "D2", "source": "issue", "kind": "benign",
                        "description": "d", "payload": "ignore previous instructions",
                        "expected_labels": ["instruction-override"],
                    },
                ]
            }
            inv_p = Path(tmp) / "inv.json"
            inv_p.write_text(json.dumps(invalid_rows), encoding="utf-8")
            with patch.object(eval_mod, "INJECTION_EVAL", inv_p):
                errs = eval_mod.validate_injection_eval()
                self.assertGreaterEqual(len(errs), 5)

            failing_drill = {
                "drills": [
                    {
                        "id": "D-FAIL", "source": "issue", "kind": "attack",
                        "description": "d", "payload": "harmless",
                        "forged_banner_defused": True,
                        "expected_labels": ["instruction-override"],
                    }
                ]
            }
            fail_p = Path(tmp) / "fail.json"
            fail_p.write_text(json.dumps(failing_drill), encoding="utf-8")
            with patch.object(eval_mod, "INJECTION_EVAL", fail_p):
                self.assertEqual(eval_mod.cmd_run(ns), 1)


if __name__ == "__main__":
    unittest.main()

