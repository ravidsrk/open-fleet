#!/usr/bin/env python3
"""Contract tests for scripts/a2a_export.py (A2A outcome card exporter)."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "a2a_export.py"


def load_module():
    spec = importlib.util.spec_from_file_location("a2a_export", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestA2AExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_catalog_export_includes_all_missions(self):
        payload = self.mod.build_catalog_cards()
        self.assertEqual(payload["schema"], "a2a-agent-card-catalog/v1")
        skill_dirs = [
            d.name for d in sorted((ROOT / "skills").iterdir())
            if d.is_dir() and (d / "SKILL.md").is_file()
        ]
        self.assertEqual(payload["count"], len(skill_dirs))
        self.assertEqual([c["name"] for c in payload["cards"]], skill_dirs)

    def test_single_mission_card_binds_evidence_manifest_and_one_way_doors(self):
        card = self.mod.build_catalog_cards(mission="ship-it")
        self.assertEqual(card["schema"], "a2a-agent-card/v1")
        self.assertEqual(card["id"], "orca-fleet:ship-it")
        self.assertEqual(card["name"], "ship-it")
        self.assertTrue(card["proof"]["mutating"])
        self.assertEqual(
            set(card["identity"].keys()),
            {"unit", "state_machine", "convergence", "ordering", "parking", "oracle"},
        )
        contracts = card["contracts"]
        self.assertEqual(
            contracts["output"]["evidence_manifest"],
            "runtime/evidence-manifest.md",
        )
        self.assertEqual(contracts["output"]["verifier"], "runtime/scripts/verify.py")
        self.assertEqual(
            contracts["governance"]["one_way_doors_ref"],
            "runtime/one-way-doors.json",
        )
        self.assertIn("merge-to-default", contracts["governance"]["one_way_door_ids"])
        self.assertIn("deploy", contracts["governance"]["one_way_door_ids"])

    def test_report_only_mission_card_uses_report_only_verifier(self):
        card = self.mod.build_catalog_cards(mission="review-it")
        self.assertFalse(card["proof"]["mutating"])
        self.assertEqual(card["contracts"]["output"]["verifier"], "report-only")

    def test_cli_check_and_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "a2a-cards.json"
            p_check = subprocess.run(
                [sys.executable, str(SCRIPT), "--check"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_check.returncode, 0, p_check.stderr)
            self.assertIn("A2A_EXPORT=ok", p_check.stdout)

            p_out = subprocess.run(
                [sys.executable, str(SCRIPT), "--mission", "clean-sweep", "--out", str(out_file)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_out.returncode, 0, p_out.stderr)
            written = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(written["id"], "orca-fleet:clean-sweep")

    def test_unknown_mission_exits_1(self):
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "--mission", "no-such-mission"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 1)
        self.assertIn("unknown mission", p.stderr)


if __name__ == "__main__":
    unittest.main()
