#!/usr/bin/env python3
"""Contract tests for document-it product surface coverage (rename-to-RED oracle) and wheel verification."""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SURFACE = _load("extract_product_surface_test", "scripts/extract_product_surface.py")
WHEEL = _load("verify_wheel_test", "scripts/verify_wheel.py")


class TestProductSurfaceDocumentationAndRenameControl(unittest.TestCase):
    def test_live_product_surface_is_100_percent_documented_and_anchored(self):
        res = SURFACE.check_coverage(ROOT)
        self.assertTrue(res["ok"], res["errors"])
        self.assertGreaterEqual(res["counts"]["cli_commands"], 16)
        self.assertGreaterEqual(res["counts"]["mcp_tools"], 19)
        self.assertGreaterEqual(res["counts"]["mcp_resources"], 10)
        self.assertEqual(res["counts"]["action_outputs"], 5)
        self.assertTrue(res["reachability"]["README.md"])
        self.assertTrue(res["reachability"]["docs/README.md"])

    def test_rename_negative_control_turns_claim_check_red(self):
        """document-it negative control: renaming an anchored symbol turns check_coverage RED."""
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "repo"
            copy.mkdir()
            shutil.copytree(ROOT / "open_fleet", copy / "open_fleet", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "docs", copy / "docs", ignore=shutil.ignore_patterns("runs", "assets"))
            shutil.copytree(ROOT / ".github" / "actions", copy / ".github" / "actions")
            shutil.copy2(ROOT / "README.md", copy / "README.md")
            # Symlink catalog dirs so OpenFleetMCPServer loads skills/playbooks/runtime cleanly.
            for d in ("skills", "playbooks", "runtime", ".claude-plugin"):
                (copy / d).symlink_to(ROOT / d, target_is_directory=True)

            # Baseline on unmutated copy is GREEN.
            clean = SURFACE.check_coverage(copy)
            self.assertTrue(clean["ok"], clean["errors"])

            # Mutate/rename anchored symbol `run_solo_review` -> `run_solo_review_renamed`.
            solo_py = copy / "open_fleet" / "solo_review.py"
            text = solo_py.read_text(encoding="utf-8")
            self.assertIn("def run_solo_review(", text)
            solo_py.write_text(text.replace("def run_solo_review(", "def run_solo_review_renamed(", 1), encoding="utf-8")
            # Also fix the import in cli.py/mcp_server.py so package import succeeds and ONLY the anchor fails.
            for rel in ("open_fleet/cli.py", "open_fleet/mcp_server.py"):
                p = copy / rel
                p.write_text(p.read_text(encoding="utf-8").replace("run_solo_review", "run_solo_review_renamed"), encoding="utf-8")

            mutated = SURFACE.check_coverage(copy)
            self.assertFalse(mutated["ok"], "rename control stayed GREEN instead of turning RED")
            self.assertTrue(
                any("open_fleet/solo_review.py:run_solo_review" in e for e in mutated["errors"]),
                mutated["errors"],
            )


class TestWheelBuildAndFreshVenvInstall(unittest.TestCase):
    def test_verify_wheel_builds_cleanly_and_passes_out_of_repo_cli_and_mcp(self):
        rep = WHEEL.verify_wheel(ROOT)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["requires_dist"], [])
        self.assertGreaterEqual(rep["mcp_tools"], 19)
        self.assertGreaterEqual(rep["mcp_resources"], 10)
        self.assertTrue(rep["cli_version"].startswith("open-fleet "))


if __name__ == "__main__":
    unittest.main()
