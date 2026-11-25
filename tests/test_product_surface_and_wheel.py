"""Contract tests for product-surface documentation coverage (document-it) and wheel packaging."""
import importlib.util
import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(rel_path, mod_name):
    spec = importlib.util.spec_from_file_location(mod_name, ROOT / rel_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SURFACE = _load("scripts/extract_product_surface.py", "extract_product_surface_test")
WHEEL = _load("scripts/verify_wheel.py", "verify_wheel_test")


def _stage_copy(copy_root):
    shutil.copytree(ROOT / "open_fleet", copy_root / "open_fleet")
    shutil.copytree(ROOT / "docs", copy_root / "docs")
    shutil.copytree(ROOT / ".github" / "actions", copy_root / ".github" / "actions")
    shutil.copy2(ROOT / "README.md", copy_root / "README.md")


class TestProductSurfaceDocumentationAndRenameControl(unittest.TestCase):
    def test_live_product_surface_is_100_percent_documented_and_anchored(self):
        res = SURFACE.check_coverage(ROOT)
        self.assertTrue(res["ok"], res["errors"])
        self.assertGreaterEqual(res["counts"]["cli_commands"], 16)
        self.assertGreaterEqual(res["counts"]["mcp_tools"], 19)
        self.assertGreaterEqual(res["counts"]["mcp_resources"], 10)
        self.assertEqual(res["counts"]["action_outputs"], 5)
        self.assertGreaterEqual(res["counts"]["doc_anchors"], 14)
        self.assertTrue(res["reachability"]["README.md"])
        self.assertTrue(res["reachability"]["docs/README.md"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = SURFACE.main(["--root", str(ROOT), "--check"])
        self.assertEqual(rc, 0)
        self.assertIn("product-surface: OK", buf.getvalue())

    def test_rename_negative_control_turns_claim_check_red(self):
        """document-it negative control: renaming a doc-anchored symbol turns --check RED."""
        with tempfile.TemporaryDirectory(prefix="open-fleet-doc-nc-") as tmp:
            copy = Path(tmp) / "repo"
            _stage_copy(copy)
            try:
                clean = SURFACE.check_coverage(copy)
                self.assertTrue(clean["ok"], clean["errors"])

                # Confirm docs/cli-and-mcp.md actually anchors the symbol we are about to rename.
                doc_text = (copy / "docs" / "cli-and-mcp.md").read_text(encoding="utf-8")
                self.assertIn("`open_fleet/solo_review.py:run_solo_review`", doc_text)

                # Mutate/rename doc-anchored symbol `run_solo_review` -> `run_solo_review_renamed`
                # while keeping all internal callers import-clean (not a crash tautology).
                solo_py = copy / "open_fleet" / "solo_review.py"
                text = solo_py.read_text(encoding="utf-8")
                self.assertIn("def run_solo_review(", text)
                solo_py.write_text(text.replace("def run_solo_review(", "def run_solo_review_renamed(", 1), encoding="utf-8")
                for rel in ("open_fleet/cli.py", "open_fleet/mcp_server.py"):
                    p = copy / rel
                    p.write_text(p.read_text(encoding="utf-8").replace("run_solo_review", "run_solo_review_renamed"), encoding="utf-8")

                mutated = SURFACE.check_coverage(copy)
                self.assertFalse(mutated["ok"], "rename control stayed GREEN instead of turning RED")
                self.assertTrue(
                    any("open_fleet/solo_review.py:run_solo_review" in e for e in mutated["errors"]),
                    mutated["errors"],
                )
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    rc = SURFACE.main(["--root", str(copy), "--check"])
                self.assertEqual(rc, 1)
                self.assertIn("open_fleet/solo_review.py:run_solo_review", err.getvalue())
            finally:
                SURFACE._load_open_fleet(ROOT)

    def test_bogus_anchor_dropped_entities_and_missing_files_fail_closed(self):
        """Negative controls for bogus doc anchors, dropped docs, unlinked README, and missing files."""
        with tempfile.TemporaryDirectory(prefix="open-fleet-doc-gaps-") as tmp:
            base = Path(tmp)

            # 1. Appending a bogus file:symbol anchor to docs/cli-and-mcp.md turns check RED.
            c1 = base / "bogus-anchor"
            _stage_copy(c1)
            doc1 = c1 / "docs" / "cli-and-mcp.md"
            doc1.write_text(doc1.read_text(encoding="utf-8") + "\nBogus: `open_fleet/cli.py:nonexistent_symbol_xyz`\n", encoding="utf-8")
            r1 = SURFACE.check_coverage(c1)
            self.assertFalse(r1["ok"])
            self.assertTrue(any("nonexistent_symbol_xyz" in e for e in r1["errors"]), r1["errors"])

            # 2. Dropping `open-fleet doctor` from ## Unified CLI Commands (even while Quickstart still
            # mentions it) plus dropping an MCP tool, MCP resource, and Action output all turn check RED.
            c2 = base / "dropped-entities"
            _stage_copy(c2)
            doc2 = c2 / "docs" / "cli-and-mcp.md"
            lines = doc2.read_text(encoding="utf-8").splitlines()
            lines = [ln for ln in lines if not ln.startswith("| `open-fleet doctor ")]
            text2 = "\n".join(lines).replace("`fleet_doctor`", "`fleet_redacted`")
            text2 = text2.replace("`open-fleet://catalog/overview`", "`open-fleet://redacted`")
            text2 = text2.replace("`overall-ok`", "`redacted-out`")
            doc2.write_text(text2 + "\n", encoding="utf-8")
            r2 = SURFACE.check_coverage(c2)
            self.assertFalse(r2["ok"])
            self.assertTrue(any("open-fleet doctor" in e for e in r2["errors"]), r2["errors"])
            self.assertTrue(any("fleet_doctor" in e for e in r2["errors"]), r2["errors"])
            self.assertTrue(any("open-fleet://catalog/overview" in e for e in r2["errors"]), r2["errors"])
            self.assertTrue(any("overall-ok" in e for e in r2["errors"]), r2["errors"])

            # 3. Unlinked plain-text mention in README.md fails Markdown link reachability.
            c3 = base / "unlinked-readme"
            _stage_copy(c3)
            (c3 / "README.md").write_text("See docs/cli-and-mcp.md without a markdown link.\n", encoding="utf-8")
            r3 = SURFACE.check_coverage(c3)
            self.assertFalse(r3["ok"])
            self.assertFalse(r3["reachability"]["README.md"])

            # 4. Missing action.yml fails closed (never vacuous 0 outputs OK).
            c4 = base / "missing-action"
            _stage_copy(c4)
            (c4 / ".github" / "actions" / "open-fleet-verify" / "action.yml").unlink()
            r4 = SURFACE.check_coverage(c4)
            self.assertFalse(r4["ok"])
            self.assertTrue(any("action.yml" in e for e in r4["errors"]), r4["errors"])

            # 5. Missing docs/cli-and-mcp.md fails cleanly via CLI main() with exit 1 (no KeyError).
            c5 = base / "missing-doc"
            _stage_copy(c5)
            (c5 / "docs" / "cli-and-mcp.md").unlink()
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = SURFACE.main(["--root", str(c5), "--check"])
            self.assertEqual(rc, 1)
            self.assertIn("missing", err.getvalue())
            SURFACE._load_open_fleet(ROOT)


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
