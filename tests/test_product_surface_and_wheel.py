"""Contract tests for product-surface documentation coverage (document-it) and wheel packaging."""
import importlib.util
import io
import shutil
import subprocess
import sys
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
CHECK = _load("scripts/check.py", "check_py_surface_wiring_test")


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
        # Verify local fast-loop wiring in scripts/check.py.
        steps = dict(CHECK.plan(1, suite=False, ruff="ruff"))
        self.assertIn("product-surface", steps)
        self.assertEqual(steps["product-surface"][-2:], ["scripts/extract_product_surface.py", "--check"])

    def test_rename_negative_control_turns_claim_check_red(self):
        """document-it negative control: renaming a doc-anchored symbol turns --check RED in a fresh process."""
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
                # across ALL callers (cli, mcp_server, ui_server) so fresh import succeeds cleanly.
                solo_py = copy / "open_fleet" / "solo_review.py"
                text = solo_py.read_text(encoding="utf-8")
                self.assertIn("def run_solo_review(", text)
                solo_py.write_text(text.replace("def run_solo_review(", "def run_solo_review_renamed(", 1), encoding="utf-8")
                for rel in ("open_fleet/cli.py", "open_fleet/mcp_server.py", "open_fleet/ui_server.py"):
                    p = copy / rel
                    p.write_text(p.read_text(encoding="utf-8").replace("run_solo_review", "run_solo_review_renamed"), encoding="utf-8")

                # 1. In-process check (verifies unconditional reload — no stale sys.modules cache).
                mutated = SURFACE.check_coverage(copy)
                self.assertFalse(mutated["ok"], "rename control stayed GREEN instead of turning RED")
                self.assertTrue(
                    any("open_fleet/solo_review.py:run_solo_review" in e for e in mutated["errors"]),
                    mutated["errors"],
                )

                # 2. Fresh isolated subprocess check (proves mutated tree imports cleanly with zero ImportError).
                proc = subprocess.run(
                    [sys.executable, "-I", str(ROOT / "scripts" / "extract_product_surface.py"),
                     "--root", str(copy), "--check"],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn("broken symbol anchor: open_fleet/solo_review.py:run_solo_review", proc.stderr)
                self.assertNotIn("ImportError", proc.stderr)
            finally:
                SURFACE._load_open_fleet(ROOT)

    def test_bogus_anchor_dropped_entities_and_missing_files_fail_closed(self):
        """Negative controls for bogus anchors, dropped docs, broken links, empty surfaces, and missing files."""
        with tempfile.TemporaryDirectory(prefix="open-fleet-doc-gaps-") as tmp:
            base = Path(tmp)
            try:
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

                # 3. Broken Markdown links & plain-text mentions fail reachability for BOTH README.md and docs/README.md.
                c3 = base / "broken-links"
                _stage_copy(c3)
                (c3 / "README.md").write_text(
                    "See docs/cli-and-mcp.md and [wrong](nonexistent/docs/cli-and-mcp.md) and [ext](https://example.com/docs/cli-and-mcp.md).\n",
                    encoding="utf-8",
                )
                (c3 / "docs" / "README.md").write_text(
                    "Broken relative prefix: [CLI](docs/cli-and-mcp.md) and plain cli-and-mcp.md.\n",
                    encoding="utf-8",
                )
                r3 = SURFACE.check_coverage(c3)
                self.assertFalse(r3["ok"])
                self.assertFalse(r3["reachability"]["README.md"])
                self.assertFalse(r3["reachability"]["docs/README.md"])

                # 4. Missing action.yml and empty outputs: both fail closed (never vacuous 0 outputs OK).
                c4 = base / "missing-action"
                _stage_copy(c4)
                (c4 / ".github" / "actions" / "open-fleet-verify" / "action.yml").unlink()
                r4 = SURFACE.check_coverage(c4)
                self.assertFalse(r4["ok"])
                self.assertTrue(any("action.yml" in e for e in r4["errors"]), r4["errors"])

                c4b = base / "empty-outputs"
                _stage_copy(c4b)
                (c4b / ".github" / "actions" / "open-fleet-verify" / "action.yml").write_text("name: test\noutputs:\n", encoding="utf-8")
                r4b = SURFACE.check_coverage(c4b)
                self.assertFalse(r4b["ok"])
                self.assertTrue(any("0 Action outputs" in e for e in r4b["errors"]), r4b["errors"])

                # 5. Missing docs/cli-and-mcp.md exits 1 cleanly (no KeyError); missing root exits 2.
                c5 = base / "missing-doc"
                _stage_copy(c5)
                (c5 / "docs" / "cli-and-mcp.md").unlink()
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    rc = SURFACE.main(["--root", str(c5), "--check"])
                self.assertEqual(rc, 1)
                self.assertIn("missing", err.getvalue())

                out2, err2 = io.StringIO(), io.StringIO()
                with redirect_stdout(out2), redirect_stderr(err2):
                    rc2 = SURFACE.main(["--root", str(base / "does-not-exist"), "--check"])
                self.assertEqual(rc2, 2)
                self.assertIn("ERROR:", err2.getvalue())
            finally:
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
