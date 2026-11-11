#!/usr/bin/env python3
"""Contract tests for runtime/scripts/quarantine_check.py (#558).

The properties that make the deny-list a switch rather than a suggestion:
entries are human acts (shape refuses anything else), a malformed list never
reads as an empty one, the matching rule is the same function every gate
calls, and the shipped (empty) list is clean against the real catalog.
"""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "runtime" / "scripts" / "quarantine_check.py"

_spec = importlib.util.spec_from_file_location("quarantine_check", SCRIPT)
qc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qc)


def entry(component="pack:gstack", ref="*", **over):
    base = {"component": component, "ref": ref, "reason": "compromised upstream",
            "date": "2026-10-14", "by": "human:maintainer"}
    base.update(over)
    return base


class Shape(unittest.TestCase):
    def parse(self, entries):
        return qc.parse_quarantine({"quarantined": entries})

    def test_valid_entry(self):
        entries, errors = self.parse([entry()])
        self.assertEqual(errors, [])
        self.assertEqual(entries[0]["kind"], "pack")

    def test_non_human_by_is_refused(self):
        _, errors = self.parse([entry(by="coordinator")])
        self.assertTrue(any("human" in e for e in errors))

    def test_bare_human_prefix_and_agent_roles_are_refused(self):
        reserved_literals = (
            "agent", "ai", "anonymous", "auto", "automatic", "bot", "coordinator", "fleet",
            "human", "model", "nobody", "none", "orca", "system", "unknown", "worker",
        )
        self.assertEqual(set(reserved_literals), set(qc._RESERVED_HUMAN_NAMES))
        for by in ("human:", "human:agent", "human:coordinator", "human:Worker", "human:unknown",
                   *(f"human:{role}" for role in reserved_literals)):
            _, errors = self.parse([entry(by=by)])
            self.assertTrue(errors, by)

    def test_missing_reason_is_refused(self):
        _, errors = self.parse([entry(reason="  ")])
        self.assertTrue(errors)

    def test_unknown_kind_is_refused(self):
        _, errors = self.parse([entry(component="widget:thing")])
        self.assertTrue(errors)

    def test_bad_date_is_refused(self):
        _, errors = self.parse([entry(date="next week")])
        self.assertTrue(errors)

    def test_short_ref_is_refused(self):
        _, errors = self.parse([entry(ref="abc123")])
        self.assertTrue(errors)

    def test_top_level_shape_is_refused(self):
        _, errors = qc.parse_quarantine({"nope": []})
        self.assertTrue(errors)

    def test_non_object_entry_is_refused(self):
        _, errors = self.parse(["pack:gstack"])
        self.assertTrue(any("not an object" in e for e in errors))


class Matching(unittest.TestCase):
    VIEW = {
        "missions": {"ship-it", "review-it"},
        "composes": {"ship-it": {"build-change", "risk-review"}, "review-it": set()},
        "pins": {"gstack": "71f6048e", "orca": "2bb20586ebc39d605e16d95f57420e20a16e7485"},
    }

    def found(self, entries, view=None):
        parsed, errors = qc.parse_quarantine({"quarantined": entries})
        self.assertEqual(errors, [])
        return qc.violations(parsed, view or self.VIEW)

    def test_mission_present(self):
        self.assertTrue(self.found([entry(component="mission:ship-it")]))

    def test_mission_absent(self):
        self.assertEqual(self.found([entry(component="mission:nope")]), [])

    def test_playbook_composed(self):
        self.assertTrue(self.found([entry(component="playbook:risk-review")]))

    def test_playbook_not_composed(self):
        self.assertEqual(self.found([entry(component="playbook:other")]), [])

    def test_pack_star_matches_any_pin(self):
        self.assertTrue(self.found([entry(component="pack:gstack", ref="*")]))

    def test_pack_ref_prefix_both_ways(self):
        self.assertTrue(self.found([entry(component="pack:gstack", ref="71f6048e")]))
        self.assertTrue(self.found(
            [entry(component="pack:orca", ref="2bb20586")]))

    def test_pack_other_commit_is_clean(self):
        self.assertEqual(self.found([entry(component="pack:gstack", ref="deadbeef")]), [])

    def test_pack_unpinned_is_clean(self):
        self.assertEqual(self.found([entry(component="pack:nope")]), [])


def write_catalog(root: Path, quarantined, layout="catalog"):
    (root / "runtime").mkdir(parents=True)
    (root / "runtime" / "quarantine.json").write_text(
        json.dumps({"quarantined": quarantined}))
    skill = root if layout == "copied" else root / "skills" / "ship-it"
    skill.mkdir(parents=True, exist_ok=True)
    protocols = root / "playbooks" if layout == "catalog" else skill / "references"
    protocols.mkdir()
    (protocols / "risk-review.md").write_text("# x\n")
    policies = root / "runtime" if layout == "catalog" else protocols
    (policies / "evidence-manifest.md").write_text("# Runtime policy — evidence\n")
    (skill / "SKILL.md").write_text("Composes `risk-review`; rides `evidence-manifest`.\n")
    return skill, protocols


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        return subprocess.run([sys.executable, str(SCRIPT), *argv],
                              capture_output=True, text=True, timeout=60)

    def test_mission_mode_refuses_quarantined_playbook(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_catalog(Path(tmp), [entry(component="playbook:risk-review")])
            result = self.run_cli("--root", tmp, "--mission", "ship-it")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_catalog_mode_clean_when_nothing_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_catalog(Path(tmp), [entry(component="mission:ship-it")])
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("present in the catalog", result.stdout)

    def test_malformed_file_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_text("{broken")
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 3)

    def test_directory_at_deny_list_path_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "runtime" / "quarantine.json").mkdir(parents=True)
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 3)

    def test_invalid_utf8_cannot_evaluate_not_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_bytes(b"\xff\xfe{}")
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 3)
            self.assertNotIn("Traceback", result.stderr)

    def test_broken_pins_beside_pack_entry_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_catalog(root, [entry(component="pack:gstack")])
            (root / "runtime" / "pins.json").write_text("{broken")
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("cannot be cleared", result.stdout)

    def test_broken_pins_without_pack_entries_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_catalog(root, [])
            (root / "runtime" / "pins.json").write_text("{broken")
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bundle_layout_playbooks_are_checked(self):
        # The dist bundle vendors playbooks under skills/<m>/references/ and
        # has no playbooks/ dir; a playbook quarantine must still refuse there.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_text(
                json.dumps({"quarantined": [entry(component="playbook:risk-review")]}))
            refs = root / "skills" / "ship-it" / "references"
            refs.mkdir(parents=True)
            (refs / "risk-review.md").write_text("# x\n")
            (root / "skills" / "ship-it" / "SKILL.md").write_text(
                "Composes `risk-review`.\n")
            result = self.run_cli("--root", tmp, "--mission", "ship-it")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_copied_bundle_root_layout_is_checked(self):
        # Root IS the mission directory (copied single-mission bundle):
        # SKILL.md and references/ at the top. A clean list must start it;
        # a playbook quarantine must refuse it.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SKILL.md").write_text("Composes `risk-review`.\n")
            refs = root / "references"
            refs.mkdir()
            (refs / "risk-review.md").write_text("# x\n")
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_text(
                json.dumps({"quarantined": []}))
            clean = self.run_cli("--root", tmp, "--mission", "ship-it")
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
            (root / "runtime" / "quarantine.json").write_text(
                json.dumps({"quarantined": [entry(component="playbook:risk-review")]}))
            refused = self.run_cli("--root", tmp, "--mission", "ship-it")
            self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)

    def test_missing_mission_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_text(
                json.dumps({"quarantined": []}))
            result = self.run_cli("--root", tmp, "--mission", "ghost")
            self.assertEqual(result.returncode, 3)
            self.assertNotIn("Traceback", result.stderr)

    def test_missing_composed_dependency_refuses_in_each_layout(self):
        # The declaration is authoritative even when copying lost the file.
        # This seam checks refusal and a useful path, not the copy operation.
        for layout in ("catalog", "bundle", "copied"):
            for declaration in ("`risk-review`", "risk-review.md", "`risk-review.md`"):
                with self.subTest(layout=layout, declaration=declaration), \
                        tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    skill, protocols = write_catalog(
                        root, [entry(component="playbook:risk-review")], layout)
                    (protocols / "risk-review.md").unlink()
                    (skill / "SKILL.md").write_text(f"Composes {declaration}.\n")
                    result = self.run_cli("--root", tmp, "--mission", "ship-it")
                    self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                    self.assertIn("risk-review.md", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_unusable_dependency_refuses_mission_and_catalog_checks(self):
        for mode in (("--mission", "ship-it"), ("--catalog",)):
            layouts = ("catalog", "bundle", "copied") if mode[0] == "--mission" else ("catalog", "bundle")
            for layout in layouts:
                for state in ("directory", "broken-link", "invalid-utf8"):
                    with self.subTest(mode=mode, layout=layout, state=state), \
                            tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        _, protocols = write_catalog(root, [], layout)
                        dependency = protocols / "risk-review.md"
                        dependency.unlink()
                        if state == "directory":
                            dependency.mkdir()
                        elif state == "broken-link":
                            dependency.symlink_to("missing-protocol.md")
                        else:
                            dependency.write_bytes(b"\xff\xfe")
                        result = self.run_cli("--root", tmp, *mode)
                        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                        self.assertIn(str(dependency), result.stderr)
                        self.assertNotIn("Traceback", result.stderr)

    def test_runtime_policies_resolve_and_ambiguous_bundle_names_still_match(self):
        for layout in ("catalog", "bundle", "copied"):
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                skill, protocols = write_catalog(root, [], layout)
                (skill / "SKILL.md").write_text(
                    "Composes risk-review.md; rides `evidence-manifest`.\n")
                clean = self.run_cli("--root", tmp, "--mission", "ship-it")
                self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
                entries, errors = qc.parse_quarantine({
                    "quarantined": [entry(component="playbook:evidence-manifest")]})
                self.assertEqual(errors, [])
                # A catalog knows the runtime directory's identity; a flat
                # bundle cannot exempt the same name on content alone.
                view = qc.mission_view(root, "ship-it")
                self.assertEqual(len(qc.violations(entries, view)), 0 if layout == "catalog" else 1)
                policies = root / "runtime" if layout == "catalog" else protocols
                (policies / "evidence-manifest.md").unlink()
                refused = self.run_cli("--root", tmp, "--mission", "ship-it")
                self.assertEqual(refused.returncode, 3, refused.stdout + refused.stderr)
                self.assertIn("evidence-manifest.md", refused.stderr)

    def test_bare_md_and_unknown_bundle_heading_retain_playbook_edge(self):
        for heading in ("", "# x\n", "# Runtime example\n", "# Playbook — risk-review\n"):
            with self.subTest(heading=heading), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                skill, protocols = write_catalog(
                    root, [entry(component="playbook:risk-review")], "copied")
                (protocols / "risk-review.md").write_text(heading)
                (skill / "SKILL.md").write_text("Composes risk-review.md.\n")
                result = self.run_cli("--root", tmp, "--mission", "ship-it")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_absent_file_says_no_quarantine_in_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli("--root", tmp, "--catalog")
            self.assertEqual(result.returncode, 0)
            self.assertIn("no quarantine in force", result.stderr)


class MainInProcess(unittest.TestCase):
    """main() through the library door, mirroring the Cli cases above.

    validate.py and preflight.py import this module's functions, and the
    CLI is a thin shell over them; pinning both doors keeps a refactor of
    one from drifting away from the other."""

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = qc.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_dependency_heading_cannot_change_quarantine_identity(self):
        # The declaration and in-memory deny-list stay fixed: only the
        # referenced document changes, so it cannot authorize its own use.
        entries, errors = qc.parse_quarantine({
            "quarantined": [entry(component="playbook:risk-review")]})
        self.assertEqual(errors, [])
        for layout in ("catalog", "bundle", "copied"):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                _, protocols = write_catalog(root, [], layout)
                policy = root / "runtime" / "quarantine.json"
                unchanged_policy = policy.read_bytes()
                for heading in ("# Playbook — risk-review", "# Runtime policy — risk-review",
                                "# Runtime pin — risk-review", "# unknown", ""):
                    with self.subTest(layout=layout, heading=heading):
                        (protocols / "risk-review.md").write_text(heading + "\n")
                        view = qc.mission_view(root, "ship-it")
                        self.assertIn("risk-review", view["composes"]["ship-it"])
                        self.assertEqual(len(qc.violations(entries, view)), 1)
                        self.assertEqual(policy.read_bytes(), unchanged_policy)

    def test_mission_mode_refuses_quarantined_playbook(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_catalog(Path(tmp), [entry(component="playbook:risk-review")])
            rc, out, _ = self.run_main("--root", tmp, "--mission", "ship-it")
            self.assertEqual(rc, 2)
            self.assertIn("QUARANTINED", out)

    def test_catalog_mode_reports_present_mission_and_stays_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_catalog(Path(tmp), [entry(component="mission:ship-it")])
            rc, out, _ = self.run_main("--root", tmp, "--catalog")
            self.assertEqual(rc, 0)
            self.assertIn("present in the catalog", out)

    def test_malformed_and_unusable_files_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_text("{broken")
            rc, _, _ = self.run_main("--root", tmp, "--catalog")
            self.assertEqual(rc, 3)
            (root / "runtime" / "quarantine.json").write_bytes(b"\xff\xfe{}")
            rc, _, _ = self.run_main("--root", tmp, "--catalog")
            self.assertEqual(rc, 3)
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "runtime" / "quarantine.json").mkdir(parents=True)
            rc, _, _ = self.run_main("--root", tmp, "--catalog")
            self.assertEqual(rc, 3)

    def test_absent_file_and_bad_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, _, err = self.run_main("--root", tmp, "--catalog")
            self.assertEqual(rc, 0)
            self.assertIn("no quarantine in force", err)
            rc, _, _ = self.run_main("--root", str(Path(tmp) / "nope"), "--catalog")
            self.assertEqual(rc, 3)

    def test_missing_mission_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "runtime" / "quarantine.json").write_text(
                json.dumps({"quarantined": []}))
            rc, _, _ = self.run_main("--root", tmp, "--mission", "ghost")
            self.assertEqual(rc, 3)

    def test_broken_pins_beside_pack_entry_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_catalog(root, [entry(component="pack:gstack")])
            (root / "runtime" / "pins.json").write_text("{broken")
            rc, out, _ = self.run_main("--root", tmp, "--catalog")
            self.assertEqual(rc, 2)
            self.assertIn("cannot be cleared", out)

    def test_pins_view_unusable_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            pins, error = qc.pins_view(root)
            self.assertEqual((pins, error), ({}, None))
            (root / "runtime" / "pins.json").write_text("[1, 2]")
            pins, error = qc.pins_view(root)
            self.assertEqual(pins, {})
            self.assertIn("expected a JSON object", error)
            (root / "runtime" / "pins.json").unlink()
            (root / "runtime" / "pins.json").mkdir()
            pins, error = qc.pins_view(root)
            self.assertEqual(pins, {})
            self.assertIn("not a regular file", error)


class ShippedTree(unittest.TestCase):
    def test_generated_and_copied_bundles_keep_catalog_playbook_edges(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as records:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "bundle.py"), "--out", tmp],
                # its build record goes to scratch, not into the source checkout's git directory
                env={**os.environ, "OPEN_FLEET_BUNDLE_RECORDS": records},
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            catalog = qc.catalog_view(ROOT)
            bundled = qc.catalog_view(Path(tmp))
            entries, errors = qc.parse_quarantine({"quarantined": [
                entry(component=f"playbook:{doc.stem}")
                for doc in sorted((ROOT / "playbooks").glob("*.md"))]})
            self.assertEqual(errors, [])
            self.assertEqual(qc.violations(entries, bundled), qc.violations(entries, catalog))
            for mission, playbooks in catalog["composes"].items():
                self.assertTrue(playbooks <= bundled["composes"][mission], mission)
                copied = qc.mission_view(Path(tmp) / "skills" / mission, mission)
                self.assertEqual(copied["composes"][mission], bundled["composes"][mission], mission)

    def test_shipped_deny_list_is_well_formed_and_clean(self):
        entries, errors, present = qc.load_quarantine(ROOT)
        self.assertTrue(present, "runtime/quarantine.json must ship in this repo")
        self.assertEqual(errors, [])
        view = qc.catalog_view(ROOT)
        self.assertEqual(
            qc.violations(entries, {**view, "missions": set()}), [])

    def test_every_mission_start_names_itself_to_preflight(self):
        # The refusal only fires where a mission start passes --mission; a
        # mission that drops it would silently un-quarantine itself.
        for skill_dir in sorted((ROOT / "skills").iterdir()):
            if skill_dir.is_dir():
                text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
                self.assertIn(f"--mission {skill_dir.name}", text, skill_dir.name)


if __name__ == "__main__":
    unittest.main()
