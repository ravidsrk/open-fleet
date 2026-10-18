#!/usr/bin/env python3
"""Contract tests for runtime/scripts/diff_scope.py.

The classification table is easy to test and easy to get wrong in a way nobody
notices. What matters more is the exit contract: "we could not look" and
"nothing matched" must both be loud, because a silent all-false gates every
review lens off and records a legitimate-looking zero.
"""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCOPE = ROOT / "runtime" / "scripts" / "diff_scope.py"
_spec = importlib.util.spec_from_file_location("diff_scope", SCOPE)
diff_scope = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diff_scope)


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=check)


def write(repo, rel, text=""):
    p = Path(repo) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class ScopeBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="diffscope-")
        self.repo = Path(self.tmp) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        write(self.repo, "README.md", "# base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base")
        git(self.repo, "checkout", "-q", "-b", "work")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_scope(self, *args):
        return subprocess.run([sys.executable, str(SCOPE), "--repo", str(self.repo), *args],
                              capture_output=True, text=True)

    def flags(self, *args):
        r = self.run_scope("--base", "main", "--json", *args)
        return json.loads(r.stdout), r

    def assert_flag(self, name, rel, content=""):
        write(self.repo, rel, content)
        data, r = self.flags()
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"][name], f"{rel} should set SCOPE_{name}: {data['flags']}")


class TestPartiallyMatchedDiff(ScopeBase):
    """#314: `unmatched` was reported only when NOTHING matched. A diff half in-scope and half
    somewhere else exited 0 with the out-of-scope half invisible — the shape most likely to
    matter, since a review lens gating on the flag set sees a clean answer."""

    def _half_matched(self):
        write(self.repo, "tests/test_thing.py", "def test_x():\n    assert True\n")   # TESTS
        write(self.repo, "odd/thing.qqq", "opaque\n")                                  # nothing

    def test_the_unmatched_half_is_reported_in_text_output(self):
        self._half_matched()
        r = self.run_scope("--base", "main")
        self.assertEqual(r.returncode, 0, "a partial match is not an error")
        self.assertIn("SCOPE_TESTS=true", r.stdout)
        self.assertIn("odd/thing.qqq", r.stdout,
                      f"the out-of-scope half must be visible: {r.stdout}")

    def test_the_unmatched_half_is_in_json(self):
        self._half_matched()
        data, r = self.flags()
        self.assertIsNone(data["error"], r.stdout)
        self.assertTrue(data["flags"]["TESTS"])
        self.assertIn("odd/thing.qqq", data["unmatched"])

    def test_strict_turns_any_unmatched_path_into_a_nonzero_exit(self):
        self._half_matched()
        r = self.run_scope("--base", "main", "--strict")
        self.assertEqual(r.returncode, 2, f"--strict must gate on unmatched: {r.stdout}")
        self.assertIn("SCOPE_ERROR=unmatched", r.stdout)

    def test_strict_is_opt_in_and_a_fully_matched_diff_still_passes(self):
        write(self.repo, "tests/test_thing.py", "def test_x():\n    assert True\n")
        r = self.run_scope("--base", "main", "--strict")
        self.assertEqual(r.returncode, 0, f"nothing unmatched, so --strict is quiet: {r.stdout}")


class TestExitContract(ScopeBase):
    def test_unresolvable_base_is_no_base_and_exit_2(self):
        r = self.run_scope("--base", "origin/nope")
        self.assertEqual(r.returncode, 2, "a green here would mean we could not look")
        self.assertIn("SCOPE_ERROR=no_base", r.stdout)
        self.assertIn("SCOPE_FRONTEND=false", r.stdout)

    def test_no_changes_is_a_legitimate_clean_zero(self):
        r = self.run_scope("--base", "main")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("SCOPE_ERROR", r.stdout)
        self.assertIn("SCOPE_BACKEND=false", r.stdout)

    def test_changed_but_unmatched_is_exit_2_and_prints_the_paths(self):
        write(self.repo, "weirdlayout/thing.qqq", "x")
        r = self.run_scope("--base", "main")
        self.assertEqual(r.returncode, 2)
        self.assertIn("SCOPE_ERROR=unmatched", r.stdout)
        self.assertIn("# unmatched: weirdlayout/thing.qqq", r.stdout)

    def test_output_is_shell_safe(self):
        write(self.repo, "src/app.py", "x = 1\n")
        r = self.run_scope("--base", "main")
        for line in r.stdout.splitlines():
            self.assertTrue(line.startswith("#") or "=" in line,
                            f"non-sourceable line: {line!r}")

    def test_help_exits_zero(self):
        r = subprocess.run([sys.executable, str(SCOPE), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--base", r.stdout)

    def test_every_flag_is_printed_even_when_false(self):
        r = self.run_scope("--base", "main")
        for name in ("FRONTEND", "BACKEND", "PROMPTS", "TESTS", "DOCS", "CONFIG",
                     "MIGRATIONS", "API", "AUTH", "SECURITY", "A11Y", "PERF"):
            self.assertIn(f"SCOPE_{name}=", r.stdout)


class TestDiffAcquisition(ScopeBase):
    def test_each_failed_required_read_is_exit_2(self):
        write(self.repo, "staged.py", "value = 1\n")
        git(self.repo, "add", "staged.py")
        write(self.repo, "new.py", "value = 2\n")
        real_run = subprocess.run
        for phase in ("committed", "working-tree", "untracked"):
            for failure in (128, subprocess.TimeoutExpired("git", 60), OSError("unavailable")):
                with self.subTest(phase=phase, failure=failure):
                    def failing_read(argv, phase=phase, failure=failure, **kwargs):
                        target = ("untracked" if "ls-files" in argv else
                                  "committed" if "main...HEAD" in argv else
                                  "working-tree" if "diff" in argv and "HEAD" in argv else None)
                        if target == phase:
                            if isinstance(failure, Exception):
                                raise failure
                            return subprocess.CompletedProcess(argv, failure, "", "read failed")
                        return real_run(argv, **kwargs)

                    out = io.StringIO()
                    with mock.patch.object(diff_scope.subprocess, "run", side_effect=failing_read), \
                            contextlib.redirect_stdout(out):
                        rc = diff_scope.main(["--repo", str(self.repo), "--base", "main", "--strict", "--json"])
                    self.assertEqual(rc, 2, out.getvalue())
                    self.assertEqual(json.loads(out.getvalue())["error"], "diff_failed")

    def test_failed_diff_is_loud_in_shell_output(self):
        real_git = diff_scope.git
        def fail_diff(repo, *args, **kwargs):
            return None if args[0] == "diff" else real_git(repo, *args, **kwargs)
        out = io.StringIO()
        with mock.patch.object(diff_scope, "git", side_effect=fail_diff), contextlib.redirect_stdout(out):
            rc = diff_scope.main(["--repo", str(self.repo), "--base", "main"])
        self.assertEqual(rc, 2, out.getvalue())
        self.assertIn("SCOPE_ERROR=diff_failed", out.getvalue())

    def test_external_diff_and_textconv_do_not_hide_changed_paths(self):
        write(self.repo, "app.py", "value = 1\n")
        git(self.repo, "add", "app.py")
        git(self.repo, "commit", "-qm", "app")
        git(self.repo, "branch", "snapshot")
        git(self.repo, "config", "diff.hidden.command", "false")
        git(self.repo, "config", "diff.hidden.textconv", "true")
        write(self.repo, ".git/info/attributes", "*.py diff=hidden\n")
        write(self.repo, "app.py", "value = 2\n")
        with mock.patch.dict(os.environ, {"GIT_EXTERNAL_DIFF": "false"}):
            r = self.run_scope("--base", "snapshot", "--strict", "--json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(json.loads(r.stdout)["flags"]["BACKEND"])


class TestHardenedGit(ScopeBase):
    def test_git_is_resolved_to_an_absolute_path(self):
        self.assertTrue(Path(diff_scope.GIT).is_absolute(), diff_scope.GIT)

    def test_replace_refs_do_not_swap_the_compared_base(self):
        # A `refs/replace/` ref pointing main's commit at one carrying tests/ would make the
        # diff against main hide a test change; GIT_NO_REPLACE_OBJECTS reads the real commit.
        write(self.repo, "tests/test_thing.py", "def test_x():\n    assert True\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "work")
        fake = git(self.repo, "commit-tree", "HEAD^{tree}", "-m", "fake").stdout.strip()
        git(self.repo, "replace", "main", fake)
        data, r = self.flags()
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["TESTS"], data["flags"])

    def test_repo_fsmonitor_command_does_not_run(self):
        marker = Path(self.tmp) / "fsmonitor-ran"
        hook = write(self.repo, "hook.sh", f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        git(self.repo, "config", "core.fsmonitor", str(hook))
        self.flags()
        self.assertFalse(marker.exists())


class TestPathClassification(ScopeBase):
    def test_frontend_component(self):
        self.assert_flag("FRONTEND", "app/components/Button.tsx", "export const B = () => null;\n")

    def test_frontend_stylesheet(self):
        self.assert_flag("FRONTEND", "styles/main.scss", ".a { color: red; }\n")

    def test_backend_source(self):
        self.assert_flag("BACKEND", "lib/worker.py", "def go():\n    return 1\n")

    def test_backend_excludes_frontend_view_files(self):
        write(self.repo, "app/components/Button.tsx", "export const B = () => null;\n")
        data, _ = self.flags()
        self.assertTrue(data["flags"]["FRONTEND"])
        self.assertFalse(data["flags"]["BACKEND"], "a view file is not backend")

    def test_tests_directory(self):
        self.assert_flag("TESTS", "tests/test_worker.py", "def test_x():\n    assert True\n")

    def test_spec_suffix(self):
        self.assert_flag("TESTS", "lib/worker.spec.ts", "it('x', () => {});\n")

    def test_docs(self):
        self.assert_flag("DOCS", "docs/guide.md", "# guide\n")

    def test_config_yaml(self):
        self.assert_flag("CONFIG", ".github/workflows/ci.yml", "on: push\n")

    def test_config_manifest(self):
        self.assert_flag("CONFIG", "package.json", "{}\n")

    def test_migrations(self):
        self.assert_flag("MIGRATIONS", "db/migrate/20260101_add_users.rb", "class X; end\n")

    def test_api_route_file(self):
        self.assert_flag("API", "app/controllers/users_controller.rb", "class C; end\n")

    def test_api_schema(self):
        self.assert_flag("API", "schema/public.graphql", "type Q { a: Int }\n")

    def test_auth_path(self):
        self.assert_flag("AUTH", "lib/session_store.py", "SESSION = {}\n")

    def test_security_path(self):
        self.assert_flag("SECURITY", "lib/crypto_helpers.py", "KEY = 1\n")

    def test_a11y_path(self):
        self.assert_flag("A11Y", "docs/a11y-notes.md", "# notes\n")

    def test_perf_path(self):
        self.assert_flag("PERF", "bench/throughput.py", "N = 1\n")

    def test_prompts_path(self):
        self.assert_flag("PROMPTS", "skills/ship-it/SKILL.md", "---\nname: x\n---\n")


class TestGeneratedBadges(ScopeBase):
    def test_whitespace_only_unknown_paths_survive_every_enumeration_source(self):
        unknown = [" ", "\t", "\n"]
        for name in unknown:
            write(self.repo, name, "{}\n")
        for source in ("untracked", "staged", "committed", "unstaged"):
            if source == "staged":
                git(self.repo, "add", "--", *unknown)
            elif source == "committed":
                git(self.repo, "commit", "-qm", "whitespace filenames")
            elif source == "unstaged":
                # Move the comparison base so only the working-tree read supplies them.
                git(self.repo, "branch", "-f", "main", "HEAD")
                for name in unknown:
                    write(self.repo, name, "changed\n")
            for with_badge in (False, True):
                with self.subTest(source=source, with_badge=with_badge):
                    badge = self.repo / "assets/badges/tests.json"
                    if with_badge:
                        write(self.repo, "assets/badges/tests.json", "{}\n")
                    try:
                        data, r = self.flags("--strict")
                        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                        self.assertEqual(data["error"], "unmatched")
                        self.assertEqual(sorted(data["unmatched"]), sorted(unknown))
                        self.assertEqual(data["flags"]["DOCS"], with_badge)
                    finally:
                        if with_badge:
                            badge.unlink()

    def test_supported_generated_payloads_are_docs_in_strict_mode(self):
        # These exact outputs are public README badges from scripts/gen-badges.py.
        # The expected classification is independent of the classifier's rule table.
        for name in ("tests.json", "missions.json"):
            with self.subTest(name=name):
                badge = write(self.repo, f"assets/badges/{name}", '{"schemaVersion": 1}\n')
                data, r = self.flags("--strict")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertTrue(data["flags"]["DOCS"])
                self.assertEqual(data["unmatched"], [])
                badge.unlink()

    def test_generated_badge_does_not_exempt_unknown_neighbors(self):
        write(self.repo, "assets/badges/tests.json", "{}\n")
        unknown = ["assets/badges/other.json", "assets/badges/tests.json.bak",
                   "assets/other.json", "nested/assets/badges/missions.json", "odd/thing.qqq"]
        for path in unknown:
            write(self.repo, path, "{}\n")
        data, r = self.flags("--strict")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(data["error"], "unmatched")
        self.assertEqual(sorted(data["unmatched"]), sorted(unknown))


class TestContentClassification(ScopeBase):
    def test_security_by_content(self):
        self.assert_flag("SECURITY", "lib/tool.py", "import subprocess\nsubprocess.run(['ls'], shell=True)\n")

    def test_a11y_by_content(self):
        self.assert_flag("A11Y", "web/page.html", '<button aria-label="close">x</button>\n')

    def test_perf_by_content(self):
        self.assert_flag("PERF", "lib/hot.py", "from functools import lru_cache\n@lru_cache\ndef f():\n    return 1\n")

    def test_auth_by_content(self):
        self.assert_flag("AUTH", "lib/entry.py", "def handler():\n    return authorize(current_user)\n")

    def test_api_by_content(self):
        self.assert_flag("API", "lib/server.py", "@app.route('/x')\ndef x():\n    return 1\n")

    def test_prompts_by_content(self):
        self.assert_flag("PROMPTS", "lib/gen.py", 'TEMPLATE = "You are a helpful assistant."\n')

    def test_a_deleted_file_contributes_only_path_signals(self):
        write(self.repo, "lib/session_thing.py", "x = 1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "add")
        (self.repo / "lib" / "session_thing.py").unlink()
        data, r = self.flags()
        self.assertTrue(data["flags"]["AUTH"], r.stdout)


class TestUnionOfSources(ScopeBase):
    def test_untracked_file_counts(self):
        write(self.repo, "db/migrate/20260202_new.rb", "class Y; end\n")
        data, _ = self.flags()
        self.assertTrue(data["flags"]["MIGRATIONS"], "a new migration is untracked until the commit")

    def test_committed_change_counts(self):
        write(self.repo, "lib/thing.py", "x = 1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "add")
        data, _ = self.flags()
        self.assertTrue(data["flags"]["BACKEND"])

    def test_staged_but_uncommitted_change_counts(self):
        write(self.repo, "lib/staged.py", "x = 1\n")
        git(self.repo, "add", "-A")
        data, _ = self.flags()
        self.assertTrue(data["flags"]["BACKEND"])

    def test_json_shape(self):
        write(self.repo, "lib/thing.py", "x = 1\n")
        data, _ = self.flags()
        self.assertEqual(sorted(data.keys()), ["base", "error", "flags", "unmatched"])
        self.assertEqual(len(data["flags"]), 12)


class TestScriptShape(unittest.TestCase):
    def test_executable_and_shebanged(self):
        self.assertTrue(os.access(SCOPE, os.X_OK))
        self.assertTrue(SCOPE.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3"))

    def test_docstring_carries_the_classification_table(self):
        text = SCOPE.read_text(encoding="utf-8")
        for flag in ("SCOPE_FRONTEND", "SCOPE_MIGRATIONS", "SCOPE_A11Y", "SCOPE_PERF"):
            self.assertIn(flag, text.split('"""')[1])


class TestScopeOverlaps(ScopeBase):
    def test_detects_tracked_and_glob_overlaps_and_builds_deps(self):
        write(self.repo, "src/routes.py", "ROUTES = []\n")
        write(self.repo, "src/billing.py", "BILLING = 1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "add files")
        spec_file = Path(self.tmp) / "slices.json"
        spec_file.write_text(json.dumps({
            "units": [
                {"id": "slice-auth", "scope": ["src/routes.py", "src/auth/*.py"]},
                {"id": "slice-billing", "scope": ["src/billing.py"]},
                {"id": "slice-admin", "scope": ["src/*.py"]},
            ]
        }), encoding="utf-8")
        r = self.run_scope("--overlap", str(spec_file), "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertIsNone(data["error"])
        self.assertEqual(len(data["overlaps"]), 2)
        self.assertEqual(data["deps"]["slice-auth"], [])
        self.assertEqual(data["deps"]["slice-billing"], [])
        self.assertEqual(data["deps"]["slice-admin"], ["slice-auth", "slice-billing"])

        r_txt = self.run_scope("--overlap", str(spec_file))
        self.assertEqual(r_txt.returncode, 0)
        self.assertIn("OVERLAP_COUNT=2", r_txt.stdout)
        self.assertIn("# overlap: slice-auth -> slice-admin", r_txt.stdout)

    def test_invalid_overlap_spec_exits_2_loudly(self):
        bad_file = Path(self.tmp) / "bad.json"
        bad_file.write_text(json.dumps({"units": [{"id": "u1", "scope": []}]}), encoding="utf-8")
        r = self.run_scope("--overlap", str(bad_file), "--json")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(json.loads(r.stdout)["error"], "invalid_overlap")

        missing = self.run_scope("--overlap", str(Path(self.tmp) / "missing.json"))
        self.assertEqual(missing.returncode, 2)
        self.assertIn("SCOPE_ERROR=invalid_overlap", missing.stdout)

    def test_detects_untracked_intersecting_globs(self):
        spec_file = Path(self.tmp) / "untracked_globs.json"
        spec_file.write_text(json.dumps({
            "units": [
                {"id": "u-reg", "scope": ["src/*registry.py"]},
                {"id": "u-routes", "scope": ["src/routes*.py"]},
                {"id": "u-other", "scope": ["lib/billing_*.py"]},
            ]
        }), encoding="utf-8")
        r = self.run_scope("--overlap", str(spec_file), "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(len(data["overlaps"]), 1)
        self.assertEqual(data["deps"]["u-routes"], ["u-reg"])
        self.assertEqual(data["deps"]["u-other"], [])

    def test_failed_git_read_exits_2_loudly(self):
        spec_file = Path(self.tmp) / "slices.json"
        spec_file.write_text(json.dumps({
            "units": [{"id": "u1", "scope": ["src/*.py"]}]
        }), encoding="utf-8")
        non_repo = Path(self.tmp) / "not-a-repo"
        non_repo.mkdir()
        r = subprocess.run(
            [sys.executable, str(SCOPE), "--repo", str(non_repo), "--overlap", str(spec_file), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 2)
        self.assertEqual(json.loads(r.stdout)["error"], "diff_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
