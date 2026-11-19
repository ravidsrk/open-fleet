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

# Fetched branch names holding a line break (tests/fixtures/refname_breaks.py; W3-07 re-attack).
_rb_spec = importlib.util.spec_from_file_location(
    "refname_breaks", ROOT / "tests" / "fixtures" / "refname_breaks.py")
refname_breaks = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(refname_breaks)
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
                                  # the merge-base diff names the resolved base COMMIT (W3-07)
                                  "committed" if any(str(a).endswith("...HEAD") for a in argv) else
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

    def test_git_absent_at_import_fails_closed_and_never_resolves_later(self):
        # W4-14: `shutil.which("git") or "git"` made "not found at import" fall back to a bare
        # name, so every later call re-resolved against whatever PATH said then — the class
        # gitexec.py raises GitAbsent to avoid. Absent at import is now a could-not-run.
        with mock.patch("shutil.which", return_value=None):
            spec = importlib.util.spec_from_file_location("diff_scope_gitless", SCOPE)
            gitless = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gitless)
        self.assertIsNone(gitless.GIT)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        marker = tmp / "late-git-ran"
        (tmp / "git").write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 0\n', encoding="utf-8")
        (tmp / "git").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": f"{tmp}{os.pathsep}{os.environ.get('PATH', '')}"}):
            self.assertIsNone(gitless.git(self.repo, "rev-parse", "HEAD"))
            with self.assertRaises(gitless.ScopeError):
                gitless._driver_blanks(self.repo)
            with self.assertRaises(gitless.ScopeError):
                gitless.predict_merge(self.repo, "main", "main")
        self.assertFalse(marker.exists(), "a git found on PATH after import answered the call")

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

    def test_the_git_floor_is_gitexecs_whole_floor(self):
        """2026-10-23 review §5: the inlined copy lacked GIT_CONFIG_GLOBAL, GIT_CONFIG_NOSYSTEM
        and safe.directory. Every gitexec.HARDENED setting must reach diff_scope's git child."""
        spec = importlib.util.spec_from_file_location("gitexec", ROOT / "runtime" / "scripts" / "gitexec.py")
        gitexec = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gitexec)
        env = diff_scope._git_env()
        want = {k: v for k, v in gitexec.HARDENED.items() if not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "GIT_CONFIG_COUNT"))}
        self.assertEqual({k: env.get(k) for k in want}, want)
        def pairs(e):
            return {e[f"GIT_CONFIG_KEY_{i}"]: e[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(e["GIT_CONFIG_COUNT"]))}
        ours = pairs(env)
        # diff_scope may pin MORE than gitexec, never less.
        self.assertEqual({k: ours.get(k) for k in pairs(gitexec.HARDENED)}, pairs(gitexec.HARDENED))

    def test_a_global_gitconfig_cannot_hide_an_untracked_migration(self):
        # A global core.excludesFile ignoring everything made the brand-new migration invisible.
        ignore = write(self.tmp, "ignore-all", "*\n")
        glob = write(self.tmp, "global.gitconfig", f"[core]\n\texcludesFile = {ignore}\n")
        write(self.repo, "db/migrate/002_add.rb", "class Add; end\n")
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(glob)}):
            data, r = self.flags()
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["MIGRATIONS"], data["flags"])

    def test_repo_fsmonitor_command_does_not_run(self):
        marker = Path(self.tmp) / "fsmonitor-ran"
        hook = write(self.repo, "hook.sh", f"#!/bin/sh\ntouch '{marker}'\n")
        hook.chmod(0o755)
        git(self.repo, "config", "core.fsmonitor", str(hook))
        self.flags()
        self.assertFalse(marker.exists())


class TestRenamesCountBothSides(ScopeBase):
    """2026-10-23 review, P2-9: rename detection folded a move into its NEW path, so moving a
    migration out of db/migrate/ or renaming session_guard.py never set MIGRATIONS/AUTH."""

    def _on_main(self, rel, text):
        write(self.repo, rel, text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", f"add {rel}")
        git(self.repo, "branch", "-f", "main", "HEAD")

    def test_a_committed_move_out_of_migrations_sets_migrations(self):
        self._on_main("db/migrate/001_init.rb", "class Init\n  def change; end\nend\n")
        (self.repo / "archive").mkdir()
        git(self.repo, "mv", "db/migrate/001_init.rb", "archive/001_init.rb")
        git(self.repo, "commit", "-qm", "move the migration out")
        data, r = self.flags()
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["MIGRATIONS"], f"the old path's lens was dropped: {data['flags']}")

    def test_a_staged_rename_away_from_an_auth_name_sets_auth(self):
        self._on_main("lib/session_guard.py", "def check():\n    return 1\n")
        git(self.repo, "mv", "lib/session_guard.py", "lib/guard.py")
        data, r = self.flags()
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["AUTH"], f"the old path's lens was dropped: {data['flags']}")


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
                    badge = self.repo / "docs/assets/badges/tests.json"
                    if with_badge:
                        write(self.repo, "docs/assets/badges/tests.json", "{}\n")
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
                badge = write(self.repo, f"docs/assets/badges/{name}", '{"schemaVersion": 1}\n')
                data, r = self.flags("--strict")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertTrue(data["flags"]["DOCS"])
                self.assertEqual(data["unmatched"], [])
                badge.unlink()

    def test_generated_badge_does_not_exempt_unknown_neighbors(self):
        write(self.repo, "docs/assets/badges/tests.json", "{}\n")
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


class PredictMergeContract(ScopeBase):
    """#590 predict-merge: 0 clean, 1 real conflict, 2 SCOPE_ERROR — an unknown
    ref must never masquerade as a conflict."""

    def setUp(self):
        super().setUp()
        write(self.repo, "shared.txt", "work\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "work change")
        git(self.repo, "checkout", "-q", "main")
        write(self.repo, "shared.txt", "main\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "main change")
        git(self.repo, "checkout", "-q", "-b", "clean", "main")
        write(self.repo, "other.txt", "x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "clean change")
        git(self.repo, "checkout", "-q", "main")

    def predict(self, *refs, json_out=False):
        extra = ["--json"] if json_out else []
        return self.run_scope("--predict-merge", *refs, *extra)

    def test_clean_conflict_and_untouched_worktree(self):
        head = git(self.repo, "rev-parse", "HEAD").stdout
        status = git(self.repo, "status", "--porcelain").stdout
        clean = self.predict("main", "clean")
        self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
        self.assertTrue(json.loads(clean.stdout)["clean"])
        conflict = self.predict("main", "work")
        self.assertEqual(conflict.returncode, 1, conflict.stdout + conflict.stderr)
        self.assertIn("shared.txt", json.loads(conflict.stdout)["conflicts"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").stdout, head)
        self.assertEqual(git(self.repo, "status", "--porcelain").stdout, status)

    def test_the_wtree_entry_runs_diff_scope_isolated(self):
        # W4-13 class: `wtree.sh predict-merge` exec'd a plain `python3`, which honours PYTHONPATH,
        # so a planted sitecustomize.py (run at startup) or json.py (shadowing the stdlib diff_scope
        # imports) ran in the coordinator. `-I` ignores PYTHONPATH and the user site.
        plant = Path(self.tmp) / "plant"
        plant.mkdir()
        marker = Path(self.tmp) / "pwned"
        for mod in ("sitecustomize", "usercustomize", "json"):
            (plant / f"{mod}.py").write_text(f"open({str(marker)!r}, 'a').write('{mod} ')\n", encoding="utf-8")
        wtree = ROOT / "runtime" / "scripts" / "wtree.sh"
        for argv in (["sh", str(wtree), "predict-merge", "main", "clean", str(self.repo)],
                     ["sh", str(wtree), str(self.repo), "predict-merge", "main", "clean"]):
            with self.subTest(argv=argv[2:4]):
                r = subprocess.run(argv, cwd=plant, capture_output=True, text=True, timeout=120,
                                   env={**os.environ, "PYTHONPATH": f"{plant}{os.pathsep}."})
                self.assertFalse(marker.exists(), f"planted modules ran: {marker.read_text() if marker.exists() else ''}")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_unknown_ref_is_no_base_not_a_conflict(self):
        for refs in (("no-such-base", "work"), ("main", "no-such-branch")):
            with self.subTest(refs=refs):
                r = self.predict(*refs)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("SCOPE_ERROR=no_base", r.stdout)
                rj = self.predict(*refs, json_out=True)
                self.assertEqual(rj.returncode, 2)
                doc = json.loads(rj.stdout)
                self.assertEqual(doc["error"], "no_base")
                self.assertIsNone(doc["clean"])
        for refs in (("main", "nope"), ("--output=/tmp/x", "work")):  # never an option to git
            with self.assertRaises(diff_scope.ScopeError) as cm:
                diff_scope.predict_merge(self.repo, *refs)
            self.assertEqual(cm.exception.kind, "no_base")

    def test_unrelated_history_is_no_base(self):
        git(self.repo, "checkout", "-q", "--orphan", "island")
        git(self.repo, "rm", "-rqf", ".")
        write(self.repo, "island.txt", "i\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "island")
        git(self.repo, "checkout", "-q", "main")
        r = self.predict("main", "island")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("SCOPE_ERROR=no_base", r.stdout)

    def _pre_238_git(self):
        """A git that predates `merge-tree --write-tree` (2.38): usage error, exit 129."""
        real = shutil.which("git")
        bindir = Path(self.tmp) / "oldgit"
        bindir.mkdir()
        shim = bindir / "git"
        shim.write_text(
            "#!/bin/sh\n"
            "for a in \"$@\"; do\n"
            "  if [ \"$a\" = --write-tree ]; then\n"
            "    echo 'usage: git merge-tree <base-tree> <branch1> <branch2>' >&2; exit 129\n"
            "  fi\n"
            "done\n"
            f"exec {real} \"$@\"\n", encoding="utf-8")
        shim.chmod(0o755)
        return {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}

    def test_old_git_is_diff_failed_never_a_guessed_verdict(self):
        env = self._pre_238_git()
        for refs in (("main", "clean"), ("main", "work")):
            with self.subTest(refs=refs):
                r = subprocess.run([sys.executable, str(SCOPE), "--repo", str(self.repo),
                                    "--predict-merge", *refs, "--json"],
                                   capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                doc = json.loads(r.stdout)
                self.assertEqual(doc["error"], "diff_failed")
                self.assertIsNone(doc["clean"])
                self.assertIn("2.38", doc["detail"])

    def test_non_utf8_path_conflict_is_reported_as_json(self):
        name = os.fsdecode(b"caf\xe9.txt")
        # The non-UTF-8 path lives only in git objects: APFS refuses to create it (Errno 92),
        # so both sides are committed with plumbing, never through the filesystem (P2-29).
        self._commit_raw_path("latin", "main", b"caf\xe9.txt", b"latin\n")
        self._commit_raw_path("main", "main", b"caf\xe9.txt", b"main\n")
        r = subprocess.run([sys.executable, str(SCOPE), "--repo", str(self.repo),
                            "--predict-merge", "main", "latin", "--json"],
                           capture_output=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        doc = json.loads(r.stdout)
        self.assertFalse(doc["clean"])
        self.assertIn(name, doc["conflicts"])

    def _commit_raw_path(self, branch, parent, raw_path, content):
        """Point `branch` at a commit on `parent` adding `raw_path` (bytes, any encoding) with
        `content`, through a private index: no checkout, no file of that name on disk."""
        def plumb(*args, data=b"", env=None):
            return subprocess.run(["git", "-C", str(self.repo), *args], input=data, env=env,
                                  capture_output=True, check=True).stdout.strip().decode()
        blob = plumb("hash-object", "-w", "--stdin", data=content)
        index = {**os.environ, "GIT_INDEX_FILE": str(Path(self.tmp) / f"index-{branch}")}
        plumb("read-tree", parent, env=index)
        plumb("update-index", "-z", "--index-info", data=b"100644 " + blob.encode() + b"\t" + raw_path + b"\0", env=index)
        tree = plumb("write-tree", env=index)
        commit = plumb("commit-tree", tree, "-p", parent, "-m", f"{branch} side")
        plumb("update-ref", f"refs/heads/{branch}", commit)

    def test_unexpected_crash_is_exit_2_not_the_conflict_code(self):
        out = io.StringIO()
        with mock.patch.object(diff_scope, "predict_merge", side_effect=RuntimeError("boom")), \
                contextlib.redirect_stdout(out):
            rc = diff_scope.main(["--repo", str(self.repo), "--predict-merge", "main", "work",
                                  "--json"])
        self.assertEqual(rc, diff_scope.EXIT_SCOPE_ERROR)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc["error"], "diff_failed")
        self.assertIn("boom", doc["detail"])



class TestTheBaseIsResolvedByExactNameW307(ScopeBase):
    """W3-07 class (Codex review follow-up): resolve_base ran `rev-parse <base>^{commit}` and,
    unnamed, cut origin/HEAD's target to the SHORT name `origin/<x>`, which gitrevisions resolves
    through refs/tags/ and refs/heads/ first. The base decides which paths count as changed, so
    which review lenses run: a tag or local branch spelled `origin/main` at the change's own tip
    (or an origin/HEAD pointed at the change's branch) emptied the diff and turned the AUTH lens
    off. The change below touches auth code; every plant used to report SCOPE_AUTH=false."""

    def setUp(self):
        super().setUp()
        git(self.repo, "update-ref", "refs/remotes/origin/main", "main")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        write(self.repo, "src/auth/login.py", "def login():\n    return True\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "touch auth")

    def scoped(self, *args):
        r = self.run_scope("--json", *args)
        return json.loads(r.stdout), r

    def test_a_tag_or_local_branch_spelled_origin_main_never_stands_in(self):
        for planted in ("refs/tags/origin/main", "refs/heads/origin/main"):
            git(self.repo, "update-ref", planted, "HEAD")
            for args in ((), ("--base", "origin/main")):
                with self.subTest(planted=planted, args=args):
                    data, r = self.scoped(*args)
                    self.assertIsNone(data["error"], r.stdout + r.stderr)
                    self.assertTrue(data["flags"]["AUTH"], r.stdout + r.stderr)
            git(self.repo, "update-ref", "-d", planted)

    def test_an_origin_head_pointed_at_the_change_s_branch_is_skipped(self):
        git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/work")
        data, r = self.scoped()
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["AUTH"], r.stdout + r.stderr)

    def test_a_local_bridge_inside_a_remote_tracking_chain_is_no_base(self):
        # Codex review round 2 (P1): for-each-ref's %(symref) is the chain's END, so origin/HEAD
        # -> refs/heads/bridge -> refs/remotes/origin/tip (the change's own tip, fetched) read as
        # remote-tracking all the way: the diff was empty and the AUTH lens off.
        git(self.repo, "update-ref", "refs/remotes/origin/tip", "HEAD")
        git(self.repo, "symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/tip")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/bridge")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/b", "refs/heads/bridge")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/a", "refs/remotes/origin/b")
        data, r = self.scoped()  # origin/HEAD skipped: origin/main
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["AUTH"], r.stdout + r.stderr)
        for base in ("origin/HEAD", "origin/a"):
            with self.subTest(base=base):
                data, r = self.scoped("--base", base)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(data["error"], "no_base", r.stdout)
                self.assertIn("refs/heads/bridge", r.stderr)

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_base(self):
        # Independent re-attack (A): str.splitlines() broke the listing at U+2028/U+2029/U+0085,
        # so a fetched `x<U+2028>refs/remotes/origin/main` at the change's own tip replaced
        # origin/main: an empty diff, the AUTH lens off.
        tip = git(self.repo, "rev-parse", "HEAD").stdout.strip()
        for ch in refname_breaks.LINE_BREAKS:
            for args in ((), ("--base", "origin/main")):
                with self.subTest(ch=ch, args=args):
                    unplant = refname_breaks.plant(self.repo, ch, tip)
                    try:
                        data, r = self.scoped(*args)
                    finally:
                        unplant()
                    self.assertIsNone(data["error"], r.stdout + r.stderr)
                    self.assertTrue(data["flags"]["AUTH"], r.stdout + r.stderr)

    def test_an_absent_remote_ref_is_not_answered_by_a_local_branch_of_its_spelling(self):
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/HEAD")
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/main")
        git(self.repo, "update-ref", "refs/heads/refs/remotes/origin/main", "HEAD")
        data, r = self.scoped("--base", "refs/remotes/origin/main")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(data["error"], "no_base", r.stdout)
        self.assertIn("exactly that name", r.stderr)

    def test_a_revision_suffix_is_no_base(self):
        for base in ("origin/main~0", "origin/main@{0}", "main^0"):
            with self.subTest(base=base):
                data, r = self.scoped("--base", base)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(data["error"], "no_base", r.stdout)
                self.assertIn("not a valid ref name", r.stderr)

    def test_head_and_an_abbreviated_id_are_advisory_bases_never_ref_names(self):
        # Re-attack C(1): off a sound lane `--base HEAD` was refused and `--base <short sha>` was
        # read as the local BRANCH of that spelling — a planted refs/heads/<short sha> at the
        # change's tip emptied the diff. Both are advisory bases now (with the NOTE), the
        # abbreviation read as an object id only; a sound lane refuses both.
        main = git(self.repo, "rev-parse", "refs/heads/main").stdout.strip()
        short = main[:9]
        git(self.repo, "update-ref", f"refs/heads/{short}", "HEAD")
        clean = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}

        def scope(base, env):
            r = subprocess.run([sys.executable, str(SCOPE), "--repo", str(self.repo), "--json",
                                "--base", base], capture_output=True, text=True, env=env)
            return json.loads(r.stdout), r

        data, r = scope(short, clean)
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertTrue(data["flags"]["AUTH"], r.stdout + r.stderr)  # diffed against main
        self.assertIn("abbreviated commit id", r.stderr)
        data, r = scope("HEAD", clean)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIsNone(data["error"], r.stdout + r.stderr)
        self.assertIn("NOTE", r.stderr)
        for base in (short, "HEAD"):
            with self.subTest(base=base):
                data, r = scope(base, {**clean, "OPEN_FLEET_PROVENANCE": "ci"})
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(data["error"], "no_base", r.stdout)

    def test_a_local_base_is_refused_on_a_lane_claiming_soundness(self):
        # Coordinator decision (the decisions.py / run_report.py precedent): where
        # ORCA_PROVENANCE / OPEN_FLEET_PROVENANCE claims soundness a local branch — the change's
        # to move — is no base, named or as the no-remote fallback; off that lane it runs with
        # the advisory NOTE.
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/HEAD")
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/main")
        clean = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        for var in ("ORCA_PROVENANCE", "OPEN_FLEET_PROVENANCE"):
            for args in (("--base", "main"), ("--base", "refs/heads/main"), ()):
                with self.subTest(var=var, args=args):
                    r = subprocess.run([sys.executable, str(SCOPE), "--repo", str(self.repo),
                                        "--json", *args], capture_output=True, text=True,
                                       env={**clean, var: "ci"})
                    self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                    self.assertEqual(json.loads(r.stdout)["error"], "no_base", r.stdout)
                    self.assertIn(f"{var}=ci claims a sound lane", r.stderr)
        r = subprocess.run([sys.executable, str(SCOPE), "--repo", str(self.repo), "--json",
                            "--base", "main"], capture_output=True, text=True, env=clean)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(json.loads(r.stdout)["flags"]["AUTH"], r.stdout)
        self.assertIn("NOTE", r.stderr)
        self.assertIn("LOCAL branch", r.stderr)

    def test_the_diff_is_taken_against_the_resolved_commit(self):
        tip = git(self.repo, "rev-parse", "refs/remotes/origin/main").stdout.strip()
        seen = []
        real = diff_scope.git

        def spy(repo, *args, **kwargs):
            seen.append(list(args))
            return real(repo, *args, **kwargs)

        with mock.patch.object(diff_scope, "git", side_effect=spy):
            flags, _unmatched, shown = diff_scope.scope(self.repo, "origin/main")
        self.assertTrue(flags["AUTH"])
        self.assertEqual(shown, "origin/main")
        diffs = [a for a in seen if a[:1] == ["diff"] and any("..." in t for t in a)]
        self.assertEqual(len(diffs), 1, seen)
        self.assertIn(f"{tip}...HEAD", diffs[0])


class TestShellCommentSanitizationAndGlobIntersects(ScopeBase):
    """Regression pins for #781: shell-mode comment escaping and _glob_intersects fixes."""

    def test_unmatched_filename_with_newline_cannot_inject_shell_command(self):
        evil_name = "weird\necho INJECTED_781\x1bfile.xyz"
        write(self.repo, evil_name, "hello\n")
        r = self.run_scope("--base", "main")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        for line in r.stdout.splitlines():
            self.assertTrue(
                line.startswith(("SCOPE_", "# ")),
                f"non-assignment, non-comment line leaked into shell output: {line!r}",
            )
        self.assertNotIn("\necho INJECTED_781", r.stdout)
        self.assertIn("\\x0a", r.stdout)
        self.assertIn("\\x1b", r.stdout)
        self.assertEqual(diff_scope._shell_comment("a\rb\nc\x00d\x7fe"), r"a\x0db\x0ac\x00d\x7fe")

    def test_error_comment_with_newline_is_single_comment_line(self):
        r = self.run_scope("--base", "missing\necho INJECTED_BASE")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        for line in r.stdout.splitlines():
            self.assertTrue(
                line.startswith(("SCOPE_", "# ")),
                f"injected line leaked into shell output: {line!r}",
            )
        self.assertNotIn("\necho INJECTED_BASE", r.stdout)

    def test_overlap_shell_comment_sanitizes_control_bytes(self):
        spec_file = Path(self.tmp) / "ctrl.json"
        spec_file.write_text(json.dumps({
            "units": [
                {"id": "u1\necho PWN1", "scope": ["src/*.py"]},
                {"id": "u2\recho PWN2", "scope": ["src/app.py"]},
            ]
        }), encoding="utf-8")
        r = self.run_scope("--overlap", str(spec_file))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for line in r.stdout.splitlines():
            self.assertTrue(
                line.startswith(("OVERLAP_COUNT=", "# ")),
                f"injected line leaked into overlap shell output: {line!r}",
            )
        self.assertNotIn("\necho PWN1", r.stdout)

    def test_glob_intersects_preserves_dot_prefixes_and_zero_segment_globstar(self):
        self.assertFalse(diff_scope._glob_intersects(".github/*", "github/*"))
        self.assertFalse(diff_scope._glob_intersects(".env", "env"))
        self.assertTrue(diff_scope._glob_intersects("./.github/*", ".github/workflows/ci.yml"))
        self.assertTrue(diff_scope._glob_intersects("src/**/foo.py", "src/foo.py"))
        self.assertTrue(diff_scope._glob_intersects("src/foo.py", "src/**/foo.py"))
        self.assertTrue(diff_scope._glob_intersects("src/**/*.py", "src/app.py"))
        self.assertTrue(diff_scope._glob_intersects("**/foo.py", "foo.py"))
        self.assertFalse(diff_scope._glob_intersects("src/**/foo.py", "src/bar.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
