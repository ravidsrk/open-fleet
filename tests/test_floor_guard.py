#!/usr/bin/env python3
"""Contract tests for runtime/scripts/floor_guard.py.

Every test builds a real, hermetic git repo in a temp dir: the guard's whole job
is reading a diff, so a fake diff would test nothing. The exit contract is the
load-bearing part — a 2 that reads as a 0 is the failure mode this script exists
to prevent — so every could-not-run path is asserted explicitly.
"""
import contextlib
import importlib.util
import io
import os
import runpy
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
GUARD = ROOT / "runtime" / "scripts" / "floor_guard.py"
_spec = importlib.util.spec_from_file_location("floor_guard", GUARD)
floor_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(floor_guard)


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)


def write(repo, rel, text):
    p = Path(repo) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def land_on_base(repo, files, branch="main"):
    """Commit {rel: text} onto `branch` without touching the checkout or the work branch.

    Waivers are read at the base ref (2026-10-23 review, P1-7), so a fixture waiver has to
    land THERE, the way a real one lands on the base branch before the change it waives."""
    index = Path(repo).parent / f"{Path(repo).name}-base-index"
    env = dict(os.environ, GIT_INDEX_FILE=str(index))

    def plumb(*args, data=None):
        return subprocess.run(["git", "-C", str(repo), *args], input=data, capture_output=True,
                              text=True, check=True, env=env).stdout.strip()
    plumb("read-tree", branch)
    for rel, text in files.items():
        blob = plumb("hash-object", "-w", "--stdin", data=text)
        plumb("update-index", "--add", "--cacheinfo", f"100644,{blob},{rel}")
    tree = plumb("write-tree")
    commit = plumb("-c", "user.name=t", "-c", "user.email=t@example.invalid",
                   "commit-tree", tree, "-p", branch, "-m", "land on base")
    plumb("update-ref", f"refs/heads/{branch}", commit)
    index.unlink(missing_ok=True)


def grant_row(ident, answer="allow", ts="2026-09-10T00:00:00Z", why="while the parser lands",
              klass="one-way", source="[source=human:lia]"):
    """A DECISIONS line shaped as a one-way human grant — the only waiver that grants (P1-7)."""
    return f"{ts} · {ident} · {klass} · {answer} · {why} {source} · t-1".replace("  ·", " ·")


def run_guard(repo, *args):
    return subprocess.run(
        [sys.executable, str(GUARD), "--repo", str(repo), *args],
        capture_output=True, text=True,
    )


BASE_CONSTRAINTS = """# CONSTRAINTS

| id | dimension | floor |
|----|-----------|-------|
| D1 | coverage | 85 |
| D2 | latency-ms | 250 |

## Exceptions

(none)
"""

BASE_TEST = """def test_thing():
    assert compute() == 4
    assert other() == 5
"""


class FloorGuardBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="floorguard-")
        self.repo = Path(self.tmp) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        write(self.repo, "CONSTRAINTS.md", BASE_CONSTRAINTS)
        write(self.repo, "FLOOR.md", "| D1 | coverage | 85 |\n")
        write(self.repo, "tests/test_thing.py", BASE_TEST)
        write(self.repo, "src/thing.spec.js", "it('x', () => {\n  expect(a).toBe(1);\n  expect(b).toBe(2);\n});\n")
        write(self.repo, "src/app.py", "def compute():\n    assert True\n    return 4\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base")
        git(self.repo, "checkout", "-q", "-b", "work")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def commit(self, message="change"):
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", message)


class TestCleanAndExitCodes(FloorGuardBase):
    def test_no_changes_is_clean(self):
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("clean", r.stdout)

    def test_benign_change_is_clean(self):
        write(self.repo, "src/app.py", "def compute():\n    return 4\n\n\ndef extra():\n    return 1\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

    def test_not_a_git_repo_exits_2(self):
        plain = Path(self.tmp) / "plain"
        plain.mkdir()
        r = run_guard(plain, "--base", "main")
        self.assertEqual(r.returncode, 2)
        self.assertIn("could not run", r.stderr)

    def test_unresolvable_base_exits_2_not_0(self):
        r = run_guard(self.repo, "--base", "origin/does-not-exist")
        self.assertEqual(r.returncode, 2, "a base that does not resolve must never read as clean")
        self.assertIn("not resolvable", r.stderr)

    def test_help_exits_zero(self):
        r = subprocess.run([sys.executable, str(GUARD), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("--base", r.stdout)

    def test_exit_codes_are_documented_in_the_docstring(self):
        text = GUARD.read_text(encoding="utf-8")
        for token in ("0  clean", "1  at least one", "2  the guard could not run"):
            self.assertIn(token, text)


class TestDiffAcquisition(FloorGuardBase):
    def test_a_bare_carriage_return_in_content_does_not_break_the_hunk_count(self):
        # text=True applied universal newlines, so a removed file holding
        # `a\r-b\nc\n` (two lines to git) arrived as three removal lines and
        # the hunk-counted parser refused a valid patch (PR #571 review).
        p = self.repo / "src" / "crlf.txt"
        p.write_bytes(b"a\r-b\nc\n")
        self.commit("add")
        git(self.repo, "branch", "-f", "main", "HEAD")
        p.unlink()
        self.commit("remove")
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        p.write_bytes(b"x\ry\n")  # untracked side goes through the same decoder
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)

    def test_disappearing_untracked_file_is_exit_2(self):
        path = write(self.repo, "disappearing.py", "value = 1\n")
        real_run = subprocess.run
        comparisons = []

        def disappear_before_comparison(argv, **kwargs):
            if "--no-index" in argv:
                path.unlink()
                result = real_run(argv, **kwargs)
                # the guard reads bytes (no newline translation); record text
                comparisons.append(subprocess.CompletedProcess(
                    result.args, result.returncode,
                    result.stdout.decode(), result.stderr.decode()))
                return result
            return real_run(argv, **kwargs)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(floor_guard.subprocess, "run", side_effect=disappear_before_comparison), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = floor_guard.main(["--repo", str(self.repo), "--base", "main"])
        self.assertEqual(len(comparisons), 1)
        self.assertEqual(comparisons[0].returncode, 1)
        self.assertEqual(comparisons[0].stdout, "")
        self.assertTrue(comparisons[0].stderr)
        self.assertEqual(rc, 2, out.getvalue() + err.getvalue())
        self.assertIn("untracked diff acquisition failed", err.getvalue())
        self.assertNotIn("floor-guard: clean", out.getvalue())

    def test_benign_untracked_file_is_clean(self):
        write(self.repo, "new.py", "value = 1\n")
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("floor-guard: clean", r.stdout)

    def test_each_failed_required_read_is_exit_2(self):
        write(self.repo, "new.py", "value = 1\n")
        real_run = subprocess.run
        for phase in ("tracked", "untracked-list", "untracked-diff"):
            for failure in (128, subprocess.TimeoutExpired("git", 60), OSError("unavailable")):
                with self.subTest(phase=phase, failure=failure):
                    def failing_read(argv, phase=phase, failure=failure, **kwargs):
                        target = ("untracked-list" if "ls-files" in argv else
                                  "untracked-diff" if "--no-index" in argv else
                                  "tracked" if "diff" in argv else None)
                        if target == phase:
                            if isinstance(failure, Exception):
                                raise failure
                            return subprocess.CompletedProcess(argv, failure, "", "read failed")
                        return real_run(argv, **kwargs)

                    out, err = io.StringIO(), io.StringIO()
                    with mock.patch.object(floor_guard.subprocess, "run", side_effect=failing_read), \
                            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = floor_guard.main(["--repo", str(self.repo), "--base", "main"])
                    self.assertEqual(rc, 2, out.getvalue() + err.getvalue())
                    self.assertNotIn("floor-guard: clean", out.getvalue())

    def test_external_diff_and_textconv_cannot_hide_violations(self):
        git(self.repo, "config", "diff.hidden.command", "false")
        git(self.repo, "config", "diff.hidden.textconv", "true")
        write(self.repo, ".gitattributes", "*.py diff=hidden\n")
        for stage in (False, True):
            with self.subTest(staged=stage):
                write(self.repo, "src/app.py", "value = 1  # noqa\n")
                write(self.repo, "new.py", "value = 1  # noqa\n")
                if stage:
                    git(self.repo, "add", "src/app.py")
                with mock.patch.dict(os.environ, {"GIT_EXTERNAL_DIFF": "false"}):
                    r = run_guard(self.repo, "--base", "main")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("src/app.py", r.stderr)
                self.assertIn("new.py", r.stderr)

    def test_a_repo_local_fsmonitor_never_runs(self):
        # core.fsmonitor in the guarded repo's own .git/config is a command git
        # runs on an index refresh; the guard reads repos it does not own.
        marker = Path(self.tmp) / "fsmonitor-ran"
        hook = Path(self.tmp) / "fsmonitor.sh"
        hook.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 1\n", encoding="utf-8")
        hook.chmod(0o755)
        git(self.repo, "config", "core.fsmonitor", str(hook))
        write(self.repo, "src/app.py", "value = 1\n")
        git(self.repo, "status", "--short")
        self.assertTrue(marker.exists(), "fixture: plain git must run the fsmonitor hook")
        marker.unlink()
        r = run_guard(self.repo, "--base", "main")
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertFalse(marker.exists(), "floor_guard ran the repo's core.fsmonitor command")

    def test_empty_untracked_file_is_clean(self):
        write(self.repo, "empty.py", "")
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stderr)


class TestSuppressions(FloorGuardBase):
    def _flags(self, line, path="src/app.py"):
        existing = (Path(self.repo) / path).read_text(encoding="utf-8") if (Path(self.repo) / path).exists() else ""
        write(self.repo, path, existing + line + "\n")
        self.commit()
        return run_guard(self.repo, "--base", "main")

    def test_added_noqa_is_flagged(self):
        r = self._flags("x = broken()  # noqa: E501")
        self.assertEqual(r.returncode, 1)
        self.assertIn("silenced-checker", r.stderr)

    def test_added_eslint_disable_is_flagged(self):
        r = self._flags("// eslint-disable-next-line no-unused-vars", path="src/app.js")
        self.assertEqual(r.returncode, 1)
        self.assertIn("silenced-checker", r.stderr)

    def test_added_ts_ignore_is_flagged(self):
        r = self._flags("// @ts-ignore", path="src/app.ts")
        self.assertEqual(r.returncode, 1)
        self.assertIn("silenced-checker", r.stderr)

    def test_added_type_ignore_is_flagged(self):
        r = self._flags("y = thing()  # type: ignore[arg-type]")
        self.assertEqual(r.returncode, 1)
        self.assertIn("silenced-checker", r.stderr)

    def test_added_pragma_no_cover_is_flagged(self):
        r = self._flags("if never():  # pragma: no cover")
        self.assertEqual(r.returncode, 1)
        self.assertIn("silenced-checker", r.stderr)

    def test_finding_names_rule_and_file_and_line(self):
        r = self._flags("z = 1  # noqa")
        self.assertEqual(r.returncode, 1)
        self.assertRegex(r.stderr, r"\[silenced-checker\] src/app\.py:\d+")

    def test_report_never_echoes_the_suppressed_content(self):
        secret = "AKIAQQQQQQQQQQQQQQQQ"
        r = self._flags(f'token = "{secret}"  # noqa')
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(secret, r.stderr + r.stdout,
                         "the guard must report the rule and location, never the matched text")


class TestSkipsAndStubs(FloorGuardBase):
    def _append_test(self, line):
        write(self.repo, "tests/test_thing.py", BASE_TEST + line + "\n")
        self.commit()
        return run_guard(self.repo, "--base", "main")

    def test_pytest_skip_marker_is_flagged(self):
        r = self._append_test("@pytest.mark.skip(reason='flaky')")
        self.assertEqual(r.returncode, 1)
        self.assertIn("test-made-easier", r.stderr)

    def test_dot_skip_is_flagged(self):
        r = self._append_test("it.skip('later', () => {})")
        self.assertEqual(r.returncode, 1)
        self.assertIn("test-made-easier", r.stderr)

    def test_xit_is_flagged(self):
        r = self._append_test("xit('broken', () => {})")
        self.assertEqual(r.returncode, 1)
        self.assertIn("test-made-easier", r.stderr)

    def test_unittest_skip_is_flagged(self):
        r = self._append_test("@unittest.skip('todo later')")
        self.assertEqual(r.returncode, 1)
        self.assertIn("test-made-easier", r.stderr)

    def test_todo_marker_is_unfinished_work(self):
        write(self.repo, "src/app.py", "def compute():\n    return 4\n\n\ndef later():\n    # TODO: implement\n    return None\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unfinished-work", r.stderr)

    def test_not_implemented_stub_is_unfinished_work(self):
        write(self.repo, "src/app.py", "def compute():\n    return 4\n\n\ndef later():\n    raise NotImplementedError\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unfinished-work", r.stderr)

    def test_swallowed_exception_is_unfinished_work(self):
        write(self.repo, "src/app.py", "def compute():\n    try:\n        return 4\n    except Exception: pass\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unfinished-work", r.stderr)


class TestAssertionRemoval(FloorGuardBase):
    def test_removed_assertion_in_a_surviving_test_is_flagged(self):
        write(self.repo, "tests/test_thing.py", "def test_thing():\n    assert compute() == 4\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("assertion-removed", r.stderr)
        self.assertIn("tests/test_thing.py", r.stderr)

    def test_removed_expect_in_a_spec_file_is_flagged(self):
        write(self.repo, "src/thing.spec.js", "it('x', () => {\n  expect(a).toBe(1);\n});\n")
        self.commit("weaken spec")
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("assertion-removed", r.stderr)

    def test_removed_assertion_in_non_test_code_is_not_flagged(self):
        write(self.repo, "src/app.py", "def compute():\n    return 4\n")
        self.commit("drop the assert from production code")
        r = run_guard(self.repo, "--base", "main")
        self.assertNotIn("assertion-removed", r.stderr)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_adding_an_assertion_is_silent(self):
        write(self.repo, "tests/test_thing.py", BASE_TEST + "    assert third() == 6\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, "tightening is silent, loosening is loud")


class TestConstraintsFile(FloorGuardBase):
    def test_lowered_threshold_is_flagged(self):
        write(self.repo, "CONSTRAINTS.md", BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("threshold-lowered", r.stderr)
        self.assertIn("85 -> 60", r.stderr)

    def test_raised_threshold_is_silent(self):
        write(self.repo, "CONSTRAINTS.md", BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 95 |"))
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_new_exception_row_is_flagged(self):
        write(self.repo, "CONSTRAINTS.md", BASE_CONSTRAINTS + "\n| W101 | ignore the lint on legacy | until Q3 |\n")
        self.commit()
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("new-exception", r.stderr)

    def test_a_differently_named_constraints_file_is_honored(self):
        write(self.repo, "FLOOR.md", "| D1 | coverage | 10 |\n")
        self.commit("lower floor")
        r = run_guard(self.repo, "--base", "main", "--constraints", "FLOOR.md")
        self.assertEqual(r.returncode, 1)
        self.assertIn("threshold-lowered", r.stderr)


class TestUntrackedAndWaivers(FloorGuardBase):
    def test_untracked_file_is_in_scope(self):
        write(self.repo, "src/new.py", "value = 1  # noqa\n")
        r = run_guard(self.repo, "--base", "main")
        self.assertEqual(r.returncode, 1, "a guard that reads only git diff misses the new file")
        self.assertIn("src/new.py", r.stderr)

    # ---- Waivers (#313, then three rounds of PR #308 review) ----
    #
    # A waiver is a DECISIONS record whose ID carries its scope —
    # `floor-waiver:<rule>:<path-or-glob>` — and whose answer grants. Scope in the id is what lets
    # the ledger retire it: a later `superseded` row ends this waiver and no other.

    ID = "floor-waiver:silenced-checker:src/new.py"

    def _decisions(self, *lines):
        write(self.repo, "src/new.py", "value = 1  # noqa\n")
        land_on_base(self.repo, {"docs/DECISIONS.md": "".join(line + "\n" for line in lines)})
        return run_guard(self.repo, "--base", "main")

    def _row(self, ident, answer="allow", ts="2026-09-10T00:00:00Z", why="while the parser lands"):
        return grant_row(ident, answer=answer, ts=ts, why=why)

    def test_a_granting_waiver_exempts_the_finding(self):
        r = self._decisions(self._row(self.ID))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 waived", r.stdout)

    def test_a_waiver_for_a_different_path_does_not_exempt(self):
        r = self._decisions(self._row("floor-waiver:silenced-checker:src/other.py"))
        self.assertEqual(r.returncode, 1)

    def test_a_waiver_for_a_different_rule_does_not_exempt(self):
        r = self._decisions(self._row("floor-waiver:threshold-lowered:src/new.py"))
        self.assertEqual(r.returncode, 1)

    def test_a_superseded_waiver_stops_granting(self):
        # PR #308 review, P1. Every waiver used to share the id `floor-waiver`, so a later
        # `superseded` row named no particular waiver and an `allow` stayed live forever. A
        # supersede record does not restate the scope — that is the whole point of superseding —
        # so the waiver has to have an identity of its own for the ledger to retire.
        r = self._decisions(
            self._row(self.ID, ts="2026-09-01T00:00:00Z"),
            self._row(self.ID, answer="superseded", ts="2026-09-02T00:00:00Z",
                      why="the vendored parser landed"))
        self.assertEqual(r.returncode, 1, f"a retired waiver still granted: {r.stdout}")

    def test_a_later_denial_overrides_an_earlier_grant(self):
        r = self._decisions(
            self._row(self.ID, ts="2026-09-01T00:00:00Z"),
            self._row(self.ID, answer="deny", ts="2026-09-02T00:00:00Z", why="refused on review"))
        self.assertEqual(r.returncode, 1, f"an older allow beat a newer deny: {r.stdout}")

    def test_a_later_grant_overrides_an_earlier_denial(self):
        # Newest-wins runs both ways, or it is not newest-wins.
        r = self._decisions(
            self._row(self.ID, answer="deny", ts="2026-09-01T00:00:00Z", why="refused"),
            self._row(self.ID, ts="2026-09-02T00:00:00Z", why="reinstated: the parser slipped"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_denied_waiver_does_not_grant(self):
        r = self._decisions(self._row(self.ID, answer="deny", why="refused on review"))
        self.assertEqual(r.returncode, 1, f"a DENIED waiver was granted: {r.stdout}")

    def test_an_explicit_glob_waives_the_subtree(self):
        r = self._decisions(self._row("floor-waiver:silenced-checker:src/**"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 waived", r.stdout)

    def test_a_bare_directory_does_not_sweep_the_tree(self):
        # #313 claimed a bare `src/` swept the tree. It never could: the old test was
        # `finding["path"] in line`, so the LINE had to contain the whole path. Kept as a guard for
        # the semantics the issue asked for, not as evidence of the bug it described.
        r = self._decisions(self._row("floor-waiver:silenced-checker:src/"))
        self.assertEqual(r.returncode, 1, f"a bare directory swept the tree: {r.stdout}")

    def test_a_glob_over_everything_is_not_a_waiver(self):
        r = self._decisions(self._row("floor-waiver:silenced-checker:**"))
        self.assertEqual(r.returncode, 1, f"`**` is a blanket, not a waiver: {r.stdout}")

    def test_a_longer_token_containing_the_rule_id_does_not_waive(self):
        r = self._decisions(self._row("floor-waiver:silenced-checkers:src/new.py"))
        self.assertEqual(r.returncode, 1, f"`silenced-checkers` is not the rule id: {r.stdout}")

    def test_a_longer_token_containing_the_path_does_not_waive(self):
        r = self._decisions(self._row("floor-waiver:silenced-checker:src/new.pyc"))
        self.assertEqual(r.returncode, 1, f"`src/new.pyc` is not `src/new.py`: {r.stdout}")

    def test_prose_naming_the_rule_and_path_is_not_a_waiver(self):
        # No prose is parsed at all now. A sentence that mentions both — including a line
        # recording that the team REFUSED the waiver, which the substring round granted — is a
        # note, not a decision about this finding.
        for why in ("silenced-checker on src/new.py",
                    "we will NOT waive silenced-checker on src/new.py",
                    "see notes/silenced-checker.md before touching src/new.py"):
            with self.subTest(why=why):
                r = self._decisions(self._row("mechanical", why=why))
                self.assertEqual(r.returncode, 1, f"prose granted a waiver: {r.stdout}")

    def test_a_waiver_in_the_old_shape_is_named_not_silently_dropped(self):
        # PR #308 review, P1. Moving scope into the id turns any pre-existing `floor-waiver` record
        # off, and a silent turn-off shows up as a red build with no reason. The old shape is NOT
        # honoured — scope-in-prose is the matching #313 removed as unsound, and a fallback would
        # restore the hole where "we will NOT waive X" grants X — but it is named, with the id to
        # write instead.
        r = self._decisions(self._row("floor-waiver", why="silenced-checker on src/new.py"))
        self.assertEqual(r.returncode, 1, "the old shape must not grant")
        self.assertIn("NOT a usable waiver", r.stderr, r.stderr)
        self.assertIn("floor-waiver:<rule>:<path>", r.stderr, r.stderr)

    def test_a_malformed_scoped_id_is_named(self):
        r = self._decisions(self._row("floor-waiver:silenced-checker"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not `floor-waiver:<rule>:<path-or-glob>`", r.stderr, r.stderr)

    def test_a_well_formed_waiver_draws_no_migration_note(self):
        r = self._decisions(self._row(self.ID))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("NOT a usable waiver", r.stderr, r.stderr)

    def test_missing_waiver_file_is_not_a_could_not_run(self):
        r = run_guard(self.repo, "--base", "main", "--waivers", "docs/NOPE.md")
        self.assertEqual(r.returncode, 0)


class TestScriptShape(unittest.TestCase):
    def test_executable_and_shebanged(self):
        self.assertTrue(os.access(GUARD, os.X_OK), "floor_guard.py must be executable")
        self.assertTrue(GUARD.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3"))

    def test_stdlib_only(self):
        text = GUARD.read_text(encoding="utf-8")
        for third_party in ("import requests", "import yaml", "import git\n"):
            self.assertNotIn(third_party, text)


def run_main(repo, *args):
    """floor_guard.main() in-process with captured output: (exit, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = floor_guard.main(["--repo", str(repo), *args])
    return code, out.getvalue(), err.getvalue()


class TestGuardSurfaceHit(unittest.TestCase):
    """The frozen surface (CONSTRAINTS.md "Guard surface"): what trips, what stays silent."""

    def test_every_whole_file_trips_on_any_line(self):
        for path in floor_guard.GUARD_SURFACE_FILES:
            with self.subTest(path=path):
                self.assertEqual(floor_guard.guard_surface_hit(path, "anything at all"), path)

    def test_trap_dir_members_trip_but_near_miss_dirs_do_not(self):
        self.assertEqual(
            floor_guard.guard_surface_hit("bench/vf-bench/traps/decoy-path.json", "{...}"),
            "bench/vf-bench/traps")
        for path in ("bench/vf-bench/traps-new/x.json", "bench/vf-bench/gate.py",
                     "bench/vf-bench/README.md"):
            with self.subTest(path=path):
                self.assertIsNone(floor_guard.guard_surface_hit(path, "some line"))

    def test_every_keyed_assignment_trips(self):
        cases = [
            ("ruff.toml", 'select = ["E9", "F63"]'),
            ("ruff.toml", '  select= ["E9"]'),
            (".coveragerc", "fail_under = 80"),
            ("tests/test_evals.py", "ROUTING_MIN_SCORE = 1.0"),
            ("bench/vf-bench/gate.py", 'EXPECTED_VERSION = "vf-bench@0.1"'),
            ("bench/vf-bench/gate.py", 'EXPECTED_CANARY_GUID = "05e6"'),
            ("bench/vf-bench/gate.py", 'EXPECTED_CORPUS_SHA256 = "a186"'),
        ]
        for path, line in cases:
            with self.subTest(path=path, line=line):
                self.assertEqual(floor_guard.guard_surface_hit(path, line), path)

    def test_use_sites_and_comments_about_a_key_stay_silent(self):
        cases = [
            ("tests/test_evals.py", '    result["score"], ROUTING_MIN_SCORE,'),
            ("tests/test_evals.py", "    # the ROUTING_MIN_SCORE floor mirrors CONSTRAINTS.md"),
            ("ruff.toml", "# the select key lists the enforced rule families"),
            (".coveragerc", "# fail_under mirrors the frozen D9 number"),
            ("bench/vf-bench/gate.py", "# bump EXPECTED_VERSION with the corpus"),
        ]
        for path, line in cases:
            with self.subTest(line=line):
                self.assertIsNone(floor_guard.guard_surface_hit(path, line))

    def test_surface_keys_in_other_files_stay_silent(self):
        cases = [
            ("docs/notes.md", "ROUTING_MIN_SCORE = 0.5"),
            ("ruff.toml.bak", 'select = ["E9"]'),
            ("sub/.gitleaksignore", "aabbcc"),
            ("evals/routing.jsonl", "{}"),
            ("tests/test_other.py", "ROUTING_MIN_SCORE = 0.5"),
        ]
        for path, line in cases:
            with self.subTest(path=path):
                self.assertIsNone(floor_guard.guard_surface_hit(path, line))

    def test_an_empty_path_is_not_a_hit(self):
        self.assertIsNone(floor_guard.guard_surface_hit("", "select = []"))
        self.assertIsNone(floor_guard.guard_surface_hit(None, "select = []"))


class TestGuardSurfaceCarveOuts(unittest.TestCase):
    """2026-10-26 review: only the ruff `select` and the coverage `fail_under` were keyed, so an
    `ignore = [...]`, a per-file-ignores table, an `exclude`, a coverage `omit` or a narrowed
    `include` lowered the bar beside the guarded key in silence."""

    def test_every_carve_out_trips(self):
        cases = [
            ("ruff.toml", 'ignore = ["F821"]'),
            ("ruff.toml", 'extend-ignore = ["F7"]'),
            ("ruff.toml", 'extend-select = ["E9"]'),
            ("ruff.toml", 'exclude = ["runtime/scripts"]'),
            ("ruff.toml", "[lint.per-file-ignores]"),
            ("ruff.toml", "[per-file-ignores]"),
            ("ruff.toml", '"tests/*" = ["F401"]'),
            ("ruff.toml", '    "F401",'),
            (".coveragerc", "omit = runtime/scripts/*"),
            (".coveragerc", "exclude_lines = .*"),
            (".coveragerc", "source = scripts"),
            (".coveragerc", "include ="),
            (".coveragerc", "    runtime/scripts/*"),
        ]
        for path, line in cases:
            with self.subTest(path=path, line=line):
                self.assertEqual(floor_guard.guard_surface_hit(path, line), path)

    def test_any_toml_quoting_of_an_entry_trips(self):
        # #707 review: only double-quoted entries matched, so a later
        # `'runtime/scripts/*' = ['F401', 'F841']` under an existing table disabled frozen rules.
        cases = [
            "'runtime/scripts/*' = ['F401', 'F841']",
            "'tests/*' = [\"F401\"]",
            "    'F841',",
            "scripts = ['F401']",
            'tests = ["F401", "F841"]',
        ]
        for line in cases:
            with self.subTest(line=line):
                self.assertEqual(floor_guard.guard_surface_hit("ruff.toml", line), "ruff.toml")

    def test_the_rest_of_those_files_stays_silent(self):
        cases = [
            ("ruff.toml", 'target-version = "py311"'),
            ("ruff.toml", "line-length = 120"),
            ("ruff.toml", "preview = true"),
            ("ruff.toml", "[lint]"),
            ("ruff.toml", "# F401 / F841 unused imports and locals"),
            (".coveragerc", "[run]"),
            (".coveragerc", "# No excludes: the bar is the raw line number."),
            (".coveragerc", ""),
        ]
        for path, line in cases:
            with self.subTest(path=path, line=line):
                self.assertIsNone(floor_guard.guard_surface_hit(path, line))


class TestThresholdEvasions(unittest.TestCase):
    """2026-10-26 review: compared as one flat list of numbers, a constraints row read unchanged
    when its criterion was reworded around the old number, when a lower number was appended in a
    later cell, or when a bullet note that shared its id paired with the removed table row."""

    D5 = ("| D5 | routing-eval | score >= 1.0 | `python3 scripts/eval.py run --suite routing "
          "--threshold 1.0` | validate.yml | 94/94 (100%) | FROZEN+PROVEN |")
    D9 = ("| D9 | coverage | line >= 80% on `runtime/scripts` + `scripts` | `coverage report` "
          "| validate.yml | **75% (6058 stmts, 1541 missed) — BELOW BAR** | FROZEN-BELOW-BAR |")

    def run_rows(self, removed, added, repo=None):
        out = []

        def pairs(rows):
            return [("CONSTRAINTS.md", 10 + i, t) for i, t in enumerate(rows)]

        floor_guard._flag_lowered_rows(pairs(added), pairs(removed), "CONSTRAINTS.md",
                                       lambda rule, _p, _l, detail: out.append((rule, detail)), repo)
        return out

    def test_the_in_place_lowering_still_reads(self):
        self.assertEqual(self.run_rows([self.D5], [self.D5.replace("score >= 1.0", "score >= 0.9")]),
                         [("threshold-lowered", "1 -> 0.9")])

    def test_a_criterion_reworded_around_the_old_number_is_flagged(self):
        out = self.run_rows([self.D5], [self.D5.replace("score >= 1.0", "score >= nine tenths (frozen at 1.0)")])
        self.assertEqual(out, [("threshold-lowered", "criterion no longer compares against a number")])

    def test_a_lower_floor_appended_in_a_later_cell_is_flagged(self):
        out = self.run_rows([self.D5], [self.D5.replace("FROZEN+PROVEN", "FROZEN+PROVEN; effective floor 0.9 while flaky")])
        self.assertEqual(out, [("threshold-lowered", "a floor-shaped number was added: 0.9")])

    def test_a_full_width_digit_is_the_same_number(self):
        self.assertEqual(self.run_rows([self.D9], [self.D9.replace("80%", "８０%")]), [])
        self.assertEqual(self.run_rows([self.D9], [self.D9.replace("80%", "７０%")]),
                         [("threshold-lowered", "80 -> 70")])

    def test_a_measurement_that_rises_is_silent_and_one_that_falls_is_not(self):
        # Every downward number in a frozen row needs a waiver, a measurement included (as before);
        # cell-scoping only stops the positions of one cell from being read against another's.
        self.assertEqual(self.run_rows([self.D9], [self.D9.replace("75% (6058 stmts, 1541 missed)",
                                                                   "76% (6100 stmts, 1600 missed)")]), [])
        self.assertEqual(self.run_rows([self.D9], [self.D9.replace("75% (6058 stmts, 1541 missed)",
                                                                   "74% (6100 stmts, 1600 missed)")]),
                         [("threshold-lowered", "75 -> 74")])

    def test_a_re_dated_note_pairs_with_itself_and_is_silent(self):
        before = "- D9: the human froze 80% against an UNMEASURED dimension"
        after = "- D9 (re-read 2026-10-26, 7 cases): the human froze 80% against an UNMEASURED dimension"
        self.assertEqual(self.run_rows([before], [after]), [])
        self.assertEqual(self.run_rows([before], [before.replace("80%", "70%")]),
                         [("threshold-lowered", "80 -> 70")])

    def test_a_note_never_pairs_with_a_table_row_that_shares_its_id(self):
        note = "- D9: the human froze 80% against"
        out = self.run_rows([self.D9, note], [note + " (note first in diff)", self.D9])
        self.assertEqual(out, [])
        out = self.run_rows([self.D9, note], [note + " (edited)"])
        self.assertEqual(out, [("threshold-lowered", "row removed or re-keyed")])

    def test_a_raised_prose_number_is_a_tightening_not_a_lowering(self):
        # PR #707 review: the prose branch flagged any vanished number, a raise included.
        before = "- D9: the human froze 80% against an UNMEASURED dimension"
        self.assertEqual(self.run_rows([before], [before.replace("80%", "90%")]), [])
        self.assertEqual(self.run_rows([before], [before.replace("80%", "70%")]),
                         [("threshold-lowered", "80 -> 70")])
        self.assertEqual(self.run_rows([before], [before.replace("80%", "the floor")]),
                         [("threshold-lowered", "80 -> (no number)")])
        two = "- D9: 80% line coverage over 5 modules"
        self.assertEqual(self.run_rows([two], [two.replace("80%", "90%").replace("5 modules", "4 modules")]),
                         [("threshold-lowered", "5 -> 4")])

    def test_an_unrelated_higher_number_does_not_hide_a_lowered_floor(self):
        # #707 review: `gone=[80]`, `fresh=[70, 100]` passed because 100 >= 80. A vanished value
        # is matched to the new values that carry its unit; any of them lower is a lowering.
        before = "- D9: the human froze 80% against an UNMEASURED dimension"
        lowered = before.replace("80%", "70%") + " (100 cases checked)"
        self.assertEqual(self.run_rows([before], [lowered]), [("threshold-lowered", "80 -> 70")])
        raised = "- D9: the human froze 85% against an UNMEASURED dimension (3 modules)"
        self.assertEqual(self.run_rows([before], [raised]), [], "a raise beside an unrelated count is silent")
        unitless = "- D9: at most 3 retries"
        self.assertEqual(self.run_rows([unitless], ["- D9: at most 2 retries in 10 runs"]),
                         [("threshold-lowered", "3 -> 2")])

    def test_an_edited_twin_does_not_hide_an_appended_duplicate(self):
        # PR #707 review: a wording edit to the original row paired it, and the appended
        # duplicate at a lower number was skipped as that key's "already paired" row.
        with tempfile.TemporaryDirectory() as tmp:
            edited = self.D9.replace("FROZEN-BELOW-BAR", "FROZEN-BELOW-BAR (reworded)")
            lower = self.D9.replace("80%", "70%")
            Path(tmp, "CONSTRAINTS.md").write_text(
                "| id | dim |\n|---|---|\n" + edited + "\n" + lower + "\n", encoding="utf-8")
            out = self.run_rows([self.D9], [edited, lower], repo=tmp)
            self.assertIn(("threshold-lowered", "duplicate row for d9"), out)

    def test_a_duplicate_row_for_a_key_the_file_keeps_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            lower = self.D9.replace("80%", "70%")
            Path(tmp, "CONSTRAINTS.md").write_text(
                "| id | dim |\n|---|---|\n" + self.D9 + "\n" + lower + "\n", encoding="utf-8")
            self.assertEqual(self.run_rows([], [lower], repo=tmp), [("threshold-lowered", "duplicate row for d9")])
            Path(tmp, "CONSTRAINTS.md").write_text("| id | dim |\n|---|---|\n" + lower + "\n", encoding="utf-8")
            self.assertEqual(self.run_rows([], [lower], repo=tmp), [], "a new floor with no twin is silent")


class TestGuardSurfaceEndToEnd(FloorGuardBase):
    def _surface_repo(self, path, content, name="surface"):
        repo = Path(self.tmp) / name
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "t")
        write(repo, path, content)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "base")
        git(repo, "checkout", "-q", "-b", "work")
        return repo

    def _lowered_floor(self):
        repo = self._surface_repo("tests/test_evals.py", "ROUTING_MIN_SCORE = 1.0\n")
        write(repo, "tests/test_evals.py", "ROUTING_MIN_SCORE = 0.5\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "lower the floor")
        return repo

    def test_a_lowered_routing_floor_is_flagged(self):
        code, _out, err = run_main(self._lowered_floor(), "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertIn("guard-surface", err)
        self.assertRegex(err, r"\[guard-surface\] tests/test_evals\.py:\d+")

    def test_a_use_site_edit_without_touching_the_floor_is_silent(self):
        repo = self._surface_repo("tests/test_evals.py",
                                  "ROUTING_MIN_SCORE = 1.0\n\n\ndef check(score):\n    return score\n")
        write(repo, "tests/test_evals.py",
              "ROUTING_MIN_SCORE = 1.0\n\n\ndef check(score):\n    return score >= ROUTING_MIN_SCORE\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "cite the floor without moving it")
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, err)

    def test_each_whole_surface_file_trips(self):
        for path, line in ((".gitleaksignore", "aabbccddeeff00112233445566778899aabbccdd\n"),
                           ("evals/routing.json", '{"prompts": []}\n'),
                           ("bench/vf-bench/VERSION", "vf-bench@0.2\n"),
                           ("bench/vf-bench/CANARY", "canary GUID 00000000-0000-0000-0000-000000000000\n"),
                           ("bench/vf-bench/traps/zz-canary.json", '{"trap": true}\n')):
            with self.subTest(path=path):
                repo = Path(self.tmp) / ("repo-" + path.replace("/", "-"))
                repo.mkdir(parents=True)
                git(repo, "init", "-q", "-b", "main")
                git(repo, "config", "user.email", "t@example.invalid")
                git(repo, "config", "user.name", "t")
                write(repo, "README.md", "base\n")
                git(repo, "add", "-A")
                git(repo, "commit", "-qm", "base")
                git(repo, "checkout", "-q", "-b", "work")
                write(repo, path, line)
                git(repo, "add", "-A")
                git(repo, "commit", "-qm", "touch the surface")
                code, _out, err = run_main(repo, "--base", "main")
                self.assertEqual(code, 1, f"{path} did not trip")
                self.assertIn("guard-surface", err)

    def test_each_keyed_surface_file_trips(self):
        for path, line in (("ruff.toml", 'select = ["E9"]\n'),
                           (".coveragerc", "[report]\nfail_under = 70\n"),
                           ("bench/vf-bench/gate.py", 'EXPECTED_VERSION = "vf-bench@0.2"\n'),
                           ("bench/vf-bench/gate.py", 'EXPECTED_CANARY_GUID = "0000"\n'),
                           ("bench/vf-bench/gate.py", 'EXPECTED_CORPUS_SHA256 = "0000"\n')):
            with self.subTest(path=path, line=line.strip()):
                write(self.repo, path, line)
                self.commit("touch the surface")
                code, _out, err = run_main(self.repo, "--base", "main")
                self.assertEqual(code, 1, f"{path}: {line.strip()} did not trip")
                self.assertIn("guard-surface", err)

    def test_header_shaped_content_cannot_move_a_surface_touch_off_its_file(self):
        # floor_guard review: removing a `-- note` line ahead of fail_under made
        # the parser attribute the fail_under removal to a file called `note`.
        for name, base, work in (
                ("removed", "[report]\n-- note\nfail_under = 80\n", "[report]\n"),
                ("added", "[report]\n", "[report]\n++ x\nfail_under = 70\n")):
            with self.subTest(case=name):
                repo = self._surface_repo(".coveragerc", base, name=f"hdr-{name}")
                write(repo, ".coveragerc", work)
                git(repo, "commit", "-qam", "edit beside a header-shaped line")
                code, _out, err = run_main(repo, "--base", "main")
                self.assertEqual(code, 1, err)
                self.assertRegex(err, r"\[guard-surface\] \.coveragerc:\d+")

    def test_a_granting_waiver_exempts_a_surface_touch(self):
        repo = self._lowered_floor()
        land_on_base(repo, {"docs/DECISIONS.md": grant_row(
            "floor-waiver:guard-surface:tests/test_evals.py",
            why="the floor moves with the eval") + "\n"})
        code, out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, err)
        self.assertIn("waived", out)

    def test_a_content_preserving_rename_still_trips(self):
        # PR #468 review, P1: with rename detection on, `git mv` renders as
        # metadata with no content lines, and a content-line guard reads that
        # as silence — renaming .coveragerc sideways would unwire D9 untripped.
        for name, (path, content) in enumerate(((".coveragerc", "[report]\nfail_under = 80\n"),
                                                     ("tests/test_evals.py",
                                                      "ROUTING_MIN_SCORE = 1.0\n"))):
            with self.subTest(path=path):
                repo = self._surface_repo(path, content, name=f"surface-{name}")
                git(repo, "mv", path, path + ".moved")
                git(repo, "commit", "-qm", "rename the guarded file")
                code, _out, err = run_main(repo, "--base", "main")
                self.assertEqual(code, 1, f"renaming {path} went silent")
                self.assertIn("guard-surface", err)


class TestScanUnits(FloorGuardBase):
    # Marker fixtures are split across string literals: each half is inert to
    # the guard, and the joined runtime string trips exactly the rule under
    # test. A contiguous marker here would be a self-finding when the guard
    # CI job diff-scans the PR that carries these tests.
    NOQA = "value = 1  # " + "noqa"
    SKIP = "@pytest.mark.sk" + "ip"
    STUB = "# T" + "ODO: later"

    def _scan(self, added=(), removed=(), name="CONSTRAINTS.md", repo=None):
        return floor_guard.scan(list(added), list(removed), name, repo or Path(self.tmp))

    def test_added_markers_flag_their_rules(self):
        findings = self._scan(added=[("src/a.py", 1, self.NOQA),
                                     ("tests/t.py", 2, self.SKIP),
                                     ("src/b.py", 3, self.STUB)])
        self.assertEqual([f["rule"] for f in findings],
                         ["silenced-checker", "test-made-easier", "unfinished-work"])
        self.assertEqual(findings[0]["path"], "src/a.py")
        self.assertEqual(findings[0]["line"], 1)
        self.assertEqual(findings[0]["detail"], "noqa")

    def test_guard_surface_flags_on_added_and_removed_lines(self):
        added = self._scan(added=[(".gitleaksignore", 1, "aabbcc")])
        self.assertEqual([(f["rule"], f["detail"]) for f in added],
                         [("guard-surface", ".gitleaksignore")])
        removed = self._scan(removed=[("evals/routing.json", 9, '  {"p": 1},')])
        self.assertEqual([(f["rule"], f["detail"]) for f in removed],
                         [("guard-surface", "evals/routing.json")])

    def test_a_lowered_number_flags_with_the_before_and_after(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 4, "| D1 | coverage | 60 |")],
                              removed=[("CONSTRAINTS.md", 4, "| D1 | coverage | 85 |")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "threshold-lowered")
        self.assertEqual(findings[0]["detail"], "85 -> 60")

    def test_only_the_lowered_number_in_a_pair_flags(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 4, "| D | a 10 b 15 |")],
                              removed=[("CONSTRAINTS.md", 4, "| D | a 10 b 20 |")])
        self.assertEqual([(f["rule"], f["detail"]) for f in findings],
                         [("threshold-lowered", "20 -> 15")])

    def test_a_raised_an_unmatched_and_a_keyless_row_stay_silent(self):
        raised = self._scan(added=[("CONSTRAINTS.md", 4, "| D1 | coverage | 95 |")],
                            removed=[("CONSTRAINTS.md", 4, "| D1 | coverage | 85 |")])
        self.assertEqual(raised, [])
        # An ADDED row with no predecessor is a new floor. A removed numbered row with no
        # same-key partner used to sit here too; it is the deleted/re-keyed row P2-5 named,
        # and TestThresholdRowsP25 pins that it now flags.
        unmatched = self._scan(added=[("CONSTRAINTS.md", 9, "| D9 | other | 1 |")],
                               removed=[])
        self.assertEqual(unmatched, [])
        keyless = self._scan(added=[("CONSTRAINTS.md", 4, "|||")],
                             removed=[("CONSTRAINTS.md", 4, "|||")])
        self.assertEqual(keyless, [])

    def test_a_number_with_no_before_value_stays_silent(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 4, "| D | a 10 b 5 |")],
                              removed=[("CONSTRAINTS.md", 4, "| D | a 10 |")])
        self.assertEqual(findings, [])

    def test_an_exception_row_flags(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 9, "| W101 | legacy | Q3 |")])
        self.assertEqual([f["rule"] for f in findings], ["new-exception"])

    def test_a_bullet_under_an_in_diff_exceptions_heading_flags(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 8, "## Exceptions"),
                                     ("CONSTRAINTS.md", 9, "- legacy stays unlinted")])
        self.assertEqual([f["rule"] for f in findings], ["new-exception"])

    def test_a_bullet_under_an_on_disk_exceptions_heading_flags(self):
        # The hermetic repo's CONSTRAINTS.md carries ## Exceptions on disk (no
        # heading line in the diff), which is the half the in-diff marker alone missed.
        findings = self._scan(added=[("CONSTRAINTS.md", 9, "- legacy stays unlinted")],
                              repo=self.repo)
        self.assertEqual([f["rule"] for f in findings], ["new-exception"])

    def test_a_bullet_with_no_exceptions_heading_stays_silent(self):
        bare = Path(self.tmp) / "bare"
        bare.mkdir()
        findings = self._scan(added=[("CONSTRAINTS.md", 9, "- a plain bullet")], repo=bare)
        self.assertEqual(findings, [])

    def test_an_unreadable_constraints_file_reads_as_no_heading(self):
        blocked = Path(self.tmp) / "blocked"
        blocked.mkdir()
        (blocked / "CONSTRAINTS.md").mkdir()
        findings = self._scan(added=[("CONSTRAINTS.md", 9, "- a plain bullet")], repo=blocked)
        self.assertEqual(findings, [])

    def test_a_plain_line_is_not_an_exception_bullet(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 9, "a plain line")], repo=self.repo)
        self.assertEqual(findings, [])

    def test_a_removed_assertion_in_a_surviving_test_flags(self):
        findings = self._scan(removed=[("tests/test_thing.py", 5, "    assert other() == 5")],
                              repo=self.repo)
        self.assertEqual([f["rule"] for f in findings], ["assertion-removed"])

    def test_a_removed_assertion_in_a_deleted_file_stays_silent(self):
        findings = self._scan(removed=[("tests/gone.py", 1, "    assert gone()")],
                              repo=self.repo)
        self.assertEqual(findings, [])

    def test_a_removed_assertion_outside_test_paths_stays_silent(self):
        findings = self._scan(removed=[("src/app.py", 2, "    assert True")], repo=self.repo)
        self.assertEqual(findings, [])

    def test_a_removed_non_assertion_line_stays_silent(self):
        findings = self._scan(removed=[("tests/test_thing.py", 1, "def test_thing():")],
                              repo=self.repo)
        self.assertEqual(findings, [])

    def test_a_head_deleted_test_file_still_counts_as_surviving(self):
        (self.repo / "tests" / "test_thing.py").unlink()
        findings = self._scan(removed=[("tests/test_thing.py", 5, "    assert other() == 5")],
                              repo=self.repo)
        self.assertEqual([f["rule"] for f in findings], ["assertion-removed"])

    def test_an_uncommitted_test_file_counts_as_surviving(self):
        write(self.repo, "tests/test_fresh.py", "def test_fresh():\n    assert fresh()\n")
        findings = self._scan(removed=[("tests/test_fresh.py", 2, "    assert fresh()")],
                              repo=self.repo)
        self.assertEqual([f["rule"] for f in findings], ["assertion-removed"])


class TestDiffParsingUnits(unittest.TestCase):
    def test_hunk_accounting_pins_added_removed_and_context_lines(self):
        diff = ("--- a/src/app.py\n"
                "+++ b/src/app.py\n"
                "@@ -1,2 +1,3 @@\n"
                " ctx\n"
                "-old\n"
                "+new\n"
                "+more\n")
        added, removed = floor_guard.parse_diff(diff)
        self.assertEqual(added, [("src/app.py", 2, "new"), ("src/app.py", 3, "more")])
        self.assertEqual(removed, [("src/app.py", 2, "old")])

    def test_new_and_deleted_files_resolve_through_dev_null(self):
        added, removed = floor_guard.parse_diff(
            "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+line\n")
        self.assertEqual(added, [("new.py", 1, "line")])
        self.assertEqual(removed, [])
        added, removed = floor_guard.parse_diff(
            "--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n")
        self.assertEqual(added, [])
        self.assertEqual(removed, [("gone.py", 1, "gone")])

    def test_content_lines_shaped_like_file_headers_stay_content(self):
        # A removed `-- note` is `--- note` on the wire and an added `++ x` is
        # `+++ x`; only the hunk's declared counts tell them from headers.
        added, removed = floor_guard.parse_diff(
            "--- a/.coveragerc\n+++ b/.coveragerc\n@@ -2,2 +2,2 @@\n"
            "--- note\n-fail_under = 80\n+++ x\n+fail_under = 70\n")
        self.assertEqual(removed, [(".coveragerc", 2, "-- note"), (".coveragerc", 3, "fail_under = 80")])
        self.assertEqual(added, [(".coveragerc", 2, "++ x"), (".coveragerc", 3, "fail_under = 70")])

    def test_a_diff_whose_hunks_do_not_add_up_cannot_run(self):
        for diff in ("--- a/x\n+++ b/x\n@@ -1,2 +1 @@\n-a\n",
                     "--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n-a\n+b\n",
                     "--- a/x\n+++ b/x\n@@ bogus @@\n"):
            with self.subTest(diff=diff), self.assertRaises(floor_guard.GuardError):
                floor_guard.parse_diff(diff)

    def test_strip_prefix_handles_prefixes_dev_null_and_bare_paths(self):
        self.assertEqual(floor_guard.strip_prefix("a/src/x.py"), "src/x.py")
        self.assertEqual(floor_guard.strip_prefix("b/src/x.py"), "src/x.py")
        self.assertEqual(floor_guard.strip_prefix("/dev/null"), "")
        self.assertEqual(floor_guard.strip_prefix("plain.py"), "plain.py")

    def test_row_key_is_the_first_nonempty_cell(self):
        self.assertEqual(floor_guard.row_key("| D1 | coverage | 85 |"), "d1")
        self.assertEqual(floor_guard.row_key("- floor: 3"), "floor")
        self.assertEqual(floor_guard.row_key("|||"), "")

    def test_numbers_reads_ints_and_decimals(self):
        self.assertEqual(floor_guard.numbers("v1.2 and 3"), [1.2, 3.0])
        self.assertEqual(floor_guard.numbers("no digits"), [])

    def test_is_constraints_matches_by_filename(self):
        self.assertTrue(floor_guard.is_constraints("CONSTRAINTS.md", "CONSTRAINTS.md"))
        self.assertTrue(floor_guard.is_constraints("docs/CONSTRAINTS.md", "CONSTRAINTS.md"))
        self.assertFalse(floor_guard.is_constraints("OTHER.md", "CONSTRAINTS.md"))
        self.assertFalse(floor_guard.is_constraints("", "CONSTRAINTS.md"))


class TestWaiverUnits(unittest.TestCase):
    def _row(self, ident, answer="allow", ts="2026-09-10T00:00:00Z"):
        return grant_row(ident, answer=answer, ts=ts, why="why")

    def _finding(self, rule="silenced-checker", path="src/new.py"):
        return {"rule": rule, "path": path, "line": 1, "detail": "noqa"}

    def test_a_granting_waiver_waives_through_the_sibling_loader(self):
        self.assertTrue(floor_guard.is_waived(
            self._finding(), [self._row("floor-waiver:silenced-checker:src/new.py")]))

    def test_a_preloaded_decisions_module_is_used_as_is(self):
        loaded = floor_guard._load_decisions()
        self.assertTrue(floor_guard.is_waived(
            self._finding(), [self._row("floor-waiver:silenced-checker:src/new.py")],
            decisions=loaded))

    def test_a_denied_a_superseded_and_a_wrong_rule_do_not_waive(self):
        ident = "floor-waiver:silenced-checker:src/new.py"
        self.assertFalse(floor_guard.is_waived(
            self._finding(), [self._row(ident, answer="deny")]))
        self.assertFalse(floor_guard.is_waived(
            self._finding(), [self._row(ident, ts="2026-09-01T00:00:00Z"),
                              self._row(ident, answer="superseded", ts="2026-09-02T00:00:00Z")]))
        self.assertFalse(floor_guard.is_waived(
            self._finding(), [self._row("floor-waiver:threshold-lowered:src/new.py")]))

    def test_prose_and_unscoped_ids_do_not_waive(self):
        self.assertFalse(floor_guard.is_waived(self._finding(), ["just a note"]))
        self.assertFalse(floor_guard.is_waived(
            self._finding(), [self._row("floor-waiver")]))

    def test_a_finding_without_a_path_is_never_waived(self):
        self.assertFalse(floor_guard.is_waived(
            {"rule": "silenced-checker"}, [self._row("floor-waiver:silenced-checker:src/new.py")]))

    def test_an_unloadable_sibling_waives_nothing(self):
        with mock.patch.object(floor_guard, "_load_decisions", side_effect=Exception("boom")):
            self.assertFalse(floor_guard.is_waived(
                self._finding(), [self._row("floor-waiver:silenced-checker:src/new.py")]))

    def test_path_scope_is_segment_wise_never_substring(self):
        hit = floor_guard._path_waived_by
        self.assertTrue(hit("src/new.py", "src/new.py"))
        self.assertTrue(hit("src/**", "src/new.py"))
        self.assertTrue(hit("src/**", "src/a/b.py"))
        self.assertFalse(hit("src", "src/new.py"))
        self.assertFalse(hit("src/", "src/new.py"))
        self.assertFalse(hit("**", "src/new.py"))
        self.assertFalse(hit("/**", "src/new.py"))
        self.assertFalse(hit("src/new.pyc", "src/new.py"))
        self.assertFalse(hit("src/new.py", "src/new.pyx"))
        self.assertFalse(hit("src/**", "srcinternal/x.py"))

    def test_missing_waiver_file_is_no_waivers(self):
        self.assertEqual(floor_guard.load_waivers("/nonexistent/DECISIONS.md"), [])

    def test_an_unreadable_waiver_file_is_a_could_not_run(self):
        with tempfile.TemporaryDirectory(prefix="waivers-") as tmp:
            with self.assertRaises(floor_guard.GuardError):
                floor_guard.load_waivers(tmp)

    def test_malformed_waivers_are_named_with_the_shape_to_write(self):
        notes = floor_guard.malformed_waivers([self._row("floor-waiver")])
        self.assertEqual(len(notes), 1)
        self.assertIn("scope is not in the id", notes[0][1])
        notes = floor_guard.malformed_waivers([self._row("floor-waiver:silenced-checker")])
        self.assertEqual(len(notes), 1)
        self.assertIn("floor-waiver:<rule>:<path-or-glob>", notes[0][1])
        good = floor_guard.malformed_waivers(
            [self._row("floor-waiver:silenced-checker:src/new.py"), "prose"])
        self.assertEqual(good, [])

    def test_malformed_waivers_survive_an_unloadable_sibling(self):
        with mock.patch.object(floor_guard, "_load_decisions", side_effect=Exception("boom")):
            self.assertEqual(floor_guard.malformed_waivers([self._row("floor-waiver")]), [])


class TestMainInProc(FloorGuardBase):
    def test_clean_reports_the_banner_in_process(self):
        code, out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 0, err)
        self.assertIn("floor-guard: clean", out)

    def test_quiet_suppresses_the_clean_banner(self):
        code, out, err = run_main(self.repo, "--base", "main", "--quiet")
        self.assertEqual(code, 0, err)
        self.assertEqual(out, "")

    def test_an_omitted_base_falls_back_to_the_local_main(self):
        code, _out, err = run_main(self.repo)
        self.assertEqual(code, 0, err)
        write(self.repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit("lower")
        code, _out, err = run_main(self.repo)
        self.assertEqual(code, 1, "the default base did not evaluate main..work")
        self.assertIn("threshold-lowered", err)

    def test_a_violation_names_the_rule_and_the_waiver_shape(self):
        write(self.repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit("lower")
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1)
        self.assertIn("[threshold-lowered]", err)
        self.assertIn("floor-waiver:<rule>:<path>", err)

    def test_a_granting_waiver_reports_the_count_in_process(self):
        write(self.repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit("lower")
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(
            "floor-waiver:threshold-lowered:CONSTRAINTS.md",
            why="the bar moves deliberately") + "\n"})
        code, out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 0, err)
        self.assertIn("(1 waived)", out)

    def test_an_unresolvable_base_is_exit_2_in_process(self):
        code, _out, err = run_main(self.repo, "--base", "origin/does-not-exist")
        self.assertEqual(code, 2)
        self.assertIn("not resolvable", err)

    def test_a_non_repo_is_exit_2_in_process(self):
        plain = Path(self.tmp) / "plain"
        plain.mkdir()
        code, _out, err = run_main(plain, "--base", "main")
        self.assertEqual(code, 2)
        self.assertIn("not inside a git work tree", err)

    def test_no_resolvable_default_base_is_exit_2(self):
        repo = Path(self.tmp) / "trunk"
        repo.mkdir()
        git(repo, "init", "-q", "-b", "trunk")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "t")
        write(repo, "file.txt", "content\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "base")
        code, _out, err = run_main(repo)
        self.assertEqual(code, 2)
        self.assertIn("no base ref could be resolved", err)

    def test_origin_head_wins_over_the_local_branch(self):
        # The distinguishing setup: the remote tip (T1, clean) and the local
        # tip (T2, violation) have different TREES, and work sits at T2. A base
        # of origin/main diffs T1..T2 and sees the violation; a base of the
        # local main diffs T2..T2 and reads clean.
        origin = Path(self.tmp) / "origin.git"
        # Branch names are explicit throughout: the runner's ambient
        # init.defaultBranch is master-is-default, the author's is main, and an
        # unborn master made `push origin main` fail only in CI (#468 gates).
        git(Path(self.tmp), "init", "-q", "--bare", "-b", "main", "origin.git")
        seed = Path(self.tmp) / "seed"
        git(Path(self.tmp), "clone", "-q", str(origin), "seed")
        git(seed, "checkout", "-q", "-b", "main")
        git(seed, "config", "user.email", "t@example.invalid")
        git(seed, "config", "user.name", "t")
        write(seed, "CONSTRAINTS.md", BASE_CONSTRAINTS)
        git(seed, "add", "-A")
        git(seed, "commit", "-qm", "base")
        git(seed, "push", "-q", "origin", "main")
        repo = Path(self.tmp) / "clone"
        git(Path(self.tmp), "clone", "-q", str(origin), "clone")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "t")
        head = git(repo, "symbolic-ref", "refs/remotes/origin/HEAD")
        self.assertEqual(head.stdout.strip(), "refs/remotes/origin/main",
                         "the clone has no origin/HEAD to prefer — the setup is wrong, not the code")
        write(repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "violation, unpushed")
        git(repo, "checkout", "-q", "-b", "work")
        code, _out, err = run_main(repo)
        self.assertEqual(code, 1, f"the guard read the local tip, not origin/HEAD: {err}")
        self.assertIn("threshold-lowered", err)

    def test_branches_without_a_merge_base_are_exit_2(self):
        git(self.repo, "checkout", "-q", "--orphan", "ghost")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "ghost")
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 2)
        self.assertIn("no merge base", err)

    def test_git_failing_to_launch_is_exit_2(self):
        with mock.patch.object(floor_guard.subprocess, "run", side_effect=OSError("no git")):
            code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 2)
        self.assertIn("could not run", err)

    def test_an_old_shape_waiver_is_named_in_process(self):
        write(self.repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit("lower")
        land_on_base(self.repo, {"docs/DECISIONS.md": (
            "2026-09-10T00:00:00Z · floor-waiver · taste · allow · the old shape · t-1\n")})
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1)
        self.assertIn("NOT a usable waiver", err)
        self.assertIn("floor-waiver:<rule>:<path>", err)

    def test_an_unloadable_sibling_grants_no_waiver_and_names_none(self):
        write(self.repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit("lower")
        write(self.repo, "docs/DECISIONS.md",
              "2026-09-10T00:00:00Z · floor-waiver · taste · allow · the old shape · t-1\n")
        with mock.patch.object(floor_guard, "_load_decisions", side_effect=Exception("boom")):
            code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1)
        self.assertIn("[threshold-lowered]", err)
        self.assertNotIn("NOT a usable waiver", err)

    def test_the_module_entry_point_runs_clean_and_exits_zero(self):
        argv = ["floor_guard.py", "--repo", str(self.repo), "--base", "main"]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as ctx:
                    runpy.run_path(str(GUARD), run_name="__main__")
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("floor-guard: clean", out.getvalue())



# ---- 2026-10-23 end-to-end review (#620, #621) ----------------------------------------------
#
# Marker fixtures are split across literals for the reason TestScanUnits gives: this file is
# itself diff-scanned by the guard in CI, and a contiguous marker would be a self-finding.
SUPPRESSED = "value = 1  # " + "no" + "qa"
SKIP_DECORATOR = "@pytest.mark.sk" + "ip"


class ReviewRepo(unittest.TestCase):
    """A fresh hermetic repo per case: base files on `main`, the change on `work`."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="floorguard-review-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def repo(self, files, name="repo"):
        repo = Path(self.tmp) / name
        repo.mkdir()
        git(repo, "init", "-q", "-b", "main")
        git(repo, "config", "user.email", "t@example.invalid")
        git(repo, "config", "user.name", "t")
        for rel, text in files.items():
            write(repo, rel, text)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "base")
        git(repo, "checkout", "-q", "-b", "work")
        return repo

    @staticmethod
    def commit(repo, message="change"):
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", message)


class TestTextDiffP16(ReviewRepo):
    """P1-6: a `.gitattributes` the change adds must not blank the rules it is judged by."""

    BASE = {
        ".coveragerc": "[report]\nfail_under = 80\n",
        "CONSTRAINTS.md": BASE_CONSTRAINTS,
        "src/app.py": "def compute():\n    return 4\n",
        "tests/test_thing.py": BASE_TEST,
    }

    def test_a_minus_diff_attribute_does_not_blank_tracked_or_untracked_files(self):
        # The review's reproduction: `* -diff` plus a lowered fail_under, a suppression, a skip
        # decorator and a lowered CONSTRAINTS row printed `floor-guard: clean`, exit 0.
        repo = self.repo(self.BASE)
        write(repo, ".gitattributes", "* -diff\n")
        write(repo, ".coveragerc", "[report]\nfail_under = 10\n")
        write(repo, "src/app.py", "def compute():\n    return 4\n" + SUPPRESSED + "\n")
        write(repo, "tests/test_thing.py", BASE_TEST + SKIP_DECORATOR + "\n")
        write(repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit(repo, "lower the bar under a -diff attribute")
        write(repo, "src/untracked.py", SUPPRESSED + "\n")
        code, out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, f"-diff blanked the guard: {out}{err}")
        self.assertRegex(err, r"\[guard-surface\] \.coveragerc:\d+")
        self.assertRegex(err, r"\[silenced-checker\] src/app\.py:\d+")
        self.assertRegex(err, r"\[silenced-checker\] src/untracked\.py:\d+")
        self.assertRegex(err, r"\[test-made-easier\] tests/test_thing\.py:\d+")
        self.assertIn("[threshold-lowered] CONSTRAINTS.md", err)

    def test_binary_media_bytes_never_read_as_code(self):
        """PR #631 rename: --text renders a JPEG as bytes, and a re-rendered hero image tripped
        unfinished-work on bytes that happened to spell a stub marker. Content rules skip binary
        MEDIA by extension; a source file with a NUL byte is still read, and a media file on the
        guard surface still trips by path."""
        repo = self.repo(self.BASE)
        marker = b"\xff\xd8\xff\xe0" + b"XX" + b"X " + b"TO" + b"DO " + b"# no" + b"qa \x00\x01" * 50
        (repo / "assets").mkdir()
        (repo / "assets" / "hero.jpg").write_bytes(marker + b"\n" + marker + b"\n")
        (repo / "tests" / "fixture.png").write_bytes(marker + b"\nassert x\n")
        self.commit(repo, "a re-rendered image")
        code, out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, f"media bytes were read as code: {out}{err}")
        write(repo, "src/app.py", "def compute():\n    return 4\n" + SUPPRESSED + "\n# \x00\n")
        trap = repo / "bench" / "vf-bench" / "traps"
        trap.mkdir(parents=True)
        (trap / "frame.png").write_bytes(marker)
        self.commit(repo, "a NUL-bearing source file and a media file on the guard surface")
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertRegex(err, r"\[silenced-checker\] src/app\.py:\d+")
        self.assertRegex(err, r"\[guard-surface\] bench/vf-bench/traps/frame\.png:\d+")
        self.assertNotIn("hero.jpg", err)
        self.assertNotIn("fixture.png", err)

    def test_a_binary_diff_driver_does_not_blank_a_file(self):
        repo = self.repo(self.BASE)
        write(repo, ".gitattributes", "*.py diff=opaque\n")
        git(repo, "config", "diff.opaque.binary", "true")
        write(repo, "src/app.py", "def compute():\n    return 4\n" + SUPPRESSED + "\n")
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertRegex(err, r"\[silenced-checker\] src/app\.py:\d+")

    def test_a_nul_byte_does_not_make_a_text_file_binary(self):
        # Content sniffing is the same hole as the attribute: one NUL byte and git prints
        # `Binary files … differ` for a file whose other lines a tool still reads.
        repo = self.repo(self.BASE)
        (repo / "src" / "app.js").write_bytes(
            b"const a = 1;\n// eslint-" + b"disable-next-line\nconst b = '\x00';\n")
        self.commit(repo)
        (repo / "src" / "fresh.js").write_bytes(b"// eslint-" + b"disable\nconst c = '\x00';\n")
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertRegex(err, r"\[silenced-checker\] src/app\.js:\d+")
        self.assertRegex(err, r"\[silenced-checker\] src/fresh\.js:\d+")

    def test_every_diff_the_guard_takes_passes_text(self):
        seen = []
        real_run = subprocess.run

        def record(argv, **kwargs):
            if "diff" in argv:
                seen.append(list(argv))
            return real_run(argv, **kwargs)

        repo = self.repo(self.BASE)
        write(repo, "src/untracked.py", "value = 1\n")
        with mock.patch.object(floor_guard.subprocess, "run", side_effect=record):
            run_main(repo, "--base", "main")
        self.assertEqual(len(seen), 2, seen)
        for argv in seen:
            self.assertIn("--text", argv)
            self.assertIn("--no-color", argv)


class TestDiffRenderingPinsP24(ReviewRepo):
    """P2-4: the guarded repo's own config must not relabel or colour the diff it parses."""

    BASE = {".coveragerc": "[report]\nfail_under = 80\n", "README.md": "base\n"}

    def _lowered(self, *config):
        repo = self.repo(self.BASE, name="repo-" + "-".join(k for k, _v in config))
        for key, value in config:
            git(repo, "config", key, value)
        write(repo, ".coveragerc", "[report]\nfail_under = 70\n")
        self.commit(repo, "lower fail_under")
        return run_main(repo, "--base", "main")

    def test_repo_local_prefix_and_colour_settings_cannot_hide_a_surface_touch(self):
        for config in ((("diff.mnemonicPrefix", "true"),),
                       (("diff.srcPrefix", "x/"), ("diff.dstPrefix", "y/")),
                       (("diff.noprefix", "true"),),
                       (("color.diff", "always"),),
                       (("color.ui", "always"),)):
            with self.subTest(config=config):
                code, out, err = self._lowered(*config)
                self.assertEqual(code, 1, f"{config} hid the touch: {out}{err}")
                self.assertRegex(err, r"\[guard-surface\] \.coveragerc:\d+")

    def test_a_noprefix_path_starting_with_a_prefix_letter_keeps_its_directory(self):
        # With no prefix, `b/.gitleaksignore` would lose its `b/` to strip_prefix and become a
        # surface file it is not; with the pin it keeps its real path.
        repo = self.repo({"b/.gitleaksignore": "x\n"}, name="noprefix-dir")
        git(repo, "config", "diff.noprefix", "true")
        write(repo, "b/.gitleaksignore", "y\n")
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, err)

    def test_both_diffs_pin_the_rendering_keys_at_command_line_precedence(self):
        seen = []
        real_run = subprocess.run

        def record(argv, **kwargs):
            if "diff" in argv:
                seen.append(list(argv))
            return real_run(argv, **kwargs)

        repo = self.repo(self.BASE, name="argv")
        write(repo, "untracked.txt", "x\n")
        with mock.patch.object(floor_guard.subprocess, "run", side_effect=record):
            run_main(repo, "--base", "main")
        self.assertEqual(len(seen), 2, seen)
        for argv in seen:
            pins = [argv[i + 1] for i, arg in enumerate(argv[:argv.index("diff")]) if arg == "-c"]
            for pin in ("diff.noprefix=false", "diff.mnemonicPrefix=false", "diff.srcPrefix=a/",
                        "diff.dstPrefix=b/", "diff.relative=false", "color.diff=false"):
                self.assertIn(pin, pins, argv)


class TestThresholdRowsP25(ReviewRepo):
    """P2-5: a numbered CONSTRAINTS row cannot lose its number by any route but the edit."""

    def _scan(self, added=(), removed=()):
        return floor_guard.scan(list(added), list(removed), "CONSTRAINTS.md", Path(self.tmp))

    def test_a_deleted_numbered_row_flags(self):
        findings = self._scan(removed=[("CONSTRAINTS.md", 4, "| D1 | coverage | 85 |")])
        self.assertEqual([(f["rule"], f["detail"]) for f in findings],
                         [("threshold-lowered", "row removed or re-keyed")])

    def test_a_rekeyed_row_flags(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 4, "| D1b | coverage | 85 |")],
                              removed=[("CONSTRAINTS.md", 4, "| D1 | coverage | 85 |")])
        self.assertEqual([f["rule"] for f in findings], ["threshold-lowered"])
        self.assertEqual(findings[0]["detail"], "row removed or re-keyed")

    def test_a_number_replaced_with_a_word_flags(self):
        findings = self._scan(added=[("CONSTRAINTS.md", 4, "| D1 | coverage | high |")],
                              removed=[("CONSTRAINTS.md", 4, "| D1 | coverage | 85 |")])
        self.assertEqual([(f["rule"], f["detail"]) for f in findings],
                         [("threshold-lowered", "85 -> (no number)")])

    def test_rows_pair_in_order_within_a_key(self):
        # Two rows share a key (a table row and its bullet note); the second loses its number.
        findings = self._scan(
            added=[("CONSTRAINTS.md", 4, "| D9 | coverage | 80 |"),
                   ("CONSTRAINTS.md", 9, "- D9: measured eighty")],
            removed=[("CONSTRAINTS.md", 4, "| D9 | coverage | 80 |"),
                     ("CONSTRAINTS.md", 9, "- D9: measured 80")])
        self.assertEqual([(f["line"], f["detail"]) for f in findings], [(9, "80 -> (no number)")])

    def test_a_moved_or_unnumbered_row_stays_silent(self):
        moved = self._scan(added=[("CONSTRAINTS.md", 12, "| D1 | coverage | 85 |")],
                           removed=[("CONSTRAINTS.md", 4, "| D1 | coverage | 85 |")])
        self.assertEqual(moved, [])
        prose = self._scan(removed=[("CONSTRAINTS.md", 2, "Status: frozen by the human.")])
        self.assertEqual(prose, [])

    def test_a_row_deleted_from_the_real_file_flags_end_to_end(self):
        for name, after in (("deleted", BASE_CONSTRAINTS.replace("| D2 | latency-ms | 250 |\n", "")),
                            ("rekeyed", BASE_CONSTRAINTS.replace("| D1 |", "| D1b |")),
                            ("worded", BASE_CONSTRAINTS.replace("| 85 |", "| eighty-five |"))):
            with self.subTest(case=name):
                repo = self.repo({"CONSTRAINTS.md": BASE_CONSTRAINTS}, name=f"rows-{name}")
                write(repo, "CONSTRAINTS.md", after)
                self.commit(repo)
                code, _out, err = run_main(repo, "--base", "main")
                self.assertEqual(code, 1, f"{name}: {err}")
                self.assertIn("[threshold-lowered] CONSTRAINTS.md", err)

    def test_an_added_note_beside_a_frozen_row_stays_silent(self):
        # The shape of this PR's own D9 note: evidence added, nothing removed.
        repo = self.repo({"CONSTRAINTS.md": BASE_CONSTRAINTS}, name="rows-note")
        write(repo, "CONSTRAINTS.md", BASE_CONSTRAINTS.replace(
            "| D2 | latency-ms | 250 |\n",
            "| D2 | latency-ms | 250 |\n\nD1 re-measured at 91 (run 123, 2026-10-23).\n"))
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, err)


class TestMovedAndQuotedTestFilesP26(ReviewRepo):
    """P2-6: a moved test file still lost the assertion it dropped; a quoted path is a path."""

    BASE = {"tests/test_thing.py": BASE_TEST, "src/app.py": "def compute():\n    return 4\n"}
    WEAKER = "def test_thing():\n    assert compute() == 4\n"

    def test_a_rename_that_drops_an_assertion_is_charged_to_the_destination(self):
        repo = self.repo(self.BASE)
        git(repo, "mv", "tests/test_thing.py", "tests/test_moved.py")
        write(repo, "tests/test_moved.py", self.WEAKER)
        self.commit(repo, "rename and weaken")
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertRegex(err, r"\[assertion-removed\] tests/test_moved\.py:\d+ "
                              r"\(dropped moving from tests/test_thing\.py:\d+\)")

    def test_a_rename_to_an_untracked_destination_is_charged_too(self):
        repo = self.repo(self.BASE)
        git(repo, "rm", "-q", "tests/test_thing.py")
        git(repo, "commit", "-qm", "delete; the successor is not added yet")
        write(repo, "tests/test_moved.py", self.WEAKER)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertIn("[assertion-removed] tests/test_moved.py", err)

    def test_a_move_out_of_the_test_tree_is_charged(self):
        # The assertions survive as text in a file no runner collects.
        repo = self.repo(self.BASE)
        git(repo, "mv", "tests/test_thing.py", "src/thing_checks.py")
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertIn("[assertion-removed] src/thing_checks.py", err)

    def test_a_faithful_rename_and_a_true_deletion_stay_silent(self):
        repo = self.repo(self.BASE, name="faithful")
        git(repo, "mv", "tests/test_thing.py", "tests/test_moved.py")
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, err)
        repo = self.repo(self.BASE, name="deleted")
        git(repo, "rm", "-q", "tests/test_thing.py")
        write(repo, "tests/test_other.py", "def test_other():\n    assert other_thing() is None\n")
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 0, f"a deleted file with no successor is not this rule: {err}")

    def test_a_non_ascii_test_path_keeps_its_assertion_rule(self):
        name = "tests/tést_thing.py"
        repo = self.repo({name: BASE_TEST})
        write(repo, name, self.WEAKER)
        self.commit(repo)
        code, _out, err = run_main(repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertIn(f"[assertion-removed] {name}:", err)

    def test_c_quoted_headers_decode(self):
        self.assertEqual(floor_guard.strip_prefix('"a/tests/t\\303\\251st x.py"\t'),
                         "tests/tést x.py")
        self.assertEqual(floor_guard.unquote_c('"b/q\\"uote\\\\back\\tt"'), 'b/q"uote\\back\tt')
        self.assertEqual(floor_guard.unquote_c("plain/path.py"), "plain/path.py")
        added, removed = floor_guard.parse_diff(
            '--- "a/tests/t\\303\\251st.py"\n+++ "b/tests/t\\303\\251st.py"\n@@ -1 +1 @@\n-x\n+y\n')
        self.assertEqual(removed, [("tests/tést.py", 1, "x")])
        self.assertEqual(added, [("tests/tést.py", 1, "y")])

    def test_a_malformed_quoted_header_cannot_run(self):
        with self.assertRaises(floor_guard.GuardError):
            floor_guard.parse_diff('--- "a/x\\q"\n+++ b/x\n@@ -1 +1 @@\n-x\n+y\n')


class TestImperativeSkipsSection5(FloorGuardBase):
    """Section 5: skips written as calls, and tests renamed out of discovery."""

    CALLS = (
        ("    self.skip" + "Test('flaky on CI')", "skiptest-call"),
        ("    rai" + "se unittest.SkipTest('later')", "raise-skiptest"),
        ("    rai" + "se SkipTest", "raise-skiptest"),
        ("    t.Skip" + "f(\"needs %s\", host)", "go-skip"),
        ("    b.Skip" + "Now()", "go-skip"),
        ("    pytest.sk" + "ip('later')", "pytest-skip-call"),
        ("    pytest.xf" + "ail('known bug')", "pytest-skip-call"),
    )

    def test_each_call_form_is_test_made_easier(self):
        for text, name in self.CALLS:
            with self.subTest(text=text):
                findings = floor_guard.scan([("tests/test_thing.py", 3, text)], [],
                                            "CONSTRAINTS.md", self.repo)
                self.assertEqual([(f["rule"], f["detail"]) for f in findings],
                                 [("test-made-easier", name)])

    def test_a_skip_call_fails_the_guard_end_to_end(self):
        write(self.repo, "tests/test_thing.py",
              "def test_thing(self):\n    self.skip" + "Test('later')\n"
              "    assert compute() == 4\n    assert other() == 5\n")
        self.commit()
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertIn("(skiptest-call)", err)

    def _renamed(self, before, after, path="tests/test_thing.py"):
        removed = [(path, 1, before)]
        added = [(path, 1, after)]
        return floor_guard.scan(added, removed, "CONSTRAINTS.md", self.repo)

    def test_a_test_renamed_out_of_discovery_flags(self):
        for before, after in (("def test_thing():", "def _test_thing():"),
                              ("def test_thing():", "def disabled_test_thing():"),
                              ("    async def test_io(self):", "    async def xtest_io(self):"),
                              ("class TestThing(unittest.TestCase):",
                               "class DisabledTestThing(unittest.TestCase):"),
                              ("func TestParse(t *testing.T) {", "func testParse(t *testing.T) {")):
            with self.subTest(after=after):
                findings = self._renamed(before, after)
                self.assertEqual([(f["rule"], f["detail"]) for f in findings],
                                 [("test-made-easier", "renamed-out-of-discovery")])

    def test_a_rename_that_stays_discoverable_or_a_move_stays_silent(self):
        for before, after in (("def test_thing():", "def test_thing_again():"),
                              ("def test_thing():", "def test_thing():"),
                              ("def helper_thing():", "def _helper_thing():")):
            with self.subTest(after=after):
                self.assertEqual(self._renamed(before, after), [])
        self.assertEqual(self._renamed("def test_thing():", "def _test_thing():",
                                       path="src/app.py"), [])

    def test_a_rename_out_of_discovery_fails_end_to_end(self):
        write(self.repo, "tests/test_thing.py", BASE_TEST.replace("def test_thing", "def _test_thing"))
        self.commit()
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertRegex(
            err, r"\[test-made-easier\] tests/test_thing\.py:1 \(renamed-out-of-discovery\)")


class TestWaiversFromTheBaseRefP17(FloorGuardBase):
    """P1-7: a waiver is a one-way human grant on the BASE ref, never the change's own line."""

    ID = "floor-waiver:silenced-checker:src/new.py"

    def setUp(self):
        super().setUp()
        self.decisions = floor_guard._load_decisions()
        write(self.repo, "src/new.py", SUPPRESSED + "\n")

    def _signed_row(self, seed, ts="2026-09-10T00:00:00Z", signed_ts=None, answer="allow"):
        ed = self.decisions._ed25519()
        payload = self.decisions.grant_payload(self.ID, answer, "reviewed by the maintainer", "t-1",
                                               ts=signed_ts or ts, klass="one-way")
        sig = ed.signature(payload, seed, ed.publickey(seed)).hex()
        return (f"{ts} · {self.ID} · one-way · {answer} · reviewed by the maintainer "
                f"[source=human:lia sig={sig}] · t-1")

    def _pin(self, seed):
        return {".orca/human-grant-pubkey": self.decisions._ed25519().publickey(seed).hex() + "\n"}

    def test_a_waiver_the_change_writes_for_itself_is_not_honoured(self):
        # The review's reproduction printed `clean (1 waived)`, exit 0.
        for committed in (True, False):
            with self.subTest(committed=committed):
                write(self.repo, "docs/DECISIONS.md", grant_row(self.ID) + "\n")
                if committed:
                    self.commit("suppress and waive it in the same change")
                code, out, err = run_main(self.repo, "--base", "main")
                self.assertEqual(code, 1, f"a self-written waiver granted: {out}")
                self.assertIn("[silenced-checker] src/new.py", err)
                self.assertNotIn("waived", out)

    def test_a_one_way_human_grant_on_the_base_is_honoured(self):
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.ID) + "\n"})
        code, out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 0, err)
        self.assertIn("(1 waived)", out)

    def test_a_taste_or_unsourced_allow_on_the_base_does_not_grant_and_is_named(self):
        for klass, source, why in (("taste", "", "not one-way"),
                                   ("mechanical", "", "not one-way"),
                                   ("one-way", "", "human source")):
            with self.subTest(klass=klass, source=source):
                land_on_base(self.repo, {"docs/DECISIONS.md":
                                         grant_row(self.ID, klass=klass, source=source) + "\n"})
                code, out, err = run_main(self.repo, "--base", "main")
                self.assertEqual(code, 1, f"a {klass} allow granted: {out}")
                self.assertIn("not honoured", err)
                self.assertIn(why, err)

    def test_a_later_superseded_line_on_the_base_retires_the_grant(self):
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.ID) + "\n" + grant_row(
            self.ID, answer="superseded", ts="2026-09-11T00:00:00Z", klass="mechanical",
            source="", why="the parser landed") + "\n"})
        code, out, _err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1, out)

    def test_a_pinned_base_key_requires_a_signature_that_verifies(self):
        seed = os.urandom(32)
        cases = (("unsigned", grant_row(self.ID), 1),
                 ("signed", self._signed_row(seed), 0),
                 ("replayed under a later ts",
                  self._signed_row(seed, ts="2026-09-12T00:00:00Z",
                                   signed_ts="2026-09-10T00:00:00Z"), 1),
                 ("signed by another key", self._signed_row(os.urandom(32)), 1))
        for name, row, expected in cases:
            with self.subTest(case=name):
                land_on_base(self.repo, {**self._pin(seed), "docs/DECISIONS.md": row + "\n"})
                code, out, err = run_main(self.repo, "--base", "main")
                self.assertEqual(code, expected, f"{name}: {out}{err}")

    def test_a_key_and_signature_the_change_brings_are_not_trusted(self):
        seed = os.urandom(32)
        for rel, text in {**self._pin(seed), "docs/DECISIONS.md": self._signed_row(seed) + "\n"}.items():
            write(self.repo, rel, text)
        self.commit("pin my own key and sign my own waiver")
        code, out, _err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1, out)

    def test_a_malformed_base_key_cannot_run(self):
        land_on_base(self.repo, {".orca/human-grant-pubkey": "not-hex\n",
                                 "docs/DECISIONS.md": grant_row(self.ID) + "\n"})
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 2, err)
        self.assertIn("not a hex public key", err)

    def test_a_ledger_outside_the_repository_cannot_run(self):
        outside = Path(self.tmp) / "elsewhere.md"
        outside.write_text(grant_row(self.ID) + "\n", encoding="utf-8")
        code, _out, err = run_main(self.repo, "--base", "main", "--waivers", str(outside))
        self.assertEqual(code, 2, err)
        self.assertIn("outside the repository", err)

    def test_an_absolute_ledger_path_inside_the_repository_is_still_read_at_the_base(self):
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.ID) + "\n"})
        ledger = str(self.repo / "docs" / "DECISIONS.md")
        code, out, err = run_main(self.repo, "--base", "main", "--waivers", ledger)
        self.assertEqual(code, 0, err)
        self.assertIn("(1 waived)", out)
        write(self.repo, "docs/DECISIONS.md", "")  # the checked-out copy says nothing
        code, out, err = run_main(self.repo, "--base", "main", "--waivers", ledger)
        self.assertEqual(code, 0, err)

    def test_the_violation_footer_says_where_a_waiver_must_land(self):
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1)
        self.assertIn("land a waiver on main FIRST", err)
        self.assertIn("class `one-way`", err)



class TestTheBaseIsResolvedByExactNameW307(FloorGuardBase):
    """W3-07 class (Codex review follow-up): resolve_base ran `rev-parse <base>^{commit}` and,
    unnamed, cut origin/HEAD's target to the SHORT name `origin/<x>`. gitrevisions tries
    refs/tags/ and refs/heads/ before refs/remotes/, so a tag or local branch spelled
    `origin/main` stood in for the remote-tracking branch — and the base is where the waivers are
    read. An origin/HEAD pointed at a local branch was used as-is; an absent refs/remotes/… name
    expanded to a local refs/heads/refs/remotes/… branch; a revision suffix read an older base.
    Each plant below carries a waiver for the change's own violation: before, `clean (1 waived)`;
    now the waivers are read at the exact remote-tracking commit, or the base is refused."""

    WAIVER = "floor-waiver:threshold-lowered:CONSTRAINTS.md"

    def setUp(self):
        super().setUp()
        # The coordinator's fetch of the reviewed default branch: no waiver there.
        git(self.repo, "update-ref", "refs/remotes/origin/main", "main")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        # The change lowers a floor.
        write(self.repo, "CONSTRAINTS.md",
              BASE_CONSTRAINTS.replace("| D1 | coverage | 85 |", "| D1 | coverage | 60 |"))
        self.commit("lower the floor")

    def waiver_on(self, ref):
        """A commit off the base carrying a waiver for the change's own violation, at `ref`."""
        git(self.repo, "branch", "planted", "main")
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.WAIVER) + "\n"},
                     branch="planted")
        git(self.repo, "update-ref", ref, "refs/heads/planted")
        git(self.repo, "branch", "-D", "planted")

    def assert_not_waived(self, *args, code=1):
        got, out, err = run_main(self.repo, *args)
        self.assertEqual(got, code, f"{out}{err}")
        self.assertNotIn("waived", out)
        return err

    def test_a_tag_spelled_origin_main_never_stands_in_for_the_remote_branch(self):
        self.waiver_on("refs/tags/origin/main")
        for args in ((), ("--base", "origin/main")):
            with self.subTest(args=args):
                err = self.assert_not_waived(*args)
                self.assertIn("[threshold-lowered]", err)

    def test_a_local_branch_spelled_origin_main_never_stands_in_for_the_remote_branch(self):
        self.waiver_on("refs/heads/origin/main")
        for args in ((), ("--base", "origin/main")):
            with self.subTest(args=args):
                self.assert_not_waived(*args)

    def test_an_origin_head_pointed_at_a_local_branch_is_skipped(self):
        self.waiver_on("refs/heads/evil")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/evil")
        self.assert_not_waived()

    def test_an_absent_remote_ref_is_not_answered_by_a_local_branch_of_its_spelling(self):
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/HEAD")
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/main")
        self.waiver_on("refs/heads/refs/remotes/origin/main")
        err = self.assert_not_waived("--base", "refs/remotes/origin/main", code=2)
        self.assertIn("exactly that name", err)

    def test_a_local_bridge_inside_a_remote_tracking_chain_is_no_base(self):
        # Codex review round 2 (P1): for-each-ref's %(symref) is the chain's END, so origin/HEAD
        # (or a named origin/<x>) -> refs/heads/bridge -> refs/remotes/origin/planted read as
        # remote-tracking all the way, and the planted waiver was honoured.
        self.waiver_on("refs/remotes/origin/planted")
        git(self.repo, "symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/planted")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/bridge")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/b", "refs/heads/bridge")
        git(self.repo, "symbolic-ref", "refs/remotes/origin/a", "refs/remotes/origin/b")
        self.assert_not_waived()  # origin/HEAD skipped: origin/main, which carries no waiver
        for base in ("origin/HEAD", "origin/a", "refs/remotes/origin/a"):
            with self.subTest(base=base):
                err = self.assert_not_waived("--base", base, code=2)
                self.assertIn("refs/heads/bridge", err)

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_base(self):
        # Independent re-attack (A): str.splitlines() broke the listing at U+2028/U+2029/U+0085,
        # so a fetched `x<U+2028>refs/remotes/origin/main` carrying a waiver replaced origin/main
        # (and origin/HEAD's target) and the change's own violation read `clean (1 waived)`.
        self.waiver_on("refs/heads/planted-waiver")
        planted = git(self.repo, "rev-parse", "refs/heads/planted-waiver").stdout.strip()
        for ch in refname_breaks.LINE_BREAKS:
            for args in ((), ("--base", "origin/main")):
                with self.subTest(ch=ch, args=args):
                    unplant = refname_breaks.plant(self.repo, ch, planted)
                    try:
                        self.assert_not_waived(*args)
                    finally:
                        unplant()

    def test_two_non_utf8_branch_names_never_stop_the_guard(self):
        # Re-attack residual: git() decoded with "replace", so fetched branches zz\xff and
        # zz\xfe both read as `zz\ufffd` and the exact-name listing refused itself as naming one
        # ref twice — exit 2 on every lane, which any branch pusher could aim at every PR's CI
        # (guard.yml fetches every branch). The default base must still be the real origin/main.
        honest = git(self.repo, "rev-parse", "refs/remotes/origin/main").stdout.strip()
        for raw in (b"refs/remotes/origin/zz\xff", b"refs/remotes/origin/zz\xfe"):
            subprocess.run([b"git", b"-C", bytes(self.repo), b"update-ref", raw,
                            honest.encode()], check=True, capture_output=True)
        for args in ((), ("--base", "origin/main")):
            with self.subTest(args=args):
                code, out, err = run_main(self.repo, *args)
                self.assertEqual(code, 1, f"{out}{err}")  # the change's own violation, judged
                self.assertIn("[threshold-lowered]", err)
                self.assertNotIn("twice", err)
        base, shown = floor_guard.resolve_base(self.repo, None)
        self.assertEqual((base, shown), (honest, "origin/main"))

    def test_a_revision_suffix_is_no_base(self):
        # The waiver stood at origin/main~1 and was retired by a later `superseded` line.
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.WAIVER) + "\n"})
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.WAIVER) + "\n" + grant_row(
            self.WAIVER, answer="superseded", ts="2026-09-11T00:00:00Z", klass="mechanical",
            source="", why="the floor holds again") + "\n"})
        git(self.repo, "update-ref", "refs/remotes/origin/main", "main")
        self.assert_not_waived("--base", "origin/main")
        for base in ("origin/main~1", "origin/main^", "origin/main@{1}", "main~1"):
            with self.subTest(base=base):
                err = self.assert_not_waived("--base", base, code=2)
                self.assertIn("not a valid ref name", err)

    def test_waivers_and_the_diff_are_read_at_the_resolved_commit(self):
        land_on_base(self.repo, {"docs/DECISIONS.md": grant_row(self.WAIVER) + "\n"})
        git(self.repo, "update-ref", "refs/remotes/origin/main", "main")
        tip = git(self.repo, "rev-parse", "refs/remotes/origin/main").stdout.strip()
        seen = []
        real = floor_guard.git

        def spy(repo, *args, **kwargs):
            seen.append(list(args))
            return real(repo, *args, **kwargs)

        with mock.patch.object(floor_guard, "git", side_effect=spy):
            code, out, err = run_main(self.repo, "--base", "origin/main")
        self.assertEqual(code, 0, err)
        self.assertIn("(1 waived)", out)
        reads = [a for a in seen if a[:1] in (["merge-base"], ["cat-file"])]
        self.assertTrue(reads, seen)
        for argv in reads:
            self.assertFalse(any("origin/main" in tok for tok in argv), argv)
            self.assertTrue(any(tok == tip or tok.startswith(tip + ":") for tok in argv), argv)

    def test_a_local_base_is_named_advisory(self):
        code, _out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 1, err)
        self.assertIn("LOCAL branch", err)

    def test_head_and_an_abbreviated_id_are_advisory_bases_never_ref_names(self):
        # Re-attack C(1): off a sound lane `--base HEAD` was refused and `--base <short sha>` was
        # read as the local BRANCH of that spelling — a planted refs/heads/<short sha> carrying a
        # waiver was honoured. HEAD and an abbreviation are now advisory bases (with the NOTE),
        # the abbreviation read as an object id only; a sound lane refuses both.
        main = git(self.repo, "rev-parse", "refs/heads/main").stdout.strip()
        short = main[:9]
        self.waiver_on(f"refs/heads/{short}")
        clean = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        with mock.patch.dict(os.environ, clean, clear=True):
            code, out, err = run_main(self.repo, "--base", short)
            self.assertEqual(code, 1, f"{out}{err}")  # main's commit: no waiver, the violation
            self.assertNotIn("waived", out)
            self.assertIn("abbreviated commit id", err)
            code, out, err = run_main(self.repo, "--base", "HEAD")
            self.assertEqual(code, 0, f"{out}{err}")  # HEAD..HEAD: nothing changed
            self.assertIn("NOTE", err)
        for base in (short, "HEAD"):
            with self.subTest(base=base), \
                    mock.patch.dict(os.environ, {**clean, "ORCA_PROVENANCE": "ci"}, clear=True):
                code, out, err = run_main(self.repo, "--base", base)
                self.assertEqual(code, 2, f"{out}{err}")
                self.assertIn("claims a sound lane", err)

    def test_a_local_base_is_refused_on_a_lane_claiming_soundness(self):
        # Coordinator decision (the decisions.py / run_report.py precedent): a local branch is the
        # change's to move, so where ORCA_PROVENANCE / OPEN_FLEET_PROVENANCE claims soundness the
        # waivers are never read there — named, or as the no-remote fallback. Off that lane the
        # same base runs with the advisory NOTE.
        self.waiver_on("refs/heads/main")
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/HEAD")
        git(self.repo, "update-ref", "-d", "refs/remotes/origin/main")
        clean = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        for var in ("ORCA_PROVENANCE", "OPEN_FLEET_PROVENANCE"):
            for args in (("--base", "main"), ("--base", "refs/heads/main"), ()):
                with self.subTest(var=var, args=args), \
                        mock.patch.dict(os.environ, {**clean, var: "ci"}, clear=True):
                    code, out, err = run_main(self.repo, *args)
                    self.assertEqual(code, 2, f"{out}{err}")
                    self.assertIn(f"{var}=ci claims a sound lane", err)
                    self.assertNotIn("waived", out)
        with mock.patch.dict(os.environ, clean, clear=True):
            code, out, err = run_main(self.repo, "--base", "main")
        self.assertEqual(code, 0, err)
        self.assertIn("(1 waived)", out)
        self.assertIn("NOTE", err)
        self.assertIn("LOCAL branch", err)


class TestSecurityHardening769(unittest.TestCase):
    """Regression tests for #769 + #772 hardening in floor_guard.py."""

    def test_coveragerc_colon_delimiters_and_section_headers(self):
        for line in ("fail_under: 50", "omit: tests/*", "branch: false",
                     "[report]", "[paths]", "[custom]"):
            with self.subTest(line=line):
                self.assertIsNotNone(floor_guard.guard_surface_hit(".coveragerc", line))
        # Adding or removing a [run] section header in a diff must still flag via scan().
        diff = (
            "diff --git a/.coveragerc b/.coveragerc\n"
            "--- a/.coveragerc\n"
            "+++ b/.coveragerc\n"
            "@@ -1,2 +1,3 @@\n"
            " [report]\n"
            "+[run]\n"
            " fail_under = 80\n"
        )
        added, removed = floor_guard.parse_diff(diff)
        findings = floor_guard.scan(added, removed, "CONSTRAINTS.md", Path("."))
        self.assertTrue(any(f["rule"] == "guard-surface" and f["path"] == ".coveragerc"
                            for f in findings), findings)

    def test_ruff_config_shadowing_and_expanded_keys(self):
        for path in (".ruff.toml", "sub/ruff.toml", "sub/.ruff.toml", "a/b/.ruff.toml"):
            with self.subTest(path=path):
                self.assertIsNotNone(floor_guard.guard_surface_hit(path, 'ignore = ["E501"]'))
        for line in ("[tool.ruff]", "[tool.ruff.lint]", "[tool.coverage.report]",
                     'tool.ruff.ignore = ["F401"]', "tool.coverage.report.fail_under = 50"):
            with self.subTest(pyproject=line):
                self.assertIsNotNone(floor_guard.guard_surface_hit("pyproject.toml", line))
        self.assertIsNone(floor_guard.guard_surface_hit("pyproject.toml", "[project]"))
        for cfg in ("setup.cfg", "tox.ini"):
            for line in ("[tool.ruff]", "[tool.coverage]", "[coverage:report]", "[coverage:run]"):
                with self.subTest(cfg=cfg, line=line):
                    self.assertIsNotNone(floor_guard.guard_surface_hit(cfg, line))
            self.assertIsNone(floor_guard.guard_surface_hit(cfg, "[metadata]"))
        for line in ('include = ["only_one.py"]', 'extend = "other.toml"',
                     'extend-include = ["x.py"]',
                     'per-file-ignores = { "a.py" = ["E501"] }',
                     'extend-per-file-ignores = { "a.py" = ["F401"] }',
                     'lint.select = ["E"]', 'lint.ignore = ["F401"]'):
            with self.subTest(ruff_key=line):
                self.assertIsNotNone(floor_guard.guard_surface_hit("ruff.toml", line))

    def test_human_grant_pubkey_is_guard_surface(self):
        self.assertIn(".orca/human-grant-pubkey", floor_guard.GUARD_SURFACE_FILES)
        self.assertIsNotNone(floor_guard.guard_surface_hit(".orca/human-grant-pubkey", "00" * 32))

    def test_lowering_catches_comparator_flips_removals_and_retained_old_numbers(self):
        cases = (
            ("| cov | >= 80% |", "| cov | <= 80% |"),
            ("| cov | > 5 |", "| cov | < 5 |"),
            ("| cov | ≥ 90% |", "| cov | ≤ 90% |"),
            ("| cov | >= 80% |", "| cov | 80% |"),
            ("| cov | >= 80% |", "| cov | >= 10% (was 80%) |"),
            ("coverage >= 80%", "coverage <= 80%"),
            ("coverage >= 80%", "coverage 80%"),
            ("coverage >= 80%", "coverage >= 10% (was 80%)"),
        )
        for before, after in cases:
            with self.subTest(before=before, after=after):
                self.assertIsNotNone(floor_guard.lowering(before, after))


if __name__ == "__main__":
    unittest.main(verbosity=2)
