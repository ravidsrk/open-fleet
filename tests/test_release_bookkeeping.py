#!/usr/bin/env python3
"""What pull requests stopped writing, and the release cut now writes (CI speed and bookkeeping).

Four files took a line from every PR, so with strict up-to-date branches every merge put every
other open PR into conflict: CHANGELOG.md's [Unreleased], the tests badge's count, the run index
and the shard weights. The changelog and the run index are pinned in tests/test_changelog.py and
tests/test_run_index.py, the shard weights in tests/test_shard_tests.py. This module pins the
badge half and the cut that ties them together:

  - between releases the tests badge is held to its SHAPE (an "N in source" inventory, never a
    pass/fail claim), not to today's count, and the README badge says it is the last release's;
  - `gen-badges.py --release` and `--check --release` are the cut's full write and check;
  - release_check.py's gate0/release-bookkeeping asks for the state docs/releases.json declares;
  - docs/ops.md's prepare and cut blocks, run in a throwaway clone, fold a fragment, take the
    badge to today's count, re-render the run index, and leave the tree clean.

    python3 -m unittest tests.test_release_bookkeeping -v
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TheTestsBadgeBetweenReleases(unittest.TestCase):
    def setUp(self):
        self.gb = load("scripts/gen-badges.py", "_bookkeeping_gen")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        where = Path(self.tmp.name)
        self.badges = where / "badges"
        self.badges.mkdir()
        # Every generated surface points at a copy, never the live tree (2026-10-23 review, P2-24).
        shutil.copytree(ROOT / "docs" / "missions", where / "missions")
        for name in ("ARCHITECTURE.md", "README.md"):
            shutil.copy2(ROOT / name, where / name)
        patch = mock.patch.multiple(self.gb, BADGES_DIR=self.badges, GUIDES_DIR=where / "missions",
                                    ARCH=where / "ARCHITECTURE.md", README=where / "README.md")
        patch.start()
        self.addCleanup(patch.stop)
        self.current = self.gb.compute()
        for name, data in self.current.items():
            (self.badges / name).write_text(json.dumps(data), encoding="utf-8")

    def tests_badge(self, **fields):
        data = {**self.current["tests.json"], **fields}
        (self.badges / "tests.json").write_text(json.dumps(data), encoding="utf-8")

    def test_an_older_count_passes_between_releases_and_fails_at_the_cut(self):
        self.tests_badge(message="12 in source")
        self.assertEqual(self.gb.check(include_test_count=False), [])
        errors = self.gb.check()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("tests.json is stale", errors[0])
        self.assertIn("gen-badges.py --release", errors[0])

    def test_validate_holds_the_badge_to_its_shape_only(self):
        validate = load("scripts/validate.py", "_bookkeeping_validate")
        self.tests_badge(message="12 in source")
        self.assertEqual(validate.check_badge_freshness(self.gb), [])
        self.tests_badge(message="12 passing")
        self.assertTrue(validate.check_badge_freshness(self.gb))

    def test_a_badge_that_reads_as_a_verdict_fails_even_between_releases(self):
        for label, fields, why in (
                ("a pass claim", {"message": "4714 passing"}, "message"),
                ("a green verdict colour", {"color": "2ea043"}, "color"),
                ("another label", {"label": "tests"}, "label"),
                ("an extra field", {"isError": False}, "isError"),
                ("no count", {"message": "many in source"}, "message")):
            with self.subTest(case=label):
                self.tests_badge(**fields)
                errors = self.gb.check(include_test_count=False)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("tests.json is malformed", errors[0])
                self.assertIn(why, errors[0])
        (self.badges / "tests.json").write_text("[]", encoding="utf-8")
        self.assertIn("not a badge object", self.gb.check(include_test_count=False)[0])
        (self.badges / "tests.json").unlink()
        self.assertIn("tests.json missing", self.gb.check(include_test_count=False)[0])

    def test_a_pull_request_write_keeps_the_release_count(self):
        self.tests_badge(message="12 in source")
        (self.badges / "missions.json").write_text("{}", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.gb.write(include_tests=False)
        self.assertIn("kept docs/assets/badges/tests.json", out.getvalue())
        self.assertEqual(json.loads((self.badges / "tests.json").read_text())["message"],
                         "12 in source")
        self.assertEqual(json.loads((self.badges / "missions.json").read_text()),
                         self.current["missions.json"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.gb.write(include_tests=True)
        self.assertEqual(json.loads((self.badges / "tests.json").read_text()),
                         self.current["tests.json"])
        self.assertEqual(self.gb.check(), [])

    def test_the_cli_maps_release_to_the_count(self):
        # Read-only against the live tree: --check is the PR check, --check --release the cut's.
        script = str(ROOT / "scripts" / "gen-badges.py")
        pr = subprocess.run([sys.executable, script, "--check"], capture_output=True, text=True)
        self.assertEqual(pr.returncode, 0, pr.stderr)
        cut = subprocess.run([sys.executable, script, "--check", "--release"],
                             capture_output=True, text=True)
        live = load("scripts/gen-badges.py", "_bookkeeping_gen_live")
        self.assertEqual(cut.returncode, 1 if live.check() else 0, cut.stderr)

    def test_the_readme_badge_says_whose_count_it_is(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        badge = [ln for ln in readme.splitlines() if "docs/assets/badges/tests.json" in ln]
        self.assertEqual(len(badge), 1, badge)
        self.assertIn("label=test%20functions%20at%20last%20release", badge[0])
        self.assertIn('alt="contract test functions at the last release"', badge[0])


class Result:
    def __init__(self, returncode, stdout="", stderr="", missing=False, timeout=False):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
        self.missing, self.timeout = missing, timeout

    @property
    def ok(self):
        return self.returncode == 0


class TheReleaseCheckAsksForTheDeclaredState(unittest.TestCase):
    def setUp(self):
        self.rc = load("scripts/release_check.py", "_bookkeeping_rc")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "docs").mkdir()

    def ctx(self, preparing, results=None):
        (self.root / "docs" / "releases.json").write_text(
            json.dumps({"releases": [], "preparing": preparing}), encoding="utf-8")
        ctx = self.rc.Context(self.root)
        ctx.calls = []

        def py(tool, *args, timeout=None):
            ctx.calls.append((tool, *args))
            return (results or {}).get((tool, *args), Result(0, f"{tool} ok"))
        ctx.py = py
        return ctx

    def test_between_releases_it_asks_for_well_formed_files_only(self):
        ctx = self.ctx(None)
        name, status, detail = self.rc.check_release_bookkeeping(ctx)
        self.assertEqual((name, status), ("gate0/release-bookkeeping", self.rc.PASS))
        self.assertTrue(detail.startswith("between releases: "), detail)
        self.assertEqual(ctx.calls, [("scripts/changelog.py", "check"),
                                     ("scripts/run_index.py", "check")])

    def test_on_a_cut_it_asks_for_everything_folded_and_current(self):
        ctx = self.ctx({"version": "9.9.9", "cut_date": "2026-12-31"})
        name, status, detail = self.rc.check_release_bookkeeping(ctx)
        self.assertEqual(status, self.rc.PASS, detail)
        self.assertTrue(detail.startswith("cut of 9.9.9: "), detail)
        self.assertEqual(ctx.calls, [("scripts/changelog.py", "check", "--released"),
                                     ("scripts/run_index.py", "check", "--current"),
                                     ("scripts/gen-badges.py", "--check", "--release")])

    def test_any_failing_or_missing_tool_fails_the_check(self):
        cut = {"version": "9.9.9", "cut_date": "2026-12-31"}
        for key, result, why in (
                (("scripts/gen-badges.py", "--check", "--release"),
                 Result(1, "", "tests.json is stale"), "tests.json is stale"),
                (("scripts/changelog.py", "check", "--released"),
                 Result(None, "", "scripts/changelog.py: not in this checkout", missing=True),
                 "not in this checkout"),
                (("scripts/run_index.py", "check", "--current"),
                 Result(None, "", "timed out after 600s", timeout=True), "timed out")):
            with self.subTest(tool=key[0]):
                _, status, detail = self.rc.check_release_bookkeeping(self.ctx(cut, {key: result}))
                self.assertEqual(status, self.rc.FAIL, detail)
                self.assertIn(why, detail)

    def test_an_unreadable_release_inventory_fails(self):
        ctx = self.ctx(None)
        (self.root / "docs" / "releases.json").write_text("[1]", encoding="utf-8")
        self.assertEqual(self.rc.check_release_bookkeeping(ctx)[1], self.rc.FAIL)
        (self.root / "docs" / "releases.json").unlink()
        self.assertEqual(self.rc.check_release_bookkeeping(ctx)[1], self.rc.FAIL)

    def test_gate_0_runs_it_and_the_checklist_shows_its_commands(self):
        self.assertIn("check_release_bookkeeping(ctx)", Path(self.rc.__file__).read_text())
        checklist = (ROOT / "docs" / "release-1.0-checklist.md").read_text(encoding="utf-8")
        gate0 = checklist.split("## Gate 0", 1)[1].split("## Gate 1", 1)[0]
        for tool, *args in self.rc.BOOKKEEPING_BETWEEN + self.rc.BOOKKEEPING_AT_CUT:
            with self.subTest(command=(tool, *args)):
                self.assertIn(" ".join(["python3", tool, *args]), gate0)


def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_COUNT": "4",
                "GIT_CONFIG_KEY_0": "user.name", "GIT_CONFIG_VALUE_0": "Release Fixture",
                "GIT_CONFIG_KEY_1": "user.email", "GIT_CONFIG_VALUE_1": "fixture@example.invalid",
                "GIT_CONFIG_KEY_2": "commit.gpgsign", "GIT_CONFIG_VALUE_2": "false",
                "GIT_CONFIG_KEY_3": "core.hooksPath", "GIT_CONFIG_VALUE_3": "/dev/null"})
    return env


class TheCutFoldsTheBookkeeping(unittest.TestCase):
    """docs/ops.md's prepare and cut blocks, run as written in a throwaway clone of this commit.

    tests/test_docs_navigation.py's walkthrough proves the blocks cut, tag and record; this
    proves what they now fold. A fragment is planted first, so the fold is never vacuous.
    """

    def test_prepare_and_cut_fold_every_fragment_and_leave_a_clean_tree(self):
        with tempfile.TemporaryDirectory(prefix="fleet-bookkeeping-") as tmp:
            repo = Path(tmp) / "repo"
            env = git_env()

            def run(*argv, ok=True):
                p = subprocess.run(argv, cwd=repo, env=env, capture_output=True, text=True,
                                   timeout=600)
                if ok:
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                return p

            subprocess.run(["git", "clone", "--quiet", "--shared", str(ROOT), str(repo)],
                           env=env, check=True, capture_output=True)
            run("git", "remote", "remove", "origin")
            run("git", "checkout", "-B", "bookkeeping-rehearsal")
            for rel in ("docs/ops.md", "docs/releases.json", "tests/test_docs_navigation.py"):
                shutil.copyfile(ROOT / rel, repo / rel)
            inventory = json.loads((repo / "docs/releases.json").read_text())
            historical = inventory["releases"]
            if inventory.get("preparing") is not None:  # the suite running on a cut itself
                prep_ver = inventory["preparing"]["version"]
                prev_ver = historical[-1]["version"]
                cl_path = repo / "CHANGELOG.md"
                cl_text, stripped = re.subn(
                    rf"(?ms)^## \[{re.escape(prep_ver)}\] - [^\n]+\n.*?(?=^## \[{re.escape(prev_ver)}\])",
                    "",
                    cl_path.read_text(encoding="utf-8"),
                    count=1,
                )
                self.assertEqual(stripped, 1, "preparing section missing from CHANGELOG.md")
                cl_path.write_text(cl_text, encoding="utf-8")
                for name in ("plugin", "marketplace"):
                    manifest = repo / f".claude-plugin/{name}.json"
                    value = json.loads(manifest.read_text(encoding="utf-8"))
                    if name == "plugin":
                        value["version"] = prev_ver
                    else:
                        value["metadata"]["version"] = prev_ver
                        value["plugins"][0]["version"] = prev_ver
                    manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
                inventory["preparing"] = None
                (repo / "docs/releases.json").write_text(json.dumps(inventory, indent=2) + "\n")
            planted = "- **A rehearsal entry** that links [ops](../docs/ops.md).\n"
            (repo / "changelog.d" / "zz-rehearsal.md").write_text(planted, encoding="utf-8")
            pending = {p.name: p.read_text(encoding="utf-8")
                       for p in sorted((repo / "changelog.d").iterdir()) if p.name != "README.md"}
            run("git", "add", "-A")
            run("git", "commit", "-qm", "Fixture release tooling")
            latest = max(tuple(map(int, r["version"].split("."))) for r in historical)
            tags = run("git", "tag", "--list").stdout.split()
            patch = latest[2] + 1
            while f"v{latest[0]}.{latest[1]}.{patch}" in tags:
                patch += 1
            version = f"{latest[0]}.{latest[1]}.{patch}"
            env.update(RELEASE_VERSION=version, RELEASE_DATE="2026-12-31")
            doc = (repo / "docs/ops.md").read_text()

            def step(name):
                match = re.search(rf"<!-- release:{name} -->\s*```bash\n(.*?)```", doc, re.S)
                self.assertIsNotNone(match, f"release {name} has no executable block")
                return run("sh", "-c", match.group(1))

            step("prepare")
            self.assertEqual(sorted(p.name for p in (repo / "changelog.d").iterdir()),
                             ["README.md"], "the cut left fragments unfolded")
            changelog = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
            section = changelog.split(f"## [{version}] - 2026-12-31\n\n", 1)
            self.assertEqual(len(section), 2, "no dated section was cut")
            released = section[1].split("\n## [", 1)[0]
            self.assertIn("- **A rehearsal entry** that links [ops](docs/ops.md).\n", released)
            for name, text in pending.items():
                with self.subTest(folded=name):
                    self.assertIn(text.replace("](../", "]("), released)
            self.assertIn("## [Unreleased]\n\n## [", changelog)
            for tool in (["scripts/changelog.py", "check", "--released"],
                         ["scripts/run_index.py", "check", "--current"],
                         ["scripts/gen-badges.py", "--check", "--release"]):
                with self.subTest(check=tool):
                    run(sys.executable, *tool)
            self.assertIn("as of 2026-12-31", (repo / "docs/runs/README.md").read_text())
            step("cut")
            self.assertEqual(run("git", "status", "--porcelain").stdout, "",
                             "the cut left changes unstaged")
            gone = run("git", "show", "--name-status", "--format=", "HEAD").stdout
            for name in pending:
                with self.subTest(fragment=name):
                    self.assertIn(f"D\tchangelog.d/{name}", gone)
            # Exercise the preparing != None branch of ReleaseCutWalkthrough on the cut itself.
            run(sys.executable, "-m", "unittest", "tests.test_docs_navigation.ReleaseCutWalkthrough")




class TheBadgeIsTheLastReleasesOwn(unittest.TestCase):
    """PR #670 review (P2): the README labels the tests badge "at last release", but main kept
    4714, while v0.8.0 (065824b091) had 3270. Between releases the committed badge must be,
    byte for byte, the badge at the last release's cut commit; a cut in progress writes its own."""

    def setUp(self):
        self.gb = load("scripts/gen-badges.py", "_bookkeeping_last_release")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git = lambda *a: subprocess.run(["git", "-C", str(self.root), *a], env=env,
                                             check=True, capture_output=True, text=True).stdout
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        (self.root / "docs" / "assets" / "badges").mkdir(parents=True)
        self.badge(3270)
        self.git("add", "-A")
        self.git("commit", "-qm", "the cut")
        self.cut = self.git("rev-parse", "HEAD").strip()
        self.releases(preparing=None)

    def badge(self, count):
        data = {"schemaVersion": 1, "label": "test functions", "message": f"{count} in source",
                "color": "6e7781"}
        (self.root / "docs" / "assets" / "badges" / "tests.json").write_text(
            json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def fixture_tests(self, count):
        """A fixture tests/ holding `count` test functions, as the release cut counts them."""
        (self.root / "tests").mkdir(exist_ok=True)
        (self.root / "tests" / "test_fixture.py").write_text(
            "".join(f"def test_{n}():\n    pass\n\n\n" for n in range(count)), encoding="utf-8")

    def releases(self, preparing, commit=None):
        data = {"preparing": preparing, "releases": [
            {"version": "0.8.0", "tag": "v0.8.0", "commit": commit or self.cut}]}
        (self.root / "docs" / "releases.json").write_text(json.dumps(data), encoding="utf-8")

    def test_the_last_releases_badge_passes(self):
        self.assertEqual(self.gb.last_release_badge_errors(self.root), [])

    def test_a_count_the_release_never_had_is_refused(self):
        self.badge(4714)
        errors = self.gb.last_release_badge_errors(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("'4714 in source'", errors[0])
        self.assertIn("'3270 in source'", errors[0])

    def test_a_cut_in_progress_writes_its_own(self):
        # The cut's own badge is what `gen-badges.py --release` writes: its tests/ count.
        self.fixture_tests(2)
        self.badge(2)
        self.releases(preparing={"version": "0.9.0"})
        self.assertEqual(self.gb.last_release_badge_errors(self.root), [])

    def test_a_claimed_cut_cannot_carry_any_number(self):
        # 2026-10-27 security audit, W6-08: `preparing` returned [] before reading anything, so a
        # PR that claimed a cut could commit a badge saying any number. A cut's badge is its own
        # count; a claim of one now costs exactly that.
        self.fixture_tests(2)
        self.badge(4714)
        self.releases(preparing={"version": "9.9.9", "cut_date": "2026-12-31"})
        errors = self.gb.last_release_badge_errors(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("'4714 in source'", errors[0])
        self.assertIn("'2 in source'", errors[0])
        self.badge(3270)  # the last release's own bytes are not the cut's count either
        self.assertTrue(self.gb.last_release_badge_errors(self.root))

    def test_a_claimed_cut_with_nothing_to_count_is_an_error(self):
        self.badge(0)
        self.releases(preparing={"version": "9.9.9"})
        errors = self.gb.last_release_badge_errors(self.root)
        self.assertTrue(errors and "tests/" in errors[0], errors)

    def test_a_release_commit_that_is_not_a_full_sha_never_reaches_git(self):
        # W6-09: the commit became part of `git show`'s argv, so `--output=<path>` was read as
        # an option and wrote a file. Only a full 40-hex commit name is passed on.
        stray = self.root / "stray"
        for commit in (f"--output={stray}", "HEAD", self.cut[:12], self.cut.upper(),
                       self.cut + "\n", "-p"):
            with self.subTest(commit=commit):
                self.releases(preparing=None, commit=commit)
                errors = self.gb.last_release_badge_errors(self.root)
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("not a full 40-hex commit", errors[0])
                self.assertEqual(list(self.root.glob("stray*")), [])

    def test_an_unreadable_release_commit_is_an_error_not_a_pass(self):
        self.releases(preparing=None, commit="0" * 40)
        errors = self.gb.last_release_badge_errors(self.root)
        self.assertTrue(errors and "cannot read" in errors[0], errors)

    def test_a_release_cut_before_the_move_is_read_at_the_old_path(self):
        # The root clean-up moved assets/ to docs/assets/; v1.0.0 and earlier hold the badge at
        # assets/badges/. The check must read the cut's own bytes there, and still refuse a change.
        new = self.root / "docs" / "assets" / "badges" / "tests.json"
        (self.root / "assets" / "badges").mkdir(parents=True)
        self.git("mv", str(new), str(self.root / "assets" / "badges" / "tests.json"))
        self.git("commit", "-qm", "a cut from before the move")
        old_cut = self.git("rev-parse", "HEAD").strip()
        self.git("mv", str(self.root / "assets" / "badges" / "tests.json"), str(new))
        self.git("commit", "-qm", "the move")
        self.releases(preparing=None, commit=old_cut)
        self.assertEqual(self.gb.last_release_badge_errors(self.root), [])
        self.badge(4714)
        errors = self.gb.last_release_badge_errors(self.root)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn(f"git show {old_cut}:assets/badges/tests.json > docs/assets/badges/tests.json", errors[0])

    def test_the_committed_badge_is_the_last_releases(self):
        self.assertEqual(self.gb.last_release_badge_errors(ROOT), [])

    def test_only_the_releases_own_bytes_pass(self):
        # Greptile (PR #671): a reformatted or reordered badge parsed equal and passed.
        path = self.root / "docs" / "assets" / "badges" / "tests.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        for label, text in {"reformatted": json.dumps(data) + "\n",
                            "reordered": json.dumps(dict(reversed(list(data.items()))), indent=2) + "\n",
                            "no final newline": path.read_text(encoding="utf-8").rstrip("\n")}.items():
            with self.subTest(change=label):
                original = path.read_bytes()
                try:
                    path.write_text(text, encoding="utf-8")
                    self.assertTrue(self.gb.last_release_badge_errors(self.root), label)
                finally:
                    path.write_bytes(original)

    def test_ci_runs_it_in_the_checks_job(self):
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        checks = workflow.split("\n  checks:\n", 1)[1].split("\n  gates:\n", 1)[0]
        self.assertIn("python3 scripts/gen-badges.py --check-last-release", checks)


if __name__ == "__main__":
    unittest.main()
