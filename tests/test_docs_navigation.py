#!/usr/bin/env python3
"""
Contract tests for the human documentation surface.

A doc surface that presents itself as complete must be machine-checked against
repo state, or it silently rots: ARCHITECTURE.md's runtime-policy list reads as
the whole runtime surface, docs/runs/README.md is the proof-honesty index the
mission frontmatter leans on, and docs/research/ only exists for readers who
can reach it. Each invariant here failed once (issue number on the test).

    python3 -m unittest discover -s tests -v
"""
import importlib.util
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("validate", ROOT / "scripts" / "validate.py")
validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate)
DOCS = ROOT / "docs"
RUNTIME = ROOT / "runtime"

# An index's inline links with optional <>, #fragment, and "title" — captures the .md path only.
INDEX_LINK = re.compile(r"\[[^\]]+\]\(\s*<?([^)>#\s]+\.md)(?:#[^)>\s]*)?>?(?:\s+\"[^\"]*\")?\s*\)")


def run_archive_index():
    """docs/runs/README.md plus the live rendering of the run-index row files.

    The README's table is a snapshot the release cut renders from docs/runs/index/<run>.json, one
    row file per run, so PRs filing runs never edit one shared line (CI speed and bookkeeping
    change). Between cuts a run filed since is indexed by its row file alone; this is the index a
    reader can render at any commit (`python3 scripts/run_index.py print`). A row file that does
    not load renders no row, so its report reads as unlinked.
    """
    spec = importlib.util.spec_from_file_location("_run_index_nav", ROOT / "scripts" / "run_index.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rows, _ = mod.load_rows(ROOT)
    return (DOCS / "runs" / "README.md").read_text(encoding="utf-8") + "\n" + mod.render(rows, "live")


def index_targets(index_path):
    """Real files an index links to, each resolved against the index's own directory."""
    links = INDEX_LINK.findall(index_path.read_text(encoding="utf-8"))
    return {p for p in ((index_path.parent / t).resolve() for t in links) if p.is_file()}


class FreshHomeInstallation(unittest.TestCase):
    def test_documented_symlinks_resolve_in_fresh_and_existing_homes(self):
        for doc in (ROOT / "README.md", DOCS / "getting-started.md"):
            blocks = [b for b in re.findall(r"```bash\n(.*?)```", doc.read_text(), re.S)
                      if "ln -s " in b]
            self.assertTrue(blocks, f"{doc.name} has no symlink install snippet")
            for index, block in enumerate(blocks):
                commands = [line for line in block.splitlines()
                            if line.startswith(("mkdir ", "ln -s "))]
                for existing in (False, True):
                    with self.subTest(doc=doc.name, snippet=index, existing=existing):
                        with tempfile.TemporaryDirectory(prefix="fleet fresh home ") as tmp:
                            home = Path(tmp)
                            (home / "open-fleet").symlink_to(ROOT, target_is_directory=True)
                            if existing:
                                (home / ".claude/skills").mkdir(parents=True)
                            cwd = ROOT if "cd open-fleet" in block else home
                            run = subprocess.run(
                                ["sh", "-c", "\n".join(commands)], cwd=cwd,
                                env={**os.environ, "HOME": tmp}, capture_output=True, text=True,
                            )
                            self.assertEqual(run.returncode, 0, run.stderr)
                            for line in commands:
                                if not line.startswith("ln -s "):
                                    continue
                                mission = line.rsplit("/", 1)[-1]
                                link = home / ".claude/skills" / mission
                                self.assertTrue(link.is_symlink(), str(link))
                                self.assertEqual(link.resolve(), ROOT / "skills" / mission)
                                self.assertTrue((link / "SKILL.md").read_text())


def git_target(cwd, env):
    """Where Git really acts from cwd: [worktree, git dir, common dir]. A path is not proof."""
    out = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--show-toplevel",
                          "--absolute-git-dir", "--git-common-dir"], cwd=cwd, env=env,
                         capture_output=True, text=True, check=True).stdout
    return [Path(line).resolve() for line in out.splitlines()]


def rehearsal_version(historical, refs):
    """First untagged patch after the latest published version.

    A real tag can exist before its provenance row lands (the tag push precedes
    the record commit), and the rehearsal clone inherits that tag, so deriving
    the version from the inventory alone collides inside that window (#555).
    """
    latest = max(tuple(map(int, r["version"].split("."))) for r in historical)
    tagged = {line.split(" refs/tags/")[-1].removesuffix("^{}")
              for line in refs.splitlines()}
    patch = latest[2] + 1
    while f"v{latest[0]}.{latest[1]}.{patch}" in tagged:
        patch += 1
    return f"{latest[0]}.{latest[1]}.{patch}"


class RehearsalVersionDerivation(unittest.TestCase):
    HISTORICAL = [{"version": "0.7.0"}, {"version": "0.7.1"}]

    @staticmethod
    def refs(*names):
        return "\n".join(f"{'0' * 40} refs/tags/{name}" for name in names)

    def test_next_patch_when_free(self):
        self.assertEqual(rehearsal_version(self.HISTORICAL, self.refs("v0.7.1")), "0.7.2")

    def test_skips_one_occupied_version(self):
        self.assertEqual(
            rehearsal_version(self.HISTORICAL, self.refs("v0.7.1", "v0.7.2")), "0.7.3")

    def test_skips_two_consecutive_occupied_versions(self):
        self.assertEqual(
            rehearsal_version(self.HISTORICAL, self.refs("v0.7.1", "v0.7.2", "v0.7.3")),
            "0.7.4")

    def test_first_free_patch_not_above_the_highest_tag(self):
        self.assertEqual(
            rehearsal_version(self.HISTORICAL, self.refs("v0.7.1", "v0.7.3")), "0.7.2")

    def test_peeled_annotated_tag_lines_count_as_the_tag(self):
        self.assertEqual(
            rehearsal_version(self.HISTORICAL, self.refs("v0.7.2", "v0.7.2^{}")), "0.7.3")


class ReleaseRehearsalIsolation(unittest.TestCase):
    def test_inherited_git_selection_cannot_mutate_another_repository(self):
        # A hook or wrapper can export Git's repository selection; cwd does not override it.
        with tempfile.TemporaryDirectory(prefix="fleet-release-decoy-") as tmp:
            decoy = Path(tmp).resolve() / "decoy"
            decoy.mkdir()
            clean = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            clean.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=decoy, env=clean,
                                               text=True, stderr=subprocess.PIPE).strip()

            git("init", "--quiet")
            self.assertEqual(git_target(decoy, clean), [decoy, decoy / ".git", decoy / ".git"])
            git("remote", "add", "origin", str(Path(tmp) / "unused-owned-origin"))
            git("-c", "user.name=Release Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                "commit", "--allow-empty", "-m", "Owned decoy")

            def snapshot():
                return {str(p.relative_to(decoy)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in decoy.rglob("*") if p.is_file()}

            before = snapshot()
            # Each of these made the unscrubbed rehearsal write into an owned decoy.
            contaminated = {**clean, "GIT_DIR": str(decoy / ".git"),
                            "GIT_COMMON_DIR": str(decoy / ".git"),
                            "GIT_INDEX_FILE": str(decoy / ".git" / "index"),
                            "GIT_OBJECT_DIRECTORY": str(decoy / ".git" / "objects")}
            result = subprocess.run(
                [sys.executable, "-m", "unittest", "tests.test_docs_navigation.ReleaseCutWalkthrough"],
                cwd=ROOT, env=contaminated, capture_output=True, text=True)
            self.assertEqual(snapshot(), before, "rehearsal modified the owned decoy repository")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class NavigableDocsHaveNoDeadLinks(unittest.TestCase):
    """The repo checked links in what it SHIPS (scripts/bundle.py, dist/) and never in what it IS.

    Both link forms the repository actually writes are checked. README.md's navigation is raw HTML
    -- `<a href="docs/getting-started.md">` -- so a markdown-only matcher would have watched the
    form these docs mostly do not use and missed the one they do (PR #342 review).

    Two exclusions, both principled rather than convenient, because a guard whose exclusions are
    unexplained is a guard nobody can trust:

    `docs/reports/**` and `docs/completion/evidence/**` are evidence records. They quote other
    files verbatim -- `docs/completion/evidence/CF-05-r3-axis-spec.md` reproduces a line of
    `docs/ops.md` including its link, which is correct relative to ops.md and dead relative to the
    quoting file. Resolving a quoted link against the quoter is a category error, and rewriting it
    would falsify the quote. Frozen report snapshots under `pin/history/` are the same shape one
    level up: their relative links resolve against the live directory they were copied from, which
    is what makes them faithful copies (see that directory's README).

    A run's artifact subtrees under `docs/runs/` are the same shape again: retained worker
    artifacts (reviews, receipts) quote probe inputs verbatim -- a slug review's `[a](u)` is the
    input under test, not a link a reader follows -- and the files are sha256-pinned evidence, so
    editing them to appease a link checker would break provenance. The run REPORTS themselves
    stay navigable and checked: top-level `docs/runs/*.md` and a directory report's own files
    (`docs/runs/<run>/*.md`, e.g. its README) are what readers follow; only second-level
    artifact subtrees (`docs/runs/<run>/<subdir>/...`) are excluded.

    Everything a reader actually navigates is checked.
    """

    EVIDENCE_TREES = ("docs/reports/", "docs/completion/evidence/")
    # `](target)` and `href="target"` / `href='target'`, skipping absolute URLs and pure anchors.
    LINK = re.compile(
        r"""\]\((?!https?:|mailto:|\#)([^)\s]+?)(?:\#[^)]*)?\)"""
        r"""|href=["'](?!https?:|mailto:|\#)([^"'\s]+?)(?:\#[^"']*)?["']""")

    @classmethod
    def _dead(cls, root, files):
        """[`file -> target`] for every link in `files` that resolves to nothing under `root`.

        The one detector. The control below plants a file and calls THIS, rather than repeating the
        matching inline: a control that re-implements the mechanism cannot notice the mechanism
        breaking, which is what the first cut of this test did -- gutting `_dead` left it green
        (PR #342 review).
        """
        dead = []
        for rel in files:
            path = Path(root) / rel
            for m in cls.LINK.finditer(path.read_text(encoding="utf-8")):
                target = m.group(1) or m.group(2)
                if target.startswith("/") or not (path.parent / target).exists():
                    dead.append(f"{rel} -> {target}")
        return dead

    def _navigable(self):
        out = subprocess.run(["git", "ls-files", "*.md"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.split()
        return [f for f in out if not f.startswith(self.EVIDENCE_TREES)
                and not (f.startswith("docs/runs/") and f.count("/") > 3)]

    def test_no_navigable_doc_links_to_something_that_is_not_there(self):
        files = self._navigable()
        self.assertGreater(len(files), 50, "the file set collapsed; the guard would pass vacuously")
        self.assertEqual(self._dead(ROOT, files), [])

    def test_the_detector_catches_each_form_the_repo_writes(self):
        # A guard over a tree that happens to be clean proves nothing about the guard. Plant one of
        # every shape, through the real detector.
        planted = {
            "md.md": "see [the thing](./no-such-file.md)\n",
            "html.md": '<a href="no-such-file.md">nav</a>\n',
            "html_single.md": "<a href='no-such-file.md'>nav</a>\n",
            "absolute.md": "see [root-relative](/etc/passwd)\n",
            "anchored.md": "see [the thing](./no-such-file.md#section)\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in planted.items():
                (Path(tmp) / name).write_text(text, encoding="utf-8")
            dead = self._dead(tmp, sorted(planted))
        self.assertEqual(len(dead), len(planted),
                         f"the detector missed a link form it must catch: {dead}")

    def test_the_detector_does_not_cry_wolf(self):
        # The other half: a link that resolves, in each form, must NOT be reported.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "target.md").write_text("#\n", encoding="utf-8")
            (Path(tmp) / "ok.md").write_text(
                'see [x](target.md) and <a href="target.md">y</a> and [z](https://example.invalid)\n'
                "and [anchor-only](#section)\n", encoding="utf-8")
            self.assertEqual(self._dead(tmp, ["ok.md", "target.md"]), [])


class ReleaseCutWalkthrough(unittest.TestCase):
    def test_next_release_preparation_cut_tag_and_provenance(self):
        # Run the documented commands in an independent ref namespace. No network,
        # real tag mutation, or shell-command mocks; the historical refs are controls.
        with tempfile.TemporaryDirectory(prefix="fleet-release-") as tmp:
            owned = Path(tmp).resolve()
            repo = owned / "repo"
            # Git's explicit repository/index/object selection overrides cwd.
            # Scrub it before cloning AND for every descendant, including shell steps.
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            env.update({"PATH": str(Path(sys.executable).parent) + os.pathsep
                   + os.environ["PATH"], "GIT_CONFIG_COUNT": "5",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_CONFIG_KEY_0": "user.name", "GIT_CONFIG_VALUE_0": "Release Fixture",
                   "GIT_CONFIG_KEY_1": "user.email",
                   "GIT_CONFIG_VALUE_1": "fixture@example.invalid",
                   "GIT_CONFIG_KEY_2": "commit.gpgsign", "GIT_CONFIG_VALUE_2": "false",
                   "GIT_CONFIG_KEY_3": "core.hooksPath", "GIT_CONFIG_VALUE_3": "/dev/null",
                   "GIT_CONFIG_KEY_4": "tag.gpgsign", "GIT_CONFIG_VALUE_4": "false"})

            def run(*argv, ok=True):
                # A directory name alone cannot prove where Git will write.
                self.assertEqual(repo.resolve().parent, owned)
                self.assertEqual(git_target(repo, env), [repo, repo / ".git", repo / ".git"],
                                 "Git escaped the owned rehearsal repository")
                p = subprocess.run(argv, cwd=repo, env=env, capture_output=True, text=True)
                if ok:
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                return p

            self.assertFalse(repo.exists())
            subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(repo)],
                           cwd=owned, env=env, check=True, capture_output=True)
            run("git", "remote", "remove", "origin")
            # Own the fixture's HEAD. CI checks the PR merge ref out DETACHED with no local
            # branch at it, and a clone of that source is detached too — so `symbolic-ref HEAD`
            # below died with "ref HEAD is not a symbolic ref" in CI while passing locally,
            # where a branch happens to point at HEAD. A rehearsal must not inherit the host's
            # HEAD state any more than it inherits its GIT_* variables.
            run("git", "checkout", "-B", "release-rehearsal")
            for path in ("docs/ops.md", "docs/releases.json", "tests/test_docs_navigation.py"):
                shutil.copyfile(ROOT / path, repo / path)
            inventory = json.loads((repo / "docs/releases.json").read_text())
            historical = inventory["releases"]
            # The full suite also runs on the preparing cut itself. Start this
            # independent rehearsal from its last published version in that case.
            if inventory.get("preparing") is not None:
                run("git", "restore", "--source", historical[-1]["commit"], "--",
                    "CHANGELOG.md", ".claude-plugin/plugin.json", ".claude-plugin/marketplace.json")
                inventory["preparing"] = None
                (repo / "docs/releases.json").write_text(json.dumps(inventory, indent=2) + "\n")
            run("git", "add", "docs/ops.md", "docs/releases.json", "tests/test_docs_navigation.py")
            run("git", "add", "CHANGELOG.md", ".claude-plugin/plugin.json",
                ".claude-plugin/marketplace.json")
            run("git", "commit", "--allow-empty", "-m", "Fixture release tooling")
            refs = run("git", "show-ref", "--tags").stdout
            # Skip versions a real tag already owns (#555): the rehearsal proves
            # the blocks work, not that the next number is free.
            version = rehearsal_version(historical, refs)
            env.update(RELEASE_VERSION=version, RELEASE_DATE="2026-09-12")
            doc = (repo / "docs/ops.md").read_text()

            def step(name, ok=True):
                match = re.search(rf"<!-- release:{name} -->\s*```bash\n(.*?)```", doc, re.S)
                self.assertIsNotNone(match, f"Release {name} has no executable walkthrough")
                # The ordinary invocation: no error-handling options beyond the block's own.
                return run("sh", "-c", match.group(1), ok=ok)

            def stopped(name, why):
                head = run("git", "rev-parse", "HEAD").stdout
                self.assertNotEqual(step(name, ok=False).returncode, 0, why)
                self.assertEqual(run("git", "rev-parse", "HEAD").stdout, head, why)
                self.assertEqual(run("git", "show-ref", "--tags").stdout, refs, why)

            dirty = repo / "dirty-fixture.txt"
            dirty.write_text("owned invalid state\n")
            stopped("prepare", "a dirty tree must stop preparation")
            self.assertEqual(run("git", "status", "--porcelain").stdout, "?? dirty-fixture.txt\n")
            dirty.unlink()
            step("prepare")
            env["RELEASE_VERSION"] = version + "9"
            stopped("cut", "a mismatched version must stop the cut")
            env["RELEASE_VERSION"] = version
            step("cut")
            cut = run("git", "rev-parse", "HEAD").stdout.strip()
            prepared = json.loads((repo / "docs/releases.json").read_text())
            self.assertEqual(prepared["releases"], historical)
            self.assertEqual(prepared["preparing"], {"version": version, "cut_date": "2026-09-12"})
            self.assertEqual(run("git", "show-ref", "--tags").stdout, refs)
            env["RELEASE_VERSION"] = version + "9"
            stopped("tag", "a mismatched version must stop tagging")
            env["RELEASE_VERSION"] = version
            dirty.write_text("owned invalid state\n")
            stopped("tag", "a dirty tree must stop tagging")
            dirty.unlink()

            def rejected_state():
                result = run(sys.executable, "-m", "unittest",
                             "tests.test_docs_navigation.TestDocsNavigation."
                             "test_every_changelog_release_has_a_cut_commit",
                             "tests.test_docs_navigation.EveryReleaseHasTheTagItDescribes",
                             ok=False)
                self.assertNotEqual(result.returncode, 0, "invalid release state passed")
                self.assertIn("FAIL:", result.stderr, result.stdout + result.stderr)
                self.assertNotIn("ERROR:", result.stderr)

            inventory_path = repo / "docs/releases.json"
            for invalid in (None, {**prepared["preparing"], "commit": cut},
                            {"version": historical[-1]["version"], "cut_date": "2026-09-12"}):
                with self.subTest(invalid_preparation=invalid):
                    inventory_path.write_text(json.dumps({**prepared, "preparing": invalid}))
                    rejected_state()
            inventory_path.write_text(json.dumps({**prepared, "releases": historical[:-1]}))
            rejected_state()  # Preparing must never exempt a published heading.
            run("git", "restore", "docs/releases.json")
            historical_tag = historical[0]["tag"]
            historical_ref = "refs/tags/" + historical_tag
            historical_object = run("git", "rev-parse", historical_ref).stdout.strip()
            run("git", "tag", "-d", historical_tag)
            rejected_state()  # Missing historical tags still fail during preparation.
            run("git", "tag", "-a", historical_tag, "HEAD", "-m", "Wrong fixture target")
            rejected_state()  # So do annotated tags at the wrong commit.
            run("git", "update-ref", historical_ref, historical_object)
            self.assertNotEqual(step("record", ok=False).returncode, 0,
                                "provenance must fail before its tag exists")
            run("git", "tag", f"v{version}", "HEAD")
            self.assertNotEqual(step("record", ok=False).returncode, 0,
                                "a lightweight tag cannot establish provenance")
            run("git", "tag", "-d", f"v{version}")
            run("git", "tag", "-a", f"v{version}", "HEAD^", "-m", "Wrong fixture cut")
            self.assertNotEqual(step("record", ok=False).returncode, 0,
                                "a tag at another cut cannot establish provenance")
            run("git", "tag", "-d", f"v{version}")
            step("tag")
            tag = f"v{version}"
            self.assertEqual(run("git", "cat-file", "-t", tag).stdout.strip(), "tag")
            self.assertEqual(run("git", "rev-parse", f"{tag}^{{commit}}").stdout.strip(), cut)
            self.assertNotEqual(step("tag", ok=False).returncode, 0, "an existing tag is immutable")

            # PR #328 review, P1: the validation and the commit inside the record step both run
            # AFTER it rewrites docs/releases.json, so a failure there leaves the release already
            # appended and preparing cleared. Rerunning it must finish the release, not stop at
            # "no release is preparing" -- the documented recovery says to rerun it.
            row = {"version": version, "tag": tag, "commit": cut, "cut_date": "2026-09-12"}
            interrupted = {**prepared, "releases": [*historical, row], "preparing": None}
            inventory_path.write_text(json.dumps(interrupted, indent=2) + "\n")
            step("record")
            resumed = json.loads(inventory_path.read_text())
            self.assertEqual(resumed["releases"], interrupted["releases"],
                             "a resumed record appended a second row")
            self.assertIsNone(resumed["preparing"])
            self.assertNotEqual(run("git", "rev-parse", "HEAD").stdout.strip(), cut,
                                "a resumed record must still commit the provenance")
            # A rerun of a COMPLETED record is a no-op, not a failure: nothing is left staged.
            step("record")
            self.assertEqual(json.loads(inventory_path.read_text()), resumed)
            # Only the row the cut actually prepares resumes. A rewritten one is not this release.
            for tampered in ({**row, "commit": run("git", "rev-parse", "HEAD").stdout.strip()},
                             {**row, "cut_date": "2020-01-01"},
                             {**row, "tag": "v0.0.0"}):
                with self.subTest(tampered=tampered):
                    inventory_path.write_text(json.dumps(
                        {**prepared, "releases": [*historical, tampered], "preparing": None}))
                    self.assertNotEqual(step("record", ok=False).returncode, 0,
                                        "a rewritten row must not pass as an interrupted record")
            run("git", "reset", "--hard", cut)

            # Interrupt recording after its inventory write: a failed in-block validation,
            # then Git locks before staging and during commit. Each retry is the same block.
            branch = run("git", "symbolic-ref", "HEAD").stdout.strip()

            def history_missing():
                run("git", "update-ref", "-d", historical_ref)
                return lambda: run("git", "update-ref", historical_ref, historical_object)

            def locked(name):
                lock = repo / ".git" / name  # created only inside this owned clone
                self.assertTrue(lock.resolve().is_relative_to(repo / ".git"))
                lock.parent.mkdir(parents=True, exist_ok=True)
                with lock.open("x") as handle:
                    handle.write("owned interruption control\n")
                return lock.unlink

            for interrupt, reason in ((history_missing, "FAIL:"),
                                      (lambda: locked("index.lock"), ".lock"),
                                      (lambda: locked(branch + ".lock"), ".lock")):
                undo = interrupt()
                try:
                    interrupted = step("record", ok=False)
                finally:
                    undo()
                self.assertNotEqual(interrupted.returncode, 0)
                self.assertIn(reason, interrupted.stderr)
                self.assertIsNone(json.loads(inventory_path.read_text())["preparing"])
                self.assertEqual(run("git", "rev-parse", "HEAD").stdout.strip(), cut)
                self.assertEqual(run("git", "rev-parse", f"{tag}^{{commit}}").stdout.strip(), cut)
            step("record")
            final = json.loads((repo / "docs/releases.json").read_text())
            self.assertIsNone(final["preparing"])
            self.assertEqual(final["releases"][:-1], historical)
            self.assertEqual(final["releases"][-1], {"version": version, "tag": tag,
                                                    "commit": cut, "cut_date": "2026-09-12"})
            self.assertNotEqual(run("git", "rev-parse", "HEAD").stdout.strip(), cut)
            provenance = run("git", "rev-parse", "HEAD").stdout.strip()
            step("record")  # A retry after success must neither duplicate rows nor add a commit.
            self.assertEqual(run("git", "rev-parse", "HEAD").stdout.strip(), provenance)
            self.assertEqual(json.loads(inventory_path.read_text()), final)
            rewritten = json.loads(json.dumps(final))
            rewritten["releases"][0]["commit"] = cut
            inventory_path.write_text(json.dumps(rewritten))
            self.assertNotEqual(step("record", ok=False).returncode, 0,
                                "a retry must not adopt a rewritten published row")
            self.assertEqual(run("git", "rev-parse", "HEAD").stdout.strip(), provenance)
            run("git", "tag", "-d", historical_tag)
            run("git", "tag", "-a", historical_tag, cut, "-m", "Rewritten fixture history")
            rejected_state()  # Changing both the row and its ref cannot rewrite a release.
            run("git", "restore", "docs/releases.json")
            run("git", "update-ref", historical_ref, historical_object)
            final_refs = run("git", "show-ref", "--tags").stdout.splitlines()
            self.assertTrue(set(refs.splitlines()).issubset(final_refs))
            self.assertEqual(run("git", "status", "--porcelain").stdout, "")
            inventory_path.write_text(json.dumps(rewritten))
            run("git", "tag", "-d", historical_tag)
            run("git", "tag", "-a", historical_tag, cut, "-m", "Committed fixture rewrite")
            run("git", "add", "docs/releases.json")
            run("git", "commit", "-m", "Invalid fixture mapping")
            run("git", "commit", "--allow-empty", "-m", "Later fixture commit")
            rejected_state()  # Committing the rewrite does not erase prior published state.


class TestDocsNavigation(unittest.TestCase):

    def test_plugin_version_matches_changelog_heading(self):
        # Issue #209: plugin.json lagged Unreleased. Version is one number,
        # written in three places — they must agree with the latest dated
        # CHANGELOG heading.
        plugin = json.loads(
            (ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
        )
        market = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )
        version = plugin["version"]
        self.assertEqual(market["metadata"]["version"], version)
        self.assertEqual(market["plugins"][0]["version"], version)
        heading = re.search(
            r"^## \[(\d+\.\d+\.\d+)\] - ",
            (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        self.assertIsNotNone(heading, "CHANGELOG has no dated version heading")
        self.assertEqual(
            heading.group(1),
            version,
            "plugin.json version does not match the latest dated CHANGELOG heading",
        )

    def test_ops_doc_names_accounts_and_incident(self):
        # Issue #215: bus-factor-1 with no inventory and no 2 a.m. paragraph.
        # Issue #233 (G-20): step 4's merge-shaped rollback was unbound —
        # reverting `git revert -m 1` stayed green. Pin it on this test; it
        # already owns the 2 a.m. Incident section.
        text = (DOCS / "ops.md").read_text(encoding="utf-8")
        for tok in ("GitHub", "plugin marketplace", "greptile", "agentskills",
                    "Incident", "Rollback"):
            self.assertIn(tok, text, f"docs/ops.md lost its {tok!r} surface")
        # Scoped per #244 review: the full actionable command must live in the
        # numbered rollback step itself — the bare substring anywhere in the
        # doc (e.g. only in explanatory prose) is not enough.
        m = re.search(r"(?ms)^\d+\. Rollback.*?(?=^\d+\. |\Z)", text)
        step = m.group(0) if m else ""
        self.assertIn(
            "git revert -m 1 <merge-sha>",
            step,
            "docs/ops.md rollback step lost its actionable -m 1 command",
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertRegex(
            readme,
            r'href="docs/ops\.md"|\]\(docs/ops\.md\)',
            "README has no working Ops navigation link",
        )

    def test_architecture_names_every_runtime_policy(self):
        # Issue #34: the "operational details ARE the product" list omitted
        # mission-scheduling.md (and sandbox-policy.md appeared nowhere at all),
        # so a reader auditing the runtime surface off ARCHITECTURE.md missed
        # real policies. Every runtime/*.md must be named somewhere in the file.
        arch = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        for f in sorted(RUNTIME.glob("*.md")):
            self.assertIn(
                f.stem, arch,
                f"runtime/{f.name} is a load-bearing policy ARCHITECTURE.md never names",
            )

    def test_run_archive_index_lists_every_report(self):
        # Issue #35: the index predated the newest run — the report that backs
        # oss-contribute's `proof: external-run` frontmatter was invisible from
        # the archive's own index. Every dated report must be a linked row.
        #
        # The glob was `2*.md`, i.e. flat files only. The newest run is a DIRECTORY
        # (2026-09-12-runtime-repin/README.md), so the guard silently stopped covering the newest
        # shape while still passing -- the same defect #35 filed, one directory level down.
        index = run_archive_index()
        reports = sorted((DOCS / "runs").glob("2*.md"))
        reports += sorted(d / "README.md" for d in (DOCS / "runs").glob("2*")
                          if d.is_dir() and (d / "README.md").is_file())
        self.assertTrue(reports, "no dated run reports found at all")
        for f in reports:
            # A directory run is linked by its directory, a flat one by its filename.
            link = f"({f.parent.name}/)" if f.name == "README.md" else f"({f.name})"
            self.assertIn(
                link, index,
                f"docs/runs/{f.relative_to(DOCS / 'runs')} is not linked from the run-archive index",
            )

    def test_run_archive_integrity_standard_matches_practice(self):
        # Issue #35: the index claimed every report carries a run-close sha256
        # integrity inventory, while the oss-contribute report retains its
        # inventory in the fork worktree. Stated standard must equal actual
        # practice: a report either carries the inline inventory or names where
        # its inventory is retained — and the index's stated standard must
        # acknowledge that retained-elsewhere form the moment any report uses it.
        index = (DOCS / "runs" / "README.md").read_text(encoding="utf-8")
        for f in sorted((DOCS / "runs").glob("2*.md")):
            text = f.read_text(encoding="utf-8")
            if "integrity inventory (sha256)" in text:
                continue  # inline inventory — the strong form
            self.assertRegex(
                text, r"(?i)integrity inventory[^.]*retained",
                f"docs/runs/{f.name} has neither an inline sha256 inventory nor "
                f"a named retention location for one",
            )
            self.assertRegex(
                index, r"(?i)retained",
                f"the index claims every report carries an inline sha256 "
                f"inventory, but docs/runs/{f.name} retains its inventory "
                f"out-of-repo — stated standard != practice",
            )

    def test_research_archive_reachable_and_dated(self):
        # Issue #36: docs/research/ was reachable only from CHANGELOG.md — no
        # navigated surface linked it, so the analysis was invisible to its
        # readers and its staleness invisible to maintainers. It must be linked
        # from at least one navigated doc, every snapshot must be indexed in the
        # archive's README, and each snapshot must open with a dated-snapshot
        # banner so its counts are read as historical, not current.
        navigated = [ROOT / "README.md", DOCS / "concepts.md", DOCS / "getting-started.md"]
        navigated += sorted((DOCS / "missions").glob("*.md"))
        navigated += sorted((DOCS / "guides").glob("*.md"))
        # a missing surface must read as this test's assertion, not a
        # FileNotFoundError traceback; with every surface gone, inbound is
        # empty and the orphan assertion still fires.
        navigated = [p for p in navigated if p.exists()]
        # an actual link target into research/ — prose that happens to contain
        # the word ("research/decision frontier") must not count as navigation.
        link = re.compile(r"\]\((?:\.\./)*(?:docs/)?research/")
        inbound = [p.name for p in navigated
                   if link.search(p.read_text(encoding="utf-8"))]
        self.assertTrue(
            inbound,
            "docs/research/ is linked from no navigated doc surface (orphan)",
        )
        research_index = (DOCS / "research" / "README.md").read_text(encoding="utf-8")
        for f in sorted((DOCS / "research").glob("2*.md")):
            self.assertIn(
                f.name, research_index,
                f"docs/research/{f.name} is missing from the archive index",
            )
            head = "\n".join(f.read_text(encoding="utf-8").splitlines()[:10])
            self.assertIn(
                "Dated snapshot", head,
                f"docs/research/{f.name} carries no dated-snapshot banner",
            )

    def test_mission_guides_name_every_skill_compose_and_ride(self):
        # After E1–E6 the human guides lagged the SKILL compose/rides clauses
        # (missing ledger-contract, evidence-manifest, acceptance-review, …).
        # A guide that omits a protocol the skill declares is a false catalog.
        protocols = {p.stem for p in (ROOT / "playbooks").glob("*.md")}
        protocols |= {p.stem for p in RUNTIME.glob("*.md")}
        guide_links = re.compile(
            r"\]\(\.\./\.\./(?:playbooks|runtime)/([a-z0-9-]+)\.md\)"
        )
        guide_section = re.compile(
            r"^## Composes\n(.*?)(?=^## |\Z)", re.DOTALL | re.MULTILINE
        )
        skills = ROOT / "skills"
        for d in sorted(skills.iterdir()):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            skill = (d / "SKILL.md").read_text(encoding="utf-8")
            # First-sentence cut is deliberate (clean-sweep caveat names
            # `runtime-prove` without composing it) — see
            # validate.guide_declared_protocol_names.
            declared = set(validate.guide_declared_protocol_names(skill))
            declared &= protocols
            guide_path = DOCS / "missions" / f"{d.name}.md"
            self.assertTrue(
                guide_path.is_file(),
                f"docs/missions/{d.name}.md is missing",
            )
            guide = guide_path.read_text(encoding="utf-8")
            section = guide_section.search(guide)
            self.assertIsNotNone(
                section,
                f"docs/missions/{d.name}.md has no ## Composes section",
            )
            named = set(validate.BACKTICK_RE.findall(section.group(1)))
            named.update(guide_links.findall(section.group(1)))
            missing = sorted(declared - named)
            self.assertEqual(
                missing, [],
                f"docs/missions/{d.name}.md Composes omits {missing} "
                f"declared in skills/{d.name}/SKILL.md",
            )

    def test_mission_guides_compose_only_what_the_skill_declares(self):
        # The reverse direction of the test above. The 2026-09-15 docs review found deflake-it and
        # prove-it listing gate-classification and map-it listing merge-serialization under
        # Composes, none of which their SKILL.md mentions at all: a false catalog in the other
        # direction, invisible because only guide ⊇ clause was checked. A guide may list a
        # protocol the skill composes or rides, names in its DEFERRED READS paragraph (anything
        # after a "Never" there is an exclusion, not a read), or tells the coordinator to
        # `read <name>.md` at a phase — and nothing else. A bare mention elsewhere in the skill
        # is prose, not a declaration (PR #396 review).
        protocols = {p.stem for p in (ROOT / "playbooks").glob("*.md")}
        protocols |= {p.stem for p in RUNTIME.glob("*.md")}
        guide_links = re.compile(
            r"\]\(\.\./\.\./(?:playbooks|runtime)/([a-z0-9-]+)\.md\)"
        )
        guide_section = re.compile(
            r"^## Composes\n(.*?)(?=^## |\Z)", re.DOTALL | re.MULTILINE
        )
        name_md = re.compile(r"\b([a-z][a-z0-9-]+)\.md\b")
        deferred_para = re.compile(r"DEFERRED READS.*?(?:\n\n|\Z)", re.DOTALL)
        phase_read = re.compile(r"\bread\s+([a-z][a-z0-9-]+)\.md\b")
        for d in sorted((ROOT / "skills").iterdir()):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            skill = (d / "SKILL.md").read_text(encoding="utf-8")
            allowed = set(validate.guide_declared_protocol_names(skill))
            para = deferred_para.search(skill)
            if para:
                allowed |= set(name_md.findall(para.group(0).split("Never")[0]))
            allowed |= set(phase_read.findall(skill))
            allowed &= protocols
            guide = (DOCS / "missions" / f"{d.name}.md").read_text(encoding="utf-8")
            section = guide_section.search(guide)
            self.assertIsNotNone(section, f"docs/missions/{d.name}.md has no ## Composes section")
            named = set(validate.BACKTICK_RE.findall(section.group(1)))
            named.update(guide_links.findall(section.group(1)))
            extra = sorted((named & protocols) - allowed)
            self.assertEqual(
                extra, [],
                f"docs/missions/{d.name}.md Composes names {extra}, which "
                f"skills/{d.name}/SKILL.md neither composes, rides, nor reads",
            )

    def test_mission_guides_state_the_skills_compatibility(self):
        # 2026-09-15 docs review: no guide surfaced its skill's hard prerequisites (gitleaks,
        # a measurement harness, mutation tooling, a docs-framework build). The guide's Needs
        # line is the SKILL's `compatibility` field verbatim, so the two cannot drift.
        needs = re.compile(r"^\*\*Needs\*\* \(the skill's `compatibility` field, verbatim\): (.+)$", re.M)
        # The validator's own frontmatter parser, so every scalar style validate.py accepts
        # (block, plain, quoted — quotes stripped) is read the same way here (PR #396 review).
        for d in sorted((ROOT / "skills").iterdir()):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            skill = (d / "SKILL.md").read_text(encoding="utf-8")
            data, err = validate.parse_frontmatter(skill)
            self.assertIsNone(err, f"skills/{d.name}/SKILL.md frontmatter: {err}")
            value = data.get("compatibility")
            self.assertTrue(value, f"skills/{d.name}/SKILL.md has no compatibility field")
            compat = " ".join(str(value).split())
            guide = (DOCS / "missions" / f"{d.name}.md").read_text(encoding="utf-8")
            g = needs.search(guide)
            self.assertIsNotNone(g, f"docs/missions/{d.name}.md has no Needs line")
            self.assertEqual(" ".join(g.group(1).split()), compat,
                             f"docs/missions/{d.name}.md Needs line drifted from the skill's compatibility field")

    def test_mission_index_lists_every_skill(self):
        # #125: docs/missions/README.md indexed 11 of 13 (attest-it, access-it missing). The index
        # must link every skills/<name> guide. #143 review: resolve each link target against the
        # index's directory and require it to point at a REAL file — a basename match through a
        # broken path is not a link a reader can follow.
        resolved = index_targets(DOCS / "missions" / "README.md")
        for d in sorted((ROOT / "skills").iterdir()):
            if d.is_dir() and not d.name.startswith((".", "_")):
                guide = (DOCS / "missions" / f"{d.name}.md").resolve()
                self.assertIn(guide, resolved,
                              f"docs/missions/README.md omits a followable link to the {d.name} guide "
                              "(a basename match through a broken path is not a link readers can follow)")

    def test_distribution_proof_mix_matches_reality(self):
        # #125: the illustrative proof mix in distribution.md must match the live proof_status rollup,
        # not a stale hand-count (was "2·1·8" for an 11-mission catalog).
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "proof_status", ROOT / "runtime" / "scripts" / "proof_status.py")
        ps = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ps)
        counts = ps.rollup(ps.collect(ROOT / "skills", ROOT))
        text = (DOCS / "distribution.md").read_text(encoding="utf-8")
        for tier in ("doctrine-only", "self-run", "external-run"):
            m = re.search(rf"(\d+)\s+{re.escape(tier)}", text)
            self.assertIsNotNone(m, f"distribution.md omits the {tier} count (live: {counts[tier]})")
            self.assertEqual(int(m.group(1)), counts[tier],
                             f"distribution.md {tier} count is stale (live: {counts[tier]})")

    def test_distribution_kit_proof_mix_matches_reality(self):
        # #235: the listing kit leads every blurb with the proof mix, so it must track the live
        # proof_status rollup like distribution.md does. Every occurrence is checked, not the first.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "proof_status", ROOT / "runtime" / "scripts" / "proof_status.py")
        ps = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ps)
        counts = ps.rollup(ps.collect(ROOT / "skills", ROOT))
        text = (DOCS / "distribution-kit.md").read_text(encoding="utf-8")
        for tier in ("doctrine-only", "self-run", "external-run"):
            found = [int(n) for n in re.findall(rf"(\d+)\s+{re.escape(tier)}", text)]
            self.assertTrue(found, f"distribution-kit.md omits the {tier} count (live: {counts[tier]})")
            self.assertEqual(set(found), {counts[tier]},
                             f"distribution-kit.md {tier} count is stale (live: {counts[tier]})")

    def test_about_description_is_canonical_and_count_free(self):
        # The GitHub About box is a repository setting, so nothing in CI can read the live
        # value. What CI *can* hold is the text a maintainer pastes into it. That text went
        # stale twice as a hardcoded count (H-04 evidence records the first repair), while
        # every machine-readable description surface had already dropped the number. Three
        # things must hold or docs/about.md stops being the handoff it claims to be.
        about = (DOCS / "about.md").read_text(encoding="utf-8")
        blocks = re.findall(r"```text\n(.*?)\n```", about, re.DOTALL)
        self.assertEqual(len(blocks), 1,
                         "docs/about.md must carry exactly one ```text block: the string to paste")
        canonical = blocks[0]
        self.assertNotIn("\n", canonical, "the About box is a single line; so is its canonical text")

        # 1. GitHub truncates past 350 characters, silently.
        self.assertLessEqual(len(canonical), 350,
                             f"About descriptions are capped at 350 chars; this is {len(canonical)}")

        # 2. It must agree with the surfaces that already say the same thing, so the three
        #    cannot drift into three different blurbs the way the counts drifted.
        marketplace = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        )["metadata"]["description"]
        plugin = json.loads(
            (ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
        )["description"]
        self.assertTrue(canonical.startswith(marketplace),
                        f"canonical About text must open with the marketplace description\n"
                        f"  marketplace: {marketplace!r}\n  about.md:    {canonical!r}")
        self.assertTrue(plugin.startswith(marketplace),
                        "plugin.json and marketplace.json descriptions have diverged")

        # 3. The count lint must actually cover the file — a canonical string nothing lints
        #    is exactly the surface that rotted in the first place.
        self.assertIn("docs/about.md", validate.COUNT_LINT_FILES,
                      "docs/about.md is not in COUNT_LINT_FILES; the count can creep back unseen")
        self.assertEqual([f for f in validate.check_doc_counts() if "about.md" in f], [])

        # 4. ...and the canonical line must be checked independently of that lint (#346).
        #    check_doc_counts only recognises a count that lands on a catalog noun it knows,
        #    so routing the whole guarantee through it would inherit every hole in its
        #    vocabulary — which is how "twenty-one autonomous fleets" slipped past. The
        #    About box has no business carrying a number in any phrasing, so say that
        #    directly rather than through a noun set that has to keep up.
        self.assertFalse(re.search(r"\d", canonical),
                         f"the canonical About text must carry no digit: {canonical!r}")
        number_word = re.compile(
            r"\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|"
            r"fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|"
            r"fifty|sixty|seventy|eighty|ninety|hundred)\b", re.IGNORECASE)
        # "one router per worker" is mission-identity prose, not a catalog size; only a
        # number word standing before the catalog nouns would be a count here.
        spelled_count = re.compile(
            rf"{number_word.pattern}[-\s]+(?:\w+[-\s]+)?"
            r"(?:missions?|fleets?|outcome-named|callable)\b", re.IGNORECASE)
        self.assertIsNone(spelled_count.search(canonical),
                          f"the canonical About text must carry no spelled catalog count: {canonical!r}")

    def test_mission_guides_show_proof_tier(self):
        # #124: every mission guide surfaces its proof tier (matching the SKILL frontmatter), so a
        # doctrine-only, never-run mission does not read as field-proven.
        for d in sorted((ROOT / "skills").iterdir()):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            tier = re.search(r"(?m)^  proof:\s*(\S+)",
                             (d / "SKILL.md").read_text(encoding="utf-8")).group(1)
            guide = (DOCS / "missions" / f"{d.name}.md").read_text(encoding="utf-8")
            m = re.search(r"(?m)^> \*\*Proof:\*\*\s*(\S+)", guide)
            self.assertIsNotNone(m, f"docs/missions/{d.name}.md has no Proof callout")
            self.assertEqual(m.group(1), tier,
                             f"docs/missions/{d.name}.md Proof tier != skills/{d.name} frontmatter")

    def test_mission_guides_show_autonomy(self):
        # #92 review: autonomy is duplicated on the SKILL frontmatter and the guide callout; without a
        # consistency check a later level change leaves one surface stale. Bind them.
        for d in sorted((ROOT / "skills").iterdir()):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            level = re.search(r"(?m)^  autonomy:\s*(L\d)",
                              (d / "SKILL.md").read_text(encoding="utf-8")).group(1)
            guide = (DOCS / "missions" / f"{d.name}.md").read_text(encoding="utf-8")
            m = re.search(r"(?m)^> \*\*Autonomy:\*\*\s*(L\d)", guide)
            self.assertIsNotNone(m, f"docs/missions/{d.name}.md has no Autonomy callout")
            self.assertEqual(m.group(1), level,
                             f"docs/missions/{d.name}.md Autonomy != skills/{d.name} frontmatter")

    def test_every_changelog_release_has_a_cut_commit(self):
        # #274: nine dated CHANGELOG headings, no immutable ref binding any of them
        # to a commit. Tags live in the repo's ref namespace rather than in a
        # branch, so a fresh clone (and CI) cannot see one; docs/releases.json is
        # the committed half a checkout can actually verify.
        inventory = json.loads((DOCS / "releases.json").read_text(encoding="utf-8"))
        releases = inventory["releases"]
        by_version = {r["version"]: r for r in releases}
        self.assertEqual(len(by_version), len(releases), "duplicate published version")
        history = subprocess.run(["git", "log", "--format=%H", "--", "docs/releases.json"],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(history.returncode, 0, history.stderr)
        self.assertTrue(history.stdout.strip(), "published inventory history is required")
        for sha in history.stdout.split():
            snapshot = subprocess.run(["git", "show", f"{sha}:docs/releases.json"],
                                      cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(snapshot.returncode, 0, snapshot.stderr)
            for published in json.loads(snapshot.stdout)["releases"]:
                version = published["version"]
                self.assertIn(version, by_version, f"published {version} was removed")
                for field in ("tag", "commit", "cut_date"):
                    self.assertEqual(by_version[version][field], published[field],
                                     f"published {version} {field} changed since {sha}")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        headings = re.findall(r"(?m)^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})", changelog)
        self.assertTrue(headings, "CHANGELOG has no dated release headings")
        preparing = inventory.get("preparing")
        if preparing is not None:
            self.assertIsInstance(preparing, dict)
            self.assertEqual(set(preparing), {"version", "cut_date"},
                             "preparation has no cut SHA or published tag yet")
            self.assertEqual((preparing["version"], preparing["cut_date"]), headings[0],
                             "only the newest dated heading can be preparing")
            self.assertNotIn(preparing["version"], by_version)
            version_tuple = lambda value: tuple(map(int, value.split(".")))
            self.assertTrue(all(version_tuple(preparing["version"]) > version_tuple(v)
                                for v in by_version), "preparation must be a new version")
            headings = headings[1:]
        self.assertEqual({v for v, _ in headings}, set(by_version),
                         "every published heading needs its immutable provenance row")
        for version, cut_date in headings:
            self.assertIn(version, by_version, f"CHANGELOG {version} has no docs/releases.json row")
            row = by_version[version]
            self.assertEqual(row["cut_date"], cut_date, version)
            self.assertRegex(row["commit"], r"^[0-9a-f]{40}$", version)
            self.assertEqual(row["tag"], f"v{version}")
            found = subprocess.run(
                ["git", "cat-file", "-e", f"{row['commit']}^{{commit}}"],
                cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self.assertEqual(
                found.returncode, 0,
                f"docs/releases.json {version} names {row['commit'][:12]}, not a commit here",
            )

    def test_verify_manifest_fields_named_in_schema(self):
        # Issue #170: verify.py's no-gh lane required manifest["review"]["artifact"],
        # a field the evidence-manifest §1 schema never declared — a worker authoring
        # its manifest against the schema doc alone produced one the gate failed
        # closed. Every manifest field verify.py reads must be named in the §1 JSON
        # schema. Element reads over list fields (criteria[].id) are covered by the
        # schema's inline object shape, not by this check.
        schema_doc = (RUNTIME / "evidence-manifest.md").read_text(encoding="utf-8")
        block = re.search(r"```json\n(.*?)```", schema_doc, re.DOTALL).group(1)
        # Top-level keys sit at 2-space indent; each key's chunk runs to the next key.
        chunks, current = {}, None
        for line in block.splitlines():
            key = re.match(r'^  "([a-z_]+)":', line)
            if key:
                current = key.group(1)
                chunks[current] = line
            elif current:
                chunks[current] += "\n" + line
        src = (ROOT / "runtime" / "scripts" / "verify.py").read_text(encoding="utf-8")
        # Literal reads — the manifest handle is always `m`.
        reads = set(re.findall(r'\bm\.get\("([a-z_]+)"', src))
        # Nested reads — (m.get("p") or {}).get("s"), or an alias assigned from
        # m.get("p") and later alias.get("s"): s must appear inside p's chunk.
        nested = set(re.findall(r'\(m\.get\("([a-z_]+)"\) or \{\}\)\.get\("([a-z_]+)"\)', src))
        aliases = dict(re.findall(r'(\w+) = m\.get\("([a-z_]+)"\)(?: or \{\})?', src))
        for alias, parent in aliases.items():
            nested |= {(parent, sub) for sub in
                       re.findall(rf'\b{alias}\.get\("([a-z_]+)"\)', src)}
        # Dynamic reads — handle.get(var) where var loops over a literal tuple in
        # the same comprehension/loop (m.get(f), intent.get(k), prov.get(k));
        # resolve each literal in the tuple against the handle's parent.
        for var, vals, handle in re.findall(
                r"for (\w+) in \(([^)]*)\)[^\]]*?\b(\w+)\.get\(\1\)", src, re.DOTALL):
            lits = set(re.findall(r'"([a-z_]+)"', vals))
            if handle == "m":
                reads |= lits
            elif handle in aliases:
                nested |= {(aliases[handle], lit) for lit in lits}
        missing = sorted(reads - set(chunks))
        self.assertEqual(
            missing, [],
            f"verify.py reads manifest fields the §1 schema never declares: {missing}",
        )
        # Key extraction, not substring: "artifact" in "artifact_path" must not count (#196).
        declared_nested = {
            parent: set(re.findall(r'"([a-z_]+)":', chunk))
            for parent, chunk in chunks.items()
        }
        bad = sorted((p, s) for p, s in nested if s not in declared_nested.get(p, set()))
        self.assertEqual(
            bad, [],
            f"verify.py reads nested manifest fields the §1 schema never declares: {bad}",
        )

    def test_verify_gate_doc_enumerates_every_orca_env_read(self):
        # Issue #177: docs/verify-gate.md is the trust-boundary doc an operator
        # audits to learn which env must be scrubbed, yet its enumeration omitted
        # ORCA_NO_GH / ORCA_LIGHTING while verify-gate.sh honored both — and
        # ORCA_NO_GH silently downgrades review verification to the local-artifact
        # lane. Every ORCA_* the script reads must appear in the doc, and the
        # no-gh downgrade must be stated in the trust-boundary section.
        script = (RUNTIME / "scripts" / "verify-gate.sh").read_text(encoding="utf-8")
        # Actual reads: ${ORCA_X:-…} expansions and $ORCA_X references.
        reads = set(re.findall(r"\$\{?(ORCA_[A-Z_]+)\b", script))
        doc = (DOCS / "verify-gate.md").read_text(encoding="utf-8")
        missing = sorted(v for v in reads if v not in doc)
        self.assertEqual(
            missing, [],
            f"verify-gate.sh reads env vars docs/verify-gate.md never names: {missing}",
        )
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        missing_ex = sorted(v for v in reads if v not in example)
        self.assertEqual(
            missing_ex, [],
            f"verify-gate.sh reads env vars .env.example never names: {missing_ex}",
        )
        # #200 review pinned "ORCA_EXECUTE_NC is an unimplemented flag that fail-closes"; #255
        # implemented the replay, so the doc must now describe what it actually DOES — the control
        # is executed in a throwaway worktree — and #256's rule that the two review-waiver lanes
        # require it. An inverted assertion, not a dropped one: the doc must not drift back into
        # promising a replay that is not there, nor omit the lanes that depend on it.
        self.assertRegex(
            doc, r"(?is)ORCA_EXECUTE_NC.{0,600}(executes the\s+negative control|throwaway worktree)",
            "docs/verify-gate.md must describe what --execute-nc does: EXECUTE the negative "
            "control in a throwaway worktree at head_sha",
        )
        for lane in ("ORCA_NO_GH", "ORCA_LIGHTING"):
            section = doc.split(f"- `{lane}`", 1)[1].split("\n- `", 1)[0]
            self.assertIn(
                "ORCA_EXECUTE_NC", section,
                f"{lane} waives the review, so the doc must say it requires ORCA_EXECUTE_NC (#256)",
            )
        _, heading, rest = doc.partition("## Trust boundary")
        self.assertTrue(heading, "docs/verify-gate.md has no trust-boundary section")
        # Bound to this H2 — a later sibling section must not keep this green (#200).
        trust = rest.split("\n## ", 1)[0]
        self.assertIn(
            "ORCA_NO_GH", trust,
            "the trust-boundary section never names ORCA_NO_GH — the no-gh lane's "
            "review-authority downgrade is undisclosed",
        )
        self.assertIn(
            "downgrade", trust.lower(),
            "the trust-boundary section names ORCA_NO_GH without stating its "
            "review-authority downgrade",
        )


class QuotationsAreAttributedToWhatTheySay(unittest.TestCase):
    """#304: a research file carried a quotation its cited source does not contain.

    The sentence was a paraphrase of a real rule from a DIFFERENT article. A repository whose
    thesis is that claims must be checkable does not get to carry an unchecked quotation, so the
    fabricated one is pinned here by its text — if it ever comes back, this fails.
    """

    PLAN = ROOT / "docs" / "research" / "2026-08-28-forward-roadmap-and-defensibility-plan.md"

    def test_the_fabricated_sentence_is_gone(self):
        text = self.PLAN.read_text(encoding="utf-8")
        body = "\n".join(ln for ln in text.splitlines() if "Correction (#304)" not in ln)
        self.assertNotIn("the level you can safely reach is exactly the level you can cheaply "
                         "prove", body,
                         "the misattributed quotation is back in the body")

    def test_the_replacement_names_the_article_it_is_from(self):
        text = self.PLAN.read_text(encoding="utf-8")
        self.assertIn("Back pressure is the rule that you can only hand a loop as much autonomy "
                      "as you can cheaply and reliably verify, and not one inch more.", text,
                      "the verified sentence is not there")
        self.assertIn("Software Factories, Light and Dark", text,
                      "the quotation does not name the article it comes from")
        self.assertIn("addyosmani.com/blog/software-factories", text,
                      "the quotation is not linked to a source a reader can check")


class MissionGuidesEmbedTheirDiagram(unittest.TestCase):
    """#385: guide<->diagram parity was a convention nothing checked.

    modernize-it.jpg sat in the assets directory while its guide never referenced it, and four
    guides had no diagram at all; sixteen others embedded theirs. Every guide the mission index
    links must embed its own asset from docs/assets/diagrams/missions/, and every asset there must be
    embedded by the guide of the same name. A `<name>-light.jpg` beside `<name>.jpg` is the same
    diagram rendered for a light theme (PR #394): it belongs to the guide `<name>`, which embeds
    both through a `<picture>` block, so it is held to the same parity.
    """

    # Guides with no rendered diagram yet. Named, not skipped: a guide leaving this set by gaining
    # its diagram fails the test until its name is removed here. The four gaps #385 parked as a
    # human item (absorb-it, document-it, migrate-it, oncall-it; run 2026-09-14 Q3) closed when
    # PR #394 regenerated every mission's contract card from a committed prompt, so the set is empty.
    KNOWN_GAPS = []
    INDEX = DOCS / "missions" / "README.md"
    ASSETS = ROOT / "docs" / "assets" / "diagrams" / "missions"
    # `src="../assets/diagrams/missions/x.jpg"`, a `<picture>` source's `srcset="…"`, and
    # `](../assets/diagrams/missions/x.jpg)`.
    EMBED = re.compile(
        r"""(?:srcset=["']|src=["']|\]\()\.\./assets/diagrams/missions/([^"')\s]+)""")

    @staticmethod
    def _guide_of(asset_name):
        """The guide stem an asset belongs to: `x.jpg` and `x-light.jpg` are both guide `x`'s."""
        return re.sub(r"-light$", "", Path(asset_name).stem)

    def _guides(self):
        """Guide stem -> text, for every docs/missions/*.md the index links (the index is the list)."""
        # The index test's own parser, so every link form it accepts counts here too.
        missions = self.INDEX.parent.resolve()
        guides = {p.stem: p.read_text(encoding="utf-8") for p in index_targets(self.INDEX)
                  if p.parent == missions and p.name != "README.md"}
        # Equal to the guides on disk, not a count floor: a narrowed set would skip the difference.
        on_disk = sorted(p.stem for p in missions.glob("*.md") if p.name != "README.md")
        self.assertEqual(sorted(guides), on_disk,
                         "the index's guide set != the guides on disk; parity would skip the difference")
        return guides

    def test_every_indexed_guide_embeds_its_own_diagram(self):
        without = []
        for stem, text in sorted(self._guides().items()):
            refs = self.EMBED.findall(text)
            dangling = [r for r in refs if not (self.ASSETS / r).is_file()]
            self.assertEqual(dangling, [], f"docs/missions/{stem}.md embeds a diagram that is not there")
            if not any(self._guide_of(r) == stem for r in refs):
                without.append(stem)
        self.assertEqual(without, self.KNOWN_GAPS,
                         "guides with no embedded diagram of their own != the named known gaps")

    def test_every_diagram_asset_is_embedded_by_its_guide(self):
        guides = self._guides()
        for asset in sorted(p for p in self.ASSETS.iterdir() if p.is_file()):
            with self.subTest(asset=asset.name):
                guide = self._guide_of(asset.name)
                self.assertIn(guide, guides, f"{asset.name} has no indexed guide of that name")
                self.assertIn(asset.name, self.EMBED.findall(guides[guide]),
                              f"docs/missions/{guide}.md never embeds {asset.name}")

    def _fixture(self, tmp, index_links, unlinked=()):
        """A parity check over a throwaway repo: sixteen bare-linked guides that embed their own
        diagram, plus the extra index lines given, a diagram-less `gap.md`, and `unlinked` guides."""
        missions, assets = tmp / "docs" / "missions", tmp / "docs" / "assets" / "diagrams" / "missions"
        missions.mkdir(parents=True)
        assets.mkdir(parents=True)
        embedded = [f"g{i:02d}" for i in range(16)]
        for stem in embedded:
            (missions / f"{stem}.md").write_text(f'<img src="../assets/diagrams/missions/{stem}.jpg">\n')
            (assets / f"{stem}.jpg").write_bytes(b"")
        for stem in ("gap", *unlinked):
            (missions / f"{stem}.md").write_text("no diagram yet\n")
        lines = [f"| [{s}]({s}.md) | x |" for s in embedded] + list(index_links)
        (missions / "README.md").write_text("\n".join(lines) + "\n")
        check = MissionGuidesEmbedTheirDiagram("test_every_indexed_guide_embeds_its_own_diagram")
        check.INDEX, check.ASSETS, check.KNOWN_GAPS = missions / "README.md", assets, ["gap"]
        return check

    def test_a_diagram_less_guide_counts_in_every_link_form_the_index_accepts(self):
        # Round-2 review: the guide set was read with a bare `](x.md)` pattern, so a gap linked as
        # `./gap.md` dropped out of parity while the index test (which accepts it) stayed green.
        for link in ("[gap](./gap.md)", "[gap](gap.md#top)", "[gap](<gap.md>)", '[gap](gap.md "t")'):
            with self.subTest(link=link), tempfile.TemporaryDirectory() as tmp:
                check = self._fixture(Path(tmp), [f"| {link} | x |"])
                check.test_every_indexed_guide_embeds_its_own_diagram()

    def test_a_guide_the_index_set_misses_fails_loudly(self):
        # A count floor let a narrowed guide set pass; the set must equal the guides on disk.
        with tempfile.TemporaryDirectory() as tmp:
            check = self._fixture(Path(tmp), ["| [gap](gap.md) | x |"], unlinked=["orphan"])
            with self.assertRaisesRegex(AssertionError, "orphan"):
                check._guides()

    def test_a_light_variant_is_held_to_its_guide(self):
        # PR #394 review of the parity check: `g00-light.jpg` is guide g00's diagram, not a guide
        # of its own, and a `<picture>` embeds it through `srcset=`, which `src=` never matched.
        with tempfile.TemporaryDirectory() as tmp:
            check = self._fixture(Path(tmp), ["| [gap](gap.md) | x |"])
            light = check.ASSETS / "g00-light.jpg"
            light.write_bytes(b"")
            with self.assertRaisesRegex(AssertionError, "g00.md never embeds g00-light.jpg"):
                check.test_every_diagram_asset_is_embedded_by_its_guide()
            guide = check.INDEX.parent / "g00.md"
            guide.write_text('<picture><source media="(prefers-color-scheme: light)" '
                             'srcset="../assets/diagrams/missions/g00-light.jpg">'
                             '<img src="../assets/diagrams/missions/g00.jpg"></picture>\n')
            check.test_every_diagram_asset_is_embedded_by_its_guide()
            check.test_every_indexed_guide_embeds_its_own_diagram()


class CompletionStatusNamesTheCommitItDescribes(unittest.TestCase):
    """#385: status.json's current_commit named 6671913 (PR #231's merge, where run 3 resumed)
    while the record it heads describes the tree after run 3's own PR merged: S5-B fixes, issue
    filing and run_pr all land inside that PR. The snapshot names its run PR, so the commit it
    describes is that PR's merge commit, read from history rather than restated here."""

    def test_current_commit_is_the_merge_of_the_recorded_run_pr(self):
        status = json.loads((DOCS / "completion" / "status.json").read_text(encoding="utf-8"))
        number = re.fullmatch(r"https://github\.com/[^/]+/[^/]+/pull/(\d+)", status["run_pr"])
        self.assertIsNotNone(number, f"run_pr is not a pull-request URL: {status['run_pr']!r}")
        commit = status["current_commit"]
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        shown = subprocess.run(["git", "show", "-s", "--format=%P%n%s", commit],
                               cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(shown.returncode, 0, f"current_commit {commit[:12]} is not a commit here "
                         "(a shallow checkout needs fetch-depth: 0)")
        parents, subject = shown.stdout.splitlines()[:2]
        self.assertEqual(len(parents.split()), 2, f"{commit[:12]} is not a merge commit")
        self.assertTrue(subject.startswith(f"Merge pull request #{number.group(1)} "),
                        f"current_commit {commit[:12]} is {subject!r}, not the merge of the "
                        f"snapshot's own run PR #{number.group(1)}")


class EveryReleaseHasTheTagItDescribes(unittest.TestCase):
    """#307: docs/releases.json bound nine versions to commits and `git tag` was empty.

    The mapping was true and the artifact it describes did not exist — no version was fetchable by
    tag, and `git describe` had nothing to work with.

    The first cut SKIPPED when no release tag was present, reasoning that an unfetched clone
    cannot prove anything about tags. That made the gate toothless in exactly the state it was
    written for — the repository's own — and CI fetches tags anyway (`fetch-depth: 0`), so the
    skip could not tell "not fetched" from "never published" where it mattered (PR #308 review,
    P1). It fails now. A gate that cannot fire in the condition it was added to detect is the
    shape this catalog refuses.
    """

    RELEASES = ROOT / "docs" / "releases.json"

    def _releases(self):
        return json.loads(self.RELEASES.read_text(encoding="utf-8"))["releases"]

    @staticmethod
    def _git(*args):
        return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)

    def test_every_release_names_a_commit_that_exists(self):
        # True with or without tags — the half that never needs a fetch.
        for rel in self._releases():
            with self.subTest(version=rel["version"]):
                self.assertEqual(
                    self._git("cat-file", "-e", rel["commit"] + "^{commit}").returncode, 0,
                    f"{rel['tag']} names a commit this repository does not have")

    def test_every_release_is_tagged_at_the_commit_it_names(self):
        releases = self._releases()
        present = {t for t in self._git("tag").stdout.split()}
        wanted = {rel["tag"] for rel in releases}
        missing = sorted(wanted - present)
        self.assertEqual(
            missing, [],
            f"released but untagged: {missing}\n"
            "docs/releases.json binds these versions to commits, so the mapping is true and the "
            "tags it describes do not exist — no version is fetchable by tag and `git describe` "
            "has nothing to work with (#307).\n"
            "If this is a shallow or --no-tags checkout, fetch them first "
            "(actions/checkout with fetch-depth: 0). Follow docs/ops.md for release recovery; "
            "preserve existing tag targets.")
        for rel in releases:
            with self.subTest(version=rel["version"]):
                self.assertEqual(self._git("cat-file", "-t", rel["tag"]).stdout.strip(), "tag",
                                 f"{rel['tag']} must be an annotated tag")
                at = self._git("rev-list", "-n", "1", rel["tag"]).stdout.strip()
                self.assertEqual(at, rel["commit"],
                                 f"{rel['tag']} points at {at[:12]}, not the commit "
                                 f"docs/releases.json names ({rel['commit'][:12]})")

    def test_the_file_documents_how_to_publish_them(self):
        # The durable half: a reader who finds the tags missing must be told what to run.
        comment = json.loads(self.RELEASES.read_text(encoding="utf-8"))["_comment"]
        self.assertIn("docs/ops.md", comment)
        self.assertIn("preparing", comment)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class ReadmeCatalogShowsProofTier(unittest.TestCase):
    """#515: the promise is made on README line one; the tier lived three clicks away in a guide.
    The catalog table now carries a Proof column, and this binds every cell to the SKILL
    frontmatter the way the guide callouts are bound."""

    ROW = re.compile(r"^\|\s*\S+\s+\*\*\[([a-z-]+)\]\(docs/missions/\1\.md\)\*\*\s*\|\s*`([a-z-]+)`\s*\|")

    def test_every_mission_row_carries_its_skill_proof_tier(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        rows = {}
        for line in readme.splitlines():
            m = self.ROW.match(line)
            if m:
                rows[m.group(1)] = m.group(2)
        missions = sorted(d.name for d in (ROOT / "skills").iterdir()
                          if d.is_dir() and not d.name.startswith((".", "_"))
                          and (d / "SKILL.md").exists())
        self.assertEqual(sorted(rows), missions,
                         "the README catalog table must carry one row per mission with a Proof cell")
        for name in missions:
            tier = re.search(r"(?m)^  proof:\s*(\S+)",
                             (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")).group(1)
            self.assertEqual(rows[name], tier, f"README Proof cell for {name} != skills/{name} frontmatter")

    def test_the_row_matcher_reads_the_table_shape(self):
        m = self.ROW.match("| 🚢 **[ship-it](docs/missions/ship-it.md)** | `doctrine-only` | Intent … | use |")
        self.assertEqual((m.group(1), m.group(2)), ("ship-it", "doctrine-only"))
        self.assertIsNone(self.ROW.match("| 🚢 **[ship-it](docs/missions/ship-it.md)** | Intent … | use |"))
