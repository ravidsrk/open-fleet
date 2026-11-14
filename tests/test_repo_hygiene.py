#!/usr/bin/env python3
"""Repo-hygiene contracts (#300).

Three unrelated findings from the supply-chain pass, each a file rather than code, and each
easy to undo silently in a later edit. The assertions are about the FILES, so they hold whoever
changes them next.
"""
import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


class RuntimeStateIsNotCommittable(unittest.TestCase):
    """`.orca/` is the Orca runtime's working directory, not repository content.

    egress.py defaults its ledger to `.orca/egress.jsonl` at mode 0600 and the dispatch key
    lives there too, so an unignored `.orca/` lets a worker commit runtime state — a private
    key among it — by accident.
    """

    def _ignored(self, rel):
        r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT)
        return r.returncode == 0

    def test_the_runtime_working_directory_is_ignored(self):
        for rel in (".orca/", ".orca/egress.jsonl", ".orca/keys/dispatch.key",
                    ".orca/anything/nested/deep.json"):
            with self.subTest(path=rel):
                self.assertTrue(self._ignored(rel), f"{rel} would be committable")

    def test_the_ignore_matches_the_path_the_code_actually_uses(self):
        # The rule is only worth anything if it covers the default the runtime writes to.
        egress = (ROOT / "runtime" / "scripts" / "egress.py").read_text(encoding="utf-8")
        m = re.search(r'^DEFAULT_LEDGER = "([^"]+)"', egress, re.M)
        self.assertIsNotNone(m, "egress.py no longer declares DEFAULT_LEDGER")
        self.assertTrue(self._ignored(m.group(1)),
                        f"egress.py writes {m.group(1)} and .gitignore does not cover it")

    def test_the_public_key_is_still_committable(self):
        """The one thing in `.orca/` that MUST be commitable — and the first cut broke it.

        Committing `.orca/dispatch-pubkey` is what turns dispatch-signature enforcement on
        (dispatch-sign.py:127). A blanket `.orca/` swept it up, and test_dispatch_sign.py said
        so; this is the same contract stated from the ignore rule's side, because the two are
        easy to change independently.
        """
        self.assertFalse(self._ignored(".orca/dispatch-pubkey"),
                         "the pubkey is ignored — signature enforcement can no longer be "
                         "turned on by committing it")
        self.assertFalse(self._ignored(".orca/human-grant-pubkey"),
                         "the human grant pubkey is ignored — signed one-way grants "
                         "can no longer be turned on by committing it")

    def test_the_rule_excludes_contents_so_the_exception_can_work(self):
        # `.orca/` would read more naturally and would NOT work: git never descends into an
        # excluded directory, so a `!` negation under one is dead. `.orca/*` is what makes the
        # pubkey exception above possible. Same idiom as `.secrets/*` + `!.secrets/*.pub`.
        rules = [ln.strip() for ln in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
                 if ln.strip().startswith((".orca", "!.orca"))]
        self.assertEqual(rules, [".orca/*", "!.orca/dispatch-pubkey",
                                 "!.orca/human-grant-pubkey"],
                         "the runtime-state rule changed shape — a bare `.orca/` would make "
                         "the pubkey exception silently inert")

    def test_ordinary_repository_paths_are_still_tracked(self):
        for rel in ("runtime/scripts/egress.py", "skills/prove-it/SKILL.md", "README.md"):
            with self.subTest(path=rel):
                self.assertFalse(self._ignored(rel), f"{rel} was swept up by an ignore rule")


class EveryScriptCompilesWithoutWarnings(unittest.TestCase):
    """A SyntaxWarning is a future SyntaxError, and CI was printing two of them.

    `run_report.py` had `\\S` inside plain docstrings, which Python flags as an invalid escape
    sequence. Local runs never showed it — a cached .pyc does not recompile — so it only appeared
    in the CI log, where every file is compiled fresh. Python has announced these become errors.
    """

    def _compile_warnings(self, files):
        import py_compile
        import tempfile
        import warnings
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "c.pyc")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                for f in files:
                    py_compile.compile(str(f), cfile=out, doraise=False)
                return [f"{Path(f).name}: {w.category.__name__}: {w.message}" for w in caught]

    def test_the_compile_check_can_actually_see_a_warning(self):
        """Without this the check is a tautology on a clean tree.

        A mutant replacing `assertEqual(found, [])` with `assertEqual([], [])` survived, because
        both are true when nothing warns — the same vacuity the stdlib-import guard above had.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad_escape.py"
            bad.write_text('"""a docstring with \\S in it"""\n', encoding="utf-8")
            self.assertTrue(self._compile_warnings([bad]),
                            "the compile scan cannot see an invalid escape sequence")
            good = Path(tmp) / "good_escape.py"
            good.write_text('r"""a raw docstring with \\S in it"""\n', encoding="utf-8")
            self.assertEqual(self._compile_warnings([good]), [],
                             "the compile scan flags a raw string that is perfectly legal")

    def test_no_source_file_compiles_with_a_warning(self):
        roots = ("scripts", "runtime/scripts", "tests", "bench", "evals/demo")
        files = [f for r in roots for f in sorted((ROOT / r).rglob("*.py"))
                 if "__pycache__" not in f.parts]
        self.assertGreater(len(files), 40, "the scan found almost no sources to compile")
        self.assertEqual(self._compile_warnings(files), [],
                         "these are future SyntaxErrors, and CI prints them today")


class TheSecretWaiverCarriesIdentityNotContent(unittest.TestCase):
    """A waiver needs the finding's fingerprint, not the finding.

    The `--baseline-path` baseline this replaced embedded each finding's commit message, author
    name and e-mail address. Measured before switching: gitleaks 8.30.1 compares Email, Author,
    Date, Message, Entropy, Description and Commit when matching a baseline entry, so deleting
    those fields stops a baseline suppressing anything at all. `.gitleaksignore` matches on the
    fingerprint alone, which is why the switch is the fix rather than a trim.
    """

    IGNORE = ROOT / ".gitleaksignore"
    # <40-hex commit>:<path>:<rule-id>:<line>
    FINGERPRINT = re.compile(r"^[0-9a-f]{40}:[^:]+:[A-Za-z0-9._-]+:\d+$")

    def _lines(self):
        text = self.IGNORE.read_text(encoding="utf-8")
        return [ln.strip() for ln in text.splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]

    def test_the_baseline_that_carried_content_is_gone(self):
        self.assertFalse((ROOT / ".gitleaks-baseline.json").exists(),
                         "the content-carrying baseline is back")

    # The exact set. Widening is the dangerous direction — one more line here silences a real
    # finding with nothing to show for it — and narrowing turns CI red rather than silent, so
    # pinning both ends is what makes this file reviewable at a glance.
    #
    # 2026-09-16 addition (PR #461, owner decision on the waiver the harden-it campaign run
    # parked in 111af419): the run's transcript quotes the AWS-doc fixture key and the
    # api_key fixture string in its own scan capture. Byte-inspected fixtures, nothing live,
    # nothing rotated; gitleaks detect scans every ref in the clone, so these fired on all
    # PRs once the campaign archive branches were pushed.
    WAIVED = {
        "03e481a106bea9dbe124fd5b5181d5769e28061f:tests/test_decisions.py:generic-api-key:111",
        "03e481a106bea9dbe124fd5b5181d5769e28061f:tests/test_decisions.py:aws-access-token:102",
        "03e481a106bea9dbe124fd5b5181d5769e28061f:tests/test_decisions.py:aws-access-token:115",
        "57760b66a8f8e282bb6ff5a8afa4a7661dd6701a:docs/runs/campaign-2026-09-16-harden-it/ADDENDUM-gitleaks-waiver.md:generic-api-key:17",
        "f0c83cb1f1aa099206058f15570706f90482414e:docs/runs/campaign-2026-09-16-harden-it/receipts/gitleaks-audit.json:generic-api-key:50",
        "f0c83cb1f1aa099206058f15570706f90482414e:docs/runs/campaign-2026-09-16-harden-it/receipts/gitleaks-audit.json:aws-access-token:9",
        "f0c83cb1f1aa099206058f15570706f90482414e:docs/runs/campaign-2026-09-16-harden-it/receipts/gitleaks-audit.json:aws-access-token:10",
        "f0c83cb1f1aa099206058f15570706f90482414e:docs/runs/campaign-2026-09-16-harden-it/receipts/gitleaks-audit.json:aws-access-token:29",
        "f0c83cb1f1aa099206058f15570706f90482414e:docs/runs/campaign-2026-09-16-harden-it/receipts/gitleaks-audit.json:aws-access-token:30",
    }

    def test_every_waived_entry_is_a_bare_fingerprint(self):
        entries = self._lines()
        self.assertTrue(entries, ".gitleaksignore waives nothing — is the scan still gated?")
        for entry in entries:
            with self.subTest(entry=entry):
                self.assertRegex(entry, self.FINGERPRINT)

    def test_the_waived_set_is_exactly_the_known_fixtures(self):
        self.assertEqual(set(self._lines()), self.WAIVED,
                         "the secret-scan waiver changed — every entry here is a finding "
                         "nobody will see again, so an addition needs its own justification")

    # Paths allowed to carry waived fingerprints, each with its justification above.
    WAIVED_PATHS = {
        "tests/test_decisions.py",
        "docs/runs/campaign-2026-09-16-harden-it/ADDENDUM-gitleaks-waiver.md",
        "docs/runs/campaign-2026-09-16-harden-it/receipts/gitleaks-audit.json",
    }

    def test_nothing_outside_the_fixture_file_is_waived(self):
        for entry in self._lines():
            with self.subTest(entry=entry):
                self.assertIn(entry.split(":")[1], self.WAIVED_PATHS,
                              "only the credential-shaped fixtures are waived")

    def test_the_waiver_carries_no_address_and_no_commit_message(self):
        text = self.IGNORE.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                            "an e-mail address is back in the secret waiver")
        for field in ('"Message"', '"Author"', '"Email"', '"Secret"', '"Match"'):
            self.assertNotIn(field, text, f"{field} is finding CONTENT, not its identity")

    def test_the_scan_reads_this_file_and_no_baseline(self):
        # A MENTION is fine — the step explains at length why the baseline went away. What must
        # not survive is an INVOCATION, which would point gitleaks at a file the repo no longer
        # has. (This test caught exactly that distinction on its own comment first.)
        wf = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        invoked = [ln.strip() for ln in wf.splitlines()
                   if "--baseline-path" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(invoked, [],
                         "the workflow still PASSES a baseline the repo no longer has")
        self.assertIn("gitleaksignore", wf,
                      "nothing in the workflow explains where the waiver lives")

    def test_the_planted_credential_control_still_runs(self):
        """The waiver is only as good as the proof that it waives nothing else.

        Checking for the WORD `canary` was not enough — it survives in the prose after the
        block that plants the key is gone. The control is three things that have to be there
        together: a throwaway clone, a key written into the waived file, and a scan of that
        clone whose SUCCESS fails the build.
        """
        wf = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        body = [ln for ln in wf.splitlines() if not ln.lstrip().startswith("#")]
        run = "\n".join(body)
        self.assertRegex(run, r'git clone --quiet \. "\$canary"',
                         "nothing clones a throwaway repo to plant the key in")
        self.assertRegex(run, r'printf .*AKIA.*>> "\$canary/tests/test_decisions\.py"',
                         "nothing plants a real-shaped key in the waived file")
        self.assertRegex(run, r'(?s)if \(cd "\$canary".{0,200}?detect.{0,400}?exit 1',
                         "a passing scan of the planted key no longer fails the build")

    def test_a_path_allowlist_cannot_hide_behind_the_fingerprint_canary(self):
        """2026-10-27 security audit, W6-03: a `.gitleaks.toml` allowlist waives by path, and the
        only canary sat in tests/test_decisions.py, so `paths = ['^scripts/.*']` passed the
        control while a real key under scripts/ went unreported. The control now plants the key
        under every top-level directory and requires the report to name each planted file."""
        wf = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        run = "\n".join(ln for ln in wf.splitlines() if not ln.lstrip().startswith("#"))
        self.assertRegex(run, r'for dir in \. \$\(git -C "\$canary" ls-tree -d --name-only HEAD\)',
                         "the canary no longer reaches every top-level directory")
        self.assertRegex(run, r'printf .*AKIA.*> "\$canary/\$file"')
        self.assertRegex(run, r'(?s)if \(cd "\$canary" && GIT_ATTR_SOURCE="\$no_attributes" '
                              r'"\$gl" detect [^\n]*'
                              r'--report-format json --report-path "\$RUNNER_TEMP/canary\.json"\)')
        self.assertRegex(run, r'python3 -I - "\$RUNNER_TEMP/canary\.json" "\$\{planted\[@\]\}"')
        self.assertIn("missed = [path for path in sys.argv[2:] if path not in reported]", run)

    def test_the_scan_reads_no_attributes_from_the_tree(self):
        """PR #718 re-attack (W6-03 class): `scripts/whatever.py -diff` in a .gitattributes, at the
        root or nested, made git render the file's history as "Binary files differ", and
        gitleaks 8.30.1 reported no leaks. Every scan reads attributes from the empty tree, and
        the canary clone plants `* -diff`, so a scan that honours the tree's attributes fails."""
        wf = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        run = "\n".join(ln for ln in wf.splitlines() if not ln.lstrip().startswith("#"))
        self.assertIn('no_attributes="4b825dc642cb6eb9a060e54bf8d69288fbee4904"', run)
        scans = [ln.strip() for ln in run.splitlines() if '"$gl" detect' in ln]
        self.assertEqual(len(scans), 2, scans)
        for scan in scans:
            with self.subTest(scan=scan):
                self.assertIn('GIT_ATTR_SOURCE="$no_attributes" "$gl" detect', scan)
        self.assertRegex(run, r"printf '\* -diff\\n' > \"\$canary/\.gitattributes\"")

    def test_a_binary_classified_credential_is_read_as_text(self):
        """PR #718 review round 5 (W6-03 class): a file with a NUL byte in it (or marked `binary`
        or `-diff`) is "Binary files differ" to `git log -p` even with attributes read from the
        empty tree, so gitleaks 8.30.1 reported no leak in it. Both scans first run the step's own
        every_path_text, which sets `diff` for every path in $GIT_DIR/info/attributes. Run here
        exactly as written in a throwaway repository, against a fixture whose fake key is
        assembled at test time, through gitleaks when it is installed and through the `git log`
        it runs (GIT_TRACE, 8.30.1) either way."""
        wf = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        run = "\n".join(ln for ln in wf.splitlines() if not ln.lstrip().startswith("#"))
        defined = re.findall(r"(?m)^ *(every_path_text\(\) \(.*\))$", run)
        self.assertEqual(len(defined), 1, "the step no longer defines every_path_text")
        self.assertRegex(run, r'(?s)every_path_text \.\n *GIT_ATTR_SOURCE="\$no_attributes" "\$gl" '
                              r'detect --redact --no-banner --source \.\n')
        self.assertRegex(run, r'(?s)git clone --quiet \. "\$canary"\n *every_path_text "\$canary"\n')
        self.assertRegex(run, r"printf 'x\\000CANARY = .*> \"\$canary/gitleaks-canary\.dat\"")
        self.assertIn("planted+=(gitleaks-canary.dat)", run)
        key = "AKIA" + "ZYXWVUTSRQPONMLK"  # gitleaks' aws-access-token shape, not a real key
        empty_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "r"

            def git(*args, **extra):
                return subprocess.run(["git", "-C", str(repo), *args], env={**env, **extra},
                                      capture_output=True, check=True, timeout=60).stdout

            subprocess.run(["git", "init", "-q", str(repo)], env=env, check=True, timeout=60)
            (repo / "credential.dat").write_bytes(b"x\x00CANARY = \"" + key.encode() + b"\"\n")
            (repo / ".gitattributes").write_text("credential.dat binary\n* -diff\n",
                                                 encoding="utf-8")
            git("add", "-A")
            git("commit", "-qm", "a binary-classified credential")

            def history():
                return git("log", "-p", "-U0", "--full-history", "--all", "--diff-filter=tuxdb",
                           GIT_ATTR_SOURCE=empty_tree)

            self.assertNotIn(key.encode(), history(), "the fixture is not binary to git")
            subprocess.run(["bash", "-c", defined[0] + "\nevery_path_text \"$1\"", "_",
                            str(repo)], env=env, check=True, timeout=60)
            self.assertIn(b"+x\x00CANARY = \"" + key.encode(), history(),
                          "the scan's history still hides the binary-classified credential")
            gitleaks = shutil.which("gitleaks")
            if gitleaks:
                report = Path(tmp) / "report.json"
                proc = subprocess.run(
                    [gitleaks, "detect", "--redact", "--no-banner", "--source", str(repo),
                     "--report-format", "json", "--report-path", str(report)],
                    env={**env, "GIT_ATTR_SOURCE": empty_tree}, capture_output=True,
                    timeout=120)
                self.assertNotEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual({f["File"] for f in json.loads(report.read_text())},
                                 {"credential.dat"})

    def test_the_scanner_config_is_on_the_frozen_guard_surface(self):
        # The allowlist file is a waiver mechanism: an edit to it must need a recorded human
        # waiver, the same as .gitleaksignore (floor_guard's guard-surface rule).
        spec = importlib.util.spec_from_file_location(
            "_floor_guard_for_hygiene", ROOT / "runtime" / "scripts" / "floor_guard.py")
        fg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fg)
        for line in ("[[allowlists]]", "paths = ['''^scripts/.*''']", "useDefault = false"):
            with self.subTest(line=line):
                self.assertEqual(fg.guard_surface_hit(".gitleaks.toml", line), ".gitleaks.toml")
        self.assertIn("`.gitleaks.toml`", (ROOT / "CONSTRAINTS.md").read_text(encoding="utf-8"))


class TheSuiteRunsOnTheStdlibAlone(unittest.TestCase):
    """CI installs no test dependencies, so a third-party import is a red build, not a skip.

    Learned the expensive way: a `yaml.safe_load` in this very file passed locally, where pyyaml
    happens to be installed, and failed on the runner. The repo already believed this —
    test_floor_guard.py uses `import yaml` as its example of a third-party import — but nothing
    enforced it, so the belief was worth exactly one commit.
    """

    # Modules that live in this directory and are imported by path, not by name.
    # orca_cli is the sibling module every runtime script imports for the CLI name (#510):
    # local, stdlib-only, not a distributable package.
    LOCAL = {"test_pins", "test_evals", "conftest", "orca_cli"}

    def _offenders(self, source, name="sample.py"):
        """Every module imported by this source, via `ast` — not a line regex.

        The first cut skipped any line containing a quote (to let test_floor_guard.py's quoted
        examples through) and read only the FIRST name of an import. `import os, yaml` and
        `import yaml  # "parser"` both sailed past it, and so did `from os import ...` on a
        commented line (PR #308 review, P2). A guard with holes is the defect it exists to catch.

        `ast` has neither problem and needs no heuristic: a quoted example parses to a string
        constant, never an Import node, and every alias in a multi-name import is visited.
        """
        stdlib = set(sys.stdlib_module_names)
        found = []
        for node in ast.walk(ast.parse(source, filename=name)):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import — no distributable package behind it.
                mods = [] if node.level else [node.module or ""]
            else:
                continue
            for mod in mods:
                top = mod.split(".")[0]
                if not top or top in stdlib or top in self.LOCAL or top == Path(name).stem:
                    continue
                found.append(f"{name}:{node.lineno}: {top}")
        return found

    def test_the_check_sees_imports_a_line_regex_missed(self):
        """PR #308 review, P2 — the holes in the first cut, each reproduced before fixing.

        All three passed the regex version and would have failed in dependency-free CI.
        """
        for source in ("import os, yaml\n",
                       'import yaml  # "parser"\n',
                       "import json\nimport requests, os\n",
                       "from yaml import safe_load\n",
                       "def f():\n    import yaml\n"):
            with self.subTest(source=source.strip()):
                self.assertTrue(self._offenders(source),
                                "a third-party import slipped past the guard")
        # And a quoted example is still not an import — test_floor_guard.py carries several.
        self.assertEqual(self._offenders('BAD = ["import yaml", "import requests"]\n'), [])
        for relative in ("from . import helpers\n", "from .helpers import thing\n",
                         "from ..pkg.mod import thing\n"):
            with self.subTest(source=relative.strip()):
                self.assertEqual(self._offenders(relative), [],
                                 "a relative import names no distributable package")

    def test_the_check_can_actually_see_a_third_party_import(self):
        """A clean tree makes `assertEqual(offenders, [])` pass whether or not the check works.

        Two negative-control mutants proved that: scanning no files at all, and allowlisting
        everything, both left the suite green. So the detector gets a sample it MUST flag —
        otherwise this is a check that only ever agrees with itself.
        """
        bad = self._offenders("import os\nimport yaml\nfrom requests import get\n")
        self.assertEqual(len(bad), 2, f"the third-party scan missed something: {bad}")
        self.assertTrue(any("yaml" in o for o in bad))
        self.assertTrue(any("requests" in o for o in bad))
        self.assertEqual(self._offenders("import os\nimport json\nfrom pathlib import Path\n"),
                         [], "the scan flagged the standard library")

    def test_no_test_imports_a_package_ci_does_not_install(self):
        offenders = []
        paths = sorted(Path(__file__).resolve().parent.glob("test_*.py"))
        self.assertGreater(len(paths), 20, "the scan found almost no test files to read")
        for path in paths:
            offenders += self._offenders(path.read_text(encoding="utf-8"), path.name)
        self.assertEqual(offenders, [],
                         "CI installs no test dependencies — these imports are a red build on "
                         "the runner and a pass on any machine that happens to have them")


class TheAlertWorkflowCannotBeTrippedByAFork(unittest.TestCase):
    """`branches: [main]` filters the workflow_run's HEAD branch, and a fork's PR branch can be
    named `main` too. No token reaches the fork, so the exposure is issue spam rather than
    credentials — but both halves of the guard are needed and neither is obvious."""

    WF = ROOT / ".github" / "workflows" / "alert-on-failure.yml"

    def _condition(self):
        """The job's `if:` folded scalar, read with the stdlib.

        This used `yaml.safe_load` and CI went red: pyyaml is not on the runner, and the whole
        suite is stdlib-only by design — test_floor_guard.py treats a bare `import yaml` as the
        third-party marker it is. Same folded-scalar shape test_pins.py already reads by hand.
        """
        out, active, indent = [], False, 0
        for line in self.WF.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not active and stripped.startswith("if:"):
                active, indent = True, len(line) - len(line.lstrip())
                rest = stripped[len("if:"):].strip()
                if rest not in (">-", ">", "|", "|-"):
                    out.append(rest)
                continue
            if active:
                if not stripped or stripped.startswith("#"):
                    continue
                if len(line) - len(line.lstrip()) <= indent:
                    break
                out.append(stripped)
        self.assertTrue(out, "the alert job has no `if:` condition at all")
        return " ".join(" ".join(out).split())

    def test_the_run_must_have_come_from_a_push(self):
        self.assertIn("github.event.workflow_run.event == 'push'", self._condition(),
                      "a PR-triggered validate run can still file an issue")

    def test_the_run_must_have_come_from_this_repository(self):
        self.assertIn(
            "github.event.workflow_run.head_repository.full_name == github.repository",
            self._condition(),
            "a fork pushing to its own `main` can still file an issue here")

    def test_the_failure_condition_and_the_drill_both_survive(self):
        cond = self._condition()
        self.assertIn("github.event.workflow_run.conclusion == 'failure'", cond,
                      "the workflow would now alert on a SUCCESSFUL run")
        self.assertIn("github.event_name == 'workflow_dispatch'", cond,
                      "the manual drill path is gone, so the alert can no longer be proven")


WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))  # .yml and .yaml
# ANY expression inside a `run:` script (2026-10-23 review, §5 CI). The runner pastes an
# expression's value into the script text before the shell parses it, so whether one is safe
# inline depends on where the value came from, which no regex can decide: the old list of
# PR-controlled contexts (base_ref, head_ref, event.*) missed github.ref_name, inputs.*,
# steps.*, needs.*, and env.* holding any of those, and a matrix can be built from
# fromJSON(needs.*). So there is no allowlist: every value reaches a script through env:,
# where the shell expands it as data and never re-parses it.
_TAINTED_EXPR_RE = re.compile(r"\$\{\{")


def _jobs(text):
    """{job: [lines]} for the top-level `jobs:` map — stdlib only (no pyyaml on the runner)."""
    jobs, current, in_jobs = {}, None, False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if in_jobs and line and not line[0].isspace() and not line.startswith("#"):
            in_jobs = False
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            jobs[current] = []
        elif current:
            jobs[current].append(line)
    return jobs


def _run_scripts(text):
    """Every `run:` script body, inline or block scalar."""
    scripts, lines = [], text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", line)
        if not m:
            continue
        indent, rest = len(m.group(1)), m.group(2)
        body = [] if rest in ("|", "|-", ">", ">-") else [rest]
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        scripts.append((i + 1, "\n".join(body)))
    return scripts


_SCANNED_KEYS = r"(?:uses|run|with|steps|jobs|persist-credentials|shell|working-directory)"
_LOOSE_KEY = re.compile(
    r"[{,]\s*[\"']?" + _SCANNED_KEYS + r"[\"']?\s*:"       # a key inside a flow mapping
    r"|[\"']" + _SCANNED_KEYS + r"[\"']\s*:"               # a quoted key
    r"|\b" + _SCANNED_KEYS + r"\s+:")                      # a space before the colon
# A merge key, an anchor (`&name`, with or without a value after it) or an alias (`*name`), as a
# YAML node starts: after a line start, whitespace or a flow indicator (a run: body is not read).
_YAML_INDIRECTION = re.compile(r"<<\s*:|(?:^|[\s\[{,])[&*][A-Za-z_][\w-]*(?=\s|$|[\]},])")
# The block YAML subset every line scan here reads as GitHub's parser does: an allowlist, held in
# scripts/release_check.py because release gate 3 reads workflows the same way. Refusing hiding
# spellings one at a time missed one a round: an explicit `? uses` / `: owner/action@v4` key, then
# `-   uses:`, a `uses:` whose value sits on the next line, and a `!!str uses:` tag (PR #718
# review round 3), each a mutable action ref the pin test never saw.
_rc_spec = importlib.util.spec_from_file_location(
    "_release_check_for_hygiene", ROOT / "scripts" / "release_check.py")
_release_check = importlib.util.module_from_spec(_rc_spec)
_rc_spec.loader.exec_module(_release_check)


def _structure_offenders(name, text):
    """Why the stdlib scans in this module could misread a workflow: they read block-style YAML
    line by line (no parser on the runner, and the suite is stdlib-only), so a workflow must be
    a `.yml` file, every line of it inside the block subset release_check.block_yaml_offenders
    allows (plain keys, two-space nesting, one `- ` per item, scalars only), and its scanned keys
    carry no anchor, alias or merge key outside a `run:` body."""
    bad = [] if name.endswith(".yml") else [f"{name}: not a .yml file"]
    bad += [f"{name}:{n}: outside the block subset: {line.strip()}"
            for n, line in _release_check.block_yaml_offenders(text)]
    lines = text.splitlines()
    in_script, indent = False, 0
    for n, line in enumerate(lines, start=1):
        if in_script:
            if not line.strip() or len(line) - len(line.lstrip()) > indent:
                continue
            in_script = False
        m = re.match(r"^(\s*)(?:- )?run:\s*([|>][-+0-9]*)?\s*(?:#.*)?$", line)
        if m and m.group(2):
            in_script, indent = True, len(m.group(1))
        code = re.split(r"(?:^|\s)#", line, maxsplit=1)[0]
        if _LOOSE_KEY.search(code) or _YAML_INDIRECTION.search(code):
            bad.append(f"{name}:{n}: {line.strip()}")
    return bad


class TheScansReadEveryWorkflowAsWritten(unittest.TestCase):
    """PR #718 re-attack: the hygiene scans read `*.yml` by regex, so a `sneaky.yaml` workflow
    with `checkout@v4`, no persist-credentials and `${{ github.event.pull_request.title }}`
    inside `run:` left them green, and so did a flow mapping (`- {uses: …@v4}`) or `uses :`.
    WORKFLOWS globs both extensions, and every workflow must be in the plain block style the
    scans read, so nothing a runner would execute is invisible to them."""

    def test_every_workflow_is_one_the_scans_read(self):
        directory = ROOT / ".github" / "workflows"
        self.assertEqual(sorted(p.name for p in directory.iterdir()),
                         sorted(p.name for p in directory.glob("*.yml")),
                         "a workflow file the hygiene scans would not read")
        self.assertEqual([p.name for p in WORKFLOWS],
                         sorted(p.name for p in directory.glob("*.y*ml")))
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(_structure_offenders(path.name,
                                                      path.read_text(encoding="utf-8")), [])

    def test_the_structure_scan_can_actually_see_one(self):
        ok = "jobs:\n  x:\n    steps:\n      - uses: a/b@" + "c" * 40 + "\n"
        self.assertEqual(_structure_offenders("w.yml", ok), [])
        self.assertTrue(_structure_offenders("sneaky.yaml", ok))
        for text in ("jobs:\n  x:\n    steps:\n      - {uses: actions/checkout@v4}\n",
                     "jobs:\n  x:\n    steps:\n      - uses : actions/checkout@v4\n",
                     'jobs:\n  x:\n    steps:\n      - "uses": actions/checkout@v4\n',
                     "jobs:\n  x:\n    steps:\n      - name: a\n        with: {persist-credentials: true}\n",
                     "x: &co\n  uses: actions/checkout@v4\njobs:\n  y:\n    steps:\n      - <<: *co\n",
                     "jobs:\n  x:\n    steps:\n      - uses: &u actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - name: a\n        with: *w\n",
                     "jobs:\n  x:\n    steps: [{run: echo}]\n",
                     # YAML explicit keys (PR #718 review round 3): `? uses` / `: owner/action@v4`
                     "jobs:\n  x:\n    steps:\n      - ? uses\n        : actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - name: a\n        ? run\n        : echo hi\n",
                     "jobs:\n  x:\n    steps:\n      -\n        ? uses\n        : actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - {? uses: actions/checkout@v4}\n",
                     # and the rest of the class: no line scan here reads these as written
                     "jobs:\n  x:\n    steps:\n      -   uses: actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - uses:\n          actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - !!str uses: actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - - uses: actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n    - uses: actions/checkout@v4\n",
                     "jobs:\n    x:\n      timeout-minutes: 0\n      steps:\n        - run: echo\n",
                     "jobs:\n  x:\n    steps:\n      - uses: \"actions/checkout@\n          v4\"\n",
                     "jobs:\n  x:\n    steps:\n      - name: a\u2028        uses: actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - run: |\n          echo\n"
                     "        'uses': actions/checkout@v4\n",
                     "jobs:\n  x:\n    steps:\n      - name: a\n        \"needs\": y\n"):
            with self.subTest(text=text):
                self.assertTrue(_structure_offenders("w.yml", text))
        script = ("jobs:\n  x:\n    steps:\n      - run: |\n          a && b {x}, y\n"
                  "          echo \"$ref\" 2>&1\n      - uses: a/b@" + "c" * 40 + "\n")
        self.assertEqual(_structure_offenders("w.yml", script), [], "a run: body is shell, not YAML")


class WorkflowsAreBoundedAndInjectionFree(unittest.TestCase):
    def test_the_scan_sees_every_workflow(self):
        self.assertGreaterEqual(len(WORKFLOWS), 10)
        self.assertGreaterEqual(sum(len(_jobs(p.read_text(encoding="utf-8")))
                                    for p in WORKFLOWS), 15)

    def test_every_job_declares_a_timeout(self):
        # Without one a hung job holds a runner for GitHub's 6-hour default.
        for path in WORKFLOWS:
            for job, body in _jobs(path.read_text(encoding="utf-8")).items():
                with self.subTest(workflow=path.name, job=job):
                    self.assertTrue(
                        any(re.match(r"^    timeout-minutes:\s*\d+\s*$", ln) for ln in body),
                        f"{path.name}:{job} has no job-level timeout-minutes")

    def test_no_run_script_interpolates_a_pr_controlled_context(self):
        for path in WORKFLOWS:
            for lineno, script in _run_scripts(path.read_text(encoding="utf-8")):
                with self.subTest(workflow=path.name, line=lineno):
                    self.assertIsNone(
                        _TAINTED_EXPR_RE.search(script),
                        f"{path.name}:{lineno} interpolates a PR-controlled context into "
                        "shell — pass it through env: and quote the variable")

    def test_the_injection_scan_can_actually_see_one(self):
        planted = ("jobs:\n  x:\n    steps:\n      - run: |\n"
                   "          echo ${{ github.base_ref }}\n")
        self.assertTrue(any(_TAINTED_EXPR_RE.search(s) for _, s in _run_scripts(planted)))
        self.assertEqual(list(_jobs(planted)), ["x"])


def _steps(job_lines):
    """A job's steps as lists of lines (each starts at its `      - ` item) — stdlib only."""
    steps, current, in_steps = [], None, False
    for line in job_lines:
        if re.match(r"^    steps:\s*$", line):
            in_steps = True
            continue
        if not in_steps:
            continue
        if re.match(r"^    \S", line):
            break
        if line.startswith("      - "):
            current = [line]
            steps.append(current)
        elif current is not None:
            current.append(line)
    return steps


def _step_name(step):
    for line in step:
        m = re.match(r"^\s*(?:- )?name:\s*(.*)$", line)
        if m:
            return m.group(1).strip()
    return ""


def _step_env(step):
    """{NAME: raw value} of a step's own `env:` map."""
    env, in_env = {}, False
    for line in step:
        if re.match(r"^        env:\s*$", line):
            in_env = True
            continue
        if in_env:
            m = re.match(r"^          ([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*$", line)
            if m:
                env[m.group(1)] = m.group(2)
            elif not line.strip().startswith("#"):
                in_env = False
    return env


def _step_script(step):
    """The step's `run:` body, dedented — what the runner hands the shell."""
    found = _run_scripts("\n".join(step))
    return textwrap.dedent(found[0][1]) if found else ""


def _bash(script, env, cwd=None):
    """Run a script the way a `run:` step with no `shell:` runs on Linux: `bash -e`."""
    full = {**os.environ, **env}
    full["PATH"] = os.path.dirname(sys.executable) + os.pathsep + full.get("PATH", "")
    return subprocess.run(["bash", "-e", "-c", script], env=full, cwd=cwd,
                          capture_output=True, text=True, timeout=60)


class TheWidenedInjectionScanSeesEveryContext(unittest.TestCase):
    """2026-10-23 review, §5 CI: the scan matched only base_ref, head_ref and event.*, so
    `steps.alert.outputs.*` sat inline in alert-on-failure.yml and nothing flagged it."""

    CONTEXTS = ("github.ref_name", "github.head_ref", "inputs.tag", "steps.alert.outputs.number",
                "needs.resolve.outputs.pr", "env.HEAD_BRANCH", "matrix.shard", "secrets.TOKEN",
                "github.event.pull_request.title")

    def test_every_context_class_inside_a_run_block_is_flagged(self):
        for ctx in self.CONTEXTS:
            for opener in ("run: |", "run: >-", "run:"):
                with self.subTest(context=ctx, opener=opener):
                    body = ("\n          echo ${{ %s }}\n" % ctx if opener != "run:"
                            else " echo ${{ %s }}\n" % ctx)
                    planted = "jobs:\n  x:\n    steps:\n      - " + opener + body
                    scripts = _run_scripts(planted)
                    self.assertTrue(scripts, "the planted run: block was not even found")
                    self.assertTrue(any(_TAINTED_EXPR_RE.search(s) for _, s in scripts),
                                    f"${{{{ {ctx} }}}} inside {opener!r} went unflagged")

    def test_an_expression_passed_through_env_is_not_a_script(self):
        # The fix the rule asks for must itself pass, or the rule could only be met by deletion.
        planted = ("jobs:\n  x:\n    steps:\n      - name: s\n        env:\n"
                   "          N: ${{ steps.alert.outputs.number }}\n"
                   "        run: |\n          echo \"$N\"\n")
        self.assertEqual([s for _, s in _run_scripts(planted) if _TAINTED_EXPR_RE.search(s)], [])

    def test_the_alert_workflow_reads_step_outputs_through_env(self):
        text = (ROOT / ".github" / "workflows" / "alert-on-failure.yml").read_text(encoding="utf-8")
        envs = {}
        for step in _steps(_jobs(text)["alert"]):
            envs.update(_step_env(step))
        self.assertEqual(envs.get("ISSUE_NUMBER"), "${{ steps.alert.outputs.number }}")
        self.assertEqual(envs.get("ALERT_ACTION"), "${{ steps.alert.outputs.action }}")


class EveryWorkflowToolComesFromAHashedLock(unittest.TestCase):
    """2026-10-23 review, §5 CI: fixture-target-app.yml ran an unpinned uvx ruff, the one tool
    install outside .github/ci-tools.lock. tests/test_pins.py pins validate.yml; this pins
    every workflow, so the next unpinned resolver fails wherever it lands."""

    UNLOCKED = re.compile(r"\buvx\b|\bpipx\s+run\b|\buv\s+tool\s+(run|install)\b")

    def _offenders(self, text):
        bad = []
        for lineno, script in _run_scripts(text):
            joined = script.replace("\\\n", " ")
            for line in joined.splitlines():
                code = line.split(" #", 1)[0]
                if self.UNLOCKED.search(code) or (
                        re.search(r"\bpip\s+install\b", code) and "--require-hashes" not in code):
                    bad.append(f"{lineno}: {line.strip()}")
        return bad

    def test_no_workflow_resolves_a_tool_outside_the_lock(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(self._offenders(path.read_text(encoding="utf-8")), [],
                                 f"{path.name} installs a tool by name, not by hash")

    def test_the_fixture_lint_installs_ruff_from_the_lock(self):
        text = (ROOT / ".github" / "workflows" / "fixture-target-app.yml").read_text(
            encoding="utf-8")
        scripts = "\n".join(s for _, s in _run_scripts("\n".join(_jobs(text)["ruff"])))
        self.assertIn("--require-hashes", scripts)
        self.assertIn(".github/ci-tools.lock", scripts)
        self.assertRegex(scripts, r"(?m)^\s*ruff check evals/demo/target-app\s*$")

    # 2026-10-27 security audit, W6-13: the fixture stack's seven `image:` refs were tags, which
    # a registry can re-point; `smoke` runs them. A digest names exactly one image index.
    IMAGE = re.compile(r"^\s*(?:-\s+)?image:\s*['\"]?([^\s'\"#]+)")
    PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")

    def _mutable_images(self, text):
        return [m.group(1) for ln in text.splitlines() if (m := self.IMAGE.match(ln))
                and not self.PINNED_IMAGE.match(m.group(1))]

    def test_every_container_image_is_pinned_by_digest(self):
        compose = (ROOT / "evals" / "demo" / "target-app" / "compose.yaml").read_text(
            encoding="utf-8")
        self.assertEqual(len([ln for ln in compose.splitlines() if self.IMAGE.match(ln)]), 7,
                         "the demo stack's image count changed; pin the new one by digest")
        self.assertEqual(self._mutable_images(compose), [],
                         "compose.yaml runs an image by a tag a registry can re-point")
        for path in WORKFLOWS:  # a job `container:` or `services:` image, should one appear
            with self.subTest(workflow=path.name):
                self.assertEqual(self._mutable_images(path.read_text(encoding="utf-8")), [])

    APP = ROOT / "evals" / "demo" / "target-app"

    def test_the_demo_containers_install_only_hashed_requirements(self):
        # PR #718 re-attack (W6-13 residual): the app containers ran `pip install -e .` against
        # the pyproject's `>=` ranges, resolved at run time, and pulled the build backend too.
        # They install the uv.lock export with --require-hashes and run the app from /srv/app.
        compose = (self.APP / "compose.yaml").read_text(encoding="utf-8")
        installs = [ln.strip() for ln in compose.splitlines()
                    if "pip install" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(len(installs), 2, "the app and staging containers each install once")
        for line in installs:
            with self.subTest(line=line):
                self.assertIn("pip install --quiet --require-hashes --only-binary :all: "
                              "-r requirements.lock", line)
                self.assertNotRegex(line, r"\s-e\s|--editable")

    def test_the_containers_lock_is_the_uv_lock(self):
        import tomllib
        lock = tomllib.loads((self.APP / "uv.lock").read_text(encoding="utf-8"))
        locked = {p["name"]: p["version"] for p in lock["package"] if "version" in p}
        text = (self.APP / "requirements.lock").read_text(encoding="utf-8")
        pinned = dict(re.findall(r"(?m)^([a-z0-9][a-z0-9._-]*)==([^\s;\\]+)", text))
        self.assertGreaterEqual(len(pinned), 10)
        for name, version in pinned.items():
            with self.subTest(package=name):
                self.assertEqual(locked.get(name), version, "re-export: uv export --frozen "
                                 "--no-dev --no-emit-project --format requirements-txt")
        blocks = re.split(r"(?m)^(?=[a-z0-9])", text)
        for block in (b for b in blocks if re.match(r"[a-z0-9]", b)):
            with self.subTest(block=block.split()[0]):
                self.assertIn("--hash=sha256:", block)
        project = tomllib.loads((self.APP / "pyproject.toml").read_text(encoding="utf-8"))
        wanted = {re.split(r"[<>=!~\[ ;]", d, maxsplit=1)[0].lower().replace("_", "-")
                  for d in project["project"]["dependencies"]}
        self.assertEqual(sorted(wanted - set(pinned)), [], "a runtime dependency is not pinned")
        # #750 C4: pyproject.toml must not declare an unlocked [build-system] (e.g. hatchling)
        # that `uv sync --locked` resolves dynamically outside uv.lock; package = false keeps the
        # fixture virtual in uv.lock.
        self.assertNotIn("build-system", project,
                         "pyproject.toml must not declare an unlocked [build-system]")
        self.assertIs(project.get("tool", {}).get("uv", {}).get("package"), False,
                      "pyproject.toml must set [tool.uv] package = false so uv sync builds no wheel")
        target_pkg = next(p for p in lock["package"] if p["name"] == "target-app")
        self.assertEqual(target_pkg.get("source"), {"virtual": "."},
                         "target-app in uv.lock must use a virtual source rather than editable build")

    def test_setup_uv_steps_pin_version_and_checksum(self):
        # #750 C4: astral-sh/setup-uv without version + checksum installs whatever uv binary is
        # latest at run time.
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            for job, body in _jobs(text).items():
                for step in _steps(body):
                    block = "\n".join(step)
                    if "astral-sh/setup-uv@" not in block:
                        continue
                    with self.subTest(workflow=path.name, job=job):
                        self.assertRegex(block, r'(?m)^\s*version:\s*"[0-9]+\.[0-9]+\.[0-9]+"\s*$')
                        self.assertRegex(block, r'(?m)^\s*checksum:\s*"[0-9a-f]{64}"\s*$')

    def test_the_image_scan_can_actually_see_one(self):
        digest = "@sha256:" + "c" * 64
        for ref in ("python:3.13-slim", "prom/prometheus:v2.53.0", "grafana/loki",
                    "python@sha256:" + "c" * 64, "python:3.13-slim@sha256:abc"):
            with self.subTest(ref=ref):
                self.assertEqual(self._mutable_images(f"    image: {ref}\n"), [ref])
        self.assertEqual(self._mutable_images(f"    image: python:3.13-slim{digest}\n"), [])

    def test_the_scan_can_actually_see_one(self):
        for line in ("uvx ruff check .", "pip install ruff==0.16.7",
                     "python3 -m pip install -r requirements.txt", "uv tool run ruff"):
            with self.subTest(line=line):
                self.assertTrue(self._offenders(
                    "jobs:\n  x:\n    steps:\n      - run: |\n          " + line + "\n"))
        self.assertEqual(self._offenders(
            "jobs:\n  x:\n    steps:\n      - run: |\n"
            "          python3 -m pip install --require-hashes --only-binary :all: \\\n"
            "            -r .github/ci-tools.lock\n"), [])


def _checkout_steps(text):
    """[(job, step lines)] for every actions/checkout step in a workflow's jobs."""
    return [(job, step) for job, body in _jobs(text).items() for step in _steps(body)
            if any(re.match(r"^\s*(?:- )?uses:\s*actions/checkout@", ln) for ln in step)]


class NoCheckoutLeavesItsTokenInTheTree(unittest.TestCase):
    """2026-10-27 security audit, W6-07: actions/checkout writes the run's token into the
    working tree's .git/config unless `persist-credentials: false`, and the PR-tree checkouts
    then ran the PR's own code (the suite, validate.py, floor_guard over the tree), which can
    read it. No step here pushes through that config: publish-dist pushes to an explicit URL
    from a fresh repository, and every other write goes through `gh` with GH_TOKEN."""

    PERSIST_OFF = re.compile(r"^\s+persist-credentials:\s*false\s*(?:#.*)?$")

    def _offenders(self, text):
        return [f"{job}: {step[0].strip()}" for job, step in _checkout_steps(text)
                if not any(self.PERSIST_OFF.match(ln) for ln in step)]

    def test_every_checkout_sets_persist_credentials_false(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertEqual(len(_checkout_steps(text)), text.count("actions/checkout@"),
                                 f"{path.name}: a checkout the step parser did not see")
                self.assertEqual(self._offenders(text), [],
                                 f"{path.name}: a checkout persists the run's token")

    def test_the_scan_can_actually_see_one(self):
        base = ("jobs:\n  x:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n"
                "        with:\n          fetch-depth: 0\n")
        self.assertEqual(len(self._offenders(base)), 1)
        self.assertEqual(self._offenders(base + "          persist-credentials: false\n"), [])
        self.assertEqual(len(self._offenders(base + "          persist-credentials: true\n")), 1)

    def test_no_step_pushes_through_the_checkouts_config(self):
        for path in WORKFLOWS:
            scripts = "\n".join(s for _, s in _run_scripts(path.read_text(encoding="utf-8")))
            for line in scripts.splitlines():
                if re.search(r"\bgit\b.*\bpush\b", line.split(" #", 1)[0]):
                    with self.subTest(workflow=path.name, line=line.strip()):
                        self.assertIn("x-access-token:${GITHUB_TOKEN}@github.com", line,
                                      "a push that relies on the token checkout persisted")


class EveryActionIsPinnedToACommit(unittest.TestCase):
    """2026-10-27 security audit, W6-15: every `uses:` was a full 40-hex SHA, held by reviewer
    attention alone. A tag (`@v4`) or branch can be moved under the workflow; a commit cannot."""

    USES = re.compile(r"^\s*(?:- )?uses:\s*([^\s#]+)")
    PINNED = re.compile(r"^(?:[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}"
                        r"|docker://[^@\s]+@sha256:[0-9a-f]{64}|\./[^@\s]+)$")

    def _unpinned(self, text):
        return [m.group(1) for ln in text.splitlines() if (m := self.USES.match(ln))
                and not self.PINNED.match(m.group(1))]

    def _hidden_or_unpinned(self, name, text):
        """Every ref USES reads that is not pinned, and every line that puts the file outside the
        block subset USES reads as written (PR #718 review round 3: an explicit `? uses` key, or
        `-   uses:`, was a `uses:` this scan never saw, so the pin test stayed green)."""
        return _structure_offenders(name, text) + self._unpinned(text)

    def test_every_uses_is_a_full_commit_sha(self):
        seen = 0
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            seen += sum(1 for ln in text.splitlines() if self.USES.match(ln))
            with self.subTest(workflow=path.name):
                self.assertEqual(self._unpinned(text), [],
                                 f"{path.name} uses an action by a movable ref")
                self.assertEqual(self._hidden_or_unpinned(path.name, text), [],
                                 f"{path.name} may hold a `uses:` this scan cannot see")
        self.assertGreaterEqual(seen, 40, "the scan stopped seeing the workflows' actions")

    def test_a_uses_key_this_scan_cannot_read_is_refused(self):
        pinned = "      - uses: actions/checkout@" + "a" * 40 + "\n"
        for hidden in ("      - ? uses\n        : owner/action@v4\n",
                       "      -\n        ? uses\n        : owner/action@v4\n",
                       "      - {? uses: owner/action@v4}\n",
                       "      -   uses: owner/action@v4\n",
                       "      - uses:\n          owner/action@v4\n",
                       "      - !!str uses: owner/action@v4\n",
                       "      - \"uses\": owner/action@v4\n",
                       "      - uses: &a owner/action@v4\n"):
            text = "jobs:\n  x:\n    steps:\n" + pinned + hidden
            with self.subTest(hidden=hidden):
                self.assertTrue(self._hidden_or_unpinned("w.yml", text))
        self.assertEqual(self._hidden_or_unpinned("w.yml", "jobs:\n  x:\n    steps:\n" + pinned), [])

    def test_the_scan_can_actually_see_one(self):
        for ref in ("actions/checkout@v4", "actions/checkout@main", "actions/checkout",
                    "actions/checkout@3d3c42e", "docker://alpine:3.20",
                    "owner/repo/path@" + "A" * 40):
            with self.subTest(ref=ref):
                self.assertEqual(self._unpinned(f"      - uses: {ref}\n"), [ref])
        for ref in ("actions/checkout@" + "a" * 40, "./.github/actions/setup",
                    "docker://alpine@sha256:" + "b" * 64):
            with self.subTest(ref=ref):
                self.assertEqual(self._unpinned(f"        uses: {ref} # v1\n"), [])


def _workflow_name(text):
    m = re.search(r"(?m)^name:\s*(.+?)\s*$", text)
    return m.group(1).strip("'\"") if m else None


class TheAlertPathNamesWorkflowsThatExist(unittest.TestCase):
    """2026-10-27 security audit, W6-17: `workflow_run` matches workflows by display `name:`,
    and main-health and the release gate ask for runs by file or name. A rename left the alert
    path silently blind (nothing fires, CI stays green), so each reference must name a real
    workflow, and the two alert paths must watch the same thing."""

    NAMES = {_workflow_name(p.read_text(encoding="utf-8")): p.name for p in WORKFLOWS}

    @staticmethod
    def _workflow_run_lists(text):
        on = text.split("\non:\n", 1)[1].split("\n\n", 1)[0] if "\non:\n" in text else ""
        block = on.split("  workflow_run:\n", 1)[1] if "  workflow_run:\n" in on else ""
        m = re.search(r"(?m)^    workflows:\s*\[([^\]]*)\]", block)
        return [w.strip().strip("'\"") for w in m.group(1).split(",")] if m else None

    def test_every_workflow_has_a_unique_name(self):
        self.assertNotIn(None, self.NAMES)
        self.assertEqual(len(self.NAMES), len(WORKFLOWS), "two workflows share a name")

    def test_every_workflow_run_trigger_names_a_real_workflow(self):
        found = 0
        for path in WORKFLOWS:
            watched = self._workflow_run_lists(path.read_text(encoding="utf-8"))
            if watched is None:
                continue
            found += 1
            for name in watched:
                with self.subTest(workflow=path.name, watches=name):
                    self.assertIn(name, self.NAMES, f"{path.name} watches a workflow named "
                                                    f"{name!r}, and none has that name")
        self.assertGreaterEqual(found, 2, "alert-on-failure and verdict-gate both watch by name")

    def test_the_alert_watches_validate_and_the_demo_by_their_real_names(self):
        watched = self._workflow_run_lists(
            (ROOT / ".github" / "workflows" / "alert-on-failure.yml").read_text(encoding="utf-8"))
        self.assertEqual({self.NAMES.get(n) for n in watched},
                         {"validate.yml", "negative-control.yml"})

    def test_main_health_reads_a_watched_workflow_file(self):
        text = (ROOT / ".github" / "workflows" / "main-health.yml").read_text(encoding="utf-8")
        files = re.findall(r"gh run list --workflow (\S+)", text)
        self.assertTrue(files, "main-health no longer asks for a workflow's runs")
        watched = self._workflow_run_lists(
            (ROOT / ".github" / "workflows" / "alert-on-failure.yml").read_text(encoding="utf-8"))
        for ref in files:
            with self.subTest(ref=ref):
                self.assertTrue((ROOT / ".github" / "workflows" / ref).is_file(),
                                f"main-health reads {ref}, which is not a workflow file")
                self.assertIn(_workflow_name((ROOT / ".github" / "workflows" / ref)
                                             .read_text(encoding="utf-8")), watched,
                              "main-health watches a workflow the alert does not")

    def test_the_release_gate_asks_for_workflows_that_exist(self):
        source = (ROOT / "scripts" / "release_check.py").read_text(encoding="utf-8")
        asked = re.findall(r'check_workflow_green_at_head\(ctx, "gate\d", "([^"]+)"\)', source)
        self.assertGreaterEqual(len(asked), 2)
        for name in asked:
            with self.subTest(workflow=name):
                self.assertIn(name, self.NAMES, f"release_check asks gh for {name!r} runs")


class EveryToolModuleRunsIsolated(unittest.TestCase):
    """PR #718 re-attack (W6-01 class, W3-01 in CI): `python3 -m pip` / `-m unittest`, `-c` and
    `python3 -` put the working directory, the PR's checkout, first on sys.path, so a PR's root
    `pip/` or `json.py` ran instead of the tool. Every such invocation in a workflow carries
    `-I` (isolated: no working directory, no user site, no PYTHON* variables). The demo app's own
    module under `uv run` is the code under test, not a tool."""

    UNISOLATED = re.compile(r"\bpython3?((?:\s+-[A-Za-z]+)*?)\s+(-m\b|-c\b|-(?=\s|$))")

    def _offenders(self, text):
        bad = []
        for lineno, script in _run_scripts(text):
            for line in script.replace("\\\n", " ").splitlines():
                code = line.split(" #", 1)[0]
                if re.search(r"\buv\s+run\s+python\b", code):
                    continue
                for m in self.UNISOLATED.finditer(code):
                    if "-I" not in m.group(1).split():
                        bad.append(f"{lineno}: {line.strip()}")
        return bad

    def test_every_tool_module_and_inline_script_runs_with_dash_i(self):
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertEqual(self._offenders(path.read_text(encoding="utf-8")), [])

    def test_the_scan_can_actually_see_one(self):
        for line in ("python3 -m pip install -r x", "python3 - <<'PY'", "python3 -c 'import glob'",
                     "PATH=x python3 -m unittest discover -s tests", "python -m coverage report",
                     "python3 -u -m pip install x"):
            with self.subTest(line=line):
                self.assertTrue(self._offenders(
                    "jobs:\n  x:\n    steps:\n      - run: |\n          " + line + "\n"))
        for line in ("python3 -I -m pip install -r x", "python3 -I - <<'PY'",
                     "python3 -I -c 'import glob'", "python3 scripts/validate.py",
                     "uv run python -m app.seed --count 0"):
            with self.subTest(line=line):
                self.assertEqual(self._offenders(
                    "jobs:\n  x:\n    steps:\n      - run: |\n          " + line + "\n"), [])


class TagPublishersRefuseAnyoneButTheMaintainer(unittest.TestCase):
    """2026-10-23 review, P2-23: release.yml and publish-dist.yml published on ANY `v*` tag push
    with `contents: write` (publish-dist force-pushes `dist`), while docs/ops.md says only the
    owner authorizes a cut. Each publisher's first step now refuses any other actor; the step is
    run here, not just read, so a guard that cannot fail is caught."""

    PUBLISHERS = ("release.yml", "publish-dist.yml")
    STEP = "Only the release maintainer publishes"

    def _guard(self, name):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        jobs = _jobs(text)
        self.assertEqual(len(jobs), 1, f"{name}: expected its one publishing job")
        steps = _steps(next(iter(jobs.values())))
        self.assertTrue(steps, f"{name}: no steps parsed")
        return text, steps

    def test_the_guard_is_the_first_step_of_every_publisher(self):
        for name in self.PUBLISHERS:
            with self.subTest(workflow=name):
                _, steps = self._guard(name)
                self.assertEqual(_step_name(steps[0]), self.STEP,
                                 f"{name}: something runs before the maintainer guard")
                env = _step_env(steps[0])
                self.assertEqual(env.get("RELEASE_MAINTAINER"), "${{ github.repository_owner }}")
                self.assertEqual(env.get("RUN_ACTOR"), "${{ github.actor }}")
                self.assertEqual(env.get("RUN_TRIGGERING_ACTOR"),
                                 "${{ github.triggering_actor }}")

    def test_the_guard_refuses_every_actor_but_the_owner(self):
        cases = (("ravidsrk", "ravidsrk", "ravidsrk", 0),
                 ("ravidsrk", "a-writer", "a-writer", 1),
                 ("ravidsrk", "ravidsrk", "a-writer", 1),
                 ("ravidsrk", "a-writer", "ravidsrk", 1),
                 ("", "", "", 1))
        for name in self.PUBLISHERS:
            script = _step_script(self._guard(name)[1][0])
            self.assertTrue(script.strip(), f"{name}: the guard step has no run: body")
            for owner, actor, trigger, want in cases:
                with self.subTest(workflow=name, actor=actor, triggering=trigger):
                    r = _bash(script, {"RELEASE_MAINTAINER": owner, "RUN_ACTOR": actor,
                                       "RUN_TRIGGERING_ACTOR": trigger})
                    self.assertEqual(r.returncode != 0, bool(want), r.stdout + r.stderr)
                    if want:
                        self.assertIn("::error::", r.stdout)

    def test_the_tag_commit_must_be_on_main(self):
        for name in self.PUBLISHERS:
            with self.subTest(workflow=name):
                text, _ = self._guard(name)
                scripts = "\n".join(s for _, s in _run_scripts(text))
                self.assertRegex(scripts, r'git merge-base --is-ancestor "\$cut" origin/main\b')


_GIT_FIXTURE_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def _publisher_steps(name):
    text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    return _steps(next(iter(_jobs(text).values())))


def _named_step(steps, title):
    found = [s for s in steps if _step_name(s).strip("\"'") == title]
    return found[0] if len(found) == 1 else None


class TheReleaseTagIsCheckedBeforeAnythingFetchesIt(unittest.TestCase):
    """2026-10-27 security audit, W6-16 and W6-11: publish-dist resolved the dispatch tag in the
    checkout's `ref:` and only shape-checked it a step later, and release.yml never shape-checked
    it at all, so `-f tag=anything` published a Release for any existing tag. Both publishers now
    check the tag is a release version before the checkout, and the checkout takes the checked
    value."""

    PUBLISHERS = ("release.yml", "publish-dist.yml")
    STEP = "The tag is a release version, checked before anything fetches it"
    GOOD = ("v0.1.0", "v1.0.0", "v10.20.30")
    BAD = ("main", "v1", "v1.0", "v1.0.0-rc1", "v1.0.0 ", " v1.0.0", "v1.0.0\nmain",
           "refs/tags/v1.0.0", "v1.0.0:refs/heads/x", "-v1.0.0", "v01x.0.0", "")

    def _check(self, name):
        steps = _publisher_steps(name)
        step = _named_step(steps, self.STEP)
        self.assertIsNotNone(step, f"{name}: no tag check step")
        return steps, step

    def test_the_check_runs_after_the_maintainer_guard_and_before_the_checkout(self):
        for name in self.PUBLISHERS:
            with self.subTest(workflow=name):
                steps, step = self._check(name)
                checkout = next(i for i, s in enumerate(steps)
                                if any("actions/checkout@" in ln for ln in s))
                self.assertEqual(steps.index(step), 1, f"{name}: the tag check is not second")
                self.assertLess(steps.index(step), checkout)

    def test_only_a_release_version_passes(self):
        for name in self.PUBLISHERS:
            _, step = self._check(name)
            script = _step_script(step)
            for tag in self.GOOD + self.BAD:
                with self.subTest(workflow=name, tag=tag), tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / "out"
                    out.write_text("", encoding="utf-8")
                    r = _bash(script, {"TAG": tag, "GITHUB_OUTPUT": str(out)})
                    if tag in self.GOOD:
                        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                        self.assertEqual(out.read_text(encoding="utf-8"),
                                         f"tag={tag}\nref=refs/tags/{tag}\n")
                    else:
                        self.assertNotEqual(r.returncode, 0, f"{tag!r} passed")
                        self.assertIn("::error::", r.stdout)
                        self.assertEqual(out.read_text(encoding="utf-8"), "")

    def test_the_tag_reaches_the_check_through_env(self):
        for name, want in (("release.yml", "${{ github.event.inputs.tag || github.ref_name }}"),
                           ("publish-dist.yml", "${{ github.event_name == 'workflow_dispatch' "
                                                "&& inputs.tag || github.ref_name }}")):
            with self.subTest(workflow=name):
                self.assertEqual(_step_env(self._check(name)[1]).get("TAG"), want)

    def test_publish_dist_checks_out_the_checked_ref(self):
        steps, _ = self._check("publish-dist.yml")
        checkout = next(s for s in steps if any("actions/checkout@" in ln for ln in s))
        refs = [ln.strip() for ln in checkout if ln.strip().startswith("ref:")]
        self.assertEqual(refs, ["ref: ${{ steps.tag.outputs.ref }}"])
        self.assertIn("id: tag", "\n".join(self._check("publish-dist.yml")[1]))


class AReleaseForAnOlderTagIsNeverLatest(unittest.TestCase):
    """W6-11: release.yml had no newest-tag guard and no `--latest=false`, so publishing a
    missing historical Release (docs/ops.md backfills nine that way) moved GitHub's "Latest"
    onto it. The step is run here against a real repository and a stub `gh`."""

    STEP = "Publish the Release (idempotent)"

    def _run(self, tag, remote_only=()):
        """Run the publish step in a clone whose `origin` (a local bare repository) holds the
        clone's tags plus `remote_only`, which the clone itself never fetched."""
        script = _step_script(_named_step(_publisher_steps("release.yml"), self.STEP))
        self.assertTrue(script.strip(), "the publish step has no run: body")
        with tempfile.TemporaryDirectory() as tmp:
            repo, bin_dir, origin = Path(tmp) / "repo", Path(tmp) / "bin", Path(tmp) / "origin.git"
            repo.mkdir()
            bin_dir.mkdir()
            git = lambda *a: subprocess.run(["git", *a], cwd=repo, env={**os.environ, **_GIT_FIXTURE_ENV},
                                            check=True, capture_output=True, text=True)
            git("init", "-q", "-b", "main")
            git("init", "-q", "--bare", str(origin))
            git("remote", "add", "origin", str(origin))
            for version in ("v0.9.0", "v0.10.0", *remote_only):
                git("commit", "-q", "--allow-empty", "-m", version)
                git("tag", "-a", version, "-m", version)
            git("push", "-q", "origin", "main", "--tags")
            for version in remote_only:  # published by another run after this one checked out
                git("tag", "-d", version)
                git("reset", "-q", "--hard", "HEAD~1")
            git("fetch", "-q", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
            git("update-ref", "refs/remotes/origin/main", "HEAD")
            log = Path(tmp) / "gh.log"
            (bin_dir / "gh").write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GH_LOG\"\n"
                "[ \"$1 $2\" = 'release view' ] && exit 1\nexit 0\n", encoding="utf-8")
            (bin_dir / "gh").chmod(0o755)
            # The stub must shadow any real gh: PATH starts with it, nothing is prepended, and
            # GH_REPO, GH_TOKEN and GH_CONFIG_DIR give a real gh no repository and no login.
            env = {**os.environ, **_GIT_FIXTURE_ENV, "TAG": tag, "GH_LOG": str(log),
                   "cut": "0" * 40, "RUNNER_TEMP": tmp, "GH_REPO": "invalid/invalid",
                   "GH_TOKEN": "", "GH_CONFIG_DIR": str(Path(tmp) / "no-gh-config"),
                   "GITHUB_STEP_SUMMARY": str(Path(tmp) / "summary"),
                   "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
            r = subprocess.run(["bash", "-e", "-c", script], env=env, cwd=repo,
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue(log.is_file(), "the step never reached the stub gh")
            return [ln for ln in log.read_text(encoding="utf-8").splitlines()
                    if ln.startswith("release create")]

    def test_the_newest_release_is_latest_and_an_older_one_is_not(self):
        newest = self._run("v0.10.0")  # version order, not string order: 0.10 > 0.9
        self.assertEqual(len(newest), 1)
        self.assertIn("--latest", newest[0].split())
        older = self._run("v0.9.0")
        self.assertEqual(len(older), 1)
        self.assertIn("--latest=false", older[0].split())
        self.assertNotIn("--latest", older[0].split())

    def test_a_newer_tag_only_the_remote_has_already_outranks_this_one(self):
        # PR #718 review (P2): a run that read its tag list before a newer release landed
        # marked its own older tag Latest after the newer one did. The decision is read from
        # the remote at the moment of publishing, so a tag this checkout never saw counts.
        stale = self._run("v0.10.0", remote_only=("v0.11.0",))
        self.assertEqual(len(stale), 1)
        self.assertIn("--latest=false", stale[0].split())
        self.assertNotIn("--latest", stale[0].split())

    def test_the_newest_tag_is_read_from_the_remote_just_before_publishing(self):
        script = _step_script(_named_step(_publisher_steps("release.yml"), self.STEP))
        lines = [ln.strip() for ln in script.splitlines()]
        read = [i for i, ln in enumerate(lines) if ln.startswith("newest=")]
        self.assertEqual(len(read), 1, "the step no longer decides the newest tag once")
        self.assertIn("git ls-remote --tags --refs origin", lines[read[0]])
        self.assertNotIn("git tag", lines[read[0]], "the newest tag comes from the checkout")
        view = next(i for i, ln in enumerate(lines) if ln.startswith("if gh release view"))
        create = next(i for i, ln in enumerate(lines) if ln.startswith("gh release create"))
        self.assertLess(view, read[0])
        self.assertLess(read[0], create)
        self.assertFalse([ln for ln in lines[read[0] + 1:create] if "git " in ln or "gh " in ln],
                         "something runs between the fresh read and the publish")

    def test_each_publisher_runs_one_at_a_time_in_a_group_of_its_own(self):
        # One running and one pending per group, never cancelled mid-run. Not one shared
        # group: GitHub cancels a group's pending run when another is queued, so a shared group
        # would let one workflow's run cancel the other's pending run for a different tag.
        groups = {}
        for name in ("release.yml", "publish-dist.yml"):
            text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            m = re.search(r"(?m)^concurrency:\n  group: (\S+)\n  cancel-in-progress: false\n", text)
            with self.subTest(workflow=name):
                self.assertIsNotNone(m, f"{name}: no top-level, never-cancelling concurrency")
                self.assertNotIn("${{", m.group(1), "a per-run group serializes nothing")
                groups[name] = m.group(1)
        self.assertEqual(groups.get("release.yml"), "release")
        self.assertEqual(groups.get("publish-dist.yml"), "publish-dist")


class TheDistIndexIsExactlyTheBundle(unittest.TestCase):
    """2026-10-27 security audit, W6-04 (publish half): `git add -A` in the fresh dist repository
    honoured any .gitignore the bundle carried, so a committed `skills/<m>/.gitignore` of `*.md`
    dropped that mission's prose from `dist` while its own bundle-files.json still listed it. The
    staging step is run here on a built-looking tree."""

    STEP = "Stage the bundle exactly as built"

    def _stage(self, files, git_env=None):
        steps = _publisher_steps("publish-dist.yml")
        step = _named_step(steps, self.STEP)
        self.assertIsNotNone(step, "publish-dist has no staging step of its own")
        publish = _named_step(steps, "Publish to the dist branch")
        self.assertLess(steps.index(step), steps.index(publish))
        self.assertNotRegex(_step_script(publish), r"\bgit\s+(add|init)\b",
                            "the publish step stages on its own again")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        dist = Path(tmp.name) / "dist"
        for rel, body in files.items():
            (dist / rel).parent.mkdir(parents=True, exist_ok=True)
            (dist / rel).write_text(body, encoding="utf-8")
        env = {**_GIT_FIXTURE_ENV, **(git_env or {}), "RUNNER_TEMP": tmp.name}
        r = _bash(_step_script(step), env, cwd=tmp.name)
        listed = subprocess.run(["git", "-C", str(dist), "ls-files"], capture_output=True,
                                text=True, env={**os.environ, **_GIT_FIXTURE_ENV}).stdout.split()
        return r, listed

    MISSION = {
        "skills/m/SKILL.md": "# m\n",
        "skills/m/notes.md": "notes\n",
        "skills/m/references/bundle-files.json": '[".gitignore", "SKILL.md", "notes.md"]\n',
        "README.md": "dist\n",
    }

    def test_a_nested_ignore_file_drops_nothing(self):
        files = {**self.MISSION, "skills/m/.gitignore": "*.md\n", ".gitignore": "*\n"}
        r, listed = self._stage(files)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(listed), sorted(files))

    def test_a_filter_that_rewrites_a_file_fails_the_stage(self):
        files = {**self.MISSION, "skills/m/.gitattributes": "*.md filter=swap\n"}
        files["skills/m/references/bundle-files.json"] = \
            '[".gitattributes", "SKILL.md", "notes.md"]\n'
        with tempfile.TemporaryDirectory() as cfg:
            config = Path(cfg) / "gitconfig"
            config.write_text("[filter \"swap\"]\n\tclean = tr a-z A-Z\n", encoding="utf-8")
            r, _ = self._stage(files, {"GIT_CONFIG_GLOBAL": str(config)})
        self.assertNotEqual(r.returncode, 0, "a clean filter changed what dist would publish")
        self.assertIn("::error::", r.stdout)

    def test_an_inventory_entry_missing_from_the_tree_fails_the_stage(self):
        files = dict(self.MISSION)
        files["skills/m/references/bundle-files.json"] = '["SKILL.md", "gone.md"]\n'
        r, _ = self._stage(files)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("skills/m/gone.md", r.stdout)


def _run_with_stub(script, env, cwd, stub_name, stub_body):
    """Run a step script under `bash -e` with a stub command FIRST on PATH (nothing prepended,
    unlike _bash), returning (result, the stub's argv log)."""
    with tempfile.TemporaryDirectory() as bin_dir:
        log = Path(bin_dir) / "argv.log"
        stub = Path(bin_dir) / stub_name
        stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STUB_LOG\"\n" + stub_body,
                        encoding="utf-8")
        stub.chmod(0o755)
        full = {**os.environ, **env, "STUB_LOG": str(log),
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
        r = subprocess.run(["bash", "-e", "-c", script], env=full, cwd=cwd,
                           capture_output=True, text=True, timeout=60)
        return r, (log.read_text(encoding="utf-8").splitlines() if log.is_file() else [])


class TheCoverageFloorReadsOnlyTheShardsOwnFiles(unittest.TestCase):
    """2026-10-27 security audit, W6-02: each shard uploaded `.coverage.*` from the checkout root
    (the PR's tree) with hidden files included, and gates combined whatever landed in its own
    checkout root, so a test that saved a padded data file as `./.coverage.pad` lifted the D9
    floor. The shard's data now goes to the runner's temp dir, is renamed to one exact name per
    shard and uploaded alone, and gates combines exactly those six files from a directory of
    its own: the checkout-glob instance (a planted `.coverage.*` file) is closed. The PR's tests
    still run inside the measured process and can add lines to the live tracer, so coverage
    remains the PR's own measurement of itself, an accepted residual (PR #718 review)."""

    TEXT = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    SHARDS = ("1", "2", "3", "4", "5", "6")

    def _step(self, job, title):
        step = _named_step(_steps(_jobs(self.TEXT)[job]), title)
        self.assertIsNotNone(step, f"validate.yml {job}: no step {title!r}")
        return step

    @staticmethod
    def _with(step, key):
        values = [m.group(1) for ln in step if (m := re.match(rf"^\s+{key}:\s*(.*?)\s*$", ln))]
        return values[0] if values else None

    def test_the_floor_claims_no_more_than_it_closes(self):
        # PR #718 review (P2): a test can still add lines to the live tracer
        # (coverage.Coverage.current().get_data().add_lines(...)), and they land in the one
        # legitimate shard file. The floor step must say which instance is closed and that the
        # rest is an accepted residual, not that the numbers are the suite's own.
        floor = self._step("gates", "Coverage floor (D9: line >= 80% on scripts + runtime/scripts)")
        said = " ".join(" ".join(ln.strip().lstrip("#").strip() for ln in floor
                                 if ln.strip().startswith("#")).split())
        self.assertIn("the checkout-glob instance (a planted `.coverage.*` file) is closed", said)
        self.assertIn("coverage remains the PR's own measurement of itself, an accepted residual",
                      said)

    def test_the_shard_writes_its_data_outside_the_checkout(self):
        script = _step_script(self._step("tests", "Run suite shard without Gitleaks"))
        export = script.find('export COVERAGE_FILE="$RUNNER_TEMP/coverage-data/shard"')
        self.assertGreaterEqual(export, 0, "the shard's data file is not redirected")
        self.assertLess(export, script.find("shard-tests.py"))

    def test_one_exact_file_is_uploaded(self):
        step = self._step("tests", "Upload the shard coverage data")
        path = self._with(step, "path")
        self.assertEqual(path, "${{ runner.temp }}/coverage-upload/"
                               "coverage-shard-${{ matrix.shard }}.data")
        self.assertNotRegex(path.replace("${{ runner.temp }}", "")
                                .replace("${{ matrix.shard }}", ""), r"[*?\[]")
        self.assertNotIn("include-hidden-files", self.TEXT)

    def test_the_shard_names_exactly_one_data_file(self):
        script = _step_script(self._step("tests", "Name the shard's one coverage data file"))
        for written, ok in ((["shard.host.123.abc"], True), ([], False),
                            (["shard.host.1.a", "shard.host.2.b"], False)):
            with self.subTest(written=written), tempfile.TemporaryDirectory() as tmp:
                data = Path(tmp) / "coverage-data"
                data.mkdir()
                for name in written:
                    (data / name).write_text(name, encoding="utf-8")
                r = _bash(script, {"RUNNER_TEMP": tmp, "SHARD": "3"}, cwd=tmp)
                uploaded = Path(tmp) / "coverage-upload" / "coverage-shard-3.data"
                self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)
                if ok:
                    self.assertEqual(uploaded.read_text(encoding="utf-8"), written[0])
                else:
                    self.assertIn("::error::", r.stdout)
                    self.assertFalse(uploaded.exists())

    def test_gates_downloads_into_a_directory_of_its_own(self):
        step = self._step("gates", "Download the shard coverage data")
        self.assertEqual(self._with(step, "path"), "${{ runner.temp }}/coverage-shards")
        self.assertEqual(self._with(step, "pattern"), "coverage-shard-*")

    def _floor(self, downloaded, planted_in_tree=()):
        script = _step_script(self._step(
            "gates", "Coverage floor (D9: line >= 80% on scripts + runtime/scripts)"))
        with tempfile.TemporaryDirectory() as tmp:
            shards, tree = Path(tmp) / "coverage-shards", Path(tmp) / "tree"
            shards.mkdir()
            tree.mkdir()
            for name in downloaded:
                (shards / name).write_text("data", encoding="utf-8")
            for name in planted_in_tree:
                (tree / name).write_text("padded", encoding="utf-8")
            r, calls = _run_with_stub(script, {"RUNNER_TEMP": tmp}, tree, "coverage", "exit 0\n")
            return r, calls, tmp

    def test_the_floor_combines_exactly_the_six_shard_files(self):
        names = [f"coverage-shard-{n}.data" for n in self.SHARDS]
        r, calls, tmp = self._floor(names, planted_in_tree=(".coverage.pad", ".coverage"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(len(calls), 2, calls)
        self.assertEqual(calls[0].split(), ["combine"] + [f"{tmp}/coverage-shards/{n}"
                                                          for n in names])
        self.assertEqual(calls[1].split(), ["report"])

    def test_a_missing_or_extra_data_file_fails_before_anything_is_combined(self):
        names = [f"coverage-shard-{n}.data" for n in self.SHARDS]
        for downloaded in (names[:5], names + [".coverage.pad"], names + ["coverage-shard-7.data"]):
            with self.subTest(downloaded=downloaded):
                r, calls, _ = self._floor(downloaded)
                self.assertNotEqual(r.returncode, 0, "the floor ran on the wrong data files")
                self.assertIn("::error::", r.stdout)
                self.assertEqual(calls, [])


class TheNegativeControlDiagnosticIsReachable(unittest.TestCase):
    """2026-10-23 review, §5 CI: `set -uo pipefail` under the runner's default `bash -e` ended
    the step on the pipeline, so the "demo itself is RED" diagnostic never printed. The step is
    run here under `bash -e` with a stub run.sh, so the diagnostic must actually appear."""

    def _script(self):
        text = (ROOT / ".github" / "workflows" / "negative-control.yml").read_text(
            encoding="utf-8")
        steps = [s for s in _steps(_jobs(text)["pinned-demo"])
                 if "evals/demo/negative-control/run.sh" in "\n".join(s)
                 and "DRIFTED" in "\n".join(s)]
        self.assertEqual(len(steps), 1, "the demo step is gone")
        return _step_script(steps[0])

    def _run(self, stub_body, pinned):
        with tempfile.TemporaryDirectory() as tmp:
            demo = Path(tmp) / "evals" / "demo" / "negative-control"
            demo.mkdir(parents=True)
            (demo / "run.sh").write_text(stub_body, encoding="utf-8")
            (demo / "head-to-head.txt").write_text(pinned, encoding="utf-8")
            return _bash(self._script(), {}, cwd=tmp)

    def test_a_red_demo_prints_its_diagnostic_and_fails(self):
        r = self._run("echo partial output\nexit 3\n", "partial output\n")
        self.assertNotEqual(r.returncode, 0, "a red demo passed the gate")
        self.assertIn("the demo itself is RED", r.stdout, r.stdout + r.stderr)
        self.assertIn("exited 3", r.stdout)

    def test_a_drifted_demo_fails_as_drift(self):
        r = self._run("echo fresh output\n", "pinned output\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("DRIFTED", r.stdout, r.stdout + r.stderr)

    def test_a_matching_demo_passes(self):
        r = self._run("echo same output\n", "same output\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("matches pinned expectations", r.stdout)


_ct_spec = importlib.util.spec_from_file_location(
    "_check_trailers", ROOT / "scripts" / "check_trailers.py")
check_trailers = importlib.util.module_from_spec(_ct_spec)
_ct_spec.loader.exec_module(check_trailers)

# A git that reads no user or system config: the host's signing, hooks and log settings
# cannot leak into the fixture repos or into what check_trailers.py reads from them.
_HERMETIC_GIT = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                 "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


class CommitTrailersAreRefused(unittest.TestCase):
    """#628 / 2026-10-23 review, §5 Commit hygiene: CONTRIBUTING.md forbids co-author and
    tool-attribution trailers, and 12 of the last 200 commits on main carried them because
    nothing checked. scripts/check_trailers.py reads a PR's own range; these fixtures are real
    repositories, because the mechanism starts from `git log BASE..HEAD`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name).resolve()
        self._env = mock.patch.dict(os.environ, _HERMETIC_GIT)
        self._env.start()
        self._git("init", "-q", ".")
        self.base = self._commit("chore: base")

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def _git(self, *args, stdin=None):
        return subprocess.run(["git", "-C", str(self.repo), "-c", "commit.gpgsign=false",
                               "-c", "core.hooksPath=" + os.devnull, *args],
                              input=stdin, capture_output=True, text=True, check=True).stdout

    def _commit(self, message):
        self._git("commit", "--allow-empty", "-q", "-F", "-", stdin=message)
        return self._git("rev-parse", "HEAD").strip()

    def _check(self, base=None, head="HEAD"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = check_trailers.main(["--base", base or self.base, "--head", head,
                                        "--root", str(self.repo)])
        return code, out.getvalue()

    def test_a_clean_range_passes(self):
        self._commit("docs: say why Co-authored-by trailers are refused\n\n"
                     "Generated with uv pip compile --generate-hashes, as before.\n\n"
                     "Signed-off-by: t <t@example.com>\n")
        code, out = self._check()
        self.assertEqual(code, 0, out)
        self.assertIn("1 commit(s)", out)

    def test_a_co_author_trailer_is_refused_in_any_case(self):
        for key in ("Co-authored-by", "Co-Authored-By", "CO-AUTHORED-BY", "co-authored-by",
                    "Co-developed-by"):
            with self.subTest(key=key):
                sha = self._commit(f"fix: a thing\n\nBody.\n\n{key}: Bot <bot@example.com>\n")
                code, out = self._check()
                self.assertEqual(code, 1, out)
                self.assertIn(f"{sha[:12]} co-author: {key}:", out)
                self.base = sha  # the next case starts from a clean range

    def test_a_tool_attribution_line_is_refused(self):
        for line in ("\N{ROBOT FACE} Generated with [Claude Code](https://claude.com/claude-code)",
                     "Generated by GitHub Copilot", "generated-by: an agent",
                     "Assisted-by: Cursor", "AI-Assisted-By: Gemini"):
            with self.subTest(line=line):
                sha = self._commit(f"feat: x\n\n{line}\n")
                code, out = self._check()
                self.assertEqual(code, 1, out)
                self.assertIn(f"{sha[:12]} tool-attribution:", out)
                self.base = sha

    def test_history_below_the_base_is_never_read(self):
        old = self._commit("fix: old\n\nCo-authored-by: Bot <bot@example.com>\n")
        self._commit("fix: new and clean\n")
        self.assertEqual(self._check(base=old)[0], 0)
        self.assertEqual(self._check(base=self.base)[0], 1, "the fixture trailer was not seen")

    def test_a_merge_commit_in_the_range_is_read(self):
        main = self._git("rev-parse", "--abbrev-ref", "HEAD").strip()
        self._git("checkout", "-q", "-b", "side")
        self._commit("feat: side work\n")
        self._git("checkout", "-q", main)
        self._commit("feat: main work\n")
        self._git("merge", "--no-ff", "-q", "side", "-m", "Merge side",
                  "-m", "Co-authored-by: Bot <bot@example.com>")
        code, out = self._check()
        self.assertEqual(code, 1, out)
        self.assertIn("co-author", out)

    def test_an_empty_range_passes(self):
        self.assertEqual(self._check(base=self.base, head=self.base)[0], 0)

    def test_an_unresolvable_end_cannot_pass_as_clean(self):
        self.assertEqual(self._check(base="0" * 40)[0], 2)
        self.assertEqual(self._check(head="no-such-ref")[0], 2)

    def test_an_option_shaped_end_is_refused_before_git_reads_it(self):
        # W2-04: `--base`/`--head` reached `rev-parse --verify` and `git log <base>..<head>` in
        # option position; a `-`-leading value is refused as an option, never handed to git.
        for base, head in (("--all", "HEAD"), (self.base, "--all"), ("-p", "HEAD")):
            with self.subTest(base=base, head=head):
                with self.assertRaises(ValueError) as ctx:
                    check_trailers.commits(self.repo, base, head)
                self.assertIn("not an option", str(ctx.exception))
                code = check_trailers.main([f"--base={base}", f"--head={head}", "--root", str(self.repo)])
                self.assertEqual(code, 2)

    def test_the_cli_fails_the_step(self):
        self._commit("fix: x\n\nCo-authored-by: Bot <bot@example.com>\n")
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "check_trailers.py"),
                            "--base", self.base, "--root", str(self.repo)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("CONTRIBUTING.md forbids", r.stdout)


class TheTrailerCheckRunsOnEveryPullRequest(unittest.TestCase):
    """The check is wired into the `checks` job, which the required `gates` job needs, over the
    PR's own range, after a full-history checkout (a shallow one cannot resolve the base and would
    exit 2). It ran inside `gates` until the CI speed change moved every check that reads no
    shard output into `checks`, which starts beside the shards instead of after them."""

    def test_gates_runs_the_check_over_the_pr_range(self):
        text = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^  pull_request:")
        steps = _steps(_jobs(text)["checks"])
        names = [_step_name(s) for s in steps]
        idx = [i for i, s in enumerate(steps) if "scripts/check_trailers.py" in _step_script(s)]
        self.assertEqual(len(idx), 1, "gates does not run scripts/check_trailers.py once")
        step = steps[idx[0]]
        self.assertIn('--base "$PR_BASE_SHA" --head "$PR_HEAD_SHA"', _step_script(step))
        env = _step_env(step)
        self.assertEqual(env.get("PR_BASE_SHA"), "${{ github.event.pull_request.base.sha }}")
        self.assertEqual(env.get("PR_HEAD_SHA"), "${{ github.event.pull_request.head.sha }}")
        self.assertIn("        if: github.event_name == 'pull_request'", step)
        checkout = [i for i, s in enumerate(steps) if "actions/checkout@" in "\n".join(s)]
        self.assertTrue(checkout and checkout[0] < idx[0],
                        f"the trailer check runs before any checkout: {names}")
        self.assertRegex("\n".join(steps[checkout[0]]), r"fetch-depth:\s*0\b")

    def test_the_job_that_runs_it_blocks_the_merge(self):
        """`checks` is not itself a required context: it blocks the merge only because the
        required `gates` job NEEDS it, and gates' first step fails unless every need succeeded
        (tests/test_shard_tests.py runs that step). Without the need, a red trailer check — and
        every other check that moved with it — would be advisory."""
        text = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        jobs = _jobs(text)
        self.assertIn("checks", jobs, "the checks job is gone from validate.yml")
        needs = [ln for ln in jobs["gates"] if re.match(r"^    needs:", ln)]
        self.assertEqual(len(needs), 1, "gates declares no single needs list")
        listed = [n.strip() for n in needs[0].split("[", 1)[1].split("]", 1)[0].split(",")]
        self.assertIn("checks", listed, "gates no longer needs checks: its checks are advisory")
        self.assertIn("    if: always()", jobs["gates"], "a red checks job would skip gates")


class RunArtifactsStayOutOfSearch(unittest.TestCase):
    """docs/runs/ holds about three quarters of the tracked files, and before #761 a search for
    `verify.py` landed 358 of its 608 hits in frozen run artifacts. docs/runs/.ignore hides the
    artifacts from ripgrep-style search tools (and the agents that use them) while every run
    report and index row stays searchable. git never reads `.ignore`, so nothing that binds or
    hashes an artifact can be affected by it."""

    IGNORE = ROOT / "docs" / "runs" / ".ignore"

    def _rules(self):
        return [ln.strip() for ln in self.IGNORE.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]

    def test_the_rules_hide_artifacts_and_keep_reports_and_the_index(self):
        # Order matters: the negations must come after the rule they carve out of.
        self.assertEqual(self._rules(), ["*/*", "!*/*.md", "!index/*"])

    def test_git_still_tracks_every_run_artifact(self):
        for rel in ("docs/runs/.ignore", "docs/runs/2026-10-25-wip-curve-604-live/report.json",
                    "docs/runs/index/2026-07-13-clean-sweep-self-run.json"):
            r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=ROOT)
            with self.subTest(path=rel):
                self.assertEqual(r.returncode, 1, "a .gitignore rule now hides it from git")

    def test_no_binding_tool_reads_the_search_ignore_file(self):
        for rel in ("scripts/bind_check.py", "runtime/scripts/run_report.py",
                    "scripts/run_index.py"):
            src = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(tool=rel):
                self.assertNotRegex(src, r"[\"']rg[\"']|ripgrep|\.ignore\b")

    @staticmethod
    def _visible(rel):
        """What the three rules leave visible, by gitignore semantics, for a path under docs/runs:
        `*/*` hides everything below a run directory, `!*/*.md` and `!index/*` re-include one
        level only (a hidden directory's contents stay hidden)."""
        parts = rel.split("/")[2:]
        if any(part.startswith(".") for part in parts):  # search tools skip dotfiles by default
            return False
        if len(parts) == 1:
            return True
        return len(parts) == 2 and (parts[1].endswith(".md") or parts[0] == "index")

    def _tracked(self):
        return set(subprocess.run(["git", "ls-files", "docs/runs"], cwd=ROOT, capture_output=True,
                                  text=True, check=True).stdout.split())

    def test_reports_and_the_index_stay_visible_and_artifacts_do_not(self):
        tracked = self._tracked()
        visible = {p for p in tracked if self._visible(p)}
        reports = {p for p in tracked if p.endswith(".md") and p.count("/") <= 3}
        index = {p for p in tracked if p.startswith("docs/runs/index/")}
        self.assertTrue(reports and index)
        self.assertLessEqual(reports | index, visible)
        artifacts = {p for p in visible if not p.endswith(".md")
                     and not p.startswith("docs/runs/index/") and p.count("/") > 2}
        self.assertEqual(artifacts, set())
        self.assertGreater(len(tracked - visible), 1000, "the rules no longer hide the artifacts")

    def test_ripgrep_applies_the_rules_as_modelled(self):
        # Where ripgrep is installed it must agree with the model, file by file, and without the
        # ignore file the artifacts come back (the control). Without it, the model above stands.
        if not shutil.which("rg"):
            return
        def listed(*extra):
            return set(subprocess.run(["rg", "--files", *extra, "docs/runs"], cwd=ROOT,
                                      stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                      timeout=120, check=True).stdout.split())
        tracked = self._tracked()
        visible = listed() & tracked
        self.assertEqual(visible, {p for p in tracked if self._visible(p)})
        self.assertGreater(len(listed("--no-ignore-dot") - listed()), 1000)


class TheWorkerWrappersDocumentEveryParameter(unittest.TestCase):
    """The coordinator learns these tools from `--help`. A bare `--source SOURCE` told it nothing
    about what `transcript` certifies or what a cursor is (agent audit, check T2)."""

    def test_every_argument_carries_help(self):
        for rel in ("runtime/scripts/worker_ops.py", "runtime/scripts/terminal_ops.py"):
            tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
            calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                     and isinstance(n.func, ast.Attribute) and n.func.attr == "add_argument"]
            self.assertTrue(calls, rel)
            for call in calls:
                flag = call.args[0].value if call.args and isinstance(call.args[0], ast.Constant) else "?"
                with self.subTest(tool=rel, flag=flag):
                    self.assertIn("help", [kw.arg for kw in call.keywords])


if __name__ == "__main__":
    unittest.main()
