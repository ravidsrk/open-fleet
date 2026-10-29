#!/usr/bin/env python3
"""#629: the coordinator-side gates must not run a command the worker named in its own repo.

Global and system git config were already off, but a worker that can write its worktree's
`.git/config` (and `.git/info/attributes`) could still get a command run on the COORDINATOR
the next time a gate diffs or reads its work, through a repository-config channel git honours:

  - a `filter.<driver>.clean/smudge/process` selected by `.gitattributes`, run when a gate
    materialises or diffs a working-tree file;
  - `core.fsmonitor`, run on `status`/`add`;
  - and the diff/textconv/hook/replace/graft channels the fixed belt and the
    `--no-ext-diff`/`--no-textconv` flags already closed, pinned here so they stay closed.

Each gate is driven the way the coordinator runs it, against a repo whose config names a
harmless probe that only touches a marker file in this test's temp dir. GREEN = the marker
is never created. Every case carries its mutation control: with the hardening removed the
marker comes back, so the test proves the hardening is load-bearing, not that the channel
was dormant. Stdlib only; no network.
"""
import contextlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

# Fetched branch names holding a line break (tests/fixtures/refname_breaks.py; W3-07 re-attack).
_rb_spec = importlib.util.spec_from_file_location(
    "refname_breaks", ROOT / "tests" / "fixtures" / "refname_breaks.py")
refname_breaks = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(refname_breaks)
SCRIPTS = ROOT / "runtime" / "scripts"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load("gitexec", "gitexec.py")
floor_guard = _load("floor_guard", "floor_guard.py")
diff_scope = _load("diff_scope", "diff_scope.py")
evidence_run = _load("evidence_run", "evidence-run.py")


def _load_with_siblings(name, filename):
    """hint_provenance imports its siblings by name (diff_scope, gitexec), as it does when it runs
    from runtime/scripts/; the directory is on the path only while it loads."""
    sys.path.insert(0, str(SCRIPTS))
    try:
        return _load(name, filename)
    finally:
        sys.path.remove(str(SCRIPTS))


hint_provenance = _load_with_siblings("hint_provenance", "hint_provenance.py")

# The setup git runs with global/system config off, so the only driver the fixtures declare is
# the probe (a stray ~/.gitconfig git-lfs filter never changes a test's outcome).
_CLEAN_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


class _Probe:
    """A git repo whose config names a probe on every exec channel. The probe appends ONE token
    per fire to a marker file; `fired()` returns the set of channels seen."""

    def __init__(self, tmp):
        self.dir = Path(tmp)
        self.repo = self.dir / "repo"
        self.marker = self.dir / "marker"
        self.probe = self.dir / "probe.sh"
        # The probe ONLY touches its marker and never reads stdin: git hands an fsmonitor hook
        # its own stdin, so a probe that read it blocked forever under an inherited pipe that
        # never closes. A filter that fires is the failure under test, so what it outputs (here,
        # nothing) never matters to a GREEN case; the 'process' protocol is never selected.
        self.probe.write_text('#!/bin/sh\necho "$1" >> ' + _sh(self.marker) + "\nexit 0\n",
                              encoding="utf-8")
        self.probe.chmod(0o755)
        self.repo.mkdir(parents=True, exist_ok=True)
        self._git("init", "-q")
        self._git("config", "user.email", "a@b")
        self._git("config", "user.name", "a")

    def _git(self, *args, cwd=None):
        return subprocess.run(["git", "-C", str(cwd or self.repo), *args], env=_CLEAN_ENV,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)

    def commit(self, name, body):
        (self.repo / name).write_text(body, encoding="utf-8")
        self._git("add", "-A")
        self._git("commit", "-qm", name)
        return self._git("rev-parse", "HEAD").stdout.strip()

    def arm_filter(self, pattern="*.txt"):
        """Select a clean/smudge filter whose command is the probe, via $GIT_DIR/info/attributes
        (the vector --attr-source cannot override) so blanking the config command is the only
        defence."""
        for key in ("filter.p.clean", "filter.p.smudge"):
            self._git("config", key, f"{self.probe} {key.split('.')[-1]}")
        info = self.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text(f"{pattern} filter=p\n", encoding="utf-8")

    def arm_fsmonitor(self):
        self._git("config", "core.fsmonitor", f"{self.probe} fsmonitor")

    def fired(self):
        if not self.marker.exists():
            return set()
        seen = {ln.strip() for ln in self.marker.read_text().splitlines() if ln.strip()}
        self.marker.unlink()
        return seen


def _sh(path):
    return "'" + str(path).replace("'", "'\\''") + "'"


# wtree.sh stages in a git dir it builds (W4 custody sweep): every call that stages or hashes
# content carries this lead. A mutation control removes it to run the pre-custody script.
_WTREE_CUSTODY = ' --git-dir="$CUSTODY" --work-tree="$TOP"'


def _pre_custody(src):
    """wtree.sh's source with its staging run in the repository itself again (controls only)."""
    assert src.count(_WTREE_CUSTODY) >= 3, "the custody lead moved: update the control"
    return src.replace(_WTREE_CUSTODY, "")


def _no_custody(repo, **_kw):
    """The pre-custody gate, for mutation controls only: a gitexec.Custody with no git dir, so the
    content-reading git runs in ``repo`` itself, under the repository's own config."""
    return contextlib.nullcontext(gitexec.Custody(None, None, (), repo))


class GitexecDriverBlanks(unittest.TestCase):
    """gitexec.driver_blanks reads the driver names the repo's OWN config declares and blanks
    each command — the attribute-selected channel a fixed -c cannot name."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        return p

    def test_a_clean_repo_declares_no_drivers(self):
        self.assertEqual(gitexec.driver_blanks(self._repo().repo), [])

    def test_every_declared_filter_and_diff_driver_command_is_blanked(self):
        p = self._repo()
        p._git("config", "filter.media.clean", "danger clean")
        p._git("config", "filter.media.smudge", "danger smudge")
        p._git("config", "filter.media.process", "danger process")
        p._git("config", "diff.jpg.textconv", "danger textconv")
        p._git("config", "diff.jpg.command", "danger command")
        # A driver name with a dot is still one subsection, so it is still covered.
        p._git("config", "filter.my.lfs.clean", "danger clean")
        # (key, value) pairs for gitexec.env(blanks=...), each key exactly as declared, each
        # value empty (git runs no command): an env pair, never a `-c` token (PR #649 review).
        # A filter is neutralised WHOLE — every command blank and required=false (PR #649).
        self.assertEqual(set(gitexec.driver_blanks(p.repo)), {
            ("filter.media.clean", ""), ("filter.media.smudge", ""), ("filter.media.process", ""),
            ("filter.media.required", "false"),
            ("diff.jpg.textconv", ""), ("diff.jpg.command", ""),
            ("filter.my.lfs.clean", ""), ("filter.my.lfs.smudge", ""),
            ("filter.my.lfs.process", ""), ("filter.my.lfs.required", "false")})

    def test_a_non_command_key_is_not_blanked(self):
        p = self._repo()
        p._git("config", "filter.media.required", "true")
        p._git("config", "diff.jpg.binary", "true")
        # PR #649 review (PRRT_kwDOTWxN9c6vvon0): a declared filter is neutralised whole even with
        # no command (git dies on a required one), while a diff driver's non-command key is not.
        self.assertEqual(gitexec.driver_blanks(p.repo), [
            ("filter.media.clean", ""), ("filter.media.smudge", ""),
            ("filter.media.process", ""), ("filter.media.required", "false")])

    def test_the_toolchain_copies_blank_exactly_what_gitexec_blanks(self):
        # diff_scope.py inlines driver_blanks and verify.py's _Authority mirrors it (each runs its
        # own git under its own env); a copy that falls behind reopens the channel at that gate.
        verify = _load("verify_parity", "verify.py")
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)
        p = self._repo()
        for key in ("filter.media.clean", "filter.media.smudge", "filter.media.process",
                    "diff.jpg.textconv", "diff.jpg.command", "filter.my.lfs.clean",
                    "merge.union.driver", "merge.union.recursive", "merge.inner.driver"):
            p._git("config", key, "danger")
        p._git("config", "filter.media.required", "true")
        want = gitexec.driver_blanks(p.repo)
        # 8 filter + 2 diff + 2 merge (union, inner — one driver override per declared name).
        self.assertEqual(len(want), 12)
        self.assertIn(("merge.union.driver", "exit 1"), want)
        self.assertIn(("merge.inner.driver", "exit 1"), want)
        self.assertEqual(diff_scope._driver_blanks(p.repo), want)
        self.assertEqual(verify._Authority.driver_blanks(p.repo), want)

    def test_a_git_dir_reads_the_config_that_git_dir_resolves(self):
        # W4-01: posix.py names a worktree by its admin git dir (`--git-dir`) and never through the
        # worktree's own `.git` pointer, so the drivers come from where that call runs: here a
        # linked worktree's admin dir, whose `includeIf gitdir:` the main checkout never matches.
        p = self._repo()
        inc = p.dir / "linked-only.gitconfig"
        inc.write_text('[filter "inc"]\n\tsmudge = danger\n', encoding="utf-8")
        p._git("config", "includeIf.gitdir:**/worktrees/**.path", str(inc))
        p._git("worktree", "add", "-q", "--detach", str(p.dir / "wt"))
        admin = p.repo / ".git" / "worktrees" / "wt"
        linked = gitexec.driver_blanks(None, git_dir=admin)
        self.assertIn(("filter.inc.smudge", ""), linked)
        self.assertEqual(linked, gitexec.driver_blanks(p.dir / "wt"))
        self.assertEqual(gitexec.driver_blanks(None, git_dir=p.repo / ".git"), [])


class StaticBeltClosesTheFixedKeyChannels(unittest.TestCase):
    """The env belt (command-line precedence, so it overrides repo .git/config) names every
    command-bearing key a fixed -c can name."""

    def test_belt_pins_the_command_bearing_keys(self):
        env = gitexec.env({"LANG": "C"})
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
                 for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pairs["core.fsmonitor"], "false")
        self.assertEqual(pairs["core.hooksPath"], os.devnull)
        self.assertEqual(pairs["diff.external"], "")
        self.assertEqual(pairs["protocol.ext.allow"], "never")
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(env["GIT_GRAFT_FILE"], os.devnull)

    def test_an_inherited_config_channel_neither_blinds_nor_outranks_the_floor(self):
        # W4-07 sweep: GIT_CONFIG_PARAMETERS (inherited `-c` pairs) is read AFTER the
        # GIT_CONFIG_COUNT pairs, so it outranks the floor; GIT_CONFIG names the ONE file
        # `git config --list` reads, so driver_blanks listed nothing while `diff`/`add` still
        # loaded the repo config and ran its filter. Neither reaches a floored child.
        inherited = {"GIT_CONFIG": os.devnull, "GIT_CONFIG_PARAMETERS": "'core.fsmonitor'='danger'"}
        env = gitexec.env(inherited)
        self.assertNotIn("GIT_CONFIG", env)
        self.assertNotIn("GIT_CONFIG_PARAMETERS", env)
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        p._git("config", "filter.media.clean", "danger")
        with mock.patch.dict(os.environ, inherited):
            self.assertIn(("filter.media.clean", ""), gitexec.driver_blanks(p.repo))
            got = subprocess.run(gitexec.argv("-C", str(p.repo), "config", "--get", "core.fsmonitor"),
                                 env=gitexec.env(), capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(got.stdout.strip(), "false")

    def test_diff_scope_drops_the_same_inherited_channels(self):
        # diff_scope inlines the floor (it is in the verifier toolchain), so it must drop the same
        # inherited variables gitexec drops, or its own driver enumeration is blinded.
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        p._git("config", "filter.media.clean", "danger")
        inherited = {k: "x" for k in gitexec._INHERITED_DROPPED}
        inherited["GIT_CONFIG"] = os.devnull
        with mock.patch.dict(os.environ, inherited):
            env = diff_scope._git_env()
            self.assertIn(("filter.media.clean", ""), diff_scope._driver_blanks(p.repo))
        self.assertEqual(set(env) & gitexec._INHERITED_DROPPED, set())

    def test_diff_scope_mirrors_the_whole_gitexec_floor(self):
        env = diff_scope._git_env()
        plain = {k: v for k, v in gitexec.HARDENED.items()
                 if not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "GIT_CONFIG_COUNT"))}
        self.assertEqual({k: env.get(k) for k in plain}, plain)

        def pairs(e):
            return {e[f"GIT_CONFIG_KEY_{i}"]: e[f"GIT_CONFIG_VALUE_{i}"]
                    for i in range(int(e["GIT_CONFIG_COUNT"]))}
        ours = pairs(env)
        self.assertEqual({k: ours.get(k) for k in pairs(gitexec.HARDENED)}, pairs(gitexec.HARDENED))


class FloorGuardWorktreeDiff(unittest.TestCase):
    """floor_guard diffs the working tree against the base — which runs a repo-config clean
    filter a .gitattributes selects, the one channel --no-ext-diff/--no-textconv leave open."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        p.arm_filter()
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        (p.repo / "b.txt").write_text("brand new\n", encoding="utf-8")  # untracked -> --no-index
        return p, base

    def _collect(self, p, base):
        mb = floor_guard.merge_base(p.repo, base)
        floor_guard.collect_diff(p.repo, mb)

    def test_no_driver_command_runs_when_the_guard_reads_the_diff(self):
        p, base = self._repo()
        self._collect(p, base)
        self.assertEqual(p.fired(), set(), "a repo-config filter ran inside floor_guard")

    def test_mutation_control_without_the_blanks_the_filter_fires(self):
        p, base = self._repo()
        # The pre-fix guard: no blanks AND no custody (the diff reads the repo's own config).
        with mock.patch.object(floor_guard.gitexec, "driver_blanks", lambda repo: []), \
                mock.patch.object(floor_guard.gitexec, "custody", _no_custody):
            self._collect(p, base)
        self.assertIn("clean", p.fired(),
                      "control: with the driver blanks removed the clean filter must fire")


class DiffScopeWorktreeDiff(unittest.TestCase):
    """diff_scope classifies the changed paths, diffing the working tree against the base."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        p.arm_filter()
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        return p, base

    def test_no_driver_command_runs_when_scope_reads_the_diff(self):
        p, base = self._repo()
        diff_scope.scope(p.repo, base)
        self.assertEqual(p.fired(), set(), "a repo-config filter ran inside diff_scope")

    def test_mutation_control_without_the_blanks_the_filter_fires(self):
        p, base = self._repo()
        # The pre-fix scope: no blanks AND no custody (the diff reads the repo's own config).
        with mock.patch.object(diff_scope, "_driver_blanks", lambda repo: []), \
                mock.patch.object(diff_scope, "_custody", _no_custody):
            diff_scope.scope(p.repo, base)
        self.assertIn("clean", p.fired(),
                      "control: with the driver blanks removed the clean filter must fire")


class HintProvenanceWorktreeDiff(unittest.TestCase):
    """hint_provenance reads a worker's live checkout to decide whether a recorded hint is still
    current: in working-tree mode changes_since() diffs the disk against the hint's source rev,
    which runs a repo-config clean filter a `$GIT_DIR/info/attributes` line selects."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        p.arm_filter()
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        return p, base

    def _changes(self, p, base):
        return hint_provenance.LiveSource(str(p.repo)).changes_since(base)

    def test_no_driver_command_runs_when_a_hint_reads_the_live_tree(self):
        p, base = self._repo()
        self.assertEqual(self._changes(p, base), {"a.txt": ("M", None)})
        self.assertEqual(p.fired(), set(), "a repo-config filter ran inside hint_provenance")

    def test_mutation_control_without_the_blanks_the_filter_fires(self):
        p, base = self._repo()
        # The pre-fix read: no blanks AND no custody (the diff reads the repo's own config).
        with mock.patch.object(hint_provenance.gitexec, "driver_blanks", lambda repo: []), \
                mock.patch.object(hint_provenance.gitexec, "custody", _no_custody):
            self._changes(p, base)
        self.assertIn("clean", p.fired(),
                      "control: with the driver blanks removed the clean filter must fire")


class WtreeFingerprint(unittest.TestCase):
    """evidence-run.py fingerprints the working tree through wtree.sh (`git add -A` + write-tree),
    which runs both core.fsmonitor and a selected clean filter against the worker's repo."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\nline2\n")
        p.arm_filter()
        p.arm_fsmonitor()
        (p.repo / "a.txt").write_text("line1\nDIRTY\n", encoding="utf-8")  # dirty -> add re-hashes
        return p

    def test_the_fingerprint_runs_no_config_command(self):
        p = self._repo()
        out, err = evidence_run.working_tree_fingerprint(str(p.repo))
        self.assertEqual(p.fired(), set(), "wtree.sh ran a repo-config command on the coordinator")
        # The dirty a.txt is filtered by the repo-declared `p`: unverifiable without running it, so
        # wtree.sh refuses honestly (exit 3) rather than fingerprint unfiltered bytes (PR #649).
        self.assertIsNone(out)
        self.assertIsInstance(err, evidence_run.WtreeUnverifiable)

    def test_mutation_control_a_stripped_wtree_fires_fsmonitor_and_the_filter(self):
        # The control is a COPY of wtree.sh with the two hardening hunks removed, run the same way,
        # so the planted channels prove they were dormant only because of the hardening.
        p = self._repo()
        src = (SCRIPTS / "wtree.sh").read_text(encoding="utf-8")
        # Every hardening pair — the env belt and the driver blanks — rides the GIT_CONFIG_* pairs
        # wtree.sh exports, counted by one final assignment (PR #649). Zero it: core.fsmonitor is
        # honoured again and no filter key is blanked.
        self.assertEqual(src.count("GIT_CONFIG_COUNT=$_n"), 1, "the count assignment moved")
        # ...and stage in the repository itself, as before the git custody (W4 custody sweep).
        stripped = _pre_custody(src).replace("GIT_CONFIG_COUNT=$_n", "GIT_CONFIG_COUNT=0")
        self.assertNotEqual(stripped, src, "the control did not change wtree.sh")
        mutant = p.dir / "wtree_control.sh"
        mutant.write_text(stripped, encoding="utf-8")
        subprocess.run(["sh", str(mutant), str(p.repo)], capture_output=True, timeout=120,
                       stdin=subprocess.DEVNULL)
        self.assertTrue(p.fired() & {"clean", "fsmonitor"},
                        "control: the stripped wtree.sh must run a planted channel")


# PR #649 review (PRRT_kwDOTWxN9c6vvony): a driver name is BYTES. git accepts 0xff, an invalid
# UTF-8 sequence, a `.` or an `=` in a `filter.<driver>.*` subsection, and a .gitattributes line
# selects that exact name. A blank that decodes the name as text (0xff -> U+FFFD) names a
# different driver, and one passed as `-c <key>=` splits a name holding `=` at its first `=`;
# either way the planted command still runs. Whitespace cannot be selected by an attribute, so
# those names are checked at the enumeration only.
_SELECTABLE = (b"\xff", b"\xc3\x28", b"x\x80y", b"\xed\xa0\x80", b"a.b", b"a=b")
_UNSELECTABLE = (b"a b", b"a\tb")


def _bgit(repo, *args):
    """git with BYTES argv, so a non-UTF-8 driver name reaches git exactly."""
    argv = [b"git", b"-C", os.fsencode(str(repo))]
    argv += [a if isinstance(a, bytes) else a.encode("utf-8") for a in args]
    return subprocess.run(argv, env=_CLEAN_ENV, capture_output=True, stdin=subprocess.DEVNULL,
                          timeout=60)


class ByteExactDriverNames(unittest.TestCase):
    """Every gate blanks the driver the attribute ACTUALLY selects, byte for byte."""

    def _repo(self, name, filtered="*.txt"):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        r = _bgit(p.repo, b"config", b"filter." + name + b".clean", os.fsencode(str(p.probe)) + b" clean")
        self.assertEqual(r.returncode, 0, r.stderr)
        info = p.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_bytes(filtered.encode() + b" filter=" + name + b"\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        # Positive control: plain git runs the planted filter, so a GREEN below is not vacuous.
        _bgit(p.repo, "diff", "--no-ext-diff", "--no-textconv", "HEAD", "--")
        self.assertIn("clean", p.fired(), f"the planted {name!r} filter is not live on bare git")
        return p, base

    def test_floor_guard_runs_no_filter_whatever_its_name(self):
        for name in _SELECTABLE:
            with self.subTest(name=name):
                p, base = self._repo(name)
                floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base))
                self.assertEqual(p.fired(), set(), f"floor_guard ran the {name!r} filter")

    def test_diff_scope_runs_no_filter_whatever_its_name(self):
        for name in _SELECTABLE:
            with self.subTest(name=name):
                p, base = self._repo(name)
                diff_scope.scope(p.repo, base)
                self.assertEqual(p.fired(), set(), f"diff_scope ran the {name!r} filter")

    def test_the_wtree_fingerprint_runs_no_filter_whatever_its_name(self):
        for name in _SELECTABLE:
            with self.subTest(name=name):
                p, _ = self._repo(name)
                out, err = evidence_run.working_tree_fingerprint(str(p.repo))
                self.assertEqual(p.fired(), set(), f"wtree.sh ran the {name!r} filter")
                # Refused as unverifiable (PR #649): which also proves the attribute's value and the
                # declared name matched byte for byte, or a fingerprint would have been printed.
                self.assertIsNone(out)
                self.assertIsInstance(err, evidence_run.WtreeUnverifiable)

    def test_the_enumeration_names_the_exact_declared_bytes(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        for name in _SELECTABLE + _UNSELECTABLE:
            self.assertEqual(_bgit(p.repo, b"config", b"filter." + name + b".clean", b"x").returncode, 0)
        keys = {os.fsencode(k) for k, v in gitexec.driver_blanks(p.repo) if v == ""}
        for name in _SELECTABLE + _UNSELECTABLE:
            self.assertIn(b"filter." + name + b".clean", keys, f"{name!r} is not blanked byte-exactly")

    def test_the_toolchain_copies_enumerate_the_same_bytes(self):
        verify = _load("verify_bytes_parity", "verify.py")
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        for name in _SELECTABLE + _UNSELECTABLE:
            _bgit(p.repo, b"config", b"filter." + name + b".clean", b"x")
        want = gitexec.driver_blanks(p.repo)
        self.assertTrue(want)
        self.assertEqual(diff_scope._driver_blanks(p.repo), want)
        self.assertEqual(verify._Authority.driver_blanks(p.repo), want)


# PR #649 review (PRRT_kwDOTWxN9c6vvon0): `filter.<driver>.required=true` makes git DIE when the
# filter does not run (`clean filter '<driver>' failed`) — with its command blanked, or with no
# command declared at all. A worker could plant one and stop every gate that reads a matching
# file: a denial of service on the coordinator. Each gate must override it to false, run
# nothing, and still read the working-tree bytes exactly as they are.
_RAW_LINE = "RAW-WORKTREE-LINE"


class RequiredFilters(unittest.TestCase):

    def _repo(self, with_command):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        p._git("config", "filter.req.required", "true")
        if with_command:
            for var in ("clean", "smudge"):
                p._git("config", f"filter.req.{var}", f"{p.probe} {var}")
        info = p.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.txt filter=req\n", encoding="utf-8")
        (p.repo / "a.txt").write_text(f"line1\n{_RAW_LINE}\n", encoding="utf-8")
        (p.repo / "b.txt").write_text("brand new\n", encoding="utf-8")
        # Positive control: plain git honours the required filter — it runs the planted command,
        # or, with none declared, dies — so a GREEN below is not vacuous.
        plain = p._git("diff", "--no-ext-diff", "--no-textconv", "HEAD", "--")
        if with_command:
            self.assertIn("clean", p.fired(), "the planted required filter is not live")
        else:
            self.assertNotEqual(plain.returncode, 0, "a required filter with no command did not stop git")
            self.assertIn("filter 'req' failed", plain.stderr)
        return p, base

    def test_floor_guard_reads_raw_bytes_and_neither_runs_nor_dies(self):
        for with_command in (True, False):
            with self.subTest(with_command=with_command):
                p, base = self._repo(with_command)
                text = floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base))
                self.assertIn("+" + _RAW_LINE, text)
                self.assertIn("+brand new", text)
                self.assertEqual(p.fired(), set(), "floor_guard ran the required filter")

    def test_diff_scope_reads_the_change_and_neither_runs_nor_dies(self):
        for with_command in (True, False):
            with self.subTest(with_command=with_command):
                p, base = self._repo(with_command)
                self.assertIn("a.txt", diff_scope.changed_files(p.repo, base))
                diff_scope.scope(p.repo, base)
                self.assertEqual(p.fired(), set(), "diff_scope ran the required filter")

    def test_the_wtree_fingerprint_refuses_honestly_and_neither_runs_nor_dies(self):
        # The changed a.txt is filtered by the repo-declared `req`: wtree.sh does not run it, does
        # not die on `required`, and refuses as unverifiable (exit 3) instead of printing a tree of
        # bytes the committed one was never built from (PR #649 review, PRRT_kwDOTWxN9c6vwb7P).
        for with_command in (True, False):
            with self.subTest(with_command=with_command):
                p, _ = self._repo(with_command)
                out, err = evidence_run.working_tree_fingerprint(str(p.repo))
                self.assertEqual(p.fired(), set(), "wtree.sh ran the required filter")
                self.assertIsNone(out)
                self.assertIsInstance(err, evidence_run.WtreeUnverifiable)
                self.assertNotIn("filter 'req' failed", err)

    def test_the_enumeration_overrides_required_for_every_declared_filter(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        p._git("config", "filter.req.required", "true")      # no command at all
        p._git("config", "diff.jpg.binary", "true")           # not a command: nothing to blank
        blanks = dict(gitexec.driver_blanks(p.repo))
        self.assertEqual(blanks.get("filter.req.required"), "false")
        for var in ("clean", "smudge", "process"):
            self.assertEqual(blanks.get(f"filter.req.{var}"), "")
        self.assertFalse([k for k in blanks if k.startswith("diff.jpg.")], blanks)


# PR #649 review (PRRT_kwDOTWxN9c6vwb7P): with a REPO-declared clean filter blanked, a filtered file
# whose stat changed is re-staged from its smudged working-tree bytes, so the fingerprint differs
# from HEAD and a good run read as STALE. Mapping those bytes back to the committed clean blob
# needs the repository's own command, which the coordinator must not run. wtree.sh therefore says
# so: exit 3 with the reason, which evidence-run.py records and verify.py check_commands reports in
# place of "STALE". An untouched file still fingerprints as HEAD (the stat cache never re-hashes).
# A filter declared in the global config is held to the same rule (W4-02): on a one-uid host the
# worker writes ~/.gitconfig too, so it never runs and a changed path it selects is unverifiable.
_UNVERIFIABLE = "cannot be compared to the committed tree without running repository-supplied commands"


class FilteredFileFidelity(unittest.TestCase):

    def _repo(self, scope="local"):
        """A checkout whose `x` filter EXPANDS stored content: the committed blob is `hello`, the
        working tree holds `EXPANDED-hello`, and the index stat cache is current and not racy.
        `scope` is where the driver is declared: the repo's own config, or a global file."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        clean = p.dir / "clean.sh"
        clean.write_text("#!/bin/sh\necho clean >> " + _sh(p.marker) + "\nexec sed -e 's/^EXPANDED-//'\n",
                         encoding="utf-8")
        clean.chmod(0o755)
        driver = {"filter.x.clean": str(clean), "filter.x.smudge": "sed -e 's/^/EXPANDED-/'"}
        env = dict(_CLEAN_ENV)
        if scope == "global":
            glob = p.dir / "global.gitconfig"
            glob.write_text("[filter \"x\"]\n" + "".join(
                f"\t{k.split('.')[-1]} = {v}\n" for k, v in driver.items()), encoding="utf-8")
            env["GIT_CONFIG_GLOBAL"] = str(glob)
        else:
            for key, value in driver.items():
                p._git("config", key, value)
        self.env = env

        def git(*a):
            return subprocess.run(["git", "-C", str(p.repo), *a], env=env, check=True,
                                  capture_output=True, text=True, stdin=subprocess.DEVNULL)
        (p.repo / ".git" / "info").mkdir(parents=True, exist_ok=True)
        (p.repo / ".git" / "info" / "attributes").write_text("*.txt filter=x\n", encoding="utf-8")
        (p.repo / "f.txt").write_text("hello\n", encoding="utf-8")
        git("add", "f.txt")
        git("commit", "-qm", "filtered")
        (p.repo / "f.txt").unlink()
        git("checkout", "--", "f.txt")
        self.assertEqual((p.repo / "f.txt").read_text(), "EXPANDED-hello\n", "fixture: smudge did not run")
        past = time.time() - 120
        os.utime(p.repo / "f.txt", (past, past))
        git("update-index", "--refresh")
        self.head_tree = git("rev-parse", "HEAD^{tree}").stdout.strip()
        p.fired()
        return p

    def _touch(self, p):
        later = time.time() - 60
        os.utime(p.repo / "f.txt", (later, later))

    def _fingerprint(self, p):
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": self.env["GIT_CONFIG_GLOBAL"]}):
            return evidence_run.working_tree_fingerprint(str(p.repo))

    def test_an_untouched_filtered_file_still_fingerprints_as_head(self):
        p = self._repo()
        out, err = self._fingerprint(p)
        self.assertIsNone(err, err)
        self.assertEqual(out, self.head_tree)
        self.assertEqual(p.fired(), set())

    def test_a_touched_filtered_file_is_unverifiable_not_stale(self):
        p = self._repo()
        self._touch(p)
        out, err = self._fingerprint(p)
        self.assertIsNone(out, "a fingerprint was produced for content it cannot compare")
        self.assertIn(_UNVERIFIABLE, err)
        self.assertIn("f.txt", err)
        self.assertIsInstance(err, evidence_run.WtreeUnverifiable)
        self.assertEqual(p.fired(), set(), "the repo-declared filter ran to make the comparison")
        r = subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env=self.env,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(r.stdout, "")

    def test_mutation_control_with_the_blanks_stripped_the_filter_runs(self):
        # The trade-off, measured: let the repo's filter run and it maps the bytes back to HEAD —
        # which is exactly the repository-supplied command the coordinator must not execute.
        p = self._repo()
        self._touch(p)
        src = (SCRIPTS / "wtree.sh").read_text(encoding="utf-8")
        self.assertEqual(src.count("GIT_CONFIG_COUNT=$_n"), 1)
        mutant = p.dir / "wtree_control.sh"
        # The blanks stripped AND staging in the repository itself (pre-custody, W4 custody sweep).
        mutant.write_text(_pre_custody(src).replace("GIT_CONFIG_COUNT=$_n", "GIT_CONFIG_COUNT=0"),
                          encoding="utf-8")
        r = subprocess.run(["sh", str(mutant), str(p.repo)], env=self.env, capture_output=True,
                           text=True, stdin=subprocess.DEVNULL, timeout=120)
        self.assertIn("clean", p.fired(), "control: the stripped wtree.sh must run the filter")
        self.assertEqual(r.stdout.strip(), self.head_tree)

    def test_a_filter_from_the_same_uid_global_config_is_unverifiable_not_run(self):
        # W4-02: the global file is not the coordinator's own on a one-uid host — the worker can
        # write it — so its filter is held to the repo rule: never run, and exit 3 for a changed
        # path it selects (the earlier "it still runs, for fidelity" let it choose the value).
        p = self._repo(scope="global")
        self._touch(p)
        out, err = self._fingerprint(p)
        self.assertIsNone(out, "a fingerprint was produced for content it cannot compare")
        self.assertIn(_UNVERIFIABLE, err)
        self.assertIsInstance(err, evidence_run.WtreeUnverifiable)
        self.assertEqual(p.fired(), set(), "the global filter ran in the coordinator")

    def test_a_repo_key_shadowing_a_global_driver_is_still_blanked(self):
        p = self._repo(scope="global")
        p._git("config", "filter.x.process", "")  # a repo-scope key naming the same driver
        self._touch(p)
        out, err = self._fingerprint(p)
        self.assertIsNone(out)
        self.assertIn(_UNVERIFIABLE, err)
        self.assertEqual(p.fired(), set())

    def test_evidence_run_and_verify_report_unverifiable_not_stale(self):
        p = self._repo()
        self._touch(p)
        runner = SCRIPTS / "evidence-run.py"
        r = subprocess.run([sys.executable, str(runner), "--label", "t", "--manifest", "m.json",
                            "--", sys.executable, "-c", "pass"], cwd=p.repo, env=self.env,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(_UNVERIFIABLE, r.stderr)
        self.assertNotIn("STALE", r.stderr)
        manifest = json.loads((p.repo / "m.json").read_text(encoding="utf-8"))
        rec = manifest["commands"][0]
        self.assertIsNone(rec["wtree"])
        self.assertIn(_UNVERIFIABLE, rec["wtree_unverifiable"])
        verify = _load("verify_unverifiable", "verify.py")
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)
        head = subprocess.run(["git", "-C", str(p.repo), "rev-parse", "HEAD"], env=self.env,
                              capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.strip()
        with mock.patch.dict(verify._ROOTS, {"git": str(p.repo)}):
            errs = verify.check_commands({"head_sha": head, "commands": [rec]}, True)
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("UNVERIFIABLE", errs[0])
        self.assertIn(_UNVERIFIABLE, errs[0])
        self.assertNotIn("STALE", errs[0])


class WtreeStagesNoDriverAddedAfterTheListing(unittest.TestCase):
    """W4 custody sweep (Codex on the W4-02 branch, P1): wtree.sh listed the declared drivers and
    then `add -A` read the repository's config again, so a `filter.<n>.clean` a still-running
    worker added in between (selected by the shared `info/attributes`) ran in the coordinator —
    and, mapping a tampered file back to its committed bytes, made the tampered tree fingerprint
    as HEAD. A racing `git` first on PATH (the one wtree.sh resolves) adds a NEVER-SEEN filter
    before EVERY call. Staging now runs in a git dir wtree.sh builds, whose config defines none."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\nline2\n")
        self.head_tree = p._git("rev-parse", "HEAD^{tree}").stdout.strip()
        # The late clean filter prints HEAD's bytes: run, it maps the tampered file back to HEAD.
        clean = p.dir / "clean.sh"
        clean.write_text("#!/bin/sh\necho clean >> " + _sh(p.marker) + "\nprintf 'line1\\nline2\\n'\n",
                         encoding="utf-8")
        clean.chmod(0o755)
        bindir = p.dir / "racebin"
        bindir.mkdir()
        counter = p.dir / "race-calls"
        # One line per call; the driver is named by the call's pid, so two gits wtree.sh runs at
        # once (its diff-index | check-attr pipeline) each add their own.
        (bindir / "git").write_text(
            "#!/bin/sh\n"
            "n=$$\n"
            f"echo $n >> {_sh(counter)}\n"
            f"printf '[filter \"late%s\"]\\n\\tclean = %s\\n\\tsmudge = %s\\n' \"$n\" {_sh(clean)} {_sh(clean)}"
            f" >> {_sh(p.repo / '.git' / 'config')}\n"
            f"printf '* filter=late%s\\n' \"$n\" >> {_sh(p.repo / '.git' / 'info' / 'attributes')}\n"
            f"exec {_sh(shutil.which('git'))} \"$@\"\n", encoding="utf-8")
        (bindir / "git").chmod(0o755)
        (p.repo / ".git" / "info").mkdir(exist_ok=True)
        self.counter = counter
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_CONFIG", "GIT_DIR"))}
        self.env.update(PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}",
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        (p.repo / "a.txt").write_text("TAMPERED\n", encoding="utf-8")
        return p

    def _run(self, p, script):
        return subprocess.run(["sh", str(script), str(p.repo)], env=self.env, capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, timeout=120)

    def test_a_filter_added_after_the_listing_neither_runs_nor_chooses_the_fingerprint(self):
        p = self._repo()
        r = self._run(p, SCRIPTS / "wtree.sh")
        self.assertGreater(len(self.counter.read_text().split()), 1, "the race never ran")
        self.assertEqual(p.fired(), set(), "a filter declared after the listing ran in the coordinator")
        self.assertNotEqual(r.stdout.strip(), self.head_tree, "a tampered tree fingerprinted as HEAD")
        # A late driver is not in the listing, so its path is hashed from its raw bytes (exit 0, a
        # tree that is not HEAD's); one the listing saw makes the changed path unverifiable (3).
        self.assertIn(r.returncode, (0, 3), r.stderr)

    def test_mutation_control_staging_in_the_repository_runs_the_late_filter(self):
        p = self._repo()
        mutant = p.dir / "wtree_control.sh"
        mutant.write_text(_pre_custody((SCRIPTS / "wtree.sh").read_text(encoding="utf-8")),
                          encoding="utf-8")
        r = self._run(p, mutant)
        self.assertIn("clean", p.fired(), "control: the late filter never ran pre-custody")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, self.head_tree),
                         "control: the late filter did not choose the fingerprint")

    def test_a_partial_clone_is_no_fingerprint_not_a_guess(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        p._git("config", "core.repositoryformatversion", "1")
        p._git("config", "extensions.partialClone", "origin")
        r = subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env=_CLEAN_ENV,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
        self.assertIn("extensions.partialclone", r.stderr)

    def test_a_planted_symlink_where_git_reads_a_file_is_no_fingerprint(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        exclude = p.repo / ".git" / "info" / "exclude"
        exclude.parent.mkdir(exist_ok=True)
        exclude.unlink(missing_ok=True)
        os.symlink(os.devnull, exclude)
        r = subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env=_CLEAN_ENV,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
        self.assertIn("not a regular file", r.stderr)

    def test_the_fingerprint_writes_nothing_into_the_repositorys_object_store(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        (p.repo / "untracked.txt").write_text("never committed\n", encoding="utf-8")
        before = sorted(str(f) for f in (p.repo / ".git" / "objects").rglob("*"))
        r = subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env=_CLEAN_ENV,
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(r.stdout.strip(), p._git("rev-parse", "HEAD^{tree}").stdout.strip())
        self.assertEqual(sorted(str(f) for f in (p.repo / ".git" / "objects").rglob("*")), before)


def _wtree(repo, env=None, script=None):
    return subprocess.run(["sh", str(script or SCRIPTS / "wtree.sh"), str(repo)], env=env or _CLEAN_ENV,
                          capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)


def _quiet_git(repo, *args):
    """Plain git with every planted channel pinned off, for fixture steps only."""
    env = {**_CLEAN_ENV, "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "core.fsmonitor",
           "GIT_CONFIG_VALUE_0": "false", "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": os.devnull}
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=a@b", "-c", "user.name=a", *args],
                          env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)


class WtreeKeepsLineEndingData(unittest.TestCase):
    """Codex on this branch (P1): CUSTODY dropped the repository's info/attributes, so a clean CRLF
    checkout of an `eol=crlf` path, once touched, staged CRLF unnormalised and read STALE. The
    attributes (and the conversion settings) are data, carried as such."""

    def _repo(self, how):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\nline2\n")
        head_tree = p._git("rev-parse", "HEAD^{tree}").stdout.strip()
        if how == "info/attributes":
            (p.repo / ".git" / "info").mkdir(exist_ok=True)
            (p.repo / ".git" / "info" / "attributes").write_text("*.txt text eol=crlf\n", encoding="utf-8")
        elif how == "core.attributesFile ending in a newline":
            # Codex (round 3): `$(...)` stripped the trailing newline and read `attrs` instead.
            (p.dir / "attrs\n").write_text("*.txt text eol=crlf\n", encoding="utf-8")
            (p.dir / "attrs").write_text("*.txt -text\n", encoding="utf-8")
            p._git("config", "core.attributesFile", str(p.dir) + "/attrs\n")
        elif how.startswith("core.attributesFile"):
            # Codex on this branch (P1, round 2): a repository-scope core.attributesFile, absolute
            # or relative to the work tree top (beside the repository, so nothing is untracked).
            (p.dir / "attrs").write_text("*.txt text eol=crlf\n", encoding="utf-8")
            p._git("config", "core.attributesFile", str(p.dir / "attrs") if how.endswith("absolute") else "../attrs")
        else:
            p._git("config", "core.autocrlf", "true")
        (p.repo / "a.txt").unlink()
        p._git("checkout", "--", "a.txt")
        self.assertEqual((p.repo / "a.txt").read_bytes(), b"line1\r\nline2\r\n", "fixture: not a CRLF checkout")
        later = time.time() + 30
        os.utime(p.repo / "a.txt", (later, later))  # touched: `add -A` re-reads it
        return p, head_tree

    def test_a_touched_clean_crlf_checkout_fingerprints_as_head(self):
        for how in ("info/attributes", "core.autocrlf", "core.attributesFile absolute",
                    "core.attributesFile relative", "core.attributesFile ending in a newline"):
            with self.subTest(how=how):
                p, head_tree = self._repo(how)
                r = _wtree(p.repo)
                self.assertEqual((r.returncode, r.stdout.strip()), (0, head_tree), r.stderr)

    def test_a_real_edit_still_changes_it(self):
        p, head_tree = self._repo("info/attributes")
        (p.repo / "a.txt").write_bytes(b"line1\r\nEDITED\r\n")
        r = _wtree(p.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(r.stdout.strip(), head_tree)


class WtreeRefusesAnUnreadableAttributesFile(unittest.TestCase):
    """Codex on this branch (P1, round 2): core.attributesFile's content is carried only from a
    regular file of at most 1 MiB, opened without blocking. A FIFO (whose open would hang the gate),
    a symlink, a directory or a larger file is no fingerprint (exit 1) at once, never dropped."""

    def test_each_is_no_fingerprint_without_hanging(self):
        for kind in ("fifo", "symlink", "directory", "oversized"):
            with self.subTest(kind=kind):
                tmp = tempfile.mkdtemp()
                self.addCleanup(lambda t=tmp: shutil.rmtree(t, ignore_errors=True))
                p = _Probe(tmp)
                p.commit("a.txt", "line1\n")
                target = p.dir / "attrs"
                if kind == "fifo":
                    os.mkfifo(target)
                elif kind == "symlink":
                    (p.dir / "real").write_text("*.txt text\n", encoding="utf-8")
                    os.symlink(p.dir / "real", target)
                elif kind == "directory":
                    target.mkdir()
                else:
                    target.write_bytes(b"#" * ((1 << 20) + 1))
                p._git("config", "core.attributesFile", str(target))
                try:
                    r = subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env=_CLEAN_ENV,
                                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
                except subprocess.TimeoutExpired:
                    self.fail(f"wtree.sh hung on a {kind} core.attributesFile")
                self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
                self.assertIn("core.attributesFile", r.stderr)

    def test_a_missing_file_is_no_attributes_as_for_git(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        p._git("config", "core.attributesFile", str(p.dir / "absent"))
        r = _wtree(p.repo)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, p._git("rev-parse", "HEAD^{tree}").stdout.strip()),
                         r.stderr)


class WtreeOpensNoUserOrSystemAttributesFile(unittest.TestCase):
    """Codex on this branch (round 3, P2): with no repository core.attributesFile, git opened its
    default user attributes file ($XDG_CONFIG_HOME/git/attributes, else ~/.config/git/attributes;
    the worker's to write on a one-uid host) and the system one, so a FIFO there hung the
    fingerprint. CUSTODY's own attributes file is now named always, and GIT_ATTR_NOSYSTEM=1."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")  # `add -A` reads attributes
        (p.repo / "b.txt").write_text("new\n", encoding="utf-8")
        return p

    def _run(self, p, env):
        try:
            return subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env=env, capture_output=True,
                                  text=True, stdin=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("wtree.sh hung opening a default attributes file")

    def test_a_fifo_at_either_default_user_attributes_file_is_never_opened(self):
        for where in ("XDG_CONFIG_HOME", "HOME"):
            with self.subTest(where=where):
                p = self._repo()
                empty = p.dir / "empty-home"
                empty.mkdir()
                base = {k: v for k, v in _CLEAN_ENV.items() if k != "XDG_CONFIG_HOME"}
                want = self._run(p, {**base, "HOME": str(empty)})
                self.assertEqual(want.returncode, 0, want.stderr)
                if where == "XDG_CONFIG_HOME":
                    xdg = p.dir / "xdg"
                    (xdg / "git").mkdir(parents=True)
                    os.mkfifo(xdg / "git" / "attributes")
                    env = {**base, "HOME": str(empty), "XDG_CONFIG_HOME": str(xdg)}
                else:
                    home = p.dir / "home"
                    (home / ".config" / "git").mkdir(parents=True)
                    os.mkfifo(home / ".config" / "git" / "attributes")
                    env = {**base, "HOME": str(home)}
                r = self._run(p, env)
                self.assertEqual((r.returncode, r.stdout), (0, want.stdout), r.stderr)

    def test_every_git_runs_with_system_attributes_off(self):
        p = self._repo()
        bindir = p.dir / "envbin"
        bindir.mkdir()
        log = p.dir / "attr-nosystem.log"
        (bindir / "git").write_text(
            '#!/bin/sh\necho "${GIT_ATTR_NOSYSTEM:-unset}" >> ' + _sh(log) + "\nexec " + _sh(_REAL_GIT) + ' "$@"\n',
            encoding="utf-8")
        (bindir / "git").chmod(0o755)
        r = self._run(p, {**_CLEAN_ENV, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"})
        self.assertEqual(r.returncode, 0, r.stderr)
        seen = log.read_text(encoding="utf-8").split()
        self.assertTrue(seen, "the wrapper never ran")
        self.assertEqual(set(seen), {"1"}, "a git ran with the system attributes file live")


class WtreeStartsNoChildGitInASubmodule(unittest.TestCase):
    """Codex on PR #724 (P1), wtree's half: `git add` probes a checked-out submodule's dirtiness with
    a child `git status` INSIDE it, under the submodule's own config, and no option or config stops
    it. A gitlink directory is kept out of `add -A` and refreshed with `update-index`, which reads
    the submodule's HEAD in-process."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        lib = p.dir / "lib"
        lib.mkdir()
        _quiet_git(p.dir, "init", "-q", str(lib))
        (lib / "f.txt").write_text("library\n", encoding="utf-8")
        _quiet_git(lib, "add", "f.txt")
        _quiet_git(lib, "commit", "-qm", "lib")
        r = _quiet_git(p.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(lib), "sub")
        self.assertEqual(r.returncode, 0, r.stderr)
        _quiet_git(p.repo, "commit", "-qm", "add sub")
        self.sub = p.repo / "sub"
        self._plant(p, self.sub)
        # Positive control: plain git's `add -A` (temp index) runs the submodule's own filter.
        idx = p.dir / "probe.index"
        shutil.copy(p.repo / ".git" / "index", idx)
        subprocess.run(["git", "-C", str(p.repo), "add", "-A"], env={**_CLEAN_ENV, "GIT_INDEX_FILE": str(idx)},
                       capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertIn("sub-clean", p.fired(), "the submodule's planted filter is not live")
        self._touch(self.sub / "f.txt")
        self.head_tree = p._git("rev-parse", "HEAD^{tree}").stdout.strip()
        return p

    @staticmethod
    def _plant(p, repo):
        """A filter, an fsmonitor and a post-index-change hook in `repo`'s OWN config."""
        for key, var in (("core.fsmonitor", "fsmonitor"), ("filter.sf.clean", "sub-clean"),
                         ("filter.sf.smudge", "sub-smudge")):
            _quiet_git(repo, "config", key, f"{p.probe} {var}")
        git_dir = Path(_quiet_git(repo, "rev-parse", "--absolute-git-dir").stdout.strip())
        (git_dir / "info").mkdir(exist_ok=True)
        (git_dir / "info" / "attributes").write_text("* filter=sf\n", encoding="utf-8")
        hook = git_dir / "hooks" / "post-index-change"
        hook.parent.mkdir(exist_ok=True)
        hook.write_text(f"#!/bin/sh\n{_sh(p.probe)} sub-hook\n", encoding="utf-8")
        hook.chmod(0o755)

    @staticmethod
    def _touch(path):
        later = time.time() + 60
        os.utime(path, (later, later))  # same size, new mtime: a refresh re-hashes it

    def test_a_checked_out_submodule_runs_nothing_and_fingerprints_as_head(self):
        p = self._repo()
        r = _wtree(p.repo)
        self.assertEqual(p.fired(), set(), "wtree.sh ran a command the submodule's config names")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, self.head_tree), r.stderr)

    def test_a_moved_submodule_still_changes_the_fingerprint(self):
        p = self._repo()
        (self.sub / "g.txt").write_text("new\n", encoding="utf-8")
        _quiet_git(self.sub, "-c", "filter.sf.clean=", "add", "g.txt")
        _quiet_git(self.sub, "commit", "-qm", "moved")
        moved = _quiet_git(self.sub, "rev-parse", "HEAD").stdout.strip()
        p.fired()
        self._touch(self.sub / "f.txt")
        idx = p.dir / "want.index"
        env = {**_CLEAN_ENV, "GIT_INDEX_FILE": str(idx)}
        subprocess.run(["git", "-C", str(p.repo), "read-tree", "HEAD"], env=env, check=True, stdin=subprocess.DEVNULL)
        subprocess.run(["git", "-C", str(p.repo), "update-index", "--cacheinfo", f"160000,{moved},sub"],
                       env=env, check=True, stdin=subprocess.DEVNULL)
        want = subprocess.run(["git", "-C", str(p.repo), "write-tree"], env=env, check=True, capture_output=True,
                              text=True, stdin=subprocess.DEVNULL).stdout.strip()
        r = _wtree(p.repo)
        self.assertEqual(p.fired(), set())
        self.assertEqual((r.returncode, r.stdout.strip()), (0, want), r.stderr)

    def test_an_untracked_nested_repository_runs_nothing(self):
        # A guard, not a regression: `add -A` adds an untracked nested repository as a gitlink
        # from its HEAD in-process, with or without gitlinks in the index (both branches here).
        for with_submodule in (True, False):
            with self.subTest(with_submodule=with_submodule):
                self._nested(with_submodule)

    def _nested(self, with_submodule):
        if with_submodule:
            p = self._repo()
        else:
            tmp = tempfile.mkdtemp()
            self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
            p = _Probe(tmp)
            p.commit("a.txt", "line1\n")
            self.head_tree = p._git("rev-parse", "HEAD^{tree}").stdout.strip()
        nested = p.repo / "nested"
        _quiet_git(p.repo, "init", "-q", str(nested))
        (nested / "n.txt").write_text("nested\n", encoding="utf-8")
        _quiet_git(nested, "add", "n.txt")
        _quiet_git(nested, "commit", "-qm", "n")
        self._plant(p, nested)
        self._touch(nested / "n.txt")
        r = _wtree(p.repo)
        self.assertEqual(p.fired(), set(), "wtree.sh ran a command a nested repository's config names")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(r.stdout.strip(), self.head_tree)

    def test_mutation_control_a_plain_add_runs_the_submodules_filter(self):
        p = self._repo()
        src = (SCRIPTS / "wtree.sh").read_text(encoding="utf-8")
        self.assertEqual(src.count('if [ -s "$CUSTODY/wtree-gitlinks" ]; then'), 1, "the gitlink branch moved")
        mutant = p.dir / "wtree_control.sh"
        mutant.write_text(src.replace('if [ -s "$CUSTODY/wtree-gitlinks" ]; then', "if false; then"),
                          encoding="utf-8")
        _wtree(p.repo, script=mutant)
        self.assertIn("sub-clean", p.fired(), "control: a plain `add -A` never probed the submodule")


class WtreeRefusesWhenTheUnverifiableCheckFails(unittest.TestCase):
    """Codex on this branch (P2): the exit-3 check piped diff-index into check-attr into a reader, so
    a failing diff-index or check-attr left HIT empty and the TREE was printed as if no declared
    filter applied. Each status decides now: a failed check is no fingerprint (exit 1)."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        p.arm_filter()
        (p.repo / "a.txt").write_text("CHANGED\n", encoding="utf-8")
        r = _wtree(p.repo)
        self.assertEqual(r.returncode, 3, "fixture: the changed filtered path is not unverifiable")
        return p

    def _failing(self, p, sub):
        bindir = p.dir / f"bin-{sub}"
        bindir.mkdir()
        (bindir / "git").write_text(
            '#!/bin/sh\nfor a in "$@"; do [ "$a" = ' + sub + ' ] && { echo "fatal: forced" >&2; exit 128; }; done\n'
            "exec " + _sh(_REAL_GIT) + ' "$@"\n', encoding="utf-8")
        (bindir / "git").chmod(0o755)
        return {**_CLEAN_ENV, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}

    def test_a_failing_diff_index_or_check_attr_is_no_fingerprint(self):
        for sub in ("diff-index", "check-attr"):
            with self.subTest(failing=sub):
                p = self._repo()
                r = _wtree(p.repo, env=self._failing(p, sub))
                self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
                self.assertIn("no fingerprint", r.stderr)
                self.assertEqual(p.fired(), set())


class WtreeTrustsNoSameUidConfigOrEnvironment(unittest.TestCase):
    """W4-02 (P1): on a single-host fleet the worker runs as the coordinator's uid, so
    `~/.gitconfig` is as much the worker's to write as `.git/config`. A global clean filter both
    ran in the coordinator and CHOSE the fingerprint: `printf 'v1'` mapped a tampered file back to
    its committed blob, so a tree no test saw printed `HEAD^{tree}` and verify graded it FRESH.
    W4-07: the environment pointers that outrank `-C` (GIT_DIR, GIT_INDEX_FILE, ...) are the
    caller's, not the fingerprint's. HOME is a scratch dir; nothing touches the real one."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        (p.repo / ".gitattributes").write_text("tampered.txt filter=evil\n", encoding="utf-8")
        p.commit("tampered.txt", "v1\n")
        self.head_tree = p._git("rev-parse", "HEAD^{tree}").stdout.strip()
        self.home = p.dir / "home"
        self.home.mkdir()
        clean = f"sh -c 'echo clean >> {_sh(p.marker)}; printf \"v1\\n\"'"
        subprocess.run(["git", "config", "-f", str(self.home / ".gitconfig"), "filter.evil.clean", clean],
                       check=True, capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_CONFIG", "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"))}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"))
        return p

    def _wtree(self, p, **extra):
        return subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env={**self.env, **extra},
                              capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)

    def test_a_global_filter_neither_runs_nor_chooses_a_tampered_fingerprint(self):
        p = self._repo()
        (p.repo / "tampered.txt").write_text("COMPLETELY DIFFERENT TAMPERED CONTENT\n", encoding="utf-8")
        r = self._wtree(p)
        self.assertEqual(p.fired(), set(), "wtree.sh ran a filter from the worker-writable ~/.gitconfig")
        self.assertNotEqual(r.stdout.strip(), self.head_tree, "a tampered tree fingerprinted as HEAD")
        # The path IS selected by a driver some config declares: comparing it to the committed blob
        # would need that command, so it is unverifiable (exit 3), never a value.
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertIn(_UNVERIFIABLE, r.stderr)
        self.assertIn("tampered.txt", r.stderr)

    def test_an_untouched_tree_still_fingerprints_as_head_under_a_global_filter(self):
        p = self._repo()
        r = self._wtree(p)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, self.head_tree), r.stderr)
        self.assertEqual(p.fired(), set())

    def test_an_untracked_file_still_changes_the_fingerprint(self):
        # Global config off must not hide content: a new file is still counted (the drop is
        # not a blanket "ignore everything"), and the global filter still does not run.
        p = self._repo()
        (p.repo / "new.txt").write_text("new\n", encoding="utf-8")
        r = self._wtree(p)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(r.stdout.strip(), self.head_tree)
        self.assertEqual(p.fired(), set())

    def test_an_inherited_git_dir_or_index_cannot_redirect_the_fingerprint(self):
        p = self._repo()
        other = _Probe(tempfile.mkdtemp(dir=str(p.dir)))
        other.commit("elsewhere.txt", "another repository\n")
        decoy_index = p.dir / "decoy.index"
        for extra in ({"GIT_DIR": str(other.repo / ".git")},
                      {"GIT_WORK_TREE": str(other.repo)},
                      {"GIT_INDEX_FILE": str(decoy_index)},
                      {"GIT_CONFIG_PARAMETERS": "'core.fsmonitor'='" + str(p.probe) + " fsmonitor'"},
                      {"GIT_CONFIG": os.devnull}):
            with self.subTest(extra=sorted(extra)):
                r = self._wtree(p, **extra)
                self.assertEqual((r.returncode, r.stdout.strip()), (0, self.head_tree), r.stderr)
                self.assertEqual(p.fired(), set())
        self.assertFalse(decoy_index.exists(), "wtree.sh seeded or wrote an inherited index")

    def test_an_inherited_git_config_cannot_hide_a_repo_driver_from_the_listing(self):
        # GIT_CONFIG names the one file `git config --list` reads: inherited, it emptied the
        # driver listing while `add -A` still loaded the repo config and ran its filter.
        p = self._repo()
        p.arm_filter()
        (p.repo / "tampered.txt").write_text("changed\n", encoding="utf-8")
        r = self._wtree(p, GIT_CONFIG=os.devnull)
        self.assertEqual(p.fired(), set(), "a repo filter ran behind an inherited GIT_CONFIG")
        self.assertEqual(r.returncode, 3, r.stderr)

    def test_git_is_resolved_once_to_an_absolute_path(self):
        # gitexec.py's rule: every call runs the one absolute git found at startup.
        code = "\n".join(ln.split(" #", 1)[0] for ln in (SCRIPTS / "wtree.sh").read_text(encoding="utf-8")
                         .splitlines() if not ln.lstrip().startswith("#"))
        # `git` in a command-word position: a line start, `$(`, a pipe, `;`/`&&`, or env's argv.
        bare = r'(?m)(^\s*|\$\(\s*|\|\s*|;\s*|&&\s*|env "\$@"\s+)git\s'
        self.assertNotRegex(code, bare, "a bare, PATH-resolved git call is left")
        self.assertIn('"$GIT" -C', code)
        self.assertIn("command -v git", code)


def _bounded(argv, env, timeout=20):
    """``argv`` in a session of its own: its CompletedProcess, or None once it outlives ``timeout``
    (the whole process group is killed then, so a child blocked opening a FIFO never outlives the
    test and a regression fails fast instead of hanging the suite)."""
    proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return None
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


class WtreeFingerprintsTheRepositoryItIsGiven(unittest.TestCase):
    """Codex, round 5 (P1): `TOP=$(git rev-parse --show-toplevel)` stripped the trailing newline of
    the repository's path, so wtree.sh pointed at /tmp/repo<NL> fingerprinted /tmp/repo, ANOTHER
    repository, and printed that one's tree. Every path git hands wtree.sh (the toplevel, the git
    dir, the common dir, the index) is now read byte-exact, and so is every core.* value it carries."""

    def _repo_at(self, path, body):
        path.mkdir()
        _quiet_git(path, "init", "-q")
        (path / "a.txt").write_text(body, encoding="utf-8")
        _quiet_git(path, "add", "-A")
        _quiet_git(path, "commit", "-qm", "c")
        return _quiet_git(path, "rev-parse", "HEAD^{tree}").stdout.strip()

    def _dir(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        return Path(os.path.realpath(tmp))

    def test_a_repository_path_ending_in_a_newline_never_fingerprints_the_other_one(self):
        d = self._dir()
        requested = self._repo_at(d / "repo\n", "the requested repository\n")
        other = self._repo_at(d / "repo", "a different repository\n")
        self.assertNotEqual(requested, other, "fixture: the two repositories hold the same tree")
        r = _wtree(d / "repo\n")
        self.assertNotEqual(r.stdout.strip(), other, "wtree.sh fingerprinted the repository at the stripped path")
        # Its common dir holds the newline, which an alternates file cannot name: no fingerprint.
        self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
        self.assertIn("no fingerprint", r.stderr)

    def test_a_linked_worktree_path_ending_in_a_newline_fingerprints_itself(self):
        # Its common dir is the main repository's, which an alternates file names, so the exact path
        # stages THIS work tree and prints its own tree, never the neighbour's.
        d = self._dir()
        head_tree = self._repo_at(d / "main", "the requested work tree\n")
        other = self._repo_at(d / "wt", "a different repository\n")
        add = _quiet_git(d / "main", "worktree", "add", "-q", "--detach", str(d / "wt\n"))
        self.assertEqual(add.returncode, 0, add.stderr)
        r = _wtree(d / "wt\n")
        self.assertNotEqual(r.stdout.strip(), other, "wtree.sh fingerprinted the repository at the stripped path")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, head_tree), r.stderr)

    def test_a_core_value_reaches_the_custody_byte_exact(self):
        # `core.eol = "lf\n"` is no eol setting to the repository's own git (it is not `lf`); the
        # stripped `lf` carried a different setting into custody. A git first on PATH records the
        # GIT_CONFIG pairs of every call wtree.sh makes.
        d = self._dir()
        self._repo_at(d / "repo", "one\n")
        _quiet_git(d / "repo", "config", "core.eol", "lf\n")
        bindir = d / "envbin"
        bindir.mkdir()
        log = d / "pairs.jsonl"
        (bindir / "git").write_text(
            f"#!{sys.executable} -I\nimport json, os, sys\n"
            f"with open({str(log)!r}, 'a', encoding='utf-8') as fh:\n"
            "    fh.write(json.dumps({k: v for k, v in os.environ.items() if k.startswith('GIT_CONFIG_')}) + '\\n')\n"
            f"os.execv({_REAL_GIT!r}, [{_REAL_GIT!r}] + sys.argv[1:])\n", encoding="utf-8")
        (bindir / "git").chmod(0o755)
        r = _wtree(d / "repo", env={**_CLEAN_ENV, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"})
        self.assertEqual(r.returncode, 0, r.stderr)
        carried = set()
        for line in log.read_text(encoding="utf-8").splitlines():
            env = json.loads(line)
            carried |= {env.get(f"GIT_CONFIG_VALUE_{i}") for i in range(int(env.get("GIT_CONFIG_COUNT", 0)))
                        if env.get(f"GIT_CONFIG_KEY_{i}") == "core.eol"}
        self.assertEqual(carried, {"lf\n"}, "core.eol did not reach the custody as the repository declares it")


# Every file wtree.sh copies into its custody (sharedindex: the split index's shared part).
_CUSTODY_COPIES = ("info/exclude", "info/attributes", "shallow", "info/sparse-checkout", "sharedindex", "index")


class WtreeCustodyCopiesReadOnlyTheDescriptorTheyCheck(unittest.TestCase):
    """Codex, round 5 (P2): copy_regular checked a file's type BY PATH and then `cp -p` opened it by
    path again, so a still-running worker that swapped in a FIFO between the two hung the
    coordinator (cp's open blocks with no writer), and a symlink swapped in was followed. Each copy
    is now opened once, without blocking or following a final symlink, checked with fstat on that
    descriptor, size-capped and copied from it. The race is made deterministic: a shim first on PATH
    for the program that OPENS the file (`cp` before, `python3` now) swaps the regular file the
    fixture planted for a FIFO or a symlink as that program starts, i.e. after every check sh made
    by path. Runs are bounded, so a regression fails fast instead of hanging."""

    def _repo(self, target):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        git_dir = Path(os.path.realpath(p.repo)) / ".git"
        if target == "sharedindex":
            _quiet_git(p.repo, "update-index", "--split-index")
            path = sorted(git_dir.glob("sharedindex.*"))[0]
        elif target == "index":
            path = git_dir / "index"
        else:
            body = {"info/exclude": "hidden.txt\n", "info/attributes": "*.txt text\n",
                    "shallow": p._git("rev-parse", "HEAD").stdout, "info/sparse-checkout": "/*\n"}[target]
            path = git_dir / target
            path.parent.mkdir(exist_ok=True)
            path.write_text(body, encoding="utf-8")
        before = _wtree(p.repo)
        self.assertEqual(before.returncode, 0, f"fixture: {target} as a regular file is no fingerprint: {before.stderr}")
        return p, path

    def _swapping_env(self, p, path, kind):
        decoy = p.dir / "decoy"
        shutil.copyfile(path, decoy)
        swapped = p.dir / "swapped"
        swap = f"rm -f {_sh(path)} && " + (f"mkfifo {_sh(path)}" if kind == "fifo" else f"ln -s {_sh(decoy)} {_sh(path)}")
        bindir = p.dir / "swapbin"
        bindir.mkdir()
        # cp opened the one file it was handed; python3 opens every custody file, so it swaps at once.
        for name, hit in (("cp", "0"), ("python3", "1")):
            (bindir / name).write_text(
                "#!/bin/sh\n"
                f"hit={hit}\n"
                f'for a in "$@"; do [ "$a" = {_sh(path)} ] && hit=1; done\n'
                f'if [ "$hit" = 1 ] && [ ! -e {_sh(swapped)} ]; then : > {_sh(swapped)}; {swap}; fi\n'
                f'exec {_sh(shutil.which(name))} "$@"\n', encoding="utf-8")
            (bindir / name).chmod(0o755)
        return {**_CLEAN_ENV, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}, swapped

    def test_a_fifo_or_symlink_swapped_in_as_the_copy_opens_is_no_fingerprint_and_never_hangs(self):
        for target in _CUSTODY_COPIES:
            for kind in ("fifo", "symlink"):
                with self.subTest(target=target, kind=kind):
                    p, path = self._repo(target)
                    env, swapped = self._swapping_env(p, path, kind)
                    r = _bounded(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], env)
                    if r is None:
                        self.fail(f"wtree.sh hung on a {kind} swapped in at {target}")
                    self.assertTrue(swapped.exists(), "the swap never ran")
                    self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
                    self.assertIn("not a regular file", r.stderr)

    def test_a_file_over_its_cap_is_no_fingerprint_and_one_at_it_is_copied(self):
        caps = {"index": (1 << 30, "1 GiB"), "sharedindex": (1 << 30, "1 GiB")}
        for target in _CUSTODY_COPIES:
            cap, label = caps.get(target, (16 << 20, "16 MiB"))
            with self.subTest(target=target):
                p, path = self._repo(target)
                with open(path, "r+b") as fh:  # sparse: nothing is written past the content
                    fh.truncate(cap + 1)
                r = _bounded(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo)], _CLEAN_ENV)
                self.assertIsNotNone(r, f"wtree.sh hung on an oversized {target}")
                self.assertEqual((r.returncode, r.stdout), (1, ""), r.stderr)
                self.assertIn(f"not a regular file of at most {label}", r.stderr)
        p, path = self._repo("info/exclude")
        (p.repo / "hidden.txt").write_text("excluded\n", encoding="utf-8")
        with open(path, "r+b") as fh:
            fh.truncate(16 << 20)
        r = _wtree(p.repo)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, p._git("rev-parse", "HEAD^{tree}").stdout.strip()),
                         r.stderr)

    def test_every_copy_still_reads_as_the_repositorys_own_git_reads_it(self):
        # Regular files at every path, a split index included: an untouched checkout fingerprints as
        # HEAD (the index copy keeps its stat cache), an untracked file info/exclude hides stays out,
        # and one it does not hide still counts.
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        _quiet_git(p.repo, "update-index", "--split-index")
        info = p.repo / ".git" / "info"
        info.mkdir(exist_ok=True)
        (info / "exclude").write_text("hidden.txt\n", encoding="utf-8")
        (info / "attributes").write_text("*.txt text\n", encoding="utf-8")
        (info / "sparse-checkout").write_text("/*\n", encoding="utf-8")
        (p.repo / ".git" / "shallow").write_text(p._git("rev-parse", "HEAD").stdout, encoding="utf-8")
        (p.repo / "hidden.txt").write_text("excluded\n", encoding="utf-8")
        self.assertTrue(list((p.repo / ".git").glob("sharedindex.*")), "fixture: no split index")
        head_tree = p._git("rev-parse", "HEAD^{tree}").stdout.strip()
        r = _wtree(p.repo)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, head_tree), r.stderr)
        (p.repo / "new.txt").write_text("new\n", encoding="utf-8")
        r = _wtree(p.repo)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(r.stdout.strip(), head_tree)


# PR #649 review (PRRT_kwDOTWxN9c6vxaeq): an `includeIf` makes the effective config depend on WHERE
# and in WHAT ref state git runs — `gitdir:` (a linked worktree's own git dir), `onbranch:` (the
# checked-out branch), `hasconfig:remote.*.url:` (another key's value). The rule is to read the
# drivers in the same directory and ref state as the git call that could run them. verify.py's
# control worktree broke it (test_verify ConditionalIncludeFilterNeverRunsInTheControl); these pin
# that every other gate holds it when it runs in a worker's LINKED worktree.
_CONDITIONS = (
    ("gitdir", "includeIf.gitdir:**/worktrees/**.path"),
    ("onbranch", "includeIf.onbranch:work.path"),
    ("hasconfig", "includeIf.hasconfig:remote.*.url:https://example.invalid/**.path"),
)


class ConditionalIncludesAreReadWhereGitRuns(unittest.TestCase):

    def _linked(self, condition, key):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        include = p.dir / f"{condition}.gitconfig"
        include.write_text(f'[filter "{condition}"]\n\tclean = {p.probe} clean\n'
                           f'\tsmudge = {p.probe} smudge\n', encoding="utf-8")
        p._git("remote", "add", "origin", "https://example.invalid/r.git")
        p._git("config", key, str(include))
        linked = p.dir / "linked"
        r = p._git("worktree", "add", "-q", "-b", "work", str(linked), base)
        self.assertEqual(r.returncode, 0, r.stderr)
        info = p.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text(f"*.txt filter={condition}\n", encoding="utf-8")
        (linked / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        p.fired()
        # Positive control: plain git in the linked worktree runs the conditionally loaded filter.
        p._git("diff", "--no-ext-diff", "--no-textconv", "HEAD", "--", cwd=linked)
        self.assertIn("clean", p.fired(), f"the {condition}: include is not live in the worktree")
        return p, linked, base

    def test_every_gate_in_a_linked_worktree_blanks_a_conditionally_included_filter(self):
        for condition, key in _CONDITIONS:
            with self.subTest(condition=condition):
                p, linked, base = self._linked(condition, key)
                floor_guard.collect_diff(linked, floor_guard.merge_base(linked, base))
                self.assertEqual(p.fired(), set(), f"floor_guard ran the {condition}: filter")
                diff_scope.scope(linked, base)
                self.assertEqual(p.fired(), set(), f"diff_scope ran the {condition}: filter")
                out, err = evidence_run.working_tree_fingerprint(str(linked))
                self.assertEqual(p.fired(), set(), f"wtree.sh ran the {condition}: filter")
                self.assertIsInstance(err, evidence_run.WtreeUnverifiable)

    def test_the_enumeration_in_the_linked_worktree_sees_what_the_source_does_not(self):
        p, linked, _ = self._linked("gitdir", _CONDITIONS[0][1])
        self.assertFalse([k for k, _ in gitexec.driver_blanks(p.repo) if k.startswith("filter.gitdir.")])
        self.assertTrue([k for k, _ in gitexec.driver_blanks(linked) if k.startswith("filter.gitdir.")])


# PR #649 review (merge-driver class): a `merge.<driver>.driver`, selected by a `merge=<driver>`
# attribute, is a command git runs when it 3-way-merges a path — on the read side through
# `git merge-tree` (diff_scope.predict_merge, and wtree.sh predict-merge, which execs it). It is
# neutralised by overriding `merge.<driver>.driver` to `exit 1` (a shell builtin that runs nothing
# and fails the merge closed). A linear in-order range revert is trivial at every step, so verify's
# revert leg cannot reach a merge driver; it carries the override defensively all the same.
class MergeDriverNeutralised(unittest.TestCase):

    def _repo(self, recursive=False):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        # The probe RESOLVES the merge (writes a result and exits 0), so a merge that runs it looks
        # clean; neutralised, the same merge is a genuine textual conflict. That difference is how a
        # fired driver is told from a blanked one, independent of the marker.
        p.probe.write_text("#!/bin/sh\necho merge >> " + _sh(p.marker) + "\n"
                           ": > \"$2\"\nexit 0\n", encoding="utf-8")
        p.probe.chmod(0o755)
        p.commit("shared.txt", "base\n")
        p._git("checkout", "-q", "-b", "side")
        (p.repo / "shared.txt").write_text("side\n", encoding="utf-8")
        p._git("commit", "-qam", "side")
        p._git("checkout", "-q", "main" if p._git("rev-parse", "--verify", "-q", "main").returncode == 0 else "master")
        (p.repo / "shared.txt").write_text("mainline\n", encoding="utf-8")
        p._git("commit", "-qam", "main")
        self.main = "main" if p._git("rev-parse", "--verify", "-q", "main").returncode == 0 else "master"
        p._git("config", "merge.m.driver", f"{p.probe} %O %A %B")
        if recursive:
            p._git("config", "merge.m.recursive", "m2")
            p._git("config", "merge.m2.driver", f"{p.probe} rec %O %A %B")
        (p.repo / ".git" / "info" / "attributes").write_text("shared.txt merge=m\n", encoding="utf-8")
        p.fired()
        # Positive control: plain merge-tree runs the driver, which resolves (exit 0) — so a GREEN
        # below both suppresses the marker AND flips the verdict back to a real conflict.
        clean = p._git("merge-tree", "--write-tree", self.main, "side")
        self.assertEqual(clean.returncode, 0, "fixture: the merge driver did not resolve on bare git")
        self.assertIn("merge", p.fired())
        return p

    def test_predict_merge_runs_no_merge_driver(self):
        p = self._repo()
        # predict_merge returns (clean, conflicts, ...): neutralised, the divergent merge that the
        # driver would have resolved is left as a real conflict — the fail-closed direction.
        result = diff_scope.predict_merge(p.repo, self.main, "side")
        self.assertEqual(p.fired(), set(), "diff_scope.predict_merge ran the merge driver")
        self.assertFalse(result["clean"], "neutralised, the divergent merge must read as a conflict")
        self.assertIn("shared.txt", result["conflicts"])

    def test_mutation_control_without_the_blanks_the_merge_driver_runs(self):
        p = self._repo()
        # The pre-fix prediction: no blanks AND no custody (merge-tree reads the repo's config).
        with mock.patch.object(diff_scope, "_driver_blanks", lambda repo: []), \
                mock.patch.object(diff_scope, "_custody", _no_custody):
            diff_scope.predict_merge(p.repo, self.main, "side")
        self.assertIn("merge", p.fired(),
                      "control: with the blanks removed the merge driver must run")

    def test_the_recursive_inner_driver_is_neutralised_too(self):
        p = self._repo(recursive=True)
        pairs = dict(gitexec.driver_blanks(p.repo))
        self.assertEqual(pairs.get("merge.m.driver"), "exit 1")
        self.assertEqual(pairs.get("merge.m2.driver"), "exit 1", "the recursive inner driver is not neutralised")

    def test_wtree_predict_merge_entry_runs_no_merge_driver(self):
        # `wtree.sh predict-merge` execs diff_scope.py --predict-merge; cover that entry point too.
        p = self._repo()
        r = subprocess.run(["sh", str(SCRIPTS / "wtree.sh"), str(p.repo), "predict-merge",
                            self.main, "side"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120)
        self.assertEqual(p.fired(), set(), "wtree.sh predict-merge ran the merge driver")
        self.assertEqual(r.returncode, 1, "a divergent merge must predict a conflict (exit 1)")


# PR #649 review (PRRT_kwDOTWxN9c6vzAIE): an empty blank list must mean "no driver declared",
# never "could not tell". A config query that errors, times out, or prints output that cannot be
# parsed used to return [] and let the gate run its content-reading git command with every planted
# driver live. Each copy now stops the gate in its own vocabulary. git itself answers an EMPTY but
# valid config with exit 0 and no output (pinned below), so exit 0 + nothing matching proceeds,
# and anything else stops.
_REAL_GIT = shutil.which("git")


def _fake_git(dirpath, mode):
    """A `git` that misbehaves ONLY for `config --list` — `fail` exits 128, `garbage` exits 0
    with output no NUL terminates — and delegates every other call to the real git, so the gate's
    content-reading command still runs (and would run any planted driver)."""
    action = {"fail": 'echo "fatal: forced config failure" >&2; exit 128',
              "garbage": "printf 'filter.x.clean'; exit 0"}[mode]
    script = Path(dirpath) / "git"
    script.write_text('#!/bin/sh\ncase " $* " in\n  *" config --list "*) ' + action + " ;;\nesac\n"
                      "exec " + _sh(_REAL_GIT) + ' "$@"\n', encoding="utf-8")
    script.chmod(0o755)
    return script


class DriverQueryFailsClosed(unittest.TestCase):

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        p.arm_filter()
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        return p, base

    def test_git_answers_an_empty_valid_config_with_exit_0_and_no_output(self):
        # The contract the copies lean on: NOT exit 1 (that is `git config --get`'s "missing").
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        subprocess.run(["git", "init", "-q", str(tmp / "r")], env=_CLEAN_ENV, check=True,
                       stdin=subprocess.DEVNULL)
        (tmp / "r" / ".git" / "config").write_text("", encoding="utf-8")
        env = {k: v for k, v in _CLEAN_ENV.items() if not k.startswith("GIT_CONFIG_")}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        r = subprocess.run(["git", "-C", str(tmp / "r"), "config", "--list", "-z", "--name-only"],
                           env=env, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertEqual((r.returncode, r.stdout), (0, b""))

    def test_none_declared_proceeds_in_every_copy(self):
        verify = _load("verify_failclosed_none", "verify.py")
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        self.assertEqual(gitexec.driver_blanks(p.repo), [])
        self.assertEqual(diff_scope._driver_blanks(p.repo), [])
        self.assertEqual(verify._Authority.driver_blanks(p.repo), [])

    def test_every_copy_refuses_a_failed_or_unparseable_query(self):
        # The parity of the fail-closed contract: same failure, each copy refuses in its own terms.
        verify = _load("verify_failclosed", "verify.py")
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)
        p, _ = self._repo()
        for mode in ("fail", "garbage"):
            with self.subTest(mode=mode):
                fake = str(_fake_git(p.dir, mode))
                with mock.patch.object(gitexec, "GIT", fake):
                    with self.assertRaises(gitexec.DriverQueryFailed):
                        gitexec.driver_blanks(p.repo)
                with mock.patch.object(diff_scope, "GIT", fake):
                    with self.assertRaises(diff_scope.ScopeError) as cm:
                        diff_scope._driver_blanks(p.repo)
                    self.assertEqual(cm.exception.kind, "diff_failed")
                with mock.patch.object(verify._Authority, "git", fake):
                    with self.assertRaises(verify._Authority.DriverQueryFailed):
                        verify._Authority.driver_blanks(p.repo)

    def test_a_timed_out_query_refuses(self):
        p, _ = self._repo()
        real_run = subprocess.run

        def slow(argv, *a, **kw):
            if "config" in argv and "--list" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout", 30))
            return real_run(argv, *a, **kw)
        with mock.patch.object(gitexec.subprocess, "run", side_effect=slow):
            with self.assertRaises(gitexec.DriverQueryFailed):
                gitexec.driver_blanks(p.repo)
        with mock.patch.object(diff_scope.subprocess, "run", side_effect=slow):
            with self.assertRaises(diff_scope.ScopeError):
                diff_scope._driver_blanks(p.repo)

    def test_floor_guard_stops_and_runs_no_filter(self):
        for mode in ("fail", "garbage"):
            with self.subTest(mode=mode):
                p, base = self._repo()
                mb = floor_guard.merge_base(p.repo, base)
                # floor_guard loads its OWN gitexec (_sibling), so patch that module's GIT.
                with mock.patch.object(floor_guard.gitexec, "GIT", str(_fake_git(p.dir, mode))):
                    with self.assertRaises(floor_guard.GuardError) as cm:
                        floor_guard.collect_diff(p.repo, mb)
                self.assertIn("driver config", str(cm.exception))
                self.assertEqual(p.fired(), set(), "floor_guard ran a filter with no blanks")

    def test_diff_scope_stops_and_runs_no_filter(self):
        for mode in ("fail", "garbage"):
            with self.subTest(mode=mode):
                p, base = self._repo()
                with mock.patch.object(diff_scope, "GIT", str(_fake_git(p.dir, mode))):
                    with self.assertRaises(diff_scope.ScopeError) as cm:
                        diff_scope.changed_files(p.repo, base)
                self.assertEqual(cm.exception.kind, "diff_failed")
                self.assertEqual(p.fired(), set(), "diff_scope ran a filter with no blanks")

    def test_wtree_stops_with_no_fingerprint_and_runs_no_filter(self):
        for mode in ("fail", "garbage"):
            with self.subTest(mode=mode):
                p, _ = self._repo()
                bindir = p.dir / f"bin-{mode}"
                bindir.mkdir()
                _fake_git(bindir, mode)
                path = str(bindir) + os.pathsep + os.environ["PATH"]
                with mock.patch.dict(os.environ, {"PATH": path}):
                    out, err = evidence_run.working_tree_fingerprint(str(p.repo))
                self.assertIsNone(out)
                self.assertNotIsInstance(err, evidence_run.WtreeUnverifiable)
                self.assertIn("config", err)
                self.assertEqual(p.fired(), set(), "wtree.sh ran a filter with no blanks")



class TheAnchorRuleWalksEverySymbolicHop(unittest.TestCase):
    """remote_tracking_commit (W3-07; Codex review round 2, P1): for-each-ref's %(symref) is a
    symbolic chain's recursively resolved END, so a local bridge inside it was invisible. Each hop
    is read with `symbolic-ref --no-recurse`; where that cannot run (git older than 2.39) a
    symbolic name is refused, while a plain remote-tracking ref still resolves."""

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.git_("init", "-q", "-b", "main")
        self.git_("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty",
                  "-m", "c")
        self.tip = self.git_("rev-parse", "HEAD")
        self.git_("update-ref", "refs/remotes/origin/main", "HEAD")
        self.git_("update-ref", "refs/remotes/origin/retired", "HEAD")
        self.git_("symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/retired")
        self.git_("symbolic-ref", "refs/remotes/w/key", "refs/heads/bridge")
        self.git_("symbolic-ref", "refs/remotes/w/hop", "refs/remotes/origin/main")

    def git_(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def runner(self, no_recurse=True):
        def run(*args):
            if not no_recurse and "--no-recurse" in args:
                return 129, ""  # git < 2.39: unknown option
            r = subprocess.run(gitexec.argv("-C", str(self.repo), *args), capture_output=True,
                               text=True, env=gitexec.env())
            return r.returncode, r.stdout
        return run

    def test_a_local_bridge_is_refused_and_a_remote_only_chain_resolves(self):
        commit, target, why = gitexec.remote_tracking_commit(self.runner(), "refs/remotes/w/key")
        self.assertIsNone(commit, target)
        self.assertIn("refs/heads/bridge", why)
        commit, target, why = gitexec.remote_tracking_commit(self.runner(), "refs/remotes/w/hop")
        self.assertEqual((commit, target, why), (self.tip, "refs/remotes/origin/main", None))

    def test_without_no_recurse_a_symbolic_name_fails_closed_and_a_plain_ref_resolves(self):
        old = self.runner(no_recurse=False)
        for name in ("refs/remotes/w/key", "refs/remotes/w/hop"):
            with self.subTest(name=name):
                commit, _target, why = gitexec.remote_tracking_commit(old, name)
                self.assertIsNone(commit)
                self.assertIn("one hop at a time", why)
        commit, _target, why = gitexec.remote_tracking_commit(old, "refs/remotes/origin/main")
        self.assertEqual(commit, self.tip, why)


class TheAnchorListingSplitsOnItsRecordTerminatorOnly(unittest.TestCase):
    """remote_tracking_commit (independent re-attack, A): the for-each-ref listing was split with
    str.splitlines(), which breaks on U+2028, U+2029 and U+0085 — characters git accepts in a
    refname — and parsed into a last-wins dict, so a fetched branch `x<U+2028>refs/remotes/
    origin/main` replaced origin/main. Records are NUL+LF-terminated and split on that only; a
    malformed record or a refname seen twice refuses the listing."""

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run([*git, "init", "-q", "-b", "main"], check=True, capture_output=True)
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "honest"], check=True)
        self.honest = subprocess.run([*git, "rev-parse", "HEAD"], check=True,
                                     capture_output=True, text=True).stdout.strip()
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "worker"], check=True)
        self.worker = subprocess.run([*git, "rev-parse", "HEAD"], check=True,
                                     capture_output=True, text=True).stdout.strip()
        subprocess.run([*git, "update-ref", "refs/remotes/origin/main", self.honest], check=True)
        subprocess.run([*git, "symbolic-ref", "refs/remotes/origin/HEAD",
                        "refs/remotes/origin/main"], check=True)

    def run_(self, *args):
        r = subprocess.run(gitexec.argv("-C", str(self.repo), *args), capture_output=True,
                           env=gitexec.env())
        return r.returncode, r.stdout.decode("utf-8", "surrogateescape")

    def test_a_line_break_in_a_fetched_branch_name_never_replaces_the_real_ref(self):
        for ch in refname_breaks.LINE_BREAKS:
            with self.subTest(ch=ch):
                unplant = refname_breaks.plant(self.repo, ch, self.worker)
                try:
                    for name in ("refs/remotes/origin/main", "refs/remotes/origin/HEAD"):
                        commit, _target, why = gitexec.remote_tracking_commit(self.run_, name)
                        self.assertEqual(commit, self.honest, why)
                finally:
                    unplant()

    def test_a_refname_seen_twice_or_a_malformed_record_refuses_the_listing(self):
        oid = "a" * 40
        rec = f"refs/remotes/origin/main\0\0{oid}\0\n"
        self.assertEqual(gitexec._ref_records(rec, "refs/remotes/")[0],
                         {"refs/remotes/origin/main": ("", oid)})
        for out in (rec + rec, rec + "refs/remotes/x\0\n", "refs/remotes/origin/main\0\0" + oid,
                    rec.replace("\0\n", "\n")):
            with self.subTest(out=out):
                listed, why = gitexec._ref_records(out, "refs/remotes/")
                self.assertIsNone(listed)
                self.assertTrue(why)


# W4 custody sweep (audit W4-01/W4-02 class): driver_blanks LISTS the drivers a config declares,
# and the content-reading git then reads that config AGAIN. A sibling worker that adds a NEVER-SEEN
# driver in between - selected for every path through the shared `info/attributes` - had it run on
# the coordinator, whatever the listing said. floor_guard's, diff_scope's and hint_provenance's
# content-reading git now runs against a git dir the gate builds (gitexec.custody), whose config
# declares no driver. The racing sibling adds a fresh filter, textconv and merge driver before
# EVERY git launch; each GREEN case has a control that restores the pre-fix gate (blanks listed,
# no custody) under the same race and sees the late driver run.
def _racing_sibling(p):
    real = subprocess.run
    seq = p.__dict__.setdefault("race_seq", [0])
    common = p.repo / ".git"

    def run(argv, *a, **kw):
        if isinstance(argv, (list, tuple)) and argv and os.path.basename(os.fsdecode(argv[0])) == "git":
            seq[0] += 1
            name = f"late{seq[0]}"
            with open(common / "config", "a", encoding="utf-8") as fh:
                fh.write(f'[filter "{name}"]\n\tclean = "{p.probe}" {name}-clean\n'
                         f'\tsmudge = "{p.probe}" {name}-smudge\n'
                         f'[diff "{name}"]\n\ttextconv = "{p.probe}" {name}-textconv\n'
                         f'[merge "{name}"]\n\tdriver = "{p.probe}" {name}-merge %O %A %B\n')
            (common / "info").mkdir(exist_ok=True)
            with open(common / "info" / "attributes", "a", encoding="utf-8") as fh:
                fh.write(f"* filter={name} diff={name} merge={name}\n")
        return real(argv, *a, **kw)
    return mock.patch.object(subprocess, "run", run)


class ContentGitRunsNoDriverAddedAfterTheListing(unittest.TestCase):

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        (p.repo / "b.txt").write_text("brand new\n", encoding="utf-8")
        return p, base

    def _diverged(self):
        """Two branches changing shared.txt differently: merge-tree 3-way-merges that path."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("shared.txt", "base\n")
        main = p._git("symbolic-ref", "--short", "HEAD").stdout.strip()
        p._git("checkout", "-q", "-b", "side")
        p.commit("shared.txt", "side\n")
        p._git("checkout", "-q", main)
        p.commit("shared.txt", "mainline\n")
        return p, main

    def _race_and_control(self, p, call, bypass):
        with _racing_sibling(p):
            got = call()
        self.assertGreater(p.race_seq[0], 0, "the race never ran")
        self.assertEqual(p.fired(), set(), "a driver added after the listing ran on the coordinator")
        with _racing_sibling(p), contextlib.ExitStack() as stack:
            for target, attr in bypass:
                stack.enter_context(mock.patch.object(target, attr, _no_custody))
            try:
                call()
            except Exception:  # the control only has to RUN the planted driver, not succeed
                pass
        self.assertTrue(p.fired(), "control: the pre-custody gate never ran the late driver")
        return got

    def test_floor_guard(self):
        p, base = self._repo()
        mb = floor_guard.merge_base(p.repo, base)
        text = self._race_and_control(p, lambda: floor_guard.collect_diff(p.repo, mb),
                                      [(floor_guard.gitexec, "custody")])
        self.assertIn("+CHANGED", text)
        self.assertIn("+brand new", text)

    def test_diff_scope_scope(self):
        p, base = self._repo()
        self._race_and_control(p, lambda: diff_scope.scope(p.repo, base), [(diff_scope, "_custody")])
        self.assertIn("a.txt", diff_scope.changed_files(p.repo, base))

    def test_diff_scope_predict_merge(self):
        p, main = self._diverged()
        result = self._race_and_control(p, lambda: diff_scope.predict_merge(p.repo, main, "side"),
                                        [(diff_scope, "_custody")])
        self.assertFalse(result["clean"], "with no merge driver the divergent merge is a conflict")
        self.assertIn("shared.txt", result["conflicts"])

    def test_hint_provenance(self):
        p, base = self._repo()
        changes = self._race_and_control(
            p, lambda: hint_provenance.LiveSource(str(p.repo)).changes_since(base),
            [(hint_provenance.gitexec, "custody")])
        self.assertEqual(changes, {"a.txt": ("M", None), "b.txt": ("A", None)})

    def test_every_site_with_an_initialized_submodule_under_the_race(self):
        # Codex on PR #724: the same race, in a repository whose checked-out submodule plants a
        # filter, an fsmonitor and a hook in its OWN config; nothing runs from either.
        for site, call in (
                ("floor_guard", lambda p, base: floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base))),
                ("diff_scope", lambda p, base: diff_scope.scope(p.repo, base)),
                ("hint_provenance", lambda p, base: hint_provenance.LiveSource(str(p.repo)).changes_since(base))):
            with self.subTest(site=site):
                p, base = self._repo()
                _plant_submodule(p)
                with _racing_sibling(p):
                    call(p, base)
                self.assertGreater(p.race_seq[0], 0, "the race never ran")
                self.assertEqual(p.fired(), set(), f"{site} ran a planted command")


class CustodyReadsWhatTheRepositoryReads(unittest.TestCase):
    """The custody must not change what an ordinary repository's diff says: the same tracked,
    staged, deleted, mode and untracked changes, rendered the same way, as the gate's plain git
    read before the custody (no driver declared, so both are the repository's own answer)."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        (p.repo / "keep.txt").write_text("keep\n", encoding="utf-8")
        (p.repo / "gone.txt").write_text("gone\n", encoding="utf-8")
        (p.repo / "run.sh").write_text("echo hi\n", encoding="utf-8")
        base = p.commit("a.txt", "line1\nline2\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        (p.repo / "staged.txt").write_text("staged\n", encoding="utf-8")
        p._git("add", "staged.txt")
        (p.repo / "gone.txt").unlink()
        (p.repo / "run.sh").chmod(0o755)
        (p.repo / "sub").mkdir()
        (p.repo / "sub" / "new file.txt").write_text("untracked\n", encoding="utf-8")
        return p, base

    def test_floor_guard_diff_is_unchanged(self):
        p, base = self._repo()
        mb = floor_guard.merge_base(p.repo, base)
        got = floor_guard.collect_diff(p.repo, mb)
        with mock.patch.object(floor_guard.gitexec, "custody", _no_custody):
            want = floor_guard.collect_diff(p.repo, mb)
        self.assertEqual(got, want)
        for needle in ("+CHANGED", "+staged", "-gone", "new mode 100755", "+untracked"):
            self.assertIn(needle, got)

    def test_diff_scope_and_hint_provenance_are_unchanged(self):
        p, base = self._repo()
        got = diff_scope.changed_files(p.repo, base)
        live = hint_provenance.LiveSource(str(p.repo)).changes_since(base)
        with mock.patch.object(diff_scope, "_custody", _no_custody), \
                mock.patch.object(hint_provenance.gitexec, "custody", _no_custody):
            self.assertEqual(got, diff_scope.changed_files(p.repo, base))
            self.assertEqual(live, hint_provenance.LiveSource(str(p.repo)).changes_since(base))
        self.assertEqual(got, ["a.txt", "gone.txt", "run.sh", "staged.txt", "sub/new file.txt"])


def _plant_submodule(p):
    """An initialized submodule `sub` in p.repo whose OWN config and attributes name the probe on
    every channel a child git inside it could take: core.fsmonitor, a clean/smudge filter selected
    for every path through its info/attributes, and a post-index-change hook. Then a same-size
    stat change inside it, so anything that refreshes its index re-hashes a file (and so runs a
    filter). Returns the submodule's work tree."""
    lib = p.dir / "lib"
    lib.mkdir()
    subprocess.run(["git", "init", "-q", str(lib)], env=_CLEAN_ENV, check=True, stdin=subprocess.DEVNULL)
    (lib / "f.txt").write_text("library\n", encoding="utf-8")
    for args in (("add", "f.txt"), ("-c", "user.email=a@b", "-c", "user.name=a", "commit", "-qm", "lib")):
        subprocess.run(["git", "-C", str(lib), *args], env=_CLEAN_ENV, check=True, stdin=subprocess.DEVNULL,
                       capture_output=True)
    r = p._git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(lib), "sub")
    assert r.returncode == 0, r.stderr
    p._git("commit", "-qm", "add sub")
    sub = p.repo / "sub"
    for key, var in (("core.fsmonitor", "fsmonitor"), ("filter.sf.clean", "sub-clean"),
                     ("filter.sf.smudge", "sub-smudge")):
        p._git("config", key, f"{p.probe} {var}", cwd=sub)
    sub_git = Path(p._git("rev-parse", "--absolute-git-dir", cwd=sub).stdout.strip())
    (sub_git / "info").mkdir(exist_ok=True)
    (sub_git / "info" / "attributes").write_text("* filter=sf\n", encoding="utf-8")
    hook = sub_git / "hooks" / "post-index-change"
    hook.parent.mkdir(exist_ok=True)
    hook.write_text(f"#!/bin/sh\n{_sh(p.probe)} sub-hook\n", encoding="utf-8")
    hook.chmod(0o755)
    later = time.time() + 30
    os.utime(sub / "f.txt", (later, later))  # same size, new mtime: a refresh re-hashes it
    return sub


class NoChildGitInsideASubmodule(unittest.TestCase):
    """Codex on PR #724 (P1): a work-tree diff of a repository with a checked-out submodule asks
    whether the submodule is dirty by starting a child `git status` INSIDE it, under the
    submodule's own config and attributes, which the custody never sees: a filter planted there
    ran on the coordinator. Every custody diff now carries gitexec.NO_SUBMODULE_CHILD
    (`--ignore-submodules=dirty`), which still reports a moved gitlink without the child."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        sub = _plant_submodule(p)
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        # Positive control: plain git's work-tree diff runs the submodule's own filter.
        p._git("diff", "--no-ext-diff", "HEAD", "--")
        self.assertIn("sub-clean", p.fired(), "the submodule's planted filter is not live")
        later = time.time() + 60
        os.utime(sub / "f.txt", (later, later))
        return p, base, sub

    SITES = {
        "floor_guard": (lambda p, base: floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base)),
                        lambda: floor_guard.gitexec),
        "diff_scope": (lambda p, base: diff_scope.changed_files(p.repo, base), lambda: diff_scope.gitexec),
        "hint_provenance": (lambda p, base: hint_provenance.LiveSource(str(p.repo)).changes_since(base),
                            lambda: hint_provenance.gitexec),
    }

    def test_no_site_starts_a_child_git_in_the_submodule(self):
        for site, (call, _mod) in self.SITES.items():
            with self.subTest(site=site):
                p, base, _sub = self._repo()
                call(p, base)
                self.assertEqual(p.fired(), set(), f"{site} ran a command the submodule's config names")

    def test_mutation_control_probing_submodule_dirtiness_runs_its_filter(self):
        for site, (call, mod) in self.SITES.items():
            with self.subTest(site=site):
                p, base, _sub = self._repo()
                with mock.patch.object(mod(), "NO_SUBMODULE_CHILD", "--ignore-submodules=none"):
                    call(p, base)
                self.assertIn("sub-clean", p.fired(), f"control: {site} never probed the submodule")

    def test_a_moved_submodule_commit_is_still_reported(self):
        p, base, sub = self._repo()
        (sub / "g.txt").write_text("new\n", encoding="utf-8")
        for args in (("add", "g.txt"), ("commit", "-qm", "moved")):
            r = subprocess.run(["git", "-C", str(sub), "-c", "user.email=a@b", "-c", "user.name=a",
                                "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                               env={**_CLEAN_ENV, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "filter.sf.clean",
                                    "GIT_CONFIG_VALUE_0": ""},
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
            self.assertEqual(r.returncode, 0, r.stderr)
        p.fired()
        later = time.time() + 90
        os.utime(sub / "f.txt", (later, later))
        mb = floor_guard.merge_base(p.repo, base)
        self.assertIn("+Subproject commit", floor_guard.collect_diff(p.repo, mb))
        self.assertIn("sub", diff_scope.changed_files(p.repo, base))
        self.assertIn("sub", hint_provenance.LiveSource(str(p.repo)).changes_since(
            p._git("rev-parse", "HEAD").stdout.strip()))
        self.assertEqual(p.fired(), set(), "reporting the moved gitlink ran the submodule's commands")


class CustodyKeepsLineEndingData(unittest.TestCase):
    """Codex on the W4-02 branch (P1), applied to the shared custody: `info/attributes` and the
    data settings that steer normalisation are data, not commands. Without them a clean CRLF
    checkout of an `eol=crlf` (or `core.autocrlf`) path, once touched, read as modified in custody."""

    def _repo(self, how):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\nline2\n")
        if how == "info/attributes":
            (p.repo / ".git" / "info").mkdir(exist_ok=True)
            (p.repo / ".git" / "info" / "attributes").write_text("*.txt text eol=crlf\n", encoding="utf-8")
        elif how.startswith("core.attributesFile"):
            # Codex on the W4-02 branch: a repository-scope core.attributesFile, absolute or
            # relative to the work tree top (here, beside the repository, so it is not untracked).
            (p.dir / "attrs").write_text("*.txt text eol=crlf\n", encoding="utf-8")
            p._git("config", "core.attributesFile", str(p.dir / "attrs") if how.endswith("absolute") else "../attrs")
        else:
            p._git("config", "core.autocrlf", "true")
        (p.repo / "a.txt").unlink()
        p._git("checkout", "--", "a.txt")
        self.assertEqual((p.repo / "a.txt").read_bytes(), b"line1\r\nline2\r\n", "fixture: not a CRLF checkout")
        later = time.time() + 30
        os.utime(p.repo / "a.txt", (later, later))  # touched: git must re-read it
        return p, base

    def test_a_clean_crlf_checkout_reads_unchanged_in_custody(self):
        for how in ("info/attributes", "core.autocrlf", "core.attributesFile absolute",
                    "core.attributesFile relative"):
            with self.subTest(how=how):
                p, base = self._repo(how)
                diff = floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base))
                self.assertNotIn("a.txt", diff)
                self.assertEqual(diff_scope.changed_files(p.repo, base), [])
                self.assertEqual(hint_provenance.LiveSource(str(p.repo)).changes_since(base), {})
                with gitexec.custody(p.repo) as c:
                    r = subprocess.run(c.argv("status", "--porcelain", gitexec.NO_SUBMODULE_CHILD),
                                       env=c.env(), capture_output=True, text=True, stdin=subprocess.DEVNULL)
                self.assertEqual((r.returncode, r.stdout), (0, ""), r.stderr)

    def test_the_posix_custody_status_reads_it_clean_too(self):
        posix = _posix()
        for how in ("info/attributes", "core.attributesFile absolute"):
            with self.subTest(how=how):
                p, _base = self._repo(how)
                proc = posix._git(["status", "--porcelain"], cwd=p.repo)
                self.assertEqual((proc.returncode, proc.stdout), (0, ""), proc.stderr)

    def test_a_real_edit_still_shows(self):
        p, base = self._repo("info/attributes")
        (p.repo / "a.txt").write_bytes(b"line1\r\nEDITED\r\n")
        self.assertIn("+EDITED", floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base)))
        self.assertEqual(diff_scope.changed_files(p.repo, base), ["a.txt"])


def _posix():
    sys.path.insert(0, str(ROOT / "runtime"))
    try:
        return importlib.import_module("providers.posix")
    finally:
        sys.path.remove(str(ROOT / "runtime"))


def _finishes(fn, seconds=30):
    """fn() run in a thread; (finished, result or exception). A hang is (False, None)."""
    import threading
    box = {}

    def target():
        try:
            box["ok"] = fn()
        except Exception as exc:  # the refusal under test
            box["err"] = exc
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(seconds)
    return (not t.is_alive()), box.get("err", box.get("ok"))


class AnUnreadableAttributesFileIsRefused(unittest.TestCase):
    """Codex on the W4-02 branch: core.attributesFile is carried as CONTENT, read only as a bounded
    regular file without blocking. A FIFO (whose open would block), a symlink, a directory or an
    oversized file refuses every site; none hangs and none silently drops it."""

    def _repo(self, kind):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        (p.repo / "a.txt").write_text("CHANGED\n", encoding="utf-8")
        target = p.dir / "attrs"
        if kind == "fifo":
            os.mkfifo(target)
        elif kind == "symlink":
            (p.dir / "real").write_text("*.txt text\n", encoding="utf-8")
            os.symlink(p.dir / "real", target)
        elif kind == "directory":
            target.mkdir()
        else:
            target.write_bytes(b"#" * (gitexec.ATTRIBUTES_FILE_LIMIT + 1))
        p._git("config", "core.attributesFile", str(target))
        return p, base

    def test_every_site_refuses_and_none_hangs(self):
        posix = _posix()
        for kind in ("fifo", "symlink", "directory", "oversized"):
            p, base = self._repo(kind)
            mb = floor_guard.merge_base(p.repo, base)
            repo = p.repo
            for site, call, refusal in (
                    ("custody", lambda r=repo: gitexec.custody(r).__enter__(), gitexec.GitCustodyRefused),
                    ("floor_guard", lambda r=repo, m=mb: floor_guard.collect_diff(r, m), floor_guard.GuardError),
                    ("diff_scope", lambda r=repo, b=base: diff_scope.changed_files(r, b), diff_scope.ScopeError),
                    ("hint_provenance", lambda r=repo, b=base: hint_provenance.LiveSource(str(r)).changes_since(b),
                     hint_provenance.ProvenanceError)):
                with self.subTest(kind=kind, site=site):
                    done, got = _finishes(call)
                    self.assertTrue(done, f"{site} hung on a {kind} core.attributesFile")
                    self.assertIsInstance(got, refusal)
            with self.subTest(kind=kind, site="posix status"):
                done, got = _finishes(lambda r=repo: posix._git(["status", "--porcelain"], cwd=r))
                self.assertTrue(done, f"posix status hung on a {kind} core.attributesFile")
                self.assertEqual(got.returncode, 127, got)
                self.assertIn("core.attributesFile", got.stderr)


class NoUserOrSystemAttributesFileIsOpened(unittest.TestCase):
    """Codex on the W4-02 branch (round 3, P2), checked here: with no repository core.attributesFile
    the custody named none, so git opened its default user attributes file ($XDG_CONFIG_HOME/git/
    attributes, else ~/.config/git/attributes; the worker's to write on a one-uid host) and the
    system one, and a FIFO there hung the call. The custody now always names its own attributes
    file, and CUSTODY_ENV carries GIT_ATTR_NOSYSTEM=1."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")  # a diff reads attributes
        return p, base

    def _sites(self, p, base):
        posix = _posix()
        mb = floor_guard.merge_base(p.repo, base)
        return (("floor_guard", lambda: floor_guard.collect_diff(p.repo, mb)),
                ("diff_scope", lambda: diff_scope.changed_files(p.repo, base)),
                ("hint_provenance", lambda: hint_provenance.LiveSource(str(p.repo)).changes_since(base)),
                ("posix status", lambda: posix._git(["status", "--porcelain"], cwd=p.repo).stdout))

    def test_a_fifo_at_either_default_user_attributes_file_is_never_opened(self):
        for where in ("XDG_CONFIG_HOME", "HOME"):
            p, base = self._repo()
            empty = p.dir / "empty-home"
            empty.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(empty)}):
                os.environ.pop("XDG_CONFIG_HOME", None)
                want = {site: call() for site, call in self._sites(p, base)}
            fifo_root = p.dir / "fifo-home"
            if where == "XDG_CONFIG_HOME":
                (fifo_root / "git").mkdir(parents=True)
                os.mkfifo(fifo_root / "git" / "attributes")
                env = {"HOME": str(empty), "XDG_CONFIG_HOME": str(fifo_root)}
            else:
                (fifo_root / ".config" / "git").mkdir(parents=True)
                os.mkfifo(fifo_root / ".config" / "git" / "attributes")
                env = {"HOME": str(fifo_root)}
            for site, call in self._sites(p, base):
                with self.subTest(where=where, site=site), mock.patch.dict(os.environ, env):
                    if "XDG_CONFIG_HOME" not in env:
                        os.environ.pop("XDG_CONFIG_HOME", None)
                    done, got = _finishes(call)
                    self.assertTrue(done, f"{site} hung opening a default attributes file at {where}")
                    self.assertEqual(got, want[site])

    def test_every_custody_git_runs_with_system_attributes_off(self):
        p, base = self._repo()
        seen, real = [], subprocess.run

        def record(argv, *a, **kw):
            # Every git but the driver listing (`config --list`, which reads no attributes and
            # keeps gitexec.env's base so it resolves the repository its caller's git does).
            if (isinstance(argv, (list, tuple)) and argv and os.path.basename(os.fsdecode(argv[0])) == "git"
                    and "--list" not in argv):
                seen.append((argv[-4:], (kw.get("env") or {}).get("GIT_ATTR_NOSYSTEM")))
            return real(argv, *a, **kw)
        with mock.patch.object(subprocess, "run", record):
            for _site, call in self._sites(p, base):
                call()
        self.assertTrue(seen)
        self.assertEqual([s for s in seen if s[1] != "1"], [],
                         "a custody-floored git ran with the system attributes file live")


class NoUserIgnoreFileIsOpened(unittest.TestCase):
    """PR #724 re-attack (item 1): the custody named its own attributes file but no
    core.excludesFile, so a custody diff (and the in-repo `ls-files --others`) opened the default user
    ignore file ($XDG_CONFIG_HOME/git/ignore, else ~/.config/git/ignore) and a FIFO there blocked
    every site until its timeout. The custody now always names an excludes file - the repository's
    own core.excludesFile content, read safely, or /dev/null - and ls-files runs in custody."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        (p.repo / "new.txt").write_text("untracked\n", encoding="utf-8")  # read through the ignores
        return p, base

    def test_a_fifo_at_either_default_user_ignore_file_is_never_opened(self):
        sites = NoUserOrSystemAttributesFileIsOpened._sites
        for where in ("XDG_CONFIG_HOME", "HOME"):
            p, base = self._repo()
            empty = p.dir / "empty-home"
            empty.mkdir()
            with mock.patch.dict(os.environ, {"HOME": str(empty)}):
                os.environ.pop("XDG_CONFIG_HOME", None)
                want = {site: call() for site, call in sites(self, p, base)}
            fifo_root = p.dir / "fifo-home"
            if where == "XDG_CONFIG_HOME":
                (fifo_root / "git").mkdir(parents=True)
                os.mkfifo(fifo_root / "git" / "ignore")
                env = {"HOME": str(empty), "XDG_CONFIG_HOME": str(fifo_root)}
            else:
                (fifo_root / ".config" / "git").mkdir(parents=True)
                os.mkfifo(fifo_root / ".config" / "git" / "ignore")
                env = {"HOME": str(fifo_root)}
            for site, call in sites(self, p, base):
                with self.subTest(where=where, site=site), mock.patch.dict(os.environ, env):
                    if "XDG_CONFIG_HOME" not in env:
                        os.environ.pop("XDG_CONFIG_HOME", None)
                    done, got = _finishes(call, seconds=20)
                    self.assertTrue(done, f"{site} blocked opening a default ignore file at {where}")
                    self.assertEqual(got, want[site])

    def test_the_repositorys_own_excludes_file_still_applies(self):
        p, base = self._repo()
        (p.dir / "ignore-new").write_text("new.txt\n", encoding="utf-8")
        p._git("config", "core.excludesFile", str(p.dir / "ignore-new"))
        self.assertNotIn("new.txt", diff_scope.changed_files(p.repo, base))
        self.assertNotIn("untracked", floor_guard.collect_diff(p.repo, floor_guard.merge_base(p.repo, base)))


class BlockingRepositoryFilesAreRefusedUpFront(unittest.TestCase):
    """PR #724 re-attack (item 3): every git reads the repository's config and follows its
    includes, and a commit walk reads `shallow`, so a FIFO there blocked each site until its
    timeout. gitexec.refuse_blocking_files checks them - without git, without blocking - before
    any git runs, and a repository core.excludesFile is carried (read safely) rather than opened by
    git. Each is refused at once."""

    def _repo(self, kind):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        (p.repo / "a.txt").write_text("line1\nCHANGED\n", encoding="utf-8")
        (p.repo / "new.txt").write_text("untracked\n", encoding="utf-8")
        fifo = p.dir / "blocking"
        os.mkfifo(fifo)
        if kind == "shallow":
            os.rename(fifo, p.repo / ".git" / "shallow")
        elif kind == "include.path":
            with open(p.repo / ".git" / "config", "a", encoding="utf-8") as fh:  # `git config` would block
                fh.write(f'[include]\n\tpath = "{fifo}"\n')
        elif kind == "includeIf (relative)":
            with open(p.repo / ".git" / "config", "a", encoding="utf-8") as fh:
                fh.write(f'[includeIf "gitdir:{p.repo}/"]\n\tpath = ../../blocking\n')
        else:
            p._git("config", "core.excludesFile", str(fifo))
        return p, base

    def test_each_site_refuses_at_once(self):
        for kind in ("shallow", "include.path", "includeIf (relative)", "core.excludesFile"):
            p, base = self._repo(kind)
            for site, call, refusal in (
                    ("floor_guard", lambda r=p.repo, b=base: floor_guard.collect_diff(r, b), floor_guard.GuardError),
                    ("diff_scope", lambda r=p.repo, b=base: diff_scope.changed_files(r, b), diff_scope.ScopeError),
                    ("hint_provenance", lambda r=p.repo: hint_provenance.LiveSource(str(r)).changes_since("HEAD"),
                     hint_provenance.ProvenanceError)):
                with self.subTest(kind=kind, site=site):
                    done, got = _finishes(call, seconds=20)
                    self.assertTrue(done, f"{site} blocked on a FIFO {kind}")
                    self.assertIsInstance(got, refusal)

    def test_regular_includes_and_shallow_files_are_fine(self):
        p, base = self._repo("core.excludesFile")
        p._git("config", "--unset", "core.excludesFile")
        (p.dir / "inc").write_text("[core]\n\tquotePath = false\n", encoding="utf-8")
        p._git("config", "include.path", str(p.dir / "inc"))
        p._git("config", "includeIf.gitdir:/nowhere/.path", str(p.dir / "absent"))
        gitexec.refuse_blocking_files(p.repo)
        self.assertIn("a.txt", diff_scope.changed_files(p.repo, base))


class IncludeTargetsAreReadAsGitReadsThem(unittest.TestCase):
    """Codex on PR #724 (round 6): the include check split config on `\n` alone, so a CRLF config
    left `\r` on the path, checked a file that does not exist, missed the FIFO git actually opens,
    and git blocked until its timeout. Config is now parsed as git's own parser reads it, and a
    file it cannot read exactly refuses. Each case below names a FIFO the way git reads it; a
    positive control proves git itself would block on that very file."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        return p

    def _git_would_block(self, p):
        try:
            subprocess.run(["git", "-C", str(p.repo), "rev-parse", "HEAD"], env=_CLEAN_ENV,
                           capture_output=True, stdin=subprocess.DEVNULL, timeout=3)
        except subprocess.TimeoutExpired:
            return True
        return False

    def _cases(self, d):
        """(name, fifo file name, config text appended to .git/config)."""
        return (
            ("CRLF", "blocking", f"[include]\r\n\tpath = {d}/blocking\r\n"),
            ("quoted", "block ing", f'[include]\n\tpath = "{d}/block ing"\n'),
            ("escaped", 'bl"oc\\k', f'[include]\n\tpath = "{d}/bl\\"oc\\\\k"\n'),
            ("continued", "blocking", f"[include]\n\tpath = {d}/blo\\\ncking\n"),
            ("commented", "blocking", f"# path = /nowhere\n[include] ; a comment\n\tpath = {d}/blocking ; trailing # comment\n"),
            ("mixed-case", "blocking", f'[InClUdE]\n\tPaTh = {d}/blocking\n'),
            ("includeIf, escaped condition", "blocking", f'[IncludeIF "gitdir:{d}/\\"x/"]\n\tpath = {d}/blocking\n'),
            ("relative", "blocking", "[include]\n\tpath = ../../blocking\n"),
        )

    def test_each_syntax_names_the_fifo_git_opens_and_is_refused(self):
        for name, fifo_name, text in self._cases("{d}"):
            with self.subTest(case=name):
                p = self._repo()
                d = str(p.dir)
                os.mkfifo(p.dir / fifo_name)
                text = text.replace("{d}", d)
                with open(p.repo / ".git" / "config", "ab") as fh:
                    fh.write(text.encode("utf-8"))
                if name != "includeIf, escaped condition":  # a false condition: git never opens it
                    self.assertTrue(self._git_would_block(p), f"fixture: git does not open the {name} FIFO")
                done, got = _finishes(lambda r=p.repo: gitexec.refuse_blocking_files(r), seconds=10)
                self.assertTrue(done)
                self.assertIsInstance(got, gitexec.GitCustodyRefused, f"{name}: the FIFO was missed")
                done, got = _finishes(lambda r=p.repo: floor_guard.collect_diff(r, "HEAD"), seconds=10)
                self.assertTrue(done, f"floor_guard blocked on the {name} include")
                self.assertIsInstance(got, floor_guard.GuardError)

    def test_a_nested_include_through_a_regular_file_is_followed(self):
        p = self._repo()
        os.mkfifo(p.dir / "blocking")
        (p.dir / "middle").write_bytes(f"[include]\r\n\tpath = {p.dir}/blocking\r\n".encode())
        with open(p.repo / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write(f"[include]\n\tpath = {p.dir}/middle\n")
        with self.assertRaises(gitexec.GitCustodyRefused):
            gitexec.refuse_blocking_files(p.repo)

    def test_a_config_the_check_cannot_parse_is_never_refused_on_doubt(self):
        # Best-effort (coordinator, PR #724 round 8): no positive finding, no refusal. git itself
        # rejects these, so nothing blocks either.
        for bad in ('[include]\n\tpath = "unterminated\n', "[include]\n\tpath = \\q\n", "[include\n",
                    "[include]\n\tpath = /x\0y\n"):
            with self.subTest(config=bad):
                p = self._repo()
                with open(p.repo / ".git" / "config", "a", encoding="utf-8") as fh:
                    fh.write(bad)
                gitexec.refuse_blocking_files(p.repo)

    def test_ordinary_configs_still_pass(self):
        p = self._repo()
        (p.dir / "inc").write_bytes(b"[core]\r\n\tquotePath = false\r\n")
        p._git("config", "include.path", str(p.dir / "inc"))
        p._git("config", "remote.origin.url", 'https://example.invalid/a "b".git')
        p._git("config", "alias.x", "!echo ; # not a comment")
        gitexec.refuse_blocking_files(p.repo)


# Codex on PR #724 (round 7): the include parser's whitespace set was written down by hand and
# missed what a newer git treats as space, so the check read a different path from the one git
# opens. These compare the parser with the INSTALLED git, byte by byte and position by position
# (they run against whatever git CI has, so a future git that reads config differently fails here).
_BYTE_TEMPLATES = {
    "value, leading": lambda b: b"[include]\n\tpath = " + b + b"X\n",
    "value, trailing": lambda b: b"[include]\n\tpath = X" + b + b"\n",
    "value, trailing, CRLF": lambda b: b"[include]\r\n\tpath = X" + b + b"\r\n",
    "value, inside": lambda b: b"[include]\n\tpath = A" + b + b"B\n",
    "value, doubled inside": lambda b: b"[include]\n\tpath = A" + b + b + b"B\n",
    "value, quoted": lambda b: b'[include]\n\tpath = "A' + b + b'B"\n',
    "value, quoted at the end": lambda b: b'[include]\n\tpath = "A' + b + b'"\n',
    "value, after a backslash": lambda b: b"[include]\n\tpath = A\\" + b + b"B\n",
    "value, after a backslash, quoted": lambda b: b'[include]\n\tpath = "A\\' + b + b'B"\n',
    "value, before a comment": lambda b: b"[include]\n\tpath = A" + b + b"; c\n",
    "value, right after =": lambda b: b"[include]\n\tpath =" + b + b"X\n",
    "key, then the byte": lambda b: b"[include]\n\tpath" + b + b"= X\n",
    "key, inside": lambda b: b"[include]\n\tpa" + b + b"th = X\n",
    "key, bare then the byte": lambda b: b"[include]\n\tpath" + b + b"\n",
    "line, leading": lambda b: b"[include]\n" + b + b"path = X\n",
    "line, alone": lambda b: b"[include]\n" + b + b"\npath = X\n",
    "header, then the byte": lambda b: b"[include]" + b + b"path = X\n",
    "header name, inside": lambda b: b"[incl" + b + b"ude]\npath = X\n",
    "header name, then the byte": lambda b: b"[include" + b + b'"s"]\npath = X\n',
    "header, before ]": lambda b: b'[include "s"' + b + b"]\npath = X\n",
    "subsection, inside": lambda b: b'[includeIf "a' + b + b'b"]\npath = X\n',
    "subsection, after a backslash": lambda b: b'[includeIf "a\\' + b + b'b"]\npath = X\n',
    "comment, leading": lambda b: b"[include]\n" + b + b"# c\npath = X\n",
    "after a comment": lambda b: b"[include]\n# c" + b + b"path = Y\npath = X\n",
    "file, leading": lambda b: b + b"[include]\npath = X\n",
}


def _git_list(path, data):
    path.write_bytes(data)
    got = subprocess.run(["git", "config", "-f", str(path), "--list", "-z"], env=_CLEAN_ENV,
                         capture_output=True, stdin=subprocess.DEVNULL, cwd=str(path.parent), timeout=30)
    if got.returncode != 0:
        return None
    out = []
    for record in got.stdout.split(b"\0")[:-1]:
        key, nl, value = record.partition(b"\n")
        out.append((key.lower(), value if nl else None))
    return out


def _parsed(data):
    try:
        entries = gitexec._parse_config(data)
    except gitexec._ConfigUnparseable:
        return None
    return [((section + (b"." + sub if sub is not None else b"") + (b"." if section else b"") + key).lower(), value)
            for section, sub, key, value in entries]


class TheIncludeCheckCoversWhatTheInstalledGitReads(unittest.TestCase):
    """The up-front include check is best-effort and never gates on parity with git (coordinator,
    PR #724 round 8): it checks every spelling a git might read. This holds the installed git to
    that: for every byte in every position, each include path git itself reads is among the
    spellings the check examines (a NUL byte aside: git truncates at it and the check skips it,
    so a FIFO named that way is left to the call's timeout)."""

    def test_every_byte_in_every_position_is_covered(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        missed = []
        for where, template in _BYTE_TEMPLATES.items():
            for byte in range(256):
                data = template(bytes([byte]))
                git = _git_list(tmp / "c", data) or []
                read = {value for key, value in git if value is not None
                        and (key == b"include.path" or (key.startswith(b"includeif.") and key.endswith(b".path")))}
                if b"\0" in data:
                    continue
                uncovered = read - gitexec._include_values(data)
                if uncovered:
                    missed.append((where, f"{byte:#04x}", sorted(uncovered)))
        self.assertEqual(missed, [], "an include path git reads is not one the check examines")

    def test_a_git_that_counts_vertical_tab_and_form_feed_as_space_is_covered(self):
        # What a newer git does (Codex, round 7): with \v and \f in its whitespace, it trims them and
        # reads `A B` inside. Both readings are among the values the check examines.
        for b in (b"\x0b", b"\x0c"):
            data = b"[include]\n\tpath = /x/fifo" + b + b"\n" + b + b"[include]" + b + b"path = A" + b + b"B\n"
            newer = gitexec._parse_config(data, space=gitexec._GIT_SPACE_SETS[1])
            self.assertEqual([e[3] for e in newer], [b"/x/fifo", b"A B"])
            self.assertTrue({b"/x/fifo", b"/x/fifo" + b, b"A B"} <= gitexec._include_values(data))

    def test_whitespace_inside_a_value_is_covered_however_a_git_renders_it(self):
        # git 2.43 turns each unquoted whitespace byte inside a value into a space; git 2.55 keeps it
        # (config.c parse_value appends the byte and trims only the trailing run). CI's 2.55 read
        # `A<TAB>B` where the check examined only `A B` (PR #724). Every rendering is examined now.
        for b in (b"\t", b"\r", b"\t\t", b" \t"):
            data = b"[include]\n\tpath = A" + b + b"B \n"
            self.assertEqual(gitexec._parse_config(data, inner="space")[0][3], b"A" + b" " * len(b) + b"B")
            self.assertEqual(gitexec._parse_config(data, inner="verbatim")[0][3], b"A" + b + b"B")
            self.assertEqual(gitexec._parse_config(data, inner="collapse")[0][3], b"A B")
            self.assertTrue({b"A" + b" " * len(b) + b"B", b"A" + b + b"B", b"A B"} <= gitexec._include_values(data))

    def test_a_fifo_named_with_inside_whitespace_is_refused_at_either_rendering(self):
        # One FIFO at the name git 2.55 reads (`blo<TAB>cking`) or the one git 2.43 reads
        # (`blo cking`): refused at once either way; where the installed git blocks on it (the
        # positive control), floor_guard refuses at once too.
        for fifo_name in ("blo\tcking", "blo cking"):
            with self.subTest(fifo=repr(fifo_name)):
                tmp = tempfile.mkdtemp()
                self.addCleanup(lambda t=tmp: shutil.rmtree(t, ignore_errors=True))
                p = _Probe(tmp)
                p.commit("a.txt", "line1\n")
                os.mkfifo(p.dir / fifo_name)
                with open(p.repo / ".git" / "config", "a", encoding="utf-8") as fh:
                    fh.write(f"[include]\n\tpath = {p.dir}/blo\tcking\n")
                try:
                    subprocess.run(["git", "-C", str(p.repo), "rev-parse", "HEAD"], env=_CLEAN_ENV,
                                   capture_output=True, stdin=subprocess.DEVNULL, timeout=3)
                    git_blocks = False
                except subprocess.TimeoutExpired:
                    git_blocks = True
                done, got = _finishes(lambda r=p.repo: gitexec.refuse_blocking_files(r), seconds=10)
                self.assertTrue(done)
                self.assertIsInstance(got, gitexec.GitCustodyRefused)
                if git_blocks:
                    done, got = _finishes(lambda r=p.repo: floor_guard.collect_diff(r, "HEAD"), seconds=10)
                    self.assertTrue(done, "floor_guard blocked")
                    self.assertIsInstance(got, floor_guard.GuardError)

    def test_a_trailing_whitespace_byte_is_refused_at_either_spelling(self):
        # Each scenario puts ONE FIFO at one of the two names a trailing \v, \f, \r or space could
        # mean: whichever a git reads, the check examines both and refuses at once; where the
        # installed git blocks on it (the positive control), floor_guard refuses at once too.
        # Unquoted, git keeps or trims the byte by its own whitespace set (\v and \f differ across
        # versions; an unquoted trailing \r or space is always trimmed, so only quoted keeps those).
        cases = [(b, q) for b in ("\x0b", "\x0c") for q in (False, True)] + [(b, True) for b in ("\r", " ")]
        for (b, quoted), fifo_at in ((c, f) for c in cases for f in ("stripped", "kept")):
            with self.subTest(byte=repr(b), quoted=quoted, fifo_at=fifo_at):
                tmp = tempfile.mkdtemp()
                self.addCleanup(lambda t=tmp: shutil.rmtree(t, ignore_errors=True))
                p = _Probe(tmp)
                p.commit("a.txt", "line1\n")
                name = "blocking" + (b if fifo_at == "kept" else "")
                os.mkfifo(p.dir / name)
                value = f"{p.dir}/blocking{b}"
                with open(p.repo / ".git" / "config", "a", encoding="utf-8") as fh:
                    fh.write(f'[include]\n\tpath = "{value}"\n' if quoted else f"[include]\n\tpath = {value}\n")
                try:
                    subprocess.run(["git", "-C", str(p.repo), "rev-parse", "HEAD"], env=_CLEAN_ENV,
                                   capture_output=True, stdin=subprocess.DEVNULL, timeout=3)
                    git_blocks = False
                except subprocess.TimeoutExpired:
                    git_blocks = True
                done, got = _finishes(lambda r=p.repo: gitexec.refuse_blocking_files(r), seconds=10)
                self.assertTrue(done)
                self.assertIsInstance(got, gitexec.GitCustodyRefused,
                                      f"the FIFO {'without' if fifo_at == 'stripped' else 'with'} "
                                      f"the trailing {b!r} was missed")
                if git_blocks:
                    done, got = _finishes(lambda r=p.repo: floor_guard.collect_diff(r, "HEAD"), seconds=10)
                    self.assertTrue(done, "floor_guard blocked")
                    self.assertIsInstance(got, floor_guard.GuardError)


class PredictMergeResolvesNamesExactly(unittest.TestCase):
    """W3-07's rule, where predict-merge resolves BASE and BRANCH (rebase onto #725): `rev-parse
    <ref>^{commit}` tried refs/heads/ before refs/remotes/, so a local branch spelled `origin/main`
    stood in for the remote-tracking one. Each name is now resolved by its exact name."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        remote = p.commit("f.txt", "x\n")  # what refs/remotes/origin/main names
        p._git("update-ref", "refs/remotes/origin/main", remote)
        p._git("checkout", "-q", "-b", "work")
        p.commit("f.txt", "z\n")  # the branch: changes f from x
        p._git("checkout", "-q", "--detach", remote)
        decoy = p.commit("f.txt", "y\n")  # a LOCAL branch spelled origin/main: changes f too
        p._git("update-ref", "refs/heads/origin/main", decoy)
        return p

    def test_origin_main_is_the_remote_tracking_ref_not_a_local_branch_of_that_spelling(self):
        p = self._repo()
        result = diff_scope.predict_merge(p.repo, "origin/main", "work")
        self.assertTrue(result["clean"], "the decoy local branch was merged, not refs/remotes/origin/main")

    def test_a_local_name_is_refused_on_a_sound_lane(self):
        p = self._repo()
        with mock.patch.dict(os.environ, {"ORCA_PROVENANCE": "ci"}):
            with self.assertRaises(diff_scope.ScopeError) as cm:
                diff_scope.predict_merge(p.repo, "origin/main", "work")
        self.assertEqual(cm.exception.kind, "no_base")
        self.assertIn("sound lane", str(cm.exception))

    def test_a_tag_or_revision_syntax_is_no_base(self):
        p = self._repo()
        p._git("tag", "v1", "work")
        for ref in ("v1", "work~1", "refs/tags/v1"):
            with self.subTest(ref=ref), self.assertRaises(diff_scope.ScopeError) as cm:
                diff_scope.predict_merge(p.repo, "origin/main", ref)
            self.assertEqual(cm.exception.kind, "no_base")


class TheUpFrontCheckIsBestEffort(unittest.TestCase):
    """Coordinator, PR #724 round 8: the up-front check refuses ONLY on a positive finding, runs no
    git (a learned-whitespace probe refused every ordinary repository on CI's newer git), and
    checks every spelling of each name it derives - including a linked worktree's commondir, which
    git trims (Codex round 8: `../..\r\n` read as `../..`)."""

    def _linked(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        wt = p.dir / "wt"
        self.assertEqual(p._git("worktree", "add", "-q", "--detach", str(wt)).returncode, 0)
        admin = Path(p._git("rev-parse", "--absolute-git-dir", cwd=wt).stdout.strip())
        return p, wt, admin

    def _blocks(self, cwd):
        try:
            subprocess.run(["git", "-C", str(cwd), "rev-parse", "HEAD"], env=_CLEAN_ENV, capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=3)
        except subprocess.TimeoutExpired:
            return True
        return False

    def test_a_crlf_commondir_and_a_fifo_common_config_are_refused_at_once(self):
        p, wt, admin = self._linked()
        (admin / "commondir").write_bytes(b"../..\r\n")
        config = p.repo / ".git" / "config"
        config.unlink()
        os.mkfifo(config)
        self.assertTrue(self._blocks(wt), "fixture: git does not open the common config through it")
        done, got = _finishes(lambda: gitexec.refuse_blocking_files(wt), seconds=10)
        self.assertTrue(done)
        self.assertIsInstance(got, gitexec.GitCustodyRefused)
        done, got = _finishes(lambda: floor_guard.collect_diff(wt, "HEAD"), seconds=10)
        self.assertTrue(done, "floor_guard blocked")
        self.assertIsInstance(got, floor_guard.GuardError)

    def test_a_trailing_whitespace_commondir_is_refused_at_either_spelling(self):
        for b in (b"\x0b", b"\x0c", b"\r", b" "):
            for fifo_at in ("stripped", "kept"):
                with self.subTest(byte=b, fifo_at=fifo_at):
                    p, wt, admin = self._linked()
                    common = p.repo / ".git"
                    if fifo_at == "kept":  # a second common dir, under the untrimmed name
                        common = admin.parent.parent.parent / (".git" + b.decode("latin-1"))
                        common.mkdir()
                        (admin / "commondir").write_bytes(os.fsencode(str(common)) + b"\n")
                    else:
                        (admin / "commondir").write_bytes(b"../.." + b + b"\n")
                    (common / "config").unlink(missing_ok=True)
                    os.mkfifo(common / "config")
                    done, got = _finishes(lambda w=wt: gitexec.refuse_blocking_files(w), seconds=10)
                    self.assertTrue(done)
                    self.assertIsInstance(got, gitexec.GitCustodyRefused)

    def test_an_ordinary_repository_is_never_refused_and_no_git_is_asked(self):
        # The check runs no git at all, so no git version can make it refuse an ordinary repository
        # (the CI regression at 4aecdc0e). Unusual but regular configs pass too.
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "line1\n")
        (p.dir / "inc").write_bytes(b"[core]\r\n\tquotePath = false\x0c\r\n")
        with open(p.repo / ".git" / "config", "ab") as fh:
            fh.write(b"[include]\r\n\tpath = " + os.fsencode(str(p.dir / "inc")) + b"\x0b\r\n"
                     b"[alias]\n\tx = \"!echo \\\\\" ; a\"\n[include]\n\tpath = \"%(prefix)/etc/x\"\n")
        real = subprocess.run

        def no_git(argv, *a, **kw):
            if isinstance(argv, (list, tuple)) and argv and os.path.basename(os.fsdecode(argv[0])) == "git":
                raise AssertionError(f"the up-front check ran git: {argv}")
            return real(argv, *a, **kw)
        with mock.patch.object(subprocess, "run", no_git):
            gitexec.refuse_blocking_files(p.repo)
        with mock.patch.object(gitexec, "GIT", "/nonexistent/a-git-that-reads-config-differently"):
            gitexec.refuse_blocking_files(p.repo)


class CustodySetupTimeoutsAreEachToolsRefusal(unittest.TestCase):
    """Codex on PR #724 (round 6): a timeout in gitexec.custody's own setup (its rev-parse and
    config queries) escaped hint_provenance as a raw TimeoutExpired, and predict-merge reported it
    as "needs git >= 2.38". Each tool's documented could-not-run outcome now carries it."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        p._git("checkout", "-q", "-b", "side")
        side = p.commit("b.txt", "two\n")
        (p.repo / "a.txt").write_text("CHANGED\n", encoding="utf-8")
        return p, base, side

    def _timeout_in_custody_setup(self):
        real = subprocess.run

        def run(argv, *a, **kw):
            if isinstance(argv, (list, tuple)) and "--absolute-git-dir" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout", 60))
            return real(argv, *a, **kw)
        return mock.patch.object(subprocess, "run", run)

    def test_every_site_reports_it_as_its_own_refusal(self):
        p, base, side = self._repo()
        with self._timeout_in_custody_setup():
            with self.assertRaises(hint_provenance.ProvenanceError):
                hint_provenance.LiveSource(str(p.repo)).changes_since(base)
            with self.assertRaises(floor_guard.GuardError):
                floor_guard.collect_diff(p.repo, base)
            with self.assertRaises(diff_scope.ScopeError):
                diff_scope.changed_files(p.repo, base)
            with self.assertRaises(diff_scope.ScopeError) as cm:
                diff_scope.predict_merge(p.repo, base, side)
        self.assertIn("timed out", str(cm.exception))
        self.assertNotIn("2.38", str(cm.exception))


class HintProvenanceTimeoutIsAProvenanceError(unittest.TestCase):
    """PR #724 re-attack (item 4): a git that blocked until its timeout surfaced as a raw
    TimeoutExpired; it is the module's own could-not-run."""

    def test_a_timed_out_git_is_a_provenance_error(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        base = p.commit("a.txt", "line1\n")
        live = hint_provenance.LiveSource(str(p.repo))
        real = subprocess.run

        def slow(argv, *a, **kw):
            if "diff" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout", 60))
            return real(argv, *a, **kw)
        with mock.patch.object(hint_provenance.subprocess, "run", side_effect=slow):
            with self.assertRaises(hint_provenance.ProvenanceError):
                live.changes_since(base)


class PartialClonesAreRefused(unittest.TestCase):
    """PR #724 re-attack (items 5, 6): git 2.43's `clone --filter` writes remote.<n>.promisor and
    remote.<n>.partialclonefilter, never extensions.partialClone, so the custody's refusal never
    fired. It now refuses a promisor remote; and predict-merge reports that reason, not "needs git
    >= 2.38"."""

    def _clone(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        (tmp / "s").mkdir()
        src = _Probe(tmp / "s")
        src.commit("a.txt", "one\n")
        base = src._git("rev-parse", "HEAD").stdout.strip()
        src._git("checkout", "-q", "-b", "side")
        src.commit("b.txt", "two\n")
        main = src._git("rev-parse", "HEAD~0").stdout.strip()
        src._git("config", "uploadpack.allowFilter", "true")
        clone = tmp / "clone"
        r = subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-local", f"file://{src.repo}",
                            str(clone)], env=_CLEAN_ENV, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertEqual(r.returncode, 0, r.stderr)
        keys = subprocess.run(["git", "-C", str(clone), "config", "--list", "--name-only"], env=_CLEAN_ENV,
                              capture_output=True, text=True).stdout
        self.assertIn("remote.origin.promisor", keys, "fixture: not a partial clone")
        (clone / "a.txt").write_text("changed\n", encoding="utf-8")
        return clone, base, main

    def test_every_site_refuses_a_partial_clone(self):
        clone, base, _main = self._clone()
        with self.assertRaises(gitexec.GitCustodyRefused):
            with gitexec.custody(clone):
                pass
        with self.assertRaises(floor_guard.GuardError):
            floor_guard.collect_diff(clone, base)
        with self.assertRaises(diff_scope.ScopeError):
            diff_scope.changed_files(clone, base)
        with self.assertRaises(hint_provenance.ProvenanceError):
            hint_provenance.LiveSource(str(clone)).changes_since(base)

    def test_predict_merge_names_the_refusal(self):
        clone, base, main = self._clone()
        with self.assertRaises(diff_scope.ScopeError) as cm:
            diff_scope.predict_merge(clone, base, main)
        self.assertIn("partial clone", str(cm.exception))
        self.assertNotIn("2.38", str(cm.exception))


class GitexecCustody(unittest.TestCase):
    """gitexec.custody: the coordinator-built git dir and the refusals it shares with the posix
    provider's run_git."""

    def _repo(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        p = _Probe(tmp)
        p.commit("a.txt", "one\n")
        return p

    def test_the_custody_dir_names_no_driver_and_reads_the_repo_objects(self):
        p = self._repo()
        p.arm_filter()
        with gitexec.custody(p.repo) as c:
            gd = Path(c.git_dir)
            cfg = (gd / "config").read_text(encoding="utf-8")
            self.assertNotIn("filter", cfg)
            # info/attributes rides as data: the `filter=p` it selects names no driver here.
            self.assertEqual((gd / "info" / "attributes").read_text(encoding="utf-8"),
                             (p.repo / ".git" / "info" / "attributes").read_text(encoding="utf-8"))
            self.assertEqual(Path(c.work_tree).resolve(), p.repo.resolve())
            self.assertIn(b"objects", (gd / "objects" / "info" / "alternates").read_bytes())
            self.assertEqual(c.lead[:2], ["-C", str(p.repo)])
            r = subprocess.run(c.argv("cat-file", "-p", "HEAD:a.txt"), env=c.env(), capture_output=True,
                               text=True, stdin=subprocess.DEVNULL)
            self.assertEqual(r.stdout, "one\n", r.stderr)
        self.assertFalse(gd.exists(), "the custody dir outlived its use")

    def test_a_partial_clone_is_refused_not_guessed(self):
        p = self._repo()
        p._git("config", "core.repositoryformatversion", "1")
        p._git("config", "extensions.partialClone", "origin")
        with self.assertRaises(gitexec.GitCustodyRefused):
            with gitexec.custody(p.repo):
                pass

    def test_a_planted_fifo_or_symlink_is_refused_not_followed(self):
        p = self._repo()
        exclude = p.repo / ".git" / "info" / "exclude"
        exclude.parent.mkdir(exist_ok=True)
        exclude.unlink(missing_ok=True)
        os.symlink("/etc/passwd", exclude)
        with self.assertRaises(gitexec.GitCustodyRefused):
            with gitexec.custody(p.repo):
                pass

    def test_custody_env_drops_selectors_and_pins_the_floor(self):
        env = gitexec.custody_env({"PATH": os.environ["PATH"], "GIT_DIR": "/elsewhere",
                                   "GIT_INDEX_FILE": "/elsewhere/index", "GIT_EXEC_PATH": "/evil"})
        for name in ("GIT_DIR", "GIT_INDEX_FILE", "GIT_EXEC_PATH"):
            self.assertNotIn(name, env)
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
                 for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pairs["log.showSignature"], "false")
        self.assertEqual(pairs["core.alternateRefsCommand"], "exit 0")
        self.assertEqual(pairs["core.hooksPath"], os.devnull)
        self.assertEqual((env["GIT_NO_LAZY_FETCH"], env["GIT_ALLOW_PROTOCOL"]), ("1", "file"))

    def test_the_posix_provider_shares_this_custody(self):
        sys.path.insert(0, str(ROOT / "runtime"))
        try:
            posix = importlib.import_module("providers.posix")
        finally:
            sys.path.remove(str(ROOT / "runtime"))
        self.assertIs(posix._custody_git_dir, posix.gitexec.custody_git_dir)
        self.assertIs(posix.GitCustodyRefused, posix.gitexec.GitCustodyRefused)
        self.assertEqual(posix.PROVIDER_FLOOR, gitexec.CUSTODY_FLOOR)
        self.assertEqual(posix.PROVIDER_FLOOR_ENV, gitexec.CUSTODY_ENV)
        self.assertEqual(posix.GIT_SELECTOR_ENV, gitexec.SELECTOR_ENV)


if __name__ == "__main__":
    unittest.main()
