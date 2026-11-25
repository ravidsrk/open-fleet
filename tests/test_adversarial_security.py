#!/usr/bin/env python3
"""Adversarial security regression suite covering A-01 through A-19.

Stdlib-only; repo modules are loaded exclusively via importlib.util.spec_from_file_location.
"""
import contextlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "runtime" / "scripts"
DENY_HOOK = SCRIPTS / "deny-hook.sh"
VERIFY_PY = SCRIPTS / "verify.py"
VERIFY_GATE = SCRIPTS / "verify-gate.sh"
GUARD_TEXT = SCRIPTS / "guard_text.py"
FLOOR_GUARD = SCRIPTS / "floor_guard.py"
DECISIONS = SCRIPTS / "decisions.py"
DISPATCH_SIGN = SCRIPTS / "dispatch-sign.py"
PREFLIGHT = SCRIPTS / "preflight.py"
SPAWN_WORKER = SCRIPTS / "spawn_worker.sh"
SPAWN_IDENTITY = SCRIPTS / "spawn_identity.py"
GITEXEC = SCRIPTS / "gitexec.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(repo),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        env=env,
        check=check,
    )


def _init_repo(repo: Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    (repo / "app.py").write_text("def value():\n    return 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-q", "-m", "init")
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


def _run_deny_hook(payload: dict, env_extra: dict | None = None, cwd: Path | None = None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["sh", str(DENY_HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
        timeout=30,
    )


def _hook_decision(proc: subprocess.CompletedProcess) -> str:
    """Return 'deny', 'ask', or 'allow' from deny-hook.sh stdout/returncode."""
    out = (proc.stdout or "").strip()
    if out:
        try:
            doc = json.loads(out)
        except json.JSONDecodeError:
            doc = {}
        hso = doc.get("hookSpecificOutput") if isinstance(doc, dict) else None
        if isinstance(hso, dict) and hso.get("permissionDecision"):
            return str(hso["permissionDecision"])
        if isinstance(doc, dict) and doc.get("decision"):
            d = str(doc["decision"])
            return "deny" if d == "block" else d
    if proc.returncode != 0:
        return "deny"
    return "allow"


class TestA01GuardTextFetch(unittest.TestCase):
    """A-01: guard_text.py --fetch path-qualified argv[0], relative PATH, wget/curl flags."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_guard_text", GUARD_TEXT)

    def test_rejects_path_qualified_binaries(self):
        for argv in (
            ["./gh", "issue", "view", "1"],
            ["/tmp/evil/gh", "issue", "view", "1"],
            ["/usr/bin/curl", "https://example.invalid"],
            ["./curl", "https://example.invalid"],
            ["sub/cat", "README.md"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(RuntimeError):
                    self.mod._validate_fetch_argv(argv)

    def test_orca_cli_requires_exact_sibling_and_no_relative_path_lookup(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fake_orca = tmp / "orca_cli.py"
            fake_orca.write_text("#!/usr/bin/env python3\nprint('pwn')\n", encoding="utf-8")
            fake_orca.chmod(0o755)
            # Direct path-qualified fake orca_cli.py must fail
            with self.assertRaises(RuntimeError):
                self.mod._validate_fetch_argv([str(fake_orca), "linear", "get", "ENG-1"])
            # python3 pointing at fake orca_cli.py must fail
            with self.assertRaises(RuntimeError):
                self.mod._validate_fetch_argv(["python3", str(fake_orca), "linear", "get", "ENG-1"])
            # Bare orca_cli.py resolving to fake dir on PATH must fail
            with mock.patch.dict(os.environ, {"PATH": str(tmp)}):
                with self.assertRaises(RuntimeError):
                    self.mod._validate_fetch_argv(["orca_cli.py", "linear", "get", "ENG-1"])
            # Relative PATH entry '.' must never resolve ./gh
            fake_gh = tmp / "gh"
            fake_gh.write_text("#!/bin/sh\necho pwn\n", encoding="utf-8")
            fake_gh.chmod(0o755)
            orig_cwd = os.getcwd()
            try:
                os.chdir(tmp)
                with mock.patch.dict(os.environ, {"PATH": "."}):
                    self.assertIsNone(self.mod._resolve_bare_binary("gh"))
            finally:
                os.chdir(orig_cwd)
        # Real sibling orca_cli.py is accepted
        sibling = str(SCRIPTS / "orca_cli.py")
        self.mod._validate_fetch_argv([sibling, "linear", "get", "ENG-1"])
        self.mod._validate_fetch_argv(["python3", sibling, "linear", "get", "ENG-1"])

    def test_wget_requires_stdout_or_head_and_rejects_unsafe_or_abbreviated_flags(self):
        for bad in (
            ["wget", "https://example.invalid"],
            ["wget", "-q", "https://example.invalid"],
            ["wget", "-e", "robots=off", "-O", "-", "https://example.invalid"],
            ["wget", "--execute=robots=off", "-O", "-", "https://example.invalid"],
            ["wget", "--outp=-", "https://example.invalid"],
            ["wget", "-O", "/tmp/out", "https://example.invalid"],
            ["wget", "--output-document=/tmp/out", "https://example.invalid"],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(RuntimeError):
                    self.mod._validate_fetch_argv(bad)
        for good in (
            ["wget", "-q", "-O", "-", "https://example.invalid"],
            ["wget", "--output-document=-", "https://example.invalid"],
            ["wget", "-q", "--method=HEAD", "https://example.invalid"],
            ["wget", "--spider", "https://example.invalid"],
        ):
            with self.subTest(good=good):
                self.mod._validate_fetch_argv(good)

    def test_curl_rejects_file_writing_and_expand_flags(self):
        for bad in (
            ["curl", "--stderr", "/tmp/x", "https://example.invalid"],
            ["curl", "--hsts", "/tmp/x", "https://example.invalid"],
            ["curl", "--etag-save", "/tmp/x", "https://example.invalid"],
            ["curl", "--libcurl", "/tmp/x", "https://example.invalid"],
            ["curl", "--expand-data", "@/etc/passwd", "https://example.invalid"],
            ["curl", "--expand-url", "https://example.invalid"],
            ["curl", "--alt-svc", "/tmp/x", "https://example.invalid"],
            ["curl", "--data-raw", "x=1", "https://example.invalid"],
            ["curl", "--variable", "k=v", "https://example.invalid"],
            ["curl", "--next", "https://example.invalid"],
            ["curl", "-Q", "DELE x", "https://example.invalid"],
            ["curl", "-:", "https://example.invalid"],
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(RuntimeError):
                    self.mod._validate_fetch_argv(bad)
        self.mod._validate_fetch_argv(["curl", "-sS", "-L", "https://example.invalid"])


class TestA02DenyHookRule5Receipt(unittest.TestCase):
    """A-02: deny-hook.sh Rule 5 egress receipt hardening."""

    def test_rejects_env_overrides_fake_python_cd_and_missing_relative_egress(self):
        with tempfile.TemporaryDirectory() as td:
            wt = Path(td)
            fake_py = wt / "python3"
            fake_py.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_py.chmod(0o755)
            receipt_args = "write --sink pr-open --host github.com --payload-class c --consent k"
            egress_abs = str(SCRIPTS / "egress.py")
            attacks = [
                f"PYTHONPATH=/tmp {egress_abs} {receipt_args} && gh issue close 34",
                f"OPEN_FLEET_EGRESS_LEDGER=/tmp/fake {egress_abs} {receipt_args} && gh issue close 34",
                f"PATH=/tmp {egress_abs} {receipt_args} && gh issue close 34",
                f"LD_PRELOAD=/tmp/x.so {egress_abs} {receipt_args} && gh issue close 34",
                f"env PYTHONPATH=/tmp python3 {egress_abs} {receipt_args} && gh issue close 34",
                f"./python3 {egress_abs} {receipt_args} && gh issue close 34",
                f"{fake_py} {egress_abs} {receipt_args} && gh issue close 34",
                f"cd sub && runtime/scripts/egress.py {receipt_args} && gh issue close 34",
                f"touch runtime/scripts/egress.py && runtime/scripts/egress.py {receipt_args} && gh issue close 34",
                f"runtime/scripts/egress.py {receipt_args} && gh issue close 34",
            ]
            for cmd in attacks:
                with self.subTest(cmd=cmd):
                    proc = _run_deny_hook(
                        {"tool_name": "Bash", "tool_input": {"command": cmd}},
                        env_extra={"OPEN_FLEET_UNIT_WORKTREE": str(wt)},
                        cwd=wt,
                    )
                    self.assertEqual(
                        _hook_decision(proc),
                        "deny",
                        f"expected deny for {cmd!r}, got stdout={proc.stdout!r} stderr={proc.stderr!r}",
                    )

            # Valid canonical egress receipt succeeds
            valid_cmd = f"python3 {egress_abs} {receipt_args} && gh issue close 34"
            proc_ok = _run_deny_hook(
                {"tool_name": "Bash", "tool_input": {"command": valid_cmd}},
                env_extra={"OPEN_FLEET_UNIT_WORKTREE": str(wt)},
                cwd=wt,
            )
            self.assertNotEqual(_hook_decision(proc_ok), "deny", proc_ok.stdout)


class TestA03DenyHookVerifySettings(unittest.TestCase):
    """A-03: deny-hook.sh --verify-settings boundary, conflict, and ambient-env isolation."""

    def _write_claude_settings(self, path: Path, cmd: str, env_block: dict | None = None):
        doc: dict = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
                        "hooks": [{"type": "command", "command": cmd}],
                    }
                ]
            }
        }
        if env_block is not None:
            doc["env"] = env_block
        path.write_text(json.dumps(doc), encoding="utf-8")

    def _run_verify_settings(self, settings: Path, extra_args: list[str], env_extra: dict | None = None):
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
        }
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            ["sh", str(DENY_HOOK), "--verify-settings", str(settings), *extra_args],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_refuses_duplicate_conflicting_and_ambient_env_settings(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            wt_a = tmp / "wt_a"
            wt_b = tmp / "wt_b"
            wt_a.mkdir()
            wt_b.mkdir()
            settings = tmp / "settings.json"
            hook = str(DENY_HOOK)

            # Duplicate OPEN_FLEET_UNIT_WORKTREE assignment keys
            self._write_claude_settings(
                settings,
                f"OPEN_FLEET_UNIT_WORKTREE={wt_a} OPEN_FLEET_UNIT_WORKTREE={wt_b} sh {hook}",
            )
            r_dup = self._run_verify_settings(settings, ["--boundary", str(wt_a)])
            self.assertNotEqual(r_dup.returncode, 0, r_dup.stdout + r_dup.stderr)

            # Conflicting OPEN_FLEET_UNIT_WORKTREE vs ORCA_UNIT_WORKTREE
            self._write_claude_settings(
                settings,
                f"OPEN_FLEET_UNIT_WORKTREE={wt_b} ORCA_UNIT_WORKTREE={wt_a} sh {hook}",
            )
            r_conf = self._run_verify_settings(settings, ["--boundary", str(wt_a)])
            self.assertNotEqual(r_conf.returncode, 0, r_conf.stdout + r_conf.stderr)

            # Settings omits worktree, ambient os.environ supplies it -> must NOT pass
            self._write_claude_settings(settings, f"sh {hook}")
            r_amb_wt = self._run_verify_settings(
                settings,
                ["--boundary", str(wt_a)],
                env_extra={"OPEN_FLEET_UNIT_WORKTREE": str(wt_a)},
            )
            self.assertNotEqual(r_amb_wt.returncode, 0, r_amb_wt.stdout + r_amb_wt.stderr)

            # Settings omits readonly, ambient os.environ supplies it -> must NOT pass
            self._write_claude_settings(
                settings,
                f"OPEN_FLEET_UNIT_WORKTREE={wt_a} sh {hook}",
            )
            r_amb_ro = self._run_verify_settings(
                settings,
                ["--boundary", str(wt_a), "--readonly"],
                env_extra={"OPEN_FLEET_HOOK_READONLY": "1"},
            )
            self.assertNotEqual(r_amb_ro.returncode, 0, r_amb_ro.stdout + r_amb_ro.stderr)

            # Valid rw settings passes (and passes the inside-boundary non-guard write probe)
            r_ok = self._run_verify_settings(settings, ["--boundary", str(wt_a)])
            self.assertEqual(r_ok.returncode, 0, r_ok.stdout + r_ok.stderr)


class TestA04VerifyExecuteNcStaging(unittest.TestCase):
    """A-04: verify.py --execute-nc nc_env hardening & phase repo ref isolation."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_verify_a04", VERIFY_PY)

    def test_phase_repo_ignores_source_replace_refs_and_grafts(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            repo = tmp / "repo"
            base = _init_repo(repo)
            seen_log = tmp / "seen_subject.txt"
            probe = repo / "test_probe.py"
            probe.write_text(
                "import pathlib, subprocess, sys\n"
                "subj = subprocess.check_output(['git', 'log', '-1', '--format=%s'], text=True).strip()\n"
                f"pathlib.Path({str(seen_log)!r}).write_text(subj, encoding='utf-8')\n"
                "text = pathlib.Path('app.py').read_text(encoding='utf-8')\n"
                "if 'return 2' not in text:\n"
                "    print('AssertionError: expected return 2', file=sys.stderr)\n"
                "    sys.exit(1)\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            (repo / "app.py").write_text("def value():\n    return 2\n", encoding="utf-8")
            _git(repo, "add", "app.py", "test_probe.py")
            _git(repo, "commit", "-q", "-m", "real-head-subject")
            head = _git(repo, "rev-parse", "HEAD").stdout.strip()
            _git(repo, "update-ref", f"refs/replace/{head}", base)
            (repo / ".git" / "info" / "grafts").write_text(f"{head}\n", encoding="utf-8")
            cmd = f"{sys.executable} test_probe.py"
            manifest = {
                "base_sha": base,
                "head_sha": head,
                "negative_control": {"tool": "revert", "paths": ["app.py"], "command": cmd},
            }
            orig_cwd = os.getcwd()
            try:
                os.chdir(repo)
                ok, errs = self.mod.execute_negative_control(manifest, cmd)
            finally:
                os.chdir(orig_cwd)
            self.assertTrue(ok, errs)
            self.assertEqual(seen_log.read_text(encoding="utf-8"), "real-head-subject")

    def test_stage_phase_repo_excludes_replace_notes_and_unrelated_refs(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            repo = tmp / "repo"
            base = _init_repo(repo)
            refs_log = tmp / "phase_refs.txt"
            probe = repo / "test_probe.py"
            probe.write_text(
                "import pathlib, subprocess, sys\n"
                "out = subprocess.check_output(['git', 'for-each-ref', '--format=%(refname)'], text=True)\n"
                f"pathlib.Path({str(refs_log)!r}).write_text(out, encoding='utf-8')\n"
                "text = pathlib.Path('app.py').read_text(encoding='utf-8')\n"
                "if 'return 2' not in text:\n"
                "    print('AssertionError: expected return 2', file=sys.stderr)\n"
                "    sys.exit(1)\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            probe.chmod(0o644)
            (repo / "app.py").write_text("def value():\n    return 2\n", encoding="utf-8")
            _git(repo, "add", "app.py", "test_probe.py")
            _git(repo, "commit", "-q", "-m", "change")
            head = _git(repo, "rev-parse", "HEAD").stdout.strip()
            # Plant refs/replace, refs/notes, and unrelated worker branch
            _git(repo, "update-ref", f"refs/replace/{head}", base)
            _git(repo, "update-ref", "refs/notes/commits", head)
            _git(repo, "update-ref", "refs/heads/worker-rogue", base)

            cmd = f"{sys.executable} test_probe.py"
            manifest = {
                "base_sha": base,
                "head_sha": head,
                "negative_control": {"tool": "revert", "paths": ["app.py"], "command": cmd},
            }
            orig_cwd = os.getcwd()
            try:
                os.chdir(repo)
                ok, errs = self.mod.execute_negative_control(manifest, cmd)
            finally:
                os.chdir(orig_cwd)
            self.assertTrue(ok, errs)
            staged_refs = [r for r in refs_log.read_text(encoding="utf-8").splitlines() if r]
            self.assertIn("refs/heads/main", staged_refs)
            self.assertFalse(any(r.startswith("refs/replace/") for r in staged_refs), staged_refs)
            self.assertFalse(any(r.startswith("refs/notes/") for r in staged_refs), staged_refs)
            self.assertNotIn("refs/heads/worker-rogue", staged_refs)

    def test_stage_phase_repo_rejects_newline_in_objects_path(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "bad\nrepo"
            base = _init_repo(repo)
            probe = repo / "test_probe.py"
            probe.write_text("import sys; sys.exit(0)\n", encoding="utf-8")
            probe.chmod(0o644)
            (repo / "app.py").write_text("def value():\n    return 2\n", encoding="utf-8")
            _git(repo, "add", "app.py", "test_probe.py")
            _git(repo, "commit", "-q", "-m", "change")
            head = _git(repo, "rev-parse", "HEAD").stdout.strip()
            cmd = f"{sys.executable} test_probe.py"
            manifest = {
                "base_sha": base,
                "head_sha": head,
                "negative_control": {"tool": "revert", "paths": ["app.py"], "command": cmd},
            }
            orig_cwd = os.getcwd()
            try:
                os.chdir(repo)
                ok, errs = self.mod.execute_negative_control(manifest, cmd)
            finally:
                os.chdir(orig_cwd)
            self.assertFalse(ok)
            self.assertTrue(
                any("control/newline bytes" in e for e in errs),
                f"expected newline rejection, got {errs!r}",
            )


class TestA05DenyHookGnuRmPrefix(unittest.TestCase):
    """A-05: deny-hook.sh GNU unambiguous long-option prefix bypass for rm."""

    def test_denies_gnu_rm_long_option_prefixes(self):
        with tempfile.TemporaryDirectory() as td:
            for cmd in (
                "rm --r /",
                "rm --re --no-p /var",
                "rm --rec --no-pres /",
                "rm --f --rec /",
                "rm --for --recur /*",
            ):
                with self.subTest(cmd=cmd):
                    proc = _run_deny_hook(
                        {"tool_name": "Bash", "tool_input": {"command": cmd}},
                        env_extra={"OPEN_FLEET_UNIT_WORKTREE": td},
                    )
                    self.assertEqual(
                        _hook_decision(proc),
                        "deny",
                        f"expected deny for {cmd!r}, got stdout={proc.stdout!r}",
                    )
            # Non-root recursive rm with GNU prefix must trip NEVER-LIST (ask/deny, never allow)
            for cmd in ("rm --f --rec /etc", "rm --for --recur /usr"):
                with self.subTest(cmd=cmd):
                    proc = _run_deny_hook(
                        {"tool_name": "Bash", "tool_input": {"command": cmd}},
                        env_extra={"OPEN_FLEET_UNIT_WORKTREE": td},
                    )
                    self.assertIn(_hook_decision(proc), ("ask", "deny"), proc.stdout)


class TestA06FloorGuardReadAtFailClosed(unittest.TestCase):
    """A-06: floor_guard.py read_at uses ls-tree and fails closed on missing blob."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_floor_guard_a06", FLOOR_GUARD)

    def test_read_at_fails_closed_when_blob_missing_and_returns_none_when_absent(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            _init_repo(repo)
            (repo / "docs").mkdir()
            (repo / "docs" / "DECISIONS.md").write_text("# Decisions\n", encoding="utf-8")
            _git(repo, "add", "docs/DECISIONS.md")
            _git(repo, "commit", "-q", "-m", "add decisions")

            self.assertIsNone(self.mod.read_at(repo, "HEAD", "docs/NO_SUCH_FILE.md"))
            self.assertEqual(self.mod.read_at(repo, "HEAD", "docs/DECISIONS.md"), "# Decisions\n")

            blob_sha = _git(repo, "rev-parse", "HEAD:docs/DECISIONS.md").stdout.strip()
            obj_path = repo / ".git" / "objects" / blob_sha[:2] / blob_sha[2:]
            obj_path.chmod(0o600)
            obj_path.unlink()

            with self.assertRaises(self.mod.GuardError):
                self.mod.read_at(repo, "HEAD", "docs/DECISIONS.md")


class TestA07FloorGuardSurfaceEvasion(unittest.TestCase):
    """A-07: floor_guard.py ruff.toml comments/excludes and structural pyproject/INI checks."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_floor_guard_a07", FLOOR_GUARD)

    def test_ruff_toml_multiline_comments_and_exclude_globs_flagged(self):
        added = [
            ("ruff.toml", 5, '  "F401", # disable unused'),
            ("ruff.toml", 6, '  "tests/**",'),
        ]
        findings = self.mod.scan(added, [], "CONSTRAINTS.md", None)
        rules = [(f["rule"], f["path"], f["line"]) for f in findings]
        self.assertIn(("guard-surface", "ruff.toml", 5), rules)
        self.assertIn(("guard-surface", "ruff.toml", 6), rules)

    def test_structural_pyproject_and_setup_cfg_edits_without_header_in_diff(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            _init_repo(repo)
            (repo / "pyproject.toml").write_text(
                "[project]\nname = 'demo'\nversion = '0.1.0'\n\n"
                "[tool.ruff.lint]\nselect = ['E9', 'F401']\nignore = []\n\n"
                "[tool.coverage.report]\nfail_under = 90\n",
                encoding="utf-8",
            )
            (repo / "setup.cfg").write_text(
                "[metadata]\nname = demo\n\n"
                "[flake8]\nmax-line-length = 100\nignore = E203\n\n"
                "[coverage:report]\nfail_under = 90\n",
                encoding="utf-8",
            )
            _git(repo, "add", "pyproject.toml", "setup.cfg")
            _git(repo, "commit", "-q", "-m", "configs")
            base = _git(repo, "rev-parse", "HEAD").stdout.strip()

            # Benign [project] edit stays clean
            (repo / "pyproject.toml").write_text(
                "[project]\nname = 'demo'\nversion = '0.2.0'\n\n"
                "[tool.ruff.lint]\nselect = ['E9', 'F401']\nignore = []\n\n"
                "[tool.coverage.report]\nfail_under = 90\n",
                encoding="utf-8",
            )
            self.assertEqual(self.mod.main(["--base", base, "--repo", str(repo), "--quiet"]), 0)

            # Edit deep inside existing [tool.ruff.lint] (no section header in --unified=0 diff)
            (repo / "pyproject.toml").write_text(
                "[project]\nname = 'demo'\nversion = '0.2.0'\n\n"
                "[tool.ruff.lint]\nselect = ['E9', 'F401']\nignore = ['F401']\n\n"
                "[tool.coverage.report]\nfail_under = 90\n",
                encoding="utf-8",
            )
            self.assertEqual(self.mod.main(["--base", base, "--repo", str(repo), "--quiet"]), 1)

            # Reset pyproject.toml, edit deep inside [flake8] in setup.cfg
            _git(repo, "checkout", "--", "pyproject.toml")
            (repo / "setup.cfg").write_text(
                "[metadata]\nname = demo\n\n"
                "[flake8]\nmax-line-length = 100\nignore = E203,F401\n\n"
                "[coverage:report]\nfail_under = 90\n",
                encoding="utf-8",
            )
            self.assertEqual(self.mod.main(["--base", base, "--repo", str(repo), "--quiet"]), 1)

            # Malformed pyproject.toml fails closed
            _git(repo, "checkout", "--", "setup.cfg")
            (repo / "pyproject.toml").write_text("[tool.ruff\nbroken = [\n", encoding="utf-8")
            self.assertEqual(self.mod.main(["--base", base, "--repo", str(repo), "--quiet"]), 1)


class TestA08UnhardenedGitCustody(unittest.TestCase):
    """A-08: gitexec.custody_env used in decisions, gitexec, preflight, dispatch-sign, spawn_worker."""

    @classmethod
    def setUpClass(cls):
        cls.decisions = _load_module("adv_decisions_a08", DECISIONS)
        cls.gitexec = _load_module("adv_gitexec_a08", GITEXEC)
        cls.preflight = _load_module("adv_preflight_a08", PREFLIGHT)
        cls.dispatch_sign = _load_module("adv_dispatch_sign_a08", DISPATCH_SIGN)

    def test_poisoned_git_env_and_repo_fsmonitor_never_execute(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            repo = tmp / "repo"
            head = _init_repo(repo)
            marker = tmp / "pwned"
            trap = tmp / "trap.sh"
            trap.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
            trap.chmod(0o755)
            # Poison repo config with fsmonitor
            _git(repo, "config", "core.fsmonitor", str(trap))
            # Poison ambient GIT_* env vars
            poison_env = {
                "GIT_CONFIG_PARAMETERS": f"'core.fsmonitor={trap}'",
                "GIT_EXEC_PATH": str(tmp),
                "GIT_DIR": str(tmp / "nonexistent-gitdir"),
            }
            with mock.patch.dict(os.environ, poison_env):
                self.decisions._pin_at_ref(repo, head)
                self.gitexec.driver_blanks(repo)
                self.preflight._run(["git", "-C", str(repo), "rev-parse", "HEAD"])
                self.dispatch_sign._in_unignored_worktree(repo / "app.py")
            self.assertFalse(marker.exists(), "poisoned git fsmonitor/exec trap executed!")

            # Check spawn_worker.sh repo-top hardening textually
            sw_text = SPAWN_WORKER.read_text(encoding="utf-8")
            self.assertIn("unset GIT_DIR GIT_WORK_TREE", sw_text)
            self.assertIn("-c core.hooksPath=/dev/null -c core.fsmonitor=false", sw_text)


class TestA09SpawnIdentityHomeEscapeAndWorktrunk(unittest.TestCase):
    """A-09: worktrunk in register_spawn record-root + spawn_identity pw_dir fallback."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_spawn_identity_a09", SPAWN_IDENTITY)

    def test_spawn_worker_includes_worktrunk_in_record_root(self):
        text = SPAWN_WORKER.read_text(encoding="utf-8")
        self.assertIn('[ "$ACTIVE_RUNTIME" != "worktrunk" ]', text)

    def test_whoami_detects_ancestor_root_in_passwd_home_when_registry_is_empty(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            empty_reg_dir = tmp / "fake_home" / ".open-fleet" / "spawn-profiles"
            empty_reg_dir.mkdir(parents=True)
            pw_home = tmp / "real_home"
            pw_reg_dir = pw_home / ".open-fleet" / "spawn-profiles"
            pw_reg = self.mod.Registry(str(pw_reg_dir))

            me_key = self.mod.key(os.getpid())
            self.assertIsNotNone(me_key)
            pw_reg.write(".roots", me_key, "ro pane-escape-test\n")

            with mock.patch.object(self.mod, "_uid_home", return_value=str(pw_home)):
                lines = self.mod.whoami(self.mod.Registry(str(empty_reg_dir)), os.getpid())
            self.assertIn(f"ROOT ro {me_key}", lines)


class TestA10VerifyMalformedRecords(unittest.TestCase):
    """A-10: verify.py guards non-dict record and non-dict negative_control without AttributeError."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_verify_a10", VERIFY_PY)

    def test_non_dict_dispatch_envelope_and_nc_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            pub = tmp / "pub"
            pub.write_text("00" * 32 + "\n", encoding="utf-8")
            for payload in ("[]", json.dumps({"record": [], "sig_b64": ""}), json.dumps({"record": "bad", "sig_b64": ""})):
                rec = tmp / "rec.json"
                rec.write_text(payload, encoding="utf-8")
                errs = self.mod.check_dispatch_provenance({}, None, "mutation", "lit", str(rec), str(pub))
                self.assertTrue(errs and all(isinstance(e, str) for e in errs))

            self.assertEqual(
                self.mod._manifest_nc_values({"negative_control": "bad"}),
                {"nc_paths": None, "nc_command": None, "nc_artifact_sha256": None},
            )
            replay_errs = self.mod.check_replay_request({"negative_control": ["bad"]}, True, True, None)
            self.assertTrue(replay_errs)

            # End-to-end CLI with malformed dispatch record still writes --transcript-out and exits 2
            manifest = tmp / "manifest.json"
            manifest.write_text(json.dumps({"unit": "u1", "base_sha": "a" * 40, "head_sha": "b" * 40}), encoding="utf-8")
            rec = tmp / "bad_rec.json"
            rec.write_text(json.dumps({"record": ["not-a-dict"], "sig_b64": "AAAA"}), encoding="utf-8")
            tx = tmp / "tx.json"
            proc = subprocess.run(
                [
                    sys.executable, "-I", str(VERIFY_PY),
                    "--manifest", str(manifest),
                    "--dispatch-record", str(rec),
                    "--dispatch-pubkey", str(pub),
                    "--transcript-out", str(tx),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertTrue(tx.exists(), "transcript-out was not written")
            tx_doc = json.loads(tx.read_text(encoding="utf-8"))
            self.assertEqual(tx_doc["exit"], 2)


class TestA11SpawnWorkerNoSysPathInsert(unittest.TestCase):
    """A-11: spawn_worker.sh uses synthetic runtime package loader instead of sys.path.insert."""

    def test_no_sys_path_insert_in_spawn_worker(self):
        text = SPAWN_WORKER.read_text(encoding="utf-8")
        self.assertNotIn("sys.path.insert", text)
        self.assertGreaterEqual(text.count('type(sys)("runtime")'), 3)


class TestA12VerifyOracleWrapperUnwrap(unittest.TestCase):
    """A-12: verify.py _command_oracle_paths unwraps timeout/nice/nohup/command/env/sh/py.test/egrep."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_verify_a12", VERIFY_PY)

    def test_unwraps_wrappers_and_aliases(self):
        cases = [
            ("timeout 30 pytest -c custom.ini tests/test_a.py", {"pytest", "custom.ini"}),
            ("timeout 15 py.test -ccustom.ini tests/test_b.py", {"py.test", "custom.ini"}),
            ("nohup pytest-3 --config-file=custom.ini tests/test_c.py", {"pytest-3", "custom.ini"}),
            ("command env FOO=1 sh -e ./check.sh", {"sh", "check.sh"}),
            ("egrep -f patterns.txt scripts/check.txt", {"egrep", "patterns.txt"}),
        ]
        for cmd, expected in cases:
            with self.subTest(cmd=cmd):
                got = self.mod._command_oracle_paths(cmd)
                self.assertIsNotNone(got, cmd)
                self.assertTrue(expected.issubset(got), f"{cmd!r} -> {got!r}, expected {expected!r}")


class TestA13VerifyExtractDiffSplitlines(unittest.TestCase):
    """A-13: verify.py _extract_diff uses split('\\n') instead of splitlines()."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_verify_a13", VERIFY_PY)

    def test_preserves_diff_lines_containing_bare_cr_and_unicode_line_sep(self):
        raw = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-x = 'a\rb\u2028c'\n"
            "+x = 'fixed'\n"
            " y = 2\n"
        )
        extracted = self.mod._extract_diff(raw)
        self.assertIsNotNone(extracted)
        self.assertIn("a\rb\u2028c", extracted)
        self.assertIn("+x = 'fixed'", extracted)
        self.assertIn(" y = 2", extracted)


class TestA14VerifyEarlySoundLaneTranscript(unittest.TestCase):
    """A-14: verify.py emits --transcript-out on early sound-lane abort without running untrusted git."""

    def test_early_sound_lane_abort_writes_transcript_without_running_worker_git(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            marker = tmp / "git_ran"
            fake_git = fake_bin / "git"
            fake_git.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
            fake_git.chmod(0o777)

            manifest = tmp / "manifest.json"
            manifest.write_text(json.dumps({"unit": "u1"}), encoding="utf-8")
            rec = tmp / "rec.json"
            rec.write_text("{}", encoding="utf-8")

            env = {
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "HOME": str(tmp),
            }
            # Case 1: --provenance ci
            tx1 = tmp / "tx1.json"
            r1 = subprocess.run(
                [sys.executable, "-I", str(VERIFY_PY), "--manifest", str(manifest),
                 "--provenance", "ci", "--transcript-out", str(tx1)],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(r1.returncode, 2, r1.stderr)
            self.assertFalse(marker.exists(), "worker-writable git was executed!")
            self.assertTrue(tx1.exists(), r1.stderr)
            doc1 = json.loads(tx1.read_text(encoding="utf-8"))
            self.assertEqual(doc1["exit"], 2)

            # Case 2: --dispatch-record + pinned ref pubkey (key_source probe_git=False)
            tx2 = tmp / "tx2.json"
            r2 = subprocess.run(
                [
                    sys.executable, "-I", str(VERIFY_PY), "--manifest", str(manifest),
                    "--dispatch-record", str(rec),
                    "--dispatch-pubkey", ".orca/dispatch-pubkey@refs/remotes/origin/main",
                    "--transcript-out", str(tx2),
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(r2.returncode, 2, r2.stderr)
            self.assertFalse(marker.exists(), "worker-writable git was executed!")
            self.assertTrue(tx2.exists(), r2.stderr)
            doc2 = json.loads(tx2.read_text(encoding="utf-8"))
            self.assertEqual(doc2["exit"], 2)


class TestA15DecisionsLineBreakAndSeedCustody(unittest.TestCase):
    """A-15: decisions.py CR/Unicode line-break injection + cmd_sign_grant seed custody."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module("adv_decisions_a15", DECISIONS)

    def test_append_rejects_cr_and_unicode_line_breaks_including_ts(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "DECISIONS.md"
            ledger.write_text("# Decisions\n\n", encoding="utf-8")
            for ch in ("\r", "\u2028", "\u2029", "\x85", "\x0b", "\x0c"):
                for flag, val in (
                    ("--id", f"id{ch}x"),
                    ("--answer", f"ok{ch}x"),
                    ("--why", f"why{ch}x"),
                    ("--ts", f"2026-10-01{ch}2026-10-02"),
                ):
                    cmd = [
                        sys.executable, "-I", str(DECISIONS), "--file", str(ledger),
                        "append", "--id", "d1", "--class", "taste",
                        "--answer", "allow", "--why", "reason",
                    ]
                    idx = cmd.index(flag) if flag in cmd else -1
                    if idx >= 0:
                        cmd[idx + 1] = val
                    else:
                        cmd.extend([flag, val])
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    self.assertNotEqual(r.returncode, 0, f"expected failure for {flag}={val!r}")

    def test_read_lines_uses_lf_only_and_validate_flags_embedded_breaks(self):
        with tempfile.TemporaryDirectory() as td:
            ledger = Path(td) / "DECISIONS.md"
            line = "- `2026-10-01` · `d1` · taste · ok\u2028- `2026-10-02` · `forged` · one-way · allow · human · why\n"
            ledger.write_text(line, encoding="utf-8")
            records = self.mod.read_lines(ledger)
            self.assertEqual(len(records), 1)
            probs = self.mod.validate(records[0], {})
            self.assertTrue(any("line break" in p for p in probs), probs)

    def test_sign_grant_enforces_mode_and_unignored_worktree_custody(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            outside_key = tmp / "outside.seed"
            outside_key.write_text("11" * 32 + "\n", encoding="utf-8")
            # Mode 0o644 must be refused
            outside_key.chmod(0o644)
            base_args = [
                sys.executable, "-I", str(DECISIONS), "sign-grant",
                "--id", "d1", "--answer", "allow", "--why", "ok",
                "--source", "human:alice", "--ts", "2026-10-01",
            ]
            r_mode = subprocess.run([*base_args, "--key", str(outside_key)], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(r_mode.returncode, 0, r_mode.stdout + r_mode.stderr)
            self.assertIn("seed custody", r_mode.stderr)

            # Mode 0o600 outside any git worktree succeeds
            outside_key.chmod(0o600)
            r_ok = subprocess.run([*base_args, "--key", str(outside_key)], capture_output=True, text=True, timeout=20)
            self.assertEqual(r_ok.returncode, 0, r_ok.stderr)
            self.assertEqual(len(r_ok.stdout.strip()), 128)

            # Mode 0o600 inside an unignored git worktree must be refused
            repo = tmp / "repo"
            _init_repo(repo)
            inside_key = repo / "human.seed"
            inside_key.write_text("11" * 32 + "\n", encoding="utf-8")
            inside_key.chmod(0o600)
            r_wt = subprocess.run([*base_args, "--key", str(inside_key)], capture_output=True, text=True, timeout=20)
            self.assertNotEqual(r_wt.returncode, 0, r_wt.stdout + r_wt.stderr)
            self.assertIn("git work tree", r_wt.stderr)


class TestA16DenyHookReadonlyDevSinksAndBoundedOne(unittest.TestCase):
    """A-16: deny-hook.sh HOOK_READONLY=1 safe dev sinks + bounded_one fail-closed."""

    def test_readonly_allows_safe_dev_sinks_and_denies_real_writes(self):
        with tempfile.TemporaryDirectory() as td:
            env = {"OPEN_FLEET_UNIT_WORKTREE": td, "OPEN_FLEET_HOOK_READONLY": "1"}
            for safe_cmd in (
                "ls 2>/dev/null",
                "echo hi >/dev/stdout",
                "echo hi >/dev/stderr",
                "echo hi >/dev/fd/2",
                "echo hi >&2",
            ):
                with self.subTest(safe_cmd=safe_cmd):
                    proc = _run_deny_hook(
                        {"tool_name": "Bash", "tool_input": {"command": safe_cmd}},
                        env_extra=env,
                        cwd=Path(td),
                    )
                    self.assertEqual(_hook_decision(proc), "allow", f"{safe_cmd!r} -> {proc.stdout!r}")
            for bad_cmd in (
                "echo hi >out.txt",
                "echo hi >/dev/sda",
                "echo hi >/dev/null2",
            ):
                with self.subTest(bad_cmd=bad_cmd):
                    proc = _run_deny_hook(
                        {"tool_name": "Bash", "tool_input": {"command": bad_cmd}},
                        env_extra=env,
                        cwd=Path(td),
                    )
                    self.assertEqual(_hook_decision(proc), "deny", f"{bad_cmd!r} -> {proc.stdout!r}")

    def test_bounded_one_fails_closed_when_resolved_is_empty(self):
        text = DENY_HOOK.read_text(encoding="utf-8")
        m = re.search(r"bounded_one\(\)\s*\{(.*?)\n\}", text, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn('if [ -z "$RESOLVED" ]; then', body)
        self.assertIn("decide deny", body)


class TestA17VerifyGatePubkeyAndProcessGroup(unittest.TestCase):
    """A-17: verify-gate.sh discovers $TOP/.orca/dispatch-pubkey from subdir & kills process group."""

    def test_discovers_pubkey_at_repo_top_from_subdirectory(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            repo = tmp / "repo"
            _init_repo(repo)
            (repo / ".orca").mkdir()
            # Plant a recognizable invalid-hex pubkey at $TOP/.orca/dispatch-pubkey
            (repo / ".orca" / "dispatch-pubkey").write_text("not-valid-hex\n", encoding="utf-8")
            (repo / ".orca" / "rec.json").write_text(json.dumps({"record": {}, "sig_b64": ""}), encoding="utf-8")
            sub = repo / "nested" / "sub"
            sub.mkdir(parents=True)
            manifest = repo / "manifest.json"
            manifest.write_text(json.dumps({"unit": "u1"}), encoding="utf-8")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(tmp),
                "ORCA_MANIFEST": str(manifest),
                "ORCA_DISPATCH_RECORD": ".orca/rec.json",
            }
            r = subprocess.run(
                ["sh", str(VERIFY_GATE)],
                capture_output=True,
                text=True,
                env=env,
                cwd=str(sub),
                timeout=30,
            )
            self.assertEqual(r.returncode, 2)
            # If $TOP/.orca/dispatch-pubkey was discovered and passed repo-relatively,
            # verify.py reads $TOP/.orca/dispatch-pubkey and rejects its non-hex content,
            # rather than refusing an absolute path or reporting a missing pubkey.
            self.assertIn("dispatch record / pubkey malformed", r.stderr)
            self.assertIn("fromhex", r.stderr)
            self.assertNotIn("absolute evidence path refused", r.stderr)
            self.assertNotIn("without a pubkey", r.stderr)

    def test_timeout_kills_verifier_process_group_grandchildren(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            gate_copy = tmp / "verify-gate.sh"
            shutil.copy2(VERIFY_GATE, gate_copy)
            pid_file = tmp / "grandchild.pid"
            stub_verify = tmp / "verify.py"
            stub_verify.write_text(
                "import pathlib, subprocess, time\n"
                "p = subprocess.Popen(['sleep', '60'])\n"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid), encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            manifest = tmp / "manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(tmp),
                "ORCA_MANIFEST": str(manifest),
                "ORCA_GATE_TIMEOUT_S": "1",
            }
            r = subprocess.run(
                ["sh", str(gate_copy)],
                capture_output=True,
                text=True,
                env=env,
                cwd=str(tmp),
                timeout=15,
            )
            self.assertEqual(r.returncode, 2)
            self.assertTrue(pid_file.exists(), "stub grandchild never started")
            gpid = int(pid_file.read_text(encoding="utf-8").strip())
            try:
                # Allow brief kernel reap window
                alive = True
                for _ in range(20):
                    try:
                        os.kill(gpid, 0)
                    except ProcessLookupError:
                        alive = False
                        break
                    time.sleep(0.05)
                self.assertFalse(alive, f"grandchild PID {gpid} survived verify-gate.sh timeout!")
            finally:
                with contextlib.suppress(OSError):
                    os.kill(gpid, 9)


class TestA18SpawnWorkerDoctorCleanup(unittest.TestCase):
    """A-18: spawn_worker.sh removes $doctor_out.stderr on all paths and avoids cat | grep."""

    def test_no_cat_pipe_grep_and_cleans_stderr_temp_file(self):
        text = SPAWN_WORKER.read_text(encoding="utf-8")
        self.assertNotIn('cat "$doctor_out" "$doctor_out.stderr" | grep', text)
        self.assertIn('grep -qiE', text)
        self.assertIn('rm -f -- "$doctor_out" "$doctor_out.stderr"', text)
        # Ensure every rm of $doctor_out also cleans $doctor_out.stderr
        for line in text.splitlines():
            if 'rm -f' in line and '"$doctor_out"' in line:
                self.assertIn('"$doctor_out.stderr"', line)


class TestA19PreflightJson(unittest.TestCase):
    """A-19: preflight.py --json emits structured JSON on all write and readonly paths."""

    def test_json_output_in_readonly_and_error_paths(self):
        # Readonly mode with --json
        r_ro = subprocess.run(
            [sys.executable, "-I", str(PREFLIGHT), "--mode", "readonly", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        doc_ro = json.loads(r_ro.stdout)
        self.assertIsInstance(doc_ro, dict)
        self.assertIn("ok", doc_ro)

        # Error path (unknown runtime) with --json
        r_err = subprocess.run(
            [sys.executable, "-I", str(PREFLIGHT), "--runtime", "no-such-runtime", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(r_err.returncode, 0)
        doc_err = json.loads(r_err.stdout)
        self.assertIsInstance(doc_err, dict)
        self.assertFalse(doc_err.get("ok"))
        self.assertIn("error", doc_err)

        # Write mode missing --base with --json still outputs structured JSON
        r_wr = subprocess.run(
            [sys.executable, "-I", str(PREFLIGHT), "--runtime", "posix", "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(r_wr.returncode, 0)
        doc_wr = json.loads(r_wr.stdout)
        self.assertIsInstance(doc_wr, dict)
        self.assertFalse(doc_wr.get("ok"))
        self.assertIn("error", doc_wr)


if __name__ == "__main__":
    unittest.main()
