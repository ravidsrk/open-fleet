#!/usr/bin/env python3
"""W3-01 (2026-10-27 security audit, P0), as a class: no control-plane entry point may import a
sibling named like a stdlib module.

`python3 <dir>/<script>.py` puts <dir> at sys.path[0], AHEAD of the stdlib. A committed
`runtime/scripts/json.py` was therefore the `json` verify.py parsed the manifest with — a stale
review went exit 2 → exit 0 — and the toolchain hash, which binds first-party FILES, never saw it.
tests/test_verify.py carries the audit's own reproduction; this module holds the class shut for
every entry point the control plane runs, three ways:

* every listed entry point opens with the same guard — `import sys`, then one `if` that drops its
  own directory from sys.path — before any other import (a `from __future__` import included:
  it is a real import of `__future__`, resolved through sys.path[0] like any other);
* behaviourally: every stdlib module name is planted as a `.py` file in BOTH script directories
  of a copy of the tree, each entry point runs (`--help`, WITHOUT -I), and no plant may load;
* no committed script in either directory is itself named like a stdlib module.

What counts as an entry point (ENTRY_POINTS): the B3/B4 carriers of the audit's threat model,
every script a pull_request CI job runs from runtime/scripts/ or scripts/ over the graded tree,
and the gate steps missions and playbooks run (preflight's quarantine gate, chain_check, the
risk-review diff_scope signals, the release gate), plus orca_cli.py, which preflight's runtime
check shares the provider-registry bootstrap with. Not listed, with the reason:
runtime/scripts/upstream_probe.py (scheduled over the default branch, never a graded tree);
evidence-run.py (the WORKER's recorder; verify.py re-derives what it writes).

The repo ROOT is planted too: preflight.py and orca_cli.py import the `runtime` package and used
to put ROOT on sys.path to do it. scripts/shard-tests.py still does — it imports the PR's own
tests/ package by design, so it runs the graded tree's code anyway and shadowing adds nothing.
"""
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ENTRY_POINTS = (
    "runtime/scripts/verify.py",
    "runtime/scripts/gate-batch.py",
    "runtime/scripts/dispatch-sign.py",
    "runtime/scripts/run_report.py",
    "runtime/scripts/inventory.py",
    "runtime/scripts/decisions.py",
    "runtime/scripts/floor_guard.py",
    "runtime/scripts/pin_review.py",
    "runtime/scripts/quarantine_check.py",
    "runtime/scripts/search_sessions.py",
    "runtime/scripts/proof_status.py",
    "runtime/scripts/preflight.py",
    "runtime/scripts/diff_scope.py",
    "runtime/scripts/chain_check.py",
    "runtime/scripts/orca_cli.py",
    # spawn_worker.sh's identity reader (W4-04): it decides a spawn's cap.
    "runtime/scripts/spawn_identity.py",
    "runtime/scripts/certification.py",
    "runtime/scripts/merge_queue.py",
    "runtime/scripts/egress.py",
    "runtime/scripts/guard_text.py",
    "runtime/scripts/sandbox_doctor.py",
    "runtime/scripts/events.py",
    "runtime/scripts/watchdog.py",
    "scripts/bind_check.py",
    "scripts/validate.py",
    "scripts/hint_replay.py",
    "scripts/shard-tests.py",
    "scripts/check_trailers.py",
    "scripts/changelog.py",
    "scripts/check.py",
    "scripts/run_index.py",
    "scripts/gen-badges.py",
    "scripts/eval.py",
    "scripts/bundle.py",
    "scripts/verdict_check.py",
    "scripts/release_check.py",
    "scripts/live_broker.py",
    "scripts/live_container.py",
    "bench/vf-bench/gate.py",
    "bench/vf-bench/replay.py",
    "bench/vf-bench/heldout.py",
    "bench/vf-bench/vfbench.py",
)

# The guard, as code (comments are free; the logic is not). `os` comes from sys.modules — it is
# loaded at start-up — so the guard itself imports nothing a plant could answer.
CANONICAL_GUARD = '''
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]
'''

PLANT = ("import os as _o\n"
         "open(_o.path.join(_o.path.dirname(__file__), 'PLANT-' + __name__), 'w').close()\n"
         "raise ImportError('a planted stdlib shadow loaded: ' + __name__)\n")

SCRIPT_DIRS = ("runtime/scripts", "scripts", "bench/vf-bench")
# Plants also go at the copied repo ROOT: a script that puts ROOT on sys.path (to import the
# `runtime` package) would let a root-level file named like a stdlib module answer.
PLANT_DIRS = ("", *SCRIPT_DIRS)


def _statements(rel):
    """The module body after its docstring."""
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"), filename=rel)
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return body


class EveryEntryPointCarriesTheGuard(unittest.TestCase):
    """The static half: a new entry point that forgets the guard fails here, by name."""

    def test_the_list_names_real_entry_points(self):
        for rel in ENTRY_POINTS:
            with self.subTest(rel=rel):
                text = (ROOT / rel).read_text(encoding="utf-8")
                self.assertIn('if __name__ == "__main__":', text, f"{rel} is not an entry point")

    def test_the_guard_is_the_first_thing_each_entry_point_runs(self):
        want = ast.dump(ast.parse(CANONICAL_GUARD).body[0])
        for rel in ENTRY_POINTS:
            with self.subTest(rel=rel):
                body = _statements(rel)
                self.assertGreaterEqual(len(body), 2, rel)
                first, second = body[0], body[1]
                self.assertTrue(isinstance(first, ast.Import)
                                and [a.name for a in first.names] == ["sys"]
                                and first.names[0].asname is None,
                                f"{rel}: the first statement after the docstring must be "
                                f"`import sys` (a builtin, never resolved through sys.path), got "
                                f"{ast.unparse(first)!r}")
                self.assertEqual(ast.dump(second), want,
                                 f"{rel}: the second statement must be the W3-01 guard, got "
                                 f"{ast.unparse(second)[:120]!r}")

    def test_no_entry_point_imports_from_future(self):
        # `from __future__ import annotations` must be the first statement of a module, so it runs
        # BEFORE any guard — and it really imports `__future__`, through sys.path[0].
        for rel in ENTRY_POINTS:
            with self.subTest(rel=rel):
                futures = [n.lineno for n in ast.walk(ast.parse((ROOT / rel).read_text(
                    encoding="utf-8"))) if isinstance(n, ast.ImportFrom)
                    and n.module == "__future__"]
                self.assertEqual(futures, [], f"{rel} imports __future__ at {futures}")

    def test_no_script_is_named_like_a_stdlib_module(self):
        for d in SCRIPT_DIRS:
            for path in sorted((ROOT / d).iterdir()):
                with self.subTest(path=f"{d}/{path.name}"):
                    self.assertNotIn(path.stem if path.suffix == ".py" else path.name,
                                     sys.stdlib_module_names,
                                     f"{d}/{path.name} shadows a stdlib module for any script "
                                     "that imports it by name")


class NoPlantedStdlibNameLoads(unittest.TestCase):
    """The behavioural half, run WITHOUT -I: the guard must hold when the caller forgets it."""

    @classmethod
    def setUpClass(cls):
        cls._td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.tree = Path(cls._td.name).resolve()
        for top in ("runtime", "scripts", "bench"):
            shutil.copytree(ROOT / top, cls.tree / top,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        cls.names = sorted(n for n in sys.stdlib_module_names if n.isidentifier())
        for d in PLANT_DIRS:
            for name in cls.names:
                target = cls.tree / d / f"{name}.py"
                if not target.exists():
                    target.write_text(PLANT, encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls._td.cleanup()

    def _loaded(self):
        return sorted(f"{d or '.'}/{p.name}" for d in PLANT_DIRS
                      for p in (self.tree / d).glob("PLANT-*"))

    def _clear(self):
        for d in PLANT_DIRS:
            for p in (self.tree / d).glob("PLANT-*"):
                p.unlink()

    def test_the_plants_would_load_without_the_guard(self):
        # The control: a script WITHOUT the guard, beside the same plants, loads one — so an empty
        # marker list below means the guard held, not that the plants were inert.
        probe = self.tree / "runtime" / "scripts" / "zz_unguarded_probe.py"
        probe.write_text("import json\n", encoding="utf-8")
        self.addCleanup(probe.unlink)
        self.addCleanup(self._clear)
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        subprocess.run([sys.executable, str(probe)], cwd=self.tree, env=env,
                       capture_output=True, timeout=60)
        self.assertIn("runtime/scripts/PLANT-json", self._loaded())

    def test_no_entry_point_loads_a_sibling_named_like_a_stdlib_module(self):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("PYTHON", "ORCA_", "OPEN_FLEET_"))}
        for rel in ENTRY_POINTS:
            with self.subTest(rel=rel):
                self._clear()
                proc = subprocess.run([sys.executable, str(self.tree / rel), "--help"],
                                      cwd=self.tree, env=env, capture_output=True, text=True,
                                      timeout=120)
                self.assertEqual(self._loaded(), [],
                                 f"{rel} loaded a planted stdlib shadow: {proc.stderr[-400:]}")
                # It got past its imports and ran: help printed, or a clean usage refusal (one
                # script reads its tree before parsing argv) — never a traceback.
                self.assertNotIn("Traceback", proc.stderr,
                                 f"{rel} --help crashed: {proc.stderr[-400:]}")
        self._clear()

    def test_the_runtime_package_loads_without_the_repo_root_on_sys_path(self):
        # PR #719 re-attack (W3-01 class): preflight.py and orca_cli.py put the repo ROOT at
        # sys.path[0] to `from runtime import providers`, so a ROOT-level __future__.py /
        # typing.py / sqlite3.py answered imports made while the package loaded — through
        # `preflight.py --mode readonly`, which review-it runs over a graded tree. Driven down the
        # real path: a selected runtime makes both load the provider registry.
        subprocess.run(["git", "init", "-q", str(self.tree)], check=True, capture_output=True)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("PYTHON", "ORCA_", "OPEN_FLEET_"))}
        env["OPEN_FLEET_RUNTIME"] = "posix"
        for rel, args in (("runtime/scripts/preflight.py", ["--mode", "readonly"]),
                          ("runtime/scripts/orca_cli.py", ["--version"])):
            with self.subTest(rel=rel):
                self._clear()
                proc = subprocess.run([sys.executable, str(self.tree / rel), *args],
                                      cwd=self.tree, env=env, capture_output=True, text=True,
                                      timeout=120)
                self.assertEqual(self._loaded(), [],
                                 f"{rel} loaded a planted stdlib shadow: {proc.stderr[-400:]}")
                self.assertNotIn("Traceback", proc.stderr, proc.stderr[-400:])
                self.assertNotIn("registry unloadable", proc.stderr, proc.stderr[-400:])
        self._clear()


if __name__ == "__main__":
    unittest.main()
