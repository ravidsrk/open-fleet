#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_floor_guard.py end-to-end against the Rust CLI.

Every test in tests/test_floor_guard.py that invokes `run_guard(repo, *args)` creates a real,
hermetic git repository and asserts exit codes, redaction, waiver verification, custody
hardening, and rule verdicts. This oracle swaps `run_guard` to execute the compiled Rust binary
(`<bin> floor --repo <repo> ...`) and fails on any behavioral divergence.
"""
import sys

# W3-01 safe-path prologue (same contract as runtime/scripts/).
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import importlib.util
import os
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Tests that inspect Python internals or Python-only in-proc mocks rather than the CLI binary.
PYTHON_INTERNAL_CLASSES = frozenset({
    "TestScriptShape",
    "TestScanUnits",
    "TestDiffParsingUnits",
    "TestWaiverUnits",
    "TestMainInProc",
    "TestThresholdRowsP25",
    "TestGuardSurfaceHit",
    "TestGuardSurfaceCarveOuts",
    "TestThresholdEvasions",
})

PYTHON_INTERNAL_METHODS = frozenset({
    "TestCleanAndExitCodes.test_help_exits_zero",
    "TestCleanAndExitCodes.test_exit_codes_are_documented_in_the_docstring",
    "TestDiffAcquisition.test_disappearing_untracked_file_is_exit_2",
})


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def default_binary():
    env_bin = os.environ.get("OPEN_FLEET_BIN")
    if env_bin:
        return Path(env_bin)
    ext = ".exe" if os.name == "nt" else ""
    return ROOT / "target" / "release" / f"open-fleet{ext}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", dest="binary", default=str(default_binary()),
                    help="Path to the compiled open-fleet binary.")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None,
                    help="Only run tests whose Class.method contains this substring.")
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"rust_floor_oracle: binary not found at {binary}", file=sys.stderr)
        print("Build it with: cargo build --release -p of-cli", file=sys.stderr)
        return 2

    # Ensure tests/ is importable if fixtures reference it, while keeping ROOT at the end.
    tfg = load_module("test_floor_guard_oracle", ROOT / "tests" / "test_floor_guard.py")

    def rust_run_guard(repo, *guard_args):
        return subprocess.run(
            [str(binary), "floor", "--repo", str(repo), *guard_args],
            capture_output=True, text=True,
        )

    tfg.run_guard = rust_run_guard

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0

    for attr_name in dir(tfg):
        obj = getattr(tfg, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        if attr_name in ("FloorGuardBase", "ReviewRepo") or attr_name in PYTHON_INTERNAL_CLASSES:
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if qual in PYTHON_INTERNAL_METHODS:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    # Also verify --help directly on the Rust binary.
    help_run = subprocess.run([str(binary), "floor", "--help"], capture_output=True, text=True)
    if help_run.returncode != 0 or "--base" not in help_run.stdout:
        print("rust_floor_oracle: `open-fleet floor --help` failed contract", file=sys.stderr)
        return 1

    print(f"rust_floor_oracle: running {selected} end-to-end adversarial tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_floor_oracle: {result.testsRun} tests in {dt:.2f}s "
          f"(failures={len(result.failures)}, errors={len(result.errors)})")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
