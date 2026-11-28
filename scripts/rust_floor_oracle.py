#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_floor_guard.py end-to-end against `open-fleet floor`."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
import subprocess
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("_rust_oracle", Path(__file__).resolve().with_name("_rust_oracle.py"))
_O = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_O)

SKIP_CLASSES = frozenset({
    "FloorGuardBase", "ReviewRepo", "TestScriptShape", "TestScanUnits",
    "TestDiffParsingUnits", "TestWaiverUnits", "TestMainInProc",
    "TestThresholdRowsP25", "TestGuardSurfaceHit", "TestGuardSurfaceCarveOuts",
    "TestThresholdEvasions",
})
SKIP_METHODS = frozenset({
    "TestCleanAndExitCodes.test_help_exits_zero",
    "TestCleanAndExitCodes.test_exit_codes_are_documented_in_the_docstring",
    "TestDiffAcquisition.test_disappearing_untracked_file_is_exit_2",
})


def _build(binary, suite, args):
    help_run = subprocess.run([str(binary), "floor", "--help"], capture_output=True, text=True)
    if help_run.returncode != 0 or "--base" not in help_run.stdout:
        print("rust_floor_oracle: `open-fleet floor --help` failed contract", file=sys.stderr)
        return None
    mod = _O.load_module("test_floor_guard_oracle", _O.ROOT / "tests" / "test_floor_guard.py")
    mod.run_guard = lambda repo, *a: subprocess.run(
        [str(binary), "floor", "--repo", str(repo), *a], capture_output=True, text=True)
    return _O.add_module_tests(
        suite, mod, skip_classes=SKIP_CLASSES, skip_methods=SKIP_METHODS, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_floor_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
