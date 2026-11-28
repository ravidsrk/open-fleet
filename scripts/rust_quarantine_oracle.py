#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_quarantine.py CLI tests against `open-fleet quarantine`."""
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


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_quarantine.py"
    allowed = _O.collect_ast_methods(
        test_path,
        only_classes=("Cli", "MainInProcess"),
        predicate=lambda _c, _m, _q, s: any(k in s for k in ("self.run_cli(", "self.run_main(")),
    )
    mod = _O.load_module("test_quarantine_oracle", test_path)
    mod.Cli.run_cli = lambda self, *a: subprocess.run(
        [str(binary), "quarantine", *a], capture_output=True, text=True)

    def rust_run_main(self, *a):
        r = subprocess.run([str(binary), "quarantine", *a], capture_output=True, text=True)
        return r.returncode, r.stdout, r.stderr

    mod.MainInProcess.run_main = rust_run_main
    return _O.add_module_tests(
        suite, mod, only_classes=("Cli", "MainInProcess"), allowed_methods=allowed, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_quarantine_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
