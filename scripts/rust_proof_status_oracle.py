#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_proof_status.py CLI tests against `open-fleet proof-status`."""
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
    mod = _O.load_module("test_proof_status_oracle", _O.ROOT / "tests" / "test_proof_status.py")

    def rust_main(argv_list):
        r = subprocess.run(
            [str(binary), "proof-status", *[str(a) for a in argv_list]],
            capture_output=True, text=True,
        )
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode

    mod.proof_status.main = rust_main
    return _O.add_module_tests(suite, mod, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_proof_status_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
