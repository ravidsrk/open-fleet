#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_chain_check.py against `open-fleet chain-check`."""
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
    mod = _O.load_module("test_chain_check_oracle", _O.ROOT / "tests" / "test_chain_check.py")
    real_run = subprocess.run

    def rust_classify(terminal):
        return real_run(
            [str(binary), "chain-check", "classify", "--", str(terminal)],
            capture_output=True, text=True,
        ).stdout.strip()

    def rust_gate(terminal, allowed):
        r = real_run(
            [str(binary), "chain-check", "gate", "--allowed", ",".join(sorted(allowed)), "--", str(terminal)],
            capture_output=True, text=True,
        )
        return (r.returncode == 0), r.stdout.strip()

    def rust_audit(root=None):
        cmd = [str(binary), "chain-check", "audit"] + (["--root", str(root)] if root is not None else [])
        return [ln for ln in real_run(cmd, capture_output=True, text=True).stderr.splitlines() if ln.strip()]

    mod.chain_check.classify = rust_classify
    mod.chain_check.gate = rust_gate
    mod.chain_check.audit = rust_audit
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(
        [str(binary), "chain-check", *cmd[2:]] if (
            isinstance(cmd, (list, tuple)) and len(cmd) >= 2 and str(cmd[1]) == str(mod.SCRIPT)
        ) else cmd, *a, **kw)
    return _O.add_module_tests(suite, mod, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_chain_check_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
