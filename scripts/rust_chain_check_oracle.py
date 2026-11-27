#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_chain_check.py against `open-fleet chain-check`."""
import sys

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
    ap.add_argument("--bin", dest="binary", default=str(default_binary()))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None)
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"rust_chain_check_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    test_path = ROOT / "tests" / "test_chain_check.py"
    mod = load_module("test_chain_check_oracle", test_path)
    real_run = subprocess.run

    def rust_classify(terminal):
        r = real_run([str(binary), "chain-check", "classify", "--", str(terminal)],
                     capture_output=True, text=True)
        return r.stdout.strip()

    def rust_gate(terminal, allowed):
        csv = ",".join(sorted(allowed))
        r = real_run([str(binary), "chain-check", "gate", "--allowed", csv, "--", str(terminal)],
                     capture_output=True, text=True)
        return (r.returncode == 0), r.stdout.strip()

    def rust_audit(root=None):
        cmd = [str(binary), "chain-check", "audit"]
        if root is not None:
            cmd += ["--root", str(root)]
        r = real_run(cmd, capture_output=True, text=True)
        return [ln for ln in r.stderr.splitlines() if ln.strip()]

    def patched_run(cmd, *a, **kw):
        if isinstance(cmd, (list, tuple)) and len(cmd) >= 2 and str(cmd[1]) == str(mod.SCRIPT):
            cmd = [str(binary), "chain-check", *cmd[2:]]
        return real_run(cmd, *a, **kw)

    mod.chain_check.classify = rust_classify
    mod.chain_check.gate = rust_gate
    mod.chain_check.audit = rust_audit
    mod.subprocess.run = patched_run

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    print(f"rust_chain_check_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_chain_check_oracle: {result.testsRun} run, {len(result.failures)} failed, "
          f"{len(result.errors)} errors in {dt:.2f}s")
    return 0 if result.wasSuccessful() and selected > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
