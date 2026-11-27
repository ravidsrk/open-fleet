#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_egress.py CLI tests against `open-fleet egress`."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import ast
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


# Pure Python-internal / in-proc mock tests that monkeypatch Python stdlib internals.
PYTHON_INTERNAL_METHODS = frozenset({
    "TestWrite.test_lock_failure_is_fail_closed_and_leaves_no_successful_receipt",
    "TestWrite.test_permissions_are_private_at_creation_before_any_chmod",
    "TestWrite.test_overlapping_writers_preserve_every_successful_receipt_in_one_chain",
    "TestWrite.test_torn_write_rolls_back_the_partial_line",
    "TestWrite.test_inode_swap_during_write_refuses",
    "TestScriptShape.test_executable_and_shebanged",
})


def _uses_python_internals(src):
    tokens = ("egress.main(", "egress.write_receipt(", "egress.scan(", "egress.load_ledger(",
              "egress.verify_ledger(", "egress.head_digest(", "egress.read_ledger(",
              "egress.default_ledger(", "egress.resolve_ledger(", "egress._", "egress.valid_ts(",
              "egress.require_field(", "egress.record_id(", "egress.canonical_line(",
              "patch(", "patch.object(")
    return any(t in src for t in tokens)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", dest="binary", default=str(default_binary()))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None)
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"rust_egress_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    test_path = ROOT / "tests" / "test_egress.py"
    source = test_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    cli_methods = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    qual = f"{node.name}.{item.name}"
                    seg = ast.get_source_segment(source, item) or ""
                    if qual in PYTHON_INTERNAL_METHODS or _uses_python_internals(seg):
                        continue
                    if any(k in seg for k in ("run_egress(", "write_one(", "subprocess.run")):
                        cli_methods.add(qual)

    mod = load_module("test_egress_oracle", test_path)

    def rust_run_egress(self, *eg_args, ledger=None, env=None):
        return subprocess.run(
            [str(binary), "egress", "--ledger", str(ledger or self.ledger), *eg_args],
            capture_output=True, text=True, env=env,
        )

    mod.EgressBase.run_egress = rust_run_egress

    # Also redirect subprocess.run([sys.executable, str(EGRESS), ...]) inside test_egress.py.
    real_run = subprocess.run

    def patched_run(cmd, *a, **kw):
        if (isinstance(cmd, (list, tuple)) and len(cmd) >= 2
                and str(cmd[1]) == str(mod.EGRESS)):
            cmd = [str(binary), "egress", *cmd[2:]]
        return real_run(cmd, *a, **kw)

    mod.subprocess.run = patched_run

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        if attr_name == "EgressBase":
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if qual not in cli_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    print(f"rust_egress_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_egress_oracle: {result.testsRun} tests in {dt:.2f}s "
          f"(failures={len(result.failures)}, errors={len(result.errors)})")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
