#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_decisions.py CLI tests against `open-fleet decisions`."""
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


def _uses_python_internals(src):
    tokens = ("decisions.main(", "decisions.validate(", "decisions.parse_line(",
              "decisions.standing(", "decisions.active(", "decisions.tally(",
              "decisions.door_hits(", "decisions.fold(", "decisions.grant_pubkey(",
              "decisions.grant_problems(", "decisions.read_lines(", "decisions._",
              "decisions.NEVER_GATE", "mock.patch", "runpy.")
    return any(t in src for t in tokens)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", dest="binary", default=str(default_binary()))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None)
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"rust_decisions_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    test_path = ROOT / "tests" / "test_decisions.py"
    source = test_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    cli_methods = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            if node.name in ("TestScriptShape", "TestNeverGateMatchesThePolicy"):
                continue
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    qual = f"{node.name}.{item.name}"
                    seg = ast.get_source_segment(source, item) or ""
                    if _uses_python_internals(seg):
                        continue
                    if any(k in seg for k in ("self.run_dec(", "self.append(", "subprocess.run", "self.run_cli(")):
                        cli_methods.add(qual)

    mod = load_module("test_decisions_oracle", test_path)

    def rust_run_dec(self, *dec_args, log=None):
        return subprocess.run(
            [str(binary), "decisions", "--file", str(log or self.log), *dec_args],
            capture_output=True, text=True,
        )

    mod.DecisionsBase.run_dec = rust_run_dec

    real_run = subprocess.run

    def patched_run(cmd, *a, **kw):
        if (isinstance(cmd, (list, tuple)) and len(cmd) >= 2
                and str(cmd[1]) == str(mod.DECISIONS)):
            cmd = [str(binary), "decisions", *cmd[2:]]
        elif (isinstance(cmd, (list, tuple)) and len(cmd) >= 3
              and cmd[1] == "-I" and str(cmd[2]) == str(mod.DECISIONS)):
            cmd = [str(binary), "decisions", *cmd[3:]]
        return real_run(cmd, *a, **kw)

    mod.subprocess.run = patched_run

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        if attr_name == "DecisionsBase":
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if qual not in cli_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    print(f"rust_decisions_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_decisions_oracle: {result.testsRun} tests in {dt:.2f}s "
          f"(failures={len(result.failures)}, errors={len(result.errors)})")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
