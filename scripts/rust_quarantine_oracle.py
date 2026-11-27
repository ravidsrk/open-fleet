#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_quarantine.py CLI tests against `open-fleet quarantine`."""
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


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", dest="binary", default=str(default_binary()))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None)
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"rust_quarantine_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    test_path = ROOT / "tests" / "test_quarantine.py"
    source = test_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    cli_methods = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in ("Cli", "MainInProcess"):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    qual = f"{node.name}.{item.name}"
                    seg = ast.get_source_segment(source, item) or ""
                    if any(k in seg for k in ("self.run_cli(", "self.run_main(")):
                        cli_methods.add(qual)

    mod = load_module("test_quarantine_oracle", test_path)

    def rust_run_cli(self, *cli_args):
        return subprocess.run(
            [str(binary), "quarantine", *cli_args],
            capture_output=True, text=True,
        )

    def rust_run_main(self, *cli_args):
        r = subprocess.run(
            [str(binary), "quarantine", *cli_args],
            capture_output=True, text=True,
        )
        return r.returncode, r.stdout, r.stderr

    mod.Cli.run_cli = rust_run_cli
    mod.MainInProcess.run_main = rust_run_main

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0
    for cls_name in ("Cli", "MainInProcess"):
        cls = getattr(mod, cls_name)
        for method_name in loader.getTestCaseNames(cls):
            qual = f"{cls_name}.{method_name}"
            if qual not in cli_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(cls(method_name))
            selected += 1

    print(f"rust_quarantine_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_quarantine_oracle: {result.testsRun} run, {len(result.failures)} failed, "
          f"{len(result.errors)} errors in {dt:.2f}s")
    return 0 if result.wasSuccessful() and selected > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
