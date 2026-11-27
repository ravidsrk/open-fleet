#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_diff_scope.py CLI tests against `open-fleet diff-scope`."""
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
    tokens = (
        "diff_scope.main(", "diff_scope.scope(", "diff_scope.predict_merge(",
        "diff_scope.resolve_base(", "diff_scope.changed_files(", "diff_scope.classify(",
        "diff_scope._", "diff_scope.GIT", "mock.patch", "wtree.sh",
    )
    return any(t in src for t in tokens)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bin", dest="binary", default=str(default_binary()))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None)
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"rust_diff_scope_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    test_path = ROOT / "tests" / "test_diff_scope.py"
    source = test_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    cli_methods = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    qual = f"{node.name}.{item.name}"
                    seg = ast.get_source_segment(source, item) or ""
                    if _uses_python_internals(seg):
                        continue
                    if any(k in seg for k in (
                        "self.run_scope(", "self.flags(", "self.assert_flag(",
                        "self.predict(", "self.scoped(", "subprocess.run", "scope(",
                    )):
                        cli_methods.add(qual)

    mod = load_module("test_diff_scope_oracle", test_path)

    def rust_run_scope(self, *scope_args):
        return subprocess.run(
            [str(binary), "diff-scope", "--repo", str(self.repo), *scope_args],
            capture_output=True, text=True,
        )

    mod.ScopeBase.run_scope = rust_run_scope

    real_run = subprocess.run

    def patched_run(cmd, *a, **kw):
        if (isinstance(cmd, (list, tuple)) and len(cmd) >= 2
                and str(cmd[1]) == str(mod.SCOPE)):
            cmd = [str(binary), "diff-scope", *cmd[2:]]
        elif (isinstance(cmd, (list, tuple)) and len(cmd) >= 3
              and cmd[1] == "-I" and str(cmd[2]) == str(mod.SCOPE)):
            cmd = [str(binary), "diff-scope", *cmd[3:]]
        return real_run(cmd, *a, **kw)

    mod.subprocess.run = patched_run

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        if attr_name == "ScopeBase":
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if qual not in cli_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    print(f"rust_diff_scope_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_diff_scope_oracle: {result.testsRun} run, {len(result.failures)} failed, "
          f"{len(result.errors)} errors in {dt:.2f}s")
    return 0 if result.wasSuccessful() and selected > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
