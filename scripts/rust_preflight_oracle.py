#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_preflight.py and tests/test_capabilities_preflight.py CLI tests against `open-fleet preflight`."""
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
        print(f"rust_preflight_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    selected = 0

    # 1. tests/test_preflight.py CLI tests
    pf_path = ROOT / "tests" / "test_preflight.py"
    pf_src = pf_path.read_text(encoding="utf-8")
    pf_tree = ast.parse(pf_src)
    pf_methods = set()
    for node in pf_tree.body:
        if isinstance(node, ast.ClassDef):
            if node.name in ("TestTimeoutSentinel", "TestHungGh"):
                continue
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    seg = ast.get_source_segment(pf_src, item) or ""
                    if ("preflight._" in seg or "mock.patch" in seg
                            or "quarantine_check.py unloadable" in seg):
                        continue
                    pf_methods.add(f"{node.name}.{item.name}")

    pf_mod = load_module("test_preflight_oracle", pf_path)
    real_run = subprocess.run

    def rust_run_preflight(*pf_args, cwd=None, env=None):
        return real_run(
            [str(binary), "preflight", *[str(a) for a in pf_args]],
            capture_output=True, text=True, cwd=cwd, env=env, timeout=60,
        )

    pf_mod.run_preflight = rust_run_preflight

    for attr_name in dir(pf_mod):
        obj = getattr(pf_mod, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if qual not in pf_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    # 2. tests/test_capabilities_preflight.py CLI tests
    cp_path = ROOT / "tests" / "test_capabilities_preflight.py"
    cp_src = cp_path.read_text(encoding="utf-8")
    cp_tree = ast.parse(cp_src)
    cp_methods = set()
    for node in cp_tree.body:
        if isinstance(node, ast.ClassDef) and node.name in (
            "TestPreflightCapabilitiesEnforcement",
            "TestFallbackProbesAndSharedResolver",
        ):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    seg = ast.get_source_segment(cp_src, item) or ""
                    if "preflight._" in seg or "self._resolve(" in seg or "mock.patch" in seg:
                        continue
                    if "run_preflight(" in seg:
                        cp_methods.add(f"{node.name}.{item.name}")

    cp_mod = load_module("test_cap_preflight_oracle", cp_path)

    def rust_cap_run_preflight(*pf_args, cwd=None, env=None):
        run_env = dict(os.environ if env is None else env)
        if env is None:
            run_env.pop("OPEN_FLEET_RUNTIME", None)
            run_env.pop("ORCA_FLEET_RUNTIME", None)
        return real_run(
            [str(binary), "preflight", *[str(a) for a in pf_args]],
            capture_output=True, text=True, cwd=cwd or ROOT, env=run_env, timeout=60,
        )

    cp_mod.run_preflight = rust_cap_run_preflight

    for cls_name in ("TestPreflightCapabilitiesEnforcement", "TestFallbackProbesAndSharedResolver"):
        cls = getattr(cp_mod, cls_name)
        for method_name in loader.getTestCaseNames(cls):
            qual = f"{cls_name}.{method_name}"
            if qual not in cp_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(cls(method_name))
            selected += 1

    print(f"rust_preflight_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_preflight_oracle: {result.testsRun} run, {len(result.failures)} failed, "
          f"{len(result.errors)} errors in {dt:.2f}s")
    return 0 if result.wasSuccessful() and selected > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
