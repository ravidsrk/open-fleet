#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_dispatch_sign.py CLI tests against `open-fleet dispatch-sign`."""
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
        print(f"rust_dispatch_sign_oracle: binary not found at {binary}", file=sys.stderr)
        return 2

    test_path = ROOT / "tests" / "test_dispatch_sign.py"
    source = test_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    cli_methods = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            if node.name in ("OneSignedFieldRule",):
                continue
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                    qual = f"{node.name}.{item.name}"
                    seg = ast.get_source_segment(source, item) or ""
                    if "mock.patch" in seg and "verify_dispatch" not in seg:
                        continue
                    if "verify._Transcript" in seg:
                        continue
                    if "self.check(" in seg:
                        continue
                    cli_methods.add(qual)

    mod = load_module("test_dispatch_sign_oracle", test_path)
    real_run = subprocess.run

    def rust_main(argv_list):
        r = real_run(
            [str(binary), "dispatch-sign", *[str(a) for a in argv_list]],
            capture_output=True, text=True,
            env={**os.environ, "OPEN_FLEET_ROOT": str(ROOT)},
        )
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode

    def rust_verify_dispatch(record_ref=None, *, pubkey_ref=None, key_ref=None,
                             profile=None, parent_profile=None):
        cmd = [str(binary), "dispatch-sign", "verify"]
        if record_ref is not None:
            cmd += ["--record", str(record_ref)]
        if pubkey_ref is not None:
            cmd += ["--pubkey", str(pubkey_ref)]
        if key_ref is not None:
            cmd += ["--key", str(key_ref)]
        if profile is not None:
            cmd += ["--profile", str(profile)]
        if parent_profile is not None:
            cmd += ["--parent-profile", str(parent_profile)]
        r = real_run(cmd, capture_output=True, text=True,
                     env={**os.environ, "OPEN_FLEET_ROOT": str(ROOT)})
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode

    ds_script = str(ROOT / "runtime" / "scripts" / "dispatch-sign.py")

    def patched_run(cmd, *a, **kw):
        if isinstance(cmd, (list, tuple)) and len(cmd) >= 2 and str(cmd[1]) == ds_script:
            cmd = [str(binary), "dispatch-sign", *cmd[2:]]
        return real_run(cmd, *a, **kw)

    mod.dispatch_sign.main = rust_main
    mod.dispatch_sign.verify_dispatch = rust_verify_dispatch
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
            if qual not in cli_methods:
                continue
            if args.pattern and args.pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            selected += 1

    print(f"rust_dispatch_sign_oracle: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"rust_dispatch_sign_oracle: {result.testsRun} run, {len(result.failures)} failed, "
          f"{len(result.errors)} errors in {dt:.2f}s")
    return 0 if result.wasSuccessful() and selected > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
