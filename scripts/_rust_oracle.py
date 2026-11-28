#!/usr/bin/env python3
"""Shared runner helpers for scripts/rust_*_oracle.py adversarial parity oracles."""
import argparse
import ast
import importlib.util
import os
import sys
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


def collect_ast_methods(test_path, *, skip_classes=(), only_classes=None, predicate=None):
    source = Path(test_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    selected = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if only_classes is not None and node.name not in only_classes:
            continue
        if node.name in skip_classes:
            continue
        for item in node.body:
            if not (isinstance(item, ast.FunctionDef) and item.name.startswith("test_")):
                continue
            qual = f"{node.name}.{item.name}"
            seg = ast.get_source_segment(source, item) or ""
            if predicate is None or predicate(node.name, item.name, qual, seg):
                selected.add(qual)
    return selected


def add_module_tests(
    suite,
    mod,
    *,
    only_classes=None,
    skip_classes=(),
    allowed_methods=None,
    skip_methods=(),
    pattern=None,
):
    loader = unittest.TestLoader()
    added = 0
    names = only_classes if only_classes is not None else dir(mod)
    for attr_name in names:
        obj = getattr(mod, attr_name)
        if not (isinstance(obj, type) and issubclass(obj, unittest.TestCase)):
            continue
        if attr_name in skip_classes:
            continue
        for method_name in loader.getTestCaseNames(obj):
            qual = f"{attr_name}.{method_name}"
            if allowed_methods is not None and qual not in allowed_methods:
                continue
            if qual in skip_methods:
                continue
            if pattern and pattern not in qual:
                continue
            suite.addTest(obj(method_name))
            added += 1
    return added


def run_oracle(name, description, build_suite, argv=None, *, require_nonempty=True):
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--bin", dest="binary", default=str(default_binary()),
                    help="Path to the compiled open-fleet binary.")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-k", dest="pattern", default=None,
                    help="Only run tests whose Class.method contains this substring.")
    args = ap.parse_args(argv)

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"{name}: binary not found at {binary}", file=sys.stderr)
        return 2

    suite = unittest.TestSuite()
    selected = build_suite(binary, suite, args)
    if selected is None:
        return 1

    print(f"{name}: running {selected} end-to-end CLI tests against {binary}")
    t0 = time.monotonic()
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    dt = time.monotonic() - t0
    print(f"{name}: {result.testsRun} run, {len(result.failures)} failed, "
          f"{len(result.errors)} errors in {dt:.2f}s")
    if not result.wasSuccessful():
        return 1
    if require_nonempty and selected == 0:
        return 1
    return 0
