#!/usr/bin/env python3
"""Parity & protocol oracle for the Rust catalog, router, sessions, solo/ci/readiness, and stdio MCP server."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("_rust_oracle", Path(__file__).resolve().with_name("_rust_oracle.py"))
_O = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_O)


def _build(binary, suite, args):
    mod = _O.load_module(
        "rust_product_oracle_suite",
        _O.ROOT / "tests" / "fixtures" / "rust_product_oracle_suite.py",
    )
    mod.BINARY = binary
    return _O.add_module_tests(suite, mod, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_product_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
