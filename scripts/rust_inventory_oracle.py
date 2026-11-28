#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_inventory.py CLI tests against `open-fleet inventory`."""
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


def _rewrite(binary, target, cmd):
    if isinstance(cmd, (list, tuple)):
        if len(cmd) >= 2 and str(cmd[1]) == target:
            return [str(binary), "inventory", *cmd[2:]]
        if len(cmd) >= 3 and cmd[1] == "-I" and str(cmd[2]) == target:
            return [str(binary), "inventory", *cmd[3:]]
    return cmd


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_inventory.py"
    allowed = _O.collect_ast_methods(
        test_path,
        skip_classes=("InventoryFenceAndSymlinkHardening",),
        predicate=lambda _c, m, _q, s: (
            "mock.patch" not in s and "test_script_shape" not in m
            and any(k in s for k in ("run_inv(", "subprocess.run", "self._signed_fenced"))
        ),
    )
    mod = _O.load_module("test_inventory_oracle", test_path)
    real_run = subprocess.run
    mod.run_inv = lambda *a: real_run(
        [str(binary), "inventory", *[str(x) for x in a]], capture_output=True, text=True)
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(_rewrite(binary, str(mod.INVENTORY), cmd), *a, **kw)
    return _O.add_module_tests(
        suite, mod,
        skip_classes=("InventoryBase", "InventorySigningFixture"),
        allowed_methods=allowed,
        pattern=args.pattern,
    )


def main(argv=None):
    return _O.run_oracle("rust_inventory_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
