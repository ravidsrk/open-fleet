#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_egress.py CLI tests against `open-fleet egress`."""
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

PYTHON_INTERNAL_METHODS = frozenset({
    "TestWrite.test_lock_failure_is_fail_closed_and_leaves_no_successful_receipt",
    "TestWrite.test_permissions_are_private_at_creation_before_any_chmod",
    "TestWrite.test_overlapping_writers_preserve_every_successful_receipt_in_one_chain",
    "TestWrite.test_torn_write_rolls_back_the_partial_line",
    "TestWrite.test_inode_swap_during_write_refuses",
    "TestScriptShape.test_executable_and_shebanged",
})
INTERNAL_TOKENS = (
    "egress.main(", "egress.write_receipt(", "egress.scan(", "egress.load_ledger(",
    "egress.verify_ledger(", "egress.head_digest(", "egress.read_ledger(",
    "egress.default_ledger(", "egress.resolve_ledger(", "egress._", "egress.valid_ts(",
    "egress.require_field(", "egress.record_id(", "egress.canonical_line(",
    "patch(", "patch.object(",
)


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_egress.py"
    allowed = _O.collect_ast_methods(
        test_path,
        predicate=lambda _c, _m, q, s: (
            q not in PYTHON_INTERNAL_METHODS
            and not any(t in s for t in INTERNAL_TOKENS)
            and any(k in s for k in ("run_egress(", "write_one(", "subprocess.run"))
        ),
    )
    mod = _O.load_module("test_egress_oracle", test_path)
    real_run = subprocess.run
    mod.EgressBase.run_egress = lambda self, *a, ledger=None, env=None: real_run(
        [str(binary), "egress", "--ledger", str(ledger or self.ledger), *a],
        capture_output=True, text=True, env=env)
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(
        [str(binary), "egress", *cmd[2:]] if (
            isinstance(cmd, (list, tuple)) and len(cmd) >= 2 and str(cmd[1]) == str(mod.EGRESS)
        ) else cmd, *a, **kw)
    return _O.add_module_tests(
        suite, mod, skip_classes=("EgressBase",), allowed_methods=allowed, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_egress_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
