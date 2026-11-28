#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_decisions.py CLI tests against `open-fleet decisions`."""
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

INTERNAL_TOKENS = (
    "decisions.main(", "decisions.validate(", "decisions.parse_line(",
    "decisions.standing(", "decisions.active(", "decisions.tally(",
    "decisions.door_hits(", "decisions.fold(", "decisions.grant_pubkey(",
    "decisions.grant_problems(", "decisions.read_lines(", "decisions._",
    "decisions.NEVER_GATE", "mock.patch", "runpy.",
)


def _rewrite(binary, target, cmd):
    if isinstance(cmd, (list, tuple)):
        if len(cmd) >= 2 and str(cmd[1]) == target:
            return [str(binary), "decisions", *cmd[2:]]
        if len(cmd) >= 3 and cmd[1] == "-I" and str(cmd[2]) == target:
            return [str(binary), "decisions", *cmd[3:]]
    return cmd


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_decisions.py"
    allowed = _O.collect_ast_methods(
        test_path,
        skip_classes=("TestScriptShape", "TestNeverGateMatchesThePolicy"),
        predicate=lambda _c, _m, _q, s: (
            not any(t in s for t in INTERNAL_TOKENS)
            and any(k in s for k in ("self.run_dec(", "self.append(", "subprocess.run", "self.run_cli("))
        ),
    )
    mod = _O.load_module("test_decisions_oracle", test_path)
    real_run = subprocess.run
    mod.DecisionsBase.run_dec = lambda self, *a, log=None: real_run(
        [str(binary), "decisions", "--file", str(log or self.log), *a], capture_output=True, text=True)
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(_rewrite(binary, str(mod.DECISIONS), cmd), *a, **kw)
    return _O.add_module_tests(
        suite, mod, skip_classes=("DecisionsBase",), allowed_methods=allowed, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_decisions_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
