#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_diff_scope.py CLI tests against `open-fleet diff-scope`."""
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
    "diff_scope.main(", "diff_scope.scope(", "diff_scope.predict_merge(",
    "diff_scope.resolve_base(", "diff_scope.changed_files(", "diff_scope.classify(",
    "diff_scope._", "diff_scope.GIT", "mock.patch", "wtree.sh",
)


def _rewrite(binary, target, cmd):
    if isinstance(cmd, (list, tuple)):
        if len(cmd) >= 2 and str(cmd[1]) == target:
            return [str(binary), "diff-scope", *cmd[2:]]
        if len(cmd) >= 3 and cmd[1] == "-I" and str(cmd[2]) == target:
            return [str(binary), "diff-scope", *cmd[3:]]
    return cmd


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_diff_scope.py"
    allowed = _O.collect_ast_methods(
        test_path,
        predicate=lambda _c, _m, _q, s: (
            not any(t in s for t in INTERNAL_TOKENS)
            and any(k in s for k in (
                "self.run_scope(", "self.flags(", "self.assert_flag(",
                "self.predict(", "self.scoped(", "subprocess.run", "scope(",
            ))
        ),
    )
    mod = _O.load_module("test_diff_scope_oracle", test_path)
    real_run = subprocess.run
    mod.ScopeBase.run_scope = lambda self, *a: real_run(
        [str(binary), "diff-scope", "--repo", str(self.repo), *a], capture_output=True, text=True)
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(_rewrite(binary, str(mod.SCOPE), cmd), *a, **kw)
    return _O.add_module_tests(
        suite, mod, skip_classes=("ScopeBase",), allowed_methods=allowed, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_diff_scope_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
