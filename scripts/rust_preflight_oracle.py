#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_preflight.py and tests/test_capabilities_preflight.py CLI tests against `open-fleet preflight`."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
import os
import subprocess
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("_rust_oracle", Path(__file__).resolve().with_name("_rust_oracle.py"))
_O = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_O)


def _build(binary, suite, args):
    real_run = subprocess.run

    pf_path = _O.ROOT / "tests" / "test_preflight.py"
    pf_methods = _O.collect_ast_methods(
        pf_path,
        skip_classes=("TestTimeoutSentinel", "TestHungGh"),
        predicate=lambda _c, _m, _q, s: not (
            "preflight._" in s or "mock.patch" in s or "quarantine_check.py unloadable" in s
        ),
    )
    pf_mod = _O.load_module("test_preflight_oracle", pf_path)
    pf_mod.run_preflight = lambda *a, cwd=None, env=None: real_run(
        [str(binary), "preflight", *[str(x) for x in a]],
        capture_output=True, text=True, cwd=cwd, env=env, timeout=60)
    selected = _O.add_module_tests(suite, pf_mod, allowed_methods=pf_methods, pattern=args.pattern)

    cp_path = _O.ROOT / "tests" / "test_capabilities_preflight.py"
    cap_classes = ("TestPreflightCapabilitiesEnforcement", "TestFallbackProbesAndSharedResolver")
    cp_methods = _O.collect_ast_methods(
        cp_path,
        only_classes=cap_classes,
        predicate=lambda _c, _m, _q, s: (
            "run_preflight(" in s and "preflight._" not in s
            and "self._resolve(" not in s and "mock.patch" not in s
        ),
    )
    cp_mod = _O.load_module("test_cap_preflight_oracle", cp_path)

    def rust_cap_run_preflight(*pf_args, cwd=None, env=None):
        run_env = dict(os.environ if env is None else env)
        if env is None:
            run_env.pop("OPEN_FLEET_RUNTIME", None)
            run_env.pop("ORCA_FLEET_RUNTIME", None)
        return real_run(
            [str(binary), "preflight", *[str(x) for x in pf_args]],
            capture_output=True, text=True, cwd=cwd or _O.ROOT, env=run_env, timeout=60)

    cp_mod.run_preflight = rust_cap_run_preflight
    selected += _O.add_module_tests(
        suite, cp_mod, only_classes=cap_classes, allowed_methods=cp_methods, pattern=args.pattern)
    return selected


def main(argv=None):
    return _O.run_oracle("rust_preflight_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
