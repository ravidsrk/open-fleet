#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_dispatch_sign.py CLI tests against `open-fleet dispatch-sign`."""
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
    test_path = _O.ROOT / "tests" / "test_dispatch_sign.py"
    allowed = _O.collect_ast_methods(
        test_path,
        skip_classes=("OneSignedFieldRule",),
        predicate=lambda _c, _m, _q, s: not (
            ("mock.patch" in s and "verify_dispatch" not in s)
            or "verify._Transcript" in s
            or "self.check(" in s
        ),
    )
    mod = _O.load_module("test_dispatch_sign_oracle", test_path)
    real_run = subprocess.run
    ds_script = str(_O.ROOT / "runtime" / "scripts" / "dispatch-sign.py")

    def rust_main(argv_list):
        r = real_run(
            [str(binary), "dispatch-sign", *[str(a) for a in argv_list]],
            capture_output=True, text=True, env={**os.environ, "OPEN_FLEET_ROOT": str(_O.ROOT)},
        )
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode

    def rust_verify_dispatch(record_ref=None, *, pubkey_ref=None, key_ref=None,
                             profile=None, parent_profile=None):
        cmd = [str(binary), "dispatch-sign", "verify"]
        for flag, val in (("--record", record_ref), ("--pubkey", pubkey_ref), ("--key", key_ref),
                          ("--profile", profile), ("--parent-profile", parent_profile)):
            if val is not None:
                cmd += [flag, str(val)]
        r = real_run(cmd, capture_output=True, text=True, env={**os.environ, "OPEN_FLEET_ROOT": str(_O.ROOT)})
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode

    mod.dispatch_sign.main = rust_main
    mod.dispatch_sign.verify_dispatch = rust_verify_dispatch
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(
        [str(binary), "dispatch-sign", *cmd[2:]] if (
            isinstance(cmd, (list, tuple)) and len(cmd) >= 2 and str(cmd[1]) == ds_script
        ) else cmd, *a, **kw)
    return _O.add_module_tests(suite, mod, allowed_methods=allowed, pattern=args.pattern)


def main(argv=None):
    return _O.run_oracle("rust_dispatch_sign_oracle", __doc__, _build, argv)


if __name__ == "__main__":
    raise SystemExit(main())
