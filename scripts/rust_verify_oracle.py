#!/usr/bin/env python3
"""Adversarial parity oracle: drive open-fleet verify against VF-Bench & test_verify.py."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
import subprocess
from pathlib import Path

_oracle_spec = importlib.util.spec_from_file_location(
    "_rust_oracle", Path(__file__).resolve().parent / "_rust_oracle.py")
_oracle = importlib.util.module_from_spec(_oracle_spec)
_oracle_spec.loader.exec_module(_oracle)

ROOT = _oracle.ROOT
VFBENCH_TEST_PATH = ROOT / "tests" / "test_vfbench.py"
VERIFY_TEST_PATH = ROOT / "tests" / "test_verify.py"
VERIFY_SCRIPT = str((ROOT / "runtime" / "scripts" / "verify.py").resolve())

VFBENCH_CLASSES = [
    "VFBenchSoundness",
    "VFBenchAncestryLeg",
    "VFBenchReviewLeg",
    "TheRefusedControlClassesAreSampled",
]


def _rewrite_cmd(binary, cmd):
    if not isinstance(cmd, (list, tuple)) or len(cmd) < 2:
        return cmd
    for idx in (1, 2):
        if idx < len(cmd):
            arg = str(cmd[idx])
            if arg.endswith("verify.py"):
                try:
                    resolved = str(Path(arg).resolve())
                except OSError:
                    resolved = arg
                if resolved == VERIFY_SCRIPT or arg.endswith("runtime/scripts/verify.py"):
                    return [str(binary), "verify", *[str(x) for x in cmd[idx + 1:]]]
    return cmd


def _build_suite(binary, suite, args):
    orig_run = subprocess.run

    def _rust_run(cmd, *rargs, **rkwargs):
        return orig_run(_rewrite_cmd(binary, cmd), *rargs, **rkwargs)

    subprocess.run = _rust_run

    def _rust_verify_main(argv=None):
        cli_args = [str(a) for a in (argv or [])]
        proc = orig_run(
            [str(binary), "verify", *cli_args],
            capture_output=True,
            text=True,
        )
        if proc.stdout:
            sys.stdout.write(proc.stdout)
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        if "-h" in cli_args or "--help" in cli_args:
            raise SystemExit(proc.returncode)
        return proc.returncode

    added = 0
    vfb_mod = _oracle.load_module("test_vfbench_oracle", VFBENCH_TEST_PATH)
    added += _oracle.add_module_tests(
        suite, vfb_mod, only_classes=VFBENCH_CLASSES, pattern=args.pattern,
    )

    def _is_cli_verify_test(cls, meth, qual, seg):
        if "verify.main(" not in seg:
            return False
        for forbidden in (
            "mock.patch",
            "unittest.mock",
            "verify._Authority",
            "verify._ROOTS",
            "verify._canonical",
            "verify.check_",
            "verify._",
        ):
            if forbidden in seg:
                return False
        return True

    verify_allowed = _oracle.collect_ast_methods(
        VERIFY_TEST_PATH,
        skip_classes=(
            "CrossToolDrift",
            "EndToEndMutationGreen",
            "VerifyW301",
            "VerifyW311",
        ),
        predicate=_is_cli_verify_test,
    )
    ver_mod = _oracle.load_module("test_verify_oracle", VERIFY_TEST_PATH)
    ver_mod.verify.main = _rust_verify_main
    added += _oracle.add_module_tests(
        suite, ver_mod, allowed_methods=verify_allowed, pattern=args.pattern,
    )
    return added


def main(argv=None):
    saved_run = subprocess.run
    try:
        return _oracle.run_oracle(
            "rust_verify_oracle",
            "Run VF-Bench + test_verify.py CLI parity tests against open-fleet verify.",
            _build_suite,
            argv,
        )
    finally:
        subprocess.run = saved_run


if __name__ == "__main__":
    raise SystemExit(main())
