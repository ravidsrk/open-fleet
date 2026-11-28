#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_run_report.py CLI & binding tests against `open-fleet run-report`."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
import json
import os
import subprocess
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("_rust_oracle", Path(__file__).resolve().with_name("_rust_oracle.py"))
_O = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_O)

UNIT_ONLY_CLASSES = (
    "ExecutionIdentity",
    "RunDirectoryBinding",
    "WipCurveObligation",
    "SignedKeyFixture",
    "ASelfPinnedKeyNeverChoosesItsJudge",
)


def _rewrite(binary, cmd):
    if isinstance(cmd, (list, tuple)):
        if len(cmd) >= 2 and Path(str(cmd[1])).name == "run_report.py":
            return [str(binary), "run-report", *[str(x) for x in cmd[2:]]]
        if len(cmd) >= 3 and str(cmd[1]) == "-I" and Path(str(cmd[2])).name == "run_report.py":
            return [str(binary), "run-report", *[str(x) for x in cmd[3:]]]
    return cmd


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_run_report.py"
    allowed = _O.collect_ast_methods(
        test_path,
        skip_classes=UNIT_ONLY_CLASSES,
        predicate=lambda _c, _m, _q, s: any(
            k in s for k in ("self._check(", "run_report.check_report(", "run_report.main(", "self.run_report(")
        ),
    )
    mod = _O.load_module("test_run_report_oracle", test_path)
    real_run = subprocess.run

    def rust_check_report(report_path, mission, tier, root=None, base=None):
        use_root = Path(root) if root is not None else _O.ROOT
        cmd = [
            str(binary),
            "run-report",
            str(report_path),
            "--mission",
            str(mission),
            "--tier",
            str(tier),
            "--root",
            str(use_root),
            "--json",
        ]
        if base is not None:
            cmd.append(f"--base={base}")
        r = real_run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode not in (0, 1, 2):
            raise AssertionError(
                f"open-fleet run-report exited {r.returncode}: {r.stdout}\n{r.stderr}"
            )
        try:
            payload = json.loads(r.stdout)
        except ValueError as err:
            raise AssertionError(
                f"open-fleet run-report --json returned non-JSON (exit {r.returncode}): "
                f"{err}\nstdout={r.stdout!r}\nstderr={r.stderr!r}"
            ) from err
        results = payload.get("results") or []
        if results:
            return list(results[0].get("errors") or [])
        if payload.get("refusal"):
            return [f"{report_path}: {payload['refusal']}"]
        return []

    def rust_main(argv_list=None):
        raw = [str(a) for a in (argv_list or [])]
        cmd = [str(binary), "run-report"]
        if not any(a == "--root" or a.startswith("--root=") for a in raw):
            cmd += ["--root", str(_O.ROOT)]
        cmd += raw
        r = real_run(cmd, capture_output=True, text=True, timeout=300)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        return r.returncode

    def rust_sound_lane_run_report(self, *extra, sound=True):
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        if sound:
            env["ORCA_PROVENANCE"] = "ci"
        cmd = [
            str(binary),
            "run-report",
            "--root",
            str(self.repo),
            str(self.path.relative_to(self.repo)),
            "--mission",
            "demo-it",
            "--tier",
            "self-run",
            *[str(x) for x in extra],
        ]
        return real_run(cmd, cwd=str(self.repo), capture_output=True, text=True, env=env, timeout=300)

    mod.run_report.check_report = rust_check_report
    mod.run_report.main = rust_main
    mod.ASoundLaneReadsTheKeyAndPolicyAtATrustedBase.run_report = rust_sound_lane_run_report
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(_rewrite(binary, cmd), *a, **kw)

    return _O.add_module_tests(
        suite,
        mod,
        skip_classes=UNIT_ONLY_CLASSES,
        allowed_methods=allowed,
        pattern=args.pattern,
    )


def main(argv=None):
    saved_run = subprocess.run
    try:
        return _O.run_oracle("rust_run_report_oracle", __doc__, _build, argv)
    finally:
        subprocess.run = saved_run


if __name__ == "__main__":
    raise SystemExit(main())
