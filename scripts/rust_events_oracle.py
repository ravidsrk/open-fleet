#!/usr/bin/env python3
"""Adversarial parity oracle: runs tests/test_events.py CLI and derivation tests against `open-fleet events`."""
import sys

if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import importlib.util
import json
import subprocess
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("_rust_oracle", Path(__file__).resolve().with_name("_rust_oracle.py"))
_O = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_O)

PYTHON_ONLY_METHODS = frozenset({
    "TestFixturesReproduce.test_committed_streams_are_the_documented_scenarios",
    "TestFixturesReproduce.test_the_report_names_raw_event_digests_and_exact_revisions",
    "TestOrderAndDuplicates.test_append_skips_an_event_the_record_already_holds",
    "TestIngest.test_re_ingesting_usage_later_is_a_duplicate_not_a_conflict",
    "TestProperties.test_any_order_and_any_re_import_derive_the_same_report",
    "TestProperties.test_reused_dispatch_ids_conserve_launch_attempts_across_waves",
    "TestProperties.test_events_entrypoint_carries_canonical_w301_guard_770",
})


def _rewrite(binary, target, cmd):
    if isinstance(cmd, (list, tuple)):
        if len(cmd) >= 2 and str(cmd[1]) == target:
            return [str(binary), "events", *[str(x) for x in cmd[2:]]]
        if len(cmd) >= 3 and cmd[1] == "-I" and str(cmd[2]) == target:
            return [str(binary), "events", *[str(x) for x in cmd[3:]]]
    return cmd


def _build(binary, suite, args):
    test_path = _O.ROOT / "tests" / "test_events.py"
    allowed = _O.collect_ast_methods(
        test_path,
        skip_classes=("Base",),
        predicate=lambda _c, _m, q, s: (
            q not in PYTHON_ONLY_METHODS
            and "mock.patch" not in s
            and any(
                k in s
                for k in (
                    "self.cli(",
                    "self.emit(",
                    "self.ingest(",
                    "self._ingest_transcript(",
                    "self.derive(",
                    "subprocess.run",
                    "subprocess.Popen",
                    "events.main(",
                )
            )
        ),
    )
    mod = _O.load_module("test_events_oracle", test_path)
    real_run = subprocess.run
    real_popen = subprocess.Popen
    target = str(mod.EVENTS)

    def rust_cli(self, *cli_args, log=None, env=None):
        return real_run(
            [str(binary), "events", "--log", str(log or self.log), *[str(a) for a in cli_args]],
            capture_output=True, text=True, env=env, cwd=str(self.tmp),
        )

    def rust_derive(self, evs, run=None):
        self.write(evs)
        cmd = [str(binary), "events", "--log", str(self.log), "report", "--json"]
        if run is not None:
            cmd += ["--run", str(run)]
        proc = real_run(cmd, capture_output=True, text=True, cwd=str(self.tmp))
        if proc.returncode == 2:
            raise mod.events.UsageError(proc.stderr.strip())
        if proc.returncode == 3:
            raise mod.events.EventsError(proc.stderr.strip())
        if proc.returncode not in (0, 1):
            raise AssertionError(f"unexpected exit {proc.returncode}: {proc.stderr}")
        return json.loads(proc.stdout)

    def rust_main(argv=None):
        proc = real_run(
            [str(binary), "events", *[str(a) for a in (argv or [])]],
            capture_output=True, text=True,
        )
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode

    mod.Base.cli = rust_cli
    mod.Base.derive = rust_derive
    mod.events.main = rust_main
    mod.subprocess.run = lambda cmd, *a, **kw: real_run(_rewrite(binary, target, cmd), *a, **kw)
    mod.subprocess.Popen = lambda cmd, *a, **kw: real_popen(_rewrite(binary, target, cmd), *a, **kw)
    return _O.add_module_tests(
        suite, mod, skip_classes=("Base",), allowed_methods=allowed, pattern=args.pattern
    )


def main(argv=None):
    saved_run, saved_popen = subprocess.run, subprocess.Popen
    try:
        return _O.run_oracle("rust_events_oracle", __doc__, _build, argv)
    finally:
        subprocess.run, subprocess.Popen = saved_run, saved_popen


if __name__ == "__main__":
    raise SystemExit(main())
