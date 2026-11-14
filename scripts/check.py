#!/usr/bin/env python3
"""One local command for the checks a PR must pass (#760).

    python3 scripts/check.py              validate + ruff + shard-partition check + full suite
    python3 scripts/check.py --no-suite   the fast loop: everything but the unittest suite
    python3 scripts/check.py --jobs 4     suite shards to run in parallel (default: CPUs, max 8)
    python3 scripts/check.py --strict     a missing ruff fails instead of being reported SKIPPED
    python3 scripts/check.py --plan       print the commands and exit

The serial suite takes the better part of an hour on a laptop (it builds real git repositories),
so the suite runs as N parallel shards through scripts/shard-tests.py, the same partition CI's
six-job matrix uses. tests/test_shard_tests.py proves that partition covers live discovery test
by test, and this command runs `--check` first so a broken partition fails here too.

Every step runs to the end even when an earlier one fails, so one run reports every red step.
The exit code is 0 only when every step that ran passed. A skipped step (ruff not installed) is
printed as SKIPPED in the summary, never as passed; `--strict` turns it into a failure. This does
not replace CI: the coverage floor, gitleaks, the bundle check and the release gates stay there.
"""
import sys

# W3-01: drop this script's own directory from sys.path before any other import, so a sibling
# named like a stdlib module can never be the module imported here (tests/test_entrypoint_guard.py).
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable or "python3"

# The exact paths CI lints (.github/workflows/validate.yml, the `ruff check` step).
# tests/test_shard_tests.py fails if the two drift apart.
RUFF_PATHS = ("scripts", "runtime/scripts", "tests", "bench", "evals/demo")

TAIL_LINES = 60


def default_jobs():
    return max(1, min(os.cpu_count() or 1, 8))


def plan(jobs, suite=True, ruff=None):
    """[(name, argv | None)] in run order. argv None means the step is SKIPPED (tool missing)."""
    steps = [("validate", [PY, "-I", "scripts/validate.py"])]
    ruff = shutil.which("ruff") if ruff is None else ruff
    steps.append(("ruff", [ruff, "check", *RUFF_PATHS] if ruff else None))
    if suite:
        steps.append(("shard-partition", [PY, "scripts/shard-tests.py", "--check", "--of", str(jobs)]))
        for i in range(1, jobs + 1):
            steps.append((f"suite {i}/{jobs}",
                          [PY, "scripts/shard-tests.py", "--shard", str(i), "--of", str(jobs)]))
    return steps


def run_steps(steps, cwd=ROOT, out=sys.stdout):
    """Run every non-skipped step in parallel. Returns [(name, status, seconds, log_tail)],
    status one of PASS / FAIL / SKIPPED, in the order given."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    started = {}
    with tempfile.TemporaryDirectory(prefix="open-fleet-check-") as logs:
        for idx, (name, argv) in enumerate(steps):
            if argv is None:
                continue
            log = open(Path(logs) / f"{idx}.log", "w+", encoding="utf-8", errors="replace")
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT)
            started[idx] = (proc, log, time.monotonic())
        # Poll, so each step is timed and reported when IT finishes, not when its turn comes.
        done = {}
        pending = dict(started)
        try:
            while pending:
                for idx, (proc, log, t0) in list(pending.items()):
                    rc = proc.poll()
                    if rc is None:
                        continue
                    seconds = time.monotonic() - t0
                    log.seek(0)
                    tail = "".join(log.readlines()[-TAIL_LINES:])
                    log.close()
                    status = "PASS" if rc == 0 else "FAIL"
                    print(f"{status:7} {steps[idx][0]} ({seconds:.0f}s)", file=out, flush=True)
                    done[idx] = (status, seconds, tail)
                    del pending[idx]
                if pending:
                    time.sleep(0.2)
        finally:
            for proc, log, _ in pending.values():  # interrupted: leave no shard running
                proc.kill()
                proc.wait()
                log.close()
        results = []
        for idx, (name, argv) in enumerate(steps):
            if argv is None:
                results.append((name, "SKIPPED", 0.0, ""))
            else:
                results.append((name, *done[idx]))
    return results


def report(results, strict, out=sys.stdout):
    failed = [r for r in results if r[1] == "FAIL"]
    skipped = [r for r in results if r[1] == "SKIPPED"]
    for name, _, _, tail in failed:
        print(f"\n--- {name}: last {TAIL_LINES} lines ---\n{tail.rstrip()}", file=out)
    print("", file=out)
    for name, _, _, _ in skipped:
        print(f"SKIPPED {name}: not installed (CI runs it; --strict makes this a failure)", file=out)
    red = len(failed) + (len(skipped) if strict else 0)
    ran = len(results) - len(skipped)
    verdict = "RED" if red else "GREEN"
    print(f"check: {verdict} — {ran - len(failed)}/{ran} steps passed, {len(skipped)} skipped",
          file=out)
    return 1 if red else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="run the PR checks locally, suite in parallel shards")
    ap.add_argument("--jobs", type=int, default=default_jobs(),
                    help="parallel suite shards (default: CPU count, at most 8)")
    ap.add_argument("--no-suite", action="store_true", help="skip the unittest suite (fast loop)")
    ap.add_argument("--strict", action="store_true", help="a skipped step fails the run")
    ap.add_argument("--plan", action="store_true", help="print the commands and exit")
    args = ap.parse_args(argv)
    if args.jobs < 1:
        ap.error("--jobs must be at least 1")
    steps = plan(args.jobs, suite=not args.no_suite)
    if args.plan:
        for name, cmd in steps:
            print(f"{name}: {' '.join(cmd) if cmd else 'SKIPPED (not installed)'}")
        return 0
    t0 = time.monotonic()
    results = run_steps(steps)
    rc = report(results, args.strict)
    print(f"check: {time.monotonic() - t0:.0f}s wall", flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
