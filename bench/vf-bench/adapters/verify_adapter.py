#!/usr/bin/env python3
"""verify_adapter.py — open-fleet's own verify.py behind the external adapter contract (#601).

This is the REFERENCE adapter, not an external verifier, and its numbers are never anyone's
product score. It exists to prove the contract carries everything a sound verifier needs: run
through it, verify.py must reach the verdict the bench's built-in sound gate reaches on the same
case (tests/test_vfbench_replay.py pins that). An external verifier's adapter has this shape —
read ONE request on stdin, write ONE JSON object on stdout, exit 0 — and the README's "External
adapter contract" section is the specification.

    python3 bench/vf-bench/replay.py run \\
        --fixture-adapter reference="python3 bench/vf-bench/adapters/verify_adapter.py"

`--verify PATH` points it at another verify.py; by default it runs the one in this checkout.
"""
import sys
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

CONTRACT = "vf-bench-adapter@1"
VERIFY = Path(__file__).resolve().parents[3] / "runtime" / "scripts" / "verify.py"


def verify_argv(request, verify):
    """The coordinator's out-of-band inputs back into verify.py's own flags: a key is its flag
    with dashes, `true` is a bare flag, and an absent key was never supplied."""
    argv = [sys.executable, "-I", str(verify), "--manifest", request["manifest_path"]]
    for key, value in request["coordinator"].items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value not in (None, False):
            argv += [flag, str(value)]
    return argv


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--verify", default=str(VERIFY))
    args = ap.parse_args(argv)
    # verify.py runs from the case's workdir, so a relative --verify is resolved from HERE first;
    # and a verifier that is not there is a crash, never a verdict — python exits 2 for a missing
    # script, which would otherwise read as RED (PR #645 review).
    verify = Path(args.verify).resolve()
    if not verify.is_file():
        print(f"--verify {args.verify}: no such file", file=sys.stderr)
        return 3
    request = json.load(sys.stdin)
    if request.get("contract") != CONTRACT:
        print(f"unsupported contract {request.get('contract')!r}", file=sys.stderr)
        return 3
    r = subprocess.run(verify_argv(request, verify), cwd=request["workdir"],
                       capture_output=True, text=True)
    if r.returncode not in (0, 2):
        # verify.py's 0/2 are verdicts; anything else is a broken run, which the contract
        # reports as a crash (non-zero exit) — never as a RED.
        print((r.stderr or r.stdout).strip()[-400:], file=sys.stderr)
        return 3
    reasons = [ln.strip() for ln in (r.stdout + r.stderr).splitlines() if ln.startswith("FAIL:")]
    version = hashlib.sha256(verify.read_bytes()).hexdigest()[:12]
    print(json.dumps({"contract": CONTRACT, "verdict": "GREEN" if r.returncode == 0 else "RED",
                      "reasons": reasons,
                      "verifier": {"name": "open-fleet verify.py (reference adapter)",
                                   "version": f"sha256:{version}"}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
