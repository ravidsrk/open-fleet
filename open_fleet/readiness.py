"""Honest proof-graduation & multi-harness certification readiness workbench.

Never fabricates `metadata.proof` tiers or `live-witnessed` certification entries.
Instead, audits live catalog state, identifies the exact highest-impact graduation
candidates and locally installed un-witnessed harnesses, and executes real zero-spend
certification/negative-probe checks (`certification.py check`, `first_run.py probes`).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from open_fleet import find_catalog_root
from open_fleet.catalog import certification_summary, list_missions, load_retained_runs
from open_fleet.setup import doctor

# Priority order for graduating doctrine-only missions based on developer adoption impact.
GRADUATION_PRIORITY: tuple[str, ...] = (
    "root-cause",
    "deflake-it",
    "floor-it",
    "document-it",
    "modernize-it",
    "map-it",
    "reshape-it",
    "speed-it",
    "migrate-it",
    "oncall-it",
    "access-it",
    "attest-it",
    "absorb-it",
    "oss-contribute",
    "field-test-it",
    "offload-it",
    "pin-it",
)


def _run_py(root: Path, argv: list[str], *, timeout: int = 120) -> dict[str, Any]:
    env = dict(os.environ)
    env["OPEN_FLEET_ROOT"] = str(root)
    try:
        proc = subprocess.run(
            argv,
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "returncode": 124, "stdout": "", "stderr": f"timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "returncode": 127, "stdout": "", "stderr": str(exc)}


def run_certification_check(root: Path | None = None) -> dict[str, Any]:
    """Run runtime/scripts/certification.py check live and return structured freshness/binding result."""
    base = (root or find_catalog_root()).resolve()
    res = _run_py(base, [sys.executable, "-I", str(base / "runtime" / "scripts" / "certification.py"), "check", "--root", str(base)], timeout=90)
    lines = [ln for ln in (res["stdout"] + "\n" + res["stderr"]).splitlines() if ln.strip()]
    failures = [ln for ln in lines if ln.startswith("FAIL:")]
    return {
        **res,
        "fresh": res["ok"] and len(failures) == 0,
        "failure_count": len(failures),
        "failures": failures,
        "summary": lines[-1] if lines else "",
    }


def run_negative_probes(root: Path | None = None) -> dict[str, Any]:
    """Run runtime/scripts/first_run.py probes --json (5 fail-closed pre-launch safety probes, zero spend)."""
    base = (root or find_catalog_root()).resolve()
    res = _run_py(base, [sys.executable, "-I", str(base / "runtime" / "scripts" / "first_run.py"), "probes", "--json"], timeout=120)
    receipt = None
    if res["stdout"].strip():
        try:
            receipt = json.loads(res["stdout"])
        except ValueError:
            receipt = None
    return {
        **res,
        "receipt": receipt,
    }


def readiness_report(
    root: Path | None = None,
    *,
    home: Path | None = None,
    env: dict[str, str] | None = None,
    run_cert_check: bool = False,
) -> dict[str, Any]:
    """Build the honest Proof Graduation & Multi-Harness Certification backlog for this catalog & host."""
    base = (root or find_catalog_root()).resolve()
    missions = list_missions(base)
    cert = certification_summary(base)
    runs = load_retained_runs(base)
    doc = doctor(base, home=home, env=env)

    prio_rank = {name: idx for idx, name in enumerate(GRADUATION_PRIORITY)}
    proven: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    for m in missions:
        if m["proof"] in ("external-run", "self-run"):
            proven.append({
                "mission": m["name"],
                "proof": m["proof"],
                "proof_evidence": m["proof_evidence"],
                "category": m["category"],
            })
        else:
            needs_orca = "cap:orca-self-audit" in (m["capabilities"].get("required") or [])
            runtime_hint = "orca" if needs_orca else "posix"
            mode_hint = "readonly" if m["name"] in ("map-it", "root-cause", "pin-it") else "write"
            candidates.append({
                "mission": m["name"],
                "priority_rank": prio_rank.get(m["name"], 99),
                "category": m["category"],
                "current_proof": m["proof"],
                "target_proof": "self-run",
                "recommended_runtime": runtime_hint,
                "required_capabilities": m["capabilities"].get("required") or [],
                "preflight_cmd": (
                    f"open-fleet preflight -- --mission {m['name']} --runtime {runtime_hint} --mode {mode_hint}"
                    + (" --base <integration-branch>" if mode_hint == "write" else "")
                ),
                "graduation_requirements": [
                    "Retained run report under docs/runs/ with RUN: header (verifier=GREEN)",
                    "Unit evidence manifest in the run directory verified by verify.py",
                    "SHA-256 inventory re-hashed cleanly by runtime/scripts/run_report.py",
                    "Run index row added under docs/runs/index/<run>.json",
                ],
            })
    candidates.sort(key=lambda c: (c["priority_rank"], c["mission"]))

    # Match locally installed harnesses against certification.json harness tiers.
    cert_h_map = {h["name"]: h for h in cert["harnesses"]}
    installed_harnesses = {h["name"]: h for h in doc["harnesses"] if h["installed"]}
    harness_opportunities: list[dict[str, Any]] = []
    for hname, h_cert in sorted(cert_h_map.items()):
        live_count = h_cert["cell_counts"].get("live-witnessed", 0)
        installed_info = installed_harnesses.get(hname)
        harness_opportunities.append({
            "harness": hname,
            "installed_locally": bool(installed_info),
            "binary_path": installed_info["path"] if installed_info else "",
            "certified_version": h_cert["version"],
            "live_witnessed_profiles": live_count,
            "fixture_tested_profiles": h_cert["cell_counts"].get("fixture-tested", 0),
            "needs_live_witness": live_count < 2,
            "inert_probe_cmd": f"python3 runtime/scripts/first_run.py --profile ro --agent {hname} --json",
            "live_container_cmd": f"python3 scripts/live_container.py run --arm first-run --agent {hname}",
        })

    cert_check = run_certification_check(base) if run_cert_check else None
    return {
        "proven_count": len(proven),
        "doctrine_only_count": len(candidates),
        "total_missions": len(missions),
        "binding_runs_count": sum(1 for r in runs if r["binds_yes"]),
        "proven_missions": proven,
        "graduation_backlog": candidates,
        "harness_certification_backlog": harness_opportunities,
        "locally_actionable_harnesses": [
            h["harness"] for h in harness_opportunities if h["installed_locally"] and h["needs_live_witness"]
        ],
        "certification_check": cert_check,
    }
