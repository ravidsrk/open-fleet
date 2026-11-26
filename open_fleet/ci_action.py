"""Drop-in CI PR verification runner (backs .github/actions/open-fleet-verify/action.yml).

Executes floor_guard.py, diff_scope.py, and optional verify.py in one fail-closed pass,
emits GitHub Actions outputs ($GITHUB_OUTPUT) and Step Summary markdown ($GITHUB_STEP_SUMMARY),
and can also run locally via `open-fleet ci-check`.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

if __name__ == "__main__" and str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from open_fleet import find_catalog_root

RISK_LENS_FLAGS = ("SECURITY", "AUTH", "MIGRATIONS", "PERF", "A11Y")


def _run_script(argv: list[str], *, cwd: Path, root: Path, timeout: int = 180) -> dict[str, Any]:
    env = dict(os.environ)
    env["OPEN_FLEET_ROOT"] = str(root)
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
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


def run_ci_verify(
    *,
    base: str,
    root: Path | None = None,
    repo: Path | None = None,
    run_floor_guard: bool = True,
    run_diff_scope: bool = True,
    strict_scope: bool = False,
    fail_on_risk_lenses: bool = False,
    manifest: str = "",
    contract_source: str = "",
    contract_digest: str = "",
    execute_nc: bool = False,
    nc_command: str = "",
    allow_static_nc: bool = False,
    no_gh: bool = False,
    unit_class: str = "",
    lighting: str = "",
    lane: str = "",
    provenance: str = "",
    github_repo: str = "",
) -> dict[str, Any]:
    """Run the composable PR verification checks and return a structured verdict."""
    base_root = (root or find_catalog_root()).resolve()
    target_repo = (repo or Path.cwd()).resolve()
    base_ref = str(base or "").strip()
    if not base_ref:
        raise ValueError("base ref is required")

    floor_result: dict[str, Any] = {"skipped": True, "ok": True, "status": "skipped", "output": ""}
    if run_floor_guard:
        fg = _run_script(
            [sys.executable, "-I", str(base_root / "runtime" / "scripts" / "floor_guard.py"), "--base", base_ref],
            cwd=target_repo,
            root=base_root,
            timeout=90,
        )
        floor_result = {
            "skipped": False,
            "ok": fg["ok"],
            "returncode": fg["returncode"],
            "status": "pass" if fg["ok"] else "fail",
            "output": (fg["stdout"] + "\n" + fg["stderr"]).strip(),
        }

    scope_result: dict[str, Any] = {
        "skipped": True,
        "ok": True,
        "status": "skipped",
        "flags": {},
        "triggered_lenses": [],
        "unmatched": [],
        "error": None,
    }
    if run_diff_scope:
        ds_cmd = [
            sys.executable,
            "-I",
            str(base_root / "runtime" / "scripts" / "diff_scope.py"),
            "--repo",
            str(target_repo),
            "--base",
            base_ref,
            "--json",
        ]
        if strict_scope:
            ds_cmd.append("--strict")
        ds = _run_script(ds_cmd, cwd=target_repo, root=base_root, timeout=90)
        parsed: dict[str, Any] = {}
        if ds["stdout"].strip():
            try:
                loaded = json.loads(ds["stdout"])
                if isinstance(loaded, dict):
                    parsed = loaded
            except ValueError:
                parsed = {}
        flags = parsed.get("flags") if isinstance(parsed.get("flags"), dict) else {}
        lenses = [flag for flag in RISK_LENS_FLAGS if flags.get(flag)]
        scope_ok = ds["ok"] and not parsed.get("error")
        if fail_on_risk_lenses and lenses:
            scope_ok = False
        scope_result = {
            "skipped": False,
            "ok": scope_ok,
            "returncode": ds["returncode"],
            "status": "pass" if scope_ok else "fail",
            "flags": flags,
            "triggered_lenses": lenses,
            "unmatched": parsed.get("unmatched") or [],
            "error": parsed.get("error") or (ds["stderr"].strip() if not ds["ok"] else None),
            "fail_on_risk_lenses_triggered": bool(fail_on_risk_lenses and lenses),
        }

    verify_result: dict[str, Any] = {"skipped": True, "ok": True, "status": "skipped", "output": ""}
    if manifest.strip():
        v_cmd = [
            sys.executable,
            "-I",
            str(base_root / "runtime" / "scripts" / "verify.py"),
            "--manifest",
            manifest.strip(),
            "--base",
            base_ref,
        ]
        if contract_source.strip():
            v_cmd.extend(["--contract-source", contract_source.strip()])
        if contract_digest.strip():
            v_cmd.extend(["--contract-digest", contract_digest.strip()])
        if execute_nc:
            v_cmd.append("--execute-nc")
        if nc_command.strip():
            v_cmd.extend(["--nc-command", nc_command.strip()])
        if allow_static_nc:
            v_cmd.append("--allow-static-nc")
        if no_gh:
            v_cmd.append("--no-gh")
        if unit_class.strip():
            v_cmd.extend(["--unit-class", unit_class.strip()])
        if lighting.strip():
            v_cmd.extend(["--lighting", lighting.strip()])
        if lane.strip():
            v_cmd.extend(["--lane", lane.strip()])
        if provenance.strip():
            v_cmd.extend(["--provenance", provenance.strip()])
        if github_repo.strip():
            v_cmd.extend(["--repo", github_repo.strip()])
        vr = _run_script(v_cmd, cwd=target_repo, root=base_root, timeout=180)
        verify_result = {
            "skipped": False,
            "ok": vr["ok"],
            "returncode": vr["returncode"],
            "status": "pass" if vr["ok"] else "fail",
            "output": (vr["stdout"] + "\n" + vr["stderr"]).strip(),
        }

    overall_ok = bool(floor_result["ok"] and scope_result["ok"] and verify_result["ok"])
    return {
        "ok": overall_ok,
        "base": base_ref,
        "repo": str(target_repo),
        "floor_guard": floor_result,
        "diff_scope": scope_result,
        "verify": verify_result,
        "triggered_lenses": scope_result["triggered_lenses"],
    }


def render_step_summary(result: dict[str, Any]) -> str:
    """Format a GitHub Actions Markdown Step Summary table for the verification run."""
    overall = "PASS" if result["ok"] else "FAIL"
    fg = result["floor_guard"]
    ds = result["diff_scope"]
    vr = result["verify"]
    lenses = ", ".join(result.get("triggered_lenses") or []) or "none"
    lines = [
        f"## open-fleet PR Verification — `{overall}`",
        "",
        f"- **Base ref:** `{result['base']}`",
        f"- **Triggered risk lenses:** `{lenses}`",
        "",
        "| Gate | Status | Detail |",
        "|---|---|---|",
        f"| `floor_guard.py` | `{fg['status'].upper()}` | {(fg.get('output') or 'skipped').splitlines()[0][:120]} |",
        f"| `diff_scope.py` | `{ds['status'].upper()}` | lenses={lenses}"
        + (f" · error={ds['error']}" if ds.get("error") else "")
        + " |",
        f"| `verify.py` | `{vr['status'].upper()}` | {(vr.get('output') or 'skipped (no manifest provided)').splitlines()[0][:120]} |",
        "",
    ]
    if not fg["ok"] and fg.get("output"):
        lines.extend(["### Floor Guard Findings", "```text", fg["output"][:3000], "```", ""])
    if not vr["ok"] and vr.get("output"):
        lines.extend(["### Verifier Output", "```text", vr["output"][:3000], "```", ""])
    return "\n".join(lines)


def render_workflow_snippet(*, base_branch: str = "main", include_manifest: bool = False) -> str:
    """Return a copy-ready GitHub Actions workflow using the reusable open-fleet-verify composite action."""
    manifest_lines = (
        "          manifest: docs/reports/unit-manifest.json\n"
        "          execute-nc: \"true\"\n"
        "          nc-command: \"pytest tests/\"\n"
        if include_manifest
        else "          # Optional: bind an evidence manifest & executed negative control\n"
        "          # manifest: docs/reports/unit-manifest.json\n"
    )
    return (
        "name: open-fleet PR Verification\n"
        "\n"
        "on:\n"
        "  pull_request:\n"
        f"    branches: [{base_branch}]\n"
        "\n"
        "permissions:\n"
        "  contents: read\n"
        "\n"
        "jobs:\n"
        "  open-fleet-verify:\n"
        "    runs-on: ubuntu-latest\n"
        "    timeout-minutes: 15\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        "          persist-credentials: false\n"
        "      - name: Run open-fleet PR verification gate\n"
        "        uses: ./.github/actions/open-fleet-verify\n"
        "        with:\n"
        "          base-ref: origin/${{ github.base_ref }}\n"
        "          run-floor-guard: \"true\"\n"
        "          run-diff-scope: \"true\"\n"
        f"{manifest_lines}"
    )


def _write_github_outputs(result: dict[str, Any]) -> None:
    out_path = (os.environ.get("GITHUB_OUTPUT") or "").strip()
    if out_path:
        lenses = ",".join(result.get("triggered_lenses") or [])
        with Path(out_path).open("a", encoding="utf-8") as fh:
            fh.write(f"overall-ok={'true' if result['ok'] else 'false'}\n")
            fh.write(f"floor-guard-status={result['floor_guard']['status']}\n")
            fh.write(f"diff-scope-status={result['diff_scope']['status']}\n")
            fh.write(f"verify-status={result['verify']['status']}\n")
            fh.write(f"triggered-lenses={lenses}\n")
    summary_path = (os.environ.get("GITHUB_STEP_SUMMARY") or "").strip()
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as fh:
            fh.write(render_step_summary(result) + "\n")


def _parse_bool(val: str | bool) -> bool:
    if isinstance(val, bool):
        return val
    return str(val or "").strip().lower() in ("1", "true", "yes", "on")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="open-fleet ci-check", description="Run open-fleet PR verification gate")
    parser.add_argument("--root", default="", help="open-fleet catalog root")
    parser.add_argument("--repo", default=".", help="target repository path")
    parser.add_argument("--base", default=os.environ.get("OF_BASE_REF", "origin/main"))
    parser.add_argument("--run-floor-guard", default=os.environ.get("OF_RUN_FLOOR_GUARD", "true"))
    parser.add_argument("--run-diff-scope", default=os.environ.get("OF_RUN_DIFF_SCOPE", "true"))
    parser.add_argument("--strict-scope", default=os.environ.get("OF_STRICT_SCOPE", "false"))
    parser.add_argument("--fail-on-risk-lenses", default=os.environ.get("OF_FAIL_ON_RISK_LENSES", "false"))
    parser.add_argument("--manifest", default=os.environ.get("OF_MANIFEST", ""))
    parser.add_argument("--contract-source", default=os.environ.get("OF_CONTRACT_SOURCE", ""))
    parser.add_argument("--contract-digest", default=os.environ.get("OF_CONTRACT_DIGEST", ""))
    parser.add_argument("--execute-nc", default=os.environ.get("OF_EXECUTE_NC", "false"))
    parser.add_argument("--nc-command", default=os.environ.get("OF_NC_COMMAND", ""))
    parser.add_argument("--allow-static-nc", default=os.environ.get("OF_ALLOW_STATIC_NC", "false"))
    parser.add_argument("--no-gh", default=os.environ.get("OF_NO_GH", "false"))
    parser.add_argument("--unit-class", default=os.environ.get("OF_UNIT_CLASS", ""))
    parser.add_argument("--lighting", default=os.environ.get("OF_LIGHTING", ""))
    parser.add_argument("--lane", default=os.environ.get("OF_LANE", ""))
    parser.add_argument("--provenance", default=os.environ.get("OF_PROVENANCE", ""))
    parser.add_argument("--github-repo", default=os.environ.get("OF_GITHUB_REPO", ""))
    parser.add_argument("--json", action="store_true", help="emit structured JSON result")
    args = parser.parse_args(argv)

    root = Path(args.root).expanduser().resolve() if args.root else find_catalog_root()
    repo = Path(args.repo).expanduser().resolve()
    res = run_ci_verify(
        base=args.base,
        root=root,
        repo=repo,
        run_floor_guard=_parse_bool(args.run_floor_guard),
        run_diff_scope=_parse_bool(args.run_diff_scope),
        strict_scope=_parse_bool(args.strict_scope),
        fail_on_risk_lenses=_parse_bool(args.fail_on_risk_lenses),
        manifest=args.manifest,
        contract_source=args.contract_source,
        contract_digest=args.contract_digest,
        execute_nc=_parse_bool(args.execute_nc),
        nc_command=args.nc_command,
        allow_static_nc=_parse_bool(args.allow_static_nc),
        no_gh=_parse_bool(args.no_gh),
        unit_class=args.unit_class,
        lighting=args.lighting,
        lane=args.lane,
        provenance=args.provenance,
        github_repo=args.github_repo,
    )
    _write_github_outputs(res)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(render_step_summary(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
