"""Solo-developer verified review lane — honest, build-blind, zero review spoofing.

Honors `playbooks/acceptance-review.md` and `runtime/scripts/verify.py`:
- Never fakes a second GitHub collaborator approval on a solo account.
- Runs `diff_scope.py` and `floor_guard.py` against `base..HEAD`.
- Enforces the irreversibility stop-list: diffs touching AUTH, SECURITY, or MIGRATIONS
  are strictly `lit` (never dark-eligible); safe Lane-A diffs with an unfakeable
  `--nc-command` may use `verify.py --lighting dark-eligible --lane A --execute-nc`.
- Generates a build-blind, anti-anchoring review packet (stripped of builder narration)
  ready for a fresh cross-model CLI reviewer (`codex`, `gemini`, `claude`, `opencode`)
  and optionally runs `verify.py` (with signed Ed25519 transcript support).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from open_fleet import find_catalog_root
from open_fleet.setup import DETECTED_HARNESS_BINS

SCHEMA_VERSION = "open-fleet-solo-review/v1"
LIT_REQUIRED_FLAGS = ("AUTH", "SECURITY", "MIGRATIONS")
RISK_LENS_FLAGS = ("SECURITY", "AUTH", "PERF", "A11Y", "MIGRATIONS")


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _run_proc(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 120) -> dict[str, Any]:
    run_env = dict(os.environ if env is None else env)
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=run_env,
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


def _git_info(repo: Path, base: str) -> dict[str, Any]:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    head = _run_proc(["git", "-C", str(repo), "rev-parse", "HEAD"], cwd=repo, env=env, timeout=20)
    tree = _run_proc(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], cwd=repo, env=env, timeout=20)
    base_res = _run_proc(["git", "-C", str(repo), "rev-parse", f"{base}^{{commit}}"], cwd=repo, env=env, timeout=20)
    files_res = _run_proc(
        ["git", "-C", str(repo), "diff", "--name-only", "--no-renames", f"{base}...HEAD"],
        cwd=repo,
        env=env,
        timeout=30,
    )
    stat_res = _run_proc(
        ["git", "-C", str(repo), "diff", "--stat", f"{base}...HEAD"],
        cwd=repo,
        env=env,
        timeout=30,
    )
    return {
        "head_sha": head["stdout"].strip() if head["ok"] else "",
        "tree_sha": tree["stdout"].strip() if tree["ok"] else "",
        "base_sha": base_res["stdout"].strip() if base_res["ok"] else "",
        "changed_files": [ln.strip() for ln in files_res["stdout"].splitlines() if ln.strip()] if files_res["ok"] else [],
        "diff_stat": stat_res["stdout"].strip() if stat_res["ok"] else "",
    }


def _cross_model_reviewers(builder_harness: str = "") -> list[dict[str, str]]:
    """Suggest locally installed coding-agent CLIs from a different vendor than the builder."""
    builder = builder_harness.strip().lower()
    suggestions: list[dict[str, str]] = []
    for name, binary in DETECTED_HARNESS_BINS:
        if name == builder:
            continue
        path = shutil.which(binary)
        if not path:
            continue
        if name == "codex":
            cmd = "codex exec --sandbox read-only - < solo-review-prompt.md"
        elif name == "claude":
            cmd = "claude -p --permission-mode plan < solo-review-prompt.md"
        elif name == "gemini":
            cmd = "gemini -p \"$(cat solo-review-prompt.md)\""
        elif name == "opencode":
            cmd = "opencode run \"$(cat solo-review-prompt.md)\""
        else:
            cmd = f"{binary} < solo-review-prompt.md"
        suggestions.append({"harness": name, "binary": binary, "path": path, "command": cmd})
    return suggestions


def _build_blind_prompt(
    *,
    base: str,
    git_meta: dict[str, Any],
    criteria_text: str,
    contract_digest: str,
    triggered_lenses: list[str],
    floor_ok: bool,
) -> str:
    lenses_str = ", ".join(triggered_lenses) if triggered_lenses else "none (acceptance axes only)"
    files_str = "\n".join(f"  - {f}" for f in git_meta["changed_files"][:60]) or "  - (working-tree or empty range)"
    criteria_block = criteria_text.strip() or "(No frozen contract file supplied — judge against the repo's tests, contracts, and diff scope.)"
    return (
        "# Build-Blind Solo Acceptance Review Packet\n\n"
        "You are an independent, read-only reviewer in a FRESH session. Do NOT edit files.\n"
        "Builder narration has been deliberately stripped to prevent anchoring.\n\n"
        f"- **Base ref / SHA:** `{base}` (`{git_meta['base_sha'] or 'unknown'}`)\n"
        f"- **Pinned `reviewed_sha`:** `{git_meta['head_sha'] or 'unknown'}` (tree `{git_meta['tree_sha'] or 'unknown'}`)\n"
        f"- **Contract digest:** `{contract_digest or 'none'}`\n"
        f"- **Floor guard status:** `{'CLEAN' if floor_ok else 'VIOLATION — BLOCKING'}`\n"
        f"- **Triggered risk lenses:** {lenses_str}\n\n"
        "## Frozen Acceptance Criteria\n\n"
        f"{criteria_block}\n\n"
        "## Changed Files (`git diff --name-only <base>...HEAD`)\n\n"
        f"{files_str}\n\n"
        "## Mandatory Protocol (`playbooks/acceptance-review.md`)\n\n"
        "1. **Blind-fix first (anti-anchoring):** BEFORE inspecting the diff, write 3–5 bullets stating where you expect the change to live, its shape, and your confidence.\n"
        "2. **Inspect the exact diff:** Run `git diff "
        f"{git_meta['base_sha'] or base}...{git_meta['head_sha'] or 'HEAD'}`.\n"
        "3. **Three isolated axes (no cross-rerank):**\n"
        "   - **Standards:** repo conventions + code smells (skip what linters already enforce).\n"
        "   - **Spec:** every criterion met? Any scope creep or missing edge case?\n"
        "   - **Test-adequacy:** would reverting the production change fail a test?\n"
        "4. **Anti-false-positive gate:** Every Critical/Required finding MUST quote its verbatim motivating code line (`path:line`). Findings without a quoted line go to an appendix.\n"
        "5. **Verdict (under 400 words):** Emit `GO` (0 Critical, 0 Required) or `NO-GO`, bound explicitly to `reviewed_sha="
        f"{git_meta['head_sha'] or 'HEAD'}`.\n"
    )


def run_solo_review(
    *,
    base: str,
    root: Path | None = None,
    repo: Path | None = None,
    contract_path: str = "",
    builder_harness: str = "",
    manifest: str = "",
    lighting: str = "auto",
    nc_command: str = "",
    no_gh: bool = True,
    transcript_out: str = "",
    transcript_key: str = "",
    packet_out: str = "",
) -> dict[str, Any]:
    """Run an honest solo-developer review check: diff_scope + floor_guard + blind packet + optional verify.py."""
    base_root = (root or find_catalog_root()).resolve()
    target_repo = (repo or base_root).resolve()
    base_ref = str(base or "").strip()
    if not base_ref:
        raise ValueError("base ref is required (e.g. origin/main or an integration BASE branch)")

    env = dict(os.environ)
    env["OPEN_FLEET_ROOT"] = str(base_root)

    # 1. Diff scope classification (fail-loud).
    ds_res = _run_proc(
        [sys.executable, "-I", str(base_root / "runtime" / "scripts" / "diff_scope.py"), "--repo", str(target_repo), "--base", base_ref, "--json"],
        cwd=target_repo,
        env=env,
        timeout=60,
    )
    scope_data: dict[str, Any] = {}
    if ds_res["stdout"].strip():
        try:
            parsed = json.loads(ds_res["stdout"])
            if isinstance(parsed, dict):
                scope_data = parsed
        except ValueError:
            scope_data = {}
    flags = scope_data.get("flags") if isinstance(scope_data.get("flags"), dict) else {}
    triggered_lenses = [f for f in RISK_LENS_FLAGS if flags.get(f)]
    lit_triggers = [f for f in LIT_REQUIRED_FLAGS if flags.get(f)]

    # 2. Quality-floor guard.
    fg_res = _run_proc(
        [sys.executable, "-I", str(base_root / "runtime" / "scripts" / "floor_guard.py"), "--base", base_ref],
        cwd=target_repo,
        env=env,
        timeout=60,
    )

    # 3. Git metadata and optional frozen contract digest.
    git_meta = _git_info(target_repo, base_ref)
    criteria_text = ""
    contract_digest = ""
    if contract_path:
        cpath = Path(contract_path).expanduser()
        if not cpath.is_absolute():
            cpath = (target_repo / cpath).resolve()
        if not cpath.is_file():
            raise FileNotFoundError(f"contract file not found: {cpath}")
        raw_bytes = cpath.read_bytes()
        contract_digest = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        criteria_text = raw_bytes.decode("utf-8", errors="replace")

    # 4. Honest lighting eligibility (acceptance-review.md & gate-classification.md).
    # If diff_scope failed (e.g. unresolvable base), fail closed to lit-required.
    scope_ok = ds_res["ok"] and not scope_data.get("error")
    dark_eligible = scope_ok and len(lit_triggers) == 0 and bool(nc_command.strip())
    requested_lighting = (lighting or "auto").strip().lower()
    if requested_lighting not in ("auto", "lit", "dark-eligible"):
        raise ValueError(f"invalid lighting {lighting!r}; choose auto, lit, or dark-eligible")

    if requested_lighting == "dark-eligible" and (not scope_ok or lit_triggers):
        raise PermissionError(
            "cannot use --lighting dark-eligible: "
            + (
                f"diff touches lit-required surfaces ({', '.join(lit_triggers)})"
                if lit_triggers
                else f"diff_scope failed ({scope_data.get('error') or ds_res['stderr'].strip()})"
            )
            + " — independent review cannot be waived"
        )
    if requested_lighting == "dark-eligible" and not nc_command.strip():
        raise ValueError("--lighting dark-eligible requires --nc-command (an unfakeable executed negative control)")

    effective_lighting = (
        "dark-eligible"
        if (requested_lighting == "dark-eligible" or (requested_lighting == "auto" and dark_eligible))
        else "lit"
    )
    if lit_triggers:
        eligibility_reason = (
            f"Diff touches lit-required surface ({', '.join(lit_triggers)}). "
            "Dark-eligible review waiver is forbidden; run a fresh cross-model or human reviewer before merge."
        )
    elif not scope_ok:
        eligibility_reason = "diff_scope did not succeed; failing closed to lit review mode."
    elif nc_command.strip():
        eligibility_reason = (
            "Diff is off the irreversibility stop-list (no AUTH/SECURITY/MIGRATIONS) and carries an "
            "executed negative-control command: eligible for solo Lane-A `--lighting dark-eligible --execute-nc`."
        )
    else:
        eligibility_reason = (
            "Diff is off the irreversibility stop-list, but no `--nc-command` was provided; "
            "provide `--nc-command` for Lane-A executed-control verification or dispatch a fresh cross-model reviewer."
        )

    blind_prompt = _build_blind_prompt(
        base=base_ref,
        git_meta=git_meta,
        criteria_text=criteria_text,
        contract_digest=contract_digest,
        triggered_lenses=triggered_lenses,
        floor_ok=fg_res["ok"],
    )
    if packet_out:
        p_out = Path(packet_out).expanduser()
        p_out.parent.mkdir(parents=True, exist_ok=True)
        p_out.write_text(blind_prompt, encoding="utf-8")

    # 5. Optional independent verify.py invocation (never spoofing GitHub APPROVE).
    verify_result: dict[str, Any] | None = None
    review_mode = "solo-lit-packet-only"
    if manifest:
        cmd = [
            sys.executable,
            "-I",
            str(base_root / "runtime" / "scripts" / "verify.py"),
            "--manifest",
            str(manifest),
            "--base",
            base_ref,
            "--lighting",
            effective_lighting,
        ]
        if effective_lighting == "dark-eligible":
            cmd.extend(["--lane", "A", "--execute-nc", "--nc-command", nc_command.strip()])
            review_mode = "solo-dark-eligible-executed-nc"
        else:
            review_mode = "solo-no-gh-lit" if no_gh else "solo-lit-github-required"
            if nc_command.strip():
                cmd.extend(["--execute-nc", "--nc-command", nc_command.strip()])
        if no_gh:
            cmd.append("--no-gh")
        if contract_path and contract_digest:
            cmd.extend(["--contract-source", contract_path, "--contract-digest", contract_digest])
        if transcript_out:
            cmd.extend(["--transcript-out", transcript_out])
        if transcript_key:
            cmd.extend(["--transcript-key", transcript_key])
        verify_result = _run_proc(cmd, cwd=target_repo, env=env, timeout=180)
    elif effective_lighting == "dark-eligible":
        review_mode = "solo-dark-eligible-ready"

    overall_ok = (
        scope_ok
        and fg_res["ok"]
        and (verify_result["ok"] if verify_result is not None else True)
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "ts": _utc_now(),
        "ok": overall_ok,
        "review_mode": review_mode,
        "base": base_ref,
        "git": git_meta,
        "diff_scope": {
            "ok": scope_ok,
            "error": scope_data.get("error"),
            "flags": flags,
            "unmatched": scope_data.get("unmatched") or [],
            "triggered_risk_lenses": triggered_lenses,
            "lit_required_triggers": lit_triggers,
        },
        "floor_guard": {
            "ok": fg_res["ok"],
            "returncode": fg_res["returncode"],
            "output": (fg_res["stdout"] + "\n" + fg_res["stderr"]).strip(),
        },
        "lighting": {
            "requested": requested_lighting,
            "effective": effective_lighting,
            "dark_eligible": dark_eligible,
            "reason": eligibility_reason,
        },
        "contract_digest": contract_digest,
        "cross_model_reviewers": _cross_model_reviewers(builder_harness),
        "blind_review_packet": blind_prompt,
        "packet_out": packet_out or None,
        "verify": verify_result,
    }
