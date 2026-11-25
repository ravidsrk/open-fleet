"""Progressive MCP-backed mission state machines (<5K tokens per active phase).

Moves deterministic phase sequencing, one-way human gates, evidence checks, and
terminal-state validation into executable code so a coding-agent coordinator loads
only the active phase's compact brief and required playbooks instead of ~25K-35K
tokens of raw prose upfront.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

from open_fleet import find_catalog_root
from open_fleet.catalog import get_mission, list_missions

SCHEMA_VERSION = "open-fleet-session/v1"
PHASE_TOKEN_CEILING = 5000

# Missions that operate purely read-only / diagnostic / planning (no integration BASE write lane).
READONLY_MISSIONS = frozenset({"review-it", "map-it", "root-cause", "pin-it"})

# Missions whose pipeline requires a human one-way FREEZE gate before dispatching write work.
FREEZE_GATE_MISSIONS = frozenset({
    "ship-it", "clean-sweep", "map-it", "harden-it", "prove-it", "deflake-it",
    "speed-it", "modernize-it", "reshape-it", "migrate-it", "oncall-it",
    "document-it", "floor-it", "access-it", "attest-it", "offload-it",
    "field-test-it", "oss-contribute", "absorb-it",
})

# Non-human actor tokens that may never satisfy a one-way human gate.
_DISALLOWED_HUMAN_ACTORS = frozenset({
    "", "agent", "ai", "auto", "bot", "claude", "codex", "coordinator",
    "gemini", "llm", "model", "opencode", "orca", "system", "worker",
})

_TERMINAL_RE = re.compile(r"^- \*\*([A-Z][A-Z0-9-]*)\*\*(\s*\(degraded\b)?", re.M)
_INLINE_TERMINAL_RE = re.compile(r"`([A-Z][A-Z0-9_]+(?:-[A-Z0-9_]+)*)`")

# Mapping from phase id to the playbooks/runtime policies relevant ONLY to that phase.
_PHASE_PLAYBOOK_MAP: dict[str, tuple[str, ...]] = {
    "preflight": ("sandbox-policy", "gate-classification"),
    "freeze": ("decide-and-freeze", "triage-state", "linear-enumeration", "plan-review"),
    "execute": ("decompose-dag", "build-change", "remediate-finding", "dispatch-lifecycle", "attention-budget"),
    "verify": ("acceptance-review", "risk-review", "runtime-prove", "evidence-manifest", "reviewed-sha-freshness"),
    "promote": ("merge-serialization", "release", "publish-evidence", "human-handoff", "mission-chaining"),
}

_PHASE_MCP_TOOLS: dict[str, list[str]] = {
    "preflight": ["fleet_doctor", "fleet_preflight", "fleet_session_advance"],
    "freeze": ["fleet_decisions", "fleet_session_approve_gate", "fleet_session_advance"],
    "execute": ["fleet_status", "fleet_diff_scope", "fleet_floor_check", "fleet_session_advance"],
    "verify": ["fleet_diff_scope", "fleet_floor_check", "fleet_solo_review", "fleet_verify_manifest", "fleet_session_advance"],
    "promote": ["fleet_session_approve_gate", "fleet_verify_manifest", "fleet_session_advance"],
}

_CHAIN_CHECK_CACHE: dict[Path, Any] = {}


def _load_chain_check(root: Path) -> Any:
    resolved = root.resolve()
    cached = _CHAIN_CHECK_CACHE.get(resolved)
    if cached is not None:
        return cached
    path = resolved / "runtime" / "scripts" / "chain_check.py"
    spec = importlib.util.spec_from_file_location("_open_fleet_chain_check", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load chain_check.py from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _CHAIN_CHECK_CACHE[resolved] = mod
    return mod


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _estimate_tokens(obj: Any) -> int:
    raw = json.dumps(obj, ensure_ascii=False) if not isinstance(obj, str) else obj
    return max(1, (len(raw.encode("utf-8")) + 3) // 4)


def default_sessions_dir(repo: Path) -> Path:
    """Resolve default session persistence directory (.orca/sessions inside repo — gitignored)."""
    base = repo.expanduser().resolve()
    if (base / ".git").exists():
        return base / ".orca" / "sessions"
    return Path.home() / ".open-fleet" / "sessions"


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def _validate_session_id(session_id: str) -> str:
    sid = str(session_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}", sid):
        raise ValueError(f"invalid session_id: {session_id!r}")
    return sid


def _declared_terminals(mission_info: dict[str, Any]) -> list[str]:
    body = mission_info.get("body") or ""
    found = [m[0] for m in _TERMINAL_RE.findall(body)]
    if not found:
        # Missions like ship-it list terminals inline in backticks under Terminal states.
        sec_match = re.search(r"(?ms)^##\s+Terminal\b.*?\n(.*?)(?=^##\s+|\Z)", body)
        if sec_match:
            for tok in _INLINE_TERMINAL_RE.findall(sec_match.group(1)):
                if tok not in found and len(tok) >= 2 and tok not in ("BASE", "HEAD", "SHA", "PR", "OPS"):
                    found.append(tok)
    return found


def build_phase_plan(mission_info: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive the deterministic phase state machine for any mission from its SKILL.md metadata."""
    name = mission_info["name"]
    is_readonly = name in READONLY_MISSIONS
    has_freeze_gate = name in FREEZE_GATE_MISSIONS
    composes = set(mission_info.get("composes") or [])
    deferred = set(mission_info.get("deferred_reads") or [])
    all_refs = composes | deferred

    def _pick_refs(phase_id: str) -> list[str]:
        candidates = _PHASE_PLAYBOOK_MAP.get(phase_id, ())
        picked = [r for r in candidates if r in all_refs]
        if not picked and candidates:
            picked = [candidates[0]]
        return picked

    phases: list[dict[str, Any]] = [
        {
            "id": "preflight",
            "title": "Preflight & Capability Gate",
            "mode": "readonly" if is_readonly else "write",
            "requires_human_gate": False,
            "gate_name": None,
            "requires_receipt": "preflight",
            "playbooks": _pick_refs("preflight"),
            "directive": (
                f"Run fail-closed preflight for `{name}` before dispatching any worker. "
                + ("Read-only mission: verify quarantine and capability support."
                   if is_readonly
                   else "Write mission: confirm integration BASE != default branch, clean baseline, and capabilities.")
            ),
        },
        {
            "id": "freeze",
            "title": "Freeze Scope / Pin Fixed Point",
            "mode": "gate" if has_freeze_gate else "readonly",
            "requires_human_gate": has_freeze_gate,
            "gate_name": "freeze" if has_freeze_gate else None,
            "requires_receipt": "freeze_contract",
            "playbooks": _pick_refs("freeze"),
            "directive": (
                "Freeze the T0 acceptance criteria / finding denominator with a SHA-256 digest "
                "and obtain explicit human approval before dispatching build workers."
                if has_freeze_gate
                else "Pin the exact fixed-point commit / PR SHA and confirm a non-empty diff or symptom repro."
            ),
        },
        {
            "id": "execute",
            "title": "Isolated Worker Execution",
            "mode": "readonly" if is_readonly else "write",
            "requires_human_gate": False,
            "gate_name": None,
            "requires_receipt": "execution",
            "playbooks": _pick_refs("execute"),
            "directive": (
                "Dispatch isolated workers (at most ONE upstream methodology router per worker) "
                "under attention-budget WIP limits. Never co-mount two routers in one worker."
            ),
        },
        {
            "id": "verify",
            "title": "Independent Verification & Floor Guard",
            "mode": "verify",
            "requires_human_gate": False,
            "gate_name": None,
            "requires_receipt": "verify",
            "playbooks": _pick_refs("verify"),
            "directive": (
                "Run diff_scope + floor_guard + independent SHA-bound verification (`verify.py`) "
                "outside the worker session. For mutation units, execute the negative control or record RED."
            ),
        },
        {
            "id": "promote",
            "title": "Close / Promotion Gate",
            "mode": "gate",
            "requires_human_gate": not is_readonly,
            "gate_name": None if is_readonly else "promote",
            "requires_receipt": "terminal",
            "playbooks": _pick_refs("promote"),
            "directive": (
                "Record the verified terminal outcome (`GO` / `NO-GO` / `MAPPED` / `PINNED`) bound to the reviewed SHA."
                if is_readonly
                else "Stop at PROMOTION_READY / BUILT with traceability evidence, or obtain an explicit one-way human grant before releasing/deploying."
            ),
        },
    ]
    return phases


def _load_compact_doc_excerpt(root: Path, bare_name: str, *, max_chars: int = 1200) -> dict[str, Any] | None:
    """Load a compact, structured excerpt of one playbook or runtime policy on demand."""
    for folder in ("playbooks", "runtime"):
        candidate = root / folder / f"{bare_name}.md"
        if candidate.is_file():
            raw = candidate.read_text(encoding="utf-8")
            lines = raw.splitlines()
            title = lines[0].lstrip("# ").strip() if lines else bare_name
            # Extract headings + concise leading bullets/text within max_chars.
            excerpt_parts: list[str] = []
            total = 0
            for ln in lines:
                s = ln.rstrip()
                if not s and excerpt_parts and excerpt_parts[-1] == "":
                    continue
                if total + len(s) + 1 > max_chars:
                    excerpt_parts.append("… [truncated; read full file only if needed]")
                    break
                excerpt_parts.append(s)
                total += len(s) + 1
            return {
                "name": bare_name,
                "path": f"{folder}/{bare_name}.md",
                "title": title,
                "excerpt": "\n".join(excerpt_parts).strip(),
            }
    return None


def start_session(
    mission: str,
    goal: str,
    *,
    root: Path | None = None,
    repo: Path | None = None,
    sessions_dir: Path | None = None,
    base_branch: str = "",
    runtime: str = "auto",
    allowed_terminals: list[str] | None = None,
) -> dict[str, Any]:
    """Create and persist a new progressive mission session starting at phase 0 (preflight)."""
    base_root = (root or find_catalog_root()).resolve()
    target_repo = (repo or base_root).resolve()
    mission_info = get_mission(mission, base_root)
    if mission_info is None:
        raise ValueError(f"unknown mission: {mission!r}")
    goal_clean = str(goal or "").strip()
    if not goal_clean:
        raise ValueError("goal must be a non-empty string")

    phases = build_phase_plan(mission_info)
    declared = _declared_terminals(mission_info)
    session_id = f"{mission}-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{secrets.token_hex(3)}"
    sdir = (sessions_dir or default_sessions_dir(target_repo)).resolve()
    now = _utc_now()

    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "mission": mission_info["name"],
        "proof": mission_info["proof"],
        "category": mission_info["category"],
        "goal": goal_clean,
        "repo": str(target_repo),
        "base": base_branch.strip(),
        "runtime": runtime.strip() or "auto",
        "status": "active",
        "current_phase_index": 0,
        "current_phase": phases[0]["id"],
        "terminal_state": None,
        "terminal_class": None,
        "declared_terminals": declared,
        "allowed_terminals": list(allowed_terminals or declared),
        "phases": phases,
        "approvals": {},
        "receipts": {},
        "history": [
            {
                "ts": now,
                "event": "session_started",
                "phase": phases[0]["id"],
                "detail": f"Initialized progressive session for {mission_info['name']}",
            }
        ],
        "created_at": now,
        "updated_at": now,
        "full_activation_budget_tokens": int(mission_info.get("activation_budget_tokens") or 0),
    }
    _atomic_write_json(sdir / f"{session_id}.json", state)
    return {
        "session": state,
        "packet": build_phase_packet(state, base_root),
    }


def load_session(
    session_id: str,
    *,
    repo: Path | None = None,
    sessions_dir: Path | None = None,
) -> dict[str, Any]:
    sid = _validate_session_id(session_id)
    sdir = (sessions_dir or default_sessions_dir(repo or Path.cwd())).resolve()
    path = sdir / f"{sid}.json"
    if not path.is_file():
        raise FileNotFoundError(f"session not found: {sid}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"corrupt or incompatible session file: {path}")
    return data


def list_sessions(
    *,
    repo: Path | None = None,
    sessions_dir: Path | None = None,
) -> list[dict[str, Any]]:
    sdir = (sessions_dir or default_sessions_dir(repo or Path.cwd())).resolve()
    if not sdir.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for path in sorted(sdir.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            continue
        out.append({
            "session_id": data.get("session_id"),
            "mission": data.get("mission"),
            "goal": data.get("goal"),
            "status": data.get("status"),
            "current_phase": data.get("current_phase"),
            "current_phase_index": data.get("current_phase_index"),
            "total_phases": len(data.get("phases") or []),
            "terminal_state": data.get("terminal_state"),
            "terminal_class": data.get("terminal_class"),
            "base": data.get("base"),
            "updated_at": data.get("updated_at"),
            "approvals": sorted((data.get("approvals") or {}).keys()),
        })
    return out


def _blocking_requirements(state: dict[str, Any]) -> list[str]:
    if state.get("status") != "active":
        return []
    phases = state.get("phases") or []
    idx = int(state.get("current_phase_index") or 0)
    if idx < 0 or idx >= len(phases):
        return []
    phase = phases[idx]
    blockers: list[str] = []
    req_receipt = phase.get("requires_receipt")
    receipts = state.get("receipts") or {}
    if req_receipt and req_receipt != "terminal":
        rec = receipts.get(req_receipt)
        if not isinstance(rec, dict) or not rec.get("ok"):
            blockers.append(f"missing passing '{req_receipt}' receipt (supply receipt with ok=true)")
    if phase.get("requires_human_gate"):
        gname = str(phase.get("gate_name") or phase["id"])
        approval = (state.get("approvals") or {}).get(gname)
        if not isinstance(approval, dict) or not approval.get("approved"):
            blockers.append(f"human one-way gate '{gname}' not approved (call approve_gate with human actor + rationale)")
    return blockers


def build_phase_packet(state: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """Build the <5K-token progressive context packet for the session's active phase only."""
    base_root = (root or find_catalog_root()).resolve()
    phases = state.get("phases") or []
    idx = min(max(0, int(state.get("current_phase_index") or 0)), max(0, len(phases) - 1))
    phase = phases[idx] if phases else {"id": "unknown", "title": "Unknown", "playbooks": [], "directive": ""}
    mission_info = get_mission(state["mission"], base_root) or {}

    # Load only the current phase's playbooks, budgeted tightly to guarantee <5K tokens total.
    playbooks_in = list(phase.get("playbooks") or [])
    per_doc_cap = max(550, min(1100, 2600 // max(1, len(playbooks_in))))
    docs: list[dict[str, Any]] = []
    for ref in playbooks_in[:4]:
        loaded = _load_compact_doc_excerpt(base_root, ref, max_chars=per_doc_cap)
        if loaded is not None:
            docs.append(loaded)

    next_phase = phases[idx + 1]["id"] if idx + 1 < len(phases) else "COMPLETE"
    blockers = _blocking_requirements(state)

    packet: dict[str, Any] = {
        "session_id": state["session_id"],
        "mission": state["mission"],
        "proof": state.get("proof"),
        "status": state.get("status"),
        "goal": state.get("goal"),
        "base": state.get("base"),
        "runtime": state.get("runtime"),
        "phase": {
            "id": phase["id"],
            "index": idx,
            "total": len(phases),
            "title": phase.get("title"),
            "mode": phase.get("mode"),
            "requires_human_gate": bool(phase.get("requires_human_gate")),
            "gate_name": phase.get("gate_name"),
            "directive": phase.get("directive"),
            "next_phase": next_phase,
        },
        "identity_contract": mission_info.get("identity") or {},
        "blocking_requirements": blockers,
        "ready_to_advance": len(blockers) == 0 and state.get("status") == "active",
        "mcp_tools_for_phase": _PHASE_MCP_TOOLS.get(phase["id"], ["fleet_status"]),
        "phase_playbooks": docs,
        "approvals": state.get("approvals") or {},
        "receipts_recorded": sorted((state.get("receipts") or {}).keys()),
        "terminal_state": state.get("terminal_state"),
        "terminal_class": state.get("terminal_class"),
    }

    phase_tokens = _estimate_tokens(packet)
    full_budget = int(state.get("full_activation_budget_tokens") or mission_info.get("activation_budget_tokens") or 0)
    saved = max(0, full_budget - phase_tokens) if full_budget else 0
    reduction_pct = round((saved / full_budget) * 100.0, 1) if full_budget > 0 else 0.0
    packet["token_budget"] = {
        "phase_tokens_est": phase_tokens,
        "phase_ceiling_tokens": PHASE_TOKEN_CEILING,
        "within_ceiling": phase_tokens < PHASE_TOKEN_CEILING,
        "full_activation_budget_tokens": full_budget,
        "saved_tokens": saved,
        "reduction_pct": reduction_pct,
    }
    return packet


def approve_gate(
    session_id: str,
    gate: str,
    actor: str,
    rationale: str,
    *,
    contract_digest: str = "",
    root: Path | None = None,
    repo: Path | None = None,
    sessions_dir: Path | None = None,
) -> dict[str, Any]:
    """Record a human approval for a one-way gate (refuses automated/agent actor names)."""
    base_root = (root or find_catalog_root()).resolve()
    target_repo = (repo or base_root).resolve()
    sdir = (sessions_dir or default_sessions_dir(target_repo)).resolve()
    state = load_session(session_id, repo=target_repo, sessions_dir=sdir)

    if state.get("status") != "active":
        raise ValueError(f"session {session_id} is not active (status={state.get('status')})")

    gate_clean = str(gate or "").strip().lower()
    actor_clean = str(actor or "").strip()
    rationale_clean = str(rationale or "").strip()
    if not gate_clean:
        raise ValueError("gate name is required")
    if actor_clean.lower() in _DISALLOWED_HUMAN_ACTORS or len(actor_clean) < 2:
        raise ValueError(
            f"one-way gate {gate_clean!r} requires a real human actor identity "
            f"(refused non-human/blank actor {actor!r}; agents never self-approve one-way gates)"
        )
    if len(rationale_clean) < 4:
        raise ValueError("rationale must be at least 4 characters explaining the human decision")

    valid_gates = {p.get("gate_name") for p in state.get("phases") or [] if p.get("gate_name")}
    if gate_clean not in valid_gates:
        raise ValueError(f"gate {gate_clean!r} is not a one-way gate for mission {state['mission']}; valid={sorted(valid_gates)}")

    now = _utc_now()
    digest_val = contract_digest.strip()
    if gate_clean == "freeze" and not digest_val:
        digest_val = "sha256:" + hashlib.sha256(f"{state['mission']}:{state['goal']}:{rationale_clean}".encode("utf-8")).hexdigest()

    approval_record = {
        "gate": gate_clean,
        "approved": True,
        "actor": actor_clean,
        "rationale": rationale_clean,
        "contract_digest": digest_val,
        "ts": now,
    }
    state.setdefault("approvals", {})[gate_clean] = approval_record
    if gate_clean == "freeze":
        state.setdefault("receipts", {})["freeze_contract"] = {
            "ok": True,
            "contract_digest": digest_val,
            "approved_by": actor_clean,
            "ts": now,
        }
    state.setdefault("history", []).append({
        "ts": now,
        "event": "gate_approved",
        "phase": state["current_phase"],
        "gate": gate_clean,
        "actor": actor_clean,
        "detail": rationale_clean,
    })
    state["updated_at"] = now
    _atomic_write_json(sdir / f"{state['session_id']}.json", state)
    return {
        "session": state,
        "approval": approval_record,
        "packet": build_phase_packet(state, base_root),
    }


def advance_session(
    session_id: str,
    *,
    receipt: dict[str, Any] | None = None,
    terminal_state: str = "",
    root: Path | None = None,
    repo: Path | None = None,
    sessions_dir: Path | None = None,
) -> dict[str, Any]:
    """Advance a session by one phase (fail-closed on missing receipts, unapproved gates, or invalid terminals)."""
    base_root = (root or find_catalog_root()).resolve()
    target_repo = (repo or base_root).resolve()
    sdir = (sessions_dir or default_sessions_dir(target_repo)).resolve()
    state = load_session(session_id, repo=target_repo, sessions_dir=sdir)

    if state.get("status") != "active":
        raise ValueError(f"session {session_id} is already {state.get('status')} (terminal={state.get('terminal_state')})")

    phases = state.get("phases") or []
    idx = int(state.get("current_phase_index") or 0)
    phase = phases[idx]
    now = _utc_now()

    # Record incoming receipt for this phase if supplied.
    req_receipt = phase.get("requires_receipt")
    if receipt is not None:
        if not isinstance(receipt, dict):
            raise ValueError("receipt must be a JSON object")
        key = str(receipt.get("kind") or req_receipt or phase["id"])
        state.setdefault("receipts", {})[key] = {**receipt, "ts": now}

    # Check if this is the final phase (promote/close).
    is_final = idx == len(phases) - 1
    if is_final:
        term = str(terminal_state or (receipt or {}).get("terminal_state") or "").strip()
        if not term:
            raise ValueError("final phase requires terminal_state (e.g. PROMOTION_READY, BUILT, GO, NO-GO, DRY)")
        cc = _load_chain_check(base_root)
        canon = cc.canonical(term)
        t_class = cc.classify(canon)
        if t_class == "unknown":
            raise ValueError(f"unrecognized terminal state {term!r} (rejected fail-closed by chain_check)")

        # Releasing / deploying on a write mission requires explicit promote human gate.
        # Note chain_check.canonical() normalizes underscores to hyphens.
        needs_promote_gate = (
            phase.get("requires_human_gate")
            and canon in {"RELEASED", "DEPLOYED-AND-VERIFIED"}
        )
        if needs_promote_gate:
            approval = (state.get("approvals") or {}).get("promote")
            if not isinstance(approval, dict) or not approval.get("approved"):
                raise PermissionError(
                    f"terminal state {canon} is a one-way release/deploy action and requires human gate 'promote' approval"
                )

        # Verify receipt must be present and ok before claiming any clean non-degraded terminal.
        verify_rec = (state.get("receipts") or {}).get("verify")
        if t_class == "clean" and (not isinstance(verify_rec, dict) or not verify_rec.get("ok")):
            raise PermissionError(
                f"cannot close with clean terminal {canon} without a passing 'verify' receipt"
            )

        state["terminal_state"] = canon
        state["terminal_class"] = t_class
        state["status"] = "completed" if t_class == "clean" else ("handoff" if t_class == "handoff" else "degraded")
        state.setdefault("history", []).append({
            "ts": now,
            "event": "session_closed",
            "phase": phase["id"],
            "terminal_state": canon,
            "terminal_class": t_class,
        })
        state["updated_at"] = now
        _atomic_write_json(sdir / f"{state['session_id']}.json", state)
        return {
            "advanced": True,
            "closed": True,
            "session": state,
            "packet": build_phase_packet(state, base_root),
        }

    # Non-final phase: check fail-closed blockers AFTER storing any newly supplied receipt.
    blockers = _blocking_requirements(state)
    if blockers:
        state["updated_at"] = now
        _atomic_write_json(sdir / f"{state['session_id']}.json", state)
        raise PermissionError(f"cannot advance past phase {phase['id']!r}: " + "; ".join(blockers))

    next_idx = idx + 1
    next_phase = phases[next_idx]
    state["current_phase_index"] = next_idx
    state["current_phase"] = next_phase["id"]
    state.setdefault("history", []).append({
        "ts": now,
        "event": "phase_advanced",
        "from_phase": phase["id"],
        "to_phase": next_phase["id"],
    })
    state["updated_at"] = now
    _atomic_write_json(sdir / f"{state['session_id']}.json", state)
    return {
        "advanced": True,
        "closed": False,
        "from_phase": phase["id"],
        "to_phase": next_phase["id"],
        "session": state,
        "packet": build_phase_packet(state, base_root),
    }


def benchmark_progressive_savings(root: Path | None = None) -> dict[str, Any]:
    """Measure per-phase token budgets vs full upfront activation load across all catalog missions."""
    base_root = (root or find_catalog_root()).resolve()
    rows: list[dict[str, Any]] = []
    for m in list_missions(base_root, include_body=True):
        phases = build_phase_plan(m)
        max_phase_tok = 0
        min_phase_tok = 999999
        for i, ph in enumerate(phases):
            stub = {
                "session_id": f"bench-{m['name']}",
                "mission": m["name"],
                "proof": m["proof"],
                "status": "active",
                "goal": "benchmark progressive phase load",
                "base": "fleet/integration",
                "runtime": "auto",
                "current_phase_index": i,
                "current_phase": ph["id"],
                "phases": phases,
                "approvals": {},
                "receipts": {},
                "full_activation_budget_tokens": m["activation_budget_tokens"],
            }
            pkt = build_phase_packet(stub, base_root)
            tok = pkt["token_budget"]["phase_tokens_est"]
            max_phase_tok = max(max_phase_tok, tok)
            min_phase_tok = min(min_phase_tok, tok)
        full = int(m["activation_budget_tokens"] or 0)
        reduction = round(((full - max_phase_tok) / full) * 100.0, 1) if full > 0 else 0.0
        rows.append({
            "mission": m["name"],
            "full_budget_tokens": full,
            "max_phase_tokens": max_phase_tok,
            "min_phase_tokens": min_phase_tok,
            "within_5k_ceiling": max_phase_tok < PHASE_TOKEN_CEILING,
            "reduction_pct": reduction,
        })
    all_within = all(r["within_ceiling"] if "within_ceiling" in r else r["within_5k_ceiling"] for r in rows)
    avg_reduction = round(sum(r["reduction_pct"] for r in rows) / max(1, len(rows)), 1)
    return {
        "mission_count": len(rows),
        "ceiling_tokens": PHASE_TOKEN_CEILING,
        "all_within_ceiling": all_within,
        "avg_reduction_pct": avg_reduction,
        "missions": rows,
    }
