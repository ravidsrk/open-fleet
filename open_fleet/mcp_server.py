"""Zero-dependency Model Context Protocol (MCP) JSON-RPC 2.0 stdio server for open-fleet.

Exposes open-fleet's verification kernel, mission catalog, intent router, preflight,
quality-floor guard, diff scope analyzer, certification matrix, and live SQLite state
as typed MCP Tools, Resources, and Prompts so any coding agent can operate open-fleet
natively without ingesting 35K tokens of raw prose or hand-assembling shell flags.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from open_fleet import catalog_version, find_catalog_root
from open_fleet.catalog import (
    build_launch_prompt,
    catalog_overview,
    certification_summary,
    get_mission,
    list_missions,
    load_capabilities,
    load_pins,
    load_quarantine,
    route_intent,
)
from open_fleet.readiness import readiness_report, run_negative_probes
from open_fleet.sessions import (
    advance_session,
    approve_gate,
    benchmark_progressive_savings,
    build_phase_packet,
    list_sessions,
    load_session,
    start_session,
)
from open_fleet.setup import build_mcp_config, doctor
from open_fleet.solo_review import run_solo_review
from open_fleet.state import read_decisions, read_workspace_status

PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_PROTOCOLS = ("2025-03-26", "2024-11-05")


def _run_helper(
    root: Path,
    argv: list[str],
    *,
    cwd: Path | None = None,
    env_extra: dict[str, str] | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    env = dict(os.environ)
    env["OPEN_FLEET_ROOT"] = str(root)
    env.setdefault("OPEN_FLEET_RUNTIME", "auto")
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd or root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return {
            "returncode": proc.returncode,
            "ok": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "ok": False, "stdout": "", "stderr": f"command timed out after {timeout}s"}
    except OSError as exc:
        return {"returncode": 127, "ok": False, "stdout": "", "stderr": str(exc)}


def run_negative_control_demo(root: Path) -> dict[str, Any]:
    """Run the head-to-head negative-control proof demo (self-score GREEN vs verify.py RED)."""
    demo_script = root / "evals" / "demo" / "negative-control" / "run.sh"
    if not demo_script.is_file():
        return {"ok": False, "returncode": 2, "stdout": "", "stderr": f"demo missing: {demo_script}"}
    res = _run_helper(root, ["sh", str(demo_script)], cwd=root, timeout=60)
    out = res["stdout"] + "\n" + res["stderr"]
    return {
        **res,
        "self_score_green": "selfscore: GREEN" in out or "PASS" in out,
        "verifier_caught_gamed_manifest": res["ok"],
    }


def run_inert_first_run(root: Path, *, profile: str = "ro", agent: str = "claude") -> dict[str, Any]:
    """Run the zero-spend inert posix first-run witness and parse its JSON receipt."""
    if profile not in ("ro", "rw"):
        return {"ok": False, "returncode": 2, "error": "profile must be 'ro' or 'rw'"}
    script = root / "runtime" / "scripts" / "first_run.py"
    res = _run_helper(
        root,
        [sys.executable, "-I", str(script), "--profile", profile, "--agent", agent, "--json"],
        cwd=root,
        timeout=90,
    )
    receipt = None
    if res["stdout"].strip():
        try:
            receipt = json.loads(res["stdout"])
        except ValueError:
            receipt = None
    return {**res, "receipt": receipt}


class OpenFleetMCPServer:
    """In-process JSON-RPC 2.0 MCP server handler (usable over stdio or embedded in tests)."""

    def __init__(self, root: Path | None = None, repo: Path | None = None) -> None:
        self.root = (root or find_catalog_root()).resolve()
        self.repo = (repo or self.root).resolve()
        self.version = catalog_version(self.root)

    def tool_definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "fleet_doctor",
                "description": "Diagnose environment readiness: Python, git history, runtime provider (auto/posix/orca), installed harnesses, hooks, quarantine, and exact next actions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "runtime": {"type": "string", "description": "Optional runtime override (auto, posix, orca, etc.)"},
                    },
                },
            },
            {
                "name": "fleet_route_mission",
                "description": "Route a developer goal to the best-matching outcome mission with proof tier, token load, capabilities, and a ready-to-run prompt.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "goal": {"type": "string", "description": "Natural-language description of the engineering outcome"},
                        "top_k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
                    },
                    "required": ["goal"],
                },
            },
            {
                "name": "fleet_list_missions",
                "description": "List open-fleet missions with proof tier, autonomy level, activation token budget, and required capabilities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "proof": {"type": "string", "enum": ["external-run", "self-run", "doctrine-only"]},
                        "category": {"type": "string"},
                    },
                },
            },
            {
                "name": "fleet_get_mission",
                "description": "Fetch a single mission's compact identity contract, composed playbooks, deferred reads, convergence proof, and launch prompt.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string", "description": "Mission name (e.g. review-it, ship-it, clean-sweep)"},
                        "include_body": {"type": "boolean", "default": False},
                    },
                    "required": ["mission"],
                },
            },
            {
                "name": "fleet_preflight",
                "description": "Run fail-closed preflight checks for a mission on a target repository (capability check, quarantine check, non-default BASE guard).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string", "description": "Mission name (e.g. review-it, ship-it)"},
                        "repo": {"type": "string", "description": "Target git repository path (defaults to workspace repo)"},
                        "mode": {"type": "string", "enum": ["readonly", "write"], "default": "readonly"},
                        "base": {"type": "string", "description": "Integration BASE branch (required in write mode)"},
                        "runtime": {"type": "string", "description": "Runtime provider (default: auto)"},
                    },
                    "required": ["mission"],
                },
            },
            {
                "name": "fleet_verify_manifest",
                "description": "Run independent SHA-bound evidence verification (runtime/scripts/verify.py) on a unit manifest.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "manifest": {"type": "string", "description": "Path to the JSON evidence manifest"},
                        "base": {"type": "string", "description": "Integration BASE branch ref"},
                        "repo": {"type": "string", "description": "Target git repository path"},
                        "contract_source": {"type": "string"},
                        "contract_digest": {"type": "string"},
                        "no_gh": {"type": "boolean", "default": False},
                        "allow_static_nc": {"type": "boolean", "default": False},
                    },
                    "required": ["manifest", "base"],
                },
            },
            {
                "name": "fleet_floor_check",
                "description": "Run runtime/scripts/floor_guard.py against a base ref to detect silenced checkers, weakened assertions, unfinished markers, or guard-surface edits.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base": {"type": "string", "default": "origin/main"},
                        "repo": {"type": "string"},
                    },
                },
            },
            {
                "name": "fleet_diff_scope",
                "description": "Run runtime/scripts/diff_scope.py to inspect changed paths and determine which risk review lenses (security, perf, a11y, migration) are triggered.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base": {"type": "string", "description": "Base git ref or commit"},
                        "strict": {"type": "boolean", "default": False},
                        "repo": {"type": "string"},
                    },
                    "required": ["base"],
                },
            },
            {
                "name": "fleet_status",
                "description": "Inspect live operational state: SQLite runs/tasks/dispatches/gates, merge queue entries, recent events, egress ledger, and governance decisions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "db_path": {"type": "string"},
                    },
                },
            },
            {
                "name": "fleet_certification",
                "description": "Inspect the honest provider & harness certification matrix (live-witnessed vs fixture-tested vs source-only vs unsupported).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                    },
                },
            },
            {
                "name": "fleet_decisions",
                "description": "Read recent durable gate decisions (mechanical, taste, one-way) from docs/DECISIONS.md.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
                    },
                },
            },
            {
                "name": "fleet_run_demo",
                "description": "Run either the negative-control proof demo (self-scoring GREEN vs verify.py RED) or a zero-spend inert posix first-run witness.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["negative-control", "first-run", "probes"], "default": "negative-control"},
                        "profile": {"type": "string", "enum": ["ro", "rw"], "default": "ro"},
                    },
                },
            },
            {
                "name": "fleet_session_start",
                "description": "Start a progressive MCP-backed mission state machine (<5K tokens/phase) persisted under .orca/sessions/.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mission": {"type": "string", "description": "Mission name (e.g. ship-it, review-it, clean-sweep)"},
                        "goal": {"type": "string", "description": "Bounded engineering goal"},
                        "base": {"type": "string", "description": "Integration BASE branch (for write missions)"},
                        "runtime": {"type": "string", "default": "auto"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"},
                    },
                    "required": ["mission", "goal"],
                },
            },
            {
                "name": "fleet_session_packet",
                "description": "Fetch the <5K-token progressive context packet for a session's active phase (required playbooks, gate blockers, and token savings).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "fleet_session_approve_gate",
                "description": "Record an explicit human approval for a one-way gate (freeze/promote). Refuses blank or agent/bot actor identities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "gate": {"type": "string", "description": "Gate name (e.g. freeze, promote)"},
                        "actor": {"type": "string", "description": "Human approver identity (name or email)"},
                        "rationale": {"type": "string", "description": "Reason for the human decision"},
                        "contract_digest": {"type": "string", "description": "Optional frozen spec sha256 digest"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"},
                    },
                    "required": ["session_id", "gate", "actor", "rationale"],
                },
            },
            {
                "name": "fleet_session_advance",
                "description": "Advance a progressive mission session by one phase (fail-closed on missing receipts, unapproved one-way gates, or invalid terminal states).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "receipt": {"type": "object", "description": "Optional phase receipt object (e.g. {ok: true, ...})"},
                        "terminal_state": {"type": "string", "description": "Terminal state when closing the final phase"},
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "fleet_session_list",
                "description": "List progressive mission sessions in the workspace plus per-mission <5K token reduction metrics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "sessions_dir": {"type": "string"},
                        "include_benchmark": {"type": "boolean", "default": False},
                    },
                },
            },
            {
                "name": "fleet_solo_review",
                "description": "Run the honest solo-developer verified review lane: diff_scope + floor_guard + lighting eligibility + build-blind review packet + optional verify.py (never spoofs GitHub APPROVE).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "base": {"type": "string", "description": "Base git ref (e.g. origin/main or integration BASE)"},
                        "repo": {"type": "string"},
                        "contract_path": {"type": "string"},
                        "builder_harness": {"type": "string"},
                        "manifest": {"type": "string"},
                        "lighting": {"type": "string", "enum": ["auto", "lit", "dark-eligible"], "default": "auto"},
                        "nc_command": {"type": "string"},
                        "no_gh": {"type": "boolean", "default": True},
                    },
                    "required": ["base"],
                },
            },
            {
                "name": "fleet_readiness",
                "description": "Compute the honest proof-graduation & multi-harness certification backlog, optionally running certification.py check live.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "check_cert": {"type": "boolean", "default": False},
                    },
                },
            },
        ]

    def resource_definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "uri": "open-fleet://catalog/overview",
                "name": "Catalog Overview",
                "description": "Proof ladder rollup, mission count, quarantine state, and upstream pins.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://catalog/missions",
                "name": "Mission Catalog",
                "description": "All discoverable outcome-named missions with six-point identity contracts.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://runtime/capabilities",
                "name": "Runtime Capabilities Matrix",
                "description": "RPI capabilities, providers, harnesses, and per-mission capability requirements.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://runtime/certification",
                "name": "Provider & Harness Certification",
                "description": "Honest per-cell certification tiers backed by bound run evidence.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://runtime/pins",
                "name": "Upstream Pins",
                "description": "Pinned commits and witness dates for Orca and upstream methodology packs.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://runtime/quarantine",
                "name": "Component Quarantine Registry",
                "description": "Human-controlled fail-closed deny-list of quarantined components.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://state/status",
                "name": "Live Workspace Fleet State",
                "description": "Read-only snapshot of SQLite runtime.db, merge queue, events, and decisions.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://governance/decisions",
                "name": "Durable Decision Ledger",
                "description": "Parsed mechanical, taste, and one-way gate decisions from docs/DECISIONS.md.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://sessions/list",
                "name": "Progressive Mission Sessions",
                "description": "Active and completed progressive (<5K-token) mission state machines in the workspace.",
                "mimeType": "application/json",
            },
            {
                "uri": "open-fleet://readiness/report",
                "name": "Proof Graduation & Certification Readiness",
                "description": "Ranked doctrine-only mission graduation backlog and locally actionable harness certification cells.",
                "mimeType": "application/json",
            },
        ]

    def prompt_definitions(self) -> list[dict[str, Any]]:
        prompts: list[dict[str, Any]] = []
        for m in list_missions(self.root):
            prompts.append({
                "name": f"mission/{m['name']}",
                "description": f"[{m['proof']}] {m['summary']}",
                "arguments": [
                    {"name": "goal", "description": "Bounded engineering goal, issue, or PR URL", "required": True},
                ],
            })
        return prompts

    def read_resource(self, uri: str) -> dict[str, Any]:
        if uri == "open-fleet://catalog/overview":
            payload: Any = catalog_overview(self.root)
        elif uri == "open-fleet://catalog/missions":
            payload = list_missions(self.root)
        elif uri.startswith("open-fleet://catalog/mission/"):
            name = uri.split("open-fleet://catalog/mission/", 1)[1].strip()
            mission = get_mission(name, self.root)
            if mission is None:
                raise KeyError(f"unknown mission: {name}")
            payload = mission
        elif uri == "open-fleet://runtime/capabilities":
            payload = load_capabilities(self.root)
        elif uri == "open-fleet://runtime/certification":
            payload = certification_summary(self.root)
        elif uri == "open-fleet://runtime/pins":
            payload = load_pins(self.root)
        elif uri == "open-fleet://runtime/quarantine":
            payload = load_quarantine(self.root)
        elif uri == "open-fleet://state/status":
            payload = read_workspace_status(self.repo)
        elif uri == "open-fleet://governance/decisions":
            payload = read_decisions(self.repo)
        elif uri == "open-fleet://sessions/list":
            payload = {"sessions": list_sessions(repo=self.repo), "benchmark": benchmark_progressive_savings(self.root)}
        elif uri == "open-fleet://readiness/report":
            payload = readiness_report(self.root)
        else:
            raise KeyError(f"unknown resource URI: {uri}")
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(payload, indent=2),
                }
            ]
        }

    def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        mission_name = name.removeprefix("mission/")
        mission = get_mission(mission_name, self.root)
        if mission is None:
            raise KeyError(f"unknown prompt: {name}")
        goal = str((arguments or {}).get("goal") or "").strip()
        text = build_launch_prompt(mission, goal)
        return {
            "description": f"Launch prompt for {mission_name} ({mission['proof']})",
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": text},
                }
            ],
        }

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        args = arguments if isinstance(arguments, dict) else {}
        is_error = False
        result: Any

        if name == "fleet_doctor":
            result = doctor(self.root, runtime=args.get("runtime"))
            result["mcp_config_claude"] = build_mcp_config("claude", self.root)
        elif name == "fleet_route_mission":
            goal = str(args.get("goal") or "").strip()
            if not goal:
                is_error = True
                result = {"error": "goal is required"}
            else:
                top_k = int(args.get("top_k") or 5)
                result = route_intent(goal, self.root, top_k=top_k)
        elif name == "fleet_list_missions":
            result = list_missions(self.root, proof=args.get("proof"), category=args.get("category"))
        elif name == "fleet_get_mission":
            mname = str(args.get("mission") or "").strip()
            found = get_mission(mname, self.root)
            if found is None:
                is_error = True
                result = {"error": f"unknown mission: {mname}"}
            else:
                if not args.get("include_body"):
                    found = {k: v for k, v in found.items() if k != "body"}
                result = found
        elif name == "fleet_preflight":
            mission = str(args.get("mission") or "").strip()
            mode = str(args.get("mode") or "readonly")
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            runtime = str(args.get("runtime") or "auto")
            cmd = [
                sys.executable,
                "-I",
                str(self.root / "runtime" / "scripts" / "preflight.py"),
                "--mission",
                mission,
                "--runtime",
                runtime,
                "--mode",
                mode,
                "--json",
            ]
            if args.get("base"):
                cmd.extend(["--base", str(args["base"])])
            res = _run_helper(self.root, cmd, cwd=repo, timeout=60)
            parsed = None
            try:
                parsed = json.loads(res["stdout"]) if res["stdout"].strip() else None
            except ValueError:
                parsed = None
            result = {**res, "parsed": parsed}
            is_error = not res["ok"]
        elif name == "fleet_verify_manifest":
            manifest = str(args.get("manifest") or "").strip()
            base_ref = str(args.get("base") or "").strip()
            if not manifest or not base_ref:
                is_error = True
                result = {"error": "manifest and base are required"}
            else:
                repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
                cmd = [
                    sys.executable,
                    "-I",
                    str(self.root / "runtime" / "scripts" / "verify.py"),
                    "--manifest",
                    manifest,
                    "--base",
                    base_ref,
                ]
                if args.get("contract_source"):
                    cmd.extend(["--contract-source", str(args["contract_source"])])
                if args.get("contract_digest"):
                    cmd.extend(["--contract-digest", str(args["contract_digest"])])
                if args.get("no_gh"):
                    cmd.append("--no-gh")
                if args.get("allow_static_nc"):
                    cmd.append("--allow-static-nc")
                result = _run_helper(self.root, cmd, cwd=repo, timeout=120)
                is_error = not result["ok"]
        elif name == "fleet_floor_check":
            base_ref = str(args.get("base") or "origin/main")
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            cmd = [
                sys.executable,
                "-I",
                str(self.root / "runtime" / "scripts" / "floor_guard.py"),
                "--base",
                base_ref,
            ]
            result = _run_helper(self.root, cmd, cwd=repo, timeout=60)
            is_error = not result["ok"]
        elif name == "fleet_diff_scope":
            base_ref = str(args.get("base") or "").strip()
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            if not base_ref:
                is_error = True
                result = {"error": "base is required"}
            else:
                cmd = [
                    sys.executable,
                    "-I",
                    str(self.root / "runtime" / "scripts" / "diff_scope.py"),
                    "--repo",
                    str(repo),
                    "--base",
                    base_ref,
                    "--json",
                ]
                if args.get("strict"):
                    cmd.append("--strict")
                res = _run_helper(self.root, cmd, cwd=repo, timeout=60)
                parsed = None
                try:
                    parsed = json.loads(res["stdout"]) if res["stdout"].strip() else None
                except ValueError:
                    parsed = None
                result = {**res, "parsed": parsed}
                is_error = not res["ok"]
        elif name == "fleet_status":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            result = read_workspace_status(repo, db_override=args.get("db_path"))
        elif name == "fleet_certification":
            summary = certification_summary(self.root)
            provider = args.get("provider")
            if provider:
                summary["providers"] = [p for p in summary["providers"] if p["name"] == provider]
            result = summary
        elif name == "fleet_decisions":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            limit = int(args.get("limit") or 30)
            result = read_decisions(repo, limit=limit)
        elif name == "fleet_run_demo":
            kind = str(args.get("kind") or "negative-control")
            if kind == "first-run":
                result = run_inert_first_run(self.root, profile=str(args.get("profile") or "ro"))
            elif kind == "probes":
                result = run_negative_probes(self.root)
            else:
                result = run_negative_control_demo(self.root)
            is_error = not result.get("ok", False)
        elif name == "fleet_session_start":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            sdir = Path(str(args["sessions_dir"])).expanduser().resolve() if args.get("sessions_dir") else None
            try:
                result = start_session(
                    str(args.get("mission") or "").strip(),
                    str(args.get("goal") or "").strip(),
                    root=self.root,
                    repo=repo,
                    sessions_dir=sdir,
                    base_branch=str(args.get("base") or ""),
                    runtime=str(args.get("runtime") or "auto"),
                )
            except (ValueError, OSError) as exc:
                is_error = True
                result = {"error": str(exc)}
        elif name == "fleet_session_packet":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            sdir = Path(str(args["sessions_dir"])).expanduser().resolve() if args.get("sessions_dir") else None
            try:
                state = load_session(str(args.get("session_id") or ""), repo=repo, sessions_dir=sdir)
                result = build_phase_packet(state, self.root)
            except (ValueError, FileNotFoundError, OSError) as exc:
                is_error = True
                result = {"error": str(exc)}
        elif name == "fleet_session_approve_gate":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            sdir = Path(str(args["sessions_dir"])).expanduser().resolve() if args.get("sessions_dir") else None
            try:
                result = approve_gate(
                    str(args.get("session_id") or ""),
                    str(args.get("gate") or ""),
                    str(args.get("actor") or ""),
                    str(args.get("rationale") or ""),
                    contract_digest=str(args.get("contract_digest") or ""),
                    root=self.root,
                    repo=repo,
                    sessions_dir=sdir,
                )
            except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
                is_error = True
                result = {"error": str(exc)}
        elif name == "fleet_session_advance":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            sdir = Path(str(args["sessions_dir"])).expanduser().resolve() if args.get("sessions_dir") else None
            try:
                result = advance_session(
                    str(args.get("session_id") or ""),
                    receipt=args.get("receipt") if isinstance(args.get("receipt"), dict) else None,
                    terminal_state=str(args.get("terminal_state") or ""),
                    root=self.root,
                    repo=repo,
                    sessions_dir=sdir,
                )
            except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
                is_error = True
                result = {"error": str(exc)}
        elif name == "fleet_session_list":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            sdir = Path(str(args["sessions_dir"])).expanduser().resolve() if args.get("sessions_dir") else None
            result = {"sessions": list_sessions(repo=repo, sessions_dir=sdir)}
            if args.get("include_benchmark"):
                result["benchmark"] = benchmark_progressive_savings(self.root)
        elif name == "fleet_solo_review":
            repo = Path(str(args.get("repo") or self.repo)).expanduser().resolve()
            try:
                result = run_solo_review(
                    base=str(args.get("base") or ""),
                    root=self.root,
                    repo=repo,
                    contract_path=str(args.get("contract_path") or ""),
                    builder_harness=str(args.get("builder_harness") or ""),
                    manifest=str(args.get("manifest") or ""),
                    lighting=str(args.get("lighting") or "auto"),
                    nc_command=str(args.get("nc_command") or ""),
                    no_gh=bool(args.get("no_gh", True)),
                )
                is_error = not result["ok"]
            except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
                is_error = True
                result = {"error": str(exc)}
        elif name == "fleet_readiness":
            result = readiness_report(self.root, run_cert_check=bool(args.get("check_cert")))
            if args.get("check_cert") and result.get("certification_check"):
                is_error = not result["certification_check"]["ok"]
        else:
            raise KeyError(f"unknown tool: {name}")

        return {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
            "structuredContent": result if isinstance(result, dict) else {"items": result},
            "isError": is_error,
        }

    def handle_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Process one JSON-RPC 2.0 request or notification; return response dict or None."""
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        # Notifications have no id and expect no response.
        if req_id is None and method in ("notifications/initialized", "notifications/cancelled", "initialized"):
            return None

        def _ok(res: Any) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": req_id, "result": res}

        def _err(code: int, message: str) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

        try:
            if method == "initialize":
                requested_ver = str(params.get("protocolVersion") or PROTOCOL_VERSION)
                chosen = requested_ver if requested_ver in SUPPORTED_PROTOCOLS else PROTOCOL_VERSION
                return _ok({
                    "protocolVersion": chosen,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {"name": "open-fleet", "version": self.version},
                    "instructions": (
                        "open-fleet MCP control plane: route goals to outcome missions with fleet_route_mission, "
                        "run fail-closed preflight and independent SHA-bound verification with fleet_preflight and "
                        "fleet_verify_manifest, and inspect fleet SQLite state with fleet_status."
                    ),
                })
            if method == "ping":
                return _ok({})
            if method == "tools/list":
                return _ok({"tools": self.tool_definitions()})
            if method == "tools/call":
                tool_name = str(params.get("name") or "")
                return _ok(self.call_tool(tool_name, params.get("arguments")))
            if method == "resources/list":
                return _ok({"resources": self.resource_definitions()})
            if method == "resources/read":
                uri = str(params.get("uri") or "")
                return _ok(self.read_resource(uri))
            if method == "prompts/list":
                return _ok({"prompts": self.prompt_definitions()})
            if method == "prompts/get":
                pname = str(params.get("name") or "")
                return _ok(self.get_prompt(pname, params.get("arguments")))
            return _err(-32601, f"Method not found: {method}")
        except KeyError as exc:
            return _err(-32602, str(exc))
        except Exception as exc:
            return _err(-32603, str(exc))


def _read_framed_message(stream: Any) -> tuple[dict[str, Any] | None, str]:
    """Read either newline-delimited JSON-RPC or Content-Length framed JSON-RPC."""
    while True:
        raw_line = stream.readline()
        if not raw_line:
            return None, "jsonl"
        line = raw_line.decode("utf-8", errors="replace").strip() if isinstance(raw_line, bytes) else raw_line.strip()
        if not line:
            continue
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
            # Consume remaining headers until blank line.
            while True:
                hdr = stream.readline()
                if not hdr or hdr.strip() in (b"", ""):
                    break
            body = stream.read(length)
            text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
            return json.loads(text), "lsp"
        return json.loads(line), "jsonl"


def _write_framed_message(stream: Any, payload: dict[str, Any], mode: str) -> None:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if mode == "lsp":
        header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
        stream.write(header + encoded)
    else:
        stream.write(encoded + b"\n")
    stream.flush()


def serve_stdio(server: OpenFleetMCPServer) -> int:
    """Run the MCP server loop over stdin/stdout until EOF."""
    in_stream = sys.stdin.buffer
    out_stream = sys.stdout.buffer
    while True:
        try:
            msg, mode = _read_framed_message(in_stream)
        except ValueError as exc:
            _write_framed_message(
                out_stream,
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"parse error: {exc}"}},
                "jsonl",
            )
            continue
        if msg is None:
            return 0
        resp = server.handle_message(msg)
        if resp is not None:
            _write_framed_message(out_stream, resp, mode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="open-fleet-mcp", description="open-fleet MCP JSON-RPC 2.0 stdio server")
    parser.add_argument("--root", help="open-fleet catalog root directory")
    parser.add_argument("--repo", help="target repository directory (defaults to current working directory)")
    args = parser.parse_args(argv)
    root = Path(args.root).expanduser().resolve() if args.root else find_catalog_root()
    repo = Path(args.repo).expanduser().resolve() if args.repo else Path.cwd().resolve()
    return serve_stdio(OpenFleetMCPServer(root=root, repo=repo))


if __name__ == "__main__":
    sys.exit(main())
