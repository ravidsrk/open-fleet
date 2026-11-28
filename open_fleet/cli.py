"""Unified `open-fleet` developer CLI — single entry point over the entire fleet kernel."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from open_fleet import catalog_version, find_catalog_root
from open_fleet.catalog import (
    catalog_overview,
    certification_summary,
    get_mission,
    list_missions,
    route_intent,
)
from open_fleet.ci_action import render_step_summary, render_workflow_snippet, run_ci_verify
from open_fleet.mcp_server import (
    OpenFleetMCPServer,
    run_inert_first_run,
    run_negative_control_demo,
    serve_stdio,
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
from open_fleet.setup import HOST_PROFILES, build_mcp_config, doctor, setup_host
from open_fleet.solo_review import run_solo_review
from open_fleet.state import read_workspace_status
from open_fleet.ui_server import serve_ui


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2))


def _cmd_doctor(args: argparse.Namespace, root: Path) -> int:
    report = doctor(root, runtime=args.runtime)
    if args.json:
        _print_json(report)
        return 1 if report["overall"] == "fail" else 0
    print(f"open-fleet doctor v{report['version']} ({report['platform']})")
    print(f"Catalog: {report['root']}")
    print("")
    for chk in report["checks"]:
        badge = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "info": "INFO"}.get(chk["status"], "INFO")
        print(f"  [{badge}] {chk['id']:20s} {chk['detail']}")
    if report["next_actions"]:
        print("\nNext steps:")
        for step in report["next_actions"]:
            print(f"  $ {step}")
    return 1 if report["overall"] == "fail" else 0


def _cmd_setup(args: argparse.Namespace, root: Path) -> int:
    try:
        res = setup_host(
            args.host,
            root=root,
            skills_dir=Path(args.skills_dir) if args.skills_dir else None,
            runtime=args.runtime,
            wire_hooks=args.wire_hooks,
            wire_mcp=args.wire_mcp,
            force=args.force,
            uninstall=args.uninstall,
            dry_run=args.dry_run,
        )
    except (ValueError, RuntimeError, OSError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"open-fleet setup: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.json:
        _print_json({"ok": True, **res})
        return 0
    prefix = "[dry-run] " if res["dry_run"] else ""
    print(f"{prefix}open-fleet setup ({res['host']} · {res['mode']}): {res['missions_affected']} missions in {res['skills_dir']}")
    for act in res["actions"]:
        print(f"  - {act}")
    for warn in res["warnings"]:
        print(f"  WARN: {warn}")
    if res.get("mcp") and not res["mcp"].get("written") and not args.uninstall:
        print(f"\nMCP config snippet ({res['mcp']['config_path']}):")
        print(res["mcp"]["content"].rstrip())
    return 0


def _cmd_missions(args: argparse.Namespace, root: Path) -> int:
    action = args.missions_action or "list"
    if action == "list":
        items = list_missions(root, proof=args.proof, category=args.category)
        if args.json:
            _print_json(items)
            return 0
        print(f"{'MISSION':16s} {'PROOF':14s} {'LOAD':8s} {'CATEGORY':28s} SUMMARY")
        print("-" * 100)
        for m in items:
            load_str = f"~{m['activation_budget_tokens']:,}" if m["activation_budget_tokens"] else "—"
            summary = m["summary"][:46] + ("…" if len(m["summary"]) > 46 else "")
            print(f"{m['name']:16s} {m['proof']:14s} {load_str:8s} {m['category']:28s} {summary}")
        return 0
    if action == "show":
        found = get_mission(args.name, root)
        if found is None:
            print(f"open-fleet: unknown mission {args.name!r}", file=sys.stderr)
            return 1
        if args.json:
            _print_json(found)
            return 0
        print(f"{found['name']}  [{found['proof']} · {found['autonomy']} · {found['category']}]")
        print(f"Summary:        {found['summary']}")
        print(f"Use when:       {found['use_when']}")
        if found["not_for"]:
            print(f"Not for:        {found['not_for']}")
        print(f"Token budget:   ~{found['activation_budget_tokens']:,}")
        print(f"Capabilities:   required={', '.join(found['capabilities']['required']) or 'none'}")
        print(f"Composes:       {', '.join(found['composes'])}")
        print("\nIdentity contract:")
        for key, val in found["identity"].items():
            print(f"  {key:14s}: {val}")
        print("\nLaunch prompt:")
        print(found["launch_prompt"])
        return 0
    if action == "route":
        goal = " ".join(args.goal).strip()
        routed = route_intent(goal, root, top_k=args.top)
        if args.json:
            _print_json(routed)
            return 0
        if not routed["matches"]:
            print("No matching mission found. Try describing the engineering outcome you want.")
            return 1
        rec = routed["recommended"]
        if rec:
            print(f"Recommended mission: {rec['mission']}  (score={rec['score']:.2f} · proof={rec['proof']})")
            print(f"  {rec['summary']}")
            print("\nCopy-ready launch prompt:")
            print(rec["launch_prompt"])
        else:
            print(f"No mission cleared the evidence floor ({routed['min_evidence']}); closest candidates:")
        print("\nTop candidates:")
        for m in routed["matches"]:
            print(f"  {m['mission']:16s} score={m['score']:6.3f}  [{m['proof']:13s}]  {m['category']}")
        return 0
    return 2


def _cmd_status(args: argparse.Namespace, root: Path) -> int:
    repo = Path(args.repo).expanduser().resolve() if args.repo else Path.cwd().resolve()
    snap = read_workspace_status(repo, db_override=args.db)
    ov = catalog_overview(root)
    payload = {"catalog": ov, "workspace": snap}
    if args.json:
        _print_json(payload)
        return 0
    rs = snap["runtime_state"]
    summary = rs["summary"]
    print(f"open-fleet status v{ov['version']} · repo={snap['repo']}")
    print(f"Catalog proof:   {ov['proof_counts']['external-run']} external-run · {ov['proof_counts']['self-run']} self-run · {ov['proof_counts']['doctrine-only']} doctrine-only")
    print(f"State DB:        {rs['db_path']} ({'present' if rs['db_exists'] else 'not initialized yet'})")
    print(f"Active fleet:    {summary['runs']} runs · {summary['tasks_total']} tasks · {summary['active_dispatches']} active dispatches · {summary['open_gates']} open gates · {summary['queued_merges']} queued merges")
    print(f"Events / Egress: {snap['events']['count']} recent events · {snap['egress']['count']} egress receipts")
    print(f"Decisions log:   {snap['decisions']['total']} recorded decisions ({snap['decisions']['path']})")
    return 0


def _cmd_certify(args: argparse.Namespace, root: Path) -> int:
    summary = certification_summary(root)
    if args.provider:
        summary["providers"] = [p for p in summary["providers"] if p["name"] == args.provider]
    if args.json:
        _print_json(summary)
        return 0
    print(f"Provider & Harness Certification (record v{summary['record_version']}, {summary['recorded']})")
    print(f"{'PROVIDER':14s} {'VERSION':18s} {'LIVE':5s} {'FIXT':5s} {'SRC':5s} {'UNSUP':5s}")
    print("-" * 60)
    for p in summary["providers"]:
        c = p["cell_counts"]
        print(f"{p['name']:14s} {str(p['certified_version'])[:18]:18s} {c['live-witnessed']:5d} {c['fixture-tested']:5d} {c['source-only']:5d} {c['unsupported']:5d}")
    return 0


def _cmd_demo(args: argparse.Namespace, root: Path) -> int:
    nc = run_negative_control_demo(root)
    fr = run_inert_first_run(root, profile=args.profile) if args.include_first_run else None
    out = {"negative_control": nc, "first_run": fr}
    if args.json:
        _print_json(out)
        return 0 if nc["ok"] and (fr is None or fr["ok"]) else 1
    print("=== 1. Negative-Control Proof (Self-Scorer vs Independent Verifier) ===")
    print(nc["stdout"].rstrip())
    if nc["stderr"].strip():
        print(nc["stderr"].rstrip(), file=sys.stderr)
    if fr is not None:
        print("\n=== 2. Standalone POSIX First-Run Witness (zero LLM spend) ===")
        if fr.get("receipt"):
            r = fr["receipt"]
            print(f"verdict={r.get('verdict')} route={r.get('route')} elapsed_s={r.get('elapsed_s')}")
        else:
            print(fr["stdout"].rstrip())
    return 0 if nc["ok"] and (fr is None or fr["ok"]) else 1


def _cmd_session(args: argparse.Namespace, root: Path) -> int:
    action = args.session_action or "list"
    repo = Path(args.repo).expanduser().resolve() if getattr(args, "repo", None) else Path.cwd().resolve()
    sdir = Path(args.sessions_dir).expanduser().resolve() if getattr(args, "sessions_dir", None) else None
    try:
        if action == "benchmark":
            bench = benchmark_progressive_savings(root)
            if args.json:
                _print_json(bench)
                return 0
            print(f"Progressive Phase Budget Benchmark ({bench['mission_count']} missions · ceiling={bench['ceiling_tokens']} tok · avg reduction={bench['avg_reduction_pct']}%)")
            print(f"{'MISSION':16s} {'FULL':8s} {'MAX_PHASE':10s} {'REDUCTION':10s} {'<5K'}")
            print("-" * 58)
            for row in bench["missions"]:
                print(
                    f"{row['mission']:16s} {row['full_budget_tokens']:8d} {row['max_phase_tokens']:10d} "
                    f"{row['reduction_pct']:9.1f}% {'OK' if row['within_5k_ceiling'] else 'OVER'}"
                )
            return 0 if bench["all_within_ceiling"] else 1
        if action == "list":
            items = list_sessions(repo=repo, sessions_dir=sdir)
            if args.json:
                _print_json({"sessions": items})
                return 0
            if not items:
                print("No progressive sessions yet. Start one with: open-fleet session start <mission> \"<goal>\"")
                return 0
            for item in items:
                print(
                    f"{item['session_id']}  [{item['status']:9s}]  mission={item['mission']:14s} "
                    f"phase={item['current_phase']} ({item['current_phase_index'] + 1}/{item['total_phases']})  "
                    f"terminal={item['terminal_state'] or '—'}"
                )
            return 0
        if action == "start":
            res = start_session(
                args.mission,
                " ".join(args.goal).strip(),
                root=root,
                repo=repo,
                sessions_dir=sdir,
                base_branch=args.base or "",
                runtime=args.runtime or "auto",
            )
            if args.json:
                _print_json(res)
                return 0
            pkt = res["packet"]
            tb = pkt["token_budget"]
            print(f"Started session: {pkt['session_id']}  (mission={pkt['mission']} · phase={pkt['phase']['id']})")
            print(f"Token budget:    ~{tb['phase_tokens_est']:,} tokens (vs ~{tb['full_activation_budget_tokens']:,} full load -> {tb['reduction_pct']}% reduction)")
            print(f"Directive:       {pkt['phase']['directive']}")
            return 0
        if action == "packet":
            st = load_session(args.session_id, repo=repo, sessions_dir=sdir)
            pkt = build_phase_packet(st, root)
            if args.json:
                _print_json(pkt)
                return 0
            tb = pkt["token_budget"]
            print(f"Session {pkt['session_id']} · mission={pkt['mission']} · phase={pkt['phase']['id']} ({pkt['phase']['index'] + 1}/{pkt['phase']['total']})")
            print(f"Tokens:   ~{tb['phase_tokens_est']:,} / {tb['phase_ceiling_tokens']:,} ({tb['reduction_pct']}% saved)")
            print(f"Blockers: {'; '.join(pkt['blocking_requirements']) or 'none (ready to advance)'}")
            print(f"Playbooks loaded: {', '.join(d['name'] for d in pkt['phase_playbooks']) or 'none'}")
            return 0
        if action == "approve":
            res = approve_gate(
                args.session_id,
                args.gate,
                args.actor,
                args.rationale,
                contract_digest=args.contract_digest or "",
                root=root,
                repo=repo,
                sessions_dir=sdir,
            )
            if args.json:
                _print_json(res)
                return 0
            print(f"Approved gate '{res['approval']['gate']}' by {res['approval']['actor']} (digest={res['approval']['contract_digest'] or 'n/a'})")
            return 0
        if action == "advance":
            rec = None
            if args.receipt_json:
                rec = json.loads(args.receipt_json)
            elif args.ok:
                rec = {"ok": True}
            res = advance_session(
                args.session_id,
                receipt=rec,
                terminal_state=args.terminal or "",
                root=root,
                repo=repo,
                sessions_dir=sdir,
            )
            if args.json:
                _print_json(res)
                return 0
            if res.get("closed"):
                st = res["session"]
                print(f"Closed session {st['session_id']}: terminal={st['terminal_state']} ({st['terminal_class']})")
            else:
                print(f"Advanced {args.session_id}: {res['from_phase']} -> {res['to_phase']}")
            return 0
    except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
        if getattr(args, "json", False):
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"open-fleet session: FAIL: {exc}", file=sys.stderr)
        return 1
    return 2


def _cmd_solo_review(args: argparse.Namespace, root: Path) -> int:
    repo = Path(args.repo).expanduser().resolve() if args.repo else Path.cwd().resolve()
    try:
        res = run_solo_review(
            base=args.base,
            root=root,
            repo=repo,
            contract_path=args.contract or "",
            builder_harness=args.builder or "",
            manifest=args.manifest or "",
            lighting=args.lighting,
            nc_command=args.nc_command or "",
            no_gh=not args.with_gh,
            transcript_out=args.transcript_out or "",
            transcript_key=args.transcript_key or "",
            packet_out=args.packet_out or "",
        )
    except (ValueError, FileNotFoundError, PermissionError, OSError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"open-fleet solo-review: FAIL: {exc}", file=sys.stderr)
        return 1
    if args.json:
        _print_json(res)
        return 0 if res["ok"] else 1
    print(f"open-fleet solo-review ({res['review_mode']}) · base={res['base']} · head={res['git']['head_sha'][:12]}")
    print(f"Floor guard:  {'CLEAN' if res['floor_guard']['ok'] else 'FAIL'}")
    print(f"Risk lenses:  {', '.join(res['diff_scope']['triggered_risk_lenses']) or 'none'}")
    print(f"Lighting:     {res['lighting']['effective']} — {res['lighting']['reason']}")
    if res["cross_model_reviewers"]:
        print("Local cross-model reviewer options:")
        for sug in res["cross_model_reviewers"][:4]:
            print(f"  - {sug['harness']:12s}: {sug['command']}")
    if res.get("packet_out"):
        print(f"Build-blind review packet written to: {res['packet_out']}")
    return 0 if res["ok"] else 1


def _cmd_ci_check(args: argparse.Namespace, root: Path) -> int:
    if args.workflow_snippet:
        print(render_workflow_snippet(base_branch=args.workflow_base, include_manifest=args.with_manifest_example), end="")
        return 0
    repo = Path(args.repo).expanduser().resolve() if args.repo else Path.cwd().resolve()
    res = run_ci_verify(
        base=args.base,
        root=root,
        repo=repo,
        run_floor_guard=not args.skip_floor,
        run_diff_scope=not args.skip_scope,
        strict_scope=args.strict_scope,
        fail_on_risk_lenses=args.fail_on_risk_lenses,
        manifest=args.manifest or "",
        contract_source=args.contract_source or "",
        contract_digest=args.contract_digest or "",
        execute_nc=args.execute_nc,
        nc_command=args.nc_command or "",
        allow_static_nc=args.allow_static_nc,
        no_gh=args.no_gh,
    )
    if args.json:
        _print_json(res)
    else:
        print(render_step_summary(res))
    return 0 if res["ok"] else 1


def _cmd_readiness(args: argparse.Namespace, root: Path) -> int:
    rep = readiness_report(root, run_cert_check=args.check_cert)
    probes = run_negative_probes(root) if args.probes else None
    payload = {**rep, "negative_probes": probes} if probes is not None else rep
    ok = (
        (rep["certification_check"]["ok"] if rep.get("certification_check") else True)
        and (probes["ok"] if probes is not None else True)
    )
    if args.json:
        _print_json(payload)
        return 0 if ok else 1
    print(f"open-fleet readiness · proven={rep['proven_count']}/{rep['total_missions']} · binding_runs={rep['binding_runs_count']}")
    print("\nTop Proof-Graduation Candidates (doctrine-only -> self-run):")
    for cand in rep["graduation_backlog"][:8]:
        print(f"  {cand['mission']:16s} [{cand['recommended_runtime']:5s}]  {cand['preflight_cmd']}")
    print("\nLocally Actionable Harnesses for Live Certification:")
    if rep["locally_actionable_harnesses"]:
        for h in rep["harness_certification_backlog"]:
            if h["harness"] in rep["locally_actionable_harnesses"]:
                print(f"  {h['harness']:12s} (live={h['live_witnessed_profiles']}/2)  {h['inert_probe_cmd']}")
    else:
        print("  (none installed beyond already-witnessed harnesses)")
    if rep.get("certification_check"):
        cc = rep["certification_check"]
        print(f"\ncertification.py check: {'PASS' if cc['ok'] else 'FAIL'} — {cc['summary']}")
    if probes is not None:
        print(f"first_run.py probes:    {'PASS' if probes['ok'] else 'FAIL'} (exit={probes['returncode']})")
    return 0 if ok else 1


def _passthrough(script: Path, passthrough_args: list[str], root: Path, *, default_auto: bool = False) -> int:
    env = dict(os.environ)
    env["OPEN_FLEET_ROOT"] = str(root)
    if default_auto and not (env.get("OPEN_FLEET_RUNTIME") or env.get("ORCA_FLEET_RUNTIME")):
        env["OPEN_FLEET_RUNTIME"] = "auto"
    proc = subprocess.run([sys.executable, "-I", str(script), *passthrough_args], env=env)
    return proc.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="open-fleet",
        description="Outcome-driven autonomous engineering fleets with independent SHA-bound verification.",
    )
    parser.add_argument("--root", help="open-fleet catalog root directory")
    parser.add_argument("--version", action="store_true", help="print version and exit")

    sub = parser.add_subparsers(dest="command")

    p_doc = sub.add_parser("doctor", help="diagnose environment, runtime, harnesses, hooks, and next steps")
    p_doc.add_argument("--runtime", help="runtime override (auto, posix, orca, ...)")
    p_doc.add_argument("--json", action="store_true", help="emit JSON output")

    p_setup = sub.add_parser("setup", help="link skills, wire completion gate hooks atomically, and configure MCP")
    p_setup.add_argument("--host", choices=sorted(HOST_PROFILES), default="claude", help="target coding-agent host")
    p_setup.add_argument("--skills-dir", help="custom skills target directory")
    p_setup.add_argument("--runtime", default="auto", help="runtime recorded in MCP config (default: auto)")
    p_setup.add_argument("--wire-hooks", action="store_true", help="atomically merge Stop/TaskCompleted hooks into host settings")
    p_setup.add_argument("--wire-mcp", action="store_true", help="register open-fleet MCP server in host config")
    p_setup.add_argument("--force", action="store_true", help="repoint existing symlinks from another clone")
    p_setup.add_argument("--uninstall", action="store_true", help="remove open-fleet symlinks and manual hooks")
    p_setup.add_argument("--dry-run", action="store_true", help="preview changes without modifying disk")
    p_setup.add_argument("--json", action="store_true", help="emit JSON output")

    p_missions = sub.add_parser("missions", help="list, inspect, or route outcome missions")
    m_sub = p_missions.add_subparsers(dest="missions_action")
    p_ml = m_sub.add_parser("list", help="list all missions")
    p_ml.add_argument("--proof", choices=("external-run", "self-run", "doctrine-only"))
    p_ml.add_argument("--category")
    p_ml.add_argument("--json", action="store_true")

    p_ms = m_sub.add_parser("show", help="show a mission's contract and launch prompt")
    p_ms.add_argument("name", help="mission name")
    p_ms.add_argument("--json", action="store_true")

    p_mr = m_sub.add_parser("route", help="recommend a mission for a natural-language goal")
    p_mr.add_argument("goal", nargs="+", help="goal description")
    p_mr.add_argument("--top", type=int, default=5)
    p_mr.add_argument("--json", action="store_true")

    p_route = sub.add_parser("route", help="shortcut for `missions route <goal>`")
    p_route.add_argument("goal", nargs="+", help="goal description")
    p_route.add_argument("--top", type=int, default=5)
    p_route.add_argument("--json", action="store_true")

    p_status = sub.add_parser("status", help="show live fleet runs, tasks, dispatches, gates, merge queue, and decisions")
    p_status.add_argument("--repo", help="target repository path")
    p_status.add_argument("--db", help="explicit runtime.db path")
    p_status.add_argument("--json", action="store_true")

    p_cert = sub.add_parser("certify", help="display honest provider & harness certification matrix")
    p_cert.add_argument("--provider", help="filter to a single provider")
    p_cert.add_argument("--json", action="store_true")

    p_demo = sub.add_parser("demo", help="run the negative-control proof demo (+ optional inert posix first-run)")
    p_demo.add_argument("--include-first-run", action="store_true", help="also run zero-spend inert posix first-run witness")
    p_demo.add_argument("--profile", choices=("ro", "rw"), default="ro")
    p_demo.add_argument("--json", action="store_true")

    p_mcp = sub.add_parser("mcp", help="start the MCP JSON-RPC 2.0 stdio server (or print config snippet)")
    p_mcp.add_argument("--repo", help="target repository path")
    p_mcp.add_argument("--print-config", choices=sorted(HOST_PROFILES), help="print MCP config snippet for a host and exit")
    p_mcp.add_argument("--runtime", default="auto")

    p_ui = sub.add_parser("ui", help="launch the open-fleet Mission Control web dashboard")
    p_ui.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    p_ui.add_argument("--port", type=int, default=8765, help="HTTP port (default: 8765)")
    p_ui.add_argument("--repo", help="target repository path")

    p_sess = sub.add_parser("session", help="progressive (<5K-token/phase) mission state machines with enforced human gates")
    s_sub = p_sess.add_subparsers(dest="session_action")
    p_ss = s_sub.add_parser("start", help="start a progressive mission session")
    p_ss.add_argument("mission", help="mission name")
    p_ss.add_argument("goal", nargs="+", help="bounded engineering goal")
    p_ss.add_argument("--base", default="", help="integration BASE branch")
    p_ss.add_argument("--runtime", default="auto")
    p_ss.add_argument("--repo", help="target repository path")
    p_ss.add_argument("--sessions-dir", help="custom session storage directory")
    p_ss.add_argument("--json", action="store_true")

    p_sl = s_sub.add_parser("list", help="list progressive sessions")
    p_sl.add_argument("--repo", help="target repository path")
    p_sl.add_argument("--sessions-dir", help="custom session storage directory")
    p_sl.add_argument("--json", action="store_true")

    p_sp = s_sub.add_parser("packet", help="show the <5K-token active phase packet")
    p_sp.add_argument("session_id")
    p_sp.add_argument("--repo", help="target repository path")
    p_sp.add_argument("--sessions-dir", help="custom session storage directory")
    p_sp.add_argument("--json", action="store_true")

    p_sa = s_sub.add_parser("approve", help="record explicit human approval for a one-way gate")
    p_sa.add_argument("session_id")
    p_sa.add_argument("--gate", required=True, help="gate name (freeze, promote)")
    p_sa.add_argument("--actor", required=True, help="human approver identity")
    p_sa.add_argument("--rationale", required=True, help="decision rationale")
    p_sa.add_argument("--contract-digest", default="")
    p_sa.add_argument("--repo", help="target repository path")
    p_sa.add_argument("--sessions-dir", help="custom session storage directory")
    p_sa.add_argument("--json", action="store_true")

    p_sv = s_sub.add_parser("advance", help="advance a progressive session by one phase (fail-closed)")
    p_sv.add_argument("session_id")
    p_sv.add_argument("--ok", action="store_true", help="record a passing receipt for the current phase")
    p_sv.add_argument("--receipt-json", default="", help="JSON receipt payload for the current phase")
    p_sv.add_argument("--terminal", default="", help="terminal state when closing the final phase")
    p_sv.add_argument("--repo", help="target repository path")
    p_sv.add_argument("--sessions-dir", help="custom session storage directory")
    p_sv.add_argument("--json", action="store_true")

    p_sb = s_sub.add_parser("benchmark", help="measure <5K-token progressive savings across all missions")
    p_sb.add_argument("--json", action="store_true")

    p_solo = sub.add_parser("solo-review", help="honest solo-developer verified review lane (diff_scope + floor_guard + blind packet + verify.py)")
    p_solo.add_argument("--base", default="origin/main", help="base git ref (default: origin/main)")
    p_solo.add_argument("--repo", help="target repository path")
    p_solo.add_argument("--contract", default="", help="frozen spec/contract file path")
    p_solo.add_argument("--builder", default="", help="builder harness name (to recommend cross-vendor reviewers)")
    p_solo.add_argument("--manifest", default="", help="optional unit manifest to verify via verify.py")
    p_solo.add_argument("--lighting", choices=("auto", "lit", "dark-eligible"), default="auto")
    p_solo.add_argument("--nc-command", default="", help="executed negative-control command for Lane-A dark-eligible verification")
    p_solo.add_argument("--with-gh", action="store_true", help="require GitHub review lookup instead of --no-gh")
    p_solo.add_argument("--transcript-out", default="")
    p_solo.add_argument("--transcript-key", default="")
    p_solo.add_argument("--packet-out", default="", help="write the build-blind reviewer prompt to a file")
    p_solo.add_argument("--json", action="store_true")

    p_ci = sub.add_parser("ci-check", help="run the reusable PR verification gate locally or emit workflow YAML")
    p_ci.add_argument("--base", default="origin/main")
    p_ci.add_argument("--repo", help="target repository path")
    p_ci.add_argument("--skip-floor", action="store_true")
    p_ci.add_argument("--skip-scope", action="store_true")
    p_ci.add_argument("--strict-scope", action="store_true")
    p_ci.add_argument("--fail-on-risk-lenses", action="store_true")
    p_ci.add_argument("--manifest", default="")
    p_ci.add_argument("--contract-source", default="")
    p_ci.add_argument("--contract-digest", default="")
    p_ci.add_argument("--execute-nc", action="store_true")
    p_ci.add_argument("--nc-command", default="")
    p_ci.add_argument("--allow-static-nc", action="store_true")
    p_ci.add_argument("--no-gh", action="store_true")
    p_ci.add_argument("--workflow-snippet", action="store_true", help="print copy-ready GitHub Actions workflow YAML")
    p_ci.add_argument("--workflow-base", default="main")
    p_ci.add_argument("--with-manifest-example", action="store_true")
    p_ci.add_argument("--json", action="store_true")

    p_rdy = sub.add_parser("readiness", help="honest proof-graduation & harness certification workbench")
    p_rdy.add_argument("--check-cert", action="store_true", help="also execute runtime/scripts/certification.py check")
    p_rdy.add_argument("--probes", action="store_true", help="also execute runtime/scripts/first_run.py probes")
    p_rdy.add_argument("--json", action="store_true")

    p_pre = sub.add_parser("preflight", help="pass-through to runtime/scripts/preflight.py (defaults runtime to auto)")
    p_pre.add_argument("extra", nargs=argparse.REMAINDER)

    p_ver = sub.add_parser("verify", help="pass-through to runtime/scripts/verify.py")
    p_ver.add_argument("extra", nargs=argparse.REMAINDER)

    p_fl = sub.add_parser("floor", help="pass-through to runtime/scripts/floor_guard.py")
    p_fl.add_argument("extra", nargs=argparse.REMAINDER)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.root).expanduser().resolve() if args.root else find_catalog_root()

    if args.version:
        print(f"open-fleet {catalog_version(root)}")
        return 0
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "doctor":
        return _cmd_doctor(args, root)
    if args.command == "setup":
        return _cmd_setup(args, root)
    if args.command == "missions":
        return _cmd_missions(args, root)
    if args.command == "route":
        args.missions_action = "route"
        return _cmd_missions(args, root)
    if args.command == "status":
        return _cmd_status(args, root)
    if args.command == "certify":
        return _cmd_certify(args, root)
    if args.command == "demo":
        return _cmd_demo(args, root)
    if args.command == "mcp":
        if args.print_config:
            cfg = build_mcp_config(args.print_config, root, runtime=args.runtime)
            print(cfg["content"].rstrip())
            return 0
        repo = Path(args.repo).expanduser().resolve() if args.repo else Path.cwd().resolve()
        return serve_stdio(OpenFleetMCPServer(root=root, repo=repo))
    if args.command == "ui":
        repo = Path(args.repo).expanduser().resolve() if args.repo else Path.cwd().resolve()
        return serve_ui(root=root, repo=repo, host=args.host, port=args.port)
    if args.command == "session":
        return _cmd_session(args, root)
    if args.command == "solo-review":
        return _cmd_solo_review(args, root)
    if args.command == "ci-check":
        return _cmd_ci_check(args, root)
    if args.command == "readiness":
        return _cmd_readiness(args, root)
    if args.command == "preflight":
        extra = [a for a in args.extra if a != "--"]
        return _passthrough(root / "runtime" / "scripts" / "preflight.py", extra, root, default_auto=True)
    if args.command == "verify":
        extra = [a for a in args.extra if a != "--"]
        return _passthrough(root / "runtime" / "scripts" / "verify.py", extra, root)
    if args.command == "floor":
        extra = [a for a in args.extra if a != "--"]
        return _passthrough(root / "runtime" / "scripts" / "floor_guard.py", extra, root)
    parser.print_help()
    return 2


def _resolve_native_engine(root: Path) -> Path | None:
    """Locate the native Rust `open-fleet` binary unless OPEN_FLEET_ENGINE=python."""
    if os.environ.get("OPEN_FLEET_ENGINE", "").strip().lower() == "python":
        return None
    ext = ".exe" if os.name == "nt" else ""
    explicit = os.environ.get("OPEN_FLEET_BIN", "").strip()
    if explicit:
        cand = Path(explicit).expanduser()
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    local = root / "target" / "release" / f"open-fleet{ext}"
    if local.is_file() and os.access(local, os.X_OK):
        return local
    return None


_NATIVE_DIRECT_VERBS = frozenset({
    "floor",
    "verify",
    "preflight",
    "solo-review",
    "ci-check",
    "readiness",
    "session",
    "status",
    "ui",
    "demo",
    "init",
    "overview",
    "certification",
    "certify",
    "egress",
    "decisions",
    "diff-scope",
    "quarantine",
    "dispatch-sign",
    "inventory",
    "proof-status",
    "chain-check",
    "events",
    "run-report",
    "hook",
    "deny-hook",
})


def _maybe_exec_native(argv: list[str]) -> int | None:
    """Delegate matching CLI invocations directly to the native Rust engine binary."""
    if not argv or argv[0] not in _NATIVE_DIRECT_VERBS:
        return None
    root = find_catalog_root()
    native = _resolve_native_engine(root)
    if native is None:
        return None
    env = dict(os.environ)
    env.setdefault("OPEN_FLEET_ROOT", str(root))
    proc = subprocess.run([str(native), *argv], env=env)
    return proc.returncode


if __name__ == "__main__":
    _native_rc = _maybe_exec_native(sys.argv[1:])
    sys.exit(_native_rc if _native_rc is not None else main())
