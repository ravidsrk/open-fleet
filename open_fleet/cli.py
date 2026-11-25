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
from open_fleet.mcp_server import (
    OpenFleetMCPServer,
    run_inert_first_run,
    run_negative_control_demo,
    serve_stdio,
)
from open_fleet.setup import HOST_PROFILES, build_mcp_config, doctor, setup_host
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


if __name__ == "__main__":
    sys.exit(main())
