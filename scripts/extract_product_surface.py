#!/usr/bin/env python3
"""Extract the public open_fleet product surface from live code and verify documentation anchors.

Used by the document-it coverage pipeline and CI:
- Extracts CLI subcommands from open_fleet/cli.py:build_parser()
- Extracts MCP tools & resources from open_fleet/mcp_server.py:OpenFleetMCPServer
- Extracts reusable GitHub Action inputs/outputs from .github/actions/open-fleet-verify/action.yml
- Verifies every extracted entity is documented in docs/cli-and-mcp.md, every anchored
  file:symbol resolves in live code, and docs/cli-and-mcp.md is reachable in one hop
  from README.md and docs/README.md.

Exit codes: 0 all entities documented & anchored · 1 coverage gap or broken anchor · 2 error.
"""
import sys

# W3-01: drop this script's own directory from sys.path before any other import.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import ast
import importlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Canonical symbol anchors verified directly against live source ASTs.
# Renaming any anchored symbol below turns --check RED (document-it rename control).
CORE_SYMBOL_ANCHORS = (
    ("open_fleet/cli.py", "build_parser"),
    ("open_fleet/cli.py", "main"),
    ("open_fleet/mcp_server.py", "OpenFleetMCPServer"),
    ("open_fleet/mcp_server.py", "serve_stdio"),
    ("open_fleet/sessions.py", "start_session"),
    ("open_fleet/sessions.py", "approve_gate"),
    ("open_fleet/sessions.py", "advance_session"),
    ("open_fleet/sessions.py", "benchmark_progressive_savings"),
    ("open_fleet/solo_review.py", "run_solo_review"),
    ("open_fleet/ci_action.py", "run_ci_verify"),
    ("open_fleet/readiness.py", "readiness_report"),
    ("open_fleet/setup.py", "doctor"),
    ("open_fleet/setup.py", "setup_host"),
    ("open_fleet/ui_server.py", "MissionControlApp"),
)


def _load_open_fleet(root):
    """Load open_fleet package from `root` cleanly via importlib (works under python3 -I)."""
    pkg_init = root / "open_fleet" / "__init__.py"
    if not pkg_init.is_file():
        raise FileNotFoundError(f"open_fleet package not found at {pkg_init}")
    # Purge any previously loaded modules if root changed.
    prev = sys.modules.get("open_fleet")
    if prev is None or Path(getattr(prev, "__file__", "")).resolve() != pkg_init.resolve():
        for name in [k for k in list(sys.modules) if k == "open_fleet" or k.startswith("open_fleet.")]:
            del sys.modules[name]
        spec = importlib.util.spec_from_file_location(
            "open_fleet",
            pkg_init,
            submodule_search_locations=[str(root / "open_fleet")],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["open_fleet"] = mod
        spec.loader.exec_module(mod)
    return {
        "cli": importlib.import_module("open_fleet.cli"),
        "mcp": importlib.import_module("open_fleet.mcp_server"),
    }


def _extract_action_io(action_yml):
    """Parse top-level inputs: and outputs: keys from composite action.yml without PyYAML."""
    inputs, outputs = [], []
    section = None
    for line in action_yml.read_text(encoding="utf-8").splitlines():
        if re.match(r"^inputs:\s*$", line):
            section = "inputs"
            continue
        if re.match(r"^outputs:\s*$", line):
            section = "outputs"
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:", line):
            section = None
            continue
        m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", line)
        if m and section == "inputs":
            inputs.append(m.group(1))
        elif m and section == "outputs":
            outputs.append(m.group(1))
    return sorted(inputs), sorted(outputs)


def _defined_symbols(py_path):
    """Top-level def/async def/class names defined in a Python source file."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def extract_surface(root=ROOT):
    """Extract the complete public product surface directly from code."""
    root = Path(root).resolve()
    mods = _load_open_fleet(root)

    parser = mods["cli"].build_parser()
    cli_commands = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            cli_commands = sorted(action.choices.keys())
            break

    srv = mods["mcp"].OpenFleetMCPServer(root=root, repo=root)
    mcp_tools = sorted(t["name"] for t in srv.tool_definitions())
    mcp_resources = sorted(r["uri"] for r in srv.resource_definitions())

    action_path = root / ".github" / "actions" / "open-fleet-verify" / "action.yml"
    action_inputs, action_outputs = _extract_action_io(action_path) if action_path.is_file() else ([], [])

    return {
        "cli_commands": cli_commands,
        "mcp_tools": mcp_tools,
        "mcp_resources": mcp_resources,
        "action_inputs": action_inputs,
        "action_outputs": action_outputs,
        "core_anchors": [{"file": f, "symbol": s} for f, s in CORE_SYMBOL_ANCHORS],
    }


def check_coverage(root=ROOT):
    """Verify every extracted entity is documented, every anchor resolves, and docs are reachable."""
    root = Path(root).resolve()
    surface = extract_surface(root)
    doc_path = root / "docs" / "cli-and-mcp.md"
    readme_path = root / "README.md"
    hub_path = root / "docs" / "README.md"

    errors = []
    if not doc_path.is_file():
        return {"ok": False, "surface": surface, "errors": [f"missing {doc_path}"]}

    doc_text = doc_path.read_text(encoding="utf-8")
    doc_lines = doc_text.splitlines()

    def _find_line(needle):
        for idx, ln in enumerate(doc_lines, 1):
            if needle in ln:
                return idx
        return None

    coverage = {"cli_commands": {}, "mcp_tools": {}, "mcp_resources": {}, "action_outputs": {}}
    for cmd in surface["cli_commands"]:
        ln = _find_line(f"open-fleet {cmd}")
        coverage["cli_commands"][cmd] = f"docs/cli-and-mcp.md:{ln}" if ln else None
        if ln is None:
            errors.append(f"undocumented CLI command: open-fleet {cmd}")

    for tool in surface["mcp_tools"]:
        ln = _find_line(f"`{tool}`")
        coverage["mcp_tools"][tool] = f"docs/cli-and-mcp.md:{ln}" if ln else None
        if ln is None:
            errors.append(f"undocumented MCP tool: {tool}")

    for uri in surface["mcp_resources"]:
        ln = _find_line(f"`{uri}`")
        coverage["mcp_resources"][uri] = f"docs/cli-and-mcp.md:{ln}" if ln else None
        if ln is None:
            errors.append(f"undocumented MCP resource: {uri}")

    for out_key in surface["action_outputs"]:
        ln = _find_line(f"`{out_key}`")
        coverage["action_outputs"][out_key] = f"docs/cli-and-mcp.md:{ln}" if ln else None
        if ln is None:
            errors.append(f"undocumented GitHub Action output: {out_key}")

    # Verify every core file:symbol anchor resolves in live AST (rename-to-RED oracle).
    anchor_results = []
    for rel_file, symbol in CORE_SYMBOL_ANCHORS:
        fpath = root / rel_file
        if not fpath.is_file():
            errors.append(f"broken anchor file: {rel_file}:{symbol}")
            anchor_results.append({"anchor": f"{rel_file}:{symbol}", "ok": False})
            continue
        syms = _defined_symbols(fpath)
        ok = symbol in syms
        anchor_results.append({"anchor": f"{rel_file}:{symbol}", "ok": ok})
        if not ok:
            errors.append(f"broken symbol anchor: {rel_file}:{symbol} not found in AST")

    # Verify one-hop reachability from README.md and docs/README.md.
    reachability = {}
    for label, path, needle in (
        ("README.md", readme_path, "docs/cli-and-mcp.md"),
        ("docs/README.md", hub_path, "cli-and-mcp.md"),
    ):
        ok = path.is_file() and needle in path.read_text(encoding="utf-8")
        reachability[label] = ok
        if not ok:
            errors.append(f"unreachable: {label} does not link {needle}")

    return {
        "ok": len(errors) == 0,
        "counts": {
            "cli_commands": len(surface["cli_commands"]),
            "mcp_tools": len(surface["mcp_tools"]),
            "mcp_resources": len(surface["mcp_resources"]),
            "action_inputs": len(surface["action_inputs"]),
            "action_outputs": len(surface["action_outputs"]),
            "core_anchors": len(CORE_SYMBOL_ANCHORS),
        },
        "coverage": coverage,
        "anchors": anchor_results,
        "reachability": reachability,
        "errors": errors,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT), help="repository root directory")
    parser.add_argument("--check", action="store_true", help="fail nonzero if any gap or broken anchor exists")
    parser.add_argument("--json", action="store_true", help="emit JSON report")
    args = parser.parse_args(argv)

    result = check_coverage(Path(args.root))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        c = result["counts"]
        print(
            f"product-surface: {c['cli_commands']} CLI commands · {c['mcp_tools']} MCP tools · "
            f"{c['mcp_resources']} MCP resources · {c['action_outputs']} Action outputs · "
            f"{c['core_anchors']} core anchors"
        )
        for err in result["errors"]:
            print(f"FAIL: {err}", file=sys.stderr)
        if result["ok"]:
            print("product-surface: OK — zero critical gaps, all anchors verified, one-hop reachable")
    return 0 if (not args.check or result["ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
