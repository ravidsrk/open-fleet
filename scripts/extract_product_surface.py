#!/usr/bin/env python3
"""Extract the public open_fleet product surface from live code and verify documentation anchors.

Used by the document-it coverage pipeline and CI:
- Extracts CLI subcommands from open_fleet/cli.py:build_parser()
- Extracts MCP tools & resources from open_fleet/mcp_server.py:OpenFleetMCPServer
- Extracts reusable GitHub Action inputs & outputs from .github/actions/open-fleet-verify/action.yml
- Parses every `open_fleet/<module>.py:<symbol>` implementation anchor directly from
  docs/cli-and-mcp.md (never a hand-copied list) and AST-verifies each anchor against live code
- Verifies 100% coverage of CLI commands (in `## Unified CLI Commands`), MCP tools, MCP resources,
  and Action outputs in docs/cli-and-mcp.md, plus resolved one-hop Markdown link reachability from
  README.md and docs/README.md.

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

# Inline backticked `open_fleet/<path>.py:<symbol>` anchors declared in docs/cli-and-mcp.md.
_DOC_ANCHOR_RE = re.compile(r"`(open_fleet/[A-Za-z0-9_./-]+\.py):([A-Za-z_][A-Za-z0-9_]*)`")
_MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)\s]+)(?:\s+[^)]*)?\)")
_MIN_DOC_ANCHORS = 10


def _load_open_fleet(root):
    """Load open_fleet package freshly from `root` via importlib (works under python3 -I).

    Always purges any prior `open_fleet` / `open_fleet.*` entries from `sys.modules` so
    repeated in-process checks against a mutated tree never read stale cached modules.
    """
    pkg_init = root / "open_fleet" / "__init__.py"
    if not pkg_init.is_file():
        raise FileNotFoundError(f"open_fleet package not found at {pkg_init}")
    for name in [k for k in list(sys.modules) if k == "open_fleet" or k.startswith("open_fleet.")]:
        del sys.modules[name]
    importlib.invalidate_caches()
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


def _extract_doc_anchors(doc_text):
    """Extract unique (rel_file, symbol) pairs anchored in documentation text."""
    seen = set()
    anchors = []
    for rel_file, symbol in _DOC_ANCHOR_RE.findall(doc_text):
        key = (rel_file, symbol)
        if key not in seen:
            seen.add(key)
            anchors.append(key)
    return anchors


def _section_lines(doc_lines, heading):
    """Return [(1-based line_no, line_text)] inside the markdown section starting at `heading`."""
    out = []
    in_section = False
    for idx, ln in enumerate(doc_lines, 1):
        stripped = ln.strip()
        if stripped == heading:
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if in_section:
            out.append((idx, ln))
    return out


def _has_resolved_markdown_link(source_path, expected_target_path):
    """True when `source_path` contains a relative Markdown link resolving to `expected_target_path`."""
    if not source_path.is_file():
        return False
    expected = expected_target_path.resolve()
    text = source_path.read_text(encoding="utf-8")
    for raw in _MD_LINK_RE.findall(text):
        target = raw.strip("<>").split("#", 1)[0].split("?", 1)[0]
        if not target or "://" in target or target.startswith(("/", "mailto:")):
            continue
        try:
            resolved = (source_path.parent / target).resolve()
        except OSError:
            continue
        if resolved == expected:
            return True
    return False


def extract_surface(root=ROOT):
    """Extract the complete public product surface directly from live code."""
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
    action_exists = action_path.is_file()
    action_inputs, action_outputs = _extract_action_io(action_path) if action_exists else ([], [])

    return {
        "cli_commands": cli_commands,
        "mcp_tools": mcp_tools,
        "mcp_resources": mcp_resources,
        "action_exists": action_exists,
        "action_inputs": action_inputs,
        "action_outputs": action_outputs,
    }


def check_coverage(root=ROOT):
    """Verify every extracted entity is documented, every doc anchor resolves, and docs are reachable."""
    root = Path(root).resolve()
    surface = extract_surface(root)
    doc_path = root / "docs" / "cli-and-mcp.md"
    readme_path = root / "README.md"
    hub_path = root / "docs" / "README.md"

    errors = []
    if not surface["cli_commands"]:
        errors.append("extracted 0 CLI commands from open_fleet/cli.py (fail-closed)")
    if not surface["mcp_tools"]:
        errors.append("extracted 0 MCP tools from open_fleet/mcp_server.py (fail-closed)")
    if not surface["mcp_resources"]:
        errors.append("extracted 0 MCP resources from open_fleet/mcp_server.py (fail-closed)")
    if not surface["action_exists"]:
        errors.append("missing .github/actions/open-fleet-verify/action.yml (fail-closed)")
    elif not surface["action_outputs"]:
        errors.append("extracted 0 Action outputs from .github/actions/open-fleet-verify/action.yml (fail-closed)")

    base_counts = {
        "cli_commands": len(surface["cli_commands"]),
        "mcp_tools": len(surface["mcp_tools"]),
        "mcp_resources": len(surface["mcp_resources"]),
        "action_inputs": len(surface["action_inputs"]),
        "action_outputs": len(surface["action_outputs"]),
        "doc_anchors": 0,
    }

    if not doc_path.is_file():
        errors.append(f"missing {doc_path}")
        return {
            "ok": False,
            "counts": base_counts,
            "surface": surface,
            "coverage": {},
            "anchors": [],
            "reachability": {},
            "errors": errors,
        }

    doc_text = doc_path.read_text(encoding="utf-8")
    doc_lines = doc_text.splitlines()
    cli_section = _section_lines(doc_lines, "## Unified CLI Commands")

    def _find_line(needle):
        for idx, ln in enumerate(doc_lines, 1):
            if needle in ln:
                return idx
        return None

    def _find_cli_command_line(cmd):
        pat = re.compile(rf"(?<![A-Za-z0-9_-])open-fleet {re.escape(cmd)}(?![A-Za-z0-9_-])")
        for idx, ln in cli_section:
            if pat.search(ln):
                return idx
        return None

    coverage = {"cli_commands": {}, "mcp_tools": {}, "mcp_resources": {}, "action_outputs": {}}
    if not cli_section:
        errors.append("missing '## Unified CLI Commands' reference section in docs/cli-and-mcp.md")
    for cmd in surface["cli_commands"]:
        ln = _find_cli_command_line(cmd)
        coverage["cli_commands"][cmd] = f"docs/cli-and-mcp.md:{ln}" if ln else None
        if ln is None:
            errors.append(f"undocumented CLI command in reference table: open-fleet {cmd}")

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

    # Parse every `open_fleet/<module>.py:<symbol>` anchor from docs/cli-and-mcp.md and AST-verify it.
    doc_anchors = _extract_doc_anchors(doc_text)
    base_counts["doc_anchors"] = len(doc_anchors)
    if len(doc_anchors) < _MIN_DOC_ANCHORS:
        errors.append(
            f"docs/cli-and-mcp.md declares only {len(doc_anchors)} file:symbol anchors "
            f"(minimum {_MIN_DOC_ANCHORS} required)"
        )

    anchor_results = []
    for rel_file, symbol in doc_anchors:
        fpath = (root / rel_file).resolve()
        if not fpath.is_relative_to(root) or not fpath.is_file():
            errors.append(f"broken anchor file: {rel_file}:{symbol}")
            anchor_results.append({"anchor": f"{rel_file}:{symbol}", "ok": False})
            continue
        syms = _defined_symbols(fpath)
        ok = symbol in syms
        anchor_results.append({"anchor": f"{rel_file}:{symbol}", "ok": ok})
        if not ok:
            errors.append(f"broken symbol anchor: {rel_file}:{symbol} not found in AST")

    # Verify resolved one-hop Markdown link reachability from README.md and docs/README.md.
    reachability = {}
    for label, path in (("README.md", readme_path), ("docs/README.md", hub_path)):
        ok = _has_resolved_markdown_link(path, doc_path)
        reachability[label] = ok
        if not ok:
            errors.append(f"unreachable: {label} has no valid relative Markdown link resolving to docs/cli-and-mcp.md")

    return {
        "ok": len(errors) == 0,
        "counts": base_counts,
        "surface": surface,
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

    try:
        result = check_coverage(Path(args.root))
    except (OSError, SyntaxError, ImportError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        c = result["counts"]
        print(
            f"product-surface: {c['cli_commands']} CLI commands · {c['mcp_tools']} MCP tools · "
            f"{c['mcp_resources']} MCP resources · {c['action_outputs']} Action outputs · "
            f"{c['doc_anchors']} doc anchors"
        )
        for err in result["errors"]:
            print(f"FAIL: {err}", file=sys.stderr)
        if result["ok"]:
            print("product-surface: OK — zero critical gaps, all doc anchors verified, one-hop reachable")
    return 0 if (not args.check or result["ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
