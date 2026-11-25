#!/usr/bin/env python3
"""Contract and E2E tests for Phase 2-4 product capabilities:
progressive <5K-token sessions, honest solo-review lane, reusable PR verify GitHub Action,
proof-graduation readiness workbench, expanded MCP/CLI/UI endpoints, and wheel packaging.
"""

import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent


def _load_open_fleet():
    """Load the in-repo open_fleet package using stdlib importlib (no third-party AST imports)."""
    if "open_fleet" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "open_fleet",
            ROOT / "open_fleet" / "__init__.py",
            submodule_search_locations=[str(ROOT / "open_fleet")],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["open_fleet"] = mod
        spec.loader.exec_module(mod)
    return {
        "sessions": importlib.import_module("open_fleet.sessions"),
        "solo_review": importlib.import_module("open_fleet.solo_review"),
        "ci_action": importlib.import_module("open_fleet.ci_action"),
        "readiness": importlib.import_module("open_fleet.readiness"),
        "mcp": importlib.import_module("open_fleet.mcp_server"),
        "ui": importlib.import_module("open_fleet.ui_server"),
        "cli": importlib.import_module("open_fleet.cli"),
    }


OF = _load_open_fleet()


def _git_env() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Test User",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test User",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=_git_env(),
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return proc.stdout.strip()


class TestProgressiveSessions(unittest.TestCase):
    def test_all_missions_stay_under_5k_token_ceiling_per_phase(self):
        bench = OF["sessions"].benchmark_progressive_savings(ROOT)
        self.assertGreaterEqual(bench["mission_count"], 22)
        self.assertTrue(bench["all_within_ceiling"], bench)
        self.assertGreater(bench["avg_reduction_pct"], 85.0)
        for row in bench["missions"]:
            self.assertLess(row["max_phase_tokens"], 5000, row)

    def test_session_lifecycle_enforces_receipts_human_gates_and_terminals(self):
        with tempfile.TemporaryDirectory() as tmp:
            sdir = Path(tmp) / "sessions"
            started = OF["sessions"].start_session(
                "ship-it",
                "Add GET /healthz endpoint",
                root=ROOT,
                repo=ROOT,
                sessions_dir=sdir,
                base_branch="fleet/healthz",
            )
            sid = started["session"]["session_id"]
            self.assertEqual(started["session"]["current_phase"], "preflight")
            self.assertTrue(started["packet"]["token_budget"]["within_ceiling"])

            # Fail closed: cannot advance past preflight without a passing receipt.
            with self.assertRaises(PermissionError):
                OF["sessions"].advance_session(sid, root=ROOT, repo=ROOT, sessions_dir=sdir)

            # Advance preflight -> freeze with passing receipt.
            step1 = OF["sessions"].advance_session(
                sid, receipt={"ok": True, "kind": "preflight"}, root=ROOT, repo=ROOT, sessions_dir=sdir
            )
            self.assertEqual(step1["to_phase"], "freeze")

            # Fail closed: agents cannot self-approve a one-way human gate.
            for bad_actor in ("", "agent", "claude", "codex", "coordinator", "auto"):
                with self.subTest(actor=bad_actor):
                    with self.assertRaises(ValueError):
                        OF["sessions"].approve_gate(
                            sid, "freeze", bad_actor, "auto-approving spec",
                            root=ROOT, repo=ROOT, sessions_dir=sdir,
                        )

            # Fail closed: cannot advance past freeze without human approval.
            with self.assertRaises(PermissionError):
                OF["sessions"].advance_session(sid, root=ROOT, repo=ROOT, sessions_dir=sdir)

            # Approve freeze as a real human -> advance freeze -> execute -> verify -> promote.
            OF["sessions"].approve_gate(
                sid, "freeze", "Ravindra Kumar", "Spec criteria AC-1 and AC-2 reviewed and frozen",
                root=ROOT, repo=ROOT, sessions_dir=sdir,
            )
            step2 = OF["sessions"].advance_session(sid, root=ROOT, repo=ROOT, sessions_dir=sdir)
            self.assertEqual(step2["to_phase"], "execute")

            step3 = OF["sessions"].advance_session(
                sid, receipt={"ok": True}, root=ROOT, repo=ROOT, sessions_dir=sdir
            )
            self.assertEqual(step3["to_phase"], "verify")

            step4 = OF["sessions"].advance_session(
                sid, receipt={"ok": True, "manifest": "docs/u1.json"}, root=ROOT, repo=ROOT, sessions_dir=sdir
            )
            self.assertEqual(step4["to_phase"], "promote")

            # Fail closed: RELEASED and DEPLOYED_AND_VERIFIED require explicit human promote gate approval.
            for gated_term in ("RELEASED", "DEPLOYED_AND_VERIFIED"):
                with self.subTest(terminal=gated_term):
                    with self.assertRaises(PermissionError):
                        OF["sessions"].advance_session(
                            sid, terminal_state=gated_term, root=ROOT, repo=ROOT, sessions_dir=sdir
                        )

            # Fail closed: unknown terminal rejected by chain_check.py.
            with self.assertRaises(ValueError):
                OF["sessions"].advance_session(
                    sid, terminal_state="DONE-WITH-MYSTERY", root=ROOT, repo=ROOT, sessions_dir=sdir
                )

            # Stopping safely at PROMOTION_READY succeeds without promote gate (stored canonically).
            closed = OF["sessions"].advance_session(
                sid, terminal_state="PROMOTION_READY", root=ROOT, repo=ROOT, sessions_dir=sdir
            )
            self.assertTrue(closed["closed"])
            self.assertEqual(closed["session"]["status"], "completed")
            self.assertEqual(closed["session"]["terminal_state"], "PROMOTION-READY")
            self.assertEqual(closed["session"]["terminal_class"], "clean")

            listed = OF["sessions"].list_sessions(repo=ROOT, sessions_dir=sdir)
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["terminal_state"], "PROMOTION-READY")


class TestSoloReviewAndCIAction(unittest.TestCase):
    def _make_temp_repo(self, tmp: Path) -> tuple[Path, str]:
        repo = tmp / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], env=_git_env(), check=True, timeout=60)
        (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
        (repo / "test_calc.py").write_text(
            "import unittest\nfrom calc import add\n\n"
            "class T(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n",
            encoding="utf-8",
        )
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "initial base")
        base_sha = _git(repo, "rev-parse", "HEAD")
        return repo, base_sha

    def test_solo_review_blocks_dark_eligible_on_security_auth_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, base_sha = self._make_temp_repo(Path(tmp))
            (repo / "auth_guard.py").write_text("def authorize(token):\n    return bool(token)\n", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "-qm", "add auth guard")

            # Auto mode classifies strictly as lit because AUTH triggers.
            res = OF["solo_review"].run_solo_review(
                base=base_sha,
                root=ROOT,
                repo=repo,
                nc_command="python3 -m unittest test_calc.py",
            )
            self.assertTrue(res["ok"])
            self.assertEqual(res["lighting"]["effective"], "lit")
            self.assertFalse(res["lighting"]["dark_eligible"])
            self.assertIn("AUTH", res["diff_scope"]["lit_required_triggers"])
            self.assertIn("Blind-fix first", res["blind_review_packet"])

            # Forcing dark-eligible on an AUTH surface must fail closed.
            with self.assertRaises(PermissionError):
                OF["solo_review"].run_solo_review(
                    base=base_sha,
                    root=ROOT,
                    repo=repo,
                    lighting="dark-eligible",
                    nc_command="python3 -m unittest test_calc.py",
                )

    def test_solo_review_lane_a_dark_eligible_with_executed_negative_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            repo, base_sha = self._make_temp_repo(tpath)
            _git(repo, "checkout", "-qb", "fleet/integration")
            (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            _git(repo, "add", "calc.py")
            _git(repo, "commit", "-qm", "fix add")
            head_sha = _git(repo, "rev-parse", "HEAD")

            # Write frozen contract + evidence manifest with revert negative control.
            contract = repo / "spec.md"
            contract.write_text("# Spec\n\n- AC-1: add(2, 3) returns 5\n", encoding="utf-8")
            contract_digest = "sha256:" + hashlib.sha256(contract.read_bytes()).hexdigest()
            manifest_path = tpath / "u1-manifest.json"
            manifest = {
                "unit": "U1",
                "unit_class": "mutation",
                "lighting": "dark-eligible",
                "head_sha": head_sha,
                "base_sha": base_sha,
                "contract": {"source": str(contract), "digest": contract_digest},
                "criteria": [{"id": "AC-1", "status": "pass", "evidence": "test_calc.py"}],
                "intent_packet": {
                    "problem": "add subtracted instead of adding",
                    "approach": "fix operator in calc.py",
                    "risks": "none",
                },
                "negative_control": {
                    "kind": "revert",
                    "target_sha": head_sha,
                    "revert_paths": ["calc.py"],
                    "command": "python3 -m unittest test_calc.py",
                    "expected": "RED",
                    "observed": "AssertionError: -1 != 5",
                },
                "commands": ["python3 -m unittest test_calc.py"],
            }
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            packet_file = tpath / "blind-packet.md"
            res = OF["solo_review"].run_solo_review(
                base=base_sha,
                root=ROOT,
                repo=repo,
                contract_path=str(contract),
                manifest=str(manifest_path),
                lighting="dark-eligible",
                nc_command="python3 -m unittest test_calc.py",
                no_gh=True,
                packet_out=str(packet_file),
            )
            self.assertEqual(res["lighting"]["effective"], "dark-eligible")
            self.assertTrue(res["lighting"]["dark_eligible"])
            self.assertEqual(res["review_mode"], "solo-dark-eligible-executed-nc")
            self.assertTrue(packet_file.is_file())
            self.assertIsNotNone(res["verify"])
            self.assertTrue(res["floor_guard"]["ok"])

    def test_ci_action_yaml_and_runner_detect_floor_violations_and_risk_lenses(self):
        action_yml = ROOT / ".github" / "actions" / "open-fleet-verify" / "action.yml"
        self.assertTrue(action_yml.is_file())
        text = action_yml.read_text(encoding="utf-8")
        self.assertIn("using: composite", text)
        self.assertIn("open_fleet/ci_action.py", text)
        # Ensure zero GitHub expression interpolation inside the bash run block.
        run_section = text.split("run: |", 1)[1]
        self.assertNotIn("${{", run_section)

        with tempfile.TemporaryDirectory() as tmp:
            repo, base_sha = self._make_temp_repo(Path(tmp))
            (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            _git(repo, "add", "calc.py")
            _git(repo, "commit", "-qm", "clean change")

            clean = OF["ci_action"].run_ci_verify(base=base_sha, root=ROOT, repo=repo)
            self.assertTrue(clean["ok"], clean)
            summary = OF["ci_action"].render_step_summary(clean)
            self.assertIn("open-fleet PR Verification", summary)
            self.assertIn("PASS", summary)

            # Introduce a silenced-checker violation; floor_guard must fail the CI gate.
            (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # no" + "qa\n", encoding="utf-8")
            _git(repo, "add", "calc.py")
            _git(repo, "commit", "-qm", "floor violation")
            violated = OF["ci_action"].run_ci_verify(base=base_sha, root=ROOT, repo=repo)
            self.assertFalse(violated["ok"])
            self.assertEqual(violated["floor_guard"]["status"], "fail")

            snippet = OF["ci_action"].render_workflow_snippet(base_branch="main", include_manifest=True)
            self.assertIn("./.github/actions/open-fleet-verify", snippet)
            self.assertIn("execute-nc", snippet)


class TestReadinessMCPCLIAndExpandedUI(unittest.TestCase):
    def test_readiness_honest_counts_and_live_cert_check(self):
        rep = OF["readiness"].readiness_report(ROOT, run_cert_check=True)
        self.assertEqual(rep["proven_count"], 5)
        self.assertGreaterEqual(rep["doctrine_only_count"], 17)
        self.assertTrue(rep["certification_check"]["ok"], rep["certification_check"])
        self.assertTrue(rep["certification_check"]["fresh"])

    def test_mcp_expanded_tools_resources_and_diff_scope_fix(self):
        srv = OF["mcp"].OpenFleetMCPServer(root=ROOT, repo=ROOT)
        tools = {t["name"] for t in srv.tool_definitions()}
        self.assertGreaterEqual(len(tools), 19)
        for name in (
            "fleet_session_start",
            "fleet_session_packet",
            "fleet_session_approve_gate",
            "fleet_session_advance",
            "fleet_session_list",
            "fleet_solo_review",
            "fleet_readiness",
        ):
            self.assertIn(name, tools)

        # Verify the diff_scope bug fix works live against origin/main.
        ds = srv.call_tool("fleet_diff_scope", {"base": "origin/main", "repo": str(ROOT)})
        self.assertFalse(ds["isError"], ds)
        self.assertIsInstance(ds["structuredContent"]["parsed"]["flags"], dict)

        # Verify new resources read cleanly.
        for uri in ("open-fleet://sessions/list", "open-fleet://readiness/report"):
            with self.subTest(uri=uri):
                res = srv.read_resource(uri)
                data = json.loads(res["contents"][0]["text"])
                self.assertIsInstance(data, dict)

    def test_cli_phase2_3_commands_and_ui_endpoints(self):
        for argv in (
            ["session", "benchmark", "--json"],
            ["ci-check", "--workflow-snippet"],
            ["readiness", "--json"],
            ["solo-review", "--base", "origin/main", "--json"],
        ):
            with self.subTest(argv=argv):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = OF["cli"].main(["--root", str(ROOT), *argv])
                self.assertEqual(rc, 0, out.getvalue())
                self.assertTrue(out.getvalue().strip())

        with tempfile.TemporaryDirectory() as tmp:
            # Point UI at a temp repo copy? Use ROOT for read endpoints and isolated sessions via API check.
            server = OF["ui"].create_server(root=ROOT, repo=ROOT, host="127.0.0.1", port=0)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{port}"
                with urlopen(f"{base}/api/readiness") as resp:
                    rdy = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(rdy["proven_count"], 5)
                with urlopen(f"{base}/api/ci-workflow") as resp:
                    wf = json.loads(resp.read().decode("utf-8"))
                    self.assertIn("open-fleet-verify", wf["workflow_yaml"])
                with urlopen(f"{base}/api/sessions") as resp:
                    sess = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(sess["benchmark"]["all_within_ceiling"])

                req_fg = Request(
                    f"{base}/api/floor-check",
                    data=json.dumps({"base": "origin/main"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(req_fg) as resp:
                    fg = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(fg["ok"], fg)

                req_solo = Request(
                    f"{base}/api/solo-review",
                    data=json.dumps({"base": "origin/main", "builder": "claude"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(req_solo) as resp:
                    sr = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(sr["ok"], sr)
                    self.assertIn("Blind-fix first", sr["blind_review_packet"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertTrue(Path(tmp).is_dir())


if __name__ == "__main__":
    unittest.main()
