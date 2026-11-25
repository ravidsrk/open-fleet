#!/usr/bin/env python3
"""Contract and integration tests for the open_fleet product layer (CLI, MCP, Setup, UI)."""

import contextlib
import importlib
import importlib.util
import io
import json
import sqlite3
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
        "pkg": importlib.import_module("open_fleet"),
        "catalog": importlib.import_module("open_fleet.catalog"),
        "state": importlib.import_module("open_fleet.state"),
        "setup": importlib.import_module("open_fleet.setup"),
        "mcp": importlib.import_module("open_fleet.mcp_server"),
        "ui": importlib.import_module("open_fleet.ui_server"),
        "cli": importlib.import_module("open_fleet.cli"),
    }


OF = _load_open_fleet()


class TestCatalogAndIntentRouter(unittest.TestCase):
    def test_catalog_overview_and_mission_listing(self):
        ov = OF["catalog"].catalog_overview(ROOT)
        self.assertGreaterEqual(ov["mission_count"], 22)
        self.assertEqual(ov["proof_counts"]["external-run"], 2)
        self.assertEqual(ov["proof_counts"]["self-run"], 3)
        self.assertTrue(ov["quarantine"]["valid"])
        self.assertIn("orca", ov["pins"])

        missions = OF["catalog"].list_missions(ROOT)
        names = {m["name"] for m in missions}
        for expected in ("ship-it", "review-it", "clean-sweep", "harden-it", "prove-it"):
            self.assertIn(expected, names)

        ext_only = OF["catalog"].list_missions(ROOT, proof="external-run")
        self.assertEqual({m["name"] for m in ext_only}, {"review-it", "ship-it"})

    def test_get_mission_has_identity_and_prompt(self):
        m = OF["catalog"].get_mission("ship-it", ROOT)
        self.assertIsNotNone(m)
        self.assertEqual(m["proof"], "external-run")
        self.assertTrue(m["identity"]["oracle"])
        self.assertIn("ship-it", m["launch_prompt"])
        self.assertIsNone(OF["catalog"].get_mission("does-not-exist", ROOT))

    def test_intent_router_matches_core_workflows(self):
        cases = (
            ("Review this PR and return a read-only GO/NO-GO verdict", "review-it"),
            ("Build and ship this feature from spec to promotion PR", "ship-it"),
            ("Harden this service against SQL injection and auth bypass", "harden-it"),
            ("Kill the intermittent flaky tests in CI", "deflake-it"),
            ("Close every open issue in the backlog until zero", "clean-sweep"),
        )
        for query, want in cases:
            with self.subTest(query=query):
                res = OF["catalog"].route_intent(query, ROOT, top_k=3)
                self.assertTrue(res["matches"])
                self.assertEqual(res["matches"][0]["mission"], want, res)
                self.assertTrue(res["above_floor"])

    def test_certification_summary_matches_live_cells(self):
        cert = OF["catalog"].certification_summary(ROOT)
        by_name = {p["name"]: p for p in cert["providers"]}
        self.assertIn("posix", by_name)
        self.assertIn("orca", by_name)
        self.assertEqual(by_name["posix"]["cell_counts"]["live-witnessed"], 2)
        self.assertEqual(by_name["orca"]["cell_counts"]["live-witnessed"], 1)


class TestSetupAndDoctor(unittest.TestCase):
    def test_doctor_runs_cleanly_in_isolated_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            rep = OF["setup"].doctor(ROOT, home=Path(tmp), runtime="auto")
            self.assertIn(rep["overall"], ("ok", "warn", "fail"))
            ids = {c["id"] for c in rep["checks"]}
            self.assertTrue({"python", "git", "runtime", "verify-gate-script", "quarantine", "claude-install"}.issubset(ids))

    def test_setup_install_wire_hooks_mcp_and_uninstall_preserve_user_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            claude_dir = home / ".claude"
            claude_dir.mkdir(parents=True)
            settings_path = claude_dir / "settings.json"
            settings_path.write_text(
                json.dumps({
                    "theme": "dark",
                    "hooks": {
                        "Stop": [{"hooks": [{"type": "command", "command": "/usr/local/bin/custom-hook"}]}]
                    },
                }),
                encoding="utf-8",
            )
            res = OF["setup"].setup_host(
                "claude",
                root=ROOT,
                home=home,
                runtime="auto",
                wire_hooks=True,
                wire_mcp=True,
            )
            self.assertGreaterEqual(res["missions_affected"], 22)
            self.assertTrue((home / ".claude" / "skills" / "ship-it").is_symlink())
            self.assertTrue(res["mcp"]["written"])

            updated = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(updated["theme"], "dark")
            stop_cmds = [h["command"] for e in updated["hooks"]["Stop"] for h in e["hooks"]]
            self.assertIn("/usr/local/bin/custom-hook", stop_cmds)
            self.assertTrue(any("verify-gate.sh --event stop" in c for c in stop_cmds))

            mcp_file = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
            self.assertIn("open-fleet", mcp_file["mcpServers"])

            # Uninstall must remove open-fleet hooks & symlinks while preserving custom hooks.
            un = OF["setup"].setup_host("claude", root=ROOT, home=home, uninstall=True)
            self.assertEqual(un["mode"], "uninstall")
            self.assertFalse((home / ".claude" / "skills" / "ship-it").exists())
            after = json.loads(settings_path.read_text(encoding="utf-8"))
            stop_after = [h["command"] for e in after["hooks"]["Stop"] for h in e["hooks"]]
            self.assertEqual(stop_after, ["/usr/local/bin/custom-hook"])

    def test_setup_refuses_stacked_claude_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".claude").mkdir(parents=True)
            (home / ".claude" / "settings.json").write_text(
                json.dumps({"enabledPlugins": {"open-fleet@open-fleet": True}}),
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                OF["setup"].setup_host("claude", root=ROOT, home=home, wire_hooks=True)

    def test_mcp_config_generation_across_hosts(self):
        for host in ("claude", "codex", "gemini", "opencode", "antigravity", "cursor"):
            with self.subTest(host=host):
                cfg = OF["setup"].build_mcp_config(host, ROOT, runtime="posix")
                self.assertIn("open-fleet", cfg["content"])
                self.assertIn("open_fleet.mcp_server", cfg["content"])


class TestStateReader(unittest.TestCase):
    def test_reads_sqlite_runtime_and_merge_queue_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "runtime.db"
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE runs (id TEXT, status TEXT);
                CREATE TABLE tasks (id TEXT, status TEXT, title TEXT);
                CREATE TABLE dispatches (dispatch_id TEXT, state TEXT, profile TEXT);
                CREATE TABLE gates (id TEXT, status TEXT);
                CREATE TABLE mq_entries (id TEXT, state TEXT);
                INSERT INTO runs VALUES ('run_1', 'active');
                INSERT INTO tasks VALUES ('t_1', 'completed', 'Add healthz');
                INSERT INTO tasks VALUES ('t_2', 'ready', 'Add docs');
                INSERT INTO dispatches VALUES ('d_1', 'running', 'rw');
                INSERT INTO gates VALUES ('g_1', 'open');
                INSERT INTO mq_entries VALUES ('mq_1', 'QUEUED');
            """)
            conn.commit()
            conn.close()

            snap = OF["state"].read_runtime_state(ROOT, db_override=db)
            self.assertTrue(snap["db_exists"])
            self.assertEqual(snap["summary"]["runs"], 1)
            self.assertEqual(snap["summary"]["tasks_total"], 2)
            self.assertEqual(snap["summary"]["active_dispatches"], 1)
            self.assertEqual(snap["summary"]["open_gates"], 1)
            self.assertEqual(snap["summary"]["queued_merges"], 1)

    def test_reads_repo_decisions_ledger(self):
        dec = OF["state"].read_decisions(ROOT, limit=10)
        self.assertTrue(dec["exists"])
        self.assertGreater(dec["total"], 10)
        self.assertTrue(dec["entries"])


class TestMCPServer(unittest.TestCase):
    def setUp(self):
        self.server = OF["mcp"].OpenFleetMCPServer(root=ROOT, repo=ROOT)

    def test_initialize_tools_resources_and_prompts_protocol(self):
        init = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26"},
        })
        self.assertEqual(init["result"]["serverInfo"]["name"], "open-fleet")
        self.assertEqual(init["result"]["protocolVersion"], "2025-03-26")

        notif = self.server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(notif)

        tools = self.server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = {t["name"] for t in tools["result"]["tools"]}
        self.assertTrue({"fleet_doctor", "fleet_route_mission", "fleet_preflight", "fleet_verify_manifest", "fleet_run_demo"}.issubset(tool_names))

        res_list = self.server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
        uris = {r["uri"] for r in res_list["result"]["resources"]}
        self.assertIn("open-fleet://catalog/overview", uris)
        read_ov = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {"uri": "open-fleet://catalog/overview"},
        })
        parsed = json.loads(read_ov["result"]["contents"][0]["text"])
        self.assertGreaterEqual(parsed["mission_count"], 22)

        prompts = self.server.handle_message({"jsonrpc": "2.0", "id": 5, "method": "prompts/list"})
        self.assertGreaterEqual(len(prompts["result"]["prompts"]), 22)
        got_prompt = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "prompts/get",
            "params": {"name": "mission/review-it", "arguments": {"goal": "PR #12"}},
        })
        self.assertIn("PR #12", got_prompt["result"]["messages"][0]["content"]["text"])

    def test_mcp_tool_calls_route_and_preflight_and_demo(self):
        routed = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "fleet_route_mission", "arguments": {"goal": "review PR #55"}},
        })
        self.assertFalse(routed["result"]["isError"])
        self.assertEqual(routed["result"]["structuredContent"]["matches"][0]["mission"], "review-it")

        pf_ok = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "fleet_preflight", "arguments": {"mission": "review-it", "runtime": "posix"}},
        })
        self.assertFalse(pf_ok["result"]["isError"])

        # pin-it requires cap:orca-self-audit and must fail closed on posix
        pf_refuse = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "fleet_preflight", "arguments": {"mission": "pin-it", "runtime": "posix"}},
        })
        self.assertTrue(pf_refuse["result"]["isError"])

        demo = self.server.handle_message({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {"name": "fleet_run_demo", "arguments": {"kind": "negative-control"}},
        })
        self.assertFalse(demo["result"]["isError"])
        self.assertTrue(demo["result"]["structuredContent"]["verifier_caught_gamed_manifest"])

    def test_framing_supports_jsonl_and_content_length(self):
        payload = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        buf_jsonl = io.BytesIO((json.dumps(payload) + "\n").encode("utf-8"))
        msg1, mode1 = OF["mcp"]._read_framed_message(buf_jsonl)
        self.assertEqual(msg1, payload)
        self.assertEqual(mode1, "jsonl")

        raw = json.dumps(payload).encode("utf-8")
        buf_lsp = io.BytesIO(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
        msg2, mode2 = OF["mcp"]._read_framed_message(buf_lsp)
        self.assertEqual(msg2, payload)
        self.assertEqual(mode2, "lsp")


class TestCLIAndMissionControlUI(unittest.TestCase):
    def test_cli_json_subcommands(self):
        for argv in (
            ["--version"],
            ["doctor", "--json"],
            ["missions", "list", "--json"],
            ["missions", "show", "review-it", "--json"],
            ["route", "harden", "this", "API", "--json"],
            ["status", "--json"],
            ["certify", "--json"],
            ["mcp", "--print-config", "claude"],
        ):
            with self.subTest(argv=argv):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = OF["cli"].main(["--root", str(ROOT), *argv])
                self.assertEqual(rc, 0, out.getvalue())
                self.assertTrue(out.getvalue().strip())

    def test_ui_http_server_serves_html_and_live_apis(self):
        server = OF["ui"].create_server(root=ROOT, repo=ROOT, host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{port}"
            with urlopen(f"{base}/") as resp:
                self.assertEqual(resp.status, 200)
                html = resp.read().decode("utf-8")
                self.assertIn("open-fleet Mission Control", html)

            with urlopen(f"{base}/api/overview") as resp:
                ov = json.loads(resp.read().decode("utf-8"))
                self.assertGreaterEqual(ov["catalog"]["mission_count"], 22)
                self.assertGreaterEqual(len(ov["mcp_tools"]), 12)

            with urlopen(f"{base}/api/setup/preview?host=codex&runtime=auto") as resp:
                setup_data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(setup_data["host"], "codex")
                self.assertIn("mcp_servers.open-fleet", setup_data["mcp"]["content"])

            req = Request(
                f"{base}/api/route",
                data=json.dumps({"goal": "review PR #99"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req) as resp:
                routed = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(routed["matches"][0]["mission"], "review-it")

            req_nc = Request(
                f"{base}/api/demo/negative-control",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req_nc) as resp:
                nc = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(nc["verifier_caught_gamed_manifest"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
