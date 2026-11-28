"""Product & protocol parity suite executed by scripts/rust_product_oracle.py."""
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def load_py_catalog():
    if "open_fleet" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "open_fleet",
            ROOT / "open_fleet" / "__init__.py",
            submodule_search_locations=[str(ROOT / "open_fleet")],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["open_fleet"] = mod
        spec.loader.exec_module(mod)
    return importlib.import_module("open_fleet.catalog")


BINARY = ROOT / "target" / "release" / ("open-fleet.exe" if os.name == "nt" else "open-fleet")
PY_CATALOG = load_py_catalog()


class RustCatalogAndMcpOracle(unittest.TestCase):
    def _cli(self, *args):
        return subprocess.run(
            [str(BINARY), *args],
            cwd=str(ROOT), capture_output=True, text=True, check=True,
        )

    def test_missions_parity_with_python_catalog(self):
        py_missions = PY_CATALOG.list_missions(ROOT)
        rust_missions = json.loads(self._cli("missions", "--repo", str(ROOT), "--json").stdout)
        self.assertEqual([m["name"] for m in rust_missions], [m["name"] for m in py_missions])
        for rm, pm in zip(rust_missions, py_missions, strict=True):
            self.assertEqual(rm["proof"], pm["proof"], rm["name"])
            self.assertEqual(rm["category"], pm["category"], rm["name"])
            self.assertEqual(rm["activation_budget_tokens"], pm["activation_budget_tokens"], rm["name"])
            self.assertEqual(rm["composes"], pm["composes"], rm["name"])
            self.assertEqual(rm["deferred_reads"], pm["deferred_reads"], rm["name"])

        ext_only = json.loads(self._cli("missions", "--proof", "external-run", "--repo", str(ROOT), "--json").stdout)
        self.assertEqual({m["name"] for m in ext_only}, {"review-it", "ship-it"})

    def test_route_intent_matches_python_across_core_intents(self):
        cases = (
            ("Review this PR and return a read-only GO/NO-GO verdict", "review-it"),
            ("Build and ship this feature from spec to promotion PR", "ship-it"),
            ("Harden this service against SQL injection and auth bypass", "harden-it"),
            ("Kill the intermittent flaky tests in CI", "deflake-it"),
            ("Close every open issue in the backlog until zero", "clean-sweep"),
            ("Migrate the database column safely without downtime", "migrate-it"),
            ("Make this service operable with alerts and runbooks", "oncall-it"),
        )
        for query, want in cases:
            with self.subTest(query=query):
                py_res = PY_CATALOG.route_intent(query, ROOT, top_k=3)
                rs_res = json.loads(self._cli("route", "--repo", str(ROOT), "--top-k", "3", "--json", query).stdout)
                self.assertEqual(rs_res["matches"][0]["mission"], want, rs_res)
                self.assertEqual(rs_res["matches"][0]["mission"], py_res["matches"][0]["mission"])
                self.assertAlmostEqual(rs_res["matches"][0]["score"], py_res["matches"][0]["score"], places=3)
                self.assertEqual(rs_res["above_floor"], py_res["above_floor"])

    def test_overview_and_certification_parity(self):
        py_ov = PY_CATALOG.catalog_overview(ROOT)
        rs_ov = json.loads(self._cli("overview", "--repo", str(ROOT), "--json").stdout)
        for key in ("mission_count", "proof_counts", "provider_count", "harness_count",
                    "live_witnessed_cells", "retained_runs_total", "retained_runs_binding",
                    "one_way_door_count"):
            self.assertEqual(rs_ov[key], py_ov[key], f"overview mismatch on {key}")

        py_cert = PY_CATALOG.certification_summary(ROOT)
        rs_cert = json.loads(self._cli("certification", "--repo", str(ROOT), "--json").stdout)
        self.assertEqual(
            {p["name"]: p["cell_counts"] for p in rs_cert["providers"]},
            {p["name"]: p["cell_counts"] for p in py_cert["providers"]},
        )

    def test_show_mission_and_unknown_exit_2(self):
        shown = json.loads(self._cli("show", "ship-it", "--repo", str(ROOT), "--json").stdout)
        self.assertEqual(shown["name"], "ship-it")
        self.assertEqual(shown["proof"], "external-run")
        self.assertIn("ship-it", shown["launch_prompt"])

        missing = subprocess.run(
            [str(BINARY), "show", "does-not-exist", "--repo", str(ROOT)],
            cwd=str(ROOT), capture_output=True, text=True,
        )
        self.assertEqual(missing.returncode, 2)

    def test_native_mcp_stdio_jsonl_protocol(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "fleet_route_mission", "arguments": {"goal": "Review this PR read-only"}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "fleet_doctor", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
             "params": {"name": "fleet_decisions", "arguments": {"limit": 5}}},
            {"jsonrpc": "2.0", "id": 7, "method": "resources/list"},
            {"jsonrpc": "2.0", "id": 8, "method": "resources/read",
             "params": {"uri": "open-fleet://catalog/overview"}},
            {"jsonrpc": "2.0", "id": 9, "method": "prompts/list"},
            {"jsonrpc": "2.0", "id": 10, "method": "prompts/get",
             "params": {"name": "mission/review-it", "arguments": {"goal": "Check PR #42"}}},
            {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
             "params": {"name": "fleet_quarantine_check", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
             "params": {"name": "fleet_proof_status", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 13, "method": "tools/call",
             "params": {"name": "fleet_diff_scope", "arguments": {"base": "HEAD"}}},
        ]
        wire = "\n".join(json.dumps(r) for r in requests) + "\n"
        proc = subprocess.run(
            [str(BINARY), "mcp", "--root", str(ROOT), "--repo", str(ROOT)],
            input=wire, capture_output=True, text=True, check=True, timeout=30,
        )
        responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        by_id = {r["id"]: r for r in responses}
        self.assertEqual(len(responses), 13)  # notification emits no response
        self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "open-fleet")
        self.assertEqual(by_id[1]["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(by_id[2]["result"], {})

        tool_names = {t["name"] for t in by_id[3]["result"]["tools"]}
        self.assertTrue({
            "fleet_doctor", "fleet_route_mission", "fleet_list_missions", "fleet_get_mission",
            "fleet_floor_check", "fleet_certification", "fleet_decisions", "fleet_egress_verify",
            "fleet_diff_scope", "fleet_quarantine_check", "fleet_proof_status",
        }.issubset(tool_names))

        route_out = by_id[4]["result"]["structuredContent"]
        self.assertEqual(route_out["matches"][0]["mission"], "review-it")
        self.assertFalse(by_id[4]["result"]["isError"])

        doc_out = by_id[5]["result"]["structuredContent"]
        self.assertTrue(doc_out["git_available"])
        self.assertGreaterEqual(doc_out["missions_count"], 22)

        dec_out = by_id[6]["result"]["structuredContent"]
        self.assertTrue(dec_out["exists"])
        self.assertGreater(dec_out["total"], 10)

        res_uris = {r["uri"] for r in by_id[7]["result"]["resources"]}
        self.assertIn("open-fleet://catalog/overview", res_uris)
        ov_text = by_id[8]["result"]["contents"][0]["text"]
        self.assertGreaterEqual(json.loads(ov_text)["mission_count"], 22)

        self.assertGreaterEqual(len(by_id[9]["result"]["prompts"]), 22)
        prompt_text = by_id[10]["result"]["messages"][0]["content"]["text"]
        self.assertIn("review-it", prompt_text)
        self.assertIn("PR #42", prompt_text)

        q_out = by_id[11]["result"]["structuredContent"]
        self.assertTrue(q_out["ok"])
        self.assertEqual(q_out["violations"], [])

        ps_out = by_id[12]["result"]["structuredContent"]
        self.assertTrue(ps_out["ok"])
        self.assertGreaterEqual(ps_out["rollup"]["total"], 22)

        ds_out = by_id[13]["result"]["structuredContent"]
        self.assertIn("flags", ds_out)
        self.assertIn("BACKEND", ds_out["flags"])

    def test_native_mcp_stdio_lsp_content_length_framing(self):
        req = json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}).encode("utf-8")
        framed = f"Content-Length: {len(req)}\r\n\r\n".encode("ascii") + req
        proc = subprocess.run(
            [str(BINARY), "mcp", "--root", str(ROOT), "--repo", str(ROOT)],
            input=framed, capture_output=True, check=True, timeout=30,
        )
        self.assertTrue(proc.stdout.startswith(b"Content-Length: "))
        _, body = proc.stdout.split(b"\r\n\r\n", 1)
        resp = json.loads(body.decode("utf-8"))
        self.assertEqual(resp, {"jsonrpc": "2.0", "id": 99, "result": {}})

    def test_native_session_lifecycle_and_5k_benchmark(self):
        bench = json.loads(self._cli("session", "benchmark", "--repo", str(ROOT), "--json").stdout)
        self.assertGreaterEqual(bench["mission_count"], 22)
        self.assertTrue(bench["all_within_ceiling"], bench)
        self.assertGreater(bench["avg_reduction_pct"], 85.0)

        with tempfile.TemporaryDirectory() as tmp:
            sdir = Path(tmp) / "sessions"
            started = json.loads(
                self._cli(
                    "session", "start", "ship-it", "Add GET /healthz endpoint",
                    "--base", "fleet/healthz", "--repo", str(ROOT),
                    "--sessions-dir", str(sdir), "--json",
                ).stdout
            )
            sid = started["session"]["session_id"]
            self.assertEqual(started["session"]["current_phase"], "preflight")
            self.assertTrue(started["packet"]["token_budget"]["within_ceiling"])

            # Fail closed without receipt
            bad = subprocess.run(
                [str(BINARY), "session", "advance", sid, "--repo", str(ROOT),
                 "--sessions-dir", str(sdir), "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(bad.returncode, 1)

            # Advance preflight -> freeze
            step1 = json.loads(
                self._cli("session", "advance", sid, "--ok", "--repo", str(ROOT),
                          "--sessions-dir", str(sdir), "--json").stdout
            )
            self.assertEqual(step1["to_phase"], "freeze")

            # Refuse agent actor on human gate
            bad_actor = subprocess.run(
                [str(BINARY), "session", "approve", sid, "--gate", "freeze",
                 "--actor", "claude", "--rationale", "auto-approving",
                 "--repo", str(ROOT), "--sessions-dir", str(sdir), "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(bad_actor.returncode, 1)

            # Approve as real human -> advance freeze -> execute -> verify -> promote -> close
            self._cli("session", "approve", sid, "--gate", "freeze",
                      "--actor", "Ravindra Kumar", "--rationale", "Spec AC-1 frozen",
                      "--repo", str(ROOT), "--sessions-dir", str(sdir), "--json")
            self._cli("session", "advance", sid, "--repo", str(ROOT),
                      "--sessions-dir", str(sdir), "--json")
            self._cli("session", "advance", sid, "--ok", "--repo", str(ROOT),
                      "--sessions-dir", str(sdir), "--json")
            self._cli("session", "advance", sid, "--ok", "--repo", str(ROOT),
                      "--sessions-dir", str(sdir), "--json")
            closed = json.loads(
                self._cli("session", "advance", sid, "--terminal", "PROMOTION_READY",
                          "--repo", str(ROOT), "--sessions-dir", str(sdir), "--json").stdout
            )
            self.assertTrue(closed["closed"])
            self.assertEqual(closed["session"]["terminal_state"], "PROMOTION-READY")
            self.assertEqual(closed["session"]["terminal_class"], "clean")

    def test_native_solo_review_ci_check_readiness_and_mcp_wave3b(self):
        rdy = json.loads(self._cli("readiness", "--repo", str(ROOT), "--json").stdout)
        self.assertGreaterEqual(rdy["total_missions"], 22)
        self.assertGreaterEqual(rdy["proven_count"], 5)

        snip = self._cli("ci-check", "--workflow-snippet", "--workflow-base", "main").stdout
        self.assertIn("open-fleet-verify", snip)

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            env = {
                **os.environ,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "T",
                "GIT_AUTHOR_EMAIL": "t@t.invalid",
                "GIT_COMMITTER_NAME": "T",
                "GIT_COMMITTER_EMAIL": "t@t.invalid",
            }
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], env=env, check=True)
            (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], env=env, check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"], env=env, check=True)
            base_sha = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                env=env, capture_output=True, text=True, check=True,
            ).stdout.strip()
            (repo / "auth_guard.py").write_text("def authorize(tok):\n    return bool(tok)\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], env=env, check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "auth"], env=env, check=True)

            sr_env = {**env, "OPEN_FLEET_ROOT": str(ROOT)}
            sr = subprocess.run(
                [str(BINARY), "solo-review", "--base", base_sha, "--repo", str(repo),
                 "--nc-command", "true", "--json"],
                env=sr_env, capture_output=True, text=True, check=True,
            )
            sr_doc = json.loads(sr.stdout)
            self.assertEqual(sr_doc["lighting"]["effective"], "lit")
            self.assertFalse(sr_doc["lighting"]["dark_eligible"])
            self.assertIn("AUTH", sr_doc["diff_scope"]["lit_required_triggers"])

            forced = subprocess.run(
                [str(BINARY), "solo-review", "--base", base_sha, "--repo", str(repo),
                 "--lighting", "dark-eligible", "--nc-command", "true", "--json"],
                env=sr_env, capture_output=True, text=True,
            )
            self.assertEqual(forced.returncode, 1)

            ci_ok = subprocess.run(
                [str(BINARY), "ci-check", "--base", base_sha, "--repo", str(repo), "--json"],
                env=sr_env, capture_output=True, text=True, check=True,
            )
            self.assertTrue(json.loads(ci_ok.stdout)["ok"])
            ci_risk = subprocess.run(
                [str(BINARY), "ci-check", "--base", base_sha, "--repo", str(repo),
                 "--fail-on-risk-lenses", "--json"],
                env=sr_env, capture_output=True, text=True,
            )
            self.assertEqual(ci_risk.returncode, 1)

        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "fleet_preflight", "arguments": {"mission": "review-it", "runtime": "posix", "mode": "readonly"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "fleet_preflight", "arguments": {"mission": "pin-it", "runtime": "posix", "mode": "readonly"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "fleet_chain_check", "arguments": {"terminal": "ABANDONED", "allowed": ["ABANDONED", "MIGRATED"]}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "fleet_readiness", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "fleet_run_report_check", "arguments": {
                 "report": "docs/runs/2026-09-14-clean-sweep-self-run.md",
                 "mission": "clean-sweep",
                 "tier": "self-run",
             }}},
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
             "params": {"name": "fleet_events_report", "arguments": {
                 "log": str(ROOT / "tests" / "fixtures" / "events" / "clean-two-waves.jsonl"),
             }}},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "fleet_verify_manifest", "arguments": {
                 "manifest": "nonexistent-manifest.json",
                 "base": "HEAD",
                 "no_gh": True,
             }}},
        ]
        wire = "\n".join(json.dumps(r) for r in reqs) + "\n"
        proc = subprocess.run(
            [str(BINARY), "mcp", "--root", str(ROOT), "--repo", str(ROOT)],
            input=wire, capture_output=True, text=True, check=True, timeout=30,
        )
        by_id = {r["id"]: r for r in (json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip())}
        self.assertFalse(by_id[1]["result"]["isError"])
        self.assertTrue(by_id[1]["result"]["structuredContent"]["ok"])
        self.assertTrue(by_id[2]["result"]["isError"])
        self.assertEqual(by_id[2]["result"]["structuredContent"]["missing_capability"], "cap:orca-self-audit")
        self.assertTrue(by_id[3]["result"]["isError"])
        self.assertEqual(by_id[3]["result"]["structuredContent"]["class"], "degraded")
        self.assertGreaterEqual(by_id[4]["result"]["structuredContent"]["total_missions"], 22)
        self.assertFalse(by_id[5]["result"]["isError"])
        self.assertTrue(by_id[5]["result"]["structuredContent"]["ok"])
        self.assertFalse(by_id[6]["result"]["isError"])
        self.assertIn("schema", by_id[6]["result"]["structuredContent"])
        self.assertTrue(by_id[7]["result"]["isError"])
        self.assertEqual(by_id[7]["result"]["structuredContent"]["exit_code"], 2)

    def test_standalone_zero_clone_binary_in_isolated_temp_dir(self):
        import shutil

        with tempfile.TemporaryDirectory(prefix="of-standalone-") as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            work_dir = tmp_path / "empty-project"
            home_dir = tmp_path / "home"
            bin_dir.mkdir()
            work_dir.mkdir()
            home_dir.mkdir()
            standalone_bin = bin_dir / BINARY.name
            shutil.copy2(BINARY, standalone_bin)
            standalone_bin.chmod(0o755)

            env = {
                k: v for k, v in os.environ.items()
                if k not in ("OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT", "CLAUDE_PLUGIN_ROOT", "OPEN_FLEET_CACHE_DIR")
            }
            env["HOME"] = str(home_dir)

            doc = subprocess.run(
                [str(standalone_bin), "doctor", "--repo", str(work_dir), "--json"],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            )
            doc_json = json.loads(doc.stdout)
            self.assertEqual(doc_json["catalog_source"], "embedded")
            self.assertGreaterEqual(doc_json["missions_count"], 22)
            self.assertGreaterEqual(doc_json["embedded_catalog_files"], 100)
            self.assertEqual(len(doc_json["embedded_catalog_sha256"]), 64)
            self.assertTrue(doc_json["ready"])
            self.assertTrue(doc_json["catalog_root"].startswith(str(home_dir / ".open-fleet" / "catalog")))

            missions = json.loads(
                subprocess.run(
                    [str(standalone_bin), "missions", "--repo", str(work_dir), "--json"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertGreaterEqual(len(missions), 22)

            routed = json.loads(
                subprocess.run(
                    [str(standalone_bin), "route", "--repo", str(work_dir), "--json", "Review this PR read-only"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertEqual(routed["matches"][0]["mission"], "review-it")

            init_res = json.loads(
                subprocess.run(
                    [str(standalone_bin), "init", "--repo", str(work_dir), "--home", str(home_dir),
                     "--harness", "claude,cursor", "--json"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertTrue(init_res["ok"])
            self.assertEqual(init_res["catalog_source"], "embedded")
            self.assertTrue(init_res["targets"][0]["hook_wired"])
            self.assertTrue(init_res["targets"][0]["deny_hook_wired"])
            settings = json.loads((home_dir / ".claude" / "settings.json").read_text(encoding="utf-8"))
            self.assertIn("Stop", settings["hooks"])
            self.assertIn("TaskCompleted", settings["hooks"])
            self.assertIn("PreToolUse", settings["hooks"])
            self.assertIn("hook --mode deny", settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"])

            doc2 = json.loads(
                subprocess.run(
                    [str(standalone_bin), "doctor", "--repo", str(work_dir), "--json"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertTrue(doc2["claude_floor_hook_wired"])
            self.assertTrue(doc2["claude_deny_hook_wired"])

            # Standalone MCP server & preflight & session benchmark with zero repo checkout
            mcp_wire = "\n".join([
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                            "params": {"name": "fleet_list_missions", "arguments": {}}}),
            ]) + "\n"
            mcp_proc = subprocess.run(
                [str(standalone_bin), "mcp", "--repo", str(work_dir)],
                cwd=str(work_dir), env=env, input=mcp_wire,
                capture_output=True, text=True, check=True, timeout=30,
            )
            mcp_by_id = {r["id"]: r for r in (json.loads(ln) for ln in mcp_proc.stdout.splitlines() if ln.strip())}
            self.assertGreaterEqual(len(mcp_by_id[1]["result"]["tools"]), 23)
            self.assertFalse(mcp_by_id[2]["result"]["isError"])

            subprocess.run(["git", "init", "-q", "-b", "main", str(work_dir)], env=env, check=True)
            pref = subprocess.run(
                [str(standalone_bin), "preflight", "--runtime", "posix", "--mission", "review-it",
                 "--mode", "readonly", "--json"],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            )
            self.assertTrue(json.loads(pref.stdout)["ok"])

            bench = json.loads(
                subprocess.run(
                    [str(standalone_bin), "session", "benchmark", "--repo", str(work_dir), "--json"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertTrue(bench["all_within_ceiling"])

    def test_native_demo_ui_and_standalone_deny_settings(self):
        import shutil
        from urllib.request import Request, urlopen

        with tempfile.TemporaryDirectory(prefix="of-phase-b-") as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            work_dir = tmp_path / "app"
            home_dir = tmp_path / "home"
            bin_dir.mkdir()
            work_dir.mkdir()
            home_dir.mkdir()
            standalone_bin = bin_dir / BINARY.name
            shutil.copy2(BINARY, standalone_bin)
            standalone_bin.chmod(0o755)

            env = {
                k: v for k, v in os.environ.items()
                if k not in ("OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT", "CLAUDE_PLUGIN_ROOT",
                             "OPEN_FLEET_CACHE_DIR", "OPEN_FLEET_BIN", "OPEN_FLEET_DENY_HOOK")
            }
            env["HOME"] = str(home_dir)

            # 1. Standalone zero-Python negative-control proof demo
            demo = subprocess.run(
                [str(standalone_bin), "demo", "--json"],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True, timeout=60,
            )
            demo_json = json.loads(demo.stdout)
            self.assertTrue(demo_json["ok"])
            self.assertEqual(demo_json["engine"], "rust")
            self.assertTrue(demo_json["self_score_green"])
            self.assertTrue(demo_json["verifier_caught_gamed_manifest"])
            self.assertEqual(demo_json["verifier_exit"], 2)
            self.assertEqual(demo_json["dropped_criterion"], "AC-2")

            # 2. Standalone deny-hook --settings -> --verify-settings round-trip (native binary command)
            settings_out = subprocess.run(
                [str(standalone_bin), "deny-hook", "--settings", str(work_dir)],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            )
            settings_doc = json.loads(settings_out.stdout)
            hook_cmd = settings_doc["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            self.assertIn("deny-hook", hook_cmd)
            settings_file = tmp_path / "claude-settings.json"
            settings_file.write_text(settings_out.stdout, encoding="utf-8")
            ver = subprocess.run(
                [str(standalone_bin), "deny-hook", "--verify-settings", str(settings_file),
                 "--harness", "claude", "--boundary", str(work_dir)],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            )
            self.assertEqual(ver.returncode, 0)

            # 3. Standalone zero-Python Mission Control HTTP + SSE server (`open-fleet ui --port 0`)
            proc = subprocess.Popen(
                [str(standalone_bin), "ui", "--host", "127.0.0.1", "--port", "0", "--repo", str(work_dir)],
                cwd=str(work_dir), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                banner = proc.stdout.readline().strip()
                self.assertIn("http://127.0.0.1:", banner, f"unexpected ui banner: {banner!r}")
                base_url = banner.split("http://", 1)[1].strip()
                base = f"http://{base_url}"

                with urlopen(f"{base}/", timeout=10) as resp:
                    self.assertEqual(resp.status, 200)
                    html = resp.read().decode("utf-8")
                    self.assertIn("open-fleet Mission Control", html)

                with urlopen(f"{base}/api/health", timeout=10) as resp:
                    health = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(health["ok"])
                    self.assertEqual(health["engine"], "rust")

                with urlopen(f"{base}/api/overview", timeout=10) as resp:
                    ov = json.loads(resp.read().decode("utf-8"))
                    self.assertGreaterEqual(ov["catalog"]["mission_count"], 22)
                    self.assertGreaterEqual(len(ov["mcp_tools"]), 23)

                with urlopen(f"{base}/api/setup/preview?host=codex&runtime=auto", timeout=10) as resp:
                    setup = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(setup["host"], "codex")
                    self.assertIn("mcp_servers.open-fleet", setup["mcp"]["content"])

                req = Request(
                    f"{base}/api/route",
                    data=json.dumps({"goal": "review PR #99"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(req, timeout=10) as resp:
                    routed = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(routed["matches"][0]["mission"], "review-it")

                req_nc = Request(
                    f"{base}/api/demo/negative-control",
                    data=b"{}",
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(req_nc, timeout=30) as resp:
                    nc = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(nc["verifier_caught_gamed_manifest"])
                    self.assertEqual(nc["engine"], "rust")

                with urlopen(f"{base}/api/events/stream", timeout=10) as resp:
                    sse = resp.read().decode("utf-8")
                    self.assertIn("event: snapshot", sse)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)

    def test_v1_binary_bound_transcript_status_and_mcp_print_config(self):
        import hashlib
        import shutil
        import sqlite3

        with tempfile.TemporaryDirectory(prefix="of-v1-") as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            work_dir = tmp_path / "app"
            home_dir = tmp_path / "home"
            keys_dir = tmp_path / "keys"
            for d in (bin_dir, work_dir, home_dir, keys_dir):
                d.mkdir()
            standalone_bin = bin_dir / BINARY.name
            shutil.copy2(BINARY, standalone_bin)
            standalone_bin.chmod(0o755)
            bin_sha = hashlib.sha256(standalone_bin.read_bytes()).hexdigest()

            env = {
                k: v for k, v in os.environ.items()
                if k not in ("OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT", "CLAUDE_PLUGIN_ROOT",
                             "OPEN_FLEET_CACHE_DIR", "OPEN_FLEET_BIN", "OPEN_FLEET_SCRIPTS_DIR")
            }
            env["HOME"] = str(home_dir)
            env["GIT_CONFIG_GLOBAL"] = os.devnull
            env["GIT_CONFIG_NOSYSTEM"] = "1"
            env["GIT_AUTHOR_NAME"] = "T"
            env["GIT_AUTHOR_EMAIL"] = "t@t.invalid"
            env["GIT_COMMITTER_NAME"] = "T"
            env["GIT_COMMITTER_EMAIL"] = "t@t.invalid"

            # 1. Doctor reports engine == "rust" and embedded catalog
            doc = json.loads(
                subprocess.run(
                    [str(standalone_bin), "doctor", "--repo", str(work_dir), "--json"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertEqual(doc["engine"], "rust")
            self.assertEqual(doc["catalog_source"], "embedded")

            # 2. Native read-only SQLite `open-fleet status --json`
            orca_dir = work_dir / ".orca"
            orca_dir.mkdir()
            db_path = orca_dir / "runtime.db"
            conn = sqlite3.connect(db_path)
            conn.executescript("""
                CREATE TABLE runs (id TEXT, status TEXT);
                CREATE TABLE tasks (id TEXT, status TEXT);
                CREATE TABLE dispatches (dispatch_id TEXT, state TEXT);
                CREATE TABLE gates (id TEXT, status TEXT);
                CREATE TABLE mq_entries (id TEXT, state TEXT);
                INSERT INTO runs VALUES ('r1', 'active');
                INSERT INTO tasks VALUES ('t1', 'completed'), ('t2', 'ready');
                INSERT INTO dispatches VALUES ('d1', 'running');
                INSERT INTO gates VALUES ('g1', 'open');
                INSERT INTO mq_entries VALUES ('m1', 'QUEUED');
            """)
            conn.commit()
            conn.close()

            st = json.loads(
                subprocess.run(
                    [str(standalone_bin), "status", "--repo", str(work_dir), "--json"],
                    cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
                ).stdout
            )
            self.assertEqual(st["engine"], "rust")
            rs = st["workspace"]["runtime_state"]
            self.assertTrue(rs["db_exists"])
            self.assertEqual(rs["summary"]["runs"], 1)
            self.assertEqual(rs["summary"]["tasks_total"], 2)
            self.assertEqual(rs["summary"]["active_dispatches"], 1)
            self.assertEqual(rs["summary"]["open_gates"], 1)
            self.assertEqual(rs["summary"]["queued_merges"], 1)

            # 3. Native `open-fleet mcp --print-config`
            claude_cfg = subprocess.run(
                [str(standalone_bin), "mcp", "--print-config", "claude"],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            ).stdout
            self.assertIn("mcpServers", claude_cfg)
            codex_cfg = subprocess.run(
                [str(standalone_bin), "mcp", "--print-config", "codex"],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            ).stdout
            self.assertIn("[mcp_servers.open-fleet]", codex_cfg)

            # 4. Standalone binary-bound transcript provenance & sign-transcript tamper check
            subprocess.run(["git", "init", "-q", "-b", "main", str(work_dir)], env=env, check=True)
            spec = work_dir / "spec.md"
            spec.write_text("# Spec\n\n- AC-1: works\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(work_dir), "add", "spec.md"], env=env, check=True)
            subprocess.run(["git", "-C", str(work_dir), "commit", "-qm", "spec"], env=env, check=True)
            base_sha = subprocess.run(
                ["git", "-C", str(work_dir), "rev-parse", "HEAD"],
                env=env, capture_output=True, text=True, check=True,
            ).stdout.strip()
            (work_dir / "docs").mkdir()
            (work_dir / "docs" / "review.md").write_text("# Review\n\nAC-1 verified.\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(work_dir), "add", "docs/review.md"], env=env, check=True)
            subprocess.run(["git", "-C", str(work_dir), "commit", "-qm", "report"], env=env, check=True)
            head = subprocess.run(
                ["git", "-C", str(work_dir), "rev-parse", "HEAD"],
                env=env, capture_output=True, text=True, check=True,
            ).stdout.strip()
            digest = "sha256:" + hashlib.sha256(spec.read_bytes()).hexdigest()
            manifest = work_dir / "manifest.json"
            manifest.write_text(json.dumps({
                "unit": "review-it",
                "unit_class": "report-only",
                "base_sha": base_sha,
                "head_sha": head,
                "contract": {"source": "spec.md", "digest": digest, "criterion_ids": ["AC-1"]},
                "criteria": [{"id": "AC-1", "text": "works", "addressed": True}],
                "pr": {"number": 0, "url": "", "reviewed_sha": head},
                "claim": "done",
            }), encoding="utf-8")

            key_path = keys_dir / "coord.key"
            subprocess.run(
                [str(standalone_bin), "dispatch-sign", "gen-key", "--out", str(key_path)],
                cwd=str(work_dir), env=env, capture_output=True, text=True, check=True,
            )
            tr_raw = tmp_path / "verdict.json"
            vf = subprocess.run(
                [str(standalone_bin), "verify", "--manifest", str(manifest),
                 "--contract-source", "spec.md", "--contract-digest", digest,
                 "--unit-class", "report-only", "--no-gh",
                 "--transcript-out", str(tr_raw)],
                cwd=str(work_dir), env=env, capture_output=True, text=True,
            )
            self.assertEqual(vf.returncode, 0, vf.stderr)
            verdict = json.loads(tr_raw.read_text(encoding="utf-8"))
            self.assertEqual(verdict["toolchain"]["engine"], "rust")
            self.assertEqual(verdict["toolchain"]["engine_binary_sha256"], bin_sha)

            tr_signed = tmp_path / "verdict.signed.json"
            signed = subprocess.run(
                [str(standalone_bin), "dispatch-sign", "sign-transcript",
                 "--key", str(key_path), "--transcript", str(tr_raw), "--out", str(tr_signed)],
                cwd=str(work_dir), env=env, capture_output=True, text=True,
            )
            self.assertEqual(signed.returncode, 0, signed.stderr)
            self.assertTrue(tr_signed.is_file())

            # Tampering engine_binary_sha256 must fail closed
            verdict["toolchain"]["engine_binary_sha256"] = "0" * 64
            tr_bad = tmp_path / "verdict.bad.json"
            tr_bad.write_text(json.dumps(verdict), encoding="utf-8")
            bad = subprocess.run(
                [str(standalone_bin), "dispatch-sign", "sign-transcript",
                 "--key", str(key_path), "--transcript", str(tr_bad)],
                cwd=str(work_dir), env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("engine_binary_sha256", bad.stderr)
