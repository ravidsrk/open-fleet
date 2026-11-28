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
