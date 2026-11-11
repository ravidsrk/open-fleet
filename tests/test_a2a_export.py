#!/usr/bin/env python3
"""Contract tests for scripts/a2a_export.py (A2A outcome card exporter)."""
import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "a2a_export.py"


def load_module():
    spec = importlib.util.spec_from_file_location("a2a_export", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestA2AExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()

    def test_catalog_export_includes_all_missions(self):
        payload = self.mod.build_catalog_cards()
        self.assertEqual(payload["schema"], "a2a-agent-card-catalog/v1")
        skill_dirs = [
            d.name for d in sorted((ROOT / "skills").iterdir())
            if d.is_dir() and (d / "SKILL.md").is_file()
        ]
        self.assertEqual(payload["count"], len(skill_dirs))
        self.assertEqual([c["name"] for c in payload["cards"]], skill_dirs)

    def test_single_mission_card_binds_evidence_manifest_and_one_way_doors(self):
        card = self.mod.build_catalog_cards(mission="ship-it")
        self.assertEqual(card["schema"], "a2a-agent-card/v1")
        self.assertEqual(card["id"], "open-fleet:ship-it")
        self.assertEqual(card["name"], "ship-it")
        self.assertTrue(card["proof"]["mutating"])
        self.assertEqual(
            set(card["identity"].keys()),
            {"unit", "state_machine", "convergence", "ordering", "parking", "oracle"},
        )
        contracts = card["contracts"]
        self.assertEqual(
            contracts["output"]["evidence_manifest"],
            "runtime/evidence-manifest.md",
        )
        self.assertEqual(contracts["output"]["verifier"], "runtime/scripts/verify.py")
        self.assertEqual(
            contracts["governance"]["one_way_doors_ref"],
            "runtime/one-way-doors.json",
        )
        self.assertIn("merge-to-default", contracts["governance"]["one_way_door_ids"])
        self.assertIn("deploy", contracts["governance"]["one_way_door_ids"])

    def test_report_only_mission_card_uses_report_only_verifier(self):
        card = self.mod.build_catalog_cards(mission="review-it")
        self.assertFalse(card["proof"]["mutating"])
        self.assertEqual(card["contracts"]["output"]["verifier"], "report-only")
        for name in ("review-it", "attest-it"):
            with self.subTest(mission=name):
                card = self.mod.build_catalog_cards(mission=name)
                self.assertFalse(card["proof"]["mutating"])
                self.assertEqual(card["proof"]["class"], "report-only")
                self.assertEqual(card["contracts"]["output"]["verifier"], "report-only")
                std = self.mod.build_standard_card(ENDPOINT, "JSONRPC", mission=name)
                self.assertIn("report-only", std["skills"][0]["tags"])
                self.assertNotIn("planning", std["skills"][0]["tags"])

    def test_planning_mission_cards_use_artifact_verification_semantics(self):
        # #750 C17: map-it and root-cause are planning units (evidence-manifest.md §3), not
        # report-only units; A2A export must classify their class, verifier, and skill tags as
        # planning / artifact-verification rather than report-only.
        for name in ("map-it", "root-cause"):
            with self.subTest(mission=name):
                card = self.mod.build_catalog_cards(mission=name)
                self.assertFalse(card["proof"]["mutating"])
                self.assertEqual(card["proof"]["class"], "planning")
                self.assertEqual(card["contracts"]["output"]["verifier"], "artifact-verification")
                std = self.mod.build_standard_card(ENDPOINT, "JSONRPC", mission=name)
                self.assertIn("planning", std["skills"][0]["tags"])
                self.assertNotIn("report-only", std["skills"][0]["tags"])

    def test_cli_check_and_out_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "a2a-cards.json"
            p_check = subprocess.run(
                [sys.executable, str(SCRIPT), "--check"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_check.returncode, 0, p_check.stderr)
            self.assertIn("A2A_EXPORT=ok", p_check.stdout)

            p_out = subprocess.run(
                [sys.executable, str(SCRIPT), "--mission", "clean-sweep", "--out", str(out_file)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_out.returncode, 0, p_out.stderr)
            written = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(written["id"], "open-fleet:clean-sweep")

    def test_unknown_mission_exits_1(self):
        p = subprocess.run(
            [sys.executable, str(SCRIPT), "--mission", "no-such-mission"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 1)
        self.assertIn("unknown mission", p.stderr)


# A real-looking endpoint for the projection tests: `.internal` is a private-use TLD, so no test
# names a public host, and it is not one of the RFC 2606/6761 placeholders the exporter refuses.
ENDPOINT = "https://fleet.corp.internal/a2a/v1"


class TestA2AStandardBoundary(unittest.TestCase):
    """The offline descriptor claims no transport; --standard-card is validated or refused (#607)."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        cls.schema_mod = cls.mod.a2a_schema
        cls.schema = cls.schema_mod.load_schema()

    def test_offline_descriptor_claims_no_transport_capability(self):
        payload = self.mod.build_catalog_cards()
        self.assertEqual(payload["kind"], "offline-mission-descriptor-catalog")
        for card in payload["cards"]:
            with self.subTest(card["id"]):
                self.assertEqual(card["kind"], "offline-mission-descriptor")
                self.assertEqual(card["schema"], "a2a-agent-card/v1")
                self.assertEqual(set(card["capabilities"].values()), {False})
                for key in ("url", "supportedInterfaces", "securitySchemes",
                            "securityRequirements", "endpoint"):
                    self.assertNotIn(key, card)
                self.assertEqual(self.mod.offline_claim_errors(card), [])

    def test_offline_claim_guard_refuses_a_true_flag_or_a_transport_key(self):
        card = self.mod.build_catalog_cards(mission="ship-it")
        cases = {
            "task history": ({"capabilities": {**card["capabilities"],
                                               "stateTransitionHistory": True}},
                             "capabilities.stateTransitionHistory"),
            "streaming": ({"capabilities": {**card["capabilities"], "streaming": True}},
                          "capabilities.streaming"),
            "endpoint": ({"url": "https://fleet.corp.internal/a2a"}, "url:"),
            "auth": ({"securitySchemes": {}}, "securitySchemes:"),
        }
        for label, (patch, expected) in cases.items():
            with self.subTest(label):
                errs = self.mod.offline_claim_errors({**card, **patch})
                self.assertTrue(any(e.startswith(expected) for e in errs), errs)

    def test_build_refuses_a_descriptor_the_claim_guard_flags(self):
        flagged = ["capabilities.streaming: True, but an offline descriptor serves no A2A task"]
        with mock.patch.object(self.mod, "offline_claim_errors", return_value=flagged):
            with self.assertRaisesRegex(self.mod.ExportError, "makes transport claims"):
                self.mod.build_catalog_cards(mission="ship-it")

    def test_the_offline_descriptor_fails_the_pinned_schema_as_a_transport_card(self):
        card = self.mod.build_catalog_cards(mission="clean-sweep")
        errs = self.schema_mod.card_errors(card)
        self.assertIn("$.supportedInterfaces: required field missing", errs)
        self.assertIn("$.schema: unknown field (not in lf.a2a.v1.AgentCard)", errs)

    def test_standard_card_validates_against_the_pinned_schema(self):
        for mission in (None, "ship-it", "review-it"):
            with self.subTest(mission=mission):
                card = self.mod.build_standard_card(ENDPOINT, "JSONRPC", mission=mission)
                self.assertEqual(self.schema_mod.card_errors(card), [])
                fields = {f.json_name for f in self.schema.messages["AgentCard"].fields}
                self.assertLessEqual(set(card), fields)
                self.assertEqual(card["supportedInterfaces"], [
                    {"url": ENDPOINT, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}])
                self.assertEqual({card["capabilities"][k] for k in (
                    "streaming", "pushNotifications", "extendedAgentCard")}, {False})
                for key in ("securitySchemes", "securityRequirements", "signatures", "provider"):
                    self.assertNotIn(key, card)
        card = self.mod.build_standard_card(ENDPOINT, "HTTP+JSON")
        skills_dirs = sorted(d.name for d in (ROOT / "skills").iterdir()
                             if (d / "SKILL.md").is_file())
        self.assertEqual([s["id"] for s in card["skills"]],
                         [f"open-fleet:{name}" for name in skills_dirs])
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text("utf-8"))
        self.assertEqual(card["version"], plugin["version"])

    def test_mission_fields_live_only_in_the_namespaced_extension(self):
        card = self.mod.build_standard_card(ENDPOINT, "GRPC", mission="ship-it")
        ext = card["capabilities"]["extensions"]
        self.assertEqual(len(ext), 1)
        self.assertEqual(ext[0]["uri"], self.mod.MISSION_EXTENSION_URI)
        self.assertTrue(ext[0]["uri"].startswith("https://github.com/ravidsrk/open-fleet/"))
        self.assertIs(ext[0]["required"], False)
        descriptor = self.mod.build_catalog_cards(mission="ship-it")
        mission = ext[0]["params"]["missions"]["open-fleet:ship-it"]
        for key in ("compatibility", "autonomy", "proof", "identity", "composition", "contracts"):
            self.assertEqual(mission[key], descriptor[key])
        outside = copy.deepcopy(card)
        del outside["capabilities"]["extensions"]
        text = json.dumps(outside)
        for marker in ('"proof"', '"identity"', '"contracts"', '"one_way_door_ids"',
                       '"autonomy"', '"stateTransitionHistory"'):
            self.assertNotIn(marker, text)

    def test_projection_refuses_placeholder_and_unreachable_endpoints(self):
        cases = {
            "": "--endpoint is required",
            "https://agent.example.com/a2a": "reserved placeholder",
            "https://example.org/a2a": "reserved placeholder",
            "https://fleet.test/a2a": "reserved placeholder",
            "https://localhost/a2a": "reserved placeholder",
            "https://127.0.0.1/a2a": "reserved placeholder",
            "https://[::1]/a2a": "reserved placeholder",
            "http://fleet.corp.internal/a2a": "expected an absolute https URL",
            "fleet.corp.internal/a2a": "expected an absolute https URL",
            "https://user:pw@fleet.corp.internal/a2a": "credentials do not belong",
            "https://fleet.corp.internal:99999/a2a": "malformed URL",
        }
        for endpoint, expected in cases.items():
            with self.subTest(endpoint):
                with self.assertRaises(self.mod.ExportError) as ctx:
                    self.mod.build_standard_card(endpoint, "JSONRPC")
                self.assertIn(expected, str(ctx.exception))
        self.assertTrue(self.mod.build_standard_card("fleet.corp.internal:443", "GRPC"))
        for endpoint in ("fleet.corp.internal", "localhost:443", "fleet.corp.internal:0"):
            with self.subTest(grpc=endpoint):
                with self.assertRaises(self.mod.ExportError):
                    self.mod.build_standard_card(endpoint, "GRPC")

    def test_projection_publishes_a_bracketed_ipv6_grpc_endpoint(self):
        # PR #636 review: endpoint_errors accepted this address and the card check then refused
        # it, so no card could be published for an IPv6 gRPC endpoint.
        endpoint = "[2606:4700:4700::1111]:443"
        card = self.mod.build_standard_card(endpoint, "GRPC", mission="ship-it")
        self.assertEqual(card["supportedInterfaces"][0]["url"], endpoint)
        self.assertEqual(self.schema_mod.card_errors(card), [])
        for bad, expected in (("[::1]:443", "reserved placeholder or loopback"),
                              ("2606:4700:4700::1111:443", "host:port"),
                              ("[2606:4700::1111]:0", "host:port")):
            with self.subTest(bad=bad):
                with self.assertRaises(self.mod.ExportError) as ctx:
                    self.mod.build_standard_card(bad, "GRPC")
                self.assertIn(expected, str(ctx.exception))

    def test_projection_refuses_an_unknown_binding_or_another_protocol_major(self):
        with self.assertRaisesRegex(self.mod.ExportError, "--binding 'SOAP'"):
            self.mod.build_standard_card(ENDPOINT, "SOAP")
        with self.assertRaisesRegex(self.mod.ExportError, "the major must be 1"):
            self.mod.build_standard_card(ENDPOINT, "JSONRPC", protocol_version="0.3")
        with self.assertRaisesRegex(self.mod.ExportError, "expected Major.Minor"):
            self.mod.build_standard_card(ENDPOINT, "JSONRPC", protocol_version="1")

    def test_projection_errors_catch_a_claim_the_schema_allows(self):
        card = self.mod.build_standard_card(ENDPOINT, "JSONRPC", mission="ship-it")
        cases = {
            "streaming": lambda c: c["capabilities"].update(streaming=True),
            "auth": lambda c: c.update(securitySchemes={}),
            "extension dropped": lambda c: c["capabilities"].update(extensions=[]),
            "extension required": lambda c: c["capabilities"]["extensions"][0].update(required=True),
        }
        for label, fn in cases.items():
            with self.subTest(label):
                doctored = copy.deepcopy(card)
                fn(doctored)
                self.assertTrue(self.mod.projection_errors(doctored, self.schema))

    def test_cli_standard_card_needs_a_supplied_endpoint_and_binding(self):
        def run(*args):
            return subprocess.run([sys.executable, str(SCRIPT), *args],
                                  capture_output=True, text=True)

        for args in (["--standard-card"], ["--standard-card", "--endpoint", ENDPOINT],
                     ["--standard-card", "--binding", "JSONRPC"],
                     ["--endpoint", ENDPOINT], ["--binding", "GRPC"]):
            with self.subTest(args=args):
                p = run(*args)
                self.assertEqual(p.returncode, 2, p.stdout)
                self.assertEqual(p.stdout, "")
        placeholder = run("--standard-card", "--endpoint", "https://a.example.com/x",
                          "--binding", "JSONRPC")
        self.assertEqual(placeholder.returncode, 1)
        self.assertEqual(placeholder.stdout, "")
        ok = run("--standard-card", "--endpoint", ENDPOINT, "--binding", "JSONRPC",
                 "--mission", "review-it")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(self.schema_mod.card_errors(json.loads(ok.stdout)), [])

    def test_docs_field_table_matches_the_pinned_schema_and_the_descriptor(self):
        rows, extra = self.mod.field_comparison()
        required = [r[0] for r in rows if r[1] == "yes"]
        self.assertEqual(required, ["name", "description", "supportedInterfaces", "version",
                                    "capabilities", "defaultInputModes", "defaultOutputModes",
                                    "skills"])
        status = {r[0]: r[2] for r in rows}
        self.assertEqual(status["capabilities"], "present, invalid")
        self.assertEqual(status["name"], "present, valid")
        self.assertEqual(status["supportedInterfaces"], "missing")
        self.assertEqual([k for k, _, _ in extra], ["schema", "kind", "id", "compatibility",
                                                    "autonomy", "proof", "identity",
                                                    "composition", "contracts"])
        doc = (ROOT / "docs" / "a2a-export.md").read_text(encoding="utf-8")
        for line in self.mod.render_comparison(rows, extra):
            if line:
                self.assertIn(line + "\n", doc)


if __name__ == "__main__":
    unittest.main()
