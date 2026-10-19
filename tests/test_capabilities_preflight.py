#!/usr/bin/env python3
"""Contract and negative-control tests for Wave 0 & Issue #586.

Covers:
1. `runtime/providers/capabilities.json` completeness and invariants across all
   8 capabilities, 14 RPI providers, and every catalog mission.
2. `runtime/scripts/preflight.py` capability-based enforcement (`--runtime`,
   `OPEN_FLEET_RUNTIME`, `ORCA_FLEET_RUNTIME`, `--strict-native-capabilities`,
   `--json`), including negative controls (`--mission pin-it --runtime posix`
   failing closed with exit 2 and `missing_capability: cap:orca-self-audit`).
3. Wave 0 neutral env var precedence (`OPEN_FLEET_EGRESS_LEDGER` in `egress.py`,
   `OPEN_FLEET_DECISIONS_FILE` in `decisions.py`, `OPEN_FLEET_GATE_MANIFEST` and
   `OPEN_FLEET_UNIT_CLASS` in `verify-gate.sh`).
4. `docs/runtimes.md` and `skills/*/SKILL.md` multi-runtime compatibility.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES_JSON = ROOT / "runtime" / "providers" / "capabilities.json"
PREFLIGHT = ROOT / "runtime" / "scripts" / "preflight.py"
EGRESS = ROOT / "runtime" / "scripts" / "egress.py"
DECISIONS = ROOT / "runtime" / "scripts" / "decisions.py"
VERIFY_GATE = ROOT / "runtime" / "scripts" / "verify-gate.sh"
SKILLS_DIR = ROOT / "skills"
RUNTIMES_DOC = ROOT / "docs" / "runtimes.md"
DOCS_README = ROOT / "docs" / "README.md"

_pf_spec = importlib.util.spec_from_file_location("preflight", PREFLIGHT)
preflight = importlib.util.module_from_spec(_pf_spec)
_pf_spec.loader.exec_module(preflight)

_eg_spec = importlib.util.spec_from_file_location("egress", EGRESS)
egress = importlib.util.module_from_spec(_eg_spec)
_eg_spec.loader.exec_module(egress)

_dec_spec = importlib.util.spec_from_file_location("decisions", DECISIONS)
decisions = importlib.util.module_from_spec(_dec_spec)
_dec_spec.loader.exec_module(decisions)

EXPECTED_CAPABILITIES = {
    "cap:core-orchestration",
    "cap:sandbox-vm",
    "cap:session-search",
    "cap:browser",
    "cap:mobile-emulator",
    "cap:issue-tracker",
    "cap:scheduler",
    "cap:orca-self-audit",
}

EXPECTED_PROVIDERS = {
    "orca",
    "posix",
    "overstory",
    "t3code",
    "ao",
    "superset",
    "gastown",
    "worktrunk",
    "jcode-swarm",
    "emdash",
    "vibe-kanban",
    "paperclip",
    "multiclaude",
    "openhands",
}


def run_preflight(*argv, cwd=None, env=None):
    import contextlib
    import io
    from unittest import mock

    run_env = dict(os.environ if env is None else env)
    if env is None:
        run_env.pop("OPEN_FLEET_RUNTIME", None)
        run_env.pop("ORCA_FLEET_RUNTIME", None)
    with mock.patch.dict(os.environ, run_env, clear=True):
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            try:
                preflight.main(list(argv))
            except SystemExit:
                pass
    return subprocess.run(
        [sys.executable, str(PREFLIGHT), *argv],
        capture_output=True,
        text=True,
        cwd=cwd or ROOT,
        env=run_env,
        timeout=60,
    )


class TestCapabilitiesMatrixSchema(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(CAPABILITIES_JSON.read_text(encoding="utf-8"))

    def test_declares_all_eight_capabilities(self):
        caps = self.data.get("capabilities", {})
        self.assertEqual(set(caps.keys()), EXPECTED_CAPABILITIES)
        for cap_id, meta in caps.items():
            self.assertTrue(meta.get("description"), f"{cap_id} lacks description")

    def test_declares_all_fourteen_providers_and_restricts_orca_self_audit(self):
        providers = self.data.get("providers", {})
        self.assertEqual(set(providers.keys()), EXPECTED_PROVIDERS)
        for name, p in providers.items():
            with self.subTest(provider=name):
                native = set(p.get("native_capabilities", []))
                fallback = set(p.get("fallback_capabilities", []))
                harnesses = p.get("supported_harnesses", [])
                self.assertIn("cap:core-orchestration", native)
                self.assertTrue(native.issubset(EXPECTED_CAPABILITIES))
                self.assertTrue(fallback.issubset(EXPECTED_CAPABILITIES))
                self.assertEqual(native & fallback, set(), f"{name} overlaps native and fallback")
                self.assertGreaterEqual(len(harnesses), 10)
                if name == "orca":
                    self.assertIn("cap:orca-self-audit", native)
                else:
                    self.assertNotIn("cap:orca-self-audit", native | fallback)
                # Every non-self-audit capability is available natively or via portable fallback.
                self.assertEqual(
                    (native | fallback) - {"cap:orca-self-audit"},
                    EXPECTED_CAPABILITIES - {"cap:orca-self-audit"},
                )

    def test_declares_every_catalog_mission(self):
        missions = self.data.get("missions", {})
        on_disk = {
            d.name
            for d in SKILLS_DIR.iterdir()
            if d.is_dir() and not d.name.startswith((".", "_")) and (d / "SKILL.md").is_file()
        }
        self.assertEqual(set(missions.keys()), on_disk)
        for m, entry in missions.items():
            with self.subTest(mission=m):
                req = entry.get("required", [])
                opt = entry.get("optional", [])
                self.assertIn("cap:core-orchestration", req)
                self.assertTrue(set(req).issubset(EXPECTED_CAPABILITIES))
                self.assertTrue(set(opt).issubset(EXPECTED_CAPABILITIES))
        self.assertIn("cap:orca-self-audit", missions["pin-it"]["required"])
        self.assertIn("cap:mobile-emulator", missions["field-test-it"]["required"])
        self.assertIn("cap:sandbox-vm", missions["offload-it"]["required"])


class TestPreflightCapabilitiesEnforcement(unittest.TestCase):
    def test_pin_it_on_posix_fails_closed_with_missing_capability(self):
        r = run_preflight("--mission", "pin-it", "--runtime", "posix")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("missing_capability: cap:orca-self-audit", r.stderr)

    def test_pin_it_on_posix_json_output_includes_missing_capability(self):
        r = run_preflight("--mission", "pin-it", "--runtime", "posix", "--json")
        self.assertEqual(r.returncode, 2, r.stderr)
        payload = json.loads(r.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["missing_capability"], "cap:orca-self-audit")
        self.assertIn("cap:orca-self-audit", payload["missing_capabilities"])

    def test_pin_it_on_orca_passes(self):
        r = run_preflight("--mission", "pin-it", "--runtime", "orca", "--mode", "readonly")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("preflight: OK", r.stdout)

    def test_ship_it_on_posix_passes(self):
        r = run_preflight("--mission", "ship-it", "--runtime", "posix", "--mode", "readonly")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("preflight: OK", r.stdout)

    def test_runtime_write_mode_still_requires_base(self):
        r = run_preflight("--mission", "ship-it", "--runtime", "posix", "--mode", "write")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("--base", r.stderr)

    def test_all_general_missions_pass_across_all_providers(self):
        data = json.loads(CAPABILITIES_JSON.read_text(encoding="utf-8"))
        for provider in EXPECTED_PROVIDERS:
            for mission in data["missions"]:
                if mission == "pin-it" and provider != "orca":
                    refusal, info = preflight._capabilities_refusal(mission, provider)
                    self.assertIsNotNone(refusal)
                    self.assertEqual(info["missing_capability"], "cap:orca-self-audit")
                else:
                    refusal, info = preflight._capabilities_refusal(mission, provider)
                    self.assertIsNone(refusal, f"{mission} failed on {provider}: {refusal}")
                    self.assertTrue(info["ok"])

    def test_strict_native_capabilities_mode(self):
        # offload-it requires cap:sandbox-vm: fallback on posix, native on openhands/orca
        r_fallback = run_preflight(
            "--mission", "offload-it", "--runtime", "posix", "--mode", "readonly"
        )
        self.assertEqual(r_fallback.returncode, 0, r_fallback.stderr)

        r_strict_fail = run_preflight(
            "--mission", "offload-it", "--runtime", "posix", "--strict-native-capabilities"
        )
        self.assertEqual(r_strict_fail.returncode, 2, r_strict_fail.stderr)
        self.assertIn("missing_capability: cap:sandbox-vm", r_strict_fail.stderr)

        r_strict_ok = run_preflight(
            "--mission",
            "offload-it",
            "--runtime",
            "openhands",
            "--strict-native-capabilities",
            "--mode",
            "readonly",
        )
        self.assertEqual(r_strict_ok.returncode, 0, r_strict_ok.stderr)

    def test_unknown_runtime_fails_closed(self):
        r = run_preflight("--mission", "ship-it", "--runtime", "not-a-provider")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("unknown_runtime", r.stderr)

    def test_env_runtime_precedence_open_fleet_over_orca(self):
        env_posix = {**os.environ, "OPEN_FLEET_RUNTIME": "posix", "ORCA_FLEET_RUNTIME": "orca"}
        r_fail = run_preflight("--mission", "pin-it", "--mode", "readonly", env=env_posix)
        self.assertEqual(r_fail.returncode, 2, r_fail.stderr)
        self.assertIn("missing_capability: cap:orca-self-audit", r_fail.stderr)

        env_orca = {**os.environ, "OPEN_FLEET_RUNTIME": "orca", "ORCA_FLEET_RUNTIME": "posix"}
        r_ok = run_preflight("--mission", "pin-it", "--mode", "readonly", env=env_orca)
        self.assertEqual(r_ok.returncode, 0, r_ok.stderr)

    def test_malformed_capabilities_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp)
            (fake_root / "runtime" / "providers").mkdir(parents=True)
            (fake_root / "runtime" / "providers" / "capabilities.json").write_text(
                "{corrupt-json", encoding="utf-8"
            )
            env = {**os.environ, "OPEN_FLEET_ROOT": str(fake_root)}
            r = run_preflight("--mission", "ship-it", "--runtime", "posix", env=env)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn("capabilities.json is malformed", r.stderr)


class TestWave0NeutralEnvVars(unittest.TestCase):
    def test_open_fleet_egress_ledger_works_and_outranks_orca_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "open-fleet-egress.jsonl"
            legacy = Path(tmp) / "orca-egress.jsonl"
            env = {
                **os.environ,
                "OPEN_FLEET_EGRESS_LEDGER": str(primary),
                "ORCA_EGRESS_LEDGER": str(legacy),
            }
            w = subprocess.run(
                [
                    sys.executable,
                    str(EGRESS),
                    "write",
                    "--sink",
                    "pr-open",
                    "--host",
                    "github.com",
                    "--payload-class",
                    "pr-body",
                    "--consent",
                    "grant:pr-open",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(w.returncode, 0, w.stderr)
            self.assertTrue(primary.is_file())
            self.assertFalse(legacy.exists())

            v = subprocess.run(
                [sys.executable, str(EGRESS), "verify"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(v.returncode, 0, v.stderr)

    def test_open_fleet_decisions_file_works_and_outranks_orca_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            primary = Path(tmp) / "OPEN_DECISIONS.md"
            legacy = Path(tmp) / "ORCA_DECISIONS.md"
            env = {
                **os.environ,
                "OPEN_FLEET_DECISIONS_FILE": str(primary),
                "ORCA_DECISIONS_FILE": str(legacy),
            }
            a = subprocess.run(
                [
                    sys.executable,
                    str(DECISIONS),
                    "append",
                    "--id",
                    "gate-wave0",
                    "--class",
                    "mechanical",
                    "--answer",
                    "ok",
                    "--why",
                    "verified neutral env precedence",
                ],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(a.returncode, 0, a.stderr)
            self.assertTrue(primary.is_file())
            self.assertFalse(legacy.exists())

            c = subprocess.run(
                [sys.executable, str(DECISIONS), "check"],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(c.returncode, 0, c.stderr)

    def test_verify_gate_honors_open_fleet_gate_manifest_and_unit_class(self):
        script_text = VERIFY_GATE.read_text(encoding="utf-8")
        self.assertIn("OPEN_FLEET_GATE_MANIFEST", script_text)
        self.assertIn("OPEN_FLEET_UNIT_CLASS", script_text)
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nonexistent-manifest.json"
            env = {
                **os.environ,
                "OPEN_FLEET_GATE_MANIFEST": str(missing),
                "OPEN_FLEET_UNIT_CLASS": "report-only",
            }
            r = subprocess.run(
                ["sh", str(VERIFY_GATE)],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertEqual(r.returncode, 2)
            self.assertIn(str(missing), r.stderr)


class TestRuntimesDocumentationAndCompatibility(unittest.TestCase):
    def test_runtimes_doc_exists_and_is_linked_from_docs_readme(self):
        self.assertTrue(RUNTIMES_DOC.is_file(), "docs/runtimes.md is missing")
        text = RUNTIMES_DOC.read_text(encoding="utf-8")
        for provider in EXPECTED_PROVIDERS:
            self.assertIn(f"`{provider}`", text)
        for cap in EXPECTED_CAPABILITIES:
            self.assertIn(f"`{cap}`", text)
        readme = DOCS_README.read_text(encoding="utf-8")
        self.assertIn("(runtimes.md)", readme)

    def test_general_missions_declare_open_fleet_rpi_in_compatibility(self):
        for d in sorted(SKILLS_DIR.iterdir()):
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            text = (d / "SKILL.md").read_text(encoding="utf-8")
            if d.name == "pin-it":
                self.assertIn("Orca runtime + orchestration skill (Orca CLI)", text)
            else:
                self.assertIn("open-fleet RPI runtime (Orca, posix,", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
