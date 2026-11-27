#!/usr/bin/env python3
"""Contract tests for the Wave 1 Rust engine workspace, launcher, and npm packaging."""
import json
import os
import stat
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class RustEnginePackaging(unittest.TestCase):
    def test_engine_version_matches_workspace_and_cli_packages(self):
        version = (ROOT / "ENGINE_VERSION").read_text(encoding="utf-8").strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")

        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(cargo["workspace"]["package"]["version"], version)
        self.assertEqual(
            cargo["workspace"]["members"],
            ["crates/of-common", "crates/of-floor", "crates/of-install", "crates/of-cli"],
        )
        self.assertTrue((ROOT / "Cargo.lock").is_file(), "Cargo.lock must be committed")

        cli_pkg = json.loads((ROOT / "cli" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(cli_pkg["version"], version)
        self.assertEqual(cli_pkg["bin"], {"open-fleet": "bin/open-fleet.js"})

        opt_deps = cli_pkg.get("optionalDependencies", {})
        self.assertEqual(len(opt_deps), 5)
        for pkg_name, pkg_ver in opt_deps.items():
            self.assertEqual(pkg_ver, version, f"{pkg_name} version mismatch")

        platform_dirs = sorted((ROOT / "cli" / "platform-packages").iterdir())
        self.assertEqual(
            [p.name for p in platform_dirs],
            ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "windows-x64"],
        )
        for pdir in platform_dirs:
            ppkg = json.loads((pdir / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(ppkg["version"], version)
            self.assertIn(ppkg["name"], opt_deps)

    def test_launcher_scripts_are_executable_and_verify_sha256(self):
        sh_launcher = ROOT / "scripts" / "open-fleet"
        js_launcher = ROOT / "cli" / "bin" / "open-fleet.js"
        for launcher in (sh_launcher, js_launcher):
            self.assertTrue(launcher.is_file(), f"missing {launcher}")
            mode = launcher.stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{launcher} is not executable")

        sh_text = sh_launcher.read_text(encoding="utf-8")
        self.assertIn("sha256", sh_text.lower())
        self.assertIn("ENGINE_VERSION", sh_text)
        self.assertIn("OPEN_FLEET_BIN", sh_text)

        js_text = js_launcher.read_text(encoding="utf-8")
        self.assertIn("sha256", js_text.lower())
        self.assertIn("OPEN_FLEET_BIN", js_text)

    def test_docs_and_contract_exist(self):
        contract = (ROOT / "CLI-CONTRACT.md").read_text(encoding="utf-8")
        self.assertIn("open-fleet floor", contract)
        self.assertIn("open-fleet init", contract)
        self.assertIn("open-fleet doctor", contract)

        engine_doc = (ROOT / "docs" / "ENGINE.md").read_text(encoding="utf-8")
        self.assertIn("of-floor", engine_doc)
        self.assertIn("scripts/rust_floor_oracle.py", engine_doc)

    def test_compiled_binary_smoke_if_present(self):
        ext = ".exe" if os.name == "nt" else ""
        binary = ROOT / "target" / "release" / f"open-fleet{ext}"
        if not binary.is_file():
            return
        version = (ROOT / "ENGINE_VERSION").read_text(encoding="utf-8").strip()
        r = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True)
        self.assertEqual(r.stdout.strip(), f"open-fleet {version}")

        doc = subprocess.run(
            [str(binary), "doctor", "--repo", str(ROOT), "--json"],
            capture_output=True, text=True, check=True,
        )
        payload = json.loads(doc.stdout)
        self.assertEqual(payload["engine_version"], version)
        self.assertTrue(payload["git_available"])
        self.assertGreaterEqual(payload["missions_count"], 22)

        with tempfile.TemporaryDirectory(prefix="of-init-smoke-") as tmp:
            init = subprocess.run(
                [str(binary), "init", "--repo", str(ROOT), "--home", tmp,
                 "--harness", "claude,cursor", "--json"],
                capture_output=True, text=True, check=True,
            )
            res = json.loads(init.stdout)
            self.assertTrue(res["ok"])
            self.assertEqual([t["harness"] for t in res["targets"]], ["claude", "cursor"])
            self.assertGreaterEqual(res["targets"][0]["missions_installed"], 22)
            self.assertTrue(res["targets"][0]["hook_wired"])
            self.assertTrue((Path(tmp) / ".claude" / "skills" / "ship-it").is_symlink())
            self.assertTrue((Path(tmp) / ".cursor" / "skills" / "ship-it").is_symlink())
            self.assertTrue((Path(tmp) / ".claude" / "settings.json").is_file())


if __name__ == "__main__":
    unittest.main()
