"""Copy-install acceptance tests with independently named protocol dependencies."""
import importlib.util
import base64
import hashlib
import json
import os
import re
import shlex
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bundle", ROOT / "scripts" / "bundle.py")
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)
_RECORDS = []


def setUpModule():
    # Build records go to a scratch directory, never the source checkout's git directory.
    records = tempfile.TemporaryDirectory()
    patcher = mock.patch.dict(os.environ, {bundle.RECORDS_ENV: records.name})
    patcher.start()
    _RECORDS.extend([patcher, records])


def tearDownModule():
    patcher, records = _RECORDS
    patcher.stop()
    records.cleanup()


class BundleClosureTests(unittest.TestCase):
    def run_command(self, cwd, *args):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("PYTHON", "GIT_"))}
        return subprocess.run(args, cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=30)

    def test_transitive_protocol_calls_are_installed(self):
        # Audit witnesses: remediate-finding calls build-change; release calls observe.
        with tempfile.TemporaryDirectory() as tmp:
            built, problems = bundle.build(tmp)
            self.assertEqual((built, problems), (22, []))
            for mission, dependency in (("pin-it", "build-change"),
                                        ("migrate-it", "observe"),
                                        ("review-it", "build-change")):
                with self.subTest(mission=mission, dependency=dependency):
                    root = Path(tmp) / "skills" / mission
                    self.assertTrue((root / "references" / f"{dependency}.md").is_file())
                    self.assertIn(f"`{dependency}`", (root / "references/README.md").read_text())

    def test_installed_entry_points_work_without_source_checkout(self):
        with tempfile.TemporaryDirectory() as install_tmp:
            installed = Path(install_tmp) / "copied mission"
            with tempfile.TemporaryDirectory() as build_tmp:
                bundle.build(build_tmp)
                shutil.copytree(Path(build_tmp) / "skills/clean-sweep", installed)
            # Build output is gone; isolated Python cannot import from the checkout.
            project = Path(install_tmp) / "project"
            project.mkdir()
            for args in (("init", "-b", "main"),
                         ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                          "commit", "--allow-empty", "-m", "fixture"),
                         ("branch", "integration")):
                result = self.run_command(project, "git", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
            for name in ("verify.py", "evidence-run.py", "preflight.py"):
                entry = installed / "runtime/scripts" / name
                self.assertTrue(entry.is_file(), str(entry))
                self.assertEqual(entry.stat().st_mode & 0o111, 0o111,
                                 f"{name} must retain its executable interface")
                result = self.run_command(project, str(entry), "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)
            script = str(installed / "runtime/scripts/preflight.py")
            for base, expected in (("integration", 0), ("main", 2)):
                result = self.run_command(project, sys.executable, "-I", script,
                                          "--offline", "--base", base, "--default", "main")
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            manifest = Path(install_tmp) / "evidence.json"
            # Execute the protocol's recorder invocation VERBATIM. A worker following the
            # protocol literally substitutes no paths, so the bundled line has to already name
            # the installed runtime; only the placeholders are filled (#322 review, P1).
            protocol = (installed / "references/build-change.md").read_text()
            invocation = next(
                line for line in protocol.splitlines()
                if line.startswith('"$OPEN_FLEET_ROOT/runtime/scripts/evidence-run.py" --label'))
            invocation = invocation.replace("<m.json>", '"$2"').replace(
                "<criterion-bound command>", shlex.join(
                    [sys.executable, "-I", "-c", "print('installed recorder executed')"]))
            self.assertFalse((project / "runtime").exists())
            result = self.run_command(
                project, "/bin/sh", "-c", "OPEN_FLEET_ROOT=$1\n" + invocation,
                "installed-flow", str(installed), str(manifest))
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads(manifest.read_text())["commands"][0]
            tree = self.run_command(project, "git", "rev-parse", "HEAD^{tree}").stdout.strip()
            self.assertEqual(record["wtree"], tree)
            self.assertEqual(record["exit"], 0)
            self.assertNotIn("WARNING", result.stderr)
            for relative in ("runtime/scripts/diff_scope.py", "runtime/scripts/ed25519.py",
                             "runtime/one-way-doors.json", "runtime/pins.json"):
                self.assertEqual((installed / relative).read_bytes(), (ROOT / relative).read_bytes())
            index = (installed / "references/README.md").read_text()
            for name in ("verify.py", "evidence-run.py", "preflight.py"):
                self.assertIn(f'"$OPEN_FLEET_ROOT/runtime/scripts/{name}"', index)
            self.assert_installed_verification(installed, project, manifest)

    def assert_installed_verification(self, installed, project, manifest):
        # A real local report-only range can pass without any review claim or network call.
        base = self.run_command(project, "git", "rev-parse", "HEAD").stdout.strip()
        (project / "report.md").write_text("Fixture report, no production changes.\n")
        self.assertEqual(self.run_command(project, "git", "add", "report.md").returncode, 0)
        result = self.run_command(project, "git", "-c", "user.name=Fixture",
                                  "-c", "user.email=fixture@example.invalid",
                                  "commit", "-m", "fixture report")
        self.assertEqual(result.returncode, 0, result.stderr)
        head = self.run_command(project, "git", "rev-parse", "HEAD").stdout.strip()
        contract = project / "contract.json"
        contract.write_text('{"criterion_ids": ["AC-1"]}\n')
        digest = "sha256:" + hashlib.sha256(contract.read_bytes()).hexdigest()
        evidence = {"unit": "installed-fixture", "base_sha": base, "head_sha": head,
                    "contract": {"digest": digest, "criterion_ids": ["AC-1"]},
                    "criteria": [{"id": "AC-1", "addressed": True}]}
        manifest.write_text(json.dumps(evidence))
        command = (sys.executable, "-I", str(installed / "runtime/scripts/verify.py"),
                   "--manifest", str(manifest), "--contract-source", "contract.json",
                   "--contract-digest", digest)
        result = self.run_command(project, *command, "--unit-class", "report-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verify: OK", result.stdout)
        self.assertIn("report-only (unsupervised)", result.stdout)
        evidence["criteria"] = []
        manifest.write_text(json.dumps(evidence))
        result = self.run_command(project, *command, "--unit-class", "report-only")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("authoritative criteria not addressed", result.stderr)
        # Mutation mode exercises diff_scope's lazy load through real changed-path binding.
        # Its missing review gate must remain RED; this is never a production approval.
        evidence["criteria"] = [{"id": "AC-1", "addressed": True}]
        (project / "control.txt").write_text(result.stderr)
        evidence["negative_control"] = {"tool": "revert", "paths": ["report.md"],
                                        "result": "RED", "artifact": "control.txt"}
        evidence["artifacts"] = [{"path": "control.txt", "sha256": hashlib.sha256(
            (project / "control.txt").read_bytes()).hexdigest()}]
        manifest.write_text(json.dumps(evidence))
        # Public RFC 8032 test-vector key, deliberately invalid signature, no private key.
        (project / "public.txt").write_text(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        (project / "dispatch.json").write_text(json.dumps(
            {"record": {}, "sig_b64": base64.b64encode(bytes(64)).decode()}))
        args = (*command, "--unit-class", "mutation", "--dispatch-record", "dispatch.json",
                "--dispatch-pubkey", "public.txt")
        result = self.run_command(project, *args)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("signature INVALID", result.stderr)
        self.assertIn("no pr.number", result.stderr)
        self.assertNotIn("could not be loaded", result.stderr)
        self.assertNotIn("negative_control.paths", result.stderr)
        for helper, diagnostic in (("diff_scope.py", "diff_scope.py could not be loaded"),
                                   ("ed25519.py", "Ed25519 verifier is unavailable")):
            path = installed / "runtime/scripts" / helper
            saved = path.read_bytes()
            path.unlink()
            try:
                result = self.run_command(project, *args)
                self.assertEqual(result.returncode, 2)
                self.assertIn(diagnostic, result.stderr)
            finally:
                path.write_bytes(saved)

    def test_the_installed_first_run_contains_its_processes_from_the_bundle_alone(self):
        # first_run.py ships in the bundle and loads its process containment beside itself: the
        # marker sweep and host probe (runtime/scripts/containment.py) ship with it (PR #668 review).
        self.assertIn("runtime/scripts/containment.py", bundle.REQUIRED_RUNTIME)
        with tempfile.TemporaryDirectory() as install_tmp:
            installed = Path(install_tmp) / "copied mission"
            with tempfile.TemporaryDirectory() as build_tmp:
                bundle.build(build_tmp)
                shutil.copytree(Path(build_tmp) / "skills/clean-sweep", installed)
            scripts = installed / "runtime/scripts"
            self.assertTrue((scripts / "containment.py").is_file())
            probe = ("import importlib.util, sys; s = importlib.util.spec_from_file_location('fr', sys.argv[1]); "
                     "m = importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                     "print(m.containment.__file__, m.containment.CALL_MARKER)")
            result = self.run_command(install_tmp, sys.executable, "-I", "-c", probe, str(scripts / "first_run.py"))
            self.assertEqual(result.returncode, 0, result.stderr)
            loaded, marker = result.stdout.strip().rsplit(" ", 1)
            self.assertEqual((Path(loaded).resolve(), marker), ((scripts / "containment.py").resolve(), "OF_CALL_ID"))

    def test_missing_runtime_helper_data_or_transitive_protocol_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle.build(tmp)
            root = Path(tmp) / "skills/pin-it"
            self.assertEqual(bundle.dangling(root), [])

            for relative in ("runtime/scripts/verify.py", "runtime/scripts/wtree.sh",
                             "runtime/scripts/ed25519.py", "runtime/one-way-doors.json",
                             "runtime/pins.json", "references/build-change.md"):
                with self.subTest(missing=relative):
                    path = root / relative
                    # Also exercises the original bug, where runtime files were never copied.
                    original = path.read_bytes() if path.exists() else None
                    if original is not None:
                        path.unlink()
                    try:
                        problems = bundle.dangling(root)
                        self.assertTrue(any(Path(relative).name in p for p in problems), problems)
                    finally:
                        if original is not None:
                            path.write_bytes(original)
            self.assertEqual(bundle.dangling(root), [])

    def test_bundled_docs_name_the_installed_runtime_not_the_project_checkout(self):
        # A worker runs these from the PROJECT repository, where `runtime/scripts/` is absent or
        # belongs to someone else, and follows the protocol literally (#322 review, P1).
        with tempfile.TemporaryDirectory() as tmp:
            bundle.build(tmp)
            for mission in ("ship-it", "pin-it", "clean-sweep"):
                root = Path(tmp) / "skills" / mission
                shipped = bundle.shipped_runtime(root)
                self.assertIn("runtime/scripts/verify.py", shipped)
                self.assertEqual(bundle.unbound_runtime(root, shipped), [])
                for document in sorted(root.rglob("*.md")):
                    with self.subTest(document=document.relative_to(root).as_posix()):
                        for match in bundle.RUNTIME_PATH_RE.finditer(document.read_text()):
                            self.assertNotIn(match.group(1), shipped)
            template = (Path(tmp) / "skills/ship-it/docs/runs/TEMPLATE.md").read_text()
            self.assertIn('`python3 "$OPEN_FLEET_ROOT/runtime/scripts/inventory.py" write <report>`',
                          template)
            # The manual-substitution instruction would send the reader hunting for what is gone.
            self.assertNotIn("Replace every `runtime/scripts/<file>` invocation", template)
            # The source template still spells the pre-rename root; the copy names one root only.
            self.assertNotIn("ORCA_FLEET_ROOT", template)
            self.assertIn("`OPEN_FLEET_ROOT` to the absolute catalog clone", template)
            self.assertIn("already name", template)
            self.assertIn('"$OPEN_FLEET_ROOT/runtime/scripts/preflight.py"',
                          (Path(tmp) / "skills/ship-it/SKILL.md").read_text())

    def test_a_runtime_path_that_reverts_to_the_repository_form_fails_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle.build(tmp)
            root = Path(tmp) / "skills/ship-it"
            shipped = bundle.shipped_runtime(root)
            document = root / "references/build-change.md"
            saved = document.read_text()
            document.write_text(saved.replace('"$OPEN_FLEET_ROOT/runtime/scripts/verify.py"',
                                              "runtime/scripts/verify.py", 1))
            try:
                problems = bundle.unbound_runtime(root, shipped)
                self.assertTrue(any("references/build-change.md" in p and "verify.py" in p
                                    for p in problems), problems)
            finally:
                document.write_text(saved)
            self.assertEqual(bundle.unbound_runtime(root, shipped), [])

    def test_absolutize_leaves_unshipped_paths_and_directory_prose_alone(self):
        shipped = {"runtime/scripts/verify.py", "runtime/pins.json"}
        # Claiming an unshipped path lives inside the mission is a claim the reader cannot check.
        self.assertEqual(
            bundle.absolutize_runtime("run runtime/scripts/absent.py now", shipped),
            "run runtime/scripts/absent.py now")
        # `runtime/scripts/` with no filename is prose about the directory, not an invocation.
        self.assertEqual(bundle.absolutize_runtime("`runtime/scripts/` never interpolates", shipped),
                         "`runtime/scripts/` never interpolates")
        self.assertEqual(bundle.absolutize_runtime("see runtime/*.md and runtime/scripts/,", shipped),
                         "see runtime/*.md and runtime/scripts/,")
        self.assertEqual(bundle.absolutize_runtime("python3 runtime/scripts/verify.py --help", shipped),
                         'python3 "$OPEN_FLEET_ROOT/runtime/scripts/verify.py" --help')
        # A link resolves to nothing beside the copy; replace it whole, and only once.
        self.assertEqual(bundle.absolutize_runtime("[the verifier](runtime/scripts/verify.py)", shipped),
                         '`"$OPEN_FLEET_ROOT/runtime/scripts/verify.py"`')
        self.assertEqual(bundle.absolutize_runtime("[pins](../../runtime/pins.json)", shipped),
                         '`"$OPEN_FLEET_ROOT/runtime/pins.json"`')
        once = bundle.absolutize_runtime("python3 runtime/scripts/verify.py", shipped)
        self.assertEqual(bundle.absolutize_runtime(once, shipped), once)

    def test_a_pre_rename_root_variable_is_normalised_in_the_copy(self):
        # A vendored document naming ORCA_FLEET_ROOT beside commands that read OPEN_FLEET_ROOT
        # would have the reader export one variable and run commands that expand the other.
        shipped = {"runtime/scripts/verify.py"}
        self.assertEqual(
            bundle.absolutize_runtime('set `ORCA_FLEET_ROOT`, then "$ORCA_FLEET_ROOT/x"', shipped),
            'set `OPEN_FLEET_ROOT`, then "$OPEN_FLEET_ROOT/x"')

    def test_installed_verifier_oracle_rejects_a_usage_only_decoy(self):
        copy = shutil.copy2

        def decoy(source, target, **kwargs):
            result = copy(source, target, **kwargs)
            if Path(source).name == "verify.py":
                Path(target).write_text("#!/usr/bin/env python3\nprint('usage: decoy')\n")
            return result

        with mock.patch.object(bundle.shutil, "copy2", decoy):
            with self.assertRaisesRegex(AssertionError, "verify: OK"):
                self.test_installed_entry_points_work_without_source_checkout()

    def test_check_rejects_files_omitted_during_copy(self):
        copy = shutil.copy2
        missing = {"verify.py", "ed25519.py", "one-way-doors.json", "build-change.md"}

        def omit(source, target, **kwargs):
            if Path(source).name not in missing:
                return copy(source, target, **kwargs)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(bundle.shutil, "copy2", omit):
            built, problems = bundle.build(tmp)
            self.assertEqual(built, 22)
            for name in missing:
                self.assertTrue(any(name in p for p in problems), (name, problems))

    def test_installed_oracle_rejects_stripped_executable_permissions(self):
        copy = shutil.copy2

        def strip_mode(source, target, **kwargs):
            result = copy(source, target, **kwargs)
            if Path(source).name == "evidence-run.py":
                Path(target).chmod(Path(target).stat().st_mode & ~0o111)
            return result

        with mock.patch.object(bundle.shutil, "copy2", strip_mode):
            with self.assertRaisesRegex(AssertionError, "executable"):
                self.test_installed_entry_points_work_without_source_checkout()

    def test_check_rejects_required_inputs_missing_before_discovery(self):
        # Copy build inputs so omission never mutates the shared source checkout.
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp).resolve() / "source"
            for directory in ("skills", "playbooks", "runtime", "docs", ".claude-plugin", "hooks"):
                shutil.copytree(ROOT / directory, source / directory)
            for name in ("ARCHITECTURE.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
                shutil.copy2(ROOT / name, source / name)
            with mock.patch.object(bundle, "ROOT", source), \
                    mock.patch.object(bundle, "SKILLS_DIR", source / "skills"), \
                    mock.patch.object(bundle.validate, "PLAYBOOKS_DIR", source / "playbooks"), \
                    mock.patch.object(bundle.validate, "RUNTIME_DIR", source / "runtime"):
                self.assertEqual(bundle.build(Path(tmp) / "out"), (22, []))
                for relative in ("runtime/scripts/ed25519.py", "runtime/scripts/diff_scope.py",
                                 "runtime/scripts/wtree.sh", "runtime/scripts/verify.py",
                                 "runtime/one-way-doors.json", "playbooks/build-change.md",
                                 "playbooks/observe.md", "runtime/evidence-manifest.md",
                                 "docs/runs/TEMPLATE.md",
                                 ".claude-plugin/plugin.json", "hooks/hooks.json",
                                 ".claude-plugin/bundle-README.md", ".claude-plugin/icon.png",
                                 "LICENSE", "THIRD_PARTY_NOTICES.md"):
                    with self.subTest(missing=relative):
                        path = source / relative
                        saved = path.read_bytes()
                        path.unlink()
                        try:
                            _built, problems = bundle.build(Path(tmp) / "out")
                            self.assertTrue(any(Path(relative).name in p for p in problems),
                                            (relative, problems))
                        finally:
                            path.write_bytes(saved)

    def test_source_symlinks_are_refused_across_all_bundle_inputs(self):
        # #750 C2: shutil.copy2 / shutil.copytree dereference source symlinks into regular files,
        # allowing host content outside the tagged tree to be published into dist across mission,
        # runtime, protocol, plugin, support-document, root-doc, and directory variants.
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            outside = base / "outside-secret.txt"
            outside.write_text("TOP_SECRET_HOST_CONTENT\n", encoding="utf-8")
            outside_dir = base / "outside-dir"
            outside_dir.mkdir()
            (outside_dir / "leaked.py").write_text("SECRET = 'leaked'\n", encoding="utf-8")
            source = base / "source"
            for directory in ("skills", "playbooks", "runtime", "docs", ".claude-plugin", "hooks"):
                shutil.copytree(ROOT / directory, source / directory)
            for name in ("ARCHITECTURE.md", "LICENSE", "THIRD_PARTY_NOTICES.md"):
                shutil.copy2(ROOT / name, source / name)
            with mock.patch.object(bundle, "ROOT", source), \
                    mock.patch.object(bundle, "SKILLS_DIR", source / "skills"), \
                    mock.patch.object(bundle.validate, "PLAYBOOKS_DIR", source / "playbooks"), \
                    mock.patch.object(bundle.validate, "RUNTIME_DIR", source / "runtime"):
                # 1. Mission extra file symlink & directory symlink
                mission_link = source / "skills" / "ship-it" / "leaked.txt"
                mission_link.symlink_to(outside)
                try:
                    built, problems = bundle.build(base / "out-mission-file")
                    self.assertEqual(built, 0)
                    self.assertTrue(any("source symlink refused: skills/ship-it/leaked.txt" in p
                                        for p in problems), problems)
                    self.assertFalse((base / "out-mission-file").exists())
                finally:
                    mission_link.unlink()

                mission_dir_link = source / "skills" / "ship-it" / "resources"
                mission_dir_link.symlink_to(outside_dir, target_is_directory=True)
                try:
                    built, problems = bundle.build(base / "out-mission-dir")
                    self.assertEqual(built, 0)
                    self.assertTrue(any("source symlink refused: skills/ship-it/resources" in p
                                        for p in problems), problems)
                finally:
                    mission_dir_link.unlink()

                # 2. Replaced existing files across runtime, protocol, plugin, support-doc, root-doc
                for relative in ("runtime/scripts/verify.py", "runtime/scripts/extra_helper.py",
                                 "playbooks/build-change.md", "runtime/evidence-manifest.md",
                                 ".claude-plugin/plugin.json", ".claude-plugin/bundle-README.md",
                                 "LICENSE", "docs/runs/TEMPLATE.md", "ARCHITECTURE.md"):
                    with self.subTest(symlink_input=relative):
                        target = source / relative
                        saved = target.read_bytes() if target.exists() else None
                        if saved is not None:
                            target.unlink()
                        target.symlink_to(outside)
                        try:
                            built, problems = bundle.build(base / "out-file")
                            self.assertEqual(built, 0)
                            self.assertTrue(any(f"source symlink refused: {relative}" in p
                                                for p in problems), (relative, problems))
                        finally:
                            target.unlink()
                            if saved is not None:
                                target.write_bytes(saved)

                # 3. Directory ancestor symlink variant (e.g. docs/runs or hooks swapped for symlink)
                hooks_dir = source / "hooks"
                hooks_backup = base / "hooks-backup"
                shutil.move(str(hooks_dir), str(hooks_backup))
                hooks_dir.symlink_to(hooks_backup, target_is_directory=True)
                try:
                    built, problems = bundle.build(base / "out-dir-anc")
                    self.assertEqual(built, 0)
                    self.assertTrue(any("source symlink refused: hooks" in p for p in problems),
                                    problems)
                finally:
                    hooks_dir.unlink()
                    shutil.move(str(hooks_backup), str(hooks_dir))

    def test_the_bundle_carries_what_the_directory_listing_reads(self):
        # #235: the developer portal blocked dist for having no README of at least 40 words in the
        # plugin folder, and takes .claude-plugin/icon.png as the listing icon: a square PNG or
        # JPEG of 512 to 2048 px, under 2 MB.
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(bundle.build(tmp), (22, []))
            readme = (Path(tmp) / "README.md").read_text(encoding="utf-8")
            self.assertEqual(readme, (ROOT / ".claude-plugin/bundle-README.md").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(re.sub(r"```.*?```", "", readme, flags=re.S).split()), 40)
            icon = (Path(tmp) / ".claude-plugin/icon.png").read_bytes()
            self.assertEqual(icon[:8], b"\x89PNG\r\n\x1a\n")
            width, height = int.from_bytes(icon[16:20], "big"), int.from_bytes(icon[20:24], "big")
            self.assertEqual(width, height)
            self.assertTrue(512 <= width <= 2048, width)
            self.assertLess(len(icon), 2 * 1024 * 1024)
            marker = json.loads((Path(tmp) / bundle.MARKER).read_text(encoding="utf-8"))
            self.assertTrue({"README.md", ".claude-plugin/icon.png"} <= set(marker["files"]))
            self.assertFalse((Path(tmp) / ".claude-plugin/bundle-README.md").exists())
            # PR #681 review: every file the README names ships in a local build too
            for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                self.assertEqual((Path(tmp) / name).read_bytes(), (ROOT / name).read_bytes(), name)
                self.assertIn(f"`{name}`", readme)

    def test_the_bundle_readme_links_only_outside_the_bundle_or_to_what_it_ships(self):
        # The bundle has no docs/: a relative link would break in the listing and the install
        readme = (ROOT / ".claude-plugin/bundle-README.md").read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)]+)\)", readme):
            self.assertTrue(target.startswith("https://"), target)

    def test_out_pointing_at_the_checkout_is_refused_before_any_delete(self):
        # #350: build() rmtrees <out>/skills before rebuilding; `--out .` resolved that to the
        # real catalog and deleted all 21 missions it was asked to copy.
        sentinel = bundle.SKILLS_DIR / "ship-it" / "SKILL.md"
        before = sentinel.read_bytes()
        for out in (str(ROOT), str(ROOT / "dist" / "..")):
            with self.subTest(out=out):
                with mock.patch("sys.stderr") as err:
                    self.assertEqual(bundle.main(["--out", out]), 2)
                written = "".join(call.args[0] for call in err.write.call_args_list)
                self.assertIn("source catalog", written)
                self.assertEqual(sentinel.read_bytes(), before)

    def test_missing_or_malformed_inventory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle.build(tmp)
            root = Path(tmp) / "skills/clean-sweep"
            inventory = root / "references/bundle-files.json"
            for contents in (None, "{", "{}"):
                with self.subTest(contents=contents):
                    if contents is None:
                        inventory.unlink(missing_ok=True)
                    else:
                        inventory.write_text(contents)
                    self.assertTrue(bundle.dangling(root))

    def test_transitive_run_report_template_has_an_installed_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(bundle.build(tmp), (22, []))
            root = Path(tmp) / "skills/pin-it"
            protocol_path = root / "references/build-change.md"
            self.assertTrue(protocol_path.is_file(), "missing mandatory build-change protocol")
            protocol = protocol_path.read_text()
            self.assertIn("docs/runs/TEMPLATE.md", protocol)
            index = (root / "references/README.md").read_text()
            matches = re.findall(r'"\$OPEN_FLEET_ROOT/([^"\n]*TEMPLATE.md)"', index)
            self.assertTrue(matches, "mandatory template needs an explicit installed path")
            template = root / matches[0]
            self.assertTrue(template.is_file())
            self.assertIn("RUN: mission=<mission>", template.read_text())
            self.assertIn("## Verifier outcome", template.read_text())
            # Copy just the mission, then execute the reporting procedure in another repo.
            with tempfile.TemporaryDirectory() as separate:
                installed = Path(separate) / "copied mission"
                shutil.copytree(root, installed)
                self.assert_installed_reporting(installed, Path(separate) / "project")
            template.unlink()
            self.assertTrue(any("TEMPLATE.md" in p for p in bundle.dangling(root)))

    def assert_installed_reporting(self, installed, project):
        project.mkdir()
        (project / "checks").mkdir()
        (project / ".gitignore").write_text("docs/runs/\ncontract.json\n__pycache__/\n")
        (project / "value.txt").write_text("42\n")
        (project / "check.py").write_text(
            "from pathlib import Path\nassert int(Path('value.txt').read_text()) > 0\n")
        (project / "checks/test_value.py").write_text(
            "import unittest\nfrom pathlib import Path\nclass Target(unittest.TestCase):\n"
            " def test_value(self):\n  self.assertEqual(Path('value.txt').read_text(), '42\\n')\n")
        for args in (("init", "-b", "main"),
                     ("add", ".gitignore", "check.py", "checks", "value.txt")):
            self.assertEqual(self.run_command(project, "git", *args).returncode, 0)
        commit = ("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                  "commit", "-m", "fixture")
        self.assertEqual(self.run_command(project, *commit).returncode, 0)
        base = self.run_command(project, "git", "rev-parse", "HEAD").stdout.strip()
        (project / "report.md").write_text("Report-only fixture.\n")
        self.assertEqual(self.run_command(project, "git", "add", "report.md").returncode, 0)
        self.assertEqual(self.run_command(project, *commit).returncode, 0)
        head = self.run_command(project, "git", "rev-parse", "HEAD").stdout.strip()
        run_dir = "docs/runs/2026-09-12-pin-it-external-run"
        evidence = project / run_dir
        evidence.mkdir(parents=True)
        manifest = run_dir + "/manifest.json"
        (project / "contract.json").write_text('{"criterion_ids": ["AC-1"]}\n')
        digest = "sha256:" + hashlib.sha256((project / "contract.json").read_bytes()).hexdigest()
        (project / manifest).write_text(json.dumps({
            "unit": "installed-report", "base_sha": base, "head_sha": head,
            "contract": {"digest": digest, "criterion_ids": ["AC-1"]},
            "criteria": [{"id": "AC-1", "addressed": True}]}))
        template = (installed / "docs/runs/TEMPLATE.md").read_text()
        replacements = {"<manifest>": manifest, "<run-dir>": run_dir,
                        "<contract-source>": "contract.json", "<contract-digest>": digest,
                        "<unit-class>": "report-only",
                        "<project-validation-command>": "python3 check.py",
                        "<project-test-command>": "python3 -m unittest discover -s checks"}

        def execute(command, suffix=""):
            for placeholder, value in replacements.items():
                command = command.replace(placeholder, value)
            command = command.replace(".txt --", suffix + ".txt --")
            # The command runs as written: the reader rewrites no paths, it only exports
            # OPEN_FLEET_ROOT, so expand that and nothing else (#322 review, P1).
            # shlex.join preserves a spaced install path.
            argv = [sys.executable if p == "python3" else
                    p.replace("$OPEN_FLEET_ROOT", str(installed))
                    for p in shlex.split(command)]
            self.assertFalse(any(p.startswith("runtime/scripts/") for p in argv), command)
            result = self.run_command(project, *argv)
            return result, shlex.join(argv)

        gates = template.split("## Gates\n", 1)[1].split("## Catalog proof promotion", 1)[0]
        commands = re.findall(r"`(python3 [^`]+)`", gates)
        self.assertTrue(commands, "missing target validation/test instructions")
        for command in commands:
            result, invocation = execute(command)
            self.assertEqual(result.returncode, 0, invocation + "\n" + result.stderr)
        records = json.loads((project / manifest).read_text())["commands"]
        self.assertEqual([r["label"] for r in records], ["validation", "tests"])
        self.assertIn("Ran 1 test", (evidence / "tests.txt").read_text())
        # Both required target checks must detect a real bad value and retain their exits.
        (project / "value.txt").write_text("-1\n")
        for command in commands:
            result, invocation = execute(command, "-red")
            self.assertEqual(result.returncode, 1, invocation + "\n" + result.stderr)
        (project / "value.txt").write_text("42\n")
        for command in commands:
            self.assertEqual(execute(command, "-restored")[0].returncode, 0)
        data = json.loads((project / manifest).read_text())
        self.assertEqual([r["exit"] for r in data["commands"]], [0, 0, 1, 1, 0, 0])
        data["artifacts"] = [{"path": p.relative_to(project).as_posix(),
                              "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                             for p in evidence.glob("*.txt")]
        (project / manifest).write_text(json.dumps(data))
        verifier = re.findall(r"`(python3 [^`]+)`", template.split(
            "## Verifier outcome", 1)[1].split("## WIP-curve", 1)[0])
        self.assertEqual(len(verifier), 1)
        result, invocation = execute(verifier[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("verify: OK", result.stdout)
        data = json.loads((project / manifest).read_text())
        self.assertEqual(data["commands"][-1]["label"], "verifier")
        self.assertEqual(data["commands"][-1]["cmd"], invocation.split(" -- ", 1)[1])
        tree = self.run_command(project, "git", "rev-parse", "HEAD^{tree}").stdout.strip()
        self.assertEqual(data["commands"][-1]["wtree"], tree)
        # No source-clone/catalog layout is available in the project.
        for missing in ("runtime", "scripts", "skills", "tests", "docs/runs/README.md"):
            self.assertFalse((project / missing).exists(), missing)
        report = run_dir + ".md"
        replacements["<report>"] = report
        inventory_commands = re.findall(r"`(python3 [^`]+)`", template.split(
            "## Run-close integrity inventory", 1)[1].split("## Gates", 1)[0])
        self.assertEqual(len(inventory_commands), 3)
        rows = "\n".join(f"| `{p.relative_to(project)}` | `{'0' * 64}` | fixture |"
                         for p in sorted(evidence.iterdir()))
        (project / report).write_text(
            f"# Installed reporting fixture\n\n"
            f"RUN: mission=pin-it tier=doctrine-only inventory_at=uncommitted "
            f"manifest={manifest} verifier=GREEN\n\n"
            f"Target: isolated external project; BASE main at {base}; head {head}; "
            f"frozen contract contract.json at {digest}.\n"
            f"Mission location: {installed}; source revision: fixture build.\n"
            "Coordinator/workers: local unittest fixture, no dispatched workers.\n"
            "Orca and human gates: inapplicable to this offline reporting fixture.\n\n"
            "## Terminal state\nReporting procedure exercised; no mission completion claimed.\n"
            "## Convergence proof\nFixture AC-1 is a report-only Git range; no live oracle.\n"
            f"## Pipeline evidence\nExact commands and exits: {manifest}.\n"
            "## WIP-curve protocol row\nInapplicable: external report-only fixture.\n"
            "## Deviations and lessons\nNo live mission run or proof promotion is claimed.\n"
            f"## Gates\nTarget validation and one target test passed; "
            f"bad-value controls failed, then restored controls passed (see {manifest}).\n"
            "## Evidence binding\nAll owned artifacts retained in the inventory commit.\n"
            "## Verifier outcome\n"
            f"{invocation}\nexit 0\n{result.stdout}\n"
            f"## Run-close integrity inventory (sha256)\n{rows}\n")
        for command in inventory_commands[:2]:
            result, invocation = execute(command)
            self.assertEqual(result.returncode, 0, invocation + "\n" + result.stderr)
            self.assertNotIn("MISSING", result.stdout)
        # A changed owned artifact must fail the actual installed inventory checker.
        saved = (evidence / "tests.txt").read_bytes()
        (evidence / "tests.txt").write_text("tampered\n")
        self.assertEqual(execute(inventory_commands[1])[0].returncode, 1)
        (evidence / "tests.txt").unlink()
        result, _ = execute(inventory_commands[1])
        self.assertIn("MISSING", result.stdout)  # The procedure rejects missing owned evidence too.
        (evidence / "tests.txt").write_bytes(saved)
        self.assertEqual(self.run_command(project, "git", "add", "-f", run_dir,
                                         "contract.json").returncode, 0)
        self.assertEqual(self.run_command(project, *commit).returncode, 0)
        evidence_sha = self.run_command(project, "git", "rev-parse", "HEAD").stdout.strip()
        replacements["<inventory_at>"] = evidence_sha
        report_path = project / report
        report_path.write_text(report_path.read_text().replace(
            "inventory_at=uncommitted", "inventory_at=" + evidence_sha))
        result, invocation = execute(inventory_commands[2])
        self.assertEqual(result.returncode, 0, invocation + "\n" + result.stderr)
        self.assertNotIn("MISSING", result.stdout)

    def test_all_missions_preserve_installed_interfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            built, problems = bundle.build(tmp)
            self.assertEqual((built, problems), (22, []))
            for source in sorted((ROOT / "skills").glob("*/SKILL.md")):
                installed = Path(tmp) / "skills" / source.parent.name
                with self.subTest(mission=source.parent.name):
                    self.assertEqual(source.read_text().split("---", 2)[1],
                                     (installed / "SKILL.md").read_text().split("---", 2)[1])
                    self.assertEqual(bundle.dangling(installed), [])
                    self.assertEqual(list(installed.rglob("*.pyc")), [])
                    for extra in source.parent.rglob("*"):
                        if extra.is_file() and extra != source:
                            self.assertEqual(extra.read_bytes(),
                                             (installed / extra.relative_to(source.parent)).read_bytes())
                    for name in ("verify.py", "evidence-run.py", "preflight.py"):
                        entry = installed / "runtime/scripts" / name
                        self.assertTrue(entry.is_file(), str(entry))
                        self.assertEqual(entry.stat().st_mode & 0o111, 0o111,
                                         f"{name} must retain its executable interface")
                        result = self.run_command(tmp, str(entry), "--help")
                        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
