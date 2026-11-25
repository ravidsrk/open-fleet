#!/usr/bin/env python3
"""Adversarial regression tests for tooling, broker, container, bundler, replay, CI, install & docs.

Covers verified findings C-01 through C-17 with stdlib-only tests loading repo modules via
importlib.util.spec_from_file_location.
"""
import ast
import contextlib
import hashlib
import http.client
import importlib.util
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, rel: str):
    path = ROOT / rel
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    prior, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = prior
    return mod


lb = _load("adv_live_broker", "scripts/live_broker.py")
lc = _load("adv_live_container", "scripts/live_container.py")
bundle = _load("adv_bundle", "scripts/bundle.py")
run_index = _load("adv_run_index", "scripts/run_index.py")
eval_mod = _load("adv_eval", "scripts/eval.py")
validate = _load("adv_validate", "scripts/validate.py")
gen_badges = _load("adv_gen_badges", "scripts/gen-badges.py")
replay = _load("adv_vf_replay", "bench/vf-bench/replay.py")
verify_adapter = _load("adv_verify_adapter", "bench/vf-bench/adapters/verify_adapter.py")

CANONICAL_GUARD_STMT = ast.dump(ast.parse('''
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]
''').body[0])

PLANT_SHADOW = (
    "import os as _o\n"
    "open(_o.path.join(_o.path.dirname(__file__), 'PLANT-' + __name__), 'w').close()\n"
    "raise ImportError('planted shadow loaded: ' + __name__)\n"
)


class _StubAPI:
    """Local stand-in Anthropic API on 127.0.0.1."""

    def __init__(self, test: unittest.TestCase):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                outer.requests.append({"path": self.path, "body": body})
                reply = b'{"input_tokens": 5}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


class LiveBrokerHardeningTests(unittest.TestCase):
    """C-01 & C-13: RFC 8259 UTF-8 without BOM, type checks, free_terms input_schema, tally flush."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="adv-broker-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.token = "sk-ant-oat01-adv-" + os.urandom(6).hex()
        self.api = _StubAPI(self)
        self.ledger_path = self.tmp / "spend.jsonl"

    def _start_broker(self, cap=5.0):
        server, ledger = lb.serve(self.token, self.ledger_path, cap, port=0, upstream=self.api.url)
        self.addCleanup(ledger.fh.close)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]
        return server, ledger

    def _post(self, raw: bytes, path="/v1/messages"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request(
            "POST", path, body=raw,
            headers={"Content-Type": "application/json", "anthropic-version": "2023-06-01"},
        )
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_utf8_bom_utf16_utf32_and_invalid_utf8_rejected_before_parse_and_in_parse_facts(self):
        self._start_broker()
        payload = json.dumps({
            "model": "claude-haiku-5-5",
            "max_tokens": 10,
            "service_tier": "standard_only",
            "messages": [{"role": "user", "content": "ok"}],
        })
        bad_bodies = {
            "utf8-bom": b"\xef\xbb\xbf" + payload.encode("utf-8"),
            "utf16-bom": payload.encode("utf-16"),
            "utf16-be-bomless": payload.encode("utf-16-be"),
            "utf16-le-bomless": payload.encode("utf-16-le"),
            "utf32-bom": payload.encode("utf-32"),
            "utf32-be-bomless": payload.encode("utf-32-be"),
            "invalid-utf8": b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":"\xff"}',
        }
        for name, raw in bad_bodies.items():
            with self.subTest(encoding=name):
                facts = lb._parse_facts(raw)
                self.assertEqual(facts["why"], "the body is not valid UTF-8 JSON")
                status, data = self._post(raw)
                self.assertEqual(status, 400, data)
                self.assertIn(b"the body is not valid UTF-8 JSON", data)
        self.assertEqual(self.api.requests, [])

    def test_non_list_tools_and_edits_rejected_cleanly_without_type_error(self):
        self._start_broker()
        for bad_tools in (123, True, {"name": "bash"}):
            with self.subTest(tools=bad_tools):
                doc = {"model": "claude-haiku-5-5", "max_tokens": 10,
                       "service_tier": "standard_only", "messages": [], "tools": bad_tools}
                self.assertIsInstance(lb.free_terms(doc), str)
                why, mult, images = lb.terms(doc)
                self.assertIsInstance(why, str)
                self.assertEqual((mult, images), (1.0, 0))
                status, _ = self._post(json.dumps(doc).encode("utf-8"), path="/v1/messages")
                self.assertEqual(status, 400)
                status_free, _ = self._post(json.dumps(doc).encode("utf-8"), path="/v1/messages/count_tokens")
                self.assertEqual(status_free, 400)
        for bad_edits in (123, True, {"type": "clear_all"}):
            with self.subTest(edits=bad_edits):
                doc = {"model": "claude-haiku-5-5", "max_tokens": 10,
                       "service_tier": "standard_only", "messages": [],
                       "context_management": {"edits": bad_edits}}
                why, mult, images = lb.terms(doc)
                self.assertIsInstance(why, str)
                self.assertEqual((mult, images), (1.0, 0))
                status, _ = self._post(json.dumps(doc).encode("utf-8"), path="/v1/messages")
                self.assertEqual(status, 400)
        self.assertEqual(self.api.requests, [])

    def test_free_terms_allows_custom_tool_file_id_schema_but_rejects_file_id_in_messages(self):
        self._start_broker()
        custom_tool = {
            "name": "read_file",
            "description": "Read a workspace file",
            "input_schema": {
                "type": "object",
                "properties": {"file_id": {"type": "string"}},
                "required": ["file_id"],
            },
        }
        good_doc = {
            "model": "claude-haiku-5-5",
            "tools": [custom_tool],
            "messages": [{"role": "user", "content": "hello"}],
        }
        self.assertIsNone(lb.free_terms(good_doc))
        status, _ = self._post(json.dumps(good_doc).encode("utf-8"), path="/v1/messages/count_tokens")
        self.assertEqual(status, 200)
        bad_doc = {
            "model": "claude-haiku-5-5",
            "tools": [custom_tool],
            "messages": [{"role": "user", "content": [{"type": "document", "source": {"type": "file", "file_id": "f1"}}]}],
        }
        self.assertIsNotNone(lb.free_terms(bad_doc))
        status_bad, _ = self._post(json.dumps(bad_doc).encode("utf-8"), path="/v1/messages/count_tokens")
        self.assertEqual(status_bad, 400)

    def test_ledger_flush_tally_persists_under_100_free_calls(self):
        ledger = lb.Ledger(self.ledger_path, 5.0)
        self.addCleanup(ledger.fh.close)
        for _ in range(3):
            self.assertTrue(ledger.free(42))
        events_before = [json.loads(ln) for ln in self.ledger_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e["event"] for e in events_before], ["open"])
        ledger.flush_tally()
        events_after = [json.loads(ln) for ln in self.ledger_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(events_after[-1]["event"], "tally")
        self.assertEqual(events_after[-1]["free_calls"], 3)
        self.assertEqual(events_after[-1]["free_bytes"], 126)
        # Flushing again when nothing new happened does not append a duplicate tally line.
        ledger.flush_tally()
        events_again = [json.loads(ln) for ln in self.ledger_path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(events_again), len(events_after))


class LiveContainerHardeningTests(unittest.TestCase):
    """C-02, C-03, C-14: interrupt fail-closed, behavioral arm, build docker_env."""

    def test_behavioral_arm_is_accepted_by_parser_and_all_arms(self):
        args = lc.parser().parse_args([
            "run", "--arm", "behavioral", "--results", "/tmp/r",
            "--timeout", "60", "--cap-usd", "1.0",
        ])
        self.assertEqual(args.arm, "behavioral")
        self.assertEqual(lc.ALL_ARMS["behavioral"], ("scripts/eval.py", "run", "--suite", "behavioral"))
        self.assertIsNone(lc.output_problem("behavioral", []))

    def test_build_passes_docker_env_stripping_credentials(self):
        with tempfile.TemporaryDirectory(prefix="adv-lc-build-") as tmp:
            root = Path(tmp)
            df = root / "Dockerfile"
            df.write_bytes(b"FROM scratch\n")
            seen_envs = []

            def fake_run(cmd, **kwargs):
                seen_envs.append(kwargs.get("env"))
                return subprocess.CompletedProcess(cmd, 1)

            ns = mock.MagicMock(
                dockerfile=str(df),
                context=None,
                image="open-fleet-live:test",
                images=str(root / "images.json"),
            )
            with mock.patch.dict(os.environ, {
                lc.TOKEN_ENV: "sk-ant-oat01-secret",
            }), mock.patch.object(lc, "committed_blob", return_value=b"FROM scratch\n"), \
                    mock.patch.object(lc.shutil, "which", return_value="/usr/bin/docker"), \
                    mock.patch.object(lc.subprocess, "run", side_effect=fake_run):
                rc = lc.build(ns)
            self.assertEqual(rc, 1)
            self.assertEqual(len(seen_envs), 1)
            self.assertIsNotNone(seen_envs[0])
            self.assertNotIn(lc.TOKEN_ENV, seen_envs[0])

    def test_interrupt_when_destroy_unverified_returns_exit_not_destroyed(self):
        with tempfile.TemporaryDirectory(prefix="adv-lc-int-") as tmp:
            base = Path(tmp)
            results, receipts, repo = base / "results", base / "receipts", base / "repo"
            token_file = base / "tok"
            token_file.write_text("sk-ant-oat01-tok\n", encoding="utf-8")
            token_file.chmod(0o600)

            def fake_export(_repo, _commit, dst):
                dst.mkdir(parents=True, exist_ok=True)
                for rel in ("scripts/eval.py", f"{lc.WRAPPER_DIR}/claude", lc.BROKER_SCRIPT):
                    p = dst / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text("stub\n", encoding="utf-8")

            create_n = 0

            def fake_docker(*argv, **kwargs):
                nonlocal create_n
                if argv and argv[0] == "create":
                    create_n += 1
                    return subprocess.CompletedProcess(argv, 0, stdout=f"cid-{create_n}\n", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            def fake_destroy(_ids, _nonce):
                return {"verified": False, "check": "ps", "output": "cid-2 still running", "errors": [], "nonzero": []}

            args = lc.parser().parse_args([
                "run", "--arm", "behavioral", "--results", str(results),
                "--receipts", str(receipts), "--token-file", str(token_file),
                "--timeout", "30", "--cap-usd", "1.0",
            ])
            args.arm_args = []
            image = {"id": "sha256:" + "a" * 64}
            err_buf = io.StringIO()
            with mock.patch.object(lc, "export_checkout", side_effect=fake_export), \
                    mock.patch.object(lc, "docker", side_effect=fake_docker), \
                    mock.patch.object(lc, "await_broker", side_effect=SystemExit(128 + signal.SIGTERM)), \
                    mock.patch.object(lc, "destroy", side_effect=fake_destroy), \
                    contextlib.redirect_stderr(err_buf):
                rc = lc.launch(args, results, receipts, token_file, "sk-ant-oat01-tok", repo, "a" * 40, image)
            self.assertEqual(rc, lc.EXIT_NOT_DESTROYED)
            self.assertIn("FAIL-CLOSED", err_buf.getvalue())
            receipt_files = list(receipts.glob("*.json"))
            self.assertEqual(len(receipt_files), 1)
            doc = json.loads(receipt_files[0].read_text(encoding="utf-8"))
            self.assertEqual(doc["interrupted"], 128 + signal.SIGTERM)
            self.assertIs(doc["destroyed"]["verified"], False)


class ReplayAndAdapterHardeningTests(unittest.TestCase):
    """C-04 & C-16: replay.py static allow_static_nc and verify_adapter.py W3-01 / -I."""

    def test_adapter_request_mirrors_sound_gate_allow_static_nc(self):
        vf = _load("adv_vfbench", "bench/vf-bench/vfbench.py")
        base_trap = {"id": "T-static", "manifest": {"unit_id": "T-1"}}
        with tempfile.TemporaryDirectory(prefix="adv-replay-") as tmp:
            holder = Path(tmp)
            for sub in ("m", "ro", "pl", "dp", "ex"):
                (holder / sub).mkdir()
            req_mut, _, _ = replay.adapter_request(vf, dict(base_trap), holder / "m")
            self.assertIs(req_mut["coordinator"].get("allow_static_nc"), True)
            req_ro, _, _ = replay.adapter_request(vf, dict(base_trap, unit_class="report-only"), holder / "ro")
            self.assertNotIn("allow_static_nc", req_ro["coordinator"])
            req_plan, _, _ = replay.adapter_request(vf, dict(base_trap, unit_class="planning"), holder / "pl")
            self.assertNotIn("allow_static_nc", req_plan["coordinator"])
            req_disp, _, _ = replay.adapter_request(vf, dict(base_trap, dispatch=True), holder / "dp")
            self.assertNotIn("allow_static_nc", req_disp["coordinator"])
            req_exec, _, _ = replay.adapter_request(vf, dict(base_trap, execute_nc=True), holder / "ex")
            self.assertNotIn("allow_static_nc", req_exec["coordinator"])
            self.assertIs(req_exec["coordinator"].get("execute_nc"), True)

    def test_verify_adapter_passes_dash_i_and_has_canonical_w301_guard(self):
        argv = verify_adapter.verify_argv({"manifest_path": "/tmp/m.json", "coordinator": {"allow_static_nc": True}}, Path("/tmp/v.py"))
        self.assertEqual(argv[:4], [sys.executable, "-I", "/tmp/v.py", "--manifest"])
        self.assertIn("--allow-static-nc", argv)
        _assert_canonical_guard(self, "bench/vf-bench/adapters/verify_adapter.py")


class BundleHardeningTests(unittest.TestCase):
    """C-05 & C-15: failed build returns before mutating --out, partial install safety, unlink OSError."""

    def test_failed_build_into_returns_without_mutating_out(self):
        with tempfile.TemporaryDirectory(prefix="adv-bundle-fail-") as tmp:
            out = Path(tmp) / "out"
            with mock.patch.object(bundle, "_build_into", return_value=(0, ["unresolved ref: ghost"])):
                count, problems = bundle.build(out, keep_record=False)
            self.assertEqual((count, problems), (0, ["unresolved ref: ghost"]))
            self.assertFalse(out.exists(), "a failed _build_into created or mutated --out")

    def test_mid_install_refusal_keeps_undeleted_stale_and_excludes_unverified_user_bytes(self):
        with tempfile.TemporaryDirectory(prefix="adv-bundle-mid-") as tmp:
            out = Path(tmp) / "out"
            records = Path(tmp) / "records"
            env_patch = mock.patch.dict(os.environ, {bundle.RECORDS_ENV: str(records)})
            with env_patch:
                count, problems = bundle.build(out, keep_record=True)
                self.assertEqual(problems, [])
                self.assertGreater(count, 0)
                # Plant a provable stale file that the next build will plan to delete, plus
                # simulate a user replacing a target file right after _claim so _install aborts.
                stale_rel = "skills/ship-it/zz-stale-test.md"
                stale_bytes = b"stale bundle bytes\n"
                stale_sha = hashlib.sha256(stale_bytes).hexdigest()
                stale_path = out / stale_rel
                stale_path.write_bytes(stale_bytes)
                marker_path = out / bundle.MARKER
                marker_doc = json.loads(marker_path.read_text(encoding="utf-8"))
                marker_doc["files"] = sorted(set(marker_doc["files"]) | {stale_rel})
                marker_doc["sha256"][stale_rel] = stale_sha
                marker_path.write_text(json.dumps(marker_doc, indent=2) + "\n", encoding="utf-8")
                rec_path = bundle._record_path(out)
                rec_doc = json.loads(rec_path.read_text(encoding="utf-8"))
                rec_doc["files"][stale_rel] = stale_sha
                rec_path.write_text(json.dumps(rec_doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")

                user_bytes = b"USER BYTES WRITTEN AFTER CLAIM\n"
                user_sha = hashlib.sha256(user_bytes).hexdigest()
                real_claim = bundle._claim

                def claim_then_replace(*args, **kwargs):
                    res = real_claim(*args, **kwargs)
                    # Replace the stale file after claim so its delete raises BundleRefused immediately,
                    # AND also replace a produced file with unverified user bytes.
                    target = out / "skills" / "review-it" / "SKILL.md"
                    tmp_u = target.with_name("SKILL.md.user")
                    tmp_u.write_bytes(user_bytes)
                    os.replace(tmp_u, target)
                    # Also add a second stale file after stale_rel that never gets unlinked
                    return res

                with mock.patch.object(bundle, "_claim", side_effect=claim_then_replace):
                    with self.assertRaises(bundle.BundleRefused):
                        bundle.build(out, keep_record=True)
                after_marker = json.loads(marker_path.read_text(encoding="utf-8"))
                # User's unverified bytes must NOT be claimed in MARKER.
                self.assertNotEqual(after_marker["sha256"].get("skills/review-it/SKILL.md"), user_sha)

    def test_tree_unlink_converts_oserror_to_bundle_refused(self):
        with tempfile.TemporaryDirectory(prefix="adv-bundle-unlink-") as tmp:
            out = Path(tmp)
            (out / "a.txt").write_bytes(b"hello")
            tree = bundle._Tree(out)
            try:
                fake_rename = (mock.Mock(side_effect=PermissionError(13, "Permission denied")), 0)
                with mock.patch.object(bundle, "_RENAME", fake_rename):
                    with self.assertRaises(bundle.BundleRefused) as cm:
                        tree.unlink("a.txt", (0, 0, "0" * 64))
                self.assertIn("cannot delete a.txt", str(cm.exception))
            finally:
                tree.close()


class RunIndexHardeningTests(unittest.TestCase):
    """C-06: check_bindings validates tier allowlist, mission agreement, and tier vs ran_as."""

    def _fixture(self, tmp, *, run_mission="ship-it", run_tier="self-run", row_mission=None,
                 ran_as="self-run", binds="yes"):
        root = Path(tmp)
        (root / "docs" / "runs" / "index").mkdir(parents=True)
        shutil.copytree(
            ROOT / "runtime" / "scripts", root / "runtime" / "scripts",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        report = "2026-11-01-demo.md"
        (root / "docs" / "runs" / report).write_text(
            f"RUN: mission={run_mission} tier={run_tier} inventory_at={'a' * 40} "
            f"manifest=docs/runs/2026-11-01-demo/manifest.json verifier=GREEN\n# Demo\n",
            encoding="utf-8",
        )
        row = {
            "report": report,
            "date": "2026-11-01",
            "mission": row_mission or f"[{run_mission}]({report})",
            "target": "demo",
            "ran_as": ran_as,
            "binds": binds,
            "outcome": "ok",
            "summary": "summary",
        }
        (root / "docs" / "runs" / "index" / "2026-11-01-demo.json").write_text(
            json.dumps(row), encoding="utf-8",
        )
        return root

    def test_real_run_index_passes_strict_binding_checks(self):
        self.assertEqual(run_index.check_bindings(ROOT), [])

    def test_invalid_tier_mission_mismatch_and_ran_as_mismatch_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, run_tier="bogus-tier")
            errs = run_index.check_bindings(root)
            self.assertTrue(any("invalid RUN tier" in e for e in errs), errs)
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, run_mission="ship-it", row_mission="[clean-sweep](2026-11-01-demo.md)")
            errs = run_index.check_bindings(root)
            self.assertTrue(any("disagrees with" in e and "RUN mission" in e for e in errs), errs)
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture(tmp, run_tier="self-run", ran_as="external-run")
            errs = run_index.check_bindings(root)
            self.assertTrue(any("disagrees with" in e and "RUN tier" in e for e in errs), errs)


class InstallScriptHardeningTests(unittest.TestCase):
    """C-09: synthetic runtime pkg, bad ORCA_CLI_COMMAND ignored for posix, Linux GNOME orca guard."""

    def test_install_sh_uses_synthetic_runtime_pkg_not_sys_path_insert(self):
        text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("sys.path.insert(0, sys.argv[1])", text)
        self.assertIn('type(sys)("runtime")', text)

    def test_posix_runtime_ignores_malformed_orca_cli_command(self):
        with tempfile.TemporaryDirectory(prefix="adv-inst-posix-") as tmp:
            skills = Path(tmp) / "skills"
            skills.mkdir()
            for d in (ROOT / "skills").iterdir():
                if d.is_dir() and (d / "SKILL.md").is_file() and not d.name.startswith((".", "_")):
                    (skills / d.name).symlink_to(d)
            env = {
                **os.environ,
                "HOME": tmp,
                "OPEN_FLEET_RUNTIME": "posix",
                "ORCA_CLI_COMMAND": "orca --evil-arg",
            }
            proc = subprocess.run(
                ["sh", str(ROOT / "scripts" / "install.sh"), "--check", f"--skills-dir={skills}"],
                env=env, capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("runtime posix: orca CLI checks skipped", proc.stdout)
            self.assertNotIn("could not resolve", proc.stdout + proc.stderr)

    def test_linux_gnome_screen_reader_orca_is_not_executed(self):
        if not sys.platform.startswith("linux"):
            return
        with tempfile.TemporaryDirectory(prefix="adv-inst-gnome-") as tmp:
            root = Path(tmp)
            bindir, skills = root / "bin", root / "skills"
            bindir.mkdir()
            skills.mkdir()
            for d in (ROOT / "skills").iterdir():
                if d.is_dir() and (d / "SKILL.md").is_file() and not d.name.startswith((".", "_")):
                    (skills / d.name).symlink_to(d)
            marker = root / "gnome-ran.txt"
            fake_gnome = bindir / "orca"
            fake_gnome.write_text(
                f"#!/usr/bin/env python3\n# GNOME Orca screen reader (gi.repository / orca.orca)\n"
                f"open({str(marker)!r}, 'w').write('RAN')\n",
                encoding="utf-8",
            )
            fake_gnome.chmod(0o755)
            base_path = [
                d for d in os.environ.get("PATH", "/usr/bin:/bin").split(os.pathsep)
                if not ((Path(d) / "orca").exists() or (Path(d) / "orca-ide").exists())
            ]
            env = {
                k: v for k, v in os.environ.items()
                if k not in ("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME", "ORCA_CLI_COMMAND",
                             "OPEN_FLEET_CLI_COMMAND", "ORCA_DEV_REPO_ROOT")
            }
            env["HOME"] = tmp
            env["PATH"] = os.pathsep.join([str(bindir), *base_path])
            proc = subprocess.run(
                ["sh", str(ROOT / "scripts" / "install.sh"), "--check", f"--skills-dir={skills}"],
                env=env, capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertFalse(marker.exists(), "GNOME screen reader stub was executed on Linux!")


class WorkflowAndTargetAppHardeningTests(unittest.TestCase):
    """C-10, C-11, C-12, C-17: CI workflow hardening and target-app fixes."""

    def test_fixture_target_app_and_validate_workflows_c10(self):
        fta = (ROOT / ".github" / "workflows" / "fixture-target-app.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(fta.count('- "ruff.toml"'), 2)
        self.assertIn("ruff check --config ruff.toml evals/demo/target-app", fta)
        val = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        shard_step = val.split("name: Run suite shard without Gitleaks", 1)[1].split("      - name:", 1)[0]
        self.assertIn("COVERAGE_RCFILE: .coveragerc", shard_step)

    def test_publish_dist_filters_release_tags_and_probes_remote_dist_c11(self):
        wf = (ROOT / ".github" / "workflows" / "publish-dist.yml").read_text(encoding="utf-8")
        self.assertEqual(wf.count("grep -E '^v[0-9]+\\.[0-9]+\\.[0-9]+$' | head -n 1"), 2)
        self.assertIn("git ls-remote --exit-code --heads origin dist", wf)
        # Behavioral check: a non-release v999-rc1 tag does not outrank v0.10.0.
        with tempfile.TemporaryDirectory(prefix="adv-dist-tags-") as tmp:
            repo = Path(tmp)
            env = {
                **os.environ,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.com",
            }
            for cmd in (
                ["git", "init", "-q", "-b", "main"],
                ["git", "commit", "-q", "--allow-empty", "-m", "init"],
                ["git", "tag", "-a", "v0.10.0", "-m", "v0.10.0"],
                ["git", "tag", "-a", "v999-rc1", "-m", "rc"],
                ["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
            ):
                subprocess.run(cmd, cwd=repo, env=env, check=True)
            out = subprocess.run(
                ["bash", "-euo", "pipefail", "-c",
                 "git tag --list 'v[0-9]*' --merged origin/main --sort=-v:refname "
                 "| grep -E '^v[0-9]+\\.[0-9]+\\.[0-9]+$' | head -n 1 || true"],
                cwd=repo, env=env, capture_output=True, text=True, check=True,
            ).stdout.strip()
            self.assertEqual(out, "v0.10.0")

    def test_verdict_gate_uses_equals_for_head_repo_and_branch_c12(self):
        wf = (ROOT / ".github" / "workflows" / "verdict-gate.yml").read_text(encoding="utf-8")
        self.assertIn('--head-repo="$RUN_HEAD_REPO" --head-branch="$RUN_HEAD_BRANCH"', wf)
        self.assertNotIn('--head-repo "$RUN_HEAD_REPO"', wf)

    def test_target_app_compose_pipefail_readme_and_seed_c17(self):
        compose = (ROOT / "evals" / "demo" / "target-app" / "compose.yaml").read_text(encoding="utf-8")
        self.assertEqual(compose.count("bash -o pipefail -c"), 2)
        self.assertNotIn('command: \'sh -c "python -m venv', compose)
        # Prove bash -o pipefail propagates non-zero exit past tee.
        res = subprocess.run(["bash", "-o", "pipefail", "-c", "false | tee /dev/null"], capture_output=True)
        self.assertNotEqual(res.returncode, 0)
        readme = (ROOT / "evals" / "demo" / "target-app" / "README.md").read_text(encoding="utf-8")
        self.assertIn("8-service compose stack", readme)
        self.assertIn("8-service stack", readme)
        self.assertIn("55 tests", readme)
        # Deliberate F4 PostgreSQL claim must remain untouched.
        self.assertIn("PostgreSQL", readme)
        seed_src = (ROOT / "evals" / "demo" / "target-app" / "app" / "seed.py").read_text(encoding="utf-8")
        self.assertIn("1. cd evals/demo/target-app", seed_src)


class ScriptHygieneAndDocsTests(unittest.TestCase):
    """C-07, C-08, C-16: script hygiene, W3-01 guards, and docs alignment."""

    def test_eval_agent_cmd_handles_whitespace_and_empty_quotes(self):
        for raw in ("   ", "\t\n ", "''", '""'):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"EVAL_AGENT_CMD": raw}):
                self.assertEqual(eval_mod._agent_cmd("EVAL_AGENT_CMD", "claude -p"), ["claude", "-p"])

    def test_validate_widened_orca_version_and_missing_pin_lint_file(self):
        self.assertEqual(validate.check_pin_version_claims(), [])
        for stale in ("v1.4.1000", "v1.5.0", "v2.0.0"):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "runtime").mkdir()
                (root / "runtime" / "pins.json").write_text(json.dumps({"orca": {"version": "v1.4.239"}}))
                (root / "README.md").write_text(f"Orca at or above the catalog pin **{stale}**\n", encoding="utf-8")
                with mock.patch.object(validate, "ROOT", root):
                    errs = validate.check_pin_version_claims()
                self.assertEqual(len(errs), 1, errs)
                self.assertIn(stale, errs[0])
        # Missing file in PIN_LINT_FILES when docs/ exists fails closed.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runtime").mkdir()
            (root / "docs").mkdir()
            (root / "runtime" / "pins.json").write_text(json.dumps({"orca": {"version": "v1.4.239"}}))
            (root / "README.md").write_text("clean\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", root):
                errs = validate.check_pin_version_claims()
            self.assertTrue(any("listed in PIN_LINT_FILES but missing" in e for e in errs), errs)

    def test_gen_badges_handles_corrupt_or_missing_releases_and_tests_badge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            errs_missing = gen_badges.last_release_badge_errors(root)
            self.assertTrue(errs_missing and "unreadable" in errs_missing[0], errs_missing)
            (root / "docs").mkdir()
            (root / "docs" / "releases.json").write_text("{not-json", encoding="utf-8")
            errs_corrupt = gen_badges.last_release_badge_errors(root)
            self.assertTrue(errs_corrupt and "unreadable" in errs_corrupt[0], errs_corrupt)
            (root / "docs" / "releases.json").write_text(
                json.dumps({"releases": [{"commit": "a" * 40}]}), encoding="utf-8",
            )
            errs_no_tag = gen_badges.last_release_badge_errors(root)
            self.assertTrue(errs_no_tag and "tag" in errs_no_tag[0], errs_no_tag)
            (root / "tests").mkdir()
            errs_cut = gen_badges.cut_badge_errors(root)
            self.assertTrue(errs_cut and "unreadable" in errs_cut[0], errs_cut)

    def test_release_check_help_documents_exit_3(self):
        r = subprocess.run(
            [sys.executable, "-I", str(ROOT / "scripts" / "release_check.py"), "--help"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("3: incomplete", r.stdout)

    def test_print_settings_snippet_requires_executable_gate_and_uses_dash_i(self):
        src = (ROOT / "hooks" / "print-settings-snippet.sh").read_text(encoding="utf-8")
        self.assertIn("cd -P", src)
        self.assertIn("pwd -P", src)
        self.assertIn("python3 -I", src)
        with tempfile.TemporaryDirectory(prefix="adv-snippet-") as tmp:
            root = Path(tmp)
            (root / "hooks").mkdir()
            (root / "runtime" / "scripts").mkdir(parents=True)
            shutil.copy2(ROOT / "hooks" / "print-settings-snippet.sh", root / "hooks" / "print-settings-snippet.sh")
            shutil.copy2(ROOT / "hooks" / "settings-snippet.json", root / "hooks" / "settings-snippet.json")
            gate = root / "runtime" / "scripts" / "verify-gate.sh"
            gate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            gate.chmod(0o644)  # exists, NOT executable
            r = subprocess.run(
                ["sh", str(root / "hooks" / "print-settings-snippet.sh"), "--check"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("non-executable", r.stderr)
            gate.chmod(0o755)
            r2 = subprocess.run(
                ["sh", str(root / "hooks" / "print-settings-snippet.sh"), "--check"],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_a2a_scripts_have_canonical_w301_guard_and_ignore_planted_shadow(self):
        for rel in ("scripts/a2a_export.py", "scripts/a2a_schema.py"):
            with self.subTest(rel=rel):
                _assert_canonical_guard(self, rel)
        with tempfile.TemporaryDirectory(prefix="adv-w301-a2a-") as tmp:
            tree = Path(tmp)
            shutil.copytree(
                ROOT / "scripts", tree / "scripts",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            shutil.copytree(
                ROOT / "runtime", tree / "runtime",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            (tree / "scripts" / "json.py").write_text(PLANT_SHADOW, encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
            for name in ("a2a_export.py", "a2a_schema.py"):
                with self.subTest(run=name):
                    r = subprocess.run(
                        [sys.executable, str(tree / "scripts" / name), "--help"],
                        cwd=tree, env=env, capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(list((tree / "scripts").glob("PLANT-*")), [])

    def test_docs_ops_and_runtime_scripts_reflect_hardened_behavior(self):
        ops = (ROOT / "docs" / "ops.md").read_text(encoding="utf-8")
        self.assertIn("#771", ops)
        self.assertIn("0 active CodeBuild jobs", ops)
        self.assertIn("fourteen workflow jobs", ops)
        self.assertIn("nine jobs", ops)
        self.assertIn("#779-3", ops)
        self.assertIn("post-veto `OWNER` GO", ops)
        for path_tok in ("bench/vf-bench/", "ruff.toml", ".ruff.toml", ".coveragerc", ".gitleaks.toml", ".gitleaksignore"):
            self.assertIn(path_tok, ops)
        rs = (ROOT / "docs" / "runtime-scripts.md").read_text(encoding="utf-8")
        for token in (
            "#775", "OPEN_FLEET_CLI_COMMAND", "--base REF", "#772",
            "_strip_emit_controls", "sliding 2-line and 3-line", "#780",
            "MAX_PAGES", "ProbeError", "#788",
            "OPEN_FLEET_MAX_BUDGET_USD", "OPEN_FLEET_REQUIRE_BUDGET", "#759",
        ):
            self.assertIn(token, rs)


def _assert_canonical_guard(test: unittest.TestCase, rel: str):
    tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"), filename=rel)
    body = list(tree.body)
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    test.assertGreaterEqual(len(body), 2, rel)
    test.assertTrue(isinstance(body[0], ast.Import) and [a.name for a in body[0].names] == ["sys"], rel)
    test.assertEqual(ast.dump(body[1]), CANONICAL_GUARD_STMT, rel)
    futures = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
    test.assertEqual(futures, [], f"{rel} has from __future__ import")


if __name__ == "__main__":
    unittest.main()
