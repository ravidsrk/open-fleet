#!/usr/bin/env python3
"""The container-based live harness: its launcher (scripts/live_container.py), its credential
broker (scripts/live_broker.py) and the arm's `claude` (scripts/live_container_bin/claude).

The launcher's tests drive it against a STAND-IN `docker`, first on PATH, that records each call's
argv (and what the call could see: the token in its environment, the export, the attestation and
the token's file it was asked to mount) and answers from a scenario. The broker's tests run it on
127.0.0.1 against a stand-in API on 127.0.0.1. No test reaches the real docker or the network,
builds an image or downloads anything. What is pinned is what a careless harness gets wrong: a
token any process of the arm can read, on a command line, in an environment `docker inspect`
shows, in a receipt or a log; a model call that passes the cap; a ledger that dies with the
container; two launches at once; a container that outlives its limit; and a teardown that loses
the receipt.

    python3 -m unittest tests.test_live_container -v
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import platform
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "live_container.py"
_spec = importlib.util.spec_from_file_location("live_container_under_test", SCRIPT)
lc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lc)
_spec = importlib.util.spec_from_file_location("live_broker_under_test", ROOT / "scripts" / "live_broker.py")
lb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lb)

CID = "c0ffee" + "0" * 58  # the arm's container
BID = "b40c3e" + "0" * 58  # the broker's container
SECRET = "/run/secrets/claude_token"  # where the broker reads the token: a read-only file mount
WRAPPER = ROOT / "scripts" / "live_container_bin" / "claude"  # the arm's `claude`, first on PATH
IMAGE_ID = "sha256:" + "ab" * 32

# The stand-in docker. It appends one JSON line per call to $FAKE_DOCKER_LOG and answers from the
# scenario in $FAKE_DOCKER_SCENARIO. At `create` it also reads what the launcher asked it to mount
# while it still exists: the export's HEAD and status, the attestation and the token file; a
# broker's create writes the scenario's ledger lines into the ledger directory it was given.
STAND_IN = r'''#!{python}
import json, os, subprocess, sys, time
argv = sys.argv[1:]
scenario = json.load(open(os.environ["FAKE_DOCKER_SCENARIO"]))
entry = {"argv": argv, "token": os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")}
role = "arm" if "--network" in argv else "broker"
if argv[:1] == ["create"]:
    mounts = {}
    for i, arg in enumerate(argv):
        if arg == "--mount":
            fields = dict(f.split("=", 1) if "=" in f else (f, True) for f in argv[i + 1].split(","))
            mounts[fields["dst"]] = fields
    entry["mounts"], entry["role"] = mounts, role
    src = mounts.get("/repo", {}).get("src")
    if src:
        git = lambda *a: subprocess.run(["git", "-C", src, *a], capture_output=True, text=True).stdout
        entry["repo_head"], entry["repo_status"] = git("rev-parse", "HEAD").strip(), git("status", "--porcelain")
    att = mounts.get(scenario["attestation_path"], {}).get("src")
    if att:
        entry["attestation"] = json.load(open(att))
    sec = mounts.get(scenario["secret_path"], {}).get("src")
    if sec:
        entry["secret"] = open(sec).read().strip()
    settings = mounts.get("/run/open-fleet/claude.json", {}).get("src")
    if settings:
        entry["claude_settings"] = json.load(open(settings))
    ledger = mounts.get("/ledger", {}).get("src")
    if ledger and scenario.get("ledger_lines"):
        with open(os.path.join(ledger, "spend.jsonl"), "w") as fh:
            fh.write("".join(json.dumps(line) + "\n" for line in scenario["ledger_lines"]))
if argv[:1] == ["build"]:
    entry["context"] = sorted(os.listdir(argv[-1]))
    if scenario.get("edit_during_build"):  # the Dockerfile changes while docker reads it
        with open(argv[argv.index("-f") + 1], "ab") as fh:
            fh.write(b"RUN echo changed during the build\n")
    if "--iidfile" in argv and not scenario.get("build_exit"):  # the id THIS build produced
        with open(argv[argv.index("--iidfile") + 1], "w") as fh:
            fh.write(scenario.get("built_id") or (scenario.get("image") or {}).get("Id") or "")
with open(os.environ["FAKE_DOCKER_LOG"], "a") as fh:
    fh.write(json.dumps(entry) + "\n")
if argv[:1] == ["kill"] and "kill" in scenario.get("fail", []):
    sys.stderr.write("Error response from daemon: cannot kill container\n")
    sys.exit(1)
if argv[:1] in (["kill"], ["rm"], ["create"]) and argv[0] in scenario.get("hang", []):
    time.sleep(scenario.get("hang_s", 5))  # a create that hangs has already made its container: `orphan`
if argv[:2] == ["image", "inspect"]:
    image = scenario.get("images_by_ref", {}).get(argv[-1], scenario.get("image"))
    if image is None:
        sys.stderr.write("Error: No such image\n")
        sys.exit(1)
    print(json.dumps(image))
elif argv[:1] == ["ps"]:
    flt = argv[argv.index("--filter") + 1]
    if flt == "label=" + scenario["label"]:
        print(scenario.get("leftovers", ""))
    else:  # this launch's own containers, by its nonce: the verification
        if "verify" in scenario.get("hang", []):
            time.sleep(scenario.get("hang_s", 5))
        if scenario.get("survive_checks"):  # listed for the first N verifications, then gone
            seen = sum(1 for line in open(os.environ["FAKE_DOCKER_LOG"])
                       if json.loads(line)["argv"][:4] == argv[:4])
            if seen <= scenario["survive_checks"]:
                print(scenario["cid"])
                sys.exit(0)
        orphan = scenario.get("orphan")
        removed = any(json.loads(line)["argv"] == ["rm", "-f", orphan] for line in open(os.environ["FAKE_DOCKER_LOG"]))
        print(orphan if orphan and not removed else scenario.get("survivor", ""))
elif argv[:1] == ["create"]:
    print(scenario["cid"] if role == "arm" else scenario["bid"])
elif argv[:1] == ["start"] and "--attach" in argv:
    sys.stdout.write(scenario.get("output", ""))
    sys.stdout.flush()
    time.sleep(scenario.get("sleep", 0))
    sys.exit(scenario.get("exit", 0))
elif argv[:1] == ["start"]:
    sys.exit(scenario.get("broker_start_exit", 0))
elif argv[:1] == ["exec"]:  # the broker's /health, probed inside its container
    sys.exit(scenario.get("broker_ready_exit", 0))
elif argv[:1] == ["build"]:
    sys.exit(scenario.get("build_exit", 0))
'''


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                          capture_output=True, text=True, check=True).stdout.strip()


class Harness(unittest.TestCase):
    """A fixture checkout holding every entry point, a token file, and the stand-in docker."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="live-container-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.repo = self.tmp / "repo"
        for script in [s for s, *_prefix in lc.ARMS.values()] + [lc.BROKER_SCRIPT]:
            path = self.repo / script
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("print('arm')\n", encoding="utf-8")
        (self.repo / WRAPPER.parent.relative_to(ROOT)).mkdir(parents=True)
        shutil.copy2(WRAPPER, self.repo / WRAPPER.relative_to(ROOT))
        # The commit holds the Dockerfile: a launch trusts the digest of the copy its commit holds.
        shutil.copy2(lc.DOCKERFILE, self.repo / lc.DOCKERFILE_REL)
        git(self.repo.parent, "init", "-q", str(self.repo))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        self.token = "fixture-oauth-token-" + os.urandom(8).hex()
        self.token_file = self.tmp / "oauth-token"
        self.token_file.write_text(self.token + "\n", encoding="utf-8")
        self.token_file.chmod(0o600)
        self.results, self.receipts, self.lock = self.tmp / "results", self.tmp / "receipts", self.tmp / "launch.lock"
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        stand_in = bin_dir / "docker"
        stand_in.write_text(STAND_IN.replace("{python}", sys.executable), encoding="utf-8")
        stand_in.chmod(0o755)
        self.log = self.tmp / "docker.jsonl"
        self.scenario_path = self.tmp / "scenario.json"
        self.scenario({})
        env = {k: v for k, v in os.environ.items() if k != lc.TOKEN_ENV}
        env.update(PATH=os.pathsep.join([str(bin_dir), env.get("PATH", "")]), FAKE_DOCKER_LOG=str(self.log),
                   FAKE_DOCKER_SCENARIO=str(self.scenario_path))
        # The launcher's own record of the images its `build` produced, kept here, never in the
        # operator's ~/of-live: the fixture image is one it built from the committed Dockerfile.
        self.images = self.tmp / "images.json"
        self.images.write_text(json.dumps({IMAGE_ID: {"ref": lc.IMAGE, "dockerfile_sha256": lc.sha256_file(lc.DOCKERFILE)}}),
                               encoding="utf-8")
        for patch in (mock.patch.dict(os.environ, env, clear=True), mock.patch.object(lc, "REPO", self.repo),
                      mock.patch.object(lc, "IMAGES", str(self.images), create=True)):
            patch.start()
            self.addCleanup(patch.stop)
        self.assertEqual(shutil.which("docker"), str(stand_in), "a test would reach the real docker")

    def scenario(self, overrides):
        doc = {"image": {"Id": IMAGE_ID, "RepoDigests": ["open-fleet-live@sha256:" + "cd" * 32],
                         "Config": {"Labels": {lc.DOCKERFILE_LABEL: lc.sha256_file(lc.DOCKERFILE)}}},
               "cid": CID, "bid": BID, "label": lc.LABEL, "attestation_path": lc.containment.ATTESTATION,
               "secret_path": SECRET, **overrides}
        self.scenario_path.write_text(json.dumps(doc), encoding="utf-8")

    def launch(self, *extra, arm="wip_curve", arm_args=("run", "--results", "/results/wip"), timeout="600",
               cap="50"):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = lc.main(["run", "--arm", arm, "--results", str(self.results), "--timeout", timeout, "--cap-usd", cap,
                          "--token-file", str(self.token_file), "--receipts", str(self.receipts),
                          "--lock", str(self.lock), *extra, "--", *arm_args])
        return rc, err.getvalue()

    def calls(self, partial=False):
        """Every call the stand-in recorded; `partial`: tolerate a line it is still writing."""
        if not self.log.is_file():
            return []
        out = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                if not partial:
                    raise
        return out

    def create(self, role):
        found = [c for c in self.calls() if c["argv"][:1] == ["create"] and c["role"] == role]
        self.assertEqual(len(found), 1, [c["argv"][:2] for c in self.calls()])
        return found[0]

    def creates(self):
        return [c for c in self.calls() if c["argv"][:1] == ["create"]]

    def receipt(self):
        found = sorted(self.receipts.glob("*.json"))
        self.assertEqual(len(found), 1, found)
        return json.loads(found[0].read_text(encoding="utf-8"))


class OneArmRunsAndBothContainersAreVerifiedDestroyed(Harness):
    def test_the_receipt_binds_the_run(self):
        self.scenario({"exit": 7})
        rc, err = self.launch()
        self.assertEqual(rc, 7, err)
        r = self.receipt()
        self.assertEqual(r["schema"], lc.RECEIPT_SCHEMA)
        self.assertEqual((r["arm"], r["arm_args"]), ("wip_curve", ["run", "--results", "/results/wip"]))
        self.assertEqual(r["commit"], self.commit)
        self.assertEqual(r["image"]["id"], IMAGE_ID)
        self.assertTrue(r["image"]["from_committed_dockerfile"])
        self.assertRegex(r["nonce"], r"^[0-9a-f]{32}$")
        self.assertEqual((r["container"]["id"], r["broker"]["id"]), (CID, BID))
        self.assertEqual(r["broker"]["cap_usd"], 50.0)
        self.assertTrue(r["started_at"] and r["ended_at"])
        self.assertEqual((r["exit_status"], r["timed_out"], r["refused"]), (7, False, None))
        self.assertIs(r["destroyed"]["verified"], True)
        self.assertEqual(r["destroyed"]["check"],
                         ["docker", "ps", "-a", "--filter", f"label={lc.LABEL}={r['nonce']}", "--format", "{{.ID}}"])
        verbs = [c["argv"][:2] if c["argv"][0] == "start" else c["argv"][:1] for c in self.calls()]
        self.assertLess(verbs.index(["start", BID]), verbs.index(["start", "--attach"]), "the arm started first")
        self.assertLess(verbs.index(["start", "--attach"]), verbs.index(["rm"]), verbs)
        self.assertEqual(verbs[-1], ["ps"], "the last word is the verification")
        for cid in (CID, BID):
            self.assertIn(["rm", "-f", cid], [c["argv"] for c in self.calls()])

    def test_the_arm_starts_only_once_the_broker_answers_inside_its_container(self):
        self.launch()
        argvs = [c["argv"] for c in self.calls()]
        probe = next(i for i, a in enumerate(argvs) if a[:2] == ["exec", BID])
        self.assertEqual(argvs[probe][2:4], ["python3", "-I"])
        self.assertIn(f"http://127.0.0.1:{lc.BROKER_PORT}/health", argvs[probe][-1])
        self.assertLess(probe, argvs.index(["start", "--attach", CID]))

    def test_the_arm_runs_the_pinned_commit_read_only_and_writes_only_the_results(self):
        self.launch()
        create = self.create("arm")
        self.assertEqual(create["repo_head"], self.commit)
        self.assertEqual(create["repo_status"], "", "the mounted export is not a clean checkout of the commit")
        mounts = create["mounts"]
        self.assertEqual(sorted(mounts), sorted(["/repo", "/results", lc.containment.ATTESTATION]))
        self.assertIs(mounts["/repo"].get("readonly"), True)
        self.assertIs(mounts[lc.containment.ATTESTATION].get("readonly"), True)
        self.assertNotIn("readonly", mounts["/results"])
        self.assertEqual(mounts["/results"]["src"], str(self.results))
        self.assertNotEqual(Path(mounts["/repo"]["src"]).resolve(), self.repo, "the operator's checkout was mounted")
        self.assertFalse(Path(mounts["/repo"]["src"]).exists(), "the export outlived the run")

    def test_the_attestation_is_this_launchs_nonce_and_lifts_the_check_inside(self):
        self.launch()
        arm, broker, r = self.create("arm"), self.create("broker"), self.receipt()
        # the arm's container joins the broker's network namespace, and with it the broker's hostname
        self.assertNotIn("--hostname", arm["argv"])
        hostname = broker["argv"][broker["argv"].index("--hostname") + 1]
        self.assertEqual(arm["attestation"]["nonce"], r["nonce"])
        # the host's name, hashed, so a run inside names one machine across launches (#604)
        self.assertEqual(arm["attestation"]["host_sha256"],
                         hashlib.sha256((platform.node() or "host").encode()).hexdigest())
        self.assertEqual(arm["attestation"]["commit"], self.commit)
        self.assertEqual(hostname, lc.containment.HARNESS_HOSTNAME + r["nonce"])
        for create in (arm, broker):
            self.assertIn(f"{lc.LABEL}={r['nonce']}", create["argv"])
        # what the launcher writes is what the check inside the container reads
        root = self.tmp / "container-root"
        att = root / lc.containment.ATTESTATION.lstrip("/")
        att.parent.mkdir(parents=True)
        att.write_text(json.dumps(arm["attestation"]), encoding="utf-8")
        (root / ".dockerenv").write_text("", encoding="utf-8")
        self.assertIsNone(lc.containment.harness_problem(root=root, hostname=hostname, probe=lambda: None))

    def test_each_arm_runs_its_own_entry_point_under_an_in_container_backstop(self):
        for arm, (script, *prefix) in lc.ARMS.items():
            with self.subTest(arm=arm):
                shutil.rmtree(self.receipts, ignore_errors=True)
                self.log.unlink(missing_ok=True)
                outs = ("--out", "/results/o", "--workdir", "/results/w")
                rc, err = self.launch(arm=arm, arm_args=("--x", "1", *outs), timeout="600")
                self.assertEqual(rc, 0, err)
                argv = self.create("arm")["argv"]
                tail = argv[argv.index(IMAGE_ID) + 1:]
                self.assertEqual(tail, ["timeout", "--kill-after=30", str(600 + lc.BACKSTOP_S), "python3",
                                        f"/repo/{script}", *prefix, "--x", "1", *outs])
        self.assertEqual(sorted(lc.ARMS), ["ablation", "first_run", "hint_replay", "trajectories", "wip_curve"])
        self.assertEqual(sorted(lc.OUTPUTS), sorted(lc.ARMS))


class BothContainersAreHardened(Harness):
    def test_non_root_limited_unprivileged_and_on_no_host_namespace(self):
        self.launch()
        for create in self.creates():
            role, argv = create["role"], create["argv"]
            with self.subTest(role=role):
                pairs = {argv[i]: argv[i + 1] for i in range(len(argv) - 1) if argv[i].startswith("--")}
                limits = lc.LIMITS if role == "arm" else lc.BROKER_LIMITS
                self.assertIn("--rm", argv)
                self.assertIn("--init", argv)
                # the arm as the image's runner; the broker as the operator, so it can read their token on Linux
                self.assertEqual(pairs["--user"], lc.USER if role == "arm" else f"{os.getuid()}:{os.getgid()}")
                self.assertFalse(pairs["--user"].split(":")[0] in ("0", "root"))
                self.assertEqual(pairs["--pids-limit"], str(limits["pids"]))
                self.assertEqual((pairs["--memory"], pairs["--memory-swap"]), (limits["memory"], limits["memory"]))
                self.assertEqual(pairs["--cpus"], limits["cpus"])
                self.assertEqual(pairs["--cap-drop"], "ALL")
                self.assertEqual(pairs["--security-opt"], "no-new-privileges")
                self.assertEqual(pairs["--log-driver"], "none")
                for banned in ("--privileged", "--cap-add", "--device", "--pid", "--ipc", "--uts", "--userns", "--net",
                               "-v", "--volume", "--volumes-from", "--add-host", "--group-add", "--env-file", "-p",
                               "--publish", "--publish-all"):
                    self.assertNotIn(banned, argv)
                self.assertFalse(any("docker.sock" in a for a in argv))
                networks = [argv[i + 1] for i, a in enumerate(argv) if a == "--network"]
                self.assertEqual(networks, [f"container:{BID}"] if role == "arm" else [],
                                 "the arm shares anything but the broker's network, or the broker anything at all")

    def test_the_limits_are_the_operators_to_set(self):
        self.launch("--pids-limit", "64", "--memory", "1g", "--cpus", "1.5")
        argv = self.create("arm")["argv"]
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "64")
        self.assertEqual(argv[argv.index("--memory") + 1], "1g")
        self.assertEqual(argv[argv.index("--cpus") + 1], "1.5")
        self.assertEqual(self.receipt()["container"]["limits"], {"pids": 64, "memory": "1g", "cpus": "1.5"})


class TheTokenStaysInTheBrokersContainer(Harness):
    """Codex at 47e0616eac: a token mounted in the arm's container is readable by uid 10001, which
    runs the agents and every test they write. The token is mounted in the broker's container
    alone; the arm's holds no credential and shares only the broker's network namespace."""

    def test_the_arms_container_holds_no_credential(self):
        rc, err = self.launch()
        self.assertEqual(rc, 0, err)
        arm = self.create("arm")
        self.assertNotIn(SECRET, arm["mounts"])
        self.assertNotIn("secret", arm, "the arm's container was given the token file")
        envs = [arm["argv"][i + 1] for i, a in enumerate(arm["argv"]) if a in ("--env", "-e")]
        self.assertEqual(envs, [f"PATH={lc.CONTAINER_PATH}"], "the arm's environment carries anything but PATH")

    def test_the_broker_alone_mounts_it_read_only_and_runs_under_the_cap(self):
        self.launch(cap="12.5")
        broker, r = self.create("broker"), self.receipt()
        mount = broker["mounts"][SECRET]
        self.assertEqual(mount["src"], str(self.token_file))
        self.assertIs(mount.get("readonly"), True)
        self.assertEqual(broker["secret"], self.token, "the mount does not carry the operator's token")
        argv = broker["argv"]
        envs = [argv[i + 1] for i, a in enumerate(argv) if a in ("--env", "-e")]
        self.assertEqual(envs, ["PATH=/usr/local/bin:/usr/bin:/bin"])
        tail = argv[argv.index(IMAGE_ID) + 1:]
        self.assertEqual(tail[3:6], ["python3", "-I", f"/repo/{lc.BROKER_SCRIPT}"])
        self.assertEqual(tail[tail.index("--cap-usd") + 1], "12.5")
        self.assertEqual(tail[tail.index("--token-file") + 1], SECRET)
        self.assertEqual(tail[tail.index("--port") + 1], str(lc.BROKER_PORT))
        ledger = Path(broker["mounts"]["/ledger"]["src"])
        self.assertNotIn("readonly", broker["mounts"]["/ledger"])
        self.assertEqual(ledger.parent, self.receipts, "the broker's ledger is not beside the receipt")
        self.assertFalse(lc.inside(ledger, self.results), "the arm could reach the broker's ledger")
        self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o700)
        self.assertEqual(r["token"]["mounted_at"], SECRET)

    def test_no_command_line_environment_receipt_or_log_carries_it(self):
        self.scenario({"output": f"an arm that printed it: {self.token}\n"})
        rc, err = self.launch()
        self.assertEqual(rc, 0, err)
        for c in self.calls():
            self.assertFalse(any(self.token in a for a in c["argv"]), c["argv"][:2])
            self.assertFalse(any(lc.TOKEN_ENV in a for a in c["argv"]), f"docker {c['argv'][0]} names the token")
            self.assertIsNone(c["token"], f"docker {c['argv'][0]} ran with the token in its environment")
        r = self.receipt()
        self.assertNotIn(self.token, json.dumps(r))
        self.assertNotIn(self.token, err)
        log = Path(r["log"])
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600, "the log is readable by others")
        text = log.read_text(encoding="utf-8")
        self.assertNotIn(self.token, text)
        self.assertIn("[REDACTED]", text)
        self.assertEqual(r["token_redactions"], 1)

    def test_a_token_file_the_arm_could_reach_is_refused(self):
        # Codex at 8585b35789: a token file inside the results mount reached the arm as /results/<name>
        self.results.mkdir()
        inside_results = self.results / "sub" / "oauth-token"
        inside_results.parent.mkdir()
        shutil.copy2(self.token_file, inside_results)
        alias = self.tmp / "alias"
        alias.symlink_to(self.results / "sub")  # a symlinked ancestor reaches the same file
        for token_file in (inside_results, alias / "oauth-token", self.repo / "oauth-token"):
            with self.subTest(token_file=token_file):
                self.token_file = token_file
                rc, err = self.launch()
                self.assertEqual(rc, 2, err)
                self.assertIn("which the arm's container mounts", err)
        self.assertEqual(self.calls(), [])

    def test_a_missing_token_file_is_refused_before_docker_is_called(self):
        self.token_file.unlink()
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("cannot be opened", err)
        self.assertEqual(self.calls(), [])

    def test_a_token_file_others_can_read_a_link_or_an_empty_file_is_refused(self):
        def refused():
            rc, err = self.launch()
            self.assertEqual(rc, 2, err)
            self.assertNotIn(self.token, err)
            self.assertEqual(self.calls(), [], "docker was called with no usable token")
            return err
        self.token_file.chmod(0o644)
        self.assertIn("readable by others", refused())
        self.token_file.chmod(0o600)
        link = self.tmp / "token-link"
        link.symlink_to(self.token_file)
        self.token_file, real = link, self.token_file
        refused()
        self.token_file = real
        real.write_text("\n", encoding="utf-8")
        self.assertIn("one line", refused())


class TheLogIsRedactedAsItIsWritten(unittest.TestCase):
    """Greptile and Codex at 47e0616eac: the output reached the disk first and was redacted at the
    end, so a killed launcher left the token in a world-readable file. Now no byte of it is ever
    written: the stream passes a redactor that holds back only what could begin the token."""

    class Sink(io.BytesIO):
        def close(self):  # the redactor closes its file at the end: keep the bytes readable
            pass

    def redact(self, chunks, secret=b"sk-ant-oat01-SECRET"):
        out = self.Sink()
        redactor = lc.Redactor(out, secret)
        written = []
        for chunk in chunks:
            redactor.write(chunk)
            written.append(out.getvalue())
        redactor.close()
        return out.getvalue(), redactor.count, written

    def test_a_token_split_across_reads_never_reaches_the_file(self):
        secret = b"sk-ant-oat01-SECRET"
        for cut in range(1, len(secret)):
            with self.subTest(cut=cut):
                text, count, written = self.redact([b"before " + secret[:cut], secret[cut:] + b" after"])
                self.assertEqual(text, b"before [REDACTED] after")
                self.assertEqual(count, 1)
                self.assertEqual(written[0], b"before ", "a piece of the token was written before the rest came")

    def test_what_only_looked_like_a_start_is_written_out_at_the_end(self):
        text, count, _ = self.redact([b"sk-ant", b"-oat01-SEC"])
        self.assertEqual((text, count), (b"sk-ant-oat01-SEC", 0))

    def test_every_occurrence_is_counted(self):
        text, count, _ = self.redact([b"a sk-ant-oat01-SECRET b sk-ant-oat01-SECRET", b"sk-ant-oat01-SECRET"])
        self.assertEqual((text, count), (b"a [REDACTED] b [REDACTED][REDACTED]", 3))


class TheBrokersLedgerIsSummarisedInTheReceipt(Harness):
    def test_the_receipt_carries_what_the_broker_settled_and_left_open(self):
        self.scenario({"ledger_lines": [
            {"event": "open", "cap_usd": 50.0},
            {"event": "start", "call": 1, "reserved_usd": 2.0},
            {"event": "settle", "call": 1, "cost_usd": 0.75, "complete": True},
            {"event": "start", "call": 2, "reserved_usd": 1.5},
            {"event": "refuse", "why": "the cap"}]})
        rc, err = self.launch()
        self.assertEqual(rc, 0, err)
        spend = self.receipt()["broker"]["spend"]
        self.assertEqual({k: v for k, v in spend.items() if k != "ledger"},
                         {"read": True, "cap_usd": 50.0, "calls": 2, "refused": 1, "settled_usd": 0.75,
                          "unsettled_calls": 1, "unsettled_reserved_usd": 1.5})

    def test_a_ledger_the_broker_never_wrote_says_so(self):
        self.launch()
        spend = self.receipt()["broker"]["spend"]
        self.assertEqual((spend["read"], spend["error"]), (False, "FileNotFoundError"))


class OutputsStayUnderResults(Harness):
    """Codex at 47e0616eac: ablation and trajectories defaulted --out to a temp dir inside the
    container, so destroying it erased the ledger. An arm whose ledger defaults to a temp dir must
    name one, and every output flag must name a path under /results."""

    def refused(self, arm, arm_args, why):
        self.log.unlink(missing_ok=True)
        rc, err = self.launch(arm=arm, arm_args=arm_args)
        self.assertEqual(rc, 2, err)
        self.assertIn(why, err)
        self.assertEqual(self.calls(), [], "docker was called for a launch whose ledger would die with it")

    def test_an_arm_whose_ledger_defaults_to_a_temp_dir_must_name_one(self):
        self.assertEqual(lc.REQUIRED["first_run"], "--workdir", "first_run's receipt.json dies in a temp workdir")
        for arm in sorted(lc.REQUIRED):
            with self.subTest(arm=arm):
                self.refused(arm, ("run", "--tier", "live"), f"needs {lc.REQUIRED[arm]} under /results")

    def test_an_output_outside_results_is_refused(self):
        cases = [("ablation", ("run", "--out", "/tmp/x")), ("ablation", ("run", "--out=../x")),
                 ("ablation", ("run", "--ou", "/repo/x")), ("trajectories", ("--out", "/results/../etc")),
                 ("wip_curve", ("run", "--results", "/tmp/wip")), ("wip_curve", ("report", "--out", "/home/x")),
                 ("first_run", ("run", "--workdir", "/tmp/sb"))]
        for arm, arm_args in cases:
            with self.subTest(arm=arm, arm_args=arm_args):
                self.refused(arm, arm_args, "is outside /results")
        self.refused("ablation", ("run", "--out"), "names no path")

    def test_an_output_under_results_runs(self):
        for arm, arm_args in (("ablation", ("run", "--out", "out")), ("hint_replay", ("--out=/results/a/r.json",)),
                              ("trajectories", ("--out", "/results")), ("first_run", ("run", "--workdir", "w"))):
            with self.subTest(arm=arm, arm_args=arm_args):
                shutil.rmtree(self.receipts, ignore_errors=True)
                rc, err = self.launch(arm=arm, arm_args=arm_args)
                self.assertEqual(rc, 0, err)


class OneLaunchAtATime(Harness):
    def test_a_held_lock_refuses_before_any_container(self):
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # another launcher, mid-launch
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("another launch holds", err)
        self.assertEqual([c["argv"][0] for c in self.calls() if c["argv"][0] in ("ps", "create")], [],
                         "the leftover check or a create ran without the lock")

    def test_the_lock_is_released_however_the_launch_ends(self):
        for scenario in ({"exit": 1}, {"leftovers": "deadbeef"}):
            with self.subTest(scenario=scenario):
                self.scenario(scenario)
                shutil.rmtree(self.receipts, ignore_errors=True)
                self.launch()
                fd = os.open(self.lock, os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)

    def test_a_harness_container_that_still_exists_refuses_the_next_launch(self):
        self.scenario({"leftovers": "deadbeef"})
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("already exists", err)
        self.assertEqual(self.creates(), [])


class RefusalsCreateNothing(Harness):
    def test_a_dirty_checkout_is_refused_before_docker_is_called(self):
        (self.repo / "untracked.py").write_text("x = 1\n", encoding="utf-8")
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("dirty", err)
        self.assertEqual(self.calls(), [])

    def test_an_unbuilt_image_is_refused(self):
        self.scenario({"image": None})
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("build it first", err)
        self.assertEqual(self.creates(), [])

    def test_a_cap_that_is_not_positive_is_refused(self):
        for cap in ("0", "-5", "nan"):
            with self.subTest(cap=cap):
                rc, err = self.launch(cap=cap)
                self.assertEqual(rc, 2, err)
                self.assertIn("--cap-usd", err)
        self.assertEqual(self.calls(), [])

    def test_an_image_not_built_from_the_committed_dockerfile_is_refused_unless_named(self):
        # 2026-10-27 audit, W5-13: `from_committed_dockerfile` was recorded and never gated on.
        for labels in ({}, {lc.DOCKERFILE_LABEL: "0" * 64}):
            with self.subTest(labels=labels):
                self.scenario({"image": {"Id": IMAGE_ID, "RepoDigests": [], "Config": {"Labels": labels}}})
                rc, err = self.launch()
                self.assertEqual(rc, 2, err)
                self.assertIn("committed Dockerfile", err)
                self.assertEqual(self.creates(), [])
        rc, err = self.launch("--allow-foreign-image")
        self.assertEqual(rc, 0, err)
        image = self.receipt()["image"]
        self.assertIs(image["from_committed_dockerfile"], False)
        self.assertIs(image["foreign_image_allowed"], True, "the opt-in is not on the record")

    def test_an_image_derived_from_the_launchers_own_is_refused_despite_its_inherited_label(self):
        # Re-attack of 82a2d00c (W5-13): docker copies a parent's labels to a child, so
        # `FROM open-fleet-live` + any RUN carried the committed Dockerfile's digest label and the
        # label-only gate passed it. The gate is the launcher's own record of what its build made.
        derived = "sha256:" + "ee" * 32
        self.scenario({"image": {"Id": derived, "RepoDigests": [],
                                 "Config": {"Labels": {lc.DOCKERFILE_LABEL: lc.sha256_file(lc.DOCKERFILE)}}}})
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("not built by this launcher", err)
        self.assertEqual(self.creates(), [])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(lc.main(["build"]), 0)
        self.assertIn(derived, json.loads(self.images.read_text(encoding="utf-8")), "a build is not recorded")
        rc, err = self.launch()
        self.assertEqual(rc, 0, err)
        self.assertIs(self.receipt()["image"]["built_by_this_launcher"], True)

    def test_the_build_records_the_id_it_produced_not_what_its_tag_names_after(self):
        # Re-attack of 4b24dfde (W5-13): `build` recorded the id `docker image inspect <tag>` found
        # once the build was over, so a tag moved to another image in between (a second build of a
        # changed Dockerfile, a `docker tag`) was recorded as built from the committed Dockerfile.
        built, moved = "sha256:" + "11" * 32, "sha256:" + "22" * 32
        label = {lc.DOCKERFILE_LABEL: lc.sha256_file(lc.DOCKERFILE)}
        self.scenario({"built_id": built,
                       "images_by_ref": {built: {"Id": built, "RepoDigests": [], "Config": {"Labels": label}}},
                       "image": {"Id": moved, "RepoDigests": [], "Config": {"Labels": label}}})
        self.images.unlink()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(lc.main(["build"]), 0)
        self.assertEqual(list(json.loads(self.images.read_text(encoding="utf-8"))), [built])
        rc, err = self.launch()  # the tag names `moved` now, which no build of this launcher made
        self.assertEqual(rc, 2, err)
        self.assertIn("not built by this launcher", err)
        self.assertEqual(self.creates(), [])

    def test_an_uncommitted_dockerfile_edit_never_builds_or_runs_as_the_committed_one(self):
        # Re-attack of 2d254d0f (W5-13): `build` labelled and recorded the digest of the Dockerfile
        # ON DISK, and a launch compared the label to the same file, so an uncommitted edit -- one
        # `git update-index --skip-worktree` keeps out of the dirty check -- was built, recorded and
        # run with `from_committed_dockerfile: true`. Both digests are now the git object's.
        dockerfile = self.repo / lc.DOCKERFILE_REL
        edited = dockerfile.read_bytes() + b"RUN echo an uncommitted edit\n"
        dockerfile.write_bytes(edited)
        git(self.repo, "update-index", "--skip-worktree", lc.DOCKERFILE_REL)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "", "the edit is not hidden from the dirty check")
        committed = hashlib.sha256(subprocess.run(["git", "-C", str(self.repo), "cat-file", "blob",
                                                  f"HEAD:{lc.DOCKERFILE_REL}"], capture_output=True,
                                                 check=True).stdout).hexdigest()
        digest = hashlib.sha256(edited).hexdigest()
        self.assertNotEqual(digest, committed)
        with mock.patch.object(lc, "DOCKERFILE", dockerfile):  # the launcher's own checkout, as in use
            before = self.images.read_bytes()
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = lc.main(["build"])
            self.assertEqual(rc, 2, err.getvalue())
            self.assertIn("committed at HEAD", err.getvalue())
            self.assertEqual([c for c in self.calls() if c["argv"][:1] == ["build"]], [], "an uncommitted edit was built")
            self.assertEqual(self.images.read_bytes(), before, "an uncommitted edit was recorded")
            # Built by hand and recorded with its own digest, the edit still never runs as committed.
            self.images.write_text(json.dumps({IMAGE_ID: {"ref": lc.IMAGE, "dockerfile_sha256": digest}}),
                                   encoding="utf-8")
            self.scenario({"image": {"Id": IMAGE_ID, "RepoDigests": [], "Config": {"Labels": {lc.DOCKERFILE_LABEL: digest}}}})
            rc, err = self.launch()
            self.assertEqual(rc, 2, err)
            self.assertIn("committed Dockerfile", err)
            self.assertEqual(self.creates(), [])
            rc, err = self.launch("--allow-foreign-image")
        self.assertEqual(rc, 0, err)
        image = self.receipt()["image"]
        self.assertIs(image["from_committed_dockerfile"], False)
        self.assertEqual(image["committed_dockerfile_sha256"], committed)

    def test_a_dockerfile_changed_while_docker_builds_it_is_not_recorded(self):
        dockerfile = self.repo / lc.DOCKERFILE_REL
        self.scenario({"edit_during_build": True})
        self.images.unlink()
        err = io.StringIO()
        with mock.patch.object(lc, "DOCKERFILE", dockerfile), contextlib.redirect_stderr(err):
            rc = lc.main(["build"])
        self.assertEqual(rc, 2, err.getvalue())
        self.assertIn("changed while docker built it", err.getvalue())
        self.assertFalse(self.images.exists(), "an image built from bytes nobody checked was recorded")

    def test_a_build_that_reports_no_image_id_records_nothing(self):
        self.scenario({"built_id": "not-an-id"})
        self.images.unlink()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(lc.main(["build"]), 2)
        self.assertIn("image id", err.getvalue())
        self.assertFalse(self.images.exists(), "a build whose id is unknown was recorded")

    def test_a_staging_path_docker_would_split_is_refused_before_anything_is_created(self):
        # W5-14: --results/--receipts/--token-file were comma-checked, the derived staging paths
        # (the export, the attestation, the settings) were not, and they go into a --mount too.
        for name in ("tmp,with-comma", 'tmp"quote'):
            with self.subTest(name=name):
                staging = self.tmp / name
                staging.mkdir()
                with mock.patch.object(tempfile, "tempdir", str(staging)):
                    rc, err = self.launch("--per-call-usd", "1")
                self.assertEqual(rc, 2, err)
                self.assertIn("--mount", err)
                self.assertEqual(self.creates(), [])
                self.assertEqual(list(staging.iterdir()), [], "the staging directory outlived the refusal")

    def test_a_refused_staging_path_makes_nothing_outside_the_staging_directory(self):
        # Why the derived mount sources are checked before the export, though broker_argv and
        # arm_argv would refuse the same path before any `docker create` (re-attack of 2d254d0f
        # called the check redundant): the launch makes the results directory, the receipts
        # directory and this launch's broker-ledger directory before it builds either argv, and a
        # refused start leaves none of them behind, nor runs the export's clone.
        staging = self.tmp / "tmp,with-comma"
        staging.mkdir()
        with mock.patch.object(tempfile, "tempdir", str(staging)), \
                mock.patch.object(lc, "export_checkout", side_effect=AssertionError("the export was cloned")):
            rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("--mount", err)
        self.assertFalse(self.results.exists(), "a refused start made the results directory")
        self.assertFalse(self.receipts.exists(), "a refused start made the receipts directory and a ledger in it")

    def test_a_staging_path_with_a_line_break_is_refused_before_anything_is_created(self):
        # W5-14's rule names a comma, a quote and a line break: docker reads a --mount as CSV, where
        # a line break ends the record. TMPDIR is the operator's environment, so any byte can be in it.
        for name in ("tmp\nline", "tmp\rreturn"):
            with self.subTest(name=name):
                staging = self.tmp / name
                staging.mkdir()
                with mock.patch.object(tempfile, "tempdir", str(staging)):
                    rc, err = self.launch()
                self.assertEqual(rc, 2, err)
                self.assertIn("--mount", err)
                self.assertEqual(self.creates(), [])
                self.assertEqual(list(staging.iterdir()), [], "the staging directory outlived the refusal")

    def test_results_or_receipts_the_container_could_reach_are_refused(self):
        for results, receipts in ((self.repo / "out", self.receipts), (self.results, self.results / "receipts")):
            with self.subTest(results=results, receipts=receipts):
                self.results, self.receipts = results, receipts
                rc, err = self.launch()
                self.assertEqual(rc, 2, err)
                self.assertIn("overlaps", err)
        self.assertEqual(self.creates(), [])


class TeardownNeverLosesTheReceipt(Harness):
    """Codex and Greptile at 47e0616eac: a `docker kill` that timed out raised out of the teardown,
    skipping the removal, the verification and the receipt. Every teardown step is now attempted
    and recorded, and the receipt is written whatever happens."""

    def test_a_hanging_kill_still_removes_verifies_and_writes_the_receipt(self):
        self.scenario({"sleep": 60, "hang": ["kill"], "hang_s": 5})
        with mock.patch.object(lc, "TEARDOWN_TIMEOUT_S", 0.5):
            rc, err = self.launch(timeout="1")
        self.assertEqual(rc, lc.EXIT_TIMED_OUT, err)
        r = self.receipt()
        self.assertIs(r["destroyed"]["verified"], True)
        self.assertIn("docker kill", " ".join(r["destroyed"]["errors"]))
        self.assertIn(["rm", "-f", CID], [c["argv"] for c in self.calls(partial=True)])

    def test_a_teardown_step_that_fails_is_recorded_in_the_receipt(self):
        # Codex at 0116e8ae34: a nonzero kill vanished from a receipt that read verified, no errors
        self.scenario({"fail": ["kill"]})
        rc, err = self.launch()
        self.assertEqual(rc, 0, err)
        destroyed = self.receipt()["destroyed"]
        self.assertIs(destroyed["verified"], True)
        self.assertIn(f"docker kill {CID}: exit 1: Error response from daemon: cannot kill container",
                      destroyed["nonzero"])

    def test_a_retried_teardown_keeps_what_the_first_one_saw(self):
        # #673: the retry replaced the first teardown's record, so its diagnostics vanished
        self.scenario({"sleep": 60, "fail": ["kill"], "survive_checks": 2})
        with mock.patch.object(lc, "DESTROY_WAIT_S", 0.3):
            rc, err = self.launch(timeout="1")
        self.assertEqual(rc, lc.EXIT_TIMED_OUT, err)
        destroyed = self.receipt()["destroyed"]
        self.assertIs(destroyed["verified"], True)
        kills = [n for n in destroyed["nonzero"] if n.startswith(f"docker kill {CID}")]
        self.assertEqual(len(kills), 2, f"one teardown's kill failure is missing: {destroyed['nonzero']}")

    def test_a_verification_that_keeps_timing_out_fails_closed_with_a_receipt(self):
        self.scenario({"hang": ["verify"], "hang_s": 5})
        with mock.patch.object(lc, "TEARDOWN_TIMEOUT_S", 0.5), mock.patch.object(lc, "DESTROY_WAIT_S", 0.5):
            rc, err = self.launch()
        self.assertEqual(rc, lc.EXIT_NOT_DESTROYED, err)
        self.assertIn("FAIL-CLOSED", err)
        r = self.receipt()
        self.assertIs(r["destroyed"]["verified"], False)
        self.assertIn("TimeoutExpired", r["destroyed"]["output"])

    def test_a_create_whose_answer_is_lost_is_found_by_its_nonce_destroyed_and_receipted(self):
        # Codex at 3c01b90b5e: docker made the broker but the launcher never got its id back
        self.scenario({"hang": ["create"], "hang_s": 5, "orphan": BID})
        with mock.patch.object(lc, "CREATE_TIMEOUT_S", 0.5):
            rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("docker create of the broker timed out", err)
        r = self.receipt()
        self.assertIsNone(r["broker"]["id"])
        self.assertIs(r["destroyed"]["verified"], True)
        self.assertIn(["rm", "-f", BID], [c["argv"] for c in self.calls(partial=True)])

    def test_a_broker_that_does_not_start_is_destroyed_and_the_launch_refused(self):
        self.scenario({"broker_start_exit": 1})
        rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("docker start of the broker failed", err)
        r = self.receipt()
        self.assertIs(r["destroyed"]["verified"], True)
        self.assertIn("docker start of the broker failed", r["refused"])
        self.assertNotIn(["start", "--attach"], [c["argv"][:2] for c in self.calls()])


class APerCallLimitReachesEveryClaudeCall(Harness):
    """A registration may fix a per-call limit (#604's claude --max-budget-usd 1.60). The launcher
    hands it to the arm's claude as a read-only settings file; the wrapper appends it."""

    def test_the_arm_gets_the_limit_read_only(self):
        rc, err = self.launch("--per-call-usd", "1.6")
        self.assertEqual(rc, 0, err)
        arm = self.create("arm")
        self.assertIs(arm["mounts"][lc.CLAUDE_SETTINGS].get("readonly"), True)
        self.assertEqual(arm["claude_settings"], {"max_budget_usd": "1.6"})
        self.assertNotIn(lc.CLAUDE_SETTINGS, self.create("broker")["mounts"])
        r = self.receipt()
        self.assertEqual(r["per_call_usd"], 1.6)
        self.assertIn(lc.CLAUDE_SETTINGS, r["container"]["mounts"])

    def test_without_one_no_settings_are_mounted(self):
        self.launch()
        self.assertNotIn(lc.CLAUDE_SETTINGS, self.create("arm")["mounts"])
        self.assertIsNone(self.receipt()["per_call_usd"])

    def test_the_limit_is_written_as_given_never_rounded(self):
        # Codex at cb51f73bb2: 0.001 became 0.00 and 1.606 became 1.61
        for limit, written in (("0.001", "0.001"), ("1.606", "1.606")):
            with self.subTest(limit=limit):
                shutil.rmtree(self.receipts, ignore_errors=True)
                self.log.unlink(missing_ok=True)
                rc, err = self.launch("--per-call-usd", limit)
                self.assertEqual(rc, 0, err)
                self.assertEqual(self.create("arm")["claude_settings"], {"max_budget_usd": written})

    def test_a_limit_that_is_not_positive_or_passes_the_cap_is_refused(self):
        for limit in ("0", "-1", "60"):
            with self.subTest(limit=limit):
                rc, err = self.launch("--per-call-usd", limit)
                self.assertEqual(rc, 2, err)
                self.assertIn("--per-call-usd", err)
        self.assertEqual(self.calls(), [])


class ABrokerNeverRunsAsRoot(Harness):
    def test_a_root_launcher_is_refused(self):
        with mock.patch.object(lc.os, "getuid", return_value=0):
            rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("not root", err)
        self.assertEqual(self.creates(), [])


class ABrokerThatNeverAnswersStartsNoArm(Harness):
    def test_it_is_destroyed_and_the_launch_refused(self):
        self.scenario({"broker_ready_exit": 1})
        with mock.patch.object(lc, "BROKER_READY_S", 0.3):
            rc, err = self.launch()
        self.assertEqual(rc, 2, err)
        self.assertIn("the broker never answered", err)
        r = self.receipt()
        self.assertIs(r["destroyed"]["verified"], True)
        self.assertIn("could not open the token file or its ledger", r["refused"])
        self.assertNotIn(["start", "--attach"], [c["argv"][:2] for c in self.calls()])


class TheWallClockLimitEndsIt(Harness):
    def test_the_launcher_kills_removes_and_verifies(self):
        self.scenario({"sleep": 60})
        started = time.monotonic()
        rc, err = self.launch(timeout="1")
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual(rc, lc.EXIT_TIMED_OUT, err)
        argvs = [c["argv"] for c in self.calls()]
        for cid in (CID, BID):
            self.assertIn(["kill", cid], argvs)
            self.assertIn(["rm", "-f", cid], argvs)
        self.assertLess(argvs.index(["kill", CID]), argvs.index(["kill", BID]),
                        "the broker went before the arm, leaving its calls unsettled")
        r = self.receipt()
        self.assertIs(r["timed_out"], True)
        self.assertIs(r["destroyed"]["verified"], True)
        self.assertIsNone(r["exit_status"])

    def test_a_container_still_listed_fails_closed(self):
        self.scenario({"survivor": CID})
        with mock.patch.object(lc, "DESTROY_WAIT_S", 0.5):
            rc, err = self.launch()
        self.assertEqual(rc, lc.EXIT_NOT_DESTROYED, err)
        self.assertIn("FAIL-CLOSED", err)
        r = self.receipt()
        self.assertIs(r["destroyed"]["verified"], False)
        self.assertIn(CID, r["destroyed"]["output"])

    def test_a_signal_destroys_both_containers_before_the_launcher_exits(self):
        self.scenario({"sleep": 60})

        def interrupt():
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if any(c["argv"][:2] == ["start", "--attach"] for c in self.calls(partial=True)):
                    os.kill(os.getpid(), signal.SIGTERM)  # only while the launcher's handler is in place
                    return
                time.sleep(0.05)
        thread = threading.Thread(target=interrupt)
        thread.start()
        try:
            with self.assertRaises(SystemExit) as raised:
                self.launch()
        finally:
            thread.join()
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        r = self.receipt()
        self.assertEqual(r["interrupted"], 128 + signal.SIGTERM)
        self.assertIs(r["destroyed"]["verified"], True)
        for cid in (CID, BID):
            self.assertIn(["kill", cid], [c["argv"][:2] for c in self.calls()])


class TheImageIsBuiltFromTheCommittedDockerfile(Harness):
    def test_build_labels_the_dockerfiles_digest_and_sends_an_empty_context(self):
        with contextlib.redirect_stderr(io.StringIO()):
            rc = lc.main(["build"])
        self.assertEqual(rc, 0)
        build = [c for c in self.calls() if c["argv"][:1] == ["build"]]
        self.assertEqual(len(build), 1)
        self.assertEqual(build[0]["argv"][:5], ["build", "-f", str(lc.DOCKERFILE), "-t", lc.IMAGE])
        self.assertIn(f"{lc.DOCKERFILE_LABEL}={lc.sha256_file(lc.DOCKERFILE)}", build[0]["argv"])
        self.assertEqual(build[0]["context"], [], "the build context is not empty")

    def test_the_dockerfile_pins_its_base_and_installs_claude_code_as_a_non_root_user(self):
        text = lc.DOCKERFILE.read_text(encoding="utf-8")
        lines = [ln.strip() for ln in text.splitlines()]
        froms = [ln for ln in lines if ln.startswith("FROM ")]
        self.assertEqual(len(froms), 1)
        self.assertRegex(froms[0], r"^FROM python:3\.13\.15-slim@sha256:[0-9a-f]{64}$")
        self.assertIn("git", re.search(r"apt-get install[^\n]*", text).group(0))
        # The installer runs from a file whose sha256 is pinned and checked first, never piped
        # into a shell, and the binary it leaves must have the release's own pinned sha256
        # (2026-10-27 audit, W5-12: a version argument is not a pin).
        install = f"bash /tmp/claude-install.sh {lc.CLAUDE_CODE}"
        self.assertIn(install, text)
        self.assertNotRegex(text, r"\|\s*(?:ba)?sh\b", "a downloaded script is piped into a shell")
        pinned = re.search(r'echo "[0-9a-f]{64}  /tmp/claude-install\.sh" \| sha256sum -c -', text)
        self.assertIsNotNone(pinned, "the installer runs without a pinned digest")
        self.assertLess(text.index(pinned.group(0)), text.index(install), "the digest is checked after it ran")
        real = f"/home/runner/.local/share/claude/versions/{lc.CLAUDE_CODE}"
        for arch in ("x86_64", "aarch64"):
            self.assertRegex(text, rf"\b{arch}\) want=[0-9a-f]{{64}} ;;", f"no pinned binary digest for {arch}")
        self.assertIn(f'echo "$want  {real}" | sha256sum -c -', text)
        self.assertLess(text.index(install), text.index(f'echo "$want  {real}"'))
        users = [i for i, ln in enumerate(lines) if ln.startswith("USER ")]
        at = next(i for i, ln in enumerate(lines) if install in ln)
        self.assertTrue(users and users[-1] < at and lines[users[-1]] == "USER runner", "installed as root")
        self.assertEqual(lc.IMAGE, f"open-fleet-live:claude-{lc.CLAUDE_CODE}")


# ---------------------------------------------------------------------------- the credential broker

def usage_events(usage_start, usage_delta, stop=True):
    """An SSE answer as the API streams one: message_start, a delta, message_delta, message_stop."""
    events = [{"type": "message_start", "message": {"id": "msg_1", "usage": usage_start}},
              {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}},
              {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": usage_delta}]
    if stop:
        events.append({"type": "message_stop"})
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


USAGE = {"input_tokens": 2, "cache_creation_input_tokens": 6392, "cache_read_input_tokens": 10307, "output_tokens": 1,
         "cache_creation": {"ephemeral_5m_input_tokens": 6392, "ephemeral_1h_input_tokens": 0},
         "inference_geo": "global"}  # as the API reported it on the live smoke call


class StandInAPI:
    """The API on 127.0.0.1: records each request and answers with the next scripted reply."""

    def __init__(self, test):
        self.requests, self.replies = [], []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append({"path": self.path, "headers": dict(self.headers.items()), "body": body})
                status, ctype, data = outer.replies.pop(0) if outer.replies else (200, "text/event-stream",
                                                                                   usage_events(USAGE, {"output_tokens": 4}))
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        test.addCleanup(self.server.server_close)
        test.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"


class TheBrokerHoldsTheTokenAndTheCap(unittest.TestCase):
    """scripts/live_broker.py: the one process with the token. It forwards a model call with the
    token in place of the arm's placeholder, refuses everything else, and refuses any call whose
    worst case would pass the cap; it settles each call as the API bills it."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="live-broker-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.token = "sk-ant-oat01-fixture-" + os.urandom(8).hex()
        self.api = StandInAPI(self)
        self.ledger_path = self.tmp / "spend.jsonl"

    def broker(self, cap=5.0):
        server, ledger = lb.serve(self.token, self.ledger_path, cap, port=0, upstream=self.api.url)
        self.addCleanup(ledger.fh.close)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]
        return ledger

    def post(self, path="/v1/messages?beta=true", doc=None, raw=None, headers=None):
        body = raw if raw is not None else json.dumps(doc if doc is not None else self.body()).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json", "anthropic-version": "2023-06-01",
                                                       "Authorization": "Bearer open-fleet-live-broker",
                                                       "x-api-key": "not-a-key", **(headers or {})})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def body(self, **extra):
        return {"model": "claude-haiku-5-5", "max_tokens": 1000, "stream": True,
                "messages": [{"role": "user", "content": "Reply with the single word ok"}], **extra}

    def events(self):
        return [json.loads(line) for line in self.ledger_path.read_text(encoding="utf-8").splitlines()]

    def test_a_call_reaches_the_api_with_the_token_in_place_of_the_placeholder(self):
        self.broker()
        status, data = self.post(headers={"anthropic-beta": "claude-code-20250219"})
        self.assertEqual(status, 200)
        self.assertEqual(data, usage_events(USAGE, {"output_tokens": 4}), "the answer was not relayed unchanged")
        (req,) = self.api.requests
        headers = {k.lower(): v for k, v in req["headers"].items()}
        self.assertEqual(headers["authorization"], f"Bearer {self.token}")
        self.assertNotIn("x-api-key", headers)
        self.assertEqual(headers["anthropic-beta"], "claude-code-20250219,oauth-2025-04-20")
        self.assertEqual(req["path"], "/v1/messages?beta=true")
        self.assertEqual(json.loads(req["body"]), self.body())
        start, settle = self.events()[1:]
        self.assertEqual((start["event"], settle["event"], settle["complete"]), ("start", "settle", True))
        self.assertAlmostEqual(settle["cost_usd"], lb.priced({**USAGE, "output_tokens": 4}, "claude-haiku-5-5"), 6)
        self.assertNotIn(self.token, self.ledger_path.read_text(encoding="utf-8"))
        self.assertNotIn(self.token.encode(), data)
        self.assertEqual(stat.S_IMODE(self.ledger_path.stat().st_mode), 0o600)

    def test_usage_settles_as_the_api_bills_it(self):
        # The live smoke run through the broker on 2026-10-25 (Claude Code 2.1.304, Haiku 5.5): the
        # API reported USAGE with 4 output tokens, and Claude Code's own total_cost_usd was 0.00090427.
        self.assertAlmostEqual(lb.priced({**USAGE, "output_tokens": 4}, "claude-haiku-5-5"), 0.00090427, 8)
        one_hour = {"cache_creation_input_tokens": 1000, "cache_creation": {"ephemeral_1h_input_tokens": 1000}}
        unsplit = {"cache_creation_input_tokens": 1000}
        self.assertAlmostEqual(lb.priced(one_hour, "claude-opus-5-5"), 1000 * 4.0 * 2.0 / 1e6)
        self.assertAlmostEqual(lb.priced(unsplit, "claude-opus-5-5"), 1000 * 4.0 * 2.0 / 1e6, msg="unsplit is not the 1h rate")
        self.assertAlmostEqual(lb.priced({"input_tokens": 200_000}, "claude-haiku-5-5"), 200_000 * 0.50 / 1e6)
        self.assertAlmostEqual(lb.priced({"output_tokens": 10}, "claude-opus-5-5", lb.FAST), 10 * 40.0 / 1e6)
        self.assertAlmostEqual(lb.priced({"output_tokens": 10}, "claude-haiku-4-5-20251001"), 10 * 5.0 / 1e6)
        self.assertGreaterEqual(lb.reservation(100, 1000, "claude-haiku-5-5"),
                                lb.priced({"input_tokens": 100 + lb.FRAMING_TOKENS, "output_tokens": 1000},
                                          "claude-haiku-5-5"))

    def test_a_call_whose_worst_case_would_pass_the_cap_never_reaches_the_api(self):
        self.broker(cap=0.001)
        status, data = self.post()
        self.assertEqual(status, 403, data)
        self.assertIn(b"spend cap", data)
        self.assertEqual(self.api.requests, [])
        self.assertEqual(self.events()[-1]["event"], "refuse")

    def test_calls_in_flight_count_against_the_cap(self):
        ledger = lb.Ledger(self.ledger_path, 1.0)
        self.addCleanup(ledger.fh.close)
        first = ledger.reserve("claude-opus-5-5", 0.6)
        self.assertIsNotNone(first)
        self.assertIsNone(ledger.reserve("claude-opus-5-5", 0.6), "a second call passed the cap beside the first")
        ledger.settle(first, 0.1, 200, {}, True)
        self.assertIsNotNone(ledger.reserve("claude-opus-5-5", 0.6))
        ledger.settle(2, None, None, {}, False)  # an unfinished call settles its whole reservation
        self.assertAlmostEqual(ledger.settled, 0.7)

    def test_a_stream_without_its_end_settles_its_whole_reservation(self):
        self.broker()
        self.api.replies.append((200, "text/event-stream", usage_events(USAGE, {"output_tokens": 4}, stop=False)))
        self.post()
        start, settle = self.events()[1:]
        self.assertIs(settle["complete"], False)
        self.assertEqual(settle["cost_usd"], start["reserved_usd"])

    def test_an_error_the_api_answers_at_once_settles_nothing(self):
        self.broker()
        self.api.replies.append((529, "application/json", b'{"type":"error","error":{"type":"overloaded_error"}}'))
        status, _data = self.post(doc=self.body(stream=False))
        self.assertEqual(status, 529)
        self.assertEqual((self.events()[-1]["cost_usd"], self.events()[-1]["complete"]), (0.0, True))

    def test_a_non_streamed_answer_settles_its_usage(self):
        self.broker()
        answer = json.dumps({"id": "msg_1", "content": [], "usage": {"input_tokens": 100, "output_tokens": 10,
                                                                      "inference_geo": "global"}}).encode()
        self.api.replies.append((200, "application/json", answer))
        self.post(doc=self.body(stream=False))
        self.assertAlmostEqual(self.events()[-1]["cost_usd"], (100 * 0.10 + 10 * 0.50) / 1e6, 9)

    def test_anything_unpriced_or_unlisted_never_reaches_the_api(self):
        self.broker()
        for path in ("/v1/complete", "/api/oauth/profile", "/v1/messages/batches"):
            with self.subTest(path=path):
                self.assertEqual(self.post(path=path)[0], 403)
        bodies = {"not JSON": b"{", "an unpriced model": self.body(model="claude-3-opus"),
                  "no max_tokens": {k: v for k, v in self.body().items() if k != "max_tokens"},
                  "a server tool": self.body(tools=[{"type": "web_search_20260209", "name": "web_search"}]),
                  "an MCP server": self.body(mcp_servers=[{"type": "url", "url": "https://x.invalid", "name": "x"}])}
        for what, body in bodies.items():
            with self.subTest(what=what):
                raw = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.assertEqual(self.post(raw=raw)[0], 400)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("GET", "/v1/models")
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        self.assertEqual(self.api.requests, [], "a refused request reached the API")
        self.assertNotIn("start", [e["event"] for e in self.events()])

    def test_only_the_checked_path_and_query_are_forwarded(self):
        self.broker()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        body = json.dumps(self.body()).encode()
        conn.request("POST", "http://elsewhere.invalid/v1/messages?beta=true", body=body,
                     headers={"Content-Type": "application/json"})
        self.assertEqual(conn.getresponse().status, 200)
        conn.close()
        self.assertEqual(self.api.requests[0]["path"], "/v1/messages?beta=true")

    def test_content_its_bytes_do_not_bound_never_reaches_the_api(self):
        # Codex at 8585b35789: an image by URL reserved its JSON bytes, not what the API bills for it
        self.broker()
        image = lambda source: {"role": "user", "content": [{"type": "image", "source": source}]}
        bodies = {
            "an image by URL": [image({"type": "url", "url": "https://x.invalid/a.png"})],
            "an image by file": [image({"type": "file", "file_id": "file_1"})],
            "a document by file id": [{"role": "user", "content": [{"type": "document", "source": {"type": "file",
                                                                                                   "file_id": "f"}}]}],
            "a PDF": [{"role": "user", "content": [{"type": "document", "source": {
                "type": "base64", "media_type": "application/pdf", "data": "JVBERi0="}}]}],
            "a URL inside a tool result": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t",
                                                                          "content": [{"type": "image", "source": {
                                                                              "type": "url", "url": "https://x.invalid"}}]}]}],
        }
        for what, messages in bodies.items():
            with self.subTest(what=what):
                status, data = self.post(doc=self.body(messages=messages))
                self.assertEqual(status, 400, data)
        self.assertEqual(self.api.requests, [])

    def test_an_inline_image_is_reserved_at_its_worst_case(self):
        img = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}
        why, mult, images = lb.terms(self.body(messages=[{"role": "user", "content": [img, img]}], inference_geo="global"))
        self.assertEqual((why, mult, images), (None, 1.0, 2))
        self.assertAlmostEqual(lb.reservation(100, 10, "claude-opus-5-5", 1.0, 2) - lb.reservation(100, 10, "claude-opus-5-5"),
                               2 * lb.IMAGE_TOKENS * 4.0 * lb.WRITE_1H / 1e6)
        self.assertGreaterEqual(lb.IMAGE_TOKENS, 4784, "below the most one image costs")

    def test_only_the_clients_own_tools_and_the_fields_it_prices_pass(self):
        # Codex at 8585b35789: an advisor tool passed, and its sub-inference was neither reserved nor settled
        self.broker()
        refused = {"an advisor tool": self.body(tools=[{"type": "advisor_20260301", "name": "advisor",
                                                        "model": "claude-fable-5-1"}]),
                   "an Anthropic-defined tool": self.body(tools=[{"type": "bash_20250124", "name": "bash"}]),
                   "an unpriced field": self.body(betas=["x"]),
                   "a container": self.body(container="c"),
                   "a priority tier": self.body(service_tier="auto"),
                   "an unpriced geography": self.body(inference_geo="eu"),
                   "an unknown speed": self.body(speed="turbo"),
                   "server-side compaction": self.body(context_management={"edits": [{"type": "compact_20260112"}]})}
        for what, body in refused.items():
            with self.subTest(what=what):
                self.assertEqual(self.post(doc=body)[0], 400, what)
        self.assertEqual(self.api.requests, [])
        tool = {"name": "Bash", "description": "run", "input_schema": {"type": "object"}}
        ok = self.body(tools=[tool, {**tool, "type": "custom"}], tool_choice={"type": "auto"}, metadata={"user_id": "u"},
                       context_management={"edits": [{"type": "clear_tool_uses_20250919"}]},
                       thinking={"type": "adaptive"}, system="s", output_config={"effort": "low"})
        self.assertEqual(self.post(doc=ok)[0], 200)

    def test_a_tool_defined_inside_the_content_is_held_to_the_same_rule(self):
        # Codex at 0116e8ae34: with inline-tools, a system message's tool_addition defined web_search
        self.broker()
        addition = lambda definition: {"role": "system", "content": [{"type": "tool_addition",
                                                                      "tool_definition": definition}]}
        user = {"role": "user", "content": "hi"}
        inline = self.body(messages=[user, addition({"type": "web_search_20250305", "name": "web_search"})])
        status, data = self.post(doc=inline, headers={"anthropic-beta": "inline-tools-2026-09-15"})
        self.assertEqual(status, 400, data)
        listed = self.body(messages=[user, addition([{"type": "advisor_20260301", "name": "advisor"}])])
        self.assertEqual(self.post(doc=listed)[0], 400)
        stray = self.body(messages=[{"role": "user", "content": [{"type": "code_execution_20260521", "name": "x"}]}])
        self.assertEqual(self.post(doc=stray)[0], 400)
        self.assertEqual(self.api.requests, [])
        own = self.body(messages=[user, addition({"name": "Lookup", "input_schema": {"type": "object"}})])
        self.assertEqual(self.post(doc=own)[0], 200, "the client's own inline tool was refused")

    def test_a_reported_web_search_is_charged(self):
        self.assertAlmostEqual(lb.settled({"server_tool_use": {"web_search_requests": 12}}, "claude-haiku-5-5"),
                               12 * lb.SEARCH_USD)
        merged = lb.merged_usage({}, {"server_tool_use": {"web_search_requests": 2, "web_fetch_requests": 1}})
        self.assertEqual(merged["server_tool_use"], {"web_search_requests": 2, "web_fetch_requests": 1})

    def test_us_inference_is_reserved_and_settled_at_its_premium(self):
        # Codex at 8585b35789: inference_geo "us" is billed at 1.1x every category
        self.assertEqual(lb.terms(self.body(inference_geo="us"))[1], 1.1)
        self.assertEqual(lb.terms(self.body(inference_geo="us", speed="fast"))[1], 1.1 * lb.FAST)
        self.broker()
        self.api.replies.append((200, "text/event-stream",
                                 usage_events({**USAGE, "inference_geo": "us"}, {"output_tokens": 4})))
        self.post(doc=self.body(inference_geo="us"))
        start, settle = self.events()[1:]
        usage = {**USAGE, "output_tokens": 4}
        self.assertAlmostEqual(settle["cost_usd"], lb.priced(usage, "claude-haiku-5-5") * 1.1, 6)
        self.assertAlmostEqual(start["reserved_usd"], lb.reservation(len(json.dumps(self.body(inference_geo="us"))),
                                                                     1000, "claude-haiku-5-5") * 1.1, 4)

    def test_an_omitted_geography_reserves_at_the_us_premium_and_settles_as_reported(self):
        # Codex at 3c01b90b5e: a request naming no geography runs in the workspace default, maybe US
        self.assertEqual(lb.terms(self.body())[1], lb.GEO_WORST)
        self.assertEqual(lb.terms(self.body(inference_geo="global"))[1], 1.0)
        usage = {**USAGE, "output_tokens": 4}
        for reported, mult in (("global", 1.0), ("us", 1.1), (None, lb.GEO_WORST), ("mars", lb.GEO_WORST)):
            with self.subTest(reported=reported):
                self.assertEqual(lb.settle_mult({**usage, "inference_geo": reported}, False), mult)
        self.assertEqual(lb.settle_mult({"inference_geo": "global", "speed": "fast"}, False), lb.FAST)
        self.broker()
        no_geo = {k: v for k, v in USAGE.items() if k != "inference_geo"}
        self.api.replies.append((200, "text/event-stream", usage_events(no_geo, {"output_tokens": 4})))
        self.post()
        start, settle = self.events()[1:]
        self.assertAlmostEqual(start["reserved_usd"], lb.reservation(len(json.dumps(self.body())), 1000,
                                                                     "claude-haiku-5-5") * lb.GEO_WORST, 4)
        self.assertAlmostEqual(settle["cost_usd"], lb.priced(usage, "claude-haiku-5-5") * lb.GEO_WORST, 6)

    def test_iterations_settle_when_they_cost_more(self):
        top = {"input_tokens": 10, "output_tokens": 10}
        iterations = [{"input_tokens": 10, "output_tokens": 10},
                      {"model": "claude-fable-5-1", "input_tokens": 1000, "output_tokens": 500},
                      {"model": "claude-unknown", "input_tokens": 100}]
        expected = (lb.priced(iterations[0], "claude-haiku-5-5") + lb.priced(iterations[1], "claude-fable-5-1")
                    + lb.priced(iterations[2], lb.COSTLIEST))
        self.assertAlmostEqual(lb.settled({**top, "iterations": iterations}, "claude-haiku-5-5"), expected)
        self.assertEqual(lb.merged_usage({}, {"iterations": iterations})["iterations"], iterations)

    def test_count_tokens_is_forwarded_and_free(self):
        self.broker()
        self.api.replies.append((200, "application/json", b'{"input_tokens": 12}'))
        status, data = self.post(path="/v1/messages/count_tokens", doc={"model": "claude-haiku-5-5", "messages": []})
        self.assertEqual((status, data), (200, b'{"input_tokens": 12}'))
        self.assertEqual(self.api.requests[0]["headers"]["Authorization"], f"Bearer {self.token}")
        self.assertEqual([e["event"] for e in self.events()], ["open"])

    def test_health_answers_without_the_token(self):
        self.broker(cap=7.0)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        self.assertEqual((resp.status, json.loads(resp.read())), (200, {"ok": True, "cap_usd": 7.0}))
        conn.close()

    # 2026-10-27 security audit, wave 5: W5-16 (a silent client parks a thread forever), W5-17
    # (count_tokens is unmetered and unbounded) and W5-18 (a fault skips the settle, and its
    # traceback goes to a log nobody keeps: the broker runs --log-driver none).

    def test_a_client_that_never_sends_is_cut_off_and_idle_connections_are_bounded(self):
        with mock.patch.object(lb, "HANDLER_TIMEOUT_S", 1.5, create=True), \
                mock.patch.object(lb, "MAX_CONNECTIONS", 2, create=True):
            self.broker()
        idle = []
        for _ in range(3):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            self.addCleanup(sock.close)
            idle.append(sock)
        # The connection past the bound evicts the idle one that has waited longest, at once: idle
        # connections never keep a new one out (re-attack of 4b24dfde).
        idle[0].settimeout(1.0)
        try:
            self.assertEqual(idle[0].recv(1), b"", "idle connections kept the one past the bound out")
        except TimeoutError:
            self.fail("idle connections kept the one past the bound out")
        # And a connection that sends nothing is closed after the handler timeout.
        idle[1].settimeout(5)
        started = time.monotonic()
        try:
            self.assertEqual(idle[1].recv(1), b"")
        except TimeoutError:
            self.fail("a silent connection held its thread past the handler timeout")
        self.assertLess(time.monotonic() - started, 4)
        status, _data = self.post(path="/v1/messages/count_tokens", doc={"model": "claude-haiku-5-5", "messages": []})
        self.assertEqual(status, 200, "the broker stopped answering once idle connections were cut")

    def test_a_trickling_request_is_cut_off_by_a_total_deadline_and_every_drop_is_recorded(self):
        # Re-attack of 82a2d00c (W5-16): the handler timeout restarts with every byte, so 32 clients
        # each sending one byte of the request line every 20 s held every slot; and a dropped or
        # expired connection left no trace in the ledger. Since the re-attack of 4b24dfde the
        # connection past the slots evicts the trickling one, and is itself cut at its deadline.
        with mock.patch.object(lb, "HANDLER_TIMEOUT_S", 5, create=True), \
                mock.patch.object(lb, "REQUEST_DEADLINE_S", 1.0, create=True), \
                mock.patch.object(lb, "MAX_CONNECTIONS", 1, create=True):
            self.broker()
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            self.addCleanup(sock.close)
            stop = threading.Event()
            self.addCleanup(stop.set)

            def trickle():
                for byte in b"POST /v1/messages HTTP/1.1\r\n":
                    if stop.wait(0.3):
                        return
                    with contextlib.suppress(OSError):
                        sock.sendall(bytes([byte]))

            threading.Thread(target=trickle, daemon=True).start()
            time.sleep(0.2)
            extra = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            self.addCleanup(extra.close)
            self.assertEqual(extra.recv(1), b"", "a connection that sends nothing outlived its deadline")
            started = time.monotonic()
            try:
                closed = sock.recv(1) == b""
            except ConnectionResetError:
                closed = True
            except TimeoutError:
                closed = False
            self.assertTrue(closed and time.monotonic() - started < 4,
                            "a request trickling one byte at a time outlived its total deadline")
            stop.set()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len([e for e in self.events() if e["event"] == "drop"]) < 2:
                time.sleep(0.05)
        drops = {e["why"] for e in self.events() if e["event"] == "drop"}
        self.assertIn("stalled request evicted", drops)  # "connection slots full": test_slots_busy_with_calls_in_flight_*
        self.assertIn("request timed out", drops)

    def test_count_tokens_is_bounded_and_recorded(self):
        with mock.patch.object(lb, "FREE_CALLS_MAX", 3, create=True), \
                mock.patch.object(lb, "FREE_RECORD_EVERY", 2, create=True):
            self.broker()
            statuses = []
            for _ in range(4):
                self.api.replies.append((200, "application/json", b'{"input_tokens": 12}'))
                statuses.append(self.post(path="/v1/messages/count_tokens",
                                          doc={"model": "claude-haiku-5-5", "messages": []})[0])
        self.assertEqual(statuses, [200, 200, 200, 403])
        self.assertEqual(len(self.api.requests), 3, "a call past the free-call bound reached the API")
        events = self.events()
        self.assertIn({"event": "free", "calls": 2}, [{k: e[k] for k in ("event", "calls") if k in e}
                                                     for e in events])
        refusal = events[-1]
        self.assertEqual(refusal["event"], "refuse")
        self.assertIn("count_tokens", refusal["why"])

    def test_a_usage_report_settled_cannot_price_still_settles_and_is_recorded(self):
        self.broker()
        answer = json.dumps({"id": "msg_1", "content": [], "usage": {
            "input_tokens": 10, "output_tokens": 10, "inference_geo": "global",
            "iterations": [{"input_tokens": "not-a-number"}]}}).encode()
        self.api.replies.append((200, "application/json", answer))
        status, _data = self.post(doc=self.body(stream=False))
        self.assertEqual(status, 200)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and "settle" not in [e["event"] for e in self.events()]:
            time.sleep(0.05)
        events = self.events()
        start = next(e for e in events if e["event"] == "start")
        settles = [e for e in events if e["event"] == "settle"]
        self.assertEqual(len(settles), 1, "the call's reservation was never settled")
        self.assertEqual(settles[0]["cost_usd"], start["reserved_usd"], "an unpriceable call settles its reservation")
        faults = [e for e in events if e["event"] == "fault"]
        self.assertEqual([f["error"] for f in faults], ["ValueError"])
        self.assertNotIn(self.token, self.ledger_path.read_text(encoding="utf-8"))

    def test_a_handler_fault_is_recorded_in_the_ledger_not_lost(self):
        self.broker()
        with mock.patch.object(lb, "terms", side_effect=RuntimeError(f"boom {self.token}")):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("POST", "/v1/messages", body=json.dumps(self.body()).encode(),
                         headers={"Content-Type": "application/json"})
            with contextlib.suppress(http.client.HTTPException, OSError):
                conn.getresponse().read()
            conn.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and "fault" not in [e["event"] for e in self.events()]:
                time.sleep(0.05)
        faults = [e for e in self.events() if e["event"] == "fault"]
        self.assertEqual(len(faults), 1, "the fault left no record anyone keeps")
        self.assertEqual(faults[0]["error"], "RuntimeError")
        self.assertTrue(faults[0]["frames"], "the fault names no frame")
        self.assertNotIn(self.token, self.ledger_path.read_text(encoding="utf-8"))
        self.assertNotIn("boom", self.ledger_path.read_text(encoding="utf-8"), "a fault records no message text")

    def test_an_upstream_that_resets_mid_call_is_recorded_as_a_fault(self):
        # Codex review of 82a2d00c: relay() caught the upstream's (or the client's) exception,
        # maybe answered 502, and recorded nothing, so the container (--log-driver none) kept
        # no trace of it. A stand-in API that resets the connection before, then after, its status.
        def resetting(send):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            self.addCleanup(listener.close)

            def serve():
                while True:
                    try:
                        conn, _ = listener.accept()
                    except OSError:
                        return
                    with conn:
                        conn.settimeout(5)
                        with contextlib.suppress(OSError):
                            conn.recv(1 << 16)
                            conn.sendall(send)
                        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            threading.Thread(target=serve, daemon=True).start()
            return f"http://127.0.0.1:{listener.getsockname()[1]}"

        for when, send in (("before its status", b""),
                           ("mid-response", b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                                            b"Content-Length: 100000\r\n\r\nevent: message_start\n")):
            with self.subTest(when=when):
                self.ledger_path = self.tmp / f"spend-{len(send)}.jsonl"
                server, ledger = lb.serve(self.token, self.ledger_path, 5.0, port=0, upstream=resetting(send))
                self.addCleanup(ledger.fh.close)
                self.addCleanup(server.server_close)
                self.addCleanup(server.shutdown)
                self.port = server.server_address[1]
                with contextlib.suppress(http.client.HTTPException, OSError):
                    self.post()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and "settle" not in [e["event"] for e in self.events()]:
                    time.sleep(0.05)
                events = self.events()
                faults = [e for e in events if e["event"] == "fault"]
                self.assertTrue(faults, f"an upstream reset {when} left no fault in the ledger: {events}")
                self.assertEqual(faults[0]["where"], "relay")
                self.assertTrue(faults[0]["frames"])
                self.assertEqual([e["event"] for e in events].count("settle"), 1, "the call was not settled")
                self.assertNotIn(self.token, self.ledger_path.read_text(encoding="utf-8"))

    def served_broker(self, upstream=None):
        """lb.serve with the module's constants as patched now; the server itself, for its slots."""
        server, ledger = lb.serve(self.token, self.ledger_path, 5.0, port=0, upstream=upstream or self.api.url)
        self.addCleanup(ledger.fh.close)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.port = server.server_address[1]
        return server

    def wait_slots_taken(self, server, n):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.slots._value != server.slots._initial_value - n:
            time.sleep(0.01)
        self.assertEqual(server.slots._value, server.slots._initial_value - n, "the connections were not served")

    def test_trickling_requests_cannot_keep_the_arms_own_calls_out(self):
        # Re-attack of 4b24dfde (W5-16): the total deadline bounds ONE connection, but a client
        # reopening them kept every slot: four connections, each trickling its request line or its
        # body under the real deadlines (30 s, 120 s), and the arm's own count_tokens call was
        # closed unanswered every time. A request still arriving gives its slot to a new connection.
        with mock.patch.object(lb, "MAX_CONNECTIONS", 4, create=True):
            server = self.served_broker()
        held = []
        for i in range(4):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            self.addCleanup(sock.close)
            sock.sendall(b"P" if i % 2 else b"POST /v1/messages/count_tokens HTTP/1.1\r\nContent-Length: 1000\r\n\r\nx")
            held.append(sock)
        self.wait_slots_taken(server, 4)
        for _ in range(3):
            self.api.replies.append((200, "application/json", b'{"input_tokens": 12}'))
            status, _data = self.post(path="/v1/messages/count_tokens", doc={"model": "claude-haiku-5-5", "messages": []})
            self.assertEqual(status, 200, "a stalled request kept the arm's own call out")
        held[0].settimeout(5)  # the one that had waited longest
        try:
            self.assertEqual(held[0].recv(1), b"", "a stalled request was answered")
        except ConnectionResetError:
            pass
        drops = [e for e in self.events() if e["event"] == "drop"]
        self.assertIn("stalled request evicted", {e["why"] for e in drops})
        self.assertNotIn("fault", [e["event"] for e in self.events()], "an eviction was recorded as a fault")

    def test_slots_busy_with_calls_in_flight_still_close_a_connection_past_them(self):
        # Only a request still arriving is evicted: a call already relayed keeps its slot, and the
        # connection past the bound is closed unanswered and counted, as before.
        release, relayed = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)

        def slow_api():
            conn, _ = listener.accept()
            with conn:
                conn.recv(1 << 16)
                relayed.set()
                release.wait(10)
                data = b'{"input_tokens": 12}'
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                             % (len(data), data))
        threading.Thread(target=slow_api, daemon=True).start()
        with mock.patch.object(lb, "MAX_CONNECTIONS", 1, create=True):
            server = self.served_broker(f"http://127.0.0.1:{listener.getsockname()[1]}")
        result = {}
        call = threading.Thread(target=lambda: result.update(status=self.post(
            path="/v1/messages/count_tokens", doc={"model": "claude-haiku-5-5", "messages": []})[0]), daemon=True)
        call.start()
        self.wait_slots_taken(server, 1)
        self.assertTrue(relayed.wait(5), "the call never reached the API")
        extra = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        self.addCleanup(extra.close)
        self.assertEqual(extra.recv(1), b"", "a connection past the slots was parked")
        release.set()
        call.join(10)
        self.assertEqual(result.get("status"), 200, "the call in flight lost its slot")
        self.assertIn("connection slots full", {e["why"] for e in self.events() if e["event"] == "drop"})

    def test_a_request_trickled_a_byte_at_a_time_is_cut_off_at_its_total_deadline(self):
        for phase in ("request line", "body"):
            with self.subTest(phase=phase):
                self.ledger_path = self.tmp / f"spend-{phase[0]}.jsonl"
                with mock.patch.object(lb, "HANDLER_TIMEOUT_S", 5, create=True), \
                        mock.patch.object(lb, "REQUEST_DEADLINE_S", 1.0, create=True), \
                        mock.patch.object(lb, "BODY_DEADLINE_S", 1.0, create=True):
                    self.served_broker()
                    sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
                    self.addCleanup(sock.close)
                    if phase == "body":
                        sock.sendall(b"POST /v1/messages HTTP/1.1\r\nContent-Length: 1000\r\n\r\n")
                    stop = threading.Event()
                    self.addCleanup(stop.set)

                    def trickle(sock=sock, stop=stop, byte=b"P" if phase == "request line" else b"x"):
                        while not stop.wait(0.3):
                            with contextlib.suppress(OSError):
                                sock.sendall(byte)

                    threading.Thread(target=trickle, daemon=True).start()
                    started, answer = time.monotonic(), b""
                    with contextlib.suppress(ConnectionResetError, TimeoutError):
                        while chunk := sock.recv(4096):
                            answer += chunk
                    stop.set()
                    self.assertLess(time.monotonic() - started, 4, f"a {phase} trickled a byte at a time outlived its deadline")
                    if phase == "body":
                        self.assertIn(b" 408 ", answer.split(b"\r\n", 1)[0])
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and "drop" not in [e["event"] for e in self.events()]:
                        time.sleep(0.05)
                    whys = {e["why"] for e in self.events() if e["event"] == "drop"}
                    self.assertIn("request timed out" if phase == "request line" else "body did not arrive", whys)

    def test_a_client_that_leaves_mid_answer_is_recorded_as_a_fault(self):
        # Codex review of 82a2d00c, its second case: the client disconnects while the broker is
        # still relaying the API's answer. The broker's write fails inside relay(); that is a fault.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)

        def streaming_api():
            conn, _ = listener.accept()
            with conn, contextlib.suppress(OSError):
                conn.recv(1 << 16)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                for _ in range(100):
                    chunk = b'data: {"type": "ping"}\n\n' * 400
                    conn.sendall(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    time.sleep(0.02)
                conn.sendall(b"0\r\n\r\n")
        threading.Thread(target=streaming_api, daemon=True).start()
        self.served_broker(f"http://127.0.0.1:{listener.getsockname()[1]}")
        body = json.dumps(self.body()).encode()
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        sock.sendall(b"POST /v1/messages HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"
                     % (len(body), body))
        self.assertTrue(sock.recv(64).startswith(b"HTTP/1.0 200"))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and "settle" not in [e["event"] for e in self.events()]:
            time.sleep(0.05)
        events = self.events()
        faults = [e for e in events if e["event"] == "fault"]
        self.assertEqual([(f["where"], bool(f["frames"])) for f in faults][:1], [("relay", True)],
                         f"a client that left mid-answer left no fault in the ledger: {events}")
        self.assertEqual([e["event"] for e in events].count("settle"), 1, "the call was not settled")

    def test_a_flood_of_faults_cannot_flood_the_ledger(self):
        # Recording every fault made each one a ledger write and an fsync: a client resetting its
        # connection mid-body in a loop grew the host's ledger without bound. Faults are counted,
        # and written per kind at most once a DROP_RECORD_S, like drops; the count rides every line.
        server = self.served_broker()
        n, started = 200, time.monotonic()
        for _ in range(n):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            sock.sendall(b"POST /v1/messages HTTP/1.1\r\nContent-Length: 100\r\n\r\nx")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.close()
        self.wait_slots_taken(server, 0)
        self.api.replies.append((200, "application/json", b'{"input_tokens": 12}'))
        self.assertEqual(self.post(path="/v1/messages/count_tokens", doc={"model": "claude-haiku-5-5", "messages": []})[0],
                         200)
        counted = lambda e: sum((e.get("faults") or {}).values()) + sum((e.get("dropped") or {}).values())
        deadline = time.monotonic() + 5  # no later event is needed: a tally line catches the count up
        while time.monotonic() < deadline and counted(self.events()[-1]) < n:
            time.sleep(0.05)
        events = self.events()
        lines = [e for e in events if e["event"] in ("fault", "drop", "tally")]
        kinds = {(e["event"], e.get("where"), e.get("error"), e.get("why")) for e in lines}
        # One line per kind per DROP_RECORD_S at most, however long a loaded host took over the flood.
        bound = len(kinds) * ((time.monotonic() - started) / lb.DROP_RECORD_S + 1)
        self.assertLessEqual(len(lines), min(bound, n / 4), f"{n} resets wrote {len(lines)} ledger lines")
        self.assertGreaterEqual(counted(events[-1]), n, f"the resets are not all counted on the ledger's last line: {events[-1]}")

    def test_refusals_cannot_flood_the_ledger_and_are_all_counted(self):
        # Pre-existing on main, the same class as the fault flood: every refusal was one fsynced
        # line quoting what the client sent, twice (a model name in `why` and in `model`), so 20
        # requests naming an 8 MiB model wrote 335 MB to the operator's disk in seconds. A refusal's
        # text is bounded, refusals are counted per kind and written like drops, and the receipt's
        # `refused` is the count, not the number of lines.
        self.broker()
        n_body, n_path, started = 10, 100, time.monotonic()
        big = {**self.body(), "model": "m" * (1 << 20)}
        for _ in range(n_body):
            self.assertEqual(self.post(doc=big)[0], 400)
        for i in range(n_path):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("GET", f"/{i}" + "x" * 4000)
            self.assertEqual(conn.getresponse().status, 403)
            conn.close()
        refused = lambda e: sum((e.get("refused") or {}).values())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and refused(self.events()[-1]) < n_body + n_path:
            time.sleep(0.05)
        self.assertLess(self.ledger_path.stat().st_size, 64 << 10, "refusals copied what the client sent into the ledger")
        events = self.events()
        lines = [e for e in events if e["event"] in ("refuse", "tally")]
        bound = 2 * ((time.monotonic() - started) / lb.DROP_RECORD_S + 1)  # two kinds: terms, path
        self.assertLessEqual(len(lines), min(bound, 20), f"{n_body + n_path} refusals wrote {len(lines)} lines")
        self.assertEqual(refused(events[-1]), n_body + n_path)
        self.assertEqual(lc.spend(self.ledger_path)["refused"], n_body + n_path, "the receipt miscounts refusals")

    def test_a_body_whose_fields_have_the_wrong_type_is_refused_not_crashed_on(self):
        self.broker()
        for extra in ({"context_management": "x"}, {"inference_geo": ["us"]}):
            with self.subTest(extra=extra):
                self.assertEqual(self.post(doc=self.body(**extra))[0], 400)
        self.assertEqual(self.api.requests, [])

    def test_stalled_holders_and_budget_waiters_cannot_keep_an_ordinary_call_out(self):
        # Codex round 10 on c952fa4f: two stalled requests whose reservations left 12 bytes of the
        # budget, the other slots filled by requests waiting for budget, and more stalled requests
        # arriving: an evicted budget waiter kept its slot until its 30 s budget deadline (the new
        # connection waited 5 s for it, holding up every connection behind it), and the budget an
        # evicted holder gave back went to another stalled waiter, so an ordinary call never got
        # in. Every wait is now evictable at once, budget goes only to a body that is arriving, and
        # a request waiting for budget takes back, for itself, what a stalled body holds. With the
        # arrivals still coming while the call is made, and with them stopped (then only the call's
        # own eviction and its taking back of a stalled share can let it in).
        for during in (True, False):
            with self.subTest(arrivals_during_the_call=during):
                self.ordinary_call_behind_stalled_requests(during)

    def test_a_max_size_call_behind_a_stalled_max_size_body_is_answered(self):
        # Codex round 11 on 8fe153d2: a stalled 32,000,000-byte body held its 416,000,000-byte share;
        # a complete call of the same length took back the share's parse part but not the stalled
        # body's buffer, and the eviction that would free it ran only after the 30 s wait, so the
        # call got 503. The stalled body is now evicted the moment its share is taken back, and the
        # call waits for its buffer to come back.
        self.broker(cap=1e9)
        stalled = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        self.addCleanup(stalled.close)
        stalled.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                        b"Content-Length: %d\r\n\r\n{" % lb.MAX_BODY)  # one byte of a max-size body
        time.sleep(0.3)
        head = b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"'
        end = b'"}]}'
        body = head + b"a" * (lb.MAX_BODY - len(head) - len(end)) + end
        started = time.monotonic()
        try:
            status, data = self.post(raw=body)
        except (OSError, http.client.HTTPException) as err:
            status, data = None, repr(err)
        took = time.monotonic() - started
        self.assertEqual(status, 200, data)
        self.assertLess(took, 10, f"a max-size call waited {took:.1f} s behind a stalled body")
        self.assertEqual(len(self.api.requests[-1]["body"]), lb.MAX_BODY)

    def test_a_stalled_body_whose_share_is_taken_back_is_closed_at_once(self):
        # Codex round 12 on 419a8435: when taking back a stalled body's share made a small call fit,
        # take() returned before evicting it, so the stalled socket stayed open, holding its buffer
        # until its own timeout; repeated, such buffers piled up out of reach. A stalled max-size
        # body and a stalled filler fill the budget; once they have stalled, a small call takes back
        # the max-size body's share: the call is answered and that body's socket is closed at once.
        # Then, on one broker, round after round of the same: no evicted body is left holding a share.
        for _round in range(2):
            server = self.served_broker()
            big, _filler = self.fill_with_stalled_bodies(server)
            time.sleep(lb.BODY_GRACE_S + 0.5)  # both have stalled
            started = time.monotonic()
            status, data = self.post()
            self.assertEqual(status, 200, data)
            self.assertLess(time.monotonic() - started, 5)
            big.settimeout(5)
            try:
                closed = big.recv(1) == b""
            except ConnectionResetError:
                closed = True
            except TimeoutError:
                closed = False
            self.assertTrue(closed, "the stalled body whose share was taken back was left open")
        server = self.served_broker()
        for _round in range(3):
            self.fill_with_stalled_bodies(server)
            time.sleep(lb.BODY_GRACE_S + 0.5)
            self.assertEqual(self.post()[0], 200)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and [t for t in server.bodies.tickets if t.cancelled]:
            time.sleep(0.05)
        self.assertEqual([t.held for t in server.bodies.tickets if t.cancelled], [],
                         "evicted bodies still hold shares of the budget")

    def fill_with_stalled_bodies(self, server):
        """A stalled max-size body and a stalled filler, holding all but 12 bytes of the budget the
        rest leaves; (the max-size body's socket, the filler's or None)."""
        def stall(length):
            conn = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            self.addCleanup(conn.close)
            conn.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\n\r\n{" % length)  # one body byte, then nothing
            return conn

        def settles(want):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not want(server.bodies.held):
                time.sleep(0.01)
            return server.bodies.held

        before = server.bodies.held
        big = stall(lb.MAX_BODY)
        held = settles(lambda h: h >= before + lb.WORST_PER_BYTE * lb.MAX_BODY)
        length = (lb.BODY_BUDGET - held - 12) // lb.WORST_PER_BYTE
        if length <= 0:
            return big, None
        filler = stall(length)
        settles(lambda h: h >= lb.BODY_BUDGET - 12 - lb.WORST_PER_BYTE)
        return big, filler

    def test_budget_goes_only_to_a_body_that_is_arriving(self):
        # A request whose body has not begun holds no share of the budget, however long it waits:
        # what is given back can go only to bodies actually arriving.
        server = self.served_broker()
        body = json.dumps(self.body()).encode()
        conn = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        self.addCleanup(conn.close)
        conn.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: %d\r\n\r\n" % len(body))
        time.sleep(0.5)
        self.assertEqual(server.bodies.held, 0, "a request with no body byte yet holds budget")
        conn.sendall(body)
        self.assertTrue(conn.recv(64).startswith(b"HTTP/1.0 200"))

    def ordinary_call_behind_stalled_requests(self, during):
        server = self.served_broker()
        big = 32_000_000
        small = (lb.BODY_BUDGET - lb.WORST_PER_BYTE * big - 12) // lb.WORST_PER_BYTE
        self.assertEqual(lb.BODY_BUDGET - lb.WORST_PER_BYTE * (big + small), 12)
        stalled = []

        def stall(length):
            conn = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            stalled.append(conn)
            conn.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\n\r\n{" % length)  # one body byte, then nothing
        self.addCleanup(lambda: [conn.close() for conn in stalled])
        for length in (big, small):  # the budget, but for 12 bytes
            stall(length)
            time.sleep(0.2)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and server.bodies.held != lb.BODY_BUDGET - 12:
            time.sleep(0.01)
        self.assertEqual(server.bodies.held, lb.BODY_BUDGET - 12, "the stalled holders did not take the budget")
        for length in [big] * (lb.MAX_CONNECTIONS - 3) + [small]:  # every other slot waits for budget
            stall(length)
        time.sleep(0.3)
        for _ in range(2):  # evict both holders: stalled waiters take what they gave back
            stall(big)
            time.sleep(0.3)
        stop = threading.Event()

        def keep_arriving():
            while not stop.wait(0.05):
                with contextlib.suppress(OSError):
                    stall(big)
        flood = threading.Thread(target=keep_arriving, daemon=True)
        flood.start()
        self.addCleanup(flood.join, 5)
        self.addCleanup(stop.set)
        time.sleep(0.3)
        if not during:
            stop.set()
            flood.join(5)
            time.sleep(0.2)
        started = time.monotonic()
        try:
            status, data = self.post()
        except (OSError, http.client.HTTPException) as err:
            status, data = None, repr(err)
        took = time.monotonic() - started
        stop.set()
        self.assertEqual(status, 200, data)
        self.assertLess(took, 10, f"an ordinary call took {took:.1f} s behind stalled requests")

    def test_a_body_is_held_once_not_twice(self):
        # Re-attack of 2d254d0f: read_body kept every chunk and then joined them, so each body was
        # held twice -- four concurrent 64 MiB bodies took the broker to 506 MB of its 512m.
        n = 8 << 20
        fake = types.SimpleNamespace(rfile=io.BufferedReader(io.BytesIO(b"x" * n)), connection=None, ledger=None,
                                     server=types.SimpleNamespace(was_evicted=lambda _conn: False),
                                     ticket=lb._Ticket(None, n))
        tracemalloc.start()
        try:
            body = lb.Broker.read_body(fake, n)
            _now, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(body), n)
        self.assertLess(peak, n + (n >> 2), f"reading a {n}-byte body peaked at {peak} bytes")

    def test_the_bodies_held_at_once_fit_the_brokers_container(self):
        # MAX_CONNECTIONS x MAX_BODY is 1 GB; the broker's container has 512m. What every connection
        # takes at once -- bodies and the bound parse_cost puts on parsing them -- is BODY_BUDGET,
        # which must leave the interpreter, its threads and its parse children room in that memory,
        # and hold the worst body MAX_BODY allows (13 times its bytes). That the bounds hold against
        # parsing itself is measured below, with adversarial and accepted bodies.
        memory = lc.BROKER_LIMITS["memory"]
        self.assertTrue(memory.endswith("m"), memory)
        limit = int(memory[:-1]) << 20
        self.assertLessEqual(lb.MAX_BODY, 32_000_000, "the API refuses a larger request")
        self.assertLessEqual(13 * lb.MAX_BODY + (1 << 20), lb.BODY_BUDGET)
        self.assertLessEqual(lb.BODY_BUDGET + lb.PARSERS * lb.PARSE_SLACK + (64 << 20), limit)

    # The broker alone in a child (the test's own copies of the bodies are not its memory), under a
    # 1 GiB data limit so a broker that parses them anyway fails there, not on the host. It prints
    # its port, serves until a line arrives on stdin, then prints its own peak (VmHWM) and the peak
    # of the largest parse child it forked (RUSAGE_CHILDREN, which counts the pages it shares with
    # the broker as well: an overcount). argv: live_broker.py, ledger, upstream, BODY_BUDGET in MiB,
    # the spend cap.
    BROKER_CHILD = ("import importlib.util, json, resource, sys\n"
                    "spec = importlib.util.spec_from_file_location('lb', sys.argv[1])\n"
                    "lb = importlib.util.module_from_spec(spec); spec.loader.exec_module(lb)\n"
                    "resource.setrlimit(resource.RLIMIT_DATA, (1 << 30, resource.getrlimit(resource.RLIMIT_DATA)[1]))\n"
                    "lb.BODY_BUDGET = int(sys.argv[4]) << 20\n"
                    "server, ledger = lb.serve('sk-ant-oat01-child', sys.argv[2], float(sys.argv[5]), port=0,\n"
                    "                          upstream=sys.argv[3])\n"
                    "print(server.server_address[1], flush=True)\n"
                    "sys.stdin.readline()\n"
                    "with open('/proc/self/status', encoding='ascii') as fh:\n"
                    "    peak = next(int(line.split()[1]) for line in fh if line.startswith('VmHWM:'))\n"
                    "print(json.dumps({'peak_kib': peak, 'children_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}),\n"
                    "      flush=True)\n")

    def test_a_body_whose_parse_would_pass_the_budget_is_refused_unparsed_and_counted(self):
        # Codex round 7 on 72739991: a ~60 MiB array of 20 million empty objects fits MAX_BODY and the
        # byte budget, but answer_post json.loads()-ed it before looking at its shape, and the dicts
        # need well over the container's 512m. parse_cost now bounds the parse first. Four bodies at
        # once, against the real budget: empty objects, nesting, tiny strings, numbers. Parsed, they
        # need some 700 MB together; refused, the broker never holds more than their bytes.
        if not sys.platform.startswith("linux"):
            return  # the broker runs in a Linux container; VmHWM is Linux's
        pad = {"empty objects": b"{}," * (4 << 20), "nesting": b"[" * 100_000, "tiny strings": b'"ab",' * (4 << 20),
               "numbers": b"1000," * (4 << 20)}
        head = b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}],"pad":['
        bodies = {what: head + filler + (b"]" * 100_000 if what == "nesting" else b"0") + b"]}"
                  for what, filler in pad.items()}
        answers, line = self.served_in_a_child(bodies)
        self.assertTrue(line, "the broker died parsing the bodies")
        peak = json.loads(line)["peak_kib"]
        self.assertLess(peak, 120 * 1024, f"the broker peaked at {peak} KiB on bodies it should never parse")
        self.assertEqual(answers, dict.fromkeys(bodies, 413), "a body was parsed rather than refused by its bound")
        self.assertEqual(self.api.requests, [])
        counts = [e["refused"] for e in self.events() if isinstance(e.get("refused"), dict)]
        self.assertEqual(counts[-1].get("body-parse"), len(bodies), counts[-1:])

    def served_in_a_child(self, bodies, cap=5.0):
        """Send `bodies` at once to a broker in its own process (BROKER_CHILD, the real BODY_BUDGET);
        ({name: HTTP status}, the line it reports its peaks on, empty if it died)."""
        child = subprocess.Popen([sys.executable, "-I", "-c", self.BROKER_CHILD, str(ROOT / "scripts" / "live_broker.py"),
                                  str(self.ledger_path), self.api.url, str(lb.BODY_BUDGET >> 20), str(cap)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        for done in (child.wait, child.kill, child.stdout.close, child.stdin.close):  # run in reverse
            self.addCleanup(done)
        self.port = int(child.stdout.readline())
        answers = {}

        def send(what):
            with contextlib.suppress(OSError, http.client.HTTPException):
                answers[what] = self.post(raw=bodies[what])[0]
        senders = [threading.Thread(target=send, args=(what,)) for what in bodies]
        for sender in senders:
            sender.start()
        for sender in senders:
            sender.join(120)
        time.sleep(lb.DROP_RECORD_S + 0.5)  # the ledger's tally line catches up the counts
        with contextlib.suppress(OSError):
            child.stdin.write("report\n")
            child.stdin.flush()
        return answers, child.stdout.readline()

    def test_the_pre_scan_itself_holds_no_memory_whatever_a_string_holds(self):
        # Codex round 8 on 70805faa: 129 literal [ inside a string forced the token walk, whose
        # regex matched a string by repeating a group per escape and kept state per repetition: 30
        # million \n escapes exhausted the broker before any bound was checked (4 MiB of them took
        # 235 MiB). The walk now finds one structural byte at a time and skips a string with find,
        # counting back only the backslashes right before a quote. Escapes, escaped quotes, long
        # backslash runs, brackets and quotes inside strings: each body costs the walk nothing but
        # time, bounded by MAX_SCAN_STEPS, and is answered.
        if not sys.platform.startswith("linux"):
            return  # the broker runs in a Linux container; VmHWM is Linux's
        brackets = b"[" * (lb.MAX_DEPTH + 1)  # inside the string: the structural count cannot answer
        content = {"escapes": b"\\n" * (2 << 20), "escaped quotes": b'\\"' * (lb.MAX_SCAN_STEPS + 1),
                   "backslash runs": b"\\\\" * (2 << 20), "structure inside": b'a,[b]:{c}\\"d\\\\ ' * (1 << 18)}
        bodies = {what: b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"'
                  + brackets + inner + b'"}],"pad":1}' for what, inner in content.items()}
        for what, body in bodies.items():  # each is the JSON it looks like
            self.assertIsInstance(json.loads(body), dict, what)
        answers, line = self.served_in_a_child(bodies)
        self.assertTrue(line, "the broker died scanning the bodies")
        peak = json.loads(line)["peak_kib"]
        self.assertLess(peak, 120 * 1024, f"the broker peaked at {peak} KiB scanning strings")
        children = json.loads(line)["children_kib"]
        self.assertLess(children, 160 * 1024, f"a parse child peaked at {children} KiB on strings of a few MiB")
        # Past MAX_SCAN_STEPS escaped quotes the walk stops and refuses; every other body is parsed
        # within its bound and refused on its terms (the "pad" field), never relayed.
        self.assertEqual(answers, {"escapes": 400, "escaped quotes": 413, "backslash runs": 400,
                                   "structure inside": 400})
        self.assertEqual(self.api.requests, [])
        counts = [e["refused"] for e in self.events() if isinstance(e.get("refused"), dict)][-1]
        self.assertEqual((counts.get("body-parse"), counts.get("terms")), (1, 3), counts)

    def test_max_size_unicode_bodies_are_accepted_and_parsed_within_the_container(self):
        # Codex round 9 on bdba24e5: 63 MiB of ASCII and one emoji fit parse_cost's old bound (5x),
        # but json.loads decodes the body to a UCS-4 str (4x) and parses the text to another (4x)
        # beside the body: past the 512m container before the terms were read. The bound now
        # charges the decoded input and the strings at their widths, MAX_BODY is the API's 32 MB,
        # and the parse runs in a child held to its bound. Max-size bodies, ASCII but for one emoji
        # (raw, or as an escaped surrogate pair) near the end, are parsed and relayed: alone, then
        # several at once. Parent and parse child together stay under the container's memory.
        if not sys.platform.startswith("linux"):
            return  # the broker runs in a Linux container; VmHWM is Linux's
        head = b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"'
        end = b'"}]}'

        def body(tail):
            return head + b"a" * (lb.MAX_BODY - len(head) - len(end) - len(tail)) + tail + end
        limit = int(lc.BROKER_LIMITS["memory"][:-1]) << 10  # KiB
        for bodies in ({"raw emoji": body("😀".encode())},
                       {"raw emoji": body("😀".encode()), "escaped emoji": body(b"\\ud83d\\ude00"),
                        "escaped emoji, early": body(b"\\ud83d\\ude00" + b"b" * 1024),
                        "raw emoji, early": body("😀".encode() + b"b" * 1024)}):
            with self.subTest(bodies=sorted(bodies)):
                for raw in bodies.values():
                    self.assertEqual(len(raw), lb.MAX_BODY)
                self.api.requests.clear()
                answers, line = self.served_in_a_child(bodies, cap=1e6)
                self.assertTrue(line, "the broker died parsing the bodies")
                got = json.loads(line)
                self.assertEqual(answers, dict.fromkeys(bodies, 200), "a max-size ordinary body was not relayed")
                self.assertEqual(sorted(len(r["body"]) for r in self.api.requests), [lb.MAX_BODY] * len(bodies))
                self.assertLess(got["peak_kib"] + got["children_kib"], limit,
                                f"broker {got['peak_kib']} KiB and a parse child {got['children_kib']} KiB pass the "
                                f"container's {limit} KiB")
                # Each body is held, parsed and freed in turn: glibc keeps no freed body buffer in a
                # thread's heap (it held 114 MB after four, before its mmap threshold was fixed).
                self.assertLess(got["peak_kib"], 96 * 1024, "freed body buffers stayed in the broker's memory")

    def test_a_parse_past_its_bound_fails_in_its_child_not_in_the_broker(self):
        # The bound parse_cost puts on a parse is the child's RLIMIT_DATA, so an estimate that ever
        # fell short would refuse the body, never grow the broker.
        if not sys.platform.startswith("linux"):
            return  # RLIMIT_DATA is enforced on Linux, where the broker runs
        body = (b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"'
                + b"a" * (8 << 20) + "😀".encode() + b'"}]}')
        self.assertEqual(lb._parse_in_child(body, 1 << 20), {"memory": True})
        facts = lb._parse_in_child(body, lb.parse_cost(body, 1 << 40) - len(body))
        self.assertEqual((facts.get("why"), facts.get("model"), facts.get("max_tokens")), (None, "claude-haiku-5-5", 10))

    def test_ordinary_large_bodies_still_pass_the_parse_bound(self):
        # Long text, non-ASCII text, a base64 image, thousands of messages and a hundred tools.
        self.broker(cap=10_000.0)  # 20 MB of input tokens at the cache-write price passes a $5 cap
        image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO" * (2 << 20)}}
        tools = [{"name": f"tool_{i}", "description": "run it, {carefully}: [a, b]",
                  "input_schema": {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
                                   "required": ["a"]}} for i in range(100)]
        turns = [{"role": "user" if i % 2 == 0 else "assistant", "content": [{"type": "text", "text": f"turn {i}, {{x}}: [y]"}]}
                 for i in range(3000)]
        big = {"model": "claude-haiku-5-5", "max_tokens": 1000, "stream": True, "tools": tools,
               "messages": [{"role": "user", "content": [{"type": "text", "text": "x, {y}: [z]\n" * (1 << 20)}, image]},
                            *turns[1:], {"role": "user", "content": "é😀 " * (1 << 20)}]}
        body = json.dumps(big, ensure_ascii=False).encode()
        self.assertGreater(len(body), 16 << 20)
        self.assertIsNotNone(lb.parse_cost(body, lb.BODY_BUDGET))
        self.assertEqual(self.post(raw=body)[0], 200)

    def test_a_body_past_the_budget_held_at_once_waits_then_is_refused_and_counted(self):
        # A budget its small body fits alone (the most a body of its length can take parsed, held
        # before it is read), and a held request that leaves less than that.
        big = self.body(messages=[{"role": "user", "content": "y" * 1800}])
        raw = json.dumps(big).encode()
        budget = lb.WORST_PER_BYTE * len(raw) + 64
        length = len(raw)
        held = lb.WORST_PER_BYTE * length
        for patch in (mock.patch.object(lb, "BODY_BUDGET", budget), mock.patch.object(lb, "BODY_WAIT_S", 0.5)):
            patch.start()
            self.addCleanup(patch.stop)
        server = self.served_broker()
        self.assertEqual(server.bodies.limit, budget)
        holder = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        self.addCleanup(holder.close)
        holder.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                       b"Content-Length: %d\r\n\r\n{" % length)  # its body is still arriving: `held` held
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.bodies.held != held:
            time.sleep(0.01)
        self.assertEqual(server.bodies.held, held)
        status, data = self.post(doc=big)
        self.assertEqual(status, 503, data)
        self.assertEqual(self.api.requests, [], "a body past the budget reached the API")
        refused = [e for e in self.events() if e["event"] == "refuse"]
        self.assertEqual([e["kind"] for e in refused], ["body-budget"])
        holder.close()  # its body never arrives: its bytes go back to the budget
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.bodies.held:
            time.sleep(0.01)
        self.assertEqual(server.bodies.held, 0, "a request's bytes were never given back")
        self.assertEqual(self.post(doc=big)[0], 200)


    def test_completed_bodies_needing_more_for_their_parses_never_wait_on_one_another(self):
        # Codex round 13 on 594f7265: 32 bodies of ~1 MB, each full of short JSON values, sent but
        # for their last byte, then completed together. Their first shares (13 times their bytes,
        # ~416 MB) left too little for any one's value-based parse charge, and once read in full
        # none was evictable: each waited for budget the others held until its 30 s deadline, then
        # 503. The same at small scale -- four such bodies, a budget all four first shares fit but no
        # larger charge does while they hold, nothing stalled -- must answer every request at once:
        # at most one body read in full waits for more while holding its share, any other is
        # refused (503) at once and gives its share back, and the one waiting is then served.
        n = 4
        head = (b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}],'
                b'"stop_sequences":[')
        body = head + b"1," * 2000 + b"1]}"
        first, cost = lb.WORST_PER_BYTE * len(body), lb.parse_cost(body, 1 << 40)
        self.assertGreater(cost, first, "the body's parse needs no more than its first share")
        budget = n * first + (cost - first) // 2  # the first shares fit; no larger charge does beside them
        self.assertGreaterEqual(budget, cost, "one body alone could not be parsed")
        wait_s = 6.0
        for patch in (mock.patch.object(lb, "BODY_BUDGET", budget), mock.patch.object(lb, "BODY_WAIT_S", wait_s),
                      mock.patch.object(lb, "BODY_GRACE_S", 60.0)):  # nothing here stalls: none is evictable
            patch.start()
            self.addCleanup(patch.stop)
        server = self.served_broker()
        conns = []
        for _ in range(n):
            conn = socket.create_connection(("127.0.0.1", self.port), timeout=wait_s * 3)
            self.addCleanup(conn.close)
            conn.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\n\r\n" % len(body) + body[:-1])
            conns.append(conn)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.bodies.held != n * first:
            time.sleep(0.01)
        self.assertEqual(server.bodies.held, n * first, "the bodies did not all hold their first shares")
        started = time.monotonic()
        for conn in conns:
            conn.sendall(body[-1:])

        def status(conn):
            data = b""
            with contextlib.suppress(OSError):
                while chunk := conn.recv(65536):
                    data += chunk
            return int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else None
        statuses = [status(conn) for conn in conns]
        took = time.monotonic() - started
        self.assertLess(took, wait_s / 2, f"completed bodies waited {took:.1f} s on one another for their parses "
                                          f"(answers {statuses})")
        self.assertIn(200, statuses, "no completed body was served")
        self.assertEqual(sorted(set(statuses) | {200, 503}), [200, 503], statuses)
        self.assertEqual(len(self.api.requests), statuses.count(200))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.bodies.held:
            time.sleep(0.01)
        self.assertEqual(server.bodies.held, 0, "a share was never given back")
        time.sleep(lb.DROP_RECORD_S + 0.5)  # the ledger's tally line catches up the counts
        self.assertEqual({e["kind"] for e in self.events() if e["event"] == "refuse"} | {"body-budget"}, {"body-budget"})
        counts = [e["refused"] for e in self.events() if isinstance(e.get("refused"), dict)]
        self.assertEqual((counts[-1:] or [{}])[-1].get("body-budget", 0), statuses.count(503), counts[-1:])

    def test_a_bodys_bytes_stay_charged_until_its_buffer_is_freed(self):
        # Codex round 1 on PR #732 at 9f895d11: a completed body refused because another already
        # waited for more gave back its whole share, its bytes' charge included, and only then wrote
        # its 503 and returned, its buffer alive all the while; another request could spend that
        # charge first, so live buffers sat outside BODY_BUDGET. Every give is watched here: none may
        # leave a request holding less than its body's bytes while something besides this watch
        # still references a buffer holding them, and a 503 after a body was read is written only
        # with its bytes still charged. Losing growers (the scenario above), and a request whose
        # relay raises after its parse, its frames still holding the buffer as do_POST cleans up.
        n = 4
        head = (b'{"model":"claude-haiku-5-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}],'
                b'"stop_sequences":[')
        body = head + b"1," * 2000 + b"1]}"
        first, cost = lb.WORST_PER_BYTE * len(body), lb.parse_cost(body, 1 << 40)
        wait_s = 6.0
        buffers, gaps, at_503 = {}, [], []
        real_read, real_give, real_fail = lb.Broker.read_body, lb._BodyBudget.give, lb.Broker.fail

        def read_body(handler, length):
            got = real_read(handler, length)
            if got is not None:
                buffers[handler.ticket] = got
            return got

        def give(budget, ticket, count=None):
            buf = buffers.get(ticket)
            left = ticket.held - (ticket.held if count is None else min(count, ticket.held))
            # References: this dict, `buf`, and getrefcount's own argument; any more is the request's.
            if buf is not None and len(buf) and sys.getrefcount(buf) > 3 and left < len(buf):
                gaps.append((len(buf), left))
            return real_give(budget, ticket, count)

        def fail(handler, status, kind, why):
            buf = buffers.get(getattr(handler, "ticket", None))
            if status == 503 and buf is not None and len(buf):
                at_503.append((handler.ticket.held, len(buf)))
            return real_fail(handler, status, kind, why)
        for patch in (mock.patch.object(lb, "BODY_BUDGET", n * first + (cost - first) // 2),
                      mock.patch.object(lb, "BODY_WAIT_S", wait_s), mock.patch.object(lb, "BODY_GRACE_S", 60.0),
                      mock.patch.object(lb.Broker, "read_body", read_body), mock.patch.object(lb.Broker, "fail", fail),
                      mock.patch.object(lb._BodyBudget, "give", give)):
            patch.start()
            self.addCleanup(patch.stop)
        server = self.served_broker()

        def send(raw, hold_last):
            conn = socket.create_connection(("127.0.0.1", self.port), timeout=wait_s * 3)
            self.addCleanup(conn.close)
            conn.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\n\r\n" % len(raw) + (raw[:-1] if hold_last else raw))
            return conn

        def answer(conn):
            data = b""
            with contextlib.suppress(OSError):
                while chunk := conn.recv(65536):
                    data += chunk
            return int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else None
        conns = [send(body, True) for _ in range(n)]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.bodies.held != n * first:
            time.sleep(0.01)
        self.assertEqual(server.bodies.held, n * first, "the bodies did not all hold their first shares")
        for conn in conns:
            conn.sendall(body[-1:])
        statuses = sorted(answer(conn) for conn in conns)
        self.assertEqual(statuses, [200, 503, 503, 503])
        self.assertEqual(len(at_503), 3, at_503)
        self.assertEqual([held >= size for held, size in at_503], [True] * 3,
                         f"a refused body's 503 was written with its bytes' charge given back (held, bytes): {at_503}")
        self.assertEqual(gaps, [], "a request gave back its bytes' charge while its buffer held them (bytes, left)")

        def raises(handler, *args):
            raise RuntimeError("the relay failed after the parse")
        with mock.patch.object(lb.Broker, "relay", raises):
            self.assertIsNone(answer(send(json.dumps(self.body()).encode(), False)), "a failed relay was answered")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and server.bodies.held:
            time.sleep(0.01)
        self.assertEqual(gaps, [], "a request gave back its bytes' charge while its frames held its buffer")
        self.assertEqual(server.bodies.held, 0, "a share was never given back")
        self.assertIn("handler", {e.get("where") for e in self.events() if e["event"] == "fault"})

    def test_at_most_one_request_waits_for_budget_while_holding_a_share(self):
        # The invariant behind the test above, on the budget itself. Of two holders that each need
        # more than fits, one waits (the grower) and the other is refused at once; while the grower
        # waits, a first take that would fit the free budget but not beside what the grower still
        # needs waits too, holding nothing; once the refused holder gives its share back the grower
        # is served, and the newcomer once the grower's share comes back.
        budget, none = lb._BodyBudget(100), (lambda _ticket: None)
        a, b, c = (lb._Ticket(None, 1) for _ in range(3))
        self.assertTrue(budget.take(a, 40, time.monotonic() + 1, none))
        self.assertTrue(budget.take(b, 40, time.monotonic() + 1, none))
        got = {}

        def take(name, ticket, n, grow):
            got[name] = budget.take(ticket, n, time.monotonic() + 10, none, grow=grow)
        threads = {"a": threading.Thread(target=take, args=("a", a, 50, True), daemon=True),
                   "c": threading.Thread(target=take, args=("c", c, 15, False), daemon=True)}
        threads["a"].start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and budget.grower is not a:
            time.sleep(0.01)
        self.assertIs(budget.grower, a, "the first holder needing more did not wait for it")
        started = time.monotonic()
        self.assertFalse(budget.take(b, 50, time.monotonic() + 10, none, grow=True))
        self.assertLess(time.monotonic() - started, 1, "a second holder waited for more beside the first")
        threads["c"].start()
        time.sleep(0.3)
        self.assertEqual(got, {}, "a take was granted past what the waiting holder needs")
        budget.give(b)  # refused: its share goes back
        threads["a"].join(5)
        self.assertEqual((got.get("a"), a.held, budget.grower), (True, 90, None))
        self.assertNotIn("c", got, "the newcomer was granted past the budget")
        budget.give(a)
        threads["c"].join(5)
        self.assertEqual((got.get("c"), budget.held), (True, 15))

# ---------------------------------------------------------------------------- the arm's `claude`

def load_wrapper():
    """The arm's `claude` wrapper as a module (it has no .py suffix), writing no bytecode."""
    loader = importlib.machinery.SourceFileLoader("live_container_claude_under_test", str(WRAPPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    prior, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = prior
    return mod


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TheArmsClaudeTalksToTheBroker(unittest.TestCase):
    """Inside the arm's container `claude` on PATH is scripts/live_container_bin/claude. It holds no
    token: it execs the pinned Claude Code with the broker as its API and a placeholder credential,
    dropping any credential, endpoint or proxy the arm's environment carries."""

    def setUp(self):
        self.wrapper = load_wrapper()

    def run_wrapper(self, *argv, environ=None, ready=True):
        execs = []

        def execve(path, args, env):  # exec never returns
            execs.append((path, list(args), dict(env)))
            raise SystemExit(0)
        err = io.StringIO()
        env = {"PATH": "/usr/bin:/bin", "HOME": "/home/runner", **(environ or {})}
        with mock.patch.object(self.wrapper.os, "execve", execve), contextlib.redirect_stderr(err), \
                mock.patch.object(self.wrapper, "broker_ready", lambda *a: ready), \
                mock.patch.dict(os.environ, env, clear=True):
            try:
                rc = self.wrapper.main(list(argv))
            except SystemExit as exc:
                rc = exc.code
        return rc, execs, err.getvalue()

    def test_claude_gets_the_broker_and_a_placeholder_never_a_credential(self):
        planted = {"CLAUDE_CODE_OAUTH_TOKEN": "sk-ant-oat01-planted", "ANTHROPIC_API_KEY": "sk-ant-api-planted",
                   "ANTHROPIC_BASE_URL": "https://elsewhere.invalid", "HTTPS_PROXY": "http://proxy.invalid:3128"}
        rc, execs, err = self.run_wrapper("-p", "hello", environ=planted)
        self.assertEqual(rc, 0, err)
        (path, args, env), = execs
        self.assertEqual((path, args), (self.wrapper.REAL, [self.wrapper.REAL, "-p", "hello"]))
        self.assertEqual(env["ANTHROPIC_BASE_URL"], f"http://127.0.0.1:{lc.BROKER_PORT}")
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], self.wrapper.PLACEHOLDER)
        for name in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "HTTPS_PROXY"):
            self.assertNotIn(name, env)
        self.assertEqual(env["PATH"], "/usr/bin:/bin")

    def test_a_broker_that_never_answers_refuses(self):
        rc, execs, err = self.run_wrapper("-p", "hello", ready=False)
        self.assertEqual((rc, execs), (2, []), err)
        self.assertIn("no credential broker answers", err)
        self.assertIn("live_container.py", err)

    def test_it_waits_for_the_broker_to_answer(self):
        port = free_port()
        with mock.patch.object(self.wrapper, "BROKER", f"http://127.0.0.1:{port}"):
            self.assertFalse(self.wrapper.broker_ready(0.5), "nothing listens, yet the broker was ready")
            server = ThreadingHTTPServer(("127.0.0.1", port), type("H", (BaseHTTPRequestHandler,), {
                "do_GET": lambda self: (self.send_response(200), self.end_headers()),
                "log_message": lambda self, *a: None}))
            threading.Timer(0.6, lambda: threading.Thread(target=server.serve_forever, daemon=True).start()).start()
            try:
                self.assertTrue(self.wrapper.broker_ready(10))
            finally:
                server.shutdown()
                server.server_close()

    def test_a_version_query_needs_no_broker(self):
        rc, execs, err = self.run_wrapper("--version", ready=False)
        self.assertEqual(rc, 0, err)
        self.assertEqual(execs[0][1], [self.wrapper.REAL, "--version"])
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", execs[0][2])

    def settings(self, content):
        path = Path(tempfile.mkdtemp(prefix="claude-settings-")) / "claude.json"
        self.addCleanup(shutil.rmtree, path.parent, True)
        path.write_text(content, encoding="utf-8")
        patch = mock.patch.object(self.wrapper, "SETTINGS", str(path))
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_per_call_limit_reaches_every_call(self):
        self.settings('{"max_budget_usd": "1.60"}')
        rc, execs, err = self.run_wrapper("-p", "hello")
        self.assertEqual(rc, 0, err)
        self.assertEqual(execs[0][1], [self.wrapper.REAL, "--max-budget-usd", "1.60", "-p", "hello"])

    def test_the_limit_comes_before_a_double_dash(self):
        # Codex at cb51f73bb2: appended after "--" the limit was a prompt, and prompt text after "--"
        # that looked like a limit was taken for the caller's own
        self.settings('{"max_budget_usd": "1.60"}')
        for argv in (("-p", "--", "hello"), ("-p", "--", "--max-budget-usd", "9")):
            with self.subTest(argv=argv):
                rc, execs, err = self.run_wrapper(*argv)
                self.assertEqual(execs[0][1], [self.wrapper.REAL, "--max-budget-usd", "1.60", *argv])

    def test_a_callers_own_limit_is_left_alone(self):
        self.settings('{"max_budget_usd": "1.60"}')
        for argv in (("-p", "x", "--max-budget-usd", "0.5"), ("-p", "x", "--max-budget-usd=0.5")):
            with self.subTest(argv=argv):
                rc, execs, err = self.run_wrapper(*argv)
                self.assertEqual(execs[0][1], [self.wrapper.REAL, *argv])

    def test_a_version_query_takes_no_limit(self):
        self.settings('{"max_budget_usd": "1.60"}')
        rc, execs, err = self.run_wrapper("--version")
        self.assertEqual(execs[0][1], [self.wrapper.REAL, "--version"])

    def test_settings_that_cannot_be_read_refuse(self):
        for content in ("not json", '{"max_budget_usd": "abc"}', '{"max_budget_usd": 0}', "[1]"):
            with self.subTest(content=content):
                self.settings(content)
                rc, execs, err = self.run_wrapper("-p", "hello")
                self.assertEqual((rc, execs), (2, []), err)
                self.assertIn("cannot be read", err)

    def test_without_settings_no_limit_is_added(self):
        missing = Path(tempfile.mkdtemp(prefix="claude-settings-")) / "absent.json"
        self.addCleanup(shutil.rmtree, missing.parent, True)
        with mock.patch.object(self.wrapper, "SETTINGS", str(missing)):
            rc, execs, err = self.run_wrapper("-p", "hello")
        self.assertEqual(execs[0][1], [self.wrapper.REAL, "-p", "hello"])

    def test_the_wrapper_the_broker_and_the_launcher_agree(self):
        self.assertEqual(self.wrapper.BROKER, f"http://127.0.0.1:{lb.PORT}")
        self.assertEqual(self.wrapper.SETTINGS, lc.CLAUDE_SETTINGS)
        self.assertEqual(lb.PORT, lc.BROKER_PORT)
        entries = lc.CONTAINER_PATH.split(":")
        self.assertEqual(entries[0], f"{lc.REPO_IN}/{WRAPPER.parent.relative_to(ROOT)}")
        self.assertNotIn("/home/runner/.local/bin", entries, "the raw claude is on the arm's PATH")
        self.assertTrue(os.access(WRAPPER, os.X_OK), "the wrapper is not executable")
        self.assertIn(f"{self.wrapper.REAL} --version", lc.DOCKERFILE.read_text(encoding="utf-8"),
                      "the image does not verify the binary the wrapper execs")
        self.assertNotIn("SECRET", vars(self.wrapper), "the arm's claude knows where a token would be")


if __name__ == "__main__":
    unittest.main()
