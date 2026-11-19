#!/usr/bin/env python3
"""Smoke tests for runtime/scripts/verify-gate.sh.

The completion-gate hook entrypoint must FAIL CLOSED: block (exit 2) when there is nothing to
verify, no authoritative contract, or the verifier fails; allow (exit 0) only when the manifest
passes against the coordinator-supplied contract.
"""
import atexit
import hashlib
import importlib.util
import itertools
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "runtime" / "scripts"
GATE = SCRIPTS / "verify-gate.sh"


_SRC_SEQ = itertools.count()


def _src(repo, ids):
    """A frozen-contract fixture INSIDE `repo`, named relatively: #267 refuses absolute and
    out-of-repo evidence paths, and verify.py resolves relative ones against the toplevel of the
    process cwd — which is why every gate test runs in a hermetic repo."""
    rel = f"contract-{next(_SRC_SEQ)}.md"
    (repo / rel).write_text("frozen\n" + "".join(f"- {i}: x\n" for i in ids), encoding="utf-8")
    return rel


def _digest(repo, rel):
    return "sha256:" + hashlib.sha256((repo / rel).read_bytes()).hexdigest()


_spec = importlib.util.spec_from_file_location("verify", SCRIPTS / "verify.py")
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)

# The dirs a host installs its root-owned tools into. NAMES only nominate: each is admitted to the
# sound-lane PATH only after verify.py's own ownership+mode probe says no node on the way to it
# is the effective user's (h409 R-1 ruling, docs/DECISIONS.md h409-r3-review-reloop).
_SYSTEM_DIR_CANDIDATES = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
_SYSTEM_PATH = []


def _system_path():
    """The PATH a SOUND-lane gate run gets: the host's genuinely root-owned system dirs and
    nothing else — no coordinator-trusted dir, no fixture dir the effective user owns (a 0555
    of one's own is one chmod from writable: review-r3 C-2), no hard links, nothing to reap.
    A sound lane pins git/gh/gitleaks by verify.py's custody PROBE and fails closed on a
    worker-writable git, so driving it with the host PATH is RED wherever git lives in a
    user-writable dir (every Homebrew host). Each candidate dir is admitted only when every
    node from `/` down to it passes the same probe the production code applies."""
    if not _SYSTEM_PATH:
        admitted = []
        for d in _SYSTEM_DIR_CANDIDATES:
            if os.path.isdir(d) and verify._Authority.classify(d) == "system":
                admitted.append(d)
        _SYSTEM_PATH.append(os.pathsep.join(admitted))
    return _SYSTEM_PATH[0]


def _require_system_tools(*tools):
    """Skip — with the tool and the reason named — when a tool the sound lane needs has no
    system-class instance on this host. verify-gate.sh itself runs `python3` from PATH, so the
    interpreter must be present there too (it is not an authority verify.py classes, so
    presence is enough)."""
    path = _system_path()
    if not path:
        raise unittest.SkipTest("no root-owned system bin dir on this host "
                                f"(candidates: {', '.join(_SYSTEM_DIR_CANDIDATES)})")
    for tool in tools:
        found = shutil.which(tool, path=path)
        if not found:
            raise unittest.SkipTest(f"{tool} has no instance under the system dirs ({path}); the "
                                    "sound-lane gate cannot run against a user-writable one")
        if tool != "python3" and verify._Authority.classify(found) != "system":
            raise unittest.SkipTest(f"{tool} at {found} is not system-class by verify.py's probe")
    return path


def run_gate(manifest=None, contract_source=None, contract_digest=None, unit_class=None,
             provenance=None, event=None, dispatch_record=None, dispatch_pubkey=None,
             gate=None, cwd=None, execute_nc=None, lighting=None, path_prefix=None):
    # A lane that claims soundness — off-worker provenance, or a signed dispatch record whose key
    # the gate may discover — resolves its authorities from the host's root-owned system dirs
    # only; the native lane runs on the host PATH and records worker-writable ones as NOTEs.
    sound = provenance is not None or dispatch_record is not None
    env = {"PATH": _require_system_tools("git", "python3") if sound else os.environ.get("PATH", "")}
    if path_prefix is not None:  # a dir the test plants FIRST on PATH, ahead of the system dirs
        env["PATH"] = str(path_prefix) + os.pathsep + env["PATH"]
    if execute_nc is not None:
        env["ORCA_EXECUTE_NC"] = execute_nc
    if lighting is not None:
        env["ORCA_LIGHTING"] = lighting
    if manifest is not None:
        env["ORCA_MANIFEST"] = str(manifest)
    if contract_source is not None:
        env["ORCA_CONTRACT_SOURCE"] = contract_source
    if contract_digest is not None:
        env["ORCA_CONTRACT_DIGEST"] = contract_digest
    if unit_class is not None:
        env["ORCA_UNIT_CLASS"] = unit_class
    if provenance is not None:
        env["ORCA_PROVENANCE"] = provenance
    if dispatch_record is not None:
        env["ORCA_DISPATCH_RECORD"] = dispatch_record
    if dispatch_pubkey is not None:
        env["ORCA_DISPATCH_PUBKEY"] = dispatch_pubkey
    argv = [str(gate or GATE)]
    if event is not None:
        argv += ["--event", event]
    return subprocess.run(argv, capture_output=True, text=True, cwd=cwd or ROOT, env=env)


_KEY_DIRS = []


def _mint_key():
    """Mint an Ed25519 keypair; returns (secret_path, public_hex). The public half is what a repo
    pins as .orca/dispatch-pubkey. The temp dir is reaped at interpreter exit (#381)."""
    d = Path(tempfile.mkdtemp())
    _KEY_DIRS.append(d)
    subprocess.run([sys.executable, str(SCRIPTS / "dispatch-sign.py"), "gen-key",
                    "--out", str(d / "key")], check=True, capture_output=True)
    return d / "key", (d / "key.pub").read_text(encoding="utf-8")


atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _KEY_DIRS])


def _sign(repo, digest, unit_class, manifest_id="review-it", lighting=None, key=None):
    """Sign a dispatch record and drop it, with its public key, INSIDE `repo` under relative names
    (#267). Returns (record_rel, pubkey_rel) — what a real dispatch would hand the gate."""
    n = next(_SRC_SEQ)
    secret, public = key if key else _mint_key()
    args = [sys.executable, str(SCRIPTS / "dispatch-sign.py"), "sign", "--key", str(secret),
            "--manifest-id", manifest_id, "--contract-digest", digest, "--unit-class", unit_class]
    if lighting:
        args += ["--lighting", lighting]
    rec = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    rec_rel, pub_rel = f".orca/rec-{n}.json", f".orca/key-{n}.pub"
    (repo / ".orca").mkdir(exist_ok=True)
    (repo / rec_rel).write_text(rec, encoding="utf-8")
    (repo / pub_rel).write_text(public, encoding="utf-8")
    return rec_rel, pub_rel


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _git_out(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _hermetic_repo():
    """A one-commit repo the gate can run inside. #163's skip is gone with it: the fixtures used to
    resolve 'HEAD' against the AMBIENT clone (unborn on some CI checkouts); now every gate test
    brings its own repo, so HEAD always resolves and nothing is skipped."""
    repo = Path(tempfile.mkdtemp())
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return repo


class GateCase(unittest.TestCase):
    """#267 bounds contract / dispatch-record / pubkey paths to the toplevel of the process cwd, so
    the gate runs inside a hermetic repo and every path it is handed is relative to that repo."""

    def setUp(self):
        self.repo = self.make_repo()
        self.addCleanup(shutil.rmtree, self.repo, True)

    def make_repo(self):
        return _hermetic_repo()

    def src(self, ids):
        return _src(self.repo, ids)

    def digest(self, rel):
        return _digest(self.repo, rel)

    def sign(self, digest, unit_class, **kw):
        return _sign(self.repo, digest, unit_class, **kw)

    def pinned(self, rel):
        """`rel` committed and named AT that commit — the form a lane claiming soundness reads a
        key in (W3-03): a bare path is the graded worker's own working tree."""
        _git(self.repo, "add", rel)
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", f"pin {rel}")
        return f"{rel}@{_git_out(self.repo, 'rev-parse', 'HEAD')}"

    def manifest(self, source, ids_declared, ids_addressed):
        return _manifest(self.repo, source, ids_declared, ids_addressed)

    def gate(self, manifest=None, *a, **kw):
        kw.setdefault("cwd", self.repo)
        return run_gate(manifest, *a, **kw)


def _gate_repo(pin_blob=None, pin_worktree=None, remote_head=True):
    """A hermetic git repo hosting a COPY of runtime/scripts, so the gate copy's HERE-relative
    dispatch-pubkey discovery (verify-gate.sh:53-60) reads THIS repo's refs/worktree, never the
    real repo's. pin_blob: pubkey committed as .orca/dispatch-pubkey (worktree copy removed unless
    pin_worktree is also set); pin_worktree: pubkey left in the worktree; remote_head: craft
    refs/remotes/origin/{main,HEAD}."""
    repo = Path(tempfile.mkdtemp())
    _git(repo, "init", "-q", "-b", "main")
    shutil.copytree(SCRIPTS, repo / "runtime" / "scripts",
                    ignore=shutil.ignore_patterns("__pycache__"))
    if pin_blob is not None or pin_worktree is not None:
        pin = repo / ".orca" / "dispatch-pubkey"
        pin.parent.mkdir(exist_ok=True)
        pin.write_text((pin_blob or pin_worktree)[1], encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    if pin_blob is not None and pin_worktree is None:
        os.remove(repo / ".orca" / "dispatch-pubkey")  # blob-only: worktree fallback cannot fire
    if remote_head:
        _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    # #193 review: origin/HEAD and local HEAD must NOT alias the same commit, or a
    # regression that reads the pin from worker-modifiable HEAD still greens
    # test_remote_blob_hit. After origin is pinned at the blob commit, advance
    # HEAD to a pinless commit so only the remote-ref read can supply the key.
    if pin_blob is not None and pin_worktree is None and remote_head:
        _git(repo, "add", "-A")
        _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "no-pin")
    return repo


def _doc_range(repo):
    """Two real commits whose only difference is a document — the honest report-only shape.

    These fixtures used `HEAD..HEAD`, which is now refused: an empty declared range asserts that
    the unit changed nothing while giving the gate no diff to check that against, and a unit that
    changed code can assert it just as easily (#310, PR #308 review)."""
    base = _git_out(repo, "rev-parse", "HEAD")
    rel = f"docs/report-{next(_SRC_SEQ)}.md"
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text("# report\n", encoding="utf-8")
    _git(repo, "add", rel)
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "report")
    return base, _git_out(repo, "rev-parse", "HEAD")


def _manifest(repo, source, ids_declared, ids_addressed):
    path = repo / f"manifest-{next(_SRC_SEQ)}.json"
    base, head = _doc_range(repo)
    path.write_text(json.dumps({
        "unit": "review-it", "unit_class": "report-only",
        "base_sha": base, "head_sha": head,
        "contract": {"source": source, "digest": _digest(repo, source),
                     "criterion_ids": ids_declared},
        "criteria": [{"id": i, "addressed": True} for i in ids_addressed],
        "pr": {"reviewed_sha": head},
    }), encoding="utf-8")
    return str(path)


class VerifyGateFailsClosed(GateCase):

    def test_no_manifest_blocks(self):
        self.assertEqual(self.gate(None).returncode, 2)

    def test_no_contract_blocks(self):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        self.assertEqual(self.gate(m, unit_class="report-only").returncode, 2)  # scope fail-closed

    def test_good_manifest_allows(self):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="report-only")
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")

    def test_scope_shrink_blocks(self):
        src = self.src(["AC-1", "AC-2"])
        m = self.manifest(src, ["AC-1", "AC-2"], ["AC-1"])
        self.assertEqual(self.gate(m, src, self.digest(src), unit_class="report-only").returncode, 2)

    def test_missing_unit_class_gated_as_mutation_blocks(self):
        # #110 fail-safe: without ORCA_UNIT_CLASS the unit is gated as mutation, so a report-only-
        # shaped manifest with no independent GitHub review blocks (exit 2) rather than passing.
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        self.assertEqual(self.gate(m, src, self.digest(src)).returncode, 2)

    def test_unknown_unit_class_fails_safe_to_mutation(self):
        # #178: an unknown ORCA_UNIT_CLASS (a typo like "mutatoin") must NOT wedge argparse with a
        # usage error — the gate forwards it verbatim, verify.py reaches the real invariant checks,
        # and _is_mutation's fallback gates the unit as mutation: a report-only-shaped manifest
        # fails a mutation invariant (exit 2), and a NOTE on stdout names the unknown value.
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="mutatoin")
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("mutatoin", r.stdout)                 # the loud NOTE, not a silent fallback
        self.assertNotIn("invalid choice", r.stderr)        # no argparse wedge
        self.assertIn("mutation unit", r.stderr)            # mutation-strict checks actually ran


class VerifyGateExecuteNC(GateCase):
    """#255/#256: ORCA_EXECUTE_NC reaches verify.py as --execute-nc, and the two review-waiver
    lanes are RED without it. Asserted through BEHAVIOUR — the messages only verify.py's executed
    path can produce — so a regression that drops the forwarding line cannot pass."""

    def _mutation_manifest(self, src, nc):
        head = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
        path = self.repo / "mutation-manifest.json"
        path.write_text(json.dumps({
            "unit": "ship-it", "base_sha": head, "head_sha": head,
            "contract": {"source": src, "digest": self.digest(src), "criterion_ids": ["AC-1"]},
            "criteria": [{"id": "AC-1", "addressed": True}],
            "negative_control": nc, "lighting": "dark-eligible",
            "reviewer_mode": "cross-vendor",
            "intent": {"goal": "g", "ruled_out": "r", "why": "w"},
        }), encoding="utf-8")
        return str(path)

    def _nc(self):
        rel = "docs/reports/u/nc.txt"
        (self.repo / "docs" / "reports" / "u").mkdir(parents=True, exist_ok=True)
        (self.repo / rel).write_text("mutant m7 KILLED — proof went RED\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "nc")
        return {"tool": "mutmut", "mutant": "m7", "result": "KILLED", "artifact": rel}

    def test_execute_nc_env_reaches_the_verifier(self):
        src = self.src(["AC-1"])
        m = self._mutation_manifest(src, self._nc())
        r = self.gate(m, src, self.digest(src), unit_class="mutation", event="task",
                      lighting="dark-eligible", execute_nc="1")
        self.assertEqual(r.returncode, 2)
        # only the EXECUTED path emits this — proof the env var was forwarded as --execute-nc
        self.assertIn("no replay is implemented", r.stderr)

    def test_dark_lane_without_execute_nc_blocks(self):
        src = self.src(["AC-1"])
        m = self._mutation_manifest(src, self._nc())
        r = self.gate(m, src, self.digest(src), unit_class="mutation", event="task",
                      lighting="dark-eligible")
        self.assertEqual(r.returncode, 2)
        self.assertIn("EXECUTED", r.stderr)
        self.assertNotIn("no replay is implemented", r.stderr)


class VerifyGateTrustBoundary(GateCase):
    """#112: the gate is advisory when provenance is in-session, sound when off-worker."""


    def test_advisory_note_when_provenance_unset(self):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="report-only")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ADVISORY", r.stderr)

    def test_no_note_when_provenance_offworker(self):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="report-only", provenance="ci")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("ADVISORY", r.stderr)


class VerifyGateStopScope(GateCase):
    """#121: Stop fires on every turn end; with no unit in progress it must ALLOW, while
    TaskCompleted (or an explicit manifest) with no manifest still blocks (mis-dispatch)."""


    def test_stop_no_manifest_allows(self):
        self.assertEqual(self.gate(None, event="stop").returncode, 0)

    def test_task_no_manifest_blocks(self):
        self.assertEqual(self.gate(None, event="task").returncode, 2)

    def test_stop_with_manifest_still_verifies(self):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="report-only", event="stop")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_stop_named_but_missing_manifest_blocks(self):
        # #141 review: a NAMED manifest whose file is deleted/mistyped means an active unit's
        # evidence is gone — Stop must fail closed, not silently treat it like "no unit in progress".
        r = self.gate("/tmp/orca-does-not-exist-" + os.urandom(4).hex() + ".json", event="stop")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("named but missing", r.stderr)


class VerifyGateSignedDispatch(GateCase):
    """#135: the gate forwards a signed dispatch record to verify.py; the signature is checked and a
    substituted value is blocked. Off-worker (provenance set) it is a soundness boundary; on the native
    path it stays advisory — no in-session anchor is trustworthy."""


    def test_signed_dispatch_verified_off_worker(self):
        # ORCA_PROVENANCE=dispatch models an OFF-WORKER context that supplies the key: verify.py checks
        # the signature and the advisory NOTE is suppressed.
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])   # _manifest's unit is "review-it"
        rec, pub = self.sign(self.digest(src), "report-only")
        r = self.gate(m, src, self.digest(src), unit_class="report-only", event="task",
                     provenance="dispatch", dispatch_record=rec, dispatch_pubkey=self.pinned(pub))  # W3-03
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("signature verified", r.stdout + r.stderr)
        self.assertNotIn("ADVISORY", r.stderr)

    def test_signed_dispatch_class_substitution_blocks(self):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        rec, pub = self.sign(self.digest(src), "mutation")   # coordinator signed 'mutation'
        r = self.gate(m, src, self.digest(src), unit_class="report-only", event="task",  # worker downgraded
                     provenance="dispatch", dispatch_record=rec, dispatch_pubkey=self.pinned(pub))  # W3-03
        self.assertEqual(r.returncode, 2)
        self.assertIn("substitution", r.stderr)

    def test_native_hook_stays_advisory_with_record(self):
        # #135 review: no in-session anchor is trustworthy (worker controls ORCA_*), so even with a
        # record + key the NATIVE path (no off-worker provenance) must stay ADVISORY — never claim sound.
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        rec, pub = self.sign(self.digest(src), "report-only")
        r = self.gate(m, src, self.digest(src), unit_class="report-only", event="task",
                     dispatch_record=rec, dispatch_pubkey=pub)   # no provenance → native path
        self.assertIn("ADVISORY", r.stderr)

    def test_the_advisory_note_says_a_ref_pin_is_only_as_good_as_who_writes_refs(self):
        # PR #719 re-attack: in a worker's own clone `git update-ref refs/remotes/origin/main`
        # succeeds, so the native lane's NOTE must say a remote-tracking or commit pin is
        # trustworthy only where the worker cannot write refs.
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="report-only", event="task")
        self.assertIn("ADVISORY", r.stderr)
        self.assertIn("refs/remotes/* too", r.stderr)
        self.assertIn("trustworthy only where the worker cannot write", r.stderr)

    def test_worker_set_env_pubkey_honored_with_advisory_note(self):
        # #164: the gate reads ORCA_DISPATCH_PUBKEY unconditionally — a WORKER-SET env key is honored
        # (ORCA_PROVENANCE gates only the NOTE, never the key source). If the env key were ignored the
        # record would be half-configured (no pin exists in this repo) and the gate would fail closed;
        # exit 0 + "signature verified" pins that verification ran AGAINST the env key.
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        rec, pub = self.sign(self.digest(src), "report-only")
        r = self.gate(m, src, self.digest(src), unit_class="report-only", event="task",
                     dispatch_record=rec, dispatch_pubkey=pub)   # worker-set env key, no provenance
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("signature verified", r.stdout + r.stderr)
        self.assertIn("ADVISORY", r.stderr)


class VerifyGateDispatchPinDiscovery(GateCase):
    """#171: verify-gate.sh:53-60 — the gate discovers the verifying key from three sources, in
    this order: (1) ORCA_DISPATCH_PUBKEY env, (2) the reviewed remote blob at origin/HEAD, (3) the
    working-tree file. Each test runs a COPY of the gate inside a hermetic temp git repo
    (_gate_repo), so the real repo's refs are never read or mutated. Behavior asserted, not argv:
    a record signed by the expected key verifies (exit 0 + 'signature verified') only if that
    source actually supplied it — otherwise verify.py fails closed.

    #267: the contract, the record and the keys all live INSIDE that repo under relative names, so
    `use_repo` swaps the case's repo for the gate-hosting one BEFORE any fixture is written."""

    def use_repo(self, **kw):
        """Replace this case's hermetic repo with a gate-hosting one, then return a pubkey the
        caller can pin into it. Two keys are minted up front because the pin has to be committed
        when the repo is built, before any fixture can be written into it."""
        pubs = [_mint_key() for _ in range(2)]
        repo = _gate_repo(**{k: (pubs[0] if v is True else v) for k, v in kw.items()})
        self.repo = repo
        self.addCleanup(shutil.rmtree, repo, True)
        return pubs

    def _run_discovered(self, src, dispatch_record, dispatch_pubkey=None):
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        return self.gate(m, src, self.digest(src), unit_class="report-only", event="task",
                         provenance="dispatch", dispatch_record=dispatch_record,
                         dispatch_pubkey=dispatch_pubkey,
                         gate=self.repo / "runtime" / "scripts" / "verify-gate.sh")

    def test_remote_blob_hit(self):
        # Pin committed on origin/main (refs/remotes/origin/HEAD resolves) but ABSENT from the
        # worktree AND from local HEAD (_gate_repo advances HEAD to a pinless commit) — only the
        # remote-blob read can supply the key. Reverting 933765a (dropping the blob read) or
        # reading HEAD instead of origin/HEAD turns this red.
        (pinned, _spare) = self.use_repo(pin_blob=True, remote_head=True)
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=pinned)
        r = self._run_discovered(src, rec)
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("signature verified", r.stdout + r.stderr)

    def test_an_origin_head_pointing_at_a_local_branch_never_names_the_key(self):
        # W3-02 (2026-10-27 security audit, P1): `symbolic-ref --short refs/remotes/origin/HEAD`
        # prints the TARGET's short name, so a worker that re-points origin/HEAD at its own LOCAL
        # branch had the gate read `.orca/dispatch-pubkey@workerbranch` — a key it committed
        # there — and its self-signed record verified, exit 0, on a lane claiming soundness.
        (coordinator, worker) = self.use_repo(pin_blob=True, remote_head=True)
        _git(self.repo, "checkout", "-q", "-b", "workerbranch")
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(worker[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "my key")
        os.remove(self.repo / ".orca" / "dispatch-pubkey")  # only a ref read can supply it now
        _git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/heads/workerbranch")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=worker)
        r = self._run_discovered(src, rec)
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("refs/heads/workerbranch", r.stderr,
                      "the gate must say which origin/HEAD target it refused")
        # The same repo, origin/HEAD back on the remote-tracking ref: the coordinator's key is
        # found there under its FULL name and its record verifies — the discovery still works.
        _git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        rec, _pub = self.sign(self.digest(src), "report-only", key=coordinator)
        r = self._run_discovered(src, rec)
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("signature verified", r.stdout + r.stderr)

    def test_the_discovered_key_ref_is_the_full_remote_tracking_name(self):
        # W3-02: a short name (`origin/main`) resolves through gitrevisions' lookup order, where a
        # local tag or branch named `origin/main` comes first; the full name cannot be shadowed.
        (pinned, _spare) = self.use_repo(pin_blob=True, remote_head=True)
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=pinned)
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_PROVENANCE": "dispatch",
               "ORCA_DISPATCH_RECORD": rec}
        r = subprocess.run(["sh", "-x", str(self.repo / "runtime" / "scripts" / "verify-gate.sh"),
                            "--event", "task"], capture_output=True, text=True, cwd=self.repo, env=env)
        self.assertIn("PUBKEY=.orca/dispatch-pubkey@refs/remotes/origin/main\n", r.stderr)

    def test_a_base_ref_that_is_a_symbolic_ref_to_a_local_branch_is_never_read(self):
        # PR #719 review (P1): refs/remotes/origin/<BASE> was trusted by SPELLING — made a
        # symbolic ref to the worker's local branch (which carries the worker's key), the gate
        # handed it to verify.py as a reviewed blob. Its final target must be remote-tracking.
        (_coordinator, worker) = self.use_repo(pin_blob=True, remote_head=False)
        _git(self.repo, "checkout", "-q", "-b", "workerbranch")
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(worker[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "my key")
        os.remove(self.repo / ".orca" / "dispatch-pubkey")
        _git(self.repo, "symbolic-ref", "refs/remotes/origin/integration", "refs/heads/workerbranch")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=worker)
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": _require_system_tools("git", "python3"), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_PROVENANCE": "dispatch",
               "ORCA_DISPATCH_RECORD": rec, "ORCA_BASE": "integration"}
        r = subprocess.run(["sh", "-x", str(self.repo / "runtime" / "scripts" / "verify-gate.sh"),
                            "--event", "task"], capture_output=True, text=True, cwd=self.repo,
                           env=env)
        self.assertNotIn("PUBKEY=.orca/dispatch-pubkey@", r.stderr)
        self.assertIn("refs/heads/workerbranch", r.stderr)
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 2, r.stderr[-600:])

    def _traced_gate(self, rec, src, **extra):
        """verify-gate.sh under `sh -x` on a sound lane, so the discovered PUBKEY is visible."""
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": _require_system_tools("git", "python3"), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_PROVENANCE": "dispatch",
               "ORCA_DISPATCH_RECORD": rec, **extra}
        return subprocess.run(["sh", "-x", str(self.repo / "runtime" / "scripts" / "verify-gate.sh"),
                               "--event", "task"], capture_output=True, text=True, cwd=self.repo,
                              env=env)

    def test_an_absent_remote_tracking_ref_never_reads_a_local_branch_of_that_spelling(self):
        # W3-07 class, Codex review (P1): with refs/remotes/origin/HEAD and …/main ABSENT,
        # `symbolic-ref` failed, the name kept its refs/remotes/ spelling, and `cat-file -e
        # refs/remotes/origin/HEAD:.orca/dispatch-pubkey` expanded it to the LOCAL branch
        # refs/heads/refs/remotes/origin/HEAD — the worker's key, handed to verify.py as a
        # reviewed blob. Every hop is now looked up by its exact name.
        (_coordinator, worker) = self.use_repo(pin_blob=True, remote_head=True)
        _git(self.repo, "checkout", "-q", "-b", "workerbranch")
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(worker[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "my key")
        os.remove(self.repo / ".orca" / "dispatch-pubkey")
        _git(self.repo, "update-ref", "-d", "refs/remotes/origin/HEAD")
        _git(self.repo, "update-ref", "-d", "refs/remotes/origin/main")
        for name in ("HEAD", "main"):
            _git(self.repo, "update-ref", f"refs/heads/refs/remotes/origin/{name}", "workerbranch")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=worker)
        r = self._traced_gate(rec, src, ORCA_BASE="main")
        self.assertNotIn("PUBKEY=.orca/dispatch-pubkey@", r.stderr)
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 2, r.stderr[-600:])

    def test_a_local_bridge_inside_the_origin_head_chain_never_names_the_key(self):
        # Codex review round 2 (P1): the listing's %(symref) is the chain's END, so origin/HEAD ->
        # refs/heads/bridge -> refs/remotes/origin/worker-pr (a fetched branch holding the
        # worker's key) read as remote-tracking all the way, and the gate handed that key on.
        (_coordinator, worker) = self.use_repo(pin_blob=True, remote_head=True)
        _git(self.repo, "checkout", "-q", "-b", "workerbranch")
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(worker[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "my key")
        os.remove(self.repo / ".orca" / "dispatch-pubkey")
        _git(self.repo, "update-ref", "refs/remotes/origin/worker-pr", "workerbranch")
        _git(self.repo, "symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/worker-pr")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=worker)
        # origin/HEAD -> bridge -> remote, then origin/HEAD -> origin/hop -> bridge -> remote
        for chain in ((("refs/remotes/origin/HEAD", "refs/heads/bridge"),),
                      (("refs/remotes/origin/hop", "refs/heads/bridge"),
                       ("refs/remotes/origin/HEAD", "refs/remotes/origin/hop"))):
            for link in chain:
                _git(self.repo, "symbolic-ref", *link)
            with self.subTest(chain=chain):
                r = self._traced_gate(rec, src)
                self.assertNotIn("PUBKEY=.orca/dispatch-pubkey@", r.stderr)
                self.assertIn("refs/heads/bridge", r.stderr)
                self.assertNotIn("signature verified", r.stdout + r.stderr)
                self.assertEqual(r.returncode, 2, r.stderr[-600:])

    def test_a_replacement_object_never_makes_a_key_appear_at_the_ref(self):
        # Independent re-attack (B), the gate's half: key discovery ran `cat-file -e
        # <ref>:.orca/dispatch-pubkey` under the ambient env, so `git replace <origin/main's
        # commit> <a commit carrying the worker's key>` made a pin appear that the reviewed
        # commit does not carry. Discovery now runs with replace objects and grafts off.
        (_unused, worker) = self.use_repo(remote_head=True)
        reviewed = _git_out(self.repo, "rev-parse", "refs/remotes/origin/main")
        _git(self.repo, "checkout", "-q", "-b", "workerbranch")
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(worker[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "my key")
        os.remove(self.repo / ".orca" / "dispatch-pubkey")
        _git(self.repo, "replace", reviewed, "workerbranch")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=worker)
        r = self._traced_gate(rec, src)
        self.assertNotIn("PUBKEY=.orca/dispatch-pubkey@", r.stderr)
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        self.assertEqual(r.returncode, 2, r.stderr[-600:])

    def test_a_base_with_a_revision_suffix_is_no_key_ref(self):
        # A key rotation retired the worker's key: origin/main's parent still pins it, and
        # ORCA_BASE=main~1 made refs/remotes/origin/main~1, which passed the refs/remotes/ case.
        (retired, current) = self.use_repo(pin_blob=True, remote_head=False)
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(current[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "rotate")
        os.remove(self.repo / ".orca" / "dispatch-pubkey")
        _git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=retired)
        for base in ("main~1", "main^", "main@{0}"):
            with self.subTest(base=base):
                r = self._traced_gate(rec, src, ORCA_BASE=base)
                self.assertNotIn("PUBKEY=.orca/dispatch-pubkey@", r.stderr)
                self.assertIn("not a valid ref name", r.stderr)
                self.assertNotIn("signature verified", r.stdout + r.stderr)
                self.assertEqual(r.returncode, 2, r.stderr[-600:])

    def test_a_bare_path_env_key_is_refused_on_a_lane_claiming_soundness(self):
        # W3-03: ORCA_DISPATCH_PUBKEY=.orca/dispatch-pubkey (a bare path) is the graded worker's
        # working tree; on a sound lane verify.py refuses it rather than verify against it.
        self.use_repo(remote_head=False)
        src = self.src(["AC-1"])
        rec, pub = self.sign(self.digest(src), "report-only")
        r = self._run_discovered(src, rec, dispatch_pubkey=pub)
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        self.assertIn("W3-03", r.stderr)

    def _ci_shaped(self):
        """A fresh actions/checkout tree: the base commit pins the coordinator's key, the PR head
        swaps the pin for the worker's, and there is no origin/HEAD and no origin/<base>."""
        (coordinator, worker) = self.use_repo(pin_blob=True, remote_head=False)
        base = _git_out(self.repo, "rev-parse", "HEAD")
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text(worker[1], encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "PR head")
        event = self.repo.parent / f"event-{next(_SRC_SEQ)}.json"
        event.write_text(json.dumps({"pull_request": {"base": {"sha": base, "ref": "main"}}}),
                         encoding="utf-8")
        self.addCleanup(event.unlink)
        return coordinator, worker, base, event

    def _run_ci(self, src, rec, event, trace=False):
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": _require_system_tools("git", "python3"), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_PROVENANCE": "ci",
               "ORCA_DISPATCH_RECORD": rec, "GITHUB_ACTIONS": "true",
               "GITHUB_EVENT_PATH": str(event)}
        argv = (["sh", "-x"] if trace else ["sh"]) + [
            str(self.repo / "runtime" / "scripts" / "verify-gate.sh"), "--event", "task"]
        return subprocess.run(argv, capture_output=True, text=True, cwd=self.repo, env=env)

    def test_a_ci_checkout_reads_the_key_at_the_pull_requests_base_commit(self):
        # W3-08 (2026-10-27 security audit, P2): a fresh CI checkout has neither origin/HEAD nor
        # origin/<base>, and the working-tree pin is refused on a sound lane, so EVERY signed
        # dispatch blocked as half-configured — the sound setup could not pass. The runner's own
        # event payload names the PR's base commit: the key is read there, at an immutable commit
        # id the PR cannot move, and never from the PR's tree (which here carries the worker's).
        coordinator, worker, base, event = self._ci_shaped()
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=coordinator)
        r = self._run_ci(src, rec, event, trace=True)
        self.assertIn(f"PUBKEY=.orca/dispatch-pubkey@{base}\n", r.stderr)
        r = self._run_ci(src, rec, event)
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("signature verified", r.stdout + r.stderr)
        # ...and the PR's own key, the one in its tree, still verifies nothing.
        rec, _pub = self.sign(self.digest(src), "report-only", key=worker)
        r = self._run_ci(src, rec, event)
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("signature INVALID", r.stderr)

    def test_worktree_fallback_is_refused_on_a_lane_claiming_soundness(self):
        # 2026-10-26 review: a CI-shaped clone has no refs/remotes/origin/HEAD, so the blob read
        # missed and the gate fell through to the WORKING TREE — the PR's own checkout, where a
        # worker swaps the pin for its key and self-signs the record. With ORCA_PROVENANCE set the
        # working-tree pin is now never read: the key stays undiscovered, verify.py sees a record
        # with no key and refuses as half-configured, and the gate says why.
        (pinned, _spare) = self.use_repo(pin_worktree=True, remote_head=False)
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=pinned)
        r = self._run_discovered(src, rec)
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("missing --dispatch-pubkey", r.stderr)
        self.assertIn("exists only in the working tree", r.stderr)

    def test_a_base_branch_blob_is_read_when_origin_head_is_absent(self):
        # The CI clone names the base branch it checks against: the pin committed there is a
        # reviewed blob, so it is read even with no origin/HEAD. Traced, because on a host whose
        # git is worker-writable the sound lane fails closed later for that reason alone.
        (pinned, _spare) = self.use_repo(pin_blob=True, remote_head=False)
        _git(self.repo, "update-ref", "refs/remotes/origin/integration", "HEAD")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=pinned)
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_PROVENANCE": "dispatch",
               "ORCA_DISPATCH_RECORD": rec, "ORCA_BASE": "integration"}
        r = subprocess.run(["sh", "-x", str(self.repo / "runtime" / "scripts" / "verify-gate.sh"),
                            "--event", "task"], capture_output=True, text=True, cwd=self.repo, env=env)
        self.assertIn("PUBKEY=.orca/dispatch-pubkey@refs/remotes/origin/integration", r.stderr)
        self.assertNotIn("+ PUBKEY=.orca/dispatch-pubkey\n", r.stderr)

    def test_the_native_lane_still_falls_back_to_the_worktree_pin(self):
        # Advisory lane (no provenance): the worktree pin is read, as documented — traced rather
        # than run to a verdict, since the enforcement lane it then enters fails closed on a host
        # whose git is worker-writable.
        (pinned, _spare) = self.use_repo(pin_worktree=True, remote_head=False)
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=pinned)
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_DISPATCH_RECORD": rec}
        r = subprocess.run(["sh", "-x", str(self.repo / "runtime" / "scripts" / "verify-gate.sh"),
                            "--event", "task"], capture_output=True, text=True, cwd=self.repo, env=env)
        self.assertIn("+ PUBKEY=.orca/dispatch-pubkey\n", r.stderr)

    def test_env_pubkey_precedes_repo_pin(self):
        # #198 review: env beats a present repo pin. A record signed by the env key verifies
        # even though origin/HEAD carries a *different* pin; a record signed by the pin key
        # fails — so a regression that ignores env and always reads the pin turns this red.
        (pinned, env_key) = self.use_repo(pin_blob=True, remote_head=True)
        src = self.src(["AC-1"])
        rec_env, pub_env = self.sign(self.digest(src), "report-only", key=env_key)
        rec_pin, _pub_pin = self.sign(self.digest(src), "report-only", key=pinned)
        pub_env = self.pinned(pub_env)  # W3-03: the sound lane reads an env key at a commit too
        r = self._run_discovered(src, rec_env, dispatch_pubkey=pub_env)
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("signature verified", r.stdout + r.stderr)
        r = self._run_discovered(src, rec_pin, dispatch_pubkey=pub_env)
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")

    def test_neither_present_proceeds_without_dispatch_check(self):
        # No remote ref, no worktree pin. The gate must pass NO --dispatch-pubkey, so verify.py
        # runs no dispatch check: a clean manifest passes; a signed record with no key anywhere
        # fails closed as HALF-CONFIGURED (missing --dispatch-pubkey) — proof the key stayed
        # undiscovered rather than silently read.
        self.use_repo(remote_head=False)
        src = self.src(["AC-1"])
        r = self._run_discovered(src, None)
        self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        rec, _pub = self.sign(self.digest(src), "report-only")
        r = self._run_discovered(src, rec)
        self.assertEqual(r.returncode, 2)
        self.assertIn("missing --dispatch-pubkey", r.stderr)


class PinDiscoveryReadsTheTargetRepo(GateCase):
    """Review P2: verify-gate.sh probed `$HERE/../..` — the PLUGIN root — for the pin, while
    verify.py reads the relative `.orca/dispatch-pubkey[@ref]` it is handed from the TARGET repo
    (the gate's cwd). Run from an installed plugin, the gate missed the target's own pin and
    could pick up the plugin's. Here the real gate (hosted in this checkout, which pins no key)
    runs inside a separate target repo that does."""

    def _target(self, remote_blob):
        secret, public = _mint_key()
        pin = self.repo / ".orca" / "dispatch-pubkey"
        pin.parent.mkdir(exist_ok=True)
        pin.write_text(public, encoding="utf-8")
        if remote_blob:
            _git(self.repo, "add", "-A")
            _git(self.repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "pin")
            _git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")
            _git(self.repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
            os.remove(pin)  # only the remote blob can supply it now
        return secret, public

    def _run(self, key):
        self.assertFalse((ROOT / ".orca" / "dispatch-pubkey").exists(),
                         "this checkout pins a key; the plugin-root probe would mask the bug")
        src = self.src(["AC-1"])
        rec, _pub = self.sign(self.digest(src), "report-only", key=key)
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        # The real GATE (plugin root = this checkout), cwd = the target, the host PATH: what is
        # asserted is WHICH key reached verify.py, and verify.py prints the signature NOTE on
        # every lane — whether the authority custody of this host then lets the run go green
        # is SoundLaneAuthoritiesAreSystemClass's question, not this one.
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": str(m),
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", "ORCA_DISPATCH_RECORD": rec}
        return subprocess.run([str(GATE), "--event", "task"], capture_output=True, text=True,
                              cwd=self.repo, env=env)

    def _assert_the_target_key_verified(self, r):
        out = r.stdout + r.stderr
        self.assertIn("signature verified", out, out)
        self.assertNotIn("missing --dispatch-pubkey", out, out)

    def test_the_target_repos_worktree_pin_is_found(self):
        self._assert_the_target_key_verified(self._run(self._target(remote_blob=False)))

    def test_the_target_repos_remote_blob_pin_is_found(self):
        self._assert_the_target_key_verified(self._run(self._target(remote_blob=True)))


class GateResolvesItsToolsOnce(GateCase):
    """Review P3: the gate ran bare `git` and `python3`, re-resolved on PATH at each use. It now
    resolves both ONCE to absolute paths, as verify.py pins its authorities."""

    def test_no_bare_git_or_python3_invocation_remains(self):
        bare = re.compile(r"(?:^|[;&|(!]|\$\(|\bif|\bthen|\belse|\bdo)\s*(?:git|python3)\s")
        hits = [line for line in GATE.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("#") and bare.search(line)]
        self.assertEqual(hits, [])

    def test_a_missing_python3_blocks_with_a_named_reason(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for tool in ("git", "dirname", "sh"):
            found = shutil.which(tool)
            if found:
                os.symlink(found, d / tool)
        m = self.repo / "m.json"
        m.write_text("{}", encoding="utf-8")
        r = subprocess.run([str(GATE)], capture_output=True, text=True, cwd=self.repo,
                           env={"PATH": str(d), "ORCA_MANIFEST": str(m)})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("python3 not on PATH", r.stderr)


class SoundLaneAuthoritiesAreSystemClass(GateCase):
    """h409 R-1 (review-r3): the round-3 fixture gave sound-lane gate runs a mkdtemp dir the
    effective user OWNED, hard-linked the host's git/gh/gitleaks into it and chmod'ed it 0555 —
    exactly the shape C-2 showed classes "system" under a mode-only probe, RED on a Linux temp
    layout, and a leak per run. The ruling: sound lanes run against the host's genuinely
    root-owned system dirs and SKIP with a named reason when a needed tool has no system-class
    instance; nothing is planted, linked or left behind."""

    def test_the_sound_lane_path_is_root_owned_system_dirs_only(self):
        path = _require_system_tools("git", "python3")
        dirs = path.split(os.pathsep)
        self.assertTrue(dirs)
        for d in dirs:
            self.assertIn(d, _SYSTEM_DIR_CANDIDATES)
            self.assertEqual(verify._Authority.classify(d), "system", d)
            for node in (Path(d), *Path(d).resolve().parents):
                self.assertNotEqual(os.stat(node).st_uid, os.geteuid(), f"{node} is the effective user's")
        self.assertEqual(verify._Authority.classify(shutil.which("git", path=path)), "system")

    def test_a_worker_owned_0555_dir_first_on_the_sound_lane_path_is_refused(self):
        # The round-3 fixture's shape, planted deliberately: a dir this user owns at 0555 holding
        # a git, FIRST on PATH. The sound lane must refuse it by name (C-2 through the gate), and
        # the dir goes back to 0755 before it is reaped — no hard link, nothing left behind.
        if os.geteuid() == 0:
            self.skipTest("running as root: ownership is not a boundary")
        system_git = shutil.which("git", path=_require_system_tools("git", "python3"))
        owned = Path(tempfile.mkdtemp(prefix="vgate-owned-", dir=Path.home()))
        self.addCleanup(shutil.rmtree, owned, True)
        self.addCleanup(os.chmod, owned, 0o755)  # cleanups run LIFO: chmod, then rmtree
        (owned / "git").write_text(f"#!/bin/sh\nexec {shlex.quote(system_git)} \"$@\"\n", encoding="utf-8")
        (owned / "git").chmod(0o555)
        owned.chmod(0o555)
        self.assertEqual(owned.stat().st_uid, os.geteuid())
        self.assertFalse(os.access(owned, os.W_OK))
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        r = self.gate(m, src, self.digest(src), unit_class="report-only", provenance="ci",
                      path_prefix=owned)
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn(f"authority: git at {owned / 'git'} is worker-writable", r.stderr)
        self.assertIn("h409 R2", r.stderr)


class SymlinkInstallGate(unittest.TestCase):
    """Issue #262: the recommended install path shipped no gate at all.

    `hooks/hooks.json` resolves through `${CLAUDE_PLUGIN_ROOT}`, which Claude Code
    sets only for plugin installs. `ln -s` into ~/.claude/skills/ loads no plugin,
    so those two hooks never fire and the missions run ungated — silently. The
    snippet is the fix; these tests keep it wired and keep the README saying so.
    """

    SNIPPET = ROOT / "hooks" / "settings-snippet.json"
    PRINTER = ROOT / "hooks" / "print-settings-snippet.sh"

    def test_plugin_hooks_still_resolve_through_the_plugin_root(self):
        data = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        commands = [
            h["command"]
            for event in data["hooks"].values()
            for matcher in event
            for h in matcher["hooks"]
        ]
        self.assertTrue(commands)
        for command in commands:
            self.assertIn("${CLAUDE_PLUGIN_ROOT}", command)

    def test_the_snippet_wires_the_same_two_events(self):
        plugin = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        snippet = json.loads(self.SNIPPET.read_text(encoding="utf-8"))
        self.assertEqual(sorted(snippet["hooks"]), sorted(plugin["hooks"]))
        for event, entries in snippet["hooks"].items():
            for matcher in entries:
                for hook in matcher["hooks"]:
                    self.assertIn("__OPEN_FLEET_ROOT__", hook["command"])
                    self.assertIn("verify-gate.sh", hook["command"])

    def test_the_printer_resolves_the_placeholder_to_a_real_script(self):
        r = subprocess.run(
            ["sh", str(self.PRINTER)], capture_output=True, text=True, cwd=str(ROOT)
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        emitted = json.loads(r.stdout)
        for event in emitted["hooks"].values():
            for matcher in event:
                for hook in matcher["hooks"]:
                    self.assertNotIn("__OPEN_FLEET_ROOT__", hook["command"])
                    script = hook["command"].split(" --event")[0]
                    self.assertTrue(Path(script).is_file(), script)

    def test_the_printer_check_mode_verifies_the_gate_script(self):
        r = subprocess.run(
            ["sh", str(self.PRINTER), "--check"], capture_output=True, text=True, cwd=str(ROOT)
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verify-gate.sh", r.stdout)

    def test_the_readme_says_a_symlink_install_has_no_gate(self):
        # The finding was that nothing told the user. A README that stops saying
        # so puts it back.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("print-settings-snippet.sh", readme)
        self.assertIn("no completion gate", readme)


class GateAliasesNeverOverrideSilently(GateCase):
    """2026-10-23 review, P3 (#614): verify-gate.sh read an OPEN_FLEET_* alias family that took
    precedence over every documented ORCA_* input unannounced — an inherited
    OPEN_FLEET_UNIT_CLASS downgraded the class the coordinator set as ORCA_UNIT_CLASS, and
    OPEN_FLEET_NO_GH added a review waiver. Either spelling still sets an input; two that
    disagree BLOCK."""

    ALIASES = (("OPEN_FLEET_GATE_MANIFEST", "ORCA_MANIFEST"), ("OPEN_FLEET_MANIFEST", "ORCA_MANIFEST"),
               ("OPEN_FLEET_CONTRACT_SOURCE", "ORCA_CONTRACT_SOURCE"),
               ("OPEN_FLEET_CONTRACT_DIGEST", "ORCA_CONTRACT_DIGEST"), ("OPEN_FLEET_REPO", "ORCA_REPO"),
               ("OPEN_FLEET_BASE", "ORCA_BASE"), ("OPEN_FLEET_SYMBOL", "ORCA_SYMBOL"),
               ("OPEN_FLEET_UNIT_CLASS", "ORCA_UNIT_CLASS"), ("OPEN_FLEET_NO_GH", "ORCA_NO_GH"),
               ("OPEN_FLEET_LIGHTING", "ORCA_LIGHTING"), ("OPEN_FLEET_UNIT_LANE", "ORCA_UNIT_LANE"),
               ("OPEN_FLEET_DISPATCH_RECORD", "ORCA_DISPATCH_RECORD"),
               ("OPEN_FLEET_DISPATCH_PUBKEY", "ORCA_DISPATCH_PUBKEY"),
               ("OPEN_FLEET_EXECUTE_NC", "ORCA_EXECUTE_NC"), ("OPEN_FLEET_NC_COMMAND", "ORCA_NC_COMMAND"),
               ("OPEN_FLEET_PROVENANCE", "ORCA_PROVENANCE"))

    def run_env(self, **env):
        return subprocess.run([str(GATE)], capture_output=True, text=True, cwd=self.repo,
                              env={"PATH": os.environ.get("PATH", ""), **env})

    def good_report(self):
        src = self.src(["AC-1"])
        return {"ORCA_MANIFEST": self.manifest(src, ["AC-1"], ["AC-1"]),
                "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src)}

    def test_an_alias_cannot_downgrade_the_coordinators_class(self):
        r = self.run_env(**self.good_report(), ORCA_UNIT_CLASS="mutation",
                         OPEN_FLEET_UNIT_CLASS="report-only")
        self.assertEqual(r.returncode, 2, f"stdout={r.stdout} stderr={r.stderr}")
        self.assertIn("disagree", r.stderr)
        self.assertNotIn("verify: OK", r.stdout)

    def test_every_pair_that_disagrees_blocks_before_the_verifier_runs(self):
        for alias, documented in self.ALIASES:
            with self.subTest(alias=alias):
                r = self.run_env(**{alias: "one", documented: "two"})
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn(f"{alias} and {documented}", r.stderr.replace("  ", " "))

    def test_either_spelling_alone_or_both_agreeing_is_honoured(self):
        base = self.good_report()
        for env in ({**base, "ORCA_UNIT_CLASS": "report-only"},
                    {**base, "OPEN_FLEET_UNIT_CLASS": "report-only"},
                    {**base, "ORCA_UNIT_CLASS": "report-only", "OPEN_FLEET_UNIT_CLASS": "report-only"},
                    {"OPEN_FLEET_GATE_MANIFEST": base["ORCA_MANIFEST"],
                     "ORCA_CONTRACT_SOURCE": base["ORCA_CONTRACT_SOURCE"],
                     "OPEN_FLEET_CONTRACT_DIGEST": base["ORCA_CONTRACT_DIGEST"],
                     "ORCA_UNIT_CLASS": "report-only"}):
            with self.subTest(env=sorted(env)):
                r = self.run_env(**env)
                self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class GateSwitchesAreValuesNotPresence(GateCase):
    """2026-10-26 review: ORCA_NO_GH / ORCA_EXECUTE_NC were read as "set" or "unset", so a
    coordinator template spelling the review waiver OFF as `false` switched it ON. A switch is now
    a value — on, off, or a refusal."""

    def _run(self, **switches):
        src = self.src(["AC-1"])
        m = self.manifest(src, ["AC-1"], ["AC-1"])
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": m,
               "ORCA_CONTRACT_SOURCE": src, "ORCA_CONTRACT_DIGEST": self.digest(src),
               "ORCA_UNIT_CLASS": "report-only", **switches}
        return subprocess.run(["sh", "-x", str(GATE), "--event", "task"], capture_output=True,
                              text=True, cwd=self.repo, env=env)

    def test_off_spellings_do_not_arm_the_waiver(self):
        for value in ("false", "0", "no", "off", "False", ""):
            with self.subTest(value=value):
                r = self._run(ORCA_NO_GH=value)
                self.assertNotIn("--no-gh", r.stderr.split("verify.py", 1)[-1][:400])
                self.assertEqual(r.returncode, 0, f"stdout={r.stdout} stderr={r.stderr[-800:]}")

    def test_on_spellings_arm_it(self):
        for value in ("1", "true", "yes", "on", "TRUE"):
            with self.subTest(value=value):
                r = self._run(ORCA_NO_GH=value)
                self.assertIn("--no-gh", r.stderr)

    def test_any_other_spelling_blocks_before_the_verifier_runs(self):
        for name, value in (("ORCA_NO_GH", "maybe"), ("ORCA_EXECUTE_NC", "2"),
                            ("OPEN_FLEET_NO_GH", "yess")):
            with self.subTest(name=name, value=value):
                r = self._run(**{name: value})
                self.assertEqual(r.returncode, 2, r.stderr[-400:])
                self.assertIn("is not a switch value", r.stderr)
                self.assertNotIn("verify.py --manifest", r.stderr)


class TheGateBoundsTheVerifierItself(GateCase):
    """2026-10-26 review: Claude Code cancels a command hook at its timeout and discards the
    output, and only exit 2 blocks a Stop or TaskCompleted — a verifier still running when the host
    gave up let the turn end. The gate now stops a verifier that runs past ORCA_GATE_TIMEOUT_S and
    blocks, and the hook files give the host a longer limit than that deadline."""

    def _slow_gate(self):
        scripts = Path(tempfile.mkdtemp(prefix="slow-gate-")) / "runtime" / "scripts"
        scripts.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, scripts.parent.parent, True)
        shutil.copy(GATE, scripts / "verify-gate.sh")
        (scripts / "verify.py").write_text("import time\ntime.sleep(30)\nprint('late PASS')\n",
                                           encoding="utf-8")
        return scripts / "verify-gate.sh"

    def test_a_verifier_past_the_deadline_is_stopped_and_the_gate_blocks(self):
        gate = self._slow_gate()
        m = Path(self.repo) / "m.json"
        m.write_text("{}", encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": str(m),
               "ORCA_GATE_TIMEOUT_S": "1"}
        started = time.monotonic()
        r = subprocess.run(["sh", str(gate), "--event", "task"], capture_output=True, text=True,
                           cwd=self.repo, env=env, timeout=60)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("ran past 1s", r.stderr)
        self.assertNotIn("late PASS", r.stdout)
        self.assertLess(time.monotonic() - started, 20)

    def test_a_bad_deadline_value_blocks(self):
        gate = self._slow_gate()
        m = Path(self.repo) / "m.json"
        m.write_text("{}", encoding="utf-8")
        for value in ("0", "soon", "-5"):
            with self.subTest(value=value):
                env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": str(m),
                       "ORCA_GATE_TIMEOUT_S": value}
                r = subprocess.run(["sh", str(gate), "--event", "task"], capture_output=True,
                                   text=True, cwd=self.repo, env=env, timeout=60)
                self.assertEqual(r.returncode, 2)
                self.assertIn("not a positive integer", r.stderr)

    def test_the_hook_files_give_the_host_a_limit_above_the_gates_deadline(self):
        gate_src = GATE.read_text(encoding="utf-8")
        default = int(re.search(r'GATE_TIMEOUT=(\d+)\n', gate_src).group(1))
        for name in ("hooks.json", "settings-snippet.json"):
            doc = json.loads((ROOT / "hooks" / name).read_text(encoding="utf-8"))
            for entries in doc["hooks"].values():
                for matcher in entries:
                    for hook in matcher["hooks"]:
                        self.assertGreater(hook["timeout"], default, name)
                        self.assertGreater(hook["timeout"], 600, "the host default fails open")


class TheGateRunsTheVerifierIsolated(GateCase):
    """W3-01 (2026-10-27 security audit, P0): the gate ran `python3 $HERE/verify.py`, so $HERE —
    the graded worktree's runtime/scripts — sat at sys.path[0] ahead of the stdlib, and a committed
    json.py there was the verifier's `json`. verify.py now drops that entry itself
    (tests/test_verify.py SiblingNamedLikeTheStdlibNeverLoads); the gate ALSO runs it under -I, so
    PYTHON* env and the user site stay out of the verdict too. Asserted from inside the verifier
    the gate starts — the flags it really ran under — and with a planted json.py beside it."""

    def test_the_verifier_runs_under_isolated_mode_and_a_planted_json_never_loads(self):
        scripts = Path(tempfile.mkdtemp(prefix="iso-gate-")) / "runtime" / "scripts"
        scripts.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, scripts.parent.parent, True)
        shutil.copy(GATE, scripts / "verify-gate.sh")
        (scripts / "verify.py").write_text(
            "import sys\nimport json\n"
            "print('isolated', sys.flags.isolated, 'json-from', json.__file__)\n",
            encoding="utf-8")
        (scripts / "json.py").write_text("raise SystemExit('PLANTED json loaded')\n",
                                         encoding="utf-8")
        m = Path(self.repo) / "m.json"
        m.write_text("{}", encoding="utf-8")
        env = {"PATH": os.environ.get("PATH", ""), "ORCA_MANIFEST": str(m)}
        r = subprocess.run(["sh", str(scripts / "verify-gate.sh"), "--event", "task"],
                           capture_output=True, text=True, cwd=self.repo, env=env, timeout=60)
        self.assertNotIn("PLANTED", r.stdout + r.stderr)
        self.assertIn("isolated 1", r.stdout, r.stderr)
        self.assertNotIn(str(scripts), r.stdout.split("json-from", 1)[-1])
        self.assertEqual(r.returncode, 0, r.stderr)


class TestVerifyGateCustodyAndBasePrefix(unittest.TestCase):
    """Regression pins for #766 (_hgit/_dgit hardened custody floor) and #788 (ORCA_BASE=origin/main
    does not probe refs/remotes/origin/origin/main)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="vgate-766-788-")
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "t@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "t"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "commit.gpgsign", "false"], check=True)
        (self.repo / ".orca").mkdir()
        (self.repo / ".orca" / "dispatch-pubkey").write_text("00" * 32 + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "pin"], check=True)
        head = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        subprocess.run(
            ["git", "-C", str(self.repo), "update-ref", "refs/remotes/origin/main", head],
            check=True,
        )
        # Drop origin/HEAD so key discovery MUST use KEY_BASE.
        subprocess.run(
            ["git", "-C", str(self.repo), "update-ref", "-d", "refs/remotes/origin/HEAD"],
            capture_output=True,
        )
        (self.repo / ".orca" / "dispatch-pubkey").unlink()
        self.scripts = Path(self._tmp.name) / "scripts"
        self.scripts.mkdir()
        shutil.copy2(GATE, self.scripts / "verify-gate.sh")
        (self.scripts / "verify.py").write_text(
            "import sys\nprint('ARGV:', ' '.join(sys.argv[1:]))\n", encoding="utf-8",
        )
        self.manifest = self.repo / "m.json"
        self.manifest.write_text("{}\n", encoding="utf-8")

    def test_origin_prefixed_and_full_remote_base_discover_pubkey(self):
        for base in ("origin/main", "refs/remotes/origin/main", "main"):
            with self.subTest(base=base):
                env = {
                    "PATH": os.environ.get("PATH", ""),
                    "ORCA_MANIFEST": str(self.manifest),
                    "ORCA_BASE": base,
                    "ORCA_PROVENANCE": "ci",
                }
                r = subprocess.run(
                    ["sh", str(self.scripts / "verify-gate.sh"), "--event", "task"],
                    cwd=str(self.repo), env=env, capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("--dispatch-pubkey .orca/dispatch-pubkey@refs/remotes/origin/main", r.stdout)

    def test_key_discovery_ignores_repo_fsmonitor_and_inherited_git_selectors(self):
        fired = self.repo / "fsmonitor-fired.txt"
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "core.fsmonitor", f"sh -c 'echo FIRED > {fired}; true'"],
            check=True,
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "ORCA_MANIFEST": str(self.manifest),
            "ORCA_BASE": "origin/main",
            "GIT_DIR": "/nonexistent/evil-git-dir",
            "GIT_CONFIG_PARAMETERS": f"'core.fsmonitor=sh -c \"echo FIRED > {fired}\"'",
            "GIT_EXTERNAL_DIFF": f"sh -c 'echo FIRED > {fired}'",
            "GIT_SSH_COMMAND": f"sh -c 'echo FIRED > {fired}'",
        }
        r = subprocess.run(
            ["sh", str(self.scripts / "verify-gate.sh"), "--event", "task"],
            cwd=str(self.repo), env=env, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("--dispatch-pubkey .orca/dispatch-pubkey@refs/remotes/origin/main", r.stdout)
        self.assertFalse(fired.exists(), "planted fsmonitor or inherited GIT_* channel fired during key discovery")
