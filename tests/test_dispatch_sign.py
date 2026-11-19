#!/usr/bin/env python3
"""In-repo key-write guard for dispatch-sign.py gen-key (#166).

The private dispatch seed must never be committable by accident: the repo's .gitignore must cover
`.secrets/`, and gen-key must refuse to write a seed at a path that resolves inside a git work tree
unless that path is git-ignored (or the caller explicitly overrides with --in-repo-ok).
"""
import base64
import contextlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "dispatch_sign", ROOT / "runtime" / "scripts" / "dispatch-sign.py")
dispatch_sign = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dispatch_sign)


def _toolchain_files() -> dict:
    """What verify.py writes into toolchain.files on THIS checkout — the set sign-transcript
    re-hashes against its own siblings (h409 O-2.4)."""
    import hashlib
    here = ROOT / "runtime" / "scripts"
    return {name: hashlib.sha256((here / name).read_bytes()).hexdigest()
            for name in dispatch_sign.TOOLCHAIN_FILES}


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True, capture_output=True)


def _gen_key(out: Path, extra=()):
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        rc = dispatch_sign.main(["gen-key", "--out", str(out), *extra])
    return rc, stderr.getvalue()


class GenKeyInRepoGuard(unittest.TestCase):
    def test_ignored_in_repo_path_works(self):
        # (a) an in-repo path covered by .gitignore is safe from `git add -A` — allowed.
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _git_init(repo)
            (repo / ".gitignore").write_text(".secrets/\n", encoding="utf-8")
            out = repo / ".secrets" / "dispatch-key"
            rc, _ = _gen_key(out)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())
            self.assertTrue(Path(str(out) + ".pub").exists())

    def test_non_ignored_in_repo_path_refused(self):
        # (b) an in-repo path git would happily stage is refused, with a loud stderr reason.
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _git_init(repo)
            out = repo / "dispatch-key"
            rc, err = _gen_key(out)
            self.assertNotEqual(rc, 0)
            self.assertIn("inside a git work tree", err)
            self.assertIn("--in-repo-ok", err)
            self.assertFalse(out.exists(), "refusal must happen before any bytes are written")

    def test_in_repo_override_flag_allows(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _git_init(repo)
            out = repo / "dispatch-key"
            rc, err = _gen_key(out, extra=["--in-repo-ok"])
            self.assertEqual(rc, 0, err)
            self.assertTrue(out.exists())

    def test_outside_repo_works(self):
        # (c) no git work tree in the ancestry — the recommended out-of-repo layout.
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "dispatch-key"
            rc, _ = _gen_key(out)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

    def test_check_ignore_error_fails_closed(self):
        # In a work tree with an inconclusive `git check-ignore`, gen-key must refuse —
        # an unknown ignore status is not proof of safety.
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _git_init(repo)
            out = repo / "dispatch-key"
            real_run = subprocess.run

            def fake_run(cmd, **kw):
                if "check-ignore" in cmd:
                    return subprocess.CompletedProcess(cmd, 128)
                return real_run(cmd, **kw)

            with unittest.mock.patch.object(dispatch_sign.subprocess, "run", side_effect=fake_run):
                rc, err = _gen_key(out)
            self.assertNotEqual(rc, 0)
            self.assertFalse(out.exists())

    def test_git_unavailable_fails_closed(self):
        # In a work tree without a usable git binary the ignore status is unverifiable — refuse.
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _git_init(repo)
            out = repo / "dispatch-key"
            with unittest.mock.patch.object(dispatch_sign.subprocess, "run",
                                            side_effect=OSError("git not found")):
                rc, _ = _gen_key(out)
            self.assertNotEqual(rc, 0)
            self.assertFalse(out.exists())

    def test_git_unavailable_out_of_repo_still_works(self):
        # No .git ancestor is PROOF of being outside any work tree — no git binary needed.
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "dispatch-key"
            with unittest.mock.patch.object(dispatch_sign.subprocess, "run",
                                            side_effect=OSError("git not found")):
                rc, _ = _gen_key(out)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

    def test_a_none_git_resolves_to_an_exec_failure_not_an_abort(self):
        # Greptile on #498: with git absent the OSError handlers ARE the git-less-operation
        # contract — an out-of-repo gen-key must still succeed, an in-repo one must still
        # refuse. Exercise the real subprocess with GIT=None (no subprocess mock): the argv
        # head must fail at EXEC as FileNotFoundError, never raise SystemExit while the
        # arguments are still being built.
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "dispatch-key"
            with unittest.mock.patch.object(dispatch_sign, "GIT", None):
                rc, _ = _gen_key(out)
            self.assertEqual(rc, 0)
            self.assertTrue(out.exists())

    def test_a_none_git_in_a_worktree_still_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            _git_init(repo)
            out = repo / "dispatch-key"
            with unittest.mock.patch.object(dispatch_sign, "GIT", None):
                rc, _ = _gen_key(out)
            self.assertNotEqual(rc, 0)
            self.assertFalse(out.exists())

    def test_external_git_dir_env_detected(self):
        # A repo resolved via GIT_DIR/core.worktree has no .git ancestor — refuse anyway.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as b:
            worktree = Path(d)
            bare = Path(b) / "repo.git"
            subprocess.run(["git", "init", "--bare", "-q", str(bare)],
                           check=True, capture_output=True)
            subprocess.run(["git", "--git-dir", str(bare), "config", "core.bare", "false"],
                           check=True, capture_output=True)
            subprocess.run(["git", "--git-dir", str(bare), "config", "core.worktree", d],
                           check=True, capture_output=True)
            out = worktree / "dispatch-key"
            with unittest.mock.patch.dict(os.environ, {"GIT_DIR": str(bare)}):
                rc, _ = _gen_key(out)
            self.assertNotEqual(rc, 0)
            self.assertFalse(out.exists())


class GenKeyFilePermissions(unittest.TestCase):
    """#163: the seed's 0o600 must hold from creation, not from a post-write chmod."""

    def test_seed_created_0600_under_zero_umask_without_chmod(self):
        # umask 0 maximizes the create-then-chmod window (0666); poisoning os.chmod pins that
        # the permission comes from os.open/fchmod, never a racy afterthought.
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "dispatch-key"
            old_umask = os.umask(0)
            try:
                with unittest.mock.patch.object(
                        dispatch_sign.os, "chmod",
                        side_effect=AssertionError("post-hoc chmod race window")):
                    rc, err = _gen_key(out)
            finally:
                os.umask(old_umask)
            self.assertEqual(rc, 0, err)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)

    def test_regeneration_tightens_preexisting_permissive_seed(self):
        # os.open's mode applies only at creation — an existing 0644 seed must still end 0600.
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "dispatch-key"
            out.write_text("stale\n", encoding="utf-8")
            os.chmod(out, 0o644)
            with unittest.mock.patch.object(
                    dispatch_sign.os, "chmod",
                    side_effect=AssertionError("post-hoc chmod race window")):
                rc, err = _gen_key(out)
            self.assertEqual(rc, 0, err)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)


class RepoGitignoreCoversSecrets(unittest.TestCase):
    def test_secrets_dir_is_ignored(self):
        rc = subprocess.run(["git", "check-ignore", ".secrets/dispatch-key"],
                            cwd=ROOT, capture_output=True).returncode
        self.assertEqual(rc, 0, ".gitignore must cover .secrets/ (#166)")

    def test_pub_files_not_ignored(self):
        # The pubkey is meant to be committed as .orca/dispatch-pubkey — never ignore it.
        for path in (".orca/dispatch-pubkey", ".secrets/dispatch-key.pub"):
            rc = subprocess.run(["git", "check-ignore", path],
                                cwd=ROOT, capture_output=True).returncode
            self.assertEqual(rc, 1, f"{path}: the dispatch pubkey must remain committable")


class TranscriptSigning(unittest.TestCase):
    """#281 / #386: the verifier's VERDICT is signed with the same scheme as the dispatch tuple.

    verify.py's verdict used to be stdout text plus an exit code — a worker can type any of it.
    `sign-transcript` wraps a verdict object in the {record, sig_b64} envelope `sign` already
    produces, over the same canonical form, with the same key files. No second scheme."""

    _RECORD = {"unit": "u1", "manifest": "docs/runs/r/manifest.json", "manifest_sha256": "ab" * 32,
               "args": {"unit_class": "mutation", "lighting": "lit"},
               "fatal": [], "notes": ["NOTE: x"], "exit": 0,
               # a verdict THIS toolchain produced: sign-transcript re-hashes the set (h409 O-2.4)
               "toolchain": {"python": "3.12.0", "files": _toolchain_files()},
               "timestamp": "2026-09-20T00:00:00+00:00"}

    def _ed(self):
        return dispatch_sign._load_ed25519()

    def test_canonical_transcript_is_field_bounded_and_order_free(self):
        # Only the transcript fields are signed, sorted, no whitespace — a worker-added key is not
        # part of the bytes, and the order a producer happened to emit is not a difference.
        canon = dispatch_sign.canonical_transcript(self._RECORD)
        self.assertEqual(canon, dispatch_sign.canonical_transcript(
            dict(reversed(list(self._RECORD.items())), extra="ignored")))
        self.assertNotIn(b"extra", canon)
        self.assertEqual(json.loads(canon.decode("utf-8")),
                         {k: self._RECORD[k] for k in dispatch_sign.TRANSCRIPT_FIELDS})
        self.assertEqual(set(dispatch_sign.TRANSCRIPT_FIELDS),
                         {"unit", "manifest", "manifest_sha256", "args", "fatal", "notes",
                          "exit", "toolchain", "timestamp"})

    def test_sign_transcript_cli_wraps_the_verdict_in_a_verifying_envelope(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            rc, err = _gen_key(key)
            self.assertEqual(rc, 0, err)
            transcript = Path(d) / "verdict.json"
            transcript.write_text(json.dumps(self._RECORD), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = dispatch_sign.main(["sign-transcript", "--key", str(key),
                                         "--transcript", str(transcript)])
            self.assertEqual(rc, 0)
            env = json.loads(out.getvalue())
            self.assertEqual(set(env), {"record", "sig_b64"})
            self.assertEqual(env["record"], self._RECORD)
            ed = self._ed()
            pub = bytes.fromhex(Path(str(key) + ".pub").read_text().strip())
            sig = base64.b64decode(env["sig_b64"])
            self.assertTrue(ed.checkvalid(sig, dispatch_sign.canonical_transcript(env["record"]), pub))
            # any byte of the record flipped -> the signature no longer verifies
            tampered = dict(env["record"], exit=2)
            self.assertFalse(ed.checkvalid(sig, dispatch_sign.canonical_transcript(tampered), pub))

    def test_sign_transcript_refuses_an_incomplete_verdict(self):
        # A verdict missing a signed field would sign an absence — refuse, rather than bind nothing.
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            _gen_key(key)
            transcript = Path(d) / "verdict.json"
            transcript.write_text(json.dumps({"unit": "u1", "exit": 0}), encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = dispatch_sign.main(["sign-transcript", "--key", str(key),
                                         "--transcript", str(transcript)])
            self.assertNotEqual(rc, 0)
            self.assertIn("manifest", err.getvalue())

    def test_sign_transcript_writes_to_out_when_asked(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            _gen_key(key)
            transcript = Path(d) / "verdict.json"
            transcript.write_text(json.dumps(self._RECORD), encoding="utf-8")
            target = Path(d) / "signed.json"
            rc = dispatch_sign.main(["sign-transcript", "--key", str(key),
                                     "--transcript", str(transcript), "--out", str(target)])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(target.read_text())["record"], self._RECORD)

    def test_the_lane_flags_are_signed_only_when_given(self):
        # Review P2: --no-gh / --lane / --execute-nc reach verify.py from argv/env, so the
        # coordinator can now sign them. Absent, the record is byte-identical to before.
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            key.write_text(bytes(range(1, 33)).hex() + "\n")
            os.chmod(key, 0o600)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = dispatch_sign.main(["sign", "--key", str(key), "--manifest-id", "u",
                                         "--contract-digest", "sha256:a", "--unit-class", "mutation",
                                         "--no-gh", "--lane", "B", "--execute-nc"])
            self.assertEqual(rc, 0, err.getvalue())
            env = json.loads(out.getvalue())
            self.assertEqual(env["record"], {"manifest_id": "u", "contract_digest": "sha256:a",
                                             "unit_class": "mutation", "no_gh": True, "lane": "B",
                                             "execute_nc": True})
            ed = self._ed()
            self.assertTrue(ed.checkvalid(base64.b64decode(env["sig_b64"]),
                                          dispatch_sign.canonical_record(env["record"]),
                                          ed.publickey(bytes(range(1, 33)))))
            self.assertIn("no_gh", dispatch_sign._RECORD_FIELDS)
            self.assertIn("lane", dispatch_sign._RECORD_FIELDS)
            self.assertIn("execute_nc", dispatch_sign._RECORD_FIELDS)

    def test_the_dispatch_envelope_is_untouched(self):
        # Reusing the envelope must not change what `sign` emits for a dispatch record.
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            key.write_text(bytes(range(1, 33)).hex() + "\n")
            os.chmod(key, 0o600)  # F-4: a signer refuses a seed any other reader can see
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = dispatch_sign.main(["sign", "--key", str(key), "--manifest-id", "u",
                                         "--contract-digest", "sha256:a", "--unit-class", "mutation"])
            self.assertEqual(rc, 0)
            env = json.loads(out.getvalue())
            self.assertEqual(env["record"], {"manifest_id": "u", "contract_digest": "sha256:a",
                                             "unit_class": "mutation"})
            ed = self._ed()
            self.assertTrue(ed.checkvalid(base64.b64decode(env["sig_b64"]),
                                          dispatch_sign.canonical_record(env["record"]),
                                          ed.publickey(bytes(range(1, 33)))))

class SeedCustodyAtUse(unittest.TestCase):
    """h409 F-4 (C3): custody was guarded at CREATION (gen-key refuses an unignored in-repo path
    and writes 0600) and never at USE — every signer read the seed bare, so a 0644 seed, or one
    committed to a repo, signed silently. At signing time the shared _seed re-asserts gen-key's
    discipline: mode with any group/other bit → refuse; inside an unignored git work tree →
    refuse; and a passing seed's custody class is named on stderr so the trail says what signed.
    The check is custody class, not existence — a 0600 seed outside any repo keeps working."""

    def _sign(self, key):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = dispatch_sign.main(["sign", "--key", str(key), "--manifest-id", "u",
                                     "--contract-digest", "sha256:a", "--unit-class", "mutation"])
        return rc, out.getvalue(), err.getvalue()

    def _sign_transcript(self, key, d):
        transcript = Path(d) / "verdict.json"
        transcript.write_text(json.dumps(TranscriptSigning._RECORD), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = dispatch_sign.main(["sign-transcript", "--key", str(key),
                                     "--transcript", str(transcript)])
        return rc, out.getvalue(), err.getvalue()

    def test_a_world_readable_seed_is_refused_by_both_signers(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            _gen_key(key)
            os.chmod(key, 0o644)
            for rc, out, err in (self._sign(key), self._sign_transcript(key, d)):
                self.assertEqual(rc, 1, err)
                self.assertEqual(out, "", "a refused seed must sign nothing")
                self.assertIn("custody", err)
                self.assertIn("0644", err)

    def test_a_seed_committed_in_an_unignored_work_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            repo.mkdir()
            _git_init(repo)
            key = repo / "committed-seed"
            _gen_key(key, extra=["--in-repo-ok"])  # creation was overridden; use must not be
            subprocess.run(["git", "add", "committed-seed"], cwd=repo, check=True, capture_output=True)
            for rc, out, err in (self._sign(key), self._sign_transcript(key, d)):
                self.assertEqual(rc, 1, err)
                self.assertEqual(out, "")
                self.assertIn("custody", err)
                self.assertIn("work tree", err)

    def test_a_0600_out_of_repo_seed_signs_and_names_its_custody_class(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            _gen_key(key)
            rc, out, err = self._sign(key)
            self.assertEqual(rc, 0, err)
            self.assertIn("sig_b64", out)
            self.assertIn("custody", err)
            self.assertIn("0600", err)

    def test_an_ignored_in_repo_0600_seed_signs(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"
            repo.mkdir()
            _git_init(repo)
            (repo / ".gitignore").write_text(".secrets/\n", encoding="utf-8")
            key = repo / ".secrets" / "dispatch-key"
            rc, err = _gen_key(key)
            self.assertEqual(rc, 0, err)
            rc, out, err = self._sign(key)
            self.assertEqual(rc, 0, err)
            self.assertIn("custody", err)


class SignTranscriptSignsOnlyItsOwnVerifiersVerdict(unittest.TestCase):
    """h409 O-2.4: `sign-transcript` checked SHAPE only (`record.get(k) is None`), so a hand-typed
    verdict — exit 0, fatal [], every toolchain hash 00…00 — signed and verified. After F-6 the
    offline signer is the seed-safe way to sign an executed-control verdict, so it now re-hashes
    `toolchain.files` against the scripts beside it and refuses a set that names another
    verifier, a partial set, or none. The maintainer signs only a verdict they produced."""

    def _sign(self, record):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            _gen_key(key)
            transcript = Path(d) / "verdict.json"
            transcript.write_text(json.dumps(record), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = dispatch_sign.main(["sign-transcript", "--key", str(key),
                                         "--transcript", str(transcript)])
            return rc, out.getvalue(), err.getvalue()

    def test_a_verdict_from_this_toolchain_signs(self):
        rc, out, err = self._sign(TranscriptSigning._RECORD)
        self.assertEqual(rc, 0, err)
        self.assertEqual(set(json.loads(out)), {"record", "sig_b64"})

    def test_the_reaudits_hand_typed_verdict_is_refused(self):
        # reaudit.md probe C: every hash 00…00, exit 0, fatal [] — it signed and verified.
        zeros = {name: "00" * 32 for name in dispatch_sign.TOOLCHAIN_FILES}
        rc, out, err = self._sign({**TranscriptSigning._RECORD,
                                   "toolchain": {"python": "3.12.0", "files": zeros}})
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("verify.py", err)
        self.assertIn("different verifier", err)
        self.assertIn("sign only a verdict object you produced", err)

    def test_one_substituted_sibling_is_refused(self):
        files = dict(_toolchain_files(), **{"ed25519.py": "ab" * 32})
        rc, _, err = self._sign({**TranscriptSigning._RECORD,
                                 "toolchain": {"python": "3.12.0", "files": files}})
        self.assertEqual(rc, 1)
        self.assertIn("ed25519.py", err)

    def test_a_partial_or_absent_file_set_is_refused(self):
        files = _toolchain_files()
        del files["diff_scope.py"]
        rc, _, err = self._sign({**TranscriptSigning._RECORD,
                                 "toolchain": {"python": "3.12.0", "files": files}})
        self.assertEqual(rc, 1)
        self.assertIn("diff_scope.py", err)
        rc, _, err = self._sign({**TranscriptSigning._RECORD, "toolchain": {"python": "3.12.0"}})
        self.assertEqual(rc, 1)
        self.assertIn("toolchain.files", err)

    def test_the_file_set_mirrors_the_verifiers(self):
        vspec = importlib.util.spec_from_file_location(
            "verify_for_toolchain", ROOT / "runtime" / "scripts" / "verify.py")
        verify = importlib.util.module_from_spec(vspec)
        vspec.loader.exec_module(verify)
        self.assertEqual(dispatch_sign.TOOLCHAIN_FILES, verify._Transcript.TOOLCHAIN)


class TestParentProfileFolding(unittest.TestCase):
    """G14: the parent bound is the MOST restrictive of the flag, the signed record, the
    inherited parent profile and the caller's own sandbox profile."""

    def check(self, profile, parent=None, env=None, *more):
        return dispatch_sign.check_profile_narrowing(profile, parent, env or {}, *more)

    def test_the_callers_sandbox_profile_bounds_the_child(self):
        for env in ({"OPEN_FLEET_SANDBOX_PROFILE": "ro"}, {"ORCA_SANDBOX_PROFILE": "ro"},
                    {"OPEN_FLEET_PARENT_PROFILE": "danger", "ORCA_PARENT_PROFILE": "ro"}):
            with self.subTest(env=env):
                ok, reason = self.check("rw", "danger", env)
                self.assertFalse(ok)
                self.assertIn("'ro'", reason)
                self.assertFalse(self.check("rw", None, env)[0], "omitting the flag must not widen")

    def test_a_signed_parent_cannot_be_widened_by_the_flag(self):
        self.assertFalse(self.check("rw", "danger", {}, "ro")[0])
        self.assertTrue(self.check("rw", "danger", {}, "rw")[0])

    def test_equal_or_narrower_passes_and_unknown_values_refuse(self):
        self.assertTrue(self.check("ro", "rw", {"OPEN_FLEET_SANDBOX_PROFILE": "ro"})[0])
        self.assertTrue(self.check("rw", None, {"OPEN_FLEET_SANDBOX_PROFILE": "rw"})[0])
        ok, reason = self.check("ro", None, {"ORCA_SANDBOX_PROFILE": "root"})
        self.assertFalse(ok)
        self.assertIn("invalid parent profile", reason)

    def test_sign_refuses_through_the_cli_with_exit_2(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("OPEN_FLEET_PARENT_PROFILE", "ORCA_PARENT_PROFILE", "ORCA_SANDBOX_PROFILE")}
        env.update(OPEN_FLEET_SANDBOX_PROFILE="ro", OPEN_FLEET_SIGNING_SEED="11" * 32)
        r = subprocess.run(["python3", str(ROOT / "runtime" / "scripts" / "dispatch-sign.py"), "sign",
                            "--manifest-id", "m-1", "--contract-digest", "a" * 64,
                            "--unit-class", "code", "--parent-profile", "danger", "--profile", "rw"],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("escalation refused", r.stderr)


class OneSignedFieldRule(unittest.TestCase):
    """2026-10-23 review, P2-2/P3 (#614): which fields a dispatch record is signed over was
    written three times (canonical_subset, envelope, verify.py) and the verifier's copy dropped
    the profile rule. signed_fields is the one rule; the envelope ships exactly the fields its
    signature covers, and verify.py verifies through canonical_record itself."""

    RECORD = {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation",
              "lighting": None, "nc_paths": ["b.py", "a.py"], "profile": "ro",
              "parent_profile": "rw", "unsigned_extra": "x"}

    def test_the_envelope_carries_exactly_the_signed_fields(self):
        env = dispatch_sign.envelope(bytes(range(32)), self.RECORD)
        self.assertEqual(set(env["record"]),
                         {k for k in dispatch_sign.signed_fields(self.RECORD)
                          if self.RECORD.get(k) is not None})
        self.assertEqual(set(env["record"]), set(dispatch_sign.canonical_subset(self.RECORD)))
        self.assertIn("profile", env["record"])
        self.assertNotIn("unsigned_extra", env["record"])

    def test_a_profile_free_record_keeps_its_exact_bytes(self):
        bare = {k: v for k, v in self.RECORD.items() if k not in dispatch_sign._PROFILE_FIELDS}
        self.assertEqual(dispatch_sign.signed_fields(bare), dispatch_sign._RECORD_FIELDS)
        self.assertNotIn(b"profile", dispatch_sign.canonical_record(bare))

    def test_the_verifier_verifies_over_the_signers_own_form(self):
        spec = importlib.util.spec_from_file_location(
            "verify_for_sign_parity", ROOT / "runtime" / "scripts" / "verify.py")
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        self.assertEqual(verify._canonical_dispatch(self.RECORD),
                         dispatch_sign.canonical_record(self.RECORD))


if __name__ == "__main__":
    unittest.main()


class BaseShaIsASignableDispatchInput(unittest.TestCase):
    """2026-10-26 review: the commit the executed negative control restores from is now a signable
    dispatch field, optional like the control's own inputs, so a coordinator that knows the fork
    point pins it and the gate refuses a manifest that moved it."""

    def test_sign_records_the_base_sha_when_given_and_omits_it_otherwise(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "dispatch-key"
            key.write_text(bytes(range(1, 33)).hex() + "\n")
            os.chmod(key, 0o600)
            for extra, want in ((["--base-sha", "f" * 40], {"base_sha": "f" * 40}), ([], {})):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = dispatch_sign.main(["sign", "--key", str(key), "--manifest-id", "u",
                                             "--contract-digest", "sha256:a", "--unit-class",
                                             "mutation", *extra])
                self.assertEqual(rc, 0, err.getvalue())
                record = json.loads(out.getvalue())["record"]
                self.assertEqual({k: v for k, v in record.items() if k == "base_sha"}, want)
        self.assertIn("base_sha", dispatch_sign._RECORD_FIELDS)


class VerifyDispatchProfileBinding(unittest.TestCase):
    """Regression pin for #784: verify_dispatch must bind --profile to the signed record's
    profile rather than letting --profile overwrite or widen an absent/narrower signed profile."""

    def test_verify_dispatch_refuses_mismatched_or_absent_signed_profile(self):
        seed = bytes(range(1, 33))
        pub = dispatch_sign._load_ed25519().publickey(seed).hex()
        ro_env = json.dumps(dispatch_sign.envelope(seed, {
            "manifest_id": "u1", "contract_digest": "sha256:abc",
            "unit_class": "mutation", "profile": "ro",
        }))
        no_prof_env = json.dumps(dispatch_sign.envelope(seed, {
            "manifest_id": "u1", "contract_digest": "sha256:abc",
            "unit_class": "mutation",
        }))
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            for k in dispatch_sign._PARENT_ENV:
                os.environ.pop(k, None)
            # Matching profile succeeds.
            self.assertEqual(dispatch_sign.verify_dispatch(ro_env, pubkey_ref=pub, profile="ro"), 0)
            # Escalation (--profile danger or rw against signed profile=ro) must fail closed.
            for bad in ("rw", "danger"):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    rc = dispatch_sign.verify_dispatch(ro_env, pubkey_ref=pub, profile=bad)
                self.assertEqual(rc, 2, bad)
                self.assertIn("does not match signed record profile", err.getvalue())
            # Requesting --profile when signed record omits profile must fail closed.
            with contextlib.redirect_stderr(io.StringIO()) as err:
                rc = dispatch_sign.verify_dispatch(no_prof_env, pubkey_ref=pub, profile="ro")
            self.assertEqual(rc, 2)
            self.assertIn("carries no profile", err.getvalue())
