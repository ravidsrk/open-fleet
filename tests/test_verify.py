#!/usr/bin/env python3
"""Negative-path tests for runtime/scripts/verify.py.

The verifier trusts NOTHING in the worker's manifest it can check against an authority: the
coordinator's frozen contract (scope) and dispatch-supplied unit class, GitHub (review), and the
artifact (negative control). Each check must fail closed.
"""
import base64
import contextlib
import errno
import hashlib
import importlib.util
import inspect
import io
import itertools
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

# Fetched branch names holding a line break (tests/fixtures/refname_breaks.py; W3-07 re-attack).
_rb_spec = importlib.util.spec_from_file_location(
    "refname_breaks", ROOT / "tests" / "fixtures" / "refname_breaks.py")
refname_breaks = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(refname_breaks)
_spec = importlib.util.spec_from_file_location("verify", ROOT / "runtime" / "scripts" / "verify.py")
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)


def _crit(*ids):
    return [{"id": i, "addressed": True} for i in ids]


_SRC_SEQ = itertools.count()


def _src(ids):
    """A frozen-contract fixture written into the CURRENT directory and named relatively — #267
    refuses absolute and out-of-repo evidence paths, so every fixture lives in the case's temp repo
    (all callers are RepoCase subclasses, which chdir there)."""
    rel = f"contract-{next(_SRC_SEQ)}.md"
    Path(rel).write_text("frozen\n" + "".join(f"- {i}: x\n" for i in ids), encoding="utf-8")
    return rel


def _digest(rel):
    # Mirrors the coordinator's `shasum -a 256` — raw bytes, no newline translation (#180).
    return "sha256:" + hashlib.sha256(Path(rel).read_bytes()).hexdigest()


def _temp_repo(suffix=None, prefix=None, dir=None):  # noqa: ANN001, ANN202 - test helper, stdlib passthrough
    """A throwaway temp dir for fixture git repos. ignore_cleanup_errors: the #340 teardown race —
    on Linux CI a late writer in the gitleaks-PATH leg can leave .git/ non-empty while rmtree runs
    (OSError 39; CI run 35074600535 hit a bare site after b726431 covered RepoCase only)."""
    return tempfile.TemporaryDirectory(suffix=suffix, prefix=prefix, dir=dir,
                                       ignore_cleanup_errors=True)


class RepoCase(unittest.TestCase):
    """#267 bounds every evidence path to the git toplevel and requires a manifest-named artifact to
    be PINNED, so fixtures live INSIDE a hermetic temp repo and are named relatively — which is also
    how a real manifest names them. The process cwd is the repo for the duration of the test, since
    verify.py's git legs and path resolution both run there."""

    def setUp(self):
        # ignore_cleanup_errors: on Linux CI, gitleaks-on-PATH can leave a file in
        # .git/objects while rmtree runs, and OSError 39 (Directory not empty)
        # failed the gitleaks step of validate (#340). The repo is throwaway.
        self._td = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.repo = Path(self._td.name).resolve()
        self.git("init", "-q", "-b", "main")
        self._cwd = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(self._leave)
        # h409 F-1: the review authority is process state pinned once per run. Every test is a
        # fresh run — a pin (or an inferred repo) left by the previous test is not its evidence.
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)

    def _leave(self):
        os.chdir(self._cwd)
        self._td.cleanup()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit(self, message="c"):
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", message)
        return self.git("rev-parse", "HEAD")

    def write(self, rel, text):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return rel

    def src(self, ids, rel="contract.md"):
        return self.write(rel, "frozen\n" + "".join(f"- {i}: x\n" for i in ids))

    def digest(self, rel):
        # Mirrors the coordinator's `shasum -a 256` — raw bytes, no newline translation (#180).
        return "sha256:" + hashlib.sha256((self.repo / rel).read_bytes()).hexdigest()

    def artifact(self, text, rel="docs/reports/u/nc.txt"):
        return self.write(rel, text)

    def pin(self, rel):
        """An `artifacts[]` inventory entry pinning an UNTRACKED working-tree artifact (#267)."""
        return {"path": rel, "sha256": hashlib.sha256((self.repo / rel).read_bytes()).hexdigest()}

    def seed_file(self, seed):
        """A coordinator seed the way gen-key leaves one: 0600, OUTSIDE any git work tree — the
        custody class every signer now re-asserts at use (h409 F-4). Returns its path (str)."""
        td = tempfile.TemporaryDirectory(prefix="orca-seed-")
        self.addCleanup(td.cleanup)
        path = Path(td.name) / "dispatch-key"
        path.write_text(seed.hex() + "\n", encoding="utf-8")
        path.chmod(0o600)
        return str(path)


class ScopeCheck(RepoCase):
    """The denominator is the coordinator's authoritative contract, not the manifest."""

    def _fatal(self, m, src, dig):
        return [e for e in verify.check_scope(m, src, dig) if not e.startswith("NOTE:")]

    def test_a_contract_hiding_criteria_is_refused_end_to_end(self):
        """#296 / A16, through check_scope rather than the helper alone.

        Testing hidden_criterion_ids() directly proves the function works and NOT that anything
        calls it — disabling the wiring in check_scope left the unit tests green. This one goes
        through the gate a unit actually meets.
        """
        rel = "contract.md"
        self.write(rel, "frozen\n- AC-1: sum\n| AC-2 | rejects None |\nAC-3 — total\n")
        m = {"contract": {"criterion_ids": ["AC-1"]}, "criteria": _crit("AC-1")}
        fatal = self._fatal(m, rel, self.digest(rel))
        self.assertTrue(any("in a form the extractor does not count" in e for e in fatal),
                        f"a contract hiding two of three criteria passed scope: {fatal}")

    def test_a_compact_id_hides_a_criterion_just_as_well(self):
        """PR #308 review, P1: A16 worked verbatim by dropping one character.

        `SC12` is a supported criterion shape, but the family prefix was read off the hyphen, so
        every compact id was skipped before any comparison — a contract counting `- SC12:` while
        hiding `| SC13 |` in a table row passed, though the hyphenated spelling was caught.
        """
        rel = "contract.md"
        self.write(rel, "frozen\n- SC12: sum\n| SC13 | rejects None |\n")
        m = {"contract": {"criterion_ids": ["SC12"]}, "criteria": _crit("SC12")}
        fatal = self._fatal(m, rel, self.digest(rel))
        self.assertTrue(any("SC13" in e for e in fatal),
                        f"a compact-id contract hiding half its criteria passed scope: {fatal}")

    def test_a_json_contract_is_not_text_scanned(self):
        """PR #308 review, P1: the escape hatch the refusal recommends has to work.

        A declared criterion_ids array IS the denominator — nothing is scraped out of prose, so
        prose cannot mislead it. Running the text heuristic over the raw JSON anyway rejected a
        valid contract for mentioning a superseded `AC-9`, and told its author to do the thing they
        had already done.
        """
        rel = "contract.json"
        self.write(rel, json.dumps({
            "criterion_ids": ["AC-1"],
            "notes": "supersedes AC-9 from the old spec",
            "criteria": [{"id": "AC-1", "text": "add(a, b) returns a + b"}],
        }, indent=2) + "\n")
        m = {"contract": {"criterion_ids": ["AC-1"]}, "criteria": _crit("AC-1")}
        fatal = self._fatal(m, rel, self.digest(rel))
        self.assertEqual(fatal, [], f"a valid JSON contract was refused: {fatal}")

    def test_a_json_contract_may_not_under_declare_its_own_criteria(self):
        # Skipping the text heuristic must not open A16 in JSON form. The check is structural —
        # the document's own criteria[] ids against its criterion_ids — not another scan.
        rel = "contract.json"
        self.write(rel, json.dumps({
            "criterion_ids": ["AC-1"],
            "criteria": [{"id": "AC-1", "text": "sum"}, {"id": "AC-2", "text": "rejects None"}],
        }, indent=2) + "\n")
        m = {"contract": {"criterion_ids": ["AC-1"]}, "criteria": _crit("AC-1")}
        fatal = self._fatal(m, rel, self.digest(rel))
        self.assertTrue(any("AC-2" in e and "criterion_ids" in e for e in fatal),
                        f"a JSON contract under-declaring its own criteria passed scope: {fatal}")

    def test_a_well_formed_contract_still_passes_scope(self):
        # The tightening must not refuse ordinary contracts, including prose references.
        rel = "contract.md"
        self.write(rel, "frozen\n- AC-1: sum per RFC-7519\n- AC-2: rejects None\n")
        m = {"contract": {"criterion_ids": ["AC-1", "AC-2"]},
             "criteria": _crit("AC-1") + _crit("AC-2")}
        fatal = self._fatal(m, rel, self.digest(rel))
        self.assertEqual(fatal, [], f"a well-formed contract was refused: {fatal}")

    def test_no_authoritative_contract_fails_closed(self):
        m = {"contract": {"criterion_ids": ["AC-1"]}, "criteria": _crit("AC-1")}
        self.assertTrue(any("no authoritative contract" in e for e in self._fatal(m, None, None)))

    def test_full_scope_passes(self):
        p = self.src(["AC-1"])
        m = {"contract": {"source": p, "digest": self.digest(p), "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1")}
        self.assertEqual(self._fatal(m, p, self.digest(p)), [])

    def test_scope_shrink_fails(self):
        p = _src(["AC-1", "AC-2"])
        m = {"contract": {"source": p, "digest": _digest(p), "criterion_ids": ["AC-1", "AC-2"]},
             "criteria": _crit("AC-1")}
        self.assertTrue(any("not addressed" in e or "scope shrunk" in e
                            for e in self._fatal(m, p, _digest(p))))

    def test_unaddressed_criterion_fails(self):
        # #111: a criterion present but addressed != true is unmet work, not a waiver.
        p = _src(["AC-1"])
        m = {"contract": {"source": p, "digest": _digest(p), "criterion_ids": ["AC-1"]},
             "criteria": [{"id": "AC-1", "addressed": False, "note": "I did NOT do this"}]}
        self.assertTrue(any("not addressed" in e for e in self._fatal(m, p, _digest(p))))

    def test_denominator_swap_fails(self):
        shrunk, full = _src(["AC-1"]), _src(["AC-1", "AC-2"])
        m = {"contract": {"source": shrunk, "digest": _digest(shrunk), "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1")}
        fatal = self._fatal(m, full, _digest(full))
        self.assertTrue(any("swap" in e or "not addressed" in e for e in fatal), fatal)

    def test_digest_mismatch_fails(self):
        p = _src(["AC-1"])
        m = {"contract": {"source": p, "criterion_ids": ["AC-1"]}, "criteria": _crit("AC-1")}
        self.assertTrue(any("does not match --contract-digest" in e
                            for e in self._fatal(m, p, "sha256:deadbeef")))


class UnitClassSelection(RepoCase):
    """#110: mutation-class comes from the dispatch, never the manifest; missing => mutation."""

    def test_is_mutation_fail_safe(self):
        self.assertTrue(verify._is_mutation(None))       # missing => mutation
        self.assertTrue(verify._is_mutation("mutation"))
        self.assertTrue(verify._is_mutation("garbage"))  # unknown => mutation
        self.assertFalse(verify._is_mutation("report-only"))
        self.assertFalse(verify._is_mutation("planning"))

    def test_manifest_unit_class_is_ignored(self):
        # #182: drive verify() itself — the selection point (is_mut = _is_mutation(unit_class),
        # the dispatch PARAMETER, never the manifest). A manifest self-declaring report-only,
        # verified with the dispatch parameter omitted (None => fail-safe) or explicit "mutation",
        # must get the mutation-strict verdict: missing pr.number, negative control, and intent
        # all fail. If verify() ever consulted m["unit_class"] this test goes red.
        p = _src(["AC-1"])
        m = {"unit": "slice-2", "unit_class": "report-only",
             "base_sha": "HEAD", "head_sha": "HEAD",
             "contract": {"source": p, "digest": _digest(p), "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1")}
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(m, fh)
        fh.close()
        for cls in (None, "mutation"):
            out, err = verify.verify(fh.name, p, _digest(p), repo="o/r", unit_class=cls)
            self.assertIsNone(err)
            fatal, _notes = out
            self.assertTrue(any("unreviewed" in e or "pr.number" in e for e in fatal),
                            (cls, fatal))
            self.assertTrue(any("negative_control" in e for e in fatal), (cls, fatal))
            self.assertTrue(any("intent" in e for e in fatal), (cls, fatal))

    def test_end_to_end_unclassified_manifest_fails_closed(self):
        # A doc-schema-conformant manifest (no pr/nc, no dispatch class) must be gated as mutation.
        p = _src(["AC-1"])
        m = {"unit": "slice-2", "base_sha": "HEAD", "head_sha": "HEAD",
             "contract": {"source": p, "digest": _digest(p), "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1")}
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(m, fh)
        fh.close()
        out, err = verify.verify(fh.name, p, _digest(p), repo="o/r", unit_class=None)
        self.assertIsNone(err)
        fatal, _notes = out
        self.assertTrue(fatal, "unclassified manifest must be gated as mutation and fail closed")

    def _write_manifest(self, m):
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(lambda: os.path.exists(fh.name) and os.unlink(fh.name))  # no leaks (#381)
        json.dump(m, fh)
        fh.close()
        return fh.name

    def _mutating_manifest(self):
        p = _src(["AC-1"])
        m = {"unit": "slice-2", "base_sha": "HEAD", "head_sha": "HEAD",
             "contract": {"source": p, "digest": _digest(p), "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1")}
        return p, self._write_manifest(m)

    def test_unknown_unit_class_notes_and_gates_as_mutation(self):
        # #178: an unknown class must reach _is_mutation's fallback — mutation-strict checks run
        # and a NOTE names the unknown value (docs/verify-gate.md: "missing/unknown => mutation").
        p, path = self._mutating_manifest()
        out, err = verify.verify(path, p, _digest(p), repo="o/r", unit_class="mutatoin")
        self.assertIsNone(err)
        fatal, notes = out
        self.assertTrue(any("NOTE:" in n and "mutatoin" in n for n in notes), notes)
        self.assertTrue(fatal, "unknown class must fail safe to mutation strictness")

    def test_unknown_unit_class_cli_is_not_a_usage_error(self):
        # #178: argparse choices= used to wedge the CLI before the fallback ran. main() must now
        # run the checks; the NOTE surfaces on stdout and fatals (not usage) decide the exit.
        p, path = self._mutating_manifest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = verify.main(["--manifest", path, "--contract-source", p,
                              "--contract-digest", _digest(p), "--unit-class", "mutatoin",
                              "--repo", "o/r"])
        self.assertEqual(rc, 2, "a mutation-invariant failure, not an argparse wedge")
        self.assertIn("mutatoin", buf.getvalue())

    def test_legal_unit_classes_emit_no_unknown_note(self):
        # Legal values behave exactly as before: no unknown-class NOTE.
        for cls in ("mutation", "report-only", "planning", None):
            p, path = self._mutating_manifest()
            out, err = verify.verify(path, p, _digest(p), repo="o/r", unit_class=cls)
            self.assertIsNone(err)
            _fatal, notes = out
            self.assertFalse(any("unknown unit class" in n for n in notes), (cls, notes))


class FreshnessCheck(unittest.TestCase):
    def test_stale_review_fails(self):
        self.assertTrue(any("stale review" in e for e in
                            verify.check_freshness({"head_sha": "a", "pr": {"reviewed_sha": "b"}})))

    def test_fresh_review_passes(self):
        self.assertEqual(verify.check_freshness({"head_sha": "a", "pr": {"reviewed_sha": "a"}}), [])

    def test_wtree_equivalence_relaxes_a_content_identical_head_move(self):
        # reviewed-sha-freshness.md: a head move whose tree is identical to the reviewed content
        # does not void the review. Build two commits with the same tree and check.
        import subprocess
        from pathlib import Path as P
        # _temp_repo: bare TemporaryDirectory hit the #340 teardown race here (OSError 39 on
        # .git, CI run 35074600535). Throwaway repo.
        with _temp_repo() as tmp:
            env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                   "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/bin"}
            def g(*a, cwd=tmp):
                return subprocess.run(["git", *a], cwd=cwd, env=env, capture_output=True, text=True)
            g("init", "-q"); P(tmp, "f.txt").write_text("same content")
            g("add", "."); g("commit", "-qm", "one")
            old_head = g("rev-parse", "HEAD").stdout.strip()
            tree = g("rev-parse", "HEAD^{tree}").stdout.strip()
            g("commit", "--amend", "-qm", "one amended")  # same tree, new SHA
            new_head = g("rev-parse", "HEAD").stdout.strip()
            self.assertNotEqual(old_head, new_head)  # a bare assert is stripped under python -O
            m = {"head_sha": new_head,
                 "pr": {"reviewed_sha": old_head, "reviewed_wtree": tree}}
            cwd = __import__("os").getcwd()
            __import__("os").chdir(tmp)
            try:
                self.assertEqual(verify.check_freshness(m), [])
                # a real content change still voids
                P(tmp, "f.txt").write_text("different")
                g("add", "."); g("commit", "-qm", "two")
                m2 = {"head_sha": g("rev-parse", "HEAD").stdout.strip(),
                      "pr": {"reviewed_sha": old_head, "reviewed_wtree": tree}}
                self.assertTrue(any("stale review" in e for e in verify.check_freshness(m2)))
            finally:
                __import__("os").chdir(cwd)

    def test_throwaway_repo_teardown_tolerates_a_late_writer(self):
        # The #340 teardown race, pinned deterministically: a writer landing files under
        # .git/ while the context manager tears the tree down raised OSError 39 (Directory
        # not empty) on Linux CI — b726431 covered RepoCase, CI run 35074600535 hit this
        # class's bare site. _temp_repo() must swallow that teardown noise.
        #
        # No threads: a threaded writer usually loses the race before its first write
        # (PR #456 review, P2 — a green threaded run proved nothing). Instead the test
        # reproduces the exact interleaving single-threaded: os.scandir is wrapped so the
        # first directory listing during teardown is exhausted FIRST and the late file is
        # planted only after — exhaust-then-plant, so the planted file can never be
        # observed by the listing on any platform (planting before iteration would race
        # getdents visibility: Linux typically shows the new entry, macOS typically does
        # not — PR #456 review round 2). Without the tolerance flag that file fails the
        # final rmdir with ENOTEMPTY; with it, teardown succeeds. Both directions are
        # asserted, so the test also re-arms itself if the flag is ever reverted.
        from unittest import mock

        class _FrozenListing:
            # The exhausted entries behind the iterator protocol rmtree needs:
            # 3.13's safe-fd lane holds `with os.scandir(fd) as it`, older lanes
            # just iterate. Entries stay real DirEntry objects.
            def __init__(self, entries):
                self._entries = entries

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def __iter__(self):
                return iter(self._entries)

        def run_teardown(make_dir):
            planted = []
            real_scandir = os.scandir

            def planting_scandir(path):
                iterator = real_scandir(path)
                if planted:
                    return iterator
                entries = list(iterator)
                try:
                    if isinstance(path, int):
                        # 3.13+ safe-fd rmtree lists by dir fd: plant fd-relative.
                        fd = os.open("late.tmp", os.O_CREAT | os.O_WRONLY,
                                     dir_fd=path)
                        os.close(fd)
                        planted.append(f"fd:{path}")
                    else:
                        candidate = Path(os.fspath(path), "late.tmp")
                        if candidate.parent.is_dir():
                            candidate.write_bytes(b"x")
                            planted.append(str(candidate))
                except OSError:
                    pass
                return _FrozenListing(entries)

            with mock.patch.object(os, "scandir", planting_scandir):
                with make_dir() as repo:
                    Path(repo, ".git", "objects").mkdir(parents=True)
            return planted

        # Green: our helper tolerates the late file.
        planted = run_teardown(_temp_repo)
        self.assertTrue(planted, "injection never fired — teardown went untested")
        # Red control: without the tolerance flag the same injection fails the
        # final rmdir with ENOTEMPTY (39 Linux, 66 macOS) — proving the
        # injection models the race.
        with self.assertRaises(OSError) as red:
            run_teardown(lambda: tempfile.TemporaryDirectory(ignore_cleanup_errors=False))
        self.assertEqual(red.exception.errno, errno.ENOTEMPTY, red.exception)


class ReviewCheck(unittest.TestCase):
    def test_a_standing_changes_requested_blocks_a_second_reviewers_approval(self):
        # #317: latest-per-reviewer, then "any non-author APPROVED at head wins" meant a blocking
        # review at the SAME head was overridden by a second approval with nothing recorded. For a
        # definition-of-done oracle that is the wrong default: a reviewer saying "not done" about
        # this exact content is evidence, and a second opinion does not erase it.
        reviews = [{"state": "CHANGES_REQUESTED", "commit_id": "H", "user": {"login": "bob"}},
                   {"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H", "user": {"login": "carol"}}]
        self.assertFalse(verify.review_ok(reviews, "H", author="alice"))

    def test_a_superseded_changes_requested_does_not_block(self):
        # The same reviewer came back and approved — latest-per-reviewer already handles it, and
        # the block must not resurrect a state its author withdrew.
        reviews = [{"state": "CHANGES_REQUESTED", "commit_id": "H", "user": {"login": "bob"}},
                   {"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H", "user": {"login": "bob"}}]
        self.assertTrue(verify.review_ok(reviews, "H", author="alice"))

    def test_a_changes_requested_at_an_older_head_does_not_block(self):
        # The block is about THIS content. A request against a head the author has since moved
        # past is not a standing objection to what is being graded.
        reviews = [{"state": "CHANGES_REQUESTED", "commit_id": "OLD", "user": {"login": "bob"}},
                   {"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H", "user": {"login": "carol"}}]
        self.assertTrue(verify.review_ok(reviews, "H", author="alice"))

    def test_review_ok_pure(self):
        self.assertTrue(verify.review_ok([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H"}], "H"))
        self.assertFalse(verify.review_ok([{"state": "COMMENTED", "commit_id": "H"}], "H"))
        self.assertFalse(verify.review_ok([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "OLD"}], "H"))

    def test_an_approval_needs_standing_in_the_repository(self):
        # Review P2: "any login that is not the PR author" let a throwaway account approve.
        # Only OWNER/MEMBER/COLLABORATOR approvals count; a missing association is no standing.
        self.assertEqual(verify._Authority.INDEPENDENT_REVIEWER_ASSOCIATIONS,
                         frozenset({"OWNER", "MEMBER", "COLLABORATOR"}))
        for assoc in ("OWNER", "MEMBER", "COLLABORATOR"):
            with self.subTest(assoc=assoc):
                self.assertTrue(verify.review_ok([{"state": "APPROVED", "commit_id": "H",
                                                   "author_association": assoc,
                                                   "user": {"login": "carol"}}], "H", author="alice"))
        for assoc in ("CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN",
                      "NONE", None, "member"):
            with self.subTest(assoc=assoc):
                review = {"state": "APPROVED", "commit_id": "H", "user": {"login": "mallory"}}
                if assoc is not None:
                    review["author_association"] = assoc
                self.assertFalse(verify.review_ok([review], "H", author="alice"))

    def test_the_author_is_excluded_whatever_their_association(self):
        self.assertFalse(verify.review_ok([{"state": "APPROVED", "commit_id": "H",
                                            "author_association": "OWNER",
                                            "user": {"login": "alice"}}], "H", author="alice"))

    def test_an_objection_from_an_account_without_standing_still_vetoes(self):
        # Refusing on an objection is the fail-closed direction; standing gates approvals only.
        reviews = [{"state": "CHANGES_REQUESTED", "commit_id": "H", "author_association": "NONE",
                    "user": {"login": "mallory"}},
                   {"state": "APPROVED", "commit_id": "H", "author_association": "MEMBER",
                    "user": {"login": "carol"}}]
        self.assertFalse(verify.review_ok(reviews, "H", author="alice"))

    def test_mutation_without_pr_number_fails_closed(self):
        m = {"unit": "ship-it", "head_sha": "H"}
        self.assertTrue(any("unreviewed" in e or "pr.number" in e
                            for e in verify.check_review(m, "o/r", True)))

    def test_report_only_skips_review(self):
        self.assertEqual(verify.check_review({"unit": "review-it"}, "o/r", False), [])


class NegativeControlCheck(RepoCase):
    def _m(self, text, **nc):
        """A manifest whose NC artifact is written in-repo and PINNED by artifacts[] (#267)."""
        rel = self.artifact(text)
        return {"unit": "ship-it", "artifacts": [self.pin(rel)],
                "negative_control": {"artifact": rel, **nc}}

    def _errs(self, m, execute=False):
        errs, _executed = verify.check_negative_control(m, True, execute=execute)
        return errs

    def test_missing_nc_fails(self):
        self.assertTrue(any("negative_control" in e for e in self._errs({"unit": "ship-it"})))

    def test_arbitrary_strings_fail(self):
        m = {"unit": "ship-it", "negative_control": {"tool": "x", "result": "y"}}
        self.assertTrue(any("negative_control" in e for e in self._errs(m)))

    def test_uncorroborating_artifact_fails(self):
        m = self._m("nothing to see here\n", tool="mutmut", mutant="m#7", result="KILLED")
        self.assertTrue(any("artifact does not" in e for e in self._errs(m)))

    def test_corroborating_artifact_passes(self):
        m = self._m("mutant m#7 was KILLED\n", tool="mutmut", mutant="m#7", result="KILLED")
        self.assertEqual(self._errs(m), [])

    def test_negation_artifact_fails(self):
        m = self._m("mutant m#7 SURVIVED — it was NOT killed\n",
                    tool="mutmut", mutant="m#7", result="KILLED")
        self.assertTrue(any("SURVIVED" in e for e in self._errs(m)))

    def test_a_negated_result_narration_fails(self):
        # PR #387 review: "the mutant was NOT killed" satisfied the bare killed/red keyword
        # scan until the #382 guard; revert the guard and this test is the only witness.
        m = self._m("mutant m#7 was KILLED\n", tool="mutmut", mutant="m#7",
                    result="the mutant was NOT killed")
        self.assertTrue(any("negates the kill" in e for e in self._errs(m)))

    def test_an_unparseable_nc_command_fails_closed_on_the_plain_lane(self):
        # PR #387 security review: an empty or unparseable --nc-command silently skipped the
        # named-command gate (want_cmd = None → pass). Now it must refuse.
        self.write("app.py", "x = 1\n")
        head = self.commit("c")
        rel = self.artifact("mutant m#7 was KILLED\n")
        m = {"unit": "u", "base_sha": head, "head_sha": head,
             "artifacts": [self.pin(rel)],
             "negative_control": {"tool": "revert", "result": "RED — mutant KILLED",
                                  "artifact": rel, "command": "true"},
             "commands": [{"cmd": "true", "exit": 0,
                           "wtree": self.git("rev-parse", "HEAD^{tree}")}]}
        for bad in ("", "pytest -k 'flaky"):
            with self.subTest(nc_command=bad):
                errs = verify.check_commands(m, True, nc_command=bad)
                self.assertTrue(any("no usable proof command" in e for e in errs), errs)

    def test_execute_nc_fails_closed_for_an_unreplayable_tool(self):
        # #255: replay exists for `revert` and `hand`. Every other tool under --execute-nc must
        # fail CLOSED — an unreplayable control is not an executed one, and a caller that ASKED
        # for execution must never get a pass built on a text read.
        m = self._m("mutant m#7 was KILLED\n", tool="mutmut", mutant="m#7", result="KILLED")
        errs, executed = verify.check_negative_control(m, True, execute=True)
        self.assertFalse(executed)
        self.assertTrue(any("no replay is implemented" in e for e in errs), errs)

    def test_report_only_unit_skips_nc(self):
        self.assertEqual(verify.check_negative_control({"unit": "review-it"}, False), ([], False))

    def test_hand_nc_without_quoted_diff_fails(self):
        # `hand` carries no pinned mutant id, so an artifact without the diff is unbound evidence.
        m = self._m("the suite went RED\n", tool="hand", result="RED")
        self.assertTrue(any("hand-written diff" in e for e in self._errs(m)))

    def test_hand_nc_with_quoted_diff_passes(self):
        m = self._m("--- a/x.py\n+++ b/x.py\n-old\n+new\nthe suite went RED\n",
                    tool="hand", result="RED")
        self.assertEqual(self._errs(m), [])

    def test_unpinned_working_tree_artifact_is_refused(self):
        # #267: present on disk, inside the repo, but neither tracked at head_sha nor carrying a
        # sha256 in artifacts[] — a file that can be rewritten between the run and the audit.
        rel = self.artifact("mutant m#7 was KILLED\n")
        m = {"unit": "ship-it", "negative_control": {
            "tool": "mutmut", "mutant": "m#7", "result": "KILLED", "artifact": rel}}
        self.assertTrue(any("unpinned evidence" in e for e in self._errs(m)))

    def test_pinned_hash_mismatch_is_refused(self):
        # #267: the artifact changed after it was inventoried — tamper-evident, as promised.
        m = self._m("mutant m#7 was KILLED\n", tool="mutmut", mutant="m#7", result="KILLED")
        self.artifact("mutant m#7 was KILLED (rewritten after the inventory)\n")
        self.assertTrue(any("artifacts[] pins" in e for e in self._errs(m)))

    def test_artifact_tracked_at_head_needs_no_inventory_entry(self):
        # #267's other leg: a committed artifact is immutable at head_sha, so the blob AT THAT
        # COMMIT is read and no artifacts[] hash is required.
        rel = self.artifact("mutant m#7 was KILLED\n")
        head = self.commit("evidence")
        m = {"unit": "ship-it", "head_sha": head, "negative_control": {
            "tool": "mutmut", "mutant": "m#7", "result": "KILLED", "artifact": rel}}
        self.assertEqual(self._errs(m), [])

    def test_absolute_artifact_path_is_refused(self):
        # docs/reviews/2026-09-10-review.md A10: the artifact walked out of the repo entirely.
        outside = Path(tempfile.mkdtemp()) / "nc.txt"
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        outside.write_text("killed m#7\n", encoding="utf-8")
        m = {"unit": "ship-it", "negative_control": {
            "tool": "mutmut", "mutant": "m#7", "result": "KILLED", "artifact": str(outside)}}
        self.assertTrue(any("absolute evidence path refused" in e for e in self._errs(m)))


    def test_escaping_relative_artifact_path_is_refused(self):
        m = {"unit": "ship-it", "negative_control": {
            "tool": "mutmut", "mutant": "m#7", "result": "KILLED",
            "artifact": "../outside/nc.txt"}}
        self.assertTrue(any("escapes the repo toplevel" in e for e in self._errs(m)))


class NegativeControlExecutorLegs(RepoCase):
    """#381: the executor's failure legs (worktree-add failure, no-op control, timeout,
    clean-phase nonzero) had no coverage — the paths most likely to matter in production."""

    PROOF = f"{sys.executable} -m unittest test_mod"

    def _manifest(self):
        self.write("app.py", "def add(a, b):\n    return a - b  # the defect\n")
        base = self.commit("base")
        self.write("app.py", "def add(a, b):\n    return a + b  # the fix\n")
        head = self.commit("fix")
        rel = self.artifact("reverted; the suite went RED (mutant KILLED)\n")
        return {"unit": "u", "base_sha": base, "head_sha": head,
                "artifacts": [self.pin(rel)],
                "negative_control": {"tool": "revert", "result": "RED — mutant KILLED",
                                     "artifact": rel, "command": self.PROOF, "paths": ["app.py"]}}

    def _run_with(self, proof_effects, apply_control=None):
        """Real worktrees and a real seal; only the PROOF command's results are scripted, in
        phase order clean -> control -> clean (review P1)."""
        m = self._manifest()
        effects, original = list(proof_effects), verify._run_at

        def fake(wt, argv, **kw):
            if argv == shlex.split(self.PROOF):
                return effects.pop(0)
            return original(wt, argv, **kw)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(verify, "_run_at", side_effect=fake))
            if apply_control is not None:
                stack.enter_context(mock.patch.object(verify, "_apply_control",
                                                      side_effect=apply_control))
            return verify.execute_negative_control(m, self.PROOF)

    def test_a_worktree_that_cannot_be_made_fails_closed(self):
        m = self._manifest()

        def fake_run(args, **kw):
            if "add" in args:
                return (1, "", "fatal: worktree add exploded")
            return (0, "", "")
        with mock.patch.object(verify, "_run", side_effect=fake_run):
            ok, msgs = verify.execute_negative_control(m, self.PROOF)
        self.assertFalse(ok)
        self.assertTrue(any("could not create the control worktree" in x for x in msgs), msgs)

    def test_a_control_that_changes_nothing_is_no_proof(self):
        # The applied tree equals head_sha's tree: a no-op mutant cannot make any proof go RED.
        # Judged by TREES now that the control is sealed into a commit, never by dirty status.
        ok, msgs = self._run_with([], apply_control=lambda *a, **k: None)
        self.assertFalse(ok)
        self.assertTrue(any("changed NOTHING" in x for x in msgs), msgs)

    def test_a_control_that_only_leaves_untracked_residue_changed_nothing(self):
        # An untracked file is not in the sealed tree, so it is not a control either.
        def residue(wt, *a, **k):
            (Path(wt) / "residue.txt").write_text("x\n")
        ok, msgs = self._run_with([], apply_control=residue)
        self.assertFalse(ok)
        self.assertTrue(any("changed NOTHING" in x for x in msgs), msgs)

    def test_a_control_run_that_times_out_is_not_a_kill(self):
        ok, msgs = self._run_with([(0, "", ""), (124, "", "timed out")])
        self.assertFalse(ok)
        self.assertTrue(any("did not complete under the control" in x for x in msgs), msgs)

    def test_a_command_red_at_clean_head_proves_nothing(self):
        effects = [
            (1, "", "FAILED (failures=1)\n"),          # clean phase: RED — the suite is broken
        ]
        ok, msgs = self._run_with(effects)
        self.assertFalse(ok)
        self.assertTrue(any("at CLEAN head_sha (before the control run)" in x for x in msgs), msgs)

    def test_a_command_red_only_after_the_control_run_proves_nothing(self):
        effects = [
            (0, "", ""),                               # clean phase: green
            (1, "", "FAILED (failures=1)\n"),          # control phase: RED with an oracle failing
            (1, "", "FAILED (failures=1)\n"),          # clean again: RED — a side effect, not a kill
        ]
        ok, msgs = self._run_with(effects)
        self.assertFalse(ok)
        self.assertTrue(any("at CLEAN head_sha (after the control run)" in x for x in msgs), msgs)


class ControlPhasesAreIndistinguishable(RepoCase):
    """Review P1: the executed control was PHASE-DISTINGUISHABLE. The control ran first, every
    phase shared the verifier's HOME and TMPDIR, and the control worktree was always dirty — so a
    "proof" that tested the phase instead of the behaviour (`git status` is empty; no marker in
    ~ or $TMPDIR yet) went RED under the control only, and was graded a kill. Each phase now gets
    a fresh HOME and TMPDIR, the mutant is sealed into a throwaway commit so every tree is clean,
    and clean runs bracket the control run. None of these proofs looks at app.py at all."""

    def _unit(self, proof):
        self.write("app.py", "VALUE = 1\n")
        self.write("proof.py", proof)
        base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        head = self.commit("head")
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        return verify.execute_negative_control(m, cmd)

    def _assert_not_a_kill(self, ok, msgs):
        self.assertFalse(ok, msgs)
        self.assertFalse(any("negative control EXECUTED" in x for x in msgs), msgs)

    def test_a_proof_that_asserts_a_clean_git_status_is_not_killed(self):
        ok, msgs = self._unit(
            "import subprocess\n"
            "out = subprocess.run(['git', 'status', '--porcelain'], capture_output=True,"
            " text=True).stdout\n"
            "assert out == '', 'dirty tree: ' + out\n")
        self._assert_not_a_kill(ok, msgs)
        self.assertTrue(any("TAUTOLOGICAL" in x for x in msgs), msgs)

    def test_a_first_run_marker_in_home_is_not_a_kill(self):
        ok, msgs = self._unit(
            "import os, pathlib\n"
            "marker = pathlib.Path(os.environ['HOME']) / '.orca-phase-marker'\n"
            "seen = marker.exists()\n"
            "marker.write_text('x')\n"
            "assert seen, 'first run in this HOME'\n")
        self._assert_not_a_kill(ok, msgs)

    def test_a_first_run_marker_in_tmpdir_is_not_a_kill(self):
        ok, msgs = self._unit(
            "import pathlib, tempfile\n"
            "marker = pathlib.Path(tempfile.gettempdir()) / 'orca-phase-marker'\n"
            "seen = marker.exists()\n"
            "marker.write_text('x')\n"
            "assert seen, 'first run in this TMPDIR'\n")
        self._assert_not_a_kill(ok, msgs)

    def test_a_marker_in_the_phase_git_dir_is_not_a_kill(self):
        # Each phase is its own repository. A marker in that repo's git dir starts absent
        # every time, so a proof that fails only when the marker is already there stays green
        # under the control.
        ok, msgs = self._unit(
            "import pathlib, subprocess\n"
            "common = subprocess.run(['git', 'rev-parse', '--git-common-dir'], capture_output=True,"
            " text=True).stdout.strip()\n"
            "marker = pathlib.Path(common) / 'orca-phase-marker'\n"
            "seen = marker.exists()\n"
            "marker.write_text('x')\n"
            "assert not seen, 'not the first run'\n")
        self._assert_not_a_kill(ok, msgs)
        self.assertTrue(any("TAUTOLOGICAL" in x for x in msgs), msgs)

    def test_a_non_ascii_checkout_path_still_runs_the_proof(self):
        parent = Path(tempfile.mkdtemp(prefix="orca-nc-")) / "répo"
        parent.mkdir()
        self.addCleanup(lambda: shutil.rmtree(parent.parent, ignore_errors=True))
        os.chdir(parent)
        self.addCleanup(lambda: os.chdir(self.repo))
        subprocess.run(["git", "init", "-q", "-b", "main"], check=True, cwd=parent)
        (parent / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (parent / "proof.py").write_text("import app\nassert app.VALUE == 2\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], check=True, cwd=parent)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base"],
                       check=True, cwd=parent)
        base = subprocess.run(["git", "rev-parse", "HEAD"], check=True, cwd=parent,
                              capture_output=True, text=True).stdout.strip()
        (parent / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], check=True, cwd=parent)
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "head"],
                       check=True, cwd=parent)
        head = subprocess.run(["git", "rev-parse", "HEAD"], check=True, cwd=parent,
                             capture_output=True, text=True).stdout.strip()
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        ok, msgs = verify.execute_negative_control(m, cmd)
        self.assertTrue(ok, msgs)

    def test_an_annotated_tag_of_head_stays_a_tag_in_every_phase(self):
        self.write("app.py", "VALUE = 1\n")
        self.write("proof.py",
                   "import subprocess\n"
                   "def git(*args):\n"
                   "    return subprocess.run(['git', *args], capture_output=True,"
                   " text=True, check=True).stdout.strip()\n"
                   "assert git('cat-file', '-t', 'v1') == 'tag', git('cat-file', '-t', 'v1')\n"
                   "assert git('rev-parse', 'v1^{commit}') == git('rev-parse', 'HEAD')\n")
        base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        head = self.commit("head")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "v1", "-m", "release")
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        ok, msgs = verify.execute_negative_control(m, cmd)
        self._assert_not_a_kill(ok, msgs)
        self.assertTrue(any("TAUTOLOGICAL" in x for x in msgs), msgs)

    def test_a_signed_tag_is_unsigned_in_the_clean_replay_too(self):
        # A signature covers the object line, so it would verify only on the clean
        # replay. Stripping it there too means a verify-tag proof fails before the
        # control and is not graded a kill.
        self.write("app.py", "VALUE = 1\n")
        self.write("proof.py",
                   "import subprocess\n"
                   "raw = subprocess.run(['git', 'cat-file', 'tag', 'v1'],"
                   " capture_output=True, check=True).stdout\n"
                   "assert b'BEGIN PGP SIGNATURE' in raw\n")
        base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        head = self.commit("head")
        payload = (f"object {head}\n"
                   "type commit\n"
                   "tag v1\n"
                   "tagger t <t@t> 1000000000 +0000\n"
                   "gpgsig -----BEGIN PGP SIGNATURE-----\n"
                   " \n"
                   " -----END PGP SIGNATURE-----\n"
                   "\n"
                   "release\n").encode()
        sha = subprocess.run(["git", "hash-object", "-t", "tag", "-w", "--stdin"],
                             input=payload, check=True, capture_output=True).stdout.decode().strip()
        self.git("update-ref", "refs/tags/v1", sha)
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        ok, msgs = verify.execute_negative_control(m, cmd)
        self.assertFalse(ok, msgs)
        self.assertTrue(any("CLEAN" in x for x in msgs), msgs)

    def test_a_message_signature_is_not_a_kill(self):
        # v0.7.1's layout: the SSH signature is appended after the message, not a
        # gpgsig header. It verifies on an unchanged object line and would fail only
        # under the control. Stripping it on the clean replay too makes that proof
        # fail before the control.
        keydir = tempfile.mkdtemp(prefix="orca-nc-key-")
        self.addCleanup(lambda: shutil.rmtree(keydir, ignore_errors=True))
        key = str(Path(keydir) / "id_ed25519")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-q", "-N", "", "-f", key], check=True)
        pub = Path(key + ".pub").read_text(encoding="utf-8").strip()
        self.write("signers", f't@t namespaces="git" {pub}\n')
        self.write("app.py", "VALUE = 1\n")
        self.write("proof.py",
                   "import subprocess\n"
                   "r = subprocess.run(['git', '-c', 'gpg.format=ssh', '-c',"
                   " 'gpg.ssh.allowedSignersFile=signers', 'verify-tag', 'v1'],"
                   " capture_output=True)\n"
                   "assert r.returncode == 0, r.stderr\n")
        base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        head = self.commit("head")
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@t",
             "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}",
             "tag", "-s", "v1", "-m", "open-fleet 0.7.1"],
            cwd=self.repo, check=True, capture_output=True)
        pre = subprocess.run(
            ["git", "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile=signers",
             "verify-tag", "v1"],
            cwd=self.repo, capture_output=True, timeout=30)
        self.assertEqual(pre.returncode, 0, pre.stderr.decode())
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        ok, msgs = verify.execute_negative_control(m, cmd)
        self.assertFalse(ok, msgs)
        self.assertTrue(any("CLEAN" in x for x in msgs), msgs)

    def test_a_nested_tag_of_head_does_not_block_a_real_kill(self):
        self.write("app.py", "VALUE = 1\n")
        self.write("proof.py", "import app\nassert app.VALUE == 2\n")
        base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        head = self.commit("head")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "inner", "-m", "inner")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "outer", "-m", "outer", "inner")
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        ok, msgs = verify.execute_negative_control(m, cmd)
        self.assertTrue(ok, msgs)

    def test_a_nested_tag_stays_a_chain_in_every_phase(self):
        self.write("app.py", "VALUE = 1\n")
        self.write("proof.py",
                   "import subprocess\n"
                   "def git(*args):\n"
                   "    return subprocess.run(['git', *args], capture_output=True,"
                   " text=True, check=True).stdout.strip()\n"
                   "assert git('cat-file', '-t', 'outer') == 'tag'\n"
                   "assert git('cat-file', '-t', 'inner') == 'tag'\n"
                   "kind = git('cat-file', '-p', 'outer').splitlines()[1]\n"
                   "assert kind == 'type tag', kind\n"
                   "assert git('rev-parse', 'outer^{commit}') == git('rev-parse', 'HEAD')\n")
        base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        head = self.commit("head")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "inner", "-m", "inner")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "tag", "-a", "outer", "-m", "outer", "inner")
        cmd = f"{shlex.quote(sys.executable)} proof.py"
        m = {"base_sha": base, "head_sha": head, "negative_control": {
            "tool": "revert", "paths": ["app.py"], "command": cmd}}
        ok, msgs = verify.execute_negative_control(m, cmd)
        self._assert_not_a_kill(ok, msgs)
        self.assertTrue(any("TAUTOLOGICAL" in x for x in msgs), msgs)

    def test_a_proof_that_compares_head_to_its_branch_ref_is_not_killed(self):
        # refs/heads/main points at head_sha in the source. A linked worktree would still
        # see that ref under the sealed control, so HEAD != refs/heads/main only then.
        ok, msgs = self._unit(
            "import subprocess\n"
            "def rev(arg):\n"
            "    return subprocess.run(['git', 'rev-parse', arg], capture_output=True,"
            " text=True, check=True).stdout.strip()\n"
            "assert rev('HEAD') == rev('refs/heads/main'), 'branch ref is not this commit'\n")
        self._assert_not_a_kill(ok, msgs)
        self.assertTrue(any("TAUTOLOGICAL" in x for x in msgs), msgs)

    def test_each_phase_runs_under_its_own_empty_home_and_tmpdir(self):
        seen = []
        original = verify._run_at

        def spy(wt, argv, **kw):
            if argv and argv[-1] == "proof.py":
                env = kw["env"]
                seen.append({k: env[k] for k in ("HOME", "TMPDIR", "TMP", "TEMP")})
                self.assertEqual(os.listdir(env["HOME"]), [])
                self.assertEqual(os.listdir(env["TMPDIR"]), [])
            return original(wt, argv, **kw)
        with mock.patch.object(verify, "_run_at", side_effect=spy):
            ok, msgs = self._unit("import app\nassert app.VALUE == 2\n")
        self.assertTrue(ok, msgs)
        self.assertEqual(len(seen), 3, seen)
        self.assertEqual(len({s["HOME"] for s in seen}), 3, seen)
        for s in seen:
            self.assertEqual(s["TMPDIR"], s["TMP"])
            self.assertEqual(s["TMPDIR"], s["TEMP"])
            self.assertNotEqual(s["HOME"], os.environ.get("HOME"))


class ReadSourceGuard(unittest.TestCase):
    """#116: a leading-dash ref/path must not reach `git show` as an option."""

    def test_option_like_ref_refused(self):
        _, err = verify.read_source("file.md@--output=/tmp/pwn")
        self.assertIn("refusing option-like", err or "")

    def test_option_like_path_refused(self):
        _, err = verify.read_source("--upload-pack=x@HEAD")
        self.assertIn("refusing option-like", err or "")


class MetaChecks(unittest.TestCase):
    """#114: intent packet, lighting legality, reviewer_mode legality — mutation-only."""

    def test_intent_required_for_mutation(self):
        self.assertTrue(verify.check_intent({"unit": "ship-it"}, True))
        self.assertTrue(verify.check_intent({"intent": {"goal": "g", "ruled_out": "", "why": "w"}}, True))
        self.assertEqual(
            verify.check_intent({"intent": {"goal": "g", "ruled_out": "r", "why": "w"}}, True), [])
        self.assertEqual(verify.check_intent({}, False), [])  # report-only skips

    def test_lighting_legal_for_mutation(self):
        self.assertTrue(verify.check_lighting({"lighting": "bright"}, True))
        self.assertTrue(verify.check_lighting({"lighting": "bogus"}, True))
        self.assertEqual(verify.check_lighting({"lighting": "lit"}, True), [])
        self.assertEqual(verify.check_lighting({"lighting": "dark-eligible"}, True), [])
        self.assertEqual(verify.check_lighting({}, False), [])

    def test_missing_lighting_defaults_to_lit(self):
        # #169: doctrine — "Recording nothing means lit" (gate-classification.md).
        self.assertEqual(verify.check_lighting({}, True), [])
        self.assertEqual(verify.check_lighting({}, True, dispatch_lighting="lit"), [])

    def test_null_lighting_is_not_omission(self):
        # An explicit null is a present illegal value, not omission — it must still fail.
        errs = verify.check_lighting({"lighting": None}, True)
        self.assertTrue(any("lighting must be" in e for e in errs), errs)

    def test_missing_lighting_with_dark_dispatch_is_a_swap(self):
        # #169: omission means lit, so a dark-eligible dispatch + omitted manifest lighting
        # implies the run used the dark waiver while the manifest says lit — still a swap.
        errs = verify.check_lighting({}, True, dispatch_lighting="dark-eligible")
        self.assertTrue(any("swap" in e for e in errs), errs)

    def test_lane_is_checked_when_dispatch_supplies_it(self):
        # Full review: verify.py never saw lane data, so the Lane-0/B half of
        # dark-eligibility rested on narration. The dispatch-supplied lane is
        # authoritative exactly like dispatch lighting.
        self.assertEqual(verify.check_lighting({}, True), [])  # unsupplied: unchanged
        self.assertEqual(verify.check_lighting({"lane": "A"}, True, dispatch_lane="A"), [])
        self.assertTrue(verify.check_lighting({"lane": "Z"}, True))  # illegal value
        errs = verify.check_lighting({"lane": "B"}, True, dispatch_lane="A")
        self.assertTrue(any("swap" in e for e in errs), errs)
        errs = verify.check_lighting({}, True, dispatch_lane="0")
        self.assertTrue(any("Lane 0" in e for e in errs), errs)
        errs = verify.check_lighting({"lighting": "dark-eligible"}, True,
                                     dispatch_lane="B",
                                     dispatch_lighting="dark-eligible")
        self.assertTrue(any("Lane A" in e for e in errs), errs)
        self.assertEqual(
            verify.check_lighting({"lighting": "dark-eligible"}, True,
                                  dispatch_lane="A",
                                  dispatch_lighting="dark-eligible"), [])
        self.assertEqual(verify.check_lighting({}, False, dispatch_lane="0"), [])

    def test_reviewer_mode_legal_for_mutation(self):
        self.assertTrue(verify.check_reviewer_mode({"reviewer_mode": "self"}, True))
        self.assertTrue(verify.check_reviewer_mode({}, True))
        self.assertEqual(verify.check_reviewer_mode({"reviewer_mode": "cross-vendor"}, True), [])
        self.assertEqual(verify.check_reviewer_mode({}, False), [])


class ReviewLookupBinding(unittest.TestCase):
    """#119 + #126: the GitHub review-lookup path is exercised; self-approval and superseded
    reviews do not count as an independent approval."""

    def setUp(self):
        self._orig_r = verify.fetch_reviews
        self._orig_a = verify.fetch_pr_author
        verify.fetch_pr_author = lambda repo, n: "pr-author"  # a resolved author, distinct from reviewers
        verify._Authority.reset()  # a pin another test left is not this test's authority (h409 F-1)
        self.addCleanup(verify._Authority.reset)

    def tearDown(self):
        verify.fetch_reviews = self._orig_r
        verify.fetch_pr_author = self._orig_a

    def _m(self):
        return {"unit": "ship-it", "head_sha": "H", "pr": {"number": 7}}

    def test_approved_at_head_passes(self):
        verify.fetch_reviews = lambda repo, n: ([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                                  "user": {"login": "carol"}}], None)
        self.assertEqual(verify.check_review(self._m(), "o/r", True), [])

    def test_no_approval_fails(self):
        verify.fetch_reviews = lambda repo, n: ([{"state": "COMMENTED", "commit_id": "H",
                                                  "user": {"login": "carol"}}], None)
        self.assertTrue(any("APPROVED" in e for e in verify.check_review(self._m(), "o/r", True)))

    def test_approval_at_wrong_sha_fails(self):
        verify.fetch_reviews = lambda repo, n: ([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "OLD",
                                                  "user": {"login": "carol"}}], None)
        self.assertTrue(any("APPROVED" in e for e in verify.check_review(self._m(), "o/r", True)))

    def test_fetch_error_fails_closed(self):
        verify.fetch_reviews = lambda repo, n: (None, "gh api failed")
        self.assertTrue(any("cannot fetch" in e for e in verify.check_review(self._m(), "o/r", True)))

    def test_author_self_approval_rejected(self):
        verify.fetch_reviews = lambda repo, n: ([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                                  "user": {"login": "alice"}}], None)
        verify.fetch_pr_author = lambda repo, n: "alice"
        self.assertTrue(any("APPROVED" in e for e in verify.check_review(self._m(), "o/r", True)))

    def test_superseded_approval_not_counted(self):
        verify.fetch_reviews = lambda repo, n: (
            [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H", "user": {"login": "bob"}},
             {"state": "COMMENTED", "commit_id": "H", "user": {"login": "bob"}}], None)
        self.assertTrue(any("APPROVED" in e for e in verify.check_review(self._m(), "o/r", True)))

    def test_independent_approval_passes_when_author_differs(self):
        verify.fetch_reviews = lambda repo, n: ([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                                  "user": {"login": "carol"}}], None)
        verify.fetch_pr_author = lambda repo, n: "alice"
        self.assertEqual(verify.check_review(self._m(), "o/r", True), [])

    def test_unresolved_author_fails_closed(self):
        # #142: if the PR-author lookup fails, we cannot exclude a self-approval — fail closed,
        # never let the author's own approval satisfy the independent-review gate.
        verify.fetch_reviews = lambda repo, n: ([{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                                  "user": {"login": "alice"}}], None)
        verify.fetch_pr_author = lambda repo, n: None
        res = verify.check_review(self._m(), "o/r", True)
        self.assertTrue(any("cannot resolve" in e.lower() for e in res), res)

    def test_dark_eligible_waives_review_only_with_an_executed_control(self):
        # #145 + #256: a dark-eligible unit (coordinator dispatch) lands without a human review, so
        # the negative control is the whole oracle — and it must have been EXECUTED. With
        # nc_executed the review leg is a NOTE; without it the lane is RED.
        verify.fetch_reviews = lambda repo, n: ([], None)
        res = verify.check_review(self._m(), "o/r", True, corroborated=True,
                                  dispatch_lighting="dark-eligible", nc_executed=True)
        self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    def test_dark_eligible_with_a_read_only_control_fails_closed(self):
        # docs/reviews/2026-09-10-review.md A1/A4/A6/A9: this exact lane went GREEN on a text file the worker wrote.
        res = verify.check_review(self._m(), "o/r", True, corroborated=True,
                                  dispatch_lighting="dark-eligible", nc_executed=False)
        self.assertTrue(any("EXECUTED" in e for e in res), res)
        self.assertFalse(any(e.startswith("NOTE:") for e in res), res)

    def test_dark_eligible_uncorroborated_fails_closed(self):
        # #149 review: a dark-eligible waiver on a worker-forgeable oracle (no out-of-band contract)
        # must fail closed — review is waived, but the oracle must be unfakeable.
        res = verify.check_review(self._m(), "o/r", True, corroborated=False, dispatch_lighting="dark-eligible")
        self.assertTrue(any("forgeable" in e and not e.startswith("NOTE:") for e in res), res)


class ReviewPagination(unittest.TestCase):
    """#167: fetch_reviews must follow ALL pages (`gh api --paginate`). Without it GitHub returns
    the first 30 reviews only, so a stale APPROVED on page 1 outranks the same reviewer's later
    CHANGES_REQUESTED, and a fresh APPROVED past page 1 is invisible. A fake `gh` on PATH
    (test_preflight.py pattern) emulates the real CLI: page 1 only without --paginate."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self._page1 = tmp / "page1.json"
        self._page2 = tmp / "page2.json"
        fakebin = tmp / "bin"
        fakebin.mkdir()
        gh = fakebin / "gh"
        # The page paths are baked in: the pinned gh runs under a SCRUBBED environment (h409
        # R3), so a FAKE_GH_* variable would never reach it.
        p1, p2 = shlex.quote(str(self._page1)), shlex.quote(str(self._page2))
        gh.write_text(
            '#!/bin/sh\n'
            'case "$*" in\n'
            '  *reviews*)\n'
            '    case " $* " in\n'
            f'      *" --paginate "*) cat {p1} {p2};;\n'
            f'      *) cat {p1};;\n'
            '    esac;;\n'
            '  *) echo "{\\"user\\":{\\"login\\":\\"pr-author\\"}}";;\n'
            'esac\n',
            encoding="utf-8",
        )
        gh.chmod(0o755)
        self._env = {"PATH": f"{fakebin}{os.pathsep}{os.environ['PATH']}"}
        # h409 F-1: the authority is pinned once per run; a library caller pins on first use, so
        # each test's fresh fakebin needs the pin cleared (and its temp-dir gh is, correctly,
        # classed worker-writable — advisory NOTEs, not fatals, on this unlabelled lane).
        verify._Authority.reset()
        self.addCleanup(verify._Authority.reset)

    def tearDown(self):
        self._tmp.cleanup()

    def _verdict_with_pages(self, page1, page2):
        self._page1.write_text(json.dumps(page1) + "\n", encoding="utf-8")
        self._page2.write_text(json.dumps(page2) + "\n", encoding="utf-8")
        with mock.patch.dict(os.environ, self._env):
            return verify.check_review(
                {"unit": "ship-it", "head_sha": "H", "pr": {"number": 7}}, "o/r", True)

    @staticmethod
    def _filler(n):
        return [{"state": "COMMENTED", "commit_id": "H",
                 "user": {"login": f"bot{i}"}} for i in range(n)]

    def test_fetches_all_pages_31_review_fixture(self):
        # 31 reviews over two pages; the only APPROVED is review #31 — invisible on page 1 alone.
        res = self._verdict_with_pages(self._filler(30),
                                       [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                         "user": {"login": "carol"}}])
        self.assertEqual([e for e in res if not e.startswith("NOTE:")], [])

    def test_page2_changes_requested_supersedes_page1_approval(self):
        page1 = self._filler(29) + [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                     "user": {"login": "carol"}}]
        page2 = [{"state": "CHANGES_REQUESTED", "commit_id": "H",
                  "user": {"login": "carol"}}]
        res = self._verdict_with_pages(page1, page2)
        self.assertTrue(any("APPROVED" in e for e in res), res)

    def test_approval_only_on_page2_passes(self):
        res = self._verdict_with_pages(self._filler(30),
                                       [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": "H",
                                         "user": {"login": "carol"}}])
        self.assertEqual([e for e in res if not e.startswith("NOTE:")], [])

    def test_gh_error_fails_closed(self):
        self._page1.write_text("not json\n", encoding="utf-8")
        self._page2.write_text("not json\n", encoding="utf-8")
        with mock.patch.dict(os.environ, self._env):
            res = verify.check_review(
                {"unit": "ship-it", "head_sha": "H", "pr": {"number": 7}}, "o/r", True)
        self.assertTrue(any("cannot fetch" in e for e in res), res)


class PaginatedJsonParsing(unittest.TestCase):
    """#167: `gh api --paginate` concatenates one JSON array per page; the parse step merges them
    and fails closed on malformed output."""

    def test_single_array_still_parses(self):
        items, err = verify.parse_review_pages(json.dumps([{"state": "APPROVED"}]))
        self.assertIsNone(err)
        self.assertEqual(items, [{"state": "APPROVED"}])

    def test_concatenated_arrays_merge(self):
        out = json.dumps([{"a": 1}]) + "\n" + json.dumps([{"b": 2}]) + "\n"
        items, err = verify.parse_review_pages(out)
        self.assertIsNone(err)
        self.assertEqual(items, [{"a": 1}, {"b": 2}])

    def test_malformed_output_fails_closed(self):
        items, err = verify.parse_review_pages('[{"a": 1}]\nnot json')
        self.assertIsNone(items)
        self.assertTrue(err)

    def test_non_array_page_fails_closed(self):
        items, err = verify.parse_review_pages('{"unexpected": "object"}')
        self.assertIsNone(items)
        self.assertTrue(err)


class ShasBinding(unittest.TestCase):
    """#119: base_sha/head_sha presence is the SHA-binding premise — bind it."""

    def test_missing_sha_fails(self):
        self.assertTrue(verify.check_shas_present({"head_sha": "H"}))
        self.assertTrue(verify.check_shas_present({}))

    def test_both_shas_present_ok(self):
        self.assertEqual(verify.check_shas_present({"base_sha": "a", "head_sha": "b"}), [])

    def test_symbolic_sha_fatal_for_mutation(self):
        errs = verify.check_real_commits({"base_sha": "HEAD", "head_sha": "HEAD"}, is_mutation=True)
        self.assertTrue(any("40-hex" in e and not e.startswith("NOTE:") for e in errs), errs)

    def test_symbolic_sha_advisory_for_report_only(self):
        errs = verify.check_real_commits({"base_sha": "HEAD", "head_sha": "HEAD"}, is_mutation=False)
        self.assertTrue(errs and all(e.startswith("NOTE:") for e in errs), errs)


class CriterionExtraction(unittest.TestCase):
    """#126 / #268: extraction catches hyphenated AND compact ids where a contract author DECLARES
    one — at the head of a list item or line, followed by a separator — and nowhere else."""

    def test_extracts_hyphenated_and_compact(self):
        ids = verify.extract_criterion_ids("- AC-1: x\n- SC12: y\n3. REQ-3) z\nREQ-4. w\n")
        self.assertEqual({"AC-1", "SC12", "REQ-3", "REQ-4"}, ids)

    def test_a11_realistic_contract_prose_is_not_a_criterion(self):
        # docs/reviews/2026-09-10-review.md A11, the one FALSE RED in the bypass log: a realistic contract whose prose
        # names a hash, a PR, an RFC and a date format. The denominator is exactly {AC-1, AC-2};
        # counting the prose tokens made every real contract unverifiable.
        contract = (
            "# Frozen contract\n\n"
            "- AC-1: the token digest is SHA-256 over the raw bytes\n"
            "- AC-2: see PR-12 and RFC-7519, and emit ISO-8601 timestamps\n"
        )
        self.assertEqual(verify.extract_criterion_ids(contract), {"AC-1", "AC-2"})

    def test_json_criterion_ids_are_preferred(self):
        # A JSON contract declares its denominator outright — no text heuristic runs at all.
        payload = json.dumps({"criterion_ids": ["AC-1", "SC-9"], "notes": "mentions RFC-7519"})
        self.assertEqual(verify.extract_criterion_ids(payload), {"AC-1", "SC-9"})

    def test_indented_and_starred_list_items_still_count(self):
        ids = verify.extract_criterion_ids("  * AC-7: x\n\t- SC-8: y\n")
        self.assertEqual({"AC-7", "SC-8"}, ids)


class RawByteDigest(RepoCase):
    """#180: the scope digest is computed over RAW BYTES, exactly what the coordinator's
    `shasum -a 256` sees — a CRLF contract must verify against its byte digest, and an LF
    contract's digest must be unchanged (byte-identical behavior for LF files)."""

    def _write(self, raw):
        return self.write("crlf-contract.md", raw)

    def test_crlf_contract_matches_shasum_digest(self):
        raw = b"frozen\r\n- AC-1: x\r\n- AC-2: y\r\n"
        p = self._write(raw)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()  # the coordinator's shasum digest
        m = {"contract": {"source": p, "digest": digest, "criterion_ids": ["AC-1", "AC-2"]},
             "criteria": _crit("AC-1", "AC-2")}
        fatal = [e for e in verify.check_scope(m, p, digest) if not e.startswith("NOTE:")]
        self.assertEqual(fatal, [])

    def test_lf_digest_unchanged(self):
        raw = b"frozen\n- AC-1: x\n"
        p = self._write(raw)
        # Pinned to the pre-#180 value: LF files must hash byte-identically to before.
        digest = "sha256:07af39c8585de6b596a28a05c0cfe432a25c294bb2166c1ffeef1db4901abf8a"
        m = {"contract": {"source": p, "digest": digest, "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1")}
        fatal = [e for e in verify.check_scope(m, p, digest) if not e.startswith("NOTE:")]
        self.assertEqual(fatal, [])

    def test_crlf_contract_via_git_ref_matches_shasum_digest(self):
        # The coordinator lane: `path@gitref` goes through `_run_bytes(["git", "show", ...])`.
        # Commit a CRLF contract (autocrlf off so the blob keeps its raw bytes) and verify
        # against the shasum digest — text=True capture would normalize CRLF away and wedge.
        raw = b"frozen\r\n- AC-1: x\r\n"
        # _temp_repo: same #340 teardown race as the FreshnessCheck site (OSError 39 on .git).
        with _temp_repo() as repo:
            Path(repo, "contract.md").write_bytes(raw)

            def git(*args):
                subprocess.run(["git", *args], cwd=repo, capture_output=True, check=True)

            git("init", "-q")
            git("-c", "core.autocrlf=false", "add", "contract.md")
            git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "freeze")
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            m = {"contract": {"source": "contract.md@HEAD", "digest": digest,
                              "criterion_ids": ["AC-1"]},
                 "criteria": _crit("AC-1")}
            cwd = os.getcwd()
            os.chdir(repo)  # read_source's `git show` runs in the process cwd
            try:
                res = verify.check_scope(m, "contract.md@HEAD", digest)
            finally:
                os.chdir(cwd)
            fatal = [e for e in res if not e.startswith("NOTE:")]
            self.assertEqual(fatal, [])


class NoGhReviewLane(RepoCase):
    """#118: the offline no-gh lane has a defined, non-silent pass path (a local reviewer artifact)."""

    def _m(self, text, head="HEADSHA123"):
        rel = self.write("docs/reports/u/review.md", text)
        return {"unit": "ship-it", "head_sha": head, "artifacts": [self.pin(rel)],
                "review": {"artifact": rel}}

    def test_no_gh_with_executed_control_passes_as_note(self):
        m = self._m("reviewed HEADSHA123 — approved by a fresh reviewer\n")
        res = verify.check_review(m, None, True, no_gh=True, corroborated=True, nc_executed=True)
        self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    def test_no_gh_without_executed_control_fails_closed(self):
        # #256: the no-gh lane replaces the GitHub review with a worker-written file, so the
        # negative control is the only oracle left and it must have been EXECUTED. This is the
        # exact shape of docs/reviews/2026-09-10-review.md A2, which landed with a NOTE and exit 0.
        m = self._m("reviewed HEADSHA123 — approved by a fresh reviewer\n")
        res = verify.check_review(m, None, True, no_gh=True, corroborated=True, nc_executed=False)
        self.assertTrue(any("EXECUTED" in e for e in res), res)
        self.assertFalse(any(e.startswith("NOTE:") for e in res), res)

    def test_no_gh_uncorroborated_fails_closed(self):
        # #138: without an out-of-band coordinator contract the local artifact is worker-forgeable.
        m = self._m("reviewed HEADSHA123 — approved by a fresh reviewer\n")
        res = verify.check_review(m, None, True, no_gh=True, corroborated=False, nc_executed=True)
        self.assertTrue(any("forgeable" in e and not e.startswith("NOTE:") for e in res), res)

    def test_no_gh_missing_artifact_fails_closed(self):
        m = {"unit": "ship-it", "head_sha": "H", "review": {}}
        res = verify.check_review(m, None, True, no_gh=True)
        self.assertTrue(any(not e.startswith("NOTE:") for e in res), res)

    def test_no_gh_artifact_not_referencing_head_fails(self):
        m = self._m("reviewed some other sha\n")
        res = verify.check_review(m, None, True, no_gh=True)
        self.assertTrue(any("does not reference head_sha" in e for e in res), res)

    def test_no_gh_artifact_outside_the_repo_fails(self):
        # #267: the reviewer record is manifest-named evidence too — same binding as the NC.
        m = {"unit": "ship-it", "head_sha": "H", "review": {"artifact": "/etc/hostname"}}
        res = verify.check_review(m, None, True, no_gh=True)
        self.assertTrue(any("absolute evidence path refused" in e for e in res), res)


class ProvenanceCheck(unittest.TestCase):
    """#91 review: a manifest claiming a regulated standard must carry the audit fields, else it is
    incomplete evidence masquerading as an Art-12/50 record."""

    def test_incomplete_provenance_with_standard_fails(self):
        errs = verify.check_provenance({"provenance": {"standard": "EU-AI-Act-Art-12"}})
        self.assertTrue(any("audit fields" in e for e in errs), errs)

    def test_complete_provenance_passes(self):
        prov = {"standard": "SOC2", "spec_version": "v1", "model": "m", "reviewer": "r@t",
                "retention": "s3://audit"}
        self.assertEqual(verify.check_provenance({"provenance": prov}), [])

    def test_no_standard_claim_skips(self):
        self.assertEqual(verify.check_provenance({"provenance": {"standard": "none"}}), [])
        self.assertEqual(verify.check_provenance({}), [])

class HiddenCriteria(unittest.TestCase):
    """#296 / A16. The denominator IS the scope guarantee — coverage is measured against it. A
    contract that writes some criteria in a form the extractor does not count shrinks what the unit
    is graded on while still reading as a full specification to a human. Three criteria graded as
    one, and the unit reported "all criteria addressed".
    """

    def test_a_mixed_form_contract_hides_criteria(self):
        text = "- AC-1: sum\n| AC-2 | rejects None |\nAC-3 — total\n"
        counted = verify.extract_criterion_ids(text)
        self.assertEqual(counted, {"AC-1"}, "the extractor's blind spot has changed")
        self.assertEqual(set(verify.hidden_criterion_ids(text, counted)), {"AC-2", "AC-3"})

    def test_prose_references_are_not_criteria(self):
        # Refusing every uncounted AAA-9 token would refuse ordinary prose. What marks a hidden
        # criterion is sharing a PREFIX with one the contract does count.
        for text in ("- AC-1: sum per RFC-7519 using SHA-256 and ISO-8601\n",
                     "- AC-1: sum\n- SC-1: perf\nsee RFC-7519 and PR-104\n"):
            counted = verify.extract_criterion_ids(text)
            self.assertEqual(verify.hidden_criterion_ids(text, counted), {},
                             f"prose was read as a hidden criterion: {text!r}")

    def test_a_same_family_mention_fails_closed(self):
        # Genuinely ambiguous — "related to AC-9 in the old spec" may be prose. Fail closed and
        # tell the author how to disambiguate, rather than silently shrink the denominator.
        text = "- AC-1: sum\nrelated to AC-9 in the old spec\n"
        counted = verify.extract_criterion_ids(text)
        self.assertEqual(set(verify.hidden_criterion_ids(text, counted)), {"AC-9"})

    def test_well_formed_contracts_are_untouched(self):
        for text in ("- AC-1: sum\n- AC-2: rejects None\n- AC-3: total\n",
                     "1. AC-1: sum\n2. AC-2: rejects None\n"):
            counted = verify.extract_criterion_ids(text)
            self.assertEqual(verify.hidden_criterion_ids(text, counted), {})

    def test_a_json_contract_needs_no_heuristic(self):
        text = '{"criterion_ids": ["AC-1", "AC-2"], "body": "| AC-2 | in a table |"}'
        counted = verify.extract_criterion_ids(text)
        self.assertEqual(counted, {"AC-1", "AC-2"})
        self.assertEqual(verify.hidden_criterion_ids(text, counted), {},
                         "an explicit criterion_ids array is unambiguous; nothing is hidden")


class MalformedManifest(unittest.TestCase):
    """#137: a malformed manifest must fail closed as an invariant failure, never crash the gate."""

    def _tmp(self, text):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        self.addCleanup(lambda: os.path.exists(f.name) and os.unlink(f.name))  # no leaks (#381)
        f.write(text)
        f.close()
        return f.name

    def test_non_object_manifest_rejected(self):
        m, err = verify.load_manifest(self._tmp("[1, 2, 3]"))
        self.assertIsNone(m)
        self.assertIn("JSON object", err)

    def test_non_dict_intent_does_not_crash(self):
        errs = verify.check_intent({"intent": "just a string"}, True)
        self.assertTrue(any("intent packet" in e for e in errs), errs)

    def test_non_scalar_lighting_does_not_crash(self):
        errs = verify.check_lighting({"lighting": ["lit"]}, True)
        self.assertTrue(any("lighting must be" in e for e in errs), errs)

    def test_non_scalar_reviewer_mode_does_not_crash(self):
        errs = verify.check_reviewer_mode({"reviewer_mode": {"x": 1}}, True)
        self.assertTrue(any("reviewer_mode must be" in e for e in errs), errs)

    def test_lighting_swap_detected(self):
        # #145: the dispatch lighting is authoritative; a worker manifest that swaps it fails.
        errs = verify.check_lighting({"lighting": "dark-eligible"}, True, dispatch_lighting="lit")
        self.assertTrue(any("swap" in e for e in errs), errs)

    def test_verify_wraps_check_exceptions(self):
        # A manifest shape that would raise inside a check becomes a fatal invariant, not a traceback.
        path = self._tmp('{"pr": "not-an-object", "head_sha": "H", "base_sha": "B"}')
        (fatal, notes), err = verify.verify(path, unit_class="mutation")
        self.assertIsNone(err)
        self.assertTrue(any("malformed manifest" in f for f in fatal), fatal)

    def test_malformed_manifest_exits_2(self):
        # #149 review: a malformed manifest is an invariant failure (exit 2), not a usage/dep error (1).
        self.assertEqual(verify.main(["--manifest", self._tmp("[1, 2, 3]")]), 2)


class MalformedScopeShapesAreNamed(RepoCase):
    """Review P3: a non-object criteria[] item and a list-valued criterion id raised AttributeError
    / TypeError inside check_scope and extract_criterion_ids. The gate failed closed, but only as an
    anonymous `malformed manifest: <Exception>`. Each wrong shape is now a fatal that names the
    field, from check_scope itself, never an exception."""

    def setUp(self):
        super().setUp()
        self.contract = self.src(["AC-1"])
        self.dig = self.digest(self.contract)

    def _scope(self, m, source=None, digest=None):
        errs = verify.check_scope(m, source or self.contract, digest or self.dig)
        self.assertTrue(errs, "a malformed shape passed the scope check")
        return errs

    def _assert_named(self, errs, *needles):
        self.assertTrue(any(all(n in e for n in needles) for e in errs), errs)
        self.assertFalse(any("Error" in e for e in errs), errs)

    def test_a_non_object_criteria_item_is_named(self):
        for item in ("AC-1", ["AC-1"], 7, None):
            with self.subTest(item=item):
                errs = self._scope({"contract": {"criterion_ids": ["AC-1"]},
                                    "criteria": [{"id": "AC-1", "addressed": True}, item]})
                self._assert_named(errs, "criteria[1]", "object")

    def test_a_non_string_criterion_id_is_named(self):
        errs = self._scope({"contract": {"criterion_ids": ["AC-1"]},
                            "criteria": [{"id": ["AC-1"], "addressed": True}]})
        self._assert_named(errs, "criteria[0].id")

    def test_list_valued_manifest_criterion_ids_are_named(self):
        for ids in ([["AC-1"]], "AC-1", {"AC-1": True}):
            with self.subTest(ids=ids):
                errs = self._scope({"contract": {"criterion_ids": ids},
                                    "criteria": [{"id": "AC-1", "addressed": True}]})
                self._assert_named(errs, "contract.criterion_ids")

    def test_non_object_contract_and_criteria_are_named(self):
        self._assert_named(self._scope({"contract": ["x"], "criteria": []}), "`contract`")
        self._assert_named(self._scope({"contract": {"criterion_ids": ["AC-1"]},
                                        "criteria": "AC-1"}), "`criteria`")
        self._assert_named(self._scope({"contract": {"digest": ["sha256:x"]}}), "contract.digest")

    def test_list_valued_ids_in_a_json_contract_are_named(self):
        rel = self.write("contract.json", json.dumps({"criterion_ids": [["AC-1"], "AC-2"]}))
        errs = self._scope({"contract": {"criterion_ids": ["AC-2"]}}, rel, self.digest(rel))
        self._assert_named(errs, "authoritative contract's criterion_ids")
        with self.assertRaises(ValueError):
            verify.extract_criterion_ids((self.repo / rel).read_text())

    def test_through_verify_the_message_is_the_named_one(self):
        path = self.write("m.json", json.dumps({"unit": "u", "contract": {"criterion_ids": ["AC-1"]},
                                                "criteria": ["AC-1"]}))
        (fatal, _notes), err = verify.verify(path, self.contract, self.dig, unit_class="report-only")
        self.assertIsNone(err)
        self.assertTrue(any("criteria[0]" in f for f in fatal), fatal)
        self.assertFalse(any("malformed manifest: " in f for f in fatal), fatal)

    def test_a_well_shaped_manifest_still_passes_scope(self):
        self.assertEqual(verify.check_scope({"contract": {"criterion_ids": ["AC-1"]},
                                             "criteria": _crit("AC-1")},
                                            self.contract, self.dig), [])


class NegativeControlSurvivor(RepoCase):
    """#137: survivor summaries (plural / percentage / count) must be rejected, not accepted."""

    def _errs(self, text):
        rel = self.artifact(text)
        m = {"artifacts": [self.pin(rel)],
             "negative_control": {"tool": "mutmut", "result": "killed", "mutant": "m7",
                                  "artifact": rel}}
        errs, _executed = verify.check_negative_control(m, True)
        return errs

    def test_percentage_survivor_rejected(self):
        self.assertTrue(self._errs("m7 mutation applied. Mutants that survived: 1. 0.0% killed.\n"))

    def test_summary_counts_survivor_rejected(self):
        self.assertTrue(self._errs("m7: Survived: 1 / Killed: 0\n"))

    def test_zero_mutants_killed_rejected(self):
        self.assertTrue(self._errs("m7 ran; 0 mutants killed.\n"))

    def test_pinned_mutant_survived_rejected(self):
        errs = self._errs("Run over 4 mutants: 3 killed. m7 survived the revert.\n")
        self.assertTrue(any("SURVIVED" in e for e in errs))

    def test_pinned_survivor_with_delimiter_rejected(self):
        # #152 review: "m7: Survived: 1" (colon-delimited) while OTHER mutants were killed must still
        # reject — the pinned mutant survived. A zero count ("survived: 0") is a kill, not a survivor.
        errs = self._errs("Run over 4 mutants: 3 killed. m7: Survived: 1.\n")
        self.assertTrue(any("SURVIVED" in e for e in errs))

    def test_pinned_zero_survivors_passes(self):
        self.assertEqual(self._errs("m7 revert applied. m7: survived: 0. 1 killed, RED.\n"), [])

    def test_pinned_zero_survivors_dash_delimited_passes(self):
        # #154 review: the zero-count lookahead must accept the same delimiters as the prefix, so
        # "m7 - survived - 0" (zero survivors) is a kill, not a false survivor.
        self.assertEqual(self._errs("m7 revert applied. m7 - survived - 0. 1 killed, RED.\n"), [])

    def test_pinned_survivor_greater_than_zero_rejected(self):
        # #155 review: "m7 survived > 0" is a survivor, not a zero count — must reject.
        errs = self._errs("Run: 3 killed. m7 survived > 0.\n")
        self.assertTrue(any("SURVIVED" in e for e in errs))

    def test_multimutant_run_with_pinned_killed_passes(self):
        # #149 review: a multi-mutant run where OTHER mutants survived but the pinned mutant m7 was
        # killed is valid — the whole-artifact survivor scan must not reject it.
        self.assertEqual(
            self._errs("m7 KILLED. Summary: 5 mutants, 2 survived, 3 killed. Proof went RED.\n"), [])

    def test_genuine_kill_still_passes(self):
        self.assertEqual(self._errs("m7 KILLED — 1 killed, 0 survived. Proof went RED.\n"), [])


class GitAuthorityChecks(unittest.TestCase):
    """#172: the git-authority legs — check_ancestry, check_symbol_on_base, infer_repo — shell out
    to `git` in the process cwd, so each test runs inside a hermetic temp repo (the
    test_verify_gate.py _gate_repo pattern: refs/remotes/origin/main pinned with update-ref)."""

    def setUp(self):
        # _temp_repo: same #340 teardown race as the FreshnessCheck site (OSError 39 on .git).
        self._tmp = _temp_repo()
        self.repo = Path(self._tmp.name)

        def git(*args):
            return subprocess.run(["git", *args], cwd=self.repo, check=True,
                                  capture_output=True, text=True)

        git("init", "-q", "-b", "main")
        Path(self.repo, "app.py").write_text("def orca_unit_symbol():\n    return 1\n",
                                             encoding="utf-8")
        git("add", "app.py")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "one")
        self.main_tip = git("rev-parse", "HEAD").stdout.strip()
        git("update-ref", "refs/remotes/origin/main", "HEAD")
        # A parentless second root: a real commit that is NOT an ancestor of origin/main.
        self.side_sha = git("-c", "user.name=t", "-c", "user.email=t@t", "commit-tree",
                            "HEAD^{tree}", "-m", "side").stdout.strip()

    def tearDown(self):
        self._tmp.cleanup()

    @contextlib.contextmanager
    def _inside_repo(self):
        cwd = os.getcwd()
        os.chdir(self.repo)  # verify.py's _git runs in the process cwd
        try:
            yield
        finally:
            os.chdir(cwd)

    def test_ancestry_passes_for_commit_on_base(self):
        with self._inside_repo():
            self.assertEqual(verify.check_ancestry({"head_sha": self.main_tip}, "main"), [])

    def test_ancestry_fails_for_commit_not_on_base(self):
        with self._inside_repo():
            errs = verify.check_ancestry({"head_sha": self.side_sha}, "main")
        self.assertTrue(any("not an ancestor of origin/main" in e for e in errs), errs)

    def test_ancestry_skips_without_base_or_ref(self):
        with self._inside_repo():
            res = verify.check_ancestry({"head_sha": self.main_tip}, None)
            self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)
            res = verify.check_ancestry({"head_sha": self.main_tip}, "no-such-branch")
            self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    def test_a_missing_base_ref_is_fatal_on_a_lane_claiming_soundness(self):
        # Review P2: deleting origin/<base> in the worker's clone turned a requested ancestry
        # proof into a skipped one on EVERY lane. Only the advisory lane may skip it now.
        self.addCleanup(verify._Authority.reset)
        for lane in ("provenance=ci", "enforcement (signed dispatch record + pubkey)"):
            with self.subTest(lane=lane), self._inside_repo():
                verify._Authority.lane = lane
                res = verify.check_ancestry({"head_sha": self.main_tip}, "no-such-branch")
                self.assertTrue(res and not any(e.startswith("NOTE:") for e in res), res)
                self.assertIn("origin/no-such-branch not found", res[0])
                # --base not given stays a NOTE: nothing was asked for
                res = verify.check_ancestry({"head_sha": self.main_tip}, None)
                self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)
                self.assertEqual(verify.check_ancestry({"head_sha": self.main_tip}, "main"), [])

    def test_symbol_on_base_found(self):
        with self._inside_repo():
            self.assertEqual(verify.check_symbol_on_base("orca_unit_symbol", "main"), [])

    def test_symbol_on_base_missing_fails(self):
        with self._inside_repo():
            errs = verify.check_symbol_on_base("no_such_symbol", "main")
        self.assertTrue(any("not found on origin/main" in e for e in errs), errs)

    def test_symbol_on_base_skips_without_inputs(self):
        with self._inside_repo():
            self.assertEqual(verify.check_symbol_on_base(None, "main"), [])
            self.assertEqual(verify.check_symbol_on_base("orca_unit_symbol", None), [])

    def test_symbol_is_never_read_on_a_local_branch_spelled_as_the_absent_remote(self):
        # W3-07 class, Codex review: `git grep … refs/remotes/origin/main` with that ref ABSENT
        # expanded the name to the local branch refs/heads/refs/remotes/origin/main — here a
        # worker commit that adds the symbol — and the change read as "on base".
        def git(*args):
            return subprocess.run(["git", *args], cwd=self.repo, check=True,
                                  capture_output=True, text=True).stdout.strip()

        Path(self.repo, "planted.py").write_text("def planted_symbol():\n    pass\n",
                                                 encoding="utf-8")
        git("add", "planted.py")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "worker")
        git("update-ref", "-d", "refs/remotes/origin/main")
        git("update-ref", "refs/heads/refs/remotes/origin/main", "HEAD")
        with self._inside_repo():
            errs = verify.check_symbol_on_base("planted_symbol", "main")
            self.assertTrue(any("not found on origin/main" in e for e in errs), errs)
            errs = verify.check_symbol_on_base("planted_symbol", "main~0")
            self.assertTrue(any("not found on origin/main~0" in e for e in errs), errs)


class GitObjectRewriteChannelsAreClosed(RepoCase):
    """Review P1: `git replace` in the graded clone rewrites what head_sha RESOLVES to, and a
    `.git/info/grafts` file rewrites a commit's parents. Both are plain files the worker can
    write, and both changed every SHA fact verify.py states — the tree a ledger binds to, the
    ancestry it checks. git_env() now carries GIT_NO_REPLACE_OBJECTS=1 and GIT_GRAFT_FILE=
    /dev/null, so the verifier reads the objects the SHAs actually name."""

    def setUp(self):
        super().setUp()
        self.write("app.py", "VALUE = 1\n")
        self.base = self.commit("base")
        self.write("app.py", "VALUE = 2\n")
        self.head = self.commit("head")
        self.real_tree = self.git("rev-parse", "HEAD^{tree}")
        self.write("app.py", "VALUE = 'what the worker wants graded'\n")
        self.decoy = self.commit("decoy")
        self.decoy_tree = self.git("rev-parse", "HEAD^{tree}")

    def test_a_replace_ref_does_not_move_what_head_sha_resolves_to(self):
        self.git("replace", self.head, self.decoy)
        # positive control: plain git on this clone now answers with the decoy's tree
        self.assertEqual(self.git("rev-parse", f"{self.head}^{{tree}}"), self.decoy_tree)
        self.assertEqual(verify._tree(self.head), self.real_tree)
        record = {"cmd": "true", "cmd_sha256": hashlib.sha256(b"true").hexdigest(),
                  "exit": 0, "wtree": self.decoy_tree}
        errs = verify.check_commands({"head_sha": self.head, "commands": [record]}, True)
        self.assertTrue(any("STALE" in e for e in errs), errs)

    def test_a_grafts_file_does_not_rewrite_ancestry(self):
        # origin/main is a commit that does NOT contain head; a graft claims it does.
        orphan = self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit-tree",
                          f"{self.base}^{{tree}}", "-m", "unrelated")
        self.git("update-ref", "refs/remotes/origin/main", orphan)
        grafts = self.repo / ".git" / "info" / "grafts"
        grafts.parent.mkdir(parents=True, exist_ok=True)
        grafts.write_text(f"{orphan} {self.head}\n", encoding="utf-8")
        positive = subprocess.run(["git", "merge-base", "--is-ancestor", self.head, orphan],
                                  cwd=self.repo, capture_output=True)
        self.assertEqual(positive.returncode, 0, "the planted graft is not live on this host")
        errs = verify.check_ancestry({"head_sha": self.head}, "main")
        self.assertTrue(any("not an ancestor of origin/main" in e for e in errs), errs)


class InferRepoFromOrigin(unittest.TestCase):
    """#172: infer_repo parses `git remote get-url origin` into owner/name across the common
    remote URL spellings; without a parseable origin it must return None (fail-soft)."""

    def setUp(self):
        # _temp_repo: same #340 teardown race as the FreshnessCheck site (OSError 39 on .git).
        self._tmp = _temp_repo()
        self.repo = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo,
                       check=True, capture_output=True)
        self._cwd = os.getcwd()
        os.chdir(self.repo)  # infer_repo's `git remote get-url origin` runs in the process cwd

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def _origin(self, url):
        subprocess.run(["git", "remote", "add", "origin", url], cwd=self.repo,
                       check=True, capture_output=True)

    def test_ssh_scp_like_url(self):
        self._origin("git@github.com:owner/repo.git")
        self.assertEqual(verify.infer_repo(), "owner/repo")

    def test_ssh_scheme_url(self):
        self._origin("ssh://git@github.com/owner/repo.git")
        self.assertEqual(verify.infer_repo(), "owner/repo")

    def test_https_url(self):
        self._origin("https://github.com/owner/repo")
        self.assertEqual(verify.infer_repo(), "owner/repo")

    def test_https_url_trailing_dot_git(self):
        self._origin("https://github.com/owner/repo.git")
        self.assertEqual(verify.infer_repo(), "owner/repo")

    def test_no_origin_returns_none(self):
        self.assertIsNone(verify.infer_repo())

    def test_unparseable_origin_returns_none(self):
        self._origin("just-a-name-no-path")
        self.assertIsNone(verify.infer_repo())


class MutationFixture(RepoCase):
    """A complete, REAL mutation unit in a hermetic repo (the #183 fixture): a module the fix
    changes, a criterion-bound proof command, the frozen contract, the NC artifact — with only
    the GitHub fetch seam mocked. Test classes compose it; it carries no tests itself."""

    def setUp(self):
        super().setUp()
        # A REAL unit: a module whose behaviour the fix changes, a criterion-bound proof command
        # that binds to it, the frozen contract, and the NC artifact — all committed, so every
        # evidence path is repo-relative and tracked at head_sha (#267).
        self.write("app.py", "def f():\n    return 1\n")
        self.write("check.py", "import app\nassert app.f() == 2, 'AC-1 violated'\n")
        self.contract = self.src(["AC-1"])
        self.nc_artifact = self.artifact("mutant m7 was KILLED — proof went RED\n")
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        self.digest = RepoCase.digest(self, self.contract)  # shadows the helper; computed once
        self.proof_cmd = f"{shlex.quote(sys.executable)} check.py"

        self._orig_r = verify.fetch_reviews
        self._orig_a = verify.fetch_pr_author
        verify.fetch_reviews = lambda repo_, n: (
            [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": self.head_sha,
              "user": {"login": "carol"}}], None)
        verify.fetch_pr_author = lambda repo_, n: "alice"  # the PR author != the reviewer

        # #204 review: a successful review/NC check returns [] — the same as a skipped
        # one. Spy the two mutation lanes so dropping either from aggregation goes red.
        self.review_calls, self.nc_calls = [], []
        self._orig_check_review = verify.check_review
        self._orig_check_nc = verify.check_negative_control

        def spy_review(*a, **k):
            self.review_calls.append((a, k))
            return self._orig_check_review(*a, **k)

        def spy_nc(*a, **k):
            self.nc_calls.append((a, k))
            return self._orig_check_nc(*a, **k)

        verify.check_review = spy_review
        verify.check_negative_control = spy_nc

    def tearDown(self):
        verify.fetch_reviews = self._orig_r
        verify.fetch_pr_author = self._orig_a
        verify.check_review = self._orig_check_review
        verify.check_negative_control = self._orig_check_nc

    def _assert_mutation_lanes_ran(self):
        self.assertTrue(self.review_calls,
                        "check_review was not invoked — review lane dropped from aggregation")
        self.assertTrue(self.nc_calls,
                        "check_negative_control was not invoked — NC lane dropped from aggregation")
        for args, _kwargs in self.review_calls:
            self.assertTrue(args[2], "review check ran with is_mutation=False")
        for args, _kwargs in self.nc_calls:
            self.assertTrue(args[1], "NC check ran with is_mutation=False")

    def _manifest(self, lighting="lit", nc=None, commands=None):
        m = {"unit": "slice-2",
             "base_sha": self.base_sha, "head_sha": self.head_sha,
             "contract": {"source": self.contract, "digest": self.digest,
                          "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1"),
             "pr": {"number": 7, "reviewed_sha": self.head_sha},
             "negative_control": nc or {"tool": "mutmut", "result": "KILLED", "mutant": "m7",
                                        "artifact": self.nc_artifact},
             # The content-bound ledger: an exit-0 run whose wtree is head_sha's tree, carrying the
             # cmd_sha256 evidence-run.py writes. Since #279 the replayed command comes from the
             # coordinator's --nc-command and must AGREE with the manifest's — and since #352 a
             # fresh record must be FOR that command: a unit does not get to nominate what proves it.
             "commands": commands if commands is not None else [
                 {"label": "tests", "cmd": self.proof_cmd,
                  "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
                  "exit": 0, "wtree": self.head_tree,
                  "artifact": self.nc_artifact}],
             "intent": {"goal": "land the change", "ruled_out": "the alternatives",
                        "why": "the criterion demands it"},
             "reviewer_mode": "cross-vendor"}
        if lighting is not None:  # None = omit the key entirely (#169: omission means lit)
            m["lighting"] = lighting
        path = self.repo / "manifest.json"
        path.write_text(json.dumps(m), encoding="utf-8")
        return str(path)

    def _revert_nc(self):
        """A real, EXECUTABLE negative control: restore app.py from base_sha and the bound proof
        command must go RED."""
        return {"tool": "revert", "result": "RED — the bound test failed under the control",
                "artifact": self.nc_artifact, "command": self.proof_cmd, "paths": ["app.py"]}

    def _run_main(self, path, *extra):
        if "--execute-nc" not in extra and "--dispatch-record" not in extra:
            extra = (*extra, "--allow-static-nc")
        buf, errbuf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            rc = verify.main(["--manifest", path,
                              "--contract-source", self.contract,
                              "--contract-digest", self.digest,
                              "--unit-class", "mutation", *extra])
        return rc, buf.getvalue(), errbuf.getvalue()


class EndToEndMutationGreen(MutationFixture):
    """#183: a complete mutation manifest must drive verify() to GREEN (exit 0) END-TO-END — every
    mutation lane (scope, SHAs, review, negative control, intent, lighting, reviewer_mode) passing
    simultaneously through the aggregation's NOTE/fatal partition. Only the GitHub fetch seam
    (fetch_reviews / fetch_pr_author) is mocked; every other check re-derives from real authorities
    (a temp git repo for the SHAs, the frozen contract, the NC artifact). Component tests cover
    each lane; this is the only net for their composition — a partition or NOTE-wording regression
    (a pass path that stops starting with "NOTE:") flips these tests red."""

    def _run_main(self, path, *extra):
        return super()._run_main(path, "--repo", "o/r", *extra)

    def test_full_pass_mutation_manifest_is_green_end_to_end(self):
        path = self._manifest()
        out, err = verify.verify(path, self.contract, self.digest, repo="o/r",
                                 unit_class="mutation", lighting="lit", allow_static_nc=True)
        self.assertIsNone(err)
        fatal, notes = out
        self.assertEqual(fatal, [], fatal)
        self._assert_mutation_lanes_ran()

    def test_main_exits_0_with_verify_ok(self):
        path = self._manifest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = verify.main(["--manifest", path,
                              "--contract-source", self.contract,
                              "--contract-digest", self.digest,
                              "--repo", "o/r",
                              "--unit-class", "mutation",
                              "--lighting", "lit",
                              "--allow-static-nc"])
        self.assertEqual(rc, 0)
        self.assertIn("verify: OK", buf.getvalue())
        self._assert_mutation_lanes_ran()

    def test_dark_eligible_with_an_executed_revert_is_green(self):
        # #255 + #256, the whole point: the review-waived lane goes GREEN only when the negative
        # control is REALLY EXECUTED — app.py restored from base_sha in a throwaway worktree at
        # head_sha, the bound command RED there and GREEN at clean head_sha.
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc())
        rc, out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                      "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, err)
        self.assertIn("negative control EXECUTED", out)
        self.assertIn("exits 0 at clean head_sha", out)
        self.assertIn("dark-eligible", out)
        self._assert_mutation_lanes_ran()

    def test_dark_eligible_without_execute_nc_is_red(self):
        # docs/reviews/2026-09-10-review.md A1/A4/A6/A9 replayed: the same manifest, the control merely READ.
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc())
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible")
        self.assertEqual(rc, 2)
        self.assertIn("EXECUTED", err)

    def test_tautological_control_is_red(self):
        # The control applies, but the "proof" passes anyway — it does not bind to the change it
        # claims to prove. A gate that reads artifacts can never see this.
        self.write("check.py", "import app\nassert True\n")
        head = self.commit("tautological proof")
        nc = {**self._revert_nc(), "artifact": self.nc_artifact}
        path = self._manifest(lighting="dark-eligible", nc=nc, commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.git("rev-parse", "HEAD^{tree}")}])
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        verify.fetch_reviews = lambda repo_, n: (
            [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": head, "user": {"login": "carol"}}], None)
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("TAUTOLOGICAL", err)

    def test_execute_nc_without_a_coordinator_command_is_refused(self):
        # #279. `negative_control.command` is worker-written and so is the `commands[]` ledger that
        # used to justify it, so neither can authorise the other. A12/A15 of the 2026-09-11 review
        # landed exactly here: a worker that writes both nominates its own "proof".
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc())
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc")
        self.assertEqual(rc, 2)
        self.assertIn("--execute-nc requires --nc-command", err)
        self.assertNotIn("TAUTOLOGICAL", err)  # refused before anything was executed

    def test_a_shell_command_in_the_manifest_is_never_executed(self):
        # The concrete A12 manifest: `sh -c` smuggles arbitrary argv onto the verifier's own host,
        # and the ledger fallback used to accept it as a "criterion-bound proof command". Now the
        # manifest is refused before the worktree is ever built, so the payload never runs.
        holder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holder, True)
        canary = Path(holder) / "canary"
        smuggled = f"sh -c 'touch {canary}; exit 1'"
        nc = {**self._revert_nc(), "command": smuggled}
        path = self._manifest(lighting="dark-eligible", nc=nc, commands=[
            {"label": "tests", "cmd": smuggled,
             "cmd_sha256": hashlib.sha256(smuggled.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.head_tree}])
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc")
        self.assertEqual(rc, 2)
        self.assertIn("--execute-nc requires --nc-command", err)
        self.assertFalse(canary.exists(), "the manifest's command was executed despite being refused")

    def test_a_ledger_record_whose_sha_does_not_match_is_refused(self):
        # cmd_sha256 that does not hash its own cmd binds nothing; a decorative digest would let a
        # record be edited after the fact. Since #279 the replay no longer reads this ledger, so the
        # integrity check lives in check_commands — where the ledger is actually graded.
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc(), commands=[
            {"label": "tests", "cmd": self.proof_cmd, "cmd_sha256": "0" * 64,
             "exit": 0, "wtree": self.head_tree}])
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("does not describe its own command", err)

    def test_a_stale_ledger_record_still_fails_the_commands_gate(self):
        # The ledger must still be fresh at head_sha's tree — that check is check_commands' job and
        # is unchanged by #279; only the NC replay stopped depending on it.
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc(), commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": "0" * 40}])
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("STALE evidence", err)

    def test_a_decoy_path_the_unit_never_changed_is_refused(self):
        # #280 / A13. base_sha..head_sha changes app.py only. A control that reverts decoy.py
        # instead makes the bound command go RED for a reason unrelated to the change — a
        # U-comparability violation (Lipsitch et al. 2010), read by the old gate as a kill.
        self.write("decoy.py", "VALUE = 1\n")
        self.commit("a file the unit did not change")
        nc = {**self._revert_nc(), "paths": ["decoy.py"]}
        path = self._manifest(lighting="dark-eligible", nc=nc)
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("does not change", err)

    def test_reverting_the_test_that_encodes_the_criterion_is_refused(self):
        # #280 / A13. Restoring the TEST makes the proof go RED because the oracle is gone, not
        # because the behaviour came back. diff_scope's SCOPE_TESTS rule is what names it a test.
        self.write("test_app.py", "def test_f():\n    assert True\n")
        head = self.commit("the unit also touches its test")
        nc = {**self._revert_nc(), "paths": ["test_app.py"]}
        path = self._manifest(lighting="dark-eligible", nc=nc)
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("TEST path", err)

    def test_a_hand_mutant_outside_the_change_is_refused(self):
        # #280 / A13b: the same decoy move through tool 'hand' — the quoted diff mutates a file the
        # unit's own range never touches. decoy.py must exist BEFORE base_sha for that to be true,
        # so the unit's range here runs from the commit that introduced it.
        self.write("decoy.py", "VALUE = 1\n")
        base = self.commit("decoy.py exists before this unit starts")
        art = self.artifact(
            "hand mutant applied — the bound test went RED (mutant KILLED):\n"
            "--- a/decoy.py\n+++ b/decoy.py\n@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n",
            rel="docs/reports/u/decoy.txt")
        head = self.commit("decoy hand artifact")
        nc = {"tool": "hand", "result": "RED", "artifact": art, "command": self.proof_cmd}
        path = self._manifest(lighting="dark-eligible", nc=nc, commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.git("rev-parse", "HEAD^{tree}")}])
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["base_sha"] = base
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("does not change", err)

    def test_a_hand_mutant_on_an_untouched_hunk_of_a_changed_file_is_refused(self):
        # PR #308 review. Binding by PATH alone left a decoy one level down: a production file can
        # carry both the criterion change and an unrelated one, and a mutant touching only the
        # unrelated hunk still goes RED under a broad command while the criterion stands.
        # app.py here gains an untouched helper at the top; base..head changes only f().
        self.write("app.py", "def helper():\n    return 'decoy'\n\n\ndef f():\n    return 1\n")
        base = self.commit("app.py with a helper the unit will not touch")
        self.write("app.py", "def helper():\n    return 'decoy'\n\n\ndef f():\n    return 2\n")
        self.commit("the unit changes f() only")
        art = self.artifact(
            "hand mutant applied — the bound test went RED (mutant KILLED):\n"
            "--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n"
            "-    return 'decoy'\n+    return 'mutated'\n", rel="docs/reports/u/hunk.txt")
        head = self.commit("decoy-hunk artifact")
        nc = {"tool": "hand", "result": "RED", "artifact": art, "command": self.proof_cmd}
        path = self._manifest(lighting="dark-eligible", nc=nc, commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.git("rev-parse", "HEAD^{tree}")}])
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["base_sha"] = base
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("they do not overlap", err)

    def test_a_stillborn_mutant_is_not_a_kill(self):
        # #280 / A14. The mutant makes app.py unimportable, so check.py dies on ImportError before
        # a single assertion runs. The exit is non-zero for ANY command — Vera-Perez et al. 2018:
        # a mutant the suite never exercises says nothing about the suite.
        art = self.artifact(
            "hand mutant RED:\n--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n"
            "-    return 2\n+    return (\n",
            rel="docs/reports/u/stillborn.txt")
        head = self.commit("stillborn hand artifact")
        nc = {"tool": "hand", "result": "RED", "artifact": art, "command": self.proof_cmd}
        path = self._manifest(lighting="dark-eligible", nc=nc)
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["commands"][0]["wtree"] = self.git("rev-parse", f"{head}^{{tree}}")
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("STILLBORN MUTANT", err)

    def test_a_stillborn_mutant_under_a_test_runner_is_not_a_kill(self):
        # PR #308 review, round 1. The first cut of #280 checked for an assertion marker BEFORE the
        # stillborn markers, and `python -m unittest` prints `FAILED (errors=1)` when a module
        # cannot be imported — so the word "FAILED" carried a collection error past the gate.
        for text in (
            "ERROR: test_add\nImportError: cannot import name 'f'\nRan 1 test\n\nFAILED (errors=1)\n",
            "ImportError while importing test module\nE   ModuleNotFoundError: No module named 'app'"
            "\n=========== 1 error in 0.04s ===========\n",
        ):
            ok, reason = verify._failure_signature(text, "")
            self.assertFalse(ok, f"a collection error was accepted as a kill: {text[:40]!r}")
            self.assertIn("error", reason)

    def test_an_error_only_runner_summary_is_not_a_kill(self):
        # No import word at all — just a runner reporting errors and no failures. An exception
        # escaping still does not show the criterion-bound assertion ran.
        ok, reason = verify._failure_signature(
            "ERROR: test_add\nTypeError: unsupported operand\nRan 1 test\n\nFAILED (errors=1)\n", "")
        self.assertFalse(ok)
        self.assertIn("error", reason)

    def test_a_bare_stillborn_traceback_is_not_a_kill(self):
        # No runner summary to read, so the substring scan is what refuses these.
        for text in ("Traceback (most recent call last):\n  File 'check.py'\nImportError: nope\n",
                     "Traceback (most recent call last):\nSyntaxError: invalid syntax\n"):
            ok, reason = verify._failure_signature(text, "")
            self.assertFalse(ok, f"a stillborn mutant was accepted: {text[:40]!r}")
            self.assertIn("STILLBORN", reason)

    def test_an_assertion_that_merely_names_an_import_error_is_a_kill(self):
        # PR #308 review, round 2: the opposite mistake. Refusing on any mention of a stillborn
        # marker rejects real REDs — `assertRaises(ModuleNotFoundError)` prints that name while its
        # oracle runs perfectly well, and a pytest traceback can pass through conftest.py.
        for text in (
            "FAIL: test_guard\nAssertionError: ModuleNotFoundError not raised\n\nFAILED (failures=1)\n",
            "tests/conftest.py:12: in fixture\nE   assert 4 == 0\n=== 1 failed in 0.03s ===\n",
            "Traceback (most recent call last):\nAssertionError: ModuleNotFoundError not raised\n",
        ):
            ok, reason = verify._failure_signature(text, "")
            self.assertTrue(ok, f"a real assertion failure was refused: {reason}")

    def test_an_assert_echoed_in_a_traceback_is_not_an_assertion_that_ran(self):
        # PR #308 review, round 3 (security). A collection traceback QUOTES the source it was
        # reading when the import blew up, so "    assert helper() == 1" appears in the output
        # while the assertion never evaluated. An unanchored substring read that as proof an
        # oracle ran, which handed the waiver lanes a stillborn control.
        for text in (
            "ImportError while importing test module '/x/tests/test_calc.py'.\n"
            "tests/test_calc.py:3: in <module>\n    assert helper() == 1\n"
            "E   ModuleNotFoundError: No module named 'calc'\n",
            "Traceback (most recent call last):\n  File 'check.py', line 3\n"
            "    assert app.f() == 2\nImportError: no module named app\n",
        ):
            ok, reason = verify._failure_signature(text, "")
            self.assertFalse(ok, f"echoed source was read as a failing assertion: {text[:50]!r}")
            self.assertIn("STILLBORN", reason)

    def test_a_pytest_failing_assertion_line_still_overrides_a_stillborn_word(self):
        # The line pytest prefixes with `E` is the assertion that FAILED; the source it quotes
        # carries no prefix. That distinction is what makes the override safe to keep.
        ok, reason = verify._failure_signature(
            "tests/conftest.py:3: in <module>\nE   assert 4 == 0\n", "")
        self.assertTrue(ok, f"a real pytest assertion failure was refused: {reason}")

    def test_a_real_assertion_failure_is_still_a_kill(self):
        # The positive direction: the tightening must not make every control RED.
        for text in ("FAIL: test_add\nAssertionError: 4 != 0\n\nFAILED (failures=1)\n",
                     "=========== 1 failed in 0.02s ===========\nE   assert 4 == 0\n",
                     "Traceback (most recent call last):\nAssertionError: AC-1 violated\n",
                     "FAILED (failures=1, errors=1)\nAssertionError: x\n"):
            ok, reason = verify._failure_signature(text, "")
            self.assertTrue(ok, f"a real assertion failure was refused: {reason}")

    def test_a_range_revert_that_would_remove_a_test_module_is_refused(self):
        # #280 / A14b + A21. With no paths the fallback reverts the whole range — taking the test
        # module the unit added with it. The bound command then fails because its oracle is gone.
        self.write("test_new.py", "def test_f():\n    assert True\n")
        head = self.commit("the unit adds a test module")
        nc = {k: v for k, v in self._revert_nc().items() if k != "paths"}
        path = self._manifest(lighting="dark-eligible", nc=nc)
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["commands"][0]["wtree"] = self.git("rev-parse", f"{head}^{{tree}}")
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("changes test paths", err)

    def test_coordinator_nc_command_overrides_and_must_agree(self):
        # --contract-source's shape, for the proof command: the coordinator supplies it out of
        # band, and a manifest that names a different one is refused rather than silently obeyed.
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc())
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", "/bin/true")
        self.assertEqual(rc, 2)
        self.assertIn("is not the command the coordinator supplied out of band", err)

    def test_coordinator_nc_command_that_agrees_is_accepted(self):
        path = self._manifest(lighting="dark-eligible", nc=self._revert_nc())
        rc, out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                      "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, err)
        self.assertIn("negative control EXECUTED", out + err)

    def test_executed_control_needs_a_bound_command(self):
        nc = {k: v for k, v in self._revert_nc().items() if k != "command"}
        path = self._manifest(lighting="dark-eligible", nc=nc)
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("negative_control.command", err)

    def test_executed_hand_control_applies_the_quoted_diff(self):
        # `hand`'s only binding to a mutation is the diff quoted in its artifact — so EXECUTING it
        # means applying exactly that diff. A fabricated diff (docs/reviews/2026-09-10-review.md A4) will not apply.
        diff = self.git("diff", f"{self.head_sha}..{self.base_sha}", "--", "app.py")
        art = self.artifact("hand mutant applied — the bound test went RED\n\n" + diff + "\n",
                            rel="docs/reports/u/hand.txt")
        self.commit("hand nc artifact")
        nc = {"tool": "hand", "result": "RED", "artifact": art, "command": self.proof_cmd}
        path = self._manifest(lighting="dark-eligible", nc=nc, commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.git("rev-parse", "HEAD^{tree}")}])
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        head = self.git("rev-parse", "HEAD")
        manifest["head_sha"] = head
        manifest["pr"]["reviewed_sha"] = head
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        verify.fetch_reviews = lambda repo_, n: (
            [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": head, "user": {"login": "carol"}}], None)
        rc, out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                      "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, err)
        self.assertIn("negative control EXECUTED", out)

    def test_fabricated_hand_diff_does_not_apply(self):
        # The hunk lands on the line the unit changed (app.py:2), so it clears the #280 hunk
        # binding and the refusal that follows is the one this test is about: the quoted content
        # is not what is there, so the diff does not apply.
        art = self.artifact(
            "hand mutant applied:\n--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n"
            "-    return something_that_is_not_there\n+    return other\n"
            "the bound test went RED (mutant killed)\n", rel="docs/reports/u/hand.txt")
        self.commit("fabricated hand artifact")
        nc = {"tool": "hand", "result": "RED", "artifact": art, "command": self.proof_cmd}
        path = self._manifest(lighting="dark-eligible", nc=nc, commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.git("rev-parse", "HEAD^{tree}")}])
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["head_sha"] = self.git("rev-parse", "HEAD")
        manifest["pr"]["reviewed_sha"] = manifest["head_sha"]
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path, "--lighting", "dark-eligible", "--execute-nc",
                                       "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("does not apply at head_sha", err)

    def test_stale_commands_ledger_is_red(self):
        # A recorded run on OTHER content does not certify this head (audit §3 item 3).
        path = self._manifest(commands=[{"label": "tests", "cmd": self.proof_cmd, "exit": 0,
                                         "wtree": "0" * 40}])
        rc, _out, err = self._run_main(path)
        self.assertEqual(rc, 2)
        self.assertIn("STALE evidence", err)

    def test_a_fresh_record_of_the_wrong_command_fails_when_the_coordinator_named_one(self):
        # #352: `evidence-run.py -- true` is content-bound and exit-0, and proved nothing.
        # When the coordinator names the proof command out of band, the ledger must show THAT
        # command green on this content.
        decoy = "true"
        path = self._manifest(commands=[{"label": "tests", "cmd": decoy,
                                         "cmd_sha256": hashlib.sha256(decoy.encode()).hexdigest(),
                                         "exit": 0, "wtree": self.head_tree}])
        rc, _out, err = self._run_main(path, "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 2)
        self.assertIn("none is the coordinator-named proof command", err)

    def test_a_fresh_record_of_the_named_command_still_passes(self):
        # The same manifest that is green without --nc-command stays green when the coordinator
        # names the very command the ledger records.
        path = self._manifest()
        rc, _out, err = self._run_main(path, "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, err)

    def test_missing_commands_ledger_is_red(self):
        path = self._manifest(commands=[])
        rc, _out, err = self._run_main(path)
        self.assertEqual(rc, 2)
        self.assertIn("no recorded command", err)

    def test_credential_in_an_artifact_fails_the_unit(self):
        # #14: evidence is SHA-pinned and permanent, so a leaked credential in it is permanent.
        self.artifact("mutant m7 was KILLED — proof went RED\n"
                      "run with AKIA" + "Q" * 16 + " exported\n")
        self.commit("leaky artifact")
        path = self._manifest()
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest["head_sha"] = self.git("rev-parse", "HEAD")
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        rc, _out, err = self._run_main(path)
        self.assertEqual(rc, 2)
        self.assertIn("redaction", err)

    def test_credential_in_a_commands_artifact_fails_the_unit(self):
        # #309: `commands[].artifact` is where a run's captured stdout lands, which makes it the
        # likeliest place for a token to end up — and it was the one named path check_redaction
        # never scanned. Everything else about this manifest is clean, so a green here means the
        # secret got SHA-pinned into permanent evidence unnoticed.
        leak = self.artifact("aws_secret_access_key = AKIA" + "Q" * 16 + "\n",
                             rel="docs/reports/u/run.log")
        self.commit("a command log with a credential in it")
        # Re-point the fixture at the new head. The review stub closes over self.head_sha, so
        # this keeps the review fresh too — without it the unit is red for a stale review and
        # the test would pass while proving nothing about redaction.
        self.head_sha = self.git("rev-parse", "HEAD")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        path = self._manifest(commands=[
            {"label": "tests", "cmd": self.proof_cmd,
             "cmd_sha256": hashlib.sha256(self.proof_cmd.encode("utf-8")).hexdigest(),
             "exit": 0, "wtree": self.head_tree, "artifact": leak}])
        rc, out, err = self._run_main(path)
        self.assertEqual(rc, 2, f"a credential in commands[].artifact passed: {out}")
        # Name the path, not just "redaction" — otherwise any unrelated FAIL satisfies this.
        self.assertTrue(any("redaction" in line and leak in line
                            for line in err.splitlines()),
                        f"no redaction FAIL naming {leak}: {err}")

    def _downgraded(self):
        """The #310 attack manifest: a real code change stripped of every mutation obligation."""
        path = self._manifest()
        m = json.loads(Path(path).read_text(encoding="utf-8"))
        for key in ("negative_control", "intent", "reviewer_mode"):
            m.pop(key, None)
        Path(path).write_text(json.dumps(m), encoding="utf-8")
        return path

    def _main(self, path, *extra):
        buf, errbuf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            rc = verify.main(["--manifest", path, "--contract-source", self.contract,
                              "--contract-digest", self.digest, "--repo", "o/r", *extra])
        return rc, buf.getvalue(), errbuf.getvalue()

    def test_unsupervised_report_only_cannot_shed_a_code_change(self):
        # #310: unit_class arrives from ORCA_UNIT_CLASS on the native in-session path, and the
        # worker owns its own environment. One env var dropped the negative control, the intent
        # packet, lighting legality and reviewer_mode — for a unit whose own base..head changes
        # production code. The same manifest is 7 FAILs as `mutation`.
        path = self._downgraded()
        rc_mut, _o, err_mut = self._main(path, "--unit-class", "mutation")
        self.assertEqual(rc_mut, 2, "the attack manifest is supposed to be red as a mutation")
        self.assertGreaterEqual(len([ln for ln in err_mut.splitlines()
                                     if ln.startswith("FAIL:")]), 4, err_mut)

        rc, out, err = self._main(path, "--unit-class", "report-only")
        self.assertEqual(rc, 2, f"a code change passed clean as report-only: {out}")
        self.assertIn("report-only", err)
        self.assertIn("app.py", err, f"the refusal must name the code it changed: {err}")

    def test_unsupervised_report_only_that_changes_no_code_is_marked_not_refused(self):
        # The honest case still works, but never silently: a report-only unit names the range its
        # report covers, that range carries no code, and the verdict records that nothing
        # off-worker authorized the class.
        doc_base = self.head_sha
        self.write("docs/report.md", "# what I found\n")
        doc_head = self.commit("the report")
        self.head_sha = doc_head   # keeps the review stub fresh (it closes over self.head_sha)
        path = self._downgraded()
        m = json.loads(Path(path).read_text(encoding="utf-8"))
        m["base_sha"] = doc_base
        Path(path).write_text(json.dumps(m), encoding="utf-8")
        rc, out, _err = self._main(path, "--unit-class", "report-only")
        self.assertEqual(rc, 0, out)
        self.assertIn("report-only (unsupervised)", out,
                      f"an unsigned downgrade must be marked in the verdict: {out}")

    def test_unsupervised_report_only_cannot_declare_an_empty_range(self):
        # PR #308 review, P1. base_sha and head_sha are the worker's too, so a unit that changed
        # production code in commit C declares base = head = C: the diff is empty, no code shows
        # up, and every mutation obligation is shed. The first cut of this check passed it with an
        # advisory note, reasoning that an empty range changes nothing — true of the declared
        # range, silent about the work.
        path = self._downgraded()
        m = json.loads(Path(path).read_text(encoding="utf-8"))
        m["base_sha"] = m["head_sha"]
        Path(path).write_text(json.dumps(m), encoding="utf-8")
        rc, out, err = self._main(path, "--unit-class", "report-only")
        self.assertEqual(rc, 2, f"an empty declared range passed: {out}")
        self.assertIn("base_sha == head_sha", err)

    def test_a_code_file_under_a_docs_directory_is_still_code(self):
        # PR #308 review, P1. The first cut asked diff_scope's PATH_RULES whether a path looked
        # like docs or tests. Those patterns match NAMES, so `src/docs/parser.py` matched DOCS and
        # `src/test_runner.py` matched TESTS, and either carried an unsigned downgrade through.
        for rel in ("src/docs/parser.py", "src/test_runner.py", "tests/test_x.py"):
            with self.subTest(path=rel):
                base = self.head_sha
                self.write(rel, "def f():\n    return 1\n")
                head = self.commit(f"add {rel}")
                prod, err = verify._production_changes(base, head)
                self.assertIsNone(err, err)
                self.assertEqual(prod, [rel], f"{rel} must count as code")
                self.head_sha = head

    def test_prose_is_decided_by_extension(self):
        base = self.head_sha
        self.write("src/notes.md", "# notes\n")
        head = self.commit("a note inside src/")
        prod, err = verify._production_changes(base, head)
        self.assertIsNone(err, err)
        self.assertEqual(prod, [], "a .md file is prose wherever it lives")

    def test_removing_the_empty_range_branch_would_not_have_been_enough(self):
        # Recorded because the review localized the fix to the equal-SHA branch, and deleting that
        # branch does NOT close the attack: a pinned equal range diffs empty, so the unit lands on
        # the no-code path and passes anyway. What closes it is demanding a NON-DEGENERATE range.
        # This asserts the underlying fact, so the reasoning cannot rot silently.
        prod, err = verify._production_changes(self.head_sha, self.head_sha)
        self.assertIsNone(err, "an equal pinned range resolves fine — that is the problem")
        self.assertEqual(prod, [], "an equal range diffs empty, so 'no code changed' is vacuous")

    def test_omitted_lighting_is_lit_end_to_end(self):
        # #169: a mutation manifest with no lighting key verifies clean — omission means lit.
        path = self._manifest(lighting=None)
        out, err = verify.verify(path, self.contract, self.digest, repo="o/r",
                                 unit_class="mutation", lighting="lit", allow_static_nc=True)
        self.assertIsNone(err)
        fatal, notes = out
        self.assertEqual(fatal, [], fatal)
        self._assert_mutation_lanes_ran()

    def test_omitted_lighting_with_dark_dispatch_fails_end_to_end(self):
        # #169: the swap interaction — dispatch used the dark waiver but the omitted manifest
        # lighting implies lit, so the aggregate is fatal (exit 2).
        path = self._manifest(lighting=None)
        out, err = verify.verify(path, self.contract, self.digest, repo="o/r",
                                 unit_class="mutation", lighting="dark-eligible")
        self.assertIsNone(err)
        fatal, notes = out
        self.assertTrue(any("swap" in f for f in fatal), fatal)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = verify.main(["--manifest", path,
                              "--contract-source", self.contract,
                              "--contract-digest", self.digest,
                              "--repo", "o/r",
                              "--unit-class", "mutation",
                              "--lighting", "dark-eligible"])
        self.assertEqual(rc, 2)
        self._assert_mutation_lanes_ran()

    def test_admission_rejects_before_any_nc_execution(self):
        for rejection in ('scope', 'sha', 'signature', 'shape'):
            with self.subTest(rejection=rejection):
                path = self._manifest(nc=self._revert_nc())
                m = json.loads(Path(path).read_text())
                kwargs = {}
                if rejection == 'scope':
                    m['criteria'] = []
                elif rejection == 'sha':
                    m['head_sha'] = 'f' * 40
                elif rejection == 'shape':
                    m['negative_control'] = ['invalid']
                else:
                    rec, pk = DispatchProvenance._signed(self,
                        {'manifest_id': m['unit'], 'contract_digest': self.digest,
                         'unit_class': 'mutation'}, sign_key=bytes(range(100, 132)))
                    kwargs = {'dispatch_record': rec, 'dispatch_pubkey': pk}
                Path(path).write_text(json.dumps(m))
                with mock.patch.object(verify, 'execute_negative_control', return_value=(True, [])) as execute, \
                        mock.patch.object(verify, '_apply_control') as apply, \
                        mock.patch.object(verify, '_run_at') as run_at:
                    result, err = verify.verify(path, self.contract, self.digest,
                        repo='o/r', unit_class='mutation', execute_nc=True,
                        nc_command=self.proof_cmd, **kwargs)
                    self.assertIsNone(err)
                    self.assertTrue(result[0])
                    execute.assert_not_called()
                    apply.assert_not_called()
                    run_at.assert_not_called()

    def test_noncommit_tree_sha_is_the_only_admission_rejection(self):
        # A tree OID resolves all blobs and diff/ledger trees, but is not a commit. Unlike an
        # invented missing SHA, it leaves artifact, scope, freshness and ledger checks admissible.
        for head, rejected in ((self.head_sha, False), (self.head_tree, True)):
            with self.subTest(rejected=rejected):
                self.head_sha = head  # also keeps the independent review fixture at this identity
                path = self._manifest(nc=self._revert_nc())
                with mock.patch.object(verify, 'execute_negative_control', return_value=(True, [])) as execute, \
                        mock.patch.object(verify, '_apply_control') as apply, \
                        mock.patch.object(verify, '_run_at') as run_at:
                    result, err = verify.verify(path, self.contract, self.digest, repo='o/r',
                        unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
                    self.assertIsNone(err)
                    self.assertEqual(result[0], [f"head_sha '{head}' is not a real commit"] if rejected else [])
                    if rejected:
                        execute.assert_not_called()
                    else:
                        execute.assert_called_once()
                    apply.assert_not_called()
                    run_at.assert_not_called()

    def test_wrong_base_rejects_before_executor_worktree_or_patch(self):
        path = self._manifest(nc=self._revert_nc())
        for tip, accepted in ((self.base_sha, False), (self.head_sha, True)):
            with self.subTest(accepted=accepted):
                self.git('update-ref', 'refs/remotes/origin/integration', tip)
                with mock.patch.object(verify, 'execute_negative_control',
                                       wraps=verify.execute_negative_control) as execute, \
                        mock.patch.object(verify, '_apply_control', wraps=verify._apply_control) as apply, \
                        mock.patch.object(verify, '_run', wraps=verify._run) as run, \
                        mock.patch.object(verify, '_run_at', wraps=verify._run_at) as run_at:
                    result, err = verify.verify(path, self.contract, self.digest, repo='o/r',
                        base='integration', unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
                    self.assertIsNone(err)
                    self.assertEqual(result[0], [] if accepted else [
                        'head_sha is not an ancestor of origin/integration (not merged / wrong base)'])
                    if accepted:
                        execute.assert_called_once()
                        apply.assert_called_once()
                        self.assertEqual(sum(c.args[1] == shlex.split(self.proof_cmd)
                                             for c in run_at.call_args_list), 3)  # clean/control/clean
                    else:
                        execute.assert_not_called()
                        apply.assert_not_called()
                        run_at.assert_not_called()
                        self.assertFalse(any('worktree' in c.args[0] for c in run.call_args_list))

    def test_signed_replay_uses_pinned_patch_with_divergent_or_missing_checkout(self):
        diff = '--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n-    return 2\n+    return 1\n'
        self.write(self.nc_artifact, 'RED\n' + diff)
        self.head_sha = self.commit('pin the signed hand mutant')
        self.head_tree = self.git('rev-parse', 'HEAD^{tree}')
        nc = {'tool': 'hand', 'artifact': self.nc_artifact, 'result': 'RED', 'command': self.proof_cmd}
        path = self._manifest(nc=nc)
        rec, pk = DispatchProvenance._signed(self, {
            'manifest_id': 'slice-2', 'contract_digest': self.digest, 'unit_class': 'mutation',
            'lighting': 'lit', 'nc_command': self.proof_cmd,
            'nc_artifact_sha256': hashlib.sha256(('RED\n' + diff).encode()).hexdigest()})
        original = verify._run_at
        for missing in (False, True):
            with self.subTest(missing=missing):
                if missing:
                    Path(self.nc_artifact).unlink()
                else:
                    # Both mutants kill the same proof; final exits alone cannot identify which ran.
                    self.write(self.nc_artifact, 'RED\n' + diff.replace('return 1', 'return 0'))
                applied, runs = [], []
                def observe(wt, argv, applied=applied, runs=runs, **kwargs):
                    if argv == shlex.split(self.proof_cmd):
                        applied.append((Path(wt) / 'app.py').read_text())
                    result = original(wt, argv, **kwargs)
                    if argv == shlex.split(self.proof_cmd):
                        runs.append(result)
                    return result
                with mock.patch.object(verify, '_run_at', side_effect=observe):
                    result, err = verify.verify(path, self.contract, self.digest, repo='o/r',
                        unit_class='mutation', lighting='lit', execute_nc=True,
                        nc_command=self.proof_cmd, dispatch_record=rec, dispatch_pubkey=pk)
                self.assertIsNone(err)
                self.assertEqual(result[0], [])
                # clean -> control -> clean (review P1)
                self.assertEqual(applied, ['def f():\n    return 2\n', 'def f():\n    return 1\n',
                                           'def f():\n    return 2\n'])
                self.assertEqual([r[0] for r in runs], [0, 1, 0])
                self.assertIn('AssertionError', runs[1][2])
                self.assertTrue(any('signature verified' in n for n in result[1]), result)

    def test_rejected_manifest_keeps_static_replay_diagnostics(self):
        path = self._manifest(commands=[])
        with mock.patch.object(verify, 'execute_negative_control') as execute:
            result, err = verify.verify(path, self.contract, self.digest, repo='o/r',
                unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
            self.assertIsNone(err)
            self.assertTrue(any('no replay is implemented' in e for e in result[0]), result)
            execute.assert_not_called()

    def test_unexecuted_nc_discloses_static_corroboration_note_c10(self):
        # #750 C10: an ordinary GitHub-reviewed mutation unit fails closed without --execute-nc
        # unless --allow-static-nc is explicitly supplied; when waived, the verdict discloses that
        # the negative control was corroborated from the artifact only.
        path = self._manifest()
        (fatal_default, _), err_default = verify.verify(
            path, self.contract, self.digest, repo='o/r', unit_class='mutation', execute_nc=False)
        self.assertIsNone(err_default)
        self.assertTrue(any('negative control was NOT executed' in f for f in fatal_default),
                        fatal_default)
        errbuf = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errbuf):
            rc_default = verify.main(['--manifest', path, '--contract-source', self.contract,
                                      '--contract-digest', self.digest, '--repo', 'o/r',
                                      '--unit-class', 'mutation'])
        self.assertEqual(rc_default, 2, errbuf.getvalue())
        (fatal, notes), err = verify.verify(path, self.contract, self.digest, repo='o/r',
                                            unit_class='mutation', execute_nc=False,
                                            allow_static_nc=True)
        self.assertIsNone(err)
        self.assertEqual(fatal, [], fatal)
        self.assertTrue(any('corroborated from artifact only (--execute-nc not set)' in n
                            for n in notes), notes)

    def test_all_six_mutation_tools_replay_when_artifact_quotes_diff_c11(self):
        # #750 C11: all six named mutation tools (mutmut, cosmic-ray, stryker, pitest,
        # cargo-mutants, go-mutesting) replay deterministically under --execute-nc when their
        # artifact quotes the mutant's unified diff, and fail closed when it does not.
        diff = '--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n-    return 2\n+    return 1\n'
        for tool in ('mutmut', 'cosmic-ray', 'stryker', 'pitest', 'cargo-mutants', 'go-mutesting'):
            with self.subTest(tool=tool):
                self.write(self.nc_artifact, f'mutant m#7 was KILLED\n{diff}')
                self.head_sha = self.commit(f'pin {tool} diff')
                self.head_tree = self.git('rev-parse', 'HEAD^{tree}')
                nc = {'tool': tool, 'mutant': 'm#7', 'artifact': self.nc_artifact,
                      'result': 'KILLED', 'command': self.proof_cmd}
                path = self._manifest(nc=nc)
                (fatal, notes), err = verify.verify(
                    path, self.contract, self.digest, repo='o/r',
                    unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
                self.assertIsNone(err)
                self.assertEqual(fatal, [], fatal)
                self.assertTrue(any(f'with the {tool} control applied' in n for n in notes), notes)

    def test_quiet_oss_contribute_pr_verifies_with_review_artifact_and_executed_nc_c15(self):
        # #750 C15: an oss-contribute unit parked awaiting-maintainer-merge has no upstream
        # OWNER/MEMBER/COLLABORATOR approval while feedback is quiet; it verifies when
        # review.artifact binds head_sha, no upstream CHANGES_REQUESTED veto exists, the
        # coordinator contract is corroborated, and the negative control is EXECUTED.
        rev_rel = 'docs/reports/u/review.md'
        rev_bytes = f'Internal review PASS at {self.head_sha}\n'.encode('utf-8')
        (self.repo / rev_rel).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / rev_rel).write_bytes(rev_bytes)
        oss_contract = self.write('oss-contract.json', json.dumps({
            'mission': 'oss-contribute', 'criterion_ids': ['AC-1'],
        }))
        oss_digest = 'sha256:' + hashlib.sha256(
            (self.repo / oss_contract).read_bytes()).hexdigest()
        path = self._manifest(nc=self._revert_nc())
        m = json.loads(Path(path).read_text(encoding='utf-8'))
        m['parked'] = [{'item': 'upstream merge', 'reason': 'awaiting-maintainer-merge'}]
        m['review'] = {'artifact': rev_rel}
        m['artifacts'] = [{'path': rev_rel, 'sha256': hashlib.sha256(rev_bytes).hexdigest()}]
        m['contract'] = {'source': oss_contract, 'digest': oss_digest, 'criterion_ids': ['AC-1']}
        Path(path).write_text(json.dumps(m), encoding='utf-8')
        with mock.patch.object(verify, 'fetch_reviews', return_value=([], None)):
            # Non-oss-contribute contract cannot self-waive GitHub review:
            m_plain = dict(m, contract={'source': self.contract, 'digest': self.digest,
                                        'criterion_ids': ['AC-1']})
            plain_path = self.write('plain-manifest.json', json.dumps(m_plain))
            (fatal_plain, _), _ = verify.verify(
                plain_path, self.contract, self.digest, repo='o/r',
                unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
            self.assertTrue(any('no INDEPENDENT APPROVED review' in f for f in fatal_plain),
                            fatal_plain)
            (fatal, notes), err = verify.verify(
                path, oss_contract, oss_digest, repo='o/r',
                unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
            self.assertIsNone(err)
            self.assertEqual(fatal, [], fatal)
            self.assertTrue(any('oss-contribute quiet PR (awaiting-maintainer-merge)' in n
                                for n in notes), notes)
            # Without --execute-nc, quiet oss-contribute PR fails closed:
            (fatal_no_nc, _), _ = verify.verify(
                path, oss_contract, oss_digest, repo='o/r',
                unit_class='mutation', execute_nc=False)
            self.assertTrue(any('no INDEPENDENT APPROVED review' in f for f in fatal_no_nc),
                            fatal_no_nc)
        # With an upstream CHANGES_REQUESTED veto, quiet oss-contribute PR fails closed:
        veto = [{'user': {'login': 'upstream-maint'}, 'author_association': 'OWNER',
                 'state': 'CHANGES_REQUESTED', 'commit_id': self.head_sha}]
        with mock.patch.object(verify, 'fetch_reviews', return_value=(veto, None)):
            (fatal_veto, _), _ = verify.verify(
                path, oss_contract, oss_digest, repo='o/r',
                unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
            self.assertTrue(any('no INDEPENDENT APPROVED review' in f for f in fatal_veto),
                            fatal_veto)

    def test_mutable_or_worktree_proof_executable_fails_closed_c19(self):
        # #750 C19: a proof executable inside the repository worktree or one whose binary identity
        # changes across phases must fail closed under --execute-nc.
        wt_bin = self.repo / 'bin' / 'pytest'
        wt_bin.parent.mkdir(parents=True, exist_ok=True)
        wt_bin.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        wt_bin.chmod(0o755)
        recs, err = verify._Authority.nc_exec_identity([str(wt_bin)], str(self.repo))
        self.assertIsNone(recs)
        self.assertIn('resolves inside the repository worktree', err)
        # Shell -c, env lookup/split bypasses, and group/world-writable binaries also fail closed:
        recs_sh, err_sh = verify._Authority.nc_exec_identity(
            ['env', 'FOO=1', 'sh', '-c', 'exit 1'], str(self.repo))
        self.assertIsNone(recs_sh)
        self.assertIn('shell -c', err_sh)
        for bad_env_argv in (
            ['env', 'PATH=./bin:/usr/bin:/bin', 'python3', 'test.py'],
            ['env', 'LD_AUDIT=/tmp/audit.so', 'python3', 'proof.py'],
            ['env', 'GLIBC_TUNABLES=glibc.rtld.audit=/tmp/audit.so', 'python3', 'proof.py'],
            ['env', 'PYTHONSAFEPATH=1', sys.executable, '-m', 'runner'],
            ['env', 'PYTHONPYCACHEPREFIX=/tmp/cache', sys.executable, 'proof.py'],
            ['env', 'SHELLOPTS=keyword', 'bash', './proof.sh'],
            ['bash', '-eo', 'keyword', '/tmp/external_proof.sh'],
            ['node', 'inspect', '/tmp/external_proof.js'],
            ['deno', 'run', '/tmp/external_proof.ts'],
            ['env', '-S', 'sh -c true'],
            ['env', '-i', 'python3', 'test.py'],
            ['env', '-C', '/tmp', 'python3', 'test.py'],
            ['env', '-u', 'PATH', 'python3', 'test.py'],
            ['sh', 'proof.sh'],
            ['sh', '/tmp/external_proof.sh'],
            [sys.executable, '/tmp/external_proof.py'],
            [sys.executable, '-W', 'ignore', '/tmp/external_proof.py'],
            ['node', '--no-warnings', '/tmp/external_proof.js'],
            ['pytest', '-c', '/tmp/external_pytest.ini'],
            ['pytest', '-otestpaths=/opt/evil'],
            ['pytest', '-opythonpath=/opt/evil'],
            ['pytest', '-o', 'testpaths=/opt/evil'],
            ['pytest', '-o', 'pythonpath=/opt/evil'],
            ['pytest', '--override-ini=pythonpath=/opt/evil'],
            [sys.executable, '-m', 'pytest', '-otestpaths=/opt/evil'],
            [sys.executable, '-m', 'unittest', 'discover', '-s', '/opt/evil'],
            ['grep', 'FIXED', '/opt/evil/app.py'],
        ):
            recs_bad, err_bad = verify._Authority.nc_exec_identity(bad_env_argv, str(self.repo))
            self.assertIsNone(recs_bad, bad_env_argv)
            self.assertIn('fail-closed', err_bad)
        # Missing/untracked shell proof script `./missing.sh` fails closed before phase execution:
        untracked_sh = self.repo / 'missing.sh'
        untracked_sh.write_text('#!/bin/sh\nexit 1\n', encoding='utf-8')
        m_untracked_sh = {
            'base_sha': self.base_sha,
            'head_sha': self.head_sha,
            'negative_control': {
                'tool': 'revert',
                'paths': ['app.py'],
                'command': 'sh ./missing.sh',
            },
        }
        ok_ush, msgs_ush = verify.execute_negative_control(m_untracked_sh, 'sh ./missing.sh')
        self.assertFalse(ok_ush, msgs_ush)
        self.assertTrue(any('not a tracked regular file in head_sha' in x for x in msgs_ush), msgs_ush)
        untracked_sh.unlink()
        # Tracked regular shell proof script `sh ./proof.sh` and hidden `.ci/proof.sh` succeed across clean -> control -> clean:
        self.write('proof.sh', f'#!/bin/sh\nexec {shlex.quote(sys.executable)} check.py\n')
        self.write('.ci/proof.sh', f'#!/bin/sh\nexec {shlex.quote(sys.executable)} check.py\n')
        sh_head = self.commit('add tracked proof.sh and .ci/proof.sh')
        try:
            m_tracked_sh = {
                'base_sha': self.base_sha,
                'head_sha': sh_head,
                'negative_control': {
                    'tool': 'revert',
                    'paths': ['app.py'],
                    'command': 'sh ./proof.sh',
                },
            }
            ok_tsh, msgs_tsh = verify.execute_negative_control(m_tracked_sh, 'sh ./proof.sh')
            self.assertTrue(ok_tsh, msgs_tsh)
            for hid_cmd in ('sh .ci/proof.sh', 'sh ./.ci/proof.sh'):
                m_hid_sh = {
                    'base_sha': self.base_sha,
                    'head_sha': sh_head,
                    'negative_control': {
                        'tool': 'revert',
                        'paths': ['app.py'],
                        'command': hid_cmd,
                    },
                }
                ok_hsh, msgs_hsh = verify.execute_negative_control(m_hid_sh, hid_cmd)
                self.assertTrue(ok_hsh, msgs_hsh)
        finally:
            self.git('reset', '--hard', self.head_sha)
            shutil.rmtree(self.repo / '.ci', ignore_errors=True)
        with tempfile.TemporaryDirectory() as ext_dir:
            os.chmod(ext_dir, 0o755)
            writable_bin = Path(ext_dir) / 'runner'
            writable_bin.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            writable_bin.chmod(0o777)
            recs_w, err_w = verify._Authority.nc_exec_identity([str(writable_bin)], str(self.repo))
            self.assertIsNone(recs_w)
            self.assertIn('writable', err_w)

        # Simulate executable digest replacement between clean and control phases:
        path = self._manifest(nc=self._revert_nc())
        real_id = verify._Authority.nc_exec_identity
        calls = []
        def tampered_id(argv, top=None, path_env=None, expected=None, when=None):
            calls.append(when)
            if when == 'before control':
                return None, 'proof executable changed before control phase; fail-closed'
            return real_id(argv, top, path_env, expected, when)
        with mock.patch.object(verify._Authority, 'nc_exec_identity', side_effect=tampered_id):
            (fatal, _), err = verify.verify(
                path, self.contract, self.digest, repo='o/r',
                unit_class='mutation', execute_nc=True, nc_command=self.proof_cmd)
        self.assertIsNone(err)
        self.assertTrue(any('proof executable changed before control phase' in f for f in fatal),
                        fatal)

    def test_versioned_pypy_unittest_discovery_and_shebang_interpreter_pinning(self):
        self.write('checks/__init__.py', '')
        self.write('checks/probe.py', 'import unittest\n')
        probe_head = self.commit('add checks/probe.py')
        try:
            self.assertTrue(
                verify._is_oracle_path(
                    'checks/probe.py',
                    nc_command='pypy3.11 -m unittest checks.probe',
                    head=probe_head,
                )
            )
            self.assertTrue(
                verify._is_oracle_path(
                    'checks/probe.py',
                    nc_command='pypy-3.10 -m pytest checks/probe.py',
                    head=probe_head,
                )
            )
        finally:
            self.git('reset', '--hard', self.head_sha)
            shutil.rmtree(self.repo / 'checks', ignore_errors=True)

        wt_interp = self.repo / 'bin' / 'local-interp'
        wt_interp.parent.mkdir(parents=True, exist_ok=True)
        wt_interp.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        wt_interp.chmod(0o755)
        try:
            with tempfile.TemporaryDirectory() as ext_dir:
                os.chmod(ext_dir, 0o755)
                ext_root = Path(ext_dir)
                bad_wrap = ext_root / 'wrap-repo-interp'
                bad_wrap.write_text(f'#!{wt_interp}\nexit 0\n', encoding='utf-8')
                bad_wrap.chmod(0o755)
                recs_repo, err_repo = verify._Authority.nc_exec_identity([str(bad_wrap)], str(self.repo))
                self.assertIsNone(recs_repo)
                self.assertIn('resolves inside the repository worktree', err_repo)

                ext_interp = ext_root / 'custom-interp'
                ext_interp.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
                ext_interp.chmod(0o755)
                good_wrap = ext_root / 'wrap-ext-interp'
                good_wrap.write_text(f'#!{ext_interp}\nexit 0\n', encoding='utf-8')
                good_wrap.chmod(0o755)
                recs_init, err_init = verify._Authority.nc_exec_identity([str(good_wrap)], str(self.repo))
                self.assertIsNone(err_init, err_init)
                self.assertIsNotNone(recs_init)

                ext_interp.write_text('#!/bin/sh\nexit 1\n', encoding='utf-8')
                recs_after, err_after = verify._Authority.nc_exec_identity(
                    [str(good_wrap)], str(self.repo), expected=recs_init, when='before control'
                )
                self.assertIsNone(recs_after)
                self.assertIn('proof executable changed before control phase', err_after)

                py_alias = ext_root / 'pycheck'
                py_alias.symlink_to(sys.executable)
                recs_alias, err_alias = verify._Authority.nc_exec_identity(
                    [str(py_alias), 'tests/test_probe.py'], str(self.repo)
                )
                self.assertIsNone(recs_alias)
                self.assertIn('via alias', err_alias)

                env_bin = shutil.which('env')
                if env_bin:
                    rel_env_wrap = ext_root / 'wrap-rel-env'
                    rel_env_wrap.write_text(f'#!{env_bin} usr/bin/sh\nexit 0\n', encoding='utf-8')
                    rel_env_wrap.chmod(0o755)
                    prev_cwd = os.getcwd()
                    try:
                        os.chdir('/')
                        recs_rel_env, err_rel_env = verify._Authority.nc_exec_identity(
                            [str(rel_env_wrap)], str(self.repo)
                        )
                        recs_rel_tok, err_rel_tok = verify._Authority.nc_exec_identity(
                            ['usr/bin/sh', 'scripts/run.sh'], str(self.repo)
                        )
                    finally:
                        os.chdir(prev_cwd)
                    self.assertIsNone(recs_rel_env)
                    self.assertIn('relative shebang env target', err_rel_env)
                    self.assertIsNone(recs_rel_tok)
                    self.assertIn("relative path containing '/'", err_rel_tok)
        finally:
            shutil.rmtree(self.repo / 'bin', ignore_errors=True)


_edspec = importlib.util.spec_from_file_location("ed25519", ROOT / "runtime" / "scripts" / "ed25519.py")
ed = importlib.util.module_from_spec(_edspec)
_edspec.loader.exec_module(ed)
_dsspec = importlib.util.spec_from_file_location("dispatch_sign", ROOT / "runtime" / "scripts" / "dispatch-sign.py")
dispatch_sign = importlib.util.module_from_spec(_dsspec)
_dsspec.loader.exec_module(dispatch_sign)


class DispatchProvenance(RepoCase):
    """#135: a coordinator-signed dispatch record makes the native in-session path sound — a worker
    that substitutes the digest / class / lighting, forges the record, or omits it is caught."""

    def _signed(self, record, seed=None, sign_key=None):
        import base64
        seed = seed or bytes(range(1, 33))
        pub = ed.publickey(seed)
        sig = ed.signature(verify._canonical_dispatch(record), sign_key or seed, ed.publickey(sign_key) if sign_key else pub)
        env = {"record": record, "sig_b64": base64.b64encode(sig).decode()}
        # #267: read_source refuses absolute paths, so the record and key are named relatively —
        # which is how a real dispatch names them anyway (a repo-pinned `.orca/dispatch-pubkey`).
        return (self.write(".orca/dispatch-record.json", json.dumps(env)),
                self.write(".orca/dispatch-pubkey", pub.hex()))

    _M = {"unit": "u"}

    def test_verified_provenance_passes(self):
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation", "lighting": "lit"})
        res = verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", "lit", rec, pk)
        self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    def test_substituted_digest_caught(self):
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:REAL", "unit_class": "mutation"})
        res = verify.check_dispatch_provenance(self._M, "sha256:WEAKER", "mutation", None, rec, pk)
        self.assertTrue(any("substitution" in e and not e.startswith("NOTE:") for e in res), res)

    def test_downgraded_class_caught(self):
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"})
        res = verify.check_dispatch_provenance(self._M, "sha256:a", "report-only", None, rec, pk)
        self.assertTrue(any("substitution" in e for e in res), res)

    def test_flipped_lighting_caught(self):
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation", "lighting": "lit"})
        res = verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", "dark-eligible", rec, pk)
        self.assertTrue(any("substitution" in e for e in res), res)

    def test_replayed_record_from_another_unit_caught(self):
        # #135 review: a valid record for unit 'u' must not certify a different manifest (replay).
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"})
        res = verify.check_dispatch_provenance({"unit": "other-unit"}, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(any("does not bind this manifest" in e for e in res), res)

    def test_forged_signature_rejected(self):
        # record signed with a DIFFERENT key than the pinned pubkey → not coordinator-signed.
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"},
                               seed=bytes(range(1, 33)), sign_key=bytes(range(100, 132)))
        res = verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(any("INVALID" in e for e in res), res)

    def test_half_configured_fails_closed(self):
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"})
        res = verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", None, rec, None)
        self.assertTrue(any("half-configured" in e for e in res), res)
        res2 = verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", None, None, pk)
        self.assertTrue(any("half-configured" in e for e in res2), res2)

    def test_no_provenance_is_advisory(self):
        self.assertEqual(verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", "lit", None, None), [])

    def test_unsigned_used_field_fails_closed(self):
        # #162 review: a field the run uses but the record didn't sign is unbound — fail closed, don't
        # silently accept it (a worker could set an unsigned lighting freely).
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"})
        res = verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", "dark-eligible", rec, pk)
        self.assertTrue(any("did not sign lighting" in e for e in res), res)

    def test_signed_nc_paths_flipped_in_the_manifest_is_caught(self):
        # #311: signing (manifest_id, contract_digest, unit_class, lighting) binds the class and the
        # denominator, and leaves the worker choosing its own oracle. A coordinator that DOES know
        # which paths the control must revert can now sign them, and a flip is a substitution.
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a",
                                "unit_class": "mutation", "nc_paths": ["app.py"]})
        m = {"unit": "u", "negative_control": {"paths": ["untouched.py"]}}
        res = verify.check_dispatch_provenance(m, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(any("substitution" in e and not e.startswith("NOTE:") for e in res), res)

    def test_signed_nc_paths_matching_the_manifest_passes(self):
        # Order is not a difference: the coordinator signs a set of paths, not a listing order.
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a",
                                "unit_class": "mutation", "nc_paths": ["b.py", "a.py"]})
        m = {"unit": "u", "negative_control": {"paths": ["a.py", "b.py"]}}
        res = verify.check_dispatch_provenance(m, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    def test_signed_nc_command_flipped_in_the_manifest_is_caught(self):
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a",
                                "unit_class": "mutation", "nc_command": "pytest test_app.py"})
        m = {"unit": "u", "negative_control": {"command": "grep -q FIXED app.py"}}
        res = verify.check_dispatch_provenance(m, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(any("substitution" in e and not e.startswith("NOTE:") for e in res), res)

    def test_unsigned_nc_inputs_stay_advisory(self):
        # The coordinator usually cannot know at dispatch time which paths a fix will touch, so
        # these fields are OPTIONAL. Omitted, the record verifies exactly as before — the #280
        # bind to base_sha..head_sha is what covers them, not a signature nobody could produce.
        rec, pk = self._signed({"manifest_id": "u", "contract_digest": "sha256:a",
                                "unit_class": "mutation"})
        m = {"unit": "u", "negative_control": {"paths": ["anything.py"], "command": "whatever"}}
        res = verify.check_dispatch_provenance(m, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    _BASE = {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"}

    def _lane_check(self, signed, **used):
        rec, pk = self._signed({**self._BASE, **signed})
        return verify.check_dispatch_provenance(self._M, "sha256:a", "mutation", None, rec, pk,
                                                **used)

    def _fatal(self, res):
        return [e for e in res if not e.startswith("NOTE:")]

    def test_an_unsigned_no_gh_waiver_is_refused(self):
        # Review P2: --no-gh waives the GitHub review and arrived from argv/ORCA_NO_GH unbound.
        res = self._lane_check({}, no_gh=True)
        self.assertTrue(any("did not sign no_gh" in e for e in self._fatal(res)), res)
        self.assertFalse(self._fatal(self._lane_check({"no_gh": True}, no_gh=True)))

    def test_a_signed_no_gh_the_run_drops_is_a_substitution(self):
        res = self._lane_check({"no_gh": True}, no_gh=False)
        self.assertTrue(any("substitution" in e for e in self._fatal(res)), res)

    def test_an_unsigned_or_flipped_lane_is_refused(self):
        res = self._lane_check({}, lane="A")
        self.assertTrue(any("did not sign lane" in e for e in self._fatal(res)), res)
        res = self._lane_check({"lane": "0"}, lane="A")
        self.assertTrue(any("substitution" in e for e in self._fatal(res)), res)
        self.assertFalse(self._fatal(self._lane_check({"lane": "A"}, lane="A")))
        # an omitted --lane against a signed lane is not a USE here; verify() adopts the signed
        # lane instead (test_an_omitted_lane_adopts_the_signed_one)
        self.assertFalse(self._fatal(self._lane_check({"lane": "A"})))

    def test_an_omitted_lane_adopts_the_signed_one(self):
        # A record signing lane "0" passed as a landed mutation when --lane was left off: the
        # provenance check skipped the unused field and check_lighting saw no lane at all
        # (PR #571 review). verify() now runs the downstream checks on the signed value.
        rec, pk = self._signed({**self._BASE, "lane": "0", "lighting": "lit"})
        self.write("m.json", json.dumps({"unit": "u"}))
        out, err = verify.verify("m.json", unit_class="mutation", contract_digest="sha256:a",
                                 dispatch_record=rec, dispatch_pubkey=pk)
        self.assertIsNone(err)
        fatal, _notes = out
        self.assertTrue(any("Lane 0" in e for e in fatal), fatal)
        self.assertFalse(any("did not sign" in e or "substitution" in e for e in fatal), fatal)

    def test_a_signed_execute_nc_cannot_be_dropped(self):
        res = self._lane_check({"execute_nc": True}, execute_nc=False)
        self.assertTrue(any("execute_nc" in e and "substitution" in e for e in self._fatal(res)), res)
        self.assertFalse(self._fatal(self._lane_check({"execute_nc": True}, execute_nc=True)))
        # executing a control the record did not require only makes the run stricter
        self.assertFalse(self._fatal(self._lane_check({}, execute_nc=True)))

    def test_the_lane_flags_reach_the_check_from_verify(self):
        rec, pk = self._signed(dict(self._BASE))
        self.write("m.json", json.dumps({"unit": "u"}))
        with mock.patch.object(verify, "check_dispatch_provenance",
                               wraps=verify.check_dispatch_provenance) as spy:
            verify.verify("m.json", unit_class="mutation", no_gh=True, lane="B",
                          execute_nc=True, dispatch_record=rec, dispatch_pubkey=pk)
        kw = spy.call_args.kwargs
        self.assertEqual((kw["no_gh"], kw["lane"], kw["execute_nc"]), (True, "B", True))

    def test_canonicalization_matches_signer_on_the_lane_fields(self):
        record = {**self._BASE, "no_gh": True, "lane": "0", "execute_nc": True}
        self.assertEqual(verify._canonical_dispatch(record), dispatch_sign.canonical_record(record))
        self.assertEqual(verify._DISPATCH_FIELDS, dispatch_sign._RECORD_FIELDS)
        # an old record (no lane flags) canonicalizes exactly as it did before they existed
        self.assertEqual(verify._canonical_dispatch(dict(self._BASE, no_gh=None, lane=None)),
                         verify._canonical_dispatch(dict(self._BASE)))

    def test_canonicalization_matches_signer(self):
        # cross-tool drift guard: the gate and the signer must canonicalize identically, else every
        # real signature would fail to verify.
        record = {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation", "lighting": "lit"}
        self.assertEqual(verify._canonical_dispatch(record), dispatch_sign.canonical_record(record))

    def test_canonicalization_matches_signer_on_the_nc_fields(self):
        # #311 widened the signed tuple, and the two sides canonicalize in two files. An nc_paths
        # list is the part that can drift silently: sorted on one side and not the other still
        # SIGNS fine and only fails at verification, on a real dispatch, in production.
        record = {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation",
                  "nc_paths": ["z.py", "a.py", "m.py"], "nc_command": "pytest -k AC_1",
                  "nc_artifact_sha256": "ab" * 32}
        self.assertEqual(verify._canonical_dispatch(record), dispatch_sign.canonical_record(record))
        # and the order the coordinator happened to type is not part of the signature
        shuffled = dict(record, nc_paths=["a.py", "m.py", "z.py"])
        self.assertEqual(verify._canonical_dispatch(record), verify._canonical_dispatch(shuffled))

    def test_the_signer_cli_produces_a_record_the_gate_accepts(self):
        # Through both entry points, not the helpers: a signature the gate rejects is worth
        # nothing, and every field added to the tuple is a chance for the two to disagree.
        import subprocess
        seed = self.seed_file(bytes(range(1, 33)))
        out = subprocess.run(
            [sys.executable, str(ROOT / "runtime" / "scripts" / "dispatch-sign.py"), "sign",
             "--key", seed, "--manifest-id", "u", "--contract-digest", "sha256:a",
             "--unit-class", "mutation", "--nc-path", "b.py", "--nc-path", "a.py",
             "--nc-command", "pytest -k AC_1"],
            capture_output=True, text=True, cwd=self.repo, check=True).stdout
        rec = self.write(".orca/dispatch-record.json", out)
        pk = self.write(".orca/dispatch-pubkey", ed.publickey(bytes(range(1, 33))).hex())
        m = {"unit": "u", "negative_control": {"paths": ["a.py", "b.py"],
                                               "command": "pytest -k AC_1"}}
        res = verify.check_dispatch_provenance(m, "sha256:a", "mutation", None, rec, pk)
        self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)


class TranscriptFixture(RepoCase):
    """#281 / #386: the verdict leaves verify.py as a SIGNED transcript, not only as stdout text.

    Given `--transcript-out` + `--transcript-key`, main() builds a machine-readable verdict object
    (unit, manifest path + sha256, the full argument tuple, fatal/notes, exit, toolchain, UTC
    timestamp) and writes it as the same {record, sig_b64} envelope dispatch-sign.py emits, over
    the same canonical form. run_report.py can then REQUIRE that envelope against a committed
    public key instead of trusting a worker-written ledger entry."""

    SEED = bytes(range(1, 33))

    def setUp(self):
        super().setUp()
        self.manifest = self.write("docs/reports/u/manifest.json", json.dumps({"unit": "u"}))
        self.key = self.seed_file(self.SEED)

    def _main(self, *extra):
        buf, errbuf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            rc = verify.main(["--manifest", self.manifest, "--unit-class", "report-only", *extra])
        return rc, buf.getvalue(), errbuf.getvalue()

    def _envelope(self, path="docs/reports/u/transcript.json"):
        return json.loads((self.repo / path).read_text(encoding="utf-8"))



class SignedTranscript(TranscriptFixture):
    """#281/#386: the --transcript-out / --transcript-key pair (fixture above; tests here)."""

    def test_the_transcript_binds_the_bytes_that_were_judged_not_a_reread(self):
        # Review P2: build() re-read args.manifest from disk AFTER worker code had run (the
        # executed control), so a manifest rewritten mid-run was what the verdict bound to.
        judged = (self.repo / self.manifest).read_bytes()
        original = verify.check_scope

        def rewrite_mid_run(*a, **k):
            (self.repo / self.manifest).write_text(json.dumps({"unit": "forged"}), encoding="utf-8")
            return original(*a, **k)
        with mock.patch.object(verify, "check_scope", side_effect=rewrite_mid_run):
            self._main("--transcript-out", "docs/reports/u/transcript.json")
        rec = self._envelope()
        self.assertEqual(rec["manifest_sha256"], hashlib.sha256(judged).hexdigest())
        self.assertEqual(rec["unit"], "u")

    def test_a_manifest_that_never_loaded_binds_no_digest(self):
        (self.repo / self.manifest).write_text("{not json", encoding="utf-8")
        rc, _out, _err = self._main("--transcript-out", "docs/reports/u/transcript.json")
        self.assertEqual(rc, 2)
        rec = self._envelope()
        self.assertIsNone(rec["manifest_sha256"])
        self.assertIsNone(rec["unit"])

    def test_no_flags_writes_nothing_and_says_nothing_new(self):
        # The unsigned default path is byte-identical to today's: the terminal lines are the
        # verdict, nothing about transcripts is printed, and no file appears.
        rc, out, err = self._main()
        self.assertIn(rc, (0, 2))
        self.assertNotIn("transcript", (out + err).lower())
        self.assertFalse(list((self.repo / "docs" / "reports" / "u").glob("transcript*")))

    def test_the_pair_emits_an_envelope_that_verifies_and_binds_the_verdict(self):
        rc, out, err = self._main("--transcript-out", "docs/reports/u/transcript.json",
                                  "--transcript-key", self.key)
        env = self._envelope()
        self.assertEqual(set(env), {"record", "sig_b64"})
        rec = env["record"]
        self.assertEqual(rec["exit"], rc)
        self.assertEqual(rec["unit"], "u")
        self.assertEqual(rec["manifest"], self.manifest)
        self.assertEqual(rec["manifest_sha256"],
                         hashlib.sha256((self.repo / self.manifest).read_bytes()).hexdigest())
        self.assertEqual(rec["args"]["unit_class"], "report-only")
        self.assertIn("lighting", rec["args"])  # the FULL tuple, unset flags included
        # the lists are the printed verdict, not a summary of it
        self.assertEqual(rec["fatal"], [l[len("FAIL: "):] for l in err.splitlines() if l.startswith("FAIL: ")])
        self.assertEqual(rec["notes"], [l for l in out.splitlines() if l.startswith("NOTE:")])
        self.assertTrue(rec["timestamp"].endswith("+00:00"), rec["timestamp"])
        self.assertIn("python", rec["toolchain"])
        self.assertEqual(rec["toolchain"]["verify_sha256"],
                         hashlib.sha256((ROOT / "runtime" / "scripts" / "verify.py").read_bytes()).hexdigest())
        pub = ed.publickey(self.SEED)
        sig = base64.b64decode(env["sig_b64"])
        self.assertTrue(ed.checkvalid(sig, verify._canonical_transcript(rec), pub))
        # any byte of the record changed -> the signature no longer verifies
        for tampered in (dict(rec, exit=0 if rc else 2), dict(rec, fatal=[]),
                         dict(rec, manifest_sha256="00" * 32)):
            self.assertFalse(ed.checkvalid(sig, verify._canonical_transcript(tampered), pub))

    def test_out_without_key_writes_the_unsigned_verdict_object(self):
        # The maintainer's seed is OFFLINE (gate G1): a verifier run without it still leaves a
        # verdict object that `dispatch-sign.py sign-transcript` can wrap later. It is NOT an
        # envelope, so run_report.py cannot mistake it for a signed one.
        rc, _, _ = self._main("--transcript-out", "docs/reports/u/transcript.json")
        rec = self._envelope()
        self.assertNotIn("sig_b64", rec)
        self.assertEqual(rec["exit"], rc)
        self.assertEqual(rec["unit"], "u")

    def test_key_without_out_is_a_usage_error_not_a_verdict(self):
        rc, _, err = self._main("--transcript-key", self.key)
        self.assertEqual(rc, 1)
        self.assertIn("--transcript-out", err)
        self.assertFalse(list((self.repo / "docs" / "reports" / "u").glob("transcript*")))

    def test_an_unreadable_key_is_a_usage_error_before_any_verdict(self):
        rc, _, err = self._main("--transcript-out", "docs/reports/u/transcript.json",
                                "--transcript-key", ".orca/missing")
        self.assertEqual(rc, 1)
        self.assertIn("--transcript-key", err)
        self.assertFalse((self.repo / "docs/reports/u/transcript.json").exists())

    def test_a_requested_transcript_that_cannot_be_written_is_a_nonzero_exit(self):
        # Round-1 R-3: `verify.py --transcript-out X && use X` must never see exit 0 and no X. A
        # requested-and-missing artifact fails closed like every other evidence path here; a RED
        # verdict keeps its own code (2) — the write failure never upgrades a RED to a usage error.
        blocker = self.repo / "docs" / "reports" / "u" / "blocked"
        blocker.write_text("a file where the directory must go\n", encoding="utf-8")
        green = (([], []), None)  # the verdict itself passes; only the requested artifact fails
        with unittest.mock.patch.object(verify, "verify", return_value=green):
            rc, out, err = self._main("--transcript-out", "docs/reports/u/blocked/transcript.json")
        self.assertIn("verify: OK", out)
        self.assertEqual(rc, 1, err)
        self.assertIn("transcript", err)
        self.assertFalse((blocker / "transcript.json").exists())
        with unittest.mock.patch.object(verify, "verify", return_value=((["x"], []), None)):
            rc, _, _ = self._main("--transcript-out", "docs/reports/u/blocked/transcript.json")
        self.assertEqual(rc, 2, "a RED verdict keeps its own exit code")

    def test_the_in_process_signer_refuses_to_sign_an_absence_like_the_offline_one(self):
        # Round-1 R-2: dispatch-sign.py refuses a verdict with a None field; verify.py's in-process
        # signer must apply the same rule, not sign manifest_sha256=None and let None==None bind.
        rc, _, err = self._main("--manifest", "docs/reports/u/missing.json",
                                "--transcript-out", "docs/reports/u/transcript.json",
                                "--transcript-key", self.key)
        self.assertNotEqual(rc, 0)
        self.assertIn("absence", err)
        self.assertFalse((self.repo / "docs/reports/u/transcript.json").exists())

    def test_canonicalization_matches_signer(self):
        # cross-tool drift guard, as for the dispatch tuple: verify.py signs, dispatch-sign.py
        # signs offline, run_report.py verifies — one canonical form or every real signature fails.
        rec = {"unit": "u", "manifest": "m.json", "manifest_sha256": "ab" * 32,
               "args": {"unit_class": "mutation", "lighting": None, "execute_nc": False},
               "fatal": ["x"], "notes": [], "exit": 2,
               "toolchain": {"python": "3", "verify_sha256": "cd" * 32},
               "timestamp": "2026-09-20T00:00:00+00:00", "extra": "not signed"}
        self.assertEqual(verify._canonical_transcript(rec), dispatch_sign.canonical_transcript(rec))
        self.assertNotIn(b"not signed", verify._canonical_transcript(rec))

    def test_help_documents_the_pair(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            verify.main(["--help"])
        for flag in ("--transcript-out", "--transcript-key"):
            self.assertIn(flag, buf.getvalue())


class PinnedEvidenceBytes(RepoCase):
    def test_builtin_floor_runs_with_scanner_present_or_absent(self):
        for scanner in (False, None, True, "actual"):
            for value in ('AKIA' + 'Q' * 16, 'password' + '=sunset123',
                          'ghp_' + 'Z' * 30 + ' #gitleaks:allow'):
                with self.subTest(scanner=scanner, value_kind=value[:4]):
                    art = self.artifact(value)
                    m = {'artifacts': [self.pin(art)]}
                    scanner_context = (contextlib.nullcontext() if scanner == 'actual' else
                                       mock.patch.object(verify, '_gitleaks_scan', return_value=scanner))
                    with scanner_context:
                        self.assertTrue(verify.check_redaction(m, None))
        art = self.artifact('clean evidence')
        with mock.patch.object(verify, '_gitleaks_scan', return_value=False):
            self.assertEqual(verify.check_redaction({'artifacts': [self.pin(art)]}, None), [])

    def test_tracked_bytes_survive_clean_overlay_and_checkout_deletion(self):
        art = self.artifact('AKIA' + 'Q' * 16)
        head = self.commit()
        m = {'head_sha': head, 'artifacts': [art]}
        for deleted in (False, True):
            if deleted:
                Path(art).unlink()
            else:
                self.write(art, 'clean overlay')
            with mock.patch.object(verify, '_gitleaks_scan', return_value=False):
                self.assertTrue(verify.check_redaction(m, None))

    def test_missing_unpinned_and_unreadable_named_evidence_fails_closed(self):
        art = self.artifact('clean')
        cases = [{'commands': [{'artifact': 'missing.txt'}]}, {'artifacts': [art]},
                 {'review': {'artifact': 'missing.txt'}}]
        for m in cases:
            self.assertTrue(verify.check_redaction(m, None), m)
        with mock.patch.object(Path, 'read_bytes', side_effect=PermissionError('denied')):
            self.assertTrue(verify.check_redaction({'artifacts': [art]}, None))

    def test_gitleaks_runs_in_the_evidence_copy_directory(self):
        # #340: inheriting the test-repo cwd let gitleaks touch .git/objects while
        # TemporaryDirectory tore the tree down (OSError 39 on Linux CI).
        observed = []

        def fake_run(args, timeout=20, cwd=None, env=None):
            observed.append((cwd, list(args)))
            return 0, "", ""

        art = self.artifact("clean evidence")
        verify._Authority.git_bin()  # pin git first: the fake _run below answers nothing real
        # gitleaks is pinned and classed at startup like gh (h409 R2); a system one is consulted.
        verify._Authority.gitleaks, verify._Authority.gitleaks_custody = "/bin/gitleaks", "system"
        with mock.patch.object(verify, "_run", side_effect=fake_run):
            self.assertEqual(verify.check_redaction({"artifacts": [self.pin(art)]}, None), [])
        leaks = [(cwd, args) for cwd, args in observed if args and args[0] == "/bin/gitleaks"]
        self.assertTrue(leaks, f"gitleaks was not invoked: {observed!r}")
        cwd, args = leaks[0]
        source = args[args.index("--source") + 1]
        self.assertEqual(Path(cwd).resolve(), Path(source).parent.resolve())
        self.assertIn("--no-git", args)

    def test_scanner_receives_the_pinned_blob(self):
        art = self.artifact(b'committed\r\nbytes\n')
        head = self.commit()
        self.write(art, 'overlay')
        observed = []
        def scanner(path):
            observed.append(Path(path).read_bytes())
            return False
        with mock.patch.object(verify, '_gitleaks_scan', side_effect=scanner):
            self.assertEqual(verify.check_redaction({'head_sha': head, 'artifacts': [art]}, None), [])
        self.assertIn(b'committed\r\nbytes\n', observed)

    def test_signed_hash_uses_the_same_blob_as_replay(self):
        art = self.artifact(b'committed mutant\r\n')
        head = self.commit()
        m = {'head_sha': head, 'negative_control': {'artifact': art}}
        want = hashlib.sha256(b'committed mutant\r\n').hexdigest()
        self.write(art, 'overlay mutant')
        self.assertEqual(verify._manifest_nc_values(m)['nc_artifact_sha256'], want)
        Path(art).unlink()
        self.assertEqual(verify._manifest_nc_values(m)['nc_artifact_sha256'], want)

    def test_real_signature_rejects_overlay_and_accepts_pinned_content(self):
        art = self.artifact('committed mutant RED\n')
        head = self.commit()
        m = {'unit': 'u', 'head_sha': head, 'negative_control': {'artifact': art}}
        self.write(art, 'overlay mutant RED\n')
        record = {'manifest_id': 'u', 'contract_digest': 'sha256:a', 'unit_class': 'mutation',
                  'nc_artifact_sha256': self.pin(art)['sha256']}
        rec, pk = DispatchProvenance._signed(self, record)
        errors = verify.check_dispatch_provenance(m, 'sha256:a', 'mutation', None, rec, pk)
        self.assertTrue(any('substitution' in e for e in errors), errors)
        record['nc_artifact_sha256'] = hashlib.sha256(b'committed mutant RED\n').hexdigest()
        rec, pk = DispatchProvenance._signed(self, record)
        Path(art).unlink()
        self.assertTrue(all(e.startswith('NOTE:') for e in
            verify.check_dispatch_provenance(m, 'sha256:a', 'mutation', None, rec, pk)))

    def test_one_verification_retains_its_initial_evidence_snapshot(self):
        art = self.artifact('original RED\n')
        path = self.write('m.json', json.dumps({'artifacts': [self.pin(art)]}))
        m, err = verify.load_manifest(path)
        self.assertIsNone(err)
        self.assertEqual(verify.read_artifact(m, art), (b'original RED\n', None))
        self.write(art, 'replacement RED\n')
        self.assertEqual(verify.read_artifact(m, art), (b'original RED\n', None))
        fresh, _ = verify.load_manifest(path)
        self.assertIsNotNone(verify.read_artifact(fresh, art)[1])


class EquivalentReviewVeto(unittest.TestCase):
    def test_equivalent_heads_share_objections_and_withdrawals(self):
        m = {'head_sha': 'H', 'pr': {'number': 7, 'reviewed_sha': 'R'}}
        def review(who, state, sha):
            return {'user': {'login': who}, 'state': state, 'commit_id': sha, 'author_association': 'MEMBER'}
        for approval, objection in (('H', 'R'), ('R', 'H')):
            reviews = [review('carol', 'APPROVED', approval),
                       review('bob', 'CHANGES_REQUESTED', objection)]
            with self.subTest(approval=approval, objection=objection), \
                    mock.patch.object(verify, '_wtree_bound', return_value=True), \
                    mock.patch.object(verify, 'fetch_pr_author', return_value='alice'), \
                    mock.patch.object(verify, 'fetch_reviews', return_value=(reviews, None)):
                self.assertTrue(verify.check_review(m, 'o/r', True), (approval, objection))
                reviews.append(review('bob', 'DISMISSED', approval))
                self.assertEqual(verify.check_review(m, 'o/r', True), [])
        with mock.patch.object(verify, '_wtree_bound', return_value=False), \
                mock.patch.object(verify, 'fetch_pr_author', return_value='alice'), \
                mock.patch.object(verify, 'fetch_reviews', return_value=(
                    [review('carol', 'APPROVED', 'R')], None)):
            self.assertTrue(verify.check_review(m, 'o/r', True))


class HandControlCoordinates(RepoCase):
    def setUp(self):
        super().setUp()
        self.original = 'def f():\n    return 2\n\ndef unrelated():\n    return 7\n'
        self.write('app.py', self.original.replace('return 2', 'return 1'))
        self.write('tests/conftest.py', 'EXPECTED_MODE = "ready"\n')
        self.base = self.commit()
        self.write('app.py', self.original)
        self.head = self.commit()
        self.m = {'base_sha': self.base, 'head_sha': self.head}

    def _diff(self, text):
        self.write('app.py', text)
        return self.git('diff') + '\n'

    def test_context_does_not_bind_an_unrelated_mutation(self):
        diff = self._diff(self.original.replace('return 7', 'return 8'))
        self.assertIsNotNone(verify._bind_hunks_to_change(diff, self.m))

    def test_every_changed_coordinate_must_bind(self):
        diff = self._diff(self.original.replace('return 2', 'return 3').replace('return 7', 'return 8'))
        self.assertIsNotNone(verify._bind_hunks_to_change(diff, self.m))

    def test_real_criterion_mutant_replays(self):
        diff = self._diff(self.original.replace('return 2', 'return 1'))
        self.assertIsNone(verify._bind_hunks_to_change(diff, self.m))
        self.git('checkout', '--', 'app.py')
        art = self.artifact('RED\n' + diff)
        self.m['artifacts'] = [self.pin(art)]
        self.assertIsNone(verify._apply_control(str(self.repo), self.m, {'artifact': art}, 'hand'))
        self.assertIn('return 1', Path('app.py').read_text())

    def test_truncated_hunk_with_allowed_path_never_reaches_executor(self):
        diff = self._diff(self.original.replace('return 2', 'return 1'))
        diff = diff[:diff.rfind('\n', 0, -1) + 1]  # remove one required context line
        self.git('restore', '--', 'app.py')
        art = self.artifact('RED\n' + diff)
        self.m['artifacts'] = [self.pin(art)]
        self.m['negative_control'] = {'tool': 'hand', 'artifact': art, 'result': 'RED'}
        with mock.patch.object(verify, 'execute_negative_control', return_value=(True, [])) as execute:
            errors, executed = verify.check_negative_control(self.m, True, True)
        self.assertFalse(executed, errors)
        self.assertTrue(any('incomplete diff hunk' in e for e in errors), errors)
        execute.assert_not_called()

    def test_deletion_rename_and_mode_endpoints_cannot_hide(self):
        good = self._diff(self.original.replace('return 2', 'return (2)'))
        variants = [
            'diff --git a/tests/conftest.py b/tests/conftest.py\n'
            'deleted file mode 100644\n--- a/tests/conftest.py\n+++ /dev/null\n'
            '@@ -1 +0,0 @@\n-EXPECTED_MODE = "ready"\n',
            'diff --git a/tests/conftest.py b/config.py\nsimilarity index 100%\n'
            'rename from tests/conftest.py\nrename to config.py\n',
            'diff --git a/tests/conftest.py b/tests/conftest.py\nold mode 100644\nnew mode 100755\n',
            'diff --git a/new.py b/new.py\nnew file mode 100644\n--- /dev/null\n+++ b/new.py\n'
            '@@ -0,0 +1 @@\n+VALUE = 1\n',
        ]
        for extra in variants:
            with self.subTest(extra=extra.splitlines()[0]):
                art = self.artifact('RED\n' + good + extra)
                self.m['artifacts'] = [self.pin(art)]
                with mock.patch.object(verify, '_run_at', return_value=(0, '', '')) as executor:
                    self.assertIsNotNone(verify._apply_control(str(self.repo), self.m,
                                                              {'artifact': art}, 'hand'))
                    executor.assert_not_called()

    def test_plain_unified_diff_binds_each_file_without_git_headers(self):
        self.write('other.py', 'VALUE = 1\n')
        base = self.commit()
        self.write('app.py', self.original.replace('return 2', 'return 3'))
        self.write('other.py', 'VALUE = 2\n')
        head = self.commit()
        diff = ('--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n-    return 3\n+    return 2\n'
                '--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-VALUE = 2\n+VALUE = 1\n')
        self.assertIsNone(verify._bind_hunks_to_change(diff, {'base_sha': base, 'head_sha': head}))

    def test_criterion_insertion_seam_binds_without_context(self):
        diff = self._diff(self.original.replace('    return 2', '    return 1\n    return 2'))
        self.assertIsNone(verify._bind_hunks_to_change(diff, self.m))


class CoordinatorOracleScope(RepoCase):
    def setUp(self):
        super().setUp()
        self.write('app.py', 'def f():\n    return 2\n')
        self.write('decoy.py', 'VALUE = 7\n')
        self.base = self.commit('correct, untested production')
        self.write('tests/test_app.py', 'import unittest\nimport app\n'
                   'class Behavior(unittest.TestCase):\n'
                   '    def test_f(self):\n        self.assertEqual(app.f(), 2)\n')
        self.head = self.commit('PF-1 style characterization only')
        self.cmd = f'{shlex.quote(sys.executable)} -m unittest discover -s tests'
        self.diff = '--- a/app.py\n+++ b/app.py\n@@ -2 +2 @@\n-    return 2\n+    return 1\n'
        self.art = self.artifact('RED criterion mutant\n' + self.diff)
        self.scope = {'kind': 'characterization', 'base_sha': self.base, 'head_sha': self.head,
                      'criterion_ids': ['AC-1'], 'paths': {'app.py': [2]},
                      'artifact_sha256': self.pin(self.art)['sha256']}

    def _run(self, scope=True, manifest_scope=None):
        contract = {'criterion_ids': ['AC-1']}
        if scope:
            contract['oracle_scope'] = self.scope
        source = self.write('frozen.json', json.dumps(contract))
        digest = self.digest(source)
        m = {'unit': 'characterization', 'base_sha': self.base, 'head_sha': self.head,
             'contract': {'source': source, 'digest': digest, 'criterion_ids': ['AC-1']},
             'criteria': _crit('AC-1'), 'lighting': 'lit',
             'intent': {'goal': 'characterize f', 'ruled_out': 'production edit', 'why': 'f is correct'},
             'reviewer_mode': 'same-vendor-fresh',
             'pr': {'number': 1, 'reviewed_sha': self.head},
             'negative_control': {'tool': 'hand', 'artifact': self.art, 'result': 'RED', 'command': self.cmd},
             'artifacts': [self.pin(self.art)],
             'commands': [{'cmd': self.cmd, 'cmd_sha256': hashlib.sha256(self.cmd.encode()).hexdigest(),
                           'exit': 0, 'wtree': self.git('rev-parse', f'{self.head}^{{tree}}')}]}
        if manifest_scope:
            m['oracle_scope'] = manifest_scope
        path = self.write('manifest.json', json.dumps(m))
        with mock.patch.object(verify, 'fetch_pr_author', return_value='author'), \
                mock.patch.object(verify, 'fetch_reviews', return_value=([
                    {'user': {'login': 'reviewer'}, 'state': 'APPROVED', 'author_association': 'MEMBER', 'commit_id': self.head}], None)):
            result, err = verify.verify(path, source, digest, repo='o/r', unit_class='mutation',
                                        lighting='lit', execute_nc=True, nc_command=self.cmd)
        self.assertIsNone(err)
        return result

    def test_pf1_production_unchanged_characterization_replays(self):
        self.assertEqual(self.git('diff', self.base, self.head, '--', 'app.py'), '')
        fatal, notes = self._run()
        self.assertEqual(fatal, [])
        self.assertTrue(any('EXECUTED' in note for note in notes))

    def test_authorized_coordinates_cannot_relocate_in_unchanged_production(self):
        self.write('app.py', '# module\n\n\ndef fixed():\n    return 2\n# fixed end\n\n\n\n'
                   'def unrelated():\n    return 2\n# unrelated end\n')
        self.base = self.commit('production before characterization')
        self.write('tests/test_app.py', 'import unittest, app\nclass Behavior(unittest.TestCase):\n'
                   '    def test_values(self):\n        self.assertEqual(app.fixed(), 2)\n'
                   '        self.assertEqual(app.unrelated(), 2)\n')
        self.head = self.commit('characterize both functions')
        self.art = self.artifact('RED\n--- a/app.py\n+++ b/app.py\n@@ -4,3 +4,3 @@\n'
                                 ' def unrelated():\n-    return 2\n+    return 0\n # unrelated end\n',
                                 'docs/reports/u/relocated.txt')
        self.scope.update(base_sha=self.base, head_sha=self.head, paths={'app.py': [5]},
                          artifact_sha256=self.pin(self.art)['sha256'])
        fatal, _ = self._run()
        self.assertTrue(any('coordinate' in e for e in fatal), fatal)

    def test_worker_scope_cannot_authorize_itself(self):
        self.assertTrue(self._run(scope=False, manifest_scope=self.scope)[0])

    def test_scope_cannot_omit_coordinates_or_swap_artifact(self):
        for field, bad in (('paths', {'app.py': [1]}), ('artifact_sha256', '0' * 64),
                           ('head_sha', self.base), ('criterion_ids', ['AC-99'])):
            with self.subTest(field=field):
                old = self.scope[field]
                self.scope[field] = bad
                with mock.patch.object(verify, 'execute_negative_control', return_value=(True, [])) as execute:
                    self.assertTrue(self._run()[0])
                    execute.assert_not_called()
                self.scope[field] = old

    def test_documentation_example_can_bind_unchanged_production(self):
        self.write('README.md', 'import app\nassert app.f() == 1\n')
        self.write('check_doc.py', 'from pathlib import Path\nexec(Path("README.md").read_text())\n')
        self.base = self.commit('old documentation example')
        self.write('README.md', 'import app\nassert app.f() == 2\n')
        self.head = self.commit('correct documentation example')
        self.cmd = f'{shlex.quote(sys.executable)} check_doc.py'
        self.scope.update(kind='documentation', base_sha=self.base, head_sha=self.head)
        fatal, notes = self._run()
        self.assertEqual(fatal, [])
        self.assertTrue(any('EXECUTED' in note for note in notes))

    def test_worker_decoy_cannot_replace_authorized_mutant(self):
        self.write(self.art, 'RED\n--- a/decoy.py\n+++ b/decoy.py\n@@ -1 +1 @@\n-VALUE = 7\n+VALUE = 8\n')
        with mock.patch.object(verify, 'execute_negative_control') as execute:
            self.assertTrue(self._run()[0])
            execute.assert_not_called()

    def test_even_explicit_scope_cannot_delete_the_test_oracle(self):
        self.write(self.art, 'RED\n--- a/tests/test_app.py\n+++ /dev/null\n@@ -1,5 +0,0 @@\n'
                   '-import unittest\n-import app\n-class Behavior(unittest.TestCase):\n'
                   '-    def test_f(self):\n-        self.assertEqual(app.f(), 2)\n')
        self.scope.update(paths={'tests/test_app.py': [1, 2, 3, 4, 5]},
                          artifact_sha256=self.pin(self.art)['sha256'])
        with mock.patch.object(verify, 'execute_negative_control') as execute:
            self.assertTrue(self._run()[0])
            execute.assert_not_called()

    def test_authorized_stillborn_and_surviving_mutants_remain_red(self):
        for value, diagnostic in (('(', 'oracle'), ('2 + 0', 'TAUTOLOGICAL')):
            with self.subTest(value=value):
                self.write(self.art, 'RED\n' + self.diff.replace('+    return 1', '+    return ' + value))
                self.scope['artifact_sha256'] = self.pin(self.art)['sha256']
                fatal, _ = self._run()
                self.assertTrue(any(diagnostic in line for line in fatal), fatal)

    def test_runner_configuration_is_not_a_test_only_characterization(self):
        self.write('conftest.py', 'EXPECTED = 2\n')
        self.head = self.commit('runner configuration is code')
        self.scope['head_sha'] = self.head
        with mock.patch.object(verify, 'execute_negative_control', return_value=(True, [])) as execute:
            self.assertTrue(self._run()[0])
            execute.assert_not_called()

    def test_production_change_cannot_use_characterization_exception(self):
        self.write('decoy.py', 'VALUE = 8\n')
        self.head = self.commit('unexpected production edit')
        self.scope['head_sha'] = self.head
        with mock.patch.object(verify, 'execute_negative_control') as execute:
            self.assertTrue(self._run()[0])
            execute.assert_not_called()


class OracleConfigurationPaths(RepoCase):
    def test_changed_runner_configuration_cannot_join_a_production_control(self):
        self.write('app.py', 'VALUE = 1\n')
        self.write('pytest.ini', '[pytest]\naddopts = -q\n')
        self.write('conftest.py', 'EXPECTED = 1\n')
        base = self.commit()
        self.write('app.py', 'VALUE = 2\n')
        self.write('pytest.ini', '[pytest]\naddopts = -v\n')
        self.write('conftest.py', 'EXPECTED = 2\n')
        head = self.commit()
        for path in ('pytest.ini', 'conftest.py'):
            with self.subTest(path=path):
                self.assertIsNotNone(verify._bind_paths_to_change(
                    ['app.py', path], {'base_sha': base, 'head_sha': head}, 'control'))


class AppliedHunkCoordinates(RepoCase):
    def setUp(self):
        super().setUp()
        self.write('app.py', '# module\n\n\ndef fixed():\n    return 1\n# fixed end\n\n\n\n'
                   'def unrelated():\n    return 2\n# unrelated end\n')
        self.write('check.py', 'import app\nassert app.fixed() == 2\nassert app.unrelated() == 2\n')
        self.base = self.commit()
        self.write('app.py', Path('app.py').read_text().replace('return 1', 'return 2'))
        self.head = self.commit()
        self.cmd = f'{shlex.quote(sys.executable)} check.py'

    def replay(self, function):
        diff = ('--- a/app.py\n+++ b/app.py\n@@ -4,3 +4,3 @@\n'
                f' def {function}():\n-    return 2\n+    return 0\n#PLACEHOLDER')
        diff = diff.replace('#PLACEHOLDER', f' # {function} end\n')
        code, _, err = verify._run_at(self.repo,
            ['git', 'apply', '--check', '--verbose', '-'], stdin_bytes=diff.encode())
        self.assertEqual(code, 0, err)
        if function == 'unrelated':
            self.assertIn('offset 6 lines', err)
        art = self.artifact('RED\n' + diff)
        m = {'base_sha': self.base, 'head_sha': self.head, 'artifacts': [self.pin(art)],
             'negative_control': {'tool': 'hand', 'artifact': art, 'result': 'RED', 'command': self.cmd}}
        with mock.patch.object(verify, '_run_at', wraps=verify._run_at) as run_at:
            result = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
        proof_runs = [c for c in run_at.call_args_list if c.args[1] == shlex.split(self.cmd)]
        self.assertEqual(len(proof_runs), 0 if function == 'unrelated' else 3)  # clean/control/clean
        return result

    def test_offset_cannot_mutate_unchanged_behavior(self):
        errors, executed = self.replay('unrelated')
        self.assertFalse(executed, errors)
        self.assertTrue(any('coordinate' in e or 'untouched' in e for e in errors), errors)

    def test_exact_criterion_mutant_still_replays(self):
        errors, executed = self.replay('fixed')
        self.assertTrue(executed, errors)


class ProofOracleProtection(RepoCase):
    def setUp(self):
        super().setUp()
        self.cmd = f'{shlex.quote(sys.executable)} runner.py'
        self.write('app.py', 'VALUE = 2\n')
        self.write('conftest.py', 'EXPECTED = 1\n')
        self.write('runner.py', 'import app, conftest\nassert app.VALUE == conftest.EXPECTED\n')
        self.base = self.commit()
        self.write('conftest.py', 'EXPECTED = 2\n')
        self.head = self.commit()

    def manifest(self, tool, diff=''):
        art = self.artifact('RED\n' + diff, f'docs/reports/u/nc-{next(_SRC_SEQ)}.txt')
        return {'base_sha': self.base, 'head_sha': self.head, 'artifacts': [self.pin(art)],
                'negative_control': {'tool': tool, 'result': 'RED', 'artifact': art, 'command': self.cmd}}

    def test_range_cannot_restore_runner_configuration(self):
        m = self.manifest('revert')
        errors, executed = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
        self.assertFalse(executed, errors)
        self.assertTrue(any('oracle' in e or 'TEST' in e for e in errors), errors)
        with mock.patch.object(verify, 'execute_negative_control') as execute:
            errors, _ = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
            self.assertTrue(errors)
            execute.assert_not_called()

    def test_makefile_and_explicit_runner_cannot_supply_the_red(self):
        for filename, command in (('Makefile', 'make test'), ('runner.py', self.cmd),
                                  ('runner.py', f'{shlex.quote(sys.executable)} -m runner'),
                                  ('runner.py', f'env {shlex.quote(sys.executable)} runner.py'),
                                  ('runner.py', f'env -- {shlex.quote(sys.executable)} -mrunner')):
            with self.subTest(filename=filename, command=command):
                self.cmd = command
                recipe = (f'test:\n\t{shlex.quote(sys.executable)} -c "import app; assert app.VALUE == 1"\n'
                          if filename == 'Makefile' else 'import app\nassert app.VALUE == 1\n')
                self.write(filename, recipe)
                self.write('app.py', 'VALUE = 1\n')
                self.base = self.commit()
                self.write(filename, recipe.replace('== 1', '== 2'))
                self.write('app.py', 'VALUE = 2\n')
                self.head = self.commit()
                self.write(filename, recipe.replace('== 1', '== 3'))
                self.write('app.py', 'VALUE = 2 + 0\n')
                diff = self.git('diff', '--', 'app.py', filename) + '\n'
                self.git('restore', '--', filename, 'app.py')
                m = self.manifest('hand', diff)
                errors, executed = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
                self.assertFalse(executed, errors)
                self.assertTrue(any('oracle' in e or 'TEST' in e for e in errors), errors)
                # Same proof command, production-only real regression remains a valid control.
                m = self.manifest('hand', '--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n'
                                         '-VALUE = 2\n+VALUE = 1\n')
                errors, executed = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
                self.assertTrue(executed, errors)

    def test_wrapped_reverts_cannot_restore_only_the_proof(self):
        self.cmd = f'env {shlex.quote(sys.executable)} runner.py'
        self.write('runner.py', 'import app\nassert app.VALUE == 1\n')
        self.base = self.commit()
        self.write('runner.py', 'import app\nassert app.VALUE == 2\n')
        self.head = self.commit()
        self.assertEqual(self.git('diff', self.base, self.head, '--', 'app.py'), '')
        for paths in (None, ['runner.py']):
            with self.subTest(paths=paths):
                m = self.manifest('revert')
                if paths:
                    m['negative_control']['paths'] = paths
                with mock.patch.object(verify, 'execute_negative_control',
                                       wraps=verify.execute_negative_control) as execute:
                    errors, executed = verify.check_negative_control(m, True, True, self.cmd)
                self.assertFalse(executed, errors)
                self.assertTrue(any('oracle' in e or 'TEST' in e for e in errors), errors)
                execute.assert_not_called()

    def test_module_pytest_config_cannot_supply_the_red(self):
        """python3 -m pytest must use pytest's option grammar: -c is config.

        If custom.ini stays a production path, a control that restores only that
        file can go RED via addopts without reverting the implementation.
        """
        self.cmd = f'{shlex.quote(sys.executable)} -m pytest -c custom.ini'
        self.write('custom.ini', '[pytest]\naddopts = -q\n')
        self.write('app.py', 'VALUE = 1\n')
        self.base = self.commit()
        self.write('custom.ini', '[pytest]\naddopts = -v\n')
        self.write('app.py', 'VALUE = 2\n')
        self.head = self.commit()
        m = self.manifest('hand', '--- a/custom.ini\n+++ b/custom.ini\n@@ -1,2 +1,2 @@\n'
                                  ' [pytest]\n-addopts = -v\n+addopts = -q\n')
        errors, executed = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
        self.assertFalse(executed, errors)
        self.assertTrue(any('oracle' in e or 'TEST' in e for e in errors), errors)
        with mock.patch.object(verify, 'execute_negative_control') as execute:
            errors, _ = verify.check_negative_control(m, True, execute=True, nc_command=self.cmd)
            self.assertTrue(errors)
            execute.assert_not_called()

    def test_unknown_proof_forms_fail_before_creating_worktrees(self):
        for command in ('nice python3 runner.py', 'env -S "python3 runner.py"',
                        'env env python3 runner.py', 'sh -c "python3 runner.py"',
                        'env PATH=tools python3 runner.py',
                        # PR #323 review, P1: an env assignment hid the runner behind `env`, so
                        # the proof read as production and a control could mutate it.
                        'env PYTHONPATH=. python runner.py',
                        'env PYTHONPATH=. python3 -u runner.py',
                        # A clustered or dangling short option hides where the value is.
                        'grep -vf patterns.txt app.py', 'grep -f', 'pytest -qc pytest.ini',
                        'python3 -c "exec(open(\"runner.py\").read())"',
                        'python3 -X presite=runner -m unittest', 'node --require runner.js check.js',
                        'make -C elsewhere test', 'custom-wrapper runner.py'):
            with self.subTest(command=command):
                self.cmd = command
                m = self.manifest('revert')
                m['negative_control']['paths'] = ['app.py']
                with mock.patch.object(verify, '_run', wraps=verify._run) as run, \
                        mock.patch.object(verify, '_apply_control') as apply:
                    ok, errors = verify.execute_negative_control(m, command)
                self.assertFalse(ok, errors)
                self.assertTrue(any('unsupported proof command' in e for e in errors), errors)
                self.assertFalse(any('worktree' in c.args[0] for c in run.call_args_list))
                apply.assert_not_called()

    def test_python_module_mode_rejects_untracked_or_flag_smuggling_runners_and_pins_repo_module(self):
        py = shlex.quote(sys.executable)
        for command in (
            f'{py} -m timeit -n 1 -r 1 -s "exec(open(\'/tmp/external_proof.py\').read())" pass',
            f'{py} -m pdb runner.py',
            f'{py} -I -m runner',
            f'{py} -m runner --eval-external',
            f'{py} -m runner /tmp/external_proof.py',
            f'{py} -m untracked_ghost_mod',
        ):
            with self.subTest(command=command):
                self.cmd = command
                m = self.manifest('revert')
                m['negative_control']['paths'] = ['app.py']
                with mock.patch.object(verify, '_apply_control') as apply:
                    ok, errors = verify.execute_negative_control(m, command)
                self.assertFalse(ok, errors)
                self.assertTrue(
                    any('unsupported proof command' in e or 'outside the staged commit' in e for e in errors),
                    errors,
                )
                apply.assert_not_called()
        # A tracked repo module that mutates itself during a phase also fails closed.
        self.write(
            'self_mutating_runner.py',
            'from pathlib import Path\n'
            'import app\n'
            'Path("self_mutating_runner.py").write_text("# tampered\\n")\n'
            'assert app.VALUE == 2\n',
        )
        self.write('app.py', 'VALUE = 1\n')
        self.base = self.commit()
        self.write('app.py', 'VALUE = 2\n')
        self.head = self.commit()
        self.cmd = f'{py} -m self_mutating_runner'
        m = self.manifest('revert')
        m['negative_control']['paths'] = ['app.py']
        ok, errors = verify.execute_negative_control(m, self.cmd)
        self.assertFalse(ok, errors)
        self.assertTrue(any('self_mutating_runner.py' in e and 'changed during' in e for e in errors), errors)
        # Parent package initializers (`harness/__init__.py`) are oracle inputs, never mutable production files.
        self.write('harness/__init__.py', 'assert False, "broken startup"\n')
        self.write(
            'harness/probe.py',
            'import app\n'
            'assert app.VALUE == 2\n',
        )
        self.write('app.py', 'VALUE = 2\n')
        self.base = self.commit()
        self.write('harness/__init__.py', 'pass\n')
        self.head = self.commit()
        self.cmd = f'{py} -m harness.probe'
        m_pkg = self.manifest('revert')
        m_pkg['negative_control']['paths'] = ['harness/__init__.py']
        self.assertIs(verify._is_oracle_path('harness/__init__.py', self.cmd, self.head), True)
        ok_pkg, err_pkg = verify.execute_negative_control(m_pkg, self.cmd)
        self.assertFalse(ok_pkg, err_pkg)
        static_pkg_errs, _ = verify.check_negative_control(m_pkg, True, execute=False, nc_command=self.cmd)
        self.assertTrue(static_pkg_errs, static_pkg_errs)



class PerRunCaches(RepoCase):
    """Review P3 (perf): _is_test_path re-loaded and re-executed diff_scope.py for every path it
    classified, and _roots_are_split spawned two git processes for every artifact read. Both
    answers are now taken once per run."""

    def test_diff_scope_is_loaded_once_for_many_paths(self):
        verify._load_diff_scope.cache_clear()
        self.addCleanup(verify._load_diff_scope.cache_clear)
        real = importlib.util.spec_from_file_location
        with mock.patch.object(verify.importlib.util, "spec_from_file_location",
                               side_effect=real) as spec:
            verdicts = [verify._is_test_path(p) for p in
                        ("tests/test_a.py", "src/a.py", "tests/test_b.py", "src/b.py", "x_test.go")]
        loads = [c for c in spec.call_args_list if c.args and c.args[0] == "diff_scope"]
        self.assertEqual(len(loads), 1, loads)
        self.assertEqual(verdicts[:4], [True, False, True, False])

    def test_a_missing_diff_scope_still_fails_closed_every_time(self):
        verify._load_diff_scope.cache_clear()
        self.addCleanup(verify._load_diff_scope.cache_clear)
        with mock.patch.object(verify.importlib.util, "spec_from_file_location",
                               side_effect=FileNotFoundError("gone")):
            self.assertIsNone(verify._is_test_path("tests/test_a.py"))
            self.assertIsNone(verify._is_test_path("tests/test_b.py"))

    def test_the_split_answer_spawns_git_once_per_run(self):
        td = _temp_repo()
        self.addCleanup(td.cleanup)
        other = Path(td.name).resolve()
        subprocess.run(["git", "init", "-q", str(other)], check=True)
        verify._ROOTS.update(git=str(other), evidence=str(self.repo))
        self.addCleanup(verify._ROOTS.update, git=None, evidence=None)
        verify._roots_are_split.cache.clear()
        self.addCleanup(verify._roots_are_split.cache.clear)
        verify._Authority.git_bin()  # pin first; its own custody probe is not this count
        with mock.patch.object(verify, "_run", wraps=verify._run) as run:
            answers = [verify._roots_are_split() for _ in range(5)]
        self.assertEqual(answers, [True] * 5)
        toplevels = [c for c in run.call_args_list if "--show-toplevel" in c.args[0]]
        # the SHA root's toplevel, once for the whole run (the evidence root is argv, no git)
        self.assertEqual(len(toplevels), 1, toplevels)


class ProofInputOptions(unittest.TestCase):
    """PR #323 review, P1.

    A short option is program-specific and may carry its value in the same token. One shared set
    read neither fact, so `pytest -c custom.ini` and `grep -fpatterns.txt` left their config and
    pattern files classified as production — a revert control could then turn the proof RED by
    changing the proof itself rather than the behavior under review.
    """

    def paths(self, command):
        return verify._command_oracle_paths(command)

    def test_a_program_specific_config_option_is_a_proof_input(self):
        for command in ('pytest -c custom.ini', 'pytest -ccustom.ini',
                        'pytest --config-file=custom.ini', 'pytest --config-file custom.ini',
                        'pytest --config=custom.ini', 'pytest -c custom.ini tests/',
                        'python3 -m pytest -c custom.ini', 'python3 -mpytest -c custom.ini',
                        'python3 -m pytest -ccustom.ini',
                        'python3 -m pytest --config-file custom.ini'):
            with self.subTest(command=command):
                self.assertIn('custom.ini', self.paths(command), command)

    def test_a_combined_short_option_is_a_proof_input(self):
        for command in ('grep -fpatterns.txt app.py', 'grep -f patterns.txt app.py',
                        'grep --file=patterns.txt app.py', 'grep --file patterns.txt app.py'):
            with self.subTest(command=command):
                self.assertIn('patterns.txt', self.paths(command), command)

    def test_a_flag_that_takes_no_value_consumes_no_operand(self):
        # grep -c counts; its operand is a pattern, and a data subject stays mutable.
        self.assertEqual(self.paths('grep -c pat app.py'), {'grep'})
        self.assertEqual(self.paths('grep -n pat app.py'), {'grep'})
        self.assertNotIn('pat', self.paths('grep -c pat app.py'))

    def test_a_cluster_or_dangling_option_is_refused_not_guessed(self):
        # The value is not where this grammar can read it, and guessing wrong leaves a proof
        # input mutable. Refusing the command is the fail-closed answer.
        for command in ('grep -vf patterns.txt app.py', 'grep -f', 'pytest -qc pytest.ini',
                        'pytest -c'):
            with self.subTest(command=command):
                self.assertIsNone(self.paths(command), command)

    def test_the_option_terminator_ends_option_reading(self):
        """PR #323 review, P1. After `--` everything is an operand however much it looks like an
        option, so `grep -- -f patterns.txt` names two files to SEARCH. Reading -f there marked a
        data subject as an oracle input and rejected the valid negative control mutation-testing
        it -- the false-positive direction, which blocks legitimate evidence."""
        self.assertNotIn('patterns.txt', self.paths('grep -- -f patterns.txt'))
        self.assertNotIn('custom.ini', self.paths('pytest -- -c custom.ini'))
        self.assertNotIn('custom.ini', self.paths('grep -- --config=custom.ini app.py'))
        # The terminator read is the SCRIPT's, not one the interpreter already consumed.
        self.assertNotIn('custom.ini', self.paths('python3 runner.py -- --config custom.ini'))
        self.assertIn('runner.py', self.paths('python3 runner.py -- --config custom.ini'))
        self.assertIn('custom.ini', self.paths('python3 runner.py --config custom.ini'))
        self.assertIn('custom.ini', self.paths('python3 -m pkg.mod --config custom.ini'))
        self.assertIn('patterns.txt', self.paths('python3 -u runner.py -f patterns.txt'))
        # A cluster after the terminator is an operand too, not a refusal.
        self.assertIsNotNone(self.paths('grep -- -vf patterns.txt'))

    def test_unrelated_programs_keep_their_grammar(self):
        self.assertEqual(self.paths('python3 runner.py'), {'python3', 'runner.py'})
        self.assertIn('Makefile.ci', self.paths('make -f Makefile.ci test'))
        self.assertIn('runner.py', self.paths('python3 -u runner.py'))


class LiteralControlPaths(RepoCase):
    @unittest.skipUnless(shutil.which('node'), 'JavaScript decrement replay requires node')
    def test_deleted_decrement_text_is_hunk_content(self):
        original = 'let counter = 3;\n++ counter;\nconsole.log(counter);\n'
        self.write('counter.js', original)
        self.write('runner.py', 'import subprocess\nassert subprocess.check_output('
                   '["node", "counter.js"], text=True).strip() == "2"\n')
        base = self.commit()
        self.write('counter.js', original.replace('++ counter;', '-- counter;'))
        head = self.commit()
        self.write('counter.js', original.replace('++ counter;', 'counter++;'))
        diff = self.git('diff') + '\n'
        self.assertIn('\n--- counter;\n+counter++;\n', diff)
        self.git('restore', '--', 'counter.js')
        self.assertEqual(verify._diff_target_paths(diff), ['counter.js'])
        art = self.artifact('RED\n' + diff)
        command = f'{shlex.quote(sys.executable)} runner.py'
        m = {'base_sha': base, 'head_sha': head, 'artifacts': [self.pin(art)],
             'negative_control': {'tool': 'hand', 'artifact': art, 'result': 'RED', 'command': command}}
        errors, executed = verify.check_negative_control(m, True, True, command)
        self.assertTrue(executed, errors)

    def test_literal_wildcard_cannot_borrow_other_file_coordinates(self):
        for name in ('values*.json', 'values?.json', 'values[ab].json', ':(glob)values*.json'):
            with self.subTest(name=name):
                original = '{\n  "note": 1,\n  "pad": 0,\n  "value": 2\n}\n'
                self.write(name, original)
                self.write('valuesa.json', original)
                self.write('runner.py', f'import json\ndata = json.load(open({name!r}))\n'
                           'assert data["value"] == 2\nassert data["note"] == 2\n')
                base = self.commit()
                self.write(name, original.replace('"note": 1', '"note": 2'))
                self.write('valuesa.json', original.replace('"value": 2', '"value": 3'))
                head = self.commit()
                self.write(name, Path(name).read_text().replace('"value": 2', '"value": 1'))
                diff = self.git('--literal-pathspecs', 'diff', '--', name) + '\n'
                self.git('--literal-pathspecs', 'restore', '--', name)
                command = f'{shlex.quote(sys.executable)} runner.py'
                art = self.artifact('RED\n' + diff, f'nc-{next(_SRC_SEQ)}.txt')
                m = {'base_sha': base, 'head_sha': head, 'artifacts': [self.pin(art)],
                     'negative_control': {'tool': 'hand', 'artifact': art, 'result': 'RED', 'command': command}}
                with mock.patch.object(verify, '_run_at', wraps=verify._run_at) as run_at:
                    errors, executed = verify.check_negative_control(m, True, True, command)
                self.assertFalse(executed, errors)
                self.assertTrue(any('untouched' in e for e in errors), errors)
                self.assertFalse(any(c.args[1] == shlex.split(command) for c in run_at.call_args_list))
                # A real regression at the changed note coordinate of the SAME literal path.
                self.write(name, original)
                diff = self.git('--literal-pathspecs', 'diff', '--', name) + '\n'
                self.git('--literal-pathspecs', 'restore', '--', name)
                art = self.artifact('RED\n' + diff, f'nc-{next(_SRC_SEQ)}.txt')
                m['negative_control']['artifact'] = art
                m['artifacts'] = [self.pin(art)]
                errors, executed = verify.check_negative_control(m, True, True, command)
                self.assertTrue(executed, errors)

    def test_literal_wildcard_revert_preserves_oracle_and_real_regression(self):
        self.write('*', '1\n')
        self.write('test_probe.py', 'assert int(open("*").read()) == 3\n')
        base = self.commit()
        self.write('*', '2\n')
        self.write('test_probe.py', 'assert int(open("*").read()) == 2\n')
        head = self.commit()
        command = f'{shlex.quote(sys.executable)} test_probe.py'
        m = {'base_sha': base, 'head_sha': head, 'negative_control': {
            'tool': 'revert', 'paths': ['*'], 'command': command}}
        observed, original_run = [], verify._run_at
        def observe(wt, argv, **kwargs):
            if argv == shlex.split(command):
                # the control is SEALED into a sibling commit (review P1), so compare the
                # checked-out tree with head_sha rather than with the worktree's own HEAD
                changed = original_run(wt, ['git', 'diff', '--name-only', head])[1].splitlines()
                observed.append((changed, (Path(wt) / 'test_probe.py').read_text()))
            return original_run(wt, argv, **kwargs)
        with mock.patch.object(verify, '_run_at', side_effect=observe):
            ok, errors = verify.execute_negative_control(m, command)
        self.assertTrue(ok, errors)
        self.assertEqual(observed, [([], 'assert int(open("*").read()) == 2\n'),
                                    (['*'], 'assert int(open("*").read()) == 2\n'),
                                    ([], 'assert int(open("*").read()) == 2\n')])

    def test_explicit_revert_inspects_actual_inventory_before_proof(self):
        self.write('app.py', 'VALUE = 1\n')
        self.write('runner.py', 'import app\nassert app.VALUE == 2\n')
        base = self.commit()
        self.write('app.py', 'VALUE = 2\n')
        head = self.commit()
        command = f'{shlex.quote(sys.executable)} runner.py'
        m = {'base_sha': base, 'head_sha': head, 'negative_control': {
            'tool': 'revert', 'paths': ['app.py'], 'command': command}}
        original_run = verify._run_at
        for extra in ('runner.py', 'extra.py'):
            with self.subTest(extra=extra):
                def inject(wt, argv, extra=extra, **kwargs):
                    result = original_run(wt, argv, **kwargs)
                    if 'checkout' in argv:
                        (Path(wt) / extra).write_text('assert False\n')
                        original_run(wt, ['git', 'add', '--', extra])
                    return result
                with mock.patch.object(verify, '_run_at', side_effect=inject) as run_at:
                    ok, errors = verify.execute_negative_control(m, command)
                self.assertFalse(ok, errors)
                self.assertTrue(any('path' in e for e in errors), errors)
                self.assertFalse(any(c.args[1] == shlex.split(command) for c in run_at.call_args_list))


class AuthoritativeReviewHistory(RepoCase):
    def setUp(self):
        super().setUp()
        self.write('app.py', 'VALUE = 2\n')
        self.reviewed = self.commit()
        self.git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '--allow-empty', '-qm', 'rebase')
        self.head = self.git('rev-parse', 'HEAD')
        self.tree = self.git('rev-parse', 'HEAD^{tree}')
        self.write('app.py', 'VALUE = 9\n')
        self.unrelated = self.commit()

    def review(self, who, state, sha):
        return {'user': {'login': who}, 'state': state, 'commit_id': sha, 'author_association': 'MEMBER'}

    def check(self, reviews, selected=None):
        m = {'head_sha': self.head, 'pr': {'number': 7, 'reviewed_sha': selected or self.head}}
        if selected:
            m['pr']['reviewed_wtree'] = self.tree
        with mock.patch.object(verify, 'fetch_reviews', return_value=(reviews, None)), \
                mock.patch.object(verify, 'fetch_pr_author', return_value='alice'):
            return verify.check_review(m, 'o/r', True)

    def test_manifest_cannot_select_away_an_equivalent_objection(self):
        reviews = [self.review('bob', 'CHANGES_REQUESTED', self.reviewed),
                   self.review('carol', 'APPROVED', self.head)]
        for selected in (None, self.head, self.reviewed):
            with self.subTest(selected=selected):
                self.assertTrue(self.check(reviews, selected))
        reviews.append(self.review('bob', 'DISMISSED', self.head))
        self.assertEqual(self.check(reviews), [])

    def test_unrelated_latest_review_does_not_withdraw_relevant_objection(self):
        for state in ('COMMENTED', 'APPROVED', 'DISMISSED', 'CHANGES_REQUESTED'):
            with self.subTest(state=state):
                reviews = [self.review('bob', 'CHANGES_REQUESTED', self.reviewed),
                           self.review('carol', 'APPROVED', self.head),
                           self.review('bob', state, self.unrelated)]
                self.assertTrue(self.check(reviews, self.reviewed))
                reviews.append(self.review('bob', 'COMMENTED', self.head))
                self.assertEqual(self.check(reviews, self.reviewed), [])

    def test_unresolved_objection_fails_closed_until_tree_is_known(self):
        reviews = [self.review('bob', 'CHANGES_REQUESTED', 'f' * 40),
                   self.review('carol', 'APPROVED', self.head)]
        self.assertTrue(any('resolve' in e for e in self.check(reviews)))
        reviews[0]['commit_id'] = self.unrelated
        self.assertEqual(self.check(reviews), [])

    def test_author_objection_and_dismissed_historical_review_do_not_veto(self):
        reviews = [self.review('alice', 'CHANGES_REQUESTED', self.reviewed),
                   self.review('bob', 'DISMISSED', self.reviewed),
                   self.review('carol', 'APPROVED', self.head)]
        self.assertEqual(self.check(reviews), [])

    def test_missing_history_superseded_on_current_content_does_not_veto(self):
        for state in ('COMMENTED', 'DISMISSED', 'APPROVED'):
            for current in (self.head, self.reviewed):
                with self.subTest(state=state, current=current):
                    reviews = [self.review('bob', 'CHANGES_REQUESTED', 'f' * 40),
                               self.review('bob', state, current),
                               self.review('carol', 'APPROVED', self.head)]
                    self.assertEqual(self.check(reviews), [])

    def test_missing_history_can_still_be_a_standing_objection(self):
        missing = self.review('bob', 'CHANGES_REQUESTED', 'f' * 40)
        approval = self.review('carol', 'APPROVED', self.head)
        for reviews in ([missing, self.review('bob', 'COMMENTED', self.unrelated), approval],
                        [self.review('bob', 'COMMENTED', self.head), missing, approval],
                        [missing, self.review('dave', 'COMMENTED', self.head), approval]):
            with self.subTest(reviews=reviews):
                self.assertTrue(any('resolve' in e for e in self.check(reviews)))


class OracleScopeKindTest(RepoCase):
    """PF-2 (prove-it self-run 2026-09-16): the oracle-scope kind gate.

    check_oracle_scope authorizes a reviewed hand control for test-only
    characterization or documentation work. The kind decides WHICH shape rules
    apply (characterization must change a test; documentation must change prose
    only) — an unknown kind slipping past this gate would skip both. The gate
    must refuse it here — including a scope that is not a mapping at all, whose
    kind cannot be read — and must admit both legal kinds past this gate (deeper
    gates still apply: the pair/ids/path checks below it).
    """

    def _contract(self, scope):
        rel = "contract-pf2.json"
        Path(rel).write_text(
            json.dumps({"criterion_ids": ["PF-2"], "oracle_scope": scope}),
            encoding="utf-8")
        return rel, _digest(rel)

    def test_bogus_kind_refused_at_kind_gate(self):
        rel, digest = self._contract({"kind": "bogus"})
        self.assertEqual(
            verify.check_oracle_scope({}, rel, digest),
            ["oracle scope: kind must be characterization or documentation"])

    def test_non_dict_scope_refused_at_kind_gate(self):
        # A legal kind NAME in an illegal SHAPE: the gate refuses on shape too.
        rel, digest = self._contract("characterization")
        self.assertEqual(
            verify.check_oracle_scope({}, rel, digest),
            ["oracle scope: kind must be characterization or documentation"])

    def test_characterization_passes_kind_gate(self):
        rel, digest = self._contract({"kind": "characterization",
                                      "base_sha": "a" * 40, "head_sha": "b" * 40})
        self.assertEqual(
            verify.check_oracle_scope({}, rel, digest),
            ["oracle scope: authorized commit pair differs from the manifest"])

    def test_documentation_passes_kind_gate(self):
        rel, digest = self._contract({"kind": "documentation",
                                      "base_sha": "a" * 40, "head_sha": "b" * 40})
        self.assertEqual(
            verify.check_oracle_scope({}, rel, digest),
            ["oracle scope: authorized commit pair differs from the manifest"])


class OracleScopeCharacterizationGateTest(RepoCase):
    """PF-3 (prove-it campaign 2026-09-16): the characterization must-change-a-test gate.

    One gate below PF-2's kind gate, check_oracle_scope enforces the lane's core
    invariant: a characterization unit MUST change a test (evidence-manifest.md
    §1 — characterization changes tests/prose only, and the test is what the
    mutant kills). A pair that changes no test must be refused here — including
    the vacuous pair that changes nothing at all; a pair that changes a test
    passes this gate and falls through to the pinned hand-mutant requirement.
    """

    def _contract(self, scope):
        rel = "contract-pf3.json"
        Path(rel).write_text(
            json.dumps({"criterion_ids": ["PF-3"], "oracle_scope": scope}),
            encoding="utf-8")
        return rel, _digest(rel)

    def _scope(self, base, head):
        return {"kind": "characterization", "base_sha": base, "head_sha": head,
                "criterion_ids": ["PF-3"], "paths": {"src/app.py": [1]}}

    def _base(self):
        self.write("src/app.py", "VALUE = 1\nTOTAL = 2\n")
        self.write("docs/note.md", "# note\n")
        self.write("tests/test_probe.py", "import unittest\n")
        return self.commit("base")

    def test_prose_only_change_refused_at_characterization_gate(self):
        base = self._base()
        self.write("docs/note.md", "# note\n\nmore prose\n")
        head = self.commit("prose only")
        rel, digest = self._contract(self._scope(base, head))
        self.assertEqual(
            verify.check_oracle_scope({"base_sha": base, "head_sha": head}, rel, digest),
            ["oracle scope: characterization must change a test"])

    def test_empty_diff_refused_at_characterization_gate(self):
        base = self._base()
        rel, digest = self._contract(self._scope(base, base))
        self.assertEqual(
            verify.check_oracle_scope({"base_sha": base, "head_sha": base}, rel, digest),
            ["oracle scope: characterization must change a test"])

    def test_test_change_passes_characterization_gate(self):
        base = self._base()
        self.write("tests/test_probe.py", "import unittest\n\n\nclass T(unittest.TestCase):\n    pass\n")
        head = self.commit("test change")
        rel, digest = self._contract(self._scope(base, head))
        self.assertEqual(
            verify.check_oracle_scope({"base_sha": base, "head_sha": head}, rel, digest),
            ["oracle scope: requires a pinned hand-mutant artifact"])


class CrossRepoRoots(RepoCase):
    """#442: a chained-run manifest lives in ONE repo and pins SHAs in ANOTHER.

    verify.py ran every git leg in the process cwd and bounded every evidence path against that
    same toplevel, so a cross-repo manifest satisfied neither invocation: run it in the fleet repo
    (where the chaining report lives) and the leg SHAs are "not a real commit"; run it in the target
    repo and every evidence path is "unreadable". There was no third place to stand. `--git-dir`
    and `--evidence-root` name the two roots separately; absent, resolution is exactly as before.

    Repo A (this case's repo, and the cwd) holds the manifest, the contract and the artifacts.
    Repo B is a second scratch repo holding the commits the manifest pins.
    """

    def setUp(self):
        super().setUp()
        # Repo B — the TARGET repo: the only place base_sha/head_sha exist.
        self._td_b = _temp_repo(prefix="orca-u442-b-")
        self.addCleanup(self._td_b.cleanup)
        self.repo_b = Path(self._td_b.name).resolve()
        self.git_b("init", "-q", "-b", "main")
        (self.repo_b / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        (self.repo_b / "check.py").write_text(
            "import app\nassert app.f() == 2, 'AC-1 violated'\n", encoding="utf-8")
        self.base_sha = self.commit_b("base")
        (self.repo_b / "app.py").write_text("def f():\n    return 2\n", encoding="utf-8")
        self.head_sha = self.commit_b("head")
        self.head_tree = self.git_b("rev-parse", "HEAD^{tree}")

        # Repo A — the EVIDENCE repo: contract and artifacts, named relatively as a manifest
        # names them, pinned by artifacts[] because they are not tracked at repo B's head_sha.
        self.contract = self.src(["AC-1"])
        self.contract_digest = RepoCase.digest(self, self.contract)
        self.nc_artifact = self.artifact("mutant m7 was KILLED — proof went RED\n")
        self.proof_cmd = f"{shlex.quote(sys.executable)} check.py"

        self._orig_r, self._orig_a = verify.fetch_reviews, verify.fetch_pr_author
        verify.fetch_reviews = lambda repo_, n: (
            [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": self.head_sha, "user": {"login": "carol"}}], None)
        verify.fetch_pr_author = lambda repo_, n: "alice"
        self.addCleanup(self._restore_gh)
        self.addCleanup(self._reset_roots)

    def _reset_roots(self):
        # main() writes the roots as PROCESS state, so a later case must not inherit them.
        # getattr, because this has to survive the control run too: with the split reverted
        # there is no _ROOTS, and a teardown that raises there would turn every assertion in
        # this class into an error — a stillborn mutant instead of a kill.
        getattr(verify, "_ROOTS", {}).update(git=None, evidence=None)

    def _restore_gh(self):
        verify.fetch_reviews, verify.fetch_pr_author = self._orig_r, self._orig_a

    def git_b(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo_b, check=True,
                              capture_output=True, text=True).stdout.strip()

    def commit_b(self, message):
        self.git_b("add", "-A")
        self.git_b("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", message)
        return self.git_b("rev-parse", "HEAD")

    def _manifest(self, **over):
        m = {"unit": "chain-leg-1",
             "base_sha": self.base_sha, "head_sha": self.head_sha,
             "contract": {"source": self.contract, "digest": self.contract_digest,
                          "criterion_ids": ["AC-1"]},
             "criteria": _crit("AC-1"),
             "artifacts": [self.pin(self.nc_artifact)],
             "pr": {"number": 7, "reviewed_sha": self.head_sha},
             "negative_control": {"tool": "mutmut", "result": "KILLED", "mutant": "m7",
                                  "artifact": self.nc_artifact},
             "commands": [{"label": "tests", "cmd": self.proof_cmd,
                           "cmd_sha256": hashlib.sha256(
                               self.proof_cmd.encode("utf-8")).hexdigest(),
                           "exit": 0, "wtree": self.head_tree,
                           "artifact": self.nc_artifact}],
             "intent": {"goal": "land the chained leg", "ruled_out": "a single-repo manifest",
                        "why": "the criterion demands it"},
             "reviewer_mode": "cross-vendor", "lighting": "lit"}
        m.update(over)
        path = self.repo / "manifest.json"
        path.write_text(json.dumps(m), encoding="utf-8")
        return str(path)

    def _run_main(self, path, *extra):
        """(exit code, combined output). argparse answers an option it does not know by exiting,
        which is a verdict on the invocation — "this verifier cannot be asked that" — so it is
        reported as the code it is and asserted on. Letting it raise past the assertion is how a
        missing flag reads as a test ERROR rather than the failure it is, and the negative control
        for this unit is precisely a verifier that does not know these two options yet."""
        buf, errbuf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            try:
                if "--execute-nc" not in extra and "--dispatch-record" not in extra:
                    extra = (*extra, "--allow-static-nc")
                rc = verify.main(["--manifest", path,
                                  "--contract-source", self.contract,
                                  "--contract-digest", self.contract_digest,
                                  "--repo", "o/r", "--unit-class", "mutation", "--lighting", "lit",
                                  *extra])
            except SystemExit as exit_:
                rc = exit_.code
        return rc, buf.getvalue() + errbuf.getvalue()

    def test_split_roots_verify_a_cross_repo_manifest_end_to_end(self):
        """The unit's whole point: evidence in repo A, SHAs in repo B, GREEN in one invocation."""
        rc, out = self._run_main(self._manifest(),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    def test_without_the_split_the_same_manifest_cannot_verify(self):
        """The negative control for the feature itself: one root cannot reach both authorities.

        Standing in the evidence repo, the pinned commits do not exist — which is exactly the
        state #442 reported, and exactly what the two flags (and only they) resolve.
        """
        rc, out = self._run_main(self._manifest())
        self.assertEqual(rc, 2, out)
        self.assertTrue(any(f"'{sha}' is not a real commit" in out
                            for sha in (self.base_sha, self.head_sha)), out)

    def test_git_dir_alone_leaves_evidence_resolution_where_it_was(self):
        """--evidence-root is not implied by --git-dir: absent, evidence still resolves against
        the CWD's toplevel. Pointing only the git leg away must not silently move the bound."""
        rc, out = self._run_main(self._manifest(), "--git-dir", str(self.repo_b))
        self.assertEqual(rc, 0, out)

    def test_an_escaping_evidence_path_is_still_refused_against_the_named_root(self):
        """#267 is preserved, not relaxed: the root moved, the bound did not."""
        m = self._manifest(negative_control={"tool": "mutmut", "result": "KILLED", "mutant": "m7",
                                             "artifact": "../outside/nc.txt"})
        rc, out = self._run_main(m, "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("escapes the evidence root", out)

    def test_an_absolute_evidence_path_is_still_refused_against_the_named_root(self):
        outside = Path(self._td_b.name) / "nc.txt"
        outside.write_text("mutant m7 was KILLED\n", encoding="utf-8")
        m = self._manifest(negative_control={"tool": "mutmut", "result": "KILLED", "mutant": "m7",
                                             "artifact": str(outside)})
        rc, out = self._run_main(m, "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("absolute evidence path refused", out)

    def test_an_unpinned_cross_repo_artifact_is_refused(self):
        """Cross-repo evidence can never be "tracked at head_sha" — the other repo does not hold
        it — so artifacts[] is the ONLY thing standing between the auditor and a rewritable file.
        Dropping the pin must fail, or the split would have bought a way around #267."""
        rc, out = self._run_main(self._manifest(artifacts=[]),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("unpinned evidence", out)

    def test_a_root_outside_a_git_repo_is_refused(self):
        """Evidence an auditor cannot re-derive from a clone is what #267 refuses; --evidence-root
        names WHICH clone, never an unversioned directory."""
        with _temp_repo(prefix="orca-u442-bare-") as loose:
            for flag in ("--git-dir", "--evidence-root"):
                with self.subTest(flag=flag):
                    rc, out = self._run_main(self._manifest(), flag, loose)
                    self.assertEqual(rc, 1, out)
                    self.assertIn("not inside a git work tree", out)

    # ---- round 2 (#442 R1/R2, T1–T5): the AUTHORITY boundary, not just the happy path ----

    def _commit_b_extra(self, files):
        """Add a commit to repo B and re-pin the manifest's head to it. app.py always moves so the
        head commit keeps changing a source file, as the fixture's first head commit does."""
        for rel, text in files.items():
            dest = self.repo_b / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        (self.repo_b / "app.py").write_text(
            "def f():\n    return 2\n# %s\n" % "-".join(sorted(files)), encoding="utf-8")
        self.head_sha = self.commit_b("head+" + ",".join(sorted(files)))
        self.head_tree = self.git_b("rev-parse", "HEAD^{tree}")
        return self.head_sha

    def _collide(self, text="mutant m7 SURVIVED and was NOT killed\n"):
        """Commit a DIFFERENT file at the evidence artifact's own relative path in the SHA repo.

        This is the collision R1/T1 turn on: nothing stops two repositories holding the same
        relative name. The planted bytes say the mutant survived, so a verifier that reads them
        instead of the pinned evidence flips the verdict RED — the kill is a verdict, not a mock.
        """
        return self._commit_b_extra({self.nc_artifact: text})

    def _read_under_split(self, m):
        """read_artifact with the roots set as main() would set them, to name the bytes that won."""
        verify._ROOTS.update(git=str(self.repo_b), evidence=str(self.repo))
        try:
            return verify.read_artifact(m, self.nc_artifact)
        finally:
            self._reset_roots()

    def test_a_colliding_sha_repo_blob_cannot_substitute_for_pinned_evidence(self):
        """R1/T1: same path in both repos — the PINNED copy in the evidence root must win.

        Unfixed, the tracked-at-head_sha shortcut asks the SHA repo for `head:path` and returns
        ITS bytes before the evidence root or artifacts[] is ever consulted: commit-pinned, to the
        wrong repository.
        """
        self._collide()
        rc, out = self._run_main(self._manifest(),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)
        raw, err = self._read_under_split({"head_sha": self.head_sha,
                                           "artifacts": [self.pin(self.nc_artifact)]})
        self.assertIsNone(err)
        self.assertEqual(raw, (self.repo / self.nc_artifact).read_bytes())
        self.assertNotIn(b"SURVIVED", raw)

    def test_a_colliding_sha_repo_blob_cannot_stand_in_for_a_missing_pin(self):
        """R1/T1: drop artifacts[] and the SHA repo's same-path blob must NOT rescue the read."""
        self._collide("mutant m7 was KILLED — proof went RED\n")
        rc, out = self._run_main(self._manifest(artifacts=[]),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("unpinned evidence", out)

    def test_a_colliding_sha_repo_blob_cannot_satisfy_a_mismatched_pin(self):
        """R1/T1: the pin is declared over the EVIDENCE bytes, so rewriting them must go RED even
        when the SHA repo still holds a well-formed blob at the same path."""
        self._collide("mutant m7 was KILLED — proof went RED\n")
        m = self._manifest()  # pins the evidence bytes as they stand...
        (self.repo / self.nc_artifact).write_text(
            "mutant m7 was KILLED — rewritten after inventory\n", encoding="utf-8")
        rc, out = self._run_main(m, "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("the evidence changed after it was inventoried", out)

    def test_two_clones_of_one_project_are_still_two_repositories(self):
        """R1: the split is not about differing paths — two clones of ONE project share every
        path. Identity of the ROOT is what licenses the tracked-blob shortcut, so a stale pin must
        still go RED even though the clone tracks a perfectly good blob at that very path."""
        self.write("app.py", "def f():\n    return 1\n")
        self.artifact("mutant m7 was KILLED — proof went RED\n")
        self.src(["AC-1"])
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        with _temp_repo(prefix="orca-u442-clone-") as clone_parent:
            clone = str(Path(clone_parent) / "c")
            subprocess.run(["git", "clone", "-q", str(self.repo), clone],
                           check=True, capture_output=True)
            m = self._manifest()  # pin taken over the committed bytes...
            (self.repo / self.nc_artifact).write_text(
                "mutant m7 was KILLED — rewritten after inventory\n", encoding="utf-8")
            rc, out = self._run_main(m, "--git-dir", clone,
                                     "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("the evidence changed after it was inventoried", out)

    def test_the_symbol_leg_runs_in_the_sha_repo_not_the_process_cwd(self):
        """R2/T5: --symbol grepped origin/<base> in the process cwd while the adjacent ancestry
        check used --git-dir. A symbol that IS on the target's base must not read as missing."""
        self.git_b("update-ref", "refs/remotes/origin/main", self.head_sha)
        rc, out = self._run_main(self._manifest(),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo),
                                 "--base", "main", "--symbol", "def f")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("not found on origin/main", out)

    def test_a_symbol_only_in_the_evidence_repo_is_not_accepted_as_on_base(self):
        """R2's other half: the same bug is a false ACCEPTANCE too. A symbol that exists only in
        the evidence repo must not satisfy a claim about the SHA repo's base."""
        self.git_b("update-ref", "refs/remotes/origin/main", self.head_sha)
        self.write("only_here.py", "ONLY_IN_EVIDENCE_REPO = 1\n")
        self.commit("evidence-only symbol")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        rc, out = self._run_main(self._manifest(),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo),
                                 "--base", "main", "--symbol", "ONLY_IN_EVIDENCE_REPO")
        self.assertEqual(rc, 2, out)
        self.assertIn("not found on origin/main", out)

    def test_a_path_at_ref_contract_read_uses_the_sha_repo(self):
        """T5: the raw-byte `path@ref` read is a SHA-repo leg. The fixture only ever read a bare
        working-tree contract, so a helper that dropped its root selection survived."""
        body = "frozen\n- AC-1: x\n"
        ref = self._commit_b_extra({"git-contract.md": body})
        source = f"git-contract.md@{ref}"
        digest = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
        self.contract, self.contract_digest = source, digest
        rc, out = self._run_main(self._manifest(
            contract={"source": source, "digest": digest, "criterion_ids": ["AC-1"]}),
            "--git-dir", str(self.repo_b), "--evidence-root", str(self.repo))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    def test_the_named_evidence_root_is_honored_from_a_distinct_cwd(self):
        """T2: every existing case ran AT repo A, where the requested root and the cwd fallback
        are the same directory — so a verifier that parsed --evidence-root and then ignored it
        passed. Stand somewhere else and only an honored flag can find the evidence."""
        path = self._manifest()
        os.chdir(self.repo_b)
        self.addCleanup(os.chdir, self.repo)
        rc, out = self._run_main(path, "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    def test_the_evidence_root_may_be_a_named_subdirectory_of_the_clone(self):
        """T2, tighter: the root is a directory, not 'the repo'. Paths bind to the NAMED root."""
        sub = self.repo / "evidence"
        (sub / "docs" / "reports" / "u").mkdir(parents=True, exist_ok=True)
        (sub / "contract.md").write_text("frozen\n- AC-1: x\n", encoding="utf-8")
        nc = sub / "docs" / "reports" / "u" / "nc.txt"
        nc.write_text("mutant m7 was KILLED — proof went RED\n", encoding="utf-8")
        digest = "sha256:" + hashlib.sha256((sub / "contract.md").read_bytes()).hexdigest()
        self.contract, self.contract_digest = "contract.md", digest
        rc, out = self._run_main(self._manifest(
            contract={"source": "contract.md", "digest": digest, "criterion_ids": ["AC-1"]},
            artifacts=[{"path": self.nc_artifact,
                        "sha256": hashlib.sha256(nc.read_bytes()).hexdigest()}]),
            "--git-dir", str(self.repo_b), "--evidence-root", str(sub))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    def test_an_evidence_path_escaping_through_a_symlink_is_refused(self):
        """T3: #267's containment is CANONICAL, not a spelling rule. The committed escape case
        spells a leading `..`, which the lexical check catches first — so the canonical check
        could be deleted outright and the suite stayed green. A symlink escapes without ever
        writing `..`.

        The escaping path is PINNED, and so is the ordinary one (#442 R2-T2): unpinned, the
        refusal could be the missing pin rather than the bound, and a verifier that let a
        declared artifacts[] entry authorize the escape would still look refused. Containment
        is not a pin check — a pin says WHICH bytes, never WHERE they may live.
        """
        (self.repo / "escape-link").symlink_to(self.repo_b, target_is_directory=True)
        escaped = self.repo_b / "nc.txt"
        escaped.write_text("mutant m7 was KILLED — proof went RED\n", encoding="utf-8")
        m = self._manifest(
            artifacts=[self.pin(self.nc_artifact),
                       {"path": "escape-link/nc.txt",
                        "sha256": hashlib.sha256(escaped.read_bytes()).hexdigest()}],
            negative_control={"tool": "mutmut", "result": "KILLED", "mutant": "m7",
                              "artifact": "escape-link/nc.txt"})
        rc, out = self._run_main(m, "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("escapes the evidence root", out)
        self.assertNotIn("unpinned evidence", out)

    def test_a_nested_evidence_root_bounds_against_itself_not_the_clone(self):
        """T3's boundary case: with the root nested inside the clone, escaping UPWARD into the
        enclosing repo is still an escape. A symlink to the parent stays inside a git work tree,
        so only the canonical bound refuses it.

        Everything the nested root owes is inside it (#442 R2-T2): its own contract, its own
        ordinary command artifact, and a pin for BOTH the ordinary path and the escaping one.
        Without them the verifier refused this manifest for a missing contract and a missing
        artifact, and the escape it was written for was never the thing being proven.
        """
        sub = self.repo / "evidence"
        (sub / "docs" / "reports" / "u").mkdir(parents=True, exist_ok=True)
        (sub / "contract.md").write_text("frozen\n- AC-1: x\n", encoding="utf-8")
        ordinary = sub / self.nc_artifact
        ordinary.write_text("mutant m7 was KILLED — proof went RED\n", encoding="utf-8")
        digest = "sha256:" + hashlib.sha256((sub / "contract.md").read_bytes()).hexdigest()
        self.contract, self.contract_digest = "contract.md", digest
        (sub / "up-link").symlink_to(self.repo, target_is_directory=True)
        escaping = f"up-link/{self.nc_artifact}"
        m = self._manifest(
            contract={"source": "contract.md", "digest": digest, "criterion_ids": ["AC-1"]},
            artifacts=[{"path": self.nc_artifact,
                        "sha256": hashlib.sha256(ordinary.read_bytes()).hexdigest()},
                       {"path": escaping,
                        "sha256": hashlib.sha256(
                            (self.repo / self.nc_artifact).read_bytes()).hexdigest()}],
            negative_control={"tool": "mutmut", "result": "KILLED", "mutant": "m7",
                              "artifact": escaping})
        rc, out = self._run_main(m, "--git-dir", str(self.repo_b), "--evidence-root", str(sub))
        self.assertEqual(rc, 2, out)
        self.assertIn("escapes the evidence root", out)
        self.assertNotIn("unpinned evidence", out)
        self.assertNotIn("contract unreadable", out)

    def test_a_valid_no_flag_run_from_a_nested_directory_still_binds_to_the_toplevel(self):
        """T4: legacy compatibility is a claim about RESOLUTION, and every no-flag fixture ran at
        the toplevel, where cwd and toplevel coincide. Run a valid single-repo manifest from a
        nested directory: resolution must still land on the git toplevel."""
        self.write("app.py", "def f():\n    return 1\n")
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        path = self._manifest()
        nested = self.repo / "deep" / "nested"
        nested.mkdir(parents=True, exist_ok=True)
        os.chdir(nested)
        self.addCleanup(os.chdir, self.repo)
        rc, out = self._run_main(path)  # no --git-dir, no --evidence-root: the legacy invocation
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    # ---- round 3 (#442 R2-T1/T3, S2-R3, guard): the ROOT CLASSIFIER and the clock ----

    def test_only_git_flag_collision_still_requires_pin(self):
        """R2-T1: ONE flag is already a split. --git-dir alone moves the SHAs to B and leaves the
        bound on A's toplevel — two roots, so the shortcut is not A's to take. A classifier that
        only calls a split when BOTH flags are named (`and` -> `or`) reads this as one repo and
        hands the verdict to B's same-path blob."""
        self._collide("mutant m7 was KILLED — proof went RED\n")
        rc, out = self._run_main(self._manifest(artifacts=[]), "--git-dir", str(self.repo_b))
        self.assertEqual(rc, 2, out)
        self.assertIn("unpinned evidence", out)

    def test_only_evidence_flag_collision_still_requires_pin(self):
        """R2-T1, the mirror: --evidence-root alone, standing IN the SHA repo. The bound moves to
        A while the SHAs stay where the verifier runs — still two roots, still no shortcut."""
        self._collide("mutant m7 was KILLED — proof went RED\n")
        path = self._manifest(artifacts=[])
        os.chdir(self.repo_b)
        self.addCleanup(os.chdir, self.repo)
        rc, out = self._run_main(path, "--evidence-root", str(self.repo))
        self.assertEqual(rc, 2, out)
        self.assertIn("unpinned evidence", out)

    def test_same_repo_nested_evidence_cannot_borrow_root_blob(self):
        """R2-T1: repository identity is not ROOT identity. With the SHAs and a nested evidence
        root in ONE clone, a classifier that resolves the evidence root back to its enclosing
        repository loses the named subdirectory and calls it single-repo — and the enclosing
        repo's tracked blob at the same relative path answers for evidence the named root never
        pinned."""
        self.write("app.py", "def f():\n    return 1\n")
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        sub = self.repo / "evidence"
        (sub / "docs" / "reports" / "u").mkdir(parents=True, exist_ok=True)
        (sub / "contract.md").write_text("frozen\n- AC-1: x\n", encoding="utf-8")
        (sub / self.nc_artifact).write_text(
            "mutant m7 was KILLED — the NAMED root's own copy\n", encoding="utf-8")
        digest = "sha256:" + hashlib.sha256((sub / "contract.md").read_bytes()).hexdigest()
        self.contract, self.contract_digest = "contract.md", digest
        rc, out = self._run_main(self._manifest(
            contract={"source": "contract.md", "digest": digest, "criterion_ids": ["AC-1"]},
            artifacts=[]), "--evidence-root", str(sub))
        self.assertEqual(rc, 2, out)
        self.assertIn("unpinned evidence", out)

    def test_symbol_only_on_head_cannot_substitute_for_base(self):
        """R2-T3: the check's claim is `on origin/<base>`, and every fixture so far pointed
        origin/main AT head, so the ref in the grep was free. A symbol that exists only on a
        LATER local HEAD is not on base, and must not read as if it were."""
        self.git_b("update-ref", "refs/remotes/origin/main", self.head_sha)
        (self.repo_b / "later.py").write_text("ONLY_ON_LOCAL_HEAD = 1\n", encoding="utf-8")
        self.git_b("add", "-A")
        self.git_b("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "later")
        rc, out = self._run_main(self._manifest(),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo),
                                 "--base", "main", "--symbol", "ONLY_ON_LOCAL_HEAD")
        self.assertEqual(rc, 2, out)
        self.assertIn("not found on origin/main", out)

    def test_symbol_only_on_base_is_found_even_when_head_deleted_it(self):
        """R2-T3's other direction, and the one a HEAD grep gets backwards: the change IS on base,
        a later local commit removed it, and the manifest's claim about base still holds."""
        self.git_b("update-ref", "refs/remotes/origin/main", self.head_sha)
        (self.repo_b / "app.py").write_text("PLACEHOLDER = 0\n", encoding="utf-8")
        self.git_b("add", "-A")
        self.git_b("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "drop def f")
        rc, out = self._run_main(self._manifest(),
                                 "--git-dir", str(self.repo_b),
                                 "--evidence-root", str(self.repo),
                                 "--base", "main", "--symbol", "def f")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("not found on origin/main", out)

    def test_the_symbol_grep_keeps_the_legacy_twenty_second_budget(self):
        """S2-R3: routing this leg through _git bought the SHA root and silently halved its clock,
        because _git defaults to 10s where the _run call it replaced defaulted to 20s. A grep that
        took 11s then turned a symbol that IS on base into a fatal miss — with neither root flag
        named, which is the invocation the unit promised to leave byte-identical.

        The clock itself is not assertable in a suite that must stay fast (the boundary is an
        11-second git), so what is pinned is the VALUE that reaches subprocess: the legacy
        default of _run, not the newer default of _git.
        """
        self.git("update-ref", "refs/remotes/origin/main", self.commit("base"))
        seen = []
        original_run = verify._run

        def recording_run(args, timeout=20, cwd=None, env=None):
            seen.append((args, timeout))
            return original_run(args, timeout=timeout, cwd=cwd, env=env)

        verify._run = recording_run
        self.addCleanup(setattr, verify, "_run", original_run)
        verify.check_symbol_on_base("def f", "main")
        greps = [t for args, t in seen if "grep" in args]
        legacy = inspect.signature(original_run).parameters["timeout"].default
        rerouted = inspect.signature(verify._git).parameters["timeout"].default
        self.assertEqual(greps, [legacy], seen)
        self.assertNotEqual(legacy, rerouted, "the two defaults coincide — the pin proves nothing")

    def test_explicitly_equal_roots_keep_the_tracked_artifact_shortcut(self):
        """R3-T1: the classifier's POSITIVE case, which nothing pinned.

        Every other case here distinguishes roots that differ — two repos, a nested subroot, one
        flag, no flags. None of them fails when the comparison is deleted outright: a classifier
        that answers `True` unconditionally still calls every one of those a split, so the whole
        suite stays green while a valid same-root manifest is refused. The identity the shortcut
        rests on is that BOTH flags may name the SAME root, and then the evidence is exactly the
        blob git tracks at head_sha — no artifacts[] pin required, as before the split existed.
        """
        self.write("app.py", "def f():\n    return 1\n")
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        rc, out = self._run_main(self._manifest(artifacts=[]),
                                 "--git-dir", str(self.repo),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    def test_an_aliased_spelling_of_one_root_is_not_a_split(self):
        """R3-T1, the canonicalization half: `.resolve()` is in that comparison because a root can
        be SPELLED two ways. A symlink to the repo is the same repository, so the shortcut is
        still available — a classifier that compares the raw strings, or skips the comparison,
        turns one root wearing two names into a refusal for unpinned evidence."""
        self.write("app.py", "def f():\n    return 1\n")
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        alias = Path(self._td_b.name) / "alias-to-a"
        alias.symlink_to(self.repo, target_is_directory=True)
        rc, out = self._run_main(self._manifest(artifacts=[]),
                                 "--git-dir", str(alias),
                                 "--evidence-root", str(self.repo))
        self.assertEqual(rc, 0, out)
        self.assertIn("verify: OK", out)

    def test_a_tracked_artifact_is_read_at_head_sha_not_at_local_HEAD(self):
        """R3-T2: `head_sha` in the shortcut is the MANIFEST's revision, not wherever the checkout
        happens to be standing. The existence probe asks `cat-file -e <head_sha>:<path>`, and the
        read that follows has to ask the same commit — a `show HEAD:<path>` reads whatever the
        working checkout advanced to, and no test here noticed.

        The shape that makes it a verdict: the manifest's revision records a SURVIVED control, a
        LATER local commit rewrites that same artifact to say KILLED. The manifest's own bytes
        refuse; the later ones approve. Evidence is immutable or it is not evidence — an auditor
        who can move HEAD can grant themselves the kill the run never produced.
        """
        self.write("app.py", "def f():\n    return 1\n")
        self.artifact("mutant m7 SURVIVED and was NOT killed\n")
        self.base_sha = self.commit("base")
        self.write("app.py", "def f():\n    return 2\n")
        self.head_sha = self.commit("manifest head")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        self.artifact("mutant m7 was KILLED — proof went RED at a LATER local commit\n")
        later_sha = self.commit("later local head")
        self.assertNotEqual(self.head_sha, later_sha)
        rc, out = self._run_main(self._manifest(artifacts=[]))
        self.assertEqual(rc, 2, out)
        self.assertIn("reports the pinned mutant SURVIVED / was not killed", out)

    def test_an_unresolvable_root_fails_closed_to_split(self):
        """The classifier's own docstring: identity must be PROVEN. When the filesystem refuses to
        canonicalize a root there is no proof either way, and the safe answer is the one that
        keeps the shortcut shut. Covered rather than waived — a branch nobody executes is a
        branch nobody knows the sign of.

        R3-T3: the fixture names two DIFFERENT roots, so True is also the ordinary comparison's
        answer — the verdict alone cannot tell a fired probe from a bypassed one. A behaviour-
        neutral refactor that binds the canonicalizer at definition time (`def _roots_are_split(
        resolve=Path.resolve)`) leaves this patch intercepting nothing, and the OSError arm can
        then be inverted to `return False` with this test still green. So the probe asserts it
        FIRED, with the literal count: the first canonicalization raises, so there is no second
        call. A refactor that walks past the hook now fails loudly until the probe is retargeted.
        """
        verify._ROOTS.update(git=str(self.repo_b), evidence=str(self.repo))
        self.addCleanup(self._reset_roots)
        verify._Authority.git_bin()  # the pin's own custody probe resolves once; not this probe (h409 R2)
        refuse = OSError(errno.ELOOP, "Too many levels of symbolic links")
        with mock.patch.object(Path, "resolve", side_effect=refuse) as fired:
            self.assertTrue(verify._roots_are_split())
        self.assertEqual(fired.call_count, 1,
                         "canonicalization exception probe must fire exactly once")

    def test_help_documents_both_roots(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            verify.main(["--help"])
        text = buf.getvalue()
        for flag in ("--git-dir", "--evidence-root"):
            self.assertIn(flag, text)

class DotSlashEvidenceSpelling(RepoCase):
    """h409 F-3 (C2): `./`-spelled evidence bound where git's cwd diverged from the toplevel.
    _resolve bounded `./reports/u/nc.txt` against the toplevel, but the git lookup handed the
    manifest STRING to `cat-file -e head:./reports/u/nc.txt`, which git resolves against ITS cwd
    — so with the verifier (or --git-dir) below the toplevel the verdict bound a path that does
    not exist at the bounded root. Both sides must see one spelling: leading `./` segments are
    stripped before the containment check AND the git lookup."""

    def setUp(self):
        super().setUp()
        self.write("app.py", "x = 1\n")
        self.artifact("mutant m7 was KILLED — proof went RED\n")  # docs/reports/u/nc.txt
        self.head = self.commit("head")
        self.m = {"head_sha": self.head}

    def test_dotslash_from_a_below_toplevel_cwd_reds_like_the_toplevel_does(self):
        # Control: from the toplevel the path is absent at the root and the read fails.
        _, err = verify._read_artifact(self.m, "./reports/u/nc.txt")
        self.assertIsNotNone(err)
        # The C2 reproduction: same manifest string, cwd = <root>/docs.
        os.chdir(self.repo / "docs")
        raw, err = verify._read_artifact(self.m, "./reports/u/nc.txt")
        self.assertIsNone(raw, "a path absent at the bounded root was read via git's cwd")
        self.assertIsNotNone(err)

    def test_dotslash_from_a_below_toplevel_git_dir_reds_too(self):
        verify._ROOTS.update(git=str(self.repo / "docs"), evidence=None)
        try:
            raw, err = verify._read_artifact(self.m, "./reports/u/nc.txt")
        finally:
            verify._ROOTS.update(git=None, evidence=None)
        self.assertIsNone(raw, "a path absent at the bounded root was read via --git-dir's cwd")
        self.assertIsNotNone(err)

    def test_dotslash_spelling_of_a_real_tracked_path_still_reads(self):
        raw, err = verify._read_artifact(self.m, "./docs/reports/u/nc.txt")
        self.assertIsNone(err)
        self.assertIn(b"KILLED", raw)
        os.chdir(self.repo / "docs")
        raw, err = verify._read_artifact(self.m, "./docs/reports/u/nc.txt")
        self.assertIsNone(err)
        self.assertIn(b"KILLED", raw)

    def test_a_tracked_directory_is_not_an_artifact(self):
        # reaudit-r2 P3: `cat-file -e` succeeds on a TREE too, and `git show` would print the
        # directory's listing as if it were artifact bytes. The probe is typed: blob or refuse.
        raw, err = verify._read_artifact(self.m, "docs/reports")
        self.assertIsNone(raw, "a tracked directory read as artifact bytes")
        self.assertIsNotNone(err)

    def test_dotslash_path_at_ref_source_resolves_against_the_toplevel(self):
        os.chdir(self.repo / "docs")
        raw, err = verify.read_source(f"./docs/reports/u/nc.txt@{self.head}")
        self.assertIsNone(err)
        self.assertIn(b"KILLED", raw)
        raw, err = verify.read_source(f"./reports/u/nc.txt@{self.head}")
        self.assertIsNone(raw, "a path@ref absent at the toplevel was read via git's cwd")


class TranscriptKeyCustody(TranscriptFixture):
    """h409 F-4 (C3), verify.py's leg: --transcript-key reads the seed through dispatch-sign.py's
    shared _seed. A 0644 seed, or one inside an unignored work tree, is a USAGE refusal (exit 1)
    before any verdict — never a transcript quietly signed by a leaked seed — and a passing seed's
    custody class is named on stderr."""

    def test_a_world_readable_seed_is_refused_before_any_verdict(self):
        os.chmod(self.key, 0o644)
        rc, out, err = self._main("--transcript-out", "docs/reports/u/transcript.json",
                                  "--transcript-key", self.key)
        self.assertEqual(rc, 1, err)
        self.assertIn("custody", err)
        self.assertIn("0644", err)
        self.assertFalse((self.repo / "docs/reports/u/transcript.json").exists())

    def test_a_seed_in_the_unignored_work_tree_is_refused(self):
        key = self.write(".orca/seed", self.SEED.hex() + "\n")
        os.chmod(self.repo / key, 0o600)
        rc, out, err = self._main("--transcript-out", "docs/reports/u/transcript.json",
                                  "--transcript-key", key)
        self.assertEqual(rc, 1, err)
        self.assertIn("custody", err)
        self.assertIn("work tree", err)

    def test_a_0600_out_of_repo_seed_signs_and_names_its_custody_class(self):
        rc, out, err = self._main("--transcript-out", "docs/reports/u/transcript.json",
                                  "--transcript-key", self.key)
        self.assertEqual(rc, 2, err)  # the minimal manifest's verdict is RED; the seed was accepted
        self.assertIn("custody", err)
        self.assertIn("0600", err)
        self.assertEqual(set(self._envelope()), {"record", "sig_b64"})


class ReviewAuthorityPinnedBeforeTheControl(MutationFixture):
    """h409 F-1 (C5): the same-run false GREEN. `gh` was a bare PATH lookup made AFTER the executed
    negative control ran the unit's own test code with the verifier's privileges — so a committed
    check.py could drop a stub `gh` into an empty user-writable dir first on PATH and the LATER
    review leg read a fabricated APPROVED from it (verified: exit 0, no stub present at start).
    The authority is now resolved to an absolute path ONCE, at startup, and only that path is
    invoked; a binary in a worker-writable location is advisory on the native lane and fatal on
    a lane that claims soundness."""

    def setUp(self):
        super().setUp()
        verify.fetch_reviews = self._orig_r  # the REAL fetch: this test is about the binary it runs
        verify.fetch_pr_author = self._orig_a
        self._pathtmp = tempfile.TemporaryDirectory(prefix="orca-c5-")
        self.addCleanup(self._pathtmp.cleanup)
        root = Path(self._pathtmp.name)
        self.droppable = root / "bin"          # EMPTY, user-writable, FIRST on PATH
        self.droppable.mkdir()
        realgh = root / "realgh"               # the stand-in "real" gh: never answers, no network
        realgh.mkdir()
        (realgh / "gh").write_text("#!/bin/sh\necho 'gh: Not Found (HTTP 404)' >&2\nexit 1\n")
        (realgh / "gh").chmod(0o755)
        self.dropped_log = root / "dropped-gh.log"
        # The worker's committed proof command: plant a gh, THEN assert the criterion. The head
        # sha it bakes into the stub is read from a FILE beside the log, not from an ORCA_* env
        # value: the control's environment is scrubbed (h409 F-6) and carries none.
        head_file = root / "head"
        stub = ("#!/bin/sh\n"
                f"echo \"DROPPED-GH ARGV: $*\" >> {shlex.quote(str(self.dropped_log))}\n"
                "case \"$*\" in *reviews*) echo '[{\"state\":\"APPROVED\",\"author_association\":\"MEMBER\",\"commit_id\":\"'\"$HEAD\"'\","
                "\"user\":{\"login\":\"carol\"}}]';; *) echo '{\"user\":{\"login\":\"alice\"}}';; esac\n")
        self.write("check.py",
                   "import os, pathlib, stat\n"
                   f"d = pathlib.Path({str(self.droppable)!r})\n"
                   f"gh = d / 'gh'\n"
                   f"head = pathlib.Path({str(head_file)!r}).read_text().strip()\n"
                   f"gh.write_text({stub!r}.replace('$HEAD', head))\n"
                   "gh.chmod(0o755)\n"
                   "import app\nassert app.f() == 2, 'AC-1 violated'\n")
        self.head_sha = self.commit("head: proof command that plants a gh")
        head_file.write_text(self.head_sha + "\n")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")  # the base the lane names
        self._env = {"PATH": f"{self.droppable}{os.pathsep}{realgh}{os.pathsep}{os.environ['PATH']}"}
        # The SECOND startup state (G-1): no gh anywhere on PATH when the authority is pinned.
        # The stand-in above hid the round-1 hole — an absent gh was "unresolved", and the review
        # leg looked again AFTER the control had planted one. PATH carries git and nothing else.
        tools = root / "tools"
        tools.mkdir()
        os.symlink(shutil.which("git"), tools / "git")
        self._env_no_gh = {"PATH": f"{self.droppable}{os.pathsep}{tools}"}
        if hasattr(verify, "_Authority"):  # absent on the pre-F-1 verifier: the revert control
            verify._Authority.reset()
            self.addCleanup(verify._Authority.reset)
        if hasattr(verify._Authority, "pin_git"):
            # This class is about gh. git is pinned and classed too (h409 R2) and the temp-dir
            # stand-in is worker-writable — a fatal of its own on a sound lane that would stop
            # the control before it runs. Class it system here; R2 has its own class below.
            orig_pin = verify._Authority.pin_git

            def pin_system_git():
                orig_pin()
                verify._Authority.git_custody = "system"
            patcher = mock.patch.object(verify._Authority, "pin_git", pin_system_git)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _attack(self, *extra, env=None):
        # --base main: a lane claiming soundness that executes the control must name the branch
        # its base_sha is bound to (2026-10-26 review); setUp pins refs/remotes/origin/main.
        path = self._manifest(nc=self._revert_nc())
        with mock.patch.dict(os.environ, env or self._env):
            return self._run_main(path, "--repo", "o/r", "--execute-nc", "--base", "main",
                                  "--nc-command", self.proof_cmd, *extra)

    def _assert_absent_at_startup_never_looked_again(self, rc, out, err):
        self.assertEqual(rc, 2, out + err)
        self.assertIn("negative control EXECUTED", out)          # the control DID run worker code
        self.assertTrue((self.droppable / "gh").exists(), "the attack did not plant its gh")
        self.assertFalse(self.dropped_log.exists(),
                         "the planted gh was consulted — an absent authority was re-resolved after the control")
        self.assertIn("gh absent at startup", err)

    def test_a_gh_dropped_by_the_executed_control_never_answers_the_review_leg(self):
        rc, out, err = self._attack()
        self.assertEqual(rc, 2, out + err)
        self.assertIn("negative control EXECUTED", out)          # the control DID run worker code
        self.assertTrue((self.droppable / "gh").exists(), "the attack did not plant its gh")
        self.assertFalse(self.dropped_log.exists(),
                         "the planted gh was consulted — the authority was resolved after the control")
        self.assertIn("cannot fetch reviews", err)               # the pre-pinned stand-in answered

    def test_a_worker_writable_gh_is_fatal_on_a_sound_lane(self):
        (self.droppable / "gh").write_text("#!/bin/sh\necho '[]'\n")
        (self.droppable / "gh").chmod(0o755)
        rc, out, err = self._attack("--provenance", "ci")
        self.assertEqual(rc, 2, out + err)
        self.assertIn("review_authority", err)
        self.assertIn("worker-writable", err)
        self.assertIn("provenance=ci", err)

    def test_a_worker_writable_gh_is_advisory_on_the_native_lane(self):
        # A gh already sitting in the writable dir before the run answers (through its pinned
        # absolute path) — but the verdict RECORDS that the authority was worker-writable.
        (self.droppable / "gh").write_text(  # the sha is baked in: gh's env is scrubbed (h409 R3)
            "#!/bin/sh\ncase \"$*\" in *reviews*) echo '[{\"state\":\"APPROVED\",\"author_association\":\"MEMBER\",\"commit_id\":\""
            + self.head_sha + "\",\"user\":{\"login\":\"carol\"}}]';; *) echo '{\"user\":{\"login\":\"alice\"}}';; esac\n")
        (self.droppable / "gh").chmod(0o755)
        rc, out, err = self._attack()
        self.assertEqual(rc, 0, out + err)
        self.assertIn("NOTE: review_authority: advisory (gh at", out)
        self.assertIn("worker-writable", out)

    def test_with_no_gh_at_startup_the_native_lane_refuses_and_records_the_absence(self):
        self.assertIsNone(shutil.which("gh", path=self._env_no_gh["PATH"]), "fixture: PATH must carry no gh")
        rc, out, err = self._attack(env=self._env_no_gh)
        self._assert_absent_at_startup_never_looked_again(rc, out, err)
        self.assertIn("NOTE: review_authority: advisory (gh absent at startup", out)
        self.assertIn("cannot fetch reviews", err)

    def test_with_no_gh_at_startup_a_sound_lane_fails_closed_naming_the_lane(self):
        rc, out, err = self._attack("--provenance", "ci", env=self._env_no_gh)
        self._assert_absent_at_startup_never_looked_again(rc, out, err)
        self.assertIn("review_authority", err)
        self.assertIn("provenance=ci", err)
        self.assertNotIn("NOTE: review_authority", out)

    def test_an_absent_pin_is_terminal_for_a_library_caller_too(self):
        # The class, not the symptom: once pinned absent, a gh that appears later is never found.
        with mock.patch.dict(os.environ, self._env_no_gh):
            verify._Authority.resolve(explicit_repo="o/r")
        self.assertEqual((verify._Authority.gh, verify._Authority.custody), (None, "absent"))
        (self.droppable / "gh").write_text("#!/bin/sh\necho '[]'\n")
        (self.droppable / "gh").chmod(0o755)
        with mock.patch.dict(os.environ, self._env):
            reviews, err = verify.fetch_reviews("o/r", 7)
        self.assertIsNone(reviews)
        self.assertIn("gh absent at startup", err)
        self.assertEqual((verify._Authority.gh, verify._Authority.custody), (None, "absent"))

    @unittest.skipIf(os.geteuid() == 0 or os.stat("/usr/bin").st_uid == os.geteuid(),
                     "this user owns /usr/bin (root?)")
    def test_a_system_gh_is_classed_system(self):
        # Round 4: the probe walks REAL nodes, so the system-class exemplar must exist — a path it
        # cannot stat is fail-closed, never system. /usr/bin/gh exists on the ubuntu runners only.
        system = next(t for t in ("/usr/bin/gh", "/usr/bin/git", "/usr/bin/env") if os.path.exists(t))
        self.assertEqual(verify._Authority.classify(system), "system")
        self.assertEqual(verify._Authority.classify(str(self.droppable / "gh")), "worker-writable")
        self.assertEqual(verify._Authority.classify(str(self.repo / "gh")), "worker-writable")


class ReviewRepoIsCoordinatorPinned(MutationFixture):
    """h409 F-2 (C1): with --repo omitted the review repository was inferred from the clone's
    origin URL — a remote the worker (and every sibling worktree sharing .git) can rewrite. On a
    lane claiming soundness that inference is REFUSED; on the native lane it is recorded as
    advisory with its source."""

    def setUp(self):
        super().setUp()
        self.git("remote", "add", "origin", "https://github.com/evil/mirror.git")
        # This class is about the REPO: a stand-in gh (never answers; the fetch is mocked by the
        # fixture) sits on PATH and is classed system, so the F-1 custody leg stays out of the
        # picture whether or not the host carries a gh — absent-at-startup is a fatal of its own.
        standin = tempfile.TemporaryDirectory(prefix="orca-c1-")
        self.addCleanup(standin.cleanup)
        (Path(standin.name) / "gh").write_text("#!/bin/sh\nexit 1\n")
        (Path(standin.name) / "gh").chmod(0o755)
        env = mock.patch.dict(os.environ, {"PATH": f"{standin.name}{os.pathsep}{os.environ['PATH']}"})
        env.start()
        self.addCleanup(env.stop)
        patcher = mock.patch.object(verify._Authority, "classify", return_value="system")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_repo_on_a_sound_lane_refuses_to_infer(self):
        rc, out, err = self._run_main(self._manifest(), "--provenance", "mcp")
        self.assertEqual(rc, 2, out + err)
        self.assertIn("review_repo", err)
        self.assertIn("evil/mirror", err)
        self.assertIn("explicit --repo", err)

    def test_no_repo_on_the_native_lane_is_advisory_and_recorded(self):
        rc, out, err = self._run_main(self._manifest())
        self.assertEqual(rc, 0, out + err)
        self.assertIn("NOTE: review_repo: advisory ('evil/mirror' inferred from origin", out)

    def test_an_explicit_repo_on_a_sound_lane_passes_without_the_note(self):
        rc, out, err = self._run_main(self._manifest(), "--provenance", "mcp", "--repo", "real/project")
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("review_repo", out + err)

    def test_the_transcript_signs_the_provenance(self):
        key = self.seed_file(bytes(range(1, 33)))
        rc, out, err = self._run_main(self._manifest(), "--repo", "real/project", "--provenance", "ci",
                                      "--transcript-out", "docs/reports/u/t.json", "--transcript-key", key)
        self.assertEqual(rc, 0, out + err)
        rec = json.loads((self.repo / "docs/reports/u/t.json").read_text())["record"]
        self.assertEqual(rec["args"]["provenance"], "ci")


class AuthorityCustodyIsAProbeNotAName(MutationFixture):
    """h409 R1 (P0, re-attack): classify() returned "system" for any binary whose PATH dir NAME
    was on a list of system bin dirs, BEFORE its writability probe or symlink resolution — and
    /opt/homebrew/bin and /opt/homebrew/sbin, both on that list, are user-writable on every
    Homebrew host. A worker-planted gh there was classed system and a SOUND lane exited 0 over
    a review the worker authored (reattack.md §R1, end-to-end). Custody is now a probe, never a
    name: the listed dir below is a user-writable temp dir whose name is put on the (now unused)
    list, so the pre-fix verifier trusts it and the fixed one does not."""

    def setUp(self):
        super().setUp()
        verify.fetch_reviews = self._orig_r  # the REAL fetch: this class is about the binary
        verify.fetch_pr_author = self._orig_a
        self._pathtmp = tempfile.TemporaryDirectory(prefix="orca-r1-")
        self.addCleanup(self._pathtmp.cleanup)
        root = Path(self._pathtmp.name)
        self.listed = root / "sbin"  # user-writable, and its NAME goes on the list
        self.listed.mkdir()
        self.tools = root / "tools"
        self.tools.mkdir()
        os.symlink(shutil.which("git"), self.tools / "git")
        self.consulted = root / "consulted.log"
        self._env = {"PATH": f"{self.listed}{os.pathsep}{self.tools}"}
        # git's custody is R2's concern (its own class below); class it system here so the only
        # authority under test is gh.
        if hasattr(verify._Authority, "pin_git"):
            orig_pin = verify._Authority.pin_git

            def pin_system_git():
                orig_pin()
                verify._Authority.git_custody = "system"
            patcher = mock.patch.object(verify._Authority, "pin_git", pin_system_git)
            patcher.start()
            self.addCleanup(patcher.stop)
        # On the pre-fix verifier this puts the writable dir on SYSTEM_BINS; on the fixed one the
        # attribute is created and consulted by nothing.
        patcher = mock.patch.object(verify._Authority, "SYSTEM_BINS", (str(self.listed),), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _plant(self, where):
        where.write_text(
            "#!/bin/sh\n" f"echo \"PLANTED-GH ARGV: $*\" >> {shlex.quote(str(self.consulted))}\n"
            "case \"$*\" in *reviews*) echo '[{\"state\":\"APPROVED\",\"author_association\":\"MEMBER\",\"commit_id\":\"" + self.head_sha
            + "\",\"user\":{\"login\":\"carol\"}}]';; *) echo '{\"user\":{\"login\":\"alice\"}}';; esac\n")
        where.chmod(0o755)

    def test_a_gh_planted_in_a_writable_dir_with_a_trusted_name_is_fatal_on_a_sound_lane(self):
        self._plant(self.listed / "gh")
        with mock.patch.dict(os.environ, self._env):
            rc, out, err = self._run_main(self._manifest(nc=self._revert_nc()), "--repo", "o/r",
                                          "--execute-nc", "--nc-command", self.proof_cmd,
                                          "--provenance", "ci")
        self.assertEqual(rc, 2, out + err)
        self.assertIn(f"review_authority: gh at {self.listed / 'gh'} is worker-writable", err)
        self.assertIn("provenance=ci", err)
        self.assertFalse(self.consulted.exists(), "the sound lane consulted the worker's gh")

    def test_a_gh_planted_in_a_writable_dir_with_a_trusted_name_is_advisory_on_the_native_lane(self):
        self._plant(self.listed / "gh")
        with mock.patch.dict(os.environ, self._env):
            rc, out, err = self._run_main(self._manifest(nc=self._revert_nc()), "--repo", "o/r",
                                          "--execute-nc", "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f"NOTE: review_authority: advisory (gh at {self.listed / 'gh'} is worker-writable)", out)

    def test_a_plain_binary_in_a_writable_listed_dir_is_worker_writable(self):  # N2b
        self._plant(self.listed / "gh")
        self.assertEqual(verify._Authority.classify(str(self.listed / "gh")), "worker-writable")

    def test_a_symlink_in_a_listed_dir_to_a_writable_target_is_worker_writable(self):  # N2a
        target = Path(self._pathtmp.name) / "evil-gh"
        self._plant(target)
        (self.listed / "gh").symlink_to(target)
        self.assertEqual(verify._Authority.classify(str(self.listed / "gh")), "worker-writable")

    @unittest.skipIf(os.access("/usr/bin", os.W_OK) or os.geteuid() == 0
                     or os.stat("/usr/bin").st_uid == os.geteuid(),
                     "this user can write or owns /usr/bin (root?)")
    def test_a_binary_in_a_dir_this_user_cannot_write_is_still_system(self):
        # The happy path: a root-owned /usr/bin classes system by the same probe, list or no list.
        # Round 4: the binary must EXIST — a node the probe cannot stat is fail-closed, not system.
        present = [t for t in ("/usr/bin/git", "/usr/bin/env", "/bin/sh") if os.path.exists(t)]
        self.assertTrue(present)
        with mock.patch.object(verify._Authority, "SYSTEM_BINS", (), create=True):
            for tool in present:
                self.assertEqual(verify._Authority.classify(tool), "system", tool)
            self.assertEqual(verify._Authority.classify("/usr/bin/gh-does-not-exist"), "worker-writable")


def _outside_every_root(path):
    """True when `path` lies under none of the roots classify() treats as a work tree — the
    temp dir, the process cwd, the toplevel — so a class of "worker-writable" can only have come
    from the PROBE branch, never from the root check (h409 R-3)."""
    p = Path(path).resolve()
    for root in (tempfile.gettempdir(), os.getcwd(), verify._toplevel(), verify._evidence_toplevel()):
        if root:
            r = Path(root).resolve()
            if p == r or r in p.parents:
                return False
    return True


class EveryHopAndEveryOwnerIsProbed(MutationFixture):
    """h409 round 4 (review-r3 C-1, C-2, R-2, R-3). Round 3 made custody a probe, but the probe
    stopped one step short twice: it resolved the PATH entry and probed only the RESOLVED
    parent by W_OK, so (C-1) a worker-planted symlink in a writable dir pointing at /bin/sh
    classed "system" — and the sound lane then ran `sh api …` against a script in the graded
    repo's cwd — and (C-2) a dir the worker OWNS at mode 0555 classed "system" too, one
    `chmod u+w` from writable. Both were end-to-end sound-lane FALSE GREENs. classify() now
    walks every node of every hop by hand and probes OWNERSHIP as well as mode. The drop dir
    here lives under $HOME — outside temp/cwd/toplevel — so every class below comes from the
    probe branch itself (R-3), not from the root check."""

    def setUp(self):
        super().setUp()
        verify.fetch_reviews = self._orig_r  # the REAL fetch: these tests are about the binary
        verify.fetch_pr_author = self._orig_a
        try:
            drop = tempfile.mkdtemp(prefix="orca-h409-r4-", dir=Path.home())
        except OSError as e:
            self.skipTest(f"cannot create a probe fixture under $HOME ({e})")
        self.drop = Path(drop)
        self.drop.chmod(0o755)  # mkdtemp's 0700 → the review's 0755 shape (R-3)
        self.addCleanup(self._reap, self.drop)
        if not _outside_every_root(self.drop):
            self.skipTest(f"$HOME fixture {self.drop} lies under a work-tree root; the probe branch "
                          "cannot be isolated on this host")
        if os.geteuid() == 0:
            self.skipTest("running as root: every hop is owned by the effective user by definition")
        # git's custody is R2's concern; class it system so the only authority under test is gh.
        if hasattr(verify._Authority, "pin_git"):  # absent on the pre-round-3 verifier (R-3 revert)
            orig_pin = verify._Authority.pin_git

            def pin_system_git():
                orig_pin()
                verify._Authority.git_custody = "system"
            patcher = mock.patch.object(verify._Authority, "pin_git", pin_system_git)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The pre-round-3 name list, for the revert proof of R-3: the $HOME dir is "trusted" by name.
        patcher = mock.patch.object(verify._Authority, "SYSTEM_BINS", (str(self.drop),), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        tools = tempfile.TemporaryDirectory(prefix="orca-h409-r4-tools-")  # the run's git, after drop
        self.addCleanup(tools.cleanup)
        os.symlink(shutil.which("git"), Path(tools.name) / "git")
        self.consulted = Path(tools.name) / "consulted.log"  # writable even when drop/ is 0555
        self._env = {"PATH": f"{self.drop}{os.pathsep}{tools.name}"}

    @staticmethod
    def _reap(d):
        for sub in (d, *d.rglob("*")):
            if sub.is_dir() and not sub.is_symlink():
                os.chmod(sub, 0o755)
        shutil.rmtree(d, ignore_errors=True)

    def _forged_review(self):
        return ("case \"$*\" in *reviews*) echo '[{\"state\":\"APPROVED\",\"author_association\":\"MEMBER\",\"commit_id\":\"" + self.head_sha
                + "\",\"user\":{\"login\":\"carol\"}}]';; *) echo '{\"user\":{\"login\":\"alice\"}}';; esac\n")

    def _plant_stub(self, where):
        where.write_text("#!/bin/sh\n" f"echo \"PLANTED-GH ARGV: $*\" >> {shlex.quote(str(self.consulted))}\n"
                         + self._forged_review())
        where.chmod(0o755)

    def _sound(self, *extra):
        with mock.patch.dict(os.environ, self._env):
            return self._run_main(self._manifest(nc=self._revert_nc()), "--repo", "o/r",
                                  "--execute-nc", "--nc-command", self.proof_cmd, "--provenance", "ci",
                                  *extra)

    def _native(self):
        with mock.patch.dict(os.environ, self._env):
            return self._run_main(self._manifest(nc=self._revert_nc()), "--repo", "o/r",
                                  "--execute-nc", "--nc-command", self.proof_cmd)

    def _assert_refused(self, rc, out, err):
        self.assertEqual(rc, 2, out + err)
        self.assertIn(f"review_authority: gh at {self.drop / 'gh'} is worker-writable", err)
        self.assertIn("provenance=ci", err)
        self.assertFalse(self.consulted.exists(), "the sound lane consulted the worker's authority")

    # --- C-1: the UNRESOLVED entry and every symlink hop -------------------------------------

    def _system_interpreter(self):
        sh = shutil.which("sh", path="/bin:/usr/bin")
        if not sh or verify._Authority.classify(sh) != "system":
            self.skipTest("no system-class /bin/sh on this host to point the symlink at")
        return sh

    def test_c1_a_symlink_in_a_writable_dir_to_a_system_interpreter_is_worker_writable(self):
        (self.drop / "gh").symlink_to(self._system_interpreter())
        self.assertEqual(verify._Authority.classify(str(self.drop / "gh")), "worker-writable")

    def test_c1_the_sound_lane_refuses_the_symlinked_interpreter_and_never_runs_the_repo_script(self):
        # reattack shape: `drop/gh -> /bin/sh`, so `gh api …` becomes `sh api …` and `api` is a
        # script in the graded repo (the verifier's cwd) that forges an APPROVED review at head.
        (self.drop / "gh").symlink_to(self._system_interpreter())
        (self.repo / "api").write_text(f"echo \"SH-API ARGV: $*\" >> {shlex.quote(str(self.consulted))}\n"
                                       + self._forged_review())
        self._assert_refused(*self._sound())

    def test_c1_the_native_lane_records_the_symlinked_interpreter_as_advisory(self):
        (self.drop / "gh").symlink_to(self._system_interpreter())
        (self.repo / "api").write_text(f"echo \"SH-API ARGV: $*\" >> {shlex.quote(str(self.consulted))}\n"
                                       + self._forged_review())
        rc, out, err = self._native()
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f"NOTE: review_authority: advisory (gh at {self.drop / 'gh'} is worker-writable)", out)

    def test_c1_a_symlinked_directory_hop_inside_a_writable_dir_is_worker_writable(self):
        # The hop is a DIRECTORY link this time: drop/sys -> /usr/bin, so drop/sys/git resolves to
        # a root-owned binary while its unresolved path runs through a dir the worker owns.
        sysdir = Path(self._system_interpreter()).parent
        (self.drop / "sys").symlink_to(sysdir)
        entry = self.drop / "sys" / Path(self._system_interpreter()).name
        self.assertEqual(Path(entry).resolve(), Path(self._system_interpreter()).resolve())
        self.assertEqual(verify._Authority.classify(str(entry)), "worker-writable")

    def test_c1_a_link_loop_or_a_dangling_link_fails_closed(self):
        (self.drop / "a").symlink_to(self.drop / "b")
        (self.drop / "b").symlink_to(self.drop / "a")
        self.assertEqual(verify._Authority.classify(str(self.drop / "a")), "worker-writable")
        (self.drop / "gh").symlink_to(self.drop / "nowhere")
        self.assertEqual(verify._Authority.classify(str(self.drop / "gh")), "worker-writable")

    def test_c1_a_symlink_node_itself_never_classes_controllable(self):
        # CI on #493 (ubuntu): /bin -> usr/bin, and a link's own lstat bits are always 0777, so
        # the world-writable mode check classed /bin/sh worker-writable on every runner. A link's
        # custody is its directory's (the node before it) and its target hops' — never its own
        # mode or owner. Revert the link early-return and the first assertion bites.
        link = self.drop / "gh"
        link.symlink_to(self._system_interpreter())
        self.assertFalse(verify._Authority._worker_controls(link, os.lstat(link)))
        self.assertTrue(verify._Authority._worker_controls(self.drop, os.lstat(self.drop)))

    # --- C-2: ownership, not mode -------------------------------------------------------------

    def _plant_owned_0555(self):
        self._plant_stub(self.drop / "gh")
        (self.drop / "gh").chmod(0o555)
        self.drop.chmod(0o555)
        st = self.drop.stat()
        self.assertEqual(st.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o555)
        self.assertFalse(os.access(self.drop, os.W_OK), "the mode probe alone must be blind here")

    def test_c2_a_worker_owned_0555_dir_is_worker_writable(self):
        self._plant_owned_0555()
        self.assertEqual(verify._Authority.classify(str(self.drop / "gh")), "worker-writable")

    def test_c2_the_sound_lane_refuses_a_gh_in_a_worker_owned_0555_dir(self):
        self._plant_owned_0555()
        self._assert_refused(*self._sound())

    def test_c2_the_native_lane_records_a_worker_owned_0555_dir_as_advisory(self):
        self._plant_owned_0555()
        rc, out, err = self._native()
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f"NOTE: review_authority: advisory (gh at {self.drop / 'gh'} is worker-writable)", out)

    def test_c2_a_worker_owned_0555_file_in_a_root_owned_dir_is_worker_writable(self):
        # Ownership of the FILE alone is enough: a 0555 file of one's own is one chmod away.
        f = self.drop / "gh"
        self._plant_stub(f)
        f.chmod(0o555)
        st = os.lstat(f)
        self.assertTrue(verify._Authority._worker_controls(f, st))

    # --- R-3: the probe branch itself, on every host ------------------------------------------

    def test_r3_a_plain_gh_in_an_owned_0755_dir_outside_every_root_is_worker_writable(self):
        # Round 3's unit tests put the drop dir under the temp root, so the ROOT check classed it
        # and the probe branch (the one the real /opt/homebrew/sbin depends on) went unexercised.
        # Here the dir is under $HOME at 0755 and its name is on the pre-round-3 list.
        self._plant_stub(self.drop / "gh")
        self.assertEqual(stat.S_IMODE(self.drop.stat().st_mode), 0o755)
        self.assertEqual(verify._Authority.classify(str(self.drop / "gh")), "worker-writable")

    def test_r3_the_sound_lane_refuses_a_gh_in_an_owned_0755_dir_outside_every_root(self):
        self._plant_stub(self.drop / "gh")
        self._assert_refused(*self._sound())

    # --- R-2: a cwd of "/" is not a work tree -------------------------------------------------

    def test_r2_a_cwd_of_root_does_not_class_a_root_owned_binary_worker_writable(self):
        sh = self._system_interpreter()
        cwd = os.getcwd()
        os.chdir("/")
        try:
            self.assertEqual(verify._Authority.classify(sh), "system")
        finally:
            os.chdir(cwd)


class EveryPostControlAuthorityIsPinned(MutationFixture):
    """h409 R2 (re-attack residual, same class as F-1): only gh got the startup pin. git was a
    bare `git` argv head everywhere, and legs of it run AFTER the executed control (the
    review-veto tree, check_symbol_on_base, the NC worktree teardown), so the same primitive C5
    used for gh — the control drops a binary into an empty dir first on PATH — reached them.
    git (and gitleaks) are now pinned to absolute paths beside gh, before the control, and
    classed by custody: a worker-writable git is fatal on a sound lane, advisory on the native."""

    def setUp(self):
        super().setUp()
        verify.fetch_reviews = self._orig_r
        verify.fetch_pr_author = self._orig_a
        self._pathtmp = tempfile.TemporaryDirectory(prefix="orca-r2-")
        self.addCleanup(self._pathtmp.cleanup)
        root = Path(self._pathtmp.name)
        self.droppable = root / "bin"   # EMPTY, user-writable, FIRST on PATH
        self.droppable.mkdir()
        self.tools = root / "tools"     # the git the run starts with
        self.tools.mkdir()
        os.symlink(shutil.which("git"), self.tools / "git")
        self.planted_log = root / "planted-git.log"
        stub = f"#!/bin/sh\necho \"PLANTED-GIT ARGV: $*\" >> {shlex.quote(str(self.planted_log))}\nexit 1\n"
        # The worker's committed proof command: plant a git, THEN assert the criterion.
        self.write("check.py",
                   "import pathlib\n"
                   f"g = pathlib.Path({str(self.droppable / 'git')!r})\n"
                   f"g.write_text({stub!r})\ng.chmod(0o755)\n"
                   "import app\nassert app.f() == 2, 'AC-1 violated'\n")
        self.head_sha = self.commit("head: proof command that plants a git")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")
        realgh = root / "realgh"        # a gh that approves head (the sha baked in: R3 scrubs env)
        realgh.mkdir()
        (realgh / "gh").write_text(
            "#!/bin/sh\ncase \"$*\" in *reviews*) echo '[{\"state\":\"APPROVED\",\"author_association\":\"MEMBER\",\"commit_id\":\"" + self.head_sha
            + "\",\"user\":{\"login\":\"carol\"}}]';; *) echo '{\"user\":{\"login\":\"alice\"}}';; esac\n")
        (realgh / "gh").chmod(0o755)
        self._env = {"PATH": f"{self.droppable}{os.pathsep}{realgh}{os.pathsep}{self.tools}"}

    def _attack(self, *extra):
        with mock.patch.dict(os.environ, self._env):
            return self._run_main(self._manifest(nc=self._revert_nc()), "--repo", "o/r",
                                  "--execute-nc", "--nc-command", self.proof_cmd, *extra)

    def test_a_git_planted_by_the_executed_control_is_never_consulted_after_it(self):
        rc, out, err = self._attack()
        self.assertIn("negative control EXECUTED", out)          # the control DID run worker code
        self.assertTrue((self.droppable / "git").exists(), "the attack did not plant its git")
        self.assertFalse(self.planted_log.exists(),
                         "a post-control git leg resolved `git` on PATH and ran the planted one")
        self.assertEqual(rc, 0, out + err)                       # every leg ran the pinned git

    def test_a_worker_writable_git_is_fatal_on_a_sound_lane(self):
        rc, out, err = self._attack("--provenance", "ci")
        self.assertEqual(rc, 2, out + err)
        self.assertIn(f"authority: git at {self.tools / 'git'} is worker-writable", err)
        self.assertIn("provenance=ci", err)
        self.assertIn("h409 R2", err)

    def test_a_worker_writable_git_is_advisory_on_the_native_lane(self):
        rc, out, err = self._attack()
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f"NOTE: authority: advisory (git at {self.tools / 'git'} is worker-writable)", out)

    def test_git_is_pinned_absolute_at_startup_and_every_leg_runs_it(self):
        with mock.patch.dict(os.environ, self._env):
            verify._Authority.resolve(explicit_repo="o/r")
            self.assertEqual(verify._Authority.git, str(self.tools / "git"))
            self.assertTrue(os.path.isabs(verify._Authority.git))
            ran = []
            with mock.patch.object(verify.subprocess, "run", side_effect=lambda a, **k: ran.append(a[0]) or
                                   subprocess.CompletedProcess(a, 1, "", "")):
                verify._toplevel()
                verify._evidence_toplevel()
                verify._root_arg("--git-dir", str(self.repo))
        self.assertEqual(set(ran), {str(self.tools / "git")}, ran)

    def test_gitleaks_is_pinned_absolute_and_its_custody_recorded(self):
        # gitleaks can only ADD hits above the built-in floor, so a worker-writable one is still
        # consulted — at its PINNED absolute path, never a PATH re-resolve — and named in a NOTE.
        (self.droppable / "gitleaks").write_text("#!/bin/sh\nexit 0\n")
        (self.droppable / "gitleaks").chmod(0o755)
        with mock.patch.dict(os.environ, self._env):
            verify._Authority.resolve(explicit_repo="o/r")
        self.assertEqual(verify._Authority.gitleaks, str(self.droppable / "gitleaks"))
        self.assertEqual(verify._Authority.gitleaks_custody, "worker-writable")
        self.assertTrue(any(line.startswith(f"NOTE: redaction: gitleaks at {self.droppable / 'gitleaks'} "
                                            "is worker-writable") for line in verify._Authority.authority_leg()))
        with mock.patch.object(verify, "_run", return_value=(0, "", "")) as run:
            self.assertIs(verify._gitleaks_scan(self.repo / "contract.md"), False)
        self.assertEqual(run.call_args[0][0][0], str(self.droppable / "gitleaks"))


class ThePinnedGhRunsUnderAScrubbedEnvironment(RepoCase):
    """h409 R3 (re-attack residual): the pinned gh ran with the ambient environment, so
    GH_HOST=attacker.example — worker-settable on the native lane — pointed even a genuine gh at
    a forged host, and every ambient secret rode along. gh now runs under an explicit allowlist;
    the host is the coordinator's, riding the pinned --repo as host/owner/name."""

    def setUp(self):
        super().setUp()
        self._pathtmp = tempfile.TemporaryDirectory(prefix="orca-r3-")
        self.addCleanup(self._pathtmp.cleanup)
        root = Path(self._pathtmp.name)
        self.seen = root / "gh-saw.log"
        fakebin = root / "bin"
        fakebin.mkdir()
        (fakebin / "gh").write_text(  # logs the env NAMES it sees and its argv, answers nothing
            "#!/bin/sh\n"
            f"/usr/bin/env | /usr/bin/cut -d= -f1 | /usr/bin/sort >> {shlex.quote(str(self.seen))}\n"
            f"echo \"ARGV: $*\" >> {shlex.quote(str(self.seen))}\n"
            "echo '[]'\n")
        (fakebin / "gh").chmod(0o755)
        self._env = {"PATH": f"{fakebin}{os.pathsep}{os.environ['PATH']}",
                     "GH_HOST": "attacker.example", "GH_CONFIG_DIR": str(root / "evil"),
                     "GH_REPO": "evil/mirror", "GH_TOKEN": "present", "GITHUB_TOKEN": "present"}

    def _fetch(self, repo):
        with mock.patch.dict(os.environ, self._env):
            verify._Authority.resolve(explicit_repo=repo)
            verify.fetch_reviews(repo, 7)
        return self.seen.read_text().splitlines()

    def test_worker_settable_gh_variables_never_reach_the_pinned_gh(self):
        seen = self._fetch("o/r")
        for name in ("GH_HOST", "GH_CONFIG_DIR", "GH_REPO"):
            self.assertNotIn(name, seen, seen)
        for name in ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN"):  # what it needs to authenticate
            self.assertIn(name, seen, seen)

    def test_the_coordinators_host_rides_the_pinned_repo(self):
        seen = self._fetch("ghe.example/o/r")
        self.assertNotIn("GH_HOST", seen)
        self.assertIn("ARGV: api --paginate --hostname ghe.example repos/o/r/pulls/7/reviews", seen)

    def test_a_plain_repo_names_no_host(self):
        seen = self._fetch("o/r")
        self.assertIn("ARGV: api --paginate repos/o/r/pulls/7/reviews", seen)

    def test_the_allowlist_is_the_whole_environment(self):
        with mock.patch.dict(os.environ, {**self._env, "SSL_CERT_FILE": "/evil/ca.pem",
                                          "HTTPS_PROXY": "http://attacker.example:8080"}):
            env = verify._Authority.gh_env()
        self.assertTrue(set(env) <= set(verify._Authority.GH_ENV_KEEP), env)
        self.assertNotIn("SSL_CERT_FILE", env)
        self.assertNotIn("HTTPS_PROXY", env)

    def test_a_fetch_failure_names_the_scrub(self):
        # h409 N-2: a proxied or XDG-configured host loses gh egress/auth under the scrub and sees
        # "cannot fetch reviews" — the fatal says why, so the cause reads as the scrub, not the net.
        (Path(self._pathtmp.name) / "bin" / "gh").write_text("#!/bin/sh\necho 'no route' >&2\nexit 1\n")
        with mock.patch.dict(os.environ, self._env):
            verify._Authority.resolve(explicit_repo="o/r")
            lines = verify.check_review({"pr": {"number": 7}, "head_sha": "0" * 40}, "o/r", True)
        fatal = [l for l in lines if not l.startswith("NOTE:")]
        self.assertEqual(len(fatal), 1, lines)
        self.assertIn("cannot fetch reviews for o/r#7", fatal[0])
        for name in ("XDG_CONFIG_HOME", "HTTPS_PROXY", "SSL_CERT_FILE"):
            self.assertIn(name, fatal[0])


class TheExecutedControlRunsUnderAScrubbedEnvironment(MutationFixture):
    """h409 F-6 (P1): the executed control ran worker code with NO `env=`, so the unit's own
    check.py saw everything the verifier held — GH_TOKEN / GITHUB_TOKEN (the review leg's
    credential: a worker holding it can post the APPROVED that satisfies review_ok) and every
    ORCA_* value. The control now runs under _Authority.nc_env(): the ambient floor (PATH, HOME,
    TMPDIR/TMP/TEMP, LANG, LC_*) and nothing else. Same fixture as the green executed revert —
    the scrub must leave a real revert control working end to end."""

    PLANTED = {"GH_TOKEN": "dummy-not-a-real-token", "GITHUB_TOKEN": "dummy-not-a-real-token",
               "GH_HOST": "attacker.example", "ORCA_CONTRACT_DIGEST": "sha256:weaker",
               "ORCA_PROVENANCE": "ci", "ORCA_HEAD": "planted", "GIT_CONFIG_COUNT": "0",
               "SSL_CERT_FILE": "/evil/ca.pem", "LC_ALL": "C.UTF-8"}

    def setUp(self):
        super().setUp()
        self._envtmp = tempfile.TemporaryDirectory(prefix="orca-f6-")
        self.addCleanup(self._envtmp.cleanup)
        self.seen = Path(self._envtmp.name) / "control-env.log"
        # The unit's committed proof command records the NAMES in its environment — never a
        # value — then asserts the criterion, so the revert control still goes RED under it.
        self.write("check.py",
                   "import os, pathlib\n"
                   f"pathlib.Path({str(self.seen)!r}).open('a').write(' '.join(sorted(os.environ)) + chr(10))\n"
                   "import app\nassert app.f() == 2, 'AC-1 violated'\n")
        self.head_sha = self.commit("head: proof command that records its environment")
        self.head_tree = self.git("rev-parse", "HEAD^{tree}")

    def _green_executed_run(self):
        path = self._manifest(nc=self._revert_nc())
        with mock.patch.dict(os.environ, self.PLANTED):
            rc, out, err = self._run_main(path, "--repo", "o/r", "--execute-nc",
                                          "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("negative control EXECUTED", out)
        self.assertIn("exits 0 at clean head_sha", out)
        runs = [set(line.split()) for line in self.seen.read_text().splitlines()]
        self.assertEqual(len(runs), 3, runs)  # clean, control, clean all executed (review P1)
        return runs

    def test_the_coordinators_token_and_orca_values_never_reach_the_control(self):
        # The reaudit.md §F-6 probe: gh_token_in_env must read False in BOTH runs of check.py.
        for seen in self._green_executed_run():
            for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_HOST", "ORCA_CONTRACT_DIGEST",
                         "ORCA_PROVENANCE", "ORCA_HEAD", "GIT_CONFIG_COUNT", "SSL_CERT_FILE"):
                self.assertNotIn(name, seen, seen)
            self.assertFalse({n for n in seen if n.startswith(("GH_", "GITHUB_", "ORCA_", "GIT_"))}, seen)

    def test_the_control_still_gets_the_ambient_floor_it_needs(self):
        for seen in self._green_executed_run():
            self.assertIn("PATH", seen, seen)
            self.assertIn("HOME", seen, seen)
            self.assertIn("LC_ALL", seen, seen)  # LC_* passes as a prefix

    def test_nc_env_is_the_allowlist_and_nothing_else(self):
        with mock.patch.dict(os.environ, {**self.PLANTED, "LC_CTYPE": "C", "LCX": "not-a-prefix-hit"}):
            env = verify._Authority.nc_env()
        keep, prefix = verify._Authority.AMBIENT_KEEP, verify._Authority.AMBIENT_KEEP_PREFIX
        self.assertTrue(all(k in keep or k.startswith(prefix) for k in env), env)
        self.assertEqual({k for k in env if k.startswith("LC")}, {"LC_ALL", "LC_CTYPE"})
        self.assertNotIn("GH_TOKEN", env)
        self.assertNotIn("ORCA_PROVENANCE", env)


class TheSeedAndTheControlNeverShareAProcess(MutationFixture):
    """h409 F-6 (P1), the custody half: `--transcript-key` opens the coordinator's seed in
    main() BEFORE verify() runs, and `--execute-nc` then runs worker code as the same uid with
    the seed's path in the parent's argv. F-4's custody check passes it — custody was asserted
    against the FILE, not against who executes in the process that opened it. The conjunction
    is refused at parse time (usage exit 1), before the seed is read and before any control runs:
    sign after the control, in a process that never ran it."""

    SEED = bytes(range(1, 33))

    def setUp(self):
        super().setUp()
        self.key = self.seed_file(self.SEED)
        self.executed = []
        orig = verify.execute_negative_control

        def spy(*a, **k):
            self.executed.append(a)
            return orig(*a, **k)
        patcher = mock.patch.object(verify, "execute_negative_control", spy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_execute_nc_with_transcript_key_is_a_usage_refusal_before_any_control_runs(self):
        path = self._manifest(nc=self._revert_nc())
        rc, out, err = self._run_main(path, "--repo", "o/r", "--execute-nc",
                                      "--nc-command", self.proof_cmd,
                                      "--transcript-out", "docs/reports/u/transcript.json",
                                      "--transcript-key", self.key)
        self.assertEqual(rc, 1, out + err)
        self.assertIn("--transcript-key cannot be combined with --execute-nc", err)
        self.assertIn("sign-transcript", err)               # the guidance: sign after the control
        self.assertNotIn("custody", err)                     # refused BEFORE the seed was read
        self.assertEqual(self.executed, [])                  # and before any control ran
        self.assertNotIn("negative control EXECUTED", out)
        self.assertFalse((self.repo / "docs/reports/u/transcript.json").exists())

    def test_execute_nc_alone_still_runs_the_control_under_the_scrub(self):
        path = self._manifest(nc=self._revert_nc())
        rc, out, err = self._run_main(path, "--repo", "o/r", "--execute-nc",
                                      "--nc-command", self.proof_cmd,
                                      "--transcript-out", "docs/reports/u/transcript.json")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(len(self.executed), 1)
        rec = json.loads((self.repo / "docs/reports/u/transcript.json").read_text())
        self.assertNotIn("sig_b64", rec)  # the unsigned verdict object sign-transcript wraps later
        self.assertTrue(rec["args"]["execute_nc"])
        # …and the documented seed-safe lane signs it in a process that never ran the control,
        # re-hashing toolchain.files against the signer's own siblings on the way (O-2.4).
        signed = self.repo / "docs/reports/u/transcript.signed.json"
        with contextlib.redirect_stderr(io.StringIO()):
            rc = dispatch_sign.main(["sign-transcript", "--key", self.key,
                                     "--transcript", str(self.repo / "docs/reports/u/transcript.json"),
                                     "--out", str(signed)])
        self.assertEqual(rc, 0)
        env = json.loads(signed.read_text())
        self.assertEqual(env["record"], rec)
        self.assertTrue(ed.checkvalid(base64.b64decode(env["sig_b64"], validate=True),
                                      verify._canonical_transcript(rec), ed.publickey(self.SEED)))

    def test_transcript_key_alone_still_signs(self):
        path = self._manifest()
        rc, out, err = self._run_main(path, "--repo", "o/r",
                                      "--transcript-out", "docs/reports/u/transcript.json",
                                      "--transcript-key", self.key)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.executed, [])
        self.assertIn("custody", err)
        env = json.loads((self.repo / "docs/reports/u/transcript.json").read_text())
        self.assertEqual(set(env), {"record", "sig_b64"})


class GitLegsRunUnderAScrubbedEnvironment(MutationFixture):
    """h409 N-4 (P2, code-exec): R3 scrubbed gh's environment in-process and left git and
    gitleaks inheriting the ambient one — and git's env is an EXEC channel. GIT_EXTERNAL_DIFF and
    GIT_CONFIG_COUNT + core.fsmonitor ran arbitrary code through verify's own git legs (status,
    diff --name-only, diff --cached), including the legs that run in the control worktree. Every
    git and gitleaks invocation now runs under _Authority.git_env(): the ambient floor plus
    GIT_TERMINAL_PROMPT=0, nothing a worker's launch env could steer with."""

    def setUp(self):
        super().setUp()
        self._envtmp = tempfile.TemporaryDirectory(prefix="orca-n4-")
        self.addCleanup(self._envtmp.cleanup)
        root = Path(self._envtmp.name)
        self.fired = root / "fired.log"            # written by the planted exec channels
        self.git_seen = root / "git-env.log"       # env NAMES the pinned git was launched with
        self.gitleaks_seen = root / "gitleaks-env.log"
        stub = root / "stub.sh"
        stub.write_text(f"#!/bin/sh\necho \"FIRED: $0 $*\" >> {shlex.quote(str(self.fired))}\nexit 0\n")
        stub.chmod(0o755)
        fakebin = root / "bin"
        fakebin.mkdir()
        real_git = shutil.which("git")
        (fakebin / "git").write_text(
            "#!/bin/sh\n"
            f"/usr/bin/env | /usr/bin/cut -d= -f1 | /usr/bin/sort >> {shlex.quote(str(self.git_seen))}\n"
            f"exec {shlex.quote(real_git)} \"$@\"\n")
        (fakebin / "git").chmod(0o755)
        (fakebin / "gitleaks").write_text(
            "#!/bin/sh\n"
            f"/usr/bin/env | /usr/bin/cut -d= -f1 | /usr/bin/sort >> {shlex.quote(str(self.gitleaks_seen))}\n"
            "exit 0\n")
        (fakebin / "gitleaks").chmod(0o755)
        self.planted = {"PATH": f"{fakebin}{os.pathsep}{os.environ['PATH']}",
                        "GIT_EXTERNAL_DIFF": str(stub),
                        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
                        "GIT_CONFIG_VALUE_0": str(stub),
                        "GIT_SSH_COMMAND": str(stub), "GIT_PROXY_COMMAND": str(stub),
                        "GH_TOKEN": "dummy-not-a-real-token", "ORCA_PROVENANCE": "ci"}

    def test_the_planted_channels_are_live_on_this_host(self):
        # The positive control for the stub proof below: the SAME env, handed to git directly,
        # runs the planted fsmonitor — so an empty log after the verifier's run is the scrub.
        subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True,
                       env={**os.environ, **self.planted}, check=False)
        self.assertTrue(self.fired.exists(), "core.fsmonitor via GIT_CONFIG_COUNT did not fire here")
        self.assertIn("FIRED:", self.fired.read_text())

    def _green_executed_run(self):
        path = self._manifest(nc=self._revert_nc())
        with mock.patch.dict(os.environ, self.planted):
            rc, out, err = self._run_main(path, "--repo", "o/r", "--execute-nc",
                                          "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("negative control EXECUTED", out)  # the worktree legs all ran
        return out

    def test_no_planted_exec_channel_fires_through_any_git_leg(self):
        out = self._green_executed_run()
        self.assertFalse(self.fired.exists(),
                         "a planted GIT_* exec channel ran through a verifier git leg: "
                         + (self.fired.read_text() if self.fired.exists() else ""))
        self.assertIn("worker-writable", out)  # the wrapper's dir is classed; advisory here

    def test_git_and_gitleaks_see_the_allowlist_and_nothing_else(self):
        self._green_executed_run()
        belt = {"GIT_TERMINAL_PROMPT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
                "GIT_NO_REPLACE_OBJECTS", "GIT_GRAFT_FILE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_KEY_1", "GIT_CONFIG_KEY_2",
                "GIT_CONFIG_VALUE_0", "GIT_CONFIG_VALUE_1", "GIT_CONFIG_VALUE_2",
                # 2026-10-23 review, P1-2: the core.hooksPath=/dev/null pair.
                "GIT_CONFIG_KEY_3", "GIT_CONFIG_VALUE_3"}
        for log in (self.git_seen, self.gitleaks_seen):
            seen = set(log.read_text().split())
            self.assertTrue(seen, f"{log.name}: the wrapper was never launched")
            for name in ("GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND",
                         "GH_TOKEN", "ORCA_PROVENANCE"):
                self.assertNotIn(name, seen, (log.name, seen))
            self.assertEqual({n for n in seen if n.startswith("GIT_")}, belt, seen)
            self.assertIn("PATH", seen)
            self.assertIn("HOME", seen)

    def test_git_env_is_nc_env_plus_the_belt(self):
        with mock.patch.dict(os.environ, self.planted):
            env = verify._Authority.git_env()
            self.assertEqual(env, {**verify._Authority.nc_env(),
                                   "GIT_TERMINAL_PROMPT": "0",
                                   "GIT_NO_REPLACE_OBJECTS": "1",
                                   "GIT_GRAFT_FILE": os.devnull,
                                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                                   "GIT_CONFIG_COUNT": "4",
                                   "GIT_CONFIG_KEY_0": "core.fsmonitor",
                                   "GIT_CONFIG_VALUE_0": "false",
                                   "GIT_CONFIG_KEY_1": "protocol.ext.allow",
                                   "GIT_CONFIG_VALUE_1": "never",
                                   "GIT_CONFIG_KEY_2": "safe.directory",
                                   "GIT_CONFIG_VALUE_2": "*",
                                   "GIT_CONFIG_KEY_3": "core.hooksPath",
                                   "GIT_CONFIG_VALUE_3": os.devnull})
        self.assertFalse({k for k in env if k.startswith(("GH_", "ORCA_"))}, env)

    def test_the_belt_closes_the_repo_local_fsmonitor_channel(self):
        # h409 B5: a `core.fsmonitor` in the graded repo's OWN .git/config is env-independent —
        # only the GIT_CONFIG_* belt (-c precedence) closes it. Positive control first: bare git
        # on the same repo DOES run the planted monitor.
        stub = self.fired.parent / "stub.sh"
        subprocess.run(["git", "config", "core.fsmonitor", str(stub)], cwd=self.repo, check=True)
        subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True,
                       env=dict(os.environ), check=False)
        self.assertTrue(self.fired.exists(), "repo-local core.fsmonitor did not fire on bare git")
        self.fired.unlink()
        self._green_executed_run()
        self.assertFalse(self.fired.exists(),
                         "repo-local core.fsmonitor fired through a belted verifier git leg")

    def test_the_belt_drops_the_global_config_files(self):
        # h409 B4: HOME → ~/.gitconfig core.fsmonitor. GIT_CONFIG_GLOBAL=/dev/null +
        # GIT_CONFIG_NOSYSTEM=1 close it; HOME stays on the floor (git needs it).
        fakehome = self.fired.parent / "fakehome"
        fakehome.mkdir()
        (fakehome / ".gitconfig").write_text(f"[core]\n\tfsmonitor = {self.fired.parent}/stub.sh\n")
        subprocess.run(["git", "status", "--porcelain"], cwd=self.repo, capture_output=True,
                       env={**os.environ, "HOME": str(fakehome)}, check=False)
        self.assertTrue(self.fired.exists(), "~/.gitconfig core.fsmonitor did not fire on bare git")
        self.fired.unlink()
        path = self._manifest(nc=self._revert_nc())
        with mock.patch.dict(os.environ, {**self.planted, "HOME": str(fakehome)}):
            rc, out, err = self._run_main(path, "--repo", "o/r", "--execute-nc",
                                          "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(self.fired.exists(),
                         "~/.gitconfig core.fsmonitor fired through a belted verifier git leg")


class MalformedEnvelopeSignaturesRefuseIdentically(RepoCase):
    """h409 O-2.2: verify.py decoded `sig_b64` leniently while run_report.py and inventory.py
    validate — three consumers of one envelope disagreed on what "malformed" means. All three
    now refuse a non-alphabet byte, a newline and trailing garbage as MALFORMED, not as a
    signature to try."""

    def _tampered(self, mutate):
        rec, pk = DispatchProvenance._signed(self, {"manifest_id": "u", "contract_digest": "sha256:a",
                                                    "unit_class": "mutation"})
        env = json.loads((self.repo / rec).read_text())
        env["sig_b64"] = mutate(env["sig_b64"])
        (self.repo / rec).write_text(json.dumps(env))
        return verify.check_dispatch_provenance({"unit": "u"}, "sha256:a", "mutation", None, rec, pk)

    def test_a_non_alphabet_byte_a_newline_and_trailing_garbage_are_malformed(self):
        for mutate in (lambda b: b[:10] + "*" + b[10:], lambda b: b[:10] + "\n" + b[10:],
                       lambda b: b + "!!"):
            res = self._tampered(mutate)
            self.assertTrue(any("malformed" in e for e in res), res)
            self.assertFalse(any("INVALID" in e for e in res), res)  # refused before checkvalid

    def test_the_three_consumers_agree(self):
        import re
        for name in ("verify.py", "run_report.py", "inventory.py"):
            src = (ROOT / "runtime" / "scripts" / name).read_text(encoding="utf-8")
            calls = re.findall(r"b64decode\([^)]*\)", src)
            self.assertTrue(calls, name)
            for call in calls:
                self.assertIn("validate=True", call, (name, call))


# ---------------------------------------------------------------------------------------------
# 2026-10-23 end-to-end review: P1-1 (#612), P1-2 (#613), P2-1/P2-2 + verifier P3s (#614).
# ---------------------------------------------------------------------------------------------

# Runner output as the real runners print it (pytest 9, Jest 29.7, Vitest 2.1.9), captured from
# the review's fixture shape and trimmed of absolute paths and stack frames.
_PYTEST_INTEST_SYNTAX = (
    "F                                                                        [100%]\n"
    "=================================== FAILURES ===================================\n"
    "___________________________________ test_add ___________________________________\n\n"
    "    def test_add():\n>       import mod\n"
    "E         File \"/w/mod.py\", line 1\n"
    "E           def add(a, b) return a + b\n"
    "E                         ^^^^^^\n"
    "E       SyntaxError: expected ':'\n\n"
    "test_mod.py:2: SyntaxError\n"
    "=========================== short test summary info ============================\n"
    "FAILED test_mod.py::test_add -   File \"/w/mod.py\", line 1\n"
    "1 failed in 0.01s\n")
_PYTEST_TB_NO = ("F                                                                        [100%]\n"
                 "FAILED test_mod.py::test_add -   File \"/w/mod.py\", line 1\n1 failed in 0.00s\n")
_PYTEST_MISSING_NAME = (
    "    def test_add():\n>       from mod import add\n"
    "E       ImportError: cannot import name 'add' from 'mod' (/w/mod.py)\n\n"
    "test_mod.py:2: ImportError\n"
    "FAILED test_mod.py::test_add - ImportError: cannot import name 'add' from 'mod' (/w/mod.py)\n"
    "1 failed in 0.01s\n")
_PYTEST_GONE_ATTRIBUTE = (
    "    def test_add():\n        import mod\n>       assert mod.add(1, 2) == 3\n"
    "               ^^^^^^^\nE       AttributeError: module 'mod' has no attribute 'add'\n\n"
    "test_mod.py:3: AttributeError\n"
    "FAILED test_mod.py::test_add - AttributeError: module 'mod' has no attribute 'add'\n"
    "1 failed in 0.01s\n")
_JEST_SUITE_SYNTAX = (
    "FAIL ./mod.test.js\n  ● Test suite failed to run\n\n"
    "    SyntaxError: /w/mod.js: Unexpected token, expected \"{\" (1:19)\n\n"
    "    > 1 | function add(a, b) return a + b\n        |                    ^\n\n"
    "Test Suites: 1 failed, 1 total\nTests:       0 total\nSnapshots:   0 total\n"
    "Time:        0.152 s\nRan all test suites.\n")
_JEST_SUITE_MISSING = (
    "FAIL ./mod.test.js\n  ● Test suite failed to run\n\n"
    "    Cannot find module './nope' from 'mod.test.js'\n\n"
    "    > 1 | const { add } = require('./nope');\n        |                 ^\n\n"
    "Test Suites: 1 failed, 1 total\nTests:       0 total\nRan all test suites.\n")
_JEST_INTEST_REQUIRE = (
    "FAIL ./mod.test.js\n  ✕ add (2 ms)\n\n  ● add\n\n"
    "    SyntaxError: /w/mod.js: Unexpected token, expected \"{\" (1:19)\n\n"
    "    > 1 | function add(a, b) return a + b\n\n"
    "Test Suites: 1 failed, 1 total\nTests:       1 failed, 1 total\n")
_VITEST_SUITE_PARSE = (
    " RUN  v2.1.9 /w\n\n ❯ mod.test.js (0 test)\n\n"
    "⎯⎯⎯⎯⎯⎯ Failed Suites 1 ⎯⎯⎯⎯⎯⎯⎯\n\n"
    " FAIL  mod.test.js [ mod.test.js ]\nError: Expected '{', got 'return'\n\n"
    " Test Files  1 failed (1)\n      Tests  no tests\n")
_VITEST_SUITE_MISSING = (
    "⎯⎯⎯⎯⎯⎯ Failed Suites 1 ⎯⎯⎯⎯⎯⎯⎯\n\n"
    " FAIL  mod.test.js [ mod.test.js ]\n"
    "Error: Failed to load url ./nope.js (resolved id: ./nope.js) in /w/mod.test.js. "
    "Does the file exist?\n\n Test Files  1 failed (1)\n      Tests  no tests\n")
_JEST_GENUINE = (
    "FAIL ./mod.test.js\n  ● add\n\n"
    "    expect(received).toBe(expected) // Object.is equality\n\n"
    "    Expected: 3\n    Received: -1\n\n"
    "FAIL ./other.test.js\n  ● add\n\n"
    "    expect(received).toBe(expected) // Object.is equality\n\n"
    "Test Suites: 2 failed, 2 total\nTests:       2 failed, 2 total\n")
_VITEST_GENUINE = (
    " ❯ mod.test.js (1 test | 1 failed) 4ms\n   × add 4ms\n"
    "⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯\n\n"
    " FAIL  mod.test.js > add\nAssertionError: expected -1 to be 3 // Object.is equality\n\n"
    " Test Files  1 failed (1)\n      Tests  1 failed (1)\n")
_PYTEST_GENUINE = ("    def test_add():\n>       assert mod.add(1, 2) == 3\nE       assert -1 == 3\n\n"
                   "FAILED test_mod.py::test_add - assert -1 == 3\n1 failed in 0.01s\n")


class StillbornBesideCountedFailures(unittest.TestCase):
    """P1-1 (#612): the stillborn reading ran only when the runner counted ZERO failures. pytest
    counts a SyntaxError raised by an in-test import as `1 failed`, Jest and Vitest count a suite
    that never loaded as a failed suite, and with one failure counted any "failed" in the output
    read as an assertion failure."""

    def refused(self, text):
        ok, reason = verify._failure_signature(text, "")
        self.assertFalse(ok, f"a stillborn control was read as a kill: {text[:80]!r}")
        self.assertIn("STILLBORN", reason)
        return reason

    def test_a_pytest_in_test_import_syntax_error_is_stillborn(self):
        reason = self.refused(_PYTEST_INTEST_SYNTAX)
        self.assertIn("1 counted failure", reason)

    def test_the_pytest_short_summary_alone_still_names_the_load_failure(self):
        self.refused(_PYTEST_TB_NO)

    def test_a_missing_name_or_attribute_under_pytest_is_stillborn(self):
        for text in (_PYTEST_MISSING_NAME, _PYTEST_GONE_ATTRIBUTE):
            with self.subTest(text=text[:40]):
                self.refused(text)

    def test_a_jest_or_vitest_suite_that_never_loaded_is_stillborn(self):
        for text in (_JEST_SUITE_SYNTAX, _JEST_SUITE_MISSING, _VITEST_SUITE_PARSE,
                     _VITEST_SUITE_MISSING):
            with self.subTest(text=text[:40]):
                self.refused(text)

    def test_jests_cross_mark_does_not_vouch_for_a_require_that_blew_up(self):
        # Jest marks the test whose in-test require raised a SyntaxError `✕`, the mark the strong
        # assertion evidence reads; the load failure the runner reported still wins.
        self.refused(_JEST_INTEST_REQUIRE)

    def test_compile_failures_under_go_and_cargo_are_stillborn(self):
        for text in ("# app\n./app.go:3:1: syntax error: unexpected }\n"
                     "FAIL\tapp [build failed]\nFAIL\n",
                     "error[E0308]: mismatched types\n  expected `i32`, found `&str`\n"
                     "error: could not compile `app` (lib) due to 1 previous error\n"):
            with self.subTest(text=text[:30]):
                self.refused(text)

    def test_a_real_assertion_beside_a_load_failure_is_refused_fail_closed(self):
        # Decided: refused. Which failing test is the criterion-bound oracle is not knowable
        # here, and a guarded import turns a stillborn module into an AssertionError.
        mixed = ("    def test_add():\n>       assert mod.add(1, 2) == 3\nE       assert -1 == 3\n\n"
                 "    def test_sub():\n>       from mod import sub\n"
                 "E       ImportError: cannot import name 'sub' from 'mod' (/w/mod.py)\n\n"
                 "2 failed in 0.02s\n")
        reason = self.refused(mixed)
        self.assertIn("2 counted failure", reason)

    def test_a_genuine_assertion_failure_with_nothing_stillborn_is_still_a_kill(self):
        for text in (_PYTEST_GENUINE, _JEST_GENUINE, _VITEST_GENUINE,
                     "    def test_guard():\n>       with pytest.raises(ModuleNotFoundError):\n"
                     "E       Failed: DID NOT RAISE <class 'ModuleNotFoundError'>\n1 failed in 0.01s\n",
                     "FAIL: test_guard\nAssertionError: ModuleNotFoundError not raised\n\n"
                     "FAILED (failures=1)\n"):
            with self.subTest(text=text[:40]):
                ok, reason = verify._failure_signature(text, "")
                self.assertTrue(ok, f"a real assertion failure was refused: {reason}")


# The review's fixture, end to end: the runner prints the REAL runner's output shape. pytest and
# Jest are not in this suite's stdlib-only toolchain, so each is a script that imports the test
# module the way the runner would and reports what the runner reports.
_FAKE_PYTEST = """import importlib.util
import sys
import traceback

spec = importlib.util.spec_from_file_location("test_mod", "test_mod.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
failed = ran = 0
for name in sorted(n for n in dir(module) if n.startswith("test_")):
    ran += 1
    try:
        getattr(module, name)()
    except Exception as exc:
        failed += 1
        print("_" * 20, name, "_" * 20)
        for chunk in traceback.format_exception_only(type(exc), exc):
            for line in chunk.rstrip("\\n").splitlines():
                print("E   " + line)
print("=" * 10, f"{failed} failed" if failed else f"{ran} passed", "in 0.01s", "=" * 10)
sys.exit(1 if failed else 0)
"""
_FAKE_JEST = """import sys

try:
    import mod
except SyntaxError as exc:
    print("FAIL ./mod.test.js")
    print("  \\u25cf Test suite failed to run")
    print()
    print(f"    SyntaxError: {exc.filename}: {exc.msg} ({exc.lineno}:{exc.offset})")
    print()
    print("Test Suites: 1 failed, 1 total")
    print("Tests:       0 total")
    sys.exit(1)
print("PASS ./mod.test.js")
print("Test Suites: 1 passed, 1 total")
print("Tests:       1 passed, 1 total")
"""


class StillbornUnderCountingRunnersEndToEnd(MutationFixture):
    """P1-1 (#612), the reviewer's reproduction: a test that imports the module and asserts
    nothing about the criterion, a `hand` control that breaks mod.py's syntax on the changed
    line, the dark-eligible lane where the executed control is the only oracle. Before the fix:
    `exited 1 on an assertion failure (RED, as required)`, `verify: OK`, exit 0."""

    def _unit(self, runner, label):
        self.write("mod.py", "def add(a, b):\n    return a - b\n")
        self.write("test_mod.py", "def test_add():\n    import mod\n    assert True\n")
        self.write("runner.py", runner)
        base = self.commit("buggy add, a test that asserts nothing")
        self.write("mod.py", "def add(a, b):\n    return a + b\n")
        self.commit("the fix")
        art = self.artifact("hand mutant RED:\n--- a/mod.py\n+++ b/mod.py\n@@ -2 +2 @@\n"
                            "-    return a + b\n+    return a +\n",
                            rel=f"docs/reports/u/nc-stillborn-{label}.txt")
        head = self.commit("hand artifact")
        cmd = f"{shlex.quote(sys.executable)} runner.py"
        path = self._manifest(lighting="dark-eligible", nc={
            "tool": "hand", "result": "RED", "artifact": art, "command": cmd})
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest.update(base_sha=base, head_sha=head)
        manifest["pr"]["reviewed_sha"] = head
        manifest["commands"] = [{"label": "tests", "cmd": cmd,
                                 "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
                                 "exit": 0, "wtree": self.git("rev-parse", f"{head}^{{tree}}")}]
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        return path, cmd

    def test_a_syntax_breaking_control_under_counting_runners_is_not_done(self):
        for label, runner in (("pytest-shaped", _FAKE_PYTEST), ("jest-shaped", _FAKE_JEST)):
            with self.subTest(runner=label):
                path, cmd = self._unit(runner, label)
                rc, out, err = self._run_main(path, "--lighting", "dark-eligible",
                                              "--execute-nc", "--nc-command", cmd)
                self.assertEqual(rc, 2, out + err)
                self.assertIn("STILLBORN MUTANT", err)
                self.assertNotIn("verify: OK", out)


class SourceRepoHooksNeverRun(MutationFixture):
    """P1-2 (#613): `worktree add` and `checkout <base> -- <paths>` ran the source repo's
    post-checkout hook as the verifier, and the revert check read the WORK TREE while the seal
    committed the INDEX — so a hook could stage a failing test into the control commit unseen.
    The reviewer's fixture: a test that asserts nothing, a four-line hook. Before the fix:
    hook not executable -> TAUTOLOGICAL, exit 2; hook executable -> `verify: OK`, exit 0."""

    _FAILING_TEST = ("import unittest\n\nimport mod\n\n\nclass T(unittest.TestCase):\n"
                     "    def test_add(self):\n        self.assertEqual(1, 2)\n")

    def setUp(self):
        super().setUp()
        self.write("mod.py", "def add(a, b):\n    return a - b\n")
        self.write("test_mod.py", "import unittest\n\nimport mod\n\n\nclass T(unittest.TestCase):\n"
                                  "    def test_add(self):\n        self.assertTrue(True)\n")
        self.base = self.commit("buggy add, a test that asserts nothing")
        self.write("mod.py", "def add(a, b):\n    return a + b\n")
        self.head = self.commit("the fix")
        self.cmd = f"{shlex.quote(sys.executable)} -m unittest test_mod"
        self.nc = {"tool": "revert", "result": "RED", "artifact": self.nc_artifact,
                   "command": self.cmd, "paths": ["mod.py"]}
        marks = tempfile.TemporaryDirectory()
        self.addCleanup(marks.cleanup)
        self.fired = Path(marks.name) / "hook-fired"

    def _stage_failing_test(self, wt):
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=wt, check=True,
                              input=self._FAILING_TEST, capture_output=True, text=True).stdout.strip()
        subprocess.run(["git", "update-index", "--cacheinfo", f"100644,{blob},test_mod.py"],
                       cwd=wt, check=True, capture_output=True)

    def _install_hook(self):
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text(
            "#!/bin/sh\n"
            f"touch {shlex.quote(str(self.fired))}\n"
            f"blob=$(printf '%s' {shlex.quote(self._FAILING_TEST)} | git hash-object -w --stdin)\n"
            'git update-index --cacheinfo "100644,$blob,test_mod.py"\n', encoding="utf-8")
        hook.chmod(0o755)
        # Positive control: the hook is live for any git that does not close the channel.
        probe = Path(tempfile.mkdtemp(prefix="orca-hook-probe-"))
        self.addCleanup(shutil.rmtree, probe, True)
        subprocess.run(["git", "worktree", "add", "-q", "--detach", str(probe / "wt"), self.head],
                       cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "worktree", "remove", "--force", str(probe / "wt")],
                       cwd=self.repo, check=True, capture_output=True)
        self.assertTrue(self.fired.exists(), "the planted post-checkout hook did not fire on bare git")
        self.fired.unlink()

    def _manifest_for_unit(self):
        path = self._manifest(lighting="dark-eligible", nc=self.nc)
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
        manifest.update(base_sha=self.base, head_sha=self.head)
        manifest["pr"]["reviewed_sha"] = self.head
        manifest["commands"] = [{"label": "tests", "cmd": self.cmd,
                                 "cmd_sha256": hashlib.sha256(self.cmd.encode("utf-8")).hexdigest(),
                                 "exit": 0, "wtree": self.git("rev-parse", f"{self.head}^{{tree}}")}]
        Path(path).write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_a_post_checkout_hook_cannot_fabricate_the_kill(self):
        self._install_hook()
        rc, out, err = self._run_main(self._manifest_for_unit(), "--lighting", "dark-eligible",
                                      "--execute-nc", "--nc-command", self.cmd)
        self.assertEqual(rc, 2, out + err)
        self.assertIn("TAUTOLOGICAL", err)
        self.assertFalse(self.fired.exists(), "the source repo's hook ran inside a verifier git leg")

    def test_every_verifier_git_leg_points_hooks_at_nothing(self):
        env = verify._Authority.git_env()
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
                 for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pairs.get("core.hooksPath"), os.devnull)

    def test_the_revert_check_reads_the_index_the_seal_commits(self):
        # Content staged in the index but absent from the work tree is what write-tree commits;
        # the check used to read the work tree and pass it.
        holder = Path(tempfile.mkdtemp(prefix="orca-nc-idx-"))
        self.addCleanup(shutil.rmtree, holder, True)
        wt = holder / "wt"
        subprocess.run(["git", "worktree", "add", "-q", "--detach", str(wt), self.head],
                       cwd=self.repo, check=True, capture_output=True)
        self.addCleanup(subprocess.run, ["git", "worktree", "remove", "--force", str(wt)],
                        cwd=self.repo, capture_output=True)
        self._stage_failing_test(wt)
        m = {"base_sha": self.base, "head_sha": self.head, "negative_control": self.nc}
        err = verify._apply_control(str(wt), m, self.nc, "revert", self.cmd)
        self.assertIsNotNone(err, "a staged test change beside the revert passed the check")
        self.assertIn("test_mod.py", err)

    def test_the_seal_binds_the_tree_it_commits(self):
        # Whatever stages content after _apply_control's check, the sealed tree is re-bound.
        real = verify._apply_control

        def apply_then_stage(wt, m, nc, tool, nc_command=None):
            err = real(wt, m, nc, tool, nc_command)
            self._stage_failing_test(wt)
            return err

        m = {"base_sha": self.base, "head_sha": self.head, "negative_control": self.nc}
        with mock.patch.object(verify, "_apply_control", side_effect=apply_then_stage):
            ok, msgs = verify.execute_negative_control(m, self.cmd)
        self.assertFalse(ok, msgs)
        self.assertTrue(any("the sealed control" in e and "TEST path" in e for e in msgs), msgs)


class ProfileSignedDispatchRecords(RepoCase):
    """P2-2 (#614): verify.py canonicalised a dispatch record over _DISPATCH_FIELDS only, while
    dispatch-sign.py appends _PROFILE_FIELDS to a record carrying a profile (#590). Every genuine
    `--profile`/`--parent-profile` record was reported INVALID, and the parity tests sampled only
    profile-free records."""

    _SCRUB = ("OPEN_FLEET_PARENT_PROFILE", "ORCA_PARENT_PROFILE", "OPEN_FLEET_SANDBOX_PROFILE",
              "ORCA_SANDBOX_PROFILE", "OPEN_FLEET_SIGNING_SEED", "ORCA_DISPATCH_SIGNING_SEED")

    def _signed(self, *extra):
        seed = bytes(range(9, 41))
        env = {k: v for k, v in os.environ.items() if k not in self._SCRUB}
        out = subprocess.run(
            [sys.executable, str(ROOT / "runtime" / "scripts" / "dispatch-sign.py"), "sign",
             "--key", self.seed_file(seed), "--manifest-id", "u", "--contract-digest", "sha256:a",
             "--unit-class", "mutation", *extra],
            capture_output=True, text=True, env=env, check=True).stdout
        return (self.write(".orca/profile-record.json", out),
                self.write(".orca/profile-pubkey", ed.publickey(seed).hex()))

    def _check(self, rec, pk):
        return verify.check_dispatch_provenance({"unit": "u"}, "sha256:a", "mutation", None, rec, pk)

    def test_a_profile_signed_record_verifies(self):
        for extra in (("--profile", "rw"), ("--profile", "ro", "--parent-profile", "rw"),
                      ("--parent-profile", "danger")):
            with self.subTest(extra=extra):
                res = self._check(*self._signed(*extra))
                self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)

    def test_a_tampered_or_stripped_profile_does_not(self):
        rec, pk = self._signed("--profile", "ro", "--parent-profile", "rw")
        env = json.loads((self.repo / rec).read_text(encoding="utf-8"))
        for mutate in (lambda r: r.update(profile="danger"), lambda r: r.pop("profile"),
                       lambda r: r.pop("parent_profile")):
            with self.subTest(mutate=mutate):
                tampered = json.loads(json.dumps(env))
                mutate(tampered["record"])
                (self.repo / rec).write_text(json.dumps(tampered), encoding="utf-8")
                self.assertTrue(any("INVALID" in e for e in self._check(rec, pk)))

    def test_canonical_parity_holds_for_profile_records(self):
        ds = dispatch_sign
        for record in ({"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation",
                        "profile": "rw"},
                       {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation",
                        "lighting": "lit", "nc_paths": ["b.py", "a.py"], "profile": "ro",
                        "parent_profile": "danger"},
                       {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation",
                        "parent_profile": "rw"}):
            with self.subTest(record=record):
                self.assertEqual(verify._canonical_dispatch(record), ds.canonical_record(record))
                self.assertIn(b'"profile"' if "profile" in record else b'"parent_profile"',
                              verify._canonical_dispatch(record))

    def test_the_transcript_form_is_the_signers_too(self):
        record = {k: f"v-{k}" for k in verify._Transcript.FIELDS}
        self.assertEqual(verify._Transcript.canonical(record),
                         dispatch_sign.canonical_transcript(record))


class RunnerDiscoveryIsTheOracle(RepoCase):
    """P2-1 (#614): "never revert the oracle" was a filename test. A test the runner collects
    under any other name — `checks/add_check.py` under `python_files = *_check.py`, a test file
    the bound command names as an operand — read as production, so `negative_control.paths`
    could revert it and the RED came from the OLD oracle failing against head."""

    PY = shlex.quote(sys.executable)

    def unit(self, base_files, head_files=None):
        for rel_path, text in base_files.items():
            self.write(rel_path, text)
        base = self.commit("base")
        changes = {"calc.py": "def add(a, b):\n    return a + b\n",
                   "checks/add_check.py": "import calc\n\n\ndef test_add():\n"
                                          "    assert calc.add(2, 2) == 4\n"}
        for rel_path, text in {**changes, **(head_files or {})}.items():
            self.write(rel_path, text)
        head = self.commit("head")
        cache = getattr(verify._is_oracle_path, "discovery", {})  # read once per run
        cache.clear()
        self.addCleanup(cache.clear)
        return {"base_sha": base, "head_sha": head}

    def base(self):
        return {"calc.py": "def add(a, b):\n    return a - b\n",
                "checks/add_check.py": "import calc\n\n\ndef test_add():\n"
                                       "    assert calc.add(2, 2) == 0\n"}

    def bind(self, m, path, cmd):
        return verify._bind_paths_to_change([path], m, "negative_control.paths", cmd)

    def assert_oracle(self, m, path, cmd):
        err = self.bind(m, path, cmd)
        self.assertIsNotNone(err, f"{path} was revertible under {cmd!r}")
        self.assertIn("TEST path", err)

    def test_python_files_in_every_pytest_config_makes_the_check_a_test(self):
        for name, text in (("pytest.ini", "[pytest]\npython_files = *_check.py\n"),
                           ("pyproject.toml", '[tool.pytest.ini_options]\npython_files = ["*_check.py"]\n'),
                           ("setup.cfg", "[tool:pytest]\npython_files = *_check.py\n"),
                           ("tox.ini", "[pytest]\npython_files = *_check.py test_*.py\n")):
            with self.subTest(config=name):
                for stale in ("pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"):
                    (self.repo / stale).unlink(missing_ok=True)
                m = self.unit({**self.base(), name: text})
                for cmd in (f"{self.PY} -m pytest -q", "pytest -q", f"{self.PY} -m pytest -q -k add"):
                    self.assert_oracle(m, "checks/add_check.py", cmd)
                    self.assertIsNone(self.bind(m, "calc.py", cmd), "the production fix stays revertible")

    def test_overrides_and_a_named_config_file_count(self):
        m = self.unit({**self.base(), "ci/custom.ini": "[pytest]\npython_files = *_check.py\n"})
        self.assert_oracle(m, "checks/add_check.py", f"{self.PY} -m pytest -q -c ci/custom.ini")
        self.assert_oracle(m, "checks/add_check.py", f"{self.PY} -m pytest -o python_files=*_check.py")
        self.assertIsNone(self.bind(m, "checks/add_check.py", f"{self.PY} -m pytest -q"))

    def test_a_test_file_the_command_names_is_the_oracle(self):
        m = self.unit(self.base())
        for cmd in (f"{self.PY} -m pytest -q checks/add_check.py",
                    f"{self.PY} -m pytest -q checks/add_check.py::test_add",
                    f"{self.PY} -m pytest -q -- checks/add_check.py",
                    f"{self.PY} -m unittest checks.add_check",
                    f"{self.PY} -m unittest discover -s checks -p *_check.py",
                    f"{self.PY} -m unittest discover checks *_check.py"):
            with self.subTest(cmd=cmd):
                self.assert_oracle(m, "checks/add_check.py", cmd)
                self.assertIsNone(self.bind(m, "calc.py", cmd))

    def test_a_unittest_class_or_method_operand_protects_its_module(self):
        """PR #631 review, P1: `-m unittest checks.add_check.TestAdd.test_add` protected
        `checks/add_check/TestAdd/test_add.py`, a file that does not exist, so the real test
        module stayed revertible. The operand resolves to its deepest module at head_sha."""
        m = self.unit(self.base(), head_files={
            "checks/__init__.py": "",
            "checks/add_check.py": "import unittest\n\nimport calc\n\n\nclass TestAdd(unittest.TestCase):\n"
                                   "    def test_add(self):\n        self.assertEqual(calc.add(2, 2), 4)\n"})
        for cmd in (f"{self.PY} -m unittest checks.add_check.TestAdd",
                    f"{self.PY} -m unittest checks.add_check.TestAdd.test_add",
                    f"{self.PY} -m unittest -v checks.add_check.TestAdd.test_add"):
            with self.subTest(cmd=cmd):
                self.assert_oracle(m, "checks/add_check.py", cmd)
                self.assertIsNone(self.bind(m, "calc.py", cmd), "the production fix stays revertible")

    def test_testpaths_scope_discovery_and_operands_widen_it(self):
        m = self.unit({**self.base(),
                       "pytest.ini": "[pytest]\npython_files = *_check.py\ntestpaths = tests\n"})
        # pytest collects under testpaths only, so a *_check.py elsewhere is not its oracle...
        self.assertIsNone(self.bind(m, "checks/add_check.py", f"{self.PY} -m pytest -q"))
        # ...until the command names that tree, when pytest collects there instead.
        self.assert_oracle(m, "checks/add_check.py", f"{self.PY} -m pytest -q checks")
        self.assert_oracle(m, "checks/add_check.py", f"{self.PY} -m pytest -q .")

    def test_jest_test_match_and_test_regex_in_package_json(self):
        js = {"calc.js": "module.exports = (a, b) => a - b;\n",
              "qa/add.js": "test('add', () => {});\n", "src/add.test.js": "test('x', () => {});\n"}
        default_match = ["**/__tests__/**/*.[jt]s?(x)", "**/?(*.)+(spec|test).[jt]s?(x)"]
        for jest in ({"testMatch": ["**/qa/**/*.js", *default_match]},
                     {"testRegex": "/qa/.*\\.js$"}, {"testRegex": ["/qa/[^/]*\\.js$"]}):
            with self.subTest(jest=jest):
                self.write("package.json", json.dumps({"name": "x", "jest": jest}))
                m = self.unit(js, {"calc.js": "module.exports = (a, b) => a + b;\n",
                                   "qa/add.js": "test('add', () => { });\n",
                                   "src/add.test.js": "test('x', () => { });\n"})
                cmd = "node node_modules/jest/bin/jest.js"
                self.assert_oracle(m, "qa/add.js", cmd)
                self.assertIsNone(self.bind(m, "calc.js", cmd), "the default testMatch over-matched")

    def test_unreadable_discovery_configuration_fails_closed(self):
        m = self.unit({**self.base(), "pyproject.toml": "[tool.pytest.ini_options\npython_files =\n"})
        err = self.bind(m, "calc.py", f"{self.PY} -m pytest -q")
        self.assertIsNotNone(err)
        self.assertIn("pyproject.toml", err)
        self.assertIn("fail-closed", err)

    def test_the_reviewers_reproduction_end_to_end(self):
        # A runner that collects checks/*_check.py, as pytest does under that config; the revert
        # restores the OLD check, which fails against the fixed head — a RED about nothing.
        runner = ("import importlib.util\nimport pathlib\nimport sys\n\nsys.path.insert(0, '.')\n"
                  "failed = 0\nfor path in sorted(pathlib.Path('checks').glob('*_check.py')):\n"
                  "    spec = importlib.util.spec_from_file_location(path.stem, path)\n"
                  "    module = importlib.util.module_from_spec(spec)\n"
                  "    spec.loader.exec_module(module)\n"
                  "    for name in sorted(n for n in dir(module) if n.startswith('test_')):\n"
                  "        try:\n            getattr(module, name)()\n"
                  "        except AssertionError as exc:\n            failed += 1\n"
                  "            print(f'FAIL: {path}::{name}')\n            print(f'AssertionError: {exc}')\n"
                  "print(f'FAILED (failures={failed})' if failed else 'OK')\nsys.exit(1 if failed else 0)\n")
        m = self.unit({**self.base(), "pytest.ini": "[pytest]\npython_files = *_check.py\n",
                       "runner.py": runner})
        cmd = f"{self.PY} runner.py"
        art = self.artifact("RED\n", "docs/reports/u/nc-oracle-revert.txt")
        m.update(artifacts=[self.pin(art)], negative_control={
            "tool": "revert", "result": "RED", "artifact": art, "command": cmd,
            "paths": ["checks/add_check.py"]})
        errors, executed = verify.check_negative_control(m, True, execute=True, nc_command=cmd)
        self.assertFalse(executed, errors)
        self.assertTrue(any("TEST path" in e for e in errors), errors)


class PrNumberIsAPositiveInteger(MutationFixture):
    """P3 (#614): pr.number came from the worker's manifest and was interpolated into the gh api
    PATH (`repos/<slug>/pulls/<n>/reviews`) unvalidated; github.com rejects dot-segments today,
    and the gate no longer relies on that."""

    def test_anything_but_a_positive_integer_is_refused_before_any_lookup(self):
        calls = []
        verify.fetch_reviews = lambda repo_, n: calls.append(n) or (
            [{"state": "APPROVED", "author_association": "MEMBER", "commit_id": self.head_sha,
              "user": {"login": "carol"}}], None)
        m = json.loads(Path(self._manifest()).read_text(encoding="utf-8"))
        for number in ("7/../../8", "7?per_page=1", "7", 7.0, -7, True, [7]):
            with self.subTest(number=number):
                m["pr"]["number"] = number
                res = verify.check_review(m, "o/r", True)
                self.assertTrue(any("not a positive integer" in e for e in res), res)
        self.assertEqual(calls, [], "a review lookup ran on an unvalidated pr.number")
        m["pr"]["number"] = 7
        self.assertFalse([e for e in verify.check_review(m, "o/r", True) if not e.startswith("NOTE:")])
        self.assertEqual(calls, [7])

    def test_the_fetchers_refuse_it_too(self):
        verify.fetch_reviews, verify.fetch_pr_author = self._orig_r, self._orig_a
        verify._Authority.gh, verify._Authority.custody = "/nonexistent/gh", "system"
        with mock.patch.object(verify, "_run", return_value=(0, "[]", "")) as run:
            reviews, err = verify.fetch_reviews("o/r", "7/../8")
            self.assertIsNone(reviews)
            self.assertIn("positive integer", err)
            self.assertIsNone(verify.fetch_pr_author("o/r", "7/../8"))
            run.assert_not_called()


class VerifierDocsMatchTheCode(unittest.TestCase):
    """P3 (#614): docs/verify-gate.md budgeted "2 checkouts + 2 runs" for an executed control
    that runs the bound command three times (clean, control, clean) and checks out four times
    (the scratch worktree plus one repository per phase); _fresh_command_records said the NC
    replay bound to the ledger, which #279 ended."""

    def test_the_budget_counts_the_phases_the_code_runs(self):
        src = (ROOT / "runtime" / "scripts" / "verify.py").read_text(encoding="utf-8")
        phases = re.search(r"for phase, commit in \(((?:\(\"\w+\", \w+\),? ?)+)\):", src)
        self.assertIsNotNone(phases, "the phase loop moved; re-pin this test against it")
        runs = phases.group(1).count("(")
        doc = (ROOT / "docs" / "verify-gate.md").read_text(encoding="utf-8")
        flat = " ".join(doc.split())
        self.assertIn(f"{runs} runs of the bound command", flat)
        self.assertIn(f"{runs + 1} checkouts", flat)
        self.assertNotIn("2 runs of the bound command", flat)

    def test_the_ledger_helper_no_longer_claims_the_replay_binds_to_it(self):
        doc = " ".join(verify._fresh_command_records.__doc__.split())
        self.assertNotIn("replay binds to", doc)
        self.assertIn("--nc-command", doc)


@contextlib.contextmanager
def _linked_control_git_dir(cls, top, head):
    """The control's pre-custody layout, for mutation controls only: a linked worktree of `top`
    (`worktree add --no-checkout`), whose admin dir reads the SHARED config and `info/attributes`
    the graded worker writes. Patched over _Authority.control_git_dir, it shows the custody is
    what keeps a planted driver from running in the control (W4 custody sweep)."""
    holder = tempfile.mkdtemp(prefix="orca-nc-linked-")
    wt = os.path.join(holder, "wt")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", top, "worktree", "add", "-q", "--no-checkout", "--detach", wt, head],
                   check=True, capture_output=True, env=env, stdin=subprocess.DEVNULL)
    try:
        yield subprocess.run(["git", "-C", wt, "rev-parse", "--absolute-git-dir"], check=True,
                             capture_output=True, text=True, env=env,
                             stdin=subprocess.DEVNULL).stdout.strip()
    finally:
        subprocess.run(["git", "-C", top, "worktree", "remove", "--force", wt], capture_output=True,
                       env=env, stdin=subprocess.DEVNULL)
        shutil.rmtree(holder, ignore_errors=True)


class ConfigFilterNeverRunsInTheControl(MutationFixture):
    """#629: `worktree add` and `checkout <base> -- <paths>` MATERIALISE worker content, running a
    repo-config clean/smudge filter a `.gitattributes` (or, as here, `$GIT_DIR/info/attributes`,
    which `--attr-source` cannot override) selects — the one channel git_env's fixed belt and the
    `--no-textconv`/`--no-ext-diff` flags cannot close. The negative control runs the worker's own
    test, so this would be a command running on the verifier BEFORE that, out of a key git.py's
    global/system scrub leaves in force. _Authority.driver_blanks closes it; this drives the full
    `--execute-nc` flow and requires the planted filter never fires."""

    def setUp(self):
        super().setUp()
        marks = tempfile.TemporaryDirectory()
        self.addCleanup(marks.cleanup)
        self.marker = Path(marks.name) / "filter-fired"
        self.probe = Path(marks.name) / "probe.sh"
        # The probe ONLY touches its marker and never reads stdin, so it cannot block on an
        # inherited pipe. A filter that fires is the failure under test; in the GREEN case the
        # driver is blanked and never runs, so app.py still reads `return 2` at head.
        self.probe.write_text("#!/bin/sh\ntouch " + shlex.quote(str(self.marker)) + "\nexit 0\n",
                             encoding="utf-8")
        self.probe.chmod(0o755)
        for key in ("filter.p.clean", "filter.p.smudge"):
            self.git("config", key, f"{self.probe} {key}")
        info = self.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py filter=p\n", encoding="utf-8")

    def _positive_control(self):
        """A bare `git worktree add` at head_sha: the planted filter fires for any git that does
        not blank the driver command, so the GREEN assertion below is not vacuous."""
        probe_dir = Path(tempfile.mkdtemp(prefix="orca-filter-probe-"))
        self.addCleanup(shutil.rmtree, probe_dir, True)
        subprocess.run(["git", "worktree", "add", "-q", "--detach", str(probe_dir / "wt"),
                        self.head_sha], cwd=self.repo, check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        subprocess.run(["git", "worktree", "remove", "--force", str(probe_dir / "wt")],
                       cwd=self.repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertTrue(self.marker.exists(),
                        "the planted clean/smudge filter did not fire on bare git")
        self.marker.unlink()

    def test_the_executed_control_runs_no_planted_filter(self):
        self._positive_control()
        rc, out, err = self._run_main(self._manifest(lighting="dark-eligible", nc=self._revert_nc()),
                                      "--lighting", "dark-eligible",
                                      "--execute-nc", "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(self.marker.exists(),
                         "a repo-config filter ran inside a verifier git leg (#629)")

    def test_mutation_control_without_the_blanks_the_filter_fires(self):
        # The pre-fix control: a linked worktree of the source (the shared config), no blanks.
        self._positive_control()
        with mock.patch.object(verify._Authority, "driver_blanks",
                               classmethod(lambda cls, repo: [])), \
                mock.patch.object(verify._Authority, "control_git_dir",
                                  classmethod(_linked_control_git_dir)):
            self._run_main(self._manifest(lighting="dark-eligible", nc=self._revert_nc()),
                           "--lighting", "dark-eligible",
                           "--execute-nc", "--nc-command", self.proof_cmd)
        self.assertTrue(self.marker.exists(),
                        "control: with the driver blanks removed the filter must fire")


class ConfigFilterByteNameNeverRunsInTheControl(ConfigFilterNeverRunsInTheControl):
    """PR #649 review (PRRT_kwDOTWxN9c6vvony): the same two cases with the selected driver named
    by a byte git accepts and a text decode cannot round-trip (0xff -> U+FFFD names another
    driver; a strict locale decode raised inside _run instead). The planted command must still
    never run in a verifier git leg, and its mutation control must still fire it."""

    NAME = b"\xff"

    def setUp(self):
        super().setUp()
        for var in (b"clean", b"smudge"):
            subprocess.run([b"git", b"config", b"filter." + self.NAME + b"." + var,
                            os.fsencode(str(self.probe)) + b" " + var],
                           cwd=self.repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
        (self.repo / ".git" / "info" / "attributes").write_bytes(
            b"*.py filter=" + self.NAME + b"\n")


class ConfigFilterEqualsNameNeverRunsInTheControl(ConfigFilterByteNameNeverRunsInTheControl):
    """A driver name holding `=`: `-c filter.a=b.clean=` is split at its FIRST `=` and blanks a
    different key, so only an env pair (key and value apart) blanks this driver."""

    NAME = b"a=b"


class ConfigRequiredFilterNeverRunsInTheControl(ConfigFilterNeverRunsInTheControl):
    """PR #649 review (PRRT_kwDOTWxN9c6vvon0): the planted filter is also `required=true`. With
    only its command blanked, git dies `clean/smudge filter 'p' failed` in the control's
    `worktree add`, so a worker could fail every unit it touched. The inherited cases require a
    GREEN control that runs nothing, and a mutation control that still runs the filter."""

    def setUp(self):
        super().setUp()
        self.git("config", "filter.p.required", "true")


class ConfigRequiredFilterWithNoCommandNeverStopsTheControl(MutationFixture):
    """`filter.<driver>.required=true` with NO command declared: plain git dies on any matching
    file, with no command to blank. The executed control must still run and go GREEN."""

    def setUp(self):
        super().setUp()
        self.git("config", "filter.r.required", "true")
        info = self.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py filter=r\n", encoding="utf-8")

    def test_a_required_filter_with_no_command_does_not_stop_the_control(self):
        # Positive control: bare git dies cleaning a matching file. (git skips a smudge it has no
        # command for, so the clean side is where a command-less required filter bites — and where
        # a blanked-but-still-required smudge bit the control's `worktree add`.)
        plain = subprocess.run(["git", "hash-object", "--path=app.py", "app.py"], cwd=self.repo,
                               capture_output=True, text=True, stdin=subprocess.DEVNULL)
        self.assertNotEqual(plain.returncode, 0, "a required filter with no command did not stop git")
        self.assertIn("filter 'r' failed", plain.stderr)
        rc, out, err = self._run_main(self._manifest(lighting="dark-eligible", nc=self._revert_nc()),
                                      "--lighting", "dark-eligible",
                                      "--execute-nc", "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)


class ConditionalIncludeFilterNeverRunsInTheControl(MutationFixture):
    """PR #649 review (PRRT_kwDOTWxN9c6vxaeq): a linked worktree's config is not its source's.
    `[includeIf "gitdir:**/worktrees/**"]` loads a filter ONLY in a linked worktree, so a blank
    list read in the source repo omits it, and the control's `worktree add` ran its smudge on the
    verifier. The drivers must be read IN the new worktree, before anything is materialised."""

    def setUp(self):
        super().setUp()
        marks = tempfile.TemporaryDirectory()
        self.addCleanup(marks.cleanup)
        self.marker = Path(marks.name) / "cond-filter-fired"
        probe = Path(marks.name) / "probe.sh"
        probe.write_text("#!/bin/sh\ntouch " + shlex.quote(str(self.marker)) + "\nexit 0\n",
                         encoding="utf-8")
        probe.chmod(0o755)
        include = Path(marks.name) / "cond.gitconfig"
        include.write_text(f'[filter "cond"]\n\tclean = {probe} clean\n\tsmudge = {probe} smudge\n',
                           encoding="utf-8")
        self.git("config", "includeIf.gitdir:**/worktrees/**.path", str(include))
        info = self.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py filter=cond\n", encoding="utf-8")

    def _positive_control(self):
        """The source repo's own config listing does NOT declare `cond`, yet bare git runs it in
        a linked worktree — the gap the review found, live on this host."""
        listing = subprocess.run(["git", "config", "--list", "--name-only"], cwd=self.repo,
                                 capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout
        self.assertNotIn("filter.cond.", listing)
        holder = Path(tempfile.mkdtemp(prefix="orca-cond-probe-"))
        self.addCleanup(shutil.rmtree, holder, True)
        subprocess.run(["git", "worktree", "add", "-q", "--detach", str(holder / "wt"),
                        self.head_sha], cwd=self.repo, check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        subprocess.run(["git", "worktree", "remove", "--force", str(holder / "wt")],
                       cwd=self.repo, check=True, capture_output=True, stdin=subprocess.DEVNULL)
        self.assertTrue(self.marker.exists(), "the conditionally included filter did not fire")
        self.marker.unlink()

    def _run(self):
        return self._run_main(self._manifest(lighting="dark-eligible", nc=self._revert_nc()),
                              "--lighting", "dark-eligible",
                              "--execute-nc", "--nc-command", self.proof_cmd)

    def test_a_filter_only_a_linked_worktree_loads_never_runs_in_the_control(self):
        self._positive_control()
        rc, out, err = self._run()
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(self.marker.exists(),
                         "a conditionally included filter ran in the control worktree (#629)")

    def test_mutation_control_drivers_read_in_the_source_repo_miss_it(self):
        # Read the drivers where the old code read them — the source repo — whatever directory
        # the call names: the conditional filter is missing from that list and runs again.
        # The control's pre-custody layout (a linked worktree, whose config view includes the
        # conditional file) is restored too: in custody no filter is defined at all.
        self._positive_control()
        source, real = str(self.repo), verify._Authority.driver_blanks
        with mock.patch.object(verify._Authority, "driver_blanks",
                               classmethod(lambda cls, repo: real(source))), \
                mock.patch.object(verify._Authority, "control_git_dir",
                                  classmethod(_linked_control_git_dir)):
            self._run()
        self.assertTrue(self.marker.exists(),
                        "control: blanks read in the source repo must miss the linked-only filter")


class ConfigMergeDriverNeutralisedInTheControl(MutationFixture):
    """PR #649 review (merge-driver class): a repo `merge.<driver>.driver` runs when git 3-way-
    merges a path. verify's control `revert`/`apply`/`checkout` legs now carry the override that
    neutralises it, via driver_blanks. A linear in-order range revert is trivial at every step and
    verify refuses a non-linear range, so the leg cannot in fact be driven to a merge (brute-forced
    in tests/test_gitexec_config_commands.py); the override rides defensively, and the real live
    site, `git merge-tree`, is covered there. This pins that the legs' env carries it and that a
    full control run with a planted merge driver stays GREEN and runs nothing."""

    def setUp(self):
        super().setUp()
        self.git("config", "merge.m.driver", "false %O %A %B")
        info = self.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py merge=m\n", encoding="utf-8")

    def test_the_control_legs_env_overrides_the_merge_driver(self):
        env = verify._Authority.blanked_env(verify._Authority.driver_blanks(str(self.repo)))
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
                 for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pairs.get("merge.m.driver"), "exit 1")

    def test_a_full_revert_control_runs_the_merge_driver_nowhere(self):
        rc, out, err = self._run_main(self._manifest(lighting="dark-eligible", nc=self._revert_nc()),
                                      "--lighting", "dark-eligible",
                                      "--execute-nc", "--nc-command", self.proof_cmd)
        self.assertEqual(rc, 0, out + err)


class ControlRunsNoDriverAddedAfterTheListing(MutationFixture):
    """W4 custody sweep (audit W4-01/W4-02 class): driver_blanks LISTS the drivers the control
    worktree's config declares, then the checkout/revert/apply reads that config again. A sibling
    worker that adds a NEVER-SEEN `filter.<n>.*`, `diff.<n>.textconv` or `merge.<n>.driver` to the
    shared config (selected for every path through the shared `info/attributes`) between the two
    had it run as the verifier. The control now runs in a git dir the verifier builds, whose config
    declares no driver. The racing sibling below adds a fresh driver before EVERY git launch."""

    def setUp(self):
        super().setUp()
        marks = tempfile.TemporaryDirectory()
        self.addCleanup(marks.cleanup)
        self.dir = Path(marks.name)
        self.marker = self.dir / "fired"
        self.seq = 0

    def _probe(self, name, passthrough):
        probe = self.dir / f"{name}.sh"
        probe.write_text("#!/bin/sh\necho " + shlex.quote(name) + " >> " + shlex.quote(str(self.marker))
                         + ("\ncat\n" if passthrough else "\nexit 0\n"), encoding="utf-8")
        probe.chmod(0o755)
        return '"' + str(probe).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _race(self):
        real = subprocess.run
        common = self.repo / ".git"

        def run(argv, *a, **kw):
            if isinstance(argv, (list, tuple)) and argv and os.path.basename(str(argv[0])) == "git":
                self.seq += 1
                name = f"late{self.seq}"
                with open(common / "config", "a", encoding="utf-8") as fh:
                    fh.write(f'[filter "{name}"]\n\tsmudge = {self._probe(name + "-smudge", True)}\n'
                             f'\tclean = {self._probe(name + "-clean", True)}\n'
                             f'[diff "{name}"]\n\ttextconv = {self._probe(name + "-textconv", False)}\n'
                             f'[merge "{name}"]\n\tdriver = {self._probe(name + "-merge", False)}\n')
                (common / "info").mkdir(exist_ok=True)
                with open(common / "info" / "attributes", "a", encoding="utf-8") as fh:
                    fh.write(f"* filter={name} diff={name} merge={name}\n")
            return real(argv, *a, **kw)
        return mock.patch.object(subprocess, "run", run)

    def _fired(self):
        return self.marker.read_text().split() if self.marker.exists() else []

    def _controls(self):
        """The revert control both ways: restoring the declared paths from base_sha (`checkout
        <base> -- <paths>`), and the linear range revert (`revert --no-commit base..head`)."""
        paths = self._revert_nc()
        ranged = {k: v for k, v in paths.items() if k != "paths"}
        return (("paths", paths), ("range", ranged))

    def _execute(self, nc):
        m = {"base_sha": self.base_sha, "head_sha": self.head_sha, "negative_control": nc}
        return verify.execute_negative_control(m, self.proof_cmd)

    def test_a_driver_added_after_every_listing_never_runs_in_the_control(self):
        for label, nc in self._controls():
            with self.subTest(control=label):
                with self._race():
                    ok, msgs = self._execute(nc)
                self.assertGreater(self.seq, 0, "the race never ran")
                self.assertEqual(self._fired(), [], f"a driver added mid-control ran ({label})")
                self.assertTrue(ok, msgs)
                self.assertTrue(any("negative control EXECUTED" in x for x in msgs), msgs)

    def test_mutation_control_the_linked_worktree_runs_the_late_driver(self):
        # The pre-custody layout, under the same race, with the real (listing) driver_blanks: the
        # driver added after the listing runs in the control's checkout. The plant is live.
        with self._race(), mock.patch.object(verify._Authority, "control_git_dir",
                                             classmethod(_linked_control_git_dir)):
            self._execute(self._revert_nc())
        self.assertTrue(self._fired(), "control: the late driver never ran in a linked worktree")

    def test_the_control_git_dir_declares_no_driver_and_writes_the_source_store(self):
        # info/attributes is carried as DATA (line endings, encodings); the filter it selects is
        # one the dir's config never defines.
        self.git("config", "filter.p.clean", "false")
        (self.repo / ".git" / "info").mkdir(exist_ok=True)
        (self.repo / ".git" / "info" / "attributes").write_text("*.py filter=p eol=crlf\n", encoding="utf-8")
        with verify._Authority.control_git_dir(str(self.repo), self.head_sha) as gd:
            gd = Path(gd)
            self.assertEqual((gd / "HEAD").read_text(encoding="utf-8").strip(), self.head_sha)
            self.assertNotIn("filter", (gd / "config").read_text(encoding="utf-8"))
            self.assertEqual((gd / "info" / "attributes").read_text(encoding="utf-8"), "*.py filter=p eol=crlf\n")
            self.assertEqual((gd / "objects").resolve(), (self.repo / ".git" / "objects").resolve())
        self.assertFalse(gd.exists(), "the control git dir outlived its use")

    def test_the_source_attributes_file_rides_as_data_or_refuses(self):
        # A repository-scope core.attributesFile is carried as CONTENT (a bounded regular file,
        # never opened blocking): the CRLF repository still executes and kills; a FIFO there is
        # the "could not create" refusal at once, never a hung control.
        outside = Path(tempfile.mkdtemp(prefix="orca-attrs-"))
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "attrs").write_text("*.py text eol=crlf\n", encoding="utf-8")
        self.git("config", "core.attributesFile", str(outside / "attrs"))
        with verify._Authority.control_git_dir(str(self.repo), self.head_sha) as gd:
            self.assertEqual((Path(gd) / "attributes").read_text(encoding="utf-8"), "*.py text eol=crlf\n")
        ok, msgs = self._execute(self._revert_nc())
        self.assertTrue(ok, msgs)
        fifo = outside / "attrs-fifo"
        os.mkfifo(fifo)
        self.git("config", "core.attributesFile", str(fifo))
        ok, msgs = self._execute(self._revert_nc())
        self.assertFalse(ok)
        self.assertTrue(any("could not create the control worktree" in x and "core.attributesFile" in x
                            for x in msgs), msgs)

    def test_a_timed_out_custody_query_refuses_the_control(self):
        # Codex on PR #724 (round 6): the control dir's core.attributesFile query ran through
        # _run_bytes, which reports a timeout as exit 1 - "unset" for `config --get` - so a
        # timed-out query proceeded as "no attributes file". It is the "could not create" refusal.
        real = subprocess.run

        def run(argv, *a, **kw):
            if isinstance(argv, (list, tuple)) and "core.attributesFile" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout", 30))
            return real(argv, *a, **kw)
        with mock.patch.object(subprocess, "run", run):
            ok, msgs = self._execute(self._revert_nc())
        self.assertFalse(ok)
        self.assertTrue(any("could not create the control worktree" in x and "timed out" in x
                            for x in msgs), msgs)

    def test_no_user_attributes_or_ignore_file_is_opened(self):
        # PR #724 re-attack (items 1, 2): a FIFO at ~/.config/git/ignore blocked the control's
        # checkout, and one at ~/.config/git/attributes the phase repositories' reset --hard (each
        # until its 120 s timeout). The control dir names its own attributes and excludes files;
        # each phase's checkout pins both to /dev/null on its own command line.
        import threading
        home = Path(tempfile.mkdtemp(prefix="orca-fifo-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / ".config" / "git").mkdir(parents=True)
        for name in ("attributes", "ignore"):
            os.mkfifo(home / ".config" / "git" / name)
        box = {}

        def run():
            box["result"] = self._execute(self._revert_nc())
        with mock.patch.dict(os.environ, {"HOME": str(home)}):
            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            worker.join(60)
        self.assertFalse(worker.is_alive(), "the executed control blocked on a default user attributes "
                         "or ignore file")
        ok, msgs = box["result"]
        self.assertTrue(ok, msgs)

    def test_a_crlf_repository_still_executes_and_kills(self):
        # A repository whose own attributes and config check *.py out with CRLF: the control's
        # checkout honours them (data), the seal normalises them, and only the reverted path
        # differs from head_sha's tree.
        (self.repo / ".git" / "info").mkdir(exist_ok=True)
        (self.repo / ".git" / "info" / "attributes").write_text("*.py text eol=crlf\n", encoding="utf-8")
        self.git("config", "core.autocrlf", "true")
        ok, msgs = self._execute(self._revert_nc())
        self.assertTrue(ok, msgs)
        self.assertTrue(any("negative control EXECUTED" in x for x in msgs), msgs)


class DriverQueryFailureRefusesTheControl(MutationFixture):
    """PR #649 review (PRRT_kwDOTWxN9c6vzAIE): when the control worktree's config query fails or
    prints output that cannot be parsed, driver_blanks used to return [] — "no drivers" — and the
    control populated the worktree with every planted filter live. The verifier must refuse
    instead. A fake git, first on PATH so it is the one verify pins, misbehaves ONLY for
    `config --list` and delegates every other call, so the planted filter really would run."""

    def setUp(self):
        super().setUp()
        marks = tempfile.TemporaryDirectory()
        self.addCleanup(marks.cleanup)
        self.dir = Path(marks.name)
        self.marker = self.dir / "filter-fired"
        probe = self.dir / "probe.sh"
        probe.write_text("#!/bin/sh\ntouch " + shlex.quote(str(self.marker)) + "\nexit 0\n",
                         encoding="utf-8")
        probe.chmod(0o755)
        for key in ("filter.p.clean", "filter.p.smudge"):
            self.git("config", key, f"{probe} {key}")
        info = self.repo / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_text("*.py filter=p\n", encoding="utf-8")

    def _fake_git_on_path(self, mode):
        action = {"fail": 'echo "fatal: forced config failure" >&2; exit 128',
                  "garbage": "printf 'filter.p.clean'; exit 0"}[mode]
        bindir = self.dir / f"bin-{mode}"
        bindir.mkdir()
        script = bindir / "git"
        script.write_text('#!/bin/sh\ncase " $* " in\n  *" config --list "*) ' + action + " ;;\nesac\n"
                          "exec " + shlex.quote(shutil.which("git")) + ' "$@"\n', encoding="utf-8")
        script.chmod(0o755)
        return mock.patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ["PATH"]})

    def test_a_failed_or_unparseable_query_refuses_and_runs_no_filter(self):
        for mode in ("fail", "garbage"):
            with self.subTest(mode=mode):
                with self._fake_git_on_path(mode):
                    rc, out, err = self._run_main(
                        self._manifest(lighting="dark-eligible", nc=self._revert_nc()),
                        "--lighting", "dark-eligible", "--execute-nc", "--nc-command", self.proof_cmd)
                self.assertEqual(rc, 2, out + err)
                self.assertIn("cannot read the control worktree's driver config", err)
                self.assertFalse(self.marker.exists(),
                                 "the control ran a planted filter with no blanks (#629)")
                verify._Authority.reset()


class TrackedArtifactPinsAreChecked(RepoCase):
    """#596 certification finding: a manifest whose `artifacts[]` sha256 was wrong for a file
    TRACKED at head_sha verified clean. The tracked-at-head read returned the blob without ever
    consulting the pin, so a manifest could inventory digests that bind nothing. A pin the
    manifest declares is a claim about the bytes; for a tracked path those bytes are the blob."""

    KILLED = b"mutant m#7 was KILLED\n"

    def _tracked(self):
        rel = self.artifact(self.KILLED)
        return rel, self.commit("evidence")

    def _nc(self, rel):
        return {"tool": "mutmut", "mutant": "m#7", "result": "KILLED", "artifact": rel}

    def test_a_tracked_artifact_with_a_wrong_pin_is_refused_at_every_reader(self):
        rel, head = self._tracked()
        m = {"unit": "ship-it", "head_sha": head, "negative_control": self._nc(rel),
             "artifacts": [{"path": rel, "sha256": "0" * 64}]}
        raw, err = verify.read_artifact(m, rel)
        self.assertIsNone(raw)
        self.assertIn("artifacts[] pins", err or "")
        errs, _ = verify.check_negative_control(m, True, execute=False)
        self.assertTrue(any("unreadable" in e for e in errs), errs)
        with mock.patch.object(verify, "_gitleaks_scan", return_value=False):
            self.assertTrue(any("artifacts[] pins" in e for e in verify.check_redaction(m, None)))

    def test_a_pin_of_the_working_tree_overlay_does_not_bind_the_tracked_blob(self):
        # The pin hashes bytes the verifier never reads: the overlay, not the blob at head_sha.
        rel, head = self._tracked()
        self.write(rel, "overlay written after the commit\n")
        m = {"unit": "ship-it", "head_sha": head, "artifacts": [self.pin(rel)]}
        raw, err = verify.read_artifact(m, rel)
        self.assertIsNone(raw)
        self.assertIn("head_sha", err or "")

    def test_the_true_pin_of_the_tracked_blob_still_passes(self):
        rel, head = self._tracked()
        want = hashlib.sha256(self.KILLED).hexdigest()
        self.write(rel, "overlay written after the commit\n")
        for digest in (want, "sha256:" + want.upper()):
            with self.subTest(digest=digest[:12]):
                m = {"unit": "ship-it", "head_sha": head, "negative_control": self._nc(rel),
                     "artifacts": [{"path": rel, "sha256": digest}]}
                self.assertEqual(verify.read_artifact(m, rel), (self.KILLED, None))
                self.assertEqual(verify.check_negative_control(m, True, execute=False)[0], [])

    def test_a_tracked_artifact_named_without_a_pin_still_reads_the_blob(self):
        # Naming a tracked path (bare string, or no entry) pins nothing extra: the blob is the pin.
        rel, head = self._tracked()
        for artifacts in ([], [rel]):
            with self.subTest(artifacts=artifacts):
                m = {"unit": "ship-it", "head_sha": head, "artifacts": artifacts}
                self.assertEqual(verify.read_artifact(m, rel), (self.KILLED, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class BaseShaIsBoundToTheIntegrationBranch(unittest.TestCase):
    """2026-10-26 review (P0): the executed control restores production files from base_sha and
    the changed-production denominator is base_sha..head_sha, yet nothing bound base_sha to
    coordinator state. A worker that declares a poison commit (production code failing under any
    call) as base_sha turns any test RED under the revert and passes a head that is wrong for the
    criterion. Named a base, base_sha must now be an ancestor of refs/remotes/origin/<base>."""

    def setUp(self):
        self._tmp = _temp_repo()
        self.repo = Path(self._tmp.name)

        def git(*args):
            return subprocess.run(["git", *args], cwd=self.repo, check=True,
                                  capture_output=True, text=True).stdout.strip()

        git("init", "-q", "-b", "main")
        Path(self.repo, "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        git("add", "app.py")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "honest base")
        self.honest_base = git("rev-parse", "HEAD")
        git("update-ref", "refs/remotes/origin/main", "HEAD")
        # The poison: a real commit on a side line the integration branch never held.
        Path(self.repo, "app.py").write_text("def f():\n    raise AssertionError('expected 2')\n",
                                             encoding="utf-8")
        git("add", "app.py")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "poison")
        self.poison = git("rev-parse", "HEAD")
        self.addCleanup(verify._Authority.reset)

    def tearDown(self):
        self._tmp.cleanup()

    @contextlib.contextmanager
    def _inside_repo(self):
        cwd = os.getcwd()
        os.chdir(self.repo)
        try:
            yield
        finally:
            os.chdir(cwd)

    def test_an_honest_base_on_the_branch_passes(self):
        with self._inside_repo():
            self.assertEqual(verify.check_base_binding({"base_sha": self.honest_base}, "main", True), [])

    def test_a_worker_chosen_base_off_the_branch_is_fatal(self):
        with self._inside_repo():
            errs = verify.check_base_binding({"base_sha": self.poison}, "main", True)
        self.assertEqual(len(errs), 1, errs)
        self.assertNotIn("NOTE:", errs[0])
        self.assertIn("not an ancestor of origin/main", errs[0])
        self.assertIn("worker chose its own base", errs[0])

    def test_without_a_base_the_native_lane_notes_and_a_sound_lane_refuses(self):
        with self._inside_repo():
            res = verify.check_base_binding({"base_sha": self.poison}, None, True)
            self.assertTrue(res and all(e.startswith("NOTE:") for e in res), res)
            self.assertEqual(verify.check_base_binding({"base_sha": self.poison}, None, False), [])
            verify._Authority.lane = "provenance=ci"
            res = verify.check_base_binding({"base_sha": self.poison}, None, True)
            self.assertTrue(res and not any(e.startswith("NOTE:") for e in res), res)
            self.assertIn("name --base", res[0])
            self.assertEqual(verify.check_base_binding({"base_sha": self.poison}, None, False), [])

    def test_a_missing_base_ref_is_left_to_the_ancestry_check(self):
        with self._inside_repo():
            self.assertEqual(verify.check_base_binding({"base_sha": self.poison}, "no-such", True), [])

    def test_an_unpinned_base_sha_is_left_to_the_sha_checks(self):
        with self._inside_repo():
            self.assertEqual(verify.check_base_binding({"base_sha": "HEAD"}, "main", True), [])

    def test_a_tag_named_like_the_remote_branch_cannot_stand_in_for_it(self):
        # The ancestry legs resolve the FULL ref name now: a pushable tag `origin/main` used to
        # shadow the remote-tracking branch under gitrevisions' lookup order.
        with self._inside_repo():
            subprocess.run(["git", "-c", "tag.gpgSign=false", "tag", "origin/main", self.poison],
                           cwd=self.repo, check=True)
            errs = verify.check_base_binding({"base_sha": self.poison}, "main", True)
            self.assertTrue(errs and "not an ancestor" in errs[0], errs)
            errs = verify.check_ancestry({"head_sha": self.poison}, "main")
            self.assertTrue(errs and "not an ancestor" in errs[0], errs)

    def test_a_signed_base_sha_the_manifest_moved_is_a_substitution(self):
        # check_dispatch_provenance: optional like the NC pins; signed, the manifest may not swap it.
        verify._Authority.reset()
        sign = verify._Transcript.signer()
        seed = bytes(range(32))
        record = {"manifest_id": "u1", "contract_digest": "sha256:" + "a" * 64,
                  "unit_class": "mutation", "base_sha": self.honest_base}
        envelope = sign.envelope(seed, record)
        (self.repo / "rec.json").write_text(json.dumps(envelope), encoding="utf-8")
        (self.repo / "pub").write_text(verify._load_ed25519().publickey(seed).hex() + "\n",
                                       encoding="utf-8")
        with self._inside_repo():  # evidence paths are repo-relative (#267)
            ok = verify.check_dispatch_provenance(
                {"unit": "u1", "base_sha": self.honest_base}, "sha256:" + "a" * 64, "mutation",
                None, "rec.json", "pub")
            self.assertTrue(ok and ok[0].startswith("NOTE:"), ok)
            bad = verify.check_dispatch_provenance(
                {"unit": "u1", "base_sha": self.poison}, "sha256:" + "a" * 64, "mutation",
                None, "rec.json", "pub")
            self.assertTrue(bad and "pre-fix content was swapped" in bad[0], bad)

    def _poison_spelled_as_the_absent_remote(self):
        """W3-07 class, Codex review: refs/remotes/origin/main ABSENT, and a LOCAL branch spelled
        refs/heads/refs/remotes/origin/main holding the poison — `rev-parse` and `merge-base`
        expand the remote name to it."""
        git = ["git", "-C", str(self.repo)]
        subprocess.run([*git, "update-ref", "-d", "refs/remotes/origin/main"], check=True)
        subprocess.run([*git, "update-ref", "refs/heads/refs/remotes/origin/main", self.poison],
                       check=True)

    def test_an_absent_remote_ref_is_not_answered_by_a_local_branch_of_its_spelling(self):
        # The base-binding and ancestry pair on a sound lane: before, both passed the poison
        # (it is an "ancestor" of the local branch); now the ref does not resolve, so the
        # ancestry proof the lane asked for is fatal and base binding is left to it.
        self._poison_spelled_as_the_absent_remote()
        verify._Authority.lane = "provenance=ci"
        with self._inside_repo():
            errs = verify.check_ancestry({"head_sha": self.poison}, "main")
            self.assertTrue(errs and not errs[0].startswith("NOTE:"), errs)
            self.assertIn("origin/main not found", errs[0])
            self.assertIn("exactly that name", errs[0])
            self.assertEqual(verify.check_base_binding({"base_sha": self.poison}, "main", True), [])

    def test_a_local_bridge_inside_the_base_chain_is_not_the_base(self):
        # Codex review round 2 (P1): refs/remotes/origin/main -> refs/heads/bridge ->
        # refs/remotes/origin/side (a fetched branch holding the poison) read as remote-tracking
        # all the way, so the poison was "on base" on a sound lane.
        git = ["git", "-C", str(self.repo)]
        subprocess.run([*git, "update-ref", "refs/remotes/origin/side", self.poison], check=True)
        subprocess.run([*git, "symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/side"],
                       check=True)
        subprocess.run([*git, "symbolic-ref", "refs/remotes/origin/main", "refs/heads/bridge"],
                       check=True)
        verify._Authority.lane = "provenance=ci"
        with self._inside_repo():
            errs = verify.check_ancestry({"head_sha": self.poison}, "main")
            self.assertTrue(errs and not errs[0].startswith("NOTE:"), errs)
            self.assertIn("refs/heads/bridge", errs[0])
            self.assertEqual(verify.check_base_binding({"base_sha": self.poison}, "main", True), [])
            self.assertTrue(any("not found on origin/main" in e
                                for e in verify.check_symbol_on_base("raise", "main")))

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_base(self):
        # Independent re-attack (A): str.splitlines() broke the listing at U+2028/U+2029/U+0085,
        # so a fetched `x<U+2028>refs/remotes/origin/main` at the poison replaced origin/main:
        # an unmerged head and a worker-chosen base_sha both passed on a sound lane.
        verify._Authority.lane = "provenance=ci"
        for ch in refname_breaks.LINE_BREAKS:
            with self.subTest(ch=ch):
                unplant = refname_breaks.plant(self.repo, ch, self.poison)
                try:
                    with self._inside_repo():
                        ancestry = verify.check_ancestry({"head_sha": self.poison}, "main")
                        binding = verify.check_base_binding({"base_sha": self.poison}, "main", True)
                finally:
                    unplant()
                self.assertTrue(ancestry and "not an ancestor" in ancestry[0], ancestry)
                self.assertTrue(binding and "not an ancestor" in binding[0], binding)

    def test_symbol_grep_names_the_resolved_commit_never_the_ref(self):
        # Re-attack C(2): a mutant grepping the NAME instead of the commit survived. The grep
        # must receive the commit the exact-name rule returned.
        seen = []
        real = verify._git

        def spy(args, *a, **k):
            seen.append(list(args))
            return real(args, *a, **k)

        with self._inside_repo(), mock.patch.object(verify, "_git", side_effect=spy):
            self.assertEqual(verify.check_symbol_on_base("def f", "main"), [])
        greps = [argv for argv in seen if argv[:1] == ["grep"]]
        self.assertEqual(len(greps), 1, seen)
        self.assertEqual(greps[0][-1], self.honest_base, greps)
        self.assertFalse(any("origin/main" in tok for tok in greps[0]), greps)

    def test_a_revision_suffix_on_the_base_is_not_a_base(self):
        verify._Authority.lane = "provenance=ci"
        with self._inside_repo():
            for base in ("main~0", "main^0", "main@{0}"):
                with self.subTest(base=base):
                    errs = verify.check_ancestry({"head_sha": self.honest_base}, base)
                    self.assertTrue(errs and not errs[0].startswith("NOTE:"), errs)
                    self.assertIn("not a valid ref name", errs[0])

    def test_the_base_is_resolved_once_and_every_later_read_names_the_commit(self):
        # merge-base used to re-resolve refs/remotes/origin/<base> (and expand it) after the
        # existence check; it now receives the commit id the exact-name rule returned.
        seen = []
        real = verify._git

        def spy(args, *a, **k):
            seen.append(list(args))
            return real(args, *a, **k)

        with self._inside_repo(), mock.patch.object(verify, "_git", side_effect=spy):
            self.assertEqual(verify.check_base_binding({"base_sha": self.honest_base}, "main",
                                                       True), [])
            self.assertEqual(verify.check_ancestry({"head_sha": self.honest_base}, "main"), [])
        reads = [argv for argv in seen if argv[:1] == ["merge-base"]]
        self.assertEqual(len(reads), 2, seen)
        for argv in reads:
            self.assertNotIn("refs/remotes/origin/main", argv)
            self.assertEqual(argv[-1], self.honest_base, argv)


class SiblingNamedLikeTheStdlibNeverLoads(unittest.TestCase):
    """W3-01 (2026-10-27 security audit, P0): `python3 runtime/scripts/verify.py` puts
    runtime/scripts at sys.path[0], AHEAD of the stdlib, so a committed sibling `json.py` was the
    `json` the verifier parsed the manifest with — and the toolchain hash binds first-party files
    only, so nothing recorded it. The audit's PoC: a stale review (RED, exit 2) turned GREEN (exit
    0) by a json.py that rewrote one field inside `loads`, with a transcript binding the untouched
    bytes. Run WITHOUT -I on purpose: the guard must hold when the caller forgets it.

    The seam: the verifier's own interpreter start-up, with the audit's two plants beside a copy
    of the toolchain. It catches a verdict reached through a substituted stdlib module; it does not
    cover a plant on a caller-chosen PYTHONPATH (the caller's own environment)."""

    # The plants proxy the REAL stdlib module (from the directory `os` came from — os is imported
    # at start-up, before sys.path[0] exists) and record that they ran.
    JSON_PLANT = (
        "import importlib.util as _u, os as _o, sys as _s\n"
        "_std = _o.path.dirname(_o.__file__)\n"
        "_spec = _u.spec_from_file_location('json', _o.path.join(_std, 'json', '__init__.py'),\n"
        "                                   submodule_search_locations=[_o.path.join(_std, 'json')])\n"
        "_m = _u.module_from_spec(_spec); _s.modules['json'] = _m; _spec.loader.exec_module(_m)\n"
        "open(_o.path.join(_o.path.dirname(__file__), 'PLANT-json'), 'w').close()\n"
        "_loads = _m.loads\n"
        "def _forged(s, *a, **k):\n"
        "    d = _loads(s, *a, **k)\n"
        "    if isinstance(d, dict) and isinstance(d.get('pr'), dict) and 'head_sha' in d:\n"
        "        d['pr']['reviewed_sha'] = d['head_sha']\n"
        "    return d\n"
        "_m.loads = _forged\n"
    )
    HASHLIB_PLANT = (
        "import importlib.util as _u, os as _o, sys as _s\n"
        "_spec = _u.spec_from_file_location('hashlib', _o.path.join(_o.path.dirname(_o.__file__),\n"
        "                                                           'hashlib.py'))\n"
        "_m = _u.module_from_spec(_spec); _s.modules['hashlib'] = _m; _spec.loader.exec_module(_m)\n"
        "open(_o.path.join(_o.path.dirname(__file__), 'PLANT-hashlib'), 'w').close()\n"
    )

    def setUp(self):
        td = _temp_repo()
        self.addCleanup(td.cleanup)
        tmp = Path(td.name).resolve()
        self.rs = tmp / "rs"
        self.rs.mkdir()
        for name in verify._Transcript.TOOLCHAIN:
            shutil.copy2(ROOT / "runtime" / "scripts" / name, self.rs / name)
        self.repo = tmp / "repo"
        self.repo.mkdir()

        def git(*args):
            return subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True,
                                  text=True).stdout.strip()

        git("init", "-q", "-b", "main")
        (self.repo / "contract.md").write_text("- AC-1: x\n", encoding="utf-8")
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")
        self.base = git("rev-parse", "HEAD")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "r.md").write_text("# report\n", encoding="utf-8")
        git("add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "head")
        head = git("rev-parse", "HEAD")
        self.digest = "sha256:" + hashlib.sha256(b"- AC-1: x\n").hexdigest()
        # The stale-review invariant: the review is pinned to base while head moved on.
        self.manifest_bytes = json.dumps({
            "unit": "u", "base_sha": self.base, "head_sha": head,
            "criteria": [{"id": "AC-1", "addressed": True}],
            "contract": {"digest": self.digest, "criterion_ids": ["AC-1"]},
            "pr": {"reviewed_sha": self.base}}).encode("utf-8")
        (self.repo / "manifest.json").write_bytes(self.manifest_bytes)

    def _run(self):
        argv = [sys.executable, str(self.rs / "verify.py"), "--manifest", "manifest.json",
                "--contract-source", f"contract.md@{self.base}", "--contract-digest", self.digest,
                "--unit-class", "report-only", "--transcript-out", "t.json"]
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("PYTHON", "ORCA_", "OPEN_FLEET_"))}
        return subprocess.run(argv, cwd=self.repo, capture_output=True, text=True, env=env,
                              timeout=120)

    def test_the_stale_review_stays_red_with_json_and_hashlib_planted_beside_the_verifier(self):
        control = self._run()
        self.assertEqual(control.returncode, 2, control.stdout + control.stderr)
        self.assertIn("stale review", control.stderr)
        (self.rs / "json.py").write_text(self.JSON_PLANT, encoding="utf-8")
        (self.rs / "hashlib.py").write_text(self.HASHLIB_PLANT, encoding="utf-8")
        planted = self._run()
        loaded = sorted(p.name for p in self.rs.glob("PLANT-*"))
        self.assertEqual(loaded, [], "a sibling named like a stdlib module loaded into the "
                                     f"verifier: {loaded}")
        self.assertEqual(planted.returncode, 2,
                         f"a planted sibling changed the verdict: {planted.stdout}{planted.stderr}")
        self.assertIn("stale review", planted.stderr)
        record = json.loads((self.repo / "t.json").read_text(encoding="utf-8"))
        self.assertEqual(record["exit"], 2)
        self.assertEqual(record["manifest_sha256"],
                         hashlib.sha256(self.manifest_bytes).hexdigest())


class SoundLaneTrustKeysAreRefPinned(RepoCase):
    """W3-03 (2026-10-27 security audit, P2): `--dispatch-pubkey .orca/dispatch-pubkey` (a bare
    path) reads the WORKING TREE — the graded worker's to write — and was accepted on a lane
    claiming soundness, with a NOTE indistinguishable from a ref-pinned key's. The rule ("pass
    path@<reviewed ref>") lived only in prose. On a provenance lane a trust key is now read only
    at a commit id or a ref whose final target is remote-tracking (resolved once) — and every NOTE names
    where the key came from. The advisory lane keeps its working-tree read, said in so many words."""

    SEED = bytes(range(1, 33))

    def setUp(self):
        super().setUp()
        record = {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"}
        self.write(".orca/dispatch-record.json",
                   json.dumps(verify._Transcript.signer().envelope(self.SEED, record)))
        self.write(".orca/dispatch-pubkey",
                   verify._load_ed25519().publickey(self.SEED).hex() + "\n")
        self.pinned = self.commit("pin the coordinator key")
        self.git("update-ref", "refs/remotes/origin/main", self.pinned)

    def _check(self, pubkey_ref, lane="provenance=ci"):
        verify._Authority.lane = lane
        return verify.check_dispatch_provenance({"unit": "u"}, "sha256:a", "mutation", None,
                                                ".orca/dispatch-record.json", pubkey_ref)

    def test_a_bare_path_key_is_refused_on_a_lane_claiming_soundness(self):
        out = self._check(".orca/dispatch-pubkey")
        self.assertEqual(len(out), 1, out)
        self.assertFalse(out[0].startswith("NOTE:"), out)
        self.assertIn("working-tree file", out[0])
        self.assertIn("W3-03", out[0])

    def test_a_key_at_a_local_name_is_refused_on_a_lane_claiming_soundness(self):
        for ref in ("main", "HEAD", "refs/heads/main"):
            with self.subTest(ref=ref):
                out = self._check(f".orca/dispatch-pubkey@{ref}")
                self.assertEqual(len(out), 1, out)
                self.assertFalse(out[0].startswith("NOTE:"), out)
                self.assertIn("local name the graded worker can move", out[0])

    def test_a_key_at_a_remote_tracking_ref_or_a_commit_id_verifies_and_says_where(self):
        for ref, where in (("refs/remotes/origin/main", "remote-tracking ref refs/remotes/origin/main"),
                           (self.pinned, f"commit {self.pinned[:12]}")):
            with self.subTest(ref=ref):
                out = self._check(f".orca/dispatch-pubkey@{ref}")
                self.assertTrue(out and all(line.startswith("NOTE:") for line in out), out)
                self.assertIn("signature verified", out[0])
                self.assertIn(where, out[0])

    def test_the_advisory_lane_still_reads_a_working_tree_key_and_says_so(self):
        out = self._check(".orca/dispatch-pubkey", lane=None)
        self.assertTrue(out and all(line.startswith("NOTE:") for line in out), out)
        self.assertIn("working-tree file .orca/dispatch-pubkey", out[0])
        self.assertIn("the graded worker can write it", out[0])

    ENFORCEMENT = "enforcement (signed dispatch record + pubkey)"

    def test_the_enforcement_lane_refuses_a_worker_writable_key_too(self):
        # PR #719 review round 2 (P1): the restriction keyed on `provenance=` only, while the
        # enforcement lane is sound for every other authority check. One rule: no lane claiming
        # soundness accepts a worker-writable key.
        for ref in (".orca/dispatch-pubkey", ".orca/dispatch-pubkey@main"):
            with self.subTest(ref=ref):
                out = self._check(ref, lane=self.ENFORCEMENT)
                self.assertEqual(len(out), 1, out)
                self.assertFalse(out[0].startswith("NOTE:"), out)
                self.assertIn("W3-03", out[0])
        out = self._check(f".orca/dispatch-pubkey@{self.pinned}", lane=self.ENFORCEMENT)
        self.assertTrue(out and out[0].startswith("NOTE:"), out)

    def _main_lane(self, pubkey):
        self.write("m.json", json.dumps({"unit": "u"}))
        buf, errbuf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            verify.main(["--manifest", "m.json", "--unit-class", "mutation",  # what the record signs
                         "--dispatch-record", ".orca/dispatch-record.json",
                         "--dispatch-pubkey", pubkey])
        return verify._Authority.lane, buf.getvalue() + errbuf.getvalue()

    def test_a_record_with_a_working_tree_key_opens_no_enforcement_lane(self):
        # The documented native flow (verify-gate's working-tree pin, an in-session env key)
        # keeps working — the signature is still checked — but a key the worker can swap no
        # longer makes the run claim soundness, and the verdict says so.
        lane, out = self._main_lane(".orca/dispatch-pubkey")
        self.assertIsNone(lane, out)
        self.assertIn("signature verified", out)
        self.assertIn("no soundness claim", out)

    def test_a_record_with_a_pinned_key_still_opens_the_enforcement_lane(self):
        lane, out = self._main_lane(f".orca/dispatch-pubkey@{self.pinned}")
        self.assertEqual(lane, self.ENFORCEMENT, out)
        self.assertIn("signature verified", out)

    def test_a_pinned_key_note_says_where_the_pin_is_trustworthy(self):
        # PR #719 re-attack: `git update-ref refs/remotes/origin/main <own commit>` succeeds in a
        # worker's own clone, and a commit id names whatever the caller chose — the verdict must
        # say the pin is trustworthy only where the worker cannot write refs.
        for ref in ("refs/remotes/origin/main", self.pinned):
            with self.subTest(ref=ref):
                out = self._check(f".orca/dispatch-pubkey@{ref}")
                self.assertTrue(out and out[0].startswith("NOTE:"), out)
                self.assertIn("trustworthy only where the worker cannot write refs", out[0])
                self.assertIn("in the worker's own clone this lane is advisory", out[0])

    def _worker_branch_key(self):
        """The worker's own key and a record it signed, committed on a LOCAL branch."""
        worker = bytes(range(50, 82))
        self.git("checkout", "-q", "-b", "workerbranch")
        record = {"manifest_id": "u", "contract_digest": "sha256:a", "unit_class": "mutation"}
        self.write(".orca/dispatch-record.json",
                   json.dumps(verify._Transcript.signer().envelope(worker, record)))
        self.write(".orca/dispatch-pubkey", verify._load_ed25519().publickey(worker).hex() + "\n")
        return self.commit("the worker's own key")

    def test_a_remote_tracking_name_that_is_a_symbolic_ref_to_a_local_branch_is_refused(self):
        # PR #719 review (P1): the check was SPELLING-only. refs/remotes/worker/key made a
        # symbolic ref to refs/heads/workerbranch passed as "remote-tracking", read_source followed
        # it, and the worker's self-signed record verified on a lane claiming soundness.
        self._worker_branch_key()
        self.git("symbolic-ref", "refs/remotes/worker/key", "refs/heads/workerbranch")
        out = self._check(".orca/dispatch-pubkey@refs/remotes/worker/key")
        self.assertEqual(len(out), 1, out)
        self.assertFalse(out[0].startswith("NOTE:"), out)
        self.assertIn("refs/heads/workerbranch", out[0])
        self.assertNotIn("signature verified", out[0])

    def test_a_symbolic_ref_whose_final_target_is_remote_tracking_is_read_at_one_commit(self):
        # refs/remotes/origin/HEAD -> refs/remotes/origin/main is the ordinary shape; it is
        # resolved ONCE and the key is read at that commit, never at the name a second time.
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        with mock.patch.object(verify, "read_source", wraps=verify.read_source) as spy:
            out = self._check(".orca/dispatch-pubkey@refs/remotes/origin/HEAD")
        self.assertTrue(out and all(line.startswith("NOTE:") for line in out), out)
        self.assertIn("refs/remotes/origin/main", out[0])
        self.assertIn(f"commit {self.pinned[:12]}", out[0])
        keys = [c.args[0] for c in spy.call_args_list if "dispatch-pubkey" in c.args[0]]
        self.assertEqual(keys, [f".orca/dispatch-pubkey@{self.pinned}"], spy.call_args_list)

    def assert_refused(self, ref, because):
        out = self._check(f".orca/dispatch-pubkey@{ref}")
        self.assertEqual(len(out), 1, out)
        self.assertFalse(out[0].startswith("NOTE:"), out)
        self.assertNotIn("signature verified", out[0])
        self.assertIn("W3-03", out[0])
        self.assertIn(because, out[0])

    def test_a_local_branch_spelled_as_an_absent_remote_tracking_ref_is_refused(self):
        # W3-07 class, Codex review (P1): with refs/remotes/worker/key ABSENT, symbolic-ref
        # failed, the target kept the supplied spelling, and rev-parse expanded it to the local
        # branch refs/heads/refs/remotes/worker/key — the worker's key — so its self-signed
        # record verified on a lane claiming soundness. Same through origin/HEAD pointing at
        # that absent spelling.
        worker = self._worker_branch_key()
        self.git("update-ref", "refs/heads/refs/remotes/worker/key", worker)
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/worker/key")
        for ref in ("refs/remotes/worker/key", "refs/remotes/origin/HEAD"):
            with self.subTest(ref=ref):
                self.assert_refused(ref, "exactly that name")

    def test_a_local_bridge_inside_a_remote_tracking_chain_is_refused(self):
        # Codex review round 2 (P1): for-each-ref's %(symref) is the chain's END, so
        # refs/remotes/worker/key -> refs/heads/bridge -> refs/remotes/origin/worker-pr (a fetched
        # branch holding the worker's key) read as remote-tracking all the way and verified.
        worker = self._worker_branch_key()
        self.git("update-ref", "refs/remotes/origin/worker-pr", worker)
        self.git("symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/worker-pr")
        self.git("symbolic-ref", "refs/remotes/worker/key", "refs/heads/bridge")
        self.git("symbolic-ref", "refs/remotes/worker/b", "refs/heads/bridge")
        self.git("symbolic-ref", "refs/remotes/worker/a", "refs/remotes/worker/b")
        for ref in ("refs/remotes/worker/key", "refs/remotes/worker/a"):
            with self.subTest(ref=ref):
                self.assert_refused(ref, "refs/heads/bridge")

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_key_ref(self):
        # Independent re-attack (A): str.splitlines() broke the listing at U+2028/U+2029/U+0085,
        # which git accepts in a refname, so a fetched `x<U+2028>refs/remotes/origin/main` at the
        # worker's key replaced origin/main and its self-signed record verified.
        worker = self._worker_branch_key()
        for ch in refname_breaks.LINE_BREAKS:
            with self.subTest(ch=ch):
                unplant = refname_breaks.plant(self.repo, ch, worker)
                try:
                    out = self._check(".orca/dispatch-pubkey@refs/remotes/origin/main")
                finally:
                    unplant()
                self.assertNotIn("signature verified", "\n".join(out))
                self.assertNotIn(worker[:12], "\n".join(out))

    def test_a_hex_named_branch_is_not_a_commit_id(self):
        # 64 hex digits are no object id in a SHA-1 repository: rev-parse expands them as a ref.
        worker = self._worker_branch_key()
        hexname = "0f" * 32
        self.git("update-ref", f"refs/heads/{hexname}", worker)
        self.assert_refused(hexname, "names no commit object")

    def test_a_revision_suffix_on_a_remote_tracking_ref_is_refused(self):
        # A key rotation retired the worker's key: origin/main's parent (and the reflog entry
        # before the rotation) still pins it, and every suffix passed the prefix check.
        self._worker_branch_key()
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.write(".orca/dispatch-pubkey", verify._load_ed25519().publickey(self.SEED).hex() + "\n")
        self.commit("rotate back to the coordinator key")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        for ref in ("refs/remotes/origin/main~1", "refs/remotes/origin/main^",
                    "refs/remotes/origin/main@{1}"):
            with self.subTest(ref=ref):
                self.assert_refused(ref, "not a valid ref name")
        # The exact name reads the current key, which did not sign the worker's record.
        out = self._check(".orca/dispatch-pubkey@refs/remotes/origin/main")
        self.assertNotIn("signature verified", "\n".join(out))


class SoundLaneNeverRunsAWorkerWritableGitleaks(RepoCase):
    """W3-10 (2026-10-27 security audit, P3): a worker-writable gitleaks was consulted on every
    lane — on a sound one too, where it is a binary the graded worker could have replaced, run by
    the coordinator's verifier, and its "clean" was framed as additive. On a lane claiming
    soundness it is now not run at all, and the NOTE says only the built-in floor scanned."""

    def _pinned(self, custody, lane):
        verify._Authority.git_bin()
        verify._Authority.gitleaks, verify._Authority.gitleaks_custody = "/x/gitleaks", custody
        verify._Authority.lane = lane

    def test_a_worker_writable_gitleaks_is_never_run_on_a_lane_claiming_soundness(self):
        self._pinned("worker-writable", "provenance=ci")
        with mock.patch.object(verify, "_run", return_value=(0, "", "")) as run:
            self.assertIsNone(verify._gitleaks_scan(self.repo / "f.txt"))
        self.assertEqual([c for c in run.call_args_list if c.args[0][0] == "/x/gitleaks"], [])
        notes = verify._Authority.authority_leg()
        self.assertTrue(any(n.startswith("NOTE: redaction:") and "NOT run" in n
                            and "only the built-in floor" in n for n in notes), notes)

    def test_the_enforcement_lane_is_sound_for_gitleaks_too(self):
        # PR #719 review (P2): a signed dispatch record + pubkey (no --provenance) is a lane the
        # other authority checks already treat as claiming soundness (a worker-writable git fails
        # it closed); the gitleaks rule must use the same predicate.
        self._pinned("worker-writable", "enforcement (signed dispatch record + pubkey)")
        with mock.patch.object(verify, "_run", return_value=(0, "", "")) as run:
            self.assertIsNone(verify._gitleaks_scan(self.repo / "f.txt"))
        self.assertEqual([c for c in run.call_args_list if c.args[0][0] == "/x/gitleaks"], [])
        notes = verify._Authority.authority_leg()
        self.assertTrue(any("NOT run" in n and "only the built-in floor" in n for n in notes), notes)

    def test_the_built_in_floor_still_refuses_on_that_lane(self):
        self._pinned("worker-writable", "provenance=ci")
        art = self.artifact("token ghp_" + "Z" * 30 + "\n")
        with mock.patch.object(verify, "_run", return_value=(0, "", "")):
            errs = verify.check_redaction({"artifacts": [self.pin(art)]}, None)
        self.assertTrue(errs and "github-token" in errs[0], errs)

    def test_built_in_floor_refuses_slack_tokens_when_gitleaks_absent_c7(self):
        # #750 C7: exercise the built-in-floor Slack token pattern (xox[baprs]-[A-Za-z0-9-]{10,128})
        # directly with gitleaks absent.
        verify._Authority.gitleaks = None
        verify._Authority.gitleaks_custody = "absent"
        for prefix in ("xoxb", "xoxp", "xoxa", "xoxr", "xoxs"):
            with self.subTest(prefix=prefix):
                art = self.artifact(f"SLACK_TOKEN={prefix}-1234567890-abcdefGHIJ\n",
                                    rel=f"docs/reports/u/slack-{prefix}.txt")
                errs = verify.check_redaction({"artifacts": [self.pin(art)]}, None)
                self.assertTrue(errs and "slack-token" in errs[0], errs)
        # Below the 10-char suffix bound does not false-positive:
        short_art = self.artifact("xoxb-12345\n", rel="docs/reports/u/slack-short.txt")
        self.assertEqual(verify.check_redaction({"artifacts": [self.pin(short_art)]}, None), [])

    def test_a_system_gitleaks_and_the_advisory_lane_still_consult_it(self):
        for custody, lane in (("system", "provenance=ci"), ("worker-writable", None)):
            with self.subTest(custody=custody, lane=lane):
                self._pinned(custody, lane)
                with mock.patch.object(verify, "_run", return_value=(0, "", "")) as run:
                    self.assertIs(verify._gitleaks_scan(self.repo / "f.txt"), False)
                self.assertEqual(run.call_args[0][0][0], "/x/gitleaks")


class TheToolchainIsHashedBeforeTheControlRuns(unittest.TestCase):
    """W3-11 (2026-10-27 security audit, P3): the transcript's toolchain hashes were taken AFTER
    verify() returned — after the executed control ran worker code — while every check had run
    with the modules loaded BEFORE it. A mid-run rewrite of a sibling was recorded as if it were
    the verifier, and never detected. The toolchain is now hashed before verify() and again
    after; any difference is a FAIL, and the transcript records the bytes that actually ran.

    The seam: verify() itself is stubbed to do what an executed control can — write a sibling of
    the verifier — so the test needs no control fixture; the toolchain is a temp copy."""

    def setUp(self):
        td = _temp_repo()
        self.addCleanup(td.cleanup)
        self.tmp = Path(td.name).resolve()
        self.rs = self.tmp / "rs"
        self.rs.mkdir()
        for name in verify._Transcript.TOOLCHAIN:
            shutil.copy2(ROOT / "runtime" / "scripts" / name, self.rs / name)
        spec = importlib.util.spec_from_file_location("verify_w311", self.rs / "verify.py")
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.mod._Authority.reset()
        self.manifest = self.tmp / "m.json"
        self.manifest.write_text('{"unit": "u"}', encoding="utf-8")
        self.original = hashlib.sha256((self.rs / "diff_scope.py").read_bytes()).hexdigest()

    def _main(self, rewrite):
        def fake_verify(*_a, judged=None, **_k):
            if rewrite:
                with open(self.rs / "diff_scope.py", "a", encoding="utf-8") as fh:
                    fh.write("\n# rewritten by the executed control\n")
            if judged is not None:
                judged["raw"] = self.manifest.read_bytes()
            return ([], ["NOTE: stubbed"]), None
        out = self.tmp / "t.json"
        buf, errbuf = io.StringIO(), io.StringIO()
        with mock.patch.object(self.mod, "verify", side_effect=fake_verify), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            rc = self.mod.main(["--manifest", str(self.manifest), "--unit-class", "report-only",
                                "--transcript-out", str(out)])
        return rc, errbuf.getvalue(), json.loads(out.read_text(encoding="utf-8"))

    def test_a_sibling_rewritten_during_the_run_is_a_fail(self):
        rc, err, record = self._main(rewrite=True)
        self.assertEqual(rc, 2, err)
        self.assertIn("diff_scope.py", err)
        self.assertIn("W3-11", err)
        self.assertEqual(record["exit"], 2)
        self.assertEqual(record["toolchain"]["files"]["diff_scope.py"], self.original,
                         "the transcript must record the bytes that RAN, not the rewrite")

    def test_an_untouched_toolchain_is_unchanged_behaviour(self):
        rc, err, record = self._main(rewrite=False)
        self.assertEqual(rc, 0, err)
        self.assertEqual(record["toolchain"]["files"]["diff_scope.py"], self.original)
