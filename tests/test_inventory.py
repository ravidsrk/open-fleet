#!/usr/bin/env python3
"""Contract tests for runtime/scripts/inventory.py.

Both real inventory shapes in this repo are exercised directly, because a parser
that only handles the fixtures it was written against is a parser that will
silently skip the next report. The exit-2 case matters most: an inventory whose
paths have all moved verified nothing, and "nothing verified" must not read as
"all verified".
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
INVENTORY = ROOT / "runtime" / "scripts" / "inventory.py"
SHIP_RUN = ROOT / "docs" / "runs" / "2026-08-28-ship-it-self-run.md"
NEGCTRL = ROOT / "evals" / "demo" / "negative-control" / "README.md"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


EXIT_MISMATCH = 1   # inventory.py's own mismatch code; asserted against the script in test_script_shape


def run_inv(*args):
    return subprocess.run([sys.executable, str(INVENTORY), *args], capture_output=True, text=True)


class InventoryBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="inventory-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def artifact(self, rel, text):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def fenced_report(self, entries, heading="## Run-close integrity inventory (sha256)"):
        body = "\n".join(f"{h}  {p}" for p, h in entries)
        report = self.tmp / "report.md"
        report.write_text(
            f"# Run\n\nsome prose\n\n{heading}\n\n```\n{body}\n```\n\n## Gates\n\n- none\n",
            encoding="utf-8")
        return report

    def table_report(self, entries):
        rows = "\n".join(f"| `{p}` | `{h}` |" for p, h in entries)
        report = self.tmp / "README.md"
        report.write_text(
            "# demo\n\n## Integrity inventory (sha256)\n\n"
            "| Artifact | sha256 |\n|----------|--------|\n" + rows + "\n\n(note)\n",
            encoding="utf-8")
        return report


class TestFencedBlock(InventoryBase):
    def test_matching_hashes_verify(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 verified", r.stdout)

    def test_a_changed_artifact_is_a_mismatch(self):
        self.artifact("a.txt", "beta\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISMATCH", r.stderr)
        self.assertIn("a.txt", r.stderr)

    def test_several_entries_are_all_read(self):
        self.artifact("a.txt", "alpha\n")
        self.artifact("sub/b.txt", "beta\n")
        report = self.fenced_report([("a.txt", sha("alpha\n")), ("sub/b.txt", sha("beta\n"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 verified", r.stdout)

    def test_a_retired_path_is_missing_not_mismatched(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n")), ("gone.txt", sha("x"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("MISSING", r.stdout)
        self.assertIn("1 verified", r.stdout)

    def test_no_listed_path_exists_is_exit_2(self):
        report = self.fenced_report([("gone.txt", sha("x")), ("also-gone.txt", sha("y"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 2, "a verification that examined nothing is not a pass")
        self.assertIn("nothing was verified", r.stderr)

    def test_heading_with_extra_words_is_found(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))],
                                    heading="### Wave two integrity inventory (sha256)")
        self.assertEqual(run_inv("check", str(report)).returncode, 0)

    def test_no_inventory_heading_is_exit_2(self):
        report = self.tmp / "plain.md"
        report.write_text("# Run\n\nno inventory here\n", encoding="utf-8")
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 2)
        self.assertIn("no '## … integrity inventory", r.stderr)

    def test_an_empty_block_is_exit_2(self):
        report = self.tmp / "empty.md"
        report.write_text("# Run\n\n## Integrity inventory (sha256)\n\n```\n```\n", encoding="utf-8")
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 2)
        self.assertIn("lists no", r.stderr)

    def test_an_unreadable_report_is_exit_2(self):
        r = run_inv("check", str(self.tmp / "does-not-exist.md"))
        self.assertEqual(r.returncode, 2)

    def test_the_block_stops_at_the_next_heading(self):
        self.artifact("a.txt", "alpha\n")
        first, other = sha("alpha\n"), sha("zzz")
        report = self.tmp / "report.md"
        report.write_text(
            "## Integrity inventory (sha256)\n\n```\n"
            + f"{first}  a.txt\n```\n\n"
            + "## Other\n\n```\n"
            + f"{other}  never-read.txt\n```\n", encoding="utf-8")
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 verified", r.stdout)
        self.assertNotIn("never-read.txt", r.stdout + r.stderr)


class TestSecondInventoryBlock(InventoryBase):
    """#315: only the FIRST `## … integrity inventory (sha256)` heading was ever read. A second
    block later in the same document was neither hashed nor compared, so a report could carry an
    honest inventory a tool checks and a fabricated one a human reads."""

    def two_block_report(self, first, second):
        def fence(entries):
            return "```\n" + "\n".join(f"{h}  {p}" for p, h in entries) + "\n```"
        report = self.tmp / "report.md"
        report.write_text(
            "# Run\n\nprose\n\n"
            "## Run-close integrity inventory (sha256)\n\n" + fence(first) + "\n\n"
            "## Appendix\n\nmore prose\n\n"
            "## Second integrity inventory (sha256)\n\n" + fence(second) + "\n\n"
            "## Gates\n\n- none\n",
            encoding="utf-8")
        return report

    def test_a_fabricated_second_block_is_a_mismatch(self):
        self.artifact("a.txt", "alpha\n")
        report = self.two_block_report([("a.txt", sha("alpha\n"))],
                                       [("a.txt", sha("something else entirely\n"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, EXIT_MISMATCH,
                         f"the second block was never checked: {r.stdout}")
        self.assertIn("MISMATCH", r.stderr)

    def test_both_honest_blocks_verify(self):
        self.artifact("a.txt", "alpha\n")
        self.artifact("b.txt", "beta\n")
        report = self.two_block_report([("a.txt", sha("alpha\n"))], [("b.txt", sha("beta\n"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 verified", r.stdout)

    def test_write_refreshes_every_block(self):
        self.artifact("a.txt", "alpha\n")
        self.artifact("b.txt", "beta\n")
        report = self.two_block_report([("a.txt", sha("stale\n"))], [("b.txt", sha("stale\n"))])
        r = run_inv("write", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("updated 2 hash(es)", r.stdout)
        self.assertEqual(run_inv("check", str(report)).returncode, 0)


class TestTableBlock(InventoryBase):
    def test_table_rows_are_parsed(self):
        self.artifact("head-to-head.txt", "transcript\n")
        report = self.table_report([("head-to-head.txt", sha("transcript\n"))])
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 verified", r.stdout)

    def test_table_separator_row_is_skipped(self):
        self.artifact("head-to-head.txt", "transcript\n")
        report = self.table_report([("head-to-head.txt", sha("transcript\n"))])
        r = run_inv("check", str(report))
        self.assertNotIn("MISSING  ---", r.stdout)

    def test_table_mismatch_is_exit_1(self):
        self.artifact("head-to-head.txt", "changed\n")
        report = self.table_report([("head-to-head.txt", sha("transcript\n"))])
        self.assertEqual(run_inv("check", str(report)).returncode, 1)

    def test_paths_resolve_relative_to_the_report_directory(self):
        self.artifact("nested/README.md", "x")
        (self.tmp / "nested" / "sibling.txt").write_text("sibling\n", encoding="utf-8")
        digest = sha("sibling\n")
        report = self.tmp / "nested" / "README.md"
        report.write_text(
            "## Integrity inventory (sha256)\n\n| Artifact | sha256 |\n|---|---|\n"
            + f"| `sibling.txt` | `{digest}` |\n", encoding="utf-8")
        r = run_inv("check", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)


class TestWrite(InventoryBase):
    def test_write_refreshes_a_stale_hash(self):
        self.artifact("a.txt", "beta\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        r = run_inv("write", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(sha("beta\n"), report.read_text(encoding="utf-8"))
        self.assertEqual(run_inv("check", str(report)).returncode, 0)

    def test_write_preserves_the_table_shape(self):
        self.artifact("head-to-head.txt", "changed\n")
        report = self.table_report([("head-to-head.txt", sha("transcript\n"))])
        run_inv("write", str(report))
        text = report.read_text(encoding="utf-8")
        self.assertIn("| `head-to-head.txt` |", text)
        self.assertIn(sha("changed\n"), text)

    def test_dry_run_changes_nothing(self):
        self.artifact("a.txt", "beta\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        before = report.read_text(encoding="utf-8")
        r = run_inv("write", str(report), "--dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertIn("would update 1", r.stdout)
        self.assertEqual(report.read_text(encoding="utf-8"), before)

    def test_write_refuses_when_a_listed_path_is_gone(self):
        report = self.fenced_report([("gone.txt", sha("x"))])
        r = run_inv("write", str(report))
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not exist", r.stderr)

    def test_write_is_idempotent(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        run_inv("write", str(report))
        first = report.read_text(encoding="utf-8")
        run_inv("write", str(report))
        self.assertEqual(report.read_text(encoding="utf-8"), first)


class TestRealReports(unittest.TestCase):
    """The two shapes that already exist in this repo must both parse."""

    def test_ship_it_run_report_parses_every_entry(self):
        r = run_inv("check", str(SHIP_RUN))
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertNotEqual(r.returncode, 2, "the fenced run-close inventory must parse")
        counts = r.stdout.strip().splitlines()[-1]
        self.assertRegex(counts, r"(\d+) verified, (\d+) mismatched, (\d+) missing")
        total = sum(int(n) for n in counts.replace(",", " ").split()
                    if n.isdigit())
        self.assertEqual(total, 5, f"expected 5 inventory entries, got: {counts}")

    def test_ship_it_immutable_run_artifacts_still_verify(self):
        r = run_inv("check", str(SHIP_RUN))
        for immutable in ("frozen-spec.md", "build-manifest.json", "negctrl.txt"):
            self.assertNotIn(immutable, r.stderr,
                             f"{immutable} is declared immutable and must still hash true")

    def test_negative_control_readme_table_parses_and_verifies(self):
        # The table form (| `file` | `hash` |) must parse, and the demo's own
        # transcript must hash true: its recorded hash drifted from the
        # committed file once (docs/reviews/2026-09-10-review.md 7.4) and the inventory check is what
        # keeps that from recurring silently.
        r = run_inv("check", str(NEGCTRL))
        self.assertEqual(r.returncode, 0,
                         f"the demo inventory must verify:\n{r.stdout}\n{r.stderr}")
        self.assertIn("1 verified", r.stdout + r.stderr)
        self.assertIn("0 mismatched", r.stdout + r.stderr)


class TestScriptShape(unittest.TestCase):
    def test_executable_and_shebanged(self):
        self.assertTrue(os.access(INVENTORY, os.X_OK))
        self.assertTrue(INVENTORY.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3"))

    def test_the_mismatch_exit_code_this_module_asserts_is_the_script_s(self):
        # A constant restated in a test is a second source of truth: if inventory.py renumbered
        # its exit codes, every mismatch assertion here would keep passing against the old number.
        src = INVENTORY.read_text(encoding="utf-8")
        self.assertIn(f"EXIT_MISMATCH = {EXIT_MISMATCH}\n", src,
                      "tests assert a mismatch code the script no longer uses")

    def test_help_names_both_subcommands(self):
        r = run_inv("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("write", r.stdout)
        self.assertIn("check", r.stdout)


class TestCheckAtRevision(unittest.TestCase):
    """`--at <rev>` hashes the git blob, not the working tree (issue #259).

    A dated report pins artifacts at the tip it closed on; the tree always moves
    afterwards. Re-hashing at the recorded commit is what keeps the pin meaningful
    — and it is the half a fabricated report cannot produce.
    """

    REPORT = "docs/runs/2026-08-28-ship-it-self-run.md"

    def test_re_derives_at_the_commit_the_report_names(self):
        r = run_inv("check", self.REPORT, "--at", "748b328")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("5 verified, 0 mismatched", r.stdout)

    def test_the_same_inventory_does_not_match_the_moved_tree(self):
        # Not a defect in the report: two of its paths are repo files that changed
        # after the run. Without --at, that is a mismatch; with it, it is not.
        r = run_inv("check", self.REPORT)
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_an_unresolvable_revision_cannot_run(self):
        r = run_inv("check", self.REPORT, "--at", "deadbeef")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("is not a commit", r.stdout + r.stderr)


class TestHardenedGit(InventoryBase):
    """gitexec.py: one absolute git, run under a hardened env, for every read-side tool."""

    def _inventory(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inventory_hardened", INVENTORY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _git(self, repo, *args):
        return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c",
                               "user.email=t@example.invalid", *args],
                              capture_output=True, text=True, check=True).stdout.strip()

    def test_a_replace_ref_cannot_swap_the_blob_a_pin_is_hashed_from(self):
        # refs/replace/ swaps any object for another; the bytes at the revision
        # are what a pin binds, so replacement objects are off for these reads.
        repo = self.tmp / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q", "-b", "main")
        (repo / "a.txt").write_text("real\n", encoding="utf-8")
        self._git(repo, "add", "a.txt")
        self._git(repo, "commit", "-qm", "base")
        real = self._git(repo, "rev-parse", "HEAD:a.txt")
        (repo / "fake.txt").write_text("forged\n", encoding="utf-8")
        fake = self._git(repo, "hash-object", "-w", "fake.txt")
        self._git(repo, "replace", real, fake)
        self.assertEqual(self._git(repo, "cat-file", "blob", "HEAD:a.txt"), "forged",
                         "fixture: plain git must see the replacement")
        inv = self._inventory()
        self.assertEqual(inv.sha256_at("HEAD", "a.txt", repo), sha("real\n"))

    def test_an_option_shaped_revision_never_reaches_git(self):
        # W2-04: `--at` sat in option position (`cat-file blob <rev>:<path>`, `rev-parse --verify
        # <rev>^{commit}`). An option is not a revision: refused before any git process starts.
        inv = self._inventory()
        with mock.patch.object(inv.subprocess, "run", side_effect=AssertionError("git was run")):
            for rev in ("--batch", "-p", "--all"):
                with self.subTest(rev=rev):
                    self.assertIsNone(inv.sha256_at(rev, "a.txt", self.tmp))
                    self.assertFalse(inv.rev_exists(rev, self.tmp))

    def test_git_is_absolute_and_the_env_closes_config_exec_channels(self):
        gitexec = self._inventory().gitexec
        self.assertTrue(os.path.isabs(gitexec.argv("status")[0]))
        env = gitexec.env({"GIT_EXTERNAL_DIFF": "x", "GIT_CONFIG_KEY_7": "core.pager",
                           "GIT_CONFIG_VALUE_7": "x", "LANG": "C"})
        self.assertNotIn("GIT_EXTERNAL_DIFF", env)
        self.assertNotIn("GIT_CONFIG_KEY_7", env)
        self.assertEqual(env["LANG"], "C")
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
                 for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pairs["core.fsmonitor"], "false")

    def test_no_git_at_startup_is_a_named_file_not_found(self):
        gitexec = self._inventory().gitexec
        with mock.patch.object(gitexec, "GIT", None):
            with self.assertRaises(FileNotFoundError) as caught:
                gitexec.argv("status")
        self.assertIn("git is not on PATH", str(caught.exception))


class InventorySigningFixture(InventoryBase):
    """#386 / U-SIG-2: the run-close inventory's ENTRY SET is signed with the coordinator's
    Ed25519 key (the dispatch-sign.py scheme, the same seed/pubkey files). The envelope is a
    detached HTML-comment line inside the inventory block — every existing block shape still
    parses with or without it — and `check --pubkey` verifies it: a tampered entry fails, an
    unsigned inventory is refused when a pubkey is configured and accepted as today when none is.
    """

    SEED = bytes(range(1, 33))
    OTHER_SEED = bytes(range(100, 132))

    def setUp(self):
        super().setUp()
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dispatch_sign", ROOT / "runtime" / "scripts" / "dispatch-sign.py")
        self.ds = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ds)
        self.ed = self.ds._load_ed25519()
        self.key = self._keypair("key", self.SEED)
        self.other_key = self._keypair("other", self.OTHER_SEED)

    def _keypair(self, name, seed):
        seed_path = self.tmp / name
        seed_path.write_text(seed.hex() + "\n", encoding="utf-8")
        seed_path.chmod(0o600)  # F-4: a signer refuses a seed any other reader can see
        (self.tmp / f"{name}.pub").write_text(self.ed.publickey(seed).hex() + "\n", encoding="utf-8")
        return seed_path

    def _pub(self, key=None):
        return str((key or self.key).with_name((key or self.key).name + ".pub"))

    def _signed_fenced(self):
        self.artifact("a.txt", "alpha\n")
        self.artifact("b.txt", "beta\n")
        report = self.fenced_report([("a.txt", sha("alpha\n")), ("b.txt", sha("beta\n"))])
        r = run_inv("sign", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, 0, r.stderr)
        return report

    def _envelopes(self, report):
        return [l for l in report.read_text(encoding="utf-8").splitlines()
                if l.startswith("<!-- inventory-signature")]

    # --- the shape that must pass ------------------------------------------------------------


class SignedInventory(InventorySigningFixture):
    """#386: signed inventory entry sets (fixture above; tests here)."""

    def test_sign_writes_one_envelope_that_check_verifies_with_the_pubkey(self):
        report = self._signed_fenced()
        self.assertEqual(len(self._envelopes(report)), 1, report.read_text())
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("2 verified", r.stdout)
        self.assertIn("signature", r.stdout.lower())

    def test_every_existing_shape_still_parses_with_the_envelope_present(self):
        # The envelope must be TOLERATED: no entry gained, none lost, in every block shape.
        self.artifact("a.txt", "alpha\n")
        self.artifact("b.txt", "beta\n")
        table = self.table_report([("a.txt", sha("alpha\n")), ("b.txt", sha("beta\n"))])
        fenced = self.fenced_report([("a.txt", sha("alpha\n")), ("b.txt", sha("beta\n"))])
        for report in (table, fenced):
            before = run_inv("check", str(report))
            self.assertEqual(run_inv("sign", str(report), "--key", str(self.key)).returncode, 0)
            after = run_inv("check", str(report))  # no pubkey: today's path, envelope ignored
            self.assertEqual(after.returncode, 0, after.stderr)
            self.assertIn("2 verified", after.stdout)
            self.assertEqual(before.stdout.split("\n")[0], after.stdout.split("\n")[0])

    def test_sign_covers_every_block_and_is_order_free(self):
        # #315: a document's claim is ALL its blocks; and a coordinator signs a SET of entries.
        self.artifact("a.txt", "alpha\n")
        self.artifact("b.txt", "beta\n")
        first = self.fenced_report([("b.txt", sha("beta\n")), ("a.txt", sha("alpha\n"))])
        second = self.tmp / "second.md"
        a, b = sha("alpha\n"), sha("beta\n")
        second.write_text(
            "## Run-close integrity inventory (sha256)\n\n```\n" + f"{a}  a.txt\n```\n\n"
            "## Appendix\n\n## Second integrity inventory (sha256)\n\n```\n"
            + f"{b}  b.txt\n```\n", encoding="utf-8")
        import importlib.util
        spec = importlib.util.spec_from_file_location("inventory", INVENTORY)
        inv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inv)
        d1 = inv.inventory_digest(inv.load(first)[2])
        d2 = inv.inventory_digest(inv.load(second)[2])
        self.assertEqual(d1, d2, "same entry set, different order/blocks -> same digest")
        self.assertEqual(run_inv("sign", str(second), "--key", str(self.key)).returncode, 0)
        self.assertEqual(len(self._envelopes(second)), 1)
        r = run_inv("check", str(second), "--pubkey", self._pub())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_signing_twice_replaces_the_envelope(self):
        report = self._signed_fenced()
        first = self._envelopes(report)
        self.assertEqual(run_inv("sign", str(report), "--key", str(self.key)).returncode, 0)
        self.assertEqual(self._envelopes(report), first)
        self.assertEqual(run_inv("check", str(report), "--pubkey", self._pub()).returncode, 0)

    # --- what must be refused ------------------------------------------------------------------
    def test_a_tampered_entry_fails_verification(self):
        report = self._signed_fenced()
        # The artifact AND its recorded hash are changed together, so the hashes still re-derive:
        # only the signature can tell that the SET the coordinator attested is not this one.
        self.artifact("a.txt", "alpha, revised\n")
        text = report.read_text(encoding="utf-8").replace(sha("alpha\n"), sha("alpha, revised\n"))
        report.write_text(text, encoding="utf-8")
        self.assertEqual(run_inv("check", str(report)).returncode, 0, "hashes alone still verify")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)
        self.assertIn("signature", r.stderr.lower())

    def test_a_dropped_entry_fails_verification(self):
        report = self._signed_fenced()
        lines = [l for l in report.read_text(encoding="utf-8").splitlines() if "b.txt" not in l]
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)

    def test_a_tampered_signature_fails_verification(self):
        report = self._signed_fenced()
        text = report.read_text(encoding="utf-8")
        line = self._envelopes(report)[0]
        import json
        env = json.loads(line[len("<!-- inventory-signature "):-len(" -->")])
        env["sig_b64"] = "A" * 86 + "=="
        report.write_text(text.replace(line, f"<!-- inventory-signature {json.dumps(env)} -->"),
                          encoding="utf-8")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)

    def test_a_signature_by_another_key_is_refused(self):
        report = self._signed_fenced()
        r = run_inv("check", str(report), "--pubkey", self._pub(self.other_key))
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)
        self.assertIn("signature", r.stderr.lower())

    def test_an_unsigned_inventory_is_refused_with_a_pubkey_and_accepted_without(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        self.assertEqual(run_inv("check", str(report)).returncode, 0)
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)
        self.assertIn("unsigned", r.stderr.lower())

    def test_a_malformed_pubkey_cannot_run(self):
        report = self._signed_fenced()
        bad = self.tmp / "bad.pub"
        bad.write_text("not-hex\n", encoding="utf-8")
        r = run_inv("check", str(report), "--pubkey", str(bad))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_sign_refuses_a_report_with_no_inventory(self):
        report = self.tmp / "none.md"
        report.write_text("# Run\n\nno inventory here\n", encoding="utf-8")
        r = run_inv("sign", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("integrity inventory", r.stderr)  # the parser's could-not-run, not argparse's

    def test_sign_refuses_when_a_listed_path_hashes_differently(self):
        # Signing attests the SET as re-derived from disk; a stale hash is not something to sign.
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("stale\n"))])
        r = run_inv("sign", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)
        self.assertEqual(self._envelopes(report), [])

    # --- write and the envelope ----------------------------------------------------------------
    def test_write_with_a_key_re_signs_the_refreshed_block(self):
        report = self._signed_fenced()
        self.artifact("a.txt", "alpha, revised\n")
        r = run_inv("write", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(run_inv("check", str(report), "--pubkey", self._pub()).returncode, 0)

    def test_write_without_a_key_leaves_a_now_stale_envelope_and_says_so(self):
        report = self._signed_fenced()
        self.artifact("a.txt", "alpha, revised\n")
        r = run_inv("write", str(report))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("stale", (r.stdout + r.stderr).lower())
        self.assertEqual(len(self._envelopes(report)), 1)  # evidence is never dropped silently
        self.assertEqual(run_inv("check", str(report), "--pubkey", self._pub()).returncode,
                         EXIT_MISMATCH)

    def test_help_names_sign(self):
        r = run_inv("--help")
        self.assertIn("sign", r.stdout)
        self.assertIn("--pubkey", run_inv("check", "--help").stdout)

    # --- round-1 G-1..G-4: the envelope is read fail-closed, inside the block only -------------
    def _inv(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inventory", INVENTORY)
        inv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inv)
        return inv

    def _envelope_line(self, record, sig_b64):
        import json
        return f"<!-- inventory-signature {json.dumps({'record': record, 'sig_b64': sig_b64})} -->"

    def _forge(self, sig_b64):
        """A KEYLESS forgery: the record is derived from the document (anyone can), only sig_b64
        is invented. Placed inside the block, exactly where a real envelope would sit."""
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        inv = self._inv()
        record = inv.signature_record(inv.load(report)[2])
        text = report.read_text(encoding="utf-8")
        report.write_text(text.replace("```\n\n## Gates", "```\n" + self._envelope_line(record, sig_b64)
                                       + "\n\n## Gates"), encoding="utf-8")
        return report, inv

    def test_a_keyless_forgery_with_a_malformed_sig_b64_is_refused(self):
        # M14: the decode branch is the ONLY thing between "digest matches" and checkvalid. A
        # forger holds no seed; a malformed sig_b64 must be a refusal in its own right — never a
        # value a caller could read as "verified".
        report, inv = self._forge("not*base64!")
        self.assertEqual(run_inv("check", str(report)).returncode, 0, "hashes alone still verify")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)
        self.assertIn("malformed", r.stderr)
        self.assertNotIn("signature verified", r.stdout + r.stderr)
        # At the function level the refusal is an exception, and validity is the digest itself.
        _report, lines, entries = inv.load(report)
        _idx, envelope = inv.find_signature(lines)
        pub = inv.read_pubkey(self._pub())
        with self.assertRaises(inv.SignatureRefused):
            inv.verify_signature(envelope, entries, pub)
        signed = self._signed_fenced()
        _r, lines, entries = inv.load(signed)
        self.assertEqual(inv.verify_signature(inv.find_signature(lines)[1], entries, pub),
                         inv.inventory_digest(entries))

    def test_a_well_formed_base64_that_is_not_a_signature_is_refused_as_malformed(self):
        import base64
        report, _inv = self._forge(base64.b64encode(b"short").decode("ascii"))
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, EXIT_MISMATCH, r.stdout + r.stderr)
        self.assertIn("malformed", r.stderr)

    def test_a_signature_line_in_prose_is_never_an_envelope(self):
        # BOT-1 / M13: the parser reads only find_blocks ranges, so only those can carry the
        # claim. A documented example pasted above the heading is not signed, not honoured, and
        # never rewritten — `sign` refuses rather than touching prose.
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        example = self._envelope_line({"entries": 1, "inventory_sha256": "0" * 64}, "A" * 86 + "==")
        text = report.read_text(encoding="utf-8").replace("some prose\n", f"some prose\n{example}\n")
        report.write_text(text, encoding="utf-8")
        self.assertEqual(run_inv("check", str(report)).returncode, 0, "no pubkey: today's path")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("outside", r.stderr)
        self.assertNotIn("unsigned", r.stderr.lower())
        r = run_inv("sign", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(report.read_text(encoding="utf-8"), text, "sign touched the document")

    def test_unsigned_write_ignores_the_envelope_and_writes_as_before(self):
        # STD-R1's second half: `write` with no --key is the pre-#386 write — it never reads the
        # envelope for enforcement, so a stray prose line cannot make it exit 2.
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("stale\n"))])
        example = self._envelope_line({"entries": 1, "inventory_sha256": "0" * 64}, "A" * 86 + "==")
        report.write_text(report.read_text(encoding="utf-8").replace("some prose\n", f"some prose\n{example}\n"),
                          encoding="utf-8")
        r = run_inv("write", str(report))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout, f"inventory: updated 1 hash(es) in {report}\n")
        self.assertEqual(r.stderr, "")
        text = report.read_text(encoding="utf-8")
        self.assertIn(sha("alpha\n"), text)
        self.assertIn(example, text)

    def test_sign_places_the_envelope_inside_an_inventory_block(self):
        report = self._signed_fenced()
        inv = self._inv()
        lines = report.read_text(encoding="utf-8").splitlines()
        idx, _env = inv.find_signature(lines)
        blocks = inv.find_blocks(lines)
        self.assertTrue(any(start < idx < end for start, end in blocks), (idx, blocks))
        self.assertEqual(run_inv("check", str(report), "--pubkey", self._pub()).returncode, 0)

    def test_a_valid_envelope_outside_every_block_is_refused_not_honoured(self):
        report = self._signed_fenced()
        lines = report.read_text(encoding="utf-8").splitlines()
        env = self._envelopes(report)[0]
        lines.remove(env)
        report.write_text("\n".join([env] + lines) + "\n", encoding="utf-8")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("outside", r.stderr)

    def test_two_envelope_lines_are_refused(self):
        # M12: ambiguity is tampering — never first-wins.
        report = self._signed_fenced()
        env = self._envelopes(report)[0]
        report.write_text(report.read_text(encoding="utf-8").replace(env, env + "\n" + env),
                          encoding="utf-8")
        self.assertEqual(len(self._envelopes(report)), 2)
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("carries one signature", r.stderr)

    def test_a_signature_line_that_is_not_an_envelope_is_refused_not_unsigned(self):
        # M15: a malformed envelope is a refusal, never silently "unsigned".
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        text = report.read_text(encoding="utf-8")
        report.write_text(text.replace("```\n\n## Gates", '```\n<!-- inventory-signature {"foo": 1} -->'
                                       "\n\n## Gates"), encoding="utf-8")
        r = run_inv("check", str(report), "--pubkey", self._pub())
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("not a {record, sig_b64}", r.stderr)
        self.assertNotIn("unsigned", r.stderr.lower())

class SeedCustodyAtSign(InventorySigningFixture):
    """h409 F-4 (C3), the inventory signer's leg: `sign --key` reads the seed through
    dispatch-sign.py's shared _seed, so a 0644 or unignored-in-repo seed is refused here too, and
    a passing seed's custody class is named on stderr."""

    def test_a_world_readable_seed_is_refused(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        self.key.chmod(0o644)
        r = run_inv("sign", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)  # could-not-run
        self.assertIn("custody", r.stderr)
        self.assertIn("0644", r.stderr)
        self.assertEqual(self._envelopes(report), [], "a refused seed must sign nothing")

    def test_a_0600_seed_signs_and_names_its_custody_class(self):
        self.artifact("a.txt", "alpha\n")
        report = self.fenced_report([("a.txt", sha("alpha\n"))])
        r = run_inv("sign", str(report), "--key", str(self.key))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("custody", r.stderr)
        self.assertIn("0600", r.stderr)


class InventoryFenceAndSymlinkHardening(unittest.TestCase):
    """Regression pins for #784: fenced code block tracking in find_blocks and symlink/containment
    rejection in resolve."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("_inventory_under_test", INVENTORY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.inv = mod

    def test_headings_inside_fenced_blocks_are_ignored(self):
        lines = [
            "# Report",
            "```markdown",
            "## Example integrity inventory (sha256)",
            "0" * 64 + "  fake.txt",
            "```",
            "## Run-close integrity inventory (sha256)",
            "~~~",
            "# comment that looks like a heading inside the inventory fence",
            "a" * 64 + "  real.txt",
            "~~~",
            "## Closing notes",
        ]
        blocks = self.inv.find_blocks(lines)
        self.assertEqual(blocks, [(5, 10)])
        entries = self.inv.parse_entries(lines, *blocks[0])
        self.assertEqual([(p, h) for _ln, p, h, _s in entries], [("real.txt", "a" * 64)])

    def test_unclosed_fence_fails_closed(self):
        lines = [
            "## Run-close integrity inventory (sha256)",
            "```",
            "a" * 64 + "  real.txt",
        ]
        with self.assertRaises(self.inv.InventoryError) as ctx:
            self.inv.find_blocks(lines)
        self.assertIn("unclosed", str(ctx.exception).lower())

    def test_resolve_rejects_symlinks_and_parent_symlink_escape(self):
        with tempfile.TemporaryDirectory(prefix="inv-sym-784-") as tmp:
            base = Path(tmp)
            outside = base / "outside"
            outside.mkdir()
            secret = outside / "secret.txt"
            secret.write_text("secret\n", encoding="utf-8")
            repo = base / "repo"
            repo.mkdir()
            report = repo / "report.md"
            report.write_text("# r\n", encoding="utf-8")
            inside = repo / "inside.txt"
            inside.write_text("ok\n", encoding="utf-8")
            # Direct symlink to outside file
            (repo / "escape.txt").symlink_to(secret)
            # Direct symlink to inside file
            (repo / "alias.txt").symlink_to(inside)
            # Intermediate symlink directory pointing outside
            (repo / "symdir").symlink_to(outside)
            self.assertEqual(self.inv.resolve("inside.txt", report, repo), inside)
            self.assertIsNone(self.inv.resolve("escape.txt", report, repo))
            self.assertIsNone(self.inv.resolve("alias.txt", report, repo))
            self.assertIsNone(self.inv.resolve("symdir/secret.txt", report, repo))


if __name__ == "__main__":
    unittest.main(verbosity=2)
