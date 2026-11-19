#!/usr/bin/env python3
"""Contract tests for runtime/scripts/egress.py.

Three properties define the receipt ledger: it is content-free (the payload text
never lands on disk), it is tamper-evident (an edited line breaks the chain), and
it is fail-closed on write (a sink that cannot receipt must not send). Each has a
test that would fail if the property were quietly dropped.
"""
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
EGRESS = ROOT / "runtime" / "scripts" / "egress.py"
SPEC = importlib.util.spec_from_file_location("egress", EGRESS)
egress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(egress)


class EgressBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="egress-")
        self.ledger = Path(self.tmp) / "state" / "egress.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_egress(self, *args, ledger=None, env=None):
        return subprocess.run(
            [sys.executable, str(EGRESS), "--ledger", str(ledger or self.ledger), *args],
            capture_output=True, text=True, env=env,
        )

    def write_one(self, sink="pr-open", host="github.com", payload_class="pr-body",
                  consent="grant:pr-open", extra=()):
        return self.run_egress("write", "--sink", sink, "--host", host,
                               "--payload-class", payload_class, "--consent", consent, *extra)

    def lines(self):
        return [ln for ln in self.ledger.read_text(encoding="utf-8").splitlines() if ln]

    def records(self):
        return [json.loads(ln) for ln in self.lines()]


class TestWrite(EgressBase):
    def test_concurrent_processes_append_to_new_and_existing_ledgers(self):
        for seeded in (False, True):
            with self.subTest(seeded=seeded):
                self.ledger = Path(self.tmp) / str(seeded) / "egress.jsonl"
                if seeded:
                    self.assertEqual(self.write_one(sink="seed").returncode, 0)
                start = threading.Barrier(12)

                def write(index, start=start):
                    start.wait(timeout=10)
                    return self.write_one(sink=f"writer-{index}")

                with ThreadPoolExecutor(12) as pool:
                    receipts = list(pool.map(write, range(12)))
                for receipt in receipts:
                    self.assertEqual(receipt.returncode, 0, receipt.stderr)
                self.assertEqual(len({r.stdout.strip() for r in receipts}), 12)
                self.assertEqual(len(self.records()), 12 + seeded)
                self.assertEqual({r["sink"] for r in self.records()},
                                 {f"writer-{i}" for i in range(12)} | ({"seed"} if seeded else set()))
                verified = self.run_egress("verify")
                self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_lock_failure_is_fail_closed_and_leaves_no_successful_receipt(self):
        stderr = io.StringIO()
        with patch("fcntl.flock", side_effect=OSError("fixture lock failure")), redirect_stderr(stderr):
            code = egress.main(["--ledger", str(self.ledger), "write", "--sink", "fixture",
                                "--host", "fixture.invalid", "--payload-class", "test",
                                "--consent", "fixture"])
        self.assertEqual(code, 3)
        self.assertIn("EGRESS_RECEIPT_FAILED", stderr.getvalue())
        self.assertEqual(self.records(), [])
        self.assertEqual(self.write_one().returncode, 0)
        self.assertEqual(self.run_egress("verify").returncode, 0)

    def test_permissions_are_private_at_creation_before_any_chmod(self):
        observed = {}
        original_mkdir, original_open, original_io_open = os.mkdir, os.open, io.open

        def observed_mkdir(path, *args, **kwargs):
            original_mkdir(path, *args, **kwargs)
            observed[Path(path)] = stat.S_IMODE(os.stat(path).st_mode)

        def observe_open(opener, path, *args, **kwargs):
            opened = opener(path, *args, **kwargs)
            if not isinstance(path, int) and Path(path) == self.ledger:
                fd = opened if isinstance(opened, int) else opened.fileno()
                observed.setdefault(self.ledger, stat.S_IMODE(os.fstat(fd).st_mode))
            return opened

        # Observe actual OS modes at creation, so a later chmod cannot hide the
        # interval where another user could open the receipt file or directory.
        old_umask = os.umask(0)
        try:
            with patch.object(os, "mkdir", observed_mkdir), \
                 patch.object(os, "open", lambda *a, **k: observe_open(original_open, *a, **k)), \
                 patch.object(io, "open", lambda *a, **k: observe_open(original_io_open, *a, **k)):
                egress.write_receipt(self.ledger, "fixture", "fixture.invalid", "test", "fixture")
        finally:
            os.umask(old_umask)
        for path, mode in ((self.ledger.parent, 0o700), (self.ledger, 0o600)):
            with self.subTest(path=path):
                self.assertEqual(observed.get(path), mode, f"unsafe initial mode for {path}")
        self.assertEqual(self.run_egress("verify").returncode, 0)

    def test_overlapping_writers_preserve_every_successful_receipt_in_one_chain(self):
        self.assertEqual(self.write_one().returncode, 0)
        tail_read = threading.Event()
        release = threading.Event()
        # The writer reads the ledger through the descriptor it holds locked (W5-02), so the
        # snapshot is observed at that read, not at a re-open of the path.
        original_read = egress._read_all

        def paused_read(fd):
            snapshot = original_read(fd)
            if not tail_read.is_set():
                tail_read.set()
                if not release.wait(10):
                    raise TimeoutError("test did not release the first tail snapshot")
            return snapshot

        def write(sink):
            return egress.write_receipt(self.ledger, sink, "fixture.invalid", "test", "fixture")

        # Pause real filesystem I/O after the first tail snapshot. The second writer
        # either completes (the buggy overlap) or waits for the first transaction.
        with patch.object(egress, "_read_all", paused_read), ThreadPoolExecutor(2) as pool:
            first = pool.submit(write, "first")
            try:
                self.assertTrue(tail_read.wait(5), "first writer never read the ledger")
                second = pool.submit(write, "second")
                try:
                    second.result(timeout=1)
                except TimeoutError:
                    pass
            finally:
                release.set()
            receipts = [first.result(timeout=5), second.result(timeout=5)]
        self.assertEqual(len(self.records()), 3)
        self.assertEqual({r["id"] for r in self.records()[1:]}, {r["id"] for r in receipts})
        verified = self.run_egress("verify")
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("3 receipt(s)", verified.stdout)

    def test_write_creates_the_ledger_and_prints_an_id(self):
        r = self.write_one()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.ledger.exists())
        self.assertRegex(r.stdout.strip(), r"^[0-9a-f]{64}$")

    def test_record_carries_every_contracted_field(self):
        self.write_one()
        record = self.records()[0]
        for field in ("id", "ts", "sink", "host", "payload_class", "bytes",
                      "payload_sha256", "consent", "prev"):
            self.assertIn(field, record)

    def test_ledger_file_is_owner_only(self):
        self.write_one()
        mode = stat.S_IMODE(self.ledger.stat().st_mode)
        self.assertEqual(mode, 0o600, f"the ledger must be 0600, got {oct(mode)}")

    def test_first_record_has_an_empty_prev(self):
        self.write_one()
        self.assertEqual(self.records()[0]["prev"], "")

    def test_second_record_chains_to_the_first_raw_line(self):
        self.write_one()
        first_raw = self.lines()[0]
        self.write_one(sink="issue-close")
        expected = hashlib.sha256(first_raw.encode("utf-8")).hexdigest()
        self.assertEqual(self.records()[1]["prev"], expected)

    def test_payload_file_is_hashed_and_never_stored(self):
        payload = Path(self.tmp) / "body.md"
        secret_text = "the entire PR body, which must never reach the ledger"
        payload.write_text(secret_text, encoding="utf-8")
        r = self.write_one(extra=("--payload-file", str(payload)))
        self.assertEqual(r.returncode, 0, r.stderr)
        record = self.records()[0]
        self.assertEqual(record["payload_sha256"],
                         hashlib.sha256(secret_text.encode("utf-8")).hexdigest())
        self.assertEqual(record["bytes"], len(secret_text.encode("utf-8")))
        self.assertNotIn(secret_text, self.ledger.read_text(encoding="utf-8"))

    def test_payload_sha_may_be_absent_when_a_subprocess_owns_the_bytes(self):
        self.write_one()
        self.assertIsNone(self.records()[0]["payload_sha256"])

    def test_a_malformed_payload_sha_is_refused(self):
        r = self.write_one(extra=("--payload-sha256", "not-a-hash"))
        self.assertEqual(r.returncode, 3)

    def test_an_unwritable_ledger_fails_closed_with_exit_3(self):
        # A directory where the ledger file belongs: the append cannot succeed,
        # whatever the process's privileges are.
        blocked = Path(self.tmp) / "blocked" / "egress.jsonl"
        blocked.mkdir(parents=True)
        r = self.run_egress("write", "--sink", "s", "--host", "h", "--payload-class", "c",
                            "--consent", "k", ledger=blocked)
        self.assertEqual(r.returncode, 3, "a sink that cannot receipt must not send")
        self.assertIn("EGRESS_RECEIPT_FAILED", r.stderr)

    def test_a_newline_in_a_field_is_refused(self):
        r = self.write_one(payload_class="pr\nbody")
        self.assertEqual(r.returncode, 3)

    def test_a_malformed_ts_is_a_usage_error_and_writes_nothing(self):
        # --ts was the one unchecked free-text field, and record_id joins
        # `k=v` lines with "\n": a ts smuggling "\nsink=..." made ids ambiguous.
        for ts in ("2026-01-01T00:00:00Z\nsink=x", "yesterday", "2026-02-30T00:00:00Z",
                   "2026-01-01 00:00:00Z", "2026-01-01T00:00:00",
                   # the shape matches, the offset names no instant (PR #571 review)
                   "2026-01-02T03:04:05+99:99", "2026-01-02T03:04:05+05:99",
                   "2026-01-02T03:04:05-24:00"):
            with self.subTest(ts=ts):
                r = self.write_one(extra=("--ts", ts))
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertFalse(self.ledger.exists())
        with self.assertRaises(egress.EgressError):
            egress.write_receipt(self.ledger, "s", "h", "c", "k", ts="2026-01-01T00:00:00Z\n")
        for ts in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.123+05:30"):
            with self.subTest(ts=ts):
                self.assertEqual(self.write_one(extra=("--ts", ts)).returncode, 0)
        self.assertEqual(self.records()[-1]["ts"], "2026-01-01T00:00:00.123+05:30")

    def test_the_ledger_env_var_is_honored(self):
        env = dict(os.environ)
        env["ORCA_EGRESS_LEDGER"] = str(self.ledger)
        r = subprocess.run(
            [sys.executable, str(EGRESS), "write", "--sink", "s", "--host", "h",
             "--payload-class", "c", "--consent", "k"],
            capture_output=True, text=True, env=env, cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.ledger.exists())


class TestVerify(EgressBase):
    def test_an_intact_chain_verifies(self):
        self.write_one()
        self.write_one(sink="issue-close")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 receipt(s)", r.stdout)

    def test_a_missing_ledger_is_an_empty_intact_chain(self):
        # Only when the caller says no receipts were expected (--allow-empty). By default no
        # receipts is EXIT_NO_RECEIPTS, never a pass (W5-03; TestTheLedgerIsWhereItSays).
        r = self.run_egress("verify", "--allow-empty")
        self.assertEqual(r.returncode, 0)
        self.assertIn("0 receipt(s)", r.stdout)

    def test_an_edited_earlier_line_breaks_the_chain(self):
        self.write_one()
        self.write_one(sink="issue-close")
        lines = self.lines()
        record = json.loads(lines[0])
        record["host"] = "elsewhere.invalid"
        lines[0] = json.dumps(record, separators=(",", ":"))
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3)
        self.assertIn("TAMPER", r.stderr)

    def test_an_edited_field_breaks_its_own_record_id(self):
        self.write_one()
        record = self.records()[0]
        record["consent"] = "grant:something-else"
        self.ledger.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3)
        self.assertIn("id does not match", r.stderr)

    def test_a_field_with_a_line_break_fails_verify_even_with_a_matching_id(self):
        # A hand-built line whose id is recomputed over a newline-carrying
        # field is self-consistent, but its id encoding is ambiguous.
        record = {"ts": "2026-01-01T00:00:00Z", "sink": "s\nhost=h", "host": "", "payload_class": "c",
                  "bytes": 0, "payload_sha256": None, "consent": "k", "prev": ""}
        record["id"] = egress.record_id(record)
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(json.dumps(record) + "\n", encoding="utf-8")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("line break", r.stderr)
        # The line-break rule is not what binds this record (2026-10-27 audit, W5-05): the same
        # hand-built single line without the break, its id recomputed, is still not a line the
        # writer produced (re-spaced JSON), and verify must refuse it on its own terms.
        record.update(sink="s", host="h")
        record["id"] = egress.record_id(record)
        self.ledger.write_text(json.dumps(record) + "\n", encoding="utf-8")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("canonical", r.stderr)

    def test_a_deleted_line_breaks_the_chain(self):
        self.write_one()
        self.write_one(sink="issue-close")
        self.write_one(sink="deploy-trigger")
        lines = self.lines()
        del lines[1]
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3)

    def test_an_unparseable_line_breaks_the_chain(self):
        self.write_one()
        with self.ledger.open("a", encoding="utf-8") as fh:
            fh.write("not json at all\n")
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3)
        self.assertIn("unparseable", r.stderr)

    def test_appending_after_a_verify_keeps_the_chain_intact(self):
        self.write_one()
        self.run_egress("verify")
        self.write_one(sink="comment")
        self.assertEqual(self.run_egress("verify").returncode, 0)


class TestAnchoredHead(EgressBase):
    """#312: a hash chain is tamper-evident against EDITS to a known chain. It says nothing about a
    chain replaced wholesale, because the replacement is internally perfect — it starts at its own
    genesis and every link checks out. Only a head digest kept where the writer cannot reach it
    tells the two apart."""

    def _head(self):
        """Computed from the ledger, not scraped from the output under test — an expectation read
        out of the thing being tested cannot disagree with it."""
        lines = self.lines()
        return hashlib.sha256(lines[-1].encode("utf-8")).hexdigest() if lines else ""

    def test_verify_reports_the_head_so_there_is_something_to_anchor(self):
        self.write_one()
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        want = hashlib.sha256(self.lines()[-1].encode("utf-8")).hexdigest()
        self.assertIn(want, r.stdout, f"verify must print the head digest: {r.stdout}")

    def test_a_wholesale_rewrite_is_caught_by_the_anchor(self):
        self.write_one()
        self.write_one(sink="issue-close")
        anchored = self._head()
        # The rewrite uses the SAME tool, legally: remove the ledger and write two fresh receipts
        # with a different host. The chain that results is flawless on its own terms.
        self.ledger.unlink()
        self.write_one(host="evil.example")
        self.write_one(sink="issue-close", host="evil.example")
        plain = self.run_egress("verify")
        self.assertEqual(plain.returncode, 0,
                         "a rewritten chain is internally intact — that is the finding, not a bug")
        r = self.run_egress("verify", "--expect-head", anchored)
        self.assertEqual(r.returncode, 3, f"the anchor must catch the rewrite: {r.stdout}{r.stderr}")
        self.assertIn("TAMPER", r.stderr)

    def test_the_anchor_passes_on_the_chain_it_names(self):
        self.write_one()
        self.write_one(sink="issue-close")
        r = self.run_egress("verify", "--expect-head", self._head())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("anchored", r.stdout)

    def test_an_appended_receipt_moves_the_head_past_the_anchor(self):
        # An anchor pins one moment. Honest growth past it is not tamper, but it is not the
        # anchored chain either — the caller re-anchors, and until it does, verify says so.
        self.write_one()
        anchored = self._head()
        self.write_one(sink="issue-close")
        self.assertEqual(self.run_egress("verify").returncode, 0)
        self.assertEqual(self.run_egress("verify", "--expect-head", anchored).returncode, 3)


class TestGrants(EgressBase):
    def test_grants_lists_each_consent_once(self):
        self.write_one(consent="grant:pr-open")
        self.write_one(consent="grant:pr-open", sink="pr-comment")
        self.write_one(consent="grant:deploy", sink="deploy-trigger")
        r = self.run_egress("grants", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = json.loads(r.stdout)
        self.assertEqual([row["consent"] for row in rows], ["grant:deploy", "grant:pr-open"])
        by_key = {row["consent"]: row for row in rows}
        self.assertEqual(by_key["grant:pr-open"]["uses"], 2)
        self.assertEqual(by_key["grant:pr-open"]["sinks"], ["pr-comment", "pr-open"])

    def test_grants_on_an_empty_ledger_says_so(self):
        r = self.run_egress("grants")
        self.assertEqual(r.returncode, 0)
        self.assertIn("no consents recorded", r.stdout)

    def test_grants_human_output_names_the_host(self):
        self.write_one(host="api.github.com")
        r = self.run_egress("grants")
        self.assertIn("api.github.com", r.stdout)


class TestScriptShape(unittest.TestCase):
    def test_executable_and_shebanged(self):
        self.assertTrue(os.access(EGRESS, os.X_OK))
        self.assertTrue(EGRESS.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3"))

    def test_help_exits_zero_and_names_the_subcommands(self):
        r = subprocess.run([sys.executable, str(EGRESS), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        for sub in ("write", "verify", "head", "grants"):
            self.assertIn(sub, r.stdout)

    def test_threat_model_is_stated_not_overclaimed(self):
        text = EGRESS.read_text(encoding="utf-8")
        self.assertIn("not an exfiltration control", text)

    def test_default_ledger_is_repo_local(self):
        self.assertIn('DEFAULT_LEDGER = ".orca/egress.jsonl"', EGRESS.read_text(encoding="utf-8"))


class TestExpectAncestor(EgressBase):
    """#561: close-to-close anchoring tolerates appends, catches rewrites."""

    def test_appends_after_the_anchor_pass(self):
        self.write_one()
        anchored = self.run_egress("head").stdout.strip()
        self.write_one(sink="issue-close")
        self.write_one(sink="pr-merge")
        r = self.run_egress("verify", "--expect-ancestor", anchored)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_wholesale_rewrite_loses_the_anchored_line(self):
        self.write_one()
        anchored = self.run_egress("head").stdout.strip()
        self.ledger.unlink()
        self.write_one(host="evil.example")
        r = self.run_egress("verify", "--expect-ancestor", anchored)
        self.assertEqual(r.returncode, 3)
        self.assertIn("TAMPER", r.stderr)

    def test_truncation_loses_the_anchored_line(self):
        self.write_one()
        self.write_one(sink="issue-close")
        anchored = self.run_egress("head").stdout.strip()
        self.ledger.write_text(self.lines()[0] + "\n", encoding="utf-8")
        r = self.run_egress("verify", "--expect-ancestor", anchored)
        self.assertEqual(r.returncode, 3)

    def test_empty_anchor_round_trips(self):
        self.assertEqual(self.run_egress("head").stdout.strip(), "(empty)")
        r = self.run_egress("verify", "--expect-head", "(empty)")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.write_one()
        r2 = self.run_egress("verify", "--expect-ancestor", "(empty)")
        self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_both_anchors_requested_both_checked(self):
        # Asking for --expect-head beside --expect-ancestor must not return
        # after the ancestor leg: a stale head fails even when the anchored
        # line is present (PR #567 review, P2).
        self.write_one()
        anchored = self.run_egress("head").stdout.strip()
        self.write_one(sink="issue-close")
        current = self.run_egress("head").stdout.strip()
        stale = self.run_egress("verify", "--expect-ancestor", anchored,
                                 "--expect-head", anchored)
        self.assertEqual(stale.returncode, 3, stale.stdout + stale.stderr)
        both = self.run_egress("verify", "--expect-ancestor", anchored,
                                "--expect-head", current)
        self.assertEqual(both.returncode, 0, both.stderr)


class TestHead(EgressBase):
    """#561: `head` prints the anchor value run close records off the writer.
    It verifies first — a head taken from a broken chain anchors tampering."""

    def test_head_prints_the_chain_head(self):
        self.write_one()
        self.write_one(sink="issue-close")
        r = self.run_egress("head")
        self.assertEqual(r.returncode, 0, r.stderr)
        want = hashlib.sha256(self.lines()[-1].encode("utf-8")).hexdigest()
        self.assertEqual(r.stdout.strip(), want)
        # And the printed head is exactly what --expect-head accepts.
        r2 = self.run_egress("verify", "--expect-head", r.stdout.strip())
        self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_head_of_empty_ledger(self):
        r = self.run_egress("head")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "(empty)")

    def test_head_refuses_a_broken_chain(self):
        self.write_one()
        lines = self.lines()
        lines[0] = lines[0].replace("pr-body", "tampered")
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        r = self.run_egress("head")
        self.assertEqual(r.returncode, 3)
        self.assertIn("TAMPER", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestLedgerIsNeverASymlink(EgressBase):
    """2026-10-26 review: the ledger was opened with O_APPEND and followed a symlink, so a planted
    `.orca/egress.jsonl -> elsewhere` redirected every receipt into another file. The writer now
    refuses a symlinked ledger and anything that is not a regular file."""

    def test_a_symlinked_ledger_is_refused(self):
        target = Path(self.tmp) / "elsewhere.txt"
        target.write_text("", encoding="utf-8")
        link = Path(self.tmp) / "linked.jsonl"
        link.symlink_to(target)
        with self.assertRaises(egress.EgressError):
            egress.write_receipt(link, "fixture", "fixture.invalid", "test", "fixture")
        self.assertEqual(target.read_text(encoding="utf-8"), "", "a receipt reached the link target")

    def test_a_directory_at_the_ledger_path_is_refused(self):
        folder = Path(self.tmp) / "folder.jsonl"
        folder.mkdir()
        with self.assertRaises(egress.EgressError):
            egress.write_receipt(folder, "fixture", "fixture.invalid", "test", "fixture")


def _v1_id(record):
    """The legacy (pre-v2) id, spelled out here rather than read from the module under test."""
    return hashlib.sha256("\n".join(f"{k}={'' if record[k] is None else record[k]}"
                                    for k in egress.FIELDS).encode("utf-8")).hexdigest()


def _v1_line(record):
    """A line exactly as the v1 writer produced it: id first, then FIELDS, compact JSON."""
    return json.dumps({"id": _v1_id(record), **{k: record[k] for k in egress.FIELDS}}, separators=(",", ":"))


class TestEveryByteIsBound(EgressBase):
    """2026-10-27 security audit, W5-05 (verify-v3 §C1): `id` covered a field list and `prev` the
    previous line, so nothing covered the LAST line's own bytes. An extra key, a re-spacing, a type
    swap or a blank line verified as intact, and a receipt written since the last close could be
    rewritten whole with its id recomputed while `verify --expect-ancestor` still said intact."""

    def _rewrite_last(self, mutate, serialise=None):
        lines = self.lines()
        record = json.loads(lines[-1])
        mutate(record)
        record["id"] = egress.record_id(record)
        lines[-1] = (serialise or (lambda r: json.dumps(r, separators=(",", ":"))))(record)
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _assert_tamper(self, why=None):
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("TAMPER", r.stderr)
        if why:
            self.assertIn(why, r.stderr)

    def test_a_key_appended_to_the_last_line_is_tamper(self):
        self.write_one()
        self.write_one(sink="issue-close")
        self._rewrite_last(lambda r: r.update(note="FORGED-IN-AFTER-THE-FACT"))
        self._assert_tamper("unknown key")

    def test_a_respaced_last_line_is_tamper(self):
        self.write_one()
        self.write_one(sink="issue-close")
        self._rewrite_last(lambda r: None, serialise=json.dumps)
        self._assert_tamper("canonical")

    def test_a_type_swapped_field_is_tamper(self):
        # The v1 id rendered `"bytes":"12"` and `"bytes":12` alike.
        self.write_one(extra=("--bytes", "12"))
        self._rewrite_last(lambda r: r.update(bytes="12"))
        self._assert_tamper("bytes")

    def test_a_duplicated_key_is_tamper_even_with_the_same_value(self):
        self.write_one()
        lines = self.lines()
        lines[-1] = lines[-1][:-1] + ',"host":"github.com"}'
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._assert_tamper("canonical")

    def test_a_blank_line_or_a_missing_final_newline_is_tamper(self):
        self.write_one()
        self.write_one(sink="issue-close")
        first, second = self.lines()
        self.ledger.write_text(f"{first}\n\n{second}\n", encoding="utf-8")
        self._assert_tamper("empty line")
        self.ledger.write_text(f"{first}\n{second}", encoding="utf-8")
        self._assert_tamper("newline")

    def test_the_id_write_prints_anchors_a_receipt_written_since_the_last_close(self):
        # verify-v3 §C1's anchored case: close N anchors its head; a receipt written since is
        # rewritten whole (host and bytes, id recomputed, canonical form) — the realistic forger.
        self.write_one(extra=("--bytes", "12"))
        close_head = self.run_egress("head").stdout.strip()
        written = self.write_one(host="evil.example", extra=("--bytes", "2"))
        self.assertEqual(written.returncode, 0, written.stderr)
        receipt_id = written.stdout.strip()
        honest = self.run_egress("verify", "--expect-ancestor", close_head, "--expect-ancestor", receipt_id)
        self.assertEqual(honest.returncode, 0, honest.stderr)
        self.assertEqual(self.run_egress("verify", "--expect-head", receipt_id).returncode, 0)
        self._rewrite_last(lambda r: r.update(host="github.com", bytes=4))
        self.assertEqual(self.run_egress("verify").returncode, 0, "the rewrite is internally consistent")
        for anchors in (("--expect-ancestor", close_head, "--expect-ancestor", receipt_id),
                        ("--expect-head", receipt_id)):
            with self.subTest(anchors=anchors):
                r = self.run_egress("verify", *anchors)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn("TAMPER", r.stderr)

    def test_a_ledger_the_verifier_refuses_is_never_written_onto(self):
        self.write_one()
        self._rewrite_last(lambda r: r.update(note="FORGED"))
        before = self.ledger.read_bytes()
        r = self.write_one(sink="issue-close")
        self.assertEqual(r.returncode, 3, "a receipt chained onto a tampered line locks the forgery in")
        self.assertEqual(r.stdout, "")
        self.assertEqual(self.ledger.read_bytes(), before)

    def test_a_legacy_ledger_verifies_and_grows_in_v2(self):
        base = {"ts": "2026-01-01T00:00:00Z", "sink": "pr-open", "host": "github.com",
                "payload_class": "pr-body", "bytes": 3, "payload_sha256": None,
                "consent": "free text the v1 writer allowed", "prev": ""}
        first = _v1_line(base)
        second = _v1_line({**base, "sink": "issue-close", "prev": hashlib.sha256(first.encode()).hexdigest()})
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(f"{first}\n{second}\n", encoding="utf-8")
        self.assertEqual(self.run_egress("verify").returncode, 0)
        self.assertEqual(self.write_one().returncode, 0)
        r = self.run_egress("verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("3 receipt(s)", r.stdout)
        newest = self.records()[-1]
        self.assertEqual(newest.get("v"), 2)
        self.assertEqual(newest["prev"], hashlib.sha256(second.encode()).hexdigest())

    def test_a_legacy_line_is_bound_only_in_the_form_the_v1_writer_produced(self):
        base = {"ts": "2026-01-01T00:00:00Z", "sink": "pr-open", "host": "github.com",
                "payload_class": "pr-body", "bytes": 3, "payload_sha256": None, "consent": "k", "prev": ""}
        self.ledger.parent.mkdir(parents=True)
        forged = json.loads(_v1_line(base))
        forged["note"] = "unbound"
        self.ledger.write_text(json.dumps(forged, separators=(",", ":")) + "\n", encoding="utf-8")
        self._assert_tamper("unknown key")
        # And never after a v2 receipt: once the v2 writer has run, only it appends.
        self.ledger.unlink()
        self.write_one()
        legacy = _v1_line({**base, "prev": hashlib.sha256(self.lines()[-1].encode()).hexdigest()})
        with self.ledger.open("a", encoding="utf-8") as fh:
            fh.write(legacy + "\n")
        self._assert_tamper("legacy")


class TestTheWriterReadsWhatTheVerifierReads(EgressBase):
    """W5-01: the writer decoded the tail leniently and the verifier strictly, so one appended
    byte made every later receipt succeed while `verify` and `head` refused the ledger for good."""

    def test_a_byte_the_verifier_refuses_stops_the_writer_before_the_send(self):
        self.write_one()
        with self.ledger.open("ab") as fh:
            fh.write(b"note=\xff\n")
        before = self.ledger.read_bytes()
        r = self.write_one(sink="issue-close")
        self.assertEqual(r.returncode, 3, "the send would go ahead on a ledger the close cannot read")
        self.assertIn("EGRESS_RECEIPT_FAILED", r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertEqual(self.run_egress("verify").returncode, 3)


class TestTheLockedLedgerIsTheOneWritten(EgressBase):
    """W5-02: `prev` was read by re-opening the PATH after locking a different open of it, so a
    ledger swapped in between chained the receipt to a stale tail and orphaned it into an unlinked
    file, while `write` exited 0."""

    def test_a_ledger_swapped_beside_the_lock_is_refused_not_lost(self):
        self.write_one()
        self.write_one(sink="issue-close")
        stale = Path(self.tmp) / "stale.jsonl"
        stale.write_text(self.lines()[0] + "\n", encoding="utf-8")
        real_flock = fcntl.flock

        def swap_after_locking(fd, operation):
            real_flock(fd, operation)
            if operation == fcntl.LOCK_EX and stale.exists():
                os.replace(stale, self.ledger)

        with patch("fcntl.flock", side_effect=swap_after_locking):
            try:
                record = egress.write_receipt(self.ledger, "late", "fixture.invalid", "test", "fixture")
            except egress.EgressError:
                record = None
        if record is not None:
            self.assertIn(record["id"], {r["id"] for r in self.records()},
                          "write reported success, and its receipt is on no ledger the path names")
        verified = self.run_egress("verify")
        self.assertEqual(verified.returncode, 0, verified.stderr)


class TestTheLedgerIsWhereItSays(EgressBase):
    """W5-03: the default ledger was relative to the working directory and an env var could route
    it anywhere, silently; a missing ledger verified as an intact empty chain; the first receipt
    created any directory tree above itself."""

    WRITE = ("write", "--sink", "pr-open", "--host", "github.com", "--payload-class", "pr-body",
             "--consent", "grant:pr-open")

    def setUp(self):
        super().setUp()
        self.repo = Path(self.tmp) / "repo"
        (self.repo / ".git").mkdir(parents=True)
        (self.repo / "sub" / "deeper").mkdir(parents=True)
        self.env = {k: v for k, v in os.environ.items()
                    if k not in (egress.PRIMARY_LEDGER_ENV, egress.LEDGER_ENV)}

    def bare(self, *args, cwd, env=None):
        return subprocess.run([sys.executable, str(EGRESS), *args], capture_output=True, text=True,
                              cwd=cwd, env=env or self.env)

    def test_the_default_ledger_is_the_repository_roots_from_any_subdirectory(self):
        r = self.bare(*self.WRITE, cwd=self.repo / "sub" / "deeper")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.repo / ".orca" / "egress.jsonl").is_file())
        self.assertFalse((self.repo / "sub" / "deeper" / ".orca").exists())
        self.assertIn("1 receipt(s)", self.bare("verify", cwd=self.repo).stdout)

    def test_outside_a_repository_the_default_refuses(self):
        outside = Path(self.tmp) / "outside"
        outside.mkdir()
        r = self.bare(*self.WRITE, cwd=outside)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertFalse((outside / ".orca").exists())

    def test_a_routed_receipt_says_where_it_went(self):
        env = {**self.env, egress.PRIMARY_LEDGER_ENV: "elsewhere.jsonl"}
        r = self.bare(*self.WRITE, cwd=self.repo / "sub", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        routed = self.repo / "sub" / "elsewhere.jsonl"
        self.assertTrue(routed.is_file())
        self.assertIn(str(routed), r.stderr)
        self.assertIn(f"not the repository ledger {self.repo / '.orca' / 'egress.jsonl'}", r.stderr)
        self.assertIn(str(routed), self.bare("verify", cwd=self.repo / "sub", env=env).stdout)

    def test_no_tree_is_created_above_the_ledgers_own_directory(self):
        r = self.run_egress(*self.WRITE, ledger=Path(self.tmp) / "a" / "b" / "c" / "egress.jsonl")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertFalse((Path(self.tmp) / "a").exists())

    def test_no_ledger_is_not_reported_as_an_intact_chain(self):
        # Codex review of 82a2d00c: a missing (or empty) canonical ledger still verified as "chain
        # intact", so a close whose receipts went elsewhere passed. No receipts is never called
        # intact, and every form fails on it (plain verify too, W5-03) unless the caller says none
        # were expected (--allow-empty, or a sealed empty head); an anchor naming a receipt always
        # fails.
        for setup in ("no ledger file", "an empty ledger file"):
            with self.subTest(setup=setup):
                if setup == "an empty ledger file":
                    self.ledger.parent.mkdir(parents=True, exist_ok=True)
                    self.ledger.write_bytes(b"")
                plain = self.run_egress("verify")
                self.assertNotIn("chain intact", plain.stdout + plain.stderr)
                self.assertIn("NO RECEIPTS", plain.stdout)
                self.assertEqual(plain.returncode, egress.EXIT_NO_RECEIPTS, "the plain form fails too")
                allowed = self.run_egress("verify", "--allow-empty")
                self.assertEqual(allowed.returncode, 0, allowed.stderr)
                self.assertIn("0 receipt(s)", allowed.stdout)
                r = self.run_egress("verify", "--require-receipts")
                self.assertEqual(r.returncode, egress.EXIT_NO_RECEIPTS, r.stdout + r.stderr)
                self.assertNotEqual(egress.EXIT_NO_RECEIPTS, 0)
                self.assertNotIn("chain intact", r.stdout + r.stderr)
                self.assertIn("NO RECEIPTS", r.stderr)
                for anchors in (("--expect-ancestor", "(empty)"),):
                    self.assertEqual(self.run_egress("verify", "--require-receipts", *anchors).returncode,
                                     egress.EXIT_NO_RECEIPTS, "an empty PREVIOUS close says nothing about this one")
                sealed_empty = self.run_egress("verify", "--require-receipts", "--expect-head", "(empty)")
                self.assertEqual(sealed_empty.returncode, 0, "an anchored empty head is an explicit none-expected")
                for anchors in (("--expect-ancestor", "ab" * 32), ("--expect-head", "ab" * 32)):
                    anchored = self.run_egress("verify", *anchors)
                    self.assertEqual(anchored.returncode, 3, "an anchor names a receipt; none is not intact")
                    self.assertIn("TAMPER", anchored.stderr)

    def test_a_close_routed_elsewhere_fails_the_required_form(self):
        # Codex's exact repro: the receipt goes to a routed ledger, the canonical one stays absent.
        routed = Path(self.tmp) / "mine.jsonl"
        w = self.bare(*self.WRITE, cwd=self.repo, env={**self.env, egress.PRIMARY_LEDGER_ENV: str(routed)})
        self.assertEqual(w.returncode, 0, w.stderr)
        self.assertTrue(routed.is_file())
        self.assertFalse((self.repo / ".orca" / "egress.jsonl").exists())
        r = self.bare("verify", "--require-receipts", cwd=self.repo)
        self.assertEqual(r.returncode, egress.EXIT_NO_RECEIPTS, r.stdout + r.stderr)
        self.assertNotIn("chain intact", r.stdout + r.stderr)
        self.assertNotIn("chain intact", self.bare("verify", cwd=self.repo).stdout)
        self.assertEqual(self.bare("verify", cwd=self.repo).returncode, egress.EXIT_NO_RECEIPTS)


class TestANonFileLedgerIsRefusedNeverWaitedOn(EgressBase):
    """Re-attack of e281e130 (P3): `verify` -- and so the close's `verify --require-receipts` --
    `head` and `grants` opened the ledger without O_NONBLOCK, so a FIFO at its path blocked them
    forever (`write` already refused it). A ledger that is not a regular file is fail-closed (3),
    said, at once: never a hang and never a pass."""

    def test_a_fifo_ledger_is_refused_by_every_reader_at_once(self):
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(self.ledger)
        for args in (("verify",), ("verify", "--require-receipts"), ("verify", "--expect-head", "(empty)"),
                     ("head",), ("grants",), ("grants", "--json")):
            with self.subTest(args=args):
                try:
                    r = subprocess.run([sys.executable, str(EGRESS), "--ledger", str(self.ledger), *args],
                                       capture_output=True, text=True, timeout=20)
                except subprocess.TimeoutExpired:
                    self.fail(f"egress.py {' '.join(args)} hung on a FIFO ledger")
                self.assertEqual(r.returncode, egress.EXIT_FAIL_CLOSED, r.stdout + r.stderr)
                self.assertIn("not a regular file", r.stderr)
                self.assertNotIn("chain intact", r.stdout + r.stderr)

    def test_the_library_readers_refuse_it_too(self):
        # merge_queue.py reads the chain through verify_ledger()/load_ledger(), in-process.
        import threading
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(self.ledger)
        outcome = []

        def read():
            try:
                egress.load_ledger(self.ledger)
                outcome.append("read")
            except egress.EgressError as err:
                outcome.append(str(err))

        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        worker.join(10)
        if worker.is_alive():
            with open(self.ledger, "wb"):  # unblock the stuck open so the suite can go on
                pass
            worker.join(5)
            self.fail("load_ledger() hung on a FIFO ledger")
        self.assertEqual(len(outcome), 1)
        self.assertIn("not a regular file", outcome[0])


class TestGrantsAnswerOnlyForAVerifiedChain(EgressBase):
    """W5-04: `grants` printed whatever consent the file held without verifying the chain, and a
    consent was any free text."""

    def test_a_forged_consent_on_a_tampered_chain_is_never_listed(self):
        self.write_one()
        self.write_one(sink="issue-close")
        lines = self.lines()
        lines[-1] = lines[-1][:-1] + ',"consent":"grant:merge-anything"}'
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        for args in (("grants",), ("grants", "--json")):
            with self.subTest(args=args):
                r = self.run_egress(*args)
                self.assertEqual(r.returncode, 3, r.stdout)
                self.assertNotIn("merge-anything", r.stdout)
                self.assertIn("TAMPER", r.stderr)

    def test_a_consent_must_name_a_grant(self):
        for consent in ("grant:\x1b[31mred", 'grant:"quoted"', " grant:x", "grant:x ", "grant:ünïcode",
                        "grant:$(id)", "grant:x;y", "_grant"):
            with self.subTest(consent=consent):
                r = self.write_one(consent=consent)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertFalse(self.ledger.exists())
        for consent in ("grant:pr-open-on-base", "run-2026-09-14-clean-sweep:base-writes", "k",
                        "task_57ea07ec0722:report-push-u-442",
                        "wip-curve run wip2-b1r1-rep1 (#604): merges only to wip-integration"):
            with self.subTest(consent=consent):
                self.assertEqual(self.write_one(consent=consent).returncode, 0)
        self.assertEqual(self.run_egress("verify").returncode, 0)


class TestGrantsAreAnchoredLikeVerify(EgressBase):
    """Re-attack of 2d254d0f (W5-04): `grants` verified the chain but took no anchor and never said
    UNANCHORED, so a consent rewritten since the last close, its id recomputed, printed with rc 0
    while `verify --expect-ancestor <that receipt's id>` gave rc 3."""

    def test_a_consent_rewritten_since_its_anchor_is_tamper_and_an_unanchored_answer_says_so(self):
        self.write_one(consent="grant:pr-open")
        close_head = self.run_egress("head").stdout.strip()
        written = self.write_one(consent="grant:pr-open", sink="issue-close")
        self.assertEqual(written.returncode, 0, written.stderr)
        receipt_id = written.stdout.strip()
        anchored = (("--expect-ancestor", close_head, "--expect-ancestor", receipt_id), ("--expect-head", receipt_id))
        for anchors in anchored:
            honest = self.run_egress("grants", *anchors)
            self.assertEqual(honest.returncode, 0, honest.stderr)
            self.assertIn("grant:pr-open", honest.stdout)
            self.assertNotIn("UNANCHORED", honest.stdout + honest.stderr)
        lines = self.lines()
        record = json.loads(lines[-1])
        record["consent"] = "grant:merge-anything"
        record["id"] = egress.record_id(record)
        lines[-1] = json.dumps(record, separators=(",", ":"))
        self.ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(self.run_egress("verify").returncode, 0, "the rewrite is internally consistent")
        self.assertEqual(self.run_egress("verify", "--expect-ancestor", receipt_id).returncode, 3)
        for anchors in anchored:
            for as_json in ((), ("--json",)):
                with self.subTest(anchors=anchors, as_json=as_json):
                    r = self.run_egress("grants", *as_json, *anchors)
                    self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                    self.assertNotIn("merge-anything", r.stdout)
                    self.assertIn("TAMPER", r.stderr)
        for as_json, stream in (((), "stdout"), (("--json",), "stderr")):
            with self.subTest(unanchored=as_json):
                r = self.run_egress("grants", *as_json)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("UNANCHORED", getattr(r, stream), "an unanchored answer reads as a clean bill")
        self.assertEqual(json.loads(self.run_egress("grants", "--json").stdout)[0]["consent"], "grant:merge-anything")


class TestNothingPrintedIsATerminalCommand(EgressBase):
    """Re-attack of 82a2d00c (W5-04): v1-prefix lines were not held to the text rule, so a v1
    consent `grant\\x1b]0;PWNED\\x07\\x1b[31mRED` verified and `grants` printed the raw escapes to
    the terminal. Every line is held to it on read, and everything printed is made inert."""

    def test_a_legacy_line_with_control_characters_is_tamper_and_never_printed(self):
        base = {"ts": "2026-01-01T00:00:00Z", "sink": "pr-open", "host": "h\x1b[2J", "payload_class": "pr-body",
                "bytes": 3, "payload_sha256": None, "consent": "grant\x1b]0;PWNED\x07\x1b[31mRED", "prev": ""}
        self.ledger.parent.mkdir(parents=True)
        self.ledger.write_text(_v1_line(base) + "\n", encoding="utf-8")
        for args in (("verify",), ("grants",), ("head",)):
            with self.subTest(args=args):
                r = self.run_egress(*args)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertNotIn("\x1b", r.stdout + r.stderr)
                self.assertNotIn("\x07", r.stdout + r.stderr)

    def test_a_path_with_control_characters_is_printed_inert(self):
        ledger = Path(self.tmp) / "led\x1b[2Jger.jsonl"
        w = self.run_egress("write", "--sink", "s", "--host", "h", "--payload-class", "c", "--consent", "k",
                            ledger=ledger)
        self.assertEqual(w.returncode, 0, w.stderr)
        v = self.run_egress("verify", ledger=ledger)
        for r in (w, v):
            self.assertNotIn("\x1b", r.stdout + r.stderr)
            self.assertIn("\\x1b", r.stdout + r.stderr, "the path is not shown at all")


class TestANestedRepositoryNeverMovesTheLedgerSilently(EgressBase):
    """Re-attack of 82a2d00c (W5-03): the default ledger stopped at the FIRST `.git` above the
    working directory, so a `.git` file planted (or a vendored repository / submodule) in a
    subdirectory silently moved receipts into `<subdir>/.orca` while the close verified the root."""

    def setUp(self):
        super().setUp()
        self.repo = Path(self.tmp) / "repo"
        (self.repo / ".git").mkdir(parents=True)
        self.env = {k: v for k, v in os.environ.items() if k not in (egress.PRIMARY_LEDGER_ENV, egress.LEDGER_ENV)}

    def bare(self, *args, cwd):
        return subprocess.run([sys.executable, str(EGRESS), *args], capture_output=True, text=True, cwd=cwd,
                              env=self.env)

    WRITE = ("write", "--sink", "pr-open", "--host", "github.com", "--payload-class", "pr-body", "--consent", "k")

    def test_a_planted_or_vendored_git_below_the_repository_refuses(self):
        for kind in ("file", "dir"):
            with self.subTest(kind=kind):
                nested = self.repo / f"vendor-{kind}" / "x"
                nested.mkdir(parents=True)
                if kind == "file":
                    (nested / ".git").write_text("gitdir: /nonexistent\n", encoding="utf-8")
                else:
                    (nested / ".git").mkdir()
                r = self.bare(*self.WRITE, cwd=nested)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn(str(self.repo), r.stderr)
                self.assertFalse((nested / ".orca").exists())
                self.assertFalse((self.repo / ".orca").exists())

    def test_a_linked_worktree_inside_the_repository_uses_its_own_ledger_and_says_so(self):
        admin = self.repo / ".git" / "worktrees" / "wt"
        admin.mkdir(parents=True)
        worktree = self.repo / "wt"
        worktree.mkdir()
        (worktree / ".git").write_text(f"gitdir: {admin}\n", encoding="utf-8")
        (admin / "gitdir").write_text(f"{worktree / '.git'}\n", encoding="utf-8")  # git's back-link
        r = self.bare(*self.WRITE, cwd=worktree)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((worktree / ".orca" / "egress.jsonl").is_file())
        self.assertIn("linked worktree", r.stderr)
        self.assertIn(str(self.repo), r.stderr)

    def test_a_gitfile_that_only_names_the_worktrees_directory_is_not_a_linked_worktree(self):
        # Re-check of 4b24dfde (W5-03): a planted `.git` FILE reading `gitdir: <repo>/.git/worktrees/x`
        # passed as a linked worktree on its text alone -- no such worktree, or one that is another
        # directory's -- and moved receipts into `<subdir>/.orca`. git's own back-link
        # (`worktrees/<name>/gitdir` naming this `.git`) must agree.
        other = self.repo / "elsewhere"
        other.mkdir()
        for case in ("no admin directory", "admin without a back-link", "back-link to another worktree"):
            with self.subTest(case=case):
                admin = self.repo / ".git" / "worktrees" / case.replace(" ", "-")
                nested = self.repo / "vendor" / case.replace(" ", "-")
                nested.mkdir(parents=True)
                (nested / ".git").write_text(f"gitdir: {admin}\n", encoding="utf-8")
                if case != "no admin directory":
                    admin.mkdir(parents=True)
                if case == "back-link to another worktree":
                    (admin / "gitdir").write_text(f"{other / '.git'}\n", encoding="utf-8")
                r = self.bare(*self.WRITE, cwd=nested)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn("nested inside the repository", r.stderr)
                self.assertFalse((nested / ".orca").exists())
                self.assertFalse((self.repo / ".orca").exists())

    def test_naming_the_nested_roots_ledger_explicitly_is_still_said(self):
        # Re-check of 4b24dfde (W5-03): `_routing_note` compared an explicit ledger with the NEAREST
        # root's default, so `--ledger .orca/egress.jsonl` (or the env var) from under a planted
        # `.git` wrote into that subdirectory with nothing on stderr, while the default refused.
        nested = self.repo / "vendor" / "x"
        nested.mkdir(parents=True)
        (nested / ".git").mkdir()
        for how in ("--ledger", "env"):
            with self.subTest(how=how):
                args = ("--ledger", ".orca/egress.jsonl", *self.WRITE) if how == "--ledger" else self.WRITE
                env = {**self.env, egress.PRIMARY_LEDGER_ENV: ".orca/egress.jsonl"} if how == "env" else self.env
                r = subprocess.run([sys.executable, str(EGRESS), *args], capture_output=True, text=True,
                                   cwd=nested, env=env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(f"receipt written to {nested / '.orca' / 'egress.jsonl'}", r.stderr)
                self.assertIn("no repository ledger", r.stderr)

    def test_a_real_git_worktree_inside_the_repository_is_a_linked_worktree(self):
        repo = Path(self.tmp) / "real"
        env = {**self.env, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}

        def git(*args):
            subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)

        repo.mkdir()
        git("init", "-q")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init")
        git("worktree", "add", "-q", str(repo / "wt"))
        r = self.bare(*self.WRITE, cwd=repo / "wt")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((repo / "wt" / ".orca" / "egress.jsonl").is_file())
        self.assertIn("linked worktree", r.stderr)


class TestDurability(EgressBase):
    """W5-06: the receipt was flushed, never fsynced, so the send could leave the machine while
    the receipt sat in the page cache."""

    def test_the_receipt_and_a_new_ledgers_directory_are_fsynced_before_returning(self):
        synced = []
        real_fsync = os.fsync

        def observed(fd):
            st = os.fstat(fd)
            synced.append((st.st_dev, st.st_ino))
            return real_fsync(fd)

        with patch.object(os, "fsync", observed):
            egress.write_receipt(self.ledger, "fixture", "fixture.invalid", "test", "fixture")
        for path in (self.ledger, self.ledger.parent):
            st = path.stat()
            with self.subTest(path=path):
                self.assertIn((st.st_dev, st.st_ino), synced, f"{path} was never fsynced")


class TestThePayloadIsStreamed(EgressBase):
    """W5-07: `--payload-file` was read whole into memory just to hash it, right before the send."""

    def test_a_payload_larger_than_one_read_is_hashed_without_reading_it_whole(self):
        payload = Path(self.tmp) / "body.bin"
        data = os.urandom(3 * (1 << 20) + 17)
        payload.write_bytes(data)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(Path, "read_bytes", side_effect=AssertionError("the payload was read whole")), \
                redirect_stderr(err), redirect_stdout(out):
            code = egress.main(["--ledger", str(self.ledger), "write", "--sink", "pr-open", "--host", "github.com",
                                "--payload-class", "pr-body", "--consent", "grant:pr-open",
                                "--payload-file", str(payload)])
        self.assertEqual(code, 0, err.getvalue())
        record = self.records()[0]
        self.assertEqual(record["payload_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(record["bytes"], len(data))


class TestAnchorAndAbbrevHardening(EgressBase):
    """#767 / #784 / #770: strict argparse (allow_abbrev=False), non-empty anchor validation,
    real 64-hex anchor counting in verify/grants, and W3-01 stdlib-shadow guard."""

    def test_abbreviated_options_are_refused(self):
        for args in (
            ("write", "--he"),
            ("write", "--h"),
            ("write", "--si", "s", "--ho", "h", "--pay", "c", "--con", "k"),
            ("verify", "--allow"),
            ("grants", "--j"),
        ):
            with self.subTest(args=args):
                r = self.run_egress(*args)
                self.assertEqual(r.returncode, egress.EXIT_USAGE, r.stdout + r.stderr)

    def test_empty_whitespace_or_malformed_anchors_exit_usage(self):
        self.write_one()
        for cmd in ("verify", "grants"):
            for flag in ("--expect-head", "--expect-ancestor"):
                for bad in ("", "   ", "\t", "not-a-sha256", "a" * 63, "g" * 64):
                    with self.subTest(cmd=cmd, flag=flag, bad=bad):
                        r = self.run_egress(cmd, flag, bad)
                        self.assertEqual(r.returncode, egress.EXIT_USAGE, r.stdout + r.stderr)

    def test_empty_ancestor_on_nonempty_ledger_stays_unanchored(self):
        self.write_one()
        v = self.run_egress("verify", "--expect-ancestor", "(empty)")
        self.assertEqual(v.returncode, 0, v.stderr)
        self.assertIn("UNANCHORED", v.stdout)
        self.assertNotIn("anchored receipt(s) present", v.stdout)
        g = self.run_egress("grants", "--expect-ancestor", "(empty)")
        self.assertEqual(g.returncode, 0, g.stderr)
        self.assertIn("UNANCHORED", g.stdout)
        g_json = self.run_egress("grants", "--json", "--expect-ancestor", "(empty)")
        self.assertEqual(g_json.returncode, 0, g_json.stderr)
        self.assertIn("UNANCHORED", g_json.stderr)
        # A real 64-hex ancestor anchor still reports anchored and suppresses UNANCHORED.
        head = self.run_egress("head").stdout.strip()
        v_real = self.run_egress("verify", "--expect-ancestor", head)
        self.assertEqual(v_real.returncode, 0, v_real.stderr)
        self.assertIn("anchored receipt(s) present", v_real.stdout)
        self.assertNotIn("UNANCHORED", v_real.stdout)
        g_real = self.run_egress("grants", "--expect-ancestor", head)
        self.assertEqual(g_real.returncode, 0, g_real.stderr)
        self.assertNotIn("UNANCHORED", g_real.stdout + g_real.stderr)

    def test_entrypoint_carries_w3_01_guard_and_blocks_stdlib_shadow(self):
        import ast
        from tests import test_entrypoint_guard as eg
        body = eg._statements("runtime/scripts/egress.py")
        self.assertGreaterEqual(len(body), 2)
        self.assertTrue(isinstance(body[0], ast.Import) and [a.name for a in body[0].names] == ["sys"])
        self.assertEqual(ast.dump(body[1]), ast.dump(ast.parse(eg.CANONICAL_GUARD).body[0]))
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            shutil.copy2(EGRESS, t / "egress.py")
            (t / "json.py").write_text("raise RuntimeError('shadow loaded')\n", encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
            r = subprocess.run([sys.executable, str(t / "egress.py"), "--help"],
                               cwd=t, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("shadow loaded", r.stderr)
