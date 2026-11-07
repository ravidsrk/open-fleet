#!/usr/bin/env python3
"""Contract tests for runtime/scripts/decisions.py.

Two properties carry the weight. First, the writer refuses what the log must
never hold: an unclassifiable decision, a pasted credential, or a one-way door
dressed as a mechanical auto-resolve. Second, the tally is deterministic —
two coordinators reading the same file must reach the same gate verdict.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

# Fetched branch names holding a line break (tests/fixtures/refname_breaks.py; W3-07 re-attack).
_rb_spec = importlib.util.spec_from_file_location(
    "refname_breaks", ROOT / "tests" / "fixtures" / "refname_breaks.py")
refname_breaks = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(refname_breaks)
DECISIONS = ROOT / "runtime" / "scripts" / "decisions.py"
DOORS = ROOT / "runtime" / "one-way-doors.json"

_spec = importlib.util.spec_from_file_location("decisions", DECISIONS)
decisions = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(decisions)


class DecisionsBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="decisions-")
        self.log = Path(self.tmp) / "docs" / "DECISIONS.md"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_dec(self, *args, log=None):
        return subprocess.run(
            [sys.executable, str(DECISIONS), "--file", str(log or self.log), *args],
            capture_output=True, text=True,
        )

    def append(self, ident, klass, answer, why, extra=()):
        return self.run_dec("append", "--id", ident, "--class", klass,
                            "--answer", answer, "--why", why, *extra)

    def seed(self, lines):
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text(
            "# DECISIONS\n\n`ts · gate-or-ask-id · class · answer · why · task_id?`\n\n"
            + "\n".join(lines) + "\n", encoding="utf-8")


class TestAppendValidation(DecisionsBase):
    def test_valid_mechanical_line_is_written(self):
        r = self.append("gate-7", "mechanical", "retry", "transient network error, repo precedent")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = self.log.read_text(encoding="utf-8")
        self.assertIn("gate-7", text)
        self.assertIn(" · mechanical · ", text)

    def test_line_format_is_the_ledger_contract_shape(self):
        self.append("gate-7", "taste", "option-b", "reversible, matches the surrounding API",
                    extra=("--task", "t-3", "--ts", "2026-09-10T09:00:00Z"))
        line = [ln for ln in self.log.read_text(encoding="utf-8").splitlines() if "gate-7" in ln][0]
        fields = [f.strip() for f in line.split("·")]
        self.assertEqual(len(fields), 6)
        self.assertEqual(fields[0], "2026-09-10T09:00:00Z")
        self.assertEqual(fields[2], "taste")
        self.assertEqual(fields[5], "t-3")

    def test_task_id_is_optional(self):
        self.append("gate-8", "mechanical", "yes", "one defensible answer")
        line = [ln for ln in self.log.read_text(encoding="utf-8").splitlines() if "gate-8" in ln][0]
        self.assertEqual(len([f for f in line.split("·")]), 5)

    def test_unknown_class_is_refused_by_the_parser(self):
        r = self.append("gate-9", "vibes", "yes", "because")
        self.assertEqual(r.returncode, 2)

    def test_empty_why_is_refused(self):
        r = self.append("gate-10", "mechanical", "yes", "")
        self.assertEqual(r.returncode, 1)
        self.assertIn("empty why", r.stderr)

    def test_empty_answer_is_refused(self):
        r = self.append("gate-11", "mechanical", "", "a reason")
        self.assertEqual(r.returncode, 1)

    def test_separator_inside_a_field_is_refused(self):
        r = self.append("gate-12", "mechanical", "a · b", "one record, one line")
        self.assertEqual(r.returncode, 1)
        self.assertIn("one record, one line", r.stderr)

    def test_newline_inside_a_field_is_refused(self):
        r = self.append("gate-13", "mechanical", "a\nb", "one record, one line")
        self.assertEqual(r.returncode, 1)

    def test_nothing_is_written_when_the_append_is_refused(self):
        self.append("gate-14", "mechanical", "yes", "fine")
        before = self.log.read_text(encoding="utf-8")
        self.append("gate-15", "mechanical", "yes", "")
        self.assertEqual(self.log.read_text(encoding="utf-8"), before)


class TestSecretScan(DecisionsBase):
    def test_aws_key_shape_is_refused(self):
        r = self.append("gate-20", "mechanical", "use it", "key AKIAABCDEFGHIJKLMNOP works")
        self.assertEqual(r.returncode, 1)
        self.assertIn("credential-shaped", r.stderr)

    def test_private_key_block_is_refused(self):
        r = self.append("gate-21", "mechanical", "ok", "-----BEGIN RSA PRIVATE KEY----- pasted here")
        self.assertEqual(r.returncode, 1)

    def test_assigned_secret_is_refused(self):
        r = self.append("gate-22", "mechanical", "ok", "set api_key=abcdefghijklmnop1234")
        self.assertEqual(r.returncode, 1)

    def test_the_refusal_never_echoes_the_value(self):
        secret = "AKIAABCDEFGHIJKLMNOP"
        r = self.append("gate-23", "mechanical", "use it", f"key {secret} works")
        self.assertNotIn(secret, r.stderr + r.stdout)

    def test_ordinary_prose_is_not_a_secret(self):
        r = self.append("gate-24", "mechanical", "retry", "the token bucket refilled, so retry once")
        self.assertEqual(r.returncode, 0, r.stderr)


class TestNeverGateMatchesThePolicy(unittest.TestCase):
    """The executable tuple and the sentence it implements cannot drift (PR #277 review).

    playbooks/risk-review.md named three NEVER_GATE lenses; decisions.py enforced two.
    Nothing failed — privacy simply became eligible to auto-gate off after ten quiet
    reviews, which is precisely the lens whose value is the miss it would catch. This
    test reads the policy sentence rather than restating it, so the next edit to either
    side has to move both.
    """

    def test_the_tuple_is_exactly_what_the_playbook_declares(self):
        text = (ROOT / "playbooks" / "risk-review.md").read_text(encoding="utf-8")
        m = re.search(r"([a-z,\s\-]+?)\s+are NEVER_GATE", text)
        self.assertIsNotNone(m, "risk-review.md no longer declares a NEVER_GATE list")
        declared = {
            w.strip() for w in m.group(1).replace(" and ", ",").replace("\n", " ").split(",")
            if w.strip()
        }
        self.assertEqual(
            declared, set(decisions.NEVER_GATE),
            f"risk-review.md declares {sorted(declared)} NEVER_GATE, decisions.py enforces "
            f"{sorted(decisions.NEVER_GATE)}",
        )

    def test_a_never_gate_lens_never_gates_off(self):
        # The behavioural property is exercised per lens in TestTally
        # (test_no_never_gate_lens_gates_off) — a membership re-assertion here
        # would prove nothing (the loop it replaces was tautological, #381).
        self.assertIn("privacy", decisions.NEVER_GATE)


class TestOneWayNet(DecisionsBase):
    def test_a_net_match_classed_mechanical_is_refused(self):
        r = self.append("gate-30", "mechanical", "yes", "we should rotate the credentials now")
        self.assertEqual(r.returncode, 1)
        self.assertIn("one-way net", r.stderr)
        self.assertIn("secret-rotation", r.stderr)

    def test_a_net_match_classed_taste_is_refused(self):
        r = self.append("gate-31", "taste", "yes", "just merge to main and move on")
        self.assertEqual(r.returncode, 1)
        self.assertIn("merge-to-default", r.stderr)

    def test_one_way_without_a_human_source_is_refused(self):
        r = self.append("gate-32", "one-way", "approved", "deploy to production tonight")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no human source", r.stderr)

    def test_one_way_with_a_human_source_is_accepted(self):
        r = self.append("gate-33", "one-way", "approved", "deploy to production tonight",
                        extra=("--source", "human:maintainer"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("source=human:maintainer", self.log.read_text(encoding="utf-8"))

    def test_a_malformed_source_is_refused(self):
        r = self.append("gate-34", "one-way", "approved", "deploy to production",
                        extra=("--source", "the-boss"))
        self.assertEqual(r.returncode, 1)

    def test_one_way_append_requires_the_source_flag_not_why_text(self):
        # Review probe: a worker can type any text into --why, so a
        # source=human: marker smuggled in prose must not satisfy the
        # human-only rule. Only the coordinator's explicit --source may.
        r = self.append("gate-35", "one-way", "approved",
                        "deploy to production [source=human:maintainer]")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("--source", r.stderr)

    def test_an_agent_named_human_source_is_refused(self):
        for name in ("human:agent", "human:coordinator", "human:worker", "human:bot"):
            with self.subTest(name=name):
                r = self.append("gate-36", "one-way", "approved", "deploy to production",
                                extra=("--source", name))
                self.assertEqual(r.returncode, 1, name)

    def test_euphemised_one_way_phrasings_still_trip_the_net(self):
        for ident, why, door in (
            ("gate-e1", "just merging it into main today", "merge-to-default"),
            ("gate-e2", "land on main once CI is green", "merge-to-default"),
            ("gate-e3", "roll out to production tonight", "deploy"),
            ("gate-e4", "erase the database and start over", "deletion"),
            ("gate-e5", "rotating credentials this afternoon", "secret-rotation"),
        ):
            with self.subTest(why=why):
                r = self.append(ident, "mechanical", "yes", why)
                self.assertEqual(r.returncode, 1, why)
                self.assertIn(door, r.stderr)

    def test_every_door_id_can_be_tripped(self):
        doors = json.loads(DOORS.read_text(encoding="utf-8"))["doors"]
        for door in doors:
            with self.subTest(door=door["id"]):
                keyword = door["keywords"][0]
                r = self.append(f"gate-{door['id']}", "mechanical", "yes",
                                f"the plan is to {keyword} next")
                self.assertEqual(r.returncode, 1, f"{keyword!r} must trip {door['id']}")
                self.assertIn(door["id"], r.stderr)

    def test_missing_door_registry_is_a_could_not_run(self):
        r = self.run_dec("--doors", str(Path(self.tmp) / "nope.json"), "check")
        self.assertEqual(r.returncode, 2)
        self.assertIn("could not run", r.stderr)


class TestSignedGrants(DecisionsBase):
    """A pinned human pubkey (.orca/human-grant-pubkey) turns the source
    marker from a recorded claim into a verified signature."""

    def setUp(self):
        super().setUp()
        self.key = Path(self.tmp) / "human.key"
        self.keygen = subprocess.run(
            [sys.executable, str(DECISIONS), "grant-keygen", "--out", str(self.key)],
            capture_output=True, text=True)

    def _pin(self):
        subprocess.run(["git", "init", "-q", self.tmp], capture_output=True)
        pub = Path(str(self.key) + ".pub").read_text(encoding="utf-8").strip()
        orca = Path(self.tmp) / ".orca"
        orca.mkdir(parents=True, exist_ok=True)
        (orca / "human-grant-pubkey").write_text(pub + "\n", encoding="utf-8")

    # Payload v2 binds the line's ts (2026-10-23 review, P2-3): the signer and the
    # appender name the same stamp.
    SIGNED_TS = "2026-09-10T09:00:00Z"

    def _sign(self, ident="gate-s1", answer="approved", why="deploy to production",
              extra=()):
        return subprocess.run(
            [sys.executable, str(DECISIONS), "sign-grant", "--key", str(self.key),
             "--id", ident, "--answer", answer, "--why", why, "--ts", self.SIGNED_TS, *extra],
            capture_output=True, text=True)

    def test_keygen_writes_a_seed_and_a_pubkey_outside_the_repo(self):
        self.assertEqual(self.keygen.returncode, 0, self.keygen.stderr)
        self.assertRegex(Path(str(self.key) + ".pub").read_text().strip(), r"^[0-9a-f]{64}$")
        import stat
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600,
                         "the seed is a private key and must be owner-only")

    def test_keygen_refuses_a_seed_inside_this_repo(self):
        inside = ROOT / "grant-key-refusal-probe"
        self.assertFalse(inside.exists())
        try:
            r = subprocess.run(
                [sys.executable, str(DECISIONS), "grant-keygen", "--out", str(inside)],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("inside a git work tree", r.stderr)
            self.assertFalse(inside.exists())
            r = subprocess.run(
                [sys.executable, str(DECISIONS), "grant-keygen", "--out", str(inside),
                 "--in-repo-ok"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(inside.exists())
        finally:
            inside.unlink(missing_ok=True)
            Path(str(inside) + ".pub").unlink(missing_ok=True)

    def test_keygen_refuses_a_seed_inside_an_unrelated_repo(self):
        # PR #546 review (round 2): checking only this script's own repo let a
        # seed land committable in any other checkout on the machine.
        other = Path(self.tmp) / "other-repo"
        other.mkdir()
        subprocess.run(["git", "init", "-q", str(other)], capture_output=True)
        target = other / "human.key"
        r = subprocess.run(
            [sys.executable, str(DECISIONS), "grant-keygen", "--out", str(target)],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("inside a git work tree", r.stderr)
        self.assertFalse(target.exists())

    def test_a_key_beside_the_log_never_overrides_the_root_pin(self):
        # PR #546 review (P1): the first ancestor key won, so a worker could
        # pin its own key at docs/.orca and sign its own grants. Only the
        # repository-root pin may count.
        rogue_key = Path(self.tmp) / "rogue.key"
        subprocess.run([sys.executable, str(DECISIONS), "grant-keygen",
                        "--out", str(rogue_key)], capture_output=True, text=True)
        rogue_pub = Path(str(rogue_key) + ".pub").read_text(encoding="utf-8")
        self._pin()
        beside = self.log.parent / ".orca"
        beside.mkdir(parents=True, exist_ok=True)
        (beside / "human-grant-pubkey").write_text(rogue_pub, encoding="utf-8")
        sig = subprocess.run(
            [sys.executable, str(DECISIONS), "sign-grant", "--key", str(rogue_key),
             "--id", "gate-s1", "--answer", "approved", "--why", "deploy to production"],
            capture_output=True, text=True)
        self.assertEqual(sig.returncode, 0, sig.stderr)
        r = self.append("gate-s1", "one-way", "approved", "deploy to production",
                        extra=("--source", "human:lia", "--grant-sig", sig.stdout.strip()))
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_an_embedded_signature_on_a_non_one_way_line_is_refused(self):
        why = f"routine [source=human:lia sig={'a' * 128}]"
        r = self.append("gate-s2", "taste", "yes", why,
                        extra=("--source", "human:lia"))
        self.assertEqual(r.returncode, 1)

    def test_a_pinned_key_makes_an_unsigned_one_way_append_refuse(self):
        self._pin()
        r = self.append("gate-s1", "one-way", "approved", "deploy to production",
                        extra=("--source", "human:lia"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("grant", r.stderr.lower())

    def test_a_signed_grant_appends_checks_and_tamper_fails(self):
        self._pin()
        sig = self._sign()
        self.assertEqual(sig.returncode, 0, sig.stderr)
        r = self.append("gate-s1", "one-way", "approved", "deploy to production",
                        extra=("--source", "human:lia", "--grant-sig", sig.stdout.strip(),
                               "--ts", self.SIGNED_TS))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sig=", self.log.read_text(encoding="utf-8"))
        self.assertEqual(self.run_dec("check").returncode, 0)
        text = self.log.read_text(encoding="utf-8").replace(
            "· approved ·", "· rejected ·")
        self.log.write_text(text, encoding="utf-8")
        bad = self.run_dec("check")
        self.assertEqual(bad.returncode, 1)
        self.assertIn("signature", bad.stderr.lower())

    def test_a_signature_for_other_content_is_refused(self):
        self._pin()
        sig = self._sign(why="deploy to production")
        r = self.append("gate-s1", "one-way", "approved", "merge to main",
                        extra=("--source", "human:lia", "--grant-sig", sig.stdout.strip()))
        self.assertEqual(r.returncode, 1)

    def test_without_a_pin_a_grant_sig_fails_closed(self):
        sig = self._sign()
        self.assertEqual(sig.returncode, 0, sig.stderr)
        r = self.append("gate-s1", "one-way", "approved", "deploy to production",
                        extra=("--source", "human:lia", "--grant-sig", sig.stdout.strip()))
        self.assertEqual(r.returncode, 1)
        self.assertIn("pubkey", r.stderr.lower())


class TestActive(DecisionsBase):
    def test_newest_line_for_an_id_wins(self):
        self.seed([
            "2026-09-01T00:00:00Z · gate-1 · taste · option-a · first pass · t-1",
            "2026-09-02T00:00:00Z · gate-1 · taste · option-b · reconsidered after review · t-1",
        ])
        r = self.run_dec("active")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("option-b", r.stdout)
        self.assertNotIn("option-a", r.stdout)

    def test_an_out_of_order_line_does_not_become_the_active_one(self):
        # #318: "newest per id wins" resolved by FILE POSITION, never comparing ts. Any merge,
        # reorder or out-of-order append silently changed which decision was live — and a ledger
        # whose ordering guarantee is "whoever wrote last" is not a ledger.
        self.seed([
            "2026-09-02T00:00:00Z · gate-9 · taste · option-b · reconsidered · t-1",
            "2026-09-01T00:00:00Z · gate-9 · taste · option-a · first pass · t-1",
        ])
        r = self.run_dec("active")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("option-b", r.stdout, "the older line won on position alone")
        self.assertNotIn("option-a", r.stdout)

    def test_a_timezone_offset_is_compared_as_an_instant_not_as_text(self):
        # PR #308 review, P1. TS_PREFIX accepts anything starting with a date, so a record can
        # carry an offset — and `2026-09-11T01:00:00+05:00` IS `2026-09-10T20:00:00Z`, earlier
        # than `2026-09-11T00:00:00Z`. Compared as text it sorted later and the OLDER decision won.
        self.seed([
            "2026-09-11T01:00:00+05:00 · gate-12 · taste · option-old · = 2026-09-10T20:00Z · t-1",
            "2026-09-11T00:00:00Z · gate-12 · taste · option-new · genuinely later · t-1",
        ])
        r = self.run_dec("active")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("option-new", r.stdout, "an offset stamp beat a genuinely later UTC one")
        self.assertNotIn("option-old", r.stdout)

    def test_a_date_only_stamp_sorts_before_the_same_days_timed_ones(self):
        self.seed([
            "2026-09-11T00:00:01Z · gate-13 · taste · option-timed · one second in · t-1",
            "2026-09-11 · gate-13 · taste · option-dateonly · midnight · t-1",
        ])
        r = self.run_dec("active")
        self.assertIn("option-timed", r.stdout, r.stdout)

    def test_an_unreadable_stamp_never_displaces_a_readable_one(self):
        self.seed([
            "2026-09-01T00:00:00Z · gate-14 · taste · option-real · dated · t-1",
            "2026-13-45nonsense · gate-14 · taste · option-junk · unparseable · t-1",
        ])
        r = self.run_dec("active")
        self.assertIn("option-real", r.stdout, f"a junk stamp won on position: {r.stdout}")

    def test_identical_timestamps_fall_back_to_file_order(self):
        # Ties are real: two decisions can share a timestamp. Position is the tiebreak, which is
        # the old behaviour preserved exactly where it is the only information available.
        self.seed([
            "2026-09-01T00:00:00Z · gate-10 · taste · option-a · first · t-1",
            "2026-09-01T00:00:00Z · gate-10 · taste · option-b · second · t-1",
        ])
        r = self.run_dec("active")
        self.assertIn("option-b", r.stdout)
        self.assertNotIn("option-a", r.stdout)

    def test_an_out_of_order_supersede_still_retires_the_id(self):
        self.seed([
            "2026-09-02T00:00:00Z · gate-11 · taste · superseded · dropped · t-1",
            "2026-09-01T00:00:00Z · gate-11 · taste · option-a · first pass · t-1",
        ])
        r = self.run_dec("active")
        self.assertNotIn("gate-11", r.stdout)

    def test_superseded_answer_retires_the_id(self):
        self.seed([
            "2026-09-01T00:00:00Z · gate-2 · taste · option-a · first pass · t-1",
            "2026-09-02T00:00:00Z · gate-2 · taste · superseded · the unit was dropped · t-1",
        ])
        r = self.run_dec("active")
        self.assertNotIn("gate-2", r.stdout)

    def test_distinct_ids_all_stay_active(self):
        self.seed([
            "2026-09-01T00:00:00Z · gate-3 · taste · a · why one · t-1",
            "2026-09-01T00:00:01Z · gate-4 · taste · b · why two · t-2",
        ])
        r = self.run_dec("active", "--json")
        self.assertEqual(len(json.loads(r.stdout)), 2)

    def test_prose_and_the_format_legend_are_not_records(self):
        self.seed(["2026-09-01T00:00:00Z · gate-5 · taste · a · why · t-1"])
        r = self.run_dec("active", "--json")
        rows = json.loads(r.stdout)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "gate-5")

    def test_missing_log_is_an_empty_active_set(self):
        r = self.run_dec("active")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "")


class TestTally(DecisionsBase):
    def _zeros(self, lens, n, then=None):
        lines = [f"2026-09-{i + 1:02d}T00:00:00Z · lens-tally:{lens} · mechanical · 0 · "
                 f"dispatch {i} found nothing · t-{i}" for i in range(n)]
        if then is not None:
            lines.append(f"2026-09-30T00:00:00Z · lens-tally:{lens} · mechanical · {then} · "
                         f"final dispatch · t-x")
        self.seed(lines)

    def test_zero_streak_is_counted_newest_first(self):
        self._zeros("a11y", 4)
        r = self.run_dec("tally", "--lens", "a11y", "--json")
        data = json.loads(r.stdout)
        self.assertEqual(data["zero_streak"], 4)
        self.assertEqual(data["dispatches"], 4)

    def test_a_nonzero_dispatch_resets_the_streak(self):
        self._zeros("a11y", 12, then="3")
        data = json.loads(self.run_dec("tally", "--lens", "a11y", "--json").stdout)
        self.assertEqual(data["zero_streak"], 0)
        self.assertFalse(data["may_gate_off"])

    def test_ten_zeros_earns_the_auto_gate_off(self):
        self._zeros("a11y", 10)
        data = json.loads(self.run_dec("tally", "--lens", "a11y", "--json").stdout)
        self.assertTrue(data["may_gate_off"])

    def test_nine_zeros_does_not(self):
        self._zeros("a11y", 9)
        data = json.loads(self.run_dec("tally", "--lens", "a11y", "--json").stdout)
        self.assertFalse(data["may_gate_off"])

    def test_security_never_gates_off(self):
        self._zeros("security", 40)
        data = json.loads(self.run_dec("tally", "--lens", "security", "--json").stdout)
        self.assertTrue(data["never_gate"])
        self.assertFalse(data["may_gate_off"], "the value of the security lens is the miss it catches")

    def test_data_migration_never_gates_off(self):
        self._zeros("data-migration", 40)
        data = json.loads(self.run_dec("tally", "--lens", "data-migration", "--json").stdout)
        self.assertFalse(data["may_gate_off"])

    def test_no_never_gate_lens_gates_off(self):
        # The behavioural property over the whole tuple, not two named lenses (#381): a lens the
        # registry adds later inherits the refusal without anyone remembering a test.
        for lens in decisions.NEVER_GATE:
            with self.subTest(lens=lens):
                self._zeros(lens, 40)
                data = json.loads(self.run_dec("tally", "--lens", lens, "--json").stdout)
                self.assertTrue(data["never_gate"])
                self.assertFalse(data["may_gate_off"])

    def test_an_unknown_lens_reads_as_zero_dispatches(self):
        self._zeros("a11y", 3)
        data = json.loads(self.run_dec("tally", "--lens", "perf", "--json").stdout)
        self.assertEqual(data["dispatches"], 0)
        self.assertFalse(data["may_gate_off"])

    def test_appended_tallies_are_readable_by_tally(self):
        for i in range(3):
            self.append("lens-tally:perf", "mechanical", "0", f"dispatch {i} clean")
        data = json.loads(self.run_dec("tally", "--lens", "perf", "--json").stdout)
        self.assertEqual(data["zero_streak"], 3)

    def test_human_readable_tally_names_the_verdict(self):
        self._zeros("a11y", 10)
        r = self.run_dec("tally", "--lens", "a11y")
        self.assertIn("zero_streak=10", r.stdout)
        self.assertIn("auto-gate off", r.stdout)


class TestCheck(DecisionsBase):
    def test_a_clean_log_passes(self):
        self.seed([
            "2026-09-01T00:00:00Z · gate-1 · mechanical · retry · transient failure · t-1",
            "2026-09-02T00:00:00Z · gate-2 · one-way · approved · deploy to production "
            "[source=human:maintainer] · t-2",
        ])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 record(s) valid", r.stdout)

    def test_a_human_source_outside_the_why_suffix_fails(self):
        # The marker counts only as the canonical suffix of the why field
        # the writer emits. The same text in the answer field is smuggled
        # prose, not a recorded grant.
        self.seed(["2026-09-01T00:00:00Z · gate-9 · one-way · approved source=human:lia · "
                   "deploy to production · t-1"])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("human source", r.stderr)

    def test_a_mis_classified_one_way_line_fails(self):
        self.seed(["2026-09-01T00:00:00Z · gate-1 · mechanical · yes · rotate the secret today · t-1"])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("secret-rotation", r.stderr)

    def test_the_failure_names_the_line_number(self):
        self.seed([
            "2026-09-01T00:00:00Z · gate-1 · mechanical · yes · fine · t-1",
            "2026-09-02T00:00:00Z · gate-2 · nonsense · yes · fine · t-2",
        ])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 1)
        self.assertRegex(r.stderr, r"DECISIONS\.md:\d+:")

    def test_an_empty_log_passes(self):
        self.seed([])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 0)

    def test_help_exits_zero(self):
        r = subprocess.run([sys.executable, str(DECISIONS), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        for sub in ("append", "active", "tally", "check"):
            self.assertIn(sub, r.stdout)


class TestCheckSince(DecisionsBase):
    """2026-10-26 review: `check` had no CI caller because the repository's own ledger carries
    records from before the human-source and class rules. `--since` draws that line: earlier
    records are counted, every later record is judged."""

    OLD_BAD = "2026-09-01T00:00:00Z · gate-old · one-way · approved · deploy to production · t-1"
    NEW_GOOD = ("2026-09-30T00:00:00Z · gate-new · one-way · approved · deploy to production "
                "[source=human:lia] · t-2")
    NEW_BAD = "2026-10-01T00:00:00Z · gate-newer · mechanical · yes · rotate the secret today · t-3"

    def test_records_before_the_fence_are_counted_not_judged(self):
        self.seed([self.OLD_BAD, self.NEW_GOOD])
        self.assertEqual(self.run_dec("check").returncode, 1, "the fence is opt-in")
        r = self.run_dec("check", "--since", "2026-09-24")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 record(s) valid", r.stdout)
        self.assertIn("1 earlier record(s) before 2026-09-24 not re-checked", r.stdout)

    def test_a_record_after_the_fence_still_fails(self):
        self.seed([self.OLD_BAD, self.NEW_BAD])
        r = self.run_dec("check", "--since", "2026-09-24")
        self.assertEqual(r.returncode, 1)
        self.assertIn("secret-rotation", r.stderr)
        self.assertNotIn("gate-old", r.stderr)

    def test_an_unreadable_stamp_is_judged_never_skipped_as_history(self):
        # PR #707 review: _instant() sorts an unreadable stamp before everything, so a malformed
        # recent record read as pre-fence history and skipped every check.
        bad = ("2026-10-26T99:99:99Z · gate-bad · one-way · approved · deploy to production · t-4")
        self.seed([self.NEW_GOOD, bad])
        r = self.run_dec("check", "--since", "2026-09-24")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("not a readable timestamp", r.stderr)
        self.assertIn("no human source", r.stderr)

    def test_a_malformed_fence_is_could_not_run(self):
        self.seed([self.NEW_GOOD])
        r = self.run_dec("check", "--since", "yesterday")
        self.assertEqual(r.returncode, 2, r.stdout)


class TestScriptShape(unittest.TestCase):
    def test_executable_and_shebanged(self):
        self.assertTrue(os.access(DECISIONS, os.X_OK))
        self.assertTrue(DECISIONS.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3"))

    def test_default_log_path_is_the_ledger_contract_path(self):
        self.assertIn('DEFAULT_LOG = "docs/DECISIONS.md"', DECISIONS.read_text(encoding="utf-8"))


class DecisionsInProcBase(DecisionsBase):
    """Drive decisions.main() in-process: same argv, same assertions, no fork.

    The classes above prove the CLI over subprocess; these prove the same
    behavior calling main() directly, which is also what lets the coverage
    floor (CONSTRAINTS.md D9) observe the module instead of a child process.
    """

    def run_main(self, *args, log=None):
        argv = ["--file", str(log or self.log), *args]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = decisions.main(argv)
        return code, out.getvalue(), err.getvalue()


class TestParseLineUnits(unittest.TestCase):
    def test_format_then_parse_round_trips_all_fields(self):
        line = decisions.format_line("2026-09-10T09:00:00Z", "gate-7", "taste",
                                     "option-b", "reversible", "t-3")
        record = decisions.parse_line(line)
        self.assertEqual(record["ts"], "2026-09-10T09:00:00Z")
        self.assertEqual(record["id"], "gate-7")
        self.assertEqual(record["class"], "taste")
        self.assertEqual(record["answer"], "option-b")
        self.assertEqual(record["why"], "reversible")
        self.assertEqual(record["task_id"], "t-3")

    def test_missing_task_id_reads_as_empty(self):
        record = decisions.parse_line(
            decisions.format_line("2026-09-10T09:00:00Z", "g", "mechanical", "yes", "why"))
        self.assertEqual(record["task_id"], "")

    def test_the_format_legend_is_not_a_record(self):
        self.assertIsNone(decisions.parse_line(
            "`ts · gate-or-ask-id · class · answer · why · task_id?`"))

    def test_prose_and_short_lines_are_not_records(self):
        for line in ("# DECISIONS", "", "just a sentence", "2026-09-10 · only-two",
                     "- a bullet without a date · x · y · z · w"):
            with self.subTest(line=line):
                self.assertIsNone(decisions.parse_line(line))

    def test_a_backticked_stamp_is_unwrapped(self):
        record = decisions.parse_line("`2026-09-10T09:00:00Z` · g · mechanical · yes · why · t-1")
        self.assertIsNotNone(record)
        self.assertEqual(record["ts"], "2026-09-10T09:00:00Z")

    def test_a_leading_bullet_is_stripped(self):
        record = decisions.parse_line("- 2026-09-10T09:00:00Z · g · mechanical · yes · why · t-1")
        self.assertIsNotNone(record)
        self.assertEqual(record["id"], "g")

    def test_extra_separators_fold_into_why_with_the_last_as_task(self):
        record = decisions.parse_line(
            "2026-09-10T09:00:00Z · g · mechanical · yes · first part · second part · t-9")
        self.assertIsNotNone(record)
        self.assertIn("first part", record["why"])
        self.assertIn("second part", record["why"])
        self.assertEqual(record["task_id"], "t-9")


class TestValidateUnits(unittest.TestCase):
    def _record(self, ident="g", klass="mechanical", answer="yes", why="a reason"):
        return decisions.parse_line(
            decisions.format_line("2026-09-10T09:00:00Z", ident, klass, answer, why, "t-1"))

    def test_a_clean_record_has_no_problems(self):
        self.assertEqual(decisions.validate(self._record(), []), [])

    def test_empty_id_answer_and_why_are_each_reported(self):
        self.assertTrue(any("empty gate-or-ask id" in p
                            for p in decisions.validate(self._record(ident=""), [])))
        self.assertTrue(any("empty answer" in p
                            for p in decisions.validate(self._record(answer=""), [])))
        self.assertTrue(any("empty why" in p
                            for p in decisions.validate(self._record(why=""), [])))

    def test_an_unknown_class_is_reported(self):
        problems = decisions.validate(self._record(klass="vibes"), [])
        self.assertTrue(any("vibes" in p and "mechanical" in p for p in problems))

    def test_every_secret_shape_is_named_never_echoed(self):
        # Halves, never the contiguous literal: this file is committed, and the
        # secret scan reads committed bytes. Each half is inert; the joined
        # runtime string is what the shape matcher sees.
        shapes = {
            "aws-access-key": ("AKIA", "IOSFODNN7EXAMPLE"),
            "github-token": ("ghp_", "abcdefghij1234567890"),
            "slack-token": ("xoxb-", "123456789012"),
            "private-key-block": ("-----BEGIN RSA PRIVATE ", "KEY-----"),
            "bearer-literal": ("Bearer ", "abcdefghij1234567890"),
            "provider-secret-key": ("sk-", "abcdefghij1234567890"),
            "assigned-secret": ("api" + "_key", "=" + "abcdefghijklmnop1234"),
        }
        for name, (left, right) in shapes.items():
            with self.subTest(shape=name):
                value = left + right
                problems = decisions.validate(self._record(why=f"pasted {value} here"), [])
                hit = [p for p in problems if "credential-shaped" in p]
                self.assertEqual(len(hit), 1, f"{name} was not refused: {problems}")
                self.assertIn(name, hit[0])
                self.assertNotIn(value, hit[0])

    def test_secret_hits_are_sorted_shape_names(self):
        value = "AKIA" + "IOSFODNN7EXAMPLE"
        self.assertEqual(decisions.secret_hits(f"key {value} here"), ["aws-access-key"])
        self.assertEqual(decisions.secret_hits("the token bucket refilled"), [])

    def test_a_net_match_classed_mechanical_names_the_door(self):
        net = decisions.load_doors()
        self.assertTrue(net, "the default door registry loaded empty")
        door_id = net[0][0]
        keyword = next(kw for did, kw in net if did == door_id)
        problems = decisions.validate(
            self._record(why=f"the plan is to {keyword} next"), net)
        self.assertTrue(any(door_id in p and "one-way net" in p for p in problems), problems)

    def test_a_net_match_classed_one_way_with_source_is_clean(self):
        net = decisions.load_doors()
        keyword = net[0][1]
        record = self._record(klass="one-way", answer="approved",
                              why=f"we will {keyword} [source=human:maintainer]")
        self.assertEqual(decisions.validate(record, net), [])

    def test_one_way_without_a_human_source_is_reported(self):
        problems = decisions.validate(
            self._record(klass="one-way", answer="approved", why="a plain reason"), [])
        self.assertTrue(any("no human source" in p for p in problems), problems)

    def test_door_hits_fold_case_and_sort(self):
        net = [("b-door", "alpha"), ("a-door", "beta")]
        self.assertEqual(decisions.door_hits("ALPHA and  beta", net), ["a-door", "b-door"])
        self.assertEqual(decisions.door_hits("nothing relevant", net), [])

    def test_fold_collapses_whitespace_and_case(self):
        self.assertEqual(decisions.fold("  Merge\n\tTo   MAIN "), "merge to main")


class TestOrderingUnits(unittest.TestCase):
    def test_z_suffix_and_lowercase_z_read_as_utc(self):
        upper = decisions._instant("2026-09-11T00:00:00Z")
        lower = decisions._instant("2026-09-11T00:00:00z")
        self.assertEqual(upper, lower)
        self.assertIsNotNone(upper.tzinfo)

    def test_an_offset_is_compared_as_an_instant(self):
        offset = decisions._instant("2026-09-11T01:00:00+05:00")
        utc = decisions._instant("2026-09-11T00:00:00Z")
        self.assertLess(offset, utc)

    def test_a_naive_stamp_is_read_as_utc(self):
        moment = decisions._instant("2026-09-11")
        self.assertIsNotNone(moment.tzinfo)
        self.assertEqual(moment, decisions._instant("2026-09-11T00:00:00Z"))

    def test_an_unparseable_stamp_sorts_before_everything(self):
        self.assertEqual(decisions._instant("2026-13-45nonsense"), decisions._UNDATED)
        self.assertEqual(decisions._instant(""), decisions._UNDATED)

    def test_recency_breaks_timestamp_ties_by_position(self):
        record = {"ts": "2026-09-01T00:00:00Z"}
        self.assertLess(decisions.recency(record, 0), decisions.recency(record, 1))

    def test_active_prefers_newest_by_instant_not_position(self):
        def rec(ts, answer):
            return {"ts": ts, "id": "g", "answer": answer}
        rows = decisions.active([rec("2026-09-02T00:00:00Z", "new"),
                                 rec("2026-09-01T00:00:00Z", "old")])
        self.assertEqual([r["answer"] for r in rows], ["new"])

    def test_active_retires_a_mixed_case_superseded(self):
        def rec(ts, answer):
            return {"ts": ts, "id": "g", "answer": answer}
        rows = decisions.active([rec("2026-09-01T00:00:00Z", "option-a"),
                                 rec("2026-09-02T00:00:00Z", "Superseded")])
        self.assertEqual(rows, [])

    def test_tally_counts_only_the_trailing_zero_run(self):
        def rec(day, answer):
            return {"ts": f"2026-09-{day:02d}T00:00:00Z", "id": "lens-tally:perf",
                    "answer": answer}
        rows = [rec(1, "0"), rec(2, "2"), rec(3, "0"), rec(4, "00")]
        result = decisions.tally(rows, "perf")
        self.assertEqual(result["dispatches"], 4)
        self.assertEqual(result["zero_streak"], 2)
        self.assertFalse(result["never_gate"])
        self.assertFalse(result["may_gate_off"])

    def test_tally_gates_off_at_ten_for_a_gating_lens(self):
        rows = [{"ts": f"2026-09-{d:02d}T00:00:00Z", "id": "lens-tally:a11y", "answer": "0"}
                for d in range(1, 11)]
        result = decisions.tally(rows, "a11y")
        self.assertTrue(result["may_gate_off"])
        self.assertEqual(decisions.tally(rows, "security")["dispatches"], 0)


class TestLoadDoorsUnits(unittest.TestCase):
    def test_the_default_registry_loads_a_nonempty_net(self):
        net = decisions.load_doors()
        self.assertTrue(net)
        door_ids = {did for did, _kw in net}
        declared = {d["id"] for d in json.loads(DOORS.read_text(encoding="utf-8"))["doors"]}
        self.assertEqual(door_ids, declared)

    def test_an_explicit_registry_path_is_honored(self):
        with tempfile.TemporaryDirectory(prefix="doors-") as tmp:
            reg = Path(tmp) / "doors.json"
            reg.write_text(json.dumps({"doors": [{"id": "d", "keywords": ["Kw"]}]}),
                           encoding="utf-8")
            self.assertEqual(decisions.load_doors(str(reg)), [("d", "kw")])

    def test_a_missing_registry_is_a_could_not_run(self):
        with self.assertRaises(decisions.DecisionsError):
            decisions.load_doors("/nonexistent/doors.json")

    def test_invalid_json_is_a_could_not_run(self):
        with tempfile.TemporaryDirectory(prefix="doors-") as tmp:
            reg = Path(tmp) / "doors.json"
            reg.write_text("{nope", encoding="utf-8")
            with self.assertRaises(decisions.DecisionsError):
                decisions.load_doors(str(reg))

    def test_a_registry_with_no_doors_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="doors-") as tmp:
            reg = Path(tmp) / "doors.json"
            reg.write_text(json.dumps({"doors": []}), encoding="utf-8")
            with self.assertRaises(decisions.DecisionsError):
                decisions.load_doors(str(reg))

    def test_a_door_without_a_keyword_net_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="doors-") as tmp:
            reg = Path(tmp) / "doors.json"
            for bad in ({"id": "d"}, {"id": "d", "keywords": []}, {"keywords": ["x"]}):
                reg.write_text(json.dumps({"doors": [bad]}), encoding="utf-8")
                with self.subTest(door=bad), self.assertRaises(decisions.DecisionsError):
                    decisions.load_doors(str(reg))


class TestMainInProc(DecisionsInProcBase):
    def test_append_writes_the_header_once_then_the_line(self):
        code, out, err = self.run_main("append", "--id", "g-1", "--class", "mechanical",
                                       "--answer", "yes", "--why", "one defensible answer",
                                       "--ts", "2026-09-10T09:00:00Z")
        self.assertEqual(code, 0, err)
        text = self.log.read_text(encoding="utf-8")
        self.assertEqual(text.count("# DECISIONS"), 1)
        self.assertIn("2026-09-10T09:00:00Z · g-1 · mechanical · yes", out)
        self.run_main("append", "--id", "g-2", "--class", "taste",
                      "--answer", "b", "--why", "reversible")
        self.assertEqual(self.log.read_text(encoding="utf-8").count("# DECISIONS"), 1)

    def test_append_adds_the_source_marker_once(self):
        code, _out, err = self.run_main(
            "append", "--id", "g-3", "--class", "one-way", "--answer", "approved",
            "--why", "deploy [source=human:lia]", "--source", "human:lia")
        self.assertEqual(code, 0, err)
        text = self.log.read_text(encoding="utf-8")
        self.assertEqual(text.count("source=human:lia"), 1)

    def test_append_refuses_a_malformed_source(self):
        code, _out, err = self.run_main(
            "append", "--id", "g-4", "--class", "one-way", "--answer", "approved",
            "--why", "deploy", "--source", "lia")
        self.assertEqual(code, 1)
        self.assertIn("--source must be shaped human:<name>", err)

    def test_append_refuses_a_separator_or_newline_in_any_field(self):
        for field, value in (("--id", "a · b"), ("--answer", "a\nb"),
                             ("--why", "has · sep"), ("--task", "t\n1")):
            with self.subTest(field=field):
                code, _out, err = self.run_main(
                    "append", "--id", "g", "--class", "mechanical",
                    "--answer", "yes", "--why", "why", field, value)
                self.assertEqual(code, 1)
                self.assertIn("one record, one line", err)

    def test_append_refuses_an_undated_line_as_unparseable(self):
        code, _out, err = self.run_main(
            "append", "--id", "g", "--class", "mechanical", "--answer", "yes",
            "--why", "why", "--ts", "not-a-date")
        self.assertEqual(code, 1)
        self.assertIn("unparseable", err)

    def test_append_refuses_and_names_a_validation_failure(self):
        code, _out, err = self.run_main(
            "append", "--id", "g", "--class", "mechanical", "--answer", "yes", "--why", "")
        self.assertEqual(code, 1)
        self.assertIn("refused", err)
        self.assertIn("empty why", err)

    def test_append_below_a_regular_file_is_a_could_not_run(self):
        blocker = Path(self.tmp) / "blocker"
        blocker.write_text("a file, not a directory", encoding="utf-8")
        code, _out, err = self.run_main(
            "append", "--id", "g", "--class", "mechanical", "--answer", "yes",
            "--why", "why", log=str(blocker / "DECISIONS.md"))
        self.assertEqual(code, 2)
        self.assertIn("could not run", err)

    def test_active_json_carries_the_record_shape(self):
        self.seed(["2026-09-01T00:00:00Z · gate-5 · taste · a · why · t-1"])
        code, out, err = self.run_main("active", "--json")
        self.assertEqual(code, 0, err)
        (row,) = json.loads(out)
        self.assertEqual(row, {"ts": "2026-09-01T00:00:00Z", "id": "gate-5",
                               "class": "taste", "answer": "a", "why": "why",
                               "task_id": "t-1"})

    def test_tally_human_readable_names_all_three_verdicts(self):
        def seed(lens, n):
            self.seed([f"2026-09-{i + 1:02d}T00:00:00Z · lens-tally:{lens} · mechanical · 0 · "
                       f"dispatch {i} clean · t-{i}" for i in range(n)])
        seed("a11y", 10)
        code, out, err = self.run_main("tally", "--lens", "a11y")
        self.assertEqual(code, 0, err)
        self.assertIn("may auto-gate off", out)
        seed("security", 40)
        _code, out, _err = self.run_main("tally", "--lens", "security")
        self.assertIn("NEVER_GATE", out)
        seed("perf", 3)
        _code, out, _err = self.run_main("tally", "--lens", "perf")
        self.assertIn("stays on", out)

    def test_check_reports_each_failure_with_its_line(self):
        self.seed(["2026-09-01T00:00:00Z · gate-1 · nonsense · yes · fine · t-1"])
        code, _out, err = self.run_main("check")
        self.assertEqual(code, 1)
        self.assertRegex(err, r":5: class 'nonsense'")

    def test_a_broken_door_registry_is_exit_2_through_main(self):
        code, _out, err = self.run_main("--doors", str(Path(self.tmp) / "nope.json"), "check")
        self.assertEqual(code, 2)
        self.assertIn("could not run", err)

    def test_a_directory_as_the_log_is_exit_2(self):
        code, _out, err = self.run_main("check", log=str(Path(self.tmp)))
        self.assertEqual(code, 2)
        self.assertIn("could not run", err)

    def test_active_on_a_missing_log_is_empty_in_process(self):
        code, out, err = self.run_main("active")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "")

    def test_append_stamps_a_fresh_source_marker(self):
        code, _out, err = self.run_main(
            "append", "--id", "g-5", "--class", "one-way", "--answer", "approved",
            "--why", "deploy tonight", "--source", "human:lia")
        self.assertEqual(code, 0, err)
        self.assertIn("[source=human:lia]",
                      [ln for ln in self.log.read_text(encoding="utf-8").splitlines()
                       if "g-5" in ln][0])

    def test_active_plain_prints_the_raw_records(self):
        self.seed(["2026-09-01T00:00:00Z · gate-6 · taste · a · why · t-1"])
        code, out, err = self.run_main("active")
        self.assertEqual(code, 0, err)
        self.assertIn("2026-09-01T00:00:00Z · gate-6 · taste · a · why · t-1", out)

    def test_tally_json_carries_the_gate_verdict(self):
        self.seed(["2026-09-01T00:00:00Z · lens-tally:a11y · mechanical · 0 · clean · t-1"])
        code, out, err = self.run_main("tally", "--lens", "a11y", "--json")
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual((data["lens"], data["zero_streak"], data["may_gate_off"]),
                         ("a11y", 1, False))

    def test_an_argparse_rejection_exits_2_through_system_exit(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                decisions.main(["--file", str(self.log), "append", "--id", "g",
                                "--class", "vibes", "--answer", "y", "--why", "w"])
        self.assertEqual(ctx.exception.code, 2)

    def test_the_module_entry_point_runs_check_and_exits_zero(self):
        self.seed(["2026-09-01T00:00:00Z · gate-1 · mechanical · yes · fine · t-1"])
        argv = ["decisions.py", "--file", str(self.log), "check"]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as ctx:
                    runpy.run_path(str(DECISIONS), run_name="__main__")
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("1 record(s) valid", out.getvalue())



# ---- 2026-10-23 end-to-end review (#621): P1-8 and P2-3 -----------------------------------------


class PinnedLedger(DecisionsBase):
    """A ledger whose repository root pins a fresh human grant key."""

    def setUp(self):
        super().setUp()
        self.seed_bytes = os.urandom(32)
        self.ed = decisions._ed25519()
        subprocess.run(["git", "init", "-q", self.tmp], capture_output=True)
        orca = Path(self.tmp) / ".orca"
        orca.mkdir(parents=True, exist_ok=True)
        (orca / "human-grant-pubkey").write_text(
            self.ed.publickey(self.seed_bytes).hex() + "\n", encoding="utf-8")

    def signed(self, ident, answer, ts, why="deploy to production", signed_ts=None,
               klass="one-way", task="t-1"):
        payload = decisions.grant_payload(ident, answer, why, task, ts=signed_ts or ts,
                                          klass=klass)
        sig = self.ed.signature(payload, self.seed_bytes, self.ed.publickey(self.seed_bytes)).hex()
        return f"{ts} · {ident} · one-way · {answer} · {why} [source=human:lia sig={sig}] · {task}"


class TestPinnedKeyRequiresEverySignatureP18(PinnedLedger):
    """P1-8: `check` and `active` must hold a hand-written line to what `append` demands."""

    UNSIGNED = ("2026-09-01T00:00:00Z · gate-p18 · one-way · approved · deploy to production "
                "[source=human:lia] · t-1")

    def test_check_fails_a_hand_written_unsigned_one_way_line(self):
        # The review's reproduction: append refused it, the same line typed in passed
        # `check` ("1 record(s) valid", exit 0).
        self.seed([self.UNSIGNED])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("no grant signature", r.stderr)

    def test_active_does_not_list_an_unsigned_one_way_line(self):
        self.seed([self.UNSIGNED])
        r = self.run_dec("active")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("gate-p18", r.stdout, "an unsigned grant was listed as live")

    def test_an_unsigned_line_neither_outranks_nor_retires_a_signed_one(self):
        self.seed([self.signed("gate-p18", "approved", "2026-09-01T00:00:00Z"),
                   "2026-09-02T00:00:00Z · gate-p18 · one-way · denied · deploy to production "
                   "[source=human:lia] · t-1"])
        rows = json.loads(self.run_dec("active", "--json").stdout)
        self.assertEqual([(r["id"], r["answer"]) for r in rows], [("gate-p18", "approved")])

    def test_a_signed_line_still_checks_and_lists(self):
        self.seed([self.signed("gate-p18", "approved", "2026-09-01T00:00:00Z")])
        self.assertEqual(self.run_dec("check").returncode, 0)
        self.assertIn("gate-p18", self.run_dec("active").stdout)

    def test_without_a_pin_an_unsigned_one_way_line_is_still_valid(self):
        shutil.rmtree(Path(self.tmp) / ".orca")
        self.seed([self.UNSIGNED])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("gate-p18", self.run_dec("active").stdout)


class TestPinRefIsTheTrustAnchor(PinnedLedger):
    """A change under check could swap `.orca/human-grant-pubkey` for a key it holds and sign
    its own one-way grants: `check` read the pin from the working tree. `--pin-ref` reads it
    from a trusted ref and refuses a tree whose pin differs (#602 trajectory probe)."""

    def setUp(self):
        super().setUp()
        self.git("checkout", "-q", "-b", "main")
        self.git("commit", "-q", "--allow-empty", "-m", "before the pin")
        self.git("branch", "unpinned")
        self.git("add", ".orca")
        self.git("commit", "-q", "-m", "pin the human grant key")
        # The trusted refs as a coordinator's clone carries them: remote-tracking, fetched — the
        # form a checked change cannot move (W3-07), unlike its own local branches.
        self.git("update-ref", "refs/remotes/origin/main", "main")
        self.git("update-ref", "refs/remotes/origin/unpinned", "unpinned")

    def git(self, *args):
        return subprocess.run(["git", "-C", self.tmp, "-c", "user.name=t", "-c", "user.email=t@x",
                               "-c", "commit.gpgsign=false", *args],
                              capture_output=True, text=True, check=True)

    def swap_pin(self):
        rogue = os.urandom(32)
        (Path(self.tmp) / ".orca" / "human-grant-pubkey").write_text(
            self.ed.publickey(rogue).hex() + "\n", encoding="utf-8")
        self.seed_bytes = rogue  # signed() now signs with the swapped-in key

    def test_a_pin_matching_the_ref_checks_as_before(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("gate-pin", self.run_dec("--pin-ref", "refs/remotes/origin/main", "active").stdout)

    def test_a_pin_swapped_in_the_tree_is_refused_against_the_ref(self):
        self.swap_pin()
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        # Without a trusted ref the swapped key verifies its own grant: the gap.
        self.assertEqual(self.run_dec("check").returncode, 0)
        r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "check")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("differs from the one pinned at refs/remotes/origin/main", r.stderr)
        r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "active")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertNotIn("gate-pin", r.stdout)

    def test_a_tree_pin_where_the_ref_pins_none_is_refused(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        r = self.run_dec("--pin-ref", "refs/remotes/origin/unpinned", "check")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("differs", r.stderr)

    def test_a_pinned_blob_the_clone_cannot_read_is_not_read_as_unpinned(self):
        # PR #635 review, P1: `cat-file -e` failed alike for an absent pin and an unreadable one,
        # so a ref whose pin blob is missing here (a partial clone) read as "unpinned"; with the
        # tree pin deleted too, unsigned one-way grants then passed.
        blob = self.git("rev-parse", "main:.orca/human-grant-pubkey").stdout.strip()
        (Path(self.tmp) / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
        shutil.rmtree(Path(self.tmp) / ".orca")
        self.seed(["2026-09-01T00:00:00Z · gate-pin · one-way · approved · deploy to production "
                   "[source=human:lia] · t-1"])
        r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "check")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("blob is unreadable", r.stderr)
        r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "active")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertNotIn("gate-pin", r.stdout)

    def test_an_unresolvable_or_option_shaped_ref_is_could_not_run(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        for ref, why in (("no-such-ref", "does not resolve to a commit"),
                         ("--output=/tmp/x", "must name a git ref, not an option")):
            with self.subTest(ref=ref):
                r = self.run_dec(f"--pin-ref={ref}", "check")
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn(why, r.stderr)


class TestPinRefIsCoordinatorOwnedW307(TestPinRefIsTheTrustAnchor):
    """W3-07 (2026-10-27 security audit, P2): the #635 anchor degraded three ways. (a) A local
    branch (`--pin-ref main`) is one the checked change can `update-ref`; (b) the ref was resolved
    by `rev-parse` and then re-resolved by `ls-tree` and `cat-file`, so it could move in between;
    (c) with no --pin-ref the working-tree pin was used silently, also where the caller claims a
    sound lane. Now: only a remote-tracking ref or a commit id anchors, it is resolved ONCE and
    that commit is what is read, and a sound lane without --pin-ref cannot run."""

    def test_a_local_branch_or_tag_is_not_a_trust_anchor(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        self.git("tag", "pin-tag", "main")
        for ref in ("main", "refs/heads/main", "pin-tag", "HEAD"):
            with self.subTest(ref=ref):
                r = self.run_dec("--pin-ref", ref, "check")
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn("remote-tracking", r.stderr)
                self.assertIn("W3-07", r.stderr)

    def test_a_remote_tracking_name_symbolic_to_a_local_branch_is_not_a_trust_anchor(self):
        # PR #719 review (P1, mirrored from verify.py's key_source): the class must be what the
        # ref RESOLVES to — refs/remotes/<x> made a symbolic ref to a local branch carrying a
        # swapped key passed by spelling.
        self.swap_pin()
        self.git("add", ".orca")
        self.git("commit", "-q", "-m", "the change's own key")
        self.git("symbolic-ref", "refs/remotes/worker/key", "refs/heads/main")
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        r = self.run_dec("--pin-ref", "refs/remotes/worker/key", "check")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("refs/heads/main", r.stderr)
        # the ordinary symbolic shape — origin/HEAD -> origin/main — still anchors
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        r = self.run_dec("--pin-ref", "refs/remotes/origin/HEAD", "check")
        self.assertEqual(r.returncode, 2, r.stdout)  # origin/main pins the ORIGINAL key: differs
        self.assertIn("differs", r.stderr)

    def test_a_commit_id_is_a_trust_anchor(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        sha = self.git("rev-parse", "main^{commit}").stdout.strip()
        r = self.run_dec("--pin-ref", sha, "check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.swap_pin()
        r = self.run_dec("--pin-ref", sha, "check")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("differs", r.stderr)

    def test_the_ref_is_resolved_once_and_the_commit_is_what_is_read(self):
        sha = self.git("rev-parse", "refs/remotes/origin/main^{commit}").stdout.strip()
        seen = []
        real = subprocess.run

        def spy(argv, *a, **k):
            seen.append(list(argv))
            return real(argv, *a, **k)

        with mock.patch.object(decisions.subprocess, "run", side_effect=spy):
            decisions._pin_at_ref(Path(self.tmp), "refs/remotes/origin/main")
        reads = [argv for argv in seen if any(op in argv for op in ("ls-tree", "cat-file"))]
        self.assertTrue(reads, seen)
        for argv in reads:
            self.assertFalse(any("refs/remotes/origin/main" in tok for tok in argv),
                             f"the ref is re-resolved after validation: {argv}")
            self.assertTrue(any(tok == sha or tok.startswith(sha + ":") for tok in argv), argv)

    def test_a_sound_lane_without_a_pin_ref_cannot_run(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        for var in ("ORCA_PROVENANCE", "OPEN_FLEET_PROVENANCE"):
            with self.subTest(var=var):
                env = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
                env[var] = "ci"
                r = subprocess.run([sys.executable, str(DECISIONS), "--file", str(self.log),
                                    "check"], capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn("--pin-ref", r.stderr)
                self.assertIn("W3-07", r.stderr)

    def test_the_working_tree_default_is_never_silent(self):
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        r = subprocess.run([sys.executable, str(DECISIONS), "--file", str(self.log), "check"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOTE", r.stderr)
        self.assertIn("working tree", r.stderr)


class TestPinRefIsAnExactNameW307(TestPinRefIsTheTrustAnchor):
    """Codex review of the W3-07 fix (P1, P2). The prefix check read the name the caller SPELLED,
    and `rev-parse` then expanded it (gitrevisions: refs/<name>, refs/tags/<name>,
    refs/heads/<name>, …): with refs/remotes/worker/key absent, a local branch
    refs/heads/refs/remotes/worker/key answered for it, and a revision suffix passed the prefix
    check too. A ref anchors only when it exists under exactly its name; a commit id only when it
    names that commit object. And with no --pin-ref an ABSENT pin was silent."""

    def rogue_branch(self, ref):
        """The change's own key and a grant it signed, committed on the LOCAL ref `ref`."""
        self.swap_pin()
        self.git("checkout", "-q", "-b", "the-change")
        self.git("add", ".orca")
        self.git("commit", "-q", "-m", "the change's own key")
        self.git("update-ref", ref, "HEAD")
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])

    def test_a_local_branch_spelled_as_an_absent_remote_tracking_ref_is_refused(self):
        # Codex's reproduction: the real refs/remotes/worker/key never exists.
        self.rogue_branch("refs/heads/refs/remotes/worker/key")
        # ...and a remote-tracking symbolic ref whose target is that absent spelling
        self.git("symbolic-ref", "refs/remotes/worker/head", "refs/remotes/worker/key")
        for ref in ("refs/remotes/worker/key", "refs/remotes/worker/head"):
            with self.subTest(ref=ref):
                r = self.run_dec("--pin-ref", ref, "check")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("exactly that name", r.stderr)
                self.assertIn("W3-07", r.stderr)
                r = self.run_dec("--pin-ref", ref, "active")
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertNotIn("gate-pin", r.stdout)

    def test_a_hex_named_branch_is_not_a_commit_id(self):
        # In a SHA-1 repository 64 hex digits are no object id, so rev-parse expands them as a
        # ref name: refs/heads/<64 hex> answered for "a commit id".
        hexname = "ab" * 32
        self.rogue_branch(f"refs/heads/{hexname}")
        for ref in (hexname, hexname.upper()):
            with self.subTest(ref=ref):
                r = self.run_dec("--pin-ref", ref, "check")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("names no commit object", r.stderr)

    def test_a_revision_suffix_on_a_remote_tracking_ref_is_refused(self):
        # A key rotation: the change holds the RETIRED key, which origin/main's parent (and its
        # reflog entry before the rotation) still pins. Each suffix passed the prefix check and
        # read that retired key, so grants it signed verified.
        retired = self.seed_bytes
        self.swap_pin()
        self.git("add", ".orca")
        self.git("commit", "-q", "-m", "rotate the human grant key")
        self.git("update-ref", "refs/remotes/origin/main", "main")
        self.seed_bytes = retired
        (Path(self.tmp) / ".orca" / "human-grant-pubkey").write_text(
            self.ed.publickey(retired).hex() + "\n", encoding="utf-8")
        self.seed([self.signed("gate-pin", "approved", "2026-09-01T00:00:00Z")])
        for ref in ("refs/remotes/origin/main~1", "refs/remotes/origin/main^",
                    "refs/remotes/origin/main@{1}", "refs/remotes/origin/main^{commit}"):
            with self.subTest(ref=ref):
                r = self.run_dec("--pin-ref", ref, "check")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("not a valid ref name", r.stderr)
        # The exact name reads the CURRENT key, which the retired one is not.
        r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "check")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("differs", r.stderr)

    def test_a_local_bridge_inside_a_remote_tracking_chain_is_refused(self):
        # Codex review round 2 (P1): for-each-ref's %(symref) is the chain's recursively resolved
        # END, so refs/remotes/worker/key -> refs/heads/bridge -> refs/remotes/origin/retired-key
        # read as pointing straight at a remote ref, and the local bridge — the change's to
        # re-point at any other remote-tracking key — was never seen. Each hop is read on its own.
        self.rogue_branch("refs/remotes/origin/retired-key")
        self.git("symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/retired-key")
        self.git("symbolic-ref", "refs/remotes/worker/key", "refs/heads/bridge")
        self.git("symbolic-ref", "refs/remotes/worker/b", "refs/heads/bridge")
        self.git("symbolic-ref", "refs/remotes/worker/a", "refs/remotes/worker/b")
        for ref in ("refs/remotes/worker/key", "refs/remotes/worker/a"):
            with self.subTest(ref=ref):
                r = self.run_dec("--pin-ref", ref, "check")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("refs/heads/bridge", r.stderr)
        # remote -> remote -> remote still anchors (the ordinary origin/HEAD shape, one hop more)
        self.git("symbolic-ref", "refs/remotes/worker/c", "refs/remotes/origin/retired-key")
        self.git("symbolic-ref", "refs/remotes/worker/d", "refs/remotes/worker/c")
        r = self.run_dec("--pin-ref", "refs/remotes/worker/d", "check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_anchor(self):
        # Independent re-attack (A): the listing was split with str.splitlines(), which breaks on
        # U+2028/U+2029/U+0085 — characters git accepts in a refname — so a fetched branch
        # `x<U+2028>refs/remotes/origin/main` added a second "record" naming origin/main at the
        # worker's commit, and the last one won. Records now split on NUL+LF only.
        honest = self.git("rev-parse", "refs/remotes/origin/main").stdout.strip()
        self.rogue_branch("refs/heads/rogue")
        rogue = self.git("rev-parse", "refs/heads/rogue").stdout.strip()
        self.assertNotEqual(rogue, honest)
        for ch in refname_breaks.LINE_BREAKS:
            with self.subTest(ch=ch):
                unplant = refname_breaks.plant(self.tmp, ch, rogue)
                try:
                    r = self.run_dec("--pin-ref", "refs/remotes/origin/main", "check")
                finally:
                    unplant()
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("differs", r.stderr)

    def test_a_deleted_working_tree_pin_is_never_silent(self):
        # Codex review P2: with neither --pin-ref nor a provenance variable, the NOTE fired only
        # when a pin was present, so the deleted case — unsigned one-way grants valid — was the
        # one that said nothing.
        shutil.rmtree(Path(self.tmp) / ".orca")
        self.seed(["2026-09-01T00:00:00Z · gate-pin · one-way · approved · deploy to production "
                   "[source=human:lia] · t-1"])
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        for command in ("check", "active"):
            with self.subTest(command=command):
                r = subprocess.run([sys.executable, str(DECISIONS), "--file", str(self.log),
                                    command], capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("NOTE", r.stderr)
                self.assertIn("absent", r.stderr)
                self.assertIn("--pin-ref", r.stderr)


class TestGrantPayloadBindsTsAndClassP23(PinnedLedger):
    """P2-3: a signature binds when the decision was taken, so it cannot be re-dated."""

    def test_a_signed_grant_replayed_under_a_later_ts_does_not_outrank_a_supersede(self):
        approved = self.signed("gate-p23", "approved", "2026-09-01T00:00:00Z")
        replay = approved.replace("2026-09-01T00:00:00Z", "2026-09-03T00:00:00Z", 1)
        self.seed([approved,
                   self.signed("gate-p23", "superseded", "2026-09-02T00:00:00Z"),
                   replay])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(":7: grant signature does not verify", r.stderr)
        self.assertEqual(json.loads(self.run_dec("active", "--json").stdout), [],
                         "a replayed approval out-ranked the later supersede")

    def test_the_payload_binds_ts_and_class(self):
        base = dict(ident="g", answer="approved", why_core="w", task_id="t")
        v2 = decisions.grant_payload(**base, ts="2026-09-01T00:00:00Z", klass="one-way")
        self.assertTrue(v2.startswith(b"open-fleet human grant v2\n"))
        self.assertIn(b"2026-09-01T00:00:00Z", v2)
        self.assertNotEqual(v2, decisions.grant_payload(**base, ts="2026-09-02T00:00:00Z",
                                                        klass="one-way"))
        self.assertNotEqual(v2, decisions.grant_payload(**base, ts="2026-09-01T00:00:00Z",
                                                        klass="taste"))

    def test_a_v1_signature_no_longer_verifies(self):
        v1 = ("orca-fleet human grant v1\n" + "\n".join(
            ["gate-v1", "approved", "deploy to production", "t-1"])).encode("utf-8")
        sig = self.ed.signature(v1, self.seed_bytes, self.ed.publickey(self.seed_bytes)).hex()
        self.seed([f"2026-09-01T00:00:00Z · gate-v1 · one-way · approved · deploy to production "
                   f"[source=human:lia sig={sig}] · t-1"])
        self.assertEqual(self.run_dec("check").returncode, 1)

    def test_append_refuses_a_timestamp_in_the_future(self):
        # `append --ts 2099-…` out-ranked a human `deny` in active().
        r = self.append("gate-p23f", "taste", "option-b", "reconsidered",
                        extra=("--ts", "2099-01-01T00:00:00Z"))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("in the future", r.stderr)
        self.assertFalse(self.log.exists() and "gate-p23f" in self.log.read_text(encoding="utf-8"))

    def test_check_names_a_hand_written_future_line(self):
        self.seed(["2099-01-01T00:00:00Z · gate-p23f · taste · option-b · reconsidered · t-1"])
        r = self.run_dec("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("in the future", r.stderr)

    def test_a_stamp_within_the_skew_is_accepted(self):
        from datetime import timedelta
        soon = decisions._now() + timedelta(seconds=60)
        r = self.append("gate-p23s", "taste", "option-b", "clock skew",
                        extra=("--ts", soon.strftime("%Y-%m-%dT%H:%M:%SZ")))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_sign_grant_binds_and_prints_the_ts_it_signed(self):
        key = Path(self.tmp) / "human.seed"
        key.write_text(self.seed_bytes.hex() + "\n", encoding="utf-8")
        signed = subprocess.run(
            [sys.executable, str(DECISIONS), "sign-grant", "--key", str(key), "--id", "gate-p23",
             "--answer", "approved", "--why", "deploy to production", "--task", "t-1"],
            capture_output=True, text=True)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        stamp = re.search(r"ts=(\S+)", signed.stderr).group(1)
        r = self.append("gate-p23", "one-way", "approved", "deploy to production",
                        extra=("--task", "t-1", "--source", "human:lia",
                               "--grant-sig", signed.stdout.strip(), "--ts", stamp))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.run_dec("check").returncode, 0)

    def test_append_with_a_signature_but_no_ts_says_which_flag_is_missing(self):
        r = self.append("gate-p23", "one-way", "approved", "deploy to production",
                        extra=("--source", "human:lia", "--grant-sig", "a" * 128))
        self.assertEqual(r.returncode, 1)
        self.assertIn("--ts", r.stderr)

    def test_sign_grant_refuses_a_future_stamp(self):
        key = Path(self.tmp) / "human.seed"
        key.write_text(self.seed_bytes.hex() + "\n", encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(DECISIONS), "sign-grant", "--key", str(key), "--id", "g",
             "--answer", "approved", "--why", "w", "--ts", "2099-01-01T00:00:00Z"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "")


class TestGrantProblemsUnits(unittest.TestCase):
    """The one rule floor_guard.py borrows for its waivers (#621, P1-7)."""

    def _record(self, klass="one-way", why="ok [source=human:lia]"):
        return decisions.parse_line(
            f"2026-09-01T00:00:00Z · floor-waiver:r:p · {klass} · allow · {why} · t-1")

    def test_only_a_sourced_one_way_line_stands_as_a_grant(self):
        self.assertEqual(decisions.grant_problems(self._record()), [])
        self.assertTrue(decisions.grant_problems(self._record(klass="taste")))
        self.assertTrue(decisions.grant_problems(self._record(why="no source")))

    def test_read_side_human_grant_of_refuses_unknown_and_every_reserved_role(self):
        for role in ("unknown", "UNKNOWN", *sorted(decisions.RESERVED_HUMAN_NAMES)):
            with self.subTest(role=role):
                rec = self._record(why=f"deploy to production [source=human:{role}]")
                self.assertEqual(decisions.human_grant_of(rec), (None, None, rec["why"]))
                self.assertTrue(decisions.grant_problems(rec))

    def test_standing_drops_only_one_way_lines_a_pinned_key_does_not_verify(self):
        pub = decisions._ed25519().publickey(os.urandom(32))
        keep = [self._record(klass="mechanical", why="retired")]
        unsigned = [self._record(), self._record(why="no source")]
        self.assertEqual(decisions.standing(keep + unsigned, pub), keep)
        # Unpinned, the marker is a record-format check: `active` lists what it always listed.
        self.assertEqual(decisions.standing(keep + unsigned), keep + unsigned)


class TestNestedRepoNeverSubstitutesGrantAnchorC20(TestPinRefIsTheTrustAnchor):
    """C20: an initialized submodule or nested `.git` directory inside an outer repository must
    never substitute its own `.orca/human-grant-pubkey` or `--pin-ref` anchor."""

    def test_nested_submodule_gitfile_and_nested_git_dir_are_refused(self):
        rogue = os.urandom(32)
        rogue_pub = self.ed.publickey(rogue).hex() + "\n"
        payload = decisions.grant_payload(
            "gate-sub", "approved", "deploy to production", "t-1",
            ts="2026-09-01T00:00:00Z", klass="one-way",
        )
        sig = self.ed.signature(payload, rogue, self.ed.publickey(rogue)).hex()
        forged_line = (
            "2026-09-01T00:00:00Z · gate-sub · one-way · approved · "
            f"deploy to production [source=human:lia sig={sig}] · t-1"
        )

        # Case 1: nested initialized submodule (.git file -> ../../.git/modules/sub)
        sub_dir = Path(self.tmp) / "vendor" / "sub"
        sub_dir.mkdir(parents=True)
        mod_git = Path(self.tmp) / ".git" / "modules" / "sub"
        subprocess.run(["git", "init", "-q", "--bare", str(mod_git)], check=True)
        (sub_dir / ".git").write_text("gitdir: ../../.git/modules/sub\n", encoding="utf-8")
        (sub_dir / ".orca").mkdir()
        (sub_dir / ".orca" / "human-grant-pubkey").write_text(rogue_pub, encoding="utf-8")
        sub_log = sub_dir / "DECISIONS.md"
        sub_log.write_text("# DECISIONS\n\n" + forged_line + "\n", encoding="utf-8")

        for extra in ((), ("--pin-ref", "refs/remotes/origin/main")):
            r = subprocess.run(
                [sys.executable, str(DECISIONS), "--file", str(sub_log), *extra, "check"],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("nested repository", r.stderr)

        # Case 2: nested .git directory inside the outer repository
        nested_dir = Path(self.tmp) / "vendor" / "nested"
        nested_dir.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(nested_dir)], check=True)
        (nested_dir / ".orca").mkdir()
        (nested_dir / ".orca" / "human-grant-pubkey").write_text(rogue_pub, encoding="utf-8")
        nested_log = nested_dir / "DECISIONS.md"
        nested_log.write_text("# DECISIONS\n\n" + forged_line + "\n", encoding="utf-8")

        r = subprocess.run(
            [sys.executable, str(DECISIONS), "--file", str(nested_log), "check"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("nested repository", r.stderr)

    def test_genuine_linked_worktree_inside_repo_still_resolves(self):
        wt_dir = Path(self.tmp) / ".worktrees" / "wt-1"
        self.git("worktree", "add", "-q", "-b", "wt-branch", str(wt_dir), "main")
        wt_log = wt_dir / "docs" / "DECISIONS.md"
        wt_log.parent.mkdir(parents=True, exist_ok=True)
        wt_log.write_text(
            "# DECISIONS\n\n" + self.signed("gate-wt", "approved", "2026-09-01T00:00:00Z") + "\n",
            encoding="utf-8",
        )
        r = subprocess.run(
            [sys.executable, str(DECISIONS), "--file", str(wt_log),
             "--pin-ref", "refs/remotes/origin/main", "check"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
