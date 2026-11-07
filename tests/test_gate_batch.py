#!/usr/bin/env python3
"""Contract tests for runtime/scripts/gate-batch.py (#419).

Human gates used to be hand-appended prose in a run's gate-batch.md — no
schema, no state machine, and a renumbered gate silently orphaned every
parked-unit citation. The tool stores typed records; these tests pin the
state machine (owed moves exactly once), the staleness boundary, the
2026-09-14 migration's byte-identical round-trip, the warn-not-error
citation check, the close wait-predicate (--blocking, not stale),
mutations re-rendering the .md view, schema/CLI agreement, inclusive
citation ranges, atomic store writes, and init refusing a pre-tooling .md
without the explicit overwrite flag.
"""
import datetime
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

# Fetched branch names holding a line break (tests/fixtures/refname_breaks.py; W3-07 re-attack).
_rb_spec = importlib.util.spec_from_file_location(
    "refname_breaks", ROOT / "tests" / "fixtures" / "refname_breaks.py")
refname_breaks = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(refname_breaks)
_spec = importlib.util.spec_from_file_location(
    "gate_batch", ROOT / "runtime" / "scripts" / "gate-batch.py")
gb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gb)


def _ed25519():
    """The vendored Ed25519 the human grant key signs with (decisions.py loads the same file)."""
    spec = importlib.util.spec_from_file_location(
        "ed25519_for_gate_batch", ROOT / "runtime" / "scripts" / "ed25519.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

RUN_DIR = ROOT / "docs" / "runs" / "2026-09-14-clean-sweep-tracker"
REAL_JSON = RUN_DIR / "gate-batch.json"
REAL_MD = RUN_DIR / "gate-batch.md"
SCHEMA = ROOT / "runtime" / "schemas" / "gate-batch.schema.json"


def fresh_batch(tmp, **kwargs):
    path = Path(tmp) / "gate-batch.json"
    kwargs.setdefault("run_id", "run_test")
    kwargs.setdefault("run_title", "test run")
    return path, gb.init_batch(path, **kwargs)


def add_owed(data, gid="G1", asked="2026-09-14", **kwargs):
    kwargs.setdefault("title", f"ask {gid}")
    kwargs.setdefault("question", f"the question {gid}")
    return gb.add_gate(data, gid=gid, asked=asked, **kwargs)


class StateTransitions(unittest.TestCase):
    def test_add_creates_an_owed_gate_with_the_next_auto_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, data = fresh_batch(tmp)
            g1 = gb.add_gate(data, title="first", question="q1")
            g2 = gb.add_gate(data, title="second", question="q2")
            self.assertEqual((g1["id"], g1["status"]), ("G1", "owed"))
            self.assertEqual((g2["id"], g2["status"]), ("G2", "owed"))
            self.assertIsNone(g1["answer"])
            self.assertIsNone(g1["answered"])
            gb.save_batch(path, data)
            self.assertEqual(gb.load_batch(path)["gates"], data["gates"])

    def test_add_with_a_duplicate_id_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1")
            with self.assertRaises(gb.GateError):
                add_owed(data, "G1")

    def test_answer_moves_owed_to_answered_with_text_and_date(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked="2026-09-14")
            gate = gb.transition(data, "G1", "answered", "the vault holds it",
                                 answered="2026-09-15", source="human:lia")
            self.assertEqual(gate["status"], "answered")
            self.assertEqual(gate["answer"], "the vault holds it")
            self.assertEqual(gate["answered"], "2026-09-15")
            self.assertEqual(gate["source"], "human:lia")

    def test_an_answer_or_waiver_records_who_gave_it(self):
        # 2026-10-26 review: an answer with no recorded human was prose anyone could have typed.
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked="2026-09-14")
            add_owed(data, "G2", asked="2026-09-14")
            for status, text in (("answered", "yes"), ("waived", "moot")):
                with self.subTest(status=status):
                    with self.assertRaises(gb.GateError) as ctx:
                        gb.transition(data, "G1", status, text, answered="2026-09-15")
                    self.assertIn("--source human:<name>", str(ctx.exception))
                    with self.assertRaises(gb.GateError):
                        gb.transition(data, "G1", status, text, answered="2026-09-15", source="coordinator")
            self.assertEqual(gb.find_gate(data, "G1")["status"], "owed", "a refused transition changes nothing")
            gate = gb.transition(data, "G2", "overtaken", None, answered="2026-09-15")
            self.assertNotIn("source", gate, "events overtook it: no person to record")

    def test_waive_moves_owed_to_waived_with_the_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G3", asked="2026-09-14")
            gate = gb.transition(data, "G3", "waived", "blind verdict suffices",
                                 answered="2026-09-16", source="human:lia")
            self.assertEqual((gate["status"], gate["answer"]),
                             ("waived", "blind verdict suffices"))

    def test_overtake_needs_no_note_when_the_body_says_why(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G4", asked="2026-09-14",
                     question="built before the pick; disclosed for the record")
            gate = gb.transition(data, "G4", "overtaken", None,
                                 answered="2026-09-14")
            self.assertEqual(gate["status"], "overtaken")
            self.assertIsNone(gate["answer"])

    def test_a_answered_gate_never_moves_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked="2026-09-14")
            gb.transition(data, "G1", "answered", "yes", answered="2026-09-15", source="human:lia")
            for status, text in (("answered", "second"), ("waived", "moot"),
                                 ("overtaken", None)):
                with self.subTest(status=status):
                    with self.assertRaises(gb.GateError):
                        gb.transition(data, "G1", status, text,
                                      answered="2026-09-16", source="human:lia")
            self.assertEqual(
                gb.find_gate(data, "G1")["answer"], "yes",
                "the failed re-transition must not touch the record")

    def test_transitioning_an_unknown_gate_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1")
            with self.assertRaises(gb.GateError):
                gb.transition(data, "G9", "answered", "yes",
                              answered="2026-09-15", source="human:lia")

    def test_a_recorded_date_before_asked_is_refused_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked="2026-09-14")
            with self.assertRaises(gb.GateError):
                gb.transition(data, "G1", "answered", "yes",
                              answered="2026-09-13", source="human:lia")
            gate = gb.find_gate(data, "G1")
            self.assertEqual(gate["status"], "owed")
            self.assertIsNone(gate["answered"])

    def test_answer_and_waive_without_text_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked="2026-09-14")
            add_owed(data, "G2", asked="2026-09-14")
            with self.assertRaises(gb.GateError):
                gb.transition(data, "G1", "answered", "  ",
                              answered="2026-09-15")
            with self.assertRaises(gb.GateError):
                gb.transition(data, "G2", "waived", "", answered="2026-09-15")
            self.assertEqual(gb.find_gate(data, "G1")["status"], "owed")


class StaleBoundary(unittest.TestCase):
    ASKED = "2026-09-10"

    def _stale_ids(self, today, days):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked=self.ASKED)
            return [g["id"] for g, _ in
                    gb.stale_gates(data, days, datetime.date(*today))]

    def test_a_gate_owed_n_minus_1_days_is_quiet(self):
        # Asked 09-10, today 09-16: 6 days owed against --days 7.
        self.assertEqual(self._stale_ids((2026, 9, 16), 7), [])

    def test_a_gate_owed_exactly_n_days_is_flagged(self):
        # Asked 09-10, today 09-17: 7 days owed against --days 7.
        self.assertEqual(self._stale_ids((2026, 9, 17), 7), ["G1"])

    def test_a_settled_gate_is_never_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp)
            add_owed(data, "G1", asked="2026-01-01")
            gb.transition(data, "G1", "answered", "long ago",
                          answered="2026-01-02", source="human:lia")
            self.assertEqual(
                gb.stale_gates(data, 7, datetime.date(2026, 9, 17)), [])


class BlockingWaitPredicate(unittest.TestCase):
    def test_list_status_owed_blocking_catches_a_fresh_blocker(self):
        # A gate asked TODAY blocking #386: `stale` is quiet (age 0 < 7)
        # but the close wait-predicate must still show it — the fresh
        # gate that used to slip through step 7.
        with tempfile.TemporaryDirectory() as tmp:
            path, data = fresh_batch(tmp)
            gb.add_gate(data, gid="G1", title="fresh", question="q",
                        asked="2026-09-16", blocking=["#386"])
            gb.add_gate(data, gid="G2", title="other unit", question="q",
                        asked="2026-09-16", blocking=["#999"])
            gb.add_gate(data, gid="G3", title="blocks nothing", question="q",
                        asked="2026-09-16")
            self.assertEqual(
                [g["id"] for g in gb.list_gates(data, "owed", "#386")],
                ["G1"])
            self.assertEqual(
                gb.stale_gates(data, 7, datetime.date(2026, 9, 16)), [],
                "the reminder query is quiet: the gate is hours old")
            gb.save_batch(path, data)
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = gb.main(["--file", str(path), "list",
                                "--status", "owed", "--blocking", "#386"])
            self.assertEqual(code, 0)
            self.assertIn("G1", out.getvalue())
            self.assertNotIn("G2", out.getvalue())
            self.assertNotIn("G3", out.getvalue())


def _parse_legacy_md(text):
    """Split a hand-written batch into (run_id, run_title, intro, gates, resolved).

    Test-only: the migration ran once through the CLI; this replays the md->json
    direction so the round-trip test does not trust the committed JSON alone.
    """
    body = text[:-1]  # the file ends in exactly one newline
    m = re.match(r"# Run-close human-gate batch \u2014 (\S+) \((.*)\)\n"
                 r"\n(.*?)\n\n(## G1 .*)\Z", body, re.S)
    run_id, run_title, intro, rest = m.groups()
    gates, resolved = [], ""
    for chunk in re.split(r"\n(?=## )", rest):
        head, _, qbody = chunk.partition("\n\n")
        if head.startswith("## Resolved"):
            resolved = qbody
            continue
        gid, title = re.match(r"## (G[0-9]+) \u00b7 (.*)", head).groups()
        # Annotations are view-only (the answer lives in the JSON store);
        # strip a trailing one before comparing question prose.
        qbody = re.sub(
            r"\n\n\*\*(?:Answered|Waived|Overtaken) \d{4}-\d{2}-\d{2}:\*\*.*\Z",
            "", qbody, flags=re.S)
        # The CLI rstrips ingested prose; the replay honors the same rule.
        gates.append((gid, title, qbody.rstrip("\n")))
    return run_id, run_title, intro, gates, resolved


# The migration's store-only judgments: what each gate relates to and blocks,
# and G4's overtaken status (its heading says it: the question was resolved
# by events before the human replied). Pinned here, not re-derived.
# Advanced 2026-09-16 by the gate session (G1/G2 answered, G3 waived via the
# CLI; the md view carries the annotations, the JSON the answers).
MIGRATED_META = {
    "G1": {"asked": "2026-09-14", "status": "answered", "related": ["#386"],
           "blocking": ["#386"],
           "answer": "Key custody: maintainer holds the offline private key, agents verify against the public half. Retention: Sigstore/Rekor anchor. Transcript prerequisite: TRACKED work before signing lands. #386 unparks on these terms.",
           "answered": "2026-09-16"},
    "G2": {"asked": "2026-09-14", "status": "answered", "related": ["#397"],
           "blocking": [],
           "answer": "Applied 2026-09-16: main + review/2026-09-14-holistic-fixes protected (strict gates + Greptile, 1 approval + dismiss-stale, conversation resolution, admins enforced). Verdict-derived reviewed_sha==head_sha remainder tracked as #452.",
           "answered": "2026-09-16"},
    "G3": {"asked": "2026-09-14", "status": "waived",
           "related": ["#392", "#391", "#395", "#400", "#402", "#403", "#401",
                       "#404"], "blocking": [],
           "answer": "Single GitHub identity: independent APPROVEs impossible in-session. Maintainer accepts build-blind COMMENTED GO + executed-NC + green CI as sufficient; recorded per the ask.",
           "answered": "2026-09-16"},
    "G4": {"asked": "2026-09-14", "status": "overtaken", "related": ["#364"],
           "blocking": [], "answer": None, "answered": "2026-09-14"},
}


def _rebuild_from_md(md_text):
    run_id, run_title, intro, gates, resolved = _parse_legacy_md(md_text)
    data = {"schema": gb.SCHEMA_TAG, "run_id": run_id, "run_title": run_title,
            "intro": intro, "gates": [], "resolved_by_events": resolved}
    for gid, title, question in gates:
        meta = MIGRATED_META[gid]
        gb.add_gate(data, gid=gid, title=title, question=question,
                    asked=meta["asked"], related=meta["related"],
                    blocking=meta["blocking"])
    for gid, meta in MIGRATED_META.items():
        if meta["status"] != "owed":
            # History, not a transition: a legacy .md records no human source, and the
            # rebuilt JSON must equal the committed one byte for byte.
            gate = gb.find_gate(data, gid)
            gate.update(status=meta["status"], answer=meta["answer"], answered=meta["answered"])
            gb.validate_gate(gate)
    return data


class MigrationRoundTrip(unittest.TestCase):
    def test_the_real_batch_round_trips_byte_identical(self):
        md_text = REAL_MD.read_text(encoding="utf-8")
        rebuilt = _rebuild_from_md(md_text)
        self.assertEqual(
            rebuilt, json.loads(REAL_JSON.read_text(encoding="utf-8")),
            "the committed JSON is not what the committed .md migrates to")
        self.assertEqual(
            gb.render_batch(rebuilt), md_text,
            "md -> json -> md lost or added a byte")
        committed = json.loads(REAL_JSON.read_text(encoding="utf-8"))
        gb.validate_batch(committed)
        self.assertEqual(gb.render_batch(committed), md_text)

    def test_recorded_answer_text_renders_as_an_annotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, data = fresh_batch(tmp, run_id="r", run_title="t",
                                  intro="i")
            add_owed(data, "G1", asked="2026-09-14", title="ask",
                     question="q?")
            gb.transition(data, "G1", "answered", "yes", answered="2026-09-15", source="human:lia")
            self.assertIn("**Answered 2026-09-15 (human:lia):** yes", gb.render_batch(data))
            gb.find_gate(data, "G1").pop("source")  # a record from before the field renders as it did
            rendered = gb.render_batch(data)
            self.assertIn("**Answered 2026-09-15:** yes", rendered)
            self.assertIn("q?", rendered.split("**Answered")[0])


class DanglingCitationsWarn(unittest.TestCase):
    def _run_dir_with(self, tmp, cited_text):
        path = Path(tmp) / "gate-batch.json"
        data = gb.init_batch(path, run_id="r", run_title="t")
        add_owed(data, "G1")
        gb.save_batch(path, data)
        (Path(tmp) / "u1-manifest.json").write_text(
            json.dumps({"note": cited_text}), encoding="utf-8")
        return path

    def test_a_manifest_citing_an_unknown_gate_warns_but_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._run_dir_with(
                tmp, "parked needs-human, ref gate-batch.json G9")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = gb.main(["--file", str(path), "list"])
            self.assertEqual(code, 0)
            self.assertIn("G9", err.getvalue())
            self.assertIn("u1-manifest.json", err.getvalue())
            self.assertIn("G1 [owed]", out.getvalue())

    def test_known_ids_and_bare_prose_never_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._run_dir_with(
                tmp, "ref gate-batch.json G1; the G9 ASK body was reworded; "
                     "see gate-batch.md G1 too")
            data = gb.load_batch(path)
            self.assertEqual(gb.check_citations(data, Path(tmp)), [])

    def test_the_real_run_dir_is_citation_clean(self):
        data = gb.load_batch(REAL_JSON)
        self.assertEqual(gb.check_citations(data, RUN_DIR), [])

    def test_line_anchored_and_range_citations_resolve(self):
        # Forms the 2026-09-14 corpus actually uses: drain-387-threads cites
        # "gate-batch.md:22 (G2 ...)", the run report "gate-batch.md G1-G4".
        # A range counts every id inside it: G3 is cited, not skipped.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "u1-manifest.json").write_text(
                json.dumps({"a": "4012708598 gate-batch.md:22 (G2 branch)",
                            "b": "wrote gate-batch.md G1-G4 at close"}),
                encoding="utf-8")
            cited = gb.cited_gate_ids(Path(tmp))
            self.assertEqual(set(cited), {"G1", "G2", "G3", "G4"})
            self.assertEqual(cited["G2"], ["u1-manifest.json"])

    def test_a_range_whose_middle_is_missing_warns_on_the_middle(self):
        # G1-G4 cited but the batch carries only G1, G2, G4: the check
        # must name G3 — the exact case endpoint-only parsing missed.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gate-batch.json"
            data = gb.init_batch(path, run_id="r", run_title="t")
            for gid in ("G1", "G2", "G4"):
                add_owed(data, gid)
            gb.save_batch(path, data)
            (Path(tmp) / "u1-manifest.json").write_text(
                json.dumps({"note": "see gate-batch.md G1-G4"}),
                encoding="utf-8")
            warnings = gb.check_citations(gb.load_batch(path), Path(tmp))
            self.assertEqual(len(warnings), 1)
            self.assertIn("G3", warnings[0])
            self.assertIn("u1-manifest.json", warnings[0])


class HelpAndWiring(unittest.TestCase):
    SUBCOMMANDS = ("init", "add", "answer", "waive", "overtake", "list",
                   "stale", "show", "render")

    def test_every_subcommand_help_carries_an_example(self):
        for sub in self.SUBCOMMANDS:
            with self.subTest(subcommand=sub):
                out = io.StringIO()
                with redirect_stdout(out), self.assertRaises(SystemExit) as cm:
                    gb.main([sub, "--help"])
                self.assertEqual(cm.exception.code, 0)
                self.assertIn("example:", out.getvalue())

    def test_conductor_close_names_the_mechanism(self):
        # Orphan-wiring philosophy (#284): the close playbook's gate rule is
        # doctrine wearing a mechanism's clothes unless it names the tool.
        text = (ROOT / "runtime" / "conductor-close.md").read_text(
            encoding="utf-8")
        self.assertIn("gate-batch.py", text)
        self.assertIn("stale", text)
        self.assertIn("overtaken", text)
        self.assertIn("--blocking", text)
        self.assertNotIn("waits while `stale`", text)

    def test_the_schema_file_and_the_module_agree(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        enum = schema["$defs"]["gate"]["properties"]["status"]["enum"]
        self.assertEqual(enum, list(gb.STATUSES))
        required = schema["$defs"]["gate"]["required"]
        self.assertEqual(set(required), set(gb.REQUIRED_GATE_KEYS))


def _schema_check(root, subschema, value, path, errors):
    """A stdlib JSON-Schema-subset evaluator (the suite takes no third-party
    deps): type/const/enum/pattern/minLength/properties/required/
    additionalProperties/items/$ref/if-then/allOf. Draft 2020-12 semantics
    for the keywords the gate-batch schema uses; anything else is ignored
    as annotation. Cross-checked against the real `jsonschema` lib on every
    record below before it was committed."""
    if "$ref" in subschema:
        node = root
        for part in subschema["$ref"].removeprefix("#/").split("/"):
            node = node[part]
        _schema_check(root, node, value, path, errors)
    want = subschema.get("type")
    if want is not None:
        wants = [want] if isinstance(want, str) else list(want)
        kinds = {"null": value is None, "string": isinstance(value, str),
                 "array": isinstance(value, list),
                 "object": isinstance(value, dict)}
        if not any(kinds.get(kind, False) for kind in wants):
            errors.append(f"{path}: want type {wants}")
            return
    if "const" in subschema and value != subschema["const"]:
        errors.append(f"{path}: want const {subschema['const']!r}")
    if "enum" in subschema and value not in subschema["enum"]:
        errors.append(f"{path}: not one of {subschema['enum']}")
    if "pattern" in subschema and isinstance(value, str):
        if not re.search(subschema["pattern"], value):
            errors.append(f"{path}: {value!r} misses {subschema['pattern']}")
    if "minLength" in subschema and isinstance(value, str):
        if len(value) < subschema["minLength"]:
            errors.append(f"{path}: shorter than {subschema['minLength']}")
    if isinstance(value, dict):
        for key in subschema.get("required", ()):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        props = subschema.get("properties", {})
        for key, sub in props.items():
            if key in value:
                _schema_check(root, sub, value[key], f"{path}.{key}",
                              errors)
        if subschema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path}: unknown field {key}")
    if isinstance(value, list) and "items" in subschema:
        for pos, item in enumerate(value):
            _schema_check(root, subschema["items"], item, f"{path}[{pos}]",
                          errors)
    for pos, sub in enumerate(subschema.get("allOf", ())):
        _schema_check(root, sub, value, f"{path}<all{pos}>", errors)
    if "if" in subschema:
        trial = []
        _schema_check(root, subschema["if"], value, path, trial)
        if not trial and "then" in subschema:
            _schema_check(root, subschema["then"], value, path, errors)


def _schema_errors(schema, batch):
    errors = []
    _schema_check(schema, schema, batch, "$", errors)
    return errors


def _batch_with_gate(**gate_fields):
    gate = {"id": "G1", "title": "ask", "question": "the ask?",
            "asked": "2026-09-14", "status": "owed", "answer": None,
            "answered": None, "related": [], "blocking": []}
    gate.update(gate_fields)
    return {"schema": "gate-batch/1", "run_id": "r", "run_title": "t",
            "intro": "", "gates": [gate], "resolved_by_events": ""}


class SchemaAndCliAgree(unittest.TestCase):
    VALID = (
        ("owed", {}),
        ("answered", {"status": "answered", "answer": "yes",
                      "answered": "2026-09-15"}),
        ("waived", {"status": "waived", "answer": "moot",
                    "answered": "2026-09-15"}),
        ("overtaken without a note",
         {"status": "overtaken", "answered": "2026-09-14"}),
        ("overtaken with a note",
         {"status": "overtaken", "answer": "merged already",
          "answered": "2026-09-14"}),
    )
    INVALID = (
        # Every class the schema used to accept while the CLI rejected.
        ("owed carrying answer text", {"answer": "early"}),
        ("owed carrying an answered date", {"answered": "2026-09-15"}),
        ("answered with a null answer",
         {"status": "answered", "answered": "2026-09-15"}),
        ("answered with a blank answer",
         {"status": "answered", "answer": "   ", "answered": "2026-09-15"}),
        ("waived with a null answer",
         {"status": "waived", "answered": "2026-09-15"}),
        ("blank title", {"title": "  "}),
        ("blank question", {"question": "\n\t "}),
        ("impossible asked date", {"asked": "2026-99-99"}),
        ("impossible answered date",
         {"status": "answered", "answer": "y", "answered": "2026-13-40"}),
    )

    def test_representative_records_agree_across_both_validators(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        for name, fields in self.VALID:
            with self.subTest(name=name):
                batch = _batch_with_gate(**fields)
                gb.validate_batch(batch)
                self.assertEqual(_schema_errors(schema, batch), [])
        for name, fields in self.INVALID:
            with self.subTest(name=name):
                batch = _batch_with_gate(**fields)
                with self.assertRaises(gb.GateError):
                    gb.validate_batch(batch)
                self.assertNotEqual(_schema_errors(schema, batch), [])

    def test_a_blank_run_title_fails_both_validators(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        batch = _batch_with_gate()
        batch["run_title"] = "  "
        with self.assertRaises(gb.GateError):
            gb.validate_batch(batch)
        self.assertNotEqual(_schema_errors(schema, batch), [])

    def test_the_real_batch_passes_both_validators(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        committed = json.loads(REAL_JSON.read_text(encoding="utf-8"))
        gb.validate_batch(committed)
        self.assertEqual(_schema_errors(schema, committed), [])


class MutationsRenderTheView(unittest.TestCase):
    def test_init_add_and_answer_re_render_the_sibling_md(self):
        # "md is a view" holds only when no second command is needed: each
        # mutation rewrites gate-batch.md, and render --check then agrees.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gate-batch.json"
            md = Path(tmp) / "gate-batch.md"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    gb.main(["--file", str(path), "init", "--title", "t",
                             "--intro", "standing"]),
                    0)
            self.assertTrue(md.is_file(), "init renders the empty view")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    gb.main(["--file", str(path), "add", "--title", "ask me",
                             "--question", "the ask?",
                             "--asked", "2026-09-14"]),
                    0)
            self.assertIn("## G1 \u00b7 ask me",
                          md.read_text(encoding="utf-8"))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    gb.main(["--file", str(path), "answer", "G1",
                             "--answer", "yes", "--date", "2026-09-15",
                             "--source", "human:lia"]),
                    0)
            self.assertIn("**Answered 2026-09-15 (human:lia):** yes",
                          md.read_text(encoding="utf-8"))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    gb.main(["--file", str(path), "render", "--check"]), 0)


class InitGuardsLegacyView(unittest.TestCase):
    LEGACY = ("# Run-close human-gate batch \u2014 legacy (Legacy run)\n"
              "\nstanding intro\n\n## G1 \u00b7 old ask\n\n"
              "the old question?\n")

    def test_init_refuses_when_the_sibling_md_already_exists(self):
        # Pre-tooling runs hold their only gate record in gate-batch.md:
        # a bare init must refuse before writing anything, leaving the
        # migration source byte-identical and creating no JSON store.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gate-batch.json"
            md = Path(tmp) / "gate-batch.md"
            md.write_text(self.LEGACY, encoding="utf-8")
            before = md.read_bytes()
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = gb.main(["--file", str(path), "init",
                                "--title", "t"])
            self.assertEqual(code, 2)
            self.assertEqual(md.read_bytes(), before,
                             "the refused run must not touch the legacy md")
            self.assertFalse(path.exists(),
                             "the refused run must not create a store")
            message = err.getvalue()
            self.assertIn("gate-batch.md", message)
            self.assertIn("--force-init-over-md", message)
            self.assertIn("back", message)

    def test_init_overwrites_legacy_md_only_with_the_explicit_flag(self):
        # The escape hatch is opt-in per run: without it the md survives,
        # with it the empty view replaces the legacy prose and the fresh
        # pair passes render --check.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gate-batch.json"
            md = Path(tmp) / "gate-batch.md"
            md.write_text(self.LEGACY, encoding="utf-8")
            before = md.read_bytes()
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(
                    gb.main(["--file", str(path), "init",
                             "--title", "t", "--force-init-over-md"]), 0)
            self.assertNotEqual(md.read_bytes(), before)
            self.assertTrue(path.is_file())
            self.assertIn("Run-close human-gate batch",
                          md.read_text(encoding="utf-8"))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    gb.main(["--file", str(path), "render", "--check"]), 0)

    def test_init_help_names_the_destruction(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            gb.main(["init", "--help"])
        self.assertEqual(cm.exception.code, 0)
        text = out.getvalue()
        self.assertIn("--force-init-over-md", text)
        self.assertIn("DESTROY", text.upper())


class AtomicSaves(unittest.TestCase):
    def test_a_failed_replace_leaves_the_old_store_untouched(self):
        # The bytes land in a tmp sibling; os.replace commits them. If the
        # commit dies, the old store reads back whole — never half a write.
        with tempfile.TemporaryDirectory() as tmp:
            path, data = fresh_batch(tmp)
            add_owed(data, "G1")
            gb.save_batch(path, data)
            before = path.read_bytes()
            add_owed(data, "G2")
            with mock.patch.object(gb.os, "replace",
                                   side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    gb.save_batch(path, data)
            try:
                self.assertEqual(path.read_bytes(), before)
                staged = Path(str(path) + ".tmp")
                self.assertTrue(staged.is_file(), "the new bytes stage first")
                self.assertIn("G2", staged.read_text(encoding="utf-8"))
            finally:
                for litter in Path(tmp).glob("*.tmp"):
                    litter.unlink()

    def test_a_successful_save_leaves_no_tmp_sibling_behind(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, data = fresh_batch(tmp)
            add_owed(data, "G1")
            gb.save_batch(path, data)
            self.assertEqual(list(Path(tmp).glob("*.tmp")), [])
            self.assertEqual(gb.load_batch(path)["gates"], data["gates"])


class Disambiguation(unittest.TestCase):
    """S13: gate-batch.py is a LOCAL run-close tracker, not upstream's
    decision-gates (orchestration gate-create/gate-resolve/gate-list). The
    same word names two mechanisms; the header, the docstring, and --help
    must all say which one this is, in place."""

    def test_docstring_disambiguates(self):
        doc = gb.__doc__ or ""
        self.assertIn("NOT", doc)
        self.assertIn("gate-create", doc)
        self.assertIn("local", doc.lower())

    def test_help_disambiguates(self):
        import subprocess
        script = ROOT / "runtime" / "scripts" / "gate-batch.py"
        r = subprocess.run(["python3", str(script), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NOT", r.stdout)
        self.assertIn("gate-create", r.stdout)

    def test_parser_description_disambiguates(self):
        parser = gb.build_parser()
        blob = (parser.description or "") + (parser.epilog or "")
        self.assertIn("NOT", blob)


class HumanAnswersAreSignedOnceAKeyIsPinned(unittest.TestCase):
    """W3-06 (2026-10-27 security audit, P2): `source` was shape-checked only (`human:\\S+`) and
    the store is plain JSON, so a worker could write `"status": "answered", "source": "human:x"`
    (or run `answer --source human:anyone`) and the run-close predicate — `list --status owed
    --blocking <unit>`, the release gate's own check — read the blocker as answered by a human.
    Once `.orca/human-grant-pubkey` is pinned (decisions.py's human grant key), a terminal gate
    counts only with a signature that verifies over the run, the gate, its status, text, date and
    source; an unverifiable one is OWED. On a lane claiming soundness, no pinned key means no
    answer verifies. With no key and no sound lane nothing changes (this repository today)."""

    SEED = bytes(range(7, 39))
    SCRIPT = ROOT / "runtime" / "scripts" / "gate-batch.py"

    def setUp(self):
        import subprocess
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name).resolve()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.tmp)], check=True)
        self.ed = _ed25519()
        self.pin = self.tmp / ".orca" / "human-grant-pubkey"
        self.pin.parent.mkdir()
        self.pin.write_text(self.ed.publickey(self.SEED).hex() + "\n", encoding="utf-8")
        self.seed_path = Path(tempfile.mkdtemp()) / "human-seed"
        self.addCleanup(lambda: self.seed_path.unlink(missing_ok=True))
        self.seed_path.write_text(self.SEED.hex() + "\n", encoding="utf-8")
        self.seed_path.chmod(0o600)
        self.batch = self.tmp / "docs" / "runs" / "r" / "gate-batch.json"
        data = gb.init_batch(self.batch, run_id="run_w306", run_title="w306")
        add_owed(data, "G1", blocking=["#1"])
        gb.save_batch(self.batch, data)

    def cli(self, *args, env_extra=None):
        import os
        import subprocess
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        env.update(env_extra or {})
        return subprocess.run([sys.executable, str(self.SCRIPT), "--file", str(self.batch), *args],
                              capture_output=True, text=True, env=env)

    def owed(self, **kw):
        r = self.cli("list", "--status", "owed", "--blocking", "#1", **kw)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def type_an_answer(self):
        data = json.loads(self.batch.read_text(encoding="utf-8"))
        data["gates"][0].update(status="answered", answer="ship it", answered="2026-09-15",
                                source="human:lia")
        self.batch.write_text(json.dumps(data), encoding="utf-8")

    def test_an_answer_typed_into_the_store_is_still_owed(self):
        self.type_an_answer()
        self.assertIn("G1 [owed]", self.owed(), "a typed answer satisfied the close predicate")

    def test_the_cli_refuses_an_unsigned_human_answer(self):
        r = self.cli("answer", "G1", "--answer", "ship it", "--source", "human:lia",
                     "--date", "2026-09-15")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("--grant-sig", r.stderr)
        self.assertIn("G1 [owed]", self.owed())

    def test_a_signed_answer_closes_the_gate_and_only_that_answer_verifies(self):
        sign = self.cli("sign-answer", "G1", "--status", "answered", "--answer", "ship it",
                        "--source", "human:lia", "--date", "2026-09-15",
                        "--key", str(self.seed_path))
        self.assertEqual(sign.returncode, 0, sign.stderr)
        sig = sign.stdout.strip()
        wrong = self.cli("answer", "G1", "--answer", "ship it NOW", "--source", "human:lia",
                         "--date", "2026-09-15", "--grant-sig", sig)
        self.assertEqual(wrong.returncode, 2, wrong.stdout)
        self.assertIn("does not verify", wrong.stderr)
        other = self.cli("answer", "G1", "--answer", "ship it", "--source", "human:mallory",
                         "--date", "2026-09-15", "--grant-sig", sig)
        self.assertEqual(other.returncode, 2, other.stdout)
        ok = self.cli("answer", "G1", "--answer", "ship it", "--source", "human:lia",
                      "--date", "2026-09-15", "--grant-sig", sig)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertNotIn("G1", self.owed())
        # the signature travels with the record: copying it onto an edited answer revokes it
        data = json.loads(self.batch.read_text(encoding="utf-8"))
        data["gates"][0]["answer"] = "ship it, and also drop the review"
        self.batch.write_text(json.dumps(data), encoding="utf-8")
        self.assertIn("G1 [owed]", self.owed())

    def test_an_overtaken_gate_needs_the_signature_too(self):
        data = json.loads(self.batch.read_text(encoding="utf-8"))
        data["gates"][0].update(status="overtaken", answered="2026-09-15")
        self.batch.write_text(json.dumps(data), encoding="utf-8")
        self.assertIn("G1 [owed]", self.owed())

    def test_a_sound_lane_with_no_pinned_key_verifies_no_answer(self):
        import subprocess
        self.pin.unlink()
        subprocess.run(["git", "-C", str(self.tmp), "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "--allow-empty", "-m", "base"], check=True)
        base = subprocess.run(["git", "-C", str(self.tmp), "rev-parse", "HEAD"], check=True,
                              capture_output=True, text=True).stdout.strip()
        self.type_an_answer()
        self.assertNotIn("G1", self.owed(), "no key, no sound lane: unchanged behaviour")
        sound = {"ORCA_PROVENANCE": "ci"}
        r = self.cli("list", "--status", "owed", env_extra=sound)
        self.assertEqual(r.returncode, 2, r.stdout)  # no --pin-ref names the trust anchor
        self.assertIn("--pin-ref", r.stderr)
        r = self.cli("--pin-ref", base, "list", "--status", "owed", env_extra=sound)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("G1 [owed]", r.stdout)


class TheOwedSetIsReadWhereTheKeyIsRead(unittest.TestCase):
    """PR #719 review round 3 (P1): signed answers protected each answer, but nothing
    authenticated WHICH gates are owed — `"gates": []`, a deleted or renamed blocker, or a
    blocked ref dropped from an owed gate, and the close predicate (`list --status owed
    --blocking <unit>`, which a coordinator reads as "shows a gate") owed nothing. With --pin-ref
    the batch at the anchor commit is read with the key, and every gate it carries that this
    batch lacks or altered is listed OWED, from the anchor's record — on stdout, where the
    predicate looks. `--pin-ref` itself takes only a commit id or a ref whose final target is
    remote-tracking, resolved once (the soundness predicate every other trust key answers to)."""

    SEED = bytes(range(13, 45))
    SCRIPT = ROOT / "runtime" / "scripts" / "gate-batch.py"

    def git(self, *args):
        import subprocess
        return subprocess.run(["git", "-C", str(self.tmp), "-c", "user.name=t", "-c",
                               "user.email=t@t", "-c", "commit.gpgsign=false", *args],
                              check=True, capture_output=True, text=True).stdout.strip()

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name).resolve()
        self.git("init", "-q", "-b", "main")
        ed = _ed25519()
        self.pin = self.tmp / ".orca" / "human-grant-pubkey"
        self.pin.parent.mkdir()
        self.pin.write_text(ed.publickey(self.SEED).hex() + "\n", encoding="utf-8")
        self.batch = self.tmp / "docs" / "runs" / "r" / "gate-batch.json"
        data = gb.init_batch(self.batch, run_id="run_set", run_title="set")
        add_owed(data, "G1", blocking=["#1"])
        add_owed(data, "G2", blocking=["#1", "#2"], related=["#9"])
        gb.save_batch(self.batch, data)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "the owed gates land")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.anchor = self.git("rev-parse", "HEAD")

    def cli(self, *args, env_extra=None, batch=None):
        import os
        import subprocess
        env = {k: v for k, v in os.environ.items() if not k.endswith("_PROVENANCE")}
        env.update(env_extra or {})
        return subprocess.run([sys.executable, str(self.SCRIPT), "--file",
                               str(batch or self.batch), *args],
                              capture_output=True, text=True, env=env)

    def edit(self, change):
        data = json.loads(self.batch.read_text(encoding="utf-8"))
        change(data)
        self.batch.write_text(json.dumps(data), encoding="utf-8")

    def owed(self, *extra, ref="refs/remotes/origin/main"):
        r = self.cli("--pin-ref", ref, "list", "--status", "owed", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_an_emptied_batch_still_owes_every_anchored_gate(self):
        self.edit(lambda d: d.update(gates=[]))
        out = self.owed("--blocking", "#1")
        self.assertIn("G1 [owed]", out)
        self.assertIn("G2 [owed]", out)
        self.assertIn("missing here", out)
        self.assertIn(self.anchor[:12], out)

    def test_a_dropped_blocked_ref_still_blocks(self):
        self.edit(lambda d: d["gates"][1].update(blocking=["#1"]))
        self.assertIn("G2 [owed]", self.owed("--blocking", "#2"))

    def test_a_renamed_gate_is_owed_under_its_anchored_id(self):
        self.edit(lambda d: d["gates"][1].update(id="G7"))
        out = self.owed()
        self.assertIn("G2 [owed]", out)
        self.assertIn("G7 [owed]", out)

    def sign_all(self, data):
        ed = _ed25519()
        for gate in data["gates"]:
            gate.update(status="answered", answer="yes", answered="2026-09-15", source="human:lia")
            gate["grant_sig"] = ed.signature(gb.answer_payload(data, gate), self.SEED,
                                             ed.publickey(self.SEED)).hex()

    def test_a_signed_answer_closes_an_anchored_gate(self):
        self.edit(self.sign_all)
        self.assertEqual(self.owed(), "")

    def test_a_gate_re_worded_or_re_dated_then_signed_is_owed(self):
        # The human signs what the record says: a question re-worded into something harmless and
        # THEN signed is not the anchored question answered.
        for field, value in (("question", "is the sky blue?"), ("title", "smaller"),
                             ("asked", "2026-09-13")):
            with self.subTest(field=field):
                self.edit(lambda d, f=field, v=value: (d["gates"][1].update({f: v}),
                                                       self.sign_all(d)))
                out = self.owed()
                self.assertIn("G2 [owed]", out)
                self.assertIn(f"its {field} differ", out)
                self.assertNotIn("G1", out)
                self.git("checkout", "-q", "--", "docs")

    def test_a_batch_claiming_another_run_owes_every_anchored_gate(self):
        self.edit(lambda d: (d.update(run_id="run_elsewhere"), self.sign_all(d)))
        out = self.owed()
        self.assertIn("G1 [owed]", out)
        self.assertIn("G2 [owed]", out)
        self.assertIn("run_elsewhere", out)

    def test_stale_and_show_read_the_same_set(self):
        self.edit(lambda d: d.update(gates=[]))
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "stale", "--days", "1",
                     "--today", "2026-10-01")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("G1 owed", r.stdout)
        self.assertIn("G2 owed", r.stdout)
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "show", "G2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("status: owed", r.stdout)
        self.assertIn("missing here", r.stdout)

    def test_a_re_dated_gate_stays_stale_from_its_anchored_date(self):
        # Codex round 4 (P2): the drifted gate was owed but its WORKER record was what the views
        # read, so an `asked` moved into the future hid an overdue anchored question from stale.
        self.edit(lambda d: d["gates"][0].update(asked="2099-01-01"))
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "stale", "--days", "7",
                     "--today", "2026-10-27")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("G1 owed 43 days (asked 2026-09-14)", r.stdout)
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "show", "G1")
        self.assertIn("asked 2026-09-14", r.stdout)
        self.assertNotIn("2099", r.stdout)
        self.assertIn("G1 [owed] asked 2026-09-14", self.owed())

    def test_a_reworded_gate_shows_the_anchored_question_title_and_refs(self):
        def reword(d):
            d["gates"][1].update(title="a harmless title", question="is the sky blue?",
                                 blocking=["#1"], related=[])
        self.edit(reword)
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "show", "G2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("the question G2", r.stdout)
        self.assertIn("ask G2", r.stdout)
        self.assertIn("#2", r.stdout)
        self.assertIn("#9", r.stdout)
        for planted in ("sky", "harmless"):
            self.assertNotIn(planted, r.stdout)
        out = self.owed("--blocking", "#2")
        self.assertIn("G2 [owed] asked 2026-09-14 \u00b7 ask G2", out)
        self.assertNotIn("harmless", out)

    def test_refs_dropped_from_an_otherwise_unchanged_gate_still_show(self):
        self.edit(lambda d: d["gates"][1].update(blocking=["#1"], related=[]))
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "show", "G2")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("related: #9", r.stdout)
        self.assertIn("blocking: #1, #2", r.stdout)

    def test_show_names_a_typed_answer_as_owed(self):
        self.edit(lambda d: d["gates"][0].update(status="answered", answer="typed",
                                                 answered="2026-09-15", source="human:x"))
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "show", "G1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("status: owed", r.stdout)
        self.assertIn("recorded answered", r.stdout)

    def test_the_pin_ref_is_a_commit_or_a_remote_tracking_ref_resolved_once(self):
        self.assertIn("G1 [owed]", self.owed(ref=self.anchor))
        self.assertIn("G1 [owed]", self.owed(ref="refs/remotes/origin/main"))
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        self.assertIn("G1 [owed]", self.owed(ref="refs/remotes/origin/HEAD"))
        # A local branch, a short name, HEAD, a tag, and a refs/remotes/ name symbolic to a local
        # branch are all the checked change's to move: refused on every lane.
        self.git("tag", "t1")
        self.git("symbolic-ref", "refs/remotes/origin/sly", "refs/heads/main")
        for ref in ("main", "refs/heads/main", "origin/main", "HEAD", "t1",
                    "refs/remotes/origin/sly", "-q"):
            with self.subTest(ref=ref):
                r = self.cli("--pin-ref", ref, "list", "--status", "owed")
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertEqual(r.stdout, "")

    def test_the_key_and_the_set_are_read_at_one_commit(self):
        seen = []
        real = gb._decisions

        def spy():
            dec = real()
            grant = dec.grant_pubkey
            dec.grant_pubkey = lambda path, ref=None: seen.append(ref) or grant(path, ref)
            return dec
        with mock.patch.object(gb, "_decisions", spy):
            pub, anchored, commit = gb.read_trust(self.batch, "refs/remotes/origin/main")
        self.assertEqual(commit, self.anchor)
        self.assertEqual(seen, [self.anchor])
        self.assertEqual([g["id"] for g in anchored["gates"]], ["G1", "G2"])
        self.assertIsNotNone(pub)

    def test_a_symlink_inside_the_repository_cannot_redirect_the_read(self):
        other = self.tmp / "docs" / "runs" / "elsewhere"
        other.mkdir()
        data = gb.init_batch(other / "gate-batch.json", run_id="run_set", run_title="set")
        gb.save_batch(other / "gate-batch.json", data)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "an empty batch elsewhere, also on main")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        run = self.batch.parent
        run.rename(self.tmp / "docs" / "runs" / "moved")
        run.symlink_to(other)
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "list", "--status", "owed")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("symlink", r.stderr)

    def test_a_batch_outside_the_anchored_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, data = fresh_batch(tmp)
            gb.save_batch(path, data)
            r = self.cli("--pin-ref", self.anchor, "list", batch=path)
            self.assertEqual(r.returncode, 2, r.stdout)

    def test_a_malformed_anchored_batch_is_could_not_run(self):
        self.batch.write_text("{not json", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "a broken store on main")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        data = gb.init_batch(self.batch.with_name("x.json"), run_id="run_set", run_title="set")
        self.batch.with_name("x.json").unlink()
        self.batch.write_text(json.dumps(data), encoding="utf-8")
        r = self.cli("--pin-ref", "refs/remotes/origin/main", "list", "--status", "owed")
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn(self.git("rev-parse", "HEAD")[:12], r.stderr)

    def test_without_an_anchor_a_pinned_key_says_the_set_is_unanchored(self):
        r = self.cli("list", "--status", "owed")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--pin-ref", r.stderr)

    def emptied_on(self, ref):
        """The change empties the batch, commits it, and points the LOCAL ref `ref` at that."""
        self.edit(lambda d: d.update(gates=[]))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "no gates owed")
        self.git("update-ref", ref, "HEAD")

    def test_a_local_branch_spelled_as_an_absent_remote_tracking_ref_is_no_anchor(self):
        # W3-07, Codex review (P1): with refs/remotes/origin/main absent, `rev-parse
        # refs/remotes/origin/main` expands to the local branch refs/heads/refs/remotes/origin/main
        # — the change's own, carrying an empty batch — and nothing was owed.
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.emptied_on("refs/heads/refs/remotes/origin/main")
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        for ref in ("refs/remotes/origin/main", "refs/remotes/origin/HEAD"):
            with self.subTest(ref=ref):
                r = self.cli("--pin-ref", ref, "list", "--status", "owed")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertIn("exactly that name", r.stderr)

    def test_a_local_bridge_inside_a_remote_tracking_chain_is_no_anchor(self):
        # Codex review round 2 (P1): for-each-ref's %(symref) is the chain's END, so
        # refs/remotes/worker/key -> refs/heads/bridge -> refs/remotes/origin/stale read as
        # remote-tracking all the way and the local bridge was never seen.
        self.emptied_on("refs/remotes/origin/stale")
        self.git("symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/stale")
        self.git("symbolic-ref", "refs/remotes/worker/key", "refs/heads/bridge")
        self.git("symbolic-ref", "refs/remotes/worker/b", "refs/heads/bridge")
        self.git("symbolic-ref", "refs/remotes/worker/a", "refs/remotes/worker/b")
        for ref in ("refs/remotes/worker/key", "refs/remotes/worker/a"):
            with self.subTest(ref=ref):
                r = self.cli("--pin-ref", ref, "list", "--status", "owed")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(r.stdout, "")
                self.assertIn("refs/heads/bridge", r.stderr)

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_anchor(self):
        # Independent re-attack (A): str.splitlines() broke the listing at U+2028/U+2029/U+0085,
        # which git accepts in a refname, so `x<U+2028>refs/remotes/origin/main` at an emptied
        # batch replaced origin/main and nothing was owed.
        self.emptied_on("refs/heads/emptied")
        emptied = self.git("rev-parse", "refs/heads/emptied")
        for ch in refname_breaks.LINE_BREAKS:
            with self.subTest(ch=ch):
                unplant = refname_breaks.plant(self.tmp, ch, emptied)
                try:
                    out = self.owed()
                finally:
                    unplant()
                self.assertIn("G1 [owed]", out)
                self.assertIn("G2 [owed]", out)

    def test_a_hex_named_branch_is_no_commit_id(self):
        # In a SHA-1 repository 64 hex digits are no object id: rev-parse expands them as a ref.
        hexname = "cd" * 32
        self.emptied_on(f"refs/heads/{hexname}")
        r = self.cli("--pin-ref", hexname, "list", "--status", "owed")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("names no commit object", r.stderr)

    def test_a_revision_suffix_names_no_anchor(self):
        # The reviewed default branch asks G3 one commit after the setUp anchor; origin/main~1
        # (or its reflog's @{1}) is the older batch without it, and passed the prefix check.
        data = json.loads(self.batch.read_text(encoding="utf-8"))
        add_owed(data, "G3", blocking=["#3"])
        gb.save_batch(self.batch, data)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "G3 is asked")
        self.git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.edit(lambda d: d.update(gates=[g for g in d["gates"] if g["id"] != "G3"]))
        self.assertIn("G3 [owed]", self.owed("--blocking", "#3"))
        for ref in ("refs/remotes/origin/main~1", "refs/remotes/origin/main^",
                    "refs/remotes/origin/main@{1}"):
            with self.subTest(ref=ref):
                r = self.cli("--pin-ref", ref, "list", "--status", "owed", "--blocking", "#3")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                self.assertEqual(r.stdout, "")
                self.assertIn("not a valid ref name", r.stderr)

    def test_nested_submodule_or_git_dir_cannot_substitute_governance_anchor(self):
        # C20: an initialized submodule (.git file -> ../../../.git/modules/sub) or nested .git
        # directory inside the outer repository must fail closed rather than substituting its own
        # .orca/human-grant-pubkey and empty gate-batch anchor.
        import subprocess
        sub_run = self.tmp / "docs" / "runs" / "sub"
        sub_run.mkdir(parents=True)
        mod_git = self.tmp / ".git" / "modules" / "sub"
        subprocess.run(["git", "init", "-q", "--bare", str(mod_git)], check=True)
        (sub_run / ".git").write_text("gitdir: ../../../.git/modules/sub\n", encoding="utf-8")
        sub_batch = sub_run / "gate-batch.json"
        data = gb.init_batch(sub_batch, run_id="run_sub", run_title="sub")
        gb.save_batch(sub_batch, data)

        r = self.cli("--pin-ref", "refs/remotes/origin/main", "list", "--status", "owed",
                     batch=sub_batch)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("nested repository", r.stderr)


if __name__ == "__main__":
    unittest.main()
