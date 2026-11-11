#!/usr/bin/env python3
"""
Doctrine consistency between missions, playbooks, runtime policies and guides (#626, #627).

The 2026-10-23 review (docs/reviews/2026-10-23-end-to-end-review.md, P1-12 and P2-26..P2-41)
found contradictions no check read: a playbook handing work to a playbook its missions never
load, a mission body relying on a doc it neither composes nor defers, a deferred read keyed to a
phase the pipeline does not have, a mission in no evidence class, a FREEZE no human gates, a pin
whose witness level disagrees with its own record. Each class below is the mechanical form of one
of those findings, written against the grammar the catalog already uses:

- composed = backticked names and bare `name.md` tokens in a Composes/rides clause
  (scripts/validate.py's COMPOSE_CLAUSE_RE — the activation-load grammar);
- deferred = every protocol name in a DEFERRED READS paragraph (up to a capital "Never", which
  opens an exclusion), plus every `read <name>` cue;
- a CALL is a backticked playbook name inside a playbook (scripts/bundle.py's grammar: "Playbooks
  call each other with bare backticks"); a bare `name.md` there is a citation of where a rule
  lives, not a call. A `read <name>.md` cue in a loaded doc is a deferred read every mission
  loading that doc inherits.

    python3 -m unittest tests.test_doctrine_consistency -v
"""
import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("validate", ROOT / "scripts" / "validate.py")
validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate)

SKILLS = ROOT / "skills"
PLAYBOOKS = ROOT / "playbooks"
RUNTIME = ROOT / "runtime"
GUIDES = ROOT / "docs" / "missions"

NAME = r"[a-z0-9][a-z0-9-]*"
DEFERRED_RE = re.compile(r"(?m)^[ \t*_]*DEFERRED READS\b(.+?)(?:\n\n|\Z)", re.DOTALL)
WORD_RE = re.compile(r"(?<![\w./-])([a-z0-9]+(?:-[a-z0-9]+)*)")
READ_CUE_RE = re.compile(rf"\b[Rr]ead\s+`?({NAME})")
# The provenance sentence names UPSTREAM skills (gstack `ship`, Matt `tdd`), not playbooks.
RECIPE_RE = re.compile(r"(?m)^Recipe:.*?\.(?=\s|\Z)", re.DOTALL)
PIPELINE_RE = re.compile(r"## Pipeline[^\n]*\n+```[^\n]*\n(.*?)```", re.DOTALL)
# A deferred read is keyed to a phase: "at VERDICT", "on entering SELF-ORIENT", "at the first BAKE",
# "at build-blind REVIEW", "at conductor LAND" — up to two lowercase words between.
DEFERRED_PHASE_RE = re.compile(r"\b(?:at|entering)\s+(?:[a-z-]+\s+){0,2}([A-Z][A-Z_-]{2,})\b")


def _playbook_names():
    return {p.stem for p in PLAYBOOKS.glob("*.md")}


def _protocol_names():
    return _playbook_names() | {p.stem for p in RUNTIME.glob("*.md")}


def _protocol_text(name):
    for base in (PLAYBOOKS, RUNTIME):
        path = base / f"{name}.md"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    return ""


def _missions():
    for d in sorted(SKILLS.iterdir()):
        if d.is_dir() and not d.name.startswith((".", "_")) and (d / "SKILL.md").is_file():
            yield d.name, (d / "SKILL.md").read_text(encoding="utf-8")


def _body(skill_text):
    """The instruction surface: frontmatter stripped, the Related pointers cut off."""
    m = re.match(r"^---[ \t]*\r?\n.*?\r?\n---[ \t]*\r?\n", skill_text, re.DOTALL)
    body = skill_text[m.end():] if m else skill_text
    return body.split("\n## Related", 1)[0]


def _names(text, protocols):
    """Protocol names a text mentions as backticked names or bare `name.md` tokens."""
    return (set(validate.BACKTICK_RE.findall(text)) | set(validate.bare_md_stems(text))) & protocols


def composed(text, protocols):
    found = set()
    for clause in validate.COMPOSE_CLAUSE_RE.findall(text):
        found |= _names(clause, protocols)
    return found


def _deferred_paragraphs(text):
    """Each DEFERRED READS paragraph up to a capital "Never" — what follows it is an exclusion."""
    return [re.split(r"\bNever\b", para, maxsplit=1)[0] for para in DEFERRED_RE.findall(text)]


def deferred(text, protocols):
    found = set()
    for para in _deferred_paragraphs(text):
        found |= set(WORD_RE.findall(para)) & protocols
    return found | read_cues(text, protocols)


def read_cues(text, protocols):
    return set(READ_CUE_RE.findall(text)) & protocols


def calls(playbook_text, playbooks, own):
    """Backticked playbook names a playbook calls, its Recipe provenance sentence excluded."""
    text = RECIPE_RE.sub("", playbook_text, count=1)
    return (set(validate.BACKTICK_RE.findall(text)) & playbooks) - {own}


def loaded_closure(skill_text, protocols):
    """What a mission loads: its clause, its deferred reads, and every read cue those docs carry."""
    body = _body(skill_text)
    loaded = composed(body, protocols) | deferred(body, protocols)
    frontier = list(loaded)
    while frontier:
        for name in read_cues(_protocol_text(frontier.pop()), protocols) - loaded:
            loaded.add(name)
            frontier.append(name)
    return loaded


def unloaded_calls():
    """[(mission, caller, callee)] — a loaded playbook calls one the mission never loads (P2-40)."""
    protocols, playbooks = _protocol_names(), _playbook_names()
    out = []
    for mission, text in _missions():
        loaded = loaded_closure(text, protocols)
        for caller in sorted(loaded & playbooks):
            for callee in sorted(calls(_protocol_text(caller), playbooks, caller) - loaded):
                out.append((mission, caller, callee))
    return out


def unloaded_mentions():
    """[(mission, name)] — a mission body names a protocol it neither composes nor defers."""
    protocols = _protocol_names()
    out = []
    for mission, text in _missions():
        body = _body(text)
        loaded = composed(body, protocols) | deferred(body, protocols)
        # The DEFERRED READS exclusion ("Never merge-serialization.md") names a doc NOT to load.
        for para in DEFERRED_RE.findall(body):
            body = body.replace(para, re.split(r"\bNever\b", para, maxsplit=1)[0])
        out.extend((mission, n) for n in sorted(_names(body, protocols) - loaded))
    return out


def deferred_phase_gaps():
    """[(mission, phase)] — a deferred read keyed to a phase the mission's pipeline lacks (P2-32)."""
    out = []
    for mission, text in _missions():
        pipe = PIPELINE_RE.search(text)
        pipeline = pipe.group(1) if pipe else ""
        for para in _deferred_paragraphs(text):
            for phase in sorted(set(DEFERRED_PHASE_RE.findall(para))):
                if not re.search(rf"(?<![A-Z_-]){re.escape(phase)}(?![A-Z_-])", pipeline):
                    out.append((mission, phase))
    return out


def evidence_classes():
    """{class label: [missions]} from runtime/evidence-manifest.md §3's class bullets."""
    text = (RUNTIME / "evidence-manifest.md").read_text(encoding="utf-8")
    section = text.split("## 3.", 1)[1].split("\n## ", 1)[0]
    missions = {name for name, _ in _missions()}
    classes = {}
    for label, members in re.findall(r"- \*\*([A-Za-z-]+) units\*\* \((.*?)\):", section, re.DOTALL):
        classes[label] = [m for m in re.findall(NAME, members) if m in missions]
    return classes


# Missions whose FREEZE snapshots a set ENUMERATED from a source the human already named by
# invoking the run (an audit document, a tracker query, the runtime docs' own claims): one
# defensible answer, so the freeze is mechanical (gate-classification.md). Every other FREEZE
# selects the target itself and is the registered one-way `freeze` door (runtime/one-way-doors.json).
MECHANICAL_FREEZE = {
    "clean-sweep": "freezes the triaged findings enumerated from the declared source",
    "oss-contribute": "freezes the triaged upstream issues enumerated from the tracker",
    "pin-it": "freezes the claim inventory extracted from runtime/*.md and runtime/scripts/",
}
FREEZE_STEP_RE = re.compile(r"\bFREEZE\b|\b[Ff]reeze the\b|\b[Ss]cope confirm\b|\bSCOPE CONFIRM\b|\bCONFIRM-SURFACE\b")
# Case-sensitive on purpose: "human-supplied" is not a gate.
GATE_MARK_RE = re.compile(r"decide-and-freeze|[Hh]uman gate|[Oo]ne-way|ONE-WAY|\bHUMAN\b")


def ungated_freezes():
    """[(mission, step)] — a pipeline step that freezes the run's target with no human gate (P1-12)."""
    out = []
    for mission, text in _missions():
        pipe = PIPELINE_RE.search(text)
        if not pipe:
            continue
        for step in re.split(r"→", pipe.group(1)):
            if not FREEZE_STEP_RE.search(step) or GATE_MARK_RE.search(step):
                continue
            # "VALIDATE the freeze" checks an existing one; only a step that freezes counts.
            if re.search(r"\bthe freeze\b", step, re.I) and not re.search(r"\bfreeze the\b|\bFREEZE\b", step):
                continue
            if mission not in MECHANICAL_FREEZE:
                out.append((mission, " ".join(step.split())[:80]))
    return out


class PlaybookCallsAreLoaded(unittest.TestCase):
    """P2-40: remediate-finding handed the fix to `build-change`, human-handoff to `agent-brief`,
    triage-state to `human-handoff`, compound-learn to `diagnose` — playbooks most of their composing
    missions never load. A call must be loaded by every mission that loads the caller, or carry a
    `read <name>.md` cue at the step that needs it (a deferred read the missions then inherit)."""

    def test_every_call_in_a_loaded_playbook_is_loaded(self):
        gaps = unloaded_calls()
        self.assertEqual(gaps, [], "\n".join(
            f"skills/{m}: loaded playbook `{caller}` calls `{callee}`, which {m} neither composes "
            "nor defers — compose/defer it, or write the call as a `read <name>.md` cue"
            for m, caller, callee in gaps))


class MissionBodiesNameOnlyLoadedDocs(unittest.TestCase):
    """§5: access-it relied on human-handoff, offload-it on ledger-contract and liveness-resume,
    modernize-it on agent-brief — none composed or deferred, so a coordinator activating the
    mission never reads them and a bundled install may not ship them."""

    def test_every_protocol_a_mission_body_names_is_composed_or_deferred(self):
        gaps = unloaded_mentions()
        self.assertEqual(gaps, [], "\n".join(
            f"skills/{m}/SKILL.md names {n} outside Related but neither composes nor defers it"
            for m, n in gaps))

    def test_no_mission_sends_an_agent_to_a_human_guide(self):
        # scripts/bundle.py ships a mission's protocols, not docs/missions/ — a pointer there from
        # SKILL.md is a dead end in every copied install (modernize-it:45, migrate-it:103).
        for mission, text in _missions():
            with self.subTest(mission=mission):
                self.assertNotIn("docs/missions/", text,
                                 f"skills/{mission}/SKILL.md points at docs/missions/, which no bundle ships")


class DeferredReadsNameRealPhases(unittest.TestCase):
    """P2-32: oss-contribute deferred reviewed-sha-freshness "at LAND" and has no LAND phase."""

    def test_every_deferred_phase_is_in_the_pipeline(self):
        gaps = deferred_phase_gaps()
        self.assertEqual(gaps, [], "\n".join(
            f"skills/{m}: a deferred read is keyed to {p}, which its Pipeline block never enters"
            for m, p in gaps))


class EveryMissionHasOneEvidenceClass(unittest.TestCase):
    """§5 / P1-12: evidence-manifest.md §3 classified 21 of 22 missions; offload-it was in none."""

    def test_each_mission_is_in_exactly_one_class(self):
        classes = evidence_classes()
        self.assertEqual(set(classes), {"Mutation", "Report-only", "Planning"},
                         "evidence-manifest.md §3's class bullets changed shape — update this parser")
        listed = [m for members in classes.values() for m in members]
        for mission, _ in _missions():
            with self.subTest(mission=mission):
                self.assertEqual(listed.count(mission), 1,
                                 f"{mission} is in {listed.count(mission)} evidence-manifest §3 classes")

    def test_mutation_class_missions_ride_the_evidence_and_sandbox_policies(self):
        mutation = set(evidence_classes()["Mutation"])
        self.assertTrue(set(validate.MUTATING_MISSIONS) <= mutation,
                        f"validate.py MUTATING_MISSIONS lists missions §3 does not: "
                        f"{sorted(set(validate.MUTATING_MISSIONS) - mutation)}")
        for mission, text in _missions():
            if mission not in mutation:
                continue
            rides = {ref for clause in validate.RIDES_CLAUSE_RE.findall(text)
                     for ref in validate.BACKTICK_RE.findall(clause)}
            with self.subTest(mission=mission):
                self.assertTrue({"evidence-manifest", "sandbox-policy"} <= rides,
                                f"{mission} is a §3 mutation unit but does not ride both "
                                "`evidence-manifest` and `sandbox-policy`")


class FreezeIsAHumanGate(unittest.TestCase):
    """P1-12: access-it, attest-it and migrate-it froze their target with no human gate while six
    missions gate it; a headless run then auto-decides the `freeze` door."""

    def test_every_target_freeze_names_its_gate(self):
        gaps = ungated_freezes()
        self.assertEqual(gaps, [], "\n".join(
            f"skills/{m}: pipeline step {s!r} freezes the target with no human gate — route it "
            "through `decide-and-freeze` as a one-way gate (or argue it mechanical here)"
            for m, s in gaps))

    def test_mechanical_freeze_exemptions_are_live(self):
        missions = dict(_missions())
        for mission in MECHANICAL_FREEZE:
            with self.subTest(mission=mission):
                pipe = PIPELINE_RE.search(missions.get(mission, ""))
                self.assertTrue(pipe and FREEZE_STEP_RE.search(pipe.group(1)),
                                f"{mission} no longer freezes — drop its exemption")


class OrcaPinWitnessAgrees(unittest.TestCase):
    """P2-41: pins.json said `live` while orca-pin.md and the run report said `source`."""

    def test_pins_json_witness_matches_the_pin_record_and_its_run_report(self):
        orca = json.loads((RUNTIME / "pins.json").read_text(encoding="utf-8"))["orca"]
        record = (RUNTIME / "orca-pin.md").read_text(encoding="utf-8")
        witnessed = re.search(r"^\|\s*Witnessed\s*\|(.*)\|\s*$", record, re.MULTILINE)
        self.assertIsNotNone(witnessed, "orca-pin.md has no Witnessed row")
        levels = re.findall(r"`(source|live)`", witnessed.group(1))
        self.assertEqual(levels[:1], [orca["witness"]],
                         "pins.json orca.witness disagrees with orca-pin.md's Witnessed row")
        run_row = re.search(r"^\|\s*Run record\s*\|(.*)\|\s*$", record, re.MULTILINE)
        self.assertIsNotNone(run_row, "orca-pin.md has no Run record row")
        report = re.search(r"docs/runs/[\w.-]+\.md", run_row.group(1))
        self.assertIsNotNone(report, "orca-pin.md's Run record names no run report")
        header = (ROOT / report.group(0)).read_text(encoding="utf-8")
        run_level = re.search(r"\bwitness:\s*(source|live)\b", header)
        self.assertIsNotNone(run_level, f"{report.group(0)} states no witness level")
        self.assertEqual(run_level.group(1), orca["witness"],
                         f"pins.json orca.witness disagrees with {report.group(0)}")


class PlaybookShape(unittest.TestCase):
    """§5: six playbooks had no `## Completion`, three no `Recipe:` line — a playbook is a
    versioned protocol with a named source and checkable completion criteria (ARCHITECTURE.md)."""

    def test_every_playbook_has_a_recipe_and_a_completion(self):
        for path in sorted(PLAYBOOKS.glob("*.md")):
            text = path.read_text(encoding="utf-8")
            with self.subTest(playbook=path.stem):
                self.assertRegex(text, r"(?m)^Recipe: \S", f"playbooks/{path.name} names no Recipe:")
                self.assertRegex(text, r"(?m)^## Completion\b",
                                 f"playbooks/{path.name} has no ## Completion section")


class GuidesMatchTheLoadSchedule(unittest.TestCase):
    """P2-32: the oss-contribute and clean-sweep guides listed docs their SKILL defers under
    "At activation"; P2-35: the getting-started tooling table covered 10 of 22 missions."""

    def test_at_activation_lists_no_deferred_doc(self):
        protocols = _protocol_names()
        links = re.compile(r"\]\(\.\./\.\./(?:playbooks|runtime)/([a-z0-9-]+)\.md\)")
        for mission, text in _missions():
            body = _body(text)
            deferred_only = deferred(body, protocols) - composed(body, protocols)
            guide = (GUIDES / f"{mission}.md").read_text(encoding="utf-8")
            section = re.search(r"^## Composes\n(.*?)(?=^## |\Z)", guide, re.DOTALL | re.MULTILINE)
            if not section:
                continue
            activation = re.split(r"(?mi)^Deferred reads\b", section.group(1), maxsplit=1)[0]
            listed = set(validate.BACKTICK_RE.findall(activation)) | set(links.findall(activation))
            with self.subTest(mission=mission):
                self.assertEqual(sorted(listed & deferred_only), [],
                                 f"docs/missions/{mission}.md lists deferred docs as loaded at activation")

    def test_getting_started_tooling_table_covers_every_mission(self):
        text = (ROOT / "docs" / "getting-started.md").read_text(encoding="utf-8")
        rows = set(re.findall(r"(?m)^\|\s*([a-z0-9-]+)\s*\|", text))
        missing = sorted(name for name, _ in _missions() if name not in rows)
        self.assertEqual(missing, [], f"docs/getting-started.md tooling table has no row for {missing}")

    def test_every_mission_with_a_land_step_loads_merge_serialization(self):
        # #750 C13: offload-it reached conductor-owned LAND without loading merge-serialization.
        protocols = _protocol_names()
        missing = []
        for mission, text in _missions():
            pipe = PIPELINE_RE.search(text)
            if not pipe or not re.search(r"\bLAND\b", pipe.group(1)):
                continue
            body = _body(text)
            loaded = composed(body, protocols) | deferred(body, protocols)
            if "merge-serialization" not in loaded:
                missing.append(mission)
        self.assertEqual(missing, [],
                         f"missions with a pipeline LAND step that never load merge-serialization: {missing}")

    def test_research_brief_delegates_writes_past_ro_workers(self):
        # #750 C14: PROFILE=ro workers cannot create or edit repository files; research-brief.md
        # must route both the initial draft and the verification-leg updates through worker_done
        # to the coordinator or a PROFILE=rw writer unit.
        text = " ".join((PLAYBOOKS / "research-brief.md").read_text(encoding="utf-8").split())
        self.assertIn("worker_done", text)
        self.assertRegex(text, r"coordinator\s*\(or a (?:separate )?`PROFILE=rw` writer unit\)\s*(?:materializes|writes)")
        self.assertRegex(text, r"coordinator\s*\(or a `PROFILE=rw` writer unit\)\s*records that verification leg")
        self.assertRegex(text, r"no `PROFILE=ro` worker mutated the (?:repository )?tree")

    def test_oss_contribute_contributed_ledger_states_are_well_formed_c16(self):
        # #750 C16: oss-contribute and ledger-contract.md must agree that a live unparked PR with
        # MERGED=f stays in FOLLOW UP, a quiet PR reaches terminal CONTRIBUTED via
        # awaiting-maintainer-merge (MERGED=f, review.artifact at head_sha, --execute-nc), and a
        # posted review-assist closes with BUILD_DONE..MERGED=n/a, FOLLOWED_UP,WT_CLEAN=t,
        # park=externally-covered.
        skill = " ".join((SKILLS / "oss-contribute" / "SKILL.md").read_text(encoding="utf-8").split())
        ledger = " ".join((RUNTIME / "ledger-contract.md").read_text(encoding="utf-8").split())
        self.assertIn("`MERGED=f` + empty `park` stays in FOLLOW UP", skill)
        self.assertIn("`awaiting-maintainer-merge` (`MERGED=f`, `review.artifact` at `head_sha`, `--execute-nc`)", skill)
        self.assertIn("`BUILD_DONE..MERGED=n/a`, `FOLLOWED_UP,WT_CLEAN=t`, `park=externally-covered`", skill)
        self.assertIn("live unparked `MERGED=f` stays in FOLLOW UP", ledger)
        self.assertIn("`BUILD_DONE..MERGED=n/a`, `FOLLOWED_UP,WT_CLEAN=t`", ledger)

    def test_threat_model_states_dispatch_signing_is_opt_in_and_dormant_by_default(self):
        # #750 C25: threat-model.md must not claim every unit is signed unconditionally while
        # verify.py and current mission/playbook usage leave dispatch signing dormant unless a
        # pubkey is pinned or passed.
        text = " ".join((RUNTIME / "threat-model.md").read_text(encoding="utf-8").split())
        self.assertNotIn("the coordinator signs each unit's contract digest", text)
        self.assertIn("opt-in", text)
        self.assertIn(".orca/dispatch-pubkey", text)
        self.assertIn("dormant by default", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
