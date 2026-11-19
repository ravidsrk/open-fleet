"""Every mechanism the doctrine leans on is NAMED where its guarantee is stated (#284).

The 2026-09-11 review found seven scripts that ship, pass CI, and are invoked by nothing: zero
references across 21 missions and 28 playbooks. A guarantee backed by an uncalled script is
doctrine wearing a mechanism's clothes, and `guard_text.py:55-56` went further — it cited a
contract test that did not exist.

So each of these asserts the raw invocation is present in the document whose guarantee depends on
it. Deleting the line turns a test red, which is the whole point: the doc and the mechanism can no
longer drift apart silently.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
PLAYBOOKS = ROOT / "playbooks"
RUNTIME = ROOT / "runtime"


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class WiredMechanisms(unittest.TestCase):
    def test_guard_text_is_named_where_the_trust_boundary_is_stated(self):
        text = read("runtime/sandbox-policy.md")
        self.assertIn("guard_text.py", text,
                      "the trust boundary says external text is DATA and names no fence")
        self.assertIn("--fetch gh issue view", text, "the fence is named but not its invocation")

    def test_decisions_is_named_where_one_way_gates_are_stated(self):
        text = read("runtime/gate-classification.md")
        self.assertIn("decisions.py", text,
                      "one-way gates are doctrine with no ledger that enforces them")
        self.assertIn("--source human:", text)

    def test_floor_guard_is_named_by_floor_its_guard_step(self):
        text = read("skills/floor-it/SKILL.md")
        self.assertIn("floor_guard.py", text,
                      "floor-it describes check_constraints-style validation without naming it")

    def test_diff_scope_is_named_by_the_scope_gated_review(self):
        text = read("playbooks/risk-review.md")
        self.assertIn("diff_scope.py", text,
                      "risk-review gates lenses by prose, so a missed signal is silent")

    def test_the_scope_gate_actually_passes_strict(self):
        # PR #308 review, P1, and the fourth time in this repo: --strict shipped and nothing
        # invoked it, so the partial-match bypass it exists to close stayed open everywhere except
        # the tests of --strict itself. A flag with no caller is a comment.
        text = read("playbooks/risk-review.md")
        self.assertIn("diff_scope.py --json --strict", text,
                      "the scope gate runs without --strict, so a half-matched diff still "
                      "dispatches on an incomplete flag set (#314)")

    def test_diff_scope_is_the_verifiers_definition_of_a_test_path(self):
        # #280 gave diff_scope its first caller: verify.py binds the negative control's paths with
        # the same SCOPE_TESTS rule the lens gate uses, so the two cannot drift apart.
        self.assertIn("diff_scope", read("runtime/scripts/verify.py"))


class TheFenceIsTheOnlyPath(unittest.TestCase):
    """The contract test `guard_text.py`'s docstring has always claimed (#284).

    It said: "A contract test that greps missions and playbooks for raw `gh issue view` outside
    this script is what keeps the fence the only path." No such test existed. This is it.
    """

    # `gh pr view` is not the only way in: inline review comments come from `gh api …/comments`,
    # list/search verbs return untrusted titles/bodies, and tracker CLIs (`linear`/`jira`) cross
    # the same trust boundary (PR #308 review, #780).
    RAW_FETCH = re.compile(
        r"gh\s+(?:issue|pr)\s+(?:view|list)\b"
        r"|gh\s+api\b[^`\n;&|]*(?:comments|issues|pulls)"
        r"|(?:<cli>|orca(?:-ide)?)\s+(?:linear|jira)\s+(?:list|search|issue|view|get)\b"
    )
    FENCED_PREFIX = re.compile(
        r"guard_text\.py(?:\s+--(?:source|label|timeout)(?:\s+|=)(?:'[^']*'|\"[^\"]*\"|\S+))*"
        r"\s+--fetch\s+$"
    )

    @classmethod
    def _is_count_only_list(cls, cmd):
        """Only numeric-count `--json number --jq 'length'` projections carry no untrusted text."""
        if not re.match(r"^gh\s+(?:issue|pr)\s+list\b", cmd):
            return False
        jsons = re.findall(r"--json(?:\s+|=)(\S+)", cmd)
        jqs = re.findall(r"(?:--jq|-q)(?:\s+|=)(['\"]?)(\S+?)\1(?=\s|$)", cmd)
        return jsons == ["number"] and [val for _, val in jqs] == ["length"]

    @classmethod
    def _line_offenders(cls, line):
        bad = []
        for match in cls.RAW_FETCH.finditer(line):
            if cls.FENCED_PREFIX.search(line[:match.start()]):
                continue
            cmd_tail = re.split(r"[`\n;&|)]", line[match.start():], maxsplit=1)[0]
            if cls._is_count_only_list(cmd_tail):
                continue
            bad.append(match.group(0))
        return bad

    def _offenders(self, directory):
        bad = []
        for path in sorted(directory.rglob("*.md")):
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                for hit in self._line_offenders(line):
                    bad.append(f"{path.relative_to(ROOT)}:{i}: {hit} ({line.strip()[:70]})")
        return bad

    def test_no_mission_fetches_tracker_text_outside_the_fence(self):
        self.assertEqual(self._offenders(SKILLS), [],
                         "a mission reads issue/PR text raw; route it through guard_text.py")

    def test_no_playbook_fetches_tracker_text_outside_the_fence(self):
        self.assertEqual(self._offenders(PLAYBOOKS), [],
                         "a playbook reads issue/PR text raw; route it through guard_text.py")

    def test_raw_fetch_catches_unfenced_list_and_tracker_reads(self):
        samples = (
            "gh pr list --repo upstream/repo --state open",
            "gh issue list --state open --json title,body",
            "gh pr list --state open --json number,title --jq 'length'",
            "<cli> linear list --filter open --json",
            "orca linear view LIN-1 --json",
            "orca-ide jira search 'project = X' --json",
            "<cli> jira list --filter all --json",
            "<cli> jira issue PROJ-1 --json",
            "<cli> jira get PROJ-1 --json",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertTrue(self._line_offenders(sample),
                                f"unfenced fetch slipped past RAW_FETCH: {sample}")

    def test_raw_fetch_exempts_numeric_count_projections_and_fenced_calls(self):
        allowed = (
            "count=$(gh pr list --state open --limit 1 --json number --jq 'length')",
            "count=$(gh issue list --state open --label 'x' --limit 1 --json number --jq 'length')",
            "`runtime/scripts/guard_text.py --source pr --fetch gh pr list --state open`",
            "`runtime/scripts/guard_text.py --source issue --fetch <cli> linear list --json`",
            "`runtime/scripts/guard_text.py --source issue --label 't' --fetch orca jira search 'q'`",
        )
        for sample in allowed:
            with self.subTest(sample=sample):
                self.assertEqual(self._line_offenders(sample), [])

    def test_guard_text_elsewhere_on_line_never_exempts_a_second_unfenced_fetch(self):
        smuggled = (
            "`runtime/scripts/guard_text.py --source issue --fetch <cli> jira search 'q'`"
            " (or `<cli> jira list --filter all`)",
            "guard_text.py --source pr --fetch gh pr view 1 && gh pr list --state open",
            "guard_text.py --source pr --fetch gh api --paginate repos/o/r/pulls/1/comments"
            " && gh api --paginate repos/o/r/pulls/2/comments",
            "use guard_text.py; gh issue list --state open",
        )
        for sample in smuggled:
            with self.subTest(sample=sample):
                self.assertEqual(len(self._line_offenders(sample)), 1,
                                 f"second unfenced fetch on same line went unflagged: {sample}")

    def test_playbooks_route_overlap_and_tracker_fetches_through_guard_text(self):
        upstream = read("playbooks/upstream-contribution.md")
        self.assertIn("runtime/scripts/guard_text.py --source pr --fetch gh pr list", upstream)
        linear = read("playbooks/linear-enumeration.md")
        for verb in ("linear list", "jira search", "jira list", "jira issue"):
            with self.subTest(verb=verb):
                self.assertIn(f"runtime/scripts/guard_text.py --source issue --fetch <cli> {verb}",
                              linear)

    def test_every_gh_api_list_fetch_paginates(self):
        # PR #308 review. `gh api` returns 30 items per page. verify.py:409 already carries the
        # lesson in a comment — "without it GitHub returns the first 30 reviews only" — and the
        # playbooks did not apply it, so a busy upstream PR silently truncates to its first page
        # and the WATCH loop reads that as the discussion going quiet.
        listing = re.compile(r"gh\s+api\b[^`\n]*/(?:comments|reviews|issues|pulls)\b")
        bad = []
        for directory in (SKILLS, PLAYBOOKS):
            for path in sorted(directory.rglob("*.md")):
                for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                    for hit in listing.finditer(line):
                        if "--paginate" not in hit.group(0):
                            bad.append(f"{path.relative_to(ROOT)}:{i}: {hit.group(0)[:70]}")
        self.assertEqual(bad, [], "a list fetch without --paginate truncates at 30 items")


class TheVerifierInvocationIsWrittenDown(unittest.TestCase):
    """#285. The catalog's whole claim rests on verify.py, and no SKILL.md or playbook contained the
    string `--execute-nc`, `--nc-command` or `evidence-run.py`. The one place a verifier command line
    was written out was docs/runs/TEMPLATE.md — a template, not a pipeline. A coordinator following a
    mission end to end was told the outcome is verified and never told what verifies it.
    """

    def test_build_change_names_the_recorder(self):
        text = read("playbooks/build-change.md")
        self.assertIn("evidence-run.py", text,
                      "the BUILD phase produces evidence without naming the recorder that binds it")
        self.assertIn("--label", text)

    def test_build_change_names_the_verifier_and_its_lane_flags(self):
        text = read("playbooks/build-change.md")
        self.assertIn("verify.py", text)
        for flag in ("--contract-source", "--contract-digest", "--unit-class",
                     "--execute-nc", "--nc-command"):
            self.assertIn(flag, text, f"the invocation omits {flag}, so a coordinator must guess it")

    def test_the_invocation_says_the_coordinator_supplies_the_authorities(self):
        # The flags are worthless if a worker fills them in: that is #279 in one sentence.
        text = read("playbooks/build-change.md")
        self.assertIn("COORDINATOR", text)
        self.assertIn("never from the manifest", text)

    def test_the_evidence_contract_points_at_the_invocation(self):
        # evidence-manifest.md is ridden by all 21 missions and sits at both its caps, so it carries
        # a pointer rather than a copy — the shared-doctrine shape the playbook layer exists for.
        text = read("runtime/evidence-manifest.md")
        self.assertIn("build-change.md", text,
                      "the evidence contract says what is checked and never where to run it")


class OrcaAnchorsSayWhatTheyMean(unittest.TestCase):
    """#302: five anchor and wording defects in the Orca-facing doctrine.

    Each was verified against a clone of stablyai/orca at the PINNED commit
    (v1.4.199 = 28957d6004) rather than taken on the review's word — and one of the five turned
    out to be right for a reason other than the one given. These tests cannot re-read upstream,
    so they hold the corrected WORDING down; re-witnessing the line numbers is pin-it's job.
    """

    SANDBOX = (ROOT / "runtime" / "sandbox-policy.md").read_text(encoding="utf-8")
    DISPATCH = (ROOT / "runtime" / "dispatch-lifecycle.md").read_text(encoding="utf-8")
    DAG = (ROOT / "runtime" / "orca-dag-semantics.md").read_text(encoding="utf-8")

    def test_the_doctor_rule_points_at_the_doctor_section(self):
        # #382: both line-pinned citations rotted (:110-122 was the snapshot section; :346-348
        # drifted next) — the policy now names the section, not the numbers.
        self.assertIn("orca-per-workspace-env`'s doctor-verdict section", self.SANDBOX)
        self.assertNotIn("orca-per-workspace-env:110-122", self.SANDBOX)
        self.assertNotIn("orca-per-workspace-env:346-348", self.SANDBOX)

    def test_six_refusal_codes_are_not_all_pinned_to_one_three_code_file(self):
        # The contract file's union is task_not_found | task_not_startable | inject_rejected.
        para = " ".join(self.DISPATCH.split())
        self.assertIn("declares the first three ONLY", para)
        # And the file has to be NAMED. Compressing this paragraph to fit the 160-line cap once
        # left "That contract file declares the first three ONLY" with no antecedent anywhere in
        # the document — a correction that had become unreadable.
        self.assertIn("orchestration-dispatch-refusal-contract.ts:8", para,
                      "the sentence points at a contract file the document never names")
        self.assertNotIn(
            "`consumer_fenced`, `dispatch_inactive` are policy answers; `runtime_error` is the "
            "catch-all whose recovery is \"do not retry unchanged\" "
            "(`orchestration-dispatch-refusal-contract.ts:8`", para,
            "all six codes are anchored to the file that declares three again")

    def test_the_per_code_anchors_live_where_the_codes_are_consumed(self):
        # Relocated rather than dropped: dispatch-lifecycle.md is at its 160-line cap, and
        # ARCHITECTURE.md:172 says a cap is paid for by moving prose, never by raising it.
        script = (ROOT / "runtime" / "scripts" / "spawn_worker.sh").read_text(encoding="utf-8")
        for anchor in ("nested-worker-depth.ts:13", "dispatch-capability.ts:18",
                       "role-mailbox-delivery.ts:52", "cli-error.ts:117"):
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, script)
        self.assertIn("POLICY_CODES", self.DISPATCH,
                      "the doctrine must name where the anchors went")

    def test_no_read_only_tier_is_attributed_to_orca(self):
        """Orca's only agent map is YOLO_TUI_AGENT_ARGS — no read-only tier for ANY agent.

        The table said "(no RO in Orca)" beside cursor and grok alone, which reads as though
        Orca supplied the others. Every `ro` entry is that agent's own native flag, chosen here.
        """
        # The TABLE ROWS, not the whole file: the prose above the table quotes the old wording
        # to explain what changed, and a whole-file scan flags that quote. (Same distinction the
        # `--baseline-path` check in test_repo_hygiene.py had to learn.)
        rows = [ln for ln in self.SANDBOX.splitlines()
                if ln.startswith("|") and "WORKER_CMD" in ln]
        self.assertTrue(rows, "the PROFILE table lost its rows")
        for row in rows:
            with self.subTest(row=row.split("|")[1].strip()):
                self.assertNotIn("no RO in Orca", row,
                                 "a row still attributes the missing tier to Orca specifically")
        self.assertIn("Orca has no read-only tier for ANY agent", self.SANDBOX)
        self.assertIn("YOLO_TUI_AGENT_ARGS", self.SANDBOX)

    def test_decision_gate_is_not_listed_as_load_bearing(self):
        """The review said nothing on CLI paths writes one. That reason is wrong — the CLI
        lists it as a valid `--type` (`orchestration.ts:71`). The conclusion still holds for a
        different reason: the RUNTIME writes one only on the legacy direct-ask path and migrates
        existing ones to `status`."""
        para = " ".join(self.DAG.split())
        self.assertNotIn("`status`, `decision_gate` (legacy/gates)", para)
        self.assertIn("legacy-ask-operation.ts:101", para)
        self.assertIn("message-inbox.ts:81", para)

    def test_the_readiness_note_is_a_version_fact_not_a_countdown(self):
        # "The next release demands …" was true for exactly one day: v1.4.200 shipped it.
        self.assertNotIn("The next release demands", self.DISPATCH)
        self.assertIn("v1.4.200", self.DISPATCH)
        self.assertIn("worker-start-readiness-settlement.ts", self.DISPATCH)


class DoctrineSaysWhatTheCatalogDoes(unittest.TestCase):
    """Four places where the doctrine had drifted from the catalog it describes (#289)."""

    def test_the_mission_test_is_six_part(self):
        # It counts six identity points; one guide still called it five.
        self.assertNotIn("five-part mission test", read("docs/missions/oss-contribute.md"))

    def test_modernize_it_hands_stateful_migration_to_migrate_it(self):
        # migrate-it landed 2026-09-10 and owns expand -> dual-write -> backfill -> switch ->
        # contract. modernize-it's handoff still pointed at a sequence of ship-it runs, so a
        # coordinator following it could not find the mission that does the work.
        text = read("skills/modernize-it/SKILL.md")
        self.assertIn("migrate-it", text,
                      "modernize-it describes a handoff without naming the mission that takes it")

    def test_the_rejection_ledger_records_what_was_admitted(self):
        # Its own footer asks for this: "when one lands or is dropped, record the outcome here".
        text = read("docs/research/REJECTED.md")
        self.assertIn("landed on", text.lower().replace("**", ""),
                      "the four 2026-09-10 admissions are not recorded in the ledger")

    def test_pin_it_is_argued_not_assumed(self):
        # #289 asked whether pin-it folds into clean-sweep. It does not, and ARCHITECTURE.md
        # already argued why; the number is what was missing.
        text = read("ARCHITECTURE.md")
        self.assertIn("finding is withdrawn", text)
        import importlib.util
        spec = importlib.util.spec_from_file_location("v", ROOT / "scripts" / "validate.py")
        validate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validate)
        def identity(name):
            data, _err = validate.parse_frontmatter(
                (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8"))
            return data["metadata"]
        a, b = identity("clean-sweep"), identity("pin-it")
        near = sum(1 for k in validate.IDENTITY_KEYS
                   if validate._point_similarity(a[k], b[k]) >= validate.IDENTITY_POINT_NEAR)
        self.assertEqual(near, 0,
                         "clean-sweep and pin-it have started to converge; re-argue ARCHITECTURE.md")


class SharedDoctrineLivesOnce(unittest.TestCase):
    """#290. prove-it and reshape-it each wrote out the characterization protocol. Duplicated
    doctrine is the failure the playbook layer exists to prevent: two copies drift, and a reader
    cannot tell which is authoritative. reshape-it's reference was worse than a copy — it pointed
    at `skills/prove-it/SKILL.md` from inside a code block, which the composition scan cannot see,
    so the dependency was invisible to the load accounting and the orphan checks alike.
    """

    def test_the_characterize_playbook_exists(self):
        self.assertTrue((PLAYBOOKS / "characterize.md").is_file())

    def test_both_missions_compose_it_visibly(self):
        # Through the Composes clause, so validate.py counts it — not a path in a code block.
        import importlib.util
        spec = importlib.util.spec_from_file_location("v", ROOT / "scripts" / "validate.py")
        validate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validate)
        for mission in ("prove-it", "reshape-it"):
            _total, parts = validate.transitive_load(SKILLS / mission)
            self.assertIn("playbooks/characterize.md", parts,
                          f"{mission} names characterize where the validator cannot see it")

    def test_the_mutation_rule_is_stated_once(self):
        # The load-bearing sentence — a compile break is not proof — belongs in the playbook, and
        # nowhere else restates the tool list it governs.
        playbook = read("playbooks/characterize.md")
        self.assertIn("a compile break is not proof", playbook.lower())
        for mission in ("prove-it", "reshape-it"):
            text = read(f"skills/{mission}/SKILL.md")
            self.assertNotIn("cargo-mutants", text,
                             f"{mission} still restates the mutation tool list characterize owns")

    def test_reshape_it_no_longer_points_into_another_skill_file(self):
        self.assertNotIn("skills/prove-it/SKILL.md", read("skills/reshape-it/SKILL.md"))

    def test_the_playbook_names_the_fields_the_verifier_reads(self):
        """A playbook that tells a worker what to record must name the SCHEMA fields, not describe
        them (PR #308 review). The first cut said "pinned mutant" and "target assertion" and left
        out `artifact` entirely — so a worker following the authoritative table would produce
        evidence verify.py refuses, and the shared playbook would be worse than the two copies it
        replaced.
        """
        playbook = read("playbooks/characterize.md")
        # Read the TABLE rows, not the whole file: every one of these words also appears in the
        # surrounding prose, so a substring check passes even with the row deleted. (Confirmed by
        # removing the artifact row and watching the first version of this test stay green.)
        rows = {line.split("|")[1].strip() for line in playbook.splitlines()
                if line.startswith("|") and line.count("|") >= 3}
        for field in ("tool", "mutant", "artifact", "result"):
            self.assertIn(f"`{field}`", rows,
                          f"characterize.md's record table has no row for negative_control.{field}")
        verifier = read("runtime/scripts/verify.py")
        self.assertIn('negative_control.artifact (an evidence path) is required', verifier,
                      "the verifier no longer requires artifact; re-check the playbook's table")
        self.assertIn("negative_control.mutant (a pinned mutant id) is required", verifier,
                      "the verifier no longer requires mutant; re-check the playbook's table")


class TheSoloRunLessonIsWhereItIsNeeded(unittest.TestCase):
    """#291. The flagship ship-it run learned that a solo fleet cannot manufacture an independent
    approver, so a mutation unit cannot close: it recorded RED and stopped, which is why ship-it
    sat at doctrine-only then. That lesson was written into the run report, the run template, the
    binder and the binder's test — and into none of the documents a coordinator running ship-it
    actually reads. A fresh coordinator would hit the same wall with no instruction for it.
    """

    SIGNAL = ("solo", "self-approve", "independent approval")

    def test_ship_it_says_what_to_do_with_one_identity(self):
        text = read("skills/ship-it/SKILL.md").lower()
        self.assertTrue(any(term in text for term in self.SIGNAL),
                        "ship-it does not say what to do when no second identity exists")
        self.assertIn("built", text, "the fallback terminal state is not named")

    def test_acceptance_review_refuses_a_faked_independent_review(self):
        text = read("playbooks/acceptance-review.md").lower()
        self.assertIn("no second identity", text)
        self.assertIn("not a reviewer", text,
                      "the playbook does not refuse a builder reviewing its own work")

    def test_both_name_the_lane_that_does_work_solo(self):
        # Recording RED is honest but terminal; the executed-control lane is the way through, and
        # a coordinator that is not told about it will simply stop.
        for path in ("skills/ship-it/SKILL.md", "playbooks/acceptance-review.md"):
            self.assertIn("executed-control lane", read(path),
                          f"{path} states the problem without naming the way through")


class EveryMissionHasAPathToProof(unittest.TestCase):
    """#292. The field-proof plan says how each mission would earn a tier above doctrine-only.
    Eight of twenty-one had no row — including all four added on a single day in 2026-09-10, and
    four whose runs exist but bind `no`. Nothing enforced the plan, which is why adding four
    missions at once did not trip anything: a mission with no path to a proof tier is a mission
    whose claim cannot be checked, and adding one must never be cheaper than planning how to
    prove it.
    """

    def _plan_rows(self):
        text = read("docs/runs/README.md")
        section = text[text.index("## Field-proof plan"):]
        return {line.split("|")[1].strip() for line in section.splitlines()
                if line.startswith("|") and line.count("|") >= 5}

    def test_every_mission_has_a_plan_row(self):
        missions = {d.name for d in SKILLS.iterdir() if (d / "SKILL.md").is_file()}
        missing = sorted(missions - self._plan_rows())
        self.assertEqual(missing, [],
                         f"missions with no path to a proof tier: {missing}")

    def test_the_plan_has_no_row_for_a_mission_that_does_not_exist(self):
        # The other direction: a row for a deleted mission is a plan for nothing.
        missions = {d.name for d in SKILLS.iterdir() if (d / "SKILL.md").is_file()}
        header = {"Mission", "---"}
        stale = sorted(r for r in self._plan_rows() if r and r not in missions and r not in header)
        self.assertEqual(stale, [], f"plan rows for missions that no longer exist: {stale}")

    def _plan_cells(self):
        text = read("docs/runs/README.md")
        section = text[text.index("## Field-proof plan"):]
        for line in section.splitlines():
            if line.startswith("|") and line.count("|") >= 5:
                cells = [c.strip() for c in line.split("|")[1:-1]]
                if (SKILLS / cells[0] / "SKILL.md").is_file():
                    yield cells[0], cells[3]

    @staticmethod
    def _plan_terminals(cell):
        """The terminal names a plan row promises, with `(or `-WITH-PARKED`)` expanded."""
        names, prev = [], None
        for token in re.findall(r"`([^`]+)`", cell):
            names.append(prev + token if token.startswith("-") and prev else token)
            if not token.startswith("-"):
                prev = token
        return names

    def test_every_plan_row_names_terminals_its_mission_declares(self):
        """PR #334 review, P2.

        The plan promised `oncall-it` would reach `RESOLVED`, a state that mission cannot report —
        a field run following it would have had no terminal to land on. The maintained check only
        asserted a row EXISTS, so the correction was protected by an archived one-off probe and a
        return to the old wording would have passed CI.
        """
        for mission, cell in self._plan_cells():
            with self.subTest(mission=mission):
                declared = (SKILLS / mission / "SKILL.md").read_text()
                named = set(re.findall(r"\b([A-Z][A-Z0-9_-]+)\b", declared))
                promised = self._plan_terminals(cell)
                self.assertTrue(promised, f"{mission}: the plan promises no terminal at all")
                unknown = [n for n in promised if n not in named]
                self.assertEqual(unknown, [], f"{mission}: the plan promises terminals the mission "
                                              f"never declares: {unknown}")

    def test_a_plan_row_promising_a_foreign_terminal_is_caught(self):
        # The guard above only helps if it actually fails on the wording it replaced.
        declared = (SKILLS / "oncall-it" / "SKILL.md").read_text()
        named = set(re.findall(r"\b([A-Z][A-Z0-9_-]+)\b", declared))
        stale = self._plan_terminals("`RESOLVED` / `RESOLVED-WITH-PARKED`")
        self.assertEqual([n for n in stale if n not in named], stale,
                         "oncall-it must not declare RESOLVED, or this guard proves nothing")

    def test_the_plan_does_not_carry_a_stale_catalog_count(self):
        # docs/runs/README.md is not in COUNT_LINT_FILES, so its "Thirteen missions are
        # doctrine-only" sat false and unpoliced while every mission was doctrine-only.
        text = read("docs/runs/README.md")
        self.assertNotIn("Thirteen missions are", text)


class ThePinPacketPublishesWhatItClaims(unittest.TestCase):
    """PR #336 review, P1.

    The packet README advertised a post-commit `manifest.json` binding the correction SHA, and no
    such file was published — only `manifest.pre-base-label.json` and the historical one under
    history/. A reader following the advertised reference found nothing, and that claim could not
    have been true at publish time anyway: a manifest binding the correction SHA cannot ship in
    the commit it binds.
    """

    PACKET = ROOT / "docs" / "reports" / "release-20260912" / "pin"

    def setUp(self):
        if not self.PACKET.is_dir():
            self.skipTest("no pin packet in this tree")

    def test_every_link_in_the_packet_resolves(self):
        # history/ holds verbatim archived copies: their links were right where they were
        # written, and rewriting them would edit retained evidence.
        docs = [d for d in sorted(self.PACKET.rglob("*.md"))
                if "history" not in d.relative_to(self.PACKET).parts]
        for doc in docs:
            for _label, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", doc.read_text()):
                link = target.split("#")[0]
                if not link or link.startswith(("http", "mailto:")):
                    continue
                with self.subTest(doc=doc.relative_to(self.PACKET).as_posix(), link=link):
                    self.assertTrue((doc.parent / link).exists(),
                                    f"{doc.name} links {link}, which does not exist")

    def test_the_packet_does_not_advertise_a_root_manifest_it_does_not_publish(self):
        """The specific claim that broke: prose naming a root artifact, with no link to go dead."""
        for doc in sorted(self.PACKET.glob("*.md")):
            text = doc.read_text(encoding="utf-8")
            for name in sorted(set(re.findall(r"(?<![\w/.-])(manifest[\w.-]*\.json)", text))):
                with self.subTest(doc=doc.name, artifact=name):
                    self.assertTrue((self.PACKET / name).is_file(),
                                    f"{doc.name} names {name} as a packet artifact, but the packet "
                                    f"root does not publish it")


class EveryUnitHasOneCanonicalContract(unittest.TestCase):
    """PR #334 review, P2.

    The claims unit shipped `claims/v2/contract.json` beside the canonical `contract.json`: a
    second contract adding AC-4 and a wider scope, bound to no manifest, no verifier input and no
    report, and referenced by nothing. A consumer following the canonical reference could not audit
    AC-4 at all, while the live tree advertised it. An alternative contract is either the canonical
    one or it is a dispatch artifact belonging in the archive — never a third thing sitting live.
    """

    REPORTS = ROOT / "docs" / "reports"

    def _live_contracts(self):
        if not self.REPORTS.is_dir():
            return []
        return [p for p in self.REPORTS.rglob("contract.json")
                if not any(part.startswith("archive-") for part in p.relative_to(ROOT).parts)]

    def test_no_unit_carries_a_second_live_contract(self):
        by_unit = {}
        for path in self._live_contracts():
            by_unit.setdefault(path.parent.parent if path.parent.name == "v2" else path.parent, []
                               ).append(path.relative_to(ROOT).as_posix())
        extra = {str(unit): sorted(paths) for unit, paths in by_unit.items() if len(paths) > 1}
        self.assertEqual(extra, {}, f"a unit with two live contracts binds neither: {extra}")

    def test_a_live_contract_declares_exactly_the_criteria_it_lists(self):
        for path in self._live_contracts():
            with self.subTest(contract=path.relative_to(ROOT).as_posix()):
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data["criterion_ids"], [c["id"] for c in data["criteria"]],
                                 "criterion_ids and criteria must name the same criteria in order")
                self.assertTrue(data.get("scope"), "a contract with no scope binds nothing")


class TheRunArchiveMatchesGit(unittest.TestCase):
    """#293. The run archive is the repository's own evidence that its missions have been executed,
    and it did not survive a read against the commits it names. These pin the corrections that a
    future edit could silently undo — each was verified against git before it was written.
    """

    SHIP_IT = "docs/runs/2026-08-28-ship-it-self-run.md"

    def test_no_report_claims_a_tier_its_own_binding_section_denies(self):
        # Three reports carried "Proof tier earned: self-run / external-run" headers while their
        # own Evidence-binding sections said doctrine-only.
        for name in ("2026-07-13-clean-sweep-self-run.md", "2026-07-13-review-it-external-run.md",
                     "2026-08-28-ship-it-self-run.md"):
            text = read(f"docs/runs/{name}")
            self.assertNotIn("Proof tier earned:", text,
                             f"{name} claims a tier its Evidence binding denies")

    def test_the_machine_readable_header_agrees_with_the_prose(self):
        """PR #308 review. Correcting the PROSE header and leaving `RUN: tier=self-run` is the same
        defect one layer down — and it was unreachable, because check_report only runs for missions
        claiming a tier above doctrine-only. A report demoted in prose kept asserting the old tier
        in the field a machine reads, with nothing to catch it."""
        header = re.compile(r"^RUN:\s.*\btier=(\S+)", re.M)
        for path in sorted((ROOT / "docs" / "runs").glob("2*.md")):
            text = path.read_text(encoding="utf-8")
            match = header.search(text)
            if not match:
                continue
            declared = match.group(1)
            demoted = ("doctrine-only" in text.split("## Evidence binding")[-1][:400]
                       if "## Evidence binding" in text else False)
            if demoted:
                self.assertEqual(declared, "doctrine-only",
                                 f"{path.name}: Evidence binding says doctrine-only, RUN: header "
                                 f"declares tier={declared}")

    def test_the_promotion_pr_is_not_described_as_open(self):
        # PR #104 merged as 9ed6fe9 on 2026-08-28, the same day the run stopped at it.
        text = read(self.SHIP_IT)
        self.assertNotIn("**open, human-owned**", text)
        self.assertIn("9ed6fe9", text, "the merge commit is not named")

    def test_pr_137_is_not_credited_with_files_it_did_not_touch(self):
        # #137 changed verify.py, tests/test_verify.py and docs; #108 changed the two named files.
        text = read(self.SHIP_IT)
        self.assertNotIn("(PRs #108/#137)", text)

    def test_the_template_is_not_described_as_pre_dating_the_run(self):
        # docs/runs/TEMPLATE.md was created 2026-09-02; this run was 2026-08-28.
        text = read(self.SHIP_IT)
        self.assertNotIn("asked for it", text,
                         "the report still says a template that post-dates it asked for something")

    def test_the_2026_09_09_inventory_records_its_own_mismatch(self):
        # Three of thirteen do not re-derive at the tip the report names.
        text = read("docs/runs/2026-09-09-clean-sweep-tracker.md")
        self.assertIn("do not re-derive at the tip this report names", text)

    def test_the_completion_ledger_carries_no_hardcoded_catalog_count(self):
        self.assertNotIn("catalog of 13 outcome-named missions",
                         read("docs/completion/STATUS.md"))

    def test_todos_points_at_the_review_that_is_actually_there(self):
        # PR #278 moved the 2026-09-10 review; TODOS still called REVIEW.md by that date.
        text = read("TODOS.md")
        self.assertIn("docs/reviews/2026-09-10-review.md", text)
        self.assertIn("2026-09-11 deep review", text)


class InstallInstructionsAreRunnable(unittest.TestCase):
    """#294. The README showed `npx skills add ravidsrk/orca-fleet` as a runnable command and the
    bundle step that fixes it afterwards, so a reader following the page in order installed a
    half-blind mission: the CLI copies dirname(SKILL.md) only, severing every ../../playbooks/
    reference. Shipping install instructions for the path a build step exists to fix is the part
    that was wrong, not the build step.
    """

    def test_the_readme_does_not_show_the_copy_install_as_runnable(self):
        readme = read("README.md")
        for line in readme.splitlines():
            stripped = line.strip()
            if stripped.startswith("npx skills add"):
                self.fail(f"README shows a runnable copy install that severs references: {stripped}")

    def test_the_readme_says_why_and_what_would_fix_it(self):
        readme = read("README.md")
        self.assertIn("not from this repository, today", readme)
        self.assertIn("published `dist/`", readme,
                      "the README states the problem without naming what would resolve it")

    def test_no_mission_description_carries_angle_brackets(self):
        # Anthropic's quick_validate.py — the package_skill.py and claude.ai upload path — rejects
        # a description containing < or >. ship-it's carried "build me <feature>".
        import importlib.util
        spec = importlib.util.spec_from_file_location("e", ROOT / "scripts" / "eval.py")
        evalmod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(evalmod)
        for skill_dir in sorted(SKILLS.iterdir()):
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue
            description = evalmod.parse_frontmatter(
                skill_md.read_text(encoding="utf-8")).get("description", "")
            for bracket in ("<", ">"):
                self.assertNotIn(bracket, description,
                                 f"{skill_dir.name}'s description contains {bracket!r}, which the "
                                 "claude.ai upload path rejects")


class ReviewCitationsResolve(unittest.TestCase):
    """#295. Replacing REVIEW.md in place left tracked source citing sections and attack ids of a
    document no longer at that path. Three MIS-RESOLVED rather than dangling, which is worse:
    `bundle.py` cited "§8 P2-18", and §8 P2-18 of the successor is a different item entirely. A
    reader following it lands somewhere plausible and wrong.

    The rule: a citation carrying an ANCHOR (a section or an attack id) must name the dated
    document, because anchors are numbered per review and only the path disambiguates them. A bare
    reference to `REVIEW.md` as a document is fine — that always means the current one.
    """

    # An anchor pins a specific claim inside a specific review: §N, A<n>, U<n>, P0-/P1-/P2-<n>.
    ANCHORED = re.compile(
        r"(?<!/)\bREVIEW\.md\b[^\n]{0,12}?"
        r"(§\s*\d|\bA\d|\bU\d|\bP[012]-\d|\bP2\s+item)")
    SEARCH_DIRS = ("runtime", "scripts", "tests", "evals", "bench", ".github")
    SEARCH_FILES = ("ARCHITECTURE.md", "AGENTS.md", ".github/CONTRIBUTING.md", "TODOS.md",
                    "CHANGELOG.md")

    def _offenders(self):
        paths = [ROOT / f for f in self.SEARCH_FILES]
        for d in self.SEARCH_DIRS:
            paths += [p for p in (ROOT / d).rglob("*")
                      if p.is_file() and p.suffix in (".py", ".sh", ".md", ".json", ".yml")
                      and "__pycache__" not in p.parts]
        bad = []
        for path in sorted(paths):
            if not path.is_file():
                continue
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if self.ANCHORED.search(line):
                    bad.append(f"{path.relative_to(ROOT)}:{i}")
        return bad

    def test_no_anchored_citation_omits_the_dated_path(self):
        bad = self._offenders()
        self.assertEqual(bad, [], "anchored REVIEW.md citations that do not name which review: "
                                  f"{bad} — anchors are numbered per review, so a bare one "
                                  "mis-resolves against whichever document holds the path today")

    def test_the_archived_predecessor_is_still_there(self):
        # Every re-pointed citation depends on this path existing.
        archive = ROOT / "docs" / "reviews" / "2026-09-10-review.md"
        self.assertTrue(archive.is_file(), "the archived predecessor review is gone; 58 citations "
                                           "now dangle")
        self.assertIn("A11", archive.read_text(encoding="utf-8"),
                      "the archived review no longer carries the attack ids cited against it")


class DormantMechanismsSaySo(unittest.TestCase):
    """Two of the seven cannot be wired from inside the repository, so they say so instead.

    #284 allows either: name the invocation, or remove the sentence claiming the guarantee holds.
    For these the second is the honest answer, and the honesty has to be pinned or it rots back.
    """

    def test_deny_hook_is_not_claimed_as_an_enforced_boundary(self):
        # It prints a registration a host must paste, and on the supervised lane nothing can.
        readme = read("README.md")
        self.assertIn("deny-hook.sh", readme)
        self.assertIn("unregistered by construction", readme,
                      "the README claims a boundary deny-hook.sh cannot enforce unregistered")

    def test_signed_dispatch_records_that_it_is_dormant(self):
        # The scheme is sound where the key is off-worker; no mission signs and no key is
        # committed, so nothing exercises it today. #281/#386 added the signed verifier
        # transcript on the same key — implemented, and dormant for the same reason: the doc
        # must say so, and must name the pubkey commit as the ONE switch that turns BOTH on, so
        # the maintainer who lands it knows every native-hook run then needs a signed record.
        text = read("docs/verify-gate.md")
        self.assertIn("dispatch-sign.py", text)
        self.assertIn("no mission or playbook signs a dispatch", text,
                      "signed dispatch reads as live; no .orca/dispatch-pubkey is committed")
        self.assertFalse((ROOT / ".orca" / "dispatch-pubkey").exists(),
                         "a pubkey is committed: the dormancy statements above are now false — "
                         "rewrite them to the live state rather than deleting this pin")
        self.assertIn("signed verifier transcript", text,
                      "the transcript path is implemented (verify.py --transcript-out/--transcript-"
                      "key, run_report.py) but the doc does not say so")
        self.assertIn("exercised by no real run yet", text,
                      "the transcript reads as live; no run report names a transcript")
        self.assertIn("enforcement switch for both", text,
                      "the doc must say committing .orca/dispatch-pubkey switches on BOTH the "
                      "dispatch-record check and the transcript requirement")

    def test_egress_records_that_no_automated_sink_calls_it(self):
        # #368: doctrine now names the receipt (merge-serialization.md), but honesty about the
        # enforcement gap is the point — no code calls it yet, and the header must say so.
        text = (RUNTIME / "scripts" / "egress.py").read_text(encoding="utf-8")
        self.assertIn("no automated sink calls it yet", text,
                      "egress.py reads as if receipts are being written; nothing automated calls it")

    def test_doctrine_names_the_egress_receipt_before_off_repo_writes(self):
        # The orphan mechanism is orphaned no longer: merge-serialization wires it ahead of sends.
        text = read("runtime/merge-serialization.md")
        self.assertIn("egress.py write", text,
                      "no policy invokes the egress receipt — it rots uninvoked (#284/#368)")

    def test_supervision_names_the_watchdog_where_the_ladder_is_stated(self):
        # #418: the stuck-but-alive ladder's first responses are mechanized, so the
        # policy must name the mechanism and its invocation — else doctrine drifts.
        text = read("runtime/worker-supervision.md")
        self.assertIn("watchdog.py", text,
                      "supervision doctrine names no liveness mechanism")
        self.assertIn("--heartbeats", text,
                      "the watchdog is named but not its invocation")


class PreflightRunsBeforeSubstantiveWork(unittest.TestCase):
    """#783: quarantine and capability refusal only protects a run when preflight executes
    before any untrusted reads, device pairing, repo init, or commits — not mid-pipeline."""

    PIPELINE_RE = re.compile(r"## Pipeline[^\n]*\n+```[^\n]*\n(.*?)```", re.DOTALL)

    def test_every_mission_runs_preflight_at_step_zero(self):
        missions = sorted(d for d in SKILLS.iterdir()
                          if d.is_dir() and not d.name.startswith((".", "_"))
                          and (d / "SKILL.md").is_file())
        self.assertEqual(len(missions), 22)
        for skill_dir in missions:
            name = skill_dir.name
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            with self.subTest(mission=name):
                if name == "review-it":
                    before_pipeline = text.split("## Pipeline", 1)[0]
                    self.assertIn("preflight.py --mission review-it --mode readonly",
                                  before_pipeline)
                    continue
                pipe = self.PIPELINE_RE.search(text)
                self.assertIsNotNone(pipe, f"{name} has no ## Pipeline code block")
                first_step = pipe.group(1).split("→", 1)[0]
                self.assertIn("runtime/scripts/preflight.py", first_step,
                              f"{name} does not invoke runtime/scripts/preflight.py at step 0")
                self.assertIn(f"--mission {name}", first_step,
                              f"{name} does not pass --mission {name} at step 0")

    def test_no_mission_uses_bare_preflight_without_script_path(self):
        for skill_dir in sorted(SKILLS.iterdir()):
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue
            text = skill_md.read_text(encoding="utf-8")
            with self.subTest(mission=skill_dir.name):
                self.assertNotRegex(text, r"\bpreflight\s+--mission\b",
                                    f"{skill_dir.name} invokes bare `preflight --mission` "
                                    "instead of `runtime/scripts/preflight.py`")

    def test_harden_it_bootstraps_base_before_threat_model_commit(self):
        text = read("skills/harden-it/SKILL.md")
        pipe = self.PIPELINE_RE.search(text)
        self.assertIsNotNone(pipe)
        body = pipe.group(1)
        bootstrap_pos = body.find("BOOTSTRAP integration BASE")
        threat_pos = body.find("THREAT-MODEL")
        self.assertGreater(bootstrap_pos, -1)
        self.assertGreater(threat_pos, -1)
        self.assertLess(bootstrap_pos, threat_pos,
                        "harden-it must bootstrap BASE (BASE != default) before THREAT-MODEL commits")


if __name__ == "__main__":
    unittest.main()
