#!/usr/bin/env python3
"""
Negative-path tests for scripts/validate.py on synthetic fixtures.

test_architecture.py proves the validator passes the real (always-valid) corpus;
from that suite's perspective every failure branch is dead code — a regression
that stops the validator from firing would ship green. These tests lock each
error branch to a fixture that must trip it.
"""
import importlib.util
import json
import math
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("validate", ROOT / "scripts" / "validate.py")
validate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(validate)

PROTOCOLS = {"diagnose"}


# A fixture's six identity points (ARCHITECTURE.md). Distinct from every real
# mission's, so a fixture never trips the identity-collision check.
FIXTURE_IDENTITY = {
    "unit": "one fixture item",
    "state_machine": "fixture-start → fixture-end",
    "convergence": "the fixture assertion holds",
    "ordering": "none — fixtures do not order",
    "parking": "FIXTURE-PARKED",
    "oracle": "the unit test that reads it",
}


def make_skill(tmp, body, frontmatter_extra="proof: doctrine-only\nautonomy: L4\n",
               name="demo-skill", identity=None):
    """Write a fixture SKILL.md.

    `frontmatter_extra` is still written in flat `key: value` form; keys the repo
    keeps under the spec's `metadata:` extension point (issue #263) are folded
    into that block here, so a test that wants a top-level extra still gets one
    and a test that sets `proof:` still means `metadata.proof`.
    """
    d = Path(tmp) / name
    d.mkdir()
    meta = dict(identity if identity is not None else FIXTURE_IDENTITY)
    top = []
    for line in frontmatter_extra.splitlines():
        key, _, value = line.partition(":")
        if key.strip() in validate.METADATA_KEYS:
            meta[key.strip()] = value.strip()
        elif line.strip():
            top.append(line)
    block = "metadata:\n" + "".join(f"  {k}: {v}\n" for k, v in meta.items())
    if "pack:" not in body.lower():
        body += "\nWorker TASK pack: one of matt | addy — never co-mount.\n"
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A fixture. Use when testing.\n"
        + ("\n".join(top) + "\n" if top else "") + block + "---\n" + body,
        encoding="utf-8",
    )
    return d


def generated_copies(gb, where):
    """Point gen-badges' generated LIVE targets at copies under `where`.

    gb.write() rewrites the mission guides' callouts, ARCHITECTURE.md's table and README.md's
    proof sentence as well as the badges. Patching only BADGES_DIR let the badge tests below
    rewrite 18 live docs/missions/*.md callouts and the live ARCHITECTURE.md table whenever
    those were stale (2026-10-23 review, P2-24 — the same hazard as test_architecture's).
    Copies, not empty dirs, so check() still sees a full catalog and passes once write() ran.
    """
    where.mkdir(parents=True, exist_ok=True)
    guides = where / "missions"
    shutil.copytree(ROOT / "docs" / "missions", guides, dirs_exist_ok=True)
    for name in ("ARCHITECTURE.md", "README.md"):
        shutil.copy2(ROOT / name, where / name)
    return mock.patch.multiple(gb, GUIDES_DIR=guides, ARCH=where / "ARCHITECTURE.md",
                               README=where / "README.md")


class TestValidatorFailureBranches(unittest.TestCase):

    def test_name_must_match_the_folder(self):
        # Full-review mutant: deleting the name/folder check left the suite green.
        with tempfile.TemporaryDirectory() as tmp:
            d = make_skill(tmp, "Composes `diagnose`.\n")
            md = d / "SKILL.md"
            md.write_text(md.read_text(encoding="utf-8").replace(
                "name: demo-skill", "name: other-skill"), encoding="utf-8")
            errs = validate.validate_skill(d, PROTOCOLS)
            self.assertTrue(any("does not match folder" in e for e in errs), errs)

    def test_description_over_1024_chars_fails(self):
        # Full-review mutant: deleting the description cap left the suite green.
        with tempfile.TemporaryDirectory() as tmp:
            d = make_skill(tmp, "Composes `diagnose`.\n")
            md = d / "SKILL.md"
            md.write_text(md.read_text(encoding="utf-8").replace(
                "A fixture. Use when testing.", "x" * 1100 + " Use when testing."),
                encoding="utf-8")
            errs = validate.validate_skill(d, PROTOCOLS)
            self.assertTrue(any("description length" in e for e in errs), errs)

    def test_frontmatter_over_34_lines_fails(self):
        # Full-review mutant: deleting the frontmatter cap left the suite green.
        with tempfile.TemporaryDirectory() as tmp:
            d = make_skill(tmp, "Composes `diagnose`.\n")
            md = d / "SKILL.md"
            text = md.read_text(encoding="utf-8")
            md.write_text(text.replace("metadata:\n", "metadata:\n" + "# pad\n" * 25, 1),
                          encoding="utf-8")
            errs = validate.validate_skill(d, PROTOCOLS)
            self.assertTrue(any("frontmatter budget" in e for e in errs), errs)

    def test_a_mission_must_state_its_one_worker_pack(self):
        good = "Worker TASK pack: one of matt | addy — never co-mount.\n"
        for bad in ("", "Worker TASK pack: one of foo | bar — never co-mount.\n",
                    "Worker TASK pack: matt; co-mount addy.\n"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                d = make_skill(tmp, "Composes `diagnose`.\n")
                md = d / "SKILL.md"
                md.write_text(md.read_text(encoding="utf-8").replace(good, bad),
                              encoding="utf-8")
                errs = validate.validate_skill(d, PROTOCOLS)
                self.assertTrue(any("worker-pack statement" in e for e in errs), errs)

    def test_a_mutating_mission_must_ride_sandbox_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_skill(tmp, "Composes `diagnose`; rides `evidence-manifest`.\n",
                           name="ship-it")
            errs = validate.validate_skill(
                d, {"diagnose", "evidence-manifest", "sandbox-policy"})
            self.assertTrue(any("must ride `sandbox-policy`" in e for e in errs), errs)

    def test_body_over_110_lines_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n" + "line\n" * 115), PROTOCOLS)
            self.assertTrue(any("body lines" in e for e in errs), errs)

    def test_unknown_frontmatter_field_fails(self):
        # Issue #263: top level is the spec allowlist and nothing else — the
        # repo's own claims moved under `metadata:`. Any other top-level key is
        # a hard error, the same way skills-ref treats it.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(
                    tmp,
                    "Composes `diagnose`.\n",
                    frontmatter_extra="proof: doctrine-only\nautonomy: L4\nauthor: x\n",
                ),
                PROTOCOLS,
            )
            self.assertTrue(
                any("unexpected top-level frontmatter fields" in e and "author" in e for e in errs),
                errs,
            )

    def test_digit_bearing_unknown_frontmatter_field_fails(self):
        # Greptile #221: the old key regex dropped `version2`, so the extras
        # allowlist never saw it.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(
                    tmp,
                    "Composes `diagnose`.\n",
                    frontmatter_extra="proof: doctrine-only\nautonomy: L4\nversion2: x\n",
                ),
                PROTOCOLS,
            )
            self.assertTrue(
                any("unexpected top-level frontmatter fields" in e and "version2" in e for e in errs),
                errs,
            )

    def test_hyphen_leading_unknown_frontmatter_field_fails(self):
        # Greptile #224: tightening the first character to [A-Za-z_] dropped
        # keys the previous `[A-Za-z_-]+` regex accepted.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(
                    tmp,
                    "Composes `diagnose`.\n",
                    frontmatter_extra="proof: doctrine-only\nautonomy: L4\n-weird: x\n",
                ),
                PROTOCOLS,
            )
            self.assertTrue(
                any("unexpected top-level frontmatter fields" in e and "-weird" in e for e in errs),
                errs,
            )

    def test_known_repo_extras_are_not_unexpected(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n"), PROTOCOLS)
            self.assertFalse(any("unexpected frontmatter fields" in e for e in errs), errs)

    def test_clause_without_backticked_names_fails(self):
        # The old ship-it shape: a Composes clause the regex can't see into.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes the playbooks directory.\n"), PROTOCOLS)
            self.assertTrue(
                any("no machine-checkable composition" in e for e in errs), errs)

    def test_dangling_backticked_composition_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `nonexistent-playbook`. \n"), PROTOCOLS)
            self.assertTrue(any("dangling composition" in e for e in errs), errs)

    def test_dangling_md_mention_outside_clause_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`. See land.md for landing.\n"), PROTOCOLS)
            self.assertTrue(
                any("dangling reference: land.md" in e for e in errs), errs)

    def test_path_prefixed_ref_is_flagged(self):
        # Basename-only resolution would let playbooks/sandbox-policy.md pass even
        # though the file lives in runtime/ — the convention is bare names.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`. See playbooks/diagnose.md.\n"), PROTOCOLS)
            self.assertTrue(any("path-prefixed reference" in e for e in errs), errs)

    def test_non_protocol_path_that_exists_is_fine(self):
        # proof_evidence and doc links are legitimate path references — the
        # path-prefix rule only guards PROTOCOL names (found by the first self-run,
        # whose closure commit tripped the old rule).
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`. Evidence: docs/getting-started.md.\n"),
                PROTOCOLS)
            self.assertEqual(errs, [])

    def test_non_protocol_path_that_does_not_exist_dangles(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`. Evidence: docs/runs/never-happened.md.\n"),
                PROTOCOLS)
            self.assertTrue(any("dangling path" in e for e in errs), errs)

    def test_uppercase_doc_mentions_exempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`. Read ../../ARCHITECTURE.md once.\n"),
                PROTOCOLS)
            self.assertEqual(errs, [])

    def test_related_backtick_is_not_an_explicit_ref(self):
        # Issue #216: a Related-section backtick used to keep an orphan alive
        # while the validator never checked it. The shared helper must not
        # treat that form as composition.
        text = (
            "Composes `diagnose`; rides `evidence-manifest`.\n\n"
            "## Related\n`mission-scheduling` (unattended sweep).\n"
        )
        refs = validate.explicit_protocol_refs(text)
        self.assertEqual(refs, {"diagnose", "evidence-manifest"})

    def test_bare_md_token_is_an_explicit_ref(self):
        text = "Composes `diagnose`. See mission-chaining.md for sequences.\n"
        refs = validate.explicit_protocol_refs(text)
        self.assertEqual(refs, {"diagnose", "mission-chaining"})

    def test_url_and_path_prefixed_md_are_not_explicit_refs(self):
        text = (
            "Composes `diagnose`. See https://example.com/upstream-guide.md "
            "and runtime/sandbox-policy.md.\n"
        )
        self.assertEqual(validate.explicit_protocol_refs(text), {"diagnose"})

    def test_compose_clause_backticks_ignore_related(self):
        text = "Composes `diagnose`; rides `evidence-manifest`.\n\n`only-in-related`\n"
        self.assertEqual(
            validate.compose_clause_backticks(text),
            ["diagnose", "evidence-manifest"],
        )

    def test_guide_declared_names_drop_caveat_sentence(self):
        # clean-sweep shape: a later sentence names a protocol the mission
        # does NOT compose. The guide check must not require it.
        text = (
            "Composes `diagnose`; rides `evidence-manifest`. "
            "Not a full `runtime-prove` pass.\n"
        )
        self.assertEqual(
            validate.guide_declared_protocol_names(text),
            ["diagnose", "evidence-manifest"],
        )
        self.assertIn("runtime-prove", validate.compose_clause_backticks(text))

    def test_abbreviation_inside_clause_does_not_truncate_scan(self):
        # ". " after "e.g" used to end the clause capture; names after it escaped.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose` (e.g. `bogus-one`), `bogus-two`.\n"),
                PROTOCOLS)
            self.assertTrue(any("`bogus-one`" in e for e in errs), errs)
            self.assertTrue(any("`bogus-two`" in e for e in errs), errs)

    def test_capitalized_rides_clause_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n\nRides `bogus-policy` at runtime.\n"),
                PROTOCOLS)
            self.assertTrue(any("`bogus-policy`" in e for e in errs), errs)

    def test_url_md_link_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(
                    tmp,
                    "Composes `diagnose`. See https://example.com/upstream-guide.md too.\n"),
                PROTOCOLS)
            self.assertEqual(errs, [])

    def test_case_typo_of_protocol_is_flagged(self):
        # The uppercase exemption must not shelter a typo of a real protocol name.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`. See Diagnose.md for the loop.\n"),
                PROTOCOLS)
            self.assertTrue(any("case/underscore typo" in e for e in errs), errs)


class TestUnreadableSkill(unittest.TestCase):
    """Issue #71: one corrupt SKILL.md must not abort the catalog."""

    def test_non_utf8_skill_md_is_one_error_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "demo-skill"
            d.mkdir()
            (d / "SKILL.md").write_bytes(b"\xff\xfe\x00\x00not utf-8")
            errs = validate.validate_skill(d, PROTOCOLS)
            self.assertEqual(len(errs), 1, errs)
            self.assertTrue(any("unreadable" in e for e in errs), errs)

    def test_oserror_skill_md_is_one_error_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = make_skill(tmp, "Composes `diagnose`.\n")
            with mock.patch.object(Path, "read_text", side_effect=OSError("EACCES")):
                errs = validate.validate_skill(d, PROTOCOLS)
            self.assertEqual(len(errs), 1, errs)
            self.assertTrue(any("unreadable" in e for e in errs), errs)

    def test_non_utf8_playbook_is_recorded_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            playbooks = Path(tmp) / "playbooks"
            runtime = Path(tmp) / "runtime"
            playbooks.mkdir()
            runtime.mkdir()
            (playbooks / "demo.md").write_bytes(b"\xff\xfe")
            (playbooks / "ok.md").write_text(
                "Escalate per diagnose.md.\n", encoding="utf-8"
            )
            with mock.patch.object(validate, "PLAYBOOKS_DIR", playbooks), \
                 mock.patch.object(validate, "RUNTIME_DIR", runtime), \
                 mock.patch.object(validate, "ROOT", Path(tmp)):
                failures = validate.check_protocol_doc_refs(PROTOCOLS)
            self.assertTrue(
                any("unreadable" in f and "demo.md" in f for f in failures), failures
            )
            self.assertFalse(any("ok.md" in f for f in failures), failures)


class TestProofStatus(unittest.TestCase):
    """The predecessor died presenting unproven missions as proven — machine-check it."""

    def test_catalog_growth_must_be_paid_for_with_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills").mkdir()
            for i in range(validate.CATALOG_BASE[0] + 1):
                make_skill(root / "skills", "Composes `diagnose`.\n", name=f"m{i:02d}-it")
            failures = validate.check_proof_ratchet(root=root)
            self.assertTrue(any("proof ratchet" in f for f in failures), failures)
            one = root / "skills" / "m00-it" / "SKILL.md"
            one.write_text(one.read_text(encoding="utf-8").replace(
                "proof: doctrine-only", "proof: self-run"), encoding="utf-8")
            failures = validate.check_proof_ratchet(root=root)
            self.assertTrue(failures, "one proven mission must not pay for growth alone")
            for i in range(1, validate.CATALOG_BASE[1] + 1):
                p = root / "skills" / f"m{i:02d}-it" / "SKILL.md"
                p.write_text(p.read_text(encoding="utf-8").replace(
                    "proof: doctrine-only", "proof: self-run"), encoding="utf-8")
            self.assertEqual(validate.check_proof_ratchet(root=root), [])

    def test_live_catalog_sits_on_the_ratchet(self):
        self.assertEqual(validate.check_proof_ratchet(), [])

    def test_missing_proof_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n", frontmatter_extra=""), PROTOCOLS)
            self.assertTrue(any("missing 'proof'" in e for e in errs), errs)

    def test_invalid_proof_value_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: battle-tested\n"), PROTOCOLS)
            self.assertTrue(any("proof 'battle-tested' invalid" in e for e in errs), errs)

    def test_advanced_proof_without_evidence_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: self-run\n"), PROTOCOLS)
            self.assertTrue(any("requires proof_evidence" in e for e in errs), errs)

    def test_advanced_proof_evidence_outside_repo_fails(self):
        # An absolute/traversal proof_evidence pointing OUTSIDE the repo must not
        # certify proof, even if the target file exists (containment guard).
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as ext:
            evpath = Path(ext) / "external-report.md"
            evpath.write_text("x\n", encoding="utf-8")
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra=f"proof: external-run\nproof_evidence: {evpath}\nautonomy: L4\n"),
                PROTOCOLS)
            self.assertTrue(any("requires proof_evidence" in e for e in errs), errs)

    def test_proof_evidence_must_be_a_docs_runs_report(self):
        # #113: an in-repo file that is NOT a docs/runs report cannot certify a proof tier.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: external-run\nproof_evidence: README.md\nautonomy: L4\n"),
                PROTOCOLS)
            self.assertTrue(any("requires proof_evidence" in e for e in errs), errs)

    def test_proof_evidence_must_mention_the_mission(self):
        # #113: a real docs/runs report for a DIFFERENT mission does not certify this one.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: self-run\n"
                           "proof_evidence: docs/runs/2026-08-28-ship-it-self-run.md\nautonomy: L4\n"),
                PROTOCOLS)
            self.assertTrue(any("must be mission" in e and "run report" in e for e in errs), errs)

    def test_prose_mention_with_wrong_filename_rejected(self):
        # #133 review: a DIFFERENT mission's report that mentions this mission in prose used to
        # satisfy the substring check. Correlation now also requires the name in the FILENAME.
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "docs" / "runs"
            runs.mkdir(parents=True)
            (runs / "2026-01-01-clean-sweep-self-run.md").write_text(
                "clean-sweep run; also touched demo-skill in passing.\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)):
                errs = validate.validate_skill(
                    make_skill(tmp, "Composes `diagnose`.\n",
                               frontmatter_extra="proof: self-run\n"
                               "proof_evidence: docs/runs/2026-01-01-clean-sweep-self-run.md\nautonomy: L4\n"),
                    PROTOCOLS)
            self.assertTrue(any("must be mission" in e for e in errs), errs)

    def test_non_utf8_run_report_is_error_not_traceback(self):
        # #133 review: a docs/runs report with invalid UTF-8 must be a per-file error, never a
        # UnicodeDecodeError that aborts the whole validation.
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "docs" / "runs"
            runs.mkdir(parents=True)
            (runs / "2026-01-01-demo-skill-self-run.md").write_bytes(b"\xff\xfe not utf8\n")
            with mock.patch.object(validate, "ROOT", Path(tmp)):
                errs = validate.validate_skill(
                    make_skill(tmp, "Composes `diagnose`.\n",
                               frontmatter_extra="proof: self-run\n"
                               "proof_evidence: docs/runs/2026-01-01-demo-skill-self-run.md\nautonomy: L4\n"),
                    PROTOCOLS)
            self.assertTrue(any("must be mission" in e for e in errs), errs)

    def test_correct_run_report_passes_correlation(self):
        # Positive control: named in filename AND body → no proof error (not always-fail).
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "docs" / "runs"
            runs.mkdir(parents=True)
            (runs / "2026-01-01-demo-skill-self-run.md").write_text(
                "# demo-skill self-run\nThis is demo-skill's run report.\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)):
                errs = validate.validate_skill(
                    make_skill(tmp, "Composes `diagnose`.\n",
                               frontmatter_extra="proof: self-run\n"
                               "proof_evidence: docs/runs/2026-01-01-demo-skill-self-run.md\nautonomy: L4\n"),
                    PROTOCOLS)
            self.assertFalse(any("must be mission" in e or "requires proof_evidence" in e for e in errs), errs)

    def test_over_budget_mission_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = "Composes `diagnose`.\n" + ("filler line\n" * validate.MISSION_MAX_LINES)
            errs = validate.validate_skill(make_skill(tmp, body), PROTOCOLS)
            self.assertTrue(any("instruction budget" in e for e in errs), errs)

    def test_mutating_mission_must_ride_evidence_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Folder name is the mission name used by the mutator check.
            d = Path(tmp) / "ship-it"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: ship-it\ndescription: Use when shipping.\n"
                "proof: doctrine-only\n---\n\nComposes `diagnose`.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(d, PROTOCOLS | {"diagnose"})
            self.assertTrue(
                any("must ride `evidence-manifest`" in e for e in errs), errs
            )

    def test_mutating_mission_compose_mention_alone_does_not_count(self):
        # Codex P2: backticks in a Composes paragraph must not satisfy the ride.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "ship-it"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: ship-it\ndescription: Use when shipping.\n"
                "proof: doctrine-only\n---\n\n"
                "Composes `diagnose`; unlike other missions it does not ride "
                "`evidence-manifest`.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(
                d, PROTOCOLS | {"diagnose", "evidence-manifest"}
            )
            self.assertTrue(
                any("must ride `evidence-manifest`" in e for e in errs), errs
            )

    def test_mutating_mission_prose_rides_does_not_count(self):
        # Greptile P2: mid-sentence "rides `…`" in anti-patterns must not satisfy.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "ship-it"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: ship-it\ndescription: Use when shipping.\n"
                "proof: doctrine-only\n---\n\n"
                "Composes `diagnose`.\n\n"
                "## Anti-patterns\n\n"
                "If the worker rides `evidence-manifest` out of turn, ignore it.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(
                d, PROTOCOLS | {"diagnose", "evidence-manifest"}
            )
            self.assertTrue(
                any("must ride `evidence-manifest`" in e for e in errs), errs
            )

    def test_mutating_mission_all_caps_rides_counts(self):
        # Greptile P2: RIDES must match like COMPOSES.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "ship-it"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: ship-it\ndescription: Use when shipping.\n"
                "proof: doctrine-only\n---\n\n"
                "Composes `diagnose`.\n\nRIDES `evidence-manifest`.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(
                d, PROTOCOLS | {"diagnose", "evidence-manifest"}
            )
            self.assertFalse(
                any("must ride `evidence-manifest`" in e for e in errs), errs
            )

    def test_mutating_mission_with_evidence_manifest_passes_that_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "ship-it"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: ship-it\ndescription: Use when shipping.\n"
                "proof: doctrine-only\n---\n\n"
                "Composes `diagnose`; rides `evidence-manifest`.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(
                d, PROTOCOLS | {"diagnose", "evidence-manifest"}
            )
            self.assertFalse(
                any("must ride `evidence-manifest`" in e for e in errs), errs
            )


class TestProtocolDocRefs(unittest.TestCase):
    """Dangling .md refs inside playbooks/ and runtime/ must fail the build too."""

    def _with_dirs(self, doc_text):
        with tempfile.TemporaryDirectory() as tmp:
            playbooks = Path(tmp) / "playbooks"
            runtime = Path(tmp) / "runtime"
            playbooks.mkdir()
            runtime.mkdir()
            (playbooks / "demo.md").write_text(doc_text, encoding="utf-8")
            with mock.patch.object(validate, "PLAYBOOKS_DIR", playbooks), \
                 mock.patch.object(validate, "RUNTIME_DIR", runtime), \
                 mock.patch.object(validate, "ROOT", Path(tmp)):
                return validate.check_protocol_doc_refs(PROTOCOLS)

    def test_dangling_ref_in_playbook_fails(self):
        failures = self._with_dirs("The LAND phase runs per land.md as always.\n")
        self.assertTrue(any("land.md" in f for f in failures), failures)

    def test_a_playbook_naming_two_router_packs_fails(self):
        failures = self._with_dirs("Recipe: Matt `tdd` + Addy `incremental-implementation`.\n")
        self.assertTrue(any("one-router" in f for f in failures), failures)

    def test_resolving_ref_in_playbook_passes(self):
        failures = self._with_dirs("Escalate per diagnose.md when the loop stalls.\n")
        self.assertEqual(failures, [])


class TestLayerSeparation(unittest.TestCase):
    """Issue #47: AGENTS.md says only skills/ may contain a SKILL.md, so the scan
    must be repo-wide — a stray SKILL.md in docs/, scripts/, or the repo root would
    auto-trigger just as badly as one in playbooks/ or runtime/."""

    def _leaks_for(self, rel_paths):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in rel_paths:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", root):
                return validate.check_layer_separation()

    def test_skill_md_outside_skills_fails_anywhere(self):
        leaks = self._leaks_for(
            ["docs/SKILL.md", "scripts/SKILL.md", "SKILL.md", "playbooks/SKILL.md"])
        self.assertEqual(
            leaks, ["SKILL.md", "docs/SKILL.md", "playbooks/SKILL.md", "scripts/SKILL.md"])

    def test_mission_skill_md_is_not_a_leak(self):
        self.assertEqual(self._leaks_for(["skills/demo/SKILL.md"]), [])

    def test_bare_or_nested_skills_skill_md_is_a_leak(self):
        leaks = self._leaks_for(["skills/SKILL.md", "skills/demo/evals/SKILL.md"])
        self.assertEqual(leaks, ["skills/SKILL.md", "skills/demo/evals/SKILL.md"])

    def test_dot_and_dependency_dirs_are_not_repo_content(self):
        self.assertEqual(
            self._leaks_for([".git/SKILL.md", "node_modules/x/SKILL.md"]), [])

    def test_untracked_dot_dirs_are_not_repo_content(self):
        # #139 review: a checkout-local .venv/.tox/tool dot-dir holding a SKILL.md must not be
        # read as a layer leak; only tracked dot-dirs (.claude-plugin) stay in scope.
        self.assertEqual(
            self._leaks_for([".venv/lib/SKILL.md", ".tox/x/SKILL.md", ".greptile-internal/SKILL.md"]), [])

    def test_tracked_dot_dir_skill_is_caught(self):
        # #150 review: a TRACKED SKILL.md under a dot-dir (.github, .vscode) is repo content and MUST
        # be caught; only UNtracked local dot-dirs (.venv) are skipped. Git is the tracked oracle.
        import subprocess as sp
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sp.run(["git", "-C", tmp, "init", "-q"], check=True)
            for rel in (".github/SKILL.md", ".venv/lib/SKILL.md", "skills/demo/SKILL.md"):
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x", encoding="utf-8")
            sp.run(["git", "-C", tmp, "add", ".github/SKILL.md", "skills/demo/SKILL.md"], check=True)
            leaks = validate.check_layer_separation(root=root)
        self.assertIn(".github/SKILL.md", leaks)          # tracked dot-dir content → caught
        self.assertNotIn(".venv/lib/SKILL.md", leaks)     # untracked local dir → skipped
        self.assertNotIn("skills/demo/SKILL.md", leaks)   # the one discoverable form


class TestCountAgnosticGuards(unittest.TestCase):
    """The count-lint, keyword-check, and badge-freshness guards must each be able to fire —
    a mission is added by a human, so the guards that keep the docs count-agnostic and the
    manifest/badges in sync are the safety net."""

    def test_count_lint_matches_catalog_counts(self):
        for s in ("11 missions", "eleven missions", "twelve missions", "10 outcome-named",
                  "11 callable", "eleven outcome-named", "twelve callable"):
            self.assertRegex(s, validate.COUNT_LINT_RE, s)

    def test_count_lint_matches_stale_phrasing_classes(self):
        # Issue #33: phrasings that outlived the ten-mission era and slid past the
        # old `\d+\s+missions` shape — hyphenated counts, and number-word +
        # adjective + noun taglines (with or without markdown bold).
        for s in ("the ten-mission set", "an 11-mission catalog",
                  "Ten **autonomous fleets** for the runtime",
                  "eleven autonomous fleets"):
            self.assertRegex(s, validate.COUNT_LINT_RE, s)

    def test_count_lint_matches_proof_tier_counts(self):
        # #282: "The catalog reads 21 `doctrine-only`." is a hardcoded catalog count, and it sat
        # in README.md while this guard was green — the tiers were not in the noun set and a
        # backtick was not a separator. The guard against this exact rot had a hole in it.
        for s in ("21 `doctrine-only`", "21 doctrine-only", "seventeen self-run",
                  "12 external-run"):
            self.assertRegex(s, validate.COUNT_LINT_RE, s)
        # Count-agnostic phrasing of the same fact must still pass.
        self.assertNotRegex("Every mission in the catalog reads `doctrine-only`.",
                            validate.COUNT_LINT_RE)

    def test_count_lint_matches_compound_spelled_counts(self):
        # #346: the spelled set stopped at "twenty", so every count past it was invisible —
        # and the compound form broke the guard in a second, sneakier way. In "twenty-one
        # autonomous fleets" the "one" was eaten by the single optional-adjective slot,
        # leaving nothing to match "autonomous", so the repo's OWN tagline shape slipped
        # through at exactly the catalog size that made the phrase current. A compound is
        # one number token, not a number plus a word.
        for s in ("twenty-one autonomous fleets", "twenty-one **autonomous fleets**",
                  "twenty-one outcome-named fleets", "twenty one missions",
                  "thirty-one missions", "forty-two callable",
                  "Twenty-one outcome-named autonomous fleets for the Orca runtime"):
            self.assertRegex(s, validate.COUNT_LINT_RE, s)
        # A lone ones-word is still mission-identity prose, not a catalog size — that is
        # the invariant the compound must not cost us.
        for s in ("one mission", "two missions", "three missions", "one router per worker"):
            self.assertNotRegex(s, validate.COUNT_LINT_RE, s)

    def test_check_doc_counts_flags_all_n_near_mission_talk(self):
        # Issue #33: "…one mission or all ten." — a catalog count with no noun.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text(
                "whether it copies one mission or all ten. Check the tree after.\n",
                encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)), \
                 mock.patch.object(validate, "COUNT_LINT_FILES", ("README.md",)):
                failures = validate.check_doc_counts()
        self.assertTrue(any("all ten" in f for f in failures), failures)

    def test_all_n_near_bare_catalog_talk_is_flagged(self):
        # Deliberate width (Greptile P2 on #59): in the linted doc surfaces
        # "catalog" only ever means the mission catalog, so "all N" next to it is
        # a catalog count even with no mission/fleet word on the line.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text(
                "the catalog covers all eleven of them.\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)), \
                 mock.patch.object(validate, "COUNT_LINT_FILES", ("README.md",)):
                failures = validate.check_doc_counts()
        self.assertTrue(any("all eleven" in f for f in failures), failures)

    def test_all_n_off_mission_lines_is_not_a_catalog_count(self):
        # "all ten" only reads as a catalog count next to mission/fleet/catalog talk.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text(
                "run all ten checks before landing anything.\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)), \
                 mock.patch.object(validate, "COUNT_LINT_FILES", ("README.md",)):
                self.assertEqual(validate.check_doc_counts(), [])

    def test_count_lint_ignores_mission_identity_prose(self):
        # "one mission" / "two missions" in the identity discussion are NOT catalog counts.
        for s in ("are one mission (clean-sweep)", "two workflows are the same mission",
                  "each mission is one outcome", "the missions genuinely differ",
                  "docs/assets/badges/missions.json"):
            self.assertIsNone(validate.COUNT_LINT_RE.search(s), s)

    def test_check_doc_counts_flags_hardcoded_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text("open-fleet ships eleven missions.\n",
                                                 encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)), \
                 mock.patch.object(validate, "COUNT_LINT_FILES", ("README.md",)):
                failures = validate.check_doc_counts()
        self.assertTrue(any("eleven missions" in f for f in failures), failures)

    def test_check_doc_counts_exempts_predecessor(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text(
                "Its predecessor shipped twelve missions with two proven.\n", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)), \
                 mock.patch.object(validate, "COUNT_LINT_FILES", ("README.md",)):
                self.assertEqual(validate.check_doc_counts(), [])

    def test_check_doc_counts_predecessor_after_count_still_flags(self):
        # The exemption is positional: a CURRENT catalog count followed by a predecessor
        # mention on the same line must still fail the lint.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "README.md").write_text(
                "We now have 12 missions, improving on the predecessor's approach.\n",
                encoding="utf-8")
            with mock.patch.object(validate, "ROOT", Path(tmp)), \
                 mock.patch.object(validate, "COUNT_LINT_FILES", ("README.md",)):
                failures = validate.check_doc_counts()
        self.assertTrue(any("12 missions" in f for f in failures), failures)

    def test_check_manifest_keywords_flags_missing_mission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".claude-plugin").mkdir()
            (root / ".claude-plugin" / "plugin.json").write_text(
                '{"keywords": ["ship-it"]}', encoding="utf-8")
            skills = root / "skills"
            for m in ("ship-it", "new-mission"):
                (skills / m).mkdir(parents=True)
                (skills / m / "SKILL.md").write_text("x", encoding="utf-8")
            with mock.patch.object(validate, "ROOT", root), \
                 mock.patch.object(validate, "SKILLS_DIR", skills):
                failures = validate.check_manifest_keywords()
        self.assertTrue(any("new-mission" in f for f in failures), failures)
        self.assertFalse(any("ship-it" in f for f in failures), failures)

    def test_guards_pass_on_the_real_repo(self):
        # The valid corpus must be green on all three guards.
        self.assertEqual(validate.check_doc_counts(), [])
        self.assertEqual(validate.check_manifest_keywords(), [])
        self.assertEqual(validate.check_badge_freshness(), [])

    def test_ledger_row_guard_passes_on_the_real_repo(self):
        self.assertEqual(validate.check_ledger_rows(), [])

    def test_a_ledger_row_dropping_a_canonical_flag_fails(self):
        # #357: absorb-it's row shipped without `lighting` while gate-classification mandates it
        # on every dispatched unit — the guard must catch exactly that drop.
        with tempfile.TemporaryDirectory() as tmp:
            skills = Path(tmp) / "skills"
            (skills / "demo-it").mkdir(parents=True)
            (skills / "demo-it" / "SKILL.md").write_text(
                "---\nname: demo-it\n---\n\n`| task_id | unit | BUILD_DONE | PR_OPEN | BOT | "
                "REVIEWED | MERGED | WT_CLEAN | park | evidence |`\n", encoding="utf-8")
            with mock.patch.object(validate, "SKILLS_DIR", skills):
                failures = validate.check_ledger_rows()
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("demo-it", failures[0])
        self.assertIn("lighting", failures[0])
        # #750 C12: offload-it's inline, multi-line-wrapped row omitted BUILD_DONE and BOT and
        # escaped `row.startswith("| task_id |")`.
        with tempfile.TemporaryDirectory() as tmp:
            skills = Path(tmp) / "skills"
            (skills / "demo-it").mkdir(parents=True)
            (skills / "demo-it" / "SKILL.md").write_text(
                "---\nname: demo-it\n---\n\nOne row per recipe: `| task_id | recipe | INTERVIEW | SCAFFOLD |\n"
                "PROVISION | PR_OPEN | REVIEWED | MERGED | WT_CLEAN | lighting | park | evidence |`.\n",
                encoding="utf-8")
            with mock.patch.object(validate, "SKILLS_DIR", skills):
                wrapped_failures = validate.check_ledger_rows()
        self.assertEqual(len(wrapped_failures), 1, wrapped_failures)
        self.assertIn("demo-it", wrapped_failures[0])
        self.assertIn("BUILD_DONE", wrapped_failures[0])
        self.assertIn("BOT", wrapped_failures[0])

    def test_badge_check_flags_stale(self):
        # tests.json is written CURRENT so the only error can come from missions.json's
        # staleness — a "missing file" error must not be able to satisfy this test.
        import json as _json
        spec = importlib.util.spec_from_file_location("_gb", ROOT / "scripts" / "gen-badges.py")
        gb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gb)
        current = gb.compute()
        with tempfile.TemporaryDirectory() as tmp:
            bd = Path(tmp) / "badges"
            bd.mkdir()
            (bd / "missions.json").write_text(
                '{"schemaVersion": 1, "label": "missions", "message": "999", "color": "1f6feb"}',
                encoding="utf-8")
            (bd / "tests.json").write_text(_json.dumps(current["tests.json"]), encoding="utf-8")
            with mock.patch.object(gb, "BADGES_DIR", bd):
                errs = gb.check()
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("missions.json", errs[0])
        self.assertIn("stale", errs[0])

    def test_badge_check_reports_missing_dirs_cleanly(self):
        # A fresh checkout without skills/ must produce an error string, not a traceback.
        spec = importlib.util.spec_from_file_location("_gb2", ROOT / "scripts" / "gen-badges.py")
        gb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gb)
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(gb, "SKILLS_DIR", Path(tmp) / "nope"):
                errs = gb.check()
        self.assertTrue(errs and "missing" in errs[0], errs)

    def test_gen_badges_rejects_unknown_arguments_without_writing(self):
        # #353: `if "--check" in sys.argv[1:]` treated a typo'd --chek as "write" — CI would
        # have mutated the committed badges instead of checking them.
        badge = ROOT / "docs" / "assets" / "badges" / "tests.json"
        before = badge.read_bytes()
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen-badges.py"), "--chek"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, "an unknown flag exited 0")
        self.assertEqual(badge.read_bytes(), before, "an unknown flag rewrote the badge")

    def test_badge_inventory_is_honest_for_failing_and_passing_suites(self):
        spec = importlib.util.spec_from_file_location("_inventory", ROOT / "scripts/gen-badges.py")
        gb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gb)
        generated = []
        for outcome, expected_exit in ((False, 1), (True, 0)):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                tests = Path(tmp)
                (tests / "test_fixture.py").write_text(
                    "import unittest\nclass Fixture(unittest.TestCase):\n"
                    f"    def test_behavior(self):\n        self.assertTrue({outcome!r})\n",
                    encoding="utf-8",
                )
                run = subprocess.run(
                    [sys.executable, "-m", "unittest", "discover", "-s", str(tests)],
                    capture_output=True, text=True,
                )
                self.assertEqual(run.returncode, expected_exit, run.stdout + run.stderr)
                self.assertIn("Ran 1 test", run.stderr)
                if not outcome:
                    self.assertIn("AssertionError", run.stderr)
                with mock.patch.object(gb, "TESTS_DIR", tests), \
                     mock.patch.object(gb, "BADGES_DIR", tests / "badges"), \
                     generated_copies(gb, tests / "generated"):
                    gb.write()
                    badge = json.loads((gb.BADGES_DIR / "tests.json").read_text())
                    generated.append(badge)
                    self.assertEqual(gb.check(), [])
                # The fixture's single definition exists in source regardless of its exit.
                self.assertEqual(badge["label"], "test functions")
                self.assertEqual(badge["message"], "1 in source")
                self.assertEqual(badge["color"], "6e7781")  # neutral inventory
        self.assertEqual(generated[0], generated[1])

    def test_badge_counts_definitions_not_text_that_reads_like_one(self):
        """PR #334 review, P2.

        The count was a regex over the text, and this suite embeds test sources AS DATA — a test
        about test files carries test files in fixture strings. Where such a string body starts a
        line, the regex counted it as a definition. The badge is a public inventory, so it counts
        what Python would call a test function.
        """
        spec = importlib.util.spec_from_file_location("_counts", ROOT / "scripts/gen-badges.py")
        gb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gb)
        cases = (
            # (source, definitions actually present)
            ('FIXTURE = """\ndef test_embedded():\n    pass\n"""\n\ndef test_real():\n    pass\n', 1),
            ('BASE = """def test_inline():\n    pass\n"""\ndef test_real():\n    pass\n', 1),
            ("def test_a():\n    pass\n\n\nasync def test_b():\n    pass\n", 2),
            ('S = """\n    def test_indented(self):\n        pass\n"""\n', 0),
            ("class T:\n    def test_method(self):\n        pass\n", 1),
            ("def helper():\n    pass\n", 0),
        )
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            fixture = tests / "test_fixture.py"
            with mock.patch.object(gb, "TESTS_DIR", tests):
                for source, expected in cases:
                    with self.subTest(source=source):
                        fixture.write_text(source, encoding="utf-8")
                        self.assertEqual(gb.test_count(), expected, source)

    def test_badge_inventory_refreshes_counts_and_rejects_success_claims(self):
        spec = importlib.util.spec_from_file_location("_counts", ROOT / "scripts/gen-badges.py")
        gb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gb)
        with tempfile.TemporaryDirectory() as tmp:
            tests = Path(tmp)
            fixture = tests / "test_fixture.py"
            with mock.patch.object(gb, "TESTS_DIR", tests), \
                 mock.patch.object(gb, "BADGES_DIR", tests / "badges"), \
                 generated_copies(gb, tests / "generated"):
                for source, count in (("", 0), ("def test_one(): pass\n", 1),
                                      ("def test_one(): pass\ndef test_two(): pass\n", 2)):
                    fixture.write_text(source, encoding="utf-8")
                    self.assertTrue(any("tests.json" in err for err in gb.check()))
                    gb.write()
                    path = gb.BADGES_DIR / "tests.json"
                    badge = json.loads(path.read_text())
                    self.assertEqual(badge["message"], f"{count} in source")
                    self.assertEqual(gb.check(), [])
                for field, value in (("message", "2 passing"), ("color", "2ea043")):
                    path.write_text(json.dumps({**badge, field: value}), encoding="utf-8")
                    errors = gb.check()
                    self.assertEqual(len(errors), 1, errors)
                    self.assertIn("tests.json is stale", errors[0])
                fixture.unlink()
                self.assertTrue(any("tests.json is stale" in err for err in gb.check()))
                gb.write()
                self.assertEqual(json.loads(path.read_text())["message"], "0 in source")
                self.assertEqual(gb.check(), [])

class ParseFrontmatterBindingTest(unittest.TestCase):
    """prove-it self-run criterion PF-1: a YAML block-scalar frontmatter value
    (`key: >` / `key: |` + indented continuation) must parse to a single
    space-joined string carrying every continuation line. Missions fold
    `description:` / `compatibility:` this way; a regression would silently
    truncate them past the compose-clause and description checks. Bound to
    parse_frontmatter's fold path (validate.py ~156-181); the pinned mutant that
    kills it is the fold join `" "` -> `""` on the final-key branch.
    """

    def test_block_scalar_folds_to_space_joined_string(self):
        text = (
            "---\n"
            "name: demo\n"
            "description: >\n"
            "  first line\n"
            "  second line\n"
            "---\nbody\n"
        )
        data, err = validate.parse_frontmatter(text)
        self.assertIsNone(err)
        self.assertEqual(data["description"], "first line second line")

    def test_block_scalar_followed_by_another_key_folds(self):
        # #90 review: a block scalar that is NOT the last key exercises the mid-loop fold join — a
        # separate code path from the post-loop join the test above covers.
        text = (
            "---\n"
            "name: demo\n"
            "description: >\n"
            "  first line\n"
            "  second line\n"
            "proof: doctrine-only\n"
            "---\nbody\n"
        )
        data, err = validate.parse_frontmatter(text)
        self.assertIsNone(err)
        self.assertEqual(data["description"], "first line second line")
        self.assertEqual(data["proof"], "doctrine-only")


class AutonomyFieldTest(unittest.TestCase):
    """#82: every mission declares an Osmani autonomy level L0-L5; the validator
    rejects a missing or illegal value (negative-path proof the guard fires)."""

    def test_missing_autonomy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: doctrine-only\n"), PROTOCOLS)
            self.assertTrue(any("missing 'autonomy'" in e for e in errs), errs)

    def test_illegal_autonomy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: doctrine-only\nautonomy: L9\n"), PROTOCOLS)
            self.assertTrue(any("autonomy 'L9' invalid" in e for e in errs), errs)


class GuardBypassTest(unittest.TestCase):
    """#122: lowercase composes, the byte budget, and the dot-dir SKILL scan."""

    def test_lowercase_composes_dangling_caught(self):
        # A lowercase "composes" in a SEPARATE paragraph used to escape the clause scan entirely.
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n\nIt also composes `nonexistent-proto`.\n"),
                PROTOCOLS)
            self.assertTrue(any("nonexistent-proto" in e for e in errs), errs)

    def test_byte_budget_fires_on_a_huge_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = "Composes `diagnose`.\n" + ("x " * 20000) + "\n"  # ~2 lines, ~40KB
            errs = validate.validate_skill(make_skill(tmp, body), PROTOCOLS)
            self.assertTrue(any("byte cap" in e for e in errs), errs)

    def test_dotdir_skill_leak_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills" / "foo").mkdir(parents=True)
            (root / "skills" / "foo" / "SKILL.md").write_text("x", encoding="utf-8")
            (root / ".claude-plugin").mkdir()
            (root / ".claude-plugin" / "SKILL.md").write_text("x", encoding="utf-8")
            leaks = validate.check_layer_separation(root=root)
            self.assertIn(".claude-plugin/SKILL.md", leaks)
            self.assertNotIn("skills/foo/SKILL.md", leaks)

class MetadataBlock(unittest.TestCase):
    """Issue #263: the repo's claims live under `metadata:`, the spec's extension point."""

    def test_metadata_block_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "demo-skill"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: demo-skill\ndescription: A fixture. Use when testing.\n---\n"
                "Composes `diagnose`.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(d, PROTOCOLS)
            self.assertTrue(any("missing 'metadata:' block" in e for e in errs), errs)

    def test_metadata_must_be_a_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "demo-skill"
            d.mkdir()
            (d / "SKILL.md").write_text(
                "---\nname: demo-skill\ndescription: A fixture. Use when testing.\n"
                "metadata: a string\n---\nComposes `diagnose`.\n",
                encoding="utf-8",
            )
            errs = validate.validate_skill(d, PROTOCOLS)
            self.assertTrue(any("metadata must be a map" in e for e in errs), errs)

    def test_unknown_metadata_key_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           frontmatter_extra="proof: doctrine-only\nautonomy: L4\n",
                           identity=dict(FIXTURE_IDENTITY, vibes="great")),
                PROTOCOLS,
            )
            self.assertTrue(any("unexpected metadata keys" in e and "vibes" in e for e in errs), errs)

    def test_metadata_value_has_a_length_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           identity=dict(FIXTURE_IDENTITY, unit="u" * 300)),
                PROTOCOLS,
            )
            self.assertTrue(any("chars >" in e and "metadata.unit" in e for e in errs), errs)

    def test_parse_frontmatter_reads_the_nested_block(self):
        data, err = validate.parse_frontmatter(
            "---\nname: x\ndescription: >-\n  folded\n  text\n"
            "metadata:\n  proof: self-run\n  autonomy: L4\ncompatibility: y\n---\nbody\n"
        )
        self.assertIsNone(err)
        self.assertEqual(data["metadata"], {"proof": "self-run", "autonomy": "L4"})
        self.assertEqual(data["description"], "folded text")
        self.assertEqual(data["compatibility"], "y")


class MissionIdentity(unittest.TestCase):
    """Issue #265: ARCHITECTURE.md's six-point test, made executable."""

    def test_every_identity_point_is_required(self):
        for missing in validate.IDENTITY_KEYS:
            identity = {k: v for k, v in FIXTURE_IDENTITY.items() if k != missing}
            with tempfile.TemporaryDirectory() as tmp:
                errs = validate.validate_skill(
                    make_skill(tmp, "Composes `diagnose`.\n", identity=identity), PROTOCOLS
                )
                self.assertTrue(
                    any(f"missing metadata.{missing}" in e for e in errs),
                    f"{missing} was not required: {errs}",
                )

    def _catalog(self, tmp, *skills):
        root = Path(tmp)
        (root / "skills").mkdir()
        for name, identity in skills:
            make_skill(root / "skills", "Composes `diagnose`.\n", name=name, identity=identity)
        return root

    def test_two_missions_with_the_same_six_points_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(
                tmp, ("alpha-it", FIXTURE_IDENTITY), ("beta-it", FIXTURE_IDENTITY)
            )
            errors, _warnings = validate.identity_collisions(root=root)
            self.assertTrue(
                any("alpha-it and beta-it" in e for e in errors),
                f"a duplicated identity tuple passed: {errors}",
            )

    def test_differing_on_one_point_warns_but_does_not_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = dict(FIXTURE_IDENTITY, oracle="a completely different authority entirely")
            root = self._catalog(tmp, ("alpha-it", FIXTURE_IDENTITY), ("beta-it", other))
            errors, warnings = validate.identity_collisions(root=root)
            self.assertEqual(errors, [])
            self.assertTrue(any("differ on only oracle" in w for w in warnings), warnings)

    def test_differing_on_two_points_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = dict(
                FIXTURE_IDENTITY,
                oracle="a completely different authority entirely",
                unit="an unrelated kind of thing altogether",
            )
            root = self._catalog(tmp, ("alpha-it", FIXTURE_IDENTITY), ("beta-it", other))
            errors, warnings = validate.identity_collisions(root=root)
            self.assertEqual((errors, warnings), ([], []))

    def test_a_one_word_paraphrase_of_every_point_is_refused(self):
        """#288 / D3b. Raw surface tokens made this a duplicate-STRING detector wearing an identity
        test's name: swapping one word a point dropped similarity from 1.00 to 0.667, under the
        0.85 bar, on all six at once. A second mission could restate the first and pass."""
        original = {
            "unit": "one finite backlog item drained to zero with evidence",
            "state_machine": "triage then remediate then verify then close",
            "convergence": "a full re-enumeration finds no open item remaining",
            "ordering": "highest severity finding first, then oldest",
            "parking": "PARKED with a named blocking reason recorded",
            "oracle": "the tracker query that returns no open items",
        }
        paraphrase = {
            "unit": "one finite backlog item emptied to zero with evidence",
            "state_machine": "triage then remediate then check then close",
            "convergence": "a full re-enumeration finds no open item outstanding",
            "ordering": "highest severity finding first, then earliest",
            "parking": "PARKED with a named blocking cause recorded",
            "oracle": "the tracker query that returns no open entries",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("alpha-it", original), ("beta-it", paraphrase))
            errors, _warnings = validate.identity_collisions(root=root)
        self.assertTrue(any("restate one identity" in e for e in errors),
                        f"a paraphrased identity passed: {errors}")

    def test_a_disjoint_vocabulary_paraphrase_is_refused(self):
        # Full-review probe T2b: every content word swapped for a synonym the
        # routing table never mentions (ticket/queue/replicated/repaired/
        # confirmed/recounting/checkout/person/checks/revision) left no shared
        # stems, so the identity read as divergent. Concept canonicalisation,
        # not string overlap, has to close this.
        original = {
            "unit": "one open issue from the frozen backlog",
            "state_machine": "open then reproduced then fixed then independently verified then closed",
            "convergence": "a full re-enumeration of the backlog finds zero open issues",
            "ordering": "one issue per isolated worktree, merges serialised",
            "parking": "PARKED when a human decision is required",
            "oracle": "the repository test suite at the reviewed commit",
        }
        paraphrase = {
            "unit": "a single unresolved ticket from the fixed queue",
            "state_machine": "outstanding then replicated then repaired then separately confirmed then resolved",
            "convergence": "recounting every queued ticket shows none remain unresolved",
            "ordering": "each ticket alone in its own checkout, landings serialised",
            "parking": "held aside whenever a person must decide",
            "oracle": "the project automated checks at the signed-off revision",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("alpha-it", original), ("beta-it", paraphrase))
            errors, _warnings = validate.identity_collisions(root=root)
        self.assertTrue(errors, "a disjoint-vocabulary paraphrase passed the identity gate")

    def test_inflection_alone_does_not_defeat_the_test(self):
        # Stemming closes the cheapest paraphrase of all: pluralising and re-tensing.
        original = {
            "unit": "one finite backlog item drained to zero with evidence",
            "state_machine": "triage then remediate then verify then close",
            "convergence": "a full re-enumeration finds no open item remaining",
            "ordering": "highest severity finding first, then oldest",
            "parking": "PARKED with a named blocking reason recorded",
            "oracle": "the tracker query that returns no open items",
        }
        inflected = {k: v.replace("backlog", "backlogs").replace("drained", "draining")
                        .replace("finds", "finding").replace("returns", "returning")
                     for k, v in original.items()}
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("alpha-it", original), ("beta-it", inflected))
            errors, _warnings = validate.identity_collisions(root=root)
        # Specifically the SIX-POINT message, not the paraphrase one: stemming must make an
        # inflected copy read as the same point, not merely a similar one. Without it these score
        # ~0.71 and would be caught one rung down, which would leave the tokenizer untested.
        self.assertTrue(any("the same six identity points" in e for e in errors),
                        f"stemming did not collapse inflection: {errors}")

    def test_a_genuinely_distinct_mission_is_not_flagged(self):
        # The gate must not fire on real disagreement. ARCHITECTURE.md deliberately allows two
        # missions to differ on one point (WARN) or two (silent) — those average high while being
        # distinct, which is why the gate reads the WEAKEST point rather than the mean.
        distinct = {k: f"an entirely unrelated {k} with nothing in common at all"
                    for k in validate.IDENTITY_KEYS}
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("alpha-it", FIXTURE_IDENTITY), ("beta-it", distinct))
            errors, warnings = validate.identity_collisions(root=root)
        self.assertEqual((errors, warnings), ([], []))

    def test_live_catalog_has_no_identity_collision(self):
        errors, _warnings = validate.identity_collisions()
        self.assertEqual(errors, [], "two missions in the catalog are one mission")

    PADDING = "carefully and rigorously, with thorough attention to quality and correctness throughout"

    def _live_identity(self, mission):
        text = (ROOT / "skills" / mission / "SKILL.md").read_text(encoding="utf-8")
        data, err = validate.parse_frontmatter(text)
        self.assertIsNone(err)
        return {k: data["metadata"][k] for k in validate.IDENTITY_KEYS}

    def test_a_padded_restatement_of_a_real_mission_is_refused(self):
        """Jaccard's union denominator let filler dilute a verbatim restatement: the same six
        points, each with a clause of padding, scored under the NEAR bar on every point."""
        real = self._live_identity("floor-it")
        padded = {k: f"{v}, {self.PADDING}" for k, v in real.items()}

        def jaccard(a, b):
            ta, tb = validate._identity_tokens(a), validate._identity_tokens(b)
            return len(ta & tb) / len(ta | tb)
        # The fixture IS the attack: plain Jaccard reads at least one point as divergent...
        self.assertTrue(any(jaccard(real[k], padded[k]) < 0.4 for k in real),
                        "padding no longer dilutes Jaccard — the fixture proves nothing")
        # ...and the padding stays inside the per-point length cap, so it is a legal declaration.
        self.assertEqual(validate.identity_point_length_errors(padded), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("floor-it", real), ("zz-padded-it", padded))
            errors, _warnings = validate.identity_collisions(root=root)
        self.assertTrue(any("floor-it and zz-padded-it" in e for e in errors),
                        f"a padded restatement passed the identity gate: {errors}")

    def test_negation_is_a_divergence_not_a_match(self):
        self.assertEqual(validate._point_similarity("issue closed", "issue not closed"), 0.0)
        self.assertEqual(validate._point_similarity("merge allowed", "merge never allowed"), 0.0)
        self.assertEqual(validate._point_similarity("tests pass", "tests don't pass"), 0.0)
        # "no" is a quantity, not polarity: it must still MATCH "zero".
        self.assertEqual(validate._point_similarity("finds no open issues",
                                                    "finds zero open issues"), 1.0)

    def test_a_negated_qualifier_does_not_hide_a_duplicate(self):
        """Global polarity let one added negator zero a point: floor-it's own identity with
        "not unrelated work" on unit and "never order unrelated dimensions" on ordering passed
        as a different mission (PR #571 review). A negated clause about NEW words is padding."""
        real = self._live_identity("floor-it")
        qualified = dict(real, unit=f"{real['unit']}, not unrelated work",
                         ordering=f"{real['ordering']}, never order unrelated dimensions")
        self.assertEqual(validate.identity_point_length_errors(qualified), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("floor-it", real), ("zz-qualified-it", qualified))
            errors, _warnings = validate.identity_collisions(root=root)
        self.assertTrue(any("floor-it and zz-qualified-it" in e for e in errors),
                        f"a negation-qualified restatement passed the identity gate: {errors}")

    def test_negated_points_are_not_a_false_positive_collision(self):
        base = dict(FIXTURE_IDENTITY, convergence="every issue closed at the reviewed commit",
                    parking="merge allowed once a human decision is recorded")
        negated = dict(base, convergence="every issue not closed at the reviewed commit",
                       parking="merge never allowed once a human decision is recorded")
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, ("alpha-it", base), ("beta-it", negated))
            errors, warnings = validate.identity_collisions(root=root)
        # Differs on two points — ARCHITECTURE.md's silent case, not a duplicate.
        self.assertEqual((errors, warnings), ([], []))

    def test_an_overlong_identity_point_fails(self):
        words = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima "
                 "mike november oscar papa quebec romeo sierra tango uniform victor").split()
        long_point = " ".join(words[:validate.IDENTITY_POINT_MAX_TOKENS + 1])
        with tempfile.TemporaryDirectory() as tmp:
            errs = validate.validate_skill(
                make_skill(tmp, "Composes `diagnose`.\n",
                           identity=dict(FIXTURE_IDENTITY, oracle=long_point)), PROTOCOLS)
        self.assertTrue(any("metadata.oracle" in e and "content words" in e for e in errs), errs)

    def test_every_live_identity_point_fits_the_cap(self):
        for skill in sorted((ROOT / "skills").glob("*/SKILL.md")):
            with self.subTest(mission=skill.parent.name):
                self.assertEqual(
                    validate.identity_point_length_errors(self._live_identity(skill.parent.name)),
                    [])

    def test_a_tokenizer_failure_fails_loudly(self):
        # It used to fall back to unstemmed words, silently loosening the gate.
        with mock.patch.object(validate._eval_validator, "tokenize",
                               side_effect=RuntimeError("tokenizer broke")):
            with self.assertRaises(RuntimeError):
                validate._identity_tokens("one open issue")


class ActivationLoad(unittest.TestCase):
    """Issue #276: the transitive load a mission makes mandatory, bounded."""

    def test_the_clause_counts_and_a_deferred_read_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            composed = make_skill(tmp, "Composes `diagnose`.\n")
            with_clause, _ = validate.transitive_load(composed, PROTOCOLS)
        with tempfile.TemporaryDirectory() as tmp:
            deferred = make_skill(
                tmp,
                "Composes `triage-state`.\n\nDEFERRED READS: diagnose.md when diagnosing.\n",
            )
            without, _ = validate.transitive_load(deferred, {"diagnose", "triage-state"})
        self.assertGreater(with_clause, 0)
        # `diagnose` moved out of the clause, so it is no longer activation load.
        self.assertNotIn("playbooks/diagnose.md", validate.transitive_load(deferred, PROTOCOLS)[1])
        self.assertGreater(with_clause, 0)
        self.assertGreater(without, 0)

    def test_a_mission_over_the_cap_fails(self):
        original = validate.MISSION_MAX_LOAD_TOKENS
        validate.MISSION_MAX_LOAD_TOKENS = 1
        try:
            with tempfile.TemporaryDirectory() as tmp:
                errs = validate.validate_skill(
                    make_skill(tmp, "Composes `diagnose`.\n"), PROTOCOLS
                )
                self.assertTrue(any("activation load" in e for e in errs), errs)
        finally:
            validate.MISSION_MAX_LOAD_TOKENS = original

    def test_live_catalog_is_under_the_cap_and_the_cap_is_a_ratchet(self):
        rows = validate.load_report()
        self.assertTrue(rows, "no missions measured")
        worst = max(tokens for _name, tokens in rows)
        self.assertLessEqual(worst, validate.MISSION_MAX_LOAD_TOKENS)
        # Ratchet: a cap far above the live maximum has stopped bounding anything.
        self.assertGreater(
            worst, validate.MISSION_MAX_LOAD_TOKENS - 2000,
            f"the heaviest mission is {worst} tokens against a "
            f"{validate.MISSION_MAX_LOAD_TOKENS} cap — lower the cap to track it",
        )


class PerMissionLoadBudgets(unittest.TestCase):
    """2026-10-23 review, section 5: one catalog-wide cap bounded only the heaviest mission. Each
    mission now has a budget in scripts/mission-load-budgets.json, and check_load_budgets()
    refuses growth past it, slack above it, a mission without one and a budget without a mission."""

    def _catalog(self, tmp, budgets, step=500, slack=1000):
        root = Path(tmp)
        skills = root / "skills"
        skills.mkdir()
        make_skill(skills, "Composes `diagnose`.\n", name="alpha")
        make_skill(skills, "Composes `diagnose`.\n", name="beta")
        (root / "scripts").mkdir()
        (root / "scripts" / "mission-load-budgets.json").write_text(
            json.dumps({"step": step, "max_slack": slack, "budgets": budgets}), encoding="utf-8")
        return root

    def _loads(self, root):
        return dict(validate.load_report(root))

    def test_the_live_catalog_fits_its_budgets(self):
        self.assertEqual(validate.check_load_budgets(), [])

    def test_a_budget_that_fits_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            fitted = {name: load + 10 for name, load in loads.items()}
            self._catalog_rewrite(root, fitted)
            self.assertEqual(validate.check_load_budgets(root), [])

    def _catalog_rewrite(self, root, budgets, step=500, slack=1000):
        (root / "scripts" / "mission-load-budgets.json").write_text(
            json.dumps({"step": step, "max_slack": slack, "budgets": budgets}), encoding="utf-8")

    def test_growth_past_a_budget_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            self._catalog_rewrite(root, {"alpha": loads["alpha"] - 1, "beta": loads["beta"]})
            failures = validate.check_load_budgets(root)
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("alpha: activation load", failures[0])

    def test_slack_above_the_limit_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            self._catalog_rewrite(root, {"alpha": loads["alpha"] + 1001, "beta": loads["beta"]})
            failures = validate.check_load_budgets(root)
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("alpha: budget", failures[0])
            self.assertIn("lower it", failures[0])

    def test_a_mission_without_a_budget_and_a_budget_without_a_mission_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            self._catalog_rewrite(root, {"alpha": loads["alpha"], "gamma": 100})
            failures = validate.check_load_budgets(root)
            self.assertTrue(any(f.startswith("beta: no integer budget") for f in failures), failures)
            self.assertTrue(any(f.startswith("gamma: a budget for a mission") for f in failures),
                            failures)

    def test_a_budget_above_the_catalog_cap_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            over = validate.MISSION_MAX_LOAD_TOKENS + 1
            self._catalog_rewrite(root, {"alpha": over, "beta": loads["beta"]}, slack=over)
            failures = validate.check_load_budgets(root)
            self.assertTrue(any("above the" in f for f in failures), failures)

    def test_a_missing_or_malformed_budget_file_fails_closed(self):
        for text in (None, "{ not json", '{"budgets": []}', '{"step": 0, "max_slack": 1, "budgets": {}}'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                root = self._catalog(tmp, {})
                path = root / "scripts" / "mission-load-budgets.json"
                if text is None:
                    path.unlink()
                else:
                    path.write_text(text, encoding="utf-8")
                failures = validate.check_load_budgets(root)
                self.assertEqual(len(failures), 1, failures)
                self.assertIn("unreadable", failures[0])

    # Declared headroom (2026-10-26): with none, ship-it sat 7 tokens under its budget and one
    # sentence in any doc it loads failed an unrelated PR.
    def _with_headroom(self, root, budgets, headroom, step=100, slack=100):
        (root / "scripts" / "mission-load-budgets.json").write_text(json.dumps(
            {"step": step, "headroom": headroom, "max_slack": slack, "budgets": budgets}), encoding="utf-8")

    def test_declared_headroom_is_room_to_grow_not_slack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            line = {name: math.ceil(load * 1.05) for name, load in loads.items()}
            self._with_headroom(root, {name: line[name] + 100 for name in loads}, 0.05)
            self.assertEqual(validate.check_load_budgets(root), [])
            self._with_headroom(root, {"alpha": line["alpha"] + 101, "beta": line["beta"]}, 0.05)
            failures = validate.check_load_budgets(root)
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("plus its 5.0% headroom", failures[0])
            self.assertIn("lower it", failures[0])

    def test_headroom_never_admits_growth_past_a_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            self._with_headroom(root, {"alpha": loads["alpha"] - 1, "beta": loads["beta"]}, 0.05)
            failures = validate.check_load_budgets(root)
            self.assertEqual(len(failures), 1, failures)
            self.assertIn("alpha: activation load", failures[0])

    def test_the_suggested_budget_carries_the_headroom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            self._with_headroom(root, {"beta": math.ceil(loads["beta"] * 1.05)}, 0.05)
            want = -(-math.ceil(loads["alpha"] * 1.05) // 100) * 100
            self.assertEqual(validate.check_load_budgets(root),
                             [f"alpha: no integer budget (measured ~{loads['alpha']} tokens; add {want})"])

    def test_a_malformed_headroom_fails_closed(self):
        for headroom in (-0.01, 0.1, 2.5, "2.5%", True, None):
            with self.subTest(headroom=headroom), tempfile.TemporaryDirectory() as tmp:
                root = self._catalog(tmp, {})
                self._with_headroom(root, dict(self._loads(root)), headroom)
                failures = validate.check_load_budgets(root)
                self.assertEqual(len(failures), 1, failures)
                self.assertIn("unreadable", failures[0])

    def test_growing_into_the_headroom_stays_green(self):
        # The headroom is spent by growth, so nothing may demand it again above the grown load
        # (PR #705 review, P1: a check against today's load re-imposed it on every run).
        with tempfile.TemporaryDirectory() as tmp:
            root = self._catalog(tmp, {})
            loads = self._loads(root)
            self._with_headroom(root, {name: load + 1 for name, load in loads.items()}, 0.05)
            self.assertEqual(validate.check_load_budgets(root), [])

    def test_the_cap_holds_every_committed_budget(self):
        # Against the committed budgets, never against headroom above today's load (see above).
        data = json.loads((ROOT / "scripts" / "mission-load-budgets.json").read_text(encoding="utf-8"))
        self.assertGreater(data["headroom"], 0, "the live budgets declare no headroom")
        self.assertLessEqual(max(data["budgets"].values()), validate.MISSION_MAX_LOAD_TOKENS,
                             "a committed budget sits above the catalog cap")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class PinVersionClaims(unittest.TestCase):
    """#512: the Orca floor was typed by hand in three places and lagged runtime/pins.json by
    fifteen releases. A version named beside the pin must be the pin; a version named for
    another reason (a support-window range, an observed build) stays free."""

    def _tree(self, tmp, readme, pin="v1.4.215"):
        root = Path(tmp)
        (root / "runtime").mkdir()
        (root / "runtime" / "pins.json").write_text(json.dumps({"orca": {"version": pin}}))
        (root / "README.md").write_text(readme)
        return root

    def test_the_real_tree_names_no_stale_pin(self):
        self.assertEqual(validate.check_pin_version_claims(), [])

    def test_a_floor_that_lags_the_pin_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "at or above the catalog pin, currently **v1.4.200**\n")
            with mock.patch.object(validate, "ROOT", root):
                failures = validate.check_pin_version_claims()
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("README.md:1", failures[0])
        self.assertIn("v1.4.200", failures[0])
        self.assertIn("v1.4.215", failures[0])

    def test_the_floor_operator_alone_is_context_enough(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "to run missions add Orca ≥ v1.4.100, gh, Claude Code\n")
            with mock.patch.object(validate, "ROOT", root):
                self.assertEqual(len(validate.check_pin_version_claims()), 1)

    def test_a_version_named_for_another_reason_is_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "Tested against v1.4.209 through v1.4.215; upstream ships daily.\n"
                                   "the on-PATH app then ran 1.4.204 while the witness binary was newer\n")
            with mock.patch.object(validate, "ROOT", root):
                self.assertEqual(validate.check_pin_version_claims(), [])

    def test_the_pin_itself_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "at or above the catalog pin, currently **v1.4.215**\n")
            with mock.patch.object(validate, "ROOT", root):
                self.assertEqual(validate.check_pin_version_claims(), [])

    def test_an_unreadable_pin_is_a_failure_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._tree(tmp, "≥ v1.4.215\n")
            (root / "runtime" / "pins.json").write_text("{}")
            with mock.patch.object(validate, "ROOT", root):
                failures = validate.check_pin_version_claims()
        self.assertEqual(len(failures), 1)
        self.assertIn("pins.json", failures[0])
