#!/usr/bin/env python3
"""Contract tests for VF-Bench v0 (#79).

VF-Bench measures verifier SOUNDNESS (false-done rate), not agent capability. The property under
test: open-fleet's sound verifier is fooled by NO trap (0% false-done), a self-scoring gate is
fooled by at least one (else there is no contrast), and the sound gate still passes a valid control
(it is not trivially always-RED).
"""
import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("vfbench", ROOT / "bench" / "vf-bench" / "vfbench.py")
vfbench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vfbench)


class VFBenchCorpus(unittest.TestCase):
    def test_corpus_nonempty_and_well_formed(self):
        traps = vfbench.load_traps()
        self.assertGreaterEqual(len(traps), 4)
        for t in traps:
            for k in ("id", "class", "sound_expected", "manifest"):
                self.assertIn(k, t, t)
            self.assertIn(t["sound_expected"], ("RED", "GREEN"))


class VFBenchSoundness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # #163: the wrong-sha trap's RED verdict rests on verify.py's git commit-existence leg,
        # which degrades to a NOTE outside a git work tree — there the trap flips GREEN and the
        # soundness score silently measures nothing. Skip loudly instead of grading ambient state.
        r = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, cwd=vfbench.ROOT)
        if r.returncode != 0:
            raise unittest.SkipTest("vf-bench traps rely on the ambient git clone — verify.py's "
                                    "commit-existence leg is NOTE-skipped outside one")
        cls.res = vfbench.run()

    def test_sound_gate_scores_zero_false_done(self):
        sound = self.res["open-fleet verify.py (sound)"]
        self.assertEqual(sound["false_done"], 0, "the sound verifier must not be fooled by any trap")

    def test_naive_self_scorer_is_fooled(self):
        naive = self.res["self-scoring (naive)"]
        self.assertGreater(naive["false_done"], 0, "a self-scoring gate must be fooled (else no contrast)")

    def test_sound_gate_passes_the_valid_control(self):
        rows = {r["id"]: r for r in self.res["open-fleet verify.py (sound)"]["rows"]}
        self.assertEqual(rows["valid-control-1"]["verdict"], "GREEN", "sound gate must not be always-RED")

    def test_sound_gate_passes_the_mutation_valid_control(self):
        # #257: the report-only control only exercises the scope leg. THIS one drives every
        # mutation authority at once — an executed revert, an independent APPROVED review, a
        # pinned artifact inventory, a fresh commands ledger — so "not always-RED" is proven for
        # the class docs/reviews/2026-09-10-review.md's bypass log broke.
        rows = {r["id"]: r for r in self.res["open-fleet verify.py (sound)"]["rows"]}
        self.assertIn("mutation-valid-control-1", rows,
                      "the mutation-class positive control was skipped or dropped")
        self.assertEqual(rows["mutation-valid-control-1"]["verdict"], "GREEN",
                         "a real mutation unit with an EXECUTED negative control must pass")

    def test_waiver_lane_traps_are_red(self):
        # #256: dark-eligible and no-gh both waive the review; with a merely-READ control they
        # must be RED. These are docs/reviews/2026-09-10-review.md A1/A2/A4/A6/A9 in the corpus.
        rows = {r["id"]: r for r in self.res["open-fleet verify.py (sound)"]["rows"]}
        for trap_id in ("fabricated-nc-dark-eligible-1", "fabricated-nc-no-gh-1"):
            self.assertEqual(rows[trap_id]["verdict"], "RED", trap_id)

    def test_readme_result_table_matches_computed(self):
        # #125: the hand-typed result table must match the computed corpus (was a stale 4/4·0/4).
        if self.res["open-fleet verify.py (sound)"]["skipped"]:
            self.skipTest("traps were skipped on this checkout — the corpus totals the README "
                          "pins are the FULL-clone ones (see test_shallow_skips_are_named)")
        readme = (ROOT / "bench" / "vf-bench" / "README.md").read_text(encoding="utf-8")
        naive, sound = self.res["self-scoring (naive)"], self.res["open-fleet verify.py (sound)"]
        self.assertRegex(readme, rf"self-scoring \(naive\)\s*\|\s*{naive['false_done']}/{naive['red_total']}\b")
        self.assertRegex(readme, rf"verify\.py.*\|\s*{sound['false_done']}/{sound['red_total']}\b")

    def test_readme_publishes_the_false_reject_rate_too(self):
        # #600: false acceptance and false rejection are published side by side — a gate that
        # refuses everything scores 0% false-done, so the first number alone flatters it. The
        # denominator is the corpus's own control count: a skip can drop a control from a run,
        # never add a rejection, so this pin holds on a shallow checkout too.
        readme = (ROOT / "bench" / "vf-bench" / "README.md").read_text(encoding="utf-8")
        controls = sum(1 for t in vfbench.load_traps() if t["sound_expected"] == "GREEN")
        for label, res in (("self-scoring \\(naive\\)", self.res["self-scoring (naive)"]),
                           ("verify\\.py` \\(sound\\)", self.res["open-fleet verify.py (sound)"])):
            with self.subTest(gate=label):
                self.assertRegex(readme, rf"{label}\s*\|[^|]*\|[^|]*\|\s*{res['false_reject']}/"
                                         rf"{controls}\s*\|")

    def test_false_rejection_is_scored_beside_false_acceptance(self):
        # #600: a valid control going RED is a scored FALSE REJECTION, counted per gate.
        for name, res in self.res.items():
            with self.subTest(gate=name):
                self.assertEqual(res["false_reject"], len(res["valid_failed"]))
                self.assertEqual(res["false_reject_rate"],
                                 res["false_reject"] / res["valid_total"] if res["valid_total"] else 0.0)
        self.assertEqual(self.res["open-fleet verify.py (sound)"]["false_reject"], 0,
                         self.res["open-fleet verify.py (sound)"]["false_rejects"])

    def test_every_reasoned_trap_is_refused_for_the_invariant_it_plants(self):
        # #600: a RED from an unrelated leg is not a catch; the bench names it instead of scoring it.
        self.assertEqual(self.res["open-fleet verify.py (sound)"]["wrong_reason"], [])

    def test_every_corpus_case_is_scored_or_skipped_by_name(self):
        # #600: no silent denominator omission — the scored and named-skipped cases ARE the corpus.
        sound = self.res["open-fleet verify.py (sound)"]
        self.assertEqual(sound["red_total"] + sound["valid_total"] + len(sound["skipped"]),
                         len(vfbench.load_traps()))
        self.assertEqual(sound["corpus_total"], len(vfbench.load_traps()))


class VFBenchShallowSkips(unittest.TestCase):
    """#257 / docs/reviews/2026-09-10-review.md P2 item 22: a trap that pins a real commit cannot be scored on a shallow
    clone. It must be SKIPPED BY NAME — in the corpus report and in --json — never silently
    scored, because a degraded leg reads as a RED the gate did not earn."""

    def test_skip_reason_names_the_missing_commit(self):
        trap = {"id": "x", "class": "y", "requires_commits": ["0" * 40]}
        reason = vfbench.skip_reason(trap)
        self.assertIsNotNone(reason)
        self.assertIn("shallow clone", reason)
        self.assertIn("0" * 12, reason)

    def test_no_skip_when_the_commit_is_present(self):
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              cwd=vfbench.ROOT)
        if head.returncode != 0:
            raise unittest.SkipTest("no ambient git clone")
        self.assertIsNone(vfbench.skip_reason({"requires_commits": [head.stdout.strip()]}))

    def test_review_leg_trap_declares_its_pinned_commits(self):
        trap = next(t for t in vfbench.load_traps() if t["class"] == "review-fetch-fail-closed")
        self.assertEqual(sorted(trap["requires_commits"]),
                         sorted([trap["manifest"]["base_sha"], trap["manifest"]["head_sha"]]))

    def test_report_names_skipped_traps(self):
        rows = {"id": "pinned-trap-1", "class": "review-fetch-fail-closed",
                "reason": "shallow clone: pinned commit deadbeefdead is not in this checkout"}
        res = {"g": {"false_done": 0, "red_total": 1, "rate": 0.0, "rows": [], "skipped": [rows]}}
        buf = io.StringIO()
        orig = vfbench.run
        vfbench.run = lambda: res
        try:
            with contextlib.redirect_stdout(buf):
                vfbench.main([])
        finally:
            vfbench.run = orig
        out = buf.getvalue()
        self.assertIn("NOT SCORED", out)
        self.assertIn("pinned-trap-1", out)
        self.assertIn("fetch-depth: 0", out)


class VFBenchForwarding(unittest.TestCase):
    """#140 review: base/repo (and unit_class) are best-effort at the verdict level, so a regression
    that drops or swaps their forwarding into verify.py would pass unnoticed by verdicts alone.
    Assert the argv the sound gate builds carries every dispatch input, correctly paired."""

    def test_sound_gate_forwards_dispatch_inputs(self):
        captured = {}

        class _R:
            returncode = 0

        def fake_run(cmd, *a, **k):
            captured["cmd"] = cmd
            return _R()

        orig = vfbench.subprocess.run
        vfbench.subprocess.run = fake_run
        try:
            vfbench.sound_gate({
                "manifest": {"head_sha": "H"},
                "contract_source": "c@ref", "contract_digest": "sha256:x",
                "unit_class": "mutation", "base": "main", "repo": "o/r",
            })
        finally:
            vfbench.subprocess.run = orig
        cmd = captured["cmd"]
        for flag, val in (("--unit-class", "mutation"), ("--base", "main"), ("--repo", "o/r"),
                          ("--contract-source", "c@ref"), ("--contract-digest", "sha256:x")):
            self.assertIn(flag, cmd)
            self.assertEqual(cmd[cmd.index(flag) + 1], val, f"{flag} value not forwarded")


class VFBenchRobustness(unittest.TestCase):
    """#100 review: the harness must not leak temp manifests, and a broken verifier (exit 1) must not
    be scored as a caught trap."""

    def test_sound_gate_removes_temp_manifest(self):
        captured = {}

        class _R:
            returncode = 2
            stderr = ""

        def fake_run(cmd, *a, **k):
            captured["path"] = cmd[cmd.index("--manifest") + 1]
            return _R()

        orig = vfbench.subprocess.run
        vfbench.subprocess.run = fake_run
        try:
            vfbench.sound_gate({"manifest": {"head_sha": "H"}})
        finally:
            vfbench.subprocess.run = orig
        self.assertFalse(Path(captured["path"]).exists(), "sound_gate leaked its temp manifest")

    def test_sound_gate_raises_on_broken_verifier(self):
        class _R:
            returncode = 1  # usage/dependency error — not a 0/2 verdict
            stderr = "dependency: git not on PATH"

        orig = vfbench.subprocess.run
        vfbench.subprocess.run = lambda *a, **k: _R()
        try:
            with self.assertRaises(RuntimeError):
                vfbench.sound_gate({"manifest": {"head_sha": "H"}})
        finally:
            vfbench.subprocess.run = orig


class VFBenchAncestryLeg(unittest.TestCase):
    """#172: vf-bench scores exit codes only, so a RED verdict on the non-ancestor-sha trap would
    not by itself prove the ancestry leg fired. Pin the right reason: when the sound gate runs
    that trap, the verifier's fatals must include the ancestry error (a phantom head_sha also
    trips the real-commit leg — see the trap note — so both messages are asserted).

    Hermetic: check_ancestry reads origin/<base> from cwd, so this test builds a temp repo with
    refs/remotes/origin/main instead of skipping when the ambient clone is a shallow CI checkout
    (#201 review). #267 refuses evidence paths outside the toplevel, so the trap's contract fixture
    is COPIED into that temp repo and named relatively — the coordinator's contract has to live in
    the tree the verifier is auditing."""

    def test_non_ancestor_trap_is_red_via_the_ancestry_leg(self):
        trap = next(t for t in vfbench.load_traps() if t["class"] == "non-ancestor-sha")
        tmp = Path(tempfile.mkdtemp())
        try:
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp,
                           check=True, capture_output=True)
            (tmp / "README").write_text("x\n", encoding="utf-8")
            contract_rel = "contract.md"
            (tmp / contract_rel).write_bytes(
                (vfbench.ROOT / trap["contract_source"]).read_bytes())
            subprocess.run(["git", "add", "-A"], cwd=tmp, check=True, capture_output=True)
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                            "commit", "-qm", "init"], cwd=tmp, check=True, capture_output=True)
            subprocess.run(["git", "update-ref", "refs/remotes/origin/main", "HEAD"],
                           cwd=tmp, check=True, capture_output=True)
            path = tmp / "manifest.json"
            path.write_text(json.dumps(trap["manifest"]), encoding="utf-8")
            r = subprocess.run(
                [sys.executable, str(vfbench.VERIFY), "--manifest", str(path),
                 "--contract-source", contract_rel,
                 "--contract-digest", trap["contract_digest"],
                 "--unit-class", trap["unit_class"], "--base", trap["base"]],
                capture_output=True, text=True, cwd=tmp)
        finally:
            shutil.rmtree(tmp, True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("not an ancestor of origin/main", r.stderr)
        self.assertIn("is not a real commit", r.stderr)


class VFBenchReviewLeg(unittest.TestCase):
    """#174: vf-bench scores exit codes only, so a RED verdict on the review-fetch-fail-closed
    trap would not by itself prove check_review ran past the pr.number guard. Pin the right
    reason twice: (1) with the ambient environment the trap fails CLOSED at the review fetch
    (the trap's repo owner contains an underscore, which GitHub usernames forbid, so the lookup
    404s even authenticated; without gh the same leg reports 'gh not on PATH' — both wordings
    carry 'cannot fetch reviews'), and (2) with a stubbed gh serving review pages the verdict is
    decided by review_ok ALONE — COMMENTED-only stays RED, an independent APPROVED at head_sha
    flips GREEN — so a regression that accepts COMMENTED reviews turns this trap into a
    false-done. The ancestry leg is #172's non-ancestor-sha trap — referenced, not duplicated."""

    @classmethod
    def setUpClass(cls):
        cls.trap = next(t for t in vfbench.load_traps() if t["class"] == "review-fetch-fail-closed")

    def _run_verify(self, env=None):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(self.trap["manifest"], fh)
            path = fh.name
        try:
            return subprocess.run(
                [sys.executable, str(vfbench.VERIFY), "--manifest", path,
                 "--contract-source", self.trap["contract_source"],
                 "--contract-digest", self.trap["contract_digest"],
                 "--unit-class", self.trap["unit_class"], "--repo", self.trap["repo"],
                 "--allow-static-nc"],
                capture_output=True, text=True, cwd=vfbench.ROOT, env=env)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_review_trap_is_red_via_the_fail_closed_fetch(self):
        # Aggregation, not fail-fast: a missing trap SHA still runs check_review, so
        # this pin holds on a shallow clone. Skipping would hide a fetch-leg regression.
        r = self._run_verify()
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertNotIn("no pr.number", r.stderr)  # the leg ran PAST the pr.number guard
        self.assertIn("cannot fetch reviews", r.stderr)  # and failed CLOSED at the fetch

    def test_review_trap_verdict_tracks_review_ok(self):
        head = self.trap["manifest"]["head_sha"]
        # #257: the same named skip vfbench.py reports — a shallow checkout cannot score a trap
        # pinned to a real commit, and saying so beats measuring the checkout.
        reason = vfbench.skip_reason(self.trap)
        if reason:
            raise unittest.SkipTest(f"{reason} — the GREEN half cannot run here; "
                                    "CI must check out with fetch-depth: 0")

        def env_with_stub(reviews):
            stub = (
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "endpoint = sys.argv[-1]\n"
                "if endpoint.endswith('/reviews'):\n"
                f"    print(json.dumps({json.dumps(reviews)}))\n"
                "elif '/pulls/' in endpoint:\n"
                "    print(json.dumps({'user': {'login': 'vf-author'}}))\n"
                "else:\n"
                "    sys.exit(1)\n"
            )
            d = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, d, True)
            p = Path(d) / "gh"
            p.write_text(stub, encoding="utf-8")
            p.chmod(0o755)
            return {**os.environ, "PATH": f"{d}{os.pathsep}{os.environ['PATH']}"}

        commented = [{"user": {"login": "vf-reviewer"}, "state": "COMMENTED", "commit_id": head,
                      "author_association": "MEMBER"}]
        approved = [{"user": {"login": "vf-reviewer"}, "state": "APPROVED", "commit_id": head,
                     "author_association": "MEMBER"}]
        r = self._run_verify(env=env_with_stub(commented))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("no INDEPENDENT APPROVED review at head_sha", r.stderr)
        r = self._run_verify(env=env_with_stub(approved))
        self.assertEqual(r.returncode, 0, f"every non-review check must pass: {r.stderr}")


class TheRefusedControlClassesAreSampled(unittest.TestCase):
    """#306: "0% false-done" only means something if the suite samples what actually gets through.

    The bypass log landed nine of thirteen gaming manifests against this mechanism, so the number
    was measuring the traps that had been chosen, not the gate's strength. Four are the classes the
    review found, and building them found a real gap: the path bind ran only on the --execute-nc
    leg, so a NARRATED decoy path or oracle revert passed. The bench read 2/17 false-done until
    that was fixed.

    The fifth, `decoy-hand-diff`, came out of the review OF that fix — the same asymmetry one tool
    over, for `hand` controls. Hence five, not four; the class was named before it grew (PR #308
    review).
    """

    TRAPS = ROOT / "bench" / "vf-bench" / "traps"
    REQUIRED = {"decoy-path", "oracle-mutation", "stillborn-mutant", "grep-command",
                "decoy-hand-diff"}

    def _traps(self):
        return {t["class"]: t for t in
                (json.loads(p.read_text(encoding="utf-8")) for p in self.TRAPS.glob("*.json"))}

    def test_every_refused_class_has_a_trap(self):
        missing = sorted(self.REQUIRED - set(self._traps()))
        self.assertEqual(missing, [], "a control class the review found is no longer sampled")

    def test_each_is_expected_to_be_refused(self):
        for name, trap in self._traps().items():
            if name in self.REQUIRED:
                with self.subTest(trap=name):
                    self.assertEqual(trap["sound_expected"], "RED",
                                     "a gaming manifest the gate must refuse")
                    self.assertEqual(trap.get("unit_class"), "mutation")

    def test_the_decoy_and_oracle_traps_stay_in_the_narrated_lane(self):
        """Executed, both are no-ops that #255 refuses — which is the right verdict for the wrong
        reason, and would have passed before #280 existed. Narrated, the static path bind is the
        only thing between the manifest and a GREEN, which is what these traps are for."""
        for name in ("decoy-path", "oracle-mutation"):
            with self.subTest(trap=name):
                self.assertFalse(self._traps()[name].get("execute_nc"),
                                 "executed, this trap measures #255 rather than the path bind")

    # The refusal each trap must earn. A RED alone is not evidence the benchmark still measures
    # the advertised bypass: a trap refused as MALFORMED, or by an unrelated prerequisite, scores
    # the same 0/20 and says nothing (PR #308 review, P2). This is not hypothetical — the
    # stillborn trap shipped in a first draft refused for exactly that reason, its diff in a
    # `negative_control.diff` field the manifest reader rejects, never reaching the check it names.
    REFUSAL = {
        "decoy-path": "which base_sha..head_sha does not change",
        "oracle-mutation": "which is a TEST path",
        "stillborn-mutant": "STILLBORN MUTANT",
        "grep-command": "produced NO output at all",
        "decoy-hand-diff": "the hand mutant's diff names",
        "class-downgrade": "changed code",
        # #369: the four legacy skeletal traps rebuilt on the run-time fixture, each missing
        # exactly one leg — deleting the check it exists to measure now turns the trap GREEN,
        # and this map pins WHICH refusal must fire.
        "missing-negative-control": "negative_control.tool must be one of",
        "unreviewed-mutation": "no pr.number to look up an independent review",
        "fabricated-negative-control": "does not reference the pinned mutant",
        "unclassified-mutation": "negative_control.tool must be one of",
        # #371: the two legs the bench previously never sampled at all — the redaction refusal
        # (#14/#267) and the negative half of the content-bound commands ledger.
        "credential-in-evidence": "credential shape(s)",
        "stale-wtree": "STALE evidence",
        # #612 / #613 (2026-10-23 review, P1-1 / P1-2): runners that COUNT a load failure as a
        # failed test, and a hook in the graded repo's .git that supplies the RED.
        "stillborn-pytest-shape": "beside 1 counted failure(s)",
        "stillborn-jest-shape": "test suite failed to run",
        "stillborn-vitest-shape": "failed suites 1",
        "stillborn-mixed": "beside 2 counted failure(s)",
        "hook-staged-kill": "TAUTOLOGICAL",
    }

    def test_each_trap_is_refused_for_the_reason_it_exists_to_test(self):
        """Run the gate and read WHY, not just the verdict."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_vfbench_reasons", ROOT / "bench" / "vf-bench" / "vfbench.py")
        vb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vb)
        traps = self._traps()
        for name, want in self.REFUSAL.items():
            with self.subTest(trap=name):
                self.assertIn(name, traps, "the trap is gone")
                fails = self._refusals(vb, traps[name])
                self.assertTrue(fails, f"{name} was not refused at all")
                self.assertTrue(
                    any(want in f for f in fails),
                    f"{name} was refused, but not for its own reason.\n"
                    f"  wanted a line containing: {want!r}\n"
                    f"  got: " + "\n       ".join(f[:160] for f in fails))

    @staticmethod
    def _refusals(vb, trap):
        """The FAIL lines verify.py emits for one fixture-backed trap."""
        import os
        import subprocess
        import sys
        import tempfile
        holder = Path(tempfile.mkdtemp(prefix="vfbench-reason-"))
        try:
            repo = holder / "repo"
            facts = vb.FIXTURES[trap.get("fixture", "mutation-revert")](repo)
            (repo / "vf-manifest.json").write_text(
                json.dumps(vb._render(trap["manifest"], facts)), encoding="utf-8")
            cmd = [sys.executable, str(vb.VERIFY), "--manifest", str(repo / "vf-manifest.json"),
                   "--contract-source", "contract.md",
                   "--contract-digest", facts["contract_digest"]]
            unit_class = trap.get("unit_class", "mutation")
            if unit_class is not None:  # explicit null models the coordinator not classifying (#369)
                cmd += ["--unit-class", unit_class]
            if trap.get("lighting"):
                cmd += ["--lighting", trap["lighting"]]
            if trap.get("execute_nc"):
                cmd.append("--execute-nc")
                if trap.get("nc_command"):
                    cmd += ["--nc-command", vb._render(trap["nc_command"], facts)]
            elif not trap.get("dispatch") and unit_class not in ("report-only", "planning"):
                cmd.append("--allow-static-nc")
            if trap.get("repo"):
                cmd += ["--repo", trap["repo"]]
            env = dict(os.environ)
            if trap.get("gh_stub"):
                env["PATH"] = (vb._gh_stub(holder / "bin", facts["head_sha"])
                               + os.pathsep + env["PATH"])
            r = subprocess.run(cmd, capture_output=True, text=True, cwd=repo, env=env)
            return [ln.strip() for ln in (r.stdout + r.stderr).splitlines()
                    if ln.startswith("FAIL:")]
        finally:
            shutil.rmtree(holder, ignore_errors=True)

    def test_the_stillborn_trap_quotes_a_real_diff_in_its_artifact(self):
        # It first carried the diff in a `negative_control.diff` field, which got the manifest
        # refused as MALFORMED — a trap refused for the wrong reason measures nothing.
        trap = self._traps()["stillborn-mutant"]
        nc = trap["manifest"]["negative_control"]
        self.assertEqual(nc["tool"], "hand")
        self.assertNotIn("diff", nc, "the diff belongs in the artifact, where verify.py reads it")
        self.assertTrue(nc["artifact"].endswith("nc-stillborn.txt"))
        vf = (ROOT / "bench" / "vf-bench" / "vfbench.py").read_text(encoding="utf-8")
        self.assertIn("FIXTURE_NC_STILLBORN", vf, "the fixture no longer writes that artifact")
        self.assertIn("nc_stillborn_sha256", vf, "the artifact's digest is not exposed as a fact")


class CountingRunnersAndHooksAreSampled(unittest.TestCase):
    """#612 / #613 (2026-10-23 review, P1-1 / P1-2). The stillborn trap above runs `unittest`,
    whose summary says `errors=1` — the one runner the old reading handled. pytest counts an
    in-test import's SyntaxError as `1 failed`, Jest and Vitest count a suite that never loaded
    as a failed suite, and a run can fail an assertion AND a load in one go; a post-checkout hook
    in the graded repo could also stage the kill. Each trap is EXECUTED and sits beside a valid
    control on the same fixture and runner shape, whose genuine assertion kill must stay GREEN —
    so the traps cannot be cleared by refusing everything that runner prints."""

    PAIRS = {"stillborn-pytest-shape": "pytest-shape-valid-control-1",
             "stillborn-jest-shape": "jest-shape-valid-control-1",
             "stillborn-vitest-shape": "vitest-shape-valid-control-1",
             "stillborn-mixed": "mixed-shape-valid-control-1",
             "hook-staged-kill": "hook-valid-control-1"}

    def setUp(self):
        self.traps = [json.loads(p.read_text(encoding="utf-8"))
                      for p in (ROOT / "bench" / "vf-bench" / "traps").glob("*.json")]
        self.by_class = {t["class"]: t for t in self.traps}
        self.by_id = {t["id"]: t for t in self.traps}

    def test_each_trap_is_executed_and_expected_red(self):
        for name in self.PAIRS:
            with self.subTest(trap=name):
                trap = self.by_class[name]
                self.assertEqual(trap["sound_expected"], "RED")
                self.assertTrue(trap.get("execute_nc"), "narrated, the runner never prints a thing")
                self.assertIn(trap["fixture"], vfbench.SHAPES)

    def test_each_trap_has_a_green_neighbour_on_the_same_runner(self):
        for name, control_id in self.PAIRS.items():
            with self.subTest(trap=name):
                trap, control = self.by_class[name], self.by_id[control_id]
                self.assertEqual(control["sound_expected"], "GREEN")
                self.assertEqual(control["fixture"], trap["fixture"])
                self.assertTrue(control.get("execute_nc"))

    def test_the_vitest_shape_never_says_syntaxerror(self):
        # The point of that trap: only the runner's suite-level verdict marks the load failure.
        runner = vfbench.SHAPES["vitest-shaped"][0]
        self.assertIn("Failed Suites 1", runner)
        self.assertNotIn("SyntaxError:", runner.split("except SyntaxError")[1])


class RunScoresRejectionsAndReasons(unittest.TestCase):
    """#600: the bench scores false REJECTION beside false acceptance, and holds a gate that gives
    reasons to the refusal each trap declares. Fast by design: a stand-in gate over a two-case
    corpus, so these pin the scoring itself rather than the verifier."""

    CORPUS = [
        {"id": "planted-1", "class": "planted", "sound_expected": "RED",
         "expect_reason": "the planted invariant", "manifest": {}},
        {"id": "control-1", "class": "control-not-a-trap", "sound_expected": "GREEN", "manifest": {}},
    ]

    def _run(self, gate):
        saved = (vfbench.load_traps, vfbench.GATES)
        vfbench.load_traps = lambda: [dict(t) for t in self.CORPUS]
        vfbench.GATES = {"g": gate}
        try:
            return vfbench.run()["g"]
        finally:
            vfbench.load_traps, vfbench.GATES = saved

    def test_a_red_for_another_reason_is_named_not_counted_as_a_catch(self):
        def gate(trap, detail=None):
            detail["fails"] = ["FAIL: some unrelated leg"]
            return trap["sound_expected"] == "GREEN"
        res = self._run(gate)
        self.assertEqual(res["false_done"], 0)
        self.assertEqual([w["id"] for w in res["wrong_reason"]], ["planted-1"])
        self.assertEqual(res["wrong_reason"][0]["want"], "the planted invariant")

    def test_the_declared_refusal_clears_it(self):
        def gate(trap, detail=None):
            detail["fails"] = ["FAIL: refused for the planted invariant, as declared"]
            return trap["sound_expected"] == "GREEN"
        res = self._run(gate)
        self.assertEqual(res["wrong_reason"], [])
        self.assertEqual(res["false_reject"], 0)

    def test_a_red_valid_control_is_a_scored_false_rejection_with_its_refusal(self):
        def gate(trap, detail=None):
            detail["fails"] = ["FAIL: the planted invariant"]
            return False
        res = self._run(gate)
        self.assertEqual(res["false_reject"], 1)
        self.assertEqual(res["valid_failed"], ["control-1"])
        self.assertEqual(res["false_rejects"][0]["refusals"], ["FAIL: the planted invariant"])
        self.assertEqual(res["false_reject_rate"], 1.0)

    def test_a_gate_that_gives_no_reasons_is_scored_on_verdicts_alone(self):
        res = self._run(lambda trap, detail=None: False)
        self.assertEqual(res["wrong_reason"], [])
        self.assertEqual(res["false_done"], 0)

    def test_a_red_fixture_control_is_scored_not_raised(self):
        # Before #600 a fixture control going RED raised out of fixture_gate, so a run stopped at
        # the first broken control and published no false-rejection count at all.
        control = next(t for t in vfbench.load_traps() if t["id"] == "narrated-valid-control-1")
        broken = json.loads(json.dumps(control))
        broken["manifest"]["reviewer_mode"] = "self"
        detail = {}
        self.assertFalse(vfbench.fixture_gate(broken, detail))
        self.assertTrue(any("reviewer_mode must be one of" in f for f in detail["fails"]),
                        detail)


class IsolatedInvariantTrapsAreSampled(unittest.TestCase):
    """#600: the verifier invariants the 2026-10-23 review listed as unsampled each have an
    isolated trap with a neighbouring valid control. tests/test_vfbench_guards.py deletes each
    trap's guard; this class pins that the corpus carries them at all, shaped as required."""

    REQUIRED = {
        "dispatch-profile-tamper", "dispatch-class-substitution", "dispatch-replay",
        "hidden-criterion-table", "hidden-criterion-json", "lighting-illegal", "lighting-swap",
        "empty-intent", "reviewer-mode-illegal", "provenance-incomplete", "surviving-mutant",
        "zero-kill-artifact", "oracle-scope-revert", "oracle-scope-production",
        "oracle-scope-artifact-swap", "pr-number-path", "pr-number-bool", "pr-number-negative",
        "author-as-approver", "non-member-approver", "dismissed-approval",
        "nc-artifact-symlink-escape", "unpinned-artifact", "missing-artifact-path",
        "criterion-unaddressed", "criterion-ids-shrunk", "manifest-digest-swap",
        "stale-reviewed-sha",
    }

    def setUp(self):
        self.traps = vfbench.load_traps()
        self.by_class = {t["class"]: t for t in self.traps}
        self.by_id = {t["id"]: t for t in self.traps}

    def test_each_is_present_red_and_declares_its_refusal_and_neighbour(self):
        for name in sorted(self.REQUIRED):
            with self.subTest(trap=name):
                self.assertIn(name, self.by_class, "the trap is gone")
                trap = self.by_class[name]
                self.assertEqual(trap["sound_expected"], "RED")
                self.assertTrue(trap.get("expect_reason"))
                self.assertIn(trap.get("neighbour"), self.by_id)
                self.assertEqual(self.by_id[trap["neighbour"]]["sound_expected"], "GREEN")

    def test_the_signed_dispatch_cases_are_profile_signed(self):
        # The 2026-10-23 review's P2-2: every profile-signed record read as forged. The valid
        # neighbour is profile-signed, and the tamper trap edits the profile and nothing else.
        control = self.by_id["dispatch-valid-control-1"]
        self.assertIn("profile", control["dispatch"]["record"])
        tamper = self.by_class["dispatch-profile-tamper"]
        self.assertEqual(set(tamper["dispatch"]["tamper"]), {"profile"})
        self.assertEqual(tamper["dispatch"]["record"], control["dispatch"]["record"])

    def test_the_provenance_control_is_complete_not_true(self):
        # The presence-vs-truth exhibit: every audit field filled, with values nothing verifies.
        prov = self.by_id["provenance-present-valid-control-1"]["manifest"]["provenance"]
        self.assertTrue(all(isinstance(v, str) and v.strip() for v in prov.values()))
        self.assertEqual(prov["model"], "vf-model-0")


class TheInventoryHasNoSilentOmissions(unittest.TestCase):
    """#600: the README's verifier check inventory maps every check to a trap, a justified
    unsupported case, or a deferred item. A check missing from it, a trap row naming no corpus
    case, a corpus trap no row names, or a non-trap row with no reason is a silent omission."""

    STATUSES = ("trap", "unsupported", "deferred")
    # Guards that live outside a check_* function but refuse on their own.
    HELPERS = {"verify", "execute_negative_control", "review_ok", "_resolve", "_read_artifact",
               "_Authority.authority_leg", "_Authority.review_leg", "_Authority.key_source"}

    def _rows(self):
        readme = (ROOT / "bench" / "vf-bench" / "README.md").read_text(encoding="utf-8")
        section = readme.split("## Verifier check inventory", 1)[1].split("\n## ", 1)[0]
        return [[c.strip() for c in line.strip().strip("|").split("|")]
                for line in section.splitlines() if line.startswith("| `")]

    def test_every_row_is_well_formed(self):
        rows = self._rows()
        self.assertGreater(len(rows), 40)
        for row in rows:
            with self.subTest(row=row[:2]):
                self.assertEqual(len(row), 4, row)
                self.assertIn(row[2], self.STATUSES)

    def test_every_check_is_inventoried(self):
        verify_src = (ROOT / "runtime" / "scripts" / "verify.py").read_text(encoding="utf-8")
        checks = set(re.findall(r"^def (check_\w+)\(", verify_src, re.M)) | self.HELPERS
        named = {n for row in self._rows() for n in re.findall(r"`([\w.]+)`", row[0])}
        self.assertEqual(sorted(checks - named), [], "a verifier check has no inventory row")
        self.assertEqual(sorted(named - checks), [], "an inventory row names no verifier check")

    def test_trap_rows_name_corpus_cases_and_others_say_why(self):
        classes = {t["class"] for t in vfbench.load_traps()}
        for row in self._rows():
            with self.subTest(row=row[:2]):
                named = re.findall(r"`([^`]+)`", row[3])
                if row[2] == "trap":
                    self.assertTrue(named, "a trap row must name its corpus case(s)")
                    self.assertEqual(sorted(set(named) - classes), [])
                else:
                    self.assertGreaterEqual(len(row[3]), 40, "an out-of-scope row must say why")

    def test_every_corpus_trap_is_inventoried(self):
        inventoried = {n for row in self._rows() if row[2] == "trap"
                       for n in re.findall(r"`([^`]+)`", row[3])}
        red = {t["class"] for t in vfbench.load_traps() if t["sound_expected"] == "RED"}
        self.assertEqual(sorted(red - inventoried), [], "a corpus trap is missing from the inventory")


def _message(node, names):
    """The text of a message expression, an f-string's values read as `{}`; None if it is not one.
    A local name bound to a literal, a `.format` template and the left side of `"..." + suffix`
    resolve to their literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in node.values)
    if isinstance(node, ast.Name):
        return names.get(node.id)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        text = _message(node.func.value, names)
        return None if text is None else re.sub(r"\{[^{}]*\}", "{}", text)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _message(node.left, names)
    return None


def _messages(node, names):
    """Every message a returned or appended expression can carry: list items, a comprehension's
    element, both arms of a conditional, both sides of a list concatenation, and each operand of
    an `or` (`gerr.strip() or "fallback"`)."""
    if isinstance(node, ast.List):
        for item in node.elts:
            yield from _messages(item, names)
    elif isinstance(node, ast.BoolOp):
        for operand in node.values:
            yield from _messages(operand, names)
    elif isinstance(node, ast.ListComp):
        yield from _messages(node.elt, names)
    elif isinstance(node, ast.IfExp):
        yield from _messages(node.body, names)
        yield from _messages(node.orelse, names)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and _message(node, names) is None:
        yield from _messages(node.left, names)
        yield from _messages(node.right, names)
    else:
        text = _message(node, names)
        if text is not None:
            yield text


def refusal_sites(source, functions):
    """#600, PR #643 review: every message verify.py can refuse with, read from its SOURCE, per
    named function (`Class.method` for a method), nested helpers included. A site is a message a
    function returns in a list, returns as the error half of a `(value, error)` pair, appends /
    extends onto a list, or assigns as a list inside an exception handler. A message composed in
    a helper outside the inventory and forwarded whole is that helper's, not a site here. Lines
    starting `NOTE:` are advisories, not refusals, and come back apart.
    Returns ({function: {refusal}}, {function: {note}})."""
    defs = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef):
            defs[node.name] = node
        elif isinstance(node, ast.ClassDef):
            defs.update((f"{node.name}.{sub.name}", sub) for sub in node.body
                        if isinstance(sub, ast.FunctionDef))
    refusals, notes = {}, {}
    for name in functions:
        names = {n.targets[0].id: _message(n.value, {}) for n in ast.walk(defs[name])
                 if isinstance(n, ast.Assign) and len(n.targets) == 1
                 and isinstance(n.targets[0], ast.Name) and _message(n.value, {}) is not None}
        found = set()
        for n in ast.walk(defs[name]):
            if isinstance(n, ast.Return) and n.value is not None:
                found.update(_messages(n.value.elts[-1] if isinstance(n.value, ast.Tuple)
                                       else n.value, names))
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr in ("append", "extend") and isinstance(n.func.value, ast.Name)):
                for arg in n.args:
                    found.update(_messages(arg, names))
            elif isinstance(n, ast.ExceptHandler):  # an exception turned into a refusal list
                for stmt in n.body:
                    if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.List):
                        found.update(_messages(stmt.value, names))
        refusals[name] = {m for m in found if not m.startswith("NOTE:")}
        notes[name] = found - refusals[name]
    return refusals, notes


class EveryRefusalSiteHasAnInventoryRow(unittest.TestCase):
    """#600, PR #643 review: comparing FUNCTION names let a guard's row vanish unnoticed — delete
    check_scope's digest-mismatch row and check_scope is still named by its other rows. The unit
    is the refusal SITE (refusal_sites, read from verify.py's source): each inventory row cites,
    after `Sites:`, the sites it owns by a stem of their message. A site no row cites, a stem that
    names no site or several, and a row whose deletion nothing would notice all fail here."""

    # verify()'s unknown-class handling is an advisory, not a refusal (its fail-safe is the row
    # above it); the NOTE it prints is that row's anchor, pinned so the row cannot vanish either.
    ANCHORING_NOTES = {"verify": ("unknown unit class",)}

    def setUp(self):
        source = (ROOT / "runtime" / "scripts" / "verify.py").read_text(encoding="utf-8")
        checks = set(re.findall(r"^def (check_\w+)\(", source, re.M))
        self.refusals, notes = refusal_sites(source, checks | TheInventoryHasNoSilentOmissions.HELPERS)
        self.anchors = {(f, n) for f, stems in self.ANCHORING_NOTES.items() for stem in stems
                        for n in notes[f] if stem in n}
        self.sites = {(f, s) for f, found in self.refusals.items() for s in found} | self.anchors
        self.rows = TheInventoryHasNoSilentOmissions._rows(self)

    @staticmethod
    def _stems(row):
        return re.findall(r"`([^`]+)`", row[1].partition("Sites:")[2])

    def _resolve(self, row, stem):
        """The sites a row's stem names: in the functions the row names, an exact message before a
        substring match; a predicate that prints nothing itself (review_ok) cites the refusal its
        caller prints, so its stems are looked up everywhere."""
        funcs = set(re.findall(r"`([\w.]+)`", row[0]))
        pool = {site for site in self.sites if site[0] in funcs} or self.sites
        return {site for site in pool if site[1] == stem} or {site for site in pool if stem in site[1]}

    def _cited(self, rows):
        return {site for row in rows for stem in self._stems(row) for site in self._resolve(row, stem)}

    @staticmethod
    def _cases(rows):
        return {n for row in rows if row[2] == "trap" for n in re.findall(r"`([^`]+)`", row[3])}

    def test_the_sites_are_read_from_source(self):
        # A broken extractor would make every check below pass on an empty set.
        self.assertGreater(len(self.sites), 100)
        self.assertIn(("check_scope", "scope: authoritative source does not match --contract-digest "
                                      "({} != {})"), self.sites)
        self.assertEqual(sorted(f for f, found in self.refusals.items() if not found), ["review_ok"],
                         "only review_ok, a predicate, may refuse without a message of its own")
        self.assertEqual(len(self.anchors), sum(map(len, self.ANCHORING_NOTES.values())),
                         "an anchoring NOTE no longer names exactly one NOTE in verify.py")

    def test_every_stem_names_exactly_one_site(self):
        for row in self.rows:
            for stem in self._stems(row):
                with self.subTest(row=row[:2], stem=stem):
                    self.assertEqual(len(self._resolve(row, stem)), 1,
                                     "a stem must name exactly one refusal site of its row's check")

    def test_every_refusal_site_has_a_row(self):
        uncited = sorted(f"{f}: {s}" for f, s in self.sites - self._cited(self.rows))
        self.assertEqual(uncited, [], "a refusal site in verify.py has no inventory row")

    def test_no_row_can_be_deleted_unnoticed(self):
        # What a row alone contributes: a site or a corpus case no other row covers. Deleting a
        # row with neither would leave every other test here, and the corpus check, green.
        red = {t["class"] for t in vfbench.load_traps() if t["sound_expected"] == "RED"}
        cited, cases = self._cited(self.rows) & self.sites, self._cases(self.rows) & red
        for i, row in enumerate(self.rows):
            with self.subTest(row=row[:2]):
                rest = self.rows[:i] + self.rows[i + 1:]
                lost = (cited - self._cited(rest)) | (cases - self._cases(rest))
                self.assertTrue(lost, "deleting this row fails no test: cite a site no other row "
                                "cites, or name a corpus case no other row names")


if __name__ == "__main__":
    unittest.main(verbosity=2)
