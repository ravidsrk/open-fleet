"""Tests for scripts/verdict_check.py (#452): GO-at-tip verdict rule."""

import contextlib
import importlib.util
import io
import json
import os
import re
import runpy
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "verdict_check", _ROOT / "scripts" / "verdict_check.py")
verdict_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verdict_check)
go_reviews_at_tip = verdict_check.go_reviews_at_tip
verdict_at_tip = verdict_check.verdict_at_tip

HEAD = "a" * 40
OTHER = "b" * 40


def review(body, state="APPROVED", login="reviewer", association="MEMBER"):
    return {"state": state, "body": body, "submitted_at": "2026-09-16T00:00:00Z",
            "user": {"login": login}, "author_association": association}


def go_body(sha):
    return f"Looks good.\n\nVERDICT: GO\nreviewed_sha: {sha}\n"


class VerdictAtTip(unittest.TestCase):
    def test_fresh_go_at_tip_passes(self):
        self.assertTrue(verdict_at_tip([review(go_body(HEAD))], HEAD))

    def test_stale_go_fails(self):
        self.assertFalse(verdict_at_tip([review(go_body(OTHER))], HEAD))

    def test_no_go_fails(self):
        self.assertFalse(verdict_at_tip([review("lgtm"), review("", "COMMENTED")], HEAD))
        self.assertFalse(verdict_at_tip([], HEAD))

    def test_dismissed_go_does_not_count(self):
        self.assertFalse(verdict_at_tip([review(go_body(HEAD), state="DISMISSED")], HEAD))

    def test_short_sha_never_matches(self):
        self.assertFalse(verdict_at_tip([review(go_body(HEAD[:7]))], HEAD))
        self.assertFalse(verdict_at_tip([review(go_body(HEAD[:39] + "zz"))], HEAD))

    def test_sha_comparison_is_case_insensitive(self):
        self.assertTrue(verdict_at_tip([review(go_body(HEAD.upper()))], HEAD))

    def test_verdict_marker_is_exact_uppercase(self):
        # PR #465 review, P1: the CI job gate matches the literal `VERDICT: GO`,
        # so the parser must too — a case-insensitive parser would accept verdicts
        # CI never evaluates.
        self.assertFalse(verdict_at_tip([review(go_body(HEAD).replace("VERDICT", "verdict"))], HEAD))
        self.assertFalse(verdict_at_tip([review(go_body(HEAD).replace("GO", "go"))], HEAD))
        self.assertFalse(verdict_at_tip([review("VERDICT: GOAHEAD\nreviewed_sha: " + HEAD)], HEAD))
        self.assertFalse(verdict_at_tip([review("VERDICT: NO-GO\nreviewed_sha: " + HEAD)], HEAD))

    def test_approved_go_always_counts(self):
        self.assertTrue(verdict_at_tip([review(go_body(HEAD), state="APPROVED")], HEAD))
        self.assertFalse(verdict_at_tip(
            [review(go_body(HEAD), state="CHANGES_REQUESTED")], HEAD))
        self.assertFalse(verdict_at_tip(
            [review(go_body(HEAD), state="PENDING")], HEAD))

    def test_commented_go_counts_from_pr_author(self):
        # The coordinator binding its own verdict — the normal fleet flow, since
        # GitHub forbids approving your own PR. A SHA binding, not review: required
        # approvals stay branch protection's (module docstring). It counts because the
        # author is the OWNER: a fork author's own GO does not (W6-06, below).
        mine = review(go_body(HEAD), state="COMMENTED", login="coord",
                      association="OWNER")
        self.assertTrue(verdict_at_tip([mine], HEAD, pr_author="coord"))

    def test_commented_go_counts_from_trusted_tiers(self):
        for association in ("OWNER", "MEMBER", "COLLABORATOR"):
            with self.subTest(association=association):
                r = review(go_body(HEAD), state="COMMENTED", login="peer",
                           association=association)
                self.assertTrue(verdict_at_tip([r], HEAD, pr_author="coord"))

    def test_commented_go_from_a_stranger_never_counts(self):
        # PR #460 review, P1: COMMENTED is open to any signed-in user, so a
        # drive-by comment must never satisfy this required check.
        for association in ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER",
                            "NONE", None):
            with self.subTest(association=association):
                r = review(go_body(HEAD), state="COMMENTED", login="stranger",
                           association=association)
                self.assertFalse(verdict_at_tip([r], HEAD, pr_author="coord"))

    def test_missing_body_is_not_a_go(self):
        self.assertFalse(verdict_at_tip([{"state": "APPROVED"}], HEAD))
        self.assertFalse(verdict_at_tip([{"state": "APPROVED", "body": None}], HEAD))

    def test_newest_go_wins_among_several(self):
        reviews = [review(go_body(OTHER)), review(go_body(HEAD))]
        hits = go_reviews_at_tip(reviews, HEAD)
        self.assertEqual(len(hits), 1)


class GhApiUnits(unittest.TestCase):
    def _proc(self, stdout="", stderr="", code=0):
        return subprocess.CompletedProcess(["gh", "api"], code, stdout, stderr)

    def _call(self, proc, paginate=False):
        with mock.patch.object(verdict_check.subprocess, "run", return_value=proc) as m:
            result = verdict_check._gh_api("pulls/1", "o/r", paginate=paginate)
        argv = m.call_args[0][0]
        if paginate:
            self.assertEqual(argv[:4], ["gh", "api", "--paginate", "--slurp"])
        else:
            self.assertEqual(argv[:2], ["gh", "api"])
            self.assertNotIn("--paginate", argv)
        self.assertIn("repos/o/r/pulls/1", argv)
        return result

    def test_a_json_object_comes_back_parsed(self):
        self.assertEqual(self._call(self._proc('{"sha": "abc"}')), {"sha": "abc"})

    def test_empty_output_is_empty(self):
        self.assertEqual(self._call(self._proc("")), {})
        self.assertEqual(self._call(self._proc(""), paginate=True), [])

    def test_slurped_pages_are_merged(self):
        proc = self._proc('[[{"a": 1}], [{"b": 2}, {"c": 3}]]\n')
        self.assertEqual(self._call(proc, paginate=True), [{"a": 1}, {"b": 2}, {"c": 3}])

    def test_concatenated_pages_without_separators_are_merged(self):
        # Plain --paginate prints `][` with no newline between pages; a line
        # splitter read that as one malformed document.
        for text in ('[{"a": 1}][{"b": 2}]', '[{"a": 1}]\n\n[{"b": 2}]\n',
                     '[{"a": 1}, {"x": "]["}]  [{"b": 2}]'):
            with self.subTest(text=text):
                got = self._call(self._proc(text), paginate=True)
                self.assertEqual(got[0], {"a": 1})
                self.assertEqual(got[-1], {"b": 2})

    def test_garbage_raises_instead_of_reading_as_no_reviews(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._call(self._proc('[{"a": 1}] trailing'), paginate=True)
        self.assertIn("unparseable", str(ctx.exception))
        with self.assertRaises(RuntimeError):
            self._call(self._proc('{"a": 1}{"b": 2}'))
        with self.assertRaises(RuntimeError):
            self._call(self._proc('{"a": 1}'), paginate=True)

    def test_a_nonzero_exit_raises_with_the_stderr(self):
        with mock.patch.object(verdict_check.subprocess, "run",
                               return_value=self._proc("", "Not Found", 1)):
            with self.assertRaises(RuntimeError) as ctx:
                verdict_check._gh_api("pulls/1", "o/r")
        self.assertIn("gh api pulls/1 failed: Not Found", str(ctx.exception))


class CheckPrUnits(unittest.TestCase):
    PR = {"head": {"sha": HEAD}, "user": {"login": "coord"}}

    def _check(self, pr_payload, reviews_payload):
        def fake(path, repo, paginate=False):
            self.assertEqual(repo, "o/r")
            # Only the LIST endpoint paginates; the PR object is one document.
            self.assertEqual(paginate, path != "pulls/7")
            return pr_payload if path == "pulls/7" else reviews_payload
        with mock.patch.object(verdict_check, "_gh_api", side_effect=fake):
            return verdict_check.check_pr("7", "o/r")

    def test_head_author_reviews_and_hits_come_back_wired(self):
        reviews = [review(go_body(HEAD)), review("lgtm")]
        head, got, hits, author = self._check(dict(self.PR), reviews)
        self.assertEqual(head, HEAD)
        self.assertEqual(got, reviews)
        self.assertEqual(len(hits), 1)
        self.assertEqual(author, "coord")

    def test_a_paginated_single_object_response_unwraps(self):
        head, _got, hits, _author = self._check([dict(self.PR)], [review(go_body(HEAD))])
        self.assertEqual(head, HEAD)
        self.assertEqual(len(hits), 1)

    def test_an_empty_pr_payload_reads_as_no_head(self):
        head, _got, hits, author = self._check([], [])
        self.assertEqual(head, "")
        self.assertEqual(hits, [])
        self.assertEqual(author, "")

    def test_a_non_list_reviews_payload_reads_as_no_reviews(self):
        _head, got, hits, _author = self._check(dict(self.PR), {"message": "odd"})
        self.assertEqual(got, [])
        self.assertEqual(hits, [])


class MainInProc(unittest.TestCase):
    def _main(self, argv, payload=None, error=None):
        def fake(pr_number, repo):
            self.assertEqual(repo, "o/r")
            if error is not None:
                raise error
            return payload
        out, err = io.StringIO(), io.StringIO()
        # These cases are about the verdict: the PR changes no grader path (W6-01 has its own).
        no_grader_change = mock.patch.object(verdict_check, "grader_refusal",
                                             return_value=([], None))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), no_grader_change:
            with mock.patch.object(verdict_check, "check_pr", side_effect=fake):
                code = verdict_check.main(argv)
        return code, out.getvalue(), err.getvalue()

    def _payload(self, reviews):
        return (HEAD, reviews,
                verdict_check.go_reviews_at_tip(reviews, HEAD, "coord"), "coord")

    def test_a_go_at_tip_passes_and_names_the_author(self):
        code, out, err = self._main(["--pr", "7", "--repo", "o/r"],
                                    self._payload([review(go_body(HEAD))]))
        self.assertEqual(code, 0, err)
        self.assertIn("1 trusted at tip", out)
        self.assertIn("@reviewer [APPROVED]", out)
        self.assertIn("PASS", out)

    def test_a_stale_go_fails_asking_for_a_fresh_verdict(self):
        code, _out, err = self._main(["--pr", "7", "--repo", "o/r"],
                                     self._payload([review(go_body(OTHER))]))
        self.assertEqual(code, 1)
        self.assertIn("none binds the current head", err)

    def test_an_untrusted_go_fails_as_a_drive_by(self):
        stranger = review(go_body(HEAD), state="COMMENTED", login="stranger",
                          association="NONE")
        code, _out, err = self._main(["--pr", "7", "--repo", "o/r"],
                                     self._payload([stranger]))
        self.assertEqual(code, 1)
        self.assertIn("drive-by", err)

    def test_no_go_at_all_fails_plainly(self):
        code, _out, err = self._main(["--pr", "7", "--repo", "o/r"], self._payload([]))
        self.assertEqual(code, 1)
        self.assertIn("no GO verdict review", err)

    def test_a_missing_repo_is_a_usage_error(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            code, _out, err = self._main(["--pr", "7"], self._payload([]))
        self.assertEqual(code, 2)
        self.assertIn("need --repo", err)

    def test_a_malformed_repo_is_a_usage_error(self):
        code, _out, err = self._main(["--pr", "7", "--repo", "noslash"], self._payload([]))
        self.assertEqual(code, 2)
        self.assertIn("need --repo", err)

    def test_the_repo_defaults_to_the_environment(self):
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r"}):
            code, _out, err = self._main(["--pr", "7"], self._payload([]))
        self.assertEqual(code, 1, err)  # parsed the env repo, then failed on no GO

    def test_an_api_failure_is_exit_2(self):
        code, _out, err = self._main(["--pr", "7", "--repo", "o/r"],
                                     error=RuntimeError("gh api down"))
        self.assertEqual(code, 2)
        self.assertIn("gh api down", err)

    def test_a_missing_pr_number_exits_2_through_system_exit(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                verdict_check.main(["--repo", "o/r"])
        self.assertEqual(ctx.exception.code, 2)

    def test_the_module_entry_point_rejects_a_missing_pr(self):
        argv = ["verdict_check.py", "--repo", "o/r"]
        with contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(sys, "argv", argv):
                with self.assertRaises(SystemExit) as ctx:
                    runpy.run_path(str(_ROOT / "scripts" / "verdict_check.py"),
                                   run_name="__main__")
        self.assertEqual(ctx.exception.code, 2)


class PostStatusGate(unittest.TestCase):
    """--post-status is the authoritative gate (verdict-gate.yml): the verdict becomes a
    commit status on the PR's current head, and the exit code says whether it was posted."""

    OTHER_PR = {"number": 9, "head": {"sha": "c" * 40}}

    def _run(self, argv, reviews, pulls=None, post_rc=0):
        posted = []

        def fake_api(path, repo, paginate=False):
            self.assertEqual(repo, "o/r")
            if path.startswith("pulls?"):
                return pulls or []
            if path == "pulls/7":
                return {"number": 7, "head": {"sha": HEAD, "repo": {"full_name": "o/r"}},
                        "base": {"sha": OTHER, "repo": {"full_name": "o/r"}},
                        "user": {"login": "coord"}}
            return reviews

        def fake_run(cmd, **_kw):
            posted.append(cmd)
            return subprocess.CompletedProcess(cmd, post_rc, "", "denied" if post_rc else "")

        out, err = io.StringIO(), io.StringIO()
        env = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_RUN_ID": "42"}
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.dict(os.environ, env), \
                mock.patch.object(verdict_check, "_gh_api", side_effect=fake_api), \
                mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_run):
            code = verdict_check.main(argv + ["--repo", "o/r"])
        return code, posted, out.getvalue() + err.getvalue()

    def _fields(self, cmd):
        return dict(cmd[i + 1].split("=", 1) for i, a in enumerate(cmd) if a == "-f")

    def test_a_go_at_tip_posts_success_on_the_head(self):
        code, posted, _ = self._run(["--pr", "7", "--post-status"], [review(go_body(HEAD))])
        self.assertEqual(code, 0)
        self.assertEqual(len(posted), 1)
        self.assertIn(f"repos/o/r/statuses/{HEAD}", posted[0])
        fields = self._fields(posted[0])
        self.assertEqual((fields["state"], fields["context"]), ("success", "verdict-gate"))
        self.assertEqual(fields["target_url"], "https://github.com/o/r/actions/runs/42")

    def test_no_go_posts_failure_and_still_exits_zero(self):
        # The status IS the verdict; a red run on the default branch for every
        # unverdicted review would be noise, so the exit code reports the post.
        code, posted, _ = self._run(["--pr", "7", "--post-status"], [review(go_body(OTHER))])
        self.assertEqual(code, 0)
        fields = self._fields(posted[0])
        self.assertEqual(fields["state"], "failure")
        self.assertIn("none binds the current head", fields["description"])
        self.assertLessEqual(len(fields["description"]), 140)

    def test_a_custom_context_is_honoured(self):
        _code, posted, _ = self._run(["--pr", "7", "--post-status", "gate-x"], [])
        self.assertEqual(self._fields(posted[0])["context"], "gate-x")

    def test_a_failed_post_is_exit_2(self):
        code, _posted, out = self._run(["--pr", "7", "--post-status"], [], post_rc=1)
        self.assertEqual(code, 2)
        self.assertIn("denied", out)

    def test_without_post_status_nothing_is_posted(self):
        code, posted, _ = self._run(["--pr", "7"], [])
        self.assertEqual((code, posted), (1, []))

    def test_head_sha_finds_the_one_open_pr_at_that_head(self):
        pulls = [self.OTHER_PR, {"number": 7, "head": {"sha": HEAD.upper()}}]
        code, posted, out = self._run(["--head-sha", HEAD, "--post-status"],
                                      [review(go_body(HEAD))], pulls=pulls)
        self.assertEqual(code, 0, out)
        self.assertIn("PR #7", out)
        self.assertEqual(self._fields(posted[0])["state"], "success")

    def test_head_sha_with_no_or_several_prs_posts_nothing(self):
        for pulls in ([], [{"number": 7, "head": {"sha": HEAD}},
                           {"number": 8, "head": {"sha": HEAD}}]):
            with self.subTest(n=len(pulls)):
                code, posted, out = self._run(["--head-sha", HEAD, "--post-status"], [],
                                              pulls=pulls)
                self.assertEqual((code, posted), (2, []))
                self.assertIn("exactly one", out)

    def test_a_short_head_sha_is_refused(self):
        code, posted, out = self._run(["--head-sha", "abc123", "--post-status"], [])
        self.assertEqual((code, posted), (2, []))
        self.assertIn("full 40-hex", out)

    def test_resolve_pr_prints_the_number_and_posts_nothing(self):
        pulls = [{"number": 7, "head": {"sha": HEAD}}]
        code, posted, out = self._run(["--head-sha", HEAD, "--resolve-pr"], [], pulls=pulls)
        self.assertEqual((code, posted), (0, []))
        self.assertEqual(out.strip(), "7")

    def test_resolve_pr_refuses_a_numberless_match_and_needs_head_sha(self):
        code, _posted, out = self._run(["--head-sha", HEAD, "--resolve-pr"], [],
                                       pulls=[{"number": None, "head": {"sha": HEAD}}])
        self.assertEqual(code, 2)
        self.assertIn("no usable number", out)
        code, _posted, out = self._run(["--pr", "7", "--resolve-pr"], [])
        self.assertEqual(code, 2)
        self.assertIn("needs --head-sha", out)

    def test_pr_and_head_sha_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                verdict_check.main(["--pr", "7", "--head-sha", HEAD, "--repo", "o/r"])
        self.assertEqual(ctx.exception.code, 2)


class TheGateRunsOnlyDefaultBranchCode(unittest.TestCase):
    """verdict-gate.yml is the required check: nothing the PR under review can edit may run
    in it, runs for one PR must post in order, and its status must come from an identity a
    fork PR or a writer's branch workflow cannot mint."""

    TEXT = (_ROOT / ".github" / "workflows" / "verdict-gate.yml").read_text(encoding="utf-8")
    TRIGGER = (_ROOT / ".github" / "workflows" / "verdict-check.yml").read_text(encoding="utf-8")

    def _job(self, name):
        jobs = "\n" + self.TEXT.split("\njobs:\n", 1)[1]
        body = jobs.split(f"\n  {name}:\n", 1)[1]
        return body.split("\n  gate:\n", 1)[0] if name == "resolve" else body

    def test_it_runs_only_on_workflow_run_of_verdict_check(self):
        on = self.TEXT.split("\non:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(on, "  workflow_run:\n    workflows: [verdict-check]\n"
                             "    types: [completed]")
        # a dispatch loads the workflow from whichever branch is picked (PR #572 review)
        self.assertNotIn("workflow_dispatch", self.TEXT.split("\nname:", 1)[1])

    def test_every_checkout_is_the_default_branch_checker_alone(self):
        checkouts = self.TEXT.split("actions/checkout@")[1:]
        self.assertEqual(len(checkouts), 2)
        for block in checkouts:
            head = block.split("- uses:", 1)[0]
            self.assertIn("ref: ${{ github.sha }}", head)
            self.assertIn("sparse-checkout: scripts/verdict_check.py", head)
            self.assertIn("persist-credentials: false", head)
        self.assertNotRegex(self.TEXT, r"ref:\s*\$\{\{\s*github\.event\.workflow_run\.head")
        self.assertNotIn("pull_request.head", self.TEXT)

    def test_resolve_names_the_pr_through_the_default_branch_script(self):
        job = self._job("resolve")
        self.assertIn("--head-sha \"$RUN_HEAD_SHA\" --resolve-pr", job)
        self.assertIn("*[!0-9]*", job)  # only a number reaches the lock and the gate
        self.assertNotIn("statuses: write", job)

    def test_gate_serialises_per_pr_and_posts_through_the_default_branch_script(self):
        job = self._job("gate")
        self.assertIn("needs: resolve", job)
        self.assertIn("group: verdict-gate-pr-${{ needs.resolve.outputs.pr }}", job)
        self.assertIn("cancel-in-progress: false", job)
        self.assertIn('python3 scripts/verdict_check.py --post-status --pr "$PR_NUMBER"', job)
        self.assertEqual(verdict_check.STATUS_CONTEXT, "verdict-gate")

    def test_permissions_are_per_job_and_only_the_gate_writes_statuses(self):
        self.assertRegex(self.TEXT, r"(?m)^permissions: \{\}$")
        self.assertEqual(len(re.findall(r"(?m)^ +statuses: write$", self.TEXT)), 1)
        self.assertIn("    permissions:\n      contents: read\n      pull-requests: read\n"
                      "      statuses: write\n", self._job("gate"))

    def test_the_app_key_lives_in_the_branch_restricted_environment(self):
        job = self._job("gate")
        self.assertIn("environment: verdict-gate", job)
        self.assertIn("if: vars.VERDICT_GATE_CLIENT_ID != ''", job)
        self.assertRegex(job, r"actions/create-github-app-token@[0-9a-f]{40} # v")
        self.assertIn("steps.app.outputs.token || secrets.GITHUB_TOKEN", job)
        self.assertIn("::warning::verdict-gate posts as github-actions", job)
        self.assertNotIn("VERDICT_GATE_PRIVATE_KEY", self._job("resolve"))

    def test_the_trigger_always_completes_a_run(self):
        # A `relay` job with no `if:` — every review, GO or not, wakes the gate.
        jobs = self.TRIGGER.split("\njobs:\n", 1)[1]
        relay = jobs.split("\n  verdict:\n", 1)[0]
        self.assertIn("  relay:\n", relay)
        self.assertNotIn("if:", relay)


class WorkflowRunsTheBaseChecker(unittest.TestCase):
    """verdict-check.yml must never run a checker the PR under review could rewrite."""

    TEXT = (_ROOT / ".github" / "workflows" / "verdict-check.yml").read_text(encoding="utf-8")

    def test_the_checker_is_checked_out_from_the_base_sha_into_its_own_path(self):
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", self.TEXT)
        self.assertIn("path: base-checker", self.TEXT)
        self.assertIn("python3 base-checker/scripts/verdict_check.py", self.TEXT)
        # exactly one checkout, and it is the base one — no PR tree on disk at all
        self.assertEqual(self.TEXT.count("actions/checkout@"), 1)
        self.assertNotRegex(self.TEXT, r"(?m)^\s+run: python3 scripts/verdict_check\.py")

    def test_permissions_are_read_only_and_explicit(self):
        self.assertRegex(self.TEXT,
                         r"(?m)^permissions:\n  contents: read\n  pull-requests: read\n")

    def test_the_trigger_gate_mirrors_the_scripts_trust_tiers(self):
        # The PR author's GO-marker review still triggers evaluation: the owner's self-GO
        # counts, and a fork author sees theirs refused (W6-06).
        self.assertIn(
            "github.event.review.user.login == github.event.pull_request.user.login",
            self.TEXT)



class AContradictedGoIsNotAGo(unittest.TestCase):
    """2026-10-23 review, §5: `VERDICT: GO` followed by `VERDICT: NO-GO` in one review body read
    as GO — the first GO line won. Any non-GO verdict line voids the review (fail closed)."""

    def test_go_then_no_go_is_not_a_go(self):
        body = f"VERDICT: GO\nreviewed_sha: {HEAD}\n\nOn reflection:\nVERDICT: NO-GO\n"
        self.assertFalse(verdict_at_tip([review(body)], HEAD))
        self.assertFalse(verdict_at_tip([review(body, state="COMMENTED", association="OWNER")], HEAD))

    def test_no_go_then_go_is_not_a_go_either(self):
        body = f"VERDICT: NO-GO\nreviewed_sha: {HEAD}\nVERDICT: GO\n"
        self.assertFalse(verdict_at_tip([review(body)], HEAD))

    def test_any_other_verdict_line_voids_the_review(self):
        for other in ("VERDICT: HOLD", "  VERDICT: GO-ISH", "VERDICT:"):
            body = go_body(HEAD) + other + "\n"
            with self.subTest(other=other):
                self.assertFalse(verdict_at_tip([review(body)], HEAD))

    def test_a_repeated_go_is_still_a_go(self):
        self.assertTrue(verdict_at_tip([review(go_body(HEAD) + "VERDICT: GO\n")], HEAD))


class AForkAuthorCannotGoTheirOwnPr(unittest.TestCase):
    """2026-10-27 security audit, W6-06: a COMMENTED GO from the PR author counted whoever the
    author was, so a fork author could post `VERDICT: GO` on their own head and turn the last
    required context green. The author's own GO is a SHA binding only from a trusted account."""

    def test_a_fork_authors_self_go_never_counts(self):
        for association in ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE", None):
            with self.subTest(association=association):
                mine = review(go_body(HEAD), state="COMMENTED", login="forker",
                              association=association)
                self.assertFalse(verdict_at_tip([mine], HEAD, pr_author="forker"))

    def test_an_approved_go_from_an_untrusted_account_never_counts(self):
        # PR #718 review (Codex, P1): any GitHub account can submit an APPROVED review on a public
        # repository; it only fails to count toward native required reviews. The state proves
        # nothing about the author, so APPROVED passes the same trust tiers as COMMENTED.
        for association in ("NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", None):
            for login, pr_author in (("outsider", "coord"), ("forker", "forker")):
                with self.subTest(association=association, login=login):
                    approved = review(go_body(HEAD), state="APPROVED", login=login,
                                      association=association)
                    self.assertFalse(verdict_at_tip([approved], HEAD, pr_author=pr_author))

    def test_the_gate_reports_an_untrusted_approval_as_untrusted(self):
        pr = {"number": 7, "head": {"sha": HEAD, "repo": {"full_name": "o/r"}},
              "base": {"ref": "main", "repo": {"full_name": "o/r"}}, "user": {"login": "coord"},
              "author_association": "OWNER", "changed_files": 0}
        approved = review(go_body(HEAD), state="APPROVED", login="outsider", association="NONE")

        def fake_api(path, repo, paginate=False):
            return {"pulls/7": pr, "pulls/7/reviews": [approved]}.get(path, [])

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check, "_gh_api", side_effect=fake_api):
            code = verdict_check.main(["--pr", "7", "--repo", "o/r"])
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("untrusted", err.getvalue())

    def test_the_owners_self_go_still_binds(self):
        mine = review(go_body(HEAD), state="COMMENTED", login="ravidsrk", association="OWNER")
        self.assertTrue(verdict_at_tip([mine], HEAD, pr_author="ravidsrk"))

    def test_the_gate_reports_a_self_go_from_a_fork_as_untrusted(self):
        pr = {"number": 7, "head": {"sha": HEAD, "repo": {"full_name": "forker/r"}},
              "base": {"ref": "main", "repo": {"full_name": "o/r"}}, "user": {"login": "forker"},
              "author_association": "CONTRIBUTOR", "changed_files": 0}
        mine = review(go_body(HEAD), state="COMMENTED", login="forker", association="CONTRIBUTOR")

        def fake_api(path, repo, paginate=False):
            return {"pulls/7": pr, "pulls/7/reviews": [mine]}.get(path, [])

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check, "_gh_api", side_effect=fake_api):
            code = verdict_check.main(["--pr", "7", "--repo", "o/r"])
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("untrusted", err.getvalue())


class TheLatestTrustedVerdictAtTheHeadDecides(unittest.TestCase):
    """PR #718 re-attack (W6-06): a trusted NO-GO did not veto. An owner's CHANGES_REQUESTED, or a
    `VERDICT: NO-GO` bound to the same head, posted after a GO left the gate green. The latest
    trusted verdict bound to the head decides: a later NO-GO blocks, a later GO clears it."""

    @staticmethod
    def at(body, when, state="COMMENTED", association="OWNER", login="o", commit=HEAD):
        r = review(body, state=state, login=login, association=association)
        r["submitted_at"], r["commit_id"] = when, commit
        return r

    GO = staticmethod(lambda when, **kw: TheLatestTrustedVerdictAtTheHeadDecides.at(
        go_body(HEAD), when, **kw))
    NO_GO = f"Not yet.\n\nVERDICT: NO-GO\nreviewed_sha: {HEAD}\n"

    def test_a_later_trusted_no_go_blocks(self):
        for later in (self.at(self.NO_GO, "2026-10-27T02:00:00Z"),
                      self.at("Needs work.", "2026-10-27T02:00:00Z", state="CHANGES_REQUESTED"),
                      self.at("VERDICT: NO-GO\n", "2026-10-27T02:00:00Z"),  # bound by commit_id
                      self.at(self.NO_GO, "2026-10-27T02:00:00Z", state="APPROVED",
                              association="MEMBER", login="peer")):
            with self.subTest(later=later["body"], state=later["state"]):
                reviews = [self.GO("2026-10-27T01:00:00Z"), later]
                self.assertFalse(verdict_at_tip(reviews, HEAD, pr_author="o"))

    def test_a_later_go_clears_a_no_go(self):
        reviews = [self.at(self.NO_GO, "2026-10-27T01:00:00Z"),
                   self.at("Needs work.", "2026-10-27T01:30:00Z", state="CHANGES_REQUESTED"),
                   self.GO("2026-10-27T02:00:00Z")]
        self.assertTrue(verdict_at_tip(reviews, HEAD, pr_author="o"))

    def test_only_a_trusted_verdict_at_this_head_can_veto(self):
        go = self.GO("2026-10-27T01:00:00Z")
        for later in (
                self.at(self.NO_GO, "2026-10-27T02:00:00Z", association="NONE", login="x"),
                self.at("Needs work.", "2026-10-27T02:00:00Z", state="CHANGES_REQUESTED",
                        association="CONTRIBUTOR", login="x"),
                self.at(self.NO_GO.replace(HEAD, OTHER), "2026-10-27T02:00:00Z", commit=OTHER),
                self.at("Needs work.", "2026-10-27T02:00:00Z", state="CHANGES_REQUESTED",
                        commit=OTHER),
                self.at("Needs work.", "2026-10-27T02:00:00Z", state="DISMISSED"),
                self.at("A comment, no verdict.", "2026-10-27T02:00:00Z")):
            with self.subTest(later=later["body"], state=later["state"]):
                self.assertTrue(verdict_at_tip([go, later], HEAD, pr_author="o"))

    def test_the_gate_names_the_veto(self):
        pr = {"number": 7, "head": {"sha": HEAD}, "user": {"login": "o"},
              "author_association": "OWNER", "changed_files": 0}
        reviews = [self.GO("2026-10-27T01:00:00Z"), self.at(self.NO_GO, "2026-10-27T02:00:00Z")]

        def fake_api(path, repo, paginate=False):
            return {"pulls/7": pr, "pulls/7/reviews": reviews}.get(path, [])

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check, "_gh_api", side_effect=fake_api), \
                mock.patch.object(verdict_check, "grader_refusal", return_value=([], None)):
            code = verdict_check.main(["--pr", "7", "--repo", "o/r"])
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("NO-GO", err.getvalue())


class APrCannotChangeItsOwnGrader(unittest.TestCase):
    """2026-10-27 security audit, W6-01 (P1): a `pull_request` run loads its workflow from the
    PR's merge ref, so a fork PR that empties the `gates`, `guard` and `pinned-demo` jobs gets
    three green required contexts with nothing checked. `verdict-gate` is the one required
    context whose code comes from the default branch; it now refuses a PR that changes the
    grader unless the repository owner wrote it."""

    OWNER_GO = review(go_body(HEAD), state="COMMENTED", login="o", association="OWNER")
    BASE = "c" * 40

    def _pr(self, login="forker", association="CONTRIBUTOR", changed=None, head=HEAD,
            head_repo="o/r"):
        # A fork's PR still has its head in this repository's network; the head repo names it.
        pr = {"number": 7, "head": {"sha": head, "repo": {"full_name": head_repo}},
              "base": {"ref": "main", "sha": self.BASE, "repo": {"full_name": "o/r"}},
              "user": {"login": login}, "author_association": association}
        if changed is not None:
            pr["changed_files"] = changed
        return pr

    def _run(self, files, pr=None, pr_after=None, post=True, reviews=None, listed=None,
             fail=()):
        """`files` is what the compare API says the exact head changed; `listed` is what the
        PR's (SHA-less) files list says, which the gate must not read. `fail` names reads that
        error the way a failed `gh api` does: "compare/", or "pulls/7#2" for the second PR read."""
        pr = pr or self._pr(changed=len(files))
        seen = {"pulls/7": 0}
        self.compared = []
        posted = []

        def fake_api(path, repo, paginate=False):
            self.assertEqual(repo, "o/r")
            if path == "pulls/7":
                seen["pulls/7"] += 1
                if seen["pulls/7"] >= 2 and "pulls/7#2" in fail:
                    raise RuntimeError("gh api pulls/7 failed: HTTP 502")
                return pr if seen["pulls/7"] == 1 or pr_after is None else pr_after
            if any(path.startswith(prefix) for prefix in fail):
                raise RuntimeError(f"gh api {path} failed: HTTP 404: No common ancestor")
            if path == "pulls/7/reviews":
                self.assertTrue(paginate)
                return [self.OWNER_GO] if reviews is None else reviews
            if path.startswith("compare/"):
                self.compared.append(path)
                return {"files": files}
            if path.startswith("pulls/7/files"):
                return files if listed is None else listed
            self.fail(f"unexpected API path {path}")

        def fake_run(cmd, **_kw):
            posted.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        argv = ["--pr", "7", "--repo", "o/r"] + (["--post-status"] if post else [])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check, "_gh_api", side_effect=fake_api), \
                mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_run):
            code = verdict_check.main(argv)
        fields = (dict(c[i + 1].split("=", 1) for i, a in enumerate(c) if a == "-f")
                  for c in posted)
        return code, list(fields), out.getvalue() + err.getvalue()

    @staticmethod
    def _files(*names, status="modified"):
        return [{"filename": n, "status": status} for n in names]

    def test_a_fork_pr_that_edits_a_workflow_is_refused_even_with_a_go(self):
        for path in (".github/workflows/validate.yml", ".github/workflows/guard.yml",
                     ".github/workflows/new-gate.yml", ".github/actions/setup/action.yml",
                     ".github/ci-tools.lock"):
            with self.subTest(path=path):
                code, posted, out = self._run(self._files("scripts/x.py", path))
                self.assertEqual(code, 0, out)  # --post-status: the status IS the verdict
                self.assertEqual(len(posted), 1)
                self.assertEqual(posted[0]["state"], "failure", out)
                self.assertIn("grader", posted[0]["description"])
                self.assertLessEqual(len(posted[0]["description"]), 140)
                self.assertIn(path, out)

    def test_without_post_status_the_refusal_is_exit_1(self):
        code, posted, out = self._run(self._files(".github/workflows/validate.yml"), post=False)
        self.assertEqual((code, posted), (1, []))
        self.assertIn("grader", out)

    def test_a_removed_or_renamed_workflow_is_a_grader_change(self):
        for files in (self._files(".github/workflows/negative-control.yml", status="removed"),
                      [{"filename": "docs/old-gate.yml", "status": "renamed",
                        "previous_filename": ".github/workflows/guard.yml"}],
                      [{"filename": ".github/workflows/guard.yml", "status": "renamed",
                        "previous_filename": "docs/guard.yml"}]):
            with self.subTest(files=files):
                _code, posted, out = self._run(files)
                self.assertEqual(posted[0]["state"], "failure", out)

    def test_the_owners_pr_may_change_the_grader(self):
        files = self._files(".github/workflows/validate.yml", ".github/ci-tools.lock")
        for login, association in (("o", "OWNER"), ("O", "CONTRIBUTOR"), ("someone", "OWNER")):
            with self.subTest(login=login, association=association):
                pr = self._pr(login=login, association=association, changed=len(files))
                _code, posted, out = self._run(files, pr=pr)
                self.assertEqual(posted[0]["state"], "success", out)

    def test_a_collaborator_is_not_the_owner(self):
        files = self._files(".github/workflows/validate.yml")
        for association in ("MEMBER", "COLLABORATOR"):
            with self.subTest(association=association):
                pr = self._pr(login="peer", association=association, changed=1)
                _code, posted, out = self._run(files, pr=pr)
                self.assertEqual(posted[0]["state"], "failure", out)

    def test_a_pr_that_leaves_the_grader_alone_passes_on_its_go(self):
        files = self._files("scripts/x.py", "tests/test_x.py", ".github/CONTRIBUTING.md",
                            ".github/CODEOWNERS", "docs/.github/workflows/x.yml",
                            ".github/workflows-notes.md")
        _code, posted, out = self._run(files)
        self.assertEqual(posted[0]["state"], "success", out)

    def test_a_files_list_that_may_be_truncated_is_refused(self):
        # The compare API lists at most 300 files; a grader change past the cut must not hide.
        few = self._files("scripts/x.py")
        _code, posted, out = self._run(few, pr=self._pr(changed=2))
        self.assertEqual(posted[0]["state"], "failure", out)
        self.assertIn("files", posted[0]["description"])
        many = self._files(*(f"docs/f{i}.md" for i in range(300)))
        _code, posted, out = self._run(many, pr=self._pr())
        self.assertEqual(posted[0]["state"], "failure", out)

    def test_the_grader_read_is_bound_to_the_exact_head(self):
        # PR #718 re-attack: the PR files list carries no SHA, so a head flipped
        # M -> benign -> M across the gate's reads passed. The changed paths are read for the
        # exact head the status is posted on (compare base...head.sha), never the list.
        _code, posted, out = self._run(self._files(".github/workflows/validate.yml"),
                                       listed=self._files("docs/benign.md"))
        self.assertEqual(posted[0]["state"], "failure", out)
        self.assertEqual(self.compared, [f"compare/main...{HEAD}"])

    def test_an_owner_pr_from_a_fork_branch_gets_no_exemption(self):
        # The fork keeps push access to its branch, so the owner's name on the PR does not make
        # its head the owner's. The exemption needs the head in this repository.
        files = self._files(".github/workflows/validate.yml")
        for head_repo in ("forker/r", None):
            with self.subTest(head_repo=head_repo):
                pr = self._pr(login="o", association="OWNER", changed=1, head_repo=head_repo)
                _code, posted, out = self._run(files, pr=pr)
                self.assertEqual(posted[0]["state"], "failure", out)

    def test_the_gate_scripts_are_the_grader_too(self):
        # PR #718 re-attack: every required job runs PR code, so a one-file rewrite of the script
        # a gate runs (shard-tests.py running nothing, gate.py exiting 0, run.sh printing the
        # pinned transcript) made the gate green. A non-owner PR may not change those scripts.
        for path in verdict_check.GATE_SCRIPTS:
            with self.subTest(path=path):
                _code, posted, out = self._run(self._files(path))
                self.assertEqual(posted[0]["state"], "failure", out)
        for path in ("scripts/shard-tests.py", "bench/vf-bench/gate.py",
                     "evals/demo/negative-control/run.sh"):
            self.assertIn(path, verdict_check.GATE_SCRIPTS)

    def test_a_new_top_level_module_is_the_grader_too(self):
        # Jobs run `python3 -m coverage` / `-m unittest` from the checkout root (shard-tests.py),
        # so a root `coverage/` or `unittest.py` would run instead of the locked tool.
        for path in ("pip/__init__.py", "coverage/__init__.py", "unittest.py", "json.py",
                     "sitecustomize.py", "evil.pth", "x.so", "newdir/readme.md"):
            with self.subTest(path=path):
                _code, posted, out = self._run(self._files(path))
                self.assertEqual(posted[0]["state"], "failure", out)
        for path in ("README.md", "docs/x.md", "tests/test_new.py", ".gitignore"):
            with self.subTest(path=path):
                _code, posted, out = self._run(self._files(path))
                self.assertEqual(posted[0]["state"], "success", out)

    def test_a_grader_directory_itself_and_the_test_package_init_are_the_grader(self):
        # PR #718 re-attack PoC: `.github/workflows` changed as a path of its own (a file or a
        # symlink where the directory was) passed. And `tests/__init__.py` runs in every shard
        # before any test (`-m unittest tests.<module>`), so it could rewrite the runner.
        for path in (".github", ".github/workflows", ".github/actions/", "tests/__init__.py"):
            with self.subTest(path=path):
                _code, posted, out = self._run(self._files(path))
                self.assertEqual(posted[0]["state"], "failure", out)
        _code, posted, out = self._run(self._files(".github/Workflows/x.yml"))
        self.assertEqual(posted[0]["state"], "success", "GitHub reads .github/workflows only")

    def test_an_owner_own_branch_pr_never_waits_on_the_grader_read(self):
        # PR #718 review (availability): the compare read ran before the owner exemption, and a
        # failed `gh api` raised, so verdict-gate errored with no status on every owner PR,
        # the PR that would fix it included, with admins enforced on main. The owner's
        # own-branch PR is decided from the PR object already read, on its verdict alone.
        owner = self._pr(login="o", association="OWNER", changed=1)
        files = self._files(".github/workflows/validate.yml")
        for fail in (("compare/",), ("compare/", "pulls/7#2")):
            with self.subTest(fail=fail):
                code, posted, out = self._run(files, pr=owner, fail=fail)
                self.assertEqual(code, 0, out)
                self.assertEqual(posted[0]["state"], "success", out)
                code, posted, out = self._run(files, pr=owner, fail=fail, reviews=[])
                self.assertEqual(posted[0]["state"], "failure", out)
                self.assertIn("no GO verdict review", posted[0]["description"])
        unnamed = self._pr(login="o", association="OWNER", changed=1)
        unnamed["base"] = {"repo": {"full_name": "o/r"}}  # no ref, no sha: nothing to compare
        code, posted, out = self._run(files, pr=unnamed)
        self.assertEqual((code, posted[0]["state"]), (0, "success"), out)

    def test_an_owner_pr_whose_grader_read_hangs_still_gets_its_status(self):
        # A failed read was covered, a hung one was not: `gh api` ran with no timeout, so a
        # compare read that never answered held the gate job to its 10-minute limit and the
        # owner's PR got no status at all. Each read is bounded and a timeout is a failed read.
        owner = self._pr(login="o", association="OWNER", changed=1)
        posted, timeouts = [], []

        def fake_run(cmd, **kw):
            path = cmd[-1]
            if any("/statuses/" in arg for arg in cmd):
                posted.append(dict(c.split("=", 1) for i, c in enumerate(cmd)
                                   if i and cmd[i - 1] == "-f"))
                return subprocess.CompletedProcess(cmd, 0, "", "")
            timeouts.append(kw.get("timeout"))
            if "/compare/" in path:
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            body = [[self.OWNER_GO]] if path.endswith("/reviews") else owner
            return subprocess.CompletedProcess(cmd, 0, json.dumps(body), "")

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_run):
            code = verdict_check.main(["--pr", "7", "--repo", "o/r", "--post-status"])
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())
        self.assertEqual(posted[0]["state"], "success", err.getvalue())
        self.assertTrue(timeouts and all(isinstance(t, (int, float)) and 0 < t <= 120
                                         for t in timeouts), timeouts)

    def test_a_failed_read_fails_any_other_pr_closed_with_a_posted_status(self):
        # Not a missing status: a clear failure the PR's checks list shows.
        for fail in (("compare/",), ("pulls/7#2",)):
            with self.subTest(fail=fail):
                code, posted, out = self._run(self._files("docs/x.md"), fail=fail)
                self.assertEqual(code, 0, out)
                self.assertEqual(len(posted), 1, out)
                self.assertEqual(posted[0]["state"], "failure", out)
                self.assertIn("cannot read", posted[0]["description"])
                self.assertLessEqual(len(posted[0]["description"]), 140)
        code, posted, out = self._run(self._files("docs/x.md"), fail=("compare/",), post=False)
        self.assertEqual((code, posted), (1, []))

    def test_the_top_level_list_is_this_repositorys(self):
        listed = subprocess.run(["git", "-C", str(_ROOT), "ls-tree", "-d", "--name-only", "HEAD"],
                                capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(sorted(verdict_check.TOP_LEVEL_DIRS), sorted(listed))

    def test_the_gate_scripts_list_holds_what_the_required_jobs_run(self):
        # Every script a required job (gates and its needs, pinned-demo) names on a run: line.
        # guard runs the base branch's floor_guard.py, which no PR can edit.
        named = set()
        for workflow, jobs in (("validate.yml", ("tests", "floor", "checks", "gates", "vfbench",
                                                 "vfbench_replay")),
                               ("negative-control.yml", ("pinned-demo",))):
            data = (_ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            section = "\n" + data.split("\njobs:\n", 1)[1]
            for job in jobs:
                body = section.split(f"\n  {job}:\n", 1)[1]
                body = re.split(r"\n  [A-Za-z0-9_-]+:\n", body, maxsplit=1)[0]
                named |= set(re.findall(r"(?:python3|sh|bash)\s+(?:-\S+\s+)*"
                                        r"((?:scripts|runtime|bench|evals)/[\w./-]+\.(?:py|sh))",
                                        body))
        self.assertTrue(named)
        self.assertEqual(sorted(named - set(verdict_check.GATE_SCRIPTS)), [])
        self.assertEqual(sorted(set(verdict_check.GATE_SCRIPTS) - named), [],
                         "a listed gate script no required job runs any more")

    def test_reads_use_the_jobs_token_and_the_status_the_apps(self):
        # The compare API needs Contents: read, which the gate's app does not hold; the job's
        # own GITHUB_TOKEN (contents: read) reads, and only the status uses the app identity.
        gate = (_ROOT / ".github" / "workflows" / "verdict-gate.yml").read_text(encoding="utf-8")
        job = gate.split("\n  gate:\n", 1)[1]
        self.assertIn("          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n", job)
        self.assertIn("          GH_STATUS_TOKEN: ${{ steps.app.outputs.token || "
                      "secrets.GITHUB_TOKEN }}\n", job)
        sent = []
        with mock.patch.dict(os.environ, {"GH_STATUS_TOKEN": "app-token", "GH_TOKEN": "job"}), \
                mock.patch.object(verdict_check.subprocess, "run",
                                  side_effect=lambda cmd, **kw: sent.append(kw.get("env")) or
                                  subprocess.CompletedProcess(cmd, 0, "", "")):
            verdict_check.post_status("o/r", HEAD, "success", "ok")
        self.assertEqual(sent[0]["GH_TOKEN"], "app-token")

    def test_a_head_that_moves_during_the_evaluation_is_refused(self):
        moved = self._pr(changed=1, head=OTHER)
        _code, posted, out = self._run(self._files("scripts/x.py"), pr_after=moved)
        self.assertEqual(posted[0]["state"], "failure", out)
        self.assertIn("moved", posted[0]["description"])

    def test_the_grader_refusal_outranks_a_missing_go(self):
        _code, posted, out = self._run(self._files(".github/workflows/validate.yml"),
                                       reviews=[])
        self.assertEqual(posted[0]["state"], "failure")
        self.assertIn("grader", posted[0]["description"])

    def test_the_gate_job_can_read_the_files_list(self):
        # The files endpoint needs Pull requests: read, which the gate's app token carries.
        gate = (_ROOT / ".github" / "workflows" / "verdict-gate.yml").read_text(encoding="utf-8")
        self.assertIn("permission-pull-requests: read", gate)



class EveryReadAfterTheHeadPostsAStatus(unittest.TestCase):
    """PR #718 review round 4 (P2): with the PR read done, a hung `pulls/7/reviews` read raised
    out of check_pr and main exited 2 with no status, though the head was known, an owner's
    own-branch PR included. Once the head is known, every later read that hangs or fails ends in
    a posted status: failure, saying which read, and the owner's PR keeps its exemption for the
    grader (compare) read alone. Driven through subprocess, so each read really hangs
    (TimeoutExpired) or really fails (a non-zero `gh api` exit)."""

    OWNER_GO = review(go_body(HEAD), state="COMMENTED", login="o", association="OWNER")

    @staticmethod
    def _pr(owner):
        login, association = ("o", "OWNER") if owner else ("writer", "COLLABORATOR")
        return {"number": 7, "head": {"sha": HEAD, "repo": {"full_name": "o/r"}},
                "base": {"ref": "main", "sha": "c" * 40, "repo": {"full_name": "o/r"}},
                "user": {"login": login}, "author_association": association,
                "changed_files": 1}

    def _run(self, site, how, owner, post=True):
        """`site` is "reviews", "pulls/7#2" (the second PR read) or "compare"; `how` is "hang"
        or "error"."""
        pr, posted, reads = self._pr(owner), [], {"pulls/7": 0}

        def fake_run(cmd, **kw):
            if any("/statuses/" in arg for arg in cmd):
                posted.append(dict(arg.split("=", 1) for i, arg in enumerate(cmd)
                                   if i and cmd[i - 1] == "-f"))
                return subprocess.CompletedProcess(cmd, 0, "", "")
            path = cmd[-1].removeprefix("repos/o/r/")
            if path == "pulls/7":
                reads["pulls/7"] += 1
            name = "pulls/7#2" if path == "pulls/7" and reads["pulls/7"] == 2 else \
                "compare" if path.startswith("compare/") else \
                "reviews" if path == "pulls/7/reviews" else path
            if name == site:
                if how == "hang":
                    raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
                return subprocess.CompletedProcess(cmd, 1, "", "HTTP 502: Bad Gateway")
            body = ([[self.OWNER_GO]] if name == "reviews" else
                    {"files": [{"filename": "docs/x.md"}]} if name == "compare" else pr)
            return subprocess.CompletedProcess(cmd, 0, json.dumps(body), "")

        argv = ["--pr", "7", "--repo", "o/r"] + (["--post-status"] if post else [])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_run):
            code = verdict_check.main(argv)
        return code, posted, out.getvalue() + err.getvalue()

    def test_a_reviews_read_that_hangs_or_fails_posts_failure(self):
        for how in ("hang", "error"):
            for owner in (False, True):
                with self.subTest(how=how, owner=owner):
                    code, posted, out = self._run("reviews", how, owner)
                    self.assertEqual(code, 0, out)
                    self.assertEqual(len(posted), 1, out)
                    self.assertEqual(posted[0]["state"], "failure", out)
                    self.assertIn("reviews", posted[0]["description"])
                    self.assertLessEqual(len(posted[0]["description"]), 140)
            code, posted, out = self._run("reviews", how, owner=False, post=False)
            self.assertEqual((code, posted), (2, []), out)

    def test_a_second_pr_read_that_hangs_or_fails_posts_failure(self):
        for how in ("hang", "error"):
            with self.subTest(how=how):
                code, posted, out = self._run("pulls/7#2", how, owner=False)
                self.assertEqual(code, 0, out)
                self.assertEqual(posted[0]["state"], "failure", out)
                self.assertIn("cannot read", posted[0]["description"])

    def test_any_read_failure_after_the_head_posts_failure(self):
        # The net under grader_refusal's own fail-closed handling: a read added there that
        # raises still ends in a posted failure, never in exit 2 with no status.
        with mock.patch.object(verdict_check, "grader_refusal",
                               side_effect=RuntimeError("gh api compare/x failed: HTTP 500")):
            code, posted, out = self._run("none", "error", owner=False)
        self.assertEqual(code, 0, out)
        self.assertEqual(posted[0]["state"], "failure", out)
        self.assertIn("cannot read what this head changes", posted[0]["description"])

    def test_a_compare_read_that_hangs_or_fails_posts_a_status(self):
        for how in ("hang", "error"):
            with self.subTest(how=how, owner=False):
                code, posted, out = self._run("compare", how, owner=False)
                self.assertEqual(code, 0, out)
                self.assertEqual(posted[0]["state"], "failure", out)
                self.assertIn("cannot read", posted[0]["description"])
            with self.subTest(how=how, owner=True):
                # The owner's own-branch PR: the grader read is best-effort (docs/ops.md).
                code, posted, out = self._run("compare", how, owner=True)
                self.assertEqual((code, posted[0]["state"]), (0, "success"), out)


class MergeGateBypassesClosed(unittest.TestCase):
    """Regression tests for #779, #770, #769, and #771 merge-gate and workflow hardenings."""

    @staticmethod
    def _at(body, when, state="COMMENTED", association="OWNER", login="o", commit=HEAD):
        r = review(body, state=state, login=login, association=association)
        r["submitted_at"], r["commit_id"] = when, commit
        return r

    def test_indented_or_spaced_go_cannot_clear_veto_or_revive_pre_veto_go(self):
        # #779-1: parser mismatch between ANY_VERDICT_RE and VERDICT_RE allowed a quoted
        # `    VERDICT: GO` after a CHANGES_REQUESTED to clear the veto and revive the earlier GO.
        go1 = self._at(go_body(HEAD), "2026-11-01T01:00:00Z")
        veto = self._at("Needs fixes.", "2026-11-01T02:00:00Z", state="CHANGES_REQUESTED")
        for quoted in (
            f"Quoting earlier review:\n    VERDICT: GO\nreviewed_sha: {HEAD}\n",
            f"VERDICT : GO\nreviewed_sha: {HEAD}\n",
            f"\tVERDICT: GO\nreviewed_sha: {HEAD}\n",
        ):
            with self.subTest(quoted=quoted):
                reviews = [go1, veto, self._at(quoted, "2026-11-01T03:00:00Z")]
                self.assertEqual(go_reviews_at_tip(reviews, HEAD, pr_author="o"), [])
                self.assertFalse(verdict_at_tip(reviews, HEAD, pr_author="o"))

    def test_post_veto_go_returns_only_qualifying_reviews_newer_than_veto(self):
        # #779-1: when a later strict GO clears a veto, only the post-veto GO is returned; the
        # vetoed pre-veto GO is never revived in hits.
        go1 = self._at(go_body(HEAD), "2026-11-01T01:00:00Z", association="OWNER", login="o")
        veto = self._at("Stop.", "2026-11-01T02:00:00Z", state="CHANGES_REQUESTED")
        go2 = self._at(go_body(HEAD), "2026-11-01T03:00:00Z", association="COLLABORATOR",
                       login="collab")
        hits = go_reviews_at_tip([go1, veto, go2], HEAD, pr_author="o")
        self.assertEqual(hits, [go2])

    def test_quoted_prior_reviewed_sha_does_not_nullify_head_veto(self):
        # #779-2: a CHANGES_REQUESTED or non-GO VERDICT submitted on commit_id == HEAD still
        # vetoes HEAD even when the body quotes an older `reviewed_sha: <OTHER>`.
        go1 = self._at(go_body(HEAD), "2026-11-01T01:00:00Z")
        for later in (
            self._at(f"Earlier you had:\nreviewed_sha: {OTHER}\nFix this.",
                     "2026-11-01T02:00:00Z", state="CHANGES_REQUESTED", commit=HEAD),
            self._at(f"VERDICT: NO-GO\nreviewed_sha: {OTHER}\n",
                     "2026-11-01T02:00:00Z", state="COMMENTED", commit=HEAD),
            self._at(f"Still broken at head:\nreviewed_sha: {HEAD}\n",
                     "2026-11-01T02:00:00Z", state="CHANGES_REQUESTED", commit=OTHER),
        ):
            with self.subTest(body=later["body"], commit=later["commit_id"]):
                self.assertFalse(verdict_at_tip([go1, later], HEAD, pr_author="o"))

    def test_conflicting_reviewed_sha_lines_in_go_body_fail_closed(self):
        # #779-2: a GO body naming two different reviewed_sha values must fail closed.
        for body in (
            f"VERDICT: GO\nreviewed_sha: {HEAD}\nreviewed_sha: {OTHER}\n",
            f"VERDICT: GO\nreviewed_sha: {OTHER}\nreviewed_sha: {HEAD}\n",
        ):
            with self.subTest(body=body):
                self.assertFalse(verdict_at_tip([self._at(body, "2026-11-01T01:00:00Z")], HEAD))
                # Also cannot clear an earlier veto.
                go1 = self._at(go_body(HEAD), "2026-11-01T01:00:00Z")
                veto = self._at("Hold.", "2026-11-01T02:00:00Z", state="CHANGES_REQUESTED")
                self.assertFalse(verdict_at_tip(
                    [go1, veto, self._at(body, "2026-11-01T03:00:00Z")], HEAD))

    def test_collaborator_go_on_owner_opened_pr_cannot_bypass_grader_refusal(self):
        # #779-3: a non-owner collaborator pushing grader edits onto an owner-opened base-repo PR
        # and posting VERDICT: GO must be refused; benign edits with collaborator GO still pass;
        # and a vetoed pre-veto OWNER GO followed by a collaborator GO is still refused.
        pr = {"number": 7, "head": {"sha": HEAD, "repo": {"full_name": "o/r"}},
              "base": {"ref": "main", "sha": "c" * 40, "repo": {"full_name": "o/r"}},
              "user": {"login": "o"}, "author_association": "OWNER", "changed_files": 1}
        collab_go = self._at(go_body(HEAD), "2026-11-01T03:00:00Z", state="APPROVED",
                             association="COLLABORATOR", login="collab")
        member_go = self._at(go_body(HEAD), "2026-11-01T03:00:00Z", state="APPROVED",
                             association="MEMBER", login="member")
        owner_go = self._at(go_body(HEAD), "2026-11-01T01:00:00Z", state="COMMENTED",
                            association="OWNER", login="o")
        veto = self._at("Re-check.", "2026-11-01T02:00:00Z", state="CHANGES_REQUESTED",
                        association="OWNER", login="o")

        def run_gate(reviews, files, compare_fail=False):
            posted = []

            def fake_api(path, repo, paginate=False):
                if path == "pulls/7":
                    return pr
                if path == "pulls/7/reviews":
                    return reviews
                if path.startswith("compare/"):
                    if compare_fail:
                        raise RuntimeError("gh api compare failed: HTTP 502")
                    return {"files": files}
                self.fail(f"unexpected API path {path}")

            def fake_run(cmd, **_kw):
                posted.append(dict(c.split("=", 1) for i, c in enumerate(cmd)
                                   if i and cmd[i - 1] == "-f"))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    mock.patch.object(verdict_check, "_gh_api", side_effect=fake_api), \
                    mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_run):
                code = verdict_check.main(["--pr", "7", "--repo", "o/r", "--post-status"])
            return code, posted, out.getvalue() + err.getvalue()

        grader_file = [{"filename": ".github/workflows/validate.yml", "status": "modified"}]
        benign_file = [{"filename": "docs/notes.md", "status": "modified"}]
        for reviews in ([collab_go], [member_go], [owner_go, veto, collab_go]):
            with self.subTest(reviews=len(reviews)):
                code, posted, out = run_gate(reviews, grader_file)
                self.assertEqual((code, posted[0]["state"]), (0, "failure"), out)
                self.assertIn("grader", posted[0]["description"])
                # Compare read failure also fails closed without an OWNER GO.
                code, posted, out = run_gate(reviews, benign_file, compare_fail=True)
                self.assertEqual((code, posted[0]["state"]), (0, "failure"), out)
                self.assertIn("cannot read", posted[0]["description"])
        # Benign edit on owner-opened PR with collaborator GO passes.
        code, posted, out = run_gate([collab_go], benign_file)
        self.assertEqual((code, posted[0]["state"]), (0, "success"), out)

    def test_duplicate_head_fork_prs_disambiguated_by_head_repo_and_branch(self):
        # #779-4: an attacker opening a second fork PR at the same head SHA must not DoS resolve.
        pulls = [
            {"number": 7, "head": {"sha": HEAD, "ref": "fix-bug",
                                   "repo": {"full_name": "alice/r"}}},
            {"number": 99, "head": {"sha": HEAD, "ref": "fix-bug",
                                    "repo": {"full_name": "attacker/r"}}},
            {"number": 100, "head": {"sha": HEAD, "ref": "other-branch",
                                     "repo": {"full_name": "alice/r"}}},
        ]
        with mock.patch.object(verdict_check, "_gh_api", return_value=pulls):
            self.assertEqual(
                verdict_check.pr_for_head(HEAD, "o/r", head_repo="ALICE/r", head_branch="fix-bug"),
                "7",
            )
            with self.assertRaises(RuntimeError):
                verdict_check.pr_for_head(HEAD, "o/r")
            with self.assertRaises(RuntimeError):
                verdict_check.pr_for_head(HEAD, "o/r", head_repo="alice/r")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(verdict_check, "_gh_api", return_value=pulls):
            code = verdict_check.main(["--head-sha", HEAD, "--resolve-pr", "--repo", "o/r",
                                       "--head-repo", "alice/r", "--head-branch", "fix-bug"])
        self.assertEqual((code, out.getvalue().strip()), (0, "7"), err.getvalue())
        # --head-repo/--head-branch without --head-sha is a usage error (exit 2).
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(verdict_check.main(["--pr", "7", "--repo", "o/r",
                                                 "--head-repo", "alice/r"]), 2)
        gate_yml = (_ROOT / ".github" / "workflows" / "verdict-gate.yml").read_text(encoding="utf-8")
        self.assertIn("RUN_HEAD_REPO: ${{ github.event.workflow_run.head_repository.full_name }}",
                      gate_yml)
        self.assertIn("RUN_HEAD_BRANCH: ${{ github.event.workflow_run.head_branch }}", gate_yml)
        self.assertIn('--head-repo "$RUN_HEAD_REPO" --head-branch "$RUN_HEAD_BRANCH"', gate_yml)

    def test_post_status_passes_timeout_and_wraps_timeout_expired(self):
        # #779-5: post_status must bound `gh api` with GH_API_TIMEOUT.
        seen = {}

        def fake_ok(cmd, **kw):
            seen["timeout"] = kw.get("timeout")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_ok):
            verdict_check.post_status("o/r", HEAD, "success", "ok")
        self.assertEqual(seen["timeout"], verdict_check.GH_API_TIMEOUT)

        def fake_hang(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

        with mock.patch.object(verdict_check.subprocess, "run", side_effect=fake_hang):
            with self.assertRaises(RuntimeError) as ctx:
                verdict_check.post_status("o/r", HEAD, "success", "ok")
        self.assertIn("gave no answer", str(ctx.exception))

    def test_vfbench_dir_and_config_files_are_guarded_grader_paths(self):
        # #770 + #769: bench/vf-bench/ (including new stdlib-shadow files) and tool config files
        # are grader paths that non-owner PRs cannot add or modify.
        for path in ("bench/vf-bench/hashlib.py", "bench/vf-bench/vfbench.py",
                     "bench/vf-bench/traps/new.json", "bench/vf-bench", "bench",
                     "ruff.toml", ".ruff.toml", ".coveragerc", ".gitleaks.toml",
                     ".gitleaksignore"):
            with self.subTest(path=path):
                self.assertTrue(verdict_check._is_grader(path), path)

    def test_no_workflow_targets_concurrency_1_codebuild_and_verdict_needs_relay(self):
        # #771: all concurrency-1 codebuild-gha-open-fleet-* jobs moved off CodeBuild to
        # ubuntu-latest, and verdict-check.yml serializes `verdict` after `relay`.
        wf_dir = _ROOT / ".github" / "workflows"
        for wf in sorted(wf_dir.glob("*.yml")):
            text = wf.read_text(encoding="utf-8")
            run_lines = [ln for ln in text.splitlines()
                         if ln.strip().startswith("runs-on:")]
            for ln in run_lines:
                with self.subTest(workflow=wf.name, line=ln.strip()):
                    self.assertNotIn("codebuild-gha-open-fleet", ln.split("#", 1)[0])
        vc = (wf_dir / "verdict-check.yml").read_text(encoding="utf-8")
        verdict_job = vc.split("\n  verdict:\n", 1)[1]
        self.assertIn("    needs: relay\n", verdict_job)


if __name__ == "__main__":
    unittest.main()
