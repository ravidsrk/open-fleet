#!/usr/bin/env python3
"""Contract tests for runtime/scripts/search_sessions.py (S19).

`orca search` with an --index-status precheck: a disabled or
degraded/closed index refuses before the query runs (exit 2, the query
never fires); a healthy index proceeds with validated flags. Non-results
answers (stale/malformed cursor, unavailable) are failures, never empty
results.
"""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "runtime" / "scripts" / "search_sessions.py"

HEALTHY = {"enabled": True, "phase": "current", "filesIndexed": 10,
           "filesDue": 0, "filesFailed": 0, "degradedRoots": [],
           "lastReconcileAt": 1, "lastSweepCompletedAt": 1, "generation": 3}

RESULTS = {"kind": "results", "hits": [{"sessionId": "s1"}, {"sessionId": "s2"}],
           "page": {"cursor": "c9", "hasMore": True}, "generation": 3,
           "truncated": {"candidates": False, "snippets": 0, "query": False,
                         "freshness": False}, "durationMs": 12}


def load():
    spec = importlib.util.spec_from_file_location("search_sessions", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_cli(args, status=None, results=None):
    with tempfile.TemporaryDirectory() as tmp:
        st = Path(tmp) / "status.json"
        st.write_text(json.dumps({"result": status if status is not None
                                  else HEALTHY}))
        rs = Path(tmp) / "results.json"
        rs.write_text(json.dumps({"result": results if results is not None
                                  else RESULTS}))
        log = Path(tmp) / "calls.log"
        stub = Path(tmp) / "orca"
        stub.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> \"{log}\"\n"
            'case "$*" in\n'
            f'  *index-status*) cat "{st}" ;;\n'
            f'  *) cat "{rs}" ;;\n'
            "esac\n")
        stub.chmod(0o755)
        env = {"PATH": f"{tmp}:/usr/bin:/bin", "ORCA_CLI_COMMAND": "orca"}
        p = subprocess.run(["python3", str(SCRIPT), *args], env=env,
                           capture_output=True, text=True)
        calls = log.read_text() if log.exists() else ""
        return p.returncode, p.stdout, p.stderr, calls


class TestPrecheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load()

    def test_healthy_phases_pass(self):
        for phase in ("current", "idle", "indexing"):
            status = dict(HEALTHY, phase=phase)
            self.assertEqual(self.m.check_index(status), phase)

    def test_disabled_refused(self):
        with self.assertRaises(self.m.Refused):
            self.m.check_index(dict(HEALTHY, enabled=False))

    def test_bad_phases_refused(self):
        for phase in ("degraded", "closed", "bogus"):
            with self.subTest(phase=phase), self.assertRaises(self.m.Refused):
                self.m.check_index(dict(HEALTHY, phase=phase))

    def test_absent_fields_refused(self):
        with self.assertRaises(self.m.Refused):
            self.m.check_index({"phase": "current"})
        with self.assertRaises(self.m.Refused):
            self.m.check_index("not-an-object")


class TestArgv(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load()

    def test_argv_full(self):
        argv = self.m.build_search_argv(self.m.parse_args(
            ["my query", "--scope", "conversation", "--fresh", "--limit", "50",
             "--cursor", "c", "--agent", "claude", "--agent", "codex",
             "--path", "/a", "--since", "2026-08-01T00:00:00Z",
             "--sort", "newest", "--debug", "--environment", "env",
             "--pairing-code", "pc"]))
        self.assertEqual(argv, ["search", "my query", "--scope", "conversation",
                                "--fresh", "--limit", "50", "--cursor", "c",
                                "--agent", "claude", "--agent", "codex",
                                "--path", "/a",
                                "--since", "2026-08-01T00:00:00Z",
                                "--sort", "newest", "--debug",
                                "--environment", "env", "--pairing-code", "pc"])

    def test_query_flag_form(self):
        argv = self.m.build_search_argv(
            self.m.parse_args(["--query", "q words"]))
        self.assertEqual(argv, ["search", "--query", "q words"])

    def test_missing_query_refused(self):
        with self.assertRaises(self.m.Refused):
            self.m.build_search_argv(self.m.parse_args([]))

    def test_query_and_flag_together_refused(self):
        with self.assertRaises(self.m.Refused):
            self.m.build_search_argv(
                self.m.parse_args(["q", "--query", "q2"]))

    def test_bad_scope_sort_refused(self):
        with self.assertRaises(self.m.Refused):
            self.m.build_search_argv(self.m.parse_args(["q", "--scope", "x"]))
        with self.assertRaises(self.m.Refused):
            self.m.build_search_argv(self.m.parse_args(["q", "--sort", "x"]))

    def test_limit_range_is_1_to_100(self):
        for bad in ("0", "101", "abc"):
            with self.subTest(bad=bad), self.assertRaises(self.m.Refused):
                self.m.build_search_argv(self.m.parse_args(
                    ["q", "--limit", bad]))

    def test_bad_since_refused(self):
        with self.assertRaises(self.m.Refused):
            self.m.build_search_argv(
                self.m.parse_args(["q", "--since", "yesterday"]))


class TestCli(unittest.TestCase):
    def test_search_runs_precheck_then_query(self):
        rc, out, err, calls = run_cli(["flaky test"])
        self.assertEqual(rc, 0, err)
        self.assertIn("PRECHECK=ok phase=current", out)
        self.assertIn("HITS=2", out)
        self.assertIn("NEXT_CURSOR=c9", out)
        lines = calls.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("index-status", lines[0])
        self.assertIn("search flaky test", lines[1])

    def test_results_print_bounded_snippets(self):
        rc, out, err, _c = run_cli(["flaky test"], results={
            "kind": "results",
            "hits": [
                {"sessionId": "s1", "title": "Resize race", "score": 12.5,
                 "evidence": {"snippet": "the resize handler drops it",
                             "role": "assistant"}},
                {"sessionId": "s2", "title": "Other", "score": 3.0,
                 "evidence": {"snippet": "y" * 600, "role": "user"}}],
            "page": {"cursor": "none", "hasMore": False}})
        self.assertEqual(rc, 0, err)
        self.assertIn("HIT s1 score=12.5 Resize race", out)
        self.assertIn("SNIPPET [assistant]: the resize handler drops it", out)
        self.assertIn("[truncated 100 chars]", out)
        self.assertNotIn("y" * 600, out)

    def test_hit_without_evidence_prints_none(self):
        rc, out, err, _c = run_cli(["flaky test"], results={
            "kind": "results", "hits": [{"sessionId": "s1"}],
            "page": {"cursor": "none", "hasMore": False}})
        self.assertEqual(rc, 0, err)
        self.assertIn("HIT s1 score=? (untitled)", out)
        self.assertIn("SNIPPET: (none)", out)

    def test_snippet_prints_inert(self):
        rc, out, err, _c = run_cli(["flaky test"], results={
            "kind": "results",
            "hits": [{"sessionId": "s1", "title": "t",
                      "score": 1.0,
                      "evidence": {"snippet": "\x1b[2Kx",
                                  "role": "assistant"}}],
            "page": {"cursor": "none", "hasMore": False}})
        self.assertEqual(rc, 0, err)
        self.assertIn("\\x1b", out)
        self.assertNotIn("\x1b", out)

    def test_precheck_only_runs_no_query(self):
        rc, out, err, calls = run_cli(["--precheck-only"])
        self.assertEqual(rc, 0, err)
        self.assertIn("PRECHECK=ok", out)
        self.assertNotIn("HITS=", out)
        self.assertEqual(len(calls.splitlines()), 1)

    def test_degraded_index_refuses_before_query(self):
        status = dict(HEALTHY, phase="degraded")
        rc, _o, err, calls = run_cli(["q"], status=status)
        self.assertEqual(rc, 2, err)
        self.assertIn("REFUSED", err)
        self.assertIn("degraded", err)
        self.assertEqual(len(calls.splitlines()), 1)

    def test_stale_cursor_is_a_failure(self):
        rc, _o, err, _c = run_cli(
            ["q"], results={"kind": "stale-cursor", "generation": 3})
        self.assertEqual(rc, 1, err)
        self.assertIn("stale-cursor", err)

    def test_unavailable_is_a_failure(self):
        rc, _o, err, _c = run_cli(
            ["q"], results={"kind": "unavailable", "reason": "disabled"})
        self.assertEqual(rc, 1, err)
        self.assertIn("unavailable", err)

    def test_refusal_exits_2(self):
        rc, _o, err, calls = run_cli(["q", "--limit", "500"])
        self.assertEqual(rc, 2, err)
        self.assertIn("REFUSED", err)
        self.assertEqual(calls, "")


class TestEpisodicHint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load()

    def test_episodic_hint_matches_run_manifests_and_caps_at_15_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            r1 = runs_dir / "2026-10-01-clean-sweep-550"
            r1.mkdir(parents=True)
            (r1 / "manifest.json").write_text(json.dumps({
                "units": [
                    {
                        "id": f"U{i}",
                        "status": "verified" if i % 2 == 0 else "parked",
                        "files_touched": ["runtime/scripts/watchdog.py"],
                        "parking_reason": "needs-human: env gate" if i % 2 == 1 else "",
                        "intent": {"invariant": f"invariant {i}"},
                    }
                    for i in range(1, 20)
                ]
            }))
            lines = self.m.build_episodic_hint(
                ["runtime/scripts/*"], runs_dir=str(runs_dir))
            self.assertLessEqual(len(lines), 15)
            joined = "\n".join(lines)
            self.assertIn("EPISODIC_HINT:", joined)
            self.assertIn("PRIOR_RUNS=19 SESSION_HITS=0", joined)
            self.assertIn("2026-10-01-clean-sweep-550 / U1 (parked)", joined)

    def test_episodic_hint_cli_without_query_runs_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            r1 = runs_dir / "2026-10-02-ship-it-100"
            r1.mkdir(parents=True)
            (r1 / "manifest.json").write_text(json.dumps({
                "units": [{
                    "id": "U-auth",
                    "status": "verified",
                    "files_touched": ["src/auth/token.py"],
                    "intent": {"invariant": "refresh token rotates once"},
                }]
            }))
            rc, out, err, calls = run_cli([
                "--episodic-hint",
                "--path", "src/auth/*",
                "--runs-dir", str(runs_dir),
            ])
            self.assertEqual(rc, 0, err)
            self.assertEqual(calls, "")
            self.assertIn("EPISODIC_HINT:", out)
            self.assertIn("U-auth (verified)", out)
            self.assertIn("refresh token rotates once", out)

    def test_episodic_hint_refuses_when_neither_path_nor_query_given(self):
        rc, _out, err, calls = run_cli(["--episodic-hint"])
        self.assertEqual(rc, 2, err)
        self.assertIn("REFUSED", err)
        self.assertEqual(calls, "")

    def test_episodic_hint_matches_real_archived_manifest(self):
        lines = self.m.build_episodic_hint(
            ["runtime/scripts/verify.py"],
            runs_dir=str(ROOT / "docs" / "runs"),
        )
        joined = "\n".join(lines)
        self.assertLessEqual(len(joined.splitlines()), 15)
        self.assertIn("prove-it-2026-09-16-PF-2", joined)

    def test_episodic_hint_folds_embedded_newlines(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            r1 = runs_dir / "2026-10-05-run"
            r1.mkdir(parents=True)
            (r1 / "manifest.json").write_text(json.dumps({
                "unit": "U-multi\nline",
                "files_touched": ["src/app.py"],
                "parking_reason": "line1\nline2\nline3",
            }))
            lines = self.m.build_episodic_hint(
                ["src/app.py"],
                runs_dir=str(runs_dir),
                session_hits=[{
                    "sessionId": "s1\ns2",
                    "title": "title1\ntitle2",
                    "evidence": {"snippet": "snip1\nsnip2"},
                }],
            )
            joined = "\n".join(lines)
            self.assertEqual(len(joined.splitlines()), len(lines))
            self.assertLessEqual(len(joined.splitlines()), 15)

    def test_episodic_hint_malformed_hits_fails(self):
        rc, _out, err, _calls = run_cli(
            ["--episodic-hint", "flaky", "--path", "src/app.py"],
            results={"kind": "results", "hits": "not-a-list"},
        )
        self.assertEqual(rc, 1, err)
        self.assertIn("search results answer names no hits", err)

    def test_disjoint_directories_with_same_basename_do_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            r1 = runs_dir / "2026-10-06-run"
            r1.mkdir(parents=True)
            (r1 / "manifest.json").write_text(json.dumps({
                "unit": "U-billing",
                "head_sha": "a" * 40,
                "files_touched": ["services/billing/index.ts"],
            }))
            no_match = "\n".join(self.m.build_episodic_hint(
                ["services/auth/index.ts"], runs_dir=str(runs_dir)))
            self.assertIn("PRIOR_RUNS=0", no_match)
            match = "\n".join(self.m.build_episodic_hint(
                ["services/billing/index.ts"], runs_dir=str(runs_dir)))
            self.assertIn("U-billing (recorded)", match)
            self.assertNotIn("(verified)", match)


if __name__ == "__main__":
    unittest.main()
