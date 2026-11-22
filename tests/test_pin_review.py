#!/usr/bin/env python3
"""Contract tests for runtime/scripts/pin_review.py (#559).

The class boundaries are the security content: an instruction file landing
in `code`, or a hook landing outside `permission-surface`, is exactly how a
rug-pull hides in a bump diff. These tests pin the classifier and the CLI's
fail-closed exits.
"""
import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "runtime" / "scripts" / "pin_review.py"

_spec = importlib.util.spec_from_file_location("pin_review", SCRIPT)
pr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr)


class Classify(unittest.TestCase):
    def test_instruction_shapes(self):
        for path in ("skills/triage/SKILL.md", "AGENTS.md", "README.md",
                     "prompts/system.txt", "docs/guide.prompt", "cso/SKILL.md.tmpl"):
            self.assertEqual(pr.classify(path), "instruction", path)

    def test_permission_shapes(self):
        for path in ("hosts/claude/hooks/stop-hook.ts", ".claude-plugin/plugin.json",
                     "hooks/hooks.json", "package.json", "x/hook-extract.sh",
                     ".github/workflows/ci.yml"):
            self.assertEqual(pr.classify(path), "permission-surface", path)

    def test_code_shapes(self):
        for path in ("src/main.py", "lib/util.ts", "bin/tool"):
            self.assertEqual(pr.classify(path), "code", path)

    def test_hook_and_installer_executables_are_surface(self):
        # gstack 47d639ab shipped hooks as bin/ executables and installs via
        # a root `setup` that writes settings; both used to land in `code`.
        for path in ("bin/gstack-hook-check", "autoplan/bin/phase-publication-hook",
                     "plan-ceo-review/bin/mode-handoff-hook.ts", "setup", "setup.ps1",
                     "scripts/install.sh", "bin/gstack-capy-install"):
            self.assertEqual(pr.classify(path), "permission-surface", path)

    def test_hook_and_installer_tokens_spare_tests_and_prose(self):
        for path, klass in (("test/autoplan-publication-hook.test.ts", "permission-surface"),
                            ("test/helpers/install-fixture.ts", "permission-surface"),
                            ("docs/install.md", "instruction"),
                            ("qa/sections/browser-setup.md.tmpl", "instruction")):
            self.assertEqual(pr.classify(path), klass, path)

    def test_frontmatter_permission_keys(self):
        text = ("---\nname: x\nallowed-tools:\n  - Read\n  - Bash\n"
                "hooks:\n  PreToolUse:\n    - matcher: Read\n"
                "description: d\n---\n# body\nhooks: not frontmatter\n")
        self.assertEqual(pr.permission_keys(text), {
            "allowed-tools": "allowed-tools:\n  - Read\n  - Bash",
            "hooks": "hooks:\n  PreToolUse:\n    - matcher: Read",
        })
        self.assertEqual(pr.permission_keys("# no frontmatter\nhooks: x\n"), {})

    def test_quoted_frontmatter_keys_are_the_same_keys(self):
        text = ("---\n\"name\": x\n\"allowed-tools\":\n- Bash\n"
                "'hooks': {}\n\"description\": d\n---\n")
        self.assertEqual(pr.permission_keys(text), {
            "allowed-tools": '"allowed-tools":\n- Bash',
            "hooks": "'hooks': {}",
        })

    def test_hooks_win_over_markdown(self):
        # A Markdown file inside hooks/ ships beside executable hooks; it is
        # reviewed with the surface, not with prose.
        self.assertEqual(pr.classify("hooks/README.md"), "permission-surface")

    def test_slash_commands_are_instructions(self):
        # commands/*.toml (and the .gemini/.claude mirrors) are definitions
        # an agent executes on invocation, per the upstream audit — not code.
        for path in ("commands/build.toml", ".gemini/commands/build.toml",
                     ".claude/commands/build.md"):
            self.assertEqual(pr.classify(path), "instruction", path)


class CompletedReview(unittest.TestCase):
    GOOD = (
        "Verdict: clean\n\n"
        "Instruction changes read: two skill files, wording only.\n"
        "Permission-surface changes read: none.\n"
    )

    def test_completed_review_passes(self):
        self.assertEqual(pr.completed_review_problems(self.GOOD), [])

    def test_verdict_only_edit_fails(self):
        # Swapping UNREVIEWED for a verdict word while the note placeholders
        # stand is not a review.
        text = self.GOOD.replace("two skill files, wording only.", "<which>")
        self.assertTrue(pr.completed_review_problems(text))

    def test_unreviewed_and_unsupported_verdicts_fail(self):
        self.assertTrue(pr.completed_review_problems(
            self.GOOD.replace("clean", "UNREVIEWED")))
        self.assertTrue(pr.completed_review_problems(
            self.GOOD.replace("Verdict: clean", "Verdict: lgtm")))

    def test_large_bump_lists_every_path(self):
        grouped = {"instruction": [f"M doc-{i}.md" for i in range(61)],
                   "permission-surface": [], "code": []}
        text = pr.render("demo", "u", "a" * 40, "b" * 40, grouped, "2026-10-14")
        self.assertIn("- `M doc-60.md`", text)
        self.assertNotIn("by top-level directory", text)


def make_pack(tmp: Path):
    repo = tmp / "pack"
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "SKILL.md").write_text("# skill\n")
    (repo / "run.py").write_text("print(1)\n")
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
         "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
         "commit", "-q", "-m", "one"], check=True)
    first = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, check=True).stdout.strip()
    (repo / "SKILL.md").write_text("# skill v2\n")
    (repo / "hooks").mkdir()
    (repo / "hooks" / "hooks.json").write_text("{}\n")
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
         "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid",
         "commit", "-q", "-m", "two"], check=True)
    second = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    return repo, first, second


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        return subprocess.run([sys.executable, str(SCRIPT), *argv],
                              capture_output=True, text=True, timeout=60)

    def test_diff_classifies_bump(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, first, second = make_pack(Path(tmp))
            result = self.run_cli("--repo", str(repo), "--pack", "demo",
                                  "--from", first, "--to", second)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("### instruction (1)", result.stdout)
            self.assertIn("### permission-surface (1)", result.stdout)
            self.assertIn("Verdict: UNREVIEWED", result.stdout)

    def test_rename_out_of_hooks_lists_both_sides(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, first, _ = make_pack(Path(tmp))
            (repo / "hooks").mkdir(exist_ok=True)
            (repo / "hooks" / "session-start.sh").write_text("#!/bin/sh\n")
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "commit", "-q",
                            "-m", "hook"], check=True)
            hooked = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                    capture_output=True, text=True,
                                    check=True).stdout.strip()
            (repo / "scripts").mkdir()
            subprocess.run(["git", "-C", str(repo), "mv", "hooks/session-start.sh",
                            "scripts/session-start.sh"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "commit", "-q",
                            "-m", "move"], check=True)
            moved = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                   capture_output=True, text=True,
                                   check=True).stdout.strip()
            result = self.run_cli("--repo", str(repo), "--pack", "demo",
                                  "--from", hooked, "--to", moved)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("D hooks/session-start.sh", result.stdout)
            self.assertIn("### permission-surface (1)", result.stdout)

    def test_non_ascii_filename_keeps_its_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, first, _ = make_pack(Path(tmp))
            (repo / "café-guide.md").write_text("# café\n")
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "commit", "-q",
                            "-m", "café"], check=True)
            new = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                 capture_output=True, text=True,
                                 check=True).stdout.strip()
            result = self.run_cli("--repo", str(repo), "--pack", "demo",
                                  "--from", first, "--to", new)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("café-guide.md", result.stdout)
            self.assertIn("### instruction (2)", result.stdout)

    def test_skill_frontmatter_grant_joins_the_surface(self):
        # A skill that adds a hook or a tool grant in its own frontmatter
        # widens permissions though its path classes as instruction.
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, second = make_pack(Path(tmp))
            (repo / "SKILL.md").write_text(
                "---\nname: demo\nallowed-tools:\n  - Bash\n---\n# skill v3\n")
            (repo / "other").mkdir()
            (repo / "other" / "SKILL.md").write_text(
                "---\nname: other\ndescription: wording only\n---\n# o\n")
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "commit", "-q",
                            "-m", "grant"], check=True)
            new = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                 capture_output=True, text=True,
                                 check=True).stdout.strip()
            result = self.run_cli("--repo", str(repo), "--pack", "demo",
                                  "--from", second, "--to", new)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("- `M SKILL.md (frontmatter: allowed-tools)`", result.stdout)
            self.assertIn("### permission-surface (1)", result.stdout)
            self.assertNotIn("other/SKILL.md (frontmatter", result.stdout)

    def test_bad_commit_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, _ = make_pack(Path(tmp))
            result = self.run_cli("--repo", str(repo), "--pack", "demo",
                                  "--to", "0" * 40)
            self.assertEqual(result.returncode, 3)


class LibraryAndMain(unittest.TestCase):
    """The same contract through the library door. The subprocess Cli tests
    prove the argv wiring; these pin the functions tests/test_pins.py and
    the bumper's own scripting import, so a refactor of main() cannot move
    behavior without a test noticing."""

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = pr.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_changed_paths_diff_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, first, second = make_pack(Path(tmp))
            diff = {path: status
                    for status, path in pr.changed_paths(repo, first, second)}
            self.assertEqual(diff, {"SKILL.md": "M", "hooks/hooks.json": "A"})
            baseline = pr.changed_paths(repo, None, second)
            self.assertEqual(
                sorted(baseline),
                [("A", "SKILL.md"), ("A", "hooks/hooks.json"), ("A", "run.py")])

    def test_resolve_and_git_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, second = make_pack(Path(tmp))
            self.assertEqual(pr.resolve(repo, "HEAD"), second)
            with self.assertRaises(pr.PinReviewError):
                pr.resolve(repo, "0" * 40)

    def test_an_option_shaped_ref_is_refused_before_git_reads_it(self):
        # W2-04: `--to`/`--old` reached `rev-parse --verify <ref>^{commit}` in option position.
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, _ = make_pack(Path(tmp))
            for ref in ("--all", "-h", "--show-toplevel"):
                with self.subTest(ref=ref):
                    with self.assertRaises(pr.PinReviewError) as ctx:
                        pr.resolve(repo, ref)
                    self.assertIn("not an option", str(ctx.exception))

    def test_truncated_diff_stream_refuses(self):
        # A status token with no path behind it must not silently drop a
        # change from the review surface.
        original = pr._git
        pr._git = lambda repo, *argv: "M\0path.md\0D\0"
        try:
            with self.assertRaises(pr.PinReviewError):
                pr.changed_paths(Path("."), "a", "b")
        finally:
            pr._git = original

    def test_classify_changes_groups_and_sorts(self):
        grouped = pr.classify_changes(
            [("M", "b.md"), ("A", "hooks/h.json"), ("M", "a.md"),
             ("M", "src/x.py")])
        self.assertEqual(grouped["instruction"], ["M a.md", "M b.md"])
        self.assertEqual(grouped["permission-surface"], ["A hooks/h.json"])
        self.assertEqual(grouped["code"], ["M src/x.py"])

    def test_baseline_render_rolls_up_but_never_the_surface(self):
        grouped = {
            "instruction": [f"A docs-{i % 3}/doc-{i}.md" for i in range(61)],
            "permission-surface": [f"A hooks/{i}.json" for i in range(61)],
            "code": [],
        }
        text = pr.render("demo", "u", None, "b" * 40, grouped, "2026-10-14")
        self.assertIn("baseline inventory", text)
        self.assertIn("by top-level directory", text)
        self.assertIn("- `A hooks/60.json`", text)

    def test_main_bump_without_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, first, second = make_pack(Path(tmp))
            rc, out, _ = self.run_main("--repo", str(repo), "--pack", "demo",
                                       "--from", first, "--to", second)
            self.assertEqual(rc, 0)
            self.assertIn("Verdict: UNREVIEWED", out)
            self.assertIn("no origin remote", out)

    def test_main_baseline_with_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, second = make_pack(Path(tmp))
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin",
                            "https://example.invalid/pack.git"], check=True)
            rc, out, _ = self.run_main("--repo", str(repo), "--pack", "demo",
                                       "--to", second)
            self.assertEqual(rc, 0)
            self.assertIn("baseline inventory", out)
            self.assertIn("https://example.invalid/pack.git", out)

    def test_main_bad_commit_cannot_evaluate(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, _ = make_pack(Path(tmp))
            rc, _, err = self.run_main("--repo", str(repo), "--pack", "demo",
                                       "--to", "0" * 40)
            self.assertEqual(rc, 3)
            self.assertIn("pin_review:", err)

    def test_git_timeout_is_cannot_evaluate_not_traceback(self):
        # A slow on-demand fetch (blobless clone) must surface as the
        # documented cannot-evaluate, not a raw TimeoutExpired (PR #566 P2).
        def slow(*argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd="git", timeout=120)

        original = pr.subprocess.run
        pr.subprocess.run = slow
        try:
            with self.assertRaises(pr.PinReviewError):
                pr._git(Path("."), "rev-parse", "HEAD")
        finally:
            pr.subprocess.run = original


class ArtifactKind(unittest.TestCase):
    """Baseline verdicts belong to the initial inventories only; every
    later pin is a bump and must carry a diff span to the pinned commit
    (PR #566 review, P1)."""

    BUMP = "a" * 40
    OLD = "b" * 40

    def bump_text(self, verdict="clean", span=True, new=None):
        span_line = f"`{self.OLD}` → `{new or self.BUMP}`" if span else "x"
        return f"Verdict: {verdict}\n{span_line}\n"

    def test_shipped_baselines_pass(self):
        for name in pr.BASELINE_ARTIFACTS:
            self.assertEqual(
                pr.artifact_kind_problems(
                    "Verdict: baseline recorded\n", name, "c" * 40), [], name)

    def test_baseline_artifact_needs_baseline_verdict(self):
        name = sorted(pr.BASELINE_ARTIFACTS)[0]
        self.assertTrue(pr.artifact_kind_problems(
            self.bump_text(), name, "c" * 40))

    def test_bump_with_span_to_the_pin_passes(self):
        self.assertEqual(pr.artifact_kind_problems(
            self.bump_text(), "demo-x.md", self.BUMP), [])
        # Abbreviated pin against a full span, and the reverse.
        self.assertEqual(pr.artifact_kind_problems(
            self.bump_text(), "demo-x.md", self.BUMP[:8]), [])

    def test_bump_cannot_wear_a_baseline_verdict(self):
        problems = pr.artifact_kind_problems(
            self.bump_text(verdict="baseline recorded"), "demo-x.md", self.BUMP)
        self.assertTrue(any("bump must review the diff" in p for p in problems))

    def test_bump_without_span_or_to_wrong_commit_fails(self):
        self.assertTrue(pr.artifact_kind_problems(
            self.bump_text(span=False), "demo-x.md", self.BUMP))
        self.assertTrue(pr.artifact_kind_problems(
            self.bump_text(new="d" * 40), "demo-x.md", self.BUMP))


class SecurityHardening787(unittest.TestCase):
    """Regression tests for #766 + #787 hardening in pin_review.py."""

    def test_test_paths_with_hook_or_install_tokens_are_permission_surface(self):
        for path in ("test/autoplan-publication-hook.test.ts",
                     "tests/helpers/install-fixture.py",
                     "fixtures/pre-hook.sh",
                     "tests/setup-tool.ts"):
            self.assertEqual(pr.classify(path), "permission-surface", path)
        for path in ("test/math.test.ts", "tests/test_parser.py", "fixtures/sample.py"):
            self.assertEqual(pr.classify(path), "code", path)

    def test_permission_keys_handles_bom_trailing_spaces_and_quoted_delimiters(self):
        bom_and_spaces = (
            "\ufeff---   \n"
            "name: demo\n"
            "description: \"first line\n---\nsecond line\"\n"
            "note: 'another\n---\nquoted line'\n"
            "summary: user's guide\n"
            "tools:\n  - Bash\n"
            "permissionMode: bypassPermissions\n"
            "mcpServers:\n  evil: {}\n"
            "hooks:\n  PreToolUse: []\n"
            "---  \n"
            "# body\n"
            "allowed-tools: [NotFrontmatter]\n"
        )
        found = pr.permission_keys(bom_and_spaces)
        self.assertEqual(set(found), {"tools", "permissionMode", "mcpServers", "hooks"})
        self.assertNotIn("allowed-tools", found)

    def test_frontmatter_permission_changes_covers_commands_agents_and_templates(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, base = make_pack(Path(tmp))
            files = {
                ".claude/commands/run.md": "---\nname: run\ntools:\n  - Bash\n---\n# cmd\n",
                ".claude/agents/reviewer.md": "---\nname: rev\npermissionMode: acceptEdits\n---\n# ag\n",
                "skills/demo/SKILL.md.tmpl": "---\nname: demo\nmcpServers:\n  srv: {}\n---\n# tmpl\n",
                "docs/notes.md": "---\nhooks: ignored-non-surface-doc\n---\n# note\n",
            }
            for rel, content in files.items():
                p = repo / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t",
                            "-c", "user.email=t@t.invalid", "commit", "-q", "-m", "fm"], check=True)
            head = pr.resolve(repo, "HEAD")
            changes = pr.changed_paths(repo, base, head)
            entries = pr.frontmatter_permission_changes(repo, base, head, changes)
            self.assertIn("A .claude/commands/run.md (frontmatter: tools)", entries)
            self.assertIn("A .claude/agents/reviewer.md (frontmatter: permissionMode)", entries)
            self.assertIn("A skills/demo/SKILL.md.tmpl (frontmatter: mcpServers)", entries)
            self.assertFalse(any("docs/notes.md" in e for e in entries), entries)

    def test_git_and_show_route_through_gitexec_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo, _, head = make_pack(Path(tmp))
            seen = []
            real_run = pr.subprocess.run

            def spy(argv, *args, **kwargs):
                seen.append((list(argv), dict(kwargs)))
                return real_run(argv, *args, **kwargs)

            pr.subprocess.run = spy
            try:
                pr._git(repo, "rev-parse", "HEAD")
                blob = pr._show(repo, head, "SKILL.md")
            finally:
                pr.subprocess.run = real_run
            self.assertIsNotNone(blob)
            self.assertEqual(len(seen), 2)
            for argv, kwargs in seen:
                self.assertEqual(argv[0], str(pr.gitexec.GIT))
                self.assertEqual(kwargs.get("stdin"), subprocess.DEVNULL)
                env = kwargs.get("env") or {}
                self.assertEqual(env.get("GIT_CONFIG_NOSYSTEM"), "1")
                self.assertEqual(env.get("GIT_NO_REPLACE_OBJECTS"), "1")
                self.assertIn("core.hooksPath", env.values())


if __name__ == "__main__":
    unittest.main()
