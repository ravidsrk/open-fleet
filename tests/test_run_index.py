#!/usr/bin/env python3
"""The run-archive index as one row file per run (scripts/run_index.py; CI speed and bookkeeping).

docs/runs/README.md's table took one hand-written row per run and its "N reports read yes"
summary was retyped beside it, so two PRs that each filed a run conflicted, and the hand-kept
counts drifted (the "no" breakdown named three pin-it rows; the table held ten). These pin the
replacement: one docs/runs/index/<run>.json per dated report, every rule a row file must meet,
a rendering that is a pure function of the row files, a README block that may lag between
releases but never contradicts itself, and the cut's exact re-render.

    python3 -m unittest tests.test_run_index -v
"""
import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "run_index.py"


def load(path=SCRIPT, name="_run_index_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ri = load()


def row(report, date="2026-01-02", binds="no — a reason", **extra):
    data = {"date": date, "report": report, "mission": f"[demo-it]({report})",
            "target": "this repo", "ran_as": "self-run", "binds": binds, "outcome": "DONE"}
    if binds.startswith("yes"):
        data["summary"] = f"the {date} demo-it run"
    data.update(extra)
    return data


def make_root(tmp, reports=("2026-01-02-demo-it-self-run.md", "2026-01-03-demo-it-run/")):
    """docs/runs/ with the given reports, one valid row each, and a README with empty markers."""
    root = Path(tmp)
    runs = root / "docs" / "runs"
    (runs / "index").mkdir(parents=True)
    for report in reports:
        if report.endswith("/"):
            (runs / report).mkdir()
            (runs / report / "README.md").write_text("# run\n", encoding="utf-8")
        else:
            (runs / report).write_text("# run\n", encoding="utf-8")
        write_row(root, row(report, date=report[:10]))
    (runs / "README.md").write_text(f"# Run archive\n\nIntro.\n\n{ri.BEGIN}\n{ri.END}\n\nAfter.\n",
                                    encoding="utf-8")
    return root


def write_row(root, data, name=None):
    name = name or ri.row_key(data["report"]) + ".json"
    path = Path(root) / "docs" / "runs" / "index" / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class TheLiveIndex(unittest.TestCase):
    def test_every_dated_report_has_exactly_one_well_formed_row(self):
        self.assertGreaterEqual(len(ri.dated_reports(ROOT)), 28)
        self.assertEqual(ri.check_rows(ROOT), [])

    def test_the_committed_snapshot_is_consistent_with_itself(self):
        self.assertEqual(ri.check_snapshot(ROOT), [])

    def test_the_rendering_links_every_dated_report(self):
        rows, errors = ri.load_rows(ROOT)
        self.assertEqual(errors, [])
        rendered = ri.render(rows, "2026-10-24")
        for report in ri.dated_reports(ROOT):
            with self.subTest(report=report):
                self.assertIn(f"({report})", rendered)

    def test_the_count_is_the_tables_own(self):
        rows, _ = ri.load_rows(ROOT)
        yes = sum(1 for r in rows if r["binds"].startswith("yes"))
        self.assertIn(f"{yes} of the {len(rows)} reports in the archive read **yes**:",
                      ri.render(rows, "2026-10-24"))


class RowLinksResolve(unittest.TestCase):
    """PR #670 review (P2, PRRT_kwDOTWxN9c6v5pBs): row_errors checked the report exists but not the
    links in a row's cells, and the README stays unchanged between releases, so a dead link in a new
    row passed CI and only broke the next release. Every relative link resolves from docs/runs/."""

    def test_a_dead_link_in_any_cell_is_refused(self):
        report = "2026-01-02-demo-it-self-run.md"
        for cell in ("target", "outcome"):
            with self.subTest(cell=cell), tempfile.TemporaryDirectory() as tmp:
                root = make_root(tmp)
                write_row(root, row(report, **{cell: "see [inventory](missing.md)"}))
                errors = ri.check_rows(root)
                self.assertTrue(any("missing.md" in e and "does not resolve" in e for e in errors),
                                f"{cell}: {errors}")
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write_row(root, row(report, binds="yes", summary="the run, [notes](gone/notes.md)"))
            self.assertTrue(any("gone/notes.md" in e for e in ri.check_rows(root)))

    def test_live_links_anchors_and_urls_pass(self):
        report = "2026-01-02-demo-it-self-run.md"
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write_row(root, row(report, target="[the other run](2026-01-03-demo-it-run/)",
                                outcome="[spec](https://example.invalid/x) [top](#runs) "
                                        f"[report]({report}#section)"))
            self.assertEqual(ri.check_rows(root), [])


class RowCellsHoldMarkdownLinksOnly(unittest.TestCase):
    """PR #670 review (P2): RowLinksResolve checks Markdown links, so an HTML link in a cell
    escaped it and broke the README at the cut. A row cell carries Markdown links only."""

    def test_an_html_link_in_a_cell_is_refused(self):
        report = "2026-01-02-demo-it-self-run.md"
        for text in ('<a href="missing.md">inventory</a>', "<img src='x.png'>",
                     '<a title=">" href="missing.md">notes</a>', "<a title='>' src='x.png'>",
                     '<a\nhref="missing.md">split</a>'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                root = make_root(tmp)
                write_row(root, row(report, outcome=text.replace("\n", " ")))
                errors = ri.check_rows(root)
                self.assertTrue(any("Markdown link" in e for e in errors), f"{text}: {errors}")


class RowFilesAreHeldToTheTableShape(unittest.TestCase):
    def test_a_clean_fixture_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            self.assertEqual(ri.check_rows(root), [])

    def test_each_broken_row_is_refused_with_its_reason(self):
        report = "2026-01-02-demo-it-self-run.md"
        cases = {
            "missing cell": ({k: v for k, v in row(report).items() if k != "outcome"}, "missing or empty"),
            "empty cell": (row(report, target=" "), "missing or empty"),
            "unknown key": (row(report, notes="x"), "unknown keys"),
            "bad date": (row(report, date="2026-02-30"), "is not YYYY-MM-DD"),
            "report gone": (row("2026-01-02-gone.md"), "is not a run report"),
            "nested report": (row("2026-01-03-demo-it-run/README.md"), "is not a run report"),
            "unlinked": (row(report, mission="[demo-it](other.md)"), "does not link"),
            "pipe": (row(report, outcome="a | b"), "breaks the table"),
            "newline": (row(report, target="a\nb"), "breaks the table"),
            "binds word": (row(report, binds="maybe"), "opens with 'yes' or 'no'"),
            "yes, no summary": ({**row(report, binds="yes"), "summary": ""}, "needs the summary"),
            "no with summary": (row(report, summary="x"), "only a row that binds"),
            "order": (row(report, order=-1), "non-negative integer"),
            "order bool": (row(report, order=True), "non-negative integer"),
        }
        for label, (data, why) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                root = make_root(tmp)
                write_row(root, data, name=ri.row_key(report) + ".json")
                errors = ri.check_rows(root)
                self.assertTrue(any(why in e for e in errors), f"{label}: {errors}")

    def test_files_that_are_not_rows_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            index = root / "docs" / "runs" / "index"
            (index / "notes.md").write_text("x", encoding="utf-8")
            (index / "broken.json").write_text("{", encoding="utf-8")
            (index / "list.json").write_text("[]", encoding="utf-8")
            write_row(root, row("2026-01-02-demo-it-self-run.md"), name="misnamed.json")
            errors = "\n".join(ri.check_rows(root))
            self.assertIn("notes.md: only <run>.json", errors)
            self.assertIn("broken.json: unreadable", errors)
            self.assertIn("list.json: a row file is one JSON object", errors)
            self.assertIn("misnamed.json: name the file after its report", errors)

    def test_completeness_both_ways(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            (root / "docs" / "runs" / "2026-01-04-demo-it-new.md").write_text("# new\n")
            errors = ri.check_rows(root)
            self.assertEqual(errors, ["docs/runs/2026-01-04-demo-it-new.md has no row: add "
                                      "docs/runs/index/2026-01-04-demo-it-new.json"])
            # Not a dated report: a campaign directory and the archive's own README need no row.
            (root / "docs" / "runs" / "campaign-2026-01-05-demo-it").mkdir()
            (root / "docs" / "runs" / "2026-01-06-no-readme").mkdir()
            write_row(root, row("2026-01-04-demo-it-new.md"))
            self.assertEqual(ri.check_rows(root), [])


class TheRendering(unittest.TestCase):
    def test_rows_sort_by_date_then_order_then_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp, reports=("2026-01-02-b.md", "2026-01-02-a.md", "2026-01-01-z.md"))
            write_row(root, row("2026-01-02-b.md", date="2026-01-02", order=1))
            write_row(root, row("2026-01-02-a.md", date="2026-01-02", order=2,
                                binds="yes — binds"))
            rows, errors = ri.load_rows(root)
            self.assertEqual(errors, [])
            self.assertEqual([r["report"] for r in rows],
                             ["2026-01-01-z.md", "2026-01-02-b.md", "2026-01-02-a.md"])
            block = ri.render(rows, "2026-02-01")
            self.assertTrue(block.startswith(ri.BEGIN + "\n") and block.endswith("\n" + ri.END))
            self.assertIn("as of 2026-02-01", block)
            self.assertIn("1 of the 3 reports in the archive read **yes**:\n"
                          "- the 2026-01-02 demo-it run.\n", block)
            self.assertIn(ri.HEADER + "\n| 2026-01-01 | [demo-it](2026-01-01-z.md) |", block)
            self.assertEqual(block, ri.render(rows, "2026-02-01"))

    def test_write_then_current_then_a_new_run_makes_it_stale_not_inconsistent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            self.assertTrue(ri.check_current(root), "an empty block passed as current")
            self.assertEqual(ri.write("2026-02-01", root), 2)
            text = (root / "docs" / "runs" / "README.md").read_text(encoding="utf-8")
            self.assertTrue(text.startswith("# Run archive\n\nIntro.\n\n" + ri.BEGIN))
            self.assertTrue(text.endswith(ri.END + "\n\nAfter.\n"))
            self.assertEqual(ri.check_current(root), [])
            self.assertEqual(ri.check_snapshot(root), [])
            # A PR files a run: row file only. The block lags (stale for a cut), yet stays
            # consistent with itself, so the PR passes without touching the README.
            (root / "docs" / "runs" / "2026-01-09-demo-it-later.md").write_text("# later\n")
            write_row(root, row("2026-01-09-demo-it-later.md", binds="yes — binds"))
            self.assertEqual(ri.check_rows(root), [])
            self.assertEqual(ri.check_snapshot(root), [])
            self.assertTrue(any("is not the rendering" in e for e in ri.check_current(root)))
            ri.write("2026-02-02", root)
            self.assertEqual(ri.check_current(root), [])

    def test_a_hand_edited_snapshot_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            ri.write("2026-02-01", root)
            readme = root / "docs" / "runs" / "README.md"
            good = readme.read_text(encoding="utf-8")
            first = [ln for ln in good.split("\n") if ln.startswith("| 2")][0]
            for label, text, why in (
                    ("count", good.replace("0 of the 2 reports", "1 of the 2 reports"), "says 1 of 2"),
                    ("duplicate row", good.replace(first, first + "\n" + first), "twice"),
                    ("no stamp", good.replace("as of 2026-02-01", "lately"), "no 'as of' date"),
                    ("no markers", good.replace(ri.BEGIN, ""), "no generated run-index block")):
                with self.subTest(case=label):
                    readme.write_text(text, encoding="utf-8")
                    errors = ri.check_snapshot(root)
                    self.assertTrue(any(why in e for e in errors), f"{label}: {errors}")
            readme.write_text(good, encoding="utf-8")
            (root / "docs" / "runs" / "2026-01-02-demo-it-self-run.md").unlink()
            self.assertTrue(any("not a run report" in e for e in ri.check_snapshot(root)))

    def test_a_tree_without_the_archive_reports_rather_than_raises(self):
        """validate.py runs this beside later gates (the quarantine gate among them), so a tree
        with no docs/runs/ must get an error line, never a traceback that ends validate early
        (tests/test_validate_wiring.py's partial copy caught exactly that)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(ri.check_rows(root), [])
            self.assertIn("is missing", ri.check_snapshot(root)[0])
            self.assertIn("is missing", ri.check_current(root)[0])
            with self.assertRaises(ValueError):
                ri.write("2026-02-01", root)

    def test_write_refuses_bad_rows_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            readme = root / "docs" / "runs" / "README.md"
            before = readme.read_text(encoding="utf-8")
            write_row(root, row("2026-01-02-demo-it-self-run.md", binds="perhaps"))
            with self.assertRaises(ValueError):
                ri.write("2026-02-01", root)
            self.assertEqual(readme.read_text(encoding="utf-8"), before)


class TheCommandLine(unittest.TestCase):
    def run_cli(self, root, *args):
        """run_index.main in this process, ROOT pointed at the fixture (so coverage sees it)."""
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(ri, "ROOT", root), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            rc = ri.main(list(args))
        return subprocess.CompletedProcess(args, rc, out.getvalue(), err.getvalue())

    def test_it_runs_as_a_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            (root / "scripts").mkdir()
            shutil.copy2(SCRIPT, root / "scripts" / "run_index.py")
            ri.write("2026-02-01", root)
            r = subprocess.run([sys.executable, str(root / "scripts" / "run_index.py"), "check"],
                               cwd=root, capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("run index: 2 reports, one row each", r.stdout)

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            (root / "scripts").mkdir()
            shutil.copy2(SCRIPT, root / "scripts" / "run_index.py")
            self.assertEqual(self.run_cli(root, "check", "--current").returncode, 1)
            self.assertEqual(self.run_cli(root, "write", "--as-of", "2026-13-01").returncode, 2)
            w = self.run_cli(root, "write", "--as-of", "2026-02-01")
            self.assertEqual(w.returncode, 0, w.stderr)
            self.assertIn("rendered from 2 row files, as of 2026-02-01", w.stdout)
            c = self.run_cli(root, "check", "--current")
            self.assertEqual(c.returncode, 0, c.stdout + c.stderr)
            p = self.run_cli(root, "print")
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("0 of the 2 reports", p.stdout)
            (root / "docs" / "runs" / "2026-01-07-demo-it-x.md").write_text("# x\n")
            c = self.run_cli(root, "check")
            self.assertEqual(c.returncode, 1, c.stdout)
            self.assertIn("FAIL docs/runs/2026-01-07-demo-it-x.md has no row", c.stdout)

    def test_validate_reports_a_missing_row(self):
        spec = importlib.util.spec_from_file_location("_validate_ri", ROOT / "scripts" / "validate.py")
        validate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validate)
        self.assertEqual(validate.check_run_index(), [])
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            (root / "scripts").mkdir()
            shutil.copy2(SCRIPT, root / "scripts" / "run_index.py")
            ri.write("2026-02-01", root)
            (root / "docs" / "runs" / "2026-01-07-demo-it-x.md").write_text("# x\n")
            with mock.patch.object(validate, "ROOT", root):
                errors = validate.check_run_index()
            self.assertEqual(len(errors), 1, errors)
            self.assertIn("2026-01-07-demo-it-x.md has no row", errors[0])


class OnlyACompleteLinkTagIsRefusedInACell(unittest.TestCase):
    """Codex at 54fe725bee: `x<a ... href=value` with no tag closed, and `<span data-href=...>`,
    were refused as HTML links. A cell is refused only for a complete open tag carrying an
    attribute named exactly href or src, outside a Markdown code span."""

    def errors(self, text):
        report = "2026-01-02-demo-it-self-run.md"
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write_row(root, row(report, outcome=text))
            return [e for e in ri.check_rows(root) if "HTML link" in e]

    def test_what_renders_as_no_link_is_accepted(self):
        for text in ("x<a and later the words href=value in prose", '<span data-href="identifier">plain</span>',
                     'the check names `<a href="missing.md">` as code', '<a name="top">no link</a>'):
            with self.subTest(text=text):
                self.assertEqual(self.errors(text), [])

    def test_a_complete_link_tag_outside_code_is_still_refused(self):
        for text in ('<A HREF=missing.md>notes</A>', '`code` then <img src="x.png"/>'):
            with self.subTest(text=text):
                self.assertEqual(len(self.errors(text)), 1, text)


class RawHtmlInACellIsRefused(unittest.TestCase):
    """2026-10-27 security audit, W6-14: a cell is rendered verbatim into docs/runs/README.md,
    and only a tag carrying href or src was refused, so `<script>alert(1)</script>` passed every
    check. Any raw HTML outside a code span or an escape is refused now; a link tag keeps its own
    message."""

    def errors(self, cell, text):
        report = "2026-01-02-demo-it-self-run.md"
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write_row(root, row(report, **{cell: text}))
            return [e for e in ri.check_rows(root) if "raw HTML" in e]

    def test_raw_html_with_no_link_in_it_is_refused(self):
        for text in ("<script>alert(1)</script>", "<b>bold</b>", "a <!-- hidden --> note",
                     "</div> then text", '<span class="x">styled</span>'):
            for cell in ("outcome", "target"):
                with self.subTest(cell=cell, text=text):
                    self.assertEqual(len(self.errors(cell, text)), 1, text)

    def test_code_escapes_autolinks_and_comparisons_are_text(self):
        for text in ("`<script>` named as code", "an escaped \\<script> is text",
                     "see <https://example.org/x> for more", "mail <a@b.example>",
                     "3 < 5 and x<5", "flags `--source human:<name>`"):
            with self.subTest(text=text):
                self.assertEqual(self.errors("outcome", text), [])

    def test_a_link_tag_keeps_its_own_message(self):
        report = "2026-01-02-demo-it-self-run.md"
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write_row(root, row(report, outcome='<a href="x.md">x</a>'))
            errors = ri.check_rows(root)
        self.assertEqual([e for e in errors if "HTML link" in e or "raw HTML" in e],
                         [e for e in errors if "HTML link" in e])



class DangerousSchemesInACellAreRefused(unittest.TestCase):
    """PR #718 re-attack (W6-14): a cell's `<javascript:alert(1)>` autolink reached
    docs/runs/README.md. A javascript:, vbscript:, data: or file: scheme is refused wherever it
    stands in a cell (review round 3: by token, not by the Markdown construct around it)."""

    def errors(self, text):
        report = "2026-01-02-demo-it-self-run.md"
        with tempfile.TemporaryDirectory() as tmp:
            root = make_root(tmp)
            write_row(root, row(report, outcome=text))
            return [e for e in ri.check_rows(root) if "scheme" in e]

    def test_a_dangerous_scheme_is_refused(self):
        for text in ("see <javascript:alert(1)>", "<vbscript:msgbox(1)>", "[x](data:text/html,x)",
                     "[x](file:///etc/passwd)", "[x](JAVA&#83;CRIPT:alert(1))",
                     "[x](https://example.org/javascript:)", "- [p]: javascript:alert(1)",
                     "> - [p]: <javascript:alert(1)>", "[x](javascript\\:alert(1))",
                     "[x](javascript&colon;x)", "[x](%6Aavascript:x)"):
            with self.subTest(text=text):
                self.assertEqual(len(self.errors(text)), 1, text)

    def test_ordinary_links_pass(self):
        for text in ("see <https://example.org>", "the metadata: key"):
            with self.subTest(text=text):
                self.assertEqual(self.errors(text), [])


class YesRowsMustActuallyBind(unittest.TestCase):
    """Regression pin for #784: a row claiming `binds: yes...` must actually bind under
    `run_report.check_report()`, and 2026-10-25-wip-curve-604-live.json must record its honest
    non-binding state."""

    def test_wip_curve_604_live_row_records_non_binding_wtree(self):
        data = json.loads(
            (ROOT / "docs" / "runs" / "index" / "2026-10-25-wip-curve-604-live.json").read_text(encoding="utf-8")
        )
        self.assertTrue(data["binds"].startswith("no "), data["binds"])
        self.assertIn("14df5c90150c", data["binds"])
        self.assertNotIn("summary", data)

    def test_check_bindings_rejects_a_yes_row_that_does_not_bind(self):
        with tempfile.TemporaryDirectory(prefix="ri-bind-784-") as tmp:
            root = make_root(tmp, reports=("2026-01-02-demo-it-self-run.md",))
            (root / "runtime" / "scripts").mkdir(parents=True)
            for name in ("run_report.py", "inventory.py", "gitexec.py", "dispatch-sign.py", "ed25519.py"):
                shutil.copy2(ROOT / "runtime" / "scripts" / name, root / "runtime" / "scripts" / name)
            write_row(root, row("2026-01-02-demo-it-self-run.md", binds="yes — claims to bind"))
            errors = ri.check_rows(root)
            self.assertTrue(
                any("binds claims 'yes'" in e and "fails run_report" in e for e in errors),
                errors,
            )


if __name__ == "__main__":
    unittest.main()
