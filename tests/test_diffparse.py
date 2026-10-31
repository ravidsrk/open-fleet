#!/usr/bin/env python3
"""Direct unit tests for runtime/scripts/diffparse.py (#736).

diffparse.records is the hunk-counting unified-diff reader floor_guard.py reads
diffs with. verify.py's _diff_records keeps its own copy of the same grammar, so
these tests pin diffparse only. They stop a refactor from bringing back the
prefix-only bug its docstring records: a removed ``-- note`` line is
``--- note`` on the wire, and a reader that took it for a file header renamed
the rest of the hunk.
"""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "diffparse", ROOT / "runtime" / "scripts" / "diffparse.py")
diffparse = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diffparse)


def kinds(text):
    return [(kind, line) for kind, line, _ in diffparse.records(text)]


HEADER = "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n"


class NormalHunk(unittest.TestCase):
    def test_every_record_kind_appears(self):
        text = HEADER + "@@ -1,2 +1,2 @@\n keep\n-old\n+new\n\\ No newline at end of file\n"
        self.assertEqual(kinds(text), [
            ("header", "diff --git a/f.txt b/f.txt"),
            ("header", "--- a/f.txt"),
            ("header", "+++ b/f.txt"),
            ("hunk", "@@ -1,2 +1,2 @@"),
            (" ", " keep"),
            ("-", "-old"),
            ("+", "+new"),
            ("marker", "\\ No newline at end of file"),
            ("header", ""),
        ])

    def test_hunk_match_is_returned_only_on_hunk_records(self):
        text = HEADER + "@@ -4,2 +7,2 @@\n a\n b\n"
        for kind, _, match in diffparse.records(text):
            if kind == "hunk":
                self.assertEqual(match.groups(), ("4", "2", "7", "2"))
            else:
                self.assertIsNone(match)


class ContentThatLooksLikeAHeader(unittest.TestCase):
    def test_removed_dash_dash_line_is_content_not_header(self):
        # A removed line whose text is "-- note" is "--- note" on the wire.
        text = HEADER + "@@ -1,2 +1,1 @@\n--- note\n keep\n"
        got = kinds(text)
        self.assertIn(("-", "--- note"), got)
        self.assertNotIn(("header", "--- note"), got)

    def test_added_plus_plus_line_is_content_not_header(self):
        # An added line whose text is "++ x" is "+++ x" on the wire.
        text = HEADER + "@@ -1,1 +1,2 @@\n keep\n+++ x\n"
        got = kinds(text)
        self.assertIn(("+", "+++ x"), got)
        self.assertNotIn(("header", "+++ x"), got)

    def test_same_lines_after_the_counts_are_spent_are_headers(self):
        text = HEADER + "@@ -1 +1 @@\n-a\n+b\n--- a/g.txt\n+++ b/g.txt\n"
        got = kinds(text)
        self.assertIn(("header", "--- a/g.txt"), got)
        self.assertIn(("header", "+++ b/g.txt"), got)


class NoNewlineMarker(unittest.TestCase):
    def test_marker_does_not_consume_a_hunk_count(self):
        # Counts 1/1: the marker sits between "-a" and "+b"; if it consumed a
        # count, "+b" would overflow the hunk or the hunk would end early.
        text = HEADER + "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n"
        self.assertEqual(kinds(text)[4:7], [
            ("-", "-a"),
            ("marker", "\\ No newline at end of file"),
            ("+", "+b"),
        ])


class OmittedCounts(unittest.TestCase):
    def test_counts_default_to_one(self):
        text = HEADER + "@@ -3 +3 @@\n-x\n+y\n"
        got = kinds(text)
        self.assertEqual(got[3:6], [("hunk", "@@ -3 +3 @@"), ("-", "-x"), ("+", "+y")])

    def test_a_second_line_beyond_the_default_is_not_content(self):
        # With the default 1/1 spent, a following "-z" is outside the hunk.
        text = HEADER + "@@ -3 +3 @@\n-x\n+y\n-z\n"
        self.assertIn(("header", "-z"), kinds(text))


class LineSplitting(unittest.TestCase):
    def test_carriage_return_inside_a_line_does_not_split_it(self):
        text = HEADER + "@@ -1 +1 @@\n-a\rb\n+c\n"
        got = kinds(text)
        self.assertIn(("-", "-a\rb"), got)
        self.assertIn(("+", "+c"), got)

    def test_form_feed_inside_a_line_does_not_split_it(self):
        text = HEADER + "@@ -1 +1 @@\n-a\x0cb\n+c\x0cd\n"
        got = kinds(text)
        self.assertIn(("-", "-a\x0cb"), got)
        self.assertIn(("+", "+c\x0cd"), got)


class Malformed(unittest.TestCase):
    def test_truncated_hunk_raises(self):
        text = HEADER + "@@ -1,3 +1,3 @@\n keep\n"
        with self.assertRaises(ValueError):
            list(diffparse.records(text))

    def test_truncated_hunk_at_end_of_text_without_newline_raises(self):
        text = HEADER + "@@ -1,2 +1,2 @@\n keep"
        with self.assertRaises(ValueError):
            list(diffparse.records(text))

    def test_malformed_hunk_header_raises(self):
        with self.assertRaises(ValueError):
            list(diffparse.records(HEADER + "@@ nonsense @@\n"))

    def test_hunk_exceeding_its_counts_raises(self):
        # Old side declares 1; a context line spends old and new, then "-b"
        # would take old to -1 while new is still owed.
        text = HEADER + "@@ -1,1 +1,2 @@\n a\n-b\n"
        with self.assertRaises(ValueError):
            list(diffparse.records(text))


if __name__ == "__main__":
    unittest.main()
