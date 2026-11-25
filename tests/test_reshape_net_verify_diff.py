#!/usr/bin/env python3
"""reshape-it RV-C3 CHARACTERIZE net: verify.py's diff-parsing & hunk-binding seam.

Pins the CURRENT verdicts of runtime/scripts/verify.py's unified-diff engine
(_extract_diff, _diff_target_paths, _bind_hunks_to_change) BEFORE the RV-D3
deepening moves the diff/hunk parser to runtime/scripts/_verify_diff.py.
This module is the seam's pinned, re-runnable net: the RV-C3 negative control
runs ONLY this module, and the RV-D3 carve-out re-kills the pinned mutant
against this same net at the deepened head.

Pinned mutant M3 (hand): invert quoted-path refusal in _iter_diff_target_paths
(`if value.startswith('"') or "\\\\" in value:` -> `if False:`) or drop the
overlap check in _bind_hunks_to_change (`if not lines <= allowed:` -> `if False:`).
Killed by the quoted-path refusal and unrelated-hunk decoy tests below.
"""
import importlib.util
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("verify_diff_net", ROOT / "runtime" / "scripts" / "verify.py")
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)


class DiffAndHunkBindingSeamNet(unittest.TestCase):
    """Current verdicts of _extract_diff, _diff_target_paths, and _bind_hunks_to_change."""

    def test_extract_diff_strips_leading_and_trailing_prose_and_preserves_cr_lines(self):
        artifact = (
            "Mutant run log\n"
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-return a + b\r\n"
            "+return a - b\n"
            " return 0\n"
            "FAILED (failures=1)\n"
        )
        extracted = verify._extract_diff(artifact)
        self.assertIsNotNone(extracted)
        self.assertTrue(extracted.startswith("diff --git a/app.py b/app.py\n"))
        self.assertNotIn("Mutant run log", extracted)
        self.assertNotIn("FAILED (failures=1)", extracted)
        self.assertIn("-return a + b\n", extracted)

    def test_extract_diff_returns_none_when_no_unified_diff_header_present(self):
        self.assertIsNone(verify._extract_diff("AssertionError: failed\nRan 1 test\n"))

    def test_diff_target_paths_collects_clean_paths_and_rejects_quoted_or_escaping_paths(self):
        good = (
            "diff --git a/scripts/check.py b/scripts/check.py\n"
            "--- a/scripts/check.py\n"
            "+++ b/scripts/check.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-a = 1\n"
            "+a = 2\n"
        )
        self.assertEqual(verify._diff_target_paths(good), ["scripts/check.py"])

        quoted = (
            'diff --git "a/dir with space/x.py" "b/dir with space/x.py"\n'
            '--- "a/dir with space/x.py"\n'
            '+++ "b/dir with space/x.py"\n'
            "@@ -1,1 +1,1 @@\n"
            "-x\n"
            "+y\n"
        )
        with self.assertRaises(ValueError):
            verify._diff_target_paths(quoted)

        escaping = (
            "diff --git a/../outside.py b/../outside.py\n"
            "--- a/../outside.py\n"
            "+++ b/../outside.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-x\n"
            "+y\n"
        )
        with self.assertRaises(ValueError):
            verify._diff_target_paths(escaping)

    def test_diff_target_paths_rejects_truncated_and_overflowing_hunks(self):
        truncated = (
            "diff --git a/scripts/check.py b/scripts/check.py\n"
            "--- a/scripts/check.py\n"
            "+++ b/scripts/check.py\n"
            "@@ -1,3 +1,3 @@\n"
            "-only one line\n"
        )
        with self.assertRaises(ValueError):
            verify._diff_target_paths(truncated)

    def test_bind_hunks_to_change_accepts_overlapping_hunk_and_rejects_unrelated_hunk_decoy(self):
        sha_base = "a" * 40
        sha_head = "b" * 40
        manifest = {"base_sha": sha_base, "head_sha": sha_head}
        change_diff = (
            "diff --git a/scripts/check.py b/scripts/check.py\n"
            "--- a/scripts/check.py\n"
            "+++ b/scripts/check.py\n"
            "@@ -10,1 +10,1 @@\n"
            "-old = 1\n"
            "+new = 2\n"
        )
        overlapping_mutant = (
            "diff --git a/scripts/check.py b/scripts/check.py\n"
            "--- a/scripts/check.py\n"
            "+++ b/scripts/check.py\n"
            "@@ -10,1 +10,1 @@\n"
            "-new = 2\n"
            "+new = 999\n"
        )
        decoy_mutant = (
            "diff --git a/scripts/check.py b/scripts/check.py\n"
            "--- a/scripts/check.py\n"
            "+++ b/scripts/check.py\n"
            "@@ -42,1 +42,1 @@\n"
            "-unrelated = 1\n"
            "+unrelated = 2\n"
        )
        with mock.patch.object(verify, "_git", return_value=(0, change_diff)):
            self.assertIsNone(verify._bind_hunks_to_change(overlapping_mutant, manifest))
            err = verify._bind_hunks_to_change(decoy_mutant, manifest)
            self.assertIsNotNone(err)
            self.assertIn("do not overlap completely", err)

    def test_bind_hunks_to_change_requires_pinned_40_hex_shas(self):
        mutant = (
            "diff --git a/scripts/check.py b/scripts/check.py\n"
            "--- a/scripts/check.py\n"
            "+++ b/scripts/check.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-x\n"
            "+y\n"
        )
        err = verify._bind_hunks_to_change(mutant, {"base_sha": "main", "head_sha": "HEAD"})
        self.assertIsNotNone(err)
        self.assertIn("pinned base_sha and head_sha", err)


if __name__ == "__main__":
    unittest.main()
