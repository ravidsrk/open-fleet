#!/usr/bin/env python3
"""reshape-it RV-D2 WIDTH pin: runtime/scripts/verify.py's interface surface.

Guards the RV-D2 deepening (control-outcome reader moved to
runtime/scripts/_verify_sig.py behind a single _failure_signature
re-export). The count half reads verify.py as TEXT and never imports it, so
the pin stays runnable in every tree shape (including the RV-D2 revert
control, where the importable surface is the pre-deepening one).

WIDTH is the mission's own probe (skills/reshape-it/SKILL.md § SCAN):
count of lines matching ^(def |class |async def |[A-Z_]+ =).
Pre-deepening baseline: 92. Post-deepening pin: 85, raised to 88 by #442, then to 90 by
#442 round 2 (_evidence_toplevel + _roots_are_split: the evidence bound and the
single-repo/split test, each named once instead of inlined at every call site), then
to 91 by #281/#386 (`_Transcript`: the signed verifier transcript — canonical form in
parity with dispatch-sign.py, verdict build, seed load and envelope write, held in ONE
class precisely so the feature costs one name and stays under the <92 invariant). h409
F-1/F-2 (`_Authority`: the review authority pinned once at startup and classed by custody,
plus the lane that decides whether a worker-influenceable authority is advisory or fatal)
is again ONE class, and it is paid for: the single-use `_WAIVER_NEEDS_EXECUTED_NC` moved
into check_review, the only function that ever read it, so the pin holds at 91.
#608 (`check_retention_receipt`: the provenance retention receipt bound offline to its signed
inventory) is paid for the same way: the one-line `_scan_text` folded into check_redaction, its
only caller, so the pin still holds at 91. The 2026-10-26 review's `check_base_binding` (base_sha
bound to the integration branch — the executed control's pre-fix content was the worker's to
choose, P0) is paid for by inlining the single-use `_DISPATCH_NC_FIELDS` into
`_manifest_nc_values`, its only reader, so the pin still holds at 91.

The pin is a ratchet against the deepening RE-WIDENING, not a freeze: the
invariant it defends is `width < BASELINE_WIDTH`, and that baseline never
moves. #442 (the --git-dir / --evidence-root split) spends three of the
seven remaining names — `_ROOTS`, `_git_bytes`, `_root_arg` — and the
budget is named here so the next raise has to argue for itself too. What
would violate RV-D2 is the signature engine coming back, which the second
test below checks by identity and is untouched by the count.
"""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WIDTH_RE = re.compile(r"(?:def |class |async def |[A-Z_]+ =)")
# RV-D3 deepening (2026-11-25): moved the unified-diff & hunk-binding engine
# (_diff_records, _diff_target_paths, _iter_diff_target_paths, _hunk_lines,
# _bind_hunks_to_change, _nc_paths, _extract_diff) to runtime/scripts/_verify_diff.py,
# shrinking WIDTH from 91 to 84 (8 below BASELINE_WIDTH).
BASELINE_WIDTH = 92
PINNED_WIDTH = 84


def interface_width(path):
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
               if WIDTH_RE.match(line))


class VerifyWidthPin(unittest.TestCase):
    def test_interface_width_shrunk(self):
        width = interface_width(ROOT / "runtime" / "scripts" / "verify.py")
        self.assertLess(width, BASELINE_WIDTH,
                        f"verify.py WIDTH {width} is not smaller than the pre-deepening {BASELINE_WIDTH}")
        self.assertEqual(width, PINNED_WIDTH,
                         f"verify.py WIDTH {width} drifted from the pin {PINNED_WIDTH} — a new top-level "
                         "name needs a reason in this module's docstring, not a silent bump")

    def test_engine_lives_behind_the_narrow_import(self):
        spec = importlib.util.spec_from_file_location(
            "verify_width_probe", ROOT / "runtime" / "scripts" / "verify.py")
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        engine = getattr(verify, "_verify_sig", None)
        self.assertIsNotNone(engine, "verify.py no longer loads runtime/scripts/_verify_sig.py")
        self.assertIs(verify._failure_signature, engine._failure_signature,
                      "the _failure_signature re-export is not the engine's own object")
        self.assertIs(verify._counted, engine._counted,
                      "the _counted re-export is not the engine's own object")
        for detail in ("STILLBORN_MARKERS", "ASSERTION_MARKERS",
                       "STRONG_ASSERTION_RE", "_ERRORS_RE", "_FAILURES_RE"):
            self.assertFalse(hasattr(verify, detail),
                             f"implementation detail {detail} leaked back onto verify")
        diff_engine = getattr(verify, "_verify_diff", None)
        self.assertIsNotNone(diff_engine, "verify.py no longer loads runtime/scripts/_verify_diff.py")
        self.assertIs(verify._extract_diff, diff_engine._extract_diff,
                      "the _extract_diff re-export is not the diff engine's own object")
        for detail in ("_diff_records", "_iter_diff_target_paths", "_hunk_lines", "_nc_paths"):
            self.assertFalse(hasattr(verify, detail),
                             f"diff implementation detail {detail} leaked back onto verify")


if __name__ == "__main__":
    unittest.main()
