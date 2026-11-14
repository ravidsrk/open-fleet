#!/usr/bin/env python3
"""Hunk-counted unified-diff records, shared by the diff-reading guards.

A unified diff cannot be read by prefix alone: a content line is the original
line with one marker in front, so a REMOVED line whose text begins ``-- `` is
``--- …`` on the wire and an ADDED ``++ x`` is ``+++ x``. A reader that takes
every ``--- ``/``+++ `` line as a file header lets file content switch the path
it attributes findings to — removing a ``-- note`` line from ``.coveragerc``
renamed the rest of the hunk to a file called ``note`` (floor_guard review).

The only sound reader counts: an ``@@ -a,b +c,d @@`` header declares exactly
how many old-side and new-side lines follow, and until both counts are spent
every line is content whatever it starts with. This is the grammar
``verify.py:_diff_records`` uses; it lives here so guards outside verify.py
share one copy. Lines split on ``\\n`` only — ``str.splitlines`` also splits on
``\\r``, form feeds and Unicode separators inside a content line, which
miscounts the hunk.

Library only: no CLI, no exit codes. ``records`` raises ``ValueError`` on a
malformed or truncated hunk; callers map that to their could-not-run exit.
"""
import re

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
NO_NEWLINE = "\\ No newline at end of file"


def records(diff_text):
    """Yield (kind, line, hunk_match) for every line of a unified diff.

    kind is ``header`` (outside any hunk), ``hunk`` (an ``@@`` header; hunk_match
    is its match object), ``-``/``+``/`` `` (content), or ``marker`` (the
    ``\\ No newline`` annotation). hunk_match is None except on ``hunk``.
    """
    old_left = new_left = 0
    for line in diff_text.split("\n"):
        if line == NO_NEWLINE:
            yield "marker", line, None
            continue
        if old_left or new_left:
            kind = line[:1]
            if kind not in ("-", "+", " "):
                raise ValueError("incomplete diff hunk")
            old_left -= kind in ("-", " ")
            new_left -= kind in ("+", " ")
            if old_left < 0 or new_left < 0:
                raise ValueError("diff hunk exceeds declared line counts")
            yield kind, line, None
        elif line.startswith("@@"):
            match = HUNK.match(line)
            if not match:
                raise ValueError("malformed hunk header")
            old_left = 1 if match.group(2) is None else int(match.group(2))
            new_left = 1 if match.group(4) is None else int(match.group(4))
            yield "hunk", line, match
        else:
            yield "header", line, None
    if old_left or new_left:
        raise ValueError("incomplete diff hunk")
