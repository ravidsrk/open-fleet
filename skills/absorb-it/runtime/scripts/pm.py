#!/usr/bin/env python3
# pm.py — tolerant parser for `orca orchestration inbox/check` JSON output. (v3)
# Keepalives ({"_keepalive":true,...}) arrive on STDERR every 15 s — never on stdout; a capture
# that merged 2>&1 breaks naive json.load. Pipe stdout only, or filter keepalives before parsing.
# This decodes successive JSON objects, skips keepalive-only envelopes STRUCTURALLY (not by line
# filtering, which could drop a mixed keepalive+messages object), and prints each message.
#
# v3 (2026-09-10 upstream re-pin): the skip keys on `_keepalive` FIRST. A keepalive line carries
# both `_keepalive` and `_heartbeat`, but `_heartbeat` is only a deprecated alias retained for
# scripts still filtering it during migration (`check-keepalive.ts:18-26` at Orca v1.4.203) —
# v2 keyed on the alias alone, so it was correct by accident and would start miscounting every
# keepalive as an unrecognized envelope the day upstream drops it.
#
# v2 (Codex review E3 remediation): a malformed segment no longer hides everything after it —
# the parser skips to the next line and keeps going, reporting the skip count at the end.
# Missing message fields print as '?' instead of raising KeyError.
# Message text is worker-controlled and therefore untrusted: every printed field goes through
# _visible() so escape sequences (OSC 52 clipboard writes, cursor movement) print inertly — and,
# since #299, so do the characters that print NO glyph and still change what the reader sees.
#
# Usage:  orca orchestration inbox --json > inbox.json && python3 pm.py inbox.json
import json
import sys
import unicodedata


def _has_messages_key(node):
    # True if a 'messages' key exists anywhere in the decoded structure.
    if isinstance(node, dict):
        return "messages" in node or any(_has_messages_key(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_messages_key(v) for v in node)
    return False


# Unicode general categories that change what a terminal SHOWS without printing a glyph.
#   Cf — format: U+202E right-to-left override reverses the rest of a line, U+200B zero-width
#        space splits a word the reader sees as whole, U+2066/2069 isolate a run, U+FEFF hides.
#   Zl/Zp — line and paragraph separator: a line break the renderer honours and the inbox format
#        never wrote, so a message body can forge a field of its own.
# Escaping C0/C1 alone left every one of these to reach the coordinator raw from an issue title
# or a PR body (#299). Escaped, not stripped: the reader has to SEE that something was there.
# guard_text.py knows this category too and does the opposite with it — NFKC-folds and REMOVES it
# — because that is for comparing two names, where an invisible character must not make them
# differ. Here the string is being shown to a human, so it must not silently change either.
_INVISIBLE = ("Cf", "Zl", "Zp")


def _visible(value):
    # Render untrusted text inertly: escape C0/C1 controls, DEL, and the categories above so a
    # hostile message can neither drive the coordinator's terminal nor reorder what it shows.
    # \n and \t stay literal for readability.
    out = []
    for ch in str(value):
        if ch in "\n\t":
            out.append(ch)
        elif ch < " " or ch == "\x7f" or "\x80" <= ch <= "\x9f":
            out.append(f"\\x{ord(ch):02x}")
        elif unicodedata.category(ch) in _INVISIBLE:
            # \uXXXX for the BMP, \UXXXXXXXX above it — a 5-digit \u would be ambiguous.
            out.append(f"\\u{ord(ch):04x}" if ord(ch) < 0x10000 else f"\\U{ord(ch):08x}")
        else:
            out.append(ch)
    return "".join(out)


def print_inbox(raw):
    dec = json.JSONDecoder()
    i = 0
    msgs = []
    skipped = 0
    unrecognized = 0
    while i < len(raw):
        while i < len(raw) and raw[i] in " \t\r\n":
            i += 1
        if i >= len(raw):
            break
        try:
            obj, j = dec.raw_decode(raw, i)
            i = j
        except Exception:
            # Malformed segment: skip to the next line instead of aborting the whole stream.
            skipped += 1
            nl = raw.find("\n", i)
            if nl == -1:
                break
            i = nl + 1
            continue
        if not isinstance(obj, dict):
            continue
        result = obj.get("result")
        batch = result.get("messages") if isinstance(result, dict) else None
        if not isinstance(batch, list):
            batch = None  # a wrong-typed 'messages' (e.g. a string) is not a batch
        if batch is None and _has_messages_key(obj):
            # Message-bearing shape we don't parse — 'messages' misplaced at any depth
            # ({"messages": [...]}, {"data": {"messages": [...]}}, wrong-typed, or riding
            # inside a heartbeat envelope). Checked BEFORE the heartbeat skip so it can't
            # be swallowed; counting it as empty would misread a real inbox as empty.
            unrecognized += 1
            continue
        if ("_keepalive" in obj or "_heartbeat" in obj) and not batch:
            # Keepalive-only envelope; a mixed object still yields its messages below.
            # `_keepalive` is the CURRENT marker and is checked FIRST; `_heartbeat` rides the
            # same line only as a deprecated alias kept "for scripts still filtering it while
            # callers migrate" (`check-keepalive.ts:18-26` at Orca v1.4.203). Keying on the
            # alias alone — as v2 did — starts counting every keepalive as an unrecognized
            # envelope the day upstream drops it.
            continue
        for m in batch or []:
            if isinstance(m, dict):
                msgs.append(m)

    print("MESSAGES:", len(msgs))
    for m in msgs:
        print("=" * 60)
        print("ID:", _visible(m.get("id", "?")), "| FROM:", _visible(m.get("from_handle", "?")),
              "| TYPE:", _visible(m.get("type", "?")))
        print("SUBJ:", _visible(m.get("subject", "?")))
        print("BODY:", _visible(m.get("body", "")))
        print("PAYLOAD:", _visible(m.get("payload")))
    if skipped:
        print(f"pm.py: WARN: skipped {skipped} malformed segment(s)", file=sys.stderr)
    if unrecognized:
        print(
            f"pm.py: WARN: {unrecognized} envelope(s) carried a 'messages' key outside the "
            "expected {'result': {'messages': [...]}} shape — the count above may undercount",
            file=sys.stderr,
        )


def main(argv):
    if len(argv) < 2:
        print("usage: pm.py <inbox.json>", file=sys.stderr)
        return 1
    try:
        raw = open(argv[1]).read()
    except OSError as e:
        print(f"pm.py: ERROR: cannot read {argv[1]}: {e.strerror or e}", file=sys.stderr)
        return 2
    print_inbox(raw)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
