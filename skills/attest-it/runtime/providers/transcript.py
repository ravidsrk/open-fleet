#!/usr/bin/env python3
"""transcript.py — a harness's FINAL answer, read from the transcript posix records (#596).

posix records a worker's stdout and stderr line by line (`lanes/<dispatch>/events.jsonl`), around
the exit monitor's own event lines. Most launches print JSON events there, each in its own shape,
so the final answer is a different event per harness, and every other event (reasoning, tool
calls and their results, an echoed prompt, earlier turns) is NOT the answer. Two readers need
exactly that: first_run.py's report and the posix monitor's ro completion line. They share this
one so they can never disagree about what the worker answered (#596 review).

Stdlib only, with no package-relative import: posix.py imports it as a sibling module, and
first_run.py loads it by path.
"""
from __future__ import annotations

import json

# Where each posix launch (base.build_harness_command) prints its final answer on stdout. A
# Claude-only reader discarded every other harness's report and turned a finished paid run into
# NO-GO (#596 review).
FINAL_ANSWER_FORMATS = {
    "claude": "claude-stream-json",  # -p --output-format stream-json: {"type":"result","result":...}
    "codex": "codex-exec-json",      # exec --json: item.completed {"item":{"type":"agent_message","text":...}}
    "opencode": "opencode-json",     # run --format json: {"type":"text","part":{"text":...}}; step_start resets
    "omp": "pi-json",                # -p --mode json: message_end {"message":{"role":"assistant","content":[...]}}
    "pi": "pi-json",
    "goose": "goose-stream-json",    # {"type":"message","message":{"id":...,"role":"assistant","content":[...]}}
    "jcode": "jcode-ndjson",         # run --ndjson: {"type":"done","text":<every text delta of the run>}
    "hermes": "text",                # chat --oneshot -Q: plain text
    "crush": "text",                 # run -q: plain text
    "gemini": "text",                # -p with no --output-format: plain text
}
# These carry every turn's text, not only the last answer: a reader anchors at the answer's end
# (first_run.py at its last report header; the ro completion line at the answer's last line).
ALL_TURN_FORMATS = ("jcode-ndjson", "text")
# Lines the posix monitor itself writes into the transcript, around the worker's own output.
MONITOR_EVENTS = ("turn_started", "launch_refused", "sandbox_git_synced", "sandbox_git_sync_failed",
                  "injected_prompt", "ro_relay_failed")


def _text_blocks(content) -> str:
    """The text blocks of a pi- or goose-style message content (a list, or pi's bare string)."""
    if isinstance(content, str):
        return content
    blocks = content if isinstance(content, list) else []
    return "".join(b["text"] for b in blocks
                   if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str))


def final_answer(agent: str, lines: list[str]) -> str:
    """The worker's final answer, read from its transcript lines in its harness's own format.

    "" for a harness with no known format: nothing it printed is read as an answer.
    """
    fmt = FINAL_ANSWER_FORMATS.get(agent)
    if fmt is None:
        return ""
    answer, kept = "", []
    parts: dict = {}  # opencode: the text parts of the current step
    run_id, run = None, ""  # goose: the chunks of the message being streamed
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if not isinstance(event, dict):
            kept.append(line)
            continue
        kind = event.get("type")
        if kind in MONITOR_EVENTS:
            continue
        kept.append(line)
        item, message, part = event.get("item"), event.get("message"), event.get("part")
        if fmt == "claude-stream-json" and kind == "result" and isinstance(event.get("result"), str):
            answer = event["result"]
        elif (fmt == "codex-exec-json" and kind == "item.completed" and isinstance(item, dict)
              and item.get("type") == "agent_message" and isinstance(item.get("text"), str)):
            answer = item["text"]
        elif fmt == "opencode-json" and kind == "step_start":
            parts = {}
        elif fmt == "opencode-json" and kind == "text" and isinstance(part, dict) and isinstance(part.get("text"), str):
            parts[part.get("id") or f"anon-{len(parts)}"] = part["text"]
            answer = "\n".join(parts.values())
        elif fmt == "jcode-ndjson" and kind == "done" and isinstance(event.get("text"), str):
            answer = event["text"]
        elif not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        elif fmt == "pi-json" and kind == "message_end":
            answer = _text_blocks(message.get("content")) or answer
        elif fmt == "goose-stream-json" and kind == "message":
            # goose emits one message as chunks sharing its id; a new id starts a new message.
            if message.get("id") is None or message.get("id") != run_id:
                run_id, run = message.get("id"), ""
            run += _text_blocks(message.get("content"))
            answer = run or answer
    if fmt == "text":
        answer = "\n".join(kept)
    return answer
