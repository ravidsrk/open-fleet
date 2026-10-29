#!/usr/bin/env python3
"""live_broker.py — the live harness's credential broker: the one process that holds the
subscription token, alone in its own container beside the arm's (scripts/live_container.py starts
both; docs/guides/live-harness.md is the operator's guide).

The arm's container shares this container's network namespace and nothing else: it reaches the
broker at 127.0.0.1:PORT, never its files, its processes or its environment. The arm's `claude`
(scripts/live_container_bin/claude) sends every model call here with a placeholder credential. The
broker forwards POST /v1/messages and /v1/messages/count_tokens to the API with the token in its
place and refuses every other request. So no process of the arm can read the token, and no model
call it makes, through claude or around it, escapes the cap: a paid call needs the token.

What this is NOT is an egress control (2026-10-27 audit, W5-15). Sharing the namespace shares its
interfaces, the route out included, so any process of the arm can open its own connection to any
host without passing through the broker, and nothing here sees, caps or records it. The broker
refuses requests made TO it; it does not stand between the arm and the network.

Every connection has a socket timeout (HANDLER_TIMEOUT_S), one deadline for its request line and
headers (REQUEST_DEADLINE_S, which a byte at a time never extends) and one for its body
(BODY_DEADLINE_S), and at most MAX_CONNECTIONS are served at once. A deadline bounds one
connection, not a client that keeps opening them, so when every slot is taken a new connection
evicts the one that has waited longest for its own request to arrive: a request still arriving
holds its slot only until someone else needs it, and only calls already read in full (relayed to
the API, or being refused) keep theirs. Every wait before that is evictable and ends at once when
evicted -- for its request line and headers, its body's first byte, its share of the body budget,
its body -- so an evicted connection gives its slot up at once. A body is at most MAX_BODY (the API's own 32 MB) and held
once (one buffer of its Content-Length), and what the bodies of every connection take together --
their bytes and the most parsing them can allocate -- is at most BODY_BUDGET. Before a body is read,
the most one of its length can take parsed as text (WORST_PER_BYTE times it) is taken from that
budget, by a request that holds none while it waits; then parse_cost, a pre-scan of its bytes,
bounds its parse (the str json.loads decodes it to and the strings parsed out of it at their
characters' width, and every JSON value): what that bound does not need goes back, and a body whose
values need more takes the rest. At most one request waits for budget while holding any: of the
bodies read in full, one may wait for that rest, every other take leaving what it needs free, and
any other whose rest does not fit at once is refused (503) and gives back all but its bytes'
charge, so no request ever waits for a share another waiting request holds (_BodyBudget; Codex
round 13 on 594f7265). Once its parse is over a body keeps only its bytes' charge while it is
relayed. The charge for a body's bytes goes back only once its buffer is freed, on every way out
of the request, an exception included (Codex round 1 on PR #732).
Budget goes only to a body that is arriving (its first byte is here); a body arriving slower than
MIN_BODY_RATE, past BODY_GRACE_S, is stalled, and a request waiting for budget takes back, for
itself, what a stalled body holds past its buffer, evicting it. A take that may wait waits up to
BODY_WAIT_S for room and is otherwise refused (503, a "body-budget" refusal);
a body whose bound could pass the whole budget, that nests past MAX_DEPTH, or whose pre-scan passes
MAX_SCAN_STEPS is refused unparsed (413, a "body-parse" refusal). The parse itself runs in a forked
child whose RLIMIT_DATA is that bound, so a parse that would pass it fails in the child and the body
is refused (413): the broker never holds a parsed body. So what the slots hold, and their parses,
fit the broker's container memory. A connection past the bound with none to evict is closed
unanswered. Every connection closed without an answer (evicted, past the bound, timed out,
malformed, a body cut short, or closed before its request) is counted as a "drop" (W5-16).
count_tokens is free but bounded: FREE_CALLS_MAX calls and FREE_BYTES_MAX body bytes per broker,
a "free" tally every FREE_RECORD_EVERY calls and the tally on every later event, and a refusal
past the bound (W5-17). The container keeps no log, so every exception in a request is a "fault"
in the ledger (where, the exception type and the frames; never a message, a request, a response
or the token): one escaping a handler, a client connection failing mid-body, an upstream or client
failure caught while relaying (and the 502 that could not be sent), and a usage report settle
cannot price. The exceptions that are not faults are a malformed request's own (a non-integer
Content-Length answered 411, a body that is not JSON answered 400 and recorded as a refusal), a
request or body past its deadline (a drop), a stream line that is not JSON, which is skipped, a
whole answer that is not JSON, which settles its call's whole reservation, the 408 a client that
left can no longer be sent, and the socket errors of a connection the broker itself evicted.
Refusals, drops and faults are counted per kind and written at most once a DROP_RECORD_S per
kind, their text bounded, with the running counts on every line and a "tally" line catching them
up, so a client that resets connections or sends refused requests in a loop cannot grow the
ledger without bound. A call's settle always runs, settling the whole reservation when its usage
cannot be priced (W5-18).

The cap is a reservation ledger. A call starts only when the settled spend, the reservations of
the calls still in flight and its own reservation fit under --cap-usd. Its reservation is its
worst case at its model's highest list price: its body's bytes as input tokens (no token is
shorter than a byte) plus FRAMING_TOKENS for the API's own framing and IMAGE_TOKENS for each
inline image, all priced as 1-hour cache writes, and its max_tokens as output. When it ends, the
reservation is released and the usage the API reported is settled as the API bills it; a call
that ends without a complete usage report settles its whole reservation.

Nothing unpriced runs (Codex at 8585b35789). A body is forwarded only when it is a JSON object
with a priced model and a positive max_tokens, every field is one the broker prices (FIELDS), every
tool is the client's own wherever it is defined (in `tools` or inside the content), and all content is inline and
bounded by its bytes. So an image or
document by URL or file id, a PDF, an advisor or other server-side tool, an MCP server,
server-side compaction, a service tier, and an inference geography other than global or US are
refused: each is billed beyond what the body's bytes bound. A call that names no geography
reserves at the US premium, and every call settles at the geography the API reports.

The ledger (--ledger, appended, mode 0600) is one JSON line per event: open, start, settle,
refuse, free, drop, fault and tally (refusals, drops and faults counted per kind and written at
most once a DROP_RECORD_S per kind, their text bounded). It never holds the token, a request or a
response. The launcher reads it after both
containers are destroyed, into the receipt.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import gc
import http.client
import io
import json
import os
import re
import resource
import select
import signal
import socket
import sys
import threading
import time
import traceback
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8787  # scripts/live_container_bin/claude's BROKER names the same port
UPSTREAM = "https://api.anthropic.com"
OAUTH_BETA = "oauth-2025-04-20"  # a subscription token is an OAuth bearer token
# USD per million tokens (input, output, cache read): the Claude API's list prices as of
# 2026-10-06. A cache write is 1.25x input for the 5-minute TTL and 2x for the 1-hour one; fast
# mode is 2x. Haiku 5.5 costs more above 100K prompt tokens (TIERED).
PRICES = {
    "claude-fable-5-1": (10.0, 50.0, 0.25), "claude-fable-5": (10.0, 50.0, 1.0),
    "claude-opus-5-5": (4.0, 20.0, 0.20), "claude-opus-5": (5.0, 25.0, 0.50),
    "claude-opus-4-8": (5.0, 25.0, 0.50), "claude-opus-4-7": (5.0, 25.0, 0.50),
    "claude-sonnet-5-5": (2.0, 10.0, 0.20), "claude-sonnet-5": (2.0, 10.0, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01), "claude-haiku-4-5": (1.0, 5.0, 0.10),
}
TIERED = {"claude-haiku-5-5": (100_000, (0.50, 2.50, 0.05))}
WRITE_5M, WRITE_1H, FAST = 1.25, 2.0, 2.0
# inference_geo "us" is billed at 1.1x every token category. A request that names none runs in the
# workspace's default geography, which may be US, so it reserves at the worst; a call settles at
# the geography the API reports it ran in (usage.inference_geo), the worst when it reports none
# (Codex at 3c01b90b5e).
GEO = {"global": 1.0, "us": 1.1}
GEO_WORST = max(GEO.values())
IMAGE_TOKENS = 4800  # above the most one image costs on any current model: 4,784 visual tokens at 2576 px
COSTLIEST = "claude-fable-5-1"  # what an iteration naming an unpriced model is charged as
SEARCH_USD = 0.01  # each web search the API reports: refused tools never run one, but any reported is charged
# An Anthropic-defined tool's type carries its version date (web_search_20250305, bash_20250124):
# one anywhere in the content is a tool definition, which only the client's own tools may be.
DATED_TYPE_RE = re.compile(r"_\d{8}$")
# Every request field the broker can price. Any other is refused, so a pricing modifier the
# broker does not know never reaches the API unpriced.
FIELDS = {"model", "messages", "system", "max_tokens", "stream", "tools", "tool_choice", "metadata", "thinking",
          "temperature", "top_p", "top_k", "stop_sequences", "output_config", "context_management", "speed",
          "inference_geo", "service_tier"}
FRAMING_TOKENS = 4096
# The API refuses a request over 32 MB, so the broker never holds a larger one (it was 64 MiB).
MAX_BODY = 32_000_000
# The memory every connection's request body may take AT ONCE, together: its bytes, and what parsing
# them can allocate. MAX_CONNECTIONS x MAX_BODY never fit the broker's container (BROKER_LIMITS,
# 512m), and four concurrent 64 MiB bodies held twice each took it to 506 MB (re-attack of
# 2d254d0f); holding each once did not bound the parse either -- 20 million empty objects in 60 MiB
# parse to over 1 GiB (Codex round 7), and 63 MiB of ASCII with one emoji is decoded and parsed to
# two UCS-4 copies, 504 MiB with the body (Codex round 9). So a request takes the most a body of its
# Content-Length can need parsed as text (WORST_PER_BYTE) from this budget before its first body byte
# is read and, before anything parses it, the rest of parse_cost's bound on the parse; a first take
# waits up to BODY_WAIT_S for room, as does the one body read in full that may wait for the rest
# (_BodyBudget: any other is refused at once), else is refused (503) and counted, and a body whose
# bound alone is past the budget is refused (413) unparsed and counted. The parse itself
# runs in a forked child whose RLIMIT_DATA is that bound (_parse_in_child), so the bound is not an
# estimate the container trusts: a parse that would pass it fails there, and the body is refused.
# The worst body MAX_BODY can hold (13 times its bytes, see parse_cost) fits, and the budget leaves
# the interpreter, its threads and PARSERS children room in the container's memory.
BODY_BUDGET = 400 << 20
BODY_WAIT_S = 30
# The most one parsed JSON value costs, its slot in its container included: measured at peak on
# CPython 3.12 (an empty object in an array 75 bytes, an object member under a distinct key 103,
# two-character strings 56, numbers 43). Characters are charged by parse_cost, by their width.
VALUE_COST = 128
# Parses at once, each in a child of its own (_parse_in_child), and how long one may take. A child
# is given its bound past what it inherited, and PARSE_SLACK for the parse's own bookkeeping.
PARSERS = 2
PARSE_SECONDS = 60
PARSE_SLACK = 16 << 20
# parse_cost's bound per byte of a body whose values cost nothing: 1 + 4 + 2 x 4 (see there).
WORST_PER_BYTE = 13
# A body is STALLED once its bytes arrive slower than MIN_BODY_RATE, after BODY_GRACE_S: then what it
# holds of the budget past its buffer can be taken back by any request waiting for budget, which
# polls for that every RECLAIM_POLL_S. An ordinary client on the arm's loopback sends a 32 MB body in
# well under a second.
MIN_BODY_RATE = 1 << 20
BODY_GRACE_S = 1.0
RECLAIM_POLL_S = 0.1
RELEASE_WAIT_S = 5.0  # how long past its deadline a wait waits for an evicted body's buffer to come back
MAX_DEPTH = 128  # a request's JSON nests a few levels (a tool's input schema a dozen or so)
# The walk's steps: one per structural byte outside a string and one per escaped quote inside one.
# An ordinary request takes tens of thousands; past this many the body is refused, so the walk's
# time is bounded whatever the body holds.
MAX_SCAN_STEPS = 2_000_000
# The next structural byte: ONE byte, never a repeated group (a regex that matched a string by
# repeating a group per escape kept state per repetition, so 30 million \n escapes made the
# pre-scan itself exhaust the broker -- Codex round 8). Strings are skipped with bytes.find.
_STRUCTURAL = re.compile(rb'["\[\]{},:]')
# The widest character the body can decode to (a lead byte of a 4-byte UTF-8 sequence, or of one
# past U+00FF), and the widest a string's escape can make (a high-surrogate \u escape pairs into an
# astral character; any other \u escape past \u00ff is BMP). One byte each: never a repeated group.
_UTF8_ASTRAL = re.compile(rb"[\xf0-\xf4]")
_UTF8_WIDE = re.compile(rb"[\xc4-\xef]")
_ESCAPE_ASTRAL = re.compile(rb"\\u[dD][89abAB]")
_ESCAPE_WIDE = re.compile(rb"\\u(?:0[1-9a-fA-F]|[1-9a-fA-F])")
_BACKSLASH = 0x5C
_RUN_CHUNK = 4096
UPSTREAM_TIMEOUT_S = 900
HANDLER_TIMEOUT_S = 60  # each read or write on a client connection (W5-16)
REQUEST_DEADLINE_S = 30  # the request line and headers, in all: a byte at a time never extends it
BODY_DEADLINE_S = 120  # the whole request body, however slowly it trickles
DROP_RECORD_S = 1.0  # a "drop" or "fault" line per kind at most this often; the counts ride every line
MAX_CONNECTIONS = 32  # served at once: the broker's --pids-limit is 64
EVICT_WAIT_S = 5  # how long a new connection waits for the slot an evicted one gives up
FREE_CALLS_MAX, FREE_BYTES_MAX = 5000, 2 << 30  # count_tokens per broker (W5-17)
FREE_RECORD_EVERY = 100  # a "free" tally event every this many count_tokens calls
PRICED_PATH, FREE_PATH = "/v1/messages", "/v1/messages/count_tokens"
DATED_RE = re.compile(r"-\d{8}$")
# What the client sent that never reaches the API: its credential, and hop-by-hop headers.
DROP = {"host", "authorization", "x-api-key", "content-length", "connection", "keep-alive", "proxy-authorization",
        "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "accept-encoding", "cookie"}
DROP_BACK = {"content-length", "transfer-encoding", "connection", "keep-alive", "content-encoding", "set-cookie"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def short(value, limit=100):
    """`value` for a ledger line: a string cut to `limit` characters, anything else by its type."""
    if value is None or (isinstance(value, str) and len(value) <= limit):
        return value
    return f"{value[:limit]}… ({len(value)} chars)" if isinstance(value, str) else f"<{type(value).__name__}>"


def model_key(model):
    """The PRICES key for `model` (a dated id prices as its alias), or None."""
    key = DATED_RE.sub("", model) if isinstance(model, str) else None
    return key if key in PRICES else None


def priced(usage, model, mult=1.0):
    """USD for one call's reported usage, as the API bills it: each cache write at its TTL's rate
    (the 1-hour rate when the report does not split them), at the tier its prompt reached."""
    key = model_key(model)
    tokens = lambda key, doc=usage: max(int(doc.get(key) or 0), 0)
    prompt = tokens("input_tokens") + tokens("cache_creation_input_tokens") + tokens("cache_read_input_tokens")
    inp, out, read = PRICES[key]
    if key in TIERED and prompt > TIERED[key][0]:
        inp, out, read = TIERED[key][1]
    split = usage.get("cache_creation") if isinstance(usage.get("cache_creation"), dict) else {}
    w5, w1 = tokens("ephemeral_5m_input_tokens", split), tokens("ephemeral_1h_input_tokens", split)
    written = tokens("cache_creation_input_tokens")
    write = w5 * WRITE_5M + w1 * WRITE_1H if split and w5 + w1 == written else written * WRITE_1H
    usd = (tokens("input_tokens") * inp + write * inp + tokens("cache_read_input_tokens") * read
           + tokens("output_tokens") * out) / 1e6
    return usd * mult


def settled(usage, model, mult=1.0):
    """USD for a finished call: its usage, or the sum of the iterations the API reported (each at
    its own model's price, an unpriced one at the costliest) when that sum is larger."""
    usd = priced(usage, model, mult)
    iterations = [it for it in usage.get("iterations") or [] if isinstance(it, dict)]
    if iterations:
        named = lambda it: it.get("model") if model_key(it.get("model")) else model if it.get("model") is None else COSTLIEST
        usd = max(usd, sum(priced(it, named(it), mult) for it in iterations))
    searches = (usage.get("server_tool_use") or {}).get("web_search_requests") or 0
    return usd + max(int(searches), 0) * SEARCH_USD


def reservation(body_len, max_tokens, model, mult=1.0, images=0):
    """USD for one call's worst case: every byte of its body an input token written to the 1-hour
    cache, plus the framing and IMAGE_TOKENS for each image, and every token of max_tokens an
    output token, at its model's highest tier."""
    key = model_key(model)
    inp, out, _read = TIERED[key][1] if key in TIERED else PRICES[key]
    usd = ((body_len + FRAMING_TOKENS + images * IMAGE_TOKENS) * inp * WRITE_1H + max_tokens * out) / 1e6
    return usd * mult


def content_problem(node, found):
    """Why some content in `node` is not bounded by its bytes, or None; counts inline images."""
    if isinstance(node, list):
        for item in node:
            if why := content_problem(item, found):
                return why
    elif isinstance(node, dict):
        if "file_id" in node:
            return "content by file id is billed by what the file holds, not by the request's bytes"
        # A tool can be defined inside the content too, not only in `tools` (a system message's
        # tool_addition, Codex at 0116e8ae34): the same rule holds wherever one is defined.
        definitions = node.get("tool_definition")
        for tool in definitions if isinstance(definitions, list) else [definitions] if definitions is not None else []:
            kind = tool.get("type") if isinstance(tool, dict) else "malformed"
            if kind not in (None, "custom"):
                return f"a {kind} tool is not the client's own: it is billed beyond the request's tokens"
        if isinstance(node.get("type"), str) and DATED_TYPE_RE.search(node["type"]):
            return f"a {node['type']} tool is not the client's own: it is billed beyond the request's tokens"
        source = node.get("source")
        if isinstance(source, dict):
            kind, media = source.get("type"), str(source.get("media_type") or "")
            if kind in ("url", "file"):
                return f"content by {kind} is billed by what it fetches, not by the request's bytes"
            if media == "application/pdf":
                return "a PDF is billed per page, which its bytes do not bound"
            if kind == "base64" and media.startswith("image/"):
                found["images"] += 1
        for value in node.values():
            if why := content_problem(value, found):
                return why
    return None


def _string_end(body, at, steps):
    """(the index just past the string whose content starts at `at`, len(body) when it never
    closes; the walk's steps, one more per escaped quote passed), or None past MAX_SCAN_STEPS. A
    quote ends the string unless an odd run of backslashes precedes it; only that run is looked
    at, from the quote backwards in fixed chunks, so the extra memory is O(1) and the work linear:
    every other escape (a \\n, a \\u) cannot hide a quote and is passed over by find."""
    while True:
        quote = body.find(b'"', at)
        if quote < 0:
            return len(body), steps
        run, end = 0, quote
        while end > at and body[end - 1] == _BACKSLASH:
            start = max(at, end - _RUN_CHUNK)
            chunk = body[start:end]
            kept = len(chunk.rstrip(b"\\"))
            run += len(chunk) - kept
            if kept:
                break
            end = start
        if run % 2 == 0:
            return quote + 1, steps
        steps += 1
        if steps > MAX_SCAN_STEPS:
            return None
        at = quote + 1


def _frames(err):
    """An exception's frames as `file:line:function`, the last twelve, never its message."""
    return [f"{os.path.basename(f.filename)}:{f.lineno}:{f.name}"
            for f in traceback.extract_tb(err.__traceback__)][-12:] if err is not None else []


_PARSING = threading.BoundedSemaphore(PARSERS)


def _parse_facts(body):
    """What the broker needs of a body, read from json.loads(body): its terms (why, mult, images),
    and its model, max_tokens and speed. Run in the parse child."""
    try:
        doc = json.loads(body)
    except (ValueError, RecursionError):
        doc = None
    why, mult, images = terms(doc)
    facts = {"why": why and short(why, 300), "mult": mult, "images": images, "model": None, "max_tokens": None,
             "fast": False}
    if isinstance(doc, dict):
        facts.update(model=short(doc.get("model")), fast=doc.get("speed") == "fast")
        if not why:
            facts["max_tokens"] = doc["max_tokens"]
    return facts


def _vm_data():
    """This process's private writable memory (VmData), in bytes; None where /proc does not say."""
    try:
        with open("/proc/self/status", encoding="ascii") as fh:
            return next(int(line.split()[1]) * 1024 for line in fh if line.startswith("VmData:"))
    except (OSError, ValueError, StopIteration):
        return None


def _parse_in_child(body, allowance):
    """_parse_facts(body), computed in a forked child that may allocate `allowance` bytes (and
    PARSE_SLACK) past what it inherited -- RLIMIT_DATA, which Linux, where the broker runs, enforces
    on every private writable mapping -- so a parse past the bound parse_cost put on it fails in the
    child, never in the broker. The child shares the body with the broker (copy-on-write), runs with
    the garbage collector off (a collection would touch, and so copy, the broker's whole heap), and
    hands back only the facts. At most PARSERS at once. Returns the facts; {"memory": True} when the
    parse passed its bound; {"error": name, "frames": [...]} when it raised; {"timeout": True} past
    PARSE_SECONDS."""
    with _PARSING:
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:  # the child: never returns, so no frame of the broker's runs here
            code = 70
            try:
                os.close(read_fd)
                gc.disable()
                held = _vm_data()
                if held is not None:
                    soft, hard = resource.getrlimit(resource.RLIMIT_DATA)
                    want = held + allowance + PARSE_SLACK
                    resource.setrlimit(resource.RLIMIT_DATA, (want if hard == resource.RLIM_INFINITY
                                                              else min(want, hard), hard))
                try:
                    facts = _parse_facts(body)
                except MemoryError:
                    facts = {"memory": True}
                except Exception as exc:  # e.g. a fault in terms(): its name and frames, never its text
                    facts = {"error": type(exc).__name__, "frames": _frames(exc)}
                view = memoryview(json.dumps(facts).encode())
                while view:
                    view = view[os.write(write_fd, view):]
                code = 0
            except BaseException:
                code = 71
            finally:
                os._exit(code)
        os.close(write_fd)
        chunks, deadline, timed_out = [], time.monotonic() + PARSE_SECONDS, False
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    timed_out = True
                    break
                if not select.select([read_fd], [], [], min(left, 1.0))[0]:
                    continue
                chunk = os.read(read_fd, 1 << 16)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(read_fd)
            if timed_out:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
    if timed_out:
        return {"timeout": True}
    try:
        facts = json.loads(b"".join(chunks))
    except ValueError:
        return {"memory": True}  # it died without a word: out of memory where nothing could be raised
    return facts if isinstance(facts, dict) else {"memory": True}


def widths(body):
    """(the bytes per character of the str json.loads decodes `body` to, the most bytes per
    character of any str it parses out of it): CPython stores a str at the width of its widest
    character, 1 (Latin-1), 2 (BMP) or 4 (astral), so one emoji makes a whole string four times its
    length. The decoded input is as wide as the widest raw character; a parsed string as wide as
    that, or as a \\u escape it holds."""
    if body.isascii():
        wide_in = 1
    elif _UTF8_ASTRAL.search(body):
        wide_in = 4
    elif _UTF8_WIDE.search(body):
        wide_in = 2
    else:
        wide_in = 1
    wide_str = wide_in
    if wide_str < 4 and b"\\u" in body:
        if _ESCAPE_ASTRAL.search(body):
            wide_str = 4
        elif wide_str < 2 and _ESCAPE_WIDE.search(body):
            wide_str = 2
    return wide_in, wide_str


def parse_cost(body, limit):
    """An upper bound on the memory parsing `body` takes, the body itself included, or None when
    that is past `limit`, the body nests past MAX_DEPTH, or walking it takes more than
    MAX_SCAN_STEPS steps. Per byte of the body (no character is shorter than a byte): the body
    itself (1); the str json.loads decodes it to, at the widest character's width (widths: 1, 2 or
    4); and the strings parsed out of it at theirs, twice over -- the C parser builds an escaped
    string in a writer that over-allocates by a quarter and, widening, holds the narrow buffer
    beside the wide one (1.56 times the string at the worst measured: 10.25 bytes per byte with the
    decoded input). So 13 times its bytes at most. Then VALUE_COST per JSON value, values bounded
    from the structure: one for the top, two per opening bracket (itself and its first element),
    one per comma or colon. _parse_in_child holds the parse to this bound.

    A count of those bytes over the whole body answers at C speed when it is within bounds (it
    can only overcount, by bytes inside strings), which covers an ordinary request. Otherwise the
    body is walked once outside its strings: the next structural byte is found by a one-byte regex,
    a string is skipped to its closing quote by _string_end. Its extra memory is O(1), and the walk
    stops as soon as a bound is passed."""
    wide_in, wide_str = widths(body)
    base = len(body) * (1 + wide_in + 2 * wide_str)
    if base > limit:
        return None
    opens = body.count(b"[") + body.count(b"{")
    crude = 1 + 2 * opens + body.count(b",") + body.count(b":")
    if opens <= MAX_DEPTH and base + crude * VALUE_COST <= limit:
        return base + crude * VALUE_COST
    values, depth, steps, at = 1, 0, 0, 0
    while (found := _STRUCTURAL.search(body, at)) is not None:
        here = found.start()
        byte, at = body[here], here + 1
        steps += 1
        if byte == 0x22:  # a string: its content is never structure
            skipped = _string_end(body, at, steps)
            if skipped is None:
                return None
            at, steps = skipped
        elif byte in b"[{":
            depth += 1
            values += 2
            if depth > MAX_DEPTH:
                return None
        elif byte in b"]}":
            depth -= 1
        else:  # a comma or a colon: one more value follows
            values += 1
        if steps > MAX_SCAN_STEPS or base + values * VALUE_COST > limit:
            return None
    return base + values * VALUE_COST


def terms(doc):
    """(why the body cannot be priced or None, its price multiplier, its inline images)."""
    if not isinstance(doc, dict):
        return "the body is not a JSON object", 1.0, 0
    if extra := sorted(set(doc) - FIELDS):
        return f"a field the broker cannot price: {', '.join(extra)}", 1.0, 0
    if model_key(doc.get("model")) is None:
        return f"no price for model {doc.get('model')!r}: the broker runs only {', '.join(sorted(PRICES))}", 1.0, 0
    max_tokens = doc.get("max_tokens")
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
        return "the body carries no positive integer max_tokens", 1.0, 0
    for tool in doc.get("tools") or []:
        kind = tool.get("type") if isinstance(tool, dict) else "malformed"
        if kind not in (None, "custom"):
            return f"a {kind} tool is not the client's own: it is billed beyond the request's tokens", 1.0, 0
    if not isinstance(doc.get("context_management") or {}, dict):
        return "context_management is not an object", 1.0, 0
    for edit in (doc.get("context_management") or {}).get("edits") or []:
        kind = edit.get("type") if isinstance(edit, dict) else "malformed"
        if not (isinstance(kind, str) and kind.startswith("clear_")):
            return f"a {kind} context edit runs inference beyond the request's tokens", 1.0, 0
    if doc.get("service_tier", "standard_only") != "standard_only":
        return f"service tier {doc['service_tier']!r} is not priced", 1.0, 0
    if doc.get("speed") not in (None, "standard", "fast"):
        return f"speed {doc['speed']!r} is not priced", 1.0, 0
    geo = doc.get("inference_geo")
    if geo is not None and (not isinstance(geo, str) or geo not in GEO):
        return f"inference geography {geo!r} is not priced", 1.0, 0
    found = {"images": 0}
    if why := content_problem([doc.get("system"), doc.get("messages")], found):
        return why, 1.0, 0
    return None, GEO.get(geo, GEO_WORST) * (FAST if doc.get("speed") == "fast" else 1.0), found["images"]


def settle_mult(usage, fast):
    """The price multiplier a finished call is billed at: the geography and speed the API reports
    it ran at (the worst geography when it reports none), fast when either side says so."""
    return GEO.get(usage.get("inference_geo"), GEO_WORST) * (FAST if fast or usage.get("speed") == "fast" else 1.0)


def merged_usage(seen, usage):
    """The API reports usage at message_start and (cumulatively) at message_delta: keep each
    count's largest value, the cache-write split's and the server tools' included."""
    for key, value in (usage or {}).items():
        if isinstance(value, int) and not isinstance(value, bool):
            seen[key] = max(seen.get(key, 0), value)
        elif key in ("cache_creation", "server_tool_use") and isinstance(value, dict):
            merged_usage(seen.setdefault(key, {}), value)
        elif key == "iterations" and isinstance(value, list):
            seen[key] = value
        elif key in ("inference_geo", "speed") and isinstance(value, str):
            seen[key] = value
    return seen


class Ledger:
    """The reservation ledger: settled spend, the calls in flight, and the append-only file."""

    def __init__(self, path, cap_usd):
        self.cap, self.settled, self.inflight, self.n = cap_usd, 0.0, {}, 0
        self.free_calls = self.free_bytes = 0
        self.dropped, self.faults, self.refused, self.written, self.catch_up = {}, {}, {}, {}, None
        self.lock = threading.Lock()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        self.fh = os.fdopen(fd, "a", encoding="utf-8")
        self.write({"event": "open", "cap_usd": cap_usd, "prices_usd_per_mtok": PRICES, "tiered": TIERED, "geo": GEO,
                    "image_tokens": IMAGE_TOKENS,
                    "framing_tokens": FRAMING_TOKENS, "pid": os.getpid()})

    def write(self, entry):
        tally = {"free_calls": self.free_calls, "free_bytes": self.free_bytes} if self.free_calls else {}
        if self.dropped:
            tally["dropped"] = dict(self.dropped)
        if self.faults:
            tally["faults"] = dict(self.faults)
        if self.refused:
            tally["refused"] = dict(self.refused)
        self.fh.write(json.dumps({"at": now(), **entry, **tally}, sort_keys=True) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())

    def free(self, nbytes):
        """True when one more count_tokens call of `nbytes` fits the free-call bound (W5-17): free
        is not unbounded, and what was used is on the record."""
        with self.lock:
            if self.free_calls + 1 > FREE_CALLS_MAX or self.free_bytes + nbytes > FREE_BYTES_MAX:
                self._refuse("count_tokens", f"the count_tokens bound ({FREE_CALLS_MAX} calls, {FREE_BYTES_MAX} bytes)")
                return False
            self.free_calls += 1
            self.free_bytes += nbytes
            if self.free_calls % FREE_RECORD_EVERY == 0:
                self.write({"event": "free", "calls": self.free_calls, "bytes": self.free_bytes})
            return True

    def _due(self, kind):
        """True when a line of `kind` may be written now: the first, then one a DROP_RECORD_S. One
        not written now is still counted, and a "tally" line DROP_RECORD_S later carries it, so
        no count waits for a later event that may never come (the container is destroyed, not
        stopped). Called with the lock held."""
        if time.monotonic() - self.written.get(kind, float("-inf")) < DROP_RECORD_S:
            if self.catch_up is None:
                self.catch_up = threading.Timer(DROP_RECORD_S, self._tally)
                self.catch_up.daemon = True
                self.catch_up.start()
            return False
        self.written[kind] = time.monotonic()
        return True

    def _tally(self):
        with self.lock:
            self.catch_up = None
            if not self.fh.closed:  # a broker shut down in-process (the tests) has closed it
                self.write({"event": "tally"})

    def drop(self, why):
        """A connection closed without an answer (evicted, slots full, a request past its deadline,
        a malformed one): counted, and written as a "drop" line at most every DROP_RECORD_S per
        reason, so a flood of them cannot flood the ledger (2026-10-27 re-attack, W5-16)."""
        with self.lock:
            self.dropped[why] = self.dropped.get(why, 0) + 1
            if self._due(("drop", why)):
                self.write({"event": "drop", "why": why, "count": self.dropped[why]})

    def fault(self, where, err):
        """A fault, recorded where it is kept: the exception's type and frames, never its message
        (which may quote a request), a request, a response or the token (W5-18). Counted per
        where and type, and written like a drop: the first, then at most one a DROP_RECORD_S, so a
        client resetting connections in a loop cannot grow the ledger, and an fsync, per reset."""
        self.fault_named(where, type(err).__name__, _frames(err))

    def fault_named(self, where, name, frames):
        """A fault by its exception's type name and frames: one raised where they were taken, in a
        parse child (_parse_in_child), which hands back only those."""
        kind = f"{where}:{name}"
        with self.lock:
            self.faults[kind] = self.faults.get(kind, 0) + 1
            if self._due(("fault", kind)):
                self.write({"event": "fault", "where": where, "error": name, "frames": frames,
                            "count": self.faults[kind]})

    def reserve(self, model, usd):
        """A call id when the call fits under the cap with every call in flight, else None."""
        with self.lock:
            committed = self.settled + sum(self.inflight.values())
            if committed + usd > self.cap:
                self._refuse("cap", "the cap", model, reserved_usd=round(usd, 6), committed_usd=round(committed, 6))
                return None
            self.n += 1
            self.inflight[self.n] = usd
            self.write({"event": "start", "call": self.n, "model": model, "reserved_usd": round(usd, 6)})
            return self.n

    def refuse(self, kind, why, model=None):
        with self.lock:
            self._refuse(kind, why, model)

    def _refuse(self, kind, why, model=None, **detail):
        """A refusal of `kind` (path, terms, cap, count_tokens), counted, and written like a drop:
        the first, then at most one a DROP_RECORD_S per kind, the counts riding every line. Its text
        is bounded, since `why` and `model` quote what the client sent: a refusal was one fsynced
        line holding a model name twice, so 20 requests naming an 8 MiB model wrote 335 MB to the
        operator's disk (2026-10-27 re-attack of 4b24dfde, beside W5-16/W5-17). Lock held."""
        self.refused[kind] = self.refused.get(kind, 0) + 1
        if self._due(("refuse", kind)):
            self.write({"event": "refuse", "kind": kind, "model": short(model), "why": short(why, 300), **detail,
                        "count": self.refused[kind]})

    def settle(self, call, usd, status, usage, complete):
        """Release the call's reservation and settle `usd`, or the whole reservation when None."""
        with self.lock:
            reserved = self.inflight.pop(call, 0.0)
            usd = reserved if usd is None else usd
            self.settled += usd
            self.write({"event": "settle", "call": call, "cost_usd": round(usd, 6), "status": status, "usage": usage,
                        "complete": complete, "settled_usd": round(self.settled, 6)})


class _DeadlineReader(io.RawIOBase):
    """A socket's reads, each bounded by what is left of one shared deadline."""

    def __init__(self, sock, deadline, per_read):
        super().__init__()
        self.sock, self.deadline, self.per_read = sock, deadline, per_read

    def readable(self):
        return True

    def readinto(self, buffer):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("the request's deadline passed")
        self.sock.settimeout(min(left, self.per_read))
        return self.sock.recv_into(buffer)


class Broker(BaseHTTPRequestHandler):
    """One request: forwarded with the token in place of the client's credential, or refused."""

    server_version = "open-fleet-live-broker"
    token = ledger = upstream = None  # set by serve()
    request_deadline = REQUEST_DEADLINE_S

    def log_message(self, *args):  # no request line anywhere: the ledger is the record
        pass

    def setup(self):
        """The usual buffered streams, except that every read of the request is held to ONE
        deadline: the per-read socket timeout restarts with each byte, so a client trickling the
        request line a byte at a time kept its thread for ever (re-attack, W5-16)."""
        super().setup()
        self.reader = _DeadlineReader(self.connection, time.monotonic() + self.request_deadline, self.timeout)
        self.rfile = io.BufferedReader(self.reader)

    def log_error(self, format, *args):
        # http.server reports a timed-out or malformed request here; record its kind, never its text.
        if self.server.was_evicted(self.connection):
            return  # its eviction is the drop already counted
        self.ledger.drop("request timed out" if format.startswith("Request timed out") else "malformed request")

    def handle(self):
        """One request (http.server's HTTP/1.0: never a second on the same connection). A
        connection closed before its request line is a drop; an evicted one's socket errors are
        the eviction's, already counted, never a fault."""
        try:
            super().handle()
        except OSError:
            if not self.server.was_evicted(self.connection):
                raise
            return
        if not getattr(self, "raw_requestline", b"") and not self.server.was_evicted(self.connection):
            self.ledger.drop("closed before a request")

    def fail(self, status, kind, why):
        data = json.dumps({"type": "error", "error": {"type": kind, "message": f"open-fleet live broker: {why}"}})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data.encode())

    def do_GET(self):
        if not self.server.request_read(self.connection):
            return  # evicted while it stalled: closed unanswered, and counted
        if self.path == "/health":
            data = json.dumps({"ok": True, "cap_usd": self.ledger.cap}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.ledger.refuse("path", f"GET {urllib.parse.urlsplit(self.path).path}")
        self.fail(403, "permission_error", "only POST /v1/messages and /v1/messages/count_tokens are forwarded")

    def do_POST(self):
        target = urllib.parse.urlsplit(self.path)
        path = target.path
        self.target = path + (f"?{target.query}" if target.query else "")  # what is forwarded: never a host
        if path not in (PRICED_PATH, FREE_PATH):
            self.ledger.refuse("path", f"POST {path}")
            return self.fail(403, "permission_error", "only POST /v1/messages and /v1/messages/count_tokens are forwarded")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.fail(411, "invalid_request_error", "a request needs a Content-Length")
        if not 0 <= length <= MAX_BODY:
            return self.fail(413, "invalid_request_error", f"a body over {MAX_BODY} bytes")
        # Before a byte is read, the most a body of this length can need parsed as text
        # (WORST_PER_BYTE) is taken, by a request holding none while it waits; what the pre-scan
        # finds it does not need goes back at once, and a body whose JSON values need more takes
        # it then, at most one body waiting for that at a time (answer_post, _BodyBudget).
        bodies, worst = self.server.bodies, WORST_PER_BYTE * length
        if worst > bodies.limit:
            self.ledger.refuse("body-parse", f"a {length}-byte body, which could parse past the "
                                             f"{bodies.limit}-byte budget")
            return self.fail(413, "invalid_request_error", "the body is too large for the broker to parse within "
                                                           "its memory")
        self.ticket = ticket = _Ticket(self.connection, length)
        self.body = None  # the body's one buffer, once read_body allocates it
        self.server.track(self.connection, ticket)
        try:
            # Budget goes only to a body that is arriving: its first byte must be here (a stalled
            # request waits for it holding no budget, and is evictable like any reader).
            self.reader.deadline = time.monotonic() + BODY_DEADLINE_S
            if length and not self.body_arriving():
                if not self.server.was_evicted(self.connection):
                    self.ledger.drop("body did not arrive")
                return None
            if not bodies.take(ticket, worst, time.monotonic() + BODY_WAIT_S, self.server.reclaimed):
                if ticket.cancelled:
                    return None  # evicted while it waited: closed unanswered, and counted
                self.ledger.refuse("body-budget", f"{length} body bytes and their parse past the {bodies.limit} "
                                                  "held at once")
                return self.fail(503, "overloaded_error", "the broker holds as many request bodies as it can; retry")
            ticket.since, ticket.arriving = time.monotonic(), True
            self.answer_post(path, length)
        finally:
            # The charge for a body's bytes goes back only once its buffer is gone, on every way
            # out: an exception's frames still reference it here, so it is emptied in place first
            # (Codex round 1 on PR #732). What is past its bytes may go back earlier, never they.
            self.drop_body()
            bodies.give(ticket)

    def drop_body(self):
        """Free this request's body buffer in place, whatever still references it. Its one export,
        read_body's view, is released before read_body returns, so this never fails; if it did, the
        BufferError would escape (a fault) before any of the share went back, which then stays held:
        never a charge returned while its bytes live."""
        body, self.body = self.body, None
        if body is not None:
            body.clear()

    def body_arriving(self):
        """Whether the body's first byte arrives before the body's deadline (or an eviction)."""
        try:
            return bool(self.rfile.peek(1))
        except (TimeoutError, OSError):
            return False

    def answer_post(self, path, length):
        """do_POST once the body's bytes are taken from the budget (BODY_BUDGET)."""
        body = self.read_body(length)
        self.ticket.arriving = False  # read in full, or never: no longer a body that may stall
        if not self.server.request_read(self.connection):
            return  # evicted while it stalled: closed unanswered, and counted (W5-16)
        self.connection.settimeout(self.timeout)  # the answer's writes get the plain per-call timeout
        if body is None:
            # Already counted (a "body" fault, or a "body did not arrive" drop): a client that is
            # gone cannot be told, and that is not a second fault.
            with contextlib.suppress(OSError):
                self.fail(408, "invalid_request_error", f"the body did not arrive within {BODY_DEADLINE_S:g} s")
            return
        bodies, ticket = self.server.bodies, self.ticket
        if path == FREE_PATH:  # relayed unparsed: only its bytes stay held
            bodies.give(ticket, ticket.held - len(body))
            if not self.ledger.free(len(body)):
                return self.fail(403, "permission_error", "the count_tokens bound would be passed")
            return self.relay(body, None, None, False)
        # What parsing may allocate is bounded BEFORE anything parses the body, and held in the same
        # budget as its bytes: holding the body once never bounded its parse (Codex rounds 7 and 9).
        cost = parse_cost(body, bodies.limit)
        if cost is None:
            self.ledger.refuse("body-parse", f"a {len(body)}-byte body whose parse could pass the "
                                             f"{bodies.limit}-byte budget, or that nests past {MAX_DEPTH}")
            return self.fail(413, "invalid_request_error", "the body's JSON is too large or too deeply nested "
                                                           "for the broker to parse within its memory")
        # A larger charge than the one taken before the body was read is waited for by at most one
        # body read in full at a time; any other is refused at once and gives back all but its
        # bytes' charge, so bodies read in full never wait on one another's shares (_BodyBudget,
        # Codex round 13); its bytes' charge goes back with its buffer (do_POST).
        if cost <= ticket.held:
            bodies.give(ticket, ticket.held - cost)
        elif not bodies.take(ticket, cost - ticket.held, time.monotonic() + BODY_WAIT_S, self.server.reclaimed,
                             grow=True):
            bodies.give(ticket, ticket.held - len(body))  # its parse's share; its bytes' stays until they go
            self.ledger.refuse("body-budget", f"a parse of up to {cost} bytes past the {bodies.limit} held at once")
            return self.fail(503, "overloaded_error", "the broker holds as many request bodies as it can; retry")
        self.price_and_relay(body, cost - len(body))

    def price_and_relay(self, body, allowance):
        """Parse a body parse_cost has bounded, and whose bound is taken, in a child held to that
        bound; check its terms, reserve its worst case, and relay it. The broker never holds the
        parsed body."""
        facts = _parse_in_child(body, allowance)
        # The parse child has exited: what its bound held goes back, and the body keeps its buffer.
        self.server.bodies.give(self.ticket, self.ticket.held - len(body))
        if facts.get("error"):
            # A fault in the child (in terms(), say): recorded as a handler fault, and, as one
            # raised here would, the connection is closed unanswered.
            self.ledger.fault_named("handler", short(str(facts["error"]), 80),
                                    [short(str(f), 200) for f in facts.get("frames") or []][-12:])
            self.close_connection = True
            return None
        if facts.get("memory") or facts.get("timeout"):
            why = "its parse passed its bound" if facts.get("memory") else f"it did not parse in {PARSE_SECONDS} s"
            self.ledger.refuse("body-parse", f"a {len(body)}-byte body: {why}")
            return self.fail(413, "invalid_request_error", "the body's JSON could not be parsed within the "
                                                           "broker's memory")
        why, model = facts["why"], facts["model"]
        if why:
            self.ledger.refuse("terms", why, model)
            return self.fail(400, "invalid_request_error", why)
        call = self.ledger.reserve(model, reservation(len(body), facts["max_tokens"], model, facts["mult"],
                                                      facts["images"]))
        if call is None:
            return self.fail(403, "permission_error", f"the spend cap (${self.ledger.cap:g}) would be passed")
        self.relay(body, call, model, facts["fast"])

    def read_body(self, length):
        """The request's `length` body bytes, or None when they do not all arrive by the deadline:
        the socket timeout bounds each read, this bounds the trickle (W5-16). Read into ONE buffer
        of exactly `length` bytes, never chunks joined after (which held each body twice)."""
        body = self.body = bytearray(length)  # do_POST frees it before its charge goes back
        got, deadline = 0, time.monotonic() + BODY_DEADLINE_S
        view = memoryview(body)
        try:
            while got < length:
                if time.monotonic() > deadline:
                    break
                try:
                    n = self.rfile.readinto1(view[got:got + (1 << 20)])
                except TimeoutError:  # the body's deadline, or the per-read timeout: not a fault
                    break
                except OSError as err:  # the client's connection failed
                    if not self.server.was_evicted(self.connection):
                        self.ledger.fault("body", err)
                    return None
                if not n:
                    break
                got += n
                self.ticket.got = got  # its progress: a body that stalls can be evicted (_BodyBudget)
        finally:
            view.release()
        if got < length:
            if not self.server.was_evicted(self.connection):
                self.ledger.drop("body did not arrive")
            return None
        return body

    def relay(self, body, call, model, fast):
        """Forward to the API and relay the answer as it arrives; settle the call's usage."""
        usage, complete, status, conn = {}, False, None, None
        try:
            up = urllib.parse.urlsplit(self.upstream)
            conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
            conn = conn_cls(up.hostname, up.port, timeout=UPSTREAM_TIMEOUT_S)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP}
            betas = [b.strip() for b in self.headers.get("anthropic-beta", "").split(",") if b.strip()]
            headers = {k: v for k, v in headers.items() if k.lower() != "anthropic-beta"}
            headers.update({"Authorization": f"Bearer {self.token}", "Accept-Encoding": "identity",
                            "anthropic-beta": ",".join(betas + ([OAUTH_BETA] if OAUTH_BETA not in betas else []))})
            conn.request("POST", self.target, body=body, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            self.send_response(resp.status)
            for key, value in resp.getheaders():
                if key.lower() not in DROP_BACK:
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            sse = "text/event-stream" in (resp.getheader("Content-Type") or "")
            pending, whole = b"", []
            while chunk := resp.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
                if call is None:
                    continue
                if not sse:
                    whole.append(chunk)
                    continue
                pending += chunk
                *lines, pending = pending.split(b"\n")
                for line in lines:
                    if not line.startswith(b"data:"):
                        continue
                    try:
                        event = json.loads(line[5:])
                    except ValueError:
                        continue
                    if event.get("type") == "message_start":
                        merged_usage(usage, (event.get("message") or {}).get("usage"))
                    elif event.get("type") == "message_delta":
                        merged_usage(usage, event.get("usage"))
                    elif event.get("type") == "message_stop":
                        complete = True
            if call is not None and not sse:
                try:
                    doc = json.loads(b"".join(whole))
                except ValueError:
                    doc = None
                if isinstance(doc, dict) and isinstance(doc.get("usage"), dict):
                    merged_usage(usage, doc["usage"])
                    complete = status == 200
                elif status != 200:  # an error the API answered at once bills nothing
                    complete = True
        except Exception as err:  # the client left, or the API did: whatever ran is settled below
            # Recorded where it is kept (the container keeps no log): type and frames only.
            self.ledger.fault("relay", err)
            if status is None:
                try:
                    self.fail(502, "api_error", f"the API could not be reached ({type(err).__name__})")
                except OSError as reply_err:  # the client is gone too
                    self.ledger.fault("relay-reply", reply_err)
        finally:
            if conn is not None:
                conn.close()
            if call is not None:
                # Priced inside its own guard, so a usage report of a shape the broker cannot price
                # still settles (its whole reservation) and is recorded, never skipped (W5-18).
                usd = None
                if complete:
                    try:
                        usd = settled(usage, model, settle_mult(usage, fast))
                    except Exception as err:  # any type surprise in the report: settle the reservation
                        self.ledger.fault("settle", err)
                self.ledger.settle(call, usd, status, usage, complete)


def read_token(path):
    """The token, from the read-only mount: one ASCII line. A refusal names the path, never a byte."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        token = raw.decode("ascii").strip()
    except (OSError, UnicodeDecodeError) as err:
        raise SystemExit(f"live_broker: cannot read the token at {path} ({type(err).__name__})") from None
    if not token or any(c.isspace() for c in token):
        raise SystemExit(f"live_broker: the token at {path} must be one line")
    return token


class _Ticket:
    """One request's share of BODY_BUDGET: what it holds (`held`), its body buffer's part of that
    (`raw`, its Content-Length), how much of its body has arrived (`got`) since its budget was
    granted (`since`), whether its body is still arriving, and whether it was evicted."""

    __slots__ = ("request", "raw", "held", "got", "since", "arriving", "cancelled")

    def __init__(self, request, length):
        self.request, self.raw, self.held, self.got = request, length, 0, 0
        self.since, self.arriving, self.cancelled = 0.0, False, False

    def stalled(self, now):
        """Its body is still arriving, but slower than MIN_BODY_RATE once BODY_GRACE_S has passed."""
        return self.arriving and self.got < self.raw and \
            self.got < MIN_BODY_RATE * (now - self.since - BODY_GRACE_S)


class _BodyBudget:
    """BODY_BUDGET: what the bodies of all connections, and their parses, hold at once. A request
    takes from it with `take`, which waits for room until a deadline; while it waits it takes back
    what any stalled body holds past its buffer (`_reclaim`), so stalled requests cannot keep the
    budget from one whose body is arriving, and what it takes back is its own at once, never handed
    to another waiter. An evicted request's wait ends at once (`cancel`). `give` returns a share.

    The invariant that keeps it deadlock-free: AT MOST ONE REQUEST WAITS FOR BUDGET WHILE HOLDING
    ANY. A body's first take is made before it holds any (do_POST); only a body read in full whose
    parse needs more than it took before it was read takes again holding a share (`grow`), and of
    those only one -- the grower -- may wait: any other whose charge does not fit at once is refused
    and gives back at once all it holds past its bytes, whose charge it keeps only until its buffer
    is freed, as it ends (do_POST). While the grower waits every other take leaves what it still
    needs free, so nothing granted after it can keep it out. Every share it waits for is held by a
    request that never waits for budget -- a body arriving (ended by BODY_DEADLINE_S, or taken back
    once stalled), pre-scanned (MAX_SCAN_STEPS), parsed (PARSERS at a time, each in PARSE_SECONDS)
    or relayed, or one refused and ending, its 503 written -- and every other waiter holds nothing
    anyone waits for, so no set of requests can wait on one another: the grower is served once those
    end, or its own deadline answers it (Codex round 13 on 594f7265: 32 completed ~1 MB bodies, each
    holding its first share and waiting for a larger one, waited on one another until every one was
    refused). No share is ever given back below a body's bytes while its buffer holds them."""

    def __init__(self, limit):
        self.limit, self.held, self.cond = limit, 0, threading.Condition()
        self.tickets = set()  # every ticket holding a share
        self.grower, self.growth = None, 0  # the one request waiting while it holds a share, and what it needs

    def take(self, ticket, n, deadline, reclaimed, grow=False):
        """Add `n` to `ticket`'s share; False when it was evicted (cancelled) or the deadline passed
        first, or -- `grow`, a body read in full that holds a share and needs `n` more for its
        parse -- at once when another such body already waits (the grower: see the class's
        invariant). A take other than the grower's fits only beside what the grower still needs.
        `reclaimed(ticket)` is called, outside the lock and AT ONCE, for each stalled request
        whose share was taken back, to evict it: its thread then ends and gives its buffer back, and
        this wait goes on for that (re-attack of c952fa4f: the evictions ran only once the wait was
        over, so a stalled 32 MB body kept its buffer charge and a 32 MB call behind it got 503). A
        wait whose deadline passes while an evicted request's buffer is still on its way back waits
        up to RELEASE_WAIT_S more for it."""
        grace = deadline + RELEASE_WAIT_S
        try:
            while True:
                victims = []
                try:
                    with self.cond:
                        if ticket.cancelled:
                            return False
                        if n <= 0:  # nothing to take: never a wait
                            return True
                        room = self.limit - (self.growth if self.grower not in (None, ticket) else 0)
                        if self.held + n > room:
                            victims = self._reclaim(n, room)
                        if self.held + n <= room:
                            self.held += n
                            ticket.held += n
                            self.tickets.add(ticket)
                            if self.grower is ticket:  # served: what it needed is now held, not kept free
                                self.grower, self.growth = None, 0
                            return True
                        if grow and self.grower is None:
                            self.grower, self.growth = ticket, n
                        elif grow and self.grower is not ticket:
                            return False  # another body read in full already waits holding a share
                        if not victims:
                            now = time.monotonic()
                            releasing = sum(t.held for t in self.tickets if t.cancelled)
                            end = grace if self.held - releasing + n <= room else deadline
                            if now >= end:
                                return False
                            self.cond.wait(min(end - now, RECLAIM_POLL_S))
                finally:
                    # Every request whose share was taken back is evicted, on every way out of this
                    # step, success included, once the lock is free (Codex round 12 on 419a8435: a
                    # take that the share made fit returned before evicting, and the stalled body
                    # kept its socket and its buffer until its own timeout).
                    for victim in victims:
                        reclaimed(victim)
        finally:
            with self.cond:
                if self.grower is ticket:  # its deadline passed, or it was evicted: its claim on the room ends
                    self.grower, self.growth = None, 0
                    self.cond.notify_all()

    def _reclaim(self, n, room):
        """Take back, stalest first, what stalled bodies hold past their buffers (which their threads
        give back as they end), until `n` fits under `room`. Lock held. Returns the requests taken
        from."""
        now, victims = time.monotonic(), []
        for victim in sorted((t for t in self.tickets if t.stalled(now)),
                             key=lambda t: t.got - MIN_BODY_RATE * (now - t.since)):
            freed = max(0, victim.held - victim.raw)
            self.held -= freed
            victim.held -= freed
            victim.cancelled, victim.arriving = True, False
            victims.append(victim)
            if self.held + n <= room:
                break
        return victims

    def cancel(self, ticket):
        """An evicted request: its wait ends at once, and what it holds past its buffer is back."""
        with self.cond:
            ticket.cancelled, ticket.arriving = True, False
            freed = max(0, ticket.held - ticket.raw)
            self.held -= freed
            ticket.held -= freed
            self.cond.notify_all()

    def give(self, ticket, n=None):
        """Return `n` of `ticket`'s share (all of it by default)."""
        with self.cond:
            n = ticket.held if n is None else min(n, ticket.held)
            self.held -= n
            ticket.held -= n
            if not ticket.held:
                self.tickets.discard(ticket)
            self.cond.notify_all()


class BrokerServer(ThreadingHTTPServer):
    """At most `slots` connections served at once, and a fault in any of them recorded in the
    ledger rather than printed to a log nobody keeps (W5-16, W5-18).

    A connection is READING until its whole request has arrived. When every slot is taken, a new
    connection evicts the reading one that has waited longest (its socket is shut, so its thread
    ends at once) and takes the slot it gives up; a call already read in full is never evicted,
    and with none reading the new connection is closed unanswered. So a client trickling requests,
    however many connections it reopens, holds a slot only until the arm's own call needs it: that
    call's request is in the socket when its thread starts, and is read in full at once (2026-10-27
    re-attack of 4b24dfde, W5-16)."""

    daemon_threads = True

    def __init__(self, address, handler, ledger, slots):
        self.ledger, self.slots = ledger, threading.BoundedSemaphore(slots)
        self.bodies = _BodyBudget(BODY_BUDGET)
        self.reading, self.evicted, self.tickets, self.state = {}, set(), {}, threading.Lock()
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False) and not (self.evict() and self.slots.acquire(timeout=EVICT_WAIT_S)):
            self.ledger.drop("connection slots full")
            self.shutdown_request(request)
            return
        with self.state:
            self.reading[request] = time.monotonic()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.done(request)
            self.slots.release()
            raise

    def evict(self):
        """Shut the reading connection that has waited longest; False when none is reading. Reading
        covers every wait before a request is read in full -- its request line and headers, its
        body's first byte, its budget, its body -- and each ends at once: the socket is shut, and a
        wait for budget is cancelled (re-attack of c952fa4f: a waiter kept its slot until its budget
        deadline, 30 s, while the new connection waited 5 s for that slot)."""
        with self.state:
            if not self.reading:
                return False
            victim = min(self.reading, key=self.reading.get)
            del self.reading[victim]
            self.evicted.add(victim)
            ticket = self.tickets.get(victim)
        if ticket is not None:
            self.bodies.cancel(ticket)
        with contextlib.suppress(OSError):
            victim.shutdown(socket.SHUT_RDWR)
        self.ledger.drop("stalled request evicted")
        return True

    def reclaimed(self, ticket):
        """A stalled body whose share of the budget a waiting request took back: evicted."""
        with self.state:
            self.reading.pop(ticket.request, None)
            self.evicted.add(ticket.request)
        with contextlib.suppress(OSError):
            ticket.request.shutdown(socket.SHUT_RDWR)
        self.ledger.drop("stalled body evicted")

    def track(self, request, ticket):
        with self.state:
            self.tickets[request] = ticket

    def request_read(self, request):
        """`request`'s whole request has arrived: from here it keeps its slot. False when it was
        evicted first, and must then end without an answer."""
        with self.state:
            self.reading.pop(request, None)
            return request not in self.evicted

    def was_evicted(self, request):
        with self.state:
            return request in self.evicted

    def done(self, request):
        with self.state:
            self.reading.pop(request, None)
            self.evicted.discard(request)
            self.tickets.pop(request, None)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.done(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        err = sys.exc_info()[1]
        if isinstance(err, OSError) and self.was_evicted(request):
            return  # the eviction's own consequence, already counted as a drop
        self.ledger.fault("handler", err)


def _return_large_frees():
    """Fix glibc's mmap threshold at its 128 KiB default: past its first large free glibc raises
    the threshold up to 32 MiB, after which a body's buffer comes from a thread's heap and stays
    in its RSS once freed -- four 32 MB bodies on four threads left 114 MB held. Fixed, every
    buffer that large is its own mapping, returned when freed. A C library without mallopt, or
    another one, is left as it is."""
    with contextlib.suppress(OSError, AttributeError, TypeError):
        ctypes.CDLL(None).mallopt(-3, 128 << 10)  # M_MMAP_THRESHOLD


def serve(token, ledger_path, cap_usd, port=PORT, upstream=UPSTREAM, host="127.0.0.1"):
    """A started server (its own thread) and its ledger; the caller owns shutdown."""
    _return_large_frees()
    handler = type("BoundBroker", (Broker,), {"token": token, "ledger": Ledger(ledger_path, cap_usd),
                                              "upstream": upstream, "timeout": HANDLER_TIMEOUT_S,
                                              "request_deadline": REQUEST_DEADLINE_S})
    server = BrokerServer((host, port), handler, handler.ledger, MAX_CONNECTIONS)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler.ledger


def main(argv=None):
    p = argparse.ArgumentParser(prog="live_broker.py", description=__doc__.split("\n", 1)[0])
    p.add_argument("--token-file", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--cap-usd", type=float, required=True)
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--upstream", default=UPSTREAM, help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    if not args.cap_usd > 0:
        p.error("--cap-usd must be a positive number of dollars")
    server, _ledger = serve(read_token(args.token_file), args.ledger, args.cap_usd, args.port, args.upstream)
    print(f"live_broker: listening on 127.0.0.1:{server.server_address[1]}, cap ${args.cap_usd:g}", file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
