#!/usr/bin/env python3
"""search_sessions.py — orca search with an --index-status precheck (S19).

Upstream argv (pinned specs/search.ts, handlers/search.ts,
shared/ai-vault-search-contract.ts):

* ``search --index-status`` answers ``{enabled, phase, filesIndexed, filesDue,
  filesFailed, …}`` with phase ∈ idle|indexing|current|degraded|closed. This
  wrapper runs it FIRST: enabled=false or phase ∈ {degraded, closed} refuses
  (exit 2) before the query fires — searching an index the host reports broken
  proves nothing. current/idle/indexing proceed (--fresh asks the host to
  reconcile first, then searches anyway).
* ``search <query>|--query … [--scope conversation|all] [--fresh] [--limit 1-100]
  [--cursor …] [--agent …]* [--path …]* [--since <iso>] [--sort relevance|newest]
  [--debug]``. The query rides positionally or as --query, never both (upstream
  reads unquoted words as command names). --limit caps at 100; --since must be
  ISO 8601 with an offset.

Results answers print HITS=/NEXT_CURSOR=; stale-cursor, malformed-cursor, and
unavailable are failures (exit 1), never empty results. --precheck-only runs
just the verdict. Live index behavior is PARKED (needs-human: run against a
host mid-indexing and confirm phase gating).

--local-harnesses (and the automatic fallback when the runtime is not orca)
scans the ten harnesses' own session stores read-only — claude-code, codex,
opencode, omp, pi, jcode, goose, hermes, crush, openhands — each through a
reader that follows its upstream on-disk format (see the per-reader comments).
It is a token scan, not an index: every query re-reads the stores. One hit per
session; --since drops undated records; --path matches the session's cwd;
--cursor pages with the ``local:<offset>`` NEXT_CURSOR it printed (any other
cursor is refused). On EVERY path (Orca results included) every untrusted
field is fenced: snippets inside guard_text envelopes, and the
HIT-line fields (session id, score, title, role) folded to one line with
forged banners defused and directive-shaped text labelled — a transcript must
not be able to forge a HIT line or close an envelope. The episodic hint
applies the same defusing and labelling to every entry.

Exit: 0 ok · 1 runtime/refusal/receipt failure · 2 usage/precheck refusal.
"""
import argparse
import datetime
import fnmatch
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import orca_cli
except ImportError:  # loaded by file path (tests): the resolver sits beside this script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import orca_cli
import guard_text
from pm import _visible

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

GOOD_PHASES = ("current", "idle", "indexing")
SCOPES = ("conversation", "all")
SORTS = ("relevance", "newest")
DEFAULT_RUNS_DIR = Path(__file__).resolve().parent.parent.parent / "docs" / "runs"


class Refused(Exception):
    """Usage/validation/precheck refusal: exit 2, the query never fired."""


class Failed(Exception):
    """The runtime refused or the receipt is unreadable: exit 1."""


def _nonempty(value, flag):
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise Refused(f"{flag} needs a non-empty value")
    return value


def _limit(raw):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"--limit must be 1-100, got {raw!r}")
    value = int(raw)
    if value < 1 or value > 100:
        raise Refused(f"--limit must be 1-100, got {raw!r}")
    return raw


def _since(raw):
    try:
        stamp = raw.replace("Z", "+00:00") if isinstance(raw, str) else raw
        parsed = datetime.datetime.fromisoformat(stamp)
    except (ValueError, TypeError):
        raise Refused(f"--since must be ISO 8601 with an offset, e.g. "
                      f"2026-08-01T00:00:00Z — got {raw!r}")
    if parsed.tzinfo is None:
        raise Refused(f"--since must carry an offset, got {raw!r}")
    return raw


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="search_sessions.py",
        description="Orca session search with an index precheck.")
    parser.add_argument("query", nargs="?", default=None)
    parser.add_argument("--query", dest="query_flag", default=None)
    parser.add_argument("--scope", default=None)
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--limit", default=None)
    parser.add_argument("--cursor", default=None)
    parser.add_argument("--agent", action="append", default=[])
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--since", default=None)
    parser.add_argument("--sort", default=None)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--environment", default=None)
    parser.add_argument("--pairing-code", default=None)
    parser.add_argument("--precheck-only", action="store_true")
    parser.add_argument("--episodic-hint", action="store_true")
    parser.add_argument("--runs-dir", default=None)
    parser.add_argument("--local-harnesses", action="store_true")
    return parser.parse_args(argv)


def _one_line(text, limit=90):
    rendered = _visible(str(text or "")).replace("\\n", " ").replace("\\r", " ")
    collapsed = " ".join(rendered.splitlines()).strip()
    return collapsed[:limit]


def _path_matches(candidate, target):
    c = str(candidate).strip().lstrip("./")
    t = str(target).strip().lstrip("./")
    if not c or not t:
        return False
    if (c == t or fnmatch.fnmatchcase(c, t) or fnmatch.fnmatchcase(t, c)
            or c.startswith(t.rstrip("/") + "/")
            or t.startswith(c.rstrip("/") + "/")):
        return True
    if "/" not in c or "/" not in t:
        cb = os.path.basename(c)
        tb = os.path.basename(t)
        if cb and tb and "*" not in tb and "?" not in tb and cb == tb:
            return True
    return False


def _extract_unit_records(data):
    if not isinstance(data, dict):
        return []
    records = []
    if isinstance(data.get("units"), list):
        records.extend(u for u in data["units"] if isinstance(u, dict))
    if isinstance(data.get("unit"), dict):
        records.append(data["unit"])
    elif isinstance(data.get("unit"), str) and data["unit"].strip():
        records.append(data)
    return records


def _extract_touched_tokens(unit):
    touched = []
    for key in ("files_touched", "scope_allow"):
        val = unit.get(key)
        if isinstance(val, list):
            touched.extend(str(x) for x in val)
    oscope = unit.get("oracle_scope")
    if isinstance(oscope, dict) and isinstance(oscope.get("files"), list):
        touched.extend(str(x) for x in oscope["files"])
    prose_blobs = []
    for key in ("claim", "parking_reason"):
        if isinstance(unit.get(key), str):
            prose_blobs.append(unit[key])
    for key in ("intent", "negative_control", "touching"):
        obj = unit.get(key)
        if isinstance(obj, dict):
            prose_blobs.extend(str(v) for v in obj.values() if isinstance(v, str))
        elif isinstance(obj, str):
            prose_blobs.append(obj)
    for item in (unit.get("criteria") or []):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            prose_blobs.append(item["text"])
    for blob in prose_blobs:
        for tok in blob.replace("'", " ").replace('"', " ").replace("(", " ").replace(")", " ").split():
            cleaned = tok.strip(",:;`")
            if "/" in cleaned or cleaned.endswith((".py", ".sh", ".md", ".json", ".ts", ".yml")):
                touched.append(cleaned.split("@", 1)[0])
    return touched


def _guard_entry(line, *raw_fields):
    """An episodic-hint entry carries untrusted transcript/manifest text into a
    TRUSTED hint: banners defused (no forged envelope markers) and the entry
    labelled when any raw field — or the composed line — looks like a directive."""
    names = []
    for value in (*raw_fields, line):
        for name in guard_text.line_labels(str(value or "")):
            if name not in names:
                names.append(name)
    body = guard_text.defuse_banners(line)
    if names and body.startswith("- "):
        return f"- [INJECTION-PATTERN:{','.join(names)}] {body[2:]}"
    return f"[INJECTION-PATTERN:{','.join(names)}] {body}" if names else body


def build_episodic_hint(paths, runs_dir=None, session_hits=None, max_lines=15):
    """Build a bounded <= max_lines episodic memory hint from docs/runs manifests and session hits."""
    clean_paths = [_nonempty(p, "--path") for p in (paths or []) if p is not None]
    if not clean_paths and session_hits is None:
        raise Refused("--episodic-hint requires at least one --path or query")
    rdir = Path(runs_dir) if runs_dir is not None else DEFAULT_RUNS_DIR
    prior_entries = []
    if rdir.is_dir() and clean_paths:
        manifests = sorted(rdir.rglob("*manifest*.json"), reverse=True)
        for mf in manifests:
            try:
                data = json.loads(mf.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            run_id = _one_line(mf.parent.name if mf.parent != rdir else mf.stem, 48)
            for unit in _extract_unit_records(data):
                touched = _extract_touched_tokens(unit)
                if not any(_path_matches(f, p) for f in touched for p in clean_paths):
                    continue
                raw_uid = unit.get("id") or unit.get("unit_id") or unit.get("unit") or "unit"
                uid = _one_line(raw_uid, 40)
                status = _one_line(unit.get("status") or "recorded", 24)
                intent = unit.get("intent") if isinstance(unit.get("intent"), dict) else {}
                inv = _one_line(intent.get("invariant") or intent.get("goal") or intent.get("why") or unit.get("claim") or "", 90)
                park = _one_line(unit.get("parking_reason") or "", 90)
                detail = f"parked={park}" if park else (f"invariant={inv}" if inv else "touched matching scope")
                prior_entries.append(_guard_entry(
                    f"- [run {run_id} / {uid} ({status})] {detail}",
                    raw_uid, unit.get("parking_reason"), inv))

    hit_entries = []
    for hit in (session_hits or []):
        if not isinstance(hit, dict):
            continue
        sid = _one_line(hit.get("sessionId") or "?", 40)
        title = _one_line(hit.get("title") or "(untitled)", 60)
        ev = hit.get("evidence") if isinstance(hit.get("evidence"), dict) else {}
        snip = _one_line(ev.get("snippet") or "", 80)
        suffix = f" — {snip}" if snip else ""
        hit_entries.append(_guard_entry(
            f"- [session {sid}] {title}{suffix}",
            hit.get("sessionId"), hit.get("title"), ev.get("snippet")))

    header = [
        "EPISODIC_HINT: Prior Runs & Pitfalls (max 15 lines)",
        "PATHS: " + guard_text.defuse_banners(
            ', '.join(_one_line(p, 80) for p in clean_paths) if clean_paths else '(query-only)'),
        f"PRIOR_RUNS={len(prior_entries)} SESSION_HITS={len(hit_entries)}",
    ]
    budget = max(1, max_lines - len(header))
    combined = (prior_entries + hit_entries)[:budget]
    if not combined:
        combined = ["- (no prior run manifests or session hits matched this scope)"]
    flat = []
    for item in header + combined:
        flat.extend(" ".join(str(item).splitlines()).strip() for _ in (0,))
    return flat[:max_lines]


def build_search_argv(ns):
    if (ns.query is None) == (ns.query_flag is None):
        raise Refused("pass the query positionally or as --query, not both "
                      "and not neither")
    query = ns.query if ns.query is not None else ns.query_flag
    if not query:
        raise Refused("the query must be non-empty")
    if ns.query is not None:
        argv = ["search", ns.query]
    else:
        argv = ["search", "--query", ns.query_flag]
    if ns.scope is not None:
        if ns.scope not in SCOPES:
            raise Refused(f"--scope must be one of {','.join(SCOPES)}, "
                          f"got {ns.scope!r}")
        argv += ["--scope", ns.scope]
    if ns.fresh:
        argv += ["--fresh"]
    if ns.limit is not None:
        argv += ["--limit", _limit(ns.limit)]
    if _nonempty(ns.cursor, "--cursor") is not None:
        argv += ["--cursor", ns.cursor]
    for agent in ns.agent:
        argv += ["--agent", _nonempty(agent, "--agent")]
    for path in ns.path:
        argv += ["--path", _nonempty(path, "--path")]
    if ns.since is not None:
        argv += ["--since", _since(ns.since)]
    if ns.sort is not None:
        if ns.sort not in SORTS:
            raise Refused(f"--sort must be one of {','.join(SORTS)}, "
                          f"got {ns.sort!r}")
        argv += ["--sort", ns.sort]
    if ns.debug:
        argv += ["--debug"]
    if _nonempty(ns.environment, "--environment") is not None:
        argv += ["--environment", ns.environment]
    if _nonempty(ns.pairing_code, "--pairing-code") is not None:
        argv += ["--pairing-code", ns.pairing_code]
    return argv


def check_index(status):
    """Precheck verdict: return the phase or raise Refused."""
    if not isinstance(status, dict):
        raise Refused("index precheck: the status receipt is not an object")
    if status.get("enabled") is not True:
        raise Refused("index precheck: the host reports enabled=false — the "
                      "index is off, so a search would prove nothing")
    phase = status.get("phase")
    if phase not in GOOD_PHASES:
        raise Refused(f"index precheck: phase={phase or 'absent'} — searching "
                      f"a degraded/closed index proves nothing")
    return phase


SNIPPET_LIMIT = 500


def _bounded(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated {len(text) - limit} chars]"


def _guard_labels(*values):
    """Injection-pattern labels across untrusted field values (detection only)."""
    names = []
    for value in values:
        for name in guard_text.line_labels(str(value or "")):
            if name not in names:
                names.append(name)
    return names


def _guard_field(value, limit=200):
    """Render one untrusted field for a TRUSTED framing line (HIT/EPISODIC lines).

    Inert (_visible escapes controls), one line (newlines folded, so a title
    cannot fabricate a HIT/SNIPPET line), banners defused (a title cannot forge
    a `<<< END UNTRUSTED` marker), and directive-shaped text labelled.
    """
    raw = str(value if value is not None else "")
    text = _visible(raw).replace("\\n", " ").replace("\\r", " ")
    text = " ".join(text.split())[:limit]
    text = guard_text.defuse_banners(text)
    names = _guard_labels(raw)
    return f"[INJECTION-PATTERN:{','.join(names)}] {text}" if names else text


def _source_name(agent):
    """The envelope's source word sits inside the banner: keep it a bare token."""
    token = "".join(ch for ch in str(agent or "session") if ch.isalnum() or ch in "-_")
    return (token or "session")[:32]


def format_results(result):
    """Render a results receipt. Every path (Orca, local harnesses, fallback)
    fences: HIT-line fields are folded/defused (_guard_field) and every snippet
    sits inside a guard_text envelope with each body line indented, so no
    untrusted text can start a line with HIT/SNIPPET or close the envelope."""
    if not isinstance(result, dict):
        raise Failed("search receipt is not an object")
    kind = result.get("kind")
    if kind != "results":
        detail = result.get("reason") or ""
        raise Failed(f"search answered {kind or 'unknown'}"
                     f"{' (' + detail + ')' if detail else ''} — not results")
    hits = result.get("hits")
    if not isinstance(hits, list):
        raise Failed("search results answer names no hits")
    page = result.get("page") if isinstance(result.get("page"), dict) else {}
    lines = [f"HITS={len(hits)}",
             f"NEXT_CURSOR={_guard_field(page.get('cursor') or 'none', 120)}"]
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        ev = hit.get("evidence") if isinstance(hit.get("evidence"),
                                               dict) else {}
        snippet = ev.get("snippet") if isinstance(ev.get("snippet"),
                                                  str) else ""
        # Every field on the HIT line is untrusted (a transcript can name its own
        # session): one line, inert, banners defused, directives labelled.
        lines.append(f"HIT {_guard_field(hit.get('sessionId') or '?', 120)} "
                     f"score={_guard_field(hit.get('score', '?'), 24)} "
                     f"{_guard_field(hit.get('title') or '(untitled)', 200)}")
        role = _guard_field(ev.get("role", "?"), 32)
        if snippet:
            bounded_snip = _bounded(_visible(snippet), SNIPPET_LIMIT)
            indented = "\n".join("  " + ln for ln in bounded_snip.split("\n"))
            fenced_snip = guard_text.envelope(
                indented,
                source=_source_name(hit.get("agent")),
                label=_guard_field(hit.get("sessionId") or "?", 60),
            )
            lines.append(f"SNIPPET [{role}]:\n{fenced_snip}")
        else:
            lines.append("SNIPPET: (none)")
    return lines


# ---------------------------------------------------------------------------
# Native local transcript indexer (#581). Each reader follows the harness's
# real on-disk format (upstream source, cited per reader) and yields records:
#   {harness, session_id, title, cwd, timestamp, role, content, file_path}
# Every store is opened READ-ONLY; nothing here writes to a harness's data.
# ---------------------------------------------------------------------------

_AGENT_ALIASES = {
    "claude": "claude-code",
    "claude-code": "claude-code",
    "codex": "codex",
    "opencode": "opencode",
    "omp": "omp",
    "oh-my-pi": "omp",
    "pi": "pi",
    "pi-mono": "pi",
    "jcode": "jcode",
    "goose": "goose",
    "hermes": "hermes",
    "crush": "crush",
    "openhands": "openhands",
    "software-agent-sdk": "openhands",
}

# Content-block types that carry human-readable conversation text, across the
# harnesses' block vocabularies (tool calls/arguments and images are skipped).
_TEXT_BLOCK_TYPES = {"text", "input_text", "output_text", "tool_result",
                     "toolResult", "summary_text"}


def _norm_agent(name):
    raw = str(name or "").strip().lower()
    return _AGENT_ALIASES.get(raw, raw)


def _extract_text(val):
    if val is None:
        return ""
    if isinstance(val, str):
        stripped = val.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                parsed = json.loads(stripped)
                inner = _extract_text(parsed)
                if inner:
                    return inner
            except (ValueError, TypeError):
                pass
        return val
    if isinstance(val, list):
        parts = [_extract_text(item) for item in val]
        return " ".join(p for p in parts if p)
    if isinstance(val, dict):
        btype = val.get("type")
        if isinstance(btype, str) and btype and btype not in _TEXT_BLOCK_TYPES:
            # A typed block that is not text (tool call, image, thinking,
            # finish marker): no conversation text to index.
            return ""
        if btype and isinstance(val.get("data"), dict):
            # crush's {"type": "text"|"tool_result", "data": {...}} part wrapper.
            data = val["data"]
            return _extract_text({k: data[k] for k in ("text", "content") if k in data})
        parts = []
        for k in ("text", "content", "message", "body", "parts",
                  "observation", "summary", "output"):
            if k in val and val[k] is not None:
                sub = _extract_text(val[k])
                if sub:
                    parts.append(sub)
        return " ".join(parts)
    if isinstance(val, (int, float, bool)):
        return ""
    return str(val)


def _parse_any_ts(val):
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        ts = float(val)
        if ts > 1e11:
            ts /= 1000.0
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(val, str):
        s = val.strip()
        if s.replace(".", "", 1).isdigit():
            return _parse_any_ts(float(s))
        try:
            if s.endswith(("Z", "z")):
                s = s[:-1] + "+00:00"
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.astimezone(datetime.timezone.utc)
        except ValueError:
            return None
    return None


def _env_path(*names):
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return Path(value).expanduser()
    return None


def _home():
    return Path(os.environ.get("HOME") or str(Path.home()))


def _xdg_data_home():
    return _env_path("XDG_DATA_HOME") or (_home() / ".local" / "share")


def _rec(harness, sid, title, cwd, ts, role, content, fp):
    return {"harness": harness, "session_id": str(sid or ""), "title": str(title or ""),
            "cwd": str(cwd or ""), "timestamp": ts, "role": str(role or "assistant"),
            "content": content, "file_path": str(fp)}


def _read_jsonl(fp):
    try:
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _read_json(fp):
    try:
        data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return data


def _glob(root, *patterns):
    found = set()
    if root is None or not root.is_dir():
        return []
    for pat in patterns:
        found.update(p for p in root.glob(pat) if p.is_file())
    return sorted(found)


def _sqlite_ro(path):
    """Read-only connection that never creates, migrates, or journals a harness DB.

    ``?mode=ro`` alone still CREATES (and leaves) ``-wal``/``-shm`` beside a
    WAL-mode database (Hermes, OpenCode, Crush, Goose all run WAL). So:

    * both side files already exist (a live writer holds the WAL): ``mode=ro``
      reads through the WAL — nothing new is created;
    * otherwise: ``immutable=1`` opens the main file with no locks and no side
      files. Tradeoff: a lone ``-wal`` with no ``-shm`` (a crashed writer) is not
      replayed, so rows still only in that WAL stay invisible until the harness
      checkpoints — never writing beside a harness's data wins over them.
    """
    if not path.is_file():
        return None
    resolved = path.resolve()
    uri = resolved.as_uri()
    wal = Path(str(resolved) + "-wal")
    shm = Path(str(resolved) + "-shm")
    suffixes = ("?mode=ro", "?mode=ro&immutable=1") if wal.exists() and shm.exists() \
        else ("?mode=ro&immutable=1",)
    for suffix in suffixes:
        conn = None
        try:
            conn = sqlite3.connect(uri + suffix, uri=True)
            conn.row_factory = sqlite3.Row
            conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
            return conn
        except sqlite3.Error:
            if conn is not None:
                conn.close()  # a failed probe must not leak its connection
            continue
    return None


def _tables(conn):
    return {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')").fetchall()}


def _rows(conn, table):
    try:
        return [dict(r) for r in conn.execute(f'SELECT * FROM "{table}"').fetchall()]
    except sqlite3.Error:
        return []


def _json_col(value):
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return value
    return value


# 1. Claude Code — ~/.claude/projects/<slug>/<session-uuid>.jsonl (CLAUDE_CONFIG_DIR).
#    Lines: {type: user|assistant, sessionId, cwd, timestamp, message{role, content}};
#    {type: summary, summary, leafUuid} carries the title.
def _iter_claude():
    root = _env_path("CLAUDE_CONFIG_DIR") or (_home() / ".claude")
    for fp in _glob(root, "projects/**/*.jsonl"):
        recs = _read_jsonl(fp)
        title = next((str(r.get("summary") or r.get("customTitle") or r.get("title"))
                      for r in recs if r.get("type") in ("summary", "custom-title")
                      and (r.get("summary") or r.get("customTitle") or r.get("title"))), "")
        sid, cwd = fp.stem, ""
        for rec in recs:
            sid = str(rec.get("sessionId") or sid)
            cwd = str(rec.get("cwd") or cwd)
            msg = rec.get("message") if isinstance(rec.get("message"), dict) else None
            if msg is None or rec.get("type") not in ("user", "assistant", None):
                continue
            content = _extract_text(msg.get("content"))
            if content:
                yield _rec("claude-code", sid, title, cwd, rec.get("timestamp"),
                           msg.get("role") or rec.get("type"), content, fp)


# 2. Codex — $CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl (+ archived_sessions/,
#    cold files as .jsonl.zst). Envelope {timestamp, type, payload}; session_meta.payload carries
#    id + cwd; response_item.payload {type: message, role, content[{type: input_text|output_text}]};
#    event_msg user_message/agent_message mirror them. Titles: session_index.jsonl {id, thread_name}.
_UUID_TAIL = re.compile(r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")


def _codex_lines(fp):
    if fp.name.endswith(".zst"):
        try:
            from compression import zstd  # Python 3.14+ stdlib
        except ImportError:
            return []
        try:
            raw = zstd.decompress(fp.read_bytes()).decode("utf-8", errors="replace")
        except Exception:
            return []
        out = []
        for line in raw.splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out
    return _read_jsonl(fp)


def _iter_codex():
    root = _env_path("CODEX_HOME") or (_home() / ".codex")
    names = {}
    index = root / "session_index.jsonl"
    if index.is_file():
        for rec in _read_jsonl(index):
            if rec.get("id") and rec.get("thread_name"):
                names[str(rec["id"])] = str(rec["thread_name"])
    files = _glob(root, "sessions/**/*.jsonl", "sessions/**/*.jsonl.zst",
                  "archived_sessions/**/*.jsonl", "archived_sessions/**/*.jsonl.zst")
    for fp in files:
        m = _UUID_TAIL.findall(fp.name)
        sid, cwd, seen = (m[0] if m else fp.name.split(".")[0]), "", set()
        for rec in _codex_lines(fp):
            rtype = rec.get("type")
            payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else None
            if rtype == "session_meta" and payload:
                sid = str(payload.get("id") or payload.get("session_id") or sid)
                cwd = str(payload.get("cwd") or cwd)
                continue
            if payload is None and rtype == "message":
                payload, rtype = rec, "response_item"  # pre-envelope rollouts
            if not payload:
                continue
            role, content = None, ""
            if rtype == "response_item" and payload.get("type") == "message":
                role = payload.get("role")
                if role in ("developer", "system"):
                    continue  # injected instructions, not conversation
                content = _extract_text(payload.get("content"))
            elif rtype == "event_msg" and payload.get("type") in ("user_message", "agent_message"):
                role = "user" if payload["type"] == "user_message" else "assistant"
                content = payload.get("message") if isinstance(payload.get("message"), str) else ""
            if not content or (role, content) in seen:
                continue
            seen.add((role, content))
            yield _rec("codex", sid, names.get(sid, ""), cwd, rec.get("timestamp"),
                       role, content, fp)


# 3. OpenCode — $XDG_DATA_HOME/opencode/opencode.db (OPENCODE_DB: file name or absolute path).
#    v1: session(id, directory, title) + message(id, session_id, data{role}) +
#        part(message_id, session_id, time_created, data{type: text, text}).
#    v2: session_v2(...) + session_message(session_id, type, time_created, data{text|content[]}).
def _opencode_dbs():
    data_dir = _xdg_data_home() / "opencode"
    override = (os.environ.get("OPENCODE_DB") or "").strip()
    if override and override != ":memory:":
        p = Path(override).expanduser()
        p = p if p.is_absolute() else data_dir / p
        return [p / "opencode.db" if p.is_dir() else p]
    return sorted({data_dir / "opencode.db", *data_dir.glob("opencode-*.db")}) \
        if data_dir.is_dir() else [data_dir / "opencode.db"]


def _iter_opencode():
    for db in _opencode_dbs():
        conn = _sqlite_ro(db)
        if conn is None:
            continue
        try:
            tables = _tables(conn)
            sessions = {}
            for table in ("session", "session_v2"):
                if table in tables:
                    for row in _rows(conn, table):
                        sessions[str(row.get("id"))] = row
            if "session_message" in tables:
                for row in _rows(conn, "session_message"):
                    data = _json_col(row.get("data"))
                    content = _extract_text(data.get("content") if isinstance(data, dict)
                                            and "content" in data else data) \
                        or _extract_text(row.get("content"))
                    s = sessions.get(str(row.get("session_id")), {})
                    if content:
                        yield _rec("opencode", row.get("session_id"), s.get("title"),
                                   s.get("directory"), row.get("time_created") or row.get("created_at"),
                                   row.get("type") or row.get("role"), content, db)
            if "part" in tables:
                roles = {}
                if "message" in tables:
                    for row in _rows(conn, "message"):
                        data = _json_col(row.get("data"))
                        roles[str(row.get("id"))] = data.get("role") if isinstance(data, dict) else None
                for row in _rows(conn, "part"):
                    data = _json_col(row.get("data"))
                    if not isinstance(data, dict) or data.get("type") not in ("text", "reasoning"):
                        continue
                    if data.get("synthetic") or data.get("ignored"):
                        continue
                    text = data.get("text") if isinstance(data.get("text"), str) else ""
                    s = sessions.get(str(row.get("session_id")), {})
                    if text:
                        yield _rec("opencode", row.get("session_id"), s.get("title"),
                                   s.get("directory"), row.get("time_created"),
                                   roles.get(str(row.get("message_id"))) or "assistant", text, db)
        finally:
            conn.close()


# 4/5. pi-mono and oh-my-pi — <agent-dir>/sessions/<encoded-cwd>/<ts>_<uuid>.jsonl, session
#    version 3: a {type: "session", id, cwd, timestamp} header (omp prepends a fixed 256-byte
#    {type: "title", title} slot), then entries {type, id(8 hex), parentId, timestamp}; the
#    session id is the HEADER's id, never an entry's. message entries carry
#    message{role: user|assistant|toolResult|custom, content: str | blocks, timestamp(ms)}.
def _iter_pi_family(harness, files):
    for fp in files:
        stem = fp.stem
        sid = stem.split("_", 1)[1] if "_" in stem else stem
        title, cwd = "", ""
        for rec in _read_jsonl(fp):
            rtype = rec.get("type")
            if rtype == "title":
                title = str(rec.get("title") or title)
                continue
            if rtype == "session":
                sid = str(rec.get("id") or sid)
                cwd = str(rec.get("cwd") or cwd)
                title = str(rec.get("title") or title)
                continue
            if rtype == "session_info":
                title = str(rec.get("name") or title)
                continue
            if rtype == "title_change":
                title = str(rec.get("title") or title)
                continue
            if rtype in ("branch_summary", "compaction"):
                content, role = _extract_text(rec.get("summary")), "summary"
            elif rtype == "message" and isinstance(rec.get("message"), dict):
                msg = rec["message"]
                content, role = _extract_text(msg.get("content")), msg.get("role")
            else:
                continue
            if content:
                ts = rec.get("timestamp") or (rec.get("message") or {}).get("timestamp")
                yield _rec(harness, sid, title, cwd, ts, role, content, fp)


def _iter_pi():
    files = []
    session_dir = _env_path("PI_CODING_AGENT_SESSION_DIR")
    if session_dir is not None:
        files += _glob(session_dir, "*.jsonl", "**/*.jsonl")
    agent = _env_path("PI_CODING_AGENT_DIR") or (_home() / ".pi" / "agent")
    files += _glob(agent, "sessions/**/*.jsonl", "agent/sessions/**/*.jsonl")
    yield from _iter_pi_family("pi", sorted(set(files)))


def _iter_omp():
    roots = []
    explicit = _env_path("OMP_HOME")  # open-fleet override: the .omp root
    if explicit is not None:
        roots.append(explicit)
    else:
        cfg = (os.environ.get("PI_CONFIG_DIR") or "").strip()
        base = (Path(cfg).expanduser() if cfg and Path(cfg).expanduser().is_absolute()
                else _home() / (cfg or ".omp"))
        roots.append(base)
    files = []
    for root in roots:
        files += _glob(root, "agent/sessions/**/*.jsonl", "profiles/*/agent/sessions/**/*.jsonl")
    if explicit is None:
        files += _glob(_xdg_data_home() / "omp", "sessions/**/*.jsonl")
    yield from _iter_pi_family("omp", sorted(set(files)))


# 6. JCode — $JCODE_HOME/sessions/<session_id>.json snapshot {id, title, custom_title,
#    working_dir, messages[{id, role, content[{type: text|tool_result|...}], timestamp}]} plus an
#    append-only <session_id>.journal.jsonl of {meta{title, working_dir,...}, append_messages[]}.
def _iter_jcode():
    root = _env_path("JCODE_HOME") or (_home() / ".jcode")
    sess_dir = root / "sessions"
    snaps = [p for p in _glob(sess_dir, "*.json")]
    journals = {p.name[: -len(".journal.jsonl")]: p for p in _glob(sess_dir, "*.journal.jsonl")}
    ids = sorted({p.stem for p in snaps} | set(journals))
    for stem in ids:
        snap_fp = sess_dir / f"{stem}.json"
        snap = _read_json(snap_fp) if snap_fp.is_file() else None
        snap = snap if isinstance(snap, dict) else {}
        meta = dict(snap)
        messages, order = {}, []
        replay = list(snap.get("messages") or [])
        jfp = journals.get(stem)
        if jfp is not None:
            for entry in _read_jsonl(jfp):
                if isinstance(entry.get("meta"), dict):
                    meta.update({k: v for k, v in entry["meta"].items() if v is not None})
                replay.extend(entry.get("append_messages") or [])
        for msg in replay:  # replay is idempotent: a re-appended id replaces, never duplicates
            if not isinstance(msg, dict):
                continue
            key = str(msg.get("id") or f"#{len(order)}")
            if key not in messages:
                order.append(key)
            messages[key] = msg
        sid = str(snap.get("id") or stem)
        title = meta.get("custom_title") or meta.get("title") or meta.get("short_name") or ""
        cwd = meta.get("working_dir") or ""
        fp = snap_fp if snap_fp.is_file() else jfp
        for key in order:
            msg = messages[key]
            content = _extract_text(msg.get("content"))
            if content:
                yield _rec("jcode", sid, title, cwd, msg.get("timestamp") or meta.get("updated_at"),
                           msg.get("display_role") or msg.get("role"), content, fp)


# 7. Goose — <data_dir>/sessions/sessions.db; data_dir = $GOOSE_PATH_ROOT/data, else
#    ~/.local/share/goose (Linux) / ~/Library/Application Support/Block/goose (macOS).
#    sessions(id, name, description, working_dir, created_at, updated_at);
#    messages(session_id, role, content_json '[{"type":"text","text":...}]', created_timestamp s).
def _goose_dbs():
    root = _env_path("GOOSE_PATH_ROOT")
    if root is not None:
        if root.is_file():
            return [root]
        return [root / "data" / "sessions" / "sessions.db",
                root / "sessions" / "sessions.db", root / "sessions.db"]
    return [_xdg_data_home() / "goose" / "sessions" / "sessions.db",
            _home() / "Library" / "Application Support" / "Block" / "goose" / "sessions" / "sessions.db"]


def _iter_goose():
    seen = set()
    for db in _goose_dbs():
        if not db.is_file() or db.resolve() in seen:
            continue
        seen.add(db.resolve())
        conn = _sqlite_ro(db)
        if conn is None:
            continue
        try:
            tables = _tables(conn)
            sessions = {str(r.get("id")): r for r in _rows(conn, "sessions")} if "sessions" in tables else {}
            for row in (_rows(conn, "messages") if "messages" in tables else []):
                raw = row.get("content_json") if "content_json" in row else row.get("content")
                content = _extract_text(_json_col(raw))
                s = sessions.get(str(row.get("session_id")), {})
                if content:
                    yield _rec("goose", row.get("session_id"),
                               s.get("name") or s.get("description"),
                               s.get("working_dir") or s.get("cwd"),
                               row.get("created_timestamp") or row.get("timestamp")
                               or row.get("created_at"),
                               row.get("role"), content, db)
        finally:
            conn.close()


# 8. Hermes — $HERMES_HOME/state.db (default ~/.hermes; profiles under profiles/<name>/).
#    sessions(id, title, display_name, cwd, started_at REAL s, ...); messages(session_id, role,
#    content TEXT — multimodal parts stored as "\x00json:" + json, timestamp REAL s, active).
_HERMES_JSON_PREFIX = "\x00json:"


def _hermes_content(value):
    if isinstance(value, str) and value.startswith(_HERMES_JSON_PREFIX):
        try:
            return _extract_text(json.loads(value[len(_HERMES_JSON_PREFIX):]))
        except (ValueError, TypeError):
            return ""
    return value if isinstance(value, str) else _extract_text(value)


def _iter_hermes():
    root = _env_path("HERMES_HOME")
    if root is not None and root.is_file():
        dbs = [root]
    else:
        base = root or (_home() / ".hermes")
        dbs = [base / "state.db"] + sorted(base.glob("profiles/*/state.db")) if base.is_dir() else []
    for db in dbs:
        conn = _sqlite_ro(db)
        if conn is None:
            continue
        try:
            tables = _tables(conn)
            sessions = {str(r.get("id")): r for r in _rows(conn, "sessions")} if "sessions" in tables else {}
            for row in (_rows(conn, "messages") if "messages" in tables else []):
                if row.get("active") == 0:
                    continue
                content = _hermes_content(row.get("content"))
                s = sessions.get(str(row.get("session_id")), {})
                if content:
                    yield _rec("hermes", row.get("session_id"),
                               s.get("title") or s.get("display_name"), s.get("cwd"),
                               row.get("timestamp") or s.get("started_at"),
                               row.get("role"), content, db)
        finally:
            conn.close()


# 9. Crush — one <data_dir>/crush.db per project (default <project>/.crush), every project
#    listed in projects.json {"projects": [{path, data_dir, last_accessed}]} under
#    $CRUSH_GLOBAL_DATA, else $XDG_DATA_HOME/crush, else ~/.local/share/crush. No cwd column:
#    the project path IS the cwd. messages(session_id, role, parts '[{"type":"text",
#    "data":{"text":...}}]', created_at s); sessions(id, title, created_at).
def _crush_dbs():
    out = []
    override = _env_path("CRUSH_DATA_DIR")  # open-fleet override: a data dir or a db file
    if override is not None:
        db = override if override.is_file() else override / "crush.db"
        cwd = override.parent if override.name == ".crush" else None
        out.append((db, str(cwd) if cwd else ""))
    for base in (_env_path("CRUSH_GLOBAL_DATA"), _xdg_data_home() / "crush",
                 _home() / ".local" / "share" / "crush"):
        if base is None:
            continue
        doc = _read_json(base / "projects.json") if (base / "projects.json").is_file() else None
        for proj in (doc.get("projects") or []) if isinstance(doc, dict) else []:
            if not isinstance(proj, dict) or not proj.get("path"):
                continue
            data_dir = Path(str(proj.get("data_dir") or Path(str(proj["path"])) / ".crush"))
            out.append((data_dir / "crush.db", str(proj["path"])))
    out.append((Path.cwd() / ".crush" / "crush.db", str(Path.cwd())))
    seen, uniq = set(), []
    for db, cwd in out:
        key = str(db.resolve()) if db.exists() else str(db)
        if key not in seen:
            seen.add(key)
            uniq.append((db, cwd))
    return uniq


def _iter_crush():
    for db, project in _crush_dbs():
        conn = _sqlite_ro(db)
        if conn is None:
            continue
        try:
            tables = _tables(conn)
            sessions = {str(r.get("id")): r for r in _rows(conn, "sessions")} if "sessions" in tables else {}
            for row in (_rows(conn, "messages") if "messages" in tables else []):
                raw = row.get("parts") if "parts" in row else row.get("content")
                content = _extract_text(_json_col(raw))
                s = sessions.get(str(row.get("session_id")), {})
                if content:
                    yield _rec("crush", row.get("session_id"), s.get("title"),
                               project or s.get("cwd") or str(db.parent),
                               row.get("created_at") or s.get("created_at"),
                               row.get("role"), content, db)
        finally:
            conn.close()


# 10. OpenHands (software-agent-sdk) — <persistence_dir>/<conversation_id.hex>/base_state.json +
#    events/event-<idx:05d>-<event_id>.json (+ agent-server meta.json {title}). The session id is
#    the CONVERSATION directory, never an event id. base_state.workspace.working_dir is the cwd.
#    MessageEvent: {kind, id, timestamp (naive local), source, llm_message{role, content[{text}]}}.
#    The SDK has no home default: OH_CONVERSATIONS_PATH / OH_PERSISTENCE_DIR, then the
#    OpenHands CLI's ~/.openhands/conversations (unverified), then ~/.openhands.
def _openhands_text(ev):
    llm = ev.get("llm_message")
    if isinstance(llm, dict):
        return _extract_text(llm.get("content")), llm.get("role")
    for key in ("thought", "observation"):  # ActionEvent / ObservationEvent
        val = ev.get(key)
        if val:
            return _extract_text(val), ev.get("source")
    args = ev.get("args") if isinstance(ev.get("args"), dict) else {}  # V0 event stream
    v0 = ev.get("message") if isinstance(ev.get("message"), str) else (
        args.get("content") or args.get("thought") or ev.get("content"))
    return (_extract_text(v0) if v0 else ""), ev.get("source")


def _iter_openhands():
    roots = []
    for name in ("OH_CONVERSATIONS_PATH", "OH_PERSISTENCE_DIR"):
        p = _env_path(name)
        if p is not None:
            roots.append(p)
    if not roots:
        roots = [_home() / ".openhands" / "conversations", _home() / ".openhands"]
    conv_dirs = []
    for root in roots:
        if not root.is_dir():
            continue
        if (root / "events").is_dir():
            conv_dirs.append(root)
        conv_dirs += [p.parent for p in root.glob("*/events") if p.is_dir()]
    for conv in sorted(set(conv_dirs)):
        base = _read_json(conv / "base_state.json") if (conv / "base_state.json").is_file() else None
        base = base if isinstance(base, dict) else {}
        meta = _read_json(conv / "meta.json") if (conv / "meta.json").is_file() else None
        meta = meta if isinstance(meta, dict) else {}
        ws = base.get("workspace") if isinstance(base.get("workspace"), dict) else {}
        cwd = ws.get("working_dir") or base.get("working_dir") or ""
        sid = conv.name
        for fp in sorted((conv / "events").glob("event-*.json")):
            ev = _read_json(fp)
            if not isinstance(ev, dict):
                continue
            content, role = _openhands_text(ev)
            if not cwd and isinstance(ev.get("args"), dict):
                cwd = ev["args"].get("cwd") or cwd
            if content:
                yield _rec("openhands", sid, meta.get("title") or base.get("title"), cwd,
                           ev.get("timestamp"), role or ev.get("source"), content, fp)


_HARNESS_READERS = (_iter_claude, _iter_codex, _iter_opencode, _iter_omp, _iter_pi,
                    _iter_jcode, _iter_goose, _iter_hermes, _iter_crush, _iter_openhands)


def _collect_all_harness_records():
    for reader in _HARNESS_READERS:
        try:
            yield from reader()
        except (OSError, sqlite3.Error):
            continue  # one unreadable store never hides the other nine


LOCAL_CURSOR_PREFIX = "local:"


def _local_cursor_offset(cursor):
    """Offset named by a local-harness NEXT_CURSOR (``local:<n>``); 0 when absent.

    The local scan is stateless, so a cursor is just the next offset into the
    same deterministic ordering. Any other cursor (an Orca one, garbage) is
    refused rather than silently answered with page 1 again.
    """
    if cursor is None:
        return 0
    m = re.fullmatch(r"local:(\d{1,9})", cursor.strip())
    if not m:
        raise Refused(f"--cursor {cursor!r} is not a local-harness cursor "
                      f"(expected {LOCAL_CURSOR_PREFIX}<offset> from a previous "
                      "local NEXT_CURSOR)")
    return int(m.group(1))


def search_local_harnesses(ns):
    """Search local session stores across all 10 supported harnesses.

    One hit per session (its best-matching record supplies the snippet).
    --since drops records with no readable timestamp: undated is not "recent".
    --path matches the session's working directory (the store path only when
    the harness recorded no cwd). --cursor pages with the ``local:<offset>``
    NEXT_CURSOR a previous local page printed.
    """
    build_search_argv(ns)
    query = (ns.query if ns.query is not None else ns.query_flag) or ""
    tokens = [t.lower() for t in query.split() if t.strip()]
    want_agents = {_norm_agent(a) for a in (ns.agent or []) if a}
    want_paths = [p for p in (ns.path or []) if p]
    since_dt = _parse_any_ts(ns.since) if ns.since else None
    limit_val = int(ns.limit) if ns.limit is not None else 20

    sessions = {}
    for idx, rec in enumerate(_collect_all_harness_records()):
        if want_agents and _norm_agent(rec["harness"]) not in want_agents:
            continue
        if want_paths:
            target = rec.get("cwd") or rec.get("file_path") or ""
            if not any(_path_matches(target, p) for p in want_paths):
                continue
        rec_dt = _parse_any_ts(rec.get("timestamp"))
        if since_dt is not None and (rec_dt is None or rec_dt < since_dt):
            continue
        haystack = f"{rec['content']} {rec['title']} {rec['session_id']} {rec['cwd']}".lower()
        if tokens and not all(tok in haystack for tok in tokens):
            continue
        score = float(sum(haystack.count(tok) for tok in tokens)) if tokens else 1.0
        ts_sort = rec_dt.timestamp() if rec_dt is not None else float(idx)
        key = (rec["harness"], rec["session_id"])
        cur = sessions.get(key)
        if cur is None:
            sessions[key] = {"score": score, "ts": ts_sort, "best": (score, ts_sort), "rec": rec}
            continue
        cur["score"] += score
        cur["ts"] = max(cur["ts"], ts_sort)
        if (score, ts_sort) > cur["best"]:
            cur["best"], cur["rec"] = (score, ts_sort), rec

    scored_hits = []
    for (harness, sid), agg in sessions.items():
        rec = agg["rec"]
        qualified = sid if sid.startswith(f"{harness}:") else f"{harness}:{sid}"
        scored_hits.append((agg["score"], agg["ts"], {
            "sessionId": qualified,
            "agent": harness,
            "title": rec["title"] or qualified,
            "score": round(agg["score"], 2),
            "cwd": rec["cwd"],
            "evidence": {"role": rec["role"] or "assistant", "snippet": rec["content"]},
        }))
    if ns.sort == "newest":
        scored_hits.sort(key=lambda item: (item[1], item[0]), reverse=True)
    else:
        scored_hits.sort(key=lambda item: (item[0], item[1]), reverse=True)

    offset = _local_cursor_offset(ns.cursor)
    end = offset + limit_val
    hits = [item[2] for item in scored_hits[offset:end]]
    has_more = len(scored_hits) > end
    return {
        "kind": "results",
        "hits": hits,
        "page": {"cursor": f"{LOCAL_CURSOR_PREFIX}{end}" if has_more else "none",
                 "hasMore": has_more},
    }


def _should_fallback_to_local():
    if os.environ.get("OPEN_FLEET_LOCAL_SEARCH") == "1":
        return True
    for var in ("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME"):
        val = (os.environ.get(var) or "").strip().lower()
        if val and val != "orca":
            return True
    return False


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=180, error=Failed)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        if ns.precheck_only:
            if ns.local_harnesses:
                print("PRECHECK=ok phase=current")
                return EXIT_OK
            phase = check_index(run_orca(["search", "--index-status"]))
            print(f"PRECHECK=ok phase={phase}")
            return EXIT_OK
        if ns.episodic_hint:
            has_query = (ns.query is not None) or (ns.query_flag is not None)
            if not ns.path and not has_query:
                raise Refused("--episodic-hint requires at least one --path or query")
            hits = None
            if has_query:
                search_argv = build_search_argv(ns)
                if ns.local_harnesses:
                    hits = search_local_harnesses(ns)["hits"]
                else:
                    try:
                        check_index(run_orca(["search", "--index-status"]))
                        res = run_orca(search_argv)
                        if not isinstance(res, dict) or res.get("kind") != "results":
                            raise Failed("search receipt is not results")
                        hits = res.get("hits")
                        if not isinstance(hits, list):
                            raise Failed("search results answer names no hits")
                    except Failed:
                        if _should_fallback_to_local():
                            hits = search_local_harnesses(ns)["hits"]
                        else:
                            raise
            lines = build_episodic_hint(
                ns.path, runs_dir=ns.runs_dir, session_hits=hits)
            print("\n".join(lines))
            return EXIT_OK
        search_argv = build_search_argv(ns)
        if ns.local_harnesses:
            lines = ["PRECHECK=ok phase=current"]
            lines += format_results(search_local_harnesses(ns))
            print("\n".join(lines))
            return EXIT_OK
        try:
            phase = check_index(run_orca(["search", "--index-status"]))
            lines = [f"PRECHECK=ok phase={phase}"]
            lines += format_results(run_orca(search_argv))
        except Failed:
            if _should_fallback_to_local():
                lines = ["PRECHECK=ok phase=current"]
                lines += format_results(search_local_harnesses(ns))
            else:
                raise
        print("\n".join(lines))
        return EXIT_OK
    except Refused as exc:
        print(f"search_sessions: REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"search_sessions: FAILED: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
