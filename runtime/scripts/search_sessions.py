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

Exit: 0 ok · 1 runtime/refusal/receipt failure · 2 usage/precheck refusal.
"""
import argparse
import datetime
import fnmatch
import json
import os
from pathlib import Path
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
                prior_entries.append(f"- [run {run_id} / {uid} ({status})] {detail}")

    hit_entries = []
    for hit in (session_hits or []):
        if not isinstance(hit, dict):
            continue
        sid = _one_line(hit.get("sessionId") or "?", 40)
        title = _one_line(hit.get("title") or "(untitled)", 60)
        ev = hit.get("evidence") if isinstance(hit.get("evidence"), dict) else {}
        snip = _one_line(ev.get("snippet") or "", 80)
        suffix = f" — {snip}" if snip else ""
        hit_entries.append(f"- [session {sid}] {title}{suffix}")

    header = [
        "EPISODIC_HINT: Prior Runs & Pitfalls (max 15 lines)",
        f"PATHS: {', '.join(_one_line(p, 80) for p in clean_paths) if clean_paths else '(query-only)'}",
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


def format_results(result, fenced=False):
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
             f"NEXT_CURSOR={page.get('cursor') or 'none'}"]
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        ev = hit.get("evidence") if isinstance(hit.get("evidence"),
                                               dict) else {}
        snippet = ev.get("snippet") if isinstance(ev.get("snippet"),
                                                  str) else ""
        lines.append(f"HIT {_visible(hit.get('sessionId') or '?')} "
                     f"score={_visible(hit.get('score', '?'))} "
                     f"{_visible(hit.get('title') or '(untitled)')}")
        if snippet:
            bounded_snip = _bounded(_visible(snippet), SNIPPET_LIMIT)
            if fenced:
                fenced_snip = guard_text.envelope(
                    bounded_snip,
                    source=str(hit.get("agent") or "session"),
                    label=str(hit.get("sessionId") or "?"),
                )
                lines.append(f"SNIPPET [{_visible(ev.get('role', '?'))}]:\n"
                             f"{fenced_snip}")
            else:
                lines.append(f"SNIPPET [{_visible(ev.get('role', '?'))}]: "
                             f"{bounded_snip}")
        else:
            lines.append("SNIPPET: (none)")
    return lines


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
}


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
        parts = []
        for k in ("text", "content", "message", "body", "parts", "thought",
                  "observation", "command", "summary", "input", "output"):
            if k in val and val[k] is not None:
                sub = _extract_text(val[k])
                if sub:
                    parts.append(sub)
        if not parts and "args" in val and isinstance(val["args"], dict):
            sub = _extract_text(val["args"])
            if sub:
                parts.append(sub)
        if not parts and "extras" in val and isinstance(val["extras"], dict):
            sub = _extract_text(val["extras"])
            if sub:
                parts.append(sub)
        return " ".join(parts)
    return str(val)


def _parse_any_ts(val):
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)):
        ts = float(val)
        if ts > 1e11:
            ts /= 1000.0
        try:
            return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(val, str):
        s = val.strip()
        if s.isdigit():
            return _parse_any_ts(int(s))
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


def _iter_jsonl_records(files, harness):
    for fp in sorted(set(files)):
        if not fp.is_file():
            continue
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        file_sid = fp.stem
        if file_sid.endswith(".journal"):
            file_sid = file_sid[:-8]
        file_cwd = str(fp.parent)
        file_title = f"{harness}:{file_sid}"
        file_ts = None
        for raw_line in lines:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                rec = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            sid = str(rec.get("sessionId") or rec.get("session_id") or rec.get("id") or file_sid)
            if rec.get("sessionId") or rec.get("session_id"):
                file_sid = sid
            cwd = str(rec.get("cwd") or rec.get("project") or rec.get("directory") or file_cwd)
            if rec.get("cwd") or rec.get("project") or rec.get("directory"):
                file_cwd = cwd
            title = str(rec.get("title") or rec.get("summary") or file_title)
            if rec.get("title") or rec.get("summary"):
                file_title = title
            ts = rec.get("timestamp") or rec.get("created_at") or rec.get("ts") or rec.get("time") or file_ts
            if ts is not None:
                file_ts = ts
            msg = rec.get("message") if isinstance(rec.get("message"), dict) else {}
            payload = rec.get("payload") if isinstance(rec.get("payload"), dict) else {}
            role = str(
                msg.get("role")
                or payload.get("role")
                or rec.get("role")
                or rec.get("source")
                or rec.get("type")
                or "assistant"
            )
            content = (
                _extract_text(msg.get("content") if msg else None)
                or _extract_text(payload.get("content") if payload else None)
                or _extract_text(payload if payload else None)
                or _extract_text(rec.get("content"))
                or _extract_text(rec.get("text"))
            )
            if content:
                yield {
                    "harness": harness,
                    "session_id": sid,
                    "title": title,
                    "cwd": cwd,
                    "timestamp": ts,
                    "role": role,
                    "content": content,
                    "file_path": str(fp),
                }


def _iter_json_records(files, harness, openhands_mode=False):
    for fp in sorted(set(files)):
        if not fp.is_file():
            continue
        try:
            data = json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            default_sid = (
                fp.parent.parent.name
                if openhands_mode and fp.parent.name == "events"
                else fp.stem
            )
            sid = str(data.get("session_id") or data.get("sessionId") or data.get("id") or default_sid)
            cwd = str(
                data.get("cwd")
                or (data.get("args") or {}).get("cwd")
                if isinstance(data.get("args"), dict)
                else data.get("cwd") or str(fp.parent)
            )
            title = str(data.get("title") or data.get("summary") or f"{harness}:{sid}")
            ts = data.get("timestamp") or data.get("created_at") or data.get("ts")
            msg_list = (
                data.get("messages")
                or data.get("events")
                or data.get("entries")
                or data.get("history")
            )
            if isinstance(msg_list, list):
                for item in msg_list:
                    if not isinstance(item, dict):
                        continue
                    irole = str(item.get("role") or item.get("source") or item.get("type") or "assistant")
                    icontent = _extract_text(item)
                    its = item.get("timestamp") or item.get("created_at") or ts
                    if icontent:
                        yield {
                            "harness": harness,
                            "session_id": sid,
                            "title": title,
                            "cwd": cwd,
                            "timestamp": its,
                            "role": irole,
                            "content": icontent,
                            "file_path": str(fp),
                        }
            else:
                role = str(data.get("source") or data.get("role") or data.get("action") or "assistant")
                content = _extract_text(data)
                if content:
                    yield {
                        "harness": harness,
                        "session_id": sid,
                        "title": title,
                        "cwd": cwd,
                        "timestamp": ts,
                        "role": role,
                        "content": content,
                        "file_path": str(fp),
                    }


def _iter_sqlite_records(db_paths, harness):
    for db_path in db_paths:
        if not db_path.is_file():
            continue
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
        except sqlite3.Error:
            continue
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
                ).fetchall()
            }
            sess_table = next(
                (t for t in ("session_v2", "sessions", "session") if t in tables),
                None,
            )
            msg_table = next(
                (t for t in ("session_message", "messages", "message") if t in tables),
                None,
            )
            sessions_by_id = {}
            if sess_table:
                for srow in conn.execute(f"SELECT * FROM {sess_table}").fetchall():
                    sdict = dict(srow)
                    sid = str(
                        sdict.get("id")
                        or sdict.get("session_id")
                        or sdict.get("sessionId")
                        or ""
                    )
                    if sid:
                        sessions_by_id[sid] = sdict
            if msg_table:
                for mrow in conn.execute(f"SELECT * FROM {msg_table}").fetchall():
                    mdict = dict(mrow)
                    sid = str(
                        mdict.get("session_id")
                        or mdict.get("sessionId")
                        or mdict.get("id")
                        or harness
                    )
                    smeta = sessions_by_id.get(sid, {})
                    title = str(
                        smeta.get("title")
                        or smeta.get("name")
                        or smeta.get("slug")
                        or mdict.get("title")
                        or f"{harness}:{sid}"
                    )
                    cwd = str(
                        smeta.get("directory")
                        or smeta.get("cwd")
                        or smeta.get("path")
                        or smeta.get("project_path")
                        or smeta.get("worktree")
                        or mdict.get("cwd")
                        or mdict.get("path")
                        or str(db_path.parent)
                    )
                    ts = (
                        mdict.get("created_at")
                        or mdict.get("timestamp")
                        or mdict.get("time_created")
                        or mdict.get("updated_at")
                        or smeta.get("updated_at")
                        or smeta.get("created_at")
                        or smeta.get("time_created")
                    )
                    role = str(
                        mdict.get("role")
                        or mdict.get("source")
                        or mdict.get("type")
                        or "assistant"
                    )
                    raw_body = (
                        mdict.get("content")
                        or mdict.get("data")
                        or mdict.get("text")
                        or mdict.get("parts")
                        or mdict.get("body")
                        or mdict.get("message")
                    )
                    content = _extract_text(raw_body)
                    if content:
                        yield {
                            "harness": harness,
                            "session_id": sid,
                            "title": title,
                            "cwd": cwd,
                            "timestamp": ts,
                            "role": role,
                            "content": content,
                            "file_path": str(db_path),
                        }
        except sqlite3.Error:
            pass
        finally:
            conn.close()


def _collect_all_harness_records():
    home = Path(os.environ.get("HOME") or str(Path.home()))

    # 1. Claude Code
    claude_root = Path(os.environ["CLAUDE_CONFIG_DIR"]) if os.environ.get("CLAUDE_CONFIG_DIR") else (home / ".claude")
    if claude_root.is_dir():
        c_files = list(claude_root.glob("projects/**/*.jsonl")) + list(claude_root.glob("*.jsonl"))
        yield from _iter_jsonl_records(c_files, "claude-code")

    # 2. Codex
    codex_root = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else (home / ".codex")
    if codex_root.is_dir():
        cx_files = (
            list(codex_root.glob("sessions/**/*.jsonl"))
            + list(codex_root.glob("archived_sessions/*.jsonl"))
            + list(codex_root.glob("archived_sessions/**/*.jsonl"))
            + list(codex_root.glob("*.jsonl"))
        )
        yield from _iter_jsonl_records(cx_files, "codex")

    # 3. OpenCode
    opencode_env = os.environ.get("OPENCODE_DB")
    if opencode_env:
        oc_path = Path(opencode_env)
        oc_dbs = [oc_path / "opencode.db" if oc_path.is_dir() else oc_path]
    else:
        oc_dbs = [home / ".local" / "share" / "opencode" / "opencode.db"]
    yield from _iter_sqlite_records(oc_dbs, "opencode")

    # 4. Oh-My-Pi (omp)
    omp_root = Path(os.environ["OMP_HOME"]) if os.environ.get("OMP_HOME") else (home / ".omp")
    if omp_root.is_dir():
        omp_files = list(omp_root.glob("agent/sessions/**/*.jsonl")) + list(omp_root.rglob("*.jsonl"))
        yield from _iter_jsonl_records(omp_files, "omp")

    # 5. Pi-Mono (pi)
    pi_root = Path(os.environ["PI_CODING_AGENT_DIR"]) if os.environ.get("PI_CODING_AGENT_DIR") else (home / ".pi")
    if pi_root.is_dir():
        pi_files = list(pi_root.glob("agent/sessions/**/*.jsonl")) + list(pi_root.rglob("*.jsonl"))
        yield from _iter_jsonl_records(pi_files, "pi")

    # 6. JCode (jcode)
    jcode_root = Path(os.environ["JCODE_HOME"]) if os.environ.get("JCODE_HOME") else (home / ".jcode")
    if jcode_root.is_dir():
        j_sess = jcode_root / "sessions"
        j_dir = j_sess if j_sess.is_dir() else jcode_root
        j_jsonl = list(j_dir.rglob("*.jsonl"))
        j_json = [p for p in j_dir.rglob("*.json") if not p.name.endswith(".jsonl")]
        yield from _iter_jsonl_records(j_jsonl, "jcode")
        yield from _iter_json_records(j_json, "jcode")

    # 7. Goose (goose)
    goose_env = os.environ.get("GOOSE_PATH_ROOT")
    if goose_env:
        g_root = Path(goose_env)
        g_dbs = [g_root] if g_root.is_file() else [g_root / "sessions" / "sessions.db", g_root / "sessions.db"]
    else:
        g_dbs = [home / ".local" / "share" / "goose" / "sessions" / "sessions.db"]
    yield from _iter_sqlite_records(g_dbs, "goose")

    # 8. Hermes (hermes)
    hermes_env = os.environ.get("HERMES_HOME")
    if hermes_env:
        h_root = Path(hermes_env)
        h_dbs = [h_root] if h_root.is_file() else [h_root / "state.db"]
    else:
        h_dbs = [home / ".hermes" / "state.db"]
    yield from _iter_sqlite_records(h_dbs, "hermes")

    # 9. Crush (crush)
    crush_dbs = []
    crush_env = os.environ.get("CRUSH_DATA_DIR")
    if crush_env:
        c_root = Path(crush_env)
        crush_dbs.append(c_root if c_root.is_file() else (c_root / "crush.db"))
    crush_dbs.append(Path.cwd() / ".crush" / "crush.db")
    yield from _iter_sqlite_records(crush_dbs, "crush")

    # 10. OpenHands (openhands)
    oh_root = Path(os.environ["OH_PERSISTENCE_DIR"]) if os.environ.get("OH_PERSISTENCE_DIR") else (home / ".openhands")
    if oh_root.is_dir():
        oh_files = list(oh_root.glob("*/events/event-*.json")) + list(oh_root.rglob("event-*.json"))
        yield from _iter_json_records(oh_files, "openhands", openhands_mode=True)


def search_local_harnesses(ns):
    """Search local session stores across all 10 supported harnesses."""
    build_search_argv(ns)
    query = (ns.query if ns.query is not None else ns.query_flag) or ""
    tokens = [t.lower() for t in query.split() if t.strip()]
    want_agents = {_norm_agent(a) for a in (ns.agent or []) if a}
    want_paths = [p for p in (ns.path or []) if p]
    since_dt = _parse_any_ts(ns.since) if ns.since else None
    limit_val = int(ns.limit) if ns.limit is not None else 20

    scored_hits = []
    for idx, rec in enumerate(_collect_all_harness_records()):
        harness_norm = _norm_agent(rec["harness"])
        if want_agents and harness_norm not in want_agents and rec["harness"].lower() not in want_agents:
            continue
        if want_paths:
            cwd_str = rec.get("cwd") or ""
            fp_str = rec.get("file_path") or ""
            if not any(
                _path_matches(cwd_str, p)
                or _path_matches(fp_str, p)
                or p.lower() in cwd_str.lower()
                for p in want_paths
            ):
                continue
        rec_dt = _parse_any_ts(rec.get("timestamp"))
        if since_dt is not None and rec_dt is not None and rec_dt < since_dt:
            continue
        haystack = f"{rec['content']} {rec['title']} {rec['session_id']} {rec['cwd']}".lower()
        if tokens and not all(tok in haystack for tok in tokens):
            continue
        score = float(sum(haystack.count(tok) for tok in tokens)) if tokens else 1.0
        ts_sort = rec_dt.timestamp() if rec_dt is not None else float(idx)
        scored_hits.append((
            score,
            ts_sort,
            {
                "sessionId": f"{rec['harness']}:{rec['session_id']}"
                if not str(rec["session_id"]).startswith(f"{rec['harness']}:")
                else str(rec["session_id"]),
                "agent": rec["harness"],
                "title": rec["title"] or f"{rec['harness']}:{rec['session_id']}",
                "score": round(score, 2),
                "evidence": {
                    "role": rec["role"] or "assistant",
                    "snippet": rec["content"],
                },
            },
        ))

    if ns.sort == "newest":
        scored_hits.sort(key=lambda item: (item[1], item[0]), reverse=True)
    else:
        scored_hits.sort(key=lambda item: (item[0], item[1]), reverse=True)

    hits = [item[2] for item in scored_hits[:limit_val]]
    return {
        "kind": "results",
        "hits": hits,
        "page": {"cursor": "none", "hasMore": len(scored_hits) > limit_val},
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
            lines += format_results(search_local_harnesses(ns), fenced=True)
            print("\n".join(lines))
            return EXIT_OK
        try:
            phase = check_index(run_orca(["search", "--index-status"]))
            lines = [f"PRECHECK=ok phase={phase}"]
            lines += format_results(run_orca(search_argv))
        except Failed:
            if _should_fallback_to_local():
                lines = ["PRECHECK=ok phase=current"]
                lines += format_results(search_local_harnesses(ns), fenced=True)
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
