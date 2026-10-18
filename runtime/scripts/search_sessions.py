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
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import orca_cli
except ImportError:  # loaded by file path (tests): the resolver sits beside this script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import orca_cli
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


def format_results(result):
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
            lines.append(f"SNIPPET [{_visible(ev.get('role', '?'))}]: "
                         f"{_bounded(_visible(snippet), SNIPPET_LIMIT)}")
        else:
            lines.append("SNIPPET: (none)")
    return lines


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=180, error=Failed)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        if ns.precheck_only:
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
                check_index(run_orca(["search", "--index-status"]))
                res = run_orca(search_argv)
                if not isinstance(res, dict) or res.get("kind") != "results":
                    raise Failed("search receipt is not results")
                hits = res.get("hits")
                if not isinstance(hits, list):
                    raise Failed("search results answer names no hits")
            lines = build_episodic_hint(
                ns.path, runs_dir=ns.runs_dir, session_hits=hits)
            print("\n".join(lines))
            return EXIT_OK
        search_argv = build_search_argv(ns)
        phase = check_index(run_orca(["search", "--index-status"]))
        lines = [f"PRECHECK=ok phase={phase}"]
        lines += format_results(run_orca(search_argv))
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
