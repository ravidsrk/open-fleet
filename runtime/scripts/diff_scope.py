#!/usr/bin/env python3
"""Fail-loud scope classification: which review lenses this change earns.

A scope-gated review dispatches a lens only when the change surface signals it.
The failure mode that makes such a gate worthless is silence: a shallow checkout
resolves no base, ``git diff`` returns nothing, every flag is false, and the run
records a legitimate-looking zero findings. "We could not look" must never read
as "nothing to look at". So this script distinguishes three states -- nothing
changed, something changed and matched, something changed and matched NOTHING --
and only the first is a clean exit with all flags false.

The changed-file set is the UNION of the committed diff against the merge base,
the working tree (staged and unstaged), and untracked files. A brand-new
migration or component is exactly what a reviewer must see, and it is untracked
right up until the commit.

Categories are independent booleans -- a file can be TESTS and BACKEND at once.
Only BACKEND is deliberately exclusive of frontend view files.

===============  =============================================================
flag             path signals (and content signals, read from the working tree)
===============  =============================================================
SCOPE_FRONTEND   .css/.scss/.less/.sass, .tsx/.jsx/.vue/.svelte/.astro, .html,
                 .erb/.haml/.slim/.hbs/.ejs, tailwind/postcss config,
                 */components/*, */views/*, styles/*, css/*
SCOPE_BACKEND    .rb .py .go .rs .java .kt .php .ex .exs .cs .scala .c .cc .cpp
                 .ts .js .mjs .cjs .mts .cts -- when not a frontend view file
SCOPE_PROMPTS    *prompt*, *system_prompt*, SKILL.md, AGENTS.md, *.prompt,
                 */skills/*, */playbooks/*  ·  content: "You are a", "system prompt"
SCOPE_TESTS      *.test.*, *.spec.*, *_test.*, test_*.py, test/ tests/ spec/
                 __tests__/ cypress/ e2e/
SCOPE_DOCS       *.md, *.rst, *.adoc, docs/*, assets/badges/{tests,missions}.json
SCOPE_CONFIG     package.json, lockfiles, *.yml/*.yaml/*.toml/*.ini/*.cfg,
                 .github/*, requirements.txt, go.mod, Cargo.toml, Dockerfile
SCOPE_MIGRATIONS db/migrate/*, migrations/*, alembic/*, prisma/migrations/*,
                 db/data/*, data_migrations/*
SCOPE_API        api/*, */api/*, *controller*, *route*, *endpoint*, *.graphql,
                 *.gql, openapi.*, swagger.*  ·  content: "@app.route", "router."
SCOPE_AUTH       *auth*, *session*, *jwt*, *oauth*, *permission*, *role*,
                 *login*, *password*, *token*  ·  content: "authenticate",
                 "authorize", "set-cookie"
SCOPE_SECURITY   *security*, *crypto*, *secret*, *sanitiz*, *escape*, *csrf*
                 content: "subprocess", "shell=True", "os.system", "innerHTML",
                 "pickle.loads", "verify=False", "SELECT * FROM " + ...
SCOPE_A11Y       *a11y*, *accessib*  ·  content: "aria-", "role=", "alt=",
                 "tabindex", "<button", "<img", "focus-visible"
SCOPE_PERF       *bench*, *perf*, *cache*, *index*  ·  content: "useMemo",
                 "lru_cache", "perf_counter", "benchmark", "N+1", "EXPLAIN "
===============  =============================================================

Content signals are read from the file as it stands in the working tree, capped
at 256 KiB per file and only for files that still exist -- deterministic, no
network, and a deleted file contributes its path signals only.

Output is shell-safe: ``KEY=value`` assignments and ``#`` comments only, so
``source <(diff_scope.py)`` is legitimate. ``--json`` emits an object instead.

Exit codes
    0  classified (all-false with no changed files is a legitimate clean)
    2  SCOPE_ERROR=no_base    -- the base ref does not resolve (shallow checkout
                                 or missing fetch); nothing was examined
    2  SCOPE_ERROR=diff_failed -- a required git diff/enumeration failed
    2  SCOPE_ERROR=unmatched  -- files changed but no category matched; the
                                 unmatched paths are printed as comments

How to wire
    The scope-gated review playbook reads these flags instead of eyeballing the
    diff: each true flag dispatches its lens, and every dispatch appends its
    finding count to the DECISIONS log so the adaptive gate has real input. A
    non-zero exit is a FINDING, not a gate-off: SCOPE_ERROR parks the review with
    a named reason (fetch the base, or teach the table the new layout) and the
    run records no tally line for that sweep -- an unexamined diff must never
    contribute a zero to a lens's auto-gate streak. This matters most for
    scheduled sweeps, where nobody is watching the exit code.
"""
import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_SCOPE_ERROR = 2

CONTENT_CAP = 256 * 1024

FLAGS = (
    "FRONTEND", "BACKEND", "PROMPTS", "TESTS", "DOCS", "CONFIG",
    "MIGRATIONS", "API", "AUTH", "SECURITY", "A11Y", "PERF",
)

DEFAULT_BASES = ("origin/main", "origin/master", "main", "master")

FRONTEND_EXT = {".css", ".scss", ".less", ".sass", ".pcss", ".styl",
                ".tsx", ".jsx", ".vue", ".svelte", ".astro",
                ".erb", ".haml", ".slim", ".hbs", ".ejs", ".html", ".htm"}
BACKEND_EXT = {".rb", ".py", ".go", ".rs", ".java", ".kt", ".php", ".ex", ".exs",
               ".cs", ".scala", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".pl",
               ".ts", ".js", ".mjs", ".cjs", ".mts", ".cts"}
DOC_EXT = {".md", ".rst", ".adoc", ".txt"}
CONFIG_EXT = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties"}
CONFIG_NAMES = {"package.json", "package-lock.json", "yarn.lock", "bun.lock", "bun.lockb",
                "gemfile", "gemfile.lock", "requirements.txt", "pyproject.toml", "go.mod",
                "go.sum", "cargo.toml", "cargo.lock", "composer.json", "dockerfile",
                "makefile", "poetry.lock"}

PATH_RULES = [
    ("FRONTEND", re.compile(r"(^|/)(components|views|templates|styles|css|stylesheets)/")),
    ("FRONTEND", re.compile(r"(^|/)(tailwind|postcss)\.config\.")),
    ("PROMPTS", re.compile(r"prompt|(^|/)(skills|playbooks)/|(^|/)(SKILL|AGENTS)\.md$|\.prompt$")),
    ("TESTS", re.compile(r"\.(test|spec)\.|_(test|spec)\.|(^|/)test_[^/]*$|(^|/)(tests?|spec|__tests__|cypress|e2e)/")),
    ("DOCS", re.compile(r"(^|/)docs?/")),
    # Exact public README payloads emitted by scripts/gen-badges.py; other JSON
    # and assets still need their own review signals.
    ("DOCS", re.compile(r"^assets/badges/(tests|missions)\.json$")),
    ("CONFIG", re.compile(r"(^|/)\.github/|(^|/)\.circleci/|(^|/)ci/")),
    ("MIGRATIONS", re.compile(r"(^|/)(db/migrate|migrations|alembic|prisma/migrations|db/data|data_migrations)/")),
    ("API", re.compile(r"(^|/)api/|controller|route|endpoint|handler|\.(graphql|gql)$|(^|/)(openapi|swagger)\.")),
    ("AUTH", re.compile(r"auth|session|jwt|oauth|permission|role|login|logout|password|credential")),
    ("SECURITY", re.compile(r"security|crypto|secret|sanitiz|escape|csrf|xss|redact")),
    ("A11Y", re.compile(r"a11y|accessib|aria")),
    ("PERF", re.compile(r"bench|perf|cache|throttl|index")),
]

CONTENT_RULES = [
    ("PROMPTS", re.compile(r"You are an? |system prompt|<system>|role\s*:\s*[\"']system")),
    ("API", re.compile(r"@app\.route|@router\.|app\.(get|post|put|delete)\(|Route\(|http\.HandleFunc")),
    ("AUTH", re.compile(r"authenticate|authorize|Set-Cookie|Bearer |session\[|current_user")),
    ("SECURITY", re.compile(r"subprocess\.|shell=True|os\.system|innerHTML|pickle\.loads|verify=False|dangerouslySetInnerHTML")),
    ("A11Y", re.compile(r"aria-|role=|alt=|tabindex|tabIndex|focus-visible|<button|<img")),
    ("PERF", re.compile(r"useMemo|useCallback|lru_cache|perf_counter|benchmark|N\+1|EXPLAIN |createIndex|add_index")),
]


class ScopeError(Exception):
    """A base or required acquisition failed; partial results are not a verdict."""

    def __init__(self, message, kind="no_base", resolved=None):
        super().__init__(message)
        self.kind = kind
        self.resolved = resolved  # the base that WAS resolved before acquisition failed (#382)


# git is resolved ONCE to an absolute path and run with replacement objects and the
# config-driven execution channels off. The rule is gitexec.py's, inlined here because
# verify.py loads this file by path: a sibling import would join the signed verifier
# toolchain (verify._Transcript.TOOLCHAIN / run_report.TOOLCHAIN_FILES).
GIT = shutil.which("git") or "git"


def _git_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
           and k not in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT")}
    pairs = (("core.fsmonitor", "false"), ("protocol.ext.allow", "never"))
    env.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_COUNT": str(len(pairs))})
    for i, (k, v) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    return env


def git(repo, *args, tolerate=False):
    try:
        r = subprocess.run([GIT, "-C", str(repo), *args], capture_output=True, text=True,
                           timeout=60, env=_git_env())
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0 and not tolerate:
        return None
    return r.stdout


def resolve_base(repo, base):
    if base:
        if git(repo, "rev-parse", "--verify", "-q", base + "^{commit}") is None:
            raise ScopeError(base)
        return base
    head = git(repo, "symbolic-ref", "refs/remotes/origin/HEAD")
    if head and head.strip():
        candidate = head.strip().replace("refs/remotes/", "", 1)
        if git(repo, "rev-parse", "--verify", "-q", candidate + "^{commit}") is not None:
            return candidate
    for candidate in DEFAULT_BASES:
        if git(repo, "rev-parse", "--verify", "-q", candidate + "^{commit}") is not None:
            return candidate
    raise ScopeError("origin/HEAD")


def changed_files(repo, base):
    """Union of committed diff vs base, working tree, and untracked files."""
    names = set()

    def absorb(out, phase):
        if out is None:
            raise ScopeError(f"{phase} acquisition failed", kind="diff_failed", resolved=base)
        for name in out.split("\0"):
            if name:
                names.add(name)
    # A failed merge-base diff cannot license a different comparison. Unrelated
    # histories and other git failures both mean the requested scope is unknown.
    options = ("--no-ext-diff", "--no-textconv", "-z", "--name-only")
    absorb(git(repo, "diff", *options, f"{base}...HEAD", "--"), "committed diff")
    # Working tree (staged + unstaged); fails on a repo with no commits.
    absorb(git(repo, "diff", *options, "HEAD", "--"), "working-tree diff")
    # Untracked: the new migration/component is untracked right up until commit.
    absorb(git(repo, "ls-files", "-z", "--others", "--exclude-standard"), "untracked enumeration")
    return sorted(names)


def read_worktree(repo, path):
    p = Path(repo) / path
    try:
        if not p.is_file():
            return ""
        with p.open("rb") as fh:
            return fh.read(CONTENT_CAP).decode("utf-8", errors="replace")
    except OSError:
        return ""


def classify(repo, path):
    """Return the set of flags one path earns."""
    hits = set()
    low = path.lower()
    suffix = Path(low).suffix
    name = Path(low).name

    if suffix in FRONTEND_EXT:
        hits.add("FRONTEND")
    if suffix in DOC_EXT:
        hits.add("DOCS")
    if suffix in CONFIG_EXT or name in CONFIG_NAMES or name.startswith("dockerfile"):
        hits.add("CONFIG")
    for flag, pattern in PATH_RULES:
        if pattern.search(low):
            hits.add(flag)
    if "FRONTEND" not in hits and suffix in BACKEND_EXT:
        hits.add("BACKEND")

    text = read_worktree(repo, path)
    if text:
        for flag, pattern in CONTENT_RULES:
            if flag not in hits and pattern.search(text):
                hits.add(flag)
    return hits


def scope(repo, base=None):
    """Return (flags dict, unmatched list). Raises ScopeError when the base fails."""
    base = resolve_base(repo, base)
    flags = {f: False for f in FLAGS}
    unmatched = []
    for path in changed_files(repo, base):
        hits = classify(repo, path)
        if not hits:
            unmatched.append(path)
            continue
        for flag in hits:
            flags[flag] = True
    return flags, unmatched, base


def render_flags(flags):
    return [f"SCOPE_{name}={'true' if flags[name] else 'false'}" for name in FLAGS]


def _normalize_overlap_units(raw):
    items = raw.get("units") if isinstance(raw, dict) else raw
    if not isinstance(items, list) or not items:
        raise ScopeError("overlap spec must be a non-empty list or {units: [...]}", kind="invalid_overlap")
    units = []
    seen = set()
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise ScopeError(f"units[{idx}] must be an object", kind="invalid_overlap")
        uid = item.get("id")
        patterns = item.get("scope")
        if not isinstance(uid, str) or not uid.strip():
            raise ScopeError(f"units[{idx}].id must be a non-empty string", kind="invalid_overlap")
        if uid in seen:
            raise ScopeError(f"duplicate unit id {uid!r}", kind="invalid_overlap")
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(p, str) and p.strip() for p in patterns
        ):
            raise ScopeError(f"units[{idx}].scope must be a non-empty list of globs/paths", kind="invalid_overlap")
        seen.add(uid)
        units.append({"id": uid.strip(), "scope": [p.strip() for p in patterns]})
    return units


def _glob_intersects(pa, pb):
    """True when two glob/path patterns can match at least one common path."""
    a = pa.strip().lstrip("./")
    b = pb.strip().lstrip("./")
    if not a or not b:
        return False
    if a == b or fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a):
        return True
    if a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/"):
        return True
    la, lb = len(a), len(b)
    seen = {(0, 0)}
    stack = [(0, 0)]
    while stack:
        i, j = stack.pop()
        if i == la and j == lb:
            return True
        nxt = []
        if i < la and a[i] == "*":
            is_globstar = (i + 1 < la and a[i + 1] == "*") or (i > 0 and a[i - 1] == "*")
            nxt.append((i + 1, j))
            if j < lb and (b[j] != "/" or is_globstar):
                nxt.append((i, j + 1))
        if j < lb and b[j] == "*":
            is_globstar = (j + 1 < lb and b[j + 1] == "*") or (j > 0 and b[j - 1] == "*")
            nxt.append((i, j + 1))
            if i < la and (a[i] != "/" or is_globstar):
                nxt.append((i + 1, j))
        if i < la and j < lb:
            ca, cb = a[i], b[j]
            if ca == cb or (ca == "?" and cb != "/") or (cb == "?" and ca != "/"):
                nxt.append((i + 1, j + 1))
        for state in nxt:
            if state not in seen:
                seen.add(state)
                stack.append(state)
    return False


def detect_scope_overlaps(units, repo_files=None):
    """Return (overlaps, deps_by_unit) for pre-dispatch hot-file serialization."""
    normalized = _normalize_overlap_units(units)
    tracked = list(repo_files or [])
    overlaps = []
    deps_by_unit = {u["id"]: [] for u in normalized}
    for i, ua in enumerate(normalized):
        for ub in normalized[i + 1:]:
            shared = set()
            for fpath in tracked:
                if any(fnmatch.fnmatchcase(fpath, pa) for pa in ua["scope"]) and any(
                    fnmatch.fnmatchcase(fpath, pb) for pb in ub["scope"]
                ):
                    shared.add(fpath)
            for pa in ua["scope"]:
                for pb in ub["scope"]:
                    if _glob_intersects(pa, pb):
                        shared.add(pa if pa == pb else f"{pa} & {pb}")
            if shared:
                overlaps.append({
                    "blocker": ua["id"],
                    "blocked": ub["id"],
                    "shared": sorted(shared),
                })
                if ua["id"] not in deps_by_unit[ub["id"]]:
                    deps_by_unit[ub["id"]].append(ua["id"])
    return overlaps, deps_by_unit


def _tracked_files(repo):
    out = git(repo, "ls-files", "-z")
    if out is None:
        raise ScopeError(f"git ls-files failed in {repo}", kind="diff_failed")
    return sorted(name for name in out.split("\0") if name)


def build_parser():
    p = argparse.ArgumentParser(
        prog="diff_scope.py",
        description="Classify the changed surface into SCOPE_* review flags, failing loud when it cannot look.",
        epilog="exit 0 classified / 2 SCOPE_ERROR=no_base|diff_failed|unmatched|invalid_overlap",
    )
    p.add_argument("--base", default=None, help="base ref (default: origin/HEAD, then origin/main, origin/master, main, master)")
    p.add_argument("--repo", default=".", help="repository to classify (default: cwd)")
    p.add_argument("--strict", action="store_true",
                   help="exit nonzero when ANY changed path is unmatched, not only when nothing "
                        "matched — for a review lens that gates on the flag set (#314)")
    p.add_argument("--overlap", default=None,
                   help="pre-dispatch overlap JSON ({units: [{id, scope: [...]}]}) to serialize shared hot files")
    p.add_argument("--json", action="store_true", help="emit a JSON object instead of shell assignments")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    repo = Path(args.repo)
    if args.overlap is not None:
        try:
            raw = json.loads(Path(args.overlap).read_text(encoding="utf-8"))
            overlaps, deps = detect_scope_overlaps(raw, _tracked_files(repo))
        except (OSError, json.JSONDecodeError) as exc:
            err = ScopeError(f"cannot read overlap spec {args.overlap}: {exc}", kind="invalid_overlap")
            if args.json:
                print(json.dumps({"overlaps": [], "deps": {}, "error": err.kind}, indent=2))
            else:
                print(f"SCOPE_ERROR={err.kind}")
                print(f"# {err}")
            return EXIT_SCOPE_ERROR
        except ScopeError as err:
            if args.json:
                print(json.dumps({"overlaps": [], "deps": {}, "error": err.kind}, indent=2))
            else:
                print(f"SCOPE_ERROR={err.kind}")
                print(f"# {err}")
            return EXIT_SCOPE_ERROR
        if args.json:
            print(json.dumps({"overlaps": overlaps, "deps": deps, "error": None}, indent=2))
        else:
            print(f"OVERLAP_COUNT={len(overlaps)}")
            for item in overlaps:
                print(f"# overlap: {item['blocker']} -> {item['blocked']} ({', '.join(item['shared'])})")
        return EXIT_OK

    try:
        flags, unmatched, base = scope(repo, args.base)
    except ScopeError as err:
        empty = {f: False for f in FLAGS}
        if args.json:
            print(json.dumps({"flags": empty, "error": err.kind,
                              "base": str(err) if err.kind == "no_base" else (err.resolved or args.base),
                              "unmatched": []}, indent=2))
        else:
            for line in render_flags(empty):
                print(line)
            print(f"SCOPE_ERROR={err.kind}")
            if err.kind == "no_base":
                print(f"# base ref '{err}' is not resolvable — shallow checkout or missing fetch. Run: git fetch origin")
            else:
                print(f"# {err}; no scope verdict is available")
        return EXIT_SCOPE_ERROR

    # #314: `unmatched` used to be an error only when NOTHING matched, and the paths printed only
    # inside that branch. A diff half in-scope and half somewhere else exited 0 with the
    # out-of-scope half invisible in text output — the shape most likely to matter, because a
    # review lens gating on the flag set reads a clean answer. The paths are now always shown
    # (--json already carried them), and --strict makes ANY unmatched path a nonzero exit for a
    # lens that wants to gate on it. Default behaviour is unchanged: a partial match is
    # information, not a failure, and turning it into one by default would break every caller
    # whose repo has a file this classifier has no rule for.
    nothing_matched = bool(unmatched) and not any(flags.values())
    error = "unmatched" if nothing_matched or (unmatched and args.strict) else None
    if args.json:
        print(json.dumps({"flags": flags, "error": error, "base": base, "unmatched": unmatched[:50]}, indent=2))
    else:
        for line in render_flags(flags):
            print(line)
        if error:
            print("SCOPE_ERROR=unmatched")
        for path in unmatched[:50]:
            print(f"# unmatched: {path}")
    return EXIT_SCOPE_ERROR if error else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
