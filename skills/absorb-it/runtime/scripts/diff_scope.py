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
SCOPE_DOCS       *.md, *.rst, *.adoc, docs/*, docs/assets/badges/{tests,missions}.json
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

--predict-merge BASE BRANCH (#590) predicts the 3-way merge in memory with
``git merge-tree --write-tree`` (HEAD, index and worktree untouched) and prints
``{"clean", "tree_oid", "conflicts"}`` as JSON:
    0  clean merge
    1  the merge conflicts (``conflicts`` names the paths)
    2  SCOPE_ERROR=no_base     -- BASE or BRANCH does not resolve to a commit, or
                                  the two share no merge base; nothing was predicted
    2  SCOPE_ERROR=diff_failed -- git merge-tree --write-tree could not run
                                  (git < 2.38 included: the classic form is never
                                  guessed from), or prediction failed unexpectedly
An unresolvable ref is never reported as a conflict: exit 1 always means a
real conflict between two real commits.

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
import sys

# W3-01: `python3 <dir>/<script>.py` puts <dir> at sys.path[0], AHEAD of the stdlib, so a committed
# sibling named like a stdlib module (json.py, hashlib.py) would BE that module here, and no
# toolchain hash binds it. Drop that entry before any other import (`from __future__` imports too,
# which is why this file has none); `os` is read from sys.modules, loaded at start-up, never
# imported. `python3 -I` does the same from outside; this holds when a caller forgets it.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

EXIT_OK = 0
EXIT_PREDICTED_CONFLICT = 1  # --predict-merge only: a real conflict between two real commits
EXIT_SCOPE_ERROR = 2

CONTENT_CAP = 256 * 1024

FLAGS = (
    "FRONTEND", "BACKEND", "PROMPTS", "TESTS", "DOCS", "CONFIG",
    "MIGRATIONS", "API", "AUTH", "SECURITY", "A11Y", "PERF",
)


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
    # Exact public README payloads emitted by scripts/gen-badges.py. This repository keeps them
    # under docs/assets/badges/, which the docs rule above also covers; elsewhere a JSON file
    # still needs its own review signal.
    ("DOCS", re.compile(r"^docs/assets/badges/(tests|missions)\.json$")),
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
# verify.py loads this file by path and diff_scope's own GIT is the one its callers (and their
# tests) pin. The copy is the WHOLE floor — no global/system config, safe.directory — and a test
# pins it to gitexec.HARDENED so it cannot fall behind again (2026-10-23 review, §5). Absent at
# import is None, never a bare "git" that every later call re-resolves against PATH (W4-14):
# _argv raises.
_found = shutil.which("git")
GIT = os.path.abspath(_found) if _found else None


def _load_gitexec():
    """runtime/scripts/gitexec.py, loaded by path: the shared git custody (custody_git_dir and
    friends) and its floor. gitexec.py is already in the signed verifier toolchain (#608), so
    loading it here adds no file to what verify.py IS."""
    spec = importlib.util.spec_from_file_location(
        "open_fleet_diff_scope_gitexec", Path(__file__).resolve().parent / "gitexec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load_gitexec()


def _argv(*args):
    """[GIT, *args], or FileNotFoundError (an OSError: each caller's could-not-run path) when no
    git was on PATH at import — gitexec.argv's GitAbsent rule, inlined like the rest."""
    if GIT is None:
        raise FileNotFoundError("git is not on PATH (resolved once, at startup)")
    return [GIT, *args]


def _git_env(blanks=()):
    """gitexec.env's floor, inlined; ``blanks`` (_driver_blanks pairs) ride as further env
    pairs, so a driver name holding `=` or a non-UTF-8 byte reaches git exactly (PR #649). Every
    call also carries gitexec's custody floor (W4 custody sweep): CUSTODY_FLOOR's fixed command
    keys, CUSTODY_ENV (no lazy fetch, no transport but `file`) and no inherited repository
    selector (SELECTOR_ENV: GIT_DIR, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY, ...)."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
           and k not in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
                         "GIT_CONFIG")
           and k not in gitexec.SELECTOR_ENV}
    pairs = (("core.fsmonitor", "false"), ("protocol.ext.allow", "never"), ("safe.directory", "*"),
             # #629: the repo-config command channels a fixed key can close — hooks (post-checkout
             # on a worktree read) and the global external-diff program.
             ("core.hooksPath", os.devnull), ("diff.external", ""),
             # floor_guard's DIFF_RENDERING pins: inert for -z --name-only, kept for parity.
             ("diff.noprefix", "false"), ("diff.mnemonicPrefix", "false"), ("diff.srcPrefix", "a/"),
             ("diff.dstPrefix", "b/"), ("diff.relative", "false"), ("color.diff", "false"),
             *gitexec.CUSTODY_FLOOR, *blanks)
    env.update({"GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_COUNT": str(len(pairs))})
    for i, (k, v) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    env.update(gitexec.CUSTODY_ENV)
    return env


# gitexec.driver_blanks, inlined (verify.py loads this file by path; see the module note on
# _git_env). Blanks every filter/diff driver command the repo DECLARES — the attribute-selected
# exec channel a fixed -c cannot name (#629). Bytes in, os.fsdecode'd keys out, and each declared
# filter neutralised whole — commands blank AND required=false, or git dies on it (PR #649). A
# merge.<driver>.driver (selected when merge-tree 3-way-merges a path) is overridden to `exit 1`,
# a shell builtin that fails the merge closed and runs no repository command (PR #649 review).
_FILTER_KEY_RE = re.compile(rb"\Afilter\.(.+)\.[^.]+\Z", re.S)
_DIFF_COMMAND_KEY_RE = re.compile(rb"\Adiff\.(?:.+)\.(?:textconv|command)\Z", re.S)
_MERGE_KEY_RE = re.compile(rb"\Amerge\.(.+)\.[^.]+\Z", re.S)
_FILTER_BLANKS = ((b"clean", ""), (b"smudge", ""), (b"process", ""), (b"required", "false"))
_MERGE_DRIVER = "exit 1"


def _driver_blanks(repo):
    """gitexec.driver_blanks's pairs. [] means exactly "no driver declared" (git answers an empty
    valid config with exit 0 and no output); a query that errors, times out, exits non-zero or
    prints output that is not NUL-terminated keys raises ScopeError(diff_failed) — never [],
    which would run the diff with every planted driver live (PR #649 review)."""
    try:
        gitexec.refuse_blocking_files(repo)  # a config or include git would block opening
        r = subprocess.run(_argv("-C", str(repo), "config", "--list", "-z", "--name-only"),
                           capture_output=True, timeout=60, env=_git_env(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as err:
        raise ScopeError(f"cannot read {repo}'s driver config: {err}", kind="diff_failed") from err
    if r.returncode != 0:
        why = r.stderr.decode("utf-8", "replace").strip()[:200]
        raise ScopeError(f"cannot read {repo}'s driver config (git config exited {r.returncode}: "
                         f"{why})", kind="diff_failed")
    if r.stdout and not r.stdout.endswith(b"\0"):
        raise ScopeError(f"{repo}'s driver config listing is not NUL-terminated keys",
                         kind="diff_failed")
    keys = r.stdout.split(b"\0")[:-1] if r.stdout else []
    if any(not key for key in keys):
        raise ScopeError(f"{repo}'s driver config listing holds an empty key", kind="diff_failed")
    pairs, filt_seen, merge_seen = [], set(), set()
    for key in keys:
        filt = _FILTER_KEY_RE.match(key)
        merge = _MERGE_KEY_RE.match(key)
        if filt:
            if filt.group(1) not in filt_seen:
                filt_seen.add(filt.group(1))
                pairs += [(os.fsdecode(b"filter." + filt.group(1) + b"." + var), value)
                          for var, value in _FILTER_BLANKS]
        elif merge:
            if merge.group(1) not in merge_seen:
                merge_seen.add(merge.group(1))
                pairs.append((os.fsdecode(b"merge." + merge.group(1) + b".driver"), _MERGE_DRIVER))
        elif _DIFF_COMMAND_KEY_RE.match(key):
            pairs.append((os.fsdecode(key), ""))
    return pairs


def _custody(repo, **kw):
    """gitexec.custody over ``repo``, its facts and settings read with diff_scope's own git and
    floor: a git dir the coordinator builds over the repo's objects, whose config declares no
    filter, textconv, diff or merge driver. A driver a `.gitattributes`/`info/attributes` line
    selects is undefined there, however late the repo's config gained it (W4 custody sweep: the
    blanks _driver_blanks lists cover only drivers declared BEFORE the listing)."""
    def run(args):
        return subprocess.run(_argv("-C", str(repo), *args), capture_output=True, timeout=60,
                              env=_git_env(), stdin=subprocess.DEVNULL)
    return gitexec.custody(repo, run=run, **kw)


def git(repo, *args, tolerate=False, blanks=(), custody=None):
    """stdout of ``git <args>`` in ``repo`` (None on failure). ``custody`` (a gitexec.Custody, see
    _custody) runs it against the coordinator-built git dir over ``repo``'s work tree instead."""
    lead = custody.lead if custody is not None else ["-C", str(repo)]
    pairs = [*(custody.pairs if custody is not None else ()), *blanks]
    try:
        gitexec.refuse_blocking_files(repo)  # a config, include or `shallow` git would block opening
        # surrogateescape: a non-UTF-8 path round-trips instead of raising
        # UnicodeDecodeError (an uncaught crash would exit 1 — the conflict code).
        r = subprocess.run(_argv(*lead, *args), capture_output=True, text=True,
                           encoding="utf-8", errors="surrogateescape",
                           timeout=60, env=_git_env(pairs), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0 and not tolerate:
        return None
    return r.stdout


def _exact_runner(repo):
    """gitexec.base_commit's ``git(*args) -> (returncode, stdout)`` over diff_scope's own git."""
    def run(*args):
        out = git(repo, *args)
        return (0, out) if out is not None else (1, "")
    return run


def resolve_base(repo, base):
    """(commit, shown): the base resolved ONCE, by exact ref names only (gitexec.base_commit,
    W3-07 class); the diff is taken against `commit`, never the name. `rev-parse <base>^{commit}`
    expanded the name (refs/tags/ and refs/heads/ before refs/remotes/), so a tag or local branch
    spelled `origin/main` stood in for the remote-tracking branch, and an origin/HEAD pointed at
    a local branch was used as-is — and the base decides which paths count as changed, so which
    review lenses run. A local-branch, HEAD or abbreviated-id base is refused on a lane claiming
    soundness (gitexec.sound_lane: ORCA_PROVENANCE / OPEN_FLEET_PROVENANCE set) and NOTE'd
    elsewhere. gitexec is the module this file loads at import (its git custody too); gitexec.py is
    in the verifier toolchain since #608."""
    commit, shown, local, why = gitexec.base_commit(_exact_runner(repo), base)
    if commit is None:
        print(f"diff_scope: base {shown!r} {why}", file=sys.stderr)
        raise ScopeError(base or "origin/HEAD")
    if local:
        lane = gitexec.sound_lane()
        if lane:
            print(f"diff_scope: {lane} claims a sound lane, but base {shown!r} is {local} "
                  f"({commit[:12]}), not a remote-tracking ref or a full commit id — name "
                  "origin/<branch> or a full commit id (W3-07)", file=sys.stderr)
            raise ScopeError(base or shown)
        print(f"diff_scope: NOTE — base {shown!r} is {local} ({commit[:12]}), not a "
              "remote-tracking ref or a full commit id, so advisory; --base origin/<branch> (or a "
              "full commit id) is one the change under check cannot move", file=sys.stderr)
    return commit, shown


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
    # --no-renames: a rename is its delete AND its add, so a file moved OUT of db/migrate/
    # or away from session_guard.py still earns the lens its old path did (P2-9).
    options = ("--no-ext-diff", "--no-textconv", "--no-renames", "-z", "--name-only")
    # The working-tree diff materialises tracked files, which runs a repo-config clean/smudge
    # filter a .gitattributes selects — the one channel --no-ext-diff/--no-textconv leave open
    # (#629). Listing the declared drivers and blanking them left a window: one added after the
    # listing ran (W4 custody sweep). So that diff runs in git custody (_custody), where no driver
    # is defined at all. The listing stays as a fail-closed belt (an unreadable config is
    # diff_failed, never "no drivers"). The committed diff compares two trees by name only
    # (--name-only, --no-renames): it reads no working-tree file and renders no content, so no
    # driver can apply, and it runs in the repo, where `base` names a ref.
    blanks = _driver_blanks(repo)
    absorb(git(repo, "diff", *options, f"{base}...HEAD", "--", blanks=blanks), "committed diff")
    # Working tree (staged + unstaged); fails on a repo with no commits.
    try:
        with _custody(repo) as custody:
            # No child git inside a checked-out submodule (it would run under the submodule's own
            # config); a moved gitlink is still listed (gitexec.NO_SUBMODULE_CHILD).
            worktree = git(repo, "diff", *options, gitexec.NO_SUBMODULE_CHILD, "HEAD", "--",
                           blanks=blanks, custody=custody)
            # Untracked: the new migration/component is untracked right up until commit. Listed in
            # custody, where the repository's own core.excludesFile is carried as data and no user
            # default ignore file is opened.
            untracked = git(repo, "ls-files", "-z", "--others", "--exclude-standard", custody=custody)
    except (OSError, subprocess.SubprocessError) as err:  # GitCustodyRefused is an OSError
        raise ScopeError(f"working-tree diff acquisition failed: {err}", kind="diff_failed",
                         resolved=base) from err
    absorb(worktree, "working-tree diff")
    absorb(untracked, "untracked enumeration")
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
    base, shown = resolve_base(repo, base)  # a commit id; `shown` names it in the output
    flags = {f: False for f in FLAGS}
    unmatched = []
    for path in changed_files(repo, base):
        hits = classify(repo, path)
        if not hits:
            unmatched.append(path)
            continue
        for flag in hits:
            flags[flag] = True
    return flags, unmatched, shown


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


def predict_merge(repo, base, branch):
    """Detect 3-way merge conflicts in memory via git merge-tree without touching HEAD/index/worktree.

    Raises ScopeError(kind="no_base") when either ref does not resolve to a
    commit (or the two share no merge base), and ScopeError(kind="diff_failed")
    when merge-tree cannot run: "could not predict" must never read as a conflict.
    """
    # Each name resolved ONCE, by exact ref names only - W3-07's rule (gitexec.base_commit), as
    # resolve_base resolves a scope base: `rev-parse <ref>^{commit}` expanded it (refs/tags/ and
    # refs/heads/ before refs/remotes/), so a tag or local branch spelled `origin/main` stood in for
    # the remote-tracking branch. merge-tree is then given the two commit ids, and a LOCAL name is
    # refused on a lane claiming soundness and NOTE'd elsewhere (merge_queue.py passes commit ids).
    shas = []
    for label, ref in (("base", base), ("branch", branch)):
        commit, shown, local, why = (gitexec.base_commit(_exact_runner(repo), ref)
                                     if ref and not ref.startswith("-")
                                     else (None, ref, None, "is empty or option-shaped"))
        if commit is None:
            raise ScopeError(f"predict-merge {label} {ref!r} does not resolve to a commit in {repo} "
                             f"by its exact name: {why}", kind="no_base")
        if local:
            lane = gitexec.sound_lane()
            if lane:
                raise ScopeError(f"predict-merge: {lane} claims a sound lane, but {label} {shown!r} "
                                 f"is {local} ({commit[:12]}), not a remote-tracking ref or a full "
                                 "commit id (W3-07)", kind="no_base")
            print(f"diff_scope: NOTE — predict-merge {label} {shown!r} is {local} "
                  f"({commit[:12]}), not a remote-tracking ref or a full commit id, so advisory",
                  file=sys.stderr)
        shas.append(commit)
    # #629 (PR #649 review): merge-tree 3-way-merges the two commits, running a repo-config merge
    # driver a `merge=<driver>` attribute selects. Blanking the declared drivers left a window
    # (one added after the listing ran: W4 custody sweep), so merge-tree runs in git custody
    # (_custody): a git dir with no driver defined, over the repo's object store ("shared": the
    # merged tree it writes lands in the repo, where merge_queue.py commits it), given the two
    # commit ids resolved above, never a ref the custody dir does not hold. The listing stays as a
    # fail-closed belt, read OUTSIDE the subprocess-error catch below: an unreadable driver list
    # raises diff_failed, never a merge-tree that "could not run" quietly read as no drivers.
    blanks = _driver_blanks(repo)
    try:
        with _custody(repo, index=False, objects="shared") as custody:
            r = subprocess.run(
                _argv(*custody.lead, "-c", "core.quotePath=false",
                      "merge-tree", "--write-tree", *shas),
                capture_output=True, text=True, encoding="utf-8", errors="surrogateescape",
                timeout=60, env=_git_env([*custody.pairs, *blanks]), stdin=subprocess.DEVNULL,
            )
    except (gitexec.GitCustodyRefused, subprocess.TimeoutExpired) as err:
        # The custody's own reason (a partial clone, an unhonourable extension, a file git would
        # block on) or a git that timed out, in its setup or the merge itself - never the "needs
        # git >= 2.38" guess below (PR #724 re-attack; Codex round 6).
        raise ScopeError(f"predict-merge: {err}", kind="diff_failed") from err
    except (OSError, subprocess.SubprocessError):
        r = None

    if r is not None and r.returncode == 0:
        lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        tree_oid = lines[0] if lines else None
        return {"clean": True, "tree_oid": tree_oid, "conflicts": []}

    if r is not None and r.returncode == 1:
        conflicts = set()
        for line in r.stdout.splitlines():
            m_stage = re.match(r"^[0-9]{6}\s+[0-9a-f]{40,64}\s+[123]\t(.+)$", line)
            if m_stage:
                conflicts.add(m_stage.group(1).strip())
                continue
            m_conf = re.match(
                r"^CONFLICT\s*\([^)]+\):\s*(?:Merge conflict in\s+)?(.+?)(?:\s+deleted in .+|$)",
                line,
            )
            if m_conf:
                conflicts.add(m_conf.group(1).strip())
        return {"clean": False, "tree_oid": None, "conflicts": sorted(conflicts)}

    mb_out = git(repo, "merge-base", *shas)
    if not mb_out or not mb_out.strip():
        raise ScopeError(f"predict-merge: {base!r} and {branch!r} share no merge base", kind="no_base")
    # No guessing from the classic `git merge-tree <base> <a> <b>` form (git < 2.38): its
    # output lists every changed path ("added in remote", "changed in both" with a clean
    # 3-way result, ...), so reading it reported clean merges as conflicts. "Could not
    # predict" is SCOPE_ERROR=diff_failed (exit 2), never a verdict.
    tail = ""
    if r is not None:
        lines = (r.stderr or r.stdout or "").strip().splitlines()
        tail = f" (exit {r.returncode}: {lines[-1][:200] if lines else 'no output'})"
    raise ScopeError(
        f"predict-merge: `git merge-tree --write-tree` failed in {repo}{tail}; predicting a "
        "merge needs git >= 2.38 — the classic merge-tree form cannot tell a clean merge "
        "from a conflict, so no prediction is made",
        kind="diff_failed")


def build_parser():
    p = argparse.ArgumentParser(
        prog="diff_scope.py",
        description="Classify the changed surface into SCOPE_* review flags, failing loud when it cannot look.",
        epilog="exit 0 classified (or clean predicted merge) / 1 predicted merge conflict (--predict-merge) / "
               "2 SCOPE_ERROR=no_base|diff_failed|unmatched|invalid_overlap",
    )
    p.add_argument("--base", default=None, help="base ref (default: origin/HEAD, then origin/main, origin/master, main, master)")
    p.add_argument("--repo", default=".", help="repository to classify (default: cwd)")
    p.add_argument("--strict", action="store_true",
                   help="exit nonzero when ANY changed path is unmatched, not only when nothing "
                        "matched — for a review lens that gates on the flag set (#314)")
    p.add_argument("--overlap", default=None,
                   help="pre-dispatch overlap JSON ({units: [{id, scope: [...]}]}) to serialize shared hot files")
    p.add_argument("--predict-merge", nargs=2, metavar=("BASE", "BRANCH"), default=None,
                   help="predict 3-way merge conflicts in memory via git merge-tree (#590)")
    p.add_argument("--json", action="store_true", help="emit a JSON object instead of shell assignments")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    repo = Path(args.repo)
    if args.predict_merge is not None:
        base_ref, branch_ref = args.predict_merge
        err = None
        try:
            res = predict_merge(repo, base_ref, branch_ref)
        except ScopeError as exc:
            err = exc
        except Exception as exc:  # never exit 1 (the conflict code) on a crash
            err = ScopeError(f"predict-merge failed unexpectedly: {type(exc).__name__}: {exc}",
                             kind="diff_failed")
        if err is not None:
            if args.json:
                print(json.dumps({"clean": None, "tree_oid": None, "conflicts": [],
                                  "error": err.kind, "detail": str(err)}))
            else:
                print(f"SCOPE_ERROR={err.kind}")
                print(f"# {err}")
            return EXIT_SCOPE_ERROR
        print(json.dumps(res))
        return EXIT_OK if res["clean"] else EXIT_PREDICTED_CONFLICT
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
